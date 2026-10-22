//! Synthetic products, devices and compiler requests shared by architecture tests.

use crate::bus::access::ManagementCredential;
use crate::commissioning::CompileOptions;
use crate::commissioning::catalog::profile::ResolvedProfile;
use crate::commissioning::catalog_testing::*;
use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::error::CompileError;
use crate::commissioning::input::facts::{ObservedTarget, ProgrammingFacts};
use crate::commissioning::input::security::ObservedDataSecurity;
use crate::commissioning::input::{CommissioningIntent, DownloadMode, ProgrammingInput, TargetSelection};
use crate::configuration::ResolvedKeyMaterial;
use crate::configuration::{MaterializedDevice, ToolManagedIpConfiguration, TopologyConfiguration};
use master_data::architecture_master_data;
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_project::{DomainAddress, IpAssignment, ProjectInstallationId};
use zweidraehte_proto::address::IndividualAddress;

mod master_data;

pub(in crate::commissioning) const SYSTEM_300_EXECUTABLE_DESCRIPTOR: [u8; 10] = [1, 0, 0, 1, 0, 0, 0, 0, 0, 0];

pub(in crate::commissioning) const SYSTEM_300_PLUGIN_DESCRIPTOR: [u8; 10] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0];

pub(in crate::commissioning) fn compile(
    catalog: &std::sync::Arc<MasterData>,
    profile: ResolvedProfile,
    product: &ProductData,
    topology: TopologyConfiguration,
) -> Result<CompiledProgram, CompileError> {
    compile_with_mode(catalog, profile, product, topology, DownloadMode::Full)
}

pub(in crate::commissioning) fn compile_with_mode(
    catalog: &std::sync::Arc<MasterData>,
    profile: ResolvedProfile,
    product: &ProductData,
    topology: TopologyConfiguration,
    mode: DownloadMode,
) -> Result<CompiledProgram, CompileError> {
    compile_at(catalog, profile, product, topology, mode, IndividualAddress::new(1, 1, 10))
}

pub(in crate::commissioning) fn compile_at(
    catalog: &std::sync::Arc<MasterData>,
    profile: ResolvedProfile,
    product: &ProductData,
    topology: TopologyConfiguration,
    mode: DownloadMode,
    address: IndividualAddress,
) -> Result<CompiledProgram, CompileError> {
    let configuration = MaterializedDevice::fixture(address, Some(15)).with_topology(topology);
    let options = CompileOptions {
        target: if matches!(configuration.topology().domain_address, Some(DomainAddress::Rf(_))) {
            TargetSelection::SerialNumber([0, 0xfa, 0, 0, 0, 10])
        } else {
            TargetSelection::ExistingAddress(address)
        },
        automatic_sections: None,
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
    };

    programming_input(catalog, product, &configuration, CommissioningIntent::Download(mode), options).compile(&profile)
}

pub(in crate::commissioning) fn resolve_profile(
    catalog: &std::sync::Arc<MasterData>,
    dd0: u16,
    descriptor: Option<[u8; 10]>,
    product: &ProductData,
) -> ResolvedProfile {
    resolve_catalog_profile(catalog, Some(product), &ProfileSelection {
        discovery: ProfileDiscovery { dd0, management_descriptor_01: descriptor, management_style: None },
        variant_hint: VariantHint::Automatic,
    })
    .unwrap_or_else(|error| panic!("profile {:04X} resolves: {error:#?}", dd0))
}

pub(in crate::commissioning) fn programming_input(
    catalog: &std::sync::Arc<MasterData>,
    product: &ProductData,
    configuration: &MaterializedDevice,
    intent: CommissioningIntent,
    options: CompileOptions,
) -> ProgrammingInput {
    let keys = ResolvedKeyMaterial::default();
    let network_observations = ObservedTarget {
        previous_address: configuration.individual_address(),
        // This synthetic device has a known serial number. RF domain writes
        // use it explicitly instead of manufacturing identity during lowering.
        serial_number: Some([0, 0xfa, 0, 0, 0, 10]),
        credential: ManagementCredential::Plaintext,
    };
    ProgrammingInput::new(
        configuration
            .clone()
            .with_product(
                product.clone().bind_master_data(std::sync::Arc::clone(catalog)).expect("fixture document binds"),
            )
            .with_key_material(keys),
        intent,
        options,
    )
    .facts(ProgrammingFacts { target: Some(network_observations), data_security: ObservedDataSecurity::Disabled })
}

pub(in crate::commissioning) fn rf_topology() -> TopologyConfiguration {
    let mut topology = TopologyConfiguration::default();
    topology.domain_address = Some(DomainAddress::Rf([1, 2, 3, 4, 5, 6]));
    topology
}

pub(in crate::commissioning) fn ip_topology() -> TopologyConfiguration {
    let mut topology = TopologyConfiguration::default();
    topology.ip = Some(ToolManagedIpConfiguration {
        project_installation_id: ProjectInstallationId::new(0x123, 4).expect("project ID is in range"),
        assignment: IpAssignment::Fixed {
            address: [192, 0, 2, 10],
            subnet_mask: [255, 255, 255, 0],
            default_gateway: [192, 0, 2, 1],
        },
        routing_multicast_address: [224, 0, 23, 12],
        multicast_ttl: 16,
        friendly_name: "Architecture IP".to_owned(),
        additional_individual_addresses: vec![IndividualAddress::new(1, 1, 11)],
        security: None,
        password_users: Vec::new(),
    });
    topology
}

pub(in crate::commissioning) fn product(
    mask: &str,
    load_style: &str,
    relative: bool,
    modern_coupler: bool,
) -> ProductData {
    let segment = if relative {
        r#"<RelativeSegment Id="M-00FA_A-0001-01-0000_RS-0" Size="4" LoadStateMachine="3" Offset="0"><Data>AQIDBA==</Data></RelativeSegment>"#
    } else {
        r#"<AbsoluteSegment Id="M-00FA_A-0001-01-0000_AS-100" Address="256" Size="4" MemoryType="EEPROM"><Data>AQIDBA==</Data></AbsoluteSegment>"#
    };
    let write = if relative {
        r#"<LdCtrlWriteRelMem ObjIdx="3" Offset="0" Size="4" Verify="false" />"#
    } else {
        r#"<LdCtrlWriteMem Address="256" Size="4" Verify="false" />"#
    };
    // A System 7 download needs an association table; the fixture keeps it
    // empty in a segment of its own so the parameter segment is unchanged.
    let association_table = (!relative && matches!(mask, "MV-0701" | "MV-0705" | "MV-2705" | "MV-5705"))
        .then_some(
            r#"<AbsoluteSegment Id="M-00FA_A-0001-01-0000_AS-110" Address="272" Size="1" MemoryType="EEPROM" />"#,
        )
        .unwrap_or_default();
    let association_reference = if association_table.is_empty() {
        ""
    } else {
        r#"<AssociationTable CodeSegment="M-00FA_A-0001-01-0000_AS-110" Offset="0" MaxEntries="0" />"#
    };
    let procedures = (load_style == "ProductProcedure")
        .then(|| {
            format!(
                "<LoadProcedures><LoadProcedure><LdCtrlConnect />{write}<LdCtrlDisconnect /></LoadProcedure></LoadProcedures>"
            )
        })
        .unwrap_or_default();
    let ip_attributes = matches!(mask, "MV-5705" | "MV-57B0")
        .then_some(r#" IPConfig="Tool" AdditionalAddressesCount="2" IsSecureEnabled="false""#)
        .unwrap_or_default();
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23" CreatedBy="architecture-test" ToolVersion="1">
          <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
            <ApplicationProgram Id="M-00FA_A-0001-01-0000" ApplicationNumber="1" ApplicationVersion="1"
              ProgramType="ApplicationProgram" MaskVersion="{mask}" Name="architecture fixture"
              LoadProcedureStyle="{load_style}" PeiType="0" DefaultLanguage="en-US"
              DynamicTableManagement="false" Linkable="false"{ip_attributes}>
              <Static><Code>{segment}{association_table}</Code>{association_reference}{procedures}
                <Options LineCoupler0912NewProgrammingStyle="{modern_coupler}" />
              </Static>
            </ApplicationProgram>
          </ApplicationPrograms></Manufacturer></ManufacturerData>
        </KNX>"#
    );

    ProductData::from_mtxml_str(&xml).expect("architecture product parses")
}

pub(in crate::commissioning) fn catalog(version: u16) -> std::sync::Arc<MasterData> {
    edited_catalog(version, |xml| xml)
}

/// The architecture catalog after a textual edit of its Master Data.
pub(in crate::commissioning) fn edited_catalog(
    version: u16,
    edit: impl FnOnce(String) -> String,
) -> std::sync::Arc<MasterData> {
    parse_master_data(&edit(architecture_master_data(version))).expect("architecture Master Data parses")
}
