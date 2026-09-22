//! Shared synthetic target and program fixtures.

use crate::bus::access::ManagementCredential;
use crate::commissioning::catalog::ProgrammingCatalog;
use crate::commissioning::catalog::profile::{
    ObjectSelector, ProfileDiscovery, ProfileRequest, ReadAccess, ResolvedProfile, ResourceManagementStyle, VariantHint,
};
use crate::commissioning::catalog::rules::resolved_download_stamp_resources as download_stamp_resources;
use crate::commissioning::compiler::program::{CommissioningApduRequirements, CompiledProgram};
use crate::commissioning::evidence::{DeploymentRecord, DeviceStamp};
use crate::commissioning::image::{ImageLocation, ImageSpace, SparseDeviceImage, fingerprint_image};
use crate::commissioning::input::facts::{ObservedTarget, ProgrammingFacts};
use crate::commissioning::input::{CommissioningIntent, DownloadMode, ProgramSections, TargetSelection};
use crate::commissioning::procedure::operands::{
    MemoryAddress, MemoryService, PointerEncoding, ServiceRead, StandardMemoryService, pure_property_address,
};
use crate::commissioning::procedure::{
    ControlPath, NormalizedProcedure, OperationData, OperationExtent, OperationTarget, ProcedureOperation,
    ProcedureSourceId, ProcedureStep, RestartKind, ToolState, WriteIntent, WritePolicy,
};
use crate::commissioning::runtime::prepared::{BoundRead, ReadExpectation};
use zweidraehte_proto::address::IndividualAddress;

pub(in crate::commissioning) fn observed_stamp_reads(plan: &CompiledProgram, stamps: &[DeviceStamp]) -> Vec<BoundRead> {
    plan.download_stamps()
        .iter()
        .map(|candidate| BoundRead {
            resource: candidate.id.clone(),
            service: candidate.read.clone(),
            expected: ReadExpectation::Exact(
                stamps.iter().find(|stamp| stamp.resource == candidate.id).map(|stamp| stamp.value.clone()),
            ),
        })
        .collect()
}

pub(in crate::commissioning) fn stamp_profile(ids: &[&str]) -> ResolvedProfile {
    let mut profile = authorization_profile("SystemB", None);
    set_feature(&mut profile, "DownloadStamp", 1);
    set_resources(
        &mut profile,
        ids.iter()
            .enumerate()
            .map(|(index, id)| indexed_stamp_resource(id, 3 + index as u16, ReadAccess::Runtime, false))
            .collect(),
    );
    profile
}

pub(in crate::commissioning) fn system_b_differential_fixture()
-> (CompiledProgram, DeploymentRecord, Vec<crate::commissioning::procedure::StampDescriptor>) {
    let mut profile = stamp_profile(&["group", "application"]);
    add_resources(&mut profile, [
        indexed_stamp_resource("address", 1, ReadAccess::Runtime, false),
        indexed_stamp_resource("association", 2, ReadAccess::Runtime, false),
    ]);
    let candidates =
        download_stamp_resources(&profile, StandardMemoryService::Classic).expect("only eligible stamps resolve");
    let mut plan = partial_plan(profile, ProgramSections::GROUP_COMMUNICATION);
    let mut previous = SparseDeviceImage::new();
    let mut writes = Vec::new();
    for index in 1..=4 {
        let location =
            ImageLocation { space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index } }, offset: 0 };
        previous.apply_owned(location.clone(), vec![index as u8; 8]).expect("previous table image applies");
        plan.image
            .apply_owned(location.clone(), vec![if index == 3 { 0x42 } else { index as u8 }; 8])
            .expect("current table image applies");
        let mut step = plan.procedure.as_ref().expect("fixture has a procedure").steps[0].clone();
        step.path.control_indices = vec![usize::from(index)];
        step.sections.insert(zweidraehte_project::ProgrammingSection::GroupCommunication);
        step.operation = ProcedureOperation::Write {
            target: OperationTarget::Memory {
                service: MemoryService::Classic,
                address: MemoryAddress::Pointer {
                    space: location.space.clone(),
                    read: Box::new(ServiceRead {
                        target: OperationTarget::Property {
                            address: pure_property_address(&ObjectSelector::Index { index }, 7)
                                .expect("indexed property"),
                            start_element: 1,
                        },
                        extent: OperationExtent::property(4, 1),
                    }),
                    offset: 0,
                    encoding: PointerEncoding::Absolute,
                },
            },
            data: OperationData::Image { location, length: 8 },
            extent: OperationExtent::bytes(8),
            policy: WriteIntent::Explicit(WritePolicy::NoVerification),
        };
        writes.push(step);
    }
    let procedure = plan.procedure.as_mut().expect("fixture has a procedure");
    procedure.steps.splice(1..1, writes);
    let mut deployment = deployment_record(
        &plan.profile,
        plan.product_fingerprint,
        candidates.iter().map(|resource| DeviceStamp { resource: resource.id.clone(), value: vec![0x11; 8] }).collect(),
    );
    deployment.image_fingerprint = fingerprint_image(&previous);
    deployment.image = previous;
    (plan, deployment, candidates)
}

pub(in crate::commissioning) fn partial_plan(profile: ResolvedProfile, sections: ProgramSections) -> CompiledProgram {
    let address = IndividualAddress::new(1, 1, 1);
    let procedure_id = ProcedureSourceId::Generated { name: "test non-application partial".to_owned() };
    let path = ControlPath {
        mask_id: profile.mask().full_id.clone(),
        variant_index: profile.variant().source_index,
        procedure: procedure_id.clone(),
        contribution: None,
        control_indices: Vec::new(),
    };
    let stamps = download_stamp_resources(&profile, StandardMemoryService::Classic).expect("fixture stamps resolve");
    let stamp_output = crate::commissioning::catalog::rules::resolved_download_stamp_output(&profile, stamps)
        .expect("fixture output policy resolves");
    CompiledProgram {
        verification_reads: Vec::new(),
        facts: ProgrammingFacts::new(ObservedTarget {
            previous_address: address,
            serial_number: None,
            credential: ManagementCredential::Plaintext,
        }),
        configured_max_apdu: None,
        full_image_stamp_coverage: profile.supports_full_image_stamp_coverage().expect("fixture coverage"),
        desired_data_security: crate::commissioning::input::security::DesiredDataSecurity::Preserve,
        intent: CommissioningIntent::Download(DownloadMode::Partial(sections)),
        target: TargetSelection::ExistingAddress(address),
        individual_address: address,
        network_restart_kind: RestartKind::Basic,
        program_sections: Some(sections),
        full_program_scope: false,
        topology: Default::default(),
        verify_mode: false,
        programming_mode: None,
        native_regions: Vec::new(),
        network: Default::default(),
        profile,
        image: SparseDeviceImage::new(),
        manifest: Default::default(),
        procedure: Some(NormalizedProcedure {
            id: procedure_id,
            initial_state: ToolState::default(),
            stamp_output,
            steps: vec![
                ProcedureStep {
                    path: path.clone(),
                    source_control_code: None,
                    sections: Default::default(),
                    operation: ProcedureOperation::Connect,
                    on_error: Vec::new(),
                    secure_only: false,
                },
                ProcedureStep {
                    path,
                    source_control_code: None,
                    sections: Default::default(),
                    operation: ProcedureOperation::Disconnect,
                    on_error: Vec::new(),
                    secure_only: false,
                },
            ],
        }),
        apdu_requirements: CommissioningApduRequirements::default(),
        product_fingerprint: [0; 32],
    }
}

pub(in crate::commissioning) fn partial_resource(name: &str, length: u32, read: ReadAccess) -> String {
    format!(
        r#"<Resource Name="{name}" Access="remote"><Location AddressSpace="StandardMemory" StartAddress="512" />
        <ResourceType Length="{length}" /><AccessRights Read="{read:?}" Write="None" /></Resource>"#
    )
}

pub(in crate::commissioning) fn deployment_record(
    profile: &ResolvedProfile,
    product_fingerprint: [u8; 32],
    device_stamps: Vec<DeviceStamp>,
) -> DeploymentRecord {
    let image = SparseDeviceImage::new();
    let image_fingerprint = fingerprint_image(&image);

    DeploymentRecord {
        mask: profile.mask().clone(),
        variant: profile.variant().clone(),
        master_data_fingerprint: profile.master_data_fingerprint(),
        product_fingerprint,
        image_fingerprint,
        image,
        device_stamps,
    }
}

pub(in crate::commissioning) fn indexed_stamp_resource(
    id: &str,
    index: u16,
    read: ReadAccess,
    optional: bool,
) -> String {
    stamp_resource(id, read, optional).replace(
        "AddressSpace=\"StandardMemory\" StartAddress=\"256\"",
        &format!("AddressSpace=\"SystemProperty\" InterfaceObjectRef=\"{index}\" PropertyID=\"27\" StartAddress=\"0\""),
    )
}

pub(in crate::commissioning) fn stamp_resource(id: &str, read: ReadAccess, optional: bool) -> String {
    format!(
        r#"<Resource Name="{id}" Access="remote" Optional="{optional}">
        <Location AddressSpace="StandardMemory" StartAddress="256" />
        <ResourceType Length="8" Flavour="Stamp_SystemB" />
        <AccessRights Read="{read:?}" Write="None" /></Resource>"#
    )
}

pub(in crate::commissioning) fn set_resources(profile: &mut ResolvedProfile, resources: Vec<String>) {
    replace_profile_element(profile, "Resources", &resources.join(""));
}

pub(in crate::commissioning) fn add_resources(
    profile: &mut ResolvedProfile,
    resources: impl IntoIterator<Item = String>,
) {
    let xml = profile.catalog.master_data.source_xml();
    let old = xml
        .split_once("<Resources>")
        .expect("fixture resources")
        .1
        .split_once("</Resources>")
        .expect("fixture resources close")
        .0;
    replace_profile_element(profile, "Resources", &format!("{old}{}", resources.into_iter().collect::<String>()));
}

pub(in crate::commissioning) fn set_feature(profile: &mut ResolvedProfile, name: &str, value: u32) {
    let xml = profile.catalog.master_data.source_xml();
    let old = xml
        .split_once("<Features>")
        .expect("fixture features")
        .1
        .split_once("</Features>")
        .expect("fixture features close")
        .0;
    replace_profile_element(profile, "Features", &format!(r#"{old}<Feature Name="{name}" Value="{value}" />"#));
}

fn replace_profile_element(profile: &mut ResolvedProfile, name: &str, content: &str) {
    let xml = profile.catalog.master_data.source_xml();
    let (before, tail) = xml.split_once(&format!("<{name}>")).expect("fixture element");
    let (_, after) = tail.split_once(&format!("</{name}>")).expect("fixture element closes");
    profile.catalog = ProgrammingCatalog::from_xml(&format!("{before}<{name}>{content}</{name}>{after}"))
        .expect("edited fixture parses");
    profile.refresh_test_catalog_fingerprint();
}

pub(in crate::commissioning) fn authorization_profile(
    management_model: &str,
    authorize_levels: Option<u8>,
) -> ResolvedProfile {
    let dd0 = match management_model {
        "Bcu1" | "BCU1" => 0x0012,
        "SystemB" => 0x07b0,
        "System7" => 0x0705,
        _ => 0x0020,
    };
    let model = match management_model {
        "BCU1" => "Bcu1",
        "System7" => "BimM112",
        "Coupler" => "None",
        value => value,
    };
    let features = authorize_levels
        .map_or(String::new(), |levels| format!(r#"<Feature Name="AuthorizeLevels" Value="{levels}" />"#));
    let first_object = if model == "SystemB" { r#"<Feature Name="FirstAppObjectIdx" Value="6" />"# } else { "" };
    let catalog = ProgrammingCatalog::from_xml(&format!(r#"
        <KNX xmlns="http://knx.org/xml/project/20"><MasterData Id="MD" Version="1"><MaskVersions>
          <MaskVersion Id="MV-{management_model}" MaskVersion="{dd0}" Name="fixture" ManagementModel="{model}" MediumTypeRefId="MT-0">
            <HawkConfigurationData><Features>{features}{first_object}</Features><Resources></Resources>
              <Procedures><Procedure ProcedureType="Load" ProcedureSubType="all" /></Procedures>
            </HawkConfigurationData>
          </MaskVersion>
        </MaskVersions></MasterData></KNX>"#)).expect("profile fixture parses");
    catalog
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery {
                dd0,
                management_descriptor_01: None,
                management_style: Some(ResourceManagementStyle::LoadStateMachine),
            },
            product: None,
            variant_hint: VariantHint::Automatic,
        })
        .expect("profile fixture resolves")
}
