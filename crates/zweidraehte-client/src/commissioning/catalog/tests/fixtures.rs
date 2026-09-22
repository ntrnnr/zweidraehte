//! Shared synthetic catalog fixtures; no downloaded or vendor contents.

use super::super::{CompileError, ProgrammingCatalog};
use crate::commissioning::catalog::profile::{ProfileDiscovery, ProfileRequest, ResolvedProfile, VariantHint};
use std::path::PathBuf;
use zweidraehte_ets_files::product::ProductData;

pub(super) const AMBIGUOUS_0300: &str = r#"
  <KNX xmlns="http://knx.org/xml/project/20">
    <MasterData Id="MD" Version="1">
      <MaskVersions>
        <MaskVersion Id="MV-0300" MaskVersion="768" Name="selector" ManagementModel="PropertyBased" />
        <MaskVersion Id="MV-0300-01000000000000000000" MaskVersion="768"
          MgmtDescriptor01="01000000000000000000" Name="variant one" ManagementModel="PropertyBased">
          <HawkConfigurationData>
            <Resources>
              <Resource Name="ManagementStyle" Access="remote">
                <Location AddressSpace="Constant" StartAddress="2" />
                <ResourceType Length="1" />
                <AccessRights Read="Runtime" Write="None" />
              </Resource>
            </Resources>
            <Procedures><Procedure ProcedureType="Unload" ProcedureSubType="all" /></Procedures>
          </HawkConfigurationData>
        </MaskVersion>
        <MaskVersion Id="MV-0300-01000001000000000000" MaskVersion="768"
          MgmtDescriptor01="01000001000000000000" Name="variant two" ManagementModel="PropertyBased">
          <HawkConfigurationData>
            <Resources>
              <Resource Name="ManagementStyle" Access="remote">
                <Location AddressSpace="Constant" StartAddress="2" />
                <ResourceType Length="1" />
                <AccessRights Read="Runtime" Write="None" />
              </Resource>
            </Resources>
            <Procedures><Procedure ProcedureType="Unload" ProcedureSubType="all" /></Procedures>
          </HawkConfigurationData>
        </MaskVersion>
      </MaskVersions>
    </MasterData>
  </KNX>
"#;

pub(super) const RESOURCE_SELECTION: &str = r#"
  <KNX xmlns="http://knx.org/xml/project/23">
    <MasterData Id="MD" Version="1">
      <PropertyDataTypes>
        <PropertyDataType Name="PDT_FIXED" Size="2" />
        <PropertyDataType Name="PDT_VARIABLE" />
      </PropertyDataTypes>
      <MaskVersions>
        <MaskVersion Id="MV-0012" MaskVersion="18" Name="BCU1" ManagementModel="Bcu1" MediumTypeRefId="MT-0">
          <HawkConfigurationData>
            <Resources>
              <Resource Name="Chosen" Access="remote" Optional="true">
                <Location AddressSpace="StandardMemory" StartAddress="16" />
                <ResourceType Length="1" />
                <AccessRights Read="Runtime" Write="Configuration" />
              </Resource>
              <Resource Name="Chosen" Access="remote" MgmtStyle="simple" Optional="true">
                <Location AddressSpace="StandardMemory" StartAddress="32" />
                <ResourceType Length="1" />
                <AccessRights Read="Runtime" Write="Configuration" />
              </Resource>
            </Resources>
            <Procedures>
              <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote" />
            </Procedures>
            <InterfaceObjects>
              <InterfaceObject Index="3" ObjectType="3">
                <Property PropertyID="7" PropertyDataType="PDT_FIXED" />
                <Property PropertyID="8" PropertyDataType="PDT_FUTURE" />
              </InterfaceObject>
            </InterfaceObjects>
          </HawkConfigurationData>
        </MaskVersion>
      </MaskVersions>
    </MasterData>
  </KNX>
"#;

pub(super) const TOPOLOGY_DEPENDENT_PROFILE: &str = r#"
  <KNX xmlns="http://knx.org/xml/project/23">
    <MasterData Id="MD" Version="1">
      <MaskVersions>
        <MaskVersion Id="MV-0900" MaskVersion="2304" Name="Coupler" ManagementModel="Bcu1" MediumTypeRefId="MT-0">
          <HawkConfigurationData>
            <Resources>
              <Resource Name="GroupFilterTable" Access="remote">
                <Location AddressSpace="LcFilterMemory" StartAddress="0" />
                <ResourceType Length="8192" />
              </Resource>
            </Resources>
            <Procedures>
              <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote" />
            </Procedures>
          </HawkConfigurationData>
        </MaskVersion>
      </MaskVersions>
    </MasterData>
  </KNX>
"#;

pub(super) const GLOBAL_PROPERTY_METADATA: &str = r#"
  <KNX xmlns="http://knx.org/xml/project/23">
    <MasterData Id="MD" Version="1">
      <InterfaceObjectProperties>
        <InterfaceObjectProperty Id="PID-G-5" Number="5" Name="PID_LOAD_STATE_CONTROL" PDT="PDT-0" />
        <InterfaceObjectProperty Id="PID-G-8" Number="8" Name="PID_SERVICE_CONTROL" PDT="PDT-4" />
        <InterfaceObjectProperty Id="PID-G-78" Number="78" Name="GENERAL_PID_78" PDT="PDT-4" />
        <InterfaceObjectProperty Id="PID-0-78" Number="78" ObjectType="OT-0"
          Name="PID_HARDWARE_TYPE" PDT="PDT-22" />
        <InterfaceObjectProperty Id="PID-0-86" Number="86" ObjectType="OT-0"
          Name="PID_GROUP_TELEGR_RATE_LIMIT_NO_OF_TELEGR" PDT="PDT-4" />
        <InterfaceObjectProperty Id="PID-0-87" Number="87" ObjectType="OT-0"
          Name="PID_GROUP_TELEGR_RATE_LIMIT_TIME_BASE" PDT="PDT-4" />
      </InterfaceObjectProperties>
      <PropertyDataTypes>
        <PropertyDataType Id="PDT-0" Number="0" Name="PDT_CONTROL" Size="10" ReadSize="1" />
        <PropertyDataType Id="PDT-4" Number="4" Name="PDT_UNSIGNED_INT" Size="2" />
        <PropertyDataType Id="PDT-22" Number="22" Name="PDT_GENERIC_06" Size="6" />
        <PropertyDataType Id="PDT-35" Number="35" Name="PDT_VERSION" Size="2" />
      </PropertyDataTypes>
      <MaskVersions>
        <MaskVersion Id="MV-0705" MaskVersion="1797" Name="System 7" ManagementModel="BimM112"
          MediumTypeRefId="MT-0">
          <HawkConfigurationData>
            <Resources>
              <Resource Name="ManagementStyle" Access="remote">
                <Location AddressSpace="Constant" StartAddress="2" />
                <ResourceType Length="1" />
              </Resource>
              <Resource Name="HardwareType" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="0" PropertyID="78"
                  StartAddress="0" />
                <ResourceType Length="6" />
              </Resource>
              <Resource Name="LoadControl" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="0" PropertyID="5"
                  StartAddress="0" />
                <ResourceType Length="10" />
              </Resource>
              <Resource Name="LoadStatus" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="0" PropertyID="5"
                  StartAddress="0" />
                <ResourceType Length="1" />
              </Resource>
            </Resources>
            <Procedures>
              <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote" />
            </Procedures>
            <InterfaceObjects>
              <InterfaceObject Index="0" ObjectType="0">
                <Property PropertyID="25" PropertyDataType="PDT_VERSION" />
              </InterfaceObject>
            </InterfaceObjects>
          </HawkConfigurationData>
        </MaskVersion>
      </MaskVersions>
    </MasterData>
  </KNX>
"#;

pub(super) const RESOURCE_LOCATION_CASES: &str = r#"
  <KNX xmlns="http://knx.org/xml/project/23">
    <MasterData Id="MD" Version="1">
      <MaskVersions>
        <MaskVersion Id="MV-0013" MaskVersion="19" Name="BCU1 PL" ManagementModel="Bcu1" MediumTypeRefId="MT-1">
          <HawkConfigurationData>
            <Resources>
              <Resource Name="AddressTable" Access="remote">
                <Location AddressSpace="StandardMemory" StartAddress="256" />
                <ImgLocation AddressSpace="StandardMemory" StartAddress="259" />
                <ResourceType Length="1" Flavour="AddressTable_Bcu1PL" />
                <AccessRights Read="Runtime" Write="Configuration" />
              </Resource>
              <Resource Name="PropertyAbsent" Access="remote">
                <Location AddressSpace="Property" InterfaceObjectRef="6" PropertyID="5" StartAddress="0" />
                <ResourceType Length="1" />
              </Resource>
              <Resource Name="PropertyZero" Access="remote">
                <Location AddressSpace="Property" InterfaceObjectRef="6" Occurrence="0" PropertyID="5" StartAddress="0" />
                <ResourceType Length="1" />
              </Resource>
              <Resource Name="PropertyOne" Access="remote">
                <Location AddressSpace="Property" InterfaceObjectRef="6" Occurrence="1" PropertyID="5" StartAddress="0" />
                <ResourceType Length="1" />
              </Resource>
            </Resources>
            <Procedures>
              <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote" />
            </Procedures>
          </HawkConfigurationData>
        </MaskVersion>
      </MaskVersions>
    </MasterData>
  </KNX>
"#;

pub(super) fn coupler_catalog(mask: &str, variants: &str) -> String {
    let dd0 = u16::from_str_radix(mask, 16).expect("hex mask");

    format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23"><MasterData Id="MD" Version="1"><MaskVersions>
          <MaskVersion Id="MV-{mask}" MaskVersion="{dd0}" Name="coupler" ManagementModel="Bcu1" MediumTypeRefId="MT-0">
            {variants}
          </MaskVersion>
        </MaskVersions></MasterData></KNX>"#
    )
}

pub(super) fn product(mask: &str, load_style: &str, modern_coupler: bool) -> ProductData {
    product_with_schema(23, mask, load_style, modern_coupler)
}

pub(super) fn product_with_schema(version: u16, mask: &str, load_style: &str, modern_coupler: bool) -> ProductData {
    product_with_namespace(&format!("http://knx.org/xml/project/{version}"), mask, load_style, modern_coupler)
}

pub(super) fn product_with_namespace(
    namespace: &str,
    mask: &str,
    load_style: &str,
    modern_coupler: bool,
) -> ProductData {
    let xml = format!(
        r#"<KNX xmlns="{namespace}" CreatedBy="catalog-test" ToolVersion="1"><ManufacturerData><Manufacturer RefId="M-00FA">
          <ApplicationPrograms><ApplicationProgram Id="M-00FA_A-1-1-0000" ApplicationNumber="1"
            ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="{mask}" Name="fixture"
            LoadProcedureStyle="{load_style}" PeiType="0" DefaultLanguage="en-US"
            DynamicTableManagement="false" Linkable="false"><Static><Code />
              <Options LineCoupler0912NewProgrammingStyle="{modern_coupler}" />
            </Static></ApplicationProgram></ApplicationPrograms>
          </Manufacturer></ManufacturerData></KNX>"#
    );

    ProductData::from_mtxml_str(&xml).expect("product parses")
}

pub(super) fn unauditable_catalog() -> String {
    AMBIGUOUS_0300.replace(
        "<Procedure ProcedureType=\"Unload\" ProcedureSubType=\"all\" />",
        r#"<Procedure ProcedureType="Unload" ProcedureSubType="all">
          <LdCtrlWriteMem AddressSpace="FutureSpace" Address="0" Size="1"
            Verify="false" InlineData="00" />
        </Procedure>"#,
    )
}

pub(super) fn resolve_location_cases() -> ResolvedProfile {
    ProgrammingCatalog::from_xml(RESOURCE_LOCATION_CASES)
        .expect("catalog parses")
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery { dd0: 0x0013, management_descriptor_01: None, management_style: None },
            product: None,
            variant_hint: VariantHint::Automatic,
        })
        .expect("location profile resolves")
}

pub(super) fn resolve_resource_selection(xml: &str) -> Result<ResolvedProfile, CompileError> {
    ProgrammingCatalog::from_xml(xml).expect("syntax remains parseable").resolve(ProfileRequest {
        discovery: ProfileDiscovery { dd0: 0x0012, management_descriptor_01: None, management_style: None },
        product: None,
        variant_hint: VariantHint::Automatic,
    })
}

pub(super) fn cached_master_data(version: u8) -> PathBuf {
    let cache = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from).unwrap_or_else(|| {
        let mut home = PathBuf::from(std::env::var_os("HOME").expect("HOME identifies the cache root"));
        home.push(".cache");
        home
    });

    cache.join("knxprod").join(format!("knx_master_v{version}.xml"))
}
