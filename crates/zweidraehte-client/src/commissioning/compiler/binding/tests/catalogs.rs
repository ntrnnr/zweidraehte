use crate::commissioning::catalog::profile::ProfileDisposition;
use crate::commissioning::catalog_testing::*;
use crate::commissioning::error::CompileErrorKind;
use crate::commissioning::test_support::architecture::resolve_profile;
use crate::commissioning::test_support::architecture::{SYSTEM_300_PLUGIN_DESCRIPTOR, catalog, compile, product};
use crate::configuration::TopologyConfiguration;
pub(super) const CATALOG_XML: &str = r#"
  <KNX xmlns="http://knx.org/xml/project/23">
    <MasterData Id="MD" Version="1">
      <MaskVersions>
        <MaskVersion Id="MV-0012" MaskVersion="18" Name="BCU1" ManagementModel="Bcu1">
          <HawkConfigurationData>
            <Procedures>
              <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
                <LdCtrlConnect />
                <LdCtrlWriteMem Address="256" Size="1" Verify="false" InlineData="00" />
                <LdCtrlDisconnect />
              </Procedure>
              <Procedure ProcedureType="Load" ProcedureSubType="par,grp" Access="remote">
                <LdCtrlConnect />
                <LdCtrlWriteMem Address="256" Size="1" Verify="false" InlineData="00" />
                <LdCtrlDisconnect />
              </Procedure>
              <Procedure ProcedureType="Unload" ProcedureSubType="all" Access="remote">
                <LdCtrlConnect />
                <LdCtrlWriteMem Address="256" Size="1" Verify="false" InlineData="00" />
                <LdCtrlDisconnect />
              </Procedure>
            </Procedures>
          </HawkConfigurationData>
        </MaskVersion>
      </MaskVersions>
    </MasterData>
  </KNX>
"#;

#[test]
fn unavailable_architectures_fail_closed() {
    let catalog = catalog(23);
    let plugin_product = product("MV-0300-01000000000000000000", "ProductProcedure", false, false);
    let plugin_profile = resolve_profile(&catalog, 0x0300, Some(SYSTEM_300_PLUGIN_DESCRIPTOR), &plugin_product);
    let plugin_error = compile(&catalog, plugin_profile, &plugin_product, TopologyConfiguration::default())
        .expect_err("proprietary System 300 programming is unsupported");
    assert_eq!(plugin_error.kind, CompileErrorKind::Unprogrammable(crate::commissioning::Unprogrammable::SystemPlugin));

    let pl_product = product("MV-1900", "DefaultProcedure", false, false);
    let pl_profile = resolve_profile(&catalog, 0x1900, None, &pl_product);
    assert_eq!(pl_profile.disposition(), &ProfileDisposition::ExcludedPowerLine);
    assert!(compile(&catalog, pl_profile, &pl_product, TopologyConfiguration::default()).is_err());
    assert!(matches!(
        resolve_catalog_profile(&catalog, None, &ProfileSelection { discovery: ProfileDiscovery { dd0: 0x6800, management_descriptor_01: None, management_style: None }, variant_hint: VariantHint::Automatic }),
        Err(error) if error.kind == CompileErrorKind::Unsupported && error.message.contains("no programming configuration")
    ));
}

pub(super) const SYSTEM7_PROPERTY_CATALOG_XML: &str = r#"
  <KNX xmlns="http://knx.org/xml/project/20">
    <MasterData Id="MD" Version="1">
      <InterfaceObjectProperties>
        <InterfaceObjectProperty Id="PID-0-78" Number="78" ObjectType="OT-0"
          Name="PID_HARDWARE_TYPE" PDT="PDT-22" />
      </InterfaceObjectProperties>
      <PropertyDataTypes>
        <PropertyDataType Id="PDT-22" Number="22" Name="PDT_GENERIC_06" Size="6" />
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
                <ResourceType Length="6" Flavour="HardwareConfig_Identical" />
              </Resource>
            </Resources>
            <InterfaceObjects>
              <InterfaceObject Index="0" ObjectType="0" />
            </InterfaceObjects>
          </HawkConfigurationData>
        </MaskVersion>
      </MaskVersions>
    </MasterData>
  </KNX>
"#;

pub(super) const SYSTEM_B_APPLICATION_CATALOG_XML: &str = r#"
  <KNX xmlns="http://knx.org/xml/project/23">
    <MasterData Id="MD" Version="1">
      <PropertyDataTypes>
        <PropertyDataType Name="PDT_UNSIGNED_LONG" Size="4" />
      </PropertyDataTypes>
      <MaskVersions>
        <MaskVersion Id="MV-07B0" MaskVersion="1968" Name="System B" ManagementModel="SystemB">
          <HawkConfigurationData>
            <Resources>
              <Resource Name="ApplicationLoadControl" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="5" StartAddress="0" />
                <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
                <AccessRights Read="None" Write="Configuration" />
              </Resource>
              <Resource Name="ApplicationLoadStatus" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="5" StartAddress="0" />
                <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
                <AccessRights Read="Runtime" Write="None" />
              </Resource>
              <Resource Name="ApplicationId" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="13" StartAddress="0" />
                <ResourceType Length="5" />
                <AccessRights Read="Runtime" Write="Configuration" />
              </Resource>
              <Resource Name="ApplicationDataPtr" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="7" StartAddress="0" />
                <ResourceType Length="4" Flavour="Ptr_StandardMemory" />
                <AccessRights Read="Runtime" Write="Configuration" />
              </Resource>
              <Resource Name="PeiprogId" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="5" PropertyID="13" StartAddress="0" />
                <ResourceType Length="5" />
                <AccessRights Read="Runtime" Write="Configuration" />
              </Resource>
              <Resource Name="PeiprogLoadControl" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="5" PropertyID="5" StartAddress="0" />
                <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
                <AccessRights Read="None" Write="Configuration" />
              </Resource>
              <Resource Name="PeiprogLoadStatus" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="5" PropertyID="5" StartAddress="0" />
                <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
                <AccessRights Read="Runtime" Write="None" />
              </Resource>
              <Resource Name="PeiprogDataPtr" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="5" PropertyID="7" StartAddress="0" />
                <ResourceType Length="4" Flavour="Ptr_StandardMemory" />
                <AccessRights Read="Runtime" Write="Configuration" />
              </Resource>
            </Resources>
            <Procedures>
              <Procedure ProcedureType="Load" ProcedureSubType="ap1" Access="remote">
                <LdCtrlConnect />
                <LdCtrlUnload LsmIdx="5" />
                <LdCtrlLoad LsmIdx="4" />
                <LdCtrlMerge MergeId="2" />
                <LdCtrlMerge MergeId="4" />
                <LdCtrlWriteProp ObjIdx="4" PropId="13" Verify="true" InlineData="0000000000" />
                <LdCtrlLoadCompleted LsmIdx="4" />
                <LdCtrlMerge MergeId="7" />
                <LdCtrlDisconnect />
              </Procedure>
              <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
                <LdCtrlConnect />
                <LdCtrlLoad LsmIdx="5" />
                <LdCtrlMerge MergeId="3" />
                <LdCtrlLoad LsmIdx="4" />
                <LdCtrlMerge MergeId="2" />
                <LdCtrlMerge MergeId="5" />
                <LdCtrlMerge MergeId="4" />
                <LdCtrlWriteProp ObjIdx="5" PropId="13" Verify="true" InlineData="0000000000" />
                <LdCtrlWriteProp ObjIdx="4" PropId="13" Verify="true" InlineData="0000000000" />
                <LdCtrlLoadCompleted LsmIdx="5" />
                <LdCtrlLoadCompleted LsmIdx="4" />
                <LdCtrlMerge MergeId="7" />
                <LdCtrlDisconnect />
              </Procedure>
              <Procedure ProcedureType="Load" ProcedureSubType="par" Access="remote">
                <LdCtrlConnect />
                <LdCtrlLoadImageProp ObjIdx="4" PropId="7" />
                <LdCtrlLoadImageProp ObjIdx="5" PropId="7" />
                <LdCtrlUnload LsmIdx="5" />
                <LdCtrlUnload LsmIdx="4" />
                <LdCtrlLoad LsmIdx="5" />
                <LdCtrlMerge MergeId="3" />
                <LdCtrlCompareProp ObjIdx="5" PropId="7" InlineData="00000000" />
                <LdCtrlLoad LsmIdx="4" />
                <LdCtrlMerge MergeId="2" />
                <LdCtrlCompareProp ObjIdx="4" PropId="7" InlineData="00000000" />
                <LdCtrlMerge MergeId="5" />
                <LdCtrlMerge MergeId="4" />
                <LdCtrlWriteProp ObjIdx="5" PropId="13" Verify="true" InlineData="0000000000" />
                <LdCtrlWriteProp ObjIdx="4" PropId="13" Verify="true" InlineData="0000000000" />
                <LdCtrlLoadCompleted LsmIdx="5" />
                <LdCtrlLoadCompleted LsmIdx="4" />
                <LdCtrlMerge MergeId="7" />
                <LdCtrlDisconnect />
              </Procedure>
              <Procedure ProcedureType="Load" ProcedureSubType="par,grp" Access="remote">
                <LdCtrlConnect />
                <LdCtrlLoadImageProp ObjIdx="4" PropId="7" />
                <LdCtrlLoadImageProp ObjIdx="5" PropId="7" />
                <LdCtrlUnload LsmIdx="5" />
                <LdCtrlUnload LsmIdx="4" />
                <LdCtrlLoad LsmIdx="5" />
                <LdCtrlMerge MergeId="3" />
                <LdCtrlCompareProp ObjIdx="5" PropId="7" InlineData="00000000" />
                <LdCtrlLoad LsmIdx="4" />
                <LdCtrlMerge MergeId="2" />
                <LdCtrlCompareProp ObjIdx="4" PropId="7" InlineData="00000000" />
                <LdCtrlMerge MergeId="5" />
                <LdCtrlMerge MergeId="4" />
                <LdCtrlWriteProp ObjIdx="5" PropId="13" Verify="true" InlineData="0000000000" />
                <LdCtrlWriteProp ObjIdx="4" PropId="13" Verify="true" InlineData="0000000000" />
                <LdCtrlLoadCompleted LsmIdx="5" />
                <LdCtrlLoadCompleted LsmIdx="4" />
                <LdCtrlMerge MergeId="7" />
                <LdCtrlDisconnect />
              </Procedure>
              <Procedure ProcedureType="Load" ProcedureSubType="grp" Access="remote">
                <LdCtrlConnect />
                <LdCtrlMerge MergeId="7" />
                <LdCtrlDisconnect />
              </Procedure>
              <Procedure ProcedureType="Load" ProcedureSubType="cfg" Access="remote">
                <LdCtrlConnect />
                <LdCtrlDelay MilliSeconds="23" />
                <LdCtrlWriteMem Address="257" Size="1" Verify="false" InlineData="00" />
                <LdCtrlDisconnect />
              </Procedure>
              <Procedure ProcedureType="Unload" ProcedureSubType="all" Access="remote">
                <LdCtrlConnect />
                <LdCtrlDisconnect />
              </Procedure>
            </Procedures>
            <InterfaceObjects>
              <InterfaceObject Index="4" ObjectType="3">
                <Property PropertyID="7" PropertyDataType="PDT_UNSIGNED_LONG" />
              </InterfaceObject>
              <InterfaceObject Index="5" ObjectType="4">
                <Property PropertyID="7" PropertyDataType="PDT_UNSIGNED_LONG" />
              </InterfaceObject>
            </InterfaceObjects>
          </HawkConfigurationData>
        </MaskVersion>
      </MaskVersions>
    </MasterData>
  </KNX>
"#;
