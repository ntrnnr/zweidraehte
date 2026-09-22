//! Synthetic exact masks and resource/procedure declarations.

pub(super) fn architecture_master_data(version: u16) -> String {
    format!(
        r#"<KNX xmlns="http://knx.org/xml/project/{version}">
          <MasterData Id="MD-ARCHITECTURES-{version}" Version="1">
            <PropertyDataTypes>
              <PropertyDataType Id="PDT-4" Number="4" Name="PDT_UNSIGNED_LONG" Size="4" />
              <PropertyDataType Id="PDT-50" Number="50" Name="PDT_BINARY_INFORMATION" Size="1" />
            </PropertyDataTypes>
            <MaskVersions>
              <MaskVersion Id="MV-0012" MaskVersion="18" Name="BCU1" ManagementModel="Bcu1" MediumTypeRefId="MT-0">
                {bcu1}
              </MaskVersion>
              <MaskVersion Id="MV-0020" MaskVersion="32" Name="BCU2" ManagementModel="Bcu2" MediumTypeRefId="MT-0">
                {bcu2}
              </MaskVersion>
              <MaskVersion Id="MV-0300" MaskVersion="768" Name="System 300 selector" ManagementModel="PropertyBased" />
              <MaskVersion Id="MV-0300-01000000000000000000" MaskVersion="768"
                MgmtDescriptor01="01000000000000000000" Name="System 300 plug-in" ManagementModel="PropertyBased"
                MediumTypeRefId="MT-0">
                <HawkConfigurationData Ets3SystemPlugin="vendor.system300">{system_300_plugin}</HawkConfigurationData>
              </MaskVersion>
              <MaskVersion Id="MV-0300-01000001000000000000" MaskVersion="768"
                MgmtDescriptor01="01000001000000000000" Name="System 300" ManagementModel="PropertyBased"
                MediumTypeRefId="MT-0">
                {system_300}
              </MaskVersion>
              <MaskVersion Id="MV-0705" MaskVersion="1797" Name="System 7 TP" ManagementModel="BimM112" MediumTypeRefId="MT-0">
                {system_7_tp}
              </MaskVersion>
              <MaskVersion Id="MV-07B0" MaskVersion="1968" Name="System B TP" ManagementModel="SystemB" MediumTypeRefId="MT-0">
                {system_b_tp}
              </MaskVersion>
              <MaskVersion Id="MV-0912" MaskVersion="2322" Name="coupler" ManagementModel="Bcu1" MediumTypeRefId="MT-0">
                {coupler_modern}
                {coupler_legacy}
              </MaskVersion>
              <MaskVersion Id="MV-091A" MaskVersion="2330" Name="coupler reversed" ManagementModel="Bcu1" MediumTypeRefId="MT-0">
                {coupler_reversed_legacy}
                {coupler_reversed_modern}
              </MaskVersion>
              <MaskVersion Id="MV-1900" MaskVersion="6400" Name="PL fixture" ManagementModel="BimM112"
                MediumTypeRefId="MT-0" OtherMediumTypeRefId="MT-1">
                {power_line}
              </MaskVersion>
              <MaskVersion Id="MV-2705" MaskVersion="9989" Name="System 7 RF" ManagementModel="BimM112" MediumTypeRefId="MT-2">
                {system_7_rf}
              </MaskVersion>
              <MaskVersion Id="MV-27B0" MaskVersion="10160" Name="System B RF" ManagementModel="SystemB" MediumTypeRefId="MT-2">
                {system_b_rf}
              </MaskVersion>
              <MaskVersion Id="MV-2920" MaskVersion="10528" Name="Coupler Model 2.0" ManagementModel="SystemB"
                MediumTypeRefId="MT-0" OtherMediumTypeRefId="MT-2">
                {coupler_model_20}
              </MaskVersion>
              <MaskVersion Id="MV-5705" MaskVersion="22277" Name="System 7 IP" ManagementModel="BimM112" MediumTypeRefId="MT-5">
                {system_7_ip}
              </MaskVersion>
              <MaskVersion Id="MV-57B0" MaskVersion="22448" Name="System B IP" ManagementModel="SystemB" MediumTypeRefId="MT-5">
                {system_b_ip}
              </MaskVersion>
              <MaskVersion Id="MV-6800" MaskVersion="26624" Name="KNX IoT" ManagementModel="None" MediumTypeRefId="MT-6" />
            </MaskVersions>
          </MasterData>
        </KNX>"#,
        bcu1 = absolute_variant(),
        bcu2 = absolute_variant(),
        system_300_plugin = management_style(1),
        system_300 = styled_absolute_variant(1),
        system_7_tp = product_procedure_variant(),
        system_b_tp = system_b_variant(),
        coupler_modern = coupler_variant(true, true),
        coupler_legacy = coupler_variant(false, false),
        coupler_reversed_legacy = absolute_variant_with_legacy(Some(1)),
        coupler_reversed_modern = absolute_variant_with_legacy(None),
        power_line = styled_absolute_variant(2),
        system_7_rf = product_procedure_variant(),
        system_b_rf = system_b_variant(),
        coupler_model_20 = coupler_model_20_variant(),
        system_7_ip = product_procedure_variant(),
        system_b_ip = system_b_variant(),
    )
}

fn absolute_variant() -> String {
    absolute_variant_with_legacy(None)
}

fn absolute_variant_with_legacy(legacy: Option<i32>) -> String {
    let legacy = legacy.map(|value| format!(" LegacyVersion=\"{value}\"")).unwrap_or_default();
    let procedure = absolute_load_procedure();
    format!(
        r#"<HawkConfigurationData{legacy}>
          <Procedures>{procedure}</Procedures>
        </HawkConfigurationData>"#
    )
}

fn styled_absolute_variant(style: u8) -> String {
    let resources = management_style(style);
    let procedure = absolute_load_procedure();
    format!(
        r#"<HawkConfigurationData>
          {resources}
          <Procedures>{procedure}</Procedures>
        </HawkConfigurationData>"#
    )
}

fn product_procedure_variant() -> String {
    format!(r#"<HawkConfigurationData>{}</HawkConfigurationData>"#, management_style(2))
}

fn system_b_variant() -> String {
    let management_style = management_style_resource(2);
    format!(
        r#"<HawkConfigurationData>
          <Resources>
            {management_style}
            <Resource Name="ApplicationDataPtr" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="7" StartAddress="0" />
              <ResourceType Length="4" Flavour="Ptr_StandardMemory" />
              <AccessRights Read="Runtime" Write="Configuration" />
            </Resource>
          </Resources>
          <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
              <LdCtrlConnect />
              <LdCtrlWriteRelMem ObjIdx="3" Offset="0" Size="4" Verify="false" />
              <LdCtrlDisconnect />
            </Procedure>
          </Procedures>
          <InterfaceObjects>
            <InterfaceObject Index="3" ObjectType="3">
              <Property PropertyID="7" PropertyDataType="PDT_UNSIGNED_LONG" />
            </InterfaceObject>
          </InterfaceObjects>
        </HawkConfigurationData>"#
    )
}

fn coupler_model_20_variant() -> String {
    let management_style = management_style_resource(2);
    format!(
        r#"<HawkConfigurationData>
          <Resources>
            {management_style}
            <Resource Name="ApplicationDataPtr" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="7" StartAddress="0" />
              <ResourceType Length="4" Flavour="Ptr_StandardMemory" />
              <AccessRights Read="Runtime" Write="Configuration" />
            </Resource>
            <Resource Name="GroupFilterTable" Access="remote">
              <Location AddressSpace="RelativeMemoryByObjectType" InterfaceObjectRef="6" Occurrence="1"
                PropertyID="7" StartAddress="0" />
              <ResourceType Length="8192" />
              <AccessRights Read="Runtime" Write="Configuration" />
            </Resource>
            <Resource Name="GroupFilterTableUse" Access="remote">
              <Location AddressSpace="Property" InterfaceObjectRef="6" Occurrence="1" PropertyID="67"
                StartAddress="0" />
              <ResourceType Length="1" />
              <AccessRights Read="Runtime" Write="Configuration" />
            </Resource>
          </Resources>
          <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
              <LdCtrlConnect />
              <LdCtrlWriteRelMem ObjIdx="3" Offset="0" Size="4" Verify="false" />
              <LdCtrlClearLCFilterTable UseFunctionProp="true" />
              <LdCtrlWriteRelMem ObjType="6" Occurrence="1" Offset="0" Size="8192" Verify="true" />
              <LdCtrlWriteProp ObjType="6" Occurrence="1" PropId="67" InlineData="01" Verify="true" />
              <LdCtrlDisconnect />
            </Procedure>
          </Procedures>
          <InterfaceObjects>
            <InterfaceObject Index="3" ObjectType="3">
              <Property PropertyID="7" PropertyDataType="PDT_UNSIGNED_LONG" />
            </InterfaceObject>
            <InterfaceObject ObjectType="6">
              <Property PropertyID="7" PropertyDataType="PDT_UNSIGNED_LONG" />
              <Property PropertyID="67" PropertyDataType="PDT_BINARY_INFORMATION" />
            </InterfaceObject>
          </InterfaceObjects>
        </HawkConfigurationData>"#
    )
}

fn management_style(value: u8) -> String {
    format!("<Resources>{}</Resources>", management_style_resource(value))
}

fn management_style_resource(value: u8) -> String {
    format!(
        r#"<Resource Name="ManagementStyle" Access="remote">
          <Location AddressSpace="Constant" StartAddress="{value}" />
          <ResourceType Length="1" />
          <AccessRights Read="Runtime" Write="None" />
        </Resource>"#
    )
}

fn absolute_load_procedure() -> &'static str {
    r#"<Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
      <LdCtrlConnect />
      <LdCtrlWriteMem Address="256" Size="4" Verify="false" />
      <LdCtrlDisconnect />
    </Procedure>"#
}

fn coupler_variant(modern: bool, use_function_property: bool) -> String {
    let (legacy, length, first, second, flavour) = if modern {
        ("", 8192, "MainLcGrpConfig", "SubLcGrpConfig", "Lc_12")
    } else {
        (" LegacyVersion=\"1\"", 3584, "LcConfig", "LcGrpConfig", "Lc_11")
    };
    let interface_objects = use_function_property
        .then_some(
            r#"<InterfaceObjects>
            <InterfaceObject ObjectType="6" />
          </InterfaceObjects>"#,
        )
        .unwrap_or_default();
    let filter_table_open =
        use_function_property.then_some(r#"<LdCtrlClearLCFilterTable UseFunctionProp="false" />"#).unwrap_or_default();

    format!(
        r#"<HawkConfigurationData{legacy}>
          <Resources>
            <Resource Name="GroupFilterTable" Access="remote">
              <Location AddressSpace="LcFilterMemory" StartAddress="0" />
              <ResourceType Length="{length}" />
              <AccessRights Read="Runtime" Write="Configuration" />
            </Resource>
            <Resource Name="{first}" Access="remote">
              <Location AddressSpace="StandardMemory" StartAddress="264" />
              <ResourceType Length="1" Flavour="{flavour}" />
              <AccessRights Read="Runtime" Write="Configuration" />
            </Resource>
            <Resource Name="{second}" Access="remote">
              <Location AddressSpace="StandardMemory" StartAddress="265" />
              <ResourceType Length="1" Flavour="{flavour}" />
              <AccessRights Read="Runtime" Write="Configuration" />
            </Resource>
          </Resources>
          <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
              <LdCtrlConnect />
              <LdCtrlWriteMem Address="256" Size="4" Verify="false" />
              <LdCtrlWriteMem Address="264" Size="2" Verify="false" />
              <LdCtrlClearLCFilterTable UseFunctionProp="{use_function_property}" />
              {filter_table_open}
              <LdCtrlWriteMem AddressSpace="LcFilter" Address="0" Size="{length}" Verify="false" />
              <LdCtrlDisconnect />
            </Procedure>
          </Procedures>
          {interface_objects}
        </HawkConfigurationData>"#
    )
}
