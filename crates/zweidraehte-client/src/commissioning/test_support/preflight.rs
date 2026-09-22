use crate::commissioning::catalog::ProgrammingCatalog;
use crate::commissioning::catalog::profile::{
    ProcedureId, ProfileDiscovery, ProfileRequest, ResolvedProfile, ResourceManagementStyle, VariantHint,
};
use crate::commissioning::procedure::{
    ControlPath, NormalizedProcedure, ProcedureOperation, ProcedureSourceId, ProcedureStep, ToolState,
};

pub(in crate::commissioning) fn procedure(operations: Vec<ProcedureOperation>) -> NormalizedProcedure {
    let id = ProcedureSourceId::MasterData(ProcedureId {
        procedure_type: "Load".to_owned(),
        subtype: Some("all".to_owned()),
        management_style: None,
        source_index: 0,
    });
    let steps = operations
        .into_iter()
        .enumerate()
        .map(|(index, operation)| ProcedureStep {
            path: ControlPath {
                mask_id: "MV-TEST".to_owned(),
                variant_index: 0,
                procedure: id.clone(),
                contribution: None,
                control_indices: vec![index],
            },
            source_control_code: Some(0xf0),
            sections: Default::default(),
            operation,
            on_error: Vec::new(),
            secure_only: false,
        })
        .collect();

    NormalizedProcedure { id, initial_state: ToolState::default(), steps, stamp_output: Default::default() }
}

pub(in crate::commissioning) fn profile(resources: &str) -> ResolvedProfile {
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23"><MasterData Id="MD" Version="1">
      <PropertyDataTypes>
        <PropertyDataType Name="PDT_CHAR" Size="1"/>
        <PropertyDataType Name="PDT_INT" Size="2"/>
      </PropertyDataTypes>
      <MaskVersions><MaskVersion Id="MV-07B0" MaskVersion="1968" Name="System B" ManagementModel="SystemB">
        <HawkConfigurationData><Resources>{resources}</Resources><InterfaceObjects>
          <InterfaceObject Index="2" ObjectType="2"><Property PropertyID="20" PropertyDataType="PDT_INT"/></InterfaceObject>
          <InterfaceObject Index="3" ObjectType="4"><Property PropertyID="21" PropertyDataType="PDT_CHAR"/></InterfaceObject>
          <InterfaceObject Index="4" ObjectType="4"><Property PropertyID="21" PropertyDataType="PDT_INT"/></InterfaceObject>
        </InterfaceObjects></HawkConfigurationData>
      </MaskVersion></MaskVersions>
    </MasterData></KNX>"#
    );
    ProgrammingCatalog::from_xml(&xml)
        .expect("synthetic catalog")
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery {
                dd0: 0x07b0,
                management_descriptor_01: None,
                management_style: Some(ResourceManagementStyle::LoadStateMachine),
            },
            product: None,
            variant_hint: VariantHint::Automatic,
        })
        .expect("exact System B profile")
}
