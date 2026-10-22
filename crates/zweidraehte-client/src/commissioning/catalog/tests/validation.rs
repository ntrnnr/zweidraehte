use super::*;
use crate::commissioning::procedure::operands::StandardMemoryService;

#[test]
fn catalog_loading_does_not_interpret_unselected_controls() {
    let xml = AMBIGUOUS_0300.replace(
        "<Procedure ProcedureType=\"Unload\" ProcedureSubType=\"all\" />",
        r#"<Procedure ProcedureType="Unload" ProcedureSubType="all">
          <LdCtrlWriteMem AddressSpace="FutureSpace" Address="0" Size="1"
            Verify="false" InlineData="00" />
        </Procedure>"#,
    );
    let catalog = parse_master_data(&xml).expect("catalog preserves unknown source operands");
    let masks = &catalog.mask_versions().expect("fixture masks").versions;
    assert_eq!(masks.len(), 3);
    assert_eq!(masks[1].hawk_configs[0].procedures.as_ref().expect("fixture procedures").procedures.len(), 1);
}

#[test]
fn requested_resource_unknown_access_cannot_disappear_during_selection() {
    let xml = RESOURCE_SELECTION.replace("Access=\"remote\" Optional", "Access=\"future\" Optional");
    let error =
        resolve_catalog_profile(&parse_master_data(&xml).expect("syntax remains parseable"), None, &ProfileSelection {
            discovery: ProfileDiscovery { dd0: 0x0012, management_descriptor_01: None, management_style: None },
            variant_hint: VariantHint::Automatic,
        })
        .expect("profile selection preserves unused declarations")
        .resource("Chosen")
        .expect_err("unknown access cannot disappear during selection");

    assert_eq!(error.kind, CompileErrorKind::Unsupported);
    assert!(error.message.contains("unknown resource access token \"future\""));
}

#[test]
fn only_consumed_resource_flavours_and_locations_are_interpreted() {
    let unknown_flavour = RESOURCE_SELECTION
        .replace("<ResourceType Length=\"1\" />", "<ResourceType Length=\"1\" Flavour=\"FutureTable\" />");
    let profile = resolve_resource_selection(&unknown_flavour).expect("unselected codec is preserved");
    let error = profile
        .resource("Chosen")
        .expect("selection")
        .expect("chosen resource")
        .flavour()
        .expect_err("consumed unknown flavour must fail");

    assert_eq!(error.kind, CompileErrorKind::Unsupported);
    assert!(error.message.contains("Chosen") && error.message.contains("FutureTable"));

    let unknown_address_space = RESOURCE_SELECTION.replace("StandardMemory", "FutureMemory");
    let profile = resolve_resource_selection(&unknown_address_space).expect("unselected address space is preserved");
    let error = profile
        .resource("Chosen")
        .expect("selection")
        .expect("chosen resource")
        .read(StandardMemoryService::Classic)
        .expect_err("consumed unknown address space must fail");

    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert!(error.message.contains("FutureMemory"));

    let unknown_procedure = RESOURCE_SELECTION.replace("ProcedureType=\"Load\"", "ProcedureType=\"Future\"");
    let profile = resolve_resource_selection(&unknown_procedure).expect("unselected procedures stay unparsed");
    assert_eq!(
        profile.source().procedures.as_ref().expect("source procedures").procedures[0].procedure_type.as_str(),
        "Future"
    );
}
