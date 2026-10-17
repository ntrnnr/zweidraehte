use super::test_support::{minimal_profile, root_path};
use super::*;
use crate::commissioning::procedure::ProcedureSourceId;
use crate::commissioning::procedure::operands::StandardMemoryService;
use zweidraehte_ets_files::schema::{LdCtrlConnect, LdCtrlDeclarePropDesc, LdCtrlDelay, LdCtrlDisconnect, LdCtrlMerge};

#[test]
fn module_declarations_and_controls_follow_the_same_repeated_splices() {
    let profile = minimal_profile();
    let merge = |id| LoadControl::LdCtrlMerge(LdCtrlMerge { merge_id: id, ..Default::default() });
    let root = vec![
        LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
        merge(7),
        merge(7),
        LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
    ];
    let application = LoadProcedure { merge_id: Some(7), controls: vec![merge(4)] };
    let fragments = [("second", 6, "PDT_UNSIGNED_CHAR", 11), ("first", 7, "PDT_UNSIGNED_INT", 22)]
        .into_iter()
        .map(|(instance, index, pdt, delay)| InstantiatedModuleProcedure {
            source: ProcedureSourceId::Module {
                application_id: "app".into(),
                definition_id: "channel".into(),
                instance_id: instance.into(),
                source_index: 0,
                merge_id: 4,
            },
            procedure: LoadProcedure {
                merge_id: Some(4),
                controls: vec![
                    LoadControl::LdCtrlDeclarePropDesc(LdCtrlDeclarePropDesc {
                        obj_idx: Some(index),
                        prop_id: 208,
                        prop_type: pdt.into(),
                        max_elements: 1,
                        read_access: 3,
                        write_access: 3,
                        writable: true,
                        applies_to: Some("full,par".into()),
                        ..Default::default()
                    }),
                    LoadControl::LdCtrlDelay(LdCtrlDelay {
                        milli_seconds: delay,
                        applies_to: Some("full,par".into()),
                        ..Default::default()
                    }),
                ],
            },
        })
        .collect();
    let mut input = ProcedureInput {
        profile: &profile,
        procedure_id: root_path().procedure,
        composition: ProcedureComposition::Merged,
        controls: &root,
        product_merge_fragments: vec![&application],
        secondary_merge_fragments: Vec::new(),
        secondary_product_procedure: None,
        secondary_application_id: None,
        module_procedures: fragments,
        omitted_controls: Vec::new(),
        parameter_values: &BTreeMap::new(),
        applicability: ProcedureApplicability::full(),
        configuration_anchor: profile.configuration_anchor(),
        download_stamps: Vec::new(),
        property_parameters: &[],
        peiprog_identity_reference: false,
        application_program_2_present: false,
        progress_messages_by_reference: &BTreeMap::new(),
        progress_messages_by_id: &BTreeMap::new(),
        message_sources: Vec::new(),
        initial_tool_state: ToolState::default(),
        standard_memory_service: StandardMemoryService::Classic,
        restart_kind: RestartKind::Basic,
        application_identity: Default::default(),
        secondary_application_identity: None,
        extended_property_descriptions: false,
    };
    let declarations = property_declarations(&input).expect("module declarations resolve in execution order");
    assert_eq!(declarations.iter().map(|(_, pdt)| *pdt).collect::<Vec<_>>(), [
        "PDT_UNSIGNED_CHAR",
        "PDT_UNSIGNED_INT",
        "PDT_UNSIGNED_CHAR",
        "PDT_UNSIGNED_INT"
    ]);
    let parsed = parse(&input).expect("repeated module splices are executable");
    let delays: Vec<_> = parsed
        .program
        .steps
        .iter()
        .filter_map(|step| match &step.operation {
            ProcedureOperation::Delay { milliseconds } => Some((*milliseconds, &step.path.procedure)),
            _ => None,
        })
        .collect();
    assert_eq!(delays.iter().map(|(delay, _)| *delay).collect::<Vec<_>>(), [11, 22, 11, 22]);
    assert!(matches!(delays[0].1, ProcedureSourceId::Module { instance_id, .. } if instance_id == "second"));
    assert!(matches!(delays[1].1, ProcedureSourceId::Module { instance_id, .. } if instance_id == "first"));
    input.applicability = ProcedureApplicability::partial(ProgramSections::GROUP_COMMUNICATION);
    assert!(property_declarations(&input).expect("group-only module declarations").is_empty());
    assert!(
        !parse(&input)
            .expect("group-only module controls")
            .program
            .steps
            .iter()
            .any(|step| matches!(step.operation, ProcedureOperation::Delay { .. }))
    );
    input.applicability = ProcedureApplicability::partial(ProgramSections::PARAMETERS);
    assert_eq!(property_declarations(&input).expect("parameter module declarations").len(), 4);
    input.module_procedures[0].procedure.controls.push(merge(4));
    let Err(error) = parse(&input) else { panic!("cyclic module fragments must fail") };
    assert!(error.message.contains("recursive module procedure merge"));
}
