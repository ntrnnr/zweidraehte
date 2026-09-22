use crate::commissioning::catalog::profile::testing::fixture_profile;
use crate::commissioning::compiler::binding::procedure::test_support::{
    ProcedureCompileContext, compile_fixture, compile_fixture_with_parameters,
    compile_fixture_with_profile_and_composition, compile_procedure, minimal_profile, root_path,
};
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
use crate::commissioning::image::SparseDeviceImage;
use crate::commissioning::input::ProgramSections;
use crate::commissioning::procedure::{ProcedureOperation, RestartKind, ToolState};
use crate::configuration::{ProcedureParameter, ProcedureParameterValue};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ApplicationIdentity;
use zweidraehte_ets_files::schema::{
    LdCtrlChoose, LdCtrlConnect, LdCtrlDelay, LdCtrlDisconnect, LdCtrlLoad, LdCtrlMerge, LdCtrlTaskSegment, LdCtrlWhen,
    LdCtrlWriteMem, LoadControl, LoadProcedure,
};

#[test]
fn bcu2_omits_the_legacy_machine_five_task_announcement() {
    let profile = fixture_profile(
        "MV-0021",
        "Bcu2",
        "MT-0",
        r#"<Features><Feature Name="PropertyMappedLsms" Value="1"/></Features><Resources></Resources><InterfaceObjects></InterfaceObjects>"#,
    );
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment {
                lsm_idx: Some(3),
                address: 0x046f,
                ..Default::default()
            }),
            LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment {
                lsm_idx: Some(5),
                address: 0x0274,
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };

    let normalized = compile_fixture_with_profile_and_composition(
        profile,
        ProcedureComposition::ProductOwned,
        procedure,
        Vec::new(),
        SparseDeviceImage::new(),
    )
    .expect("BCU2 legacy object-table announcement is not executable");

    assert_eq!(normalized.steps.len(), 3);
    let ProcedureOperation::LoadRecord(record) = &normalized.steps[1].operation else { panic!("task record") };
    assert_eq!(
        record.bytes,
        zweidraehte_proto::messages::apdu::load_control::LoadControlRecord::task_segment(0x046f, 0, [0; 5])
    );
    assert!(record.poll.is_none());
    assert_eq!(normalized.steps[1].path.control_indices, [1]);
    assert!(matches!(normalized.steps[2].operation, ProcedureOperation::Disconnect));
    assert_eq!(normalized.steps[2].path.control_indices, [3]);
}

#[test]
fn inactive_choose_selector_suppresses_even_the_default_branch() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![LoadControl::Choose(LdCtrlChoose {
            param_ref_id: "P-1".to_owned(),
            internal_description: None,
            when: vec![LdCtrlWhen {
                test: None,
                is_default: Some(true),
                internal_description: None,
                controls: vec![LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 50, ..Default::default() })],
            }],
        })],
    };
    let parameters = BTreeMap::from([("P-1".to_owned(), ProcedureParameter {
        active: false,
        value: ProcedureParameterValue::Unsigned(7),
    })]);

    let normalized = compile_fixture_with_parameters(procedure, parameters).expect("inactive choice compiles");

    assert!(normalized.steps.is_empty());
}

#[test]
fn missing_choose_selector_is_rejected_instead_of_assumed_active() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![LoadControl::Choose(LdCtrlChoose {
            param_ref_id: "P-1".to_owned(),
            internal_description: None,
            when: vec![LdCtrlWhen {
                test: None,
                is_default: Some(true),
                internal_description: None,
                controls: Vec::new(),
            }],
        })],
    };

    let error = compile_fixture_with_parameters(procedure, BTreeMap::new())
        .expect_err("missing post-evaluation selector state must fail closed");

    assert!(error.to_string().contains("choose references unresolved parameter P-1"));
}

#[test]
fn applies_to_evaluates_every_typed_program_section_and_configuration_alias() {
    let delay = |milliseconds, applies_to: &str| {
        LoadControl::LdCtrlDelay(LdCtrlDelay {
            applies_to: Some(applies_to.to_owned()),
            milli_seconds: milliseconds,
            ..Default::default()
        })
    };
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            delay(1, "ap1"),
            delay(2, "ap2"),
            delay(3, "par"),
            delay(4, "grp"),
            delay(5, "cfg"),
            delay(6, "config"),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let sections = ProgramSections::APPLICATION_PROGRAM_2.union(ProgramSections::CONFIGURATION);
    let normalized = compile_procedure(ProcedureCompileContext {
        profile: minimal_profile(),
        procedure_id: root_path().procedure,
        composition: ProcedureComposition::Default,
        procedure,
        product_merge_fragments: Vec::new(),
        parameter_values: BTreeMap::new(),
        applicability: ProcedureApplicability::partial(sections),
        image: SparseDeviceImage::new(),
        property_image_facts: Vec::new(),
        relative_memory_facts: Vec::new(),
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
        initial_tool_state: ToolState::default(),
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        secure_only: false,
        extension_operations: Vec::new(),
    })
    .expect("all typed AppliesTo sections compile");

    let delays = normalized
        .steps
        .iter()
        .filter_map(|step| match &step.operation {
            ProcedureOperation::Delay { milliseconds } => Some(*milliseconds),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(delays, [2, 5, 6]);
}

#[test]
fn full_scope_does_not_also_execute_partial_variants() {
    let delay = |milliseconds, applies_to: &str| {
        LoadControl::LdCtrlDelay(LdCtrlDelay {
            applies_to: Some(applies_to.to_owned()),
            milli_seconds: milliseconds,
            ..Default::default()
        })
    };
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            delay(1, "full"),
            delay(2, "par"),
            delay(3, "full,par"),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };

    let normalized = compile_fixture(procedure, Vec::new()).expect("full procedure variants compile");
    let delays = normalized
        .steps
        .iter()
        .filter_map(|step| match &step.operation {
            ProcedureOperation::Delay { milliseconds } => Some(*milliseconds),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(delays, [1, 3]);
}

#[test]
fn record_code_errors_apply_only_to_selected_controls_and_keep_the_source_path() {
    for applies_to in ["full", "par"] {
        let controls = [
            (
                LoadControl::LdCtrlWriteMem(LdCtrlWriteMem {
                    applies_to: Some(applies_to.to_owned()),
                    address_space: Some("FutureSpace".to_owned()),
                    size: 1,
                    inline_data: Some("00".to_owned()),
                    ..Default::default()
                }),
                "unknown load-control address space",
            ),
            (
                LoadControl::LdCtrlLoad(LdCtrlLoad {
                    applies_to: Some(applies_to.to_owned()),
                    lsm_idx: Some(16),
                    ..Default::default()
                }),
                "does not fit the registered record",
            ),
        ];
        for (control, reason) in controls {
            let result = compile_fixture(LoadProcedure { merge_id: None, controls: vec![control] }, Vec::new());
            if applies_to == "par" {
                assert!(result.expect("unused control record is ignored").steps.is_empty());
            } else {
                let error = result.expect_err("selected invalid control record fails");
                assert!(error.message.contains(reason));
                assert_eq!(error.path.expect("selected error keeps provenance").control_indices, [0]);
            }
        }
    }
}

#[test]
fn a_selected_merge_hidden_in_a_fragment_choice_is_rejected() {
    let profile = minimal_profile();
    let error = compile_procedure(ProcedureCompileContext {
        profile,
        procedure_id: root_path().procedure,
        composition: ProcedureComposition::Merged,
        procedure: LoadProcedure {
            merge_id: None,
            controls: vec![LoadControl::LdCtrlMerge(LdCtrlMerge { merge_id: 7, ..Default::default() })],
        },
        product_merge_fragments: vec![LoadProcedure {
            merge_id: Some(7),
            controls: vec![LoadControl::Choose(LdCtrlChoose {
                param_ref_id: "DownloadPath".to_owned(),
                when: vec![LdCtrlWhen {
                    test: Some("9".to_owned()),
                    controls: vec![LoadControl::LdCtrlMerge(LdCtrlMerge { merge_id: 7, ..Default::default() })],
                    ..Default::default()
                }],
                ..Default::default()
            })],
        }],
        parameter_values: BTreeMap::from([("DownloadPath".to_owned(), ProcedureParameter {
            active: true,
            value: ProcedureParameterValue::Unsigned(9),
        })]),
        applicability: ProcedureApplicability::full(),
        image: SparseDeviceImage::new(),
        property_image_facts: Vec::new(),
        relative_memory_facts: Vec::new(),
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
        initial_tool_state: ToolState::default(),
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        secure_only: false,
        extension_operations: Vec::new(),
    })
    .expect_err("a selected fragment cannot recursively splice itself through a choice");

    assert!(error.message.contains("nested merge"));
    let path = error.path.expect("composition names the source control");
    assert_eq!(path.control_indices, [0, 0, 0, 0]);
}
