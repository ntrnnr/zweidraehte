use crate::commissioning::compiler::binding::procedure::test_support::compile_fixture;
use crate::commissioning::compiler::features::{ModuleProcedureFragment, ProcedureCompilationPhase};
use crate::commissioning::procedure::{ProcedureOperation, WriteIntent};
use zweidraehte_ets_files::schema::{
    LdCtrlConnect, LdCtrlDisconnect, LdCtrlLoad, LdCtrlLoadCompleted, LdCtrlRestart, LdCtrlUnload, LdCtrlWriteMem,
    LoadControl, LoadProcedure,
};

#[test]
fn semantic_load_anchors_preserve_all_ordinary_machine_ordering() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: Some(1), ..Default::default() }),
            LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: Some(2), ..Default::default() }),
            LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: Some(1), ..Default::default() }),
            LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: Some(2), ..Default::default() }),
            LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: Some(1), ..Default::default() }),
            LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: Some(2), ..Default::default() }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let source = "test-overlay";
    let extension_operations = vec![
        ModuleProcedureFragment {
            source,
            section: zweidraehte_project::ProgrammingSection::Configuration,
            phase: ProcedureCompilationPhase::BeforeFirstStartLoading,
            operation: ProcedureOperation::ProgressText("overlay-unload".to_owned()),
            secure_only: true,
        },
        ModuleProcedureFragment {
            source,
            section: zweidraehte_project::ProgrammingSection::Configuration,
            phase: ProcedureCompilationPhase::AfterLastCompleteLoading,
            operation: ProcedureOperation::ProgressText("overlay-load".to_owned()),
            secure_only: true,
        },
    ];

    let normalized = compile_fixture(procedure, extension_operations).expect("semantic anchors compile");

    let descriptions: Vec<_> = normalized
        .steps
        .iter()
        .map(|step| match &step.operation {
            ProcedureOperation::LoadRecord(record) => match record.bytes[0] {
                1 => "StartLoading",
                2 => "CompleteLoading",
                4 => "StartUnloading",
                _ => "Record",
            }
            .to_owned(),
            ProcedureOperation::ProgressText(text) => text.clone(),
            operation => format!("{operation:?}"),
        })
        .collect();

    assert_eq!(descriptions, [
        "Connect",
        "StartUnloading",
        "StartUnloading",
        "overlay-unload",
        "StartLoading",
        "StartLoading",
        "CompleteLoading",
        "CompleteLoading",
        "overlay-load",
        "Disconnect",
    ]);
    assert!(normalized.steps[3].secure_only);
    assert!(normalized.steps[8].secure_only);
    assert!(!normalized.steps[4].secure_only);
    assert_eq!(normalized.steps[3].path.contribution, Some("test-overlay"));
}

#[test]
fn security_io_reload_follows_every_ordinary_machine_commit() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: Some(1), ..Default::default() }),
            LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: Some(2), ..Default::default() }),
            LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: Some(1), ..Default::default() }),
            LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: Some(2), ..Default::default() }),
            LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: Some(1), ..Default::default() }),
            LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: Some(2), ..Default::default() }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let source = "standard-data-secure";
    let contribution = |phase: ProcedureCompilationPhase, text: &str| ModuleProcedureFragment {
        source,
        section: zweidraehte_project::ProgrammingSection::GroupCommunication,
        phase,
        operation: ProcedureOperation::ProgressText(text.to_owned()),
        secure_only: true,
    };
    let extension_operations = vec![
        contribution(ProcedureCompilationPhase::BeforeFirstStartLoading, "security-unload"),
        contribution(ProcedureCompilationPhase::AfterLastCompleteLoading, "security-start-loading"),
        contribution(ProcedureCompilationPhase::AfterLastCompleteLoading, "security-complete-loading"),
        contribution(ProcedureCompilationPhase::AfterLastCompleteLoading, "security-mode"),
    ];

    let normalized = compile_fixture(procedure, extension_operations).expect("Security IO anchors compile");
    let descriptions: Vec<_> = normalized
        .steps
        .iter()
        .map(|step| match &step.operation {
            ProcedureOperation::LoadRecord(record) => match record.bytes[0] {
                1 => "StartLoading",
                2 => "CompleteLoading",
                4 => "StartUnloading",
                _ => "Record",
            }
            .to_owned(),
            ProcedureOperation::ProgressText(text) => text.clone(),
            operation => format!("{operation:?}"),
        })
        .collect();

    assert_eq!(descriptions, [
        "Connect",
        "StartUnloading",
        "StartUnloading",
        "security-unload",
        "StartLoading",
        "StartLoading",
        "CompleteLoading",
        "CompleteLoading",
        "security-start-loading",
        "security-complete-loading",
        "security-mode",
        "Disconnect",
    ]);
}

#[test]
fn semantic_contributions_fail_when_the_selected_flow_has_no_anchor() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let contributions = vec![ModuleProcedureFragment {
        source: "test-overlay",
        section: zweidraehte_project::ProgrammingSection::Configuration,
        phase: ProcedureCompilationPhase::BeforeFirstStartLoading,
        operation: ProcedureOperation::ProgressText("unreachable".to_owned()),
        secure_only: true,
    }];

    let error = compile_fixture(procedure, contributions).expect_err("missing semantic anchor must fail closed");

    assert!(error.to_string().contains("lifecycle boundary absent"));
}

#[test]
fn lifecycle_contribution_changes_the_state_seen_by_following_controls() {
    use crate::commissioning::procedure::ControlVariable;

    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: Some(1), ..Default::default() }),
            LoadControl::LdCtrlWriteMem(LdCtrlWriteMem {
                address: 0x200,
                size: 1,
                inline_data: Some("A5".to_owned()),
                verify: false,
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let contribution = ModuleProcedureFragment {
        source: "post-commit-verification",
        section: zweidraehte_project::ProgrammingSection::Parameters,
        phase: ProcedureCompilationPhase::AfterLastCompleteLoading,
        operation: ProcedureOperation::SetControlVariable {
            variable: ControlVariable::EnableVerifyOnWriteDirect,
            value: true,
        },
        secure_only: false,
    };

    let normalized = compile_fixture(procedure, vec![contribution]).expect("lifecycle state changes lower in order");
    assert!(matches!(normalized.steps[2].operation, ProcedureOperation::SetControlVariable { .. }));
    assert!(
        matches!(normalized.steps[3].operation, ProcedureOperation::Write {
            policy: WriteIntent::Memory { verify: false },
            ..
        }),
        "the following write retains runtime policy evaluation after the state change"
    );
}

#[test]
fn lifecycle_anchor_identifies_the_last_machine_and_its_session() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: Some(1), ..Default::default() }),
            LoadControl::LdCtrlRestart(LdCtrlRestart::default()),
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: Some(2), ..Default::default() }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let contribution = ModuleProcedureFragment {
        source: "final-machine-configuration",
        section: zweidraehte_project::ProgrammingSection::Configuration,
        phase: ProcedureCompilationPhase::AfterLastCompleteLoading,
        operation: ProcedureOperation::ProgressText("final-machine".to_owned()),
        secure_only: false,
    };
    let normalized = compile_fixture(procedure, vec![contribution]).expect("final machine has a live session");

    assert!(matches!(normalized.steps[2].operation, ProcedureOperation::Restart { .. }));
    assert!(matches!(normalized.steps[3].operation, ProcedureOperation::Connect));
    assert!(
        matches!(&normalized.steps[5].operation, ProcedureOperation::ProgressText(text) if text == "final-machine")
    );
    assert_eq!(normalized.steps[5].path.control_indices[0], 4);
    assert!(matches!(normalized.steps[6].operation, ProcedureOperation::Disconnect));
}

/// A security-style unload inserted by an earlier contribution.
fn generated_unload() -> ProcedureOperation {
    use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence};
    use crate::commissioning::procedure::operands::property_target;
    use crate::commissioning::procedure::{LoadEffect, LoadRecord, OperationExtent, ServiceRead};
    use zweidraehte_proto::messages::apdu::load_control::LoadState;

    let target = property_target(&ObjectSelector::Type { object_type: 17, occurrence: Occurrence::Zero }, 5, 1)
        .expect("fixture property selector");
    let read = ServiceRead { target, extent: OperationExtent::property(1, 1) };
    ProcedureOperation::LoadRecord(LoadRecord {
        write: read.clone(),
        bytes: vec![4],
        poll: Some((read, LoadState::Unloaded)),
        effect: LoadEffect::InvalidateAll,
    })
}

fn fragment(phase: ProcedureCompilationPhase, operation: ProcedureOperation) -> ModuleProcedureFragment {
    ModuleProcedureFragment {
        source: "test-overlay",
        section: zweidraehte_project::ProgrammingSection::Configuration,
        phase,
        operation,
        secure_only: false,
    }
}

fn describe(normalized: &crate::commissioning::procedure::NormalizedProcedure) -> Vec<String> {
    normalized
        .steps
        .iter()
        .map(|step| match &step.operation {
            ProcedureOperation::LoadRecord(record) => match record.bytes[0] {
                1 => "StartLoading".to_owned(),
                2 => "CompleteLoading".to_owned(),
                4 if step.path.contribution.is_some() => "GeneratedUnloading".to_owned(),
                4 => "StartUnloading".to_owned(),
                _ => "Record".to_owned(),
            },
            ProcedureOperation::ProgressText(text) => text.clone(),
            operation => format!("{operation:?}"),
        })
        .collect()
}

#[test]
fn after_last_unload_follows_unloads_inserted_by_earlier_contributions() {
    // The RF medium configuration is placed after the last unload of the
    // program as composed so far. The security unload inserted after the
    // authored unloads is therefore the one it follows.
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: Some(1), ..Default::default() }),
            LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: Some(2), ..Default::default() }),
            LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: Some(1), ..Default::default() }),
            LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: Some(1), ..Default::default() }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let normalized = compile_fixture(procedure, vec![
        fragment(ProcedureCompilationPhase::NativeSecurityUnload, generated_unload()),
        fragment(ProcedureCompilationPhase::AfterLastUnload, ProcedureOperation::ProgressText("rf".to_owned())),
    ])
    .expect("cursor resolves");

    assert_eq!(describe(&normalized), [
        "Connect",
        "StartUnloading",
        "StartUnloading",
        "GeneratedUnloading",
        "rf",
        "StartLoading",
        "CompleteLoading",
        "Disconnect",
    ]);
}

#[test]
fn after_last_unload_falls_back_to_the_first_connect() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: Some(1), ..Default::default() }),
            LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: Some(1), ..Default::default() }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let normalized = compile_fixture(procedure, vec![fragment(
        ProcedureCompilationPhase::AfterLastUnload,
        ProcedureOperation::ProgressText("rf".to_owned()),
    )])
    .expect("cursor resolves");

    assert_eq!(describe(&normalized), ["Connect", "rf", "StartLoading", "CompleteLoading", "Disconnect"]);
}
