use crate::commissioning::catalog::profile::testing::fixture_profile;
use crate::commissioning::compiler::binding::procedure::test_support::{
    ProcedureCompileContext, compile_procedure, root_path,
};
use crate::commissioning::compiler::features::{ModuleProcedureFragment, ProcedureCompilationPhase};
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
use crate::commissioning::image::SparseDeviceImage;
use crate::commissioning::input::ProgramSections;
use crate::commissioning::procedure::{ProcedureOperation, RestartKind, ToolState};
use crate::configuration::{ProcedureParameter, ProcedureParameterValue};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ApplicationIdentity;
use zweidraehte_ets_files::schema::{
    LdCtrlChoose, LdCtrlConnect, LdCtrlDelay, LdCtrlDisconnect, LdCtrlLoadCompleted, LdCtrlMerge, LdCtrlTaskSegment,
    LdCtrlUnload, LdCtrlWhen, LoadControl, LoadProcedure,
};
use zweidraehte_project::ProgrammingSection;

fn context(mask: &str, controls: Vec<LoadControl>) -> ProcedureCompileContext {
    ProcedureCompileContext {
        profile: fixture_profile(
            mask,
            "BimM112",
            "MT-0",
            r#"<Features><Feature Name="PropertyMappedLsms" Value="1"/><Feature Name="FirstAppObjectIdx" Value="4"/></Features><Resources/><InterfaceObjects><InterfaceObject Index="4" ObjectType="3"/></InterfaceObjects>"#,
        ),
        procedure_id: root_path().procedure,
        composition: ProcedureComposition::ProductOwned,
        procedure: LoadProcedure { merge_id: None, controls },
        product_merge_fragments: Vec::new(),
        parameter_values: BTreeMap::new(),
        applicability: ProcedureApplicability::partial(
            ProgramSections::PARAMETERS.union(ProgramSections::GROUP_COMMUNICATION),
        ),
        image: SparseDeviceImage::new(),
        property_image_facts: Vec::new(),
        relative_memory_facts: Vec::new(),
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
        initial_tool_state: ToolState::default(),
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        secure_only: false,
        extension_operations: [
            (ProcedureCompilationPhase::NativeSecurityUnload, "security-unload"),
            (ProcedureCompilationPhase::NativeSecurityLoad, "security-reload"),
        ]
        .into_iter()
        .map(|(phase, text)| ModuleProcedureFragment {
            source: "security-cursor-test",
            section: ProgrammingSection::GroupCommunication,
            phase,
            operation: ProcedureOperation::ProgressText(text.to_owned()),
            secure_only: true,
        })
        .collect(),
    }
}

#[test]
fn partial_security_cursors_precede_omitted_task_and_secondary_completion() {
    for mask in ["MV-07B0", "MV-27B0", "MV-57B0", "MV-0705"] {
        let controls = vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlUnload(LdCtrlUnload {
                lsm_idx: Some(4),
                applies_to: Some("all".into()),
                ..Default::default()
            }),
            LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment { lsm_idx: Some(4), ..Default::default() }),
            LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted {
                lsm_idx: Some(5),
                applies_to: Some("all".into()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 17, ..Default::default() }),
            LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted {
                lsm_idx: Some(4),
                applies_to: Some("all".into()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ];
        let program = compile_procedure(context(mask, controls)).expect("selected source binds");
        let unload = program
            .steps
            .iter()
            .position(|step| {
                step.path.contribution.is_some()
                    && matches!(&step.operation, ProcedureOperation::ProgressText(text) if text == "security-unload")
            })
            .expect("unload marker is retained");
        let reload = program
            .steps
            .iter()
            .position(|step| {
                step.path.contribution.is_some()
                    && matches!(&step.operation, ProcedureOperation::ProgressText(text) if text == "security-reload")
            })
            .expect("reload marker is retained");
        let delay = program
            .steps
            .iter()
            .position(|step| matches!(step.operation, ProcedureOperation::Delay { milliseconds: 17 }))
            .expect("ordinary delay is retained");
        assert_eq!((unload, reload), (2, 3), "mask {mask}");
        assert!(reload < delay, "omitted controls must not retarget reload");
        assert!(!program.steps.iter().any(|step| step.path.contribution.is_none() && step.path.control_indices == [2]));
        assert_eq!(
            program.steps.iter().any(|step| step.path.contribution.is_none() && step.path.control_indices == [3]),
            mask == "MV-0705"
        );
        // Captured source identity remains the omitted task, not the surviving
        // completion or the security unload's final output index.
        assert_eq!(program.steps[reload].path.control_indices[0], 2);
    }
}

#[test]
fn security_cursors_count_selected_choice_and_merge_leaves() {
    let root = vec![
        LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
        LoadControl::LdCtrlUnload(LdCtrlUnload {
            lsm_idx: Some(4),
            applies_to: Some("all".into()),
            ..Default::default()
        }),
        LoadControl::LdCtrlMerge(LdCtrlMerge { merge_id: 6, ..Default::default() }),
        LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted {
            lsm_idx: Some(4),
            applies_to: Some("all".into()),
            ..Default::default()
        }),
        LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
    ];
    let selected = vec![
        LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 17, ..Default::default() }),
        LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted {
            lsm_idx: Some(4),
            applies_to: Some("all".into()),
            ..Default::default()
        }),
    ];
    let fragment = LoadProcedure {
        merge_id: Some(6),
        controls: vec![LoadControl::Choose(LdCtrlChoose {
            param_ref_id: "DownloadPath".into(),
            internal_description: None,
            when: vec![LdCtrlWhen { test: Some("=9".into()), controls: selected, ..Default::default() }],
        })],
    };
    let mut source = context("MV-57B0", root);
    source.composition = ProcedureComposition::Merged;
    source.product_merge_fragments = vec![fragment];
    source.parameter_values = BTreeMap::from([("DownloadPath".into(), ProcedureParameter {
        active: true,
        value: ProcedureParameterValue::Unsigned(9),
    })]);
    let program = compile_procedure(source).expect("selected merge and choice bind");
    let reload = program
        .steps
        .iter()
        .position(|step| matches!(&step.operation, ProcedureOperation::ProgressText(text) if text == "security-reload"))
        .expect("reload marker is retained");
    let delay = program
        .steps
        .iter()
        .position(|step| matches!(step.operation, ProcedureOperation::Delay { milliseconds: 17 }))
        .expect("selected delay is retained");
    assert_eq!(reload + 1, delay);
    assert_eq!(&program.steps[reload].path.control_indices[..4], &[2, 0, 0, 0]);
    assert_eq!(program.steps[delay].path.control_indices, [2, 0, 0, 0]);
}
