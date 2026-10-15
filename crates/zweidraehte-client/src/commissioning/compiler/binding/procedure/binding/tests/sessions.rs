use crate::commissioning::catalog::profile::testing::{append_xml, fixture_profile};
use crate::commissioning::compiler::binding::procedure::test_support::{compile_fixture, compile_fixture_with_profile};
use crate::commissioning::compiler::features::{ModuleProcedureFragment, ProcedureCompilationPhase};
use crate::commissioning::image::SparseDeviceImage;
use crate::commissioning::procedure::{ErrorAction, ErrorHandler, LoadControlCause, ProcedureOperation, WriteIntent};
use zweidraehte_ets_files::schema::{
    LdCtrlConnect, LdCtrlDelay, LdCtrlDisconnect, LdCtrlLoad, LdCtrlMapError, LdCtrlMasterReset, LdCtrlRestart,
    LdCtrlWriteMem, LdCtrlWriteProp, LoadControl, LoadProcedure, OnError,
};

#[test]
fn feature_restart_preserves_passive_prefix_and_existing_terminals() {
    use crate::commissioning::compiler::binding::procedure::test_support::minimal_profile;
    use crate::commissioning::compiler::binding::procedure::{ProcedureInput, parse};
    use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
    use crate::commissioning::procedure::operands::StandardMemoryService;
    use crate::commissioning::procedure::{ProcedureSourceId, RestartKind, ToolState};
    use std::collections::BTreeMap;
    use zweidraehte_ets_files::product::ApplicationIdentity;
    use zweidraehte_project::ProgrammingSection;

    let profile = minimal_profile();
    let parameters = BTreeMap::new();
    // Measured native finalization keeps passive prefixes outside a generated
    // session. Without a feature restart request it leaves them unframed.
    for passive_prefix in [false, true] {
        for requested in [None, Some(RestartKind::Basic), Some(RestartKind::Confirmed)] {
            for existing_terminal in [false, true] {
                let mut controls = Vec::new();
                if passive_prefix {
                    controls.push(LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 17, ..Default::default() }));
                }
                if existing_terminal {
                    controls.extend([
                        LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                        LoadControl::LdCtrlMasterReset(LdCtrlMasterReset { erase_code: 1, ..Default::default() }),
                        LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
                    ]);
                }
                let input = ProcedureInput {
                    profile: &profile,
                    procedure_id: ProcedureSourceId::Generated { name: "native feature-finalization witness".into() },
                    composition: ProcedureComposition::Default,
                    applicability: ProcedureApplicability::full(),
                    controls: &controls,
                    product_merge_fragments: Vec::new(),
                    secondary_merge_fragments: Vec::new(),
                    secondary_application_id: None,
                    parameter_values: &parameters,
                    omitted_controls: Vec::new(),
                    configuration_anchor: profile.configuration_anchor(),
                    download_stamps: Vec::new(),
                    property_parameters: &[],
                    peiprog_identity_reference: false,
                    application_program_2_present: false,
                    progress_messages_by_reference: &BTreeMap::new(),
                    progress_messages_by_id: &BTreeMap::new(),
                    initial_tool_state: ToolState::default(),
                    standard_memory_service: StandardMemoryService::Classic,
                    restart_kind: RestartKind::Basic,
                    application_identity: ApplicationIdentity::default(),
                    secondary_application_identity: None,
                    extended_property_descriptions: false,
                };
                let mut parsed = parse(&input).expect("source metadata parses");
                parsed.add_automatic_download_session();
                if let Some(kind) = requested {
                    parsed.require_feature_restart(kind, ProgrammingSection::Configuration);
                }
                let program = parsed
                    .finish(&profile, &SparseDeviceImage::new(), true)
                    .expect("native feature lifecycle validates");
                let prefix = usize::from(passive_prefix);
                if passive_prefix {
                    assert!(matches!(program.steps[0].operation, ProcedureOperation::Delay { milliseconds: 17 }));
                }
                if existing_terminal || requested.is_some() {
                    assert_eq!(program.steps.len(), prefix + 3);
                    assert!(matches!(program.steps[prefix].operation, ProcedureOperation::Connect));
                    assert!(matches!(program.steps[prefix + 2].operation, ProcedureOperation::Disconnect));
                    if existing_terminal {
                        assert!(matches!(program.steps[prefix + 1].operation, ProcedureOperation::MasterReset {
                            erase_code: 1,
                            ..
                        }));
                        assert!(program.steps[prefix + 1].path.contribution.is_none());
                    } else {
                        assert!(matches!(program.steps[prefix + 1].operation,
                            ProcedureOperation::Restart { kind } if Some(kind) == requested));
                    }
                } else {
                    assert_eq!(program.steps.len(), prefix);
                }
            }
        }
    }
}

#[test]
fn session_validation_retains_the_authored_terminal_path() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
            LoadControl::LdCtrlRestart(LdCtrlRestart::default()),
        ],
    };
    let error = compile_fixture(procedure, Vec::new()).expect_err("restart requires an earlier session");
    assert_eq!(error.message, "procedure restarts without an open connection");
    assert_eq!(error.path.expect("the failing source control is retained").control_indices, [1]);
}

#[test]
fn a_restart_after_a_closed_session_reopens_it_on_demand() {
    // M-0077 PEI fragments restart the device inside the download; the
    // reference reopens the session for the following services and the
    // mask's final restart.
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlRestart(LdCtrlRestart::default()),
            LoadControl::LdCtrlRestart(LdCtrlRestart::default()),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    compile_fixture(procedure, Vec::new()).expect("a later restart reopens the closed session");
}

#[test]
fn terminal_service_preserves_the_following_disconnect_and_error_metadata() {
    for terminal in [
        LoadControl::LdCtrlRestart(LdCtrlRestart::default()),
        LoadControl::LdCtrlMasterReset(LdCtrlMasterReset::default()),
    ] {
        let procedure = LoadProcedure {
            merge_id: None,
            controls: vec![
                LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                LoadControl::LdCtrlMapError(LdCtrlMapError {
                    ld_ctrl_filter: Some(13),
                    original_error: 7,
                    mapped_error: 0,
                    ..Default::default()
                }),
                terminal,
                LoadControl::LdCtrlDisconnect(LdCtrlDisconnect {
                    on_errors: vec![OnError {
                        cause: "ResourceNotFound".to_owned(),
                        ignore: Some(false),
                        message_ref: Some("disconnect-failed".to_owned()),
                    }],
                    ..Default::default()
                }),
            ],
        };

        let normalized =
            compile_fixture(procedure, Vec::new()).expect("the terminal service closes the only management session");

        assert_eq!(normalized.steps.len(), 4);
        assert!(matches!(normalized.steps[0].operation, ProcedureOperation::Connect));
        assert!(matches!(normalized.steps[1].operation, ProcedureOperation::MapError {
            filter: Some(13),
            original: 7,
            mapped: 0
        }));
        assert!(matches!(
            normalized.steps[2].operation,
            ProcedureOperation::Restart { .. } | ProcedureOperation::MasterReset { .. }
        ));
        let disconnect = &normalized.steps[3];
        assert!(matches!(disconnect.operation, ProcedureOperation::Disconnect));
        assert_eq!(disconnect.path.control_indices, [3]);
        assert_eq!(disconnect.source_control_code, Some(13));
        assert_eq!(disconnect.on_error, [ErrorHandler {
            cause: LoadControlCause::ResourceNotFound,
            action: ErrorAction::FailWithMessage { message_reference: Some("disconnect-failed".to_owned()) },
        }]);
    }

    let nested = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlRestart(LdCtrlRestart::default()),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let normalized =
        compile_fixture(nested, Vec::new()).expect("the explicit disconnect remains necessary for the outer session");

    assert_eq!(normalized.steps.len(), 4);
    assert!(matches!(normalized.steps[3].operation, ProcedureOperation::Disconnect));
}

#[test]
fn late_standard_contribution_stays_inside_the_final_session() {
    let contribution = ModuleProcedureFragment {
        source: "test-ip-overlay",
        section: zweidraehte_project::ProgrammingSection::Configuration,
        phase: ProcedureCompilationPhase::BeforeSessionClose,
        operation: ProcedureOperation::ProgressText("ip-configuration".to_owned()),
        secure_only: true,
    };

    for terminal in [
        LoadControl::LdCtrlRestart(LdCtrlRestart::default()),
        LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
    ] {
        let procedure = LoadProcedure {
            merge_id: None,
            controls: vec![
                LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 1, ..Default::default() }),
                terminal,
            ],
        };
        let normalized = compile_fixture(procedure, vec![contribution.clone()])
            .expect("late contribution has an open final session");

        assert!(matches!(normalized.steps[0].operation, ProcedureOperation::Connect));
        assert!(matches!(normalized.steps[1].operation, ProcedureOperation::Delay { .. }));
        assert!(matches!(
            &normalized.steps[2].operation,
            ProcedureOperation::ProgressText(text) if text == "ip-configuration"
        ));
        assert!(normalized.steps[2].secure_only);
        assert!(matches!(
            normalized.steps[3].operation,
            ProcedureOperation::Restart { .. } | ProcedureOperation::Disconnect
        ));
    }
}

#[test]
fn late_contribution_precedes_restart_and_retains_the_authored_disconnect() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 1, ..Default::default() }),
            LoadControl::LdCtrlRestart(LdCtrlRestart::default()),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let contribution = ModuleProcedureFragment {
        source: "test-overlay",
        section: zweidraehte_project::ProgrammingSection::Configuration,
        phase: ProcedureCompilationPhase::BeforeSessionClose,
        operation: ProcedureOperation::ProgressText("late-configuration".to_owned()),
        secure_only: true,
    };

    let normalized = compile_fixture(procedure, vec![contribution])
        .expect("redundant terminal disconnect does not invalidate the session anchor");

    assert_eq!(normalized.steps.len(), 5);
    assert!(matches!(normalized.steps[0].operation, ProcedureOperation::Connect));
    assert!(matches!(normalized.steps[1].operation, ProcedureOperation::Delay { .. }));
    assert!(matches!(
        &normalized.steps[2].operation,
        ProcedureOperation::ProgressText(text) if text == "late-configuration"
    ));
    assert!(matches!(normalized.steps[3].operation, ProcedureOperation::Restart { .. }));
    assert!(matches!(normalized.steps[4].operation, ProcedureOperation::Disconnect));
    assert_eq!(normalized.steps[4].path.control_indices, [3]);
}

#[test]
fn late_contribution_cannot_use_a_disconnect_without_a_live_session() {
    let procedure =
        LoadProcedure { merge_id: None, controls: vec![LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default())] };
    let contribution = ModuleProcedureFragment {
        source: "test-overlay",
        section: zweidraehte_project::ProgrammingSection::Configuration,
        phase: ProcedureCompilationPhase::BeforeSessionClose,
        operation: ProcedureOperation::ProgressText("late-configuration".to_owned()),
        secure_only: true,
    };

    let error = compile_fixture(procedure, vec![contribution])
        .expect_err("an idempotent disconnect cannot provide a live contribution anchor");

    assert!(error.to_string().contains("lifecycle boundary absent"));
}

#[test]
fn late_standard_contribution_uses_the_last_of_multiple_sessions() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 1, ..Default::default() }),
            LoadControl::LdCtrlRestart(LdCtrlRestart::default()),
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 2, ..Default::default() }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let contribution = ModuleProcedureFragment {
        source: "test-ip-overlay",
        section: zweidraehte_project::ProgrammingSection::Configuration,
        phase: ProcedureCompilationPhase::BeforeSessionClose,
        operation: ProcedureOperation::ProgressText("ip-configuration".to_owned()),
        secure_only: true,
    };

    let normalized =
        compile_fixture(procedure, vec![contribution]).expect("the final session has an exact close boundary");

    assert!(matches!(normalized.steps[2].operation, ProcedureOperation::Restart { .. }));
    assert!(matches!(normalized.steps[3].operation, ProcedureOperation::Connect));
    assert!(matches!(normalized.steps[4].operation, ProcedureOperation::Delay { milliseconds: 2 }));
    assert!(matches!(
        &normalized.steps[5].operation,
        ProcedureOperation::ProgressText(text) if text == "ip-configuration"
    ));
    assert!(matches!(normalized.steps[6].operation, ProcedureOperation::Disconnect));
}

#[test]
fn system7_ip_anchor_follows_router_configuration_chain() {
    let mut profile = fixture_profile(
        "MV-5705",
        "BimM112",
        "MT-5",
        r#"<Features><Feature Name="PropertyMappedLsms" Value="1"/></Features><Resources></Resources><InterfaceObjects></InterfaceObjects>"#,
    );
    for (name, length) in [("RouterLoadControl", 10), ("RouterLoadStatus", 1)] {
        append_xml(
            &mut profile,
            "Resources",
            &format!(
                r#"<Resource Name="{name}"><Location AddressSpace="Property" InterfaceObjectRef="6" PropertyID="5" StartAddress="0"/><ResourceType Length="{length}" Flavour="LoadControl_Bcu2"/><AccessRights Read="Runtime" Write="Configuration"/></Resource>"#
            ),
        );
    }
    let property_write = |property_id| {
        LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
            obj_type: Some(6),
            prop_id: property_id,
            inline_data: Some("00".to_owned()),
            verify: false,
            ..Default::default()
        })
    };
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlLoad(LdCtrlLoad { obj_type: Some(6), ..Default::default() }),
            property_write(52),
            property_write(55),
            LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 17, ..Default::default() }),
            LoadControl::LdCtrlRestart(LdCtrlRestart::default()),
        ],
    };
    let contribution = ModuleProcedureFragment {
        source: "test-ip-overlay",
        section: zweidraehte_project::ProgrammingSection::Configuration,
        phase: ProcedureCompilationPhase::BeforeSessionClose,
        operation: ProcedureOperation::ProgressText("ip-configuration".to_owned()),
        secure_only: false,
    };

    let normalized = compile_fixture_with_profile(profile, procedure, vec![contribution], SparseDeviceImage::new())
        .expect("router configuration completes before the ordinary tail");

    assert!(
        matches!(&normalized.steps[4].operation, ProcedureOperation::ProgressText(text) if text == "ip-configuration")
    );
    assert!(matches!(normalized.steps[5].operation, ProcedureOperation::Delay { milliseconds: 17 }));
    assert!(matches!(normalized.steps[6].operation, ProcedureOperation::Restart { .. }));
}

#[test]
fn routing_configuration_anchor_precedes_later_application_writes() {
    use crate::commissioning::procedure::ControlVariable;
    let mut profile = fixture_profile(
        "MV-5705",
        "BimM112",
        "MT-5",
        r#"<Features><Feature Name="PropertyMappedLsms" Value="1"/></Features><Resources></Resources><InterfaceObjects></InterfaceObjects>"#,
    );
    for (name, property_id, length) in [("RouterLoadControl", 5, 10), ("RouterLoadStatus", 5, 1)] {
        append_xml(
            &mut profile,
            "Resources",
            &format!(
                r#"<Resource Name="{name}"><Location AddressSpace="Property" InterfaceObjectRef="6" PropertyID="{property_id}" StartAddress="0"/><ResourceType Length="{length}" Flavour="LoadControl_Bcu2"/><AccessRights Read="Runtime" Write="Configuration"/></Resource>"#
            ),
        );
    }
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlLoad(LdCtrlLoad { obj_type: Some(6), ..Default::default() }),
            LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                obj_type: Some(6),
                prop_id: 52,
                inline_data: Some("01".to_owned()),
                verify: false,
                ..Default::default()
            }),
            LoadControl::LdCtrlWriteMem(LdCtrlWriteMem {
                address: 0x200,
                size: 1,
                inline_data: Some("AB".to_owned()),
                verify: false,
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let contribution = ModuleProcedureFragment {
        source: "routing-then-application",
        section: zweidraehte_project::ProgrammingSection::Configuration,
        phase: ProcedureCompilationPhase::BeforeSessionClose,
        operation: ProcedureOperation::SetControlVariable {
            variable: ControlVariable::EnableVerifyOnWriteDirect,
            value: true,
        },
        secure_only: false,
    };

    let normalized = compile_fixture_with_profile(profile, procedure, vec![contribution], SparseDeviceImage::new())
        .expect("profile-specific anchor lowers in source order");
    assert!(matches!(normalized.steps[3].operation, ProcedureOperation::SetControlVariable { .. }));
    assert!(matches!(normalized.steps[4].operation, ProcedureOperation::Write {
        policy: WriteIntent::Memory { verify: false },
        ..
    }));
}
