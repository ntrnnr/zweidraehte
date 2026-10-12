use crate::commissioning::catalog::profile::ResolvedProfile;
use crate::commissioning::catalog::profile::testing::fixture_profile;
use crate::commissioning::compiler::binding::procedure::test_support::{
    ProcedureCompileContext, compile_fixture, compile_fixture_with_parameters,
    compile_fixture_with_profile_and_composition, compile_procedure, minimal_profile, root_path,
};
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
use crate::commissioning::image::SparseDeviceImage;
use crate::commissioning::input::ProgramSections;
use crate::commissioning::procedure::{OperationData, ProcedureOperation, RestartKind, ToolState};
use crate::configuration::{ProcedureParameter, ProcedureParameterValue};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ApplicationIdentity;
use zweidraehte_ets_files::schema::{
    LdCtrlChoose, LdCtrlConnect, LdCtrlDelay, LdCtrlDisconnect, LdCtrlLoad, LdCtrlMerge, LdCtrlTaskSegment, LdCtrlWhen,
    LdCtrlWriteMem, LoadControl, LoadProcedure,
};

#[test]
fn simple_management_task_records_use_the_compatibility_identity() {
    assert_task_record_identity(
        crate::commissioning::catalog::profile::ResourceManagementStyle::Simple,
        // Native full-download witnesses with PEI 0, 4 and 17 all retain
        // this simple-management record while their images own product IDs.
        ApplicationIdentity { application_id: [0xff, 0xff, 0, 0, 0xff], pei_type: 1 },
    );
}

#[test]
fn load_state_machine_task_records_keep_the_product_identity() {
    assert_task_record_identity(
        crate::commissioning::catalog::profile::ResourceManagementStyle::LoadStateMachine,
        ApplicationIdentity { application_id: [0, 0xe1, 0x20, 1, 0x10], pei_type: 17 },
    );
}

fn assert_task_record_identity(
    style: crate::commissioning::catalog::profile::ResourceManagementStyle,
    expected: ApplicationIdentity,
) {
    use zweidraehte_proto::messages::apdu::load_control::{LoadControlRecord, LsmMachine, MemLoadControlRecord};

    for composition in [ProcedureComposition::Default, ProcedureComposition::ProductOwned] {
        for property_mapped in [false, true] {
            let mut profile = fixture_profile(
                "MV-0020",
                "Bcu2",
                "MT-0",
                &format!(
                    r#"<Features><Feature Name="PropertyMappedLsms" Value="{}"/></Features>
                  <Resources>
                    <Resource Name="ApplicationLoadControl" Access="remote">
                      <Location AddressSpace="StandardMemory" StartAddress="256"/>
                      <ResourceType Length="12" Flavour="LoadControl_M112"/>
                    </Resource>
                    <Resource Name="ApplicationLoadStatus" Access="remote">
                      <Location AddressSpace="StandardMemory" StartAddress="272"/>
                      <ResourceType Length="1" Flavour="LoadControl_M112"/>
                    </Resource>
                  </Resources><InterfaceObjects></InterfaceObjects>"#,
                    u8::from(property_mapped)
                ),
            );
            profile.set_test_management_style(Some(style));
            let program = compile_procedure(ProcedureCompileContext {
                profile,
                procedure_id: root_path().procedure,
                composition,
                procedure: LoadProcedure {
                    merge_id: None,
                    controls: vec![LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment {
                        lsm_idx: Some(3),
                        address: 286,
                        ..Default::default()
                    })],
                },
                product_merge_fragments: Vec::new(),
                parameter_values: BTreeMap::new(),
                applicability: ProcedureApplicability::full(),
                image: SparseDeviceImage::new(),
                property_image_facts: Vec::new(),
                relative_memory_facts: Vec::new(),
                progress_messages_by_reference: BTreeMap::new(),
                progress_messages_by_id: BTreeMap::new(),
                initial_tool_state: ToolState::default(),
                restart_kind: RestartKind::Basic,
                application_identity: ApplicationIdentity { application_id: [0, 0xe1, 0x20, 1, 0x10], pei_type: 17 },
                extension_operations: Vec::new(),
            })
            .expect("task record lowers through the selected wire service");
            let [step] = program.steps.as_slice() else { panic!("one task record") };
            let ProcedureOperation::LoadRecord(record) = &step.operation else { panic!("task record") };
            let bytes = if property_mapped {
                LoadControlRecord::task_segment(286, expected.pei_type, expected.application_id).to_vec()
            } else {
                MemLoadControlRecord::task_segment(
                    LsmMachine::ApplicationProgram,
                    286,
                    expected.pei_type,
                    expected.application_id,
                )
                .to_vec()
            };
            assert_eq!(record.bytes, bytes, "{style:?}, {composition:?}, property={property_mapped}");
        }
    }
}

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

    // Independent native captures omit this legacy announcement for full
    // programming and every nonempty parameter/group/configuration selection.
    for applicability in full_and_partial_applicabilities() {
        let normalized = compile_procedure(task_announcement_context(
            profile.clone(),
            ProcedureComposition::ProductOwned,
            procedure.clone(),
            applicability,
        ))
        .expect("BCU2 legacy object-table announcement is not executable");

        assert_eq!(normalized.steps.len(), 3, "{applicability:?}");
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
}

#[test]
fn machine_five_task_omission_is_limited_to_bare_bcu2_product_controls() {
    let bcu2 = fixture_profile(
        "MV-0021",
        "Bcu2",
        "MT-0",
        r#"<Features><Feature Name="PropertyMappedLsms" Value="1"/></Features><Resources></Resources><InterfaceObjects></InterfaceObjects>"#,
    );
    let bare = LdCtrlTaskSegment { lsm_idx: Some(5), address: 0x0274, ..Default::default() };

    // Machine 5 is real on other families. Master Data and explicitly
    // annotated product controls also retain their authored meaning.
    for (profile, composition, control) in [
        (minimal_profile(), ProcedureComposition::ProductOwned, bare.clone()),
        (bcu2.clone(), ProcedureComposition::Default, bare.clone()),
        (bcu2, ProcedureComposition::ProductOwned, LdCtrlTaskSegment { applies_to: Some("all".to_owned()), ..bare }),
    ] {
        for applicability in full_and_partial_applicabilities() {
            let normalized = compile_procedure(task_announcement_context(
                profile.clone(),
                composition,
                LoadProcedure { merge_id: None, controls: vec![LoadControl::LdCtrlTaskSegment(control.clone())] },
                applicability,
            ))
            .expect("authored machine-five task record compiles");

            let [step] = normalized.steps.as_slice() else { panic!("one authored task record") };
            assert!(matches!(step.operation, ProcedureOperation::LoadRecord(_)));
            assert_eq!(step.path.control_indices, [0]);
        }
    }
}

fn full_and_partial_applicabilities() -> Vec<ProcedureApplicability> {
    let mut scopes = vec![ProcedureApplicability::full()];
    for bits in 1..8 {
        let mut sections = ProgramSections::empty();
        for (bit, section) in [
            (1, ProgramSections::PARAMETERS),
            (2, ProgramSections::GROUP_COMMUNICATION),
            (4, ProgramSections::CONFIGURATION),
        ] {
            if bits & bit != 0 {
                sections = sections.union(section);
            }
        }
        scopes.push(ProcedureApplicability::partial(sections));
    }
    scopes
}

fn task_announcement_context(
    profile: ResolvedProfile,
    composition: ProcedureComposition,
    procedure: LoadProcedure,
    applicability: ProcedureApplicability,
) -> ProcedureCompileContext {
    ProcedureCompileContext {
        profile,
        procedure_id: root_path().procedure,
        composition,
        procedure,
        product_merge_fragments: Vec::new(),
        parameter_values: BTreeMap::new(),
        applicability,
        image: SparseDeviceImage::new(),
        property_image_facts: Vec::new(),
        relative_memory_facts: Vec::new(),
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
        initial_tool_state: ToolState::default(),
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        extension_operations: Vec::new(),
    }
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
        extension_operations: Vec::new(),
    })
    .expect_err("a selected fragment cannot recursively splice itself through a choice");

    assert!(error.message.contains("nested merge"));
    let path = error.path.expect("composition names the source control");
    assert_eq!(path.control_indices, [0, 0, 0, 0]);
}

#[test]
fn memory_writes_send_the_declared_size_of_longer_inline_data() {
    // M-00EE_A-4301 ships Size="2" with eleven inline bytes whose tail is
    // leftover text; the write sends exactly the declared extent.
    let write = |size, inline: &str| {
        compile_fixture(
            LoadProcedure {
                merge_id: None,
                controls: vec![LoadControl::LdCtrlWriteMem(LdCtrlWriteMem {
                    address: 0x0101,
                    size,
                    inline_data: Some(inline.to_owned()),
                    ..Default::default()
                })],
            },
            Vec::new(),
        )
    };

    let normalized = write(2, "00EE68726974742F53746F").expect("longer inline data compiles");
    let [step] = normalized.steps.as_slice() else { panic!("one write step") };
    let ProcedureOperation::Write { data, extent, .. } = &step.operation else { panic!("a memory write") };
    assert_eq!(data, &OperationData::Inline(vec![0x00, 0xEE]));
    assert_eq!(extent.byte_length, 2);

    let error = write(3, "00EE").expect_err("shorter inline data cannot fill the declared size");
    assert!(error.message.contains("has only 2 bytes but Size declares 3"), "{}", error.message);
}
