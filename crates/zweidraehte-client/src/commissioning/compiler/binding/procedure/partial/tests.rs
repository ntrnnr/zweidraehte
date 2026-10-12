use super::*;
use crate::commissioning::compiler::binding::procedure::test_support::{minimal_profile, root_path};
use crate::commissioning::procedure::operands::StandardMemoryService;
use zweidraehte_ets_files::schema::{
    LdCtrlAbsSegment, LdCtrlLoad, LdCtrlLoadCompleted, LdCtrlMaxLength, LdCtrlMerge, LdCtrlRelSegment,
    LdCtrlSetControlVariable, LdCtrlTaskCtrl1, LdCtrlTaskCtrl2, LdCtrlTaskPtr, LdCtrlTaskSegment, LdCtrlUnload,
};

fn with_input(controls: &[LoadControl], sections: ProgramSections, test: impl FnOnce(ProcedureInput<'_>)) {
    let mut profile = minimal_profile();
    crate::commissioning::catalog::profile::testing::append_xml(
        &mut profile,
        "InterfaceObjects",
        r#"<InterfaceObject Index="3" ObjectType="3" />"#,
    );
    let values = BTreeMap::new();
    let messages = BTreeMap::new();
    let ids = BTreeMap::new();

    test(ProcedureInput {
        profile: &profile,
        procedure_id: root_path().procedure,
        composition: ProcedureComposition::ProductOwned,
        controls,
        product_merge_fragments: Vec::new(),
        omitted_controls: Vec::new(),
        parameter_values: &values,
        applicability: ProcedureApplicability::partial(sections),
        configuration_anchor: profile.configuration_anchor(),
        download_stamps: Vec::new(),
        property_parameters: &[],
        peiprog_identity_reference: false,
        application_program_2_present: false,
        progress_messages_by_reference: &messages,
        progress_messages_by_id: &ids,
        initial_tool_state: ToolState::default(),
        standard_memory_service: StandardMemoryService::Classic,
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        secure_only: false,
    });
}

// Native finalization removes the explicitly indexed secondary-program controls
// even when their applicability is `all`. Check the selection boundaries and
// original source paths, rather than relying on default procedures to omit them.
#[test]
fn secondary_application_finalization_preserves_scope_and_source_paths() {
    use crate::commissioning::catalog::profile::testing::fixture_profile;
    use zweidraehte_ets_files::schema::LdCtrlDelay;

    let controls = vec![
        LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: Some(5), applies_to: Some("all".into()), ..Default::default() }),
        LoadControl::LdCtrlUnload(LdCtrlUnload {
            lsm_idx: Some(5),
            applies_to: Some("all".into()),
            ..Default::default()
        }),
        LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted {
            lsm_idx: Some(5),
            applies_to: Some("all".into()),
            ..Default::default()
        }),
        LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 17, ..Default::default() }),
        LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: Some(4), applies_to: Some("all".into()), ..Default::default() }),
    ];
    let fragment = LoadProcedure { merge_id: Some(6), controls: controls.clone() };
    let root = vec![LoadControl::LdCtrlMerge(LdCtrlMerge {
        merge_id: 6,
        applies_to: Some("all".into()),
        ..Default::default()
    })];
    for mask in ["MV-07B0", "MV-07B1", "MV-0705", "MV-27B0", "MV-57B0"] {
        let profile = fixture_profile(
            mask,
            "BimM112",
            "MT-0",
            r#"<Features><Feature Name="PropertyMappedLsms" Value="1"/><Feature Name="FirstAppObjectIdx" Value="4"/></Features><Resources/><InterfaceObjects/>"#,
        );
        for full in [false, true] {
            for bits in 1..8 {
                let mut sections = ProgramSections::empty();
                if bits & 1 != 0 {
                    sections = sections.union(ProgramSections::PARAMETERS);
                }
                if bits & 2 != 0 {
                    sections = sections.union(ProgramSections::GROUP_COMMUNICATION);
                }
                if bits & 4 != 0 {
                    sections = sections.union(ProgramSections::CONFIGURATION);
                }
                for secondary in [false, true] {
                    for composition in [
                        ProcedureComposition::Default,
                        ProcedureComposition::ProductOwned,
                        ProcedureComposition::Merged,
                    ] {
                        with_input(&controls, sections, |mut input| {
                            input.composition = composition;
                            input.application_program_2_present = secondary;
                            if full {
                                input.applicability = ProcedureApplicability::full();
                            }
                            let merged = composition == ProcedureComposition::Merged;
                            let input = ProcedureInput {
                                profile: &profile,
                                controls: if merged { &root } else { &controls },
                                product_merge_fragments: if merged { vec![&fragment] } else { Vec::new() },
                                ..input
                            };
                            let parsed =
                                parse(&input).expect("explicit controls bind independently of automatic transforms");
                            let prune = profile.mask().dd0 & 0x0ff0 == 0x07b0 && !full && bits & 1 != 0 && !secondary;
                            let expected: Vec<_> = (if prune { 3..5 } else { 0..5 })
                                .map(|index| {
                                    if composition == ProcedureComposition::Merged {
                                        vec![0, index]
                                    } else {
                                        vec![index]
                                    }
                                })
                                .collect();
                            let paths: Vec<_> =
                                parsed.program.steps.iter().map(|step| step.path.control_indices.clone()).collect();
                            assert_eq!(
                                paths, expected,
                                "mask={mask} full={full} bits={bits} secondary={secondary} composition={composition:?}"
                            );
                        });
                    }
                }
            }
        }
    }
}

#[test]
fn absent_secondary_property_controls_skip_operand_binding() {
    use crate::commissioning::catalog::profile::testing::fixture_profile;
    use zweidraehte_ets_files::schema::{LdCtrlCompareProp, LdCtrlDelay, LdCtrlLoadImageProp, LdCtrlWriteProp};

    // These operands deliberately have no bindable property data. Native
    // omission must precede reference resolution, preserving the later delay.
    for applies_to in ["all", "par"] {
        let controls = vec![
            LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                obj_idx: Some(5),
                prop_id: 65535,
                inline_data: Some("invalid".into()),
                applies_to: Some(applies_to.into()),
                ..Default::default()
            }),
            LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                obj_idx: Some(5),
                prop_id: 65535,
                applies_to: Some(applies_to.into()),
                ..Default::default()
            }),
            LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                obj_idx: Some(5),
                prop_id: 65535,
                applies_to: Some(applies_to.into()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 17, ..Default::default() }),
        ];
        let profile = fixture_profile("MV-07B0", "BimM112", "MT-0", "<Resources/><InterfaceObjects/>");
        with_input(&controls, ProgramSections::PARAMETERS, |input| {
            let input = ProcedureInput { profile: &profile, ..input };
            let parsed = parse(&input).expect("absent secondary properties require no operand binding");
            assert_eq!(parsed.program.steps.len(), 1);
            assert_eq!(parsed.program.steps[0].path.control_indices, [3]);
            assert!(matches!(parsed.program.steps[0].operation, ProcedureOperation::Delay { .. }));

            let input = ProcedureInput { application_program_2_present: true, ..input };
            assert!(parse(&input).is_err(), "a present secondary application retains property operand validation");
        });
    }
}

#[test]
fn master_controls_keep_native_all_semantics_and_product_fragments_transform() {
    let allocation = || {
        LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
            lsm_idx: Some(3),
            address: 256,
            size: 4,
            mem_type: 3,
            ..Default::default()
        })
    };
    for composition in [ProcedureComposition::Default, ProcedureComposition::Merged] {
        let controls =
            vec![LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: Some(3), ..Default::default() }), allocation()];
        with_input(
            &controls,
            ProgramSections::GROUP_COMMUNICATION.union(ProgramSections::CONFIGURATION),
            |mut input| {
                input.composition = composition;
                let parsed = parse(&input).expect("Master Data procedure controls retain their selected source");
                assert_eq!(parsed.program.steps.len(), 2);
                assert!(matches!(parsed.program.steps[0].operation, ProcedureOperation::LoadRecord(_)));
                assert!(matches!(parsed.program.steps[1].operation, ProcedureOperation::AbsoluteSegment { .. }));
            },
        );
    }

    let fragment = LoadProcedure { merge_id: Some(1), controls: vec![allocation()] };
    let controls = vec![allocation(), LoadControl::LdCtrlMerge(LdCtrlMerge { merge_id: 1, ..Default::default() })];
    with_input(&controls, ProgramSections::PARAMETERS, |input| {
        let input = ProcedureInput {
            composition: ProcedureComposition::Merged,
            product_merge_fragments: vec![&fragment],
            ..input
        };
        let parsed = parse(&input).expect("only the merged product controls transform");
        assert_eq!(parsed.program.steps.len(), 2);
        assert!(matches!(parsed.program.steps[0].operation, ProcedureOperation::AbsoluteSegment { .. }));
        assert!(matches!(parsed.program.steps[1].operation, ProcedureOperation::Write {
            policy: WriteIntent::Memory { verify: true },
            ..
        }));
        assert_eq!(parsed.program.steps[1].path.control_indices, [1, 0]);
    });
}

fn controls(object_type: u16) -> Vec<LoadControl> {
    vec![
        LoadControl::LdCtrlLoad(LdCtrlLoad { obj_type: Some(object_type), ..Default::default() }),
        LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { obj_type: Some(object_type), ..Default::default() }),
        LoadControl::LdCtrlUnload(LdCtrlUnload { obj_type: Some(object_type), ..Default::default() }),
        LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
            obj_type: Some(object_type),
            address: 256,
            size: 4,
            mem_type: 3,
            ..Default::default()
        }),
        LoadControl::LdCtrlRelSegment(LdCtrlRelSegment { obj_type: Some(object_type), ..Default::default() }),
        LoadControl::LdCtrlMaxLength(LdCtrlMaxLength::default()),
        LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment { obj_type: Some(object_type), ..Default::default() }),
        LoadControl::LdCtrlTaskPtr(LdCtrlTaskPtr::default()),
        LoadControl::LdCtrlTaskCtrl1(LdCtrlTaskCtrl1::default()),
        LoadControl::LdCtrlTaskCtrl2(LdCtrlTaskCtrl2::default()),
    ]
}

#[test]
fn automatic_download_sessions_follow_selection_before_partial_transformation() {
    use zweidraehte_ets_files::schema::{LdCtrlDelay, LdCtrlSetControlVariable};

    for scope in [
        None,
        Some(ProgramSections::PARAMETERS),
        Some(ProgramSections::GROUP_COMMUNICATION),
        Some(ProgramSections::CONFIGURATION),
    ] {
        for variant in 0..6 {
            let controls = match variant {
                0 => Vec::new(),
                1 => vec![LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 1, ..Default::default() })],
                2 => vec![LoadControl::LdCtrlSetControlVariable(LdCtrlSetControlVariable {
                    name: "EnableMemoryAutoVerify".to_owned(),
                    value: true,
                    ..Default::default()
                })],
                _ => vec![LoadControl::LdCtrlUnload(LdCtrlUnload {
                    lsm_idx: Some(3),
                    applies_to: match variant {
                        4 => Some("grp".to_owned()),
                        5 => Some("full".to_owned()),
                        _ => None,
                    },
                    ..Default::default()
                })],
            };
            with_input(&controls, scope.unwrap_or_else(ProgramSections::all), |mut input| {
                if scope.is_none() {
                    input.applicability = ProcedureApplicability::full();
                }
                let mut parsed = parse(&input).expect("selected controls bind");
                parsed.add_automatic_download_session();
                // Reapplying finalization must not duplicate either boundary.
                parsed.add_automatic_download_session();
                let procedure =
                    parsed.finish(input.profile, &SparseDeviceImage::new(), true).expect("download session validates");
                let names: Vec<_> = procedure
                    .steps
                    .iter()
                    .map(|step| match step.operation {
                        ProcedureOperation::Connect => "connect",
                        ProcedureOperation::Disconnect => "disconnect",
                        ProcedureOperation::Delay { .. } => "delay",
                        ProcedureOperation::SetControlVariable { .. } => "passive",
                        ProcedureOperation::LoadRecord(_) => "load",
                        _ => panic!("unexpected operation"),
                    })
                    .collect();
                let expected: &[&str] = match variant {
                    0 => &[],
                    1 => &["delay"],
                    2 => &["passive"],
                    3 if scope.is_none() => &["connect", "load", "disconnect"],
                    3 => &["connect", "disconnect"],
                    4 if scope == Some(ProgramSections::GROUP_COMMUNICATION) => &["connect", "load", "disconnect"],
                    5 if scope.is_none() => &["connect", "load", "disconnect"],
                    _ => &[],
                };
                assert_eq!(names, expected, "scope {scope:?}, variant {variant}");
                for step in &procedure.steps {
                    if matches!(step.operation, ProcedureOperation::Connect | ProcedureOperation::Disconnect) {
                        assert!(step.source_control_code.is_none());
                        assert!(step.path.contribution.is_some());
                    } else {
                        assert_eq!(step.path.control_indices, [0]);
                    }
                }
            });
        }
    }
}

#[test]
fn automatic_session_keeps_passive_prefix_and_a_live_feature_anchor() {
    use crate::commissioning::compiler::features::{ModuleProcedureFragment, ProcedureCompilationPhase};
    use zweidraehte_ets_files::schema::LdCtrlDelay;

    let controls = vec![
        LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 7, ..Default::default() }),
        LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: Some(3), ..Default::default() }),
    ];
    with_input(&controls, ProgramSections::PARAMETERS, |input| {
        let mut parsed = parse(&input).expect("source selects before automatic omission");
        parsed.add_automatic_download_session();
        let fragment = ModuleProcedureFragment {
            source: "test-automatic-session-feature",
            section: ProgrammingSection::Configuration,
            phase: ProcedureCompilationPhase::BeforeSessionClose,
            secure_only: false,
            operation: ProcedureOperation::ProgressText("feature".to_owned()),
        };
        parsed.insert_builtin(
            fragment.phase,
            fragment.source,
            fragment.section,
            fragment.secure_only,
            fragment.operation,
        );
        let procedure =
            parsed.finish(input.profile, &SparseDeviceImage::new(), true).expect("feature uses the generated session");
        assert_eq!(procedure.steps.len(), 4);
        assert!(matches!(procedure.steps[0].operation, ProcedureOperation::Delay { milliseconds: 7 }));
        assert_eq!(procedure.steps[0].path.control_indices, [0]);
        assert!(matches!(procedure.steps[1].operation, ProcedureOperation::Connect));
        assert!(matches!(procedure.steps[2].operation, ProcedureOperation::ProgressText(_)));
        assert!(matches!(procedure.steps[3].operation, ProcedureOperation::Disconnect));
    });
}

#[test]
fn merged_fragments_activate_sessions_only_through_selected_controls() {
    for applies_to in [None, Some("grp")] {
        let fragment = LoadProcedure {
            merge_id: Some(1),
            controls: vec![LoadControl::LdCtrlUnload(LdCtrlUnload {
                lsm_idx: Some(3),
                applies_to: applies_to.map(str::to_owned),
                ..Default::default()
            })],
        };
        let controls = vec![LoadControl::LdCtrlMerge(LdCtrlMerge { merge_id: 1, ..Default::default() })];
        with_input(&controls, ProgramSections::PARAMETERS, |input| {
            let input = ProcedureInput {
                composition: ProcedureComposition::Merged,
                product_merge_fragments: vec![&fragment],
                ..input
            };
            let mut parsed = parse(&input).expect("selected fragment binds");
            parsed.add_automatic_download_session();
            let procedure =
                parsed.finish(input.profile, &SparseDeviceImage::new(), true).expect("merged session validates");
            if applies_to.is_some() {
                assert!(procedure.steps.is_empty());
            } else {
                assert_eq!(procedure.steps.len(), 2);
                assert!(matches!(procedure.steps[0].operation, ProcedureOperation::Connect));
                assert!(matches!(procedure.steps[1].operation, ProcedureOperation::Disconnect));
            }
        });
    }
}

#[test]
fn partial_auto_machine_matrix_matches_native_typed_controls() {
    use AutoControl::{Keep, Omit, WriteMemory};

    for subset in 1..8 {
        let mut sections = ProgramSections::empty();
        if subset & 1 != 0 {
            sections = sections.union(ProgramSections::PARAMETERS);
        }
        if subset & 2 != 0 {
            sections = sections.union(ProgramSections::GROUP_COMMUNICATION);
        }
        if subset & 4 != 0 {
            sections = sections.union(ProgramSections::CONFIGURATION);
        }
        let group = if subset & 2 != 0 { Keep } else { Omit };

        for object in [0, 1, 2, 3, 4, 9, 99] {
            let controls = controls(object);
            for secondary in [false, true] {
                for enabled in [false, true] {
                    with_input(&controls, sections, |mut input| {
                        input.application_program_2_present = secondary;
                        let mut lowerer = ProcedureLowerer::new(&input).unwrap();
                        lowerer.auto_segment_write = enabled;
                        let application = if enabled { WriteMemory { address: 256, size: 4 } } else { Omit };
                        let secondary_selected = subset & 1 != 0 && secondary;
                        // Columns: load, complete, unload, absolute, relative,
                        // max length, task segment, pointer, control 1/control 2.
                        let expected = match object {
                            1 | 2 => vec![group, group, group, group, group, Keep, group, Omit, Omit, Omit],
                            9 => vec![group, group, Omit, group, group, Keep, group, Omit, Omit, Omit],
                            3 => vec![Keep, Keep, Omit, application, Keep, Keep, Omit, Omit, Omit, Omit],
                            4 => vec![
                                if secondary_selected { Keep } else { Omit },
                                if secondary_selected { Keep } else { Omit },
                                Omit,
                                if secondary_selected { application } else { Omit },
                                if secondary { Keep } else { Omit },
                                Keep,
                                Omit,
                                Omit,
                                Omit,
                                Omit,
                            ],
                            _ => vec![Keep, Keep, Keep, Keep, Keep, Keep, Keep, Omit, Omit, Omit],
                        };
                        for (index, control) in controls.iter().enumerate() {
                            assert_eq!(
                                lowerer.partial_auto_control(control, &root_path().child(index)).unwrap(),
                                expected[index],
                                "subset={subset} object={object} secondary={secondary} enabled={enabled} column={index}"
                            );
                        }
                    });
                }
            }
        }
    }
}

#[test]
fn auto_application_allocations_become_verified_writes_with_authored_paths() {
    for annotation in [None, Some("auto"), Some("all")] {
        for full in [false, true] {
            let controls = vec![LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                lsm_idx: Some(3),
                address: 256,
                size: 4,
                mem_type: 3,
                applies_to: annotation.map(str::to_owned),
                ..Default::default()
            })];
            with_input(&controls, ProgramSections::CONFIGURATION, |mut input| {
                input.applicability.full = full;
                let parsed = parse(&input).expect("eligible allocation parses");
                let step = &parsed.program.steps[0];
                assert_eq!(step.path.control_indices, [0]);
                if !full && annotation != Some("all") {
                    assert_eq!(step.source_control_code, Some(9));
                    assert!(matches!(&step.operation, ProcedureOperation::Write {
                        data: OperationData::ImageWindow { location, maximum: 4 },
                        policy: WriteIntent::Memory { verify: true }, ..
                    } if location == &ImageLocation::standard_memory(256)));
                } else {
                    assert!(matches!(step.operation, ProcedureOperation::AbsoluteSegment { .. }));
                }
            });
        }
    }
}

#[test]
fn only_auto_setters_change_the_ordered_finalization_context() {
    for annotation in [None, Some("auto"), Some("all"), Some("par")] {
        let segment = || {
            LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                lsm_idx: Some(3),
                address: 256,
                size: 4,
                mem_type: 3,
                ..Default::default()
            })
        };
        let setter = |value| {
            LoadControl::LdCtrlSetControlVariable(LdCtrlSetControlVariable {
                name: "EnableSegmentWrite".to_owned(),
                value,
                applies_to: annotation.map(str::to_owned),
                ..Default::default()
            })
        };
        let controls = vec![segment(), setter(false), segment(), setter(true), segment()];
        with_input(&controls, ProgramSections::PARAMETERS, |mut input| {
            input.initial_tool_state.segment_write = false;
            let parsed = parse(&input).expect("ordered controls parse");
            let writes: Vec<_> = parsed
                .program
                .steps
                .iter()
                .filter(|step| matches!(step.operation, ProcedureOperation::Write { .. }))
                .map(|step| step.path.control_indices.clone())
                .collect();
            let expected = if annotation.is_none() || annotation == Some("auto") {
                vec![vec![0], vec![4]]
            } else {
                vec![vec![0], vec![2], vec![4]]
            };
            assert_eq!(writes, expected, "annotation={annotation:?}");
        });
    }
}

#[test]
fn partial_auto_memory_types_preserve_low_storage_bits() {
    for memory_type in [0, 1, 2, 3, 4, 5, 6, 7, 0x82, 0x83] {
        let controls = vec![LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
            lsm_idx: Some(3),
            address: 256,
            size: 4,
            mem_type: memory_type,
            ..Default::default()
        })];
        with_input(&controls, ProgramSections::PARAMETERS, |input| {
            let parsed = parse(&input).unwrap();
            assert_eq!(parsed.program.steps.len(), usize::from(memory_type & 3 == 3));
        });
    }
}
