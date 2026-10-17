use crate::commissioning::catalog::profile::ObjectSelector;
use crate::commissioning::compiler::binding::procedure::test_support::{
    ProcedureCompileContext, compile_fixture_with_image, compile_procedure, memory_target, minimal_profile, root_path,
};
use crate::commissioning::compiler::features::{ModuleProcedureFragment, ProcedureCompilationPhase};
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
use crate::commissioning::image::{ImageLocation, ImageSpace, SparseDeviceImage};
use crate::commissioning::procedure::operands::{MemoryAddress, MemoryService};
use crate::commissioning::procedure::{
    LoadEffect, OperationData, OperationExtent, OperationTarget, ProcedureOperation, RestartKind, ToolState,
};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ApplicationIdentity;
use zweidraehte_ets_files::schema::{
    LdCtrlConnect, LdCtrlDisconnect, LdCtrlLoad, LdCtrlRelSegment, LdCtrlWriteMem, LdCtrlWriteRelMem, LoadControl,
    LoadProcedure,
};
mod contributions;
mod sessions;

#[test]
fn inline_function_commands_preserve_payload_presence_and_image_state() {
    use crate::commissioning::procedure::FunctionPropertyOperation;
    use crate::commissioning::procedure::operands::PropertyAddress;
    use zweidraehte_ets_files::schema::LdCtrlInvokeFunctionProp;

    for (inline_data, expected) in [("", vec![]), ("0410", vec![4, 16]), ("FF", vec![255])] {
        let source = LoadProcedure {
            merge_id: None,
            controls: vec![
                LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                LoadControl::LdCtrlInvokeFunctionProp(LdCtrlInvokeFunctionProp {
                    obj_idx: Some(3),
                    prop_id: 42,
                    inline_data: Some(inline_data.to_owned()),
                    ..Default::default()
                }),
                LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
            ],
        };
        let program = compile_fixture_with_image(source, Vec::new(), SparseDeviceImage::new())
            .expect("present inline function payload compiles");
        assert_eq!(
            program.steps[1].operation,
            ProcedureOperation::FunctionProperty(FunctionPropertyOperation::Invoke {
                address: PropertyAddress::Indexed { object_index: 3, property_id: 42 },
                data: expected,
                effect: LoadEffect::None,
            })
        );
    }
}

#[test]
fn absent_inline_function_commands_require_a_typed_working_image_binding() {
    use crate::commissioning::error::CompileErrorKind;
    use zweidraehte_ets_files::schema::LdCtrlInvokeFunctionProp;

    let source = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlInvokeFunctionProp(LdCtrlInvokeFunctionProp {
                obj_idx: Some(3),
                prop_id: 42,
                inline_data: None,
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let error = compile_fixture_with_image(source, Vec::new(), SparseDeviceImage::new())
        .expect_err("an image-backed command cannot be replaced with an empty request");
    assert_eq!(error.kind, CompileErrorKind::Unsupported);
    assert_eq!(error.path.expect("authored failure path").control_indices, [1]);
    assert_eq!(error.message, "image-backed function-property commands require response-image binding");
}

#[test]
fn implicit_memory_writes_follow_only_preceding_load_image_ownership() {
    use zweidraehte_ets_files::schema::LdCtrlLoadImageMem;
    let write = |address, size| {
        LoadControl::LdCtrlWriteMem(LdCtrlWriteMem { address, size, verify: false, ..Default::default() })
    };
    let source = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            write(0x100, 3),
            LoadControl::LdCtrlLoadImageMem(LdCtrlLoadImageMem { address: 0x101, size: 1, ..Default::default() }),
            write(0x100, 3),
            write(0x110, 3),
            write(0x101, 0),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let normalized = compile_fixture_with_image(source, Vec::new(), SparseDeviceImage::new()).unwrap();
    let writes: Vec<_> = normalized
        .steps
        .iter()
        .filter_map(|step| {
            if let ProcedureOperation::Write { target, data, extent, .. } = &step.operation {
                Some((target, data, extent))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].0, &OperationTarget::Memory {
        service: MemoryService::Classic,
        address: MemoryAddress::Fixed(0x100)
    });
    assert_eq!(writes[0].1, &OperationData::ImageWindow {
        location: ImageLocation::standard_memory(0x100),
        maximum: 3
    });
    assert_eq!(writes[0].2, &OperationExtent::bytes(2));
}

#[test]
fn absolute_allocations_transfer_only_loadable_eeprom() {
    use zweidraehte_ets_files::schema::LdCtrlAbsSegment;

    // High memory-type flags do not change the low two-bit storage class.
    // Keeping image bytes present in every case catches accidental RAM writes.
    for memory_type in [0, 1, 2, 3, 0x82, 0x83] {
        let mut image = SparseDeviceImage::new();
        image.apply_owned(ImageLocation::standard_memory(0x4000), vec![0x5A; 4]).expect("allocation image fits");
        let procedure = LoadProcedure {
            merge_id: None,
            controls: vec![
                LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                    lsm_idx: Some(3),
                    address: 0x4000,
                    size: 4,
                    mem_type: memory_type,
                    ..Default::default()
                }),
                LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
            ],
        };
        let normalized =
            compile_fixture_with_image(procedure, Vec::new(), image).expect("absolute allocation is valid");
        let ProcedureOperation::AbsoluteSegment { transfers, .. } = &normalized.steps[1].operation else {
            panic!("absolute allocation retains one control boundary")
        };
        assert_eq!(transfers.len(), usize::from(memory_type & 3 == 3), "memory type {memory_type:#04x}");
    }
}

#[test]
fn absolute_allocation_keeps_its_authored_window_for_runtime_native_selection() {
    use zweidraehte_ets_files::schema::LdCtrlAbsSegment;

    for sparse_bytes in [false, true] {
        let mut image = SparseDeviceImage::new();
        if sparse_bytes {
            image.apply_owned(ImageLocation::standard_memory(0x4002), vec![0x5A]).expect("sparse image fits");
        }
        let procedure = LoadProcedure {
            merge_id: None,
            controls: vec![
                LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                    lsm_idx: Some(3),
                    address: 0x4000,
                    size: 8,
                    mem_type: 3,
                    ..Default::default()
                }),
                LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
            ],
        };
        let normalized = compile_fixture_with_image(procedure, Vec::new(), image).expect("allocation binds");
        let ProcedureOperation::AbsoluteSegment { record, transfers } = &normalized.steps[1].operation else {
            panic!("allocation retains one control boundary")
        };
        assert_eq!(record.effect, LoadEffect::Invalidate {
            location: ImageLocation::standard_memory(0x4000),
            length: 8,
        });
        assert_eq!(transfers.len(), 1, "an earlier LoadImage may establish native geometry at runtime");
        assert_eq!(transfers[0].extent, OperationExtent::bytes(8), "inspection reports the conservative bound");
        assert_eq!(transfers[0].data, OperationData::ImageWindow {
            location: ImageLocation::standard_memory(0x4000),
            maximum: 8,
        });
    }
}

#[test]
fn relative_segment_placeholder_expands_to_the_compiled_image_footprint() {
    let object = ObjectSelector::Index { index: 3 };
    let mut image = SparseDeviceImage::new();
    image
        .apply_owned(ImageLocation { space: ImageSpace::RelativeMemory { object: object.clone() }, offset: 0 }, vec![
            0;
            37
        ])
        .expect("group-object image fits the relative address space");
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlRelSegment(LdCtrlRelSegment {
                lsm_idx: Some(3),
                size: 2,
                mode: 0,
                fill: 0,
                ..Default::default()
            }),
            LoadControl::LdCtrlWriteRelMem(LdCtrlWriteRelMem {
                obj_idx: Some(3),
                offset: 0,
                size: 1_048_576,
                verify: true,
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };

    let normalized = compile_procedure(ProcedureCompileContext {
        profile: minimal_profile(),
        procedure_id: root_path().procedure,
        composition: ProcedureComposition::Default,
        procedure,
        product_merge_fragments: Vec::new(),
        parameter_values: BTreeMap::new(),
        applicability: ProcedureApplicability::full(),
        image,
        property_image_facts: Vec::new(),
        relative_memory_facts: vec![(object.clone(), 7)],
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
        initial_tool_state: ToolState::default(),
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        extension_operations: Vec::new(),
    })
    .expect("System B placeholder allocation expands to the project table");

    let ProcedureOperation::LoadRecord(record) = &normalized.steps[1].operation else { panic!("relative allocation") };
    assert_eq!(record.effect, LoadEffect::Invalidate {
        location: ImageLocation { space: ImageSpace::RelativeMemory { object: object.clone() }, offset: 0 },
        length: 37
    });

    let writes = normalized
        .steps
        .iter()
        .filter_map(|step| match &step.operation {
            ProcedureOperation::Write { target, extent, .. } => Some((step, target, extent)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 1, "only the explicit WriteRelMem transfers relative data");
    for (_, target, extent) in &writes {
        assert_eq!(*target, &memory_target(Some(object.clone()), 0));
        assert_eq!(**extent, OperationExtent::bytes(37));
    }
    assert_eq!(writes[0].0.path.control_indices, [2]);
}

#[test]
fn relative_allocation_fill_preserves_authored_image_writes() {
    let object = ObjectSelector::Index { index: 3 };
    let mut separated_values = vec![0; 70];
    separated_values[2] = 0x11;
    separated_values[35] = 0x22;
    separated_values[69] = 0x33;

    // Allocation fill cannot replace verification of the full authored
    // write, nor prove the current bytes after an intervening control.
    for (data, preceding_inline) in
        [(vec![1, 1, 1, 0, 0, 0, 0, 0], false), (vec![0; 8], false), (vec![0; 8], true), (separated_values, false)]
    {
        let expected_length = u32::try_from(data.len()).expect("test image length fits");
        let mut image = SparseDeviceImage::new();
        image
            .apply_owned(
                ImageLocation { space: ImageSpace::RelativeMemory { object: object.clone() }, offset: 0 },
                data,
            )
            .expect("relative image fits");
        let mut controls = vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlRelSegment(LdCtrlRelSegment {
                lsm_idx: Some(3),
                size: 2,
                mode: 1,
                fill: 0,
                ..Default::default()
            }),
        ];
        if preceding_inline {
            controls.push(LoadControl::LdCtrlWriteRelMem(LdCtrlWriteRelMem {
                obj_idx: Some(3),
                offset: 0,
                size: 1,
                inline_data: Some("A5".to_owned()),
                verify: true,
                ..Default::default()
            }));
        }
        let write_index = controls.len();
        controls.push(LoadControl::LdCtrlWriteRelMem(LdCtrlWriteRelMem {
            obj_idx: Some(3),
            offset: 0,
            size: 1_048_576,
            verify: true,
            ..Default::default()
        }));
        controls.push(LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()));

        let normalized = compile_procedure(ProcedureCompileContext {
            profile: minimal_profile(),
            procedure_id: root_path().procedure,
            composition: ProcedureComposition::Default,
            procedure: LoadProcedure { merge_id: None, controls },
            product_merge_fragments: Vec::new(),
            parameter_values: BTreeMap::new(),
            applicability: ProcedureApplicability::full(),
            image,
            property_image_facts: Vec::new(),
            relative_memory_facts: vec![(object.clone(), 7)],
            progress_messages_by_reference: BTreeMap::new(),
            progress_messages_by_id: BTreeMap::new(),
            initial_tool_state: ToolState::default(),
            restart_kind: RestartKind::Basic,
            application_identity: ApplicationIdentity::default(),
            extension_operations: Vec::new(),
        })
        .expect("the authored relative image transfer compiles");

        let writes = normalized
            .steps
            .iter()
            .filter(|step| matches!(step.operation, ProcedureOperation::Write { .. }))
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), if preceding_inline { 2 } else { 1 });
        if preceding_inline {
            assert!(matches!(
                &writes[0].operation,
                ProcedureOperation::Write { data: OperationData::Inline(bytes), .. } if bytes == &[0xa5]
            ));
        }
        let restored = writes.last().expect("the full image write remains");
        assert_eq!(restored.path.control_indices, [write_index]);
        let ProcedureOperation::Write {
            target: OperationTarget::Memory { address: MemoryAddress::Pointer { offset, .. }, .. },
            data: OperationData::ImageWindow { location, .. },
            extent,
            ..
        } = &restored.operation
        else {
            panic!("the authored control transfers the relative image");
        };
        assert_eq!((*offset, location.offset), (0, 0));
        assert_eq!(*extent, OperationExtent::bytes(expected_length));
    }
}

#[test]
fn relative_allocations_outside_table_formatting_keep_their_authored_size() {
    // M-0077 allocates 1 byte for a 123248-byte PEI program and 1280 bytes
    // for a 2048-byte parameter segment; the reference requests the authored
    // sizes, whether the image is longer or shorter.
    let sparse_object = ObjectSelector::Index { index: 3 };
    let minimum_object = ObjectSelector::Index { index: 2 };
    let mut image = SparseDeviceImage::new();
    image
        .apply_owned(ImageLocation { space: ImageSpace::RelativeMemory { object: sparse_object }, offset: 5 }, vec![
            0;
            4
        ])
        .expect("sparse relative image fits");
    image
        .apply_owned(ImageLocation { space: ImageSpace::RelativeMemory { object: minimum_object }, offset: 0 }, vec![
            0;
            3
        ])
        .expect("small relative image fits");
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlRelSegment(LdCtrlRelSegment { lsm_idx: Some(3), size: 2, ..Default::default() }),
            LoadControl::LdCtrlRelSegment(LdCtrlRelSegment { lsm_idx: Some(2), size: 11, ..Default::default() }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };

    let normalized = compile_fixture_with_image(procedure, Vec::new(), image)
        .expect("relative allocations compile beside a longer image");
    let sizes = normalized
        .steps
        .iter()
        .filter_map(|step| match &step.operation {
            ProcedureOperation::LoadRecord(record) => match &record.effect {
                LoadEffect::Invalidate {
                    location:
                        ImageLocation {
                            space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index } }, ..
                        },
                    length,
                } => {
                    let requested = u32::from_be_bytes(record.bytes[2..6].try_into().expect("allocation record size"));
                    Some((*index, (requested, *length)))
                }
                _ => None,
            },
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();

    // The request keeps the authored size; the device state still forgets
    // the whole image the allocation replaces.
    assert_eq!(sizes.get(&3), Some(&(2, 9)));
    assert_eq!(sizes.get(&2), Some(&(11, 11)));
}

#[test]
fn system_b_table_allocations_take_the_encoded_table_size() {
    use crate::commissioning::compiler::binding::procedure::test_support::{
        compile_fixture_with_profile, minimal_profile,
    };

    // M-0001_A-9A01 reserves 8002 bytes for 2000 groups and 478 bytes of
    // group objects; the reference allocates the 20, 38 and 366 bytes its
    // encoded tables use, but keeps the code segment's authored size.
    let mut profile = minimal_profile();
    crate::commissioning::catalog::profile::testing::append_xml(
        &mut profile,
        "Resources",
        r#"<Resource Name="GroupAddressTable"><Location AddressSpace="RelativeMemory" InterfaceObjectRef="1" PropertyID="7" StartAddress="0"/><ResourceType Length="2" Flavour="AddressTable_SystemB"/><AccessRights Read="Runtime" Write="Configuration"/></Resource>"#,
    );
    let mut image = SparseDeviceImage::new();
    for (index, length) in [(1, 20), (2, 38), (3, 366), (4, 5405)] {
        image
            .apply_owned(
                ImageLocation {
                    space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index } },
                    offset: 0,
                },
                vec![0; length],
            )
            .expect("relative table image fits");
    }
    let segment = |lsm_idx, size| {
        LoadControl::LdCtrlRelSegment(LdCtrlRelSegment { lsm_idx: Some(lsm_idx), size, ..Default::default() })
    };
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            segment(4, 5421),
            segment(3, 478),
            segment(1, 8002),
            segment(2, 8002),
            // Only the first allocation of a table machine is resized.
            segment(1, 8002),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };

    let normalized = compile_fixture_with_profile(profile, procedure, Vec::new(), image)
        .expect("table allocations bind against their encoded tables");
    let sizes: Vec<_> = normalized
        .steps
        .iter()
        .filter_map(|step| match &step.operation {
            ProcedureOperation::LoadRecord(record) => match &record.effect {
                LoadEffect::Invalidate {
                    location:
                        ImageLocation {
                            space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index } }, ..
                        },
                    length,
                } => Some((*index, *length)),
                _ => None,
            },
            _ => None,
        })
        .collect();

    assert_eq!(sizes, [(4, 5421), (3, 366), (1, 20), (2, 38), (1, 8002)]);
}

#[test]
fn system_b_table_allocation_ignores_a_seeded_reserve_beyond_the_encoded_table() {
    use crate::commissioning::compiler::binding::procedure::test_support::{
        ProcedureCompileContext, compile_procedure_with_tables, minimal_profile, root_path,
    };
    use crate::commissioning::compiler::image::{CompiledTableKind, CompiledTableSpan};

    // M-0002_A-0806 seeds 50 bytes on the group-object machine for a table
    // that encodes one object in four bytes. The reference allocates and
    // writes the encoded table; the seeded reserve stays image content only.
    let mut profile = minimal_profile();
    crate::commissioning::catalog::profile::testing::append_xml(
        &mut profile,
        "Resources",
        r#"<Resource Name="GroupAddressTable"><Location AddressSpace="RelativeMemory" InterfaceObjectRef="1" PropertyID="7" StartAddress="0"/><ResourceType Length="2" Flavour="AddressTable_SystemB"/><AccessRights Read="Runtime" Write="Configuration"/></Resource>"#,
    );
    let location =
        ImageLocation { space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 3 } }, offset: 0 };
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location.clone(), vec![0; 50]).expect("seeded reserve fits");
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlRelSegment(LdCtrlRelSegment { lsm_idx: Some(3), size: 2, ..Default::default() }),
            LoadControl::LdCtrlWriteRelMem(zweidraehte_ets_files::schema::LdCtrlWriteRelMem {
                obj_idx: Some(3),
                offset: 0,
                size: 1_048_576,
                verify: true,
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let spans = [CompiledTableSpan { kind: CompiledTableKind::GroupObject, location, len: 4 }];

    let normalized = compile_procedure_with_tables(
        ProcedureCompileContext {
            profile,
            procedure_id: root_path().procedure,
            composition: crate::commissioning::compiler::selection::ProcedureComposition::Default,
            procedure,
            product_merge_fragments: Vec::new(),
            parameter_values: BTreeMap::new(),
            applicability: crate::commissioning::compiler::selection::ProcedureApplicability::full(),
            image,
            property_image_facts: Vec::new(),
            relative_memory_facts: vec![(ObjectSelector::Index { index: 3 }, 7)],
            progress_messages_by_reference: BTreeMap::new(),
            progress_messages_by_id: BTreeMap::new(),
            initial_tool_state: ToolState::default(),
            restart_kind: RestartKind::Basic,
            application_identity: ApplicationIdentity::default(),
            extension_operations: Vec::new(),
        },
        &spans,
    )
    .expect("the group object allocation binds against its encoded table");
    let sizes: Vec<_> = normalized
        .steps
        .iter()
        .filter_map(|step| match &step.operation {
            ProcedureOperation::LoadRecord(record) => match &record.effect {
                LoadEffect::Invalidate { length, .. } => Some(*length),
                _ => None,
            },
            _ => None,
        })
        .collect();

    assert_eq!(sizes, [4]);
    let written: Vec<_> = normalized
        .steps
        .iter()
        .filter_map(|step| match &step.operation {
            ProcedureOperation::Write { extent, .. } => Some(extent.byte_length),
            _ => None,
        })
        .collect();
    assert_eq!(written, [4]);
}

#[test]
fn allocation_binding_keeps_its_source_when_features_precede_loading() {
    let mut image = SparseDeviceImage::new();
    image
        .apply_owned(
            ImageLocation {
                space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 3 } },
                offset: 5,
            },
            vec![0; 4],
        )
        .expect("relative image fits");
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: Some(3), ..Default::default() }),
            LoadControl::LdCtrlRelSegment(LdCtrlRelSegment { lsm_idx: Some(3), size: 2, ..Default::default() }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let features = ["first", "second"]
        .into_iter()
        .map(|label| ModuleProcedureFragment {
            source: "allocation-feature-order",
            section: zweidraehte_project::ProgrammingSection::Configuration,
            phase: ProcedureCompilationPhase::BeforeFirstStartLoading,
            operation: ProcedureOperation::ProgressText(label.to_owned()),
            secure_only: false,
        })
        .collect();
    let program = compile_fixture_with_image(procedure, features, image).expect("features and allocation bind");
    assert!(matches!(&program.steps[1].operation, ProcedureOperation::ProgressText(text) if text == "first"));
    assert!(matches!(&program.steps[2].operation, ProcedureOperation::ProgressText(text) if text == "second"));
    let allocation = &program.steps[4];
    assert_eq!(allocation.path.control_indices, [2]);
    assert!(matches!(&allocation.operation, ProcedureOperation::LoadRecord(record)
        if matches!(record.effect, LoadEffect::Invalidate { length: 9, .. })));
}

#[test]
fn image_backed_memory_write_drops_empty_range_and_splits_sparse_intersections() {
    let mut table_only = SparseDeviceImage::new();
    table_only.apply_owned(ImageLocation::standard_memory(0x0100), vec![0x11; 0x0100]).expect("table page fits");
    let empty_window = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            // This mirrors the parameterless BCU2 case: the maximum
            // window begins immediately after the table page and owns no
            // desired-image bytes.
            LoadControl::LdCtrlWriteMem(LdCtrlWriteMem {
                address: 0x0200,
                size: 0x0270,
                verify: true,
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };

    let normalized = compile_fixture_with_image(empty_window, Vec::new(), table_only.clone())
        .expect("an unowned maximum window is eliminated");
    assert_eq!(normalized.steps.len(), 2);

    let mut image = table_only;
    image.apply_owned(ImageLocation::standard_memory(0x0205), vec![0x22, 0x23]).expect("first parameter run fits");
    image.apply_owned(ImageLocation::standard_memory(0x0210), vec![0x31]).expect("second parameter run fits");
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlWriteMem(LdCtrlWriteMem {
                address: 0x0200,
                size: 0x20,
                verify: true,
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };

    let normalized = compile_fixture_with_image(procedure, Vec::new(), image)
        .expect("sparse auto writes finalize against the active image");

    assert_eq!(normalized.steps.len(), 3, "one source control owns all sparse transfers");
    let ProcedureOperation::Write {
        target: OperationTarget::Memory { service: MemoryService::Classic, address: MemoryAddress::Fixed(address) },
        data: OperationData::ImageWindow { location, maximum },
        extent,
        ..
    } = &normalized.steps[1].operation
    else {
        panic!("sparse transfer window")
    };
    assert_eq!((*address, location.offset, *maximum, extent.byte_length), (0x0200, 0x0200, 0x20, 0x11));
}

#[test]
fn empty_image_backed_relative_write_needs_no_property_resolution() {
    for size in [0, 4096] {
        let procedure = LoadProcedure {
            merge_id: None,
            controls: vec![
                LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                LoadControl::LdCtrlWriteRelMem(LdCtrlWriteRelMem {
                    obj_idx: Some(4),
                    size,
                    verify: true,
                    ..Default::default()
                }),
                LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
            ],
        };

        let normalized = compile_fixture_with_image(procedure, Vec::new(), SparseDeviceImage::new())
            .expect("an empty optional image fragment is eliminated before resource resolution");

        assert_eq!(normalized.steps.len(), 2);
        assert!(matches!(normalized.steps[0].operation, ProcedureOperation::Connect));
        assert!(matches!(normalized.steps[1].operation, ProcedureOperation::Disconnect));
    }
}
