use crate::commissioning::catalog::profile::testing::{append_xml, declare_property, edit_profile};
use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence};
use crate::commissioning::compiler::binding::procedure::test_support::{
    ProcedureCompileContext, PropertyImageFact, compile_procedure, minimal_profile, root_path,
};
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
use crate::commissioning::image::{ImageLocation, ImageSpace, SparseDeviceImage};
use crate::commissioning::input::ProgramSections;
use crate::commissioning::procedure::{
    CachePolicy, Comparison, ComparisonPadding, DescribedPropertyAction, DescribedPropertyOperation, OperationData,
    OperationExtent, ProcedureOperation, ProcedureSourceId, RestartKind, ToolState, WriteIntent,
};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ApplicationIdentity;
use zweidraehte_ets_files::schema::{
    LdCtrlCompareProp, LdCtrlConnect, LdCtrlDisconnect, LdCtrlLoadImageProp, LdCtrlWriteProp, LoadControl,
    LoadProcedure,
};

#[test]
fn system7_property_identity_compares_only_its_read_prefix() {
    let expected = "00FA0000000A11223344";
    let mut profile = minimal_profile();
    declare_property(&mut profile, &ObjectSelector::Index { index: 0 }, 78, 6, 6);
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                obj_idx: Some(0),
                prop_id: 78,
                inline_data: Some(expected.to_owned()),
                mask: Some("FF0FFFFFFFFFFFFFFFFF".into()),
                time_out: Some(u16::MAX),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let normalized = compile_procedure(ProcedureCompileContext {
        profile,
        procedure_id: ProcedureSourceId::Product {
            product_id: "M-0083_A-SYSTEM7".to_owned(),
            source_index: 0,
            merge_id: None,
        },
        composition: ProcedureComposition::ProductOwned,
        procedure,
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
        application_identity: ApplicationIdentity::default(),
        extension_operations: Vec::new(),
    })
    .expect("padded System 7 identity comparison compiles");

    let ProcedureOperation::Compare { comparison, extent, timeout_milliseconds, .. } = &normalized.steps[1].operation
    else {
        panic!("second control is the property comparison");
    };
    assert_eq!(*timeout_milliseconds, Some(65_535_000));
    let Comparison::Exact { data: OperationData::Buffer { fallback: Some(data), length, .. }, mask, padding } =
        comparison
    else {
        panic!("property identity retains its authored comparison fallback");
    };

    assert_eq!(*length, 6);
    assert_eq!(data, &[0x00, 0xfa, 0x00, 0x00, 0x00, 0x0a]);
    assert_eq!(mask.as_deref(), Some([0xff, 0x0f, 0xff, 0xff, 0xff, 0xff].as_slice()));
    assert_eq!(extent.byte_length, 6);
    assert_eq!(*padding, ComparisonPadding::None);
}

#[test]
fn image_only_property_comparison_clips_reference_and_mask_to_read_geometry() {
    let object = ObjectSelector::Index { index: 0 };
    let location = ImageLocation { space: ImageSpace::Property { object: object.clone(), property_id: 78 }, offset: 0 };
    let mut profile = minimal_profile();
    declare_property(&mut profile, &object, 78, 10, 6);
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location.clone(), (0x40..0x4a).collect()).unwrap();
    let normalized = compile_procedure(ProcedureCompileContext {
        profile,
        procedure_id: root_path().procedure,
        composition: ProcedureComposition::Default,
        procedure: LoadProcedure {
            merge_id: None,
            controls: vec![
                LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                    obj_idx: Some(0),
                    prop_id: 78,
                    mask: Some("FF0FFFFFFFFFFFFFFFFF".into()),
                    ..Default::default()
                }),
                LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
            ],
        },
        product_merge_fragments: Vec::new(),
        parameter_values: BTreeMap::new(),
        applicability: ProcedureApplicability::full(),
        image,
        property_image_facts: vec![PropertyImageFact {
            object,
            property_id: 78,
            first_element: 1,
            element_size: 10,
            image_location: location.clone(),
        }],
        relative_memory_facts: Vec::new(),
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
        initial_tool_state: ToolState::default(),
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        extension_operations: Vec::new(),
    })
    .expect("native read geometry clips a longer reference");
    let ProcedureOperation::Compare {
        comparison: Comparison::ImageExact { location: actual, length, mask },
        extent,
        ..
    } = &normalized.steps[1].operation
    else {
        panic!("image-only reference remains distinct from a transfer buffer")
    };
    assert_eq!(actual, &location);
    assert_eq!(*length, 6);
    assert_eq!(extent.byte_length, 6);
    assert_eq!(mask.as_deref(), Some([255, 15, 255, 255, 255, 255].as_slice()));
}

#[test]
fn property_comparisons_overlay_only_image_owned_reference_bits() {
    use crate::commissioning::image::ImageSegment;

    for object in [ObjectSelector::Index { index: 0 }, ObjectSelector::Type {
        object_type: 0,
        occurrence: Occurrence::from_option(Some(0)),
    }] {
        for ownership in [0, 0x0f, 0xff] {
            let location =
                ImageLocation { space: ImageSpace::Property { object: object.clone(), property_id: 78 }, offset: 0 };
            let mut profile = minimal_profile();
            declare_property(&mut profile, &object, 78, 6, 6);
            let mut image = SparseDeviceImage::new();
            image.apply(
                &ImageSegment::new(location.clone(), vec![0x40, 0x41, 0x42, 0x43, 0x44, 0x45], vec![ownership; 6])
                    .unwrap(),
            );
            let mut control = LdCtrlCompareProp {
                prop_id: 78,
                inline_data: Some("A0A1A2A3A4A5FFFF".into()),
                mask: Some("FF0FFFFFFFFFFFFF".into()),
                ..Default::default()
            };
            match object {
                ObjectSelector::Index { index } => control.obj_idx = Some(u8::try_from(index).unwrap()),
                ObjectSelector::Type { object_type, .. } => {
                    control.obj_type = Some(object_type);
                    control.occurrence = Some(0);
                }
            }
            let normalized = compile_procedure(ProcedureCompileContext {
                profile,
                procedure_id: root_path().procedure,
                composition: ProcedureComposition::Default,
                procedure: LoadProcedure {
                    merge_id: None,
                    controls: vec![
                        LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                        LoadControl::LdCtrlCompareProp(control),
                        LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
                    ],
                },
                product_merge_fragments: Vec::new(),
                parameter_values: BTreeMap::new(),
                applicability: ProcedureApplicability::full(),
                image: image.clone(),
                property_image_facts: vec![PropertyImageFact {
                    object: object.clone(),
                    property_id: 78,
                    first_element: 1,
                    element_size: 6,
                    image_location: location.clone(),
                }],
                relative_memory_facts: Vec::new(),
                progress_messages_by_reference: BTreeMap::new(),
                progress_messages_by_id: BTreeMap::new(),
                initial_tool_state: ToolState::default(),
                restart_kind: RestartKind::Basic,
                application_identity: ApplicationIdentity::default(),
                extension_operations: Vec::new(),
            })
            .expect("property image reference binds");
            let ProcedureOperation::Compare {
                comparison:
                    Comparison::Exact {
                        data: OperationData::Buffer { location: actual, length, fallback: Some(reference) },
                        mask,
                        padding,
                    },
                extent,
                ..
            } = &normalized.steps[1].operation
            else {
                panic!("property reference retains working-image fallback")
            };
            assert_eq!(actual, &location);
            assert_eq!(*length, 6);
            assert_eq!(extent.byte_length, 6);
            assert_eq!(*padding, ComparisonPadding::None);
            assert_eq!(mask.as_deref(), Some([0xff, 0x0f, 0xff, 0xff, 0xff, 0xff].as_slice()));
            let expected: Vec<_> =
                (0..6).map(|index| ((0xa0 + index) & !ownership) | ((0x40 + index) & ownership)).collect();
            assert_eq!(reference, &expected, "{object:?}, ownership {ownership:#04x}");
            // Binding is read-only, including when the image owns no bits.
            for index in 0..6 {
                let cell = ImageLocation { offset: index, ..location.clone() };
                assert_eq!(
                    image.byte(&cell),
                    (ownership != 0).then_some(((0x40 + index as u8) & ownership, ownership))
                );
            }
        }
    }
}

#[test]
fn loaded_property_replaces_the_partial_procedures_compare_placeholder() {
    // System B Load/par snapshots PID_TABLE_REFERENCE before unloading
    // the application machine. The later zero InlineData is the initial
    // value of that tool-side buffer, not an allocation-address check.
    let object = ObjectSelector::Index { index: 4 };
    let location = ImageLocation {
        space: ImageSpace::Property { object: object.clone(), property_id: zweidraehte_proto::pid::TABLE_REFERENCE },
        offset: 0,
    };
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                obj_idx: Some(4),
                prop_id: zweidraehte_proto::pid::TABLE_REFERENCE,
                ..Default::default()
            }),
            LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                obj_idx: Some(4),
                prop_id: zweidraehte_proto::pid::TABLE_REFERENCE,
                inline_data: Some("00000000".to_owned()),
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
        applicability: ProcedureApplicability::partial(ProgramSections::PARAMETERS),
        image: SparseDeviceImage::new(),
        property_image_facts: vec![PropertyImageFact {
            object,
            property_id: zweidraehte_proto::pid::TABLE_REFERENCE,
            first_element: 1,
            element_size: 4,
            image_location: location.clone(),
        }],
        relative_memory_facts: Vec::new(),
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
        initial_tool_state: ToolState::default(),
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        extension_operations: Vec::new(),
    })
    .expect("loaded property comparison compiles without a desired-image range");

    assert!(matches!(&normalized.steps[1].operation,
        ProcedureOperation::LoadImage { alignment: 4, extent, .. }
        if *extent == crate::commissioning::procedure::OperationExtent::property(4, 1)
    ));
    let ProcedureOperation::Compare { comparison, extent, .. } = &normalized.steps[2].operation else {
        panic!("third control compares the loaded property");
    };
    let Comparison::Exact { data: OperationData::Buffer { location: actual, length, .. }, .. } = comparison else {
        panic!("loaded property comparison uses its working-image snapshot");
    };
    assert_eq!(actual, &location);
    assert_eq!(*length, 4);
    assert_eq!(extent.byte_length, 4);
}

#[test]
fn load_image_property_reads_a_stamp_into_the_image_without_a_snapshot() {
    let object = ObjectSelector::Index { index: 3 };
    let location = ImageLocation { space: ImageSpace::Property { object: object.clone(), property_id: 27 }, offset: 0 };
    let mut profile = minimal_profile();
    append_xml(
        &mut profile,
        "Resources",
        r#"<Resource Name="ApplicationStamp"><Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="27" StartAddress="0"/><ResourceType Length="8" Flavour="Stamp_SystemB"/><AccessRights Read="Runtime" Write="None"/></Resource>"#,
    );
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                obj_idx: Some(3),
                prop_id: 27,
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let normalized = compile_procedure(ProcedureCompileContext {
        profile,
        procedure_id: root_path().procedure,
        composition: ProcedureComposition::Default,
        procedure,
        product_merge_fragments: Vec::new(),
        parameter_values: BTreeMap::new(),
        applicability: ProcedureApplicability::full(),
        image: SparseDeviceImage::new(),
        property_image_facts: vec![PropertyImageFact {
            object,
            property_id: 27,
            first_element: 1,
            element_size: 8,
            image_location: location.clone(),
        }],
        relative_memory_facts: Vec::new(),
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
        initial_tool_state: ToolState::default(),
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        extension_operations: Vec::new(),
    })
    .expect("download-stamp read compiles");

    // Outside System B the stamp read is an ordinary image read; the stamp
    // output selects the final image property instead of a staged value.
    assert!(matches!(
        &normalized.steps[1].operation,
        ProcedureOperation::LoadImage {
            image_location,
            extent: crate::commissioning::procedure::OperationExtent { byte_length: 8, property_elements: Some(1) },
            alignment: 8,
            ..
        } if *image_location == location
    ));
}

#[test]
fn compiled_property_value_replaces_master_data_inline_default() {
    // The control omits its occurrence; compiled images use the schema
    // default, occurrence zero.
    let object = ObjectSelector::Type { object_type: 6, occurrence: Occurrence::Zero };
    let location = ImageLocation { space: ImageSpace::Property { object: object.clone(), property_id: 54 }, offset: 0 };
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location.clone(), vec![0x0f]).expect("routing selector patch fits");

    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                obj_type: Some(6),
                prop_id: 54,
                verify: true,
                inline_data: Some("17".to_owned()),
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
        property_image_facts: vec![PropertyImageFact {
            object,
            property_id: 54,
            first_element: 1,
            element_size: 1,
            image_location: location.clone(),
        }],
        relative_memory_facts: Vec::new(),
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
        initial_tool_state: ToolState::default(),
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        extension_operations: Vec::new(),
    })
    .expect("compiled routing selector overrides the generic procedure default");

    let ProcedureOperation::Write { data: OperationData::Buffer { location: actual, length, .. }, .. } =
        &normalized.steps[1].operation
    else {
        panic!("property write uses the compiled image");
    };
    assert_eq!(actual, &location);
    assert_eq!(*length, 1);
}

// An image-backed property write needs image storage. Without any parameter,
// resource or stamp layout for the property the image never holds it, and the
// reference sends nothing; lowering must not invent a zero-length write.
#[test]
fn image_backed_property_write_without_layout_is_omitted() {
    let router = |inline_data: Option<&str>| {
        LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
            obj_type: Some(6),
            prop_id: 51,
            inline_data: inline_data.map(str::to_owned),
            ..Default::default()
        })
    };
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            router(None),
            router(Some("01")),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let normalized = compile_procedure(ProcedureCompileContext {
        profile: minimal_profile(),
        procedure_id: ProcedureSourceId::Product {
            product_id: "M-0083_A-COUPLER".to_owned(),
            source_index: 0,
            merge_id: None,
        },
        composition: ProcedureComposition::ProductOwned,
        procedure,
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
        application_identity: ApplicationIdentity::default(),
        extension_operations: Vec::new(),
    })
    .expect("router writes compile");

    let writes: Vec<_> = normalized
        .steps
        .iter()
        .filter_map(|step| match &step.operation {
            ProcedureOperation::Write { data, .. } => Some(data),
            _ => None,
        })
        .collect();
    assert_eq!(writes, [&OperationData::Inline(vec![0x01])]);
}

#[test]
fn masked_and_type_addressed_untyped_comparisons_are_described() {
    // Witnesses compare manufacturer properties such as index 5 PID 253 with
    // a mask (`FF00000000000000`) or by object type. The reference sizes them
    // like any described comparison and ANDs the mask into the leading bytes.
    let mut profile = minimal_profile();
    edit_profile(&mut profile, |xml| {
        xml.replacen(
            "</PropertyDataTypes>",
            r#"<PropertyDataType Id="PDT-4" Number="4" Name="PDT_UNSIGNED_INT" Size="2" /></PropertyDataTypes>"#,
            1,
        )
    });
    let compare = |obj_idx, obj_type| {
        LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
            obj_idx,
            obj_type,
            prop_id: 201,
            inline_data: Some("989603".into()),
            mask: Some("F0".into()),
            ..Default::default()
        })
    };
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            compare(Some(4), None),
            compare(None, Some(50)),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let normalized = compile_procedure(ProcedureCompileContext {
        profile,
        procedure_id: ProcedureSourceId::Product {
            product_id: "M-0085_A-PEI".to_owned(),
            source_index: 0,
            merge_id: None,
        },
        composition: ProcedureComposition::ProductOwned,
        procedure,
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
        application_identity: ApplicationIdentity::default(),
        extension_operations: Vec::new(),
    })
    .expect("masked described comparisons compile");

    for step in &normalized.steps[1..3] {
        let ProcedureOperation::DescribedProperty(compare) = &step.operation else {
            panic!("the comparison waits for the target's description");
        };
        let Some(ProcedureOperation::Compare { comparison, .. }) = compare.resolve(4).expect("PDT 4 has a width")
        else {
            panic!("three authored octets cover two");
        };
        assert_eq!(comparison, Comparison::Exact {
            data: OperationData::Inline(vec![0x98, 0x96]),
            mask: Some(vec![0xf0, 0xff]),
            padding: ComparisonPadding::None,
        });
    }
}

#[test]
fn untyped_indexed_property_controls_take_their_width_from_the_target_description() {
    // Index 4 has no roster entry here and PID 67/201 no global definition:
    // only the target can say how wide their elements are. Master Data still
    // numbers the PDTs that a property description can report.
    let mut profile = minimal_profile();
    edit_profile(&mut profile, |xml| {
        xml.replacen(
            "</PropertyDataTypes>",
            r#"<PropertyDataType Id="PDT-0" Number="0" Name="PDT_CONTROL" Size="10" ReadSize="1" /><PropertyDataType Id="PDT-2" Number="2" Name="PDT_UNSIGNED_CHAR" Size="1" /><PropertyDataType Id="PDT-4" Number="4" Name="PDT_UNSIGNED_INT" Size="2" /></PropertyDataTypes>"#,
            1,
        )
    });
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                obj_idx: Some(4),
                prop_id: 201,
                inline_data: Some("989603".into()),
                ..Default::default()
            }),
            LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                obj_idx: Some(4),
                prop_id: 67,
                inline_data: Some("01".into()),
                verify: true,
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };
    let normalized = compile_procedure(ProcedureCompileContext {
        profile,
        procedure_id: ProcedureSourceId::Product {
            product_id: "M-0085_A-PEI".to_owned(),
            source_index: 0,
            merge_id: None,
        },
        composition: ProcedureComposition::ProductOwned,
        procedure,
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
        application_identity: ApplicationIdentity::default(),
        extension_operations: Vec::new(),
    })
    .expect("described property controls compile");

    let ProcedureOperation::DescribedProperty(compare) = &normalized.steps[1].operation else {
        panic!("the comparison waits for the target's description");
    };
    let ProcedureOperation::DescribedProperty(write) = &normalized.steps[2].operation else {
        panic!("the write waits for the target's description");
    };
    assert_eq!(compare.elements, 1);
    assert_eq!(compare.widths, BTreeMap::from([(0, 1), (2, 1), (4, 2)]));
    assert_eq!(write.widths, BTreeMap::from([(0, 10), (2, 1), (4, 2)]));
    assert!(matches!(
        &write.action,
        DescribedPropertyAction::Write { payload, policy: WriteIntent::Property { verify: true } } if payload == &[0x01]
    ));

    // A one-octet PDT sends exactly the authored byte.
    let target = write.target.clone();
    assert_eq!(
        write.resolve(2).expect("PDT 2 has a width"),
        Some(ProcedureOperation::Write {
            target: target.clone(),
            data: OperationData::Inline(vec![0x01]),
            extent: OperationExtent::property(1, 1),
            policy: WriteIntent::Property { verify: true },
        })
    );

    // A wider element leaves the authored byte too short: nothing is sent.
    assert_eq!(write.resolve(4).expect("PDT 4 has a width"), None);
    assert_eq!(write.resolve(0).expect("PDT 0 writes ten octets"), None);
    assert!(write.resolve(9).is_err(), "an unknown PDT has no width");

    // A comparison uses only the described prefix of a longer reference.
    let ProcedureOperation::Compare { comparison, extent, cache, .. } =
        compare.resolve(4).expect("PDT 4 has a width").expect("three authored octets cover two")
    else {
        panic!("a described comparison resolves to a comparison");
    };
    assert_eq!(extent, OperationExtent::property(2, 1));
    assert_eq!(cache, CachePolicy::Populate);
    assert_eq!(comparison, Comparison::Exact {
        data: OperationData::Inline(vec![0x98, 0x96]),
        mask: None,
        padding: ComparisonPadding::None,
    });
    assert!(matches!(compare, DescribedPropertyOperation { action: DescribedPropertyAction::Compare { .. }, .. }));
}
