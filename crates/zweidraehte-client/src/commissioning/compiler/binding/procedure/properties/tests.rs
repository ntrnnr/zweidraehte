use crate::commissioning::catalog::profile::testing::{append_xml, declare_property};
use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence};
use crate::commissioning::compiler::binding::procedure::test_support::{
    ProcedureCompileContext, PropertyImageFact, compile_procedure, minimal_profile, root_path,
};
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
use crate::commissioning::image::{ImageLocation, ImageSpace, SparseDeviceImage};
use crate::commissioning::input::ProgramSections;
use crate::commissioning::procedure::{
    Comparison, ComparisonPadding, OperationData, ProcedureOperation, ProcedureSourceId, RestartKind, ToolState,
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
fn load_image_property_tags_the_exact_download_stamp() {
    let object = ObjectSelector::Index { index: 3 };
    let location = ImageLocation { space: ImageSpace::Property { object: object.clone(), property_id: 27 }, offset: 0 };
    let mut profile = minimal_profile();
    append_xml(
        &mut profile,
        "Resources",
        r#"<Resource Name="ApplicationStamp"><Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="27" StartAddress="0"/><ResourceType Length="8" Flavour="Stamp_SystemB"/><AccessRights Read="Runtime" Write="None"/></Resource>"#,
    );
    let resource_id = profile.resource("ApplicationStamp").expect("resource lookup").expect("stamp").id;
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
            image_location: location,
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

    let ProcedureOperation::ReadIntoImage { capture_as, .. } = &normalized.steps[1].operation else {
        panic!("second operation reads the stamp");
    };
    assert_eq!(capture_as, &Some(resource_id));
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
