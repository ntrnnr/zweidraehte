use crate::commissioning::catalog::profile::testing::{append_xml, declare_property, edit_profile, fixture_profile};
use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence};
use crate::commissioning::compiler::binding::procedure::test_support::{
    ProcedureCompileContext, compile_fixture, compile_fixture_with_profile,
    compile_fixture_with_profile_and_composition, compile_procedure, minimal_profile, root_path,
};
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
use crate::commissioning::image::SparseDeviceImage;
use crate::commissioning::procedure::operands::PropertyAddress;
use crate::commissioning::procedure::{
    Comparison, OperationData, OperationExtent, OperationTarget, ProcedureOperation, RestartKind, ToolState,
    WriteIntent,
};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ApplicationIdentity;
use zweidraehte_ets_files::schema::{
    LdCtrlCompareProp, LdCtrlConnect, LdCtrlDisconnect, LdCtrlLoadImageProp, LdCtrlWriteProp, LoadControl,
    LoadProcedure,
};

#[test]
fn absent_property_reads_bind_their_read_width_and_keep_dependent_references() {
    let object = ObjectSelector::Index { index: 4 };
    let mut profile = minimal_profile();
    declare_property(&mut profile, &object, 161, 2, 3);

    for inline in [None, Some("A0A1A2A3A4A5".to_owned())] {
        let procedure = LoadProcedure {
            merge_id: None,
            controls: vec![
                LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                    obj_idx: Some(4),
                    prop_id: 161,
                    start_element: Some(3),
                    count: Some(2),
                    ..Default::default()
                }),
                LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                    obj_idx: Some(4),
                    prop_id: 161,
                    start_element: Some(3),
                    count: Some(2),
                    inline_data: inline.clone(),
                    ..Default::default()
                }),
            ],
        };

        let normalized = compile_fixture_with_profile(profile.clone(), procedure, Vec::new(), SparseDeviceImage::new())
            .expect("known read metadata can allocate a missing working window");
        let ProcedureOperation::LoadImage { image_location, extent, alignment, .. } = &normalized.steps[0].operation
        else {
            panic!("first control is a working-image load");
        };

        assert_eq!(image_location.space, crate::commissioning::image::ImageSpace::Property {
            object: object.clone(),
            property_id: 161
        });
        assert_eq!(image_location.offset, 6);
        assert_eq!(extent.byte_length, 6);
        assert_eq!(extent.property_elements, Some(2));
        assert_eq!(*alignment, 3);

        let ProcedureOperation::Compare { comparison, .. } = &normalized.steps[1].operation else {
            panic!("second control is the dependent comparison");
        };
        match comparison {
            Comparison::ImageExact { location, length, .. } => {
                assert!(inline.is_none());
                assert_eq!(location, image_location);
                assert_eq!(*length, 6);
            }
            Comparison::Exact { data: OperationData::Buffer { location, length, fallback }, .. } => {
                assert!(inline.is_some());
                assert_eq!(location, image_location);
                assert_eq!(*length, 6);
                assert_eq!(fallback.as_deref(), Some(&[0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5][..]));
            }
            other => panic!("working reference was lost: {other:?}"),
        }
    }
}

#[test]
fn one_property_binding_keeps_read_and_write_widths_distinct() {
    let mut profile = minimal_profile();
    declare_property(&mut profile, &ObjectSelector::Index { index: 4 }, 161, 2, 3);
    append_xml(
        &mut profile,
        "Resources",
        r#"<Resource Name="Value"><Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="161" StartAddress="0"/><ResourceType Length="2"/></Resource>"#,
    );
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(Default::default()),
            LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                obj_idx: Some(4),
                prop_id: 161,
                inline_data: Some("010200".to_owned()),
                ..Default::default()
            }),
            LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                obj_idx: Some(4),
                prop_id: 161,
                inline_data: Some("010203".to_owned()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(Default::default()),
        ],
    };
    let program = compile_fixture_with_profile(profile, procedure, Vec::new(), SparseDeviceImage::new())
        .expect("directional PDT widths bind independently");
    assert!(matches!(&program.steps[1].operation, ProcedureOperation::Write {
        data: OperationData::Inline(bytes), extent: OperationExtent { byte_length: 2, property_elements: Some(1) }, ..
    } if bytes == &[1, 2]));
    assert!(matches!(&program.steps[2].operation, ProcedureOperation::Compare {
        comparison: Comparison::Exact { data: OperationData::Buffer { length: 3, .. }, .. },
        extent: OperationExtent { byte_length: 3, property_elements: Some(1) },
        ..
    }));
}

#[test]
fn another_property_occurrence_cannot_supply_or_invalidate_geometry() {
    let mut profile = minimal_profile();
    declare_property(&mut profile, &ObjectSelector::Type { object_type: 11, occurrence: Occurrence::Zero }, 161, 2, 2);
    append_xml(
        &mut profile,
        "Resources",
        r#"<Resource Name="OtherOccurrence" Access="unknown"><Location AddressSpace="Property" InterfaceObjectRef="11" Occurrence="1" PropertyID="161" StartAddress="0"/><ResourceType Length="9"/></Resource>"#,
    );
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(Default::default()),
            LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                obj_type: Some(11),
                occurrence: Some(0),
                prop_id: 161,
                inline_data: Some("0102".to_owned()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(Default::default()),
        ],
    };
    let program = compile_fixture_with_profile(profile, procedure, Vec::new(), SparseDeviceImage::new())
        .expect("an unused occurrence is not selected");
    assert!(matches!(&program.steps[1].operation, ProcedureOperation::Write {
        extent: OperationExtent { byte_length: 2, .. },
        ..
    }));
}

#[test]
fn read_only_property_does_not_require_a_unique_unused_write_width() {
    let mut profile = minimal_profile();
    append_xml(
        &mut profile,
        "InterfaceObjects",
        r#"<InterfaceObject Index="4"><Property PropertyID="162" PropertyDataType="WIDTH1 WIDTH3"/></InterfaceObject>"#,
    );
    edit_profile(&mut profile, |xml| {
        xml.replace("</PropertyDataTypes>", r#"<PropertyDataType Id="WIDTH1" Name="WIDTH1" Size="1" ReadSize="2"/><PropertyDataType Id="WIDTH3" Name="WIDTH3" Size="3" ReadSize="2"/></PropertyDataTypes>"#)
    });
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(Default::default()),
            LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                obj_idx: Some(4),
                prop_id: 162,
                inline_data: Some("0102".to_owned()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(Default::default()),
        ],
    };
    let program = compile_fixture_with_profile(profile, procedure, Vec::new(), SparseDeviceImage::new())
        .expect("both PDT alternatives have the same read width");
    assert!(matches!(&program.steps[1].operation, ProcedureOperation::Compare {
        extent: OperationExtent { byte_length: 2, property_elements: Some(1) },
        ..
    }));
}

#[test]
fn bcu2_global_service_control_pdt_truncates_ten_byte_default() {
    let mut profile = fixture_profile(
        "MV-0021",
        "Bcu2",
        "MT-0",
        r#"<Resources></Resources><InterfaceObjects><InterfaceObject Index="0" ObjectType="0"/></InterfaceObjects>"#,
    );

    // MV-0021 does not list PID_SERVICE_CONTROL on its Device Object.
    // Its selected write resolves this PDT-4 shape from the global property
    // catalogue; the interface object itself declares no property geometry.
    edit_profile(&mut profile, |xml| {
        xml.replacen("<PropertyDataTypes>", r#"<InterfaceObjectProperties><InterfaceObjectProperty Id="PID-0-8" Number="8" ObjectType="OT-0" Name="PID_SERVICE_CONTROL" PDT="PDT-4"/></InterfaceObjectProperties><PropertyDataTypes><PropertyDataType Id="PDT-4" Number="4" Name="PDT_UNSIGNED_INT" Size="2"/>"#, 1)
    });
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                obj_idx: Some(0),
                prop_id: 8,
                verify: false,
                inline_data: Some("00000000000000000000".to_owned()),
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
    .expect("global PID_SERVICE_CONTROL metadata fixes the BCU2 wire width");

    let ProcedureOperation::Write { target, data, extent, policy } = &normalized.steps[1].operation else {
        panic!("second control is the service-control property write");
    };
    assert_eq!(target, &OperationTarget::Property {
        address: PropertyAddress::Indexed { object_index: 0, property_id: 8 },
        start_element: 1,
    });
    assert_eq!(data, &OperationData::Inline(vec![0, 0]));
    assert_eq!(*extent, OperationExtent::property(2, 1));
    assert_eq!(*policy, WriteIntent::Property { verify: false });
}

#[test]
fn property_pdt_truncates_inline_padding_but_rejects_short_values() {
    let mut profile = minimal_profile();
    declare_property(&mut profile, &ObjectSelector::Index { index: 4 }, 27, 8, 8);
    let compile = |inline_data: &str| {
        compile_procedure(ProcedureCompileContext {
            profile: profile.clone(),
            procedure_id: root_path().procedure,
            composition: ProcedureComposition::Merged,
            procedure: LoadProcedure {
                merge_id: None,
                controls: vec![
                    LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                    LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                        obj_idx: Some(4),
                        prop_id: 27,
                        inline_data: Some(inline_data.to_owned()),
                        ..Default::default()
                    }),
                    LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
                ],
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
            application_identity: ApplicationIdentity::default(),
            extension_operations: Vec::new(),
        })
    };

    let normalized =
        compile("00000014003200000000").expect("ten-byte System B MCB buffer is constrained to its eight-byte PDT");
    let ProcedureOperation::Write { data: OperationData::Inline(data), extent, policy, .. } =
        &normalized.steps[1].operation
    else {
        panic!("second control is the property write");
    };
    assert_eq!(data.as_slice(), [0, 0, 0, 0x14, 0, 0x32, 0, 0]);
    assert_eq!(extent.byte_length, 8);
    assert_eq!(extent.property_elements, Some(1));
    assert_eq!(*policy, WriteIntent::Property { verify: false });

    let error = compile("00000014003200").expect_err("PDT padding cannot invent missing wire bytes");
    assert!(error.to_string().contains("has only 7 bytes"));
}

#[test]
fn inline_property_write_uses_its_authored_width_when_metadata_is_absent() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                obj_idx: Some(7),
                prop_id: 161,
                inline_data: Some("01".to_owned()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };

    let normalized =
        compile_fixture(procedure, Vec::new()).expect("an exact vendor-property write can retain its authored width");
    let ProcedureOperation::Write { extent, .. } = &normalized.steps[1].operation else {
        panic!("second control is the property write");
    };

    assert_eq!(extent.byte_length, 1);
    assert_eq!(extent.property_elements, Some(1));
}

#[test]
fn inline_property_compare_uses_its_authored_width_when_metadata_is_absent() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                obj_idx: Some(7),
                prop_id: 162,
                inline_data: Some("01".to_owned()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };

    let normalized = compile_fixture(procedure, Vec::new())
        .expect("a read-only vendor-property comparison can retain its authored width");
    let ProcedureOperation::Compare { extent, .. } = &normalized.steps[1].operation else {
        panic!("second control is the property comparison");
    };

    assert_eq!(extent.byte_length, 1);
    assert_eq!(extent.property_elements, Some(1));
}
