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
fn system7_property_identity_preserves_zero_padded_registration_field() {
    let expected = "00FA0000000A00000000";
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
        secure_only: false,
        extension_operations: Vec::new(),
    })
    .expect("padded System 7 identity comparison compiles");

    let ProcedureOperation::Compare { comparison, extent, timeout_milliseconds, .. } = &normalized.steps[1].operation
    else {
        panic!("second control is the property comparison");
    };
    assert_eq!(*timeout_milliseconds, Some(65_535_000));
    let Comparison::Exact { data: OperationData::Inline(data), padding, .. } = comparison else {
        panic!("property identity is an inline exact comparison");
    };

    assert_eq!(data.len(), 10);
    assert_eq!(extent.byte_length, 6);
    assert_eq!(*padding, ComparisonPadding::ExpectedTrailingZeros);
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
        secure_only: false,
        extension_operations: Vec::new(),
    })
    .expect("loaded property comparison compiles without a desired-image range");

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
        secure_only: false,
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
    let object = ObjectSelector::Type { object_type: 6, occurrence: Occurrence::Absent };
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
        secure_only: false,
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
