use super::*;

#[test]
fn system_b_stamp_reads_keep_all_controls_but_output_only_final_eligible_properties() {
    let (mut profile, _) = system_b_stamp_procedure();
    for index in 1..=4 {
        crate::commissioning::catalog::profile::testing::declare_property(
            &mut profile,
            &ObjectSelector::Index { index },
            27,
            8,
            8,
        );
    }
    let mut controls = vec![LoadControl::LdCtrlConnect(Default::default())];
    controls.extend((1..=4).map(|index| {
        LoadControl::LdCtrlLoadImageProp(zweidraehte_ets_files::schema::LdCtrlLoadImageProp {
            obj_idx: Some(index),
            prop_id: 27,
            ..Default::default()
        })
    }));
    controls.push(LoadControl::LdCtrlRestart(Default::default()));

    for omit_last_read in [false, true] {
        let mut selected = controls.clone();
        if omit_last_read {
            selected.remove(4);
        }
        let parsed = parse_stamp_controls(&profile, selected);
        for step in &parsed.program.steps[1..parsed.program.steps.len() - 1] {
            assert!(
                matches!(&step.operation, ProcedureOperation::LoadImage {
                    target: OperationTarget::Property {
                        address: PropertyAddress::Indexed { object_index: 1..=4, property_id: 27 },
                        start_element: 1
                    },
                    extent: OperationExtent {
                        byte_length: 8,
                        property_elements: Some(1),
                        property_element_width: None
                    },
                    alignment: 8,
                    ..
                }),
                "runtime stamps retain native image reads even outside the output interval"
            );
        }
        let expected = parsed.program.clone();
        let procedure = parsed.finish(&profile, &SparseDeviceImage::new(), false).expect("authored stamp reads remain");
        assert_eq!(procedure, expected, "a final-image policy cannot manufacture an omitted read");
        let DownloadStampOutput::ImageProperties(bindings) = &procedure.stamp_output else {
            panic!("System B uses final image properties")
        };
        // Only records the procedure reads have a final image segment.
        let expected: &[&str] = if omit_last_read { &["Stamp3"] } else { &["Stamp3", "Stamp4"] };
        assert_eq!(bindings.iter().map(|binding| binding.id.0.as_str()).collect::<Vec<_>>(), expected);
    }
}

#[test]
fn procedures_without_stamp_reads_publish_no_stamp() {
    // M-00FA product procedures load and restart without any
    // `LdCtrlLoadImageProp`; the reference's final image then has no PID 27
    // segment, and it extracts no stamp.
    let (profile, _) = system_b_stamp_procedure();
    let parsed = parse_stamp_controls(&profile, vec![
        LoadControl::LdCtrlConnect(Default::default()),
        LoadControl::LdCtrlRestart(Default::default()),
    ]);
    assert_eq!(parsed.program.stamp_output, DownloadStampOutput::None);
}

#[test]
fn disabled_system_b_stamp_output_keeps_an_ordinary_image_read() {
    let (mut profile, _) = system_b_stamp_procedure();
    crate::commissioning::catalog::profile::testing::edit_profile(&mut profile, |xml| {
        xml.replace(r#"Name="DownloadStamp" Value="1""#, r#"Name="DownloadStamp" Value="0""#)
    });
    crate::commissioning::catalog::profile::testing::declare_property(
        &mut profile,
        &ObjectSelector::Index { index: 1 },
        27,
        8,
        8,
    );
    let parsed = parse_stamp_controls(&profile, vec![
        LoadControl::LdCtrlConnect(Default::default()),
        LoadControl::LdCtrlLoadImageProp(zweidraehte_ets_files::schema::LdCtrlLoadImageProp {
            obj_idx: Some(1),
            prop_id: 27,
            ..Default::default()
        }),
        LoadControl::LdCtrlRestart(Default::default()),
    ]);
    // Without stamp output the read still only fills unowned image bytes;
    // nothing stages the stamp's device value.
    assert!(matches!(&parsed.program.steps[1].operation, ProcedureOperation::LoadImage {
        target: OperationTarget::Property {
            address: PropertyAddress::Indexed { object_index: 1, property_id: 27 },
            start_element: 1
        },
        extent: OperationExtent { byte_length: 8, property_elements: Some(1), property_element_width: None },
        alignment: 8,
        ..
    }));
    let inventory = crate::commissioning::catalog::rules::resolved_download_stamp_resources(
        &profile,
        StandardMemoryService::Classic,
    )
    .expect("disabled output has no candidates");
    assert!(inventory.is_empty());
    assert_eq!(
        crate::commissioning::catalog::rules::resolved_download_stamp_output(&profile, inventory)
            .expect("output policy"),
        DownloadStampOutput::None
    );
}

#[test]
fn system_b_rejects_unbound_owned_stamp_properties_before_execution() {
    let (mut profile, original) = system_b_stamp_procedure();
    let location = ImageLocation {
        space: ImageSpace::Property { object: ObjectSelector::Index { index: 5 }, property_id: 27 },
        offset: 0,
    };
    append_xml(
        &mut profile,
        "Resources",
        r#"<Resource Name="PeiprogStamp" Optional="true"><Location AddressSpace="SystemProperty" InterfaceObjectRef="5" PropertyID="27" StartAddress="0"/><ResourceType Length="8" Flavour="Stamp_SystemB"/><AccessRights Read="Runtime" Write="None"/></Resource>"#,
    );
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location, vec![0x12; 8]).expect("initial stamp image applies");

    let error = configure_stamp_fixture(&profile, &image, &mut original.clone())
        .expect_err("AP1-only output cannot bind a PEI stamp");
    assert!(error.to_string().contains("no final output resource binding"));

    // A fully owned property with an incomplete trailing record also
    // fails before execution, even when no read touches that property.
    let mut procedure = original;
    procedure.steps.remove(4);
    let location = ImageLocation {
        space: ImageSpace::Property { object: ObjectSelector::Index { index: 4 }, property_id: 27 },
        offset: 0,
    };
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location, vec![0x34; 9]).expect("incomplete initial stamp image applies");
    assert!(
        configure_stamp_fixture(&profile, &image, &mut procedure)
            .expect_err("owned stamp bytes must contain whole records")
            .to_string()
            .contains("whole output records")
    );
}

#[test]
fn system_b_rejects_explicit_image_reads_without_eligible_stamp_bindings() {
    let (mut profile, mut procedure) = system_b_stamp_procedure();
    append_xml(
        &mut profile,
        "Resources",
        r#"<Resource Name="PeiprogStamp" Optional="true"><Location AddressSpace="SystemProperty" InterfaceObjectRef="5" PropertyID="27" StartAddress="0"/><ResourceType Length="8" Flavour="Stamp_SystemB"/><AccessRights Read="Runtime" Write="None"/></Resource>"#,
    );
    let mut step = procedure.steps[4].clone();
    step.path.contribution = Some("stamp-image-extension");
    step.source_control_code = None;
    step.operation = ProcedureOperation::LoadImage {
        target: OperationTarget::Property {
            address: PropertyAddress::Indexed { object_index: 5, property_id: 27 },
            start_element: 1,
        },
        image_location: ImageLocation {
            space: ImageSpace::Property { object: ObjectSelector::Index { index: 5 }, property_id: 27 },
            offset: 0,
        },
        extent: OperationExtent::property(8, 1),
        alignment: 8,
    };
    procedure.steps.insert(5, step);
    let error = configure_stamp_fixture(&profile, &SparseDeviceImage::new(), &mut procedure)
        .expect_err("explicit LoadImage requires its final output binding");
    assert!(error.to_string().contains("no final output resource binding"));
}

#[test]
fn system_b_stamp_read_requires_absent_or_complete_initial_property_records() {
    let (profile, original) = system_b_stamp_procedure();
    let ProcedureOperation::LoadImage { image_location, .. } = &original.steps[1].operation else {
        panic!("fixture starts with a stamp read")
    };
    for length in [4, 9] {
        let mut image = SparseDeviceImage::new();
        image.apply_owned(image_location.clone(), vec![0x12; length]).expect("initial image applies");
        assert!(configure_stamp_fixture(&profile, &image, &mut original.clone()).is_err());
    }
    for owned in [false, true] {
        let mut image = SparseDeviceImage::new();
        image.represent_range(image_location, 16).expect("two stamp records fit");
        if owned {
            image.apply_owned(image_location.clone(), vec![0x12; 16]).expect("initial records apply");
        }
        configure_stamp_fixture(&profile, &image, &mut original.clone())
            .expect("a first-record read preserves the complete two-record property buffer");
    }
    let mut image = SparseDeviceImage::new();
    let patch = crate::commissioning::ImageSegment::new(image_location.clone(), vec![0x12; 8], vec![0x0f; 8])
        .expect("mixed mask segment is valid");
    image.apply(&patch);
    configure_stamp_fixture(&profile, &image, &mut original.clone())
        .expect("one exact segment preserves native boundaries");

    let mut image = SparseDeviceImage::new();
    let patch = crate::commissioning::ImageSegment::new(image_location.clone(), vec![0x12; 8], vec![
        0xff, 0xff, 0, 0, 0xff, 0xff, 0xff, 0xff,
    ])
    .expect("sparse patch is valid");
    image.apply(&patch);
    assert!(configure_stamp_fixture(&profile, &image, &mut original.clone()).is_err());
}

fn configure_stamp_fixture(
    profile: &crate::commissioning::ResolvedProfile,
    image: &SparseDeviceImage,
    program: &mut NormalizedProcedure,
) -> Result<(), CompileError> {
    let stamps = crate::commissioning::catalog::rules::resolved_download_stamp_resources(
        profile,
        StandardMemoryService::Classic,
    )?;
    program.stamp_output = crate::commissioning::catalog::rules::resolved_download_stamp_output(profile, stamps)?;
    validate_download_stamp_output(profile, image, program)
}

fn parse_stamp_controls(
    profile: &crate::commissioning::ResolvedProfile,
    controls: Vec<LoadControl>,
) -> crate::commissioning::compiler::binding::procedure::ParsedProcedure {
    let input = ProcedureInput {
        profile,
        procedure_id: ProcedureSourceId::Generated { name: "stamp-fixture".into() },
        composition: ProcedureComposition::Default,
        controls: &controls,
        product_merge_fragments: Vec::new(),
        secondary_merge_fragments: Vec::new(),
        secondary_product_procedure: None,
        secondary_application_id: None,
        module_procedures_are_empty: false,
        module_procedures: Vec::new(),
        omitted_controls: Vec::new(),
        parameter_values: &BTreeMap::new(),
        applicability: ProcedureApplicability::full(),
        configuration_anchor: profile.configuration_anchor(),
        download_stamps: crate::commissioning::catalog::rules::resolved_download_stamp_resources(
            profile,
            StandardMemoryService::Classic,
        )
        .expect("stamp inventory resolves"),
        property_parameters: &[],
        peiprog_identity_reference: false,
        application_program_2_present: false,
        progress_messages_by_reference: &BTreeMap::new(),
        progress_messages_by_id: &BTreeMap::new(),
        message_sources: Vec::new(),
        initial_tool_state: ToolState::default(),
        standard_memory_service: StandardMemoryService::Classic,
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        secondary_application_identity: None,
        extended_property_descriptions: false,
    };
    let mut parsed = crate::commissioning::compiler::binding::procedure::parse(&input).expect("stamp controls parse");
    let stamps = crate::commissioning::catalog::rules::stamps_read_by_procedure(
        &parsed.program.steps,
        input.download_stamps.clone(),
    );
    parsed.program.stamp_output = crate::commissioning::catalog::rules::resolved_download_stamp_output(profile, stamps)
        .expect("stamp output resolves");
    parsed
}
