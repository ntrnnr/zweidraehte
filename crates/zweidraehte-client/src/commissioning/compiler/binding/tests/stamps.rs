use super::*;

#[test]
fn missing_download_stamp_is_captured_once_before_restart() {
    let profile = fixture_profile(
        "MV-0705",
        "BimM112",
        "MT-0",
        r#"<Features><Feature Name="DownloadStamp" Value="1"/></Features><Resources><Resource Name="ApplicationStamp"><Location AddressSpace="SystemProperty" InterfaceObjectRef="1" PropertyID="7" StartAddress="0"/><ResourceType Length="4" Flavour="Stamp_SystemB"/><AccessRights Read="Runtime" Write="None"/></Resource></Resources><InterfaceObjects></InterfaceObjects>"#,
    );
    let stamp_id = profile.resource("ApplicationStamp").expect("lookup").expect("stamp").id;
    let mut parsed = parse_stamp_controls(&profile, vec![
        LoadControl::LdCtrlConnect(Default::default()),
        LoadControl::LdCtrlRestart(Default::default()),
    ]);
    parsed.capture_download_stamps();
    parsed.capture_download_stamps();
    let procedure = parsed.finish(&profile, &SparseDeviceImage::new(), false).expect("stamp capture precedes restart");

    assert_eq!(procedure.steps.len(), 3);
    assert!(matches!(procedure.steps[0].operation, ProcedureOperation::Connect));
    assert!(matches!(
        &procedure.steps[1].operation,
        ProcedureOperation::ReadIntoImage {
            target: OperationTarget::Property { address: PropertyAddress::Indexed { object_index: 1, property_id: 7 }, start_element: 1 },
            capture_as: Some(capture), ..
        } if *capture == stamp_id
    ));
    assert!(matches!(procedure.steps[1].on_error.as_slice(), [ErrorHandler {
        cause: LoadControlCause::ResourceNotFound,
        action: ErrorAction::Ignore
    }]));
    assert!(matches!(procedure.steps[2].operation, ProcedureOperation::Restart { .. }));
}

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
        let mut parsed = parse_stamp_controls(&profile, selected);
        for step in &parsed.program.steps[1..parsed.program.steps.len() - 1] {
            assert!(
                matches!(&step.operation, ProcedureOperation::LoadImage {
                    target: OperationTarget::Property {
                        address: PropertyAddress::Indexed { object_index: 1..=4, property_id: 27 },
                        start_element: 1
                    },
                    extent: OperationExtent { byte_length: 8, property_elements: Some(1) },
                    alignment: 8,
                    ..
                }),
                "runtime stamps retain native image reads even outside the output interval"
            );
        }
        let expected = parsed.program.clone();
        parsed.capture_download_stamps();
        parsed.capture_download_stamps();
        let procedure = parsed.finish(&profile, &SparseDeviceImage::new(), false).expect("authored stamp reads remain");
        assert_eq!(procedure, expected, "a final-image policy cannot manufacture an omitted read");
        let DownloadStampOutput::ImageProperties(bindings) = &procedure.stamp_output else {
            panic!("System B uses final image properties")
        };
        assert_eq!(bindings.iter().map(|binding| binding.id.0.as_str()).collect::<Vec<_>>(), ["Stamp3", "Stamp4"]);
    }
}

#[test]
fn disabled_system_b_stamp_output_keeps_the_authored_cached_read() {
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
    assert!(matches!(&parsed.program.steps[1].operation, ProcedureOperation::ReadIntoImage {
        target: OperationTarget::Property { address: PropertyAddress::Indexed { object_index: 1, property_id: 27 }, start_element: 1 },
        extent: OperationExtent { byte_length: 8, property_elements: Some(1) },
        cache: crate::commissioning::procedure::CachePolicy::Populate,
        capture_as: Some(id), ..
    } if id.0 == "Stamp1"));
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

    // A fully owned property with known but inconsistent geometry also
    // fails before execution, even when no read touches that property.
    let mut procedure = original;
    procedure.steps.remove(4);
    let location = ImageLocation {
        space: ImageSpace::Property { object: ObjectSelector::Index { index: 4 }, property_id: 27 },
        offset: 0,
    };
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location, vec![0x34; 16]).expect("wide initial stamp image applies");
    assert!(
        configure_stamp_fixture(&profile, &image, &mut procedure)
            .expect_err("owned stamp width must match its binding")
            .to_string()
            .contains("output byte length")
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
fn system_b_stamp_read_requires_absent_or_exact_initial_property_segment() {
    let (profile, original) = system_b_stamp_procedure();
    let ProcedureOperation::LoadImage { image_location, .. } = &original.steps[1].operation else {
        panic!("fixture starts with a stamp read")
    };
    for length in [4, 9] {
        let mut image = SparseDeviceImage::new();
        image.apply_owned(image_location.clone(), vec![0x12; length]).expect("initial image applies");
        assert!(configure_stamp_fixture(&profile, &image, &mut original.clone()).is_err());
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
        progress_messages_by_reference: &BTreeMap::new(),
        progress_messages_by_id: &BTreeMap::new(),
        initial_tool_state: ToolState::default(),
        standard_memory_service: StandardMemoryService::Classic,
        restart_kind: RestartKind::Basic,
        application_identity: ApplicationIdentity::default(),
        secure_only: false,
    };
    let mut parsed = crate::commissioning::compiler::binding::procedure::parse(&input).expect("stamp controls parse");
    parsed.program.stamp_output =
        crate::commissioning::catalog::rules::resolved_download_stamp_output(profile, input.download_stamps)
            .expect("stamp output resolves");
    parsed
}
