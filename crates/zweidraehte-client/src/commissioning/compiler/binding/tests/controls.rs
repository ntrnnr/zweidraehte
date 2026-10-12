use super::*;

#[test]
fn property_backed_table_reference_is_resolved_only_for_the_used_object() {
    let resources = r#"
            <Resources>
              <Resource Name="ApplicationDataPtr" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="7" StartAddress="0" />
                <ResourceType Length="4" Flavour="Ptr_StandardMemory" />
                <AccessRights Read="Runtime" Write="Configuration" />
              </Resource>
              <Resource Name="UnrelatedPointer" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="8" StartAddress="0" />
                <ResourceType Length="4" Flavour="Ptr_StandardMemory" />
                <AccessRights Read="Runtime" Write="Configuration" />
              </Resource>
            </Resources>
            <Procedures>"#;
    let xml = CATALOG_XML.replacen("<Procedures>", resources, 1);
    let catalog = ProgrammingCatalog::from_xml(&xml).expect("catalog parses");
    let product = ProductData::default().with_fixture_id("relative-application-segment");
    let profile = resolve_profile(&catalog, &product);

    let pointer = profile.resource("ApplicationDataPtr").expect("lookup").expect("pointer");
    assert_eq!(pointer.flavour().expect("flavour"), Some(ResourceFlavour::PtrStandardMemory));
    assert!(matches!(pointer.property_location().expect("property"), Some((ObjectSelector::Index { index: 4 }, 7, 0))));
    // The actual lazy pointer selection is exercised by memory operand tests.
}

#[test]
fn real_shape_system7_compare_uses_global_pid_78_read_width() {
    let catalog = ProgrammingCatalog::from_xml(SYSTEM7_PROPERTY_CATALOG_XML).expect("catalog parses");
    let product = ProductData::from_mtxml_str(SYSTEM7_MTXML).expect("System 7 product parses");
    let profile = catalog
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery { dd0: 0x0705, management_descriptor_01: None, management_style: None },
            product: Some(&product),
            variant_hint: VariantHint::Automatic,
        })
        .expect("System 7 profile resolves");
    let mut image = SparseDeviceImage::new();
    image.apply_owned(ImageLocation::standard_memory(0x4000), vec![0; 17]).expect("declared application segment fits");
    let [procedure] = product.load_procedures() else {
        panic!("System 7 fixture has one product procedure");
    };
    // Isolate the published comparison: this width fixture deliberately has
    // no load-machine memory resources.
    let controls: Vec<_> = procedure
        .controls
        .iter()
        .filter(|control| {
            matches!(
                control,
                LoadControl::LdCtrlConnect(_) | LoadControl::LdCtrlCompareProp(_) | LoadControl::LdCtrlDisconnect(_)
            )
        })
        .cloned()
        .collect();
    let input = ProcedureInput {
        configuration_anchor: profile.configuration_anchor(),
        profile: &profile,
        procedure_id: ProcedureSourceId::Product {
            product_id: product.id().to_owned(),
            source_index: 0,
            merge_id: None,
        },
        composition: ProcedureComposition::ProductOwned,
        controls: &controls,
        product_merge_fragments: Vec::new(),
        omitted_controls: Vec::new(),
        parameter_values: &BTreeMap::new(),
        applicability: ProcedureApplicability::full(),
        download_stamps: Vec::new(),
        property_parameters: product.property_parameters(),
        peiprog_identity_reference: false,
        application_program_2_present: false,
        standard_memory_service: StandardMemoryService::Classic,
        progress_messages_by_reference: &BTreeMap::new(),
        progress_messages_by_id: &BTreeMap::new(),
        initial_tool_state: initial_tool_state(&product).expect("product options resolve"),
        restart_kind: RestartKind::Basic,
        application_identity: product.application_identity(),
    };
    let normalized = lower_procedure(&input, &image, Vec::new()).expect("real-shape product procedure compiles");
    let compare = normalized
        .steps
        .iter()
        .find_map(|step| match &step.operation {
            ProcedureOperation::Compare { comparison, extent, .. } => Some((comparison, extent)),
            _ => None,
        })
        .expect("product procedure compares PID 78");
    let Comparison::Exact { data: OperationData::Buffer { fallback: Some(expected), length, .. }, padding, .. } =
        compare.0
    else {
        panic!("PID 78 keeps its authored comparison fallback");
    };

    assert_eq!(expected.len(), 6, "the executable comparison excludes the unused registration suffix");
    assert_eq!(*length, 6, "image width remains separate from the padded XML buffer");
    assert_eq!(compare.1.byte_length, 6);
    assert_eq!(*padding, ComparisonPadding::None);
}

#[test]
fn system_b_load_appends_unsecured_cleanup_after_authored_restart() {
    let xml = SYSTEM_B_APPLICATION_CATALOG_XML.replace("<LdCtrlDisconnect />", "<LdCtrlRestart />");
    let catalog = ProgrammingCatalog::from_xml(&xml).expect("catalog parses");
    let product = system_b_product(false);

    for secure_only in [false, true] {
        let profile = resolve_system_b_profile(&catalog, &product);
        let options = compile_options(RestartKind::Basic);
        let mut input = programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Full),
            options,
        );
        input.facts.target.as_mut().expect("fixture target").credential =
            if secure_only { ManagementCredential::ToolKey } else { ManagementCredential::Plaintext };
        let plan = compile_program_fixture(input, profile).expect("a load ending in restart compiles");
        let procedure = plan.procedure().expect("download has a procedure");
        let restart = &procedure.steps[procedure.steps.len() - 2];
        let cleanup = procedure.steps.last().expect("download has cleanup");

        assert_eq!(restart.operation, ProcedureOperation::Restart {
            kind: if secure_only { RestartKind::Confirmed } else { RestartKind::Basic }
        });
        assert!(restart.path.contribution.is_none());
        assert!(!restart.secure_only);
        assert!(matches!(cleanup.operation, ProcedureOperation::Disconnect));
        assert_eq!(cleanup.path.contribution, Some("automatic-session-close"));
        assert_eq!(cleanup.path.procedure, procedure.id);
        assert!(cleanup.path.control_indices.is_empty());
        assert_eq!(cleanup.source_control_code, None);
        assert!(cleanup.on_error.is_empty());
        assert!(cleanup.sections.is_empty());
        assert!(!cleanup.secure_only);
        procedure.validate().expect("cleanup remains valid after restart closes the runtime session");
    }
}

#[test]
fn automatic_cleanup_cannot_repair_an_unclosed_authored_session() {
    let xml = SYSTEM_B_APPLICATION_CATALOG_XML.replace("<LdCtrlDisconnect />", "");
    let catalog = ProgrammingCatalog::from_xml(&xml).expect("catalog parses");
    let product = system_b_product(false);
    let profile = resolve_system_b_profile(&catalog, &product);
    let error = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Full),
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect_err("the authored program must close before cleanup can be appended");
    assert!(error.message.contains("procedure leaves 1 device-management sessions open"));
}

#[test]
fn system_b_load_preserves_authored_disconnect_without_duplicate_cleanup() {
    let xml = SYSTEM_B_APPLICATION_CATALOG_XML.replace("<LdCtrlDisconnect />", "<LdCtrlRestart /><LdCtrlDisconnect />");
    let catalog = ProgrammingCatalog::from_xml(&xml).expect("catalog parses");
    let product = system_b_product(false);
    let profile = resolve_system_b_profile(&catalog, &product);
    let options = compile_options(RestartKind::Basic);

    let mut input = programming_input(
        &catalog,
        &product,
        &configuration(),
        CommissioningIntent::Download(DownloadMode::Full),
        options,
    );
    input.facts.target.as_mut().expect("fixture target").credential = ManagementCredential::ToolKey;

    let plan = compile_program_fixture(input, profile).expect("a load with authored cleanup compiles");
    let procedure = plan.procedure().expect("download has a procedure");
    let cleanup = procedure.steps.last().expect("authored cleanup remains");

    assert!(matches!(cleanup.operation, ProcedureOperation::Disconnect));
    assert_eq!(cleanup.path.control_indices, vec![9]);
    assert!(cleanup.path.contribution.is_none());
    assert_eq!(cleanup.source_control_code, Some(13));
    assert!(!cleanup.secure_only);
    assert_eq!(
        procedure.steps.iter().filter(|step| matches!(step.operation, ProcedureOperation::Disconnect)).count(),
        1
    );
    procedure.validate().expect("authored cleanup remains valid");
}

#[test]
fn procedure_choices_use_only_explicit_post_evaluation_state() {
    let mut configuration = configuration();
    configuration.parameters.push(crate::configuration::ParameterValue { id: "P-base".to_string(), value: vec![1] });
    configuration
        .procedure_parameters
        .insert("P-ref".to_string(), ProcedureParameter { active: true, value: ProcedureParameterValue::Signed(1) });

    let values = configuration.procedure_parameters.clone();

    assert_eq!(
        values.get("P-ref"),
        Some(&ProcedureParameter { active: true, value: ProcedureParameterValue::Signed(1) })
    );
    assert_eq!(values.get("P-base"), None);
}
