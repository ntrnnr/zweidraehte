use super::*;

#[test]
fn unused_conflicting_high_memory_resources_do_not_select_services() {
    let xml = CATALOG_XML.replace(
        "<Procedures>",
        r#"<Resources>
      <Resource Name="UnusedHighMemory" Access="remote">
        <Location AddressSpace="StandardMemory" StartAddress="65536"/>
        <ResourceType Length="1"/>
      </Resource>
      <Resource Name="UnusedHighMemory" Access="remote">
        <Location AddressSpace="StandardMemory" StartAddress="65537"/>
        <ResourceType Length="1"/>
      </Resource>
    </Resources><Procedures>"#,
    );
    let catalog = ProgrammingCatalog::from_xml(&xml).expect("catalog preserves authored alternatives");
    let product = ProductData::default().with_fixture_id("unused-memory");
    for intent in [CommissioningIntent::AssignAddress, CommissioningIntent::Unload(UnloadMode::Application)] {
        for credential in [ManagementCredential::Plaintext, ManagementCredential::ToolKey] {
            let mut input =
                programming_input(&catalog, &product, &configuration(), intent, compile_options(RestartKind::Basic));
            input.facts.target.as_mut().expect("fixture target").credential = credential;
            let plan = compile_program_fixture(input, resolve_profile(&catalog, &product))
                .expect("unselected resources cannot invalidate preparation");
            if let Some(procedure) = plan.procedure() {
                use crate::commissioning::procedure::operands::MemoryService;
                let expected = if credential.is_secure() { MemoryService::Extended } else { MemoryService::Classic };
                assert!(procedure.steps.iter().any(|step| matches!(&step.operation,
                    ProcedureOperation::Write { target: OperationTarget::Memory { service, .. }, .. } if *service == expected
                )), "selected low-memory controls bind authentication without unrelated geometry");
            }
        }
    }
}

#[test]
fn address_assignment_skips_application_image_and_extensions() {
    let catalog = ProgrammingCatalog::from_xml(CATALOG_XML).expect("catalog parses");
    let product = invalid_application_product();
    let profile = resolve_profile(&catalog, &product);
    let configuration = configuration();

    let plan = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration,
            CommissioningIntent::AssignAddress,
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect("address assignment does not compile application data");

    assert!(plan.image().is_empty());
    assert!(plan.procedure().is_none());
}

#[test]
fn routing_extension_is_required_only_when_programming_group_filters() {
    let catalog = ProgrammingCatalog::from_xml(CATALOG_XML).expect("catalog parses");
    let product = ProductData::default().with_fixture_id("extension-preflight");
    let mut profile = resolve_profile(&catalog, &product);
    profile.set_test_disposition(crate::commissioning::ProfileDisposition::CouplerRoutingRequired);

    for intent in [CommissioningIntent::AssignAddress, CommissioningIntent::Unload(UnloadMode::Application)] {
        let program = compile_program_fixture(
            programming_input(&catalog, &product, &configuration(), intent, compile_options(RestartKind::Basic)),
            profile.clone(),
        )
        .expect("address assignment and inline unload do not configure routing");
        assert!(program.image().is_empty());
    }

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
    .expect_err("full download requires the product routing selector");

    assert_eq!(error.kind, CompileErrorKind::Unsupported);
    assert!(error.message.contains("profile is not executable"));
}

#[test]
fn unknown_plugin_remains_required_for_address_assignment() {
    let catalog = ProgrammingCatalog::from_xml(CATALOG_XML).expect("catalog parses");
    let product = ProductData::default().with_fixture_id("plugin-preflight");
    let mut profile = resolve_profile(&catalog, &product);
    profile.set_test_disposition(crate::commissioning::ProfileDisposition::UnsupportedPlugin {
        plugin: "vendor.unknown".to_owned(),
    });

    let error = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::AssignAddress,
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect_err("an unknown plugin has no proven narrower scope");
    assert_eq!(error.kind, CompileErrorKind::Unsupported);
    assert!(error.message.contains("profile is not executable"));
}

#[test]
fn downloads_still_fail_closed_on_invalid_application_images() {
    let catalog = ProgrammingCatalog::from_xml(CATALOG_XML).expect("catalog parses");
    let product = invalid_application_product();
    let profile = resolve_profile(&catalog, &product);
    let configuration = configuration();

    let error = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration,
            CommissioningIntent::Download(DownloadMode::Full),
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect_err("a download must validate its application image");

    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert!(error.message.contains("data bytes but size"));
}

#[test]
fn product_procedure_validation_remains_scoped_to_downloads() {
    let catalog = ProgrammingCatalog::from_xml(CATALOG_XML).expect("catalog parses");
    let product = ProductData::default()
        .with_fixture_id("scope-test")
        .with_fixture_load_procedure_style(LoadProcedureStyle::Default)
        .with_fixture_load_procedures(vec![LoadProcedure::default()]);
    let configuration = configuration();

    let address_profile = resolve_profile(&catalog, &product);
    compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration,
            CommissioningIntent::AssignAddress,
            compile_options(RestartKind::Basic),
        ),
        address_profile,
    )
    .expect("address assignment does not consume a product load procedure");

    let unload_profile = resolve_profile(&catalog, &product);
    compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration,
            CommissioningIntent::Unload(UnloadMode::Application),
            compile_options(RestartKind::Basic),
        ),
        unload_profile,
    )
    .expect("Master Data owns the unload procedure");

    let download_profile = resolve_profile(&catalog, &product);
    let error = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration,
            CommissioningIntent::Download(DownloadMode::Full),
            compile_options(RestartKind::Basic),
        ),
        download_profile,
    )
    .expect_err("download procedure inconsistencies remain fatal");

    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert!(error.message.contains("invalid load-procedure definition"));
}
