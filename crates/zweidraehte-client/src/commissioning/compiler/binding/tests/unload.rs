use super::*;

#[test]
fn ordinary_unload_skips_unreferenced_application_image_and_extensions() {
    let catalog = ProgrammingCatalog::from_xml(CATALOG_XML).expect("catalog parses");
    let product = invalid_application_product();
    let profile = resolve_profile(&catalog, &product);
    let configuration = configuration();

    let plan = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration,
            CommissioningIntent::Unload(UnloadMode::Application),
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect("inline unload does not need the application image");

    assert!(plan.image().is_empty());
    assert!(matches!(plan.procedure().map(|procedure| &procedure.id), Some(ProcedureSourceId::MasterData(_))));
}

#[test]
fn unload_compiles_only_the_referenced_image_range() {
    let catalog = ProgrammingCatalog::from_xml(&image_backed_unload_catalog()).expect("catalog parses");
    let product = ProductData::default().with_fixture_id("scope-test").with_fixture_segments(vec![
        Segment {
            id: "referenced".to_owned(),
            address: Some(0x100),
            size: 1,
            memory_type: Some("EEPROM".to_owned()),
            user_memory: None,
            load_state_machine: None,
            data: vec![0x5a],
            mask: None,
        },
        Segment {
            id: "unrelated-invalid".to_owned(),
            address: Some(0x200),
            size: 1,
            memory_type: Some("EEPROM".to_owned()),
            user_memory: None,
            load_state_machine: None,
            data: vec![0x12, 0x34],
            mask: None,
        },
    ]);
    let profile = resolve_profile(&catalog, &product);

    let plan = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Unload(UnloadMode::Application),
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect("unrelated invalid application data cannot block unload");

    let segments = plan.image().segments();
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].location(), &ImageLocation::standard_memory(0x100));
    assert_eq!(segments[0].data(), [0x5a]);
}

#[test]
fn unload_fails_closed_when_its_referenced_image_range_is_missing() {
    let catalog = ProgrammingCatalog::from_xml(&image_backed_unload_catalog()).expect("catalog parses");
    let product = ProductData::default().with_fixture_id("scope-test");
    let profile = resolve_profile(&catalog, &product);

    let error = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Unload(UnloadMode::Application),
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect_err("a referenced range must be producible");

    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert!(error.message.contains("is not completely defined"));
}
