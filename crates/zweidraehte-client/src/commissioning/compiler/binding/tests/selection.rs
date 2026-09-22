use super::*;

fn compile_scope(
    catalog_xml: &str,
    mode: DownloadMode,
    automatic_sections: Option<ProgramSections>,
) -> Result<crate::commissioning::CompiledProgram, CompileError> {
    let catalog = ProgrammingCatalog::from_xml(catalog_xml).expect("catalog parses");
    let product = ProductData::default().with_fixture_id("scope-selection");
    let profile = resolve_profile(&catalog, &product);
    let mut options = compile_options(RestartKind::Basic);
    options.automatic_sections = automatic_sections;
    compile_program_fixture(
        programming_input(&catalog, &product, &configuration(), CommissioningIntent::Download(mode), options),
        profile,
    )
}

#[test]
fn automatic_download_never_guesses_sections() {
    let error = compile_scope(CATALOG_XML, DownloadMode::Automatic, None).expect_err("sections are required");

    assert_eq!(error.kind, CompileErrorKind::MissingEvidence);
    assert!(error.message.contains("automatic download requires explicitly resolved program sections"));
}

#[test]
fn exact_partial_section_sets_select_published_subtypes() {
    let parameters_and_groups = ProgramSections::PARAMETERS.union(ProgramSections::GROUP_COMMUNICATION);

    let program = compile_scope(CATALOG_XML, DownloadMode::Partial(parameters_and_groups), None)
        .expect("published combined subtype is available");

    assert_eq!(program.program_sections(), Some(parameters_and_groups));
    assert!(!program.is_full_program_scope());
    assert!(matches!(
        &program.procedure().expect("download has a source").id,
        ProcedureSourceId::MasterData(id) if id.subtype.as_deref() == Some("par,grp")
    ));

    let application_program_2 =
        compile_scope(CATALOG_XML, DownloadMode::Partial(ProgramSections::APPLICATION_PROGRAM_2), None)
            .expect_err("an unsupported secondary application fails before selecting a source");
    assert!(application_program_2.message.contains("has no Application Program 2"));
}

#[test]
fn unsupported_partial_combinations_fail_instead_of_falling_back() {
    for sections in [ProgramSections::APPLICATION_PROGRAM_1.union(ProgramSections::PARAMETERS), ProgramSections::all()]
    {
        let error = compile_scope(CATALOG_XML, DownloadMode::Partial(sections), None)
            .expect_err("an explicit partial request cannot substitute a semantic full download");

        assert_eq!(error.kind, CompileErrorKind::Unsupported);
        assert!(error.message.contains(&format!("partial sections {sections:?}")));
    }
}

#[test]
fn automatic_download_does_not_skip_an_ambiguous_narrower_source() {
    let xml = CATALOG_XML.replacen(
        "<Procedures>",
        r#"<Procedures>
          <Procedure ProcedureType="Load" ProcedureSubType="par" Access="remote" />
          <Procedure ProcedureType="Load" ProcedureSubType="par" Access="remote" />"#,
        1,
    );
    let error = compile_scope(&xml, DownloadMode::Automatic, Some(ProgramSections::PARAMETERS))
        .expect_err("a wider valid source cannot hide an ambiguous exact candidate");
    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert!(error.message.contains("ambiguous Load/par procedures at [0, 1]"));
}

#[test]
fn automatic_download_selects_the_narrowest_published_superset() {
    let catalog = ProgrammingCatalog::from_xml(CATALOG_XML).expect("catalog parses");
    let product = ProductData::default().with_fixture_id("automatic-scope");
    let profile = resolve_profile(&catalog, &product);
    let mut options = compile_options(RestartKind::Basic);
    options.automatic_sections = Some(ProgramSections::PARAMETERS);

    let plan = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Automatic),
            options,
        ),
        profile,
    )
    .expect("combined parameter/group procedure safely covers parameters");

    assert_eq!(plan.program_sections(), Some(ProgramSections::PARAMETERS.union(ProgramSections::GROUP_COMMUNICATION)));
    assert!(matches!(
        plan.procedure().map(|procedure| &procedure.id),
        Some(ProcedureSourceId::MasterData(id)) if id.subtype.as_deref() == Some("par,grp")
    ));
}

#[test]
fn automatic_download_marks_a_published_full_superset_as_semantic_full() {
    let catalog = ProgrammingCatalog::from_xml(CATALOG_XML).expect("catalog parses");
    let product = ProductData::default().with_fixture_id("automatic-full-scope");
    let profile = resolve_profile(&catalog, &product);
    let mut options = compile_options(RestartKind::Basic);
    options.automatic_sections = Some(ProgramSections::APPLICATION_PROGRAM_1.union(ProgramSections::PARAMETERS));

    let plan = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Automatic),
            options,
        ),
        profile,
    )
    .expect("the unsupported automatic combination widens to Load/all");

    assert_eq!(plan.program_sections(), Some(primary_application_program_sections()));
    assert!(plan.is_full_program_scope());
    assert!(matches!(
        plan.procedure().map(|procedure| &procedure.id),
        Some(ProcedureSourceId::MasterData(id)) if id.subtype.as_deref() == Some("all")
    ));
}

#[test]
fn explicit_partial_download_does_not_widen() {
    let catalog = ProgrammingCatalog::from_xml(CATALOG_XML).expect("catalog parses");
    let product = ProductData::default().with_fixture_id("explicit-scope");
    let profile = resolve_profile(&catalog, &product);

    let error = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::PARAMETERS)),
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect_err("explicit partial selection must remain exact");

    assert_eq!(error.kind, CompileErrorKind::MissingProcedure);
    assert!(error.message.contains("no exact Load/par procedure"));
}
