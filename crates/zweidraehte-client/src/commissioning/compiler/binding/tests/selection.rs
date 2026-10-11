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
fn combined_partial_sections_select_an_overlapping_source_without_widening() {
    for (sections, subtype) in [
        (ProgramSections::APPLICATION_PROGRAM_1.union(ProgramSections::PARAMETERS), "all"),
        (
            ProgramSections::PARAMETERS
                .union(ProgramSections::GROUP_COMMUNICATION)
                .union(ProgramSections::CONFIGURATION),
            "par,grp",
        ),
    ] {
        let plan = compile_scope(CATALOG_XML, DownloadMode::Partial(sections), None)
            .expect("a published overlapping source compiles the requested applicability");
        assert_eq!(plan.program_sections(), Some(sections));
        assert!(!plan.is_full_program_scope());
        assert!(matches!(plan.procedure().map(|p| &p.id),
            Some(ProcedureSourceId::MasterData(id)) if id.subtype.as_deref() == Some(subtype)));
    }
    let error = compile_scope(CATALOG_XML, DownloadMode::Partial(ProgramSections::all()), None)
        .expect_err("an explicit AP2 request still needs the secondary application definition");
    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert!(error.message.contains("has no Application Program 2"));
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

    let plan = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::PARAMETERS)),
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect("a combined source can execute just the requested parameter applicability");

    assert_eq!(plan.program_sections(), Some(ProgramSections::PARAMETERS));
    assert!(!plan.is_full_program_scope());
    assert!(matches!(plan.procedure().map(|p| &p.id),
        Some(ProcedureSourceId::MasterData(id)) if id.subtype.as_deref() == Some("par,grp")));
}

#[test]
fn overlapping_full_source_filters_full_and_unselected_control_variants() {
    let xml = CATALOG_XML.replacen(
        "<Procedures>",
        r#"<Procedures>
        <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
            <LdCtrlDelay MilliSeconds="1" AppliesTo="full" />
            <LdCtrlDelay MilliSeconds="2" AppliesTo="par" />
            <LdCtrlDelay MilliSeconds="3" AppliesTo="grp" />
            <LdCtrlDelay MilliSeconds="4" AppliesTo="cfg" />
            <LdCtrlDelay MilliSeconds="5" AppliesTo="all" />
        </Procedure>"#,
        1,
    );
    // Remove the ordinary parameter/group source so only Load/all overlaps.
    let start = xml.find("<Procedure ProcedureType=\"Load\" ProcedureSubType=\"par,grp\"").unwrap();
    let end = start + xml[start..].find("</Procedure>").unwrap() + "</Procedure>".len();
    let xml = format!("{}{}", &xml[..start], &xml[end..]);
    let plan = compile_scope(&xml, DownloadMode::Partial(ProgramSections::PARAMETERS), None).unwrap();
    let delays: Vec<_> = plan
        .procedure()
        .unwrap()
        .steps
        .iter()
        .filter_map(|step| match step.operation {
            ProcedureOperation::Delay { milliseconds } => Some(milliseconds),
            _ => None,
        })
        .collect();
    assert_eq!(delays, vec![2, 5]);
    assert_eq!(plan.program_sections(), Some(ProgramSections::PARAMETERS));
    assert!(!plan.is_full_program_scope());
}

#[test]
fn partial_source_ranking_keeps_first_tie_and_ignores_local_sources() {
    let xml = CATALOG_XML.replacen(
        "<Procedures>",
        r#"<Procedures>
        <Procedure ProcedureType="Load" ProcedureSubType="par" Access="local1">
            <LdCtrlDelay MilliSeconds="99" />
        </Procedure>
        <Procedure ProcedureType="Load" ProcedureSubType="par,grp" Access="remote">
            <LdCtrlDelay MilliSeconds="1" />
        </Procedure>
        <Procedure ProcedureType="Load" ProcedureSubType="par,grp" Access="remote">
            <LdCtrlDelay MilliSeconds="2" />
        </Procedure>"#,
        1,
    );
    let plan = compile_scope(&xml, DownloadMode::Partial(ProgramSections::PARAMETERS), None).unwrap();
    let procedure = plan.procedure().unwrap();
    assert!(matches!(&procedure.id, ProcedureSourceId::MasterData(id) if id.source_index == 1));
    assert!(matches!(procedure.steps[0].operation, ProcedureOperation::Delay { milliseconds: 1 }));
}

#[test]
fn configuration_only_has_an_empty_source_instead_of_loading_the_application() {
    let xml = CATALOG_XML.replacen(
        "<Procedures>",
        r#"<Procedures>
        <Procedure ProcedureType="Load" ProcedureSubType="cfg" Access="remote">
            <LdCtrlDelay MilliSeconds="99" />
        </Procedure>"#,
        1,
    );
    let plan = compile_scope(&xml, DownloadMode::Partial(ProgramSections::CONFIGURATION), None).unwrap();
    assert_eq!(plan.program_sections(), Some(ProgramSections::CONFIGURATION));
    assert!(!plan.is_full_program_scope());
    let procedure = plan.procedure().unwrap();
    assert!(matches!(&procedure.id, ProcedureSourceId::Generated { .. }));
    assert!(procedure.steps.is_empty());
}

#[test]
fn partial_compilation_keeps_parameter_bits_and_allocation_without_owning_application_code() {
    let catalog = ProgrammingCatalog::from_xml(CATALOG_XML).unwrap();
    let product = ProductData::default()
        .with_fixture_id("scoped-image")
        .with_fixture_segments(vec![Segment {
            id: "code".to_owned(),
            address: Some(256),
            size: 2,
            memory_type: Some("EEPROM".to_owned()),
            user_memory: None,
            load_state_machine: None,
            data: vec![0xaa, 0xcc],
            mask: None,
        }])
        .with_fixture_parameters(vec![zweidraehte_ets_files::product::ParameterLocation {
            id: "p".to_owned(),
            code_segment: "code".to_owned(),
            offset: 0,
            bit_offset: 0,
            size_bits: 4,
            legacy_patch_always: false,
            seeds_default: false,
        }]);
    let mut configuration = configuration();
    configuration.parameters.push(crate::configuration::ParameterValue { id: "p".to_owned(), value: vec![5] });
    for mode in [DownloadMode::Full, DownloadMode::Partial(ProgramSections::PARAMETERS)] {
        let profile = resolve_profile(&catalog, &product);
        let plan = compile_program_fixture(
            programming_input(
                &catalog,
                &product,
                &configuration,
                CommissioningIntent::Download(mode),
                compile_options(RestartKind::Basic),
            ),
            profile,
        )
        .unwrap();
        let (value, mask) = plan.image().byte(&ImageLocation::standard_memory(256)).unwrap();
        assert_eq!(value >> 4, 5);
        if mode == DownloadMode::Full {
            assert_eq!(mask, 0xff);
            assert_eq!(plan.image().byte(&ImageLocation::standard_memory(257)), Some((0xcc, 0xff)));
        } else {
            assert_eq!(mask, 0xf0);
            assert_eq!(plan.image().byte(&ImageLocation::standard_memory(257)), None);
        }
        assert!(
            plan.native_regions()
                .iter()
                .any(|region| region.location == ImageLocation::standard_memory(256) && region.length == 2)
        );
    }
}
