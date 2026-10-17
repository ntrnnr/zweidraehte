use super::*;

fn merge_selection_product(with_secondary: bool) -> ProductData {
    let fragments = || {
        [1, 3, 5]
            .into_iter()
            .map(|id| LoadProcedure {
                merge_id: Some(id),
                controls: vec![LoadControl::LdCtrlDelay(LdCtrlDelay {
                    applies_to: Some("all".to_owned()),
                    milli_seconds: u16::from(id),
                    ..Default::default()
                })],
            })
            .collect()
    };
    let primary = ProductData::default()
        .with_fixture_id("primary")
        .with_fixture_load_procedure_style(LoadProcedureStyle::Merged)
        .with_fixture_load_procedures(fragments());
    if !with_secondary {
        return primary;
    }
    let secondary = ProductData::default()
        .with_fixture_id("secondary")
        .with_fixture_load_procedure_style(LoadProcedureStyle::Merged)
        .with_fixture_load_procedures(fragments());
    primary
        .with_fixture_application_program_2(ApplicationProgram2Binding::Present {
            relation: ApplicationProgramRelationIdentity {
                catalog_product_id: None,
                catalog_item_id: None,
                hardware_id: "hardware".to_owned(),
                hardware2program_id: "relation".to_owned(),
                application_program_id: "primary".to_owned(),
            },
            application_program_id: "secondary".to_owned(),
        })
        .bind_secondary_application(secondary)
        .expect("secondary matches its hardware relation")
}

fn selected_fragment_ids(product: &ProductData, mode: DownloadMode) -> Result<(Vec<u8>, Vec<u8>), CompileError> {
    let catalog = ProgrammingCatalog::from_xml(
        r#"<KNX xmlns="http://knx.org/xml/project/23"><MasterData Id="MD" Version="1"><MaskVersions>
        <MaskVersion Id="MV-0012" MaskVersion="18" Name="Merge selection" ManagementModel="Bcu1">
          <HawkConfigurationData><Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
              <LdCtrlMerge MergeId="1"/><LdCtrlMerge MergeId="3"/>
            </Procedure>
            <Procedure ProcedureType="Load" ProcedureSubType="par,grp" Access="remote">
              <LdCtrlMerge MergeId="3"/>
            </Procedure>
            <Procedure ProcedureType="Unload" ProcedureSubType="all" Access="remote">
              <LdCtrlMerge MergeId="5"/>
            </Procedure>
          </Procedures></HawkConfigurationData>
        </MaskVersion></MaskVersions></MasterData></KNX>"#,
    )
    .expect("merge selection catalog parses");
    let profile = resolve_profile(&catalog, product);
    let input = programming_input(
        &catalog,
        product,
        &configuration(),
        CommissioningIntent::Download(mode),
        compile_options(RestartKind::Basic),
    );
    let compiler = crate::commissioning::compiler::ProgramCompiler::from_profile(&input, profile)?;
    let (_, selected) = crate::commissioning::compiler::selection::sources::select_procedure(&compiler)?;
    Ok((
        selected.product_merge_fragments.iter().filter_map(|fragment| fragment.merge_id).collect(),
        selected.secondary_merge_fragments.iter().filter_map(|fragment| fragment.merge_id).collect(),
    ))
}

#[test]
fn full_load_selects_its_merge_fragments_and_leaves_unload_fragments_unselected() {
    for with_secondary in [false, true] {
        let product = merge_selection_product(with_secondary);
        let (primary, secondary) = selected_fragment_ids(&product, DownloadMode::Full).expect("full source selects");
        assert_eq!(primary, [1, 3], "the full Load has no Unload MergeId 5 splice point");
        assert_eq!(secondary, if with_secondary { vec![1, 3] } else { Vec::new() });

        let (primary, secondary) = selected_fragment_ids(&product, DownloadMode::Partial(ProgramSections::PARAMETERS))
            .expect("partial source selects");
        assert_eq!(primary, [3]);
        assert_eq!(secondary, if with_secondary { vec![3] } else { Vec::new() });
    }
}

#[test]
fn unselected_merge_fragments_do_not_hide_duplicate_definitions() {
    let mut product = merge_selection_product(false);
    let mut fragments = product.load_procedures().to_vec();
    fragments.push(fragments.last().expect("Unload fragment exists").clone());
    product = product.with_fixture_load_procedures(fragments);
    let error = selected_fragment_ids(&product, DownloadMode::Full).expect_err("duplicate Unload fragment refuses");
    assert!(error.message.contains("MergeId 5 more than once"));

    let mut product = merge_selection_product(true);
    let mut secondary = product.secondary_application().expect("secondary exists").clone();
    let mut fragments = secondary.load_procedures().to_vec();
    fragments.push(fragments.last().expect("secondary Unload fragment exists").clone());
    secondary = secondary.with_fixture_load_procedures(fragments);
    product = product.bind_secondary_application(secondary).expect("same secondary identity binds");
    let error = selected_fragment_ids(&product, DownloadMode::Full).expect_err("duplicate secondary fragment refuses");
    assert!(error.message.contains("secondary application defines MergeId 5 more than once"));
}

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
fn product_owned_partial_sources_keep_authored_controls_and_requested_sections() {
    let xml = CATALOG_XML.replace("ProcedureType=\"Load\"", "ProcedureType=\"Unused\"");
    let catalog = ProgrammingCatalog::from_xml(&xml).expect("catalog without Master Data loads parses");
    let controls = [("full", 10), ("par", 11), ("grp", 12), ("cfg", 13), ("ap1", 14), ("all", 15)]
        .into_iter()
        .map(|(scope, milli_seconds)| {
            LoadControl::LdCtrlDelay(LdCtrlDelay {
                applies_to: Some(scope.to_owned()),
                milli_seconds,
                ..Default::default()
            })
        })
        .collect();
    let product = ProductData::default()
        .with_fixture_id("product-owned-partial")
        .with_fixture_load_procedure_style(LoadProcedureStyle::Product)
        .with_fixture_load_procedures(vec![LoadProcedure { merge_id: None, controls }]);
    let par = ProgramSections::PARAMETERS;
    let grp = ProgramSections::GROUP_COMMUNICATION;
    let cfg = ProgramSections::CONFIGURATION;

    for sections in [
        par,
        grp,
        cfg,
        par.union(grp),
        par.union(cfg),
        grp.union(cfg),
        par.union(grp).union(cfg),
        ProgramSections::APPLICATION_PROGRAM_1,
    ] {
        let program = compile_program_fixture(
            programming_input(
                &catalog,
                &product,
                &configuration(),
                CommissioningIntent::Download(DownloadMode::Partial(sections)),
                compile_options(RestartKind::Basic),
            ),
            resolve_profile(&catalog, &product),
        )
        .expect("product procedures do not require a published partial Master Data source");
        let procedure = program.procedure().expect("product owns the source");

        assert_eq!(program.program_sections(), Some(sections));
        assert!(!program.is_full_program_scope());
        assert!(
            matches!(&procedure.id, ProcedureSourceId::Product { product_id, source_index: 0, merge_id: None } if product_id == product.id())
        );
        let selected: Vec<_> = procedure
            .steps
            .iter()
            .filter_map(|step| match step.operation {
                ProcedureOperation::Delay { milliseconds } => Some(milliseconds),
                _ => None,
            })
            .collect();
        let expected: Vec<_> = [(par, 11), (grp, 12), (cfg, 13), (ProgramSections::APPLICATION_PROGRAM_1, 14)]
            .into_iter()
            .filter_map(|(section, delay)| sections.contains(section).then_some(delay))
            .chain([15])
            .collect();

        assert_eq!(selected, expected);
    }
}

// A memory-mapped identity at 260 and PEI type at 265 beside one product
// segment at 256. The segment size and an optional mask memory window at 256
// decide whether storage for them exists.
fn memory_identity_fixture(segment_size: u32, window: Option<u32>) -> (ProgrammingCatalog, ProductData) {
    let memory = window.map_or_else(String::new, |length| {
        format!(
            r#"<MemorySegments><MemorySegment MemoryType="EEPROM" Length="{length}">
            <Location AddressSpace="StandardMemory" StartAddress="256" />
            <AccessRights Read="Configuration" Write="Configuration" />
        </MemorySegment></MemorySegments>"#
        )
    });
    let xml = CATALOG_XML.replacen(
        "<HawkConfigurationData>",
        r#"<HawkConfigurationData><Resources>
        <Resource Name="ApplicationId" Access="remote">
            <Location AddressSpace="StandardMemory" StartAddress="260" />
            <ResourceType Length="4" />
        </Resource>
        <Resource Name="ApplicationPeiType" Access="remote">
            <Location AddressSpace="StandardMemory" StartAddress="265" />
            <ResourceType Length="1" />
        </Resource>
        </Resources>"#,
        1,
    );
    let xml = xml.replacen("</Resources>", &format!("</Resources>{memory}"), 1);
    let catalog = ProgrammingCatalog::from_xml(&xml).expect("catalog parses");
    let product = ProductData::default()
        .with_fixture_id("scoped-image")
        .with_fixture_application_identity(ApplicationIdentity { application_id: [0, 0xfa, 1, 2, 3], pei_type: 17 })
        .with_fixture_segments(vec![Segment {
            id: "code".to_owned(),
            address: Some(256),
            size: segment_size,
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
            byte_ordered: true,
        }]);
    (catalog, product)
}

#[test]
fn partial_compilation_keeps_parameter_bytes_and_allocation_without_owning_application_code() {
    // The segment covers both identity resources, so a full image owns them.
    let (catalog, product) = memory_identity_fixture(10, None);
    let mut configuration = configuration();
    configuration.parameters.push(crate::configuration::ParameterValue { id: "p".to_owned(), value: vec![5] });
    let parameters = ProgramSections::PARAMETERS;
    let groups = ProgramSections::GROUP_COMMUNICATION;
    let configuration_section = ProgramSections::CONFIGURATION;
    for style in [LoadProcedureStyle::Default, LoadProcedureStyle::Product] {
        let product = if style == LoadProcedureStyle::Product {
            product.clone().with_fixture_load_procedure_style(style).with_fixture_load_procedures(vec![LoadProcedure {
                merge_id: None,
                controls: vec![LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 1, ..Default::default() })],
            }])
        } else {
            product.clone()
        };

        for mode in [
            DownloadMode::Full,
            DownloadMode::Partial(parameters),
            DownloadMode::Partial(groups),
            DownloadMode::Partial(configuration_section),
            DownloadMode::Partial(parameters.union(groups)),
            DownloadMode::Partial(parameters.union(configuration_section)),
            DownloadMode::Partial(groups.union(configuration_section)),
            DownloadMode::Partial(parameters.union(groups).union(configuration_section)),
        ] {
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
            let parameter = plan.image().byte(&ImageLocation::standard_memory(256));
            if mode == DownloadMode::Full {
                assert_eq!(parameter.map(|(value, mask)| (value >> 4, mask)), Some((5, 0xff)));
                assert_eq!(plan.image().byte(&ImageLocation::standard_memory(257)), Some((0xcc, 0xff)));
                assert_eq!(plan.image().byte(&ImageLocation::standard_memory(260)), Some((0xfa, 0xff)));
                assert_eq!(plan.image().byte(&ImageLocation::standard_memory(265)), Some((17, 0xff)));
            } else {
                let selected = plan.program_sections().unwrap().contains(parameters);
                assert_eq!(parameter, selected.then_some((0x5a, 0xff)));
                assert_eq!(plan.image().byte(&ImageLocation::standard_memory(257)), None);
                for offset in [260, 261, 262, 263, 265] {
                    assert_eq!(plan.image().byte(&ImageLocation::standard_memory(offset)), None);
                }
            }
            assert!(
                plan.native_regions()
                    .iter()
                    .any(|region| region.location == ImageLocation::standard_memory(256) && region.length == 10)
            );
        }
    }
}

// Identity resources are mask facts, not storage. Outside every product
// segment, a full image does not invent bytes for them.
#[test]
fn memory_identity_outside_all_storage_is_not_owned() {
    // A mask window that ends before the identity does not cover it either.
    for window in [None, Some(4)] {
        let plan = full_memory_identity_plan(window);

        assert_eq!(plan.image().byte(&ImageLocation::standard_memory(257)), Some((0xcc, 0xff)));
        for offset in [260, 261, 262, 263, 265] {
            assert_eq!(plan.image().byte(&ImageLocation::standard_memory(offset)), None, "window {window:?}");
        }
    }
}

// A BCU-style identity lies in the mask's EEPROM header, outside every product
// segment but inside the mask memory window, which is storage the image has.
#[test]
fn memory_identity_inside_a_mask_memory_window_is_owned() {
    let plan = full_memory_identity_plan(Some(16));

    assert_eq!(plan.image().byte(&ImageLocation::standard_memory(260)), Some((0xfa, 0xff)));
    assert_eq!(plan.image().byte(&ImageLocation::standard_memory(265)), Some((17, 0xff)));
}

fn full_memory_identity_plan(window: Option<u32>) -> crate::commissioning::CompiledProgram {
    let (catalog, product) = memory_identity_fixture(2, window);
    let profile = resolve_profile(&catalog, &product);

    compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Full),
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect("the full download compiles")
}
