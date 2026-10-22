use super::*;
use crate::commissioning::catalog_testing::*;

#[test]
fn full_ap1_only_download_selects_the_published_complete_single_application_path() {
    let catalog = parse_master_data(SYSTEM_B_APPLICATION_CATALOG_XML).expect("catalog parses");
    let product = system_b_product(false);
    let profile = resolve_system_b_profile(&catalog, &product);

    let plan = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Full),
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect("the AP1-only complete path compiles");

    assert_eq!(plan.program_sections(), Some(primary_application_program_sections()));
    assert!(plan.is_full_program_scope());
    assert!(matches!(
        plan.procedure().map(|procedure| &procedure.id),
        Some(ProcedureSourceId::MasterData(id)) if id.subtype.as_deref() == Some("ap1")
    ));
    assert_identity_write(&plan, 4);
    assert!(!image_owns_property(&plan, 5, zweidraehte_proto::pid::PROGRAM_VERSION));

    // `Load/ap1` deliberately unloads the fixed second machine during a
    // complete replacement, but must never load, write, or complete it.
    // Product controls scoped only to the `grp` partial variant are not a
    // second spelling of `full`; vendors use distinct full/partial
    // allocation controls at the same merge point.
    assert_eq!(procedure_load_actions(&plan, 5), vec![LoadEvent::Unload]);
    assert_eq!(procedure_delays(&plan), vec![17]);
}

#[test]
fn address_assignment_does_not_require_secondary_application_metadata() {
    let catalog = parse_master_data(SYSTEM_B_APPLICATION_CATALOG_XML).expect("catalog parses");
    for product in [
        system_b_product(true),
        system_b_product(false).with_fixture_application_program_2(ApplicationProgram2Binding::Unbound),
    ] {
        let profile = resolve_system_b_profile(&catalog, &product);
        let program = compile_program_fixture(
            programming_input(
                &catalog,
                &product,
                &configuration(),
                CommissioningIntent::AssignAddress,
                compile_options(RestartKind::Basic),
            ),
            profile.clone(),
        )
        .expect("address assignment does not consume primary or secondary application definitions");
        assert!(program.image().is_empty());
        assert!(program.procedure().is_none());
        assert!(program.program_sections().is_none());

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
        .expect_err("downloading the same product still requires supported, authoritative application metadata");
        assert_eq!(error.kind, CompileErrorKind::InvalidInput);
        let reason = match product.application_program_2() {
            ApplicationProgram2Binding::Present { .. } => "PEI Program content is not bound",
            ApplicationProgram2Binding::Unbound => "loose application MTXML cannot prove AP2 absent",
            ApplicationProgram2Binding::Absent { .. } => unreachable!("fixture lacks usable AP2 evidence"),
        };
        assert!(error.message.contains(reason));
    }
}

#[test]
fn system_b_requires_authoritative_hardware_metadata() {
    let catalog = parse_master_data(SYSTEM_B_APPLICATION_CATALOG_XML).expect("catalog parses");
    let product = system_b_product(false).with_fixture_application_program_2(ApplicationProgram2Binding::Unbound);
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
    .expect_err("lone System B MTXML cannot prove AP2 absent");

    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert!(error.to_string().contains("complete package"));
    assert!(error.to_string().contains("loose application MTXML cannot prove AP2 absent"));
}

#[test]
fn declared_secondary_application_fails_closed_until_its_definition_can_be_compiled() {
    let catalog = parse_master_data(SYSTEM_B_APPLICATION_CATALOG_XML).expect("catalog parses");
    let product = system_b_product(true);
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
    .expect_err("the primary application cannot impersonate a separate PeiProgram definition");

    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert!(error.to_string().contains("M-0083_A-0138-01-0000"));
    assert!(error.to_string().contains("PEI Program content is not bound"));
}

#[test]
fn ap2_requests_fail_closed_without_the_complete_product_contribution() {
    let catalog = parse_master_data(SYSTEM_B_APPLICATION_CATALOG_XML).expect("catalog parses");
    let product = system_b_product(false);
    let explicit_profile = resolve_system_b_profile(&catalog, &product);

    let explicit = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::APPLICATION_PROGRAM_2)),
            compile_options(RestartKind::Basic),
        ),
        explicit_profile,
    )
    .expect_err("an explicit AP2 request cannot use a fixed but unused Peiprog object");
    assert!(explicit.message.contains("has no Application Program 2"));

    let automatic_profile = resolve_system_b_profile(&catalog, &product);
    let mut options = compile_options(RestartKind::Basic);
    options.automatic_sections = Some(ProgramSections::APPLICATION_PROGRAM_2);

    let automatic = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Automatic),
            options,
        ),
        automatic_profile,
    )
    .expect_err("automatic AP2 staleness cannot widen an AP1-only product");
    assert!(automatic.message.contains("has no Application Program 2"));
}

#[test]
fn automatic_ap2_download_cannot_bypass_missing_secondary_compilation() {
    let catalog = parse_master_data(SYSTEM_B_APPLICATION_CATALOG_XML).expect("catalog parses");
    let product = system_b_product(true);
    let profile = resolve_system_b_profile(&catalog, &product);
    let mut options = compile_options(RestartKind::Basic);
    options.automatic_sections = Some(ProgramSections::APPLICATION_PROGRAM_2);

    let error = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Automatic),
            options,
        ),
        profile,
    )
    .expect_err("automatic selection cannot compile AP2 from the primary application");

    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert!(error.message.contains("PEI Program content is not bound"));
}

#[test]
fn ap1_only_partial_paths_strip_only_ap2_and_preserve_their_exact_scope() {
    let catalog = parse_master_data(SYSTEM_B_APPLICATION_CATALOG_XML).expect("catalog parses");
    let product = system_b_product(false);

    let parameter_profile = resolve_system_b_profile(&catalog, &product);
    let parameters = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::PARAMETERS)),
            compile_options(RestartKind::Basic),
        ),
        parameter_profile,
    )
    .expect("the AP1 parameter path compiles without the fixed AP2 sub-flow");
    assert_identity_write(&parameters, 4);
    assert!(!image_owns_property(&parameters, 4, zweidraehte_proto::pid::PROGRAM_VERSION));
    assert!(procedure_targets_object(&parameters, 4));
    assert!(!procedure_targets_object(&parameters, 5));
    assert!(!image_owns_property(&parameters, 5, zweidraehte_proto::pid::PROGRAM_VERSION));
    assert!(procedure_delays(&parameters).is_empty());

    let combined_sections = ProgramSections::PARAMETERS.union(ProgramSections::GROUP_COMMUNICATION);
    let combined_profile = resolve_system_b_profile(&catalog, &product);
    let combined = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Partial(combined_sections)),
            compile_options(RestartKind::Basic),
        ),
        combined_profile,
    )
    .expect("the combined AP1 parameter/group path keeps its group contribution");
    assert_eq!(combined.program_sections(), Some(combined_sections));
    assert_identity_write(&combined, 4);
    assert!(!image_owns_property(&combined, 4, zweidraehte_proto::pid::PROGRAM_VERSION));
    assert!(!procedure_targets_object(&combined, 5));
    assert_eq!(procedure_delays(&combined), vec![19]);

    let group_profile = resolve_system_b_profile(&catalog, &product);
    let group = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::GROUP_COMMUNICATION)),
            compile_options(RestartKind::Basic),
        ),
        group_profile,
    )
    .expect("the group-only path keeps only its applicable contribution");
    assert_eq!(procedure_delays(&group), vec![19]);
    assert!(!procedure_targets_object(&group, 5));

    let product = system_b_product(false);
    let profile = resolve_system_b_profile(&catalog, &product);
    let configuration = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::CONFIGURATION)),
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect("configuration-only AP1 compilation preserves its exact scope");

    // Application-only configuration has no exact network configuration
    // source; it must not execute a published broad Load/cfg procedure.
    assert!(procedure_delays(&configuration).is_empty());
    assert!(!procedure_targets_object(&configuration, 5));
    assert!(!image_owns_property(&configuration, 5, zweidraehte_proto::pid::PROGRAM_VERSION));
}

#[test]
fn omitted_peiprog_controls_preserve_original_xml_and_merge_paths() {
    let catalog = parse_master_data(SYSTEM_B_APPLICATION_CATALOG_XML).expect("catalog parses");
    let product =
        system_b_product(false).with_fixture_parameters(vec![zweidraehte_ets_files::product::ParameterLocation {
            id: "selected-parameter".to_owned(),
            code_segment: "ap1-code".to_owned(),
            offset: 0,
            bit_offset: 0,
            size_bits: 8,
            legacy_patch_always: false,
            seeds_default: false,
            byte_ordered: true,
        }]);
    let mut device_configuration = configuration();
    device_configuration
        .encoded_mut()
        .parameters
        .push(crate::configuration::EncodedParameter { id: "selected-parameter".to_owned(), value: vec![0x55] });
    let profile = resolve_system_b_profile(&catalog, &product);
    let program = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &device_configuration,
            CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::PARAMETERS)),
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect("the fixed AP2 controls can be omitted");
    let steps = &program.procedure().expect("download has controls").steps;

    let identity = steps
        .iter()
        .find(|step| {
            matches!(&step.operation, ProcedureOperation::Write {
                target: OperationTarget::Property {
                    address: PropertyAddress::Indexed { object_index: 4, property_id: 13 },
                    ..
                },
                ..
            })
        })
        .expect("the primary application identity is written");
    assert_eq!(identity.path.control_indices, [14]);

    let data = steps
        .iter()
        .find(|step| {
            matches!(&step.operation, ProcedureOperation::Write {
                data: OperationData::ImageWindow {
                    location: ImageLocation {
                        space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 4 } },
                        ..
                    },
                    ..
                },
                ..
            })
        })
        .expect("the product data fragment is spliced into the primary load");
    assert_eq!(data.path.control_indices, [12, 0]);
}

#[test]
fn primary_merge_fragments_do_not_establish_application_program_2() {
    let catalog = parse_master_data(SYSTEM_B_APPLICATION_CATALOG_XML).expect("catalog parses");
    let mut product = system_b_product(false);
    let mut fragments = product.load_procedures().to_vec();
    fragments.push(LoadProcedure {
        merge_id: Some(3),
        controls: vec![LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 1, ..Default::default() })],
    });
    fragments.push(LoadProcedure {
        merge_id: Some(5),
        controls: vec![LoadControl::LdCtrlDelay(LdCtrlDelay { milli_seconds: 1, ..Default::default() })],
    });
    product = product.with_fixture_load_procedures(fragments);
    let profile = resolve_system_b_profile(&catalog, &product);

    validate_application_metadata(&profile, &product).expect("hardware metadata is authoritative");
    assert!(matches!(product.application_program_2(), ApplicationProgram2Binding::Absent { .. }));
}

#[test]
fn primary_fragment_and_mask_can_both_write_the_secondary_identity() {
    let catalog = parse_master_data(SYSTEM_B_APPLICATION_CATALOG_XML).expect("catalog parses");
    let mut product = system_b_product_with_pei_program();
    let mut fragments = product.load_procedures().to_vec();
    fragments
        .iter_mut()
        .find(|fragment| fragment.merge_id == Some(2))
        .expect("primary allocation fragment")
        .controls
        .push(LoadControl::LdCtrlWriteProp(zweidraehte_ets_files::schema::LdCtrlWriteProp {
            obj_idx: Some(5),
            prop_id: 13,
            inline_data: Some("FFFFFFFFFF".to_owned()),
            ..Default::default()
        }));
    product = product.with_fixture_load_procedures(fragments);
    let profile = resolve_system_b_profile(&catalog, &product);
    let plan = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Full),
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect("repeated secondary identity writes are authored operations");
    let writes: Vec<_> = plan
        .procedure()
        .expect("download procedure")
        .steps
        .iter()
        .filter_map(|step| match &step.operation {
            ProcedureOperation::Write {
                target:
                    OperationTarget::Property {
                        address: PropertyAddress::Indexed { object_index: 5, property_id: 13 }, ..
                    },
                data,
                ..
            } => Some((step.path.control_indices.clone(), data)),
            _ => None,
        })
        .collect();
    assert_eq!(writes.len(), 2);
    assert_ne!(writes[0].0, writes[1].0);
    for (_, data) in writes {
        assert_eq!(*data, OperationData::Inline(vec![0x00, 0x83, 0x01, 0x38, 0x01]));
    }
}

#[test]
fn ap1_partial_rejects_an_unfamiliar_fixed_ap2_block() {
    let catalog_xml = SYSTEM_B_APPLICATION_CATALOG_XML.replacen(
        r#"<LdCtrlCompareProp ObjIdx="5" PropId="7" InlineData="00000000" />"#,
        r#"<LdCtrlCompareProp ObjIdx="5" PropId="7" InlineData="01000000" />"#,
        1,
    );
    let catalog = parse_master_data(&catalog_xml).expect("catalog parses");
    let product = system_b_product(false);
    let profile = resolve_system_b_profile(&catalog, &product);

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
    .expect_err("an unfamiliar AP2 sub-flow must not be stripped by resemblance");

    assert!(error.message.contains("invalid Application Program 2 contract"));
}

#[test]
fn peiprog_identity_must_keep_the_exact_five_byte_codec() {
    let catalog_xml = SYSTEM_B_APPLICATION_CATALOG_XML.replacen(
        r#"<Resource Name="PeiprogId" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="5" PropertyID="13" StartAddress="0" />
                <ResourceType Length="5" />"#,
        r#"<Resource Name="PeiprogId" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="5" PropertyID="13" StartAddress="0" />
                <ResourceType Length="4" />"#,
        1,
    );
    let catalog = parse_master_data(&catalog_xml).expect("catalog parses");
    let product = system_b_product(false);
    let profile = resolve_system_b_profile(&catalog, &product);

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
    .expect_err("Peiprog identity must never use the four-byte AP1 legacy codec");

    assert!(error.message.contains("invalid Application Program 2 contract"));
}

#[test]
fn fixed_peiprog_resource_without_merge_anchors_does_not_create_ap2_semantics() {
    let resources = r#"
            <Resources>
              <Resource Name="PeiprogId" Access="remote">
                <Location AddressSpace="StandardMemory" StartAddress="512" />
                <ResourceType Length="5" />
                <AccessRights Read="Runtime" Write="None" />
              </Resource>
            </Resources>
            <Procedures>"#;
    let xml = CATALOG_XML.replacen("<Procedures>", resources, 1);
    let catalog = parse_master_data(&xml).expect("catalog parses");
    let product = ProductData::default().with_fixture_id("fixed-peiprog-only");
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
    .expect("a legacy fixed resource alone does not trigger AP2 block handling");

    assert_eq!(plan.program_sections(), Some(ProgramSections::PARAMETERS.union(ProgramSections::GROUP_COMMUNICATION)));
    assert!(!plan.is_full_program_scope());
}

// A property-mapped identity has no owned product storage in the image. The
// full download writes it through the patched inline payload; allocating an
// unowned buffer must not claim identity bits or replace that fallback.
#[test]
fn property_mapped_identity_is_written_inline_without_image_ownership() {
    for authored in ["0000000000", "0102030405", "00000000000000", "0102030405ABCD"] {
        let catalog_xml = SYSTEM_B_APPLICATION_CATALOG_XML.replace(
            r#"<LdCtrlWriteProp ObjIdx="4" PropId="13" Verify="true" InlineData="0000000000" />"#,
            &format!(r#"<LdCtrlWriteProp ObjIdx="4" PropId="13" Verify="true" InlineData="{authored}" />"#),
        );
        let catalog = parse_master_data(&catalog_xml).expect("catalog parses");
        let product = system_b_product(false);
        let profile = resolve_system_b_profile(&catalog, &product);

        let plan = compile_program_fixture(
            programming_input(
                &catalog,
                &product,
                &configuration(),
                CommissioningIntent::Download(DownloadMode::Full),
                compile_options(RestartKind::Basic),
            ),
            profile,
        )
        .expect("the AP1-only complete path compiles");

        assert!(!image_owns_property(&plan, 4, zweidraehte_proto::pid::PROGRAM_VERSION), "authored {authored}");
        let identity = plan
            .procedure()
            .expect("download has a procedure")
            .steps
            .iter()
            .find_map(|step| match &step.operation {
                ProcedureOperation::Write {
                    target:
                        OperationTarget::Property {
                            address: PropertyAddress::Indexed { object_index, property_id: 13 },
                            start_element: 1,
                        },
                    data,
                    ..
                } if u16::from(*object_index) == 4 => Some(data),
                _ => None,
            })
            .expect("identity has a write");
        assert_eq!(identity, &OperationData::Inline(vec![0x00, 0x83, 0x01, 0x37, 0x20]), "authored {authored}");
    }
}

#[test]
fn bound_secondary_pei_program_compiles_with_the_primary_application() {
    let catalog = parse_master_data(SYSTEM_B_APPLICATION_CATALOG_XML).expect("catalog parses");
    let product = system_b_product_with_pei_program();
    let profile = resolve_system_b_profile(&catalog, &product);

    let plan = compile_program_fixture(
        programming_input(
            &catalog,
            &product,
            &configuration(),
            CommissioningIntent::Download(DownloadMode::Full),
            compile_options(RestartKind::Basic),
        ),
        profile,
    )
    .expect("a bound PEI Program compiles with AP1");

    // The download covers both applications and loads the second machine.
    assert!(plan.program_sections().is_some_and(|sections| sections.contains(ProgramSections::APPLICATION_PROGRAM_2)));
    assert!(procedure_load_actions(&plan, 5).contains(&LoadEvent::StartLoading));

    // The PEI Program's code is image content of AP2, and its identity, not
    // the primary's, is written to PeiprogId.
    assert_identity_write_of(&plan, 5, [0x00, 0x83, 0x01, 0x38, 0x01]);
    let code = plan
        .image()
        .segments()
        .iter()
        .find(|segment| {
            segment.location().space == ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 5 } }
        })
        .cloned()
        .expect("the PEI Program's relative segment is in the image");
    assert_eq!(code.data(), &[0xa2]);
}
