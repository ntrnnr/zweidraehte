//! The vendor-XML integration tier: parse real products, resolve their exact
//! Master Data profiles, compile normalized commissioning plans, and snapshot
//! everything that would reach the device.
//!
//! The vendor XML is licensed material living in the git-ignored
//! `manuf_tool_data/`; the test skips silently when it is absent, following the
//! repository convention for such files.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;
use zweidraehte_client::commissioning::{ManagementCredential, ObservedDataSecurity};
use zweidraehte_client::commissioning::{ObservedTarget, ProgrammingFacts};

use knx_config::load;
use zweidraehte_client::commissioning::inspection::{MemoryAddress, PropertyAddress};

use std::sync::Arc;
use zweidraehte_client::commissioning::inspection::{
    LoadEffect, LoadRecord, OperationData, OperationTarget, ProcedureOperation, WriteIntent, WritePolicy,
};
use zweidraehte_client::commissioning::{
    AssociationTableEntrySize, CommissioningIntent, CompileOptions, CompiledProgram, DownloadMode, ImageSpace,
    ObjectSelector, ProfileSelection, ProgramSections, ProgrammingInput, ResolvedProfile, ResourceFlavour,
    TargetSelection, UnloadMode,
};
use zweidraehte_client::configuration::ResolvedKeyMaterial;
use zweidraehte_client::configuration::{
    InstallationConfiguration, MaterializedDevice, MembershipRole, ObjectMembership,
};
use zweidraehte_client::{GroupAddress, IndividualAddress, pid};
use zweidraehte_ets_files::MasterData;
use zweidraehte_ets_files::product::{ApplicationProgramRelation, ProductData, SelectedProduct};
use zweidraehte_ets_files::runtime::Device;
use zweidraehte_ets_files::runtime::configuration::{ParameterSetting, ProductConfiguration, apply_configuration};
use zweidraehte_ets_files::runtime::model::ParameterValue;
use zweidraehte_ets_files::runtime::parse_application_program_from_file;
use zweidraehte_ets_files::schema::{HardwareApplicationProgram2, HardwareApplicationProgramPairing};

const VENDOR_XML: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../manuf_tool_data/MDT_KP_BE_01_Push_Button_Lite_55_63_V14/M-0083/M-0083_A-009B-14-E59D.xml"
);

const VENDOR_MASTER_DATA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../manuf_tool_data/MDT_KP_BE_01_Push_Button_Lite_55_63_V14/knx_master.xml"
);

const SYSTEM_B_VENDOR_XML: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../manuf_tool_data/Weinzierl-420-1-KNX-TP-Push-Button-secure-5492-ETS5/",
    "M-00C5/M-00C5_A-040D-12-BC0E.xml"
);

const SYSTEM_B_MASTER_DATA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../manuf_tool_data/Weinzierl-420-1-KNX-TP-Push-Button-secure-5492-ETS5/knx_master.xml"
);

const BCU2_VENDOR_XML: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../manuf_tool_data/linggjanke_bcu2_secure_taster/M-00E1_A-E032-40-9322.xml"
);

#[test]
fn vendor_program_compiles_to_a_stable_download() {
    let path = Path::new(VENDOR_XML);
    let master_data = Path::new(VENDOR_MASTER_DATA);
    if !path.exists() || !master_data.exists() {
        eprintln!("skipping: the licensed vendor XML is not on this machine");
        return;
    }

    let document = parse_application_program_from_file(path).expect("the vendor program parses");
    let selected = SelectedProduct::from_document(document, None, None).expect("the product data extracts");

    // The co-packaged project-11 Master Data preserves this legacy System 7
    // product's exact resource geometry and procedure semantics.
    let catalog = Arc::new(MasterData::from_file(master_data).expect("the fixture Master Data parses"));
    let selected = selected.bind_master_data(Arc::clone(&catalog)).expect("fixture document binds");

    let mut device = Device::from_product(Arc::new(selected), None, None);
    let settings = ProductConfiguration {
        parameters: vec![
            ParameterSetting { id: "M-0083_A-009B-14-E59D_P-4".into(), value: ParameterValue::Integer(1) },
            ParameterSetting { id: "M-0083_A-009B-14-E59D_P-6".into(), value: ParameterValue::Integer(0) },
        ],
        objects: Vec::new(),
    };
    apply_configuration(&mut device, &settings).expect("the project settings apply");

    let primary = GroupAddress::from_three_level(5, 1, 1);
    let additional = GroupAddress::from_three_level(5, 1, 3);
    let second = GroupAddress::from_three_level(5, 1, 2);
    let configuration = InstallationConfiguration {
        object_memberships: vec![
            ObjectMembership { group_address: primary, com_object: 0, role: MembershipRole::Primary },
            ObjectMembership { group_address: additional, com_object: 0, role: MembershipRole::Additional },
            ObjectMembership { group_address: second, com_object: 1, role: MembershipRole::Primary },
        ],
        ..InstallationConfiguration::new(IndividualAddress::new(1, 1, 60))
    };
    let resolved = MaterializedDevice::from_evaluated(
        device.evaluate(&settings.objects).expect("checked vendor settings"),
        configuration,
    )
    .expect("the configuration resolves");

    let resolved = resolved.into_keyed(ResolvedKeyMaterial::default());
    let Some(profile) = fixture_profile(&catalog, resolved.product()) else { return };
    let full = compile_plan(&profile, &resolved, CommissioningIntent::Download(DownloadMode::Full), None);

    // The sparse data/mask pairs and normalized controls are the complete
    // non-secret device-bound result. Snapshotting both catches drift in
    // parsing, exact-profile resolution, table encoding, patching, and
    // load-control lowering.
    let mut report = String::new();
    let _ = writeln!(report, "parameters patched: {}", resolved.parameters().len());
    let _ = writeln!(report, "links: {}", resolved.object_memberships().len());
    append_plan(&mut report, &full);
    insta::assert_snapshot!("mdt_full_download", report);

    let unload = compile_plan(&profile, &resolved, CommissioningIntent::Unload(UnloadMode::AllConfiguration), None);
    let mut unload_report = String::new();
    append_plan(&mut unload_report, &unload);
    insta::assert_snapshot!("mdt_unload_all", unload_report);
}

#[test]
fn published_partial_procedures_compile_for_real_bcu2_and_system_b_products() {
    let fixtures = [
        (
            Path::new(BCU2_VENDOR_XML),
            None,
            ProgramSections::APPLICATION_PROGRAM_1
                .union(ProgramSections::PARAMETERS)
                .union(ProgramSections::GROUP_COMMUNICATION)
                .union(ProgramSections::CONFIGURATION),
        ),
        (Path::new(SYSTEM_B_VENDOR_XML), Some(Path::new(SYSTEM_B_MASTER_DATA)), ProgramSections::PARAMETERS),
    ];

    for (path, explicit_master_data, expected_parameters) in fixtures {
        if !path.exists() {
            eprintln!("skipping {}: the licensed vendor XML is not on this machine", path.display());
            continue;
        }

        let document = parse_application_program_from_file(path).expect("the vendor program parses");

        // This test exercises procedure compilation from licensed, extracted
        // ApplicationProgram XML rather than commissioning a project device.
        // AP2 presence belongs to Hardware.xml, which these old fixture
        // directories do not retain, so bind the one fact the compiler needs
        // explicitly. Package-store integration tests cover authoritative
        // CatalogItem/Product/Hardware2Program selection for live projects.
        let application_program_id =
            document.manufacturer_data.manufacturer.application_programs.programs[0].id.clone();
        let relation = ApplicationProgramRelation {
            product_id: None,
            catalog_item_id: None,
            hardware: HardwareApplicationProgramPairing {
                hardware_id: format!("fixture-hardware-{application_program_id}"),
                hardware2program_id: format!("fixture-h2p-{application_program_id}"),
                application_program_id,
                application_program_2: HardwareApplicationProgram2::Absent,
                has_individual_address: true,
            },
        };
        let selected = SelectedProduct::from_document(document, Some(relation), None)
            .expect("the compiler-only fixture binds its missing hardware relation");
        let Ok(loaded) = load::load_master_data(selected.product(), explicit_master_data) else {
            eprintln!("skipping {}: exact versioned Master Data is unavailable", path.display());
            continue;
        };
        let catalog = &loaded;
        let selected = selected.bind_master_data(Arc::clone(catalog)).expect("fixture document binds");

        let mut device = Device::from_product(Arc::new(selected), None, None);
        let settings = ProductConfiguration { parameters: Vec::new(), objects: Vec::new() };
        apply_configuration(&mut device, &settings).expect("the default product configuration applies");
        let resolved = MaterializedDevice::from_evaluated(
            device.evaluate(&settings.objects).expect("checked vendor defaults"),
            InstallationConfiguration::new(IndividualAddress::new(1, 1, 42)),
        )
        .expect("the default configuration resolves");

        let resolved = resolved.into_keyed(ResolvedKeyMaterial::default());
        let Some(profile) = fixture_profile(catalog, resolved.product()) else { continue };

        // Automatic selection is intentional. This BCU2 product owns one
        // complete procedure, so every application update safely widens to
        // that full AP1 path. System B publishes a dedicated `par` procedure.
        let parameters = compile_plan(
            &profile,
            &resolved,
            CommissioningIntent::Download(DownloadMode::Automatic),
            Some(ProgramSections::PARAMETERS),
        );
        assert_eq!(parameters.program_sections(), Some(expected_parameters), "{}", path.display());

        let full = compile_plan(&profile, &resolved, CommissioningIntent::Download(DownloadMode::Full), None);
        if path == Path::new(BCU2_VENDOR_XML) {
            assert!(parameters.is_full_program_scope());
            assert_eq!(procedure_len(&parameters), procedure_len(&full));
        } else {
            assert!(
                procedure_len(&parameters) < procedure_len(&full),
                "{} parameter procedure has {} steps, full has {}",
                path.display(),
                procedure_len(&parameters),
                procedure_len(&full),
            );
        }

        if path == Path::new(BCU2_VENDOR_XML) {
            let procedure = full.procedure().expect("a full BCU2 download has a procedure");
            let service_control_writes: Vec<_> = procedure
                .steps
                .iter()
                .filter_map(|step| match &step.operation {
                    ProcedureOperation::Write {
                        target:
                            OperationTarget::Property {
                                address: PropertyAddress::Indexed { object_index: 0, property_id },
                                start_element: 1,
                            },
                        data: OperationData::Inline(data),
                        extent,
                        policy,
                    } if u16::from(*property_id) == pid::SERVICE_CONTROL => Some((data, extent, policy)),
                    _ => None,
                })
                .collect();
            assert_eq!(service_control_writes.len(), 1, "{} must write PID_SERVICE_CONTROL once", path.display());
            let (data, extent, policy) = service_control_writes[0];
            assert_eq!(data.as_slice(), &[0, 0]);
            assert_eq!(extent.byte_length, 2);
            assert_eq!(extent.property_elements, Some(1));
            assert!(matches!(
                *policy,
                WriteIntent::Explicit(WritePolicy::NoVerification) | WriteIntent::Property { verify: false }
            ));

            assert!(procedure.steps.iter().any(|step| matches!(
                &step.operation,
                ProcedureOperation::LoadRecord(record) if record_machine(record) == Some(3) && record.bytes[0] & 0x0f == 3 && record.bytes.get(1) == Some(&2)
            )));
            assert!(!procedure.steps.iter().any(|step| matches!(
                &step.operation,
                ProcedureOperation::LoadRecord(record) if record_machine(record) == Some(5) && record.bytes[0] & 0x0f == 3 && record.bytes.get(1) == Some(&2)
            )));
        }

        if path == Path::new(SYSTEM_B_VENDOR_XML) {
            for plan in [&parameters, &full] {
                let procedure = plan.procedure().expect("a download has a procedure");
                let relative_allocations = procedure
                    .steps
                    .iter()
                    .filter_map(|step| match &step.operation {
                        ProcedureOperation::LoadRecord(record) => match &record.effect {
                            LoadEffect::Invalidate { location, length } if record.bytes.starts_with(&[3, 11]) => {
                                assert_eq!(
                                    u32::from_be_bytes(record.bytes[2..6].try_into().expect("relative size")),
                                    *length
                                );
                                match location.space {
                                    ImageSpace::RelativeMemory { object: ObjectSelector::Index { index } } => {
                                        Some((index, *length))
                                    }
                                    _ => None,
                                }
                            }
                            _ => None,
                        },
                        _ => None,
                    })
                    .collect::<BTreeMap<_, _>>();
                let mut state = procedure.initial_state;
                for step in &procedure.steps {
                    if let ProcedureOperation::SetControlVariable { variable, value } = step.operation {
                        state.set(variable, value);
                    }
                    let ProcedureOperation::Write {
                        target: OperationTarget::Memory { address: MemoryAddress::Pointer { read, offset, .. }, .. },
                        extent,
                        policy,
                        ..
                    } = &step.operation
                    else {
                        continue;
                    };
                    let OperationTarget::Property {
                        address: PropertyAddress::Indexed { object_index: index, .. }, ..
                    } = read.target
                    else {
                        panic!("fixture relative write must read an indexed table pointer");
                    };
                    let written_end = offset.checked_add(extent.byte_length).expect("relative write range fits u32");
                    assert!(
                        relative_allocations.get(&u16::from(index)).is_some_and(|allocated| *allocated >= written_end),
                        "{} allocates too little relative memory for object {index}: {relative_allocations:?}, write ends at {written_end}",
                        path.display(),
                    );
                    assert_eq!(*policy, WriteIntent::Relative { verify: true });
                    let enables_verify = plan.profile().feature("VerifyMode").expect("verify mode resolves") == Some(1);
                    assert!(
                        state.memory_auto_verify.unwrap_or(enables_verify),
                        "relative verification must select the device Verify Mode"
                    );
                }

                let application_mcb_writes: Vec<_> = procedure
                    .steps
                    .iter()
                    .filter_map(|step| match &step.operation {
                        ProcedureOperation::Write {
                            target:
                                OperationTarget::Property {
                                    address: PropertyAddress::Indexed { object_index: 4, property_id },
                                    start_element,
                                },
                            extent,
                            policy,
                            ..
                        } if u16::from(*property_id) == pid::MCB_TABLE => Some((*start_element, *extent, *policy)),
                        _ => None,
                    })
                    .collect();
                assert_eq!(
                    application_mcb_writes.len(),
                    4,
                    "{} must write all four application MCB rows",
                    path.display()
                );
                for (index, extent, policy) in application_mcb_writes {
                    assert!((1..=4).contains(&index));
                    assert_eq!(extent.byte_length, 8);
                    assert_eq!(extent.property_elements, Some(1));
                    assert!(matches!(
                        policy,
                        WriteIntent::Explicit(WritePolicy::NoVerification) | WriteIntent::Property { verify: false }
                    ));
                }

                assert!(procedure.steps.iter().any(|step| matches!(
                    &step.operation,
                    ProcedureOperation::Write {
                        target: OperationTarget::Property {
                            address:PropertyAddress::Indexed{object_index:4,property_id},
                            ..
                        },
                        data,
                        ..
                    } if u16::from(*property_id)==pid::PROGRAM_VERSION && operation_data_matches(plan, data, &resolved.product().application_identity().application_id)
                )));
                assert!(
                    procedure.steps.iter().any(|step| matches!(
                        &step.operation,
                        ProcedureOperation::ReadIntoImage {
                            target: OperationTarget::Property {
                                address:PropertyAddress::Indexed{object_index:4,property_id},
                                ..
                            },
                            extent,
                            ..
                        } if u16::from(*property_id)==pid::MCB_TABLE && extent.property_elements == Some(4)
                    )),
                    "{} must retain all four application MCB rows",
                    path.display(),
                );
            }
        }

        let group = compile_plan(
            &profile,
            &resolved,
            CommissioningIntent::Download(DownloadMode::Automatic),
            Some(ProgramSections::GROUP_COMMUNICATION),
        );
        let expected_group = if path == Path::new(SYSTEM_B_VENDOR_XML) {
            ProgramSections::GROUP_COMMUNICATION
        } else {
            ProgramSections::APPLICATION_PROGRAM_1
                .union(ProgramSections::PARAMETERS)
                .union(ProgramSections::GROUP_COMMUNICATION)
                .union(ProgramSections::CONFIGURATION)
        };
        assert_eq!(group.program_sections(), Some(expected_group), "{}", path.display());

        if path == Path::new(SYSTEM_B_VENDOR_XML) {
            assert!(
                procedure_len(&group) < procedure_len(&full),
                "System B group procedure has {} steps, full has {}",
                procedure_len(&group),
                procedure_len(&full),
            );

            let procedure = group.procedure().expect("a group download has a procedure");
            assert!(
                !procedure.steps.iter().any(|step| operation_targets_application(&step.operation)),
                "System B group-only procedure must not reload either application program",
            );
        }
    }
}

fn operation_data_matches(plan: &CompiledProgram, data: &OperationData, expected: &[u8]) -> bool {
    match data {
        OperationData::Inline(data) => data == expected,
        OperationData::Image { location, length } | OperationData::Credential { location, length, .. } => plan
            .image()
            .range(location, *length)
            .is_ok_and(|segment| segment.data() == expected && segment.mask().iter().all(|mask| *mask == u8::MAX)),
        OperationData::Buffer { .. } | OperationData::ImageOverlay { .. } | OperationData::ImageWindow { .. } => false,
    }
}

fn compile_plan(
    profile: &ResolvedProfile,
    device: &MaterializedDevice,
    intent: CommissioningIntent,
    automatic_sections: Option<ProgramSections>,
) -> CompiledProgram {
    let input = ProgrammingInput::new(device.clone(), intent, CompileOptions {
        target: TargetSelection::ExistingAddress(device.individual_address()),
        automatic_sections,
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
    })
    // This compiler-only fixture models an already-disabled application and
    // explicit plain management; it does not observe or contact vendor hardware.
    .facts(ProgrammingFacts {
        target: Some(ObservedTarget {
            previous_address: device.individual_address(),
            serial_number: None,
            credential: ManagementCredential::Plaintext,
        }),
        data_security: ObservedDataSecurity::Disabled,
    });
    // A fixed-width System B table declares its own row width; record it as
    // the observation a live target would supply.
    let declared = match profile
        .resource("GroupAssociationTable")
        .expect("association resource resolves")
        .map(|resource| resource.flavour())
        .transpose()
        .expect("association realization resolves")
        .flatten()
    {
        Some(ResourceFlavour::AssociationTableSystemBSmall) => Some(AssociationTableEntrySize::TwoBytes),
        Some(ResourceFlavour::AssociationTableSystemBBig) => Some(AssociationTableEntrySize::FourBytes),
        _ => None,
    };
    let profile = match declared {
        Some(size) => profile.clone().with_association_table_entry_size(size).expect("declared width agrees"),
        None => profile.clone(),
    };
    input.compile(&profile).expect("the normalized commissioning plan compiles")
}

fn fixture_profile(catalog: &Arc<MasterData>, product: &ProductData) -> Option<ResolvedProfile> {
    let mask = product.mask_version().expect("the product names its mask");
    let product = product.clone().bind_master_data(Arc::clone(catalog)).expect("fixture document binds");
    let mut profile = ResolvedProfile::for_product(&product, &ProfileSelection::discovered(mask.as_u16()))
        .expect("the exact product profile resolves");

    if !profile.image_requirements().expect("image requirements resolve").is_empty() {
        // Extracted vendor XML does not contain this live capability. A test
        // operator may supply an observed width; link counts are not evidence.
        let Ok(bytes) = std::env::var("KNX_TEST_SYSTEM_B_ASSOCIATION_ENTRY_SIZE") else {
            eprintln!(
                "skipping {}: set KNX_TEST_SYSTEM_B_ASSOCIATION_ENTRY_SIZE to the observed PID_TABLE row width",
                product.id()
            );
            return None;
        };
        let size = match bytes.as_str() {
            "2" => AssociationTableEntrySize::TwoBytes,
            "4" => AssociationTableEntrySize::FourBytes,
            _ => panic!("KNX_TEST_SYSTEM_B_ASSOCIATION_ENTRY_SIZE must be 2 or 4"),
        };
        profile = profile.with_association_table_entry_size(size).expect("observed width agrees with fixture metadata");
    }
    Some(profile)
}

fn append_plan(report: &mut String, plan: &CompiledProgram) {
    let _ = writeln!(report, "profile: {}", plan.profile().mask().full_id);
    let _ = writeln!(report, "sections: {:?}", plan.program_sections());

    for segment in plan.image().segments() {
        let data: String = segment.data().iter().map(|byte| format!("{byte:02x}")).collect();
        let mask: String = segment.mask().iter().map(|byte| format!("{byte:02x}")).collect();
        let _ = writeln!(
            report,
            "segment {:?} at {:#08x} ({} bytes): data={data} mask={mask}",
            segment.location().space,
            segment.location().offset,
            segment.data().len(),
        );
    }

    match plan.procedure() {
        Some(procedure) => {
            let _ = writeln!(report, "procedure: {:?}", procedure.id);
            let _ = writeln!(report, "initial state: {:?}", procedure.initial_state);
            for step in &procedure.steps {
                let _ = writeln!(report, "{step:?}");
            }
        }
        None => {
            let _ = writeln!(report, "procedure: none");
        }
    }
}

fn procedure_len(plan: &CompiledProgram) -> usize {
    plan.procedure().map_or(0, |procedure| procedure.steps.len())
}

fn record_machine(record: &LoadRecord) -> Option<u16> {
    match &record.write.target {
        OperationTarget::Property { address: PropertyAddress::Indexed { object_index, .. }, .. } => {
            Some(u16::from(*object_index))
        }
        OperationTarget::Memory { .. } if record.bytes.len() == 11 => Some(u16::from(record.bytes[0] >> 4)),
        _ => None,
    }
}

fn operation_targets_application(operation: &ProcedureOperation) -> bool {
    let application_target = |target: &OperationTarget| match target {
        OperationTarget::Property { address: PropertyAddress::Indexed { object_index: 4 | 5, .. }, .. } => true,
        OperationTarget::Memory { address: MemoryAddress::Pointer { read, .. }, .. } => {
            matches!(read.target, OperationTarget::Property {
                address: PropertyAddress::Indexed { object_index: 4 | 5, .. },
                ..
            })
        }
        _ => false,
    };
    match operation {
        ProcedureOperation::LoadRecord(record) | ProcedureOperation::AbsoluteSegment { record, .. } => {
            record_machine(record).is_some_and(|index| matches!(index, 4 | 5))
        }
        ProcedureOperation::ReadIntoImage { target, .. }
        | ProcedureOperation::LoadImage { target, .. }
        | ProcedureOperation::Write { target, .. }
        | ProcedureOperation::Compare { target, .. } => application_target(target),
        _ => false,
    }
}
