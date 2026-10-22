//! Shared synthetic target and program fixtures.

use super::*;
use crate::bus::access::ManagementCredential;
use crate::commissioning::catalog_testing::*;
use crate::commissioning::input::facts::{ObservedTarget, ProgrammingFacts};
use crate::commissioning::input::security::ObservedDataSecurity;

pub(super) fn system_b_product(application_program_2: bool) -> ProductData {
    let mut fragments = vec![
        LoadProcedure {
            merge_id: Some(2),
            controls: vec![LoadControl::LdCtrlRelSegment(LdCtrlRelSegment {
                applies_to: Some("full,par".to_owned()),
                lsm_idx: Some(4),
                size: 1,
                mode: 1,
                fill: 0,
                ..Default::default()
            })],
        },
        LoadProcedure {
            merge_id: Some(4),
            controls: vec![LoadControl::LdCtrlWriteRelMem(LdCtrlWriteRelMem {
                applies_to: Some("full,par".to_owned()),
                obj_idx: Some(4),
                offset: 0,
                size: 1,
                verify: true,
                ..Default::default()
            })],
        },
        LoadProcedure {
            merge_id: Some(7),
            controls: vec![
                LoadControl::LdCtrlDelay(LdCtrlDelay {
                    applies_to: Some("full".to_owned()),
                    milli_seconds: 17,
                    ..Default::default()
                }),
                LoadControl::LdCtrlDelay(LdCtrlDelay {
                    applies_to: Some("grp".to_owned()),
                    milli_seconds: 19,
                    ..Default::default()
                }),
                LoadControl::LdCtrlWriteMem(LdCtrlWriteMem {
                    applies_to: Some("grp".to_owned()),
                    address: 0x0100,
                    size: 1,
                    verify: false,
                    inline_data: Some("00".to_owned()),
                    ..Default::default()
                }),
            ],
        },
    ];
    let mut segments = vec![Segment {
        id: "ap1-code".to_owned(),
        address: None,
        size: 1,
        memory_type: None,
        user_memory: None,
        load_state_machine: Some(4),
        data: vec![0xa1],
        mask: None,
    }];
    if application_program_2 {
        fragments.extend([
            LoadProcedure {
                merge_id: Some(3),
                controls: vec![LoadControl::LdCtrlRelSegment(LdCtrlRelSegment {
                    applies_to: Some("full,par".to_owned()),
                    lsm_idx: Some(5),
                    size: 1,
                    mode: 1,
                    fill: 0,
                    ..Default::default()
                })],
            },
            LoadProcedure {
                merge_id: Some(5),
                controls: vec![LoadControl::LdCtrlWriteRelMem(LdCtrlWriteRelMem {
                    applies_to: Some("full,par".to_owned()),
                    obj_idx: Some(5),
                    offset: 0,
                    size: 1,
                    verify: true,
                    ..Default::default()
                })],
            },
        ]);
        segments.push(Segment {
            id: "ap2-code".to_owned(),
            address: None,
            size: 1,
            memory_type: None,
            user_memory: None,
            load_state_machine: Some(5),
            data: vec![0xa2],
            mask: None,
        });
    }

    let mut product = ProductData::default()
        .with_fixture_id(if application_program_2 { "system-b-ap2" } else { "system-b-ap1" })
        .with_fixture_mask_version_id("MV-07B0")
        .with_fixture_load_procedure_style(LoadProcedureStyle::Merged)
        .with_fixture_load_procedures(fragments)
        .with_fixture_application_identity(ApplicationIdentity {
            application_id: [0x00, 0x83, 0x01, 0x37, 0x20],
            pei_type: 0,
        })
        .with_fixture_application_program_2(if application_program_2 {
            ApplicationProgram2Binding::Present {
                relation: ApplicationProgramRelationIdentity {
                    catalog_product_id: Some("M-0083_H-1_P-1".to_owned()),
                    catalog_item_id: Some("M-0083_CI-1".to_owned()),
                    hardware_id: "M-0083_H-1".to_owned(),
                    hardware2program_id: "M-0083_H-1_HP-1".to_owned(),
                    application_program_id: "system-b-ap1".to_owned(),
                },
                application_program_id: "M-0083_A-0138-01-0000".to_owned(),
            }
        } else {
            ApplicationProgram2Binding::Absent {
                relation: ApplicationProgramRelationIdentity {
                    catalog_product_id: Some("M-0083_H-1_P-1".to_owned()),
                    catalog_item_id: Some("M-0083_CI-1".to_owned()),
                    hardware_id: "M-0083_H-1".to_owned(),
                    hardware2program_id: "M-0083_H-1_HP-1".to_owned(),
                    application_program_id: "system-b-ap1".to_owned(),
                },
            }
        })
        .with_fixture_segments(segments)
        .with_fixture_relative_segment_offset("ap1-code", 0);
    if application_program_2 {
        product = product.with_fixture_relative_segment_offset("ap2-code", 0);
    }

    product
}

/// An AP1 product whose relation binds a separate secondary PEI Program,
/// as a package loader extracts it: one LSM-5 relative segment, allocated at
/// merge point 3 and written at merge point 5.
pub(super) fn system_b_product_with_pei_program() -> ProductData {
    let relation = ApplicationProgramRelationIdentity {
        catalog_product_id: Some("M-0083_H-1_P-1".to_owned()),
        catalog_item_id: Some("M-0083_CI-1".to_owned()),
        hardware_id: "M-0083_H-1".to_owned(),
        hardware2program_id: "M-0083_H-1_HP-1".to_owned(),
        application_program_id: "system-b-ap1".to_owned(),
    };
    let pei_program = ProductData::default()
        .with_fixture_id("M-0083_A-0138-01-0000")
        .with_fixture_mask_version_id("MV-07B0")
        .with_fixture_load_procedure_style(LoadProcedureStyle::Merged)
        .with_fixture_load_procedures(vec![
            LoadProcedure {
                merge_id: Some(3),
                controls: vec![LoadControl::LdCtrlRelSegment(LdCtrlRelSegment {
                    applies_to: Some("full,par".to_owned()),
                    lsm_idx: Some(5),
                    size: 1,
                    mode: 1,
                    fill: 0,
                    ..Default::default()
                })],
            },
            LoadProcedure {
                merge_id: Some(5),
                controls: vec![LoadControl::LdCtrlWriteRelMem(LdCtrlWriteRelMem {
                    applies_to: Some("full,par".to_owned()),
                    obj_idx: Some(5),
                    offset: 0,
                    size: 1,
                    verify: true,
                    ..Default::default()
                })],
            },
        ])
        .with_fixture_application_identity(ApplicationIdentity {
            application_id: [0x00, 0x83, 0x01, 0x38, 0x01],
            pei_type: 0,
        })
        .with_fixture_segments(vec![Segment {
            id: "pei-code".to_owned(),
            address: None,
            size: 1,
            memory_type: None,
            user_memory: None,
            load_state_machine: Some(5),
            data: vec![0xa2],
            mask: None,
        }])
        .with_fixture_relative_segment_offset("pei-code", 0);
    system_b_product(false)
        .with_fixture_application_program_2(ApplicationProgram2Binding::Present {
            relation,
            application_program_id: "M-0083_A-0138-01-0000".to_owned(),
        })
        .bind_secondary_application(pei_program)
        .expect("the relation names this PEI Program")
}

pub(super) fn resolve_system_b_profile(
    catalog: &std::sync::Arc<MasterData>,
    product: &ProductData,
) -> crate::commissioning::ResolvedProfile {
    resolve_catalog_profile(catalog, Some(product), &ProfileSelection {
        discovery: ProfileDiscovery {
            dd0: 0x07b0,
            management_descriptor_01: None,
            management_style: Some(crate::commissioning::ResourceManagementStyle::LoadStateMachine),
        },
        variant_hint: VariantHint::Automatic,
    })
    .expect("System B profile resolves")
}

pub(super) fn assert_identity_write(plan: &crate::commissioning::CompiledProgram, object_index: u16) {
    assert_identity_write_of(plan, object_index, [0x00, 0x83, 0x01, 0x37, 0x20]);
}

pub(super) fn assert_identity_write_of(
    plan: &crate::commissioning::CompiledProgram,
    object_index: u16,
    expected: [u8; 5],
) {
    let data = plan
        .procedure()
        .expect("download has a procedure")
        .steps
        .iter()
        .find_map(|step| match &step.operation {
            ProcedureOperation::Write {
                target:
                    OperationTarget::Property {
                        address: PropertyAddress::Indexed { object_index: index, property_id: 13 },
                        start_element: 1,
                    },
                data,
                ..
            } if u16::from(*index) == object_index => Some(data),
            _ => None,
        })
        .expect("identity placeholder has a write");
    match data {
        OperationData::Buffer { location, length, .. } => {
            assert_eq!(*length, 5);
            assert_eq!(plan.image().range(location, *length).expect("identity is in the image").data(), expected);
        }
        OperationData::Inline(bytes) => assert_eq!(bytes, &expected),
        _ => panic!("identity placeholder must resolve its complete payload"),
    }
}

pub(super) fn procedure_targets_object(plan: &crate::commissioning::CompiledProgram, object_index: u16) -> bool {
    plan.procedure().into_iter().flat_map(|procedure| &procedure.steps).any(|step| {
        let target = match &step.operation {
            ProcedureOperation::LoadRecord(record) => &record.write.target,
            ProcedureOperation::ReadIntoImage { target, .. } | ProcedureOperation::Write { target, .. } |
            ProcedureOperation::Compare { target, .. } => target,
            _ => return false,
        };
        matches!(target, OperationTarget::Property { address: PropertyAddress::Indexed { object_index: index, .. }, .. } if u16::from(*index) == object_index)
    })
}

pub(super) fn procedure_load_actions(
    plan: &crate::commissioning::CompiledProgram,
    object_index: u16,
) -> Vec<LoadEvent> {
    plan.procedure().into_iter().flat_map(|procedure| &procedure.steps).filter_map(|step| {
        let ProcedureOperation::LoadRecord(record) = &step.operation else { return None };
        if !matches!(record.write.target, OperationTarget::Property { address: PropertyAddress::Indexed { object_index: index, .. }, .. } if u16::from(index) == object_index) {
            return None;
        }
        match record.bytes.first() {
            Some(1) => Some(LoadEvent::StartLoading),
            Some(2) => Some(LoadEvent::LoadCompleted),
            Some(4) => Some(LoadEvent::Unload),
            _ => None,
        }
    }).collect()
}

pub(super) fn procedure_delays(plan: &crate::commissioning::CompiledProgram) -> Vec<u32> {
    plan.procedure()
        .into_iter()
        .flat_map(|procedure| &procedure.steps)
        .filter_map(|step| match &step.operation {
            ProcedureOperation::Delay { milliseconds } => Some(*milliseconds),
            _ => None,
        })
        .collect()
}

pub(super) fn image_owns_property(
    plan: &crate::commissioning::CompiledProgram,
    object_index: u16,
    property_id: u16,
) -> bool {
    plan.image().segments().iter().any(|segment| {
        segment.mask().iter().any(|mask| *mask != 0)
            && matches!(
                &segment.location().space,
                crate::commissioning::ImageSpace::Property {
                    object: crate::commissioning::ObjectSelector::Index { index },
                    property_id: actual_property_id,
                } if *index == object_index && *actual_property_id == property_id
            )
    })
}

pub(super) fn invalid_application_product() -> ProductData {
    ProductData::default().with_fixture_id("scope-test").with_fixture_segments(vec![Segment {
        id: "oversized".to_owned(),
        address: Some(0x100),
        size: 1,
        memory_type: Some("EEPROM".to_owned()),
        user_memory: None,
        load_state_machine: None,
        data: vec![0x12, 0x34],
        mask: None,
    }])
}

pub(super) fn image_backed_unload_catalog() -> String {
    CATALOG_XML.replace(
        r#"<LdCtrlWriteMem Address="256" Size="1" Verify="false" InlineData="00" />"#,
        r#"<LdCtrlWriteMem Address="256" Size="1" Verify="false" />"#,
    )
}

pub(super) fn resolve_profile(
    catalog: &std::sync::Arc<MasterData>,
    _product: &ProductData,
) -> crate::commissioning::ResolvedProfile {
    resolve_catalog_profile(catalog, None, &ProfileSelection {
        discovery: ProfileDiscovery { dd0: 0x0012, management_descriptor_01: None, management_style: None },
        variant_hint: VariantHint::Automatic,
    })
    .expect("profile resolves")
}

pub(super) fn configuration() -> LoweredDeviceConfiguration {
    LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 10), Some(15))
}

/// Every fixture starts with disabled application security; access is supplied
/// separately so secure-management tests do not imply a secure application.
pub(super) fn programming_input(
    catalog: &std::sync::Arc<MasterData>,
    product: &ProductData,
    configuration: &LoweredDeviceConfiguration,
    intent: CommissioningIntent,
    options: CompileOptions,
) -> ProgrammingInput {
    let network = ObservedTarget {
        previous_address: configuration.individual_address,
        serial_number: None,
        credential: ManagementCredential::Plaintext,
    };
    let keys = ResolvedKeyMaterial::new(None);
    ProgrammingInput::new(
        MaterializedDevice::new(
            product.clone().bind_master_data(std::sync::Arc::clone(catalog)).expect("fixture document binds"),
            configuration.clone(),
            Vec::new(),
            keys,
        ),
        intent,
        options,
    )
    .facts(ProgrammingFacts::new(network).with_data_security(ObservedDataSecurity::Disabled))
}

pub(super) fn compile_options(_restart_kind: RestartKind) -> CompileOptions {
    CompileOptions {
        target: TargetSelection::ExistingAddress(IndividualAddress::new(1, 1, 10)),
        automatic_sections: None,
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
    }
}

pub(super) fn system_b_stamp_procedure() -> (crate::commissioning::ResolvedProfile, NormalizedProcedure) {
    let resources = (1..=4).map(|index| format!(r#"<Resource Name="Stamp{index}"><Location AddressSpace="SystemProperty" InterfaceObjectRef="{index}" PropertyID="27" StartAddress="0"/><ResourceType Length="8" Flavour="Stamp_SystemB"/><AccessRights Read="Runtime" Write="None"/></Resource>"#)).collect::<String>();
    let profile = fixture_profile(
        "MV-07B0",
        "SystemB",
        "MT-0",
        &format!(
            r#"<Features><Feature Name="DownloadStamp" Value="1"/><Feature Name="FirstAppObjectIdx" Value="6"/></Features><Resources>{resources}</Resources><InterfaceObjects></InterfaceObjects>"#
        ),
    );
    let source = ProcedureSourceId::Generated { name: "system-b-stamps".to_owned() };
    let mut operations = vec![ProcedureOperation::Connect];
    operations.extend((1..=4).map(|index| ProcedureOperation::LoadImage {
        target: OperationTarget::Property {
            address: PropertyAddress::Indexed { object_index: index as u8, property_id: 27 },
            start_element: 1,
        },
        image_location: ImageLocation {
            space: ImageSpace::Property { object: ObjectSelector::Index { index }, property_id: 27 },
            offset: 0,
        },
        extent: OperationExtent::property(8, 1),
        alignment: 8,
    }));
    operations.push(ProcedureOperation::Restart { kind: RestartKind::Basic });
    let steps = operations
        .into_iter()
        .enumerate()
        .map(|(index, operation)| ProcedureStep {
            path: ControlPath {
                mask_id: profile.mask().full_id.clone(),
                variant_index: profile.variant().source_index,
                procedure: source.clone(),
                contribution: None,
                control_indices: vec![index],
            },
            source_control_code: Some(match &operation {
                ProcedureOperation::Connect => 12,
                ProcedureOperation::Restart { .. } => 14,
                ProcedureOperation::LoadImage { .. } => 0xf0,
                _ => unreachable!("fixture contains only connect, property reads and restart"),
            }),
            sections: BTreeSet::new(),
            operation,
            on_error: vec![ErrorHandler { cause: LoadControlCause::ResourceNotFound, action: ErrorAction::Ignore }],
            secure_only: true,
        })
        .collect();
    let procedure = NormalizedProcedure {
        id: source,
        initial_state: ToolState::default(),
        steps,
        stamp_output: DownloadStampOutput::default(),
    };
    (profile, procedure)
}
