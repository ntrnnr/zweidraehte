use super::*;
use crate::bus::access::ManagementCredential;
use crate::commissioning::catalog::profile::ResolvedProfile;
use crate::commissioning::catalog::profile::testing::fixture_profile;
use crate::commissioning::image::ImageSpace;
use crate::commissioning::input::facts::{ObservedTarget, ProgrammingFacts};
use crate::commissioning::input::security::{DesiredDataSecurity, ObservedDataSecurity};
use crate::commissioning::procedure::FunctionPropertyOperation;
use crate::commissioning::procedure::OperationTarget;
use crate::commissioning::procedure::ProcedureStep;
use crate::commissioning::procedure::{OperationData, ProcedureOperation};
use crate::configuration::{
    GroupObjectProtection, GroupObjectSecurity, MaterializedDevice, ObjectMembership, SecurityConfig,
};
use std::collections::BTreeSet;
use zweidraehte_ets_files::product::ComObjectDef;
use zweidraehte_ets_files::product::{ProductData, fixtures::SYSTEM7_MTXML};
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};
use zweidraehte_proto::pid;

fn desired_image(
    desired: DesiredDataSecurity,
    supported: bool,
    configured: bool,
    selected: bool,
) -> Result<crate::commissioning::compiler::image::ProgramImage, CompileError> {
    let product = ProductData::from_mtxml_str(SYSTEM7_MTXML)
        .expect("fixture parses")
        .with_fixture_data_secure(supported)
        .with_fixture_security_capacities(4, 4, 0);
    let project = MaterializedDevice::fixture(IndividualAddress::new(1, 1, 10), Some(15));
    let security = configured.then(SecurityConfig::default);
    let configuration = project.with_com_objects(product.com_objects().to_vec());
    // The public input derives the desired mode from the key material, so it
    // cannot contradict the tables. Force it here to exercise the stage's own
    // contradiction checks.
    let mut input = super::super::fixture_input(&product, &configuration, security.as_ref(), None);
    input.desired_data_security = desired;
    let mut compiler = super::super::fixture_compiler(&input, &profile());
    compiler.feature_sections =
        if selected { ProgramSections::GROUP_COMMUNICATION } else { ProgramSections::PARAMETERS };
    compiler.recipes = crate::commissioning::compiler::selection::RecipeSet::Automatic;
    compiler.contribute_data_secure()?;
    Ok(compiler.image)
}

#[test]
fn disabled_security_image_defers_device_mode_validation_until_scope_is_selected() {
    let image = desired_image(DesiredDataSecurity::Disabled, true, false, true)
        .expect("desired disabled state needs no device observation");
    let flags = image.image.segments();
    assert_eq!(flags.len(), 1);
    assert_eq!(flags[0].location().space, ImageSpace::Property {
        object: SECURITY_OBJECT,
        property_id: pid::security::GO_SECURITY_FLAGS,
    });
    assert!(!flags[0].data().is_empty());
    assert!(flags[0].data().iter().all(|byte| *byte == 0));
    assert!(flags[0].mask().iter().all(|byte| *byte == 255));
    assert!(
        desired_image(DesiredDataSecurity::Disabled, true, false, false)
            .expect("unselected group flags are preserved")
            .image
            .is_empty()
    );
    // Scope exclusion also suppresses configuration that cannot be enabled.
    assert!(
        desired_image(DesiredDataSecurity::Enabled, false, false, false)
            .expect("unselected security is preserved")
            .image
            .is_empty()
    );
}

#[test]
fn desired_security_can_be_built_before_management_access_is_selected() {
    assert!(
        !desired_image(DesiredDataSecurity::Enabled, true, true, true)
            .expect("desired security image needs no management credential")
            .image
            .is_empty()
    );
    assert!(
        desired_image(DesiredDataSecurity::Preserve, true, true, true)
            .expect("explicit preserve emits no security state")
            .image
            .is_empty()
    );
    let error =
        desired_image(DesiredDataSecurity::Enabled, true, false, true).expect_err("enabling requires security tables");
    assert_eq!(error.message, "enabling Data Secure requires explicit security configuration");
    let error =
        desired_image(DesiredDataSecurity::Enabled, false, true, true).expect_err("enabling requires product support");
    assert!(error.message.contains("without Data Secure support"));
}

#[test]
fn plain_profile_needs_no_security_observation_for_explicit_disabled_intent() {
    assert!(
        desired_image(DesiredDataSecurity::Disabled, false, false, true)
            .expect("plain product has no security state")
            .image
            .is_empty()
    );
    let error = desired_image(DesiredDataSecurity::Disabled, false, true, true)
        .expect_err("disabled intent cannot carry security tables");
    assert_eq!(error.message, "Data Secure intent contradicts the supplied security configuration");
}

#[test]
fn disabled_security_owns_flags_but_transfers_only_with_keyed_management() {
    let product = ProductData::from_mtxml_str(SYSTEM7_MTXML)
        .expect("fixture parses")
        .with_fixture_data_secure(true)
        .with_fixture_security_capacities(4, 4, 0);
    let configuration = MaterializedDevice::fixture(IndividualAddress::new(1, 1, 10), Some(15))
        .with_com_objects(product.com_objects().to_vec());
    let profile = profile();

    for credential in [ManagementCredential::ToolKey, ManagementCredential::Fdsk, ManagementCredential::Plaintext] {
        let target =
            ObservedTarget { previous_address: configuration.individual_address(), serial_number: None, credential };
        let input = super::super::fixture_input(&product, &configuration, None, None)
            .with_facts(ProgrammingFacts { target: Some(target), data_security: ObservedDataSecurity::Disabled });
        let mut compiler = super::super::fixture_compiler(&input, &profile);
        compiler.contribute_data_secure().expect("disabled security compiles");
        let image = compiler.image.image;
        let crate::commissioning::compiler::selection::RecipeSet::Exact { procedure, .. } = compiler.recipes else {
            panic!("fixture has an exact procedure");
        };
        let steps = procedure.finish(&profile, &image, false).expect("feature controls bind").steps;
        let contributed: Vec<_> = steps.iter().filter(|step| step.path.contribution.is_some()).collect();
        let segments = image.segments();
        let flag_segment = segments.iter().find(|segment| {
            matches!(segment.location().space, ImageSpace::Property {
                property_id: pid::security::GO_SECURITY_FLAGS,
                ..
            })
        });
        let flag_segment = flag_segment.expect("selected group image owns public flags");
        assert!(!flag_segment.data().is_empty());
        assert!(flag_segment.data().iter().all(|byte| *byte == 0));
        assert!(flag_segment.mask().iter().all(|byte| *byte == 255));
        if credential.is_secure() {
            assert_eq!(
                contributed.iter().filter(|step| matches!(step.operation, ProcedureOperation::LoadRecord(_))).count(),
                3
            );
            assert!(contributed.iter().all(|step| step.secure_only));
            let reset_index = contributed
                .iter()
                .position(|step| {
                    matches!(&step.operation, ProcedureOperation::Write {
                    target,
                    data: OperationData::Inline(bytes),
                    extent: OperationExtent { byte_length: 2, property_elements: Some(1), property_element_width: None },
                    policy: WriteIntent::Property { verify: true },
                } if target == &property_target(pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 0)
                    && bytes == &[0, 0])
                })
                .expect("count reset precedes public flags");
            assert_eq!(reset_index, 2);
            assert_eq!(contributed[reset_index].on_error, [ErrorHandler {
                cause: LoadControlCause::ResourceNotFound,
                action: ErrorAction::Ignore,
            }]);
            assert!(matches!(&contributed[reset_index + 1].operation, ProcedureOperation::Write {
                target,
                policy: WriteIntent::Property { verify: true },
                ..
            } if target == &property_target(pid::security::GO_SECURITY_FLAGS, 1)));
            assert!(!contributed.iter().any(|step| matches!(step.operation, ProcedureOperation::FunctionProperty(_))));
        } else {
            assert!(contributed.is_empty());
        }
    }
}

#[test]
fn siat_rows_are_sorted_and_use_six_byte_sequences() {
    let first = zweidraehte_proto::address::IndividualAddress::new(1, 1, 1);
    let second = zweidraehte_proto::address::IndividualAddress::new(1, 1, 2);

    let encoded = encode_siat(&[(second, 0x0102_0304_0506), (first, 7)]).expect("SIAT encodes");

    assert_eq!(&encoded[..2], first.as_bytes());
    assert_eq!(&encoded[2..8], &[0, 0, 0, 0, 0, 7]);
    assert_eq!(&encoded[8..10], second.as_bytes());
    assert_eq!(&encoded[10..], &[1, 2, 3, 4, 5, 6]);
}

#[test]
fn go_flags_follow_the_exact_table_realization_asap_origin() {
    let effective = vec![
        ComObjectDef {
            number: 1,
            object_type: ComObjectType::Uint1,
            datapoint_type: None,
            flags: ComObjectFlags::from_byte(0),
        },
        ComObjectDef {
            number: 2,
            object_type: ComObjectType::Uint1,
            datapoint_type: None,
            flags: ComObjectFlags::from_byte(0),
        },
    ];
    let configured =
        vec![GroupObjectSecurity { com_object: 2, protection: GroupObjectProtection::AuthenticationConfidentiality }];

    let zero_based = encode_group_object_security(&configured, &effective, 0).expect("zero-based convention encodes");
    let one_based = encode_group_object_security(&configured, &effective, 1).expect("one-based convention encodes");

    assert_eq!(zero_based, [0, 0, 3]);
    assert_eq!(one_based, [0, 3]);
}

#[test]
fn go_flags_end_at_the_effective_roster() {
    // The native sparse F002 witness owns five flags for active objects 3/4,
    // even though the application declares later inactive objects through 85.
    let effective = [3, 4].map(|number| ComObjectDef {
        number,
        object_type: ComObjectType::Uint1,
        datapoint_type: None,
        flags: ComObjectFlags::from_byte(0),
    });
    let configured =
        [GroupObjectSecurity { com_object: 4, protection: GroupObjectProtection::AuthenticationConfidentiality }];
    assert_eq!(encode_group_object_security(&configured, &effective, 0).expect("sparse protection encodes"), [
        0, 0, 0, 0, 3
    ]);
}

#[test]
fn disabled_security_empty_effective_roster_has_no_flags() {
    // Native B002/F002 captures with an empty roster have no PID 61 image,
    // despite declaring communication objects in the application definition.
    let product = ProductData::from_mtxml_str(SYSTEM7_MTXML).expect("fixture parses").with_fixture_data_secure(true);
    assert!(!product.com_object_numbers().is_empty());
    let configuration = MaterializedDevice::fixture(IndividualAddress::new(1, 1, 10), Some(15));
    let input = super::super::fixture_input(&product, &configuration, None, None);
    let mut compiler = super::super::fixture_compiler(&input, &profile());
    compiler.contribute_data_secure().expect("empty roster has no security flags");
    assert!(compiler.image.image.is_empty());
}

#[test]
fn standard_overlay_writes_group_keys_from_the_image() {
    let product = ProductData::from_mtxml_str(SYSTEM7_MTXML)
        .expect("fixture parses")
        .with_fixture_data_secure(true)
        .with_fixture_security_capacities(4, 4, 0);
    let group_address = GroupAddress::from_three_level(1, 2, 3);
    let key = [0xA7; 16];
    let mut project = MaterializedDevice::fixture(IndividualAddress::new(1, 1, 10), Some(15));
    project.object_memberships_mut().push(ObjectMembership::primary(group_address, 1));
    let security =
        Some(SecurityConfig::new(vec![(group_address, key)], vec![(IndividualAddress::new(1, 1, 11), 42)], vec![
            GroupObjectSecurity { com_object: 1, protection: GroupObjectProtection::AuthenticationConfidentiality },
        ]));
    let configuration = project.with_com_objects(product.com_objects().to_vec());

    let (image, operations) =
        super::super::compile_fixture(&profile(), &product, &configuration, security.as_ref(), None, |compiler| {
            compiler.contribute_data_secure()
        });

    use crate::commissioning::procedure::operands::PropertyAddress;
    use zweidraehte_proto::messages::apdu::load_control::LoadState;
    let records: Vec<_> = operations
        .iter()
        .filter_map(|operation| match operation {
            ProcedureStep { operation: ProcedureOperation::LoadRecord(record), .. } => Some(record),
            _ => None,
        })
        .collect();
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|record| matches!(record.write.target, OperationTarget::Property {
        address: PropertyAddress::Extended {
            object_type: zweidraehte_proto::dpt::InterfaceObjectType::Security,
            property_id: 5,
            object_instance: 1
        },
        start_element: 1
    })));
    let complete_loading = operations
        .iter()
        .position(|operation| {
            matches!(operation, ProcedureStep { operation: ProcedureOperation::LoadRecord(record), .. }
            if record.poll.as_ref().is_some_and(|(_, state)| *state == LoadState::Loaded))
        })
        .expect("Security IO commits");
    // Loading the tables leaves the Security Mode alone; the session before
    // the download switches it.
    assert!(!operations.iter().any(|operation| matches!(operation, ProcedureStep {
        operation: ProcedureOperation::FunctionProperty(FunctionPropertyOperation::Invoke {
            address: PropertyAddress::Extended { property_id: pid::security::SECURITY_MODE, .. },
            ..
        }),
        ..
    })));
    // The block ends with Security IO's own commit, and its table writes are
    // verified like every other reference property write.
    assert!(operations[..=complete_loading].iter().all(|operation| match &operation.operation {
        ProcedureOperation::Write { policy, .. } => *policy == WriteIntent::Property { verify: true },
        _ => true,
    }));

    let public_pids: BTreeSet<_> = image
        .image
        .segments()
        .iter()
        .filter_map(|segment| match &segment.location().space {
            ImageSpace::Property { property_id, .. } => Some(*property_id),
            _ => None,
        })
        .collect();
    assert_eq!(
        public_pids,
        BTreeSet::from([
            pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
            pid::security::GROUP_KEY_TABLE,
            pid::security::GO_SECURITY_FLAGS,
        ])
    );

    let (location, effects, secret_target) = operations
        .iter()
        .find_map(|operation| match operation {
            ProcedureStep {
                operation:
                    ProcedureOperation::Write { data: OperationData::Credential { location, effects, .. }, target, .. },
                ..
            } => Some((location, effects, target)),
            _ => None,
        })
        .expect("group-key write is a credential write from the image");
    assert_eq!(effects.group_keys, [group_address]);
    // The key row is ordinary owned image content.
    let row = image.image.range(location, 18).expect("group-key row is in the image");
    assert_eq!(&row.data()[2..], &key[..]);
    assert!(row.mask().iter().all(|mask| *mask == 0xff));
    assert!(matches!(secret_target, OperationTarget::Property {
        address: PropertyAddress::Extended { property_id: pid::security::GROUP_KEY_TABLE, .. },
        start_element: 1,
        ..
    }));
    assert!(!operations.iter().any(|operation| matches!(operation, ProcedureStep {
        operation: ProcedureOperation::Write {
            target: OperationTarget::Property {
                address: PropertyAddress::Extended { property_id: pid::security::GROUP_KEY_TABLE, .. },
                start_element: 0,
                ..
            },
            ..
        },
        ..
    })));
    assert_eq!(&row.data()[..2], &[0, 1]);
}

fn profile() -> ResolvedProfile {
    fixture_profile(
        "MV-0705",
        "BimM112",
        "MT-0",
        r#"<Features><Feature Name="FirstAppObjectIdx" Value="5"/></Features><Resources><Resource Name="GroupObjectTable"><Location AddressSpace="StandardMemory" StartAddress="16896"/><ResourceType Length="16" Flavour="GroupObjectTable_M112"/><AccessRights Read="Configuration" Write="Configuration"/></Resource></Resources><InterfaceObjects></InterfaceObjects>"#,
    )
}

#[test]
fn security_preserves_native_source_cursor_order() {
    use crate::commissioning::compiler::binding::procedure::{ProcedureInput, parse};
    use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
    use crate::commissioning::procedure::operands::StandardMemoryService;
    use crate::commissioning::procedure::{ProcedureSourceId, RestartKind, ToolState};
    use std::collections::BTreeMap;
    use zweidraehte_ets_files::product::ApplicationIdentity;
    use zweidraehte_ets_files::schema::{
        LdCtrlConnect, LdCtrlDelay, LdCtrlDisconnect, LdCtrlLoad, LdCtrlLoadCompleted, LdCtrlMasterReset,
        LdCtrlRestart, LdCtrlUnload, LoadControl,
    };

    // These sequences distinguish the native integer-cursor behavior from a
    // first-completion rule and from reloading after all ordinary commits.
    // In particular, equal cursor positions put reload before security unload.
    // Enabling security uses the same cursors; its rows follow the reset.
    let cases: &[(&[&str], &[&str])] = &[
        (&["unload", "load", "delay", "complete", "later-delay", "complete"], &[
            "connect",
            "unload",
            "security-unload",
            "load",
            "security-start",
            "security-reset",
            "security-flags",
            "security-complete",
            "delay",
            "complete",
            "later-delay",
            "complete",
            "disconnect",
        ]),
        (&["load", "delay", "complete", "unload", "later-delay"], &[
            "connect",
            "load",
            "delay",
            "security-start",
            "security-reset",
            "security-flags",
            "security-complete",
            "complete",
            "unload",
            "security-unload",
            "later-delay",
            "disconnect",
        ]),
        (&["load", "delay", "complete"], &[
            "connect",
            "load",
            "delay",
            "security-unload",
            "security-start",
            "security-reset",
            "security-flags",
            "security-complete",
            "complete",
            "disconnect",
        ]),
        (&["unload", "complete"], &[
            "connect",
            "unload",
            "security-start",
            "security-reset",
            "security-flags",
            "security-complete",
            "security-unload",
            "complete",
            "disconnect",
        ]),
        (&["unload", "delay", "complete"], &[
            "connect",
            "unload",
            "security-unload",
            "security-start",
            "security-reset",
            "security-flags",
            "security-complete",
            "delay",
            "complete",
            "disconnect",
        ]),
        (&["unload", "load", "delay", "restart"], &[
            "connect",
            "unload",
            "security-unload",
            "load",
            "security-start",
            "security-reset",
            "security-flags",
            "security-complete",
            "delay",
            "restart",
        ]),
        (&["unload", "load", "delay", "reset"], &[
            "connect",
            "unload",
            "security-unload",
            "load",
            "security-start",
            "security-reset",
            "security-flags",
            "security-complete",
            "delay",
            "reset",
        ]),
    ];

    let product = ProductData::from_mtxml_str(SYSTEM7_MTXML)
        .expect("fixture parses")
        .with_fixture_data_secure(true)
        .with_fixture_security_capacities(4, 4, 0);
    let configuration = MaterializedDevice::fixture(IndividualAddress::new(1, 1, 10), Some(15))
        .with_com_objects(product.com_objects().to_vec());
    let mut profile = profile();
    crate::commissioning::catalog::profile::testing::append_xml(
        &mut profile,
        "Features",
        r#"<Feature Name="PropertyMappedLsms" Value="1"/>"#,
    );
    let target = ObservedTarget {
        previous_address: configuration.individual_address(),
        serial_number: None,
        credential: ManagementCredential::ToolKey,
    };
    let group_address = GroupAddress::from_three_level(1, 2, 3);
    let mut keyed_configuration = configuration.clone();
    keyed_configuration.object_memberships_mut().push(ObjectMembership::primary(group_address, 1));
    let security =
        SecurityConfig::new(vec![(group_address, [0xA7; 16])], vec![(IndividualAddress::new(1, 1, 11), 42)], vec![
            GroupObjectSecurity { com_object: 1, protection: GroupObjectProtection::AuthenticationConfidentiality },
        ]);

    for enabled in [false, true] {
        let input = if enabled {
            super::super::fixture_input(&product, &keyed_configuration, Some(&security), None)
        } else {
            super::super::fixture_input(&product, &configuration, None, None)
        }
        .with_facts(ProgrammingFacts { target: Some(target), data_security: ObservedDataSecurity::Disabled });

        for &(names, expected) in cases {
            let expected: Vec<&str> = expected
                .iter()
                .flat_map(|name| match *name {
                    "security-reset" if enabled => vec!["security-reset", "security-siat", "security-keys"],
                    name => vec![name],
                })
                .collect();
            let mut controls = vec![LoadControl::LdCtrlConnect(LdCtrlConnect::default())];
            controls.extend(names.iter().map(|name| match *name {
                "unload" => LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: Some(1), ..Default::default() }),
                "load" => LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: Some(1), ..Default::default() }),
                "complete" => {
                    LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: Some(1), ..Default::default() })
                }
                "delay" | "later-delay" => LoadControl::LdCtrlDelay(LdCtrlDelay {
                    milli_seconds: if *name == "delay" { 17 } else { 19 },
                    ..Default::default()
                }),
                "restart" => LoadControl::LdCtrlRestart(LdCtrlRestart::default()),
                "reset" => LoadControl::LdCtrlMasterReset(LdCtrlMasterReset { erase_code: 1, ..Default::default() }),
                _ => unreachable!("fixed source vocabulary"),
            }));
            if !matches!(names.last(), Some(&"restart" | &"reset")) {
                controls.push(LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()));
            }
            let empty = BTreeMap::new();
            let source = ProcedureInput {
                profile: &profile,
                procedure_id: ProcedureSourceId::Generated { name: "security-cursor-fixture".into() },
                composition: ProcedureComposition::Default,
                controls: &controls,
                product_merge_fragments: Vec::new(),
                secondary_merge_fragments: Vec::new(),
                secondary_product_procedure: None,
                secondary_application_id: None,
                module_procedures: Vec::new(),
                feature_property_objects: Vec::new(),
                omitted_controls: Vec::new(),
                parameter_values: &empty,
                applicability: ProcedureApplicability::full(),
                configuration_anchor: profile.configuration_anchor(),
                download_stamps: Vec::new(),
                property_parameters: &[],
                peiprog_identity_reference: false,
                application_program_2_present: false,
                progress_messages_by_reference: &BTreeMap::new(),
                progress_messages_by_id: &BTreeMap::new(),
                message_sources: Vec::new(),
                initial_tool_state: ToolState::default(),
                standard_memory_service: StandardMemoryService::Classic,
                restart_kind: RestartKind::Basic,
                application_identity: ApplicationIdentity::default(),
                secondary_application_identity: None,
                extended_property_descriptions: false,
            };
            let parsed = parse(&source).expect("source parses");
            let mut compiler = super::super::fixture_compiler(&input, &profile);
            let crate::commissioning::compiler::selection::RecipeSet::Exact { procedure, .. } = &mut compiler.recipes
            else {
                unreachable!("fixture has an exact recipe")
            };
            *procedure = Box::new(parsed);
            compiler.contribute_data_secure().expect("security contributes");
            let crate::commissioning::compiler::selection::RecipeSet::Exact { procedure, .. } = compiler.recipes else {
                unreachable!("fixture has an exact recipe")
            };
            let program =
                procedure.finish(&profile, &compiler.image.image, false).expect("native-shaped controls bind");
            let actual: Vec<_> = program
                .steps
                .iter()
                .map(|step| {
                    let security = step.path.contribution == Some("standard-data-secure");
                    match &step.operation {
                        ProcedureOperation::Connect => "connect",
                        ProcedureOperation::Disconnect => "disconnect",
                        ProcedureOperation::LoadRecord(record) => match (security, record.bytes[0]) {
                            (true, 4) => "security-unload",
                            (true, 1) => "security-start",
                            (true, 2) => "security-complete",
                            (false, 4) => "unload",
                            (false, 1) => "load",
                            (false, 2) => "complete",
                            _ => unreachable!("fixture load event"),
                        },
                        ProcedureOperation::Write { target, .. } if security => {
                            if target == &property_target(pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 0) {
                                "security-reset"
                            } else if target == &property_target(pid::security::GO_SECURITY_FLAGS, 1) {
                                "security-flags"
                            } else if target == &property_target(pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 1) {
                                "security-siat"
                            } else if target == &property_target(pid::security::GROUP_KEY_TABLE, 1) {
                                "security-keys"
                            } else {
                                unreachable!("fixture security property")
                            }
                        }
                        ProcedureOperation::Delay { milliseconds } => {
                            if *milliseconds == 17 {
                                "delay"
                            } else {
                                "later-delay"
                            }
                        }
                        ProcedureOperation::Restart { .. } => "restart",
                        ProcedureOperation::MasterReset { .. } => "reset",
                        _ => unreachable!("fixture operation"),
                    }
                })
                .collect();
            assert_eq!(actual, expected, "enabled {enabled}, source {names:?}");
        }
    }
}

#[test]
fn group_key_exposure_identities_follow_encoded_rows_not_input_order() {
    let product = ProductData::from_mtxml_str(SYSTEM7_MTXML)
        .expect("fixture parses")
        .with_fixture_data_secure(true)
        .with_fixture_security_capacities(4, 4, 0);
    let first = GroupAddress::from_three_level(1, 0, 1);
    let second = GroupAddress::from_three_level(1, 0, 2);
    let mut project = MaterializedDevice::fixture(IndividualAddress::new(1, 1, 10), Some(15));
    *project.object_memberships_mut() = vec![ObjectMembership::primary(second, 1), ObjectMembership::primary(first, 1)];
    let security =
        Some(SecurityConfig::new(vec![(second, [0x22; 16]), (first, [0x11; 16])], vec![], vec![GroupObjectSecurity {
            com_object: 1,
            protection: GroupObjectProtection::AuthenticationConfidentiality,
        }]));
    let configuration = project.with_com_objects(product.com_objects().to_vec());
    let (image, operations) =
        super::super::compile_fixture(&profile(), &product, &configuration, security.as_ref(), None, |compiler| {
            compiler.contribute_data_secure()
        });
    let (location, length, effects) = operations
        .iter()
        .find_map(|step| match &step.operation {
            ProcedureOperation::Write { data: OperationData::Credential { location, length, effects }, .. } => {
                Some((location, *length, effects))
            }
            _ => None,
        })
        .expect("compiled GKT transfer");
    assert_eq!(effects.group_keys, [first, second]);
    let encoded = image.image.range(location, length).expect("group-key rows are in the image");
    assert_eq!(&encoded.data()[..18], [&[0, 1][..], &[0x11; 16]].concat());
    assert_eq!(&encoded.data()[18..], [&[0, 2][..], &[0x22; 16]].concat());
}

#[test]
fn group_key_rows_are_never_split_across_telegrams() {
    // A key row is a property element: its group-address index and its key
    // must arrive in one telegram, or an interrupted transfer could leave a
    // partially overwritten key. The requirement is therefore one complete
    // 18-byte row plus the five-byte property header, independent of how many
    // rows the table holds.
    let product = ProductData::from_mtxml_str(SYSTEM7_MTXML)
        .expect("fixture parses")
        .with_fixture_data_secure(true)
        .with_fixture_security_capacities(4, 4, 0);
    let first = GroupAddress::from_three_level(1, 0, 1);
    let second = GroupAddress::from_three_level(1, 0, 2);
    let mut project = MaterializedDevice::fixture(IndividualAddress::new(1, 1, 10), Some(15));
    *project.object_memberships_mut() = vec![ObjectMembership::primary(first, 1), ObjectMembership::primary(second, 1)];
    let security =
        Some(SecurityConfig::new(vec![(first, [0x11; 16]), (second, [0x22; 16])], vec![], vec![GroupObjectSecurity {
            com_object: 1,
            protection: GroupObjectProtection::AuthenticationConfidentiality,
        }]));
    let configuration = project.with_com_objects(product.com_objects().to_vec());
    let (_, operations) =
        super::super::compile_fixture(&profile(), &product, &configuration, security.as_ref(), None, |compiler| {
            compiler.contribute_data_secure()
        });

    let (target, extent) = operations
        .iter()
        .find_map(|step| match &step.operation {
            ProcedureOperation::Write { target, data: OperationData::Credential { .. }, extent, .. } => {
                Some((target, *extent))
            }
            _ => None,
        })
        .expect("compiled GKT transfer");
    assert_eq!((extent.byte_length, extent.property_elements), (36, Some(2)));
    assert_eq!(target.fitted_minimum_apdu(extent).expect("sized row"), 5 + 18);
}

#[test]
fn undeclared_security_capacity_is_zero_and_overflow_is_a_table_overflow() {
    use crate::commissioning::error::{CompileErrorKind, OverflowedTable};

    // An archive without the capacity attributes holds empty tables; any row
    // overflows it, reported like every other Data Secure table overflow.
    let product = ProductData::from_mtxml_str(SYSTEM7_MTXML).expect("fixture parses").with_fixture_data_secure(true);
    validate_product_capabilities(&product, 0, 0).expect("empty tables fit an undeclared capacity");
    for (group_keys, siat) in [(1, 0), (0, 1)] {
        let error = validate_product_capabilities(&product, group_keys, siat).expect_err("any row overflows zero");
        assert_eq!(error.kind, CompileErrorKind::TableOverflow(OverflowedTable::SecureCommunicationPartners));
    }
    let product = product.with_fixture_security_capacities(1, 2, 0);
    validate_product_capabilities(&product, 2, 1).expect("rows within capacity fit");
    let error = validate_product_capabilities(&product, 3, 1).expect_err("three keys exceed two");
    assert!(error.message.starts_with("group-key table has 3 entries"), "{}", error.message);
}
