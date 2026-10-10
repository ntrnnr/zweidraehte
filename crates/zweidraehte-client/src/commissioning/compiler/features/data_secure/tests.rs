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
    GroupLink, GroupObjectProtection, GroupObjectSecurity, LoweredDeviceConfiguration, SecurityConfig,
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
    let project = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 10), Some(15));
    let security = configured.then(SecurityConfig::default);
    let configuration = project.with_com_objects(product.com_objects().to_vec());
    let input = super::super::fixture_input(&product, &configuration, security.as_ref(), None).data_security(desired);
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
    assert!(image.image.is_empty());
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
fn disabled_security_refreshes_public_flags_only_with_keyed_management() {
    let product = ProductData::from_mtxml_str(SYSTEM7_MTXML)
        .expect("fixture parses")
        .with_fixture_data_secure(true)
        .with_fixture_security_capacities(4, 4, 0);
    let configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 10), Some(15))
        .with_com_objects(product.com_objects().to_vec());
    let profile = profile();

    for credential in [ManagementCredential::ToolKey, ManagementCredential::Plaintext] {
        let target =
            ObservedTarget { previous_address: configuration.individual_address, serial_number: None, credential };
        let input = super::super::fixture_input(&product, &configuration, None, None)
            .data_security(DesiredDataSecurity::Disabled)
            .facts(ProgrammingFacts::new(target).with_data_security(ObservedDataSecurity::Disabled));
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
        if credential == ManagementCredential::ToolKey {
            let flag_segment = flag_segment.expect("keyed download owns public flags");
            assert!(!flag_segment.data().is_empty());
            assert!(flag_segment.data().iter().all(|byte| *byte == 0));
            assert_eq!(
                contributed.iter().filter(|step| matches!(step.operation, ProcedureOperation::LoadRecord(_))).count(),
                3
            );
            assert!(contributed.iter().all(|step| step.secure_only));
            assert!(contributed.iter().any(|step| matches!(step.operation, ProcedureOperation::Write {
                target: OperationTarget::Property { .. },
                policy: crate::commissioning::procedure::WriteIntent::Property { verify: true },
                ..
            })));
            assert!(!contributed.iter().any(|step| matches!(step.operation, ProcedureOperation::FunctionProperty(_))));
        } else {
            assert!(flag_segment.is_none());
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

    let zero_based =
        encode_group_object_security(&configured, &[1, 2], &effective, 0).expect("zero-based convention encodes");
    let one_based =
        encode_group_object_security(&configured, &[1, 2], &effective, 1).expect("one-based convention encodes");

    assert_eq!(zero_based, [0, 0, 3]);
    assert_eq!(one_based, [0, 3]);
}

#[test]
fn standard_overlay_keeps_group_keys_out_of_public_image_and_debug() {
    let product = ProductData::from_mtxml_str(SYSTEM7_MTXML)
        .expect("fixture parses")
        .with_fixture_data_secure(true)
        .with_fixture_security_capacities(4, 4, 0);
    let group_address = GroupAddress::from_three_level(1, 2, 3);
    let key = [0xA7; 16];
    let mut project = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 10), Some(15));
    project.links.push(GroupLink { group_address, com_object: 1 });
    let security =
        Some(SecurityConfig::new(vec![(group_address, key)], vec![(IndividualAddress::new(1, 1, 11), 42)], vec![
            GroupObjectSecurity { com_object: 1, protection: GroupObjectProtection::AuthenticationConfidentiality },
        ]));
    let configuration = project.with_com_objects(product.com_objects().to_vec());

    let (image, operations) =
        super::super::compile_fixture(&profile(), &product, &configuration, security.as_ref(), None, |compiler| {
            compiler.contribute_data_secure()
        });
    let payloads = &image.secret_payload;

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
    let enable_security_mode = operations.iter().position(|operation| matches!(operation,
        ProcedureStep {
            operation: ProcedureOperation::FunctionProperty(FunctionPropertyOperation::Invoke {
                address: PropertyAddress::Extended { object_type: zweidraehte_proto::dpt::InterfaceObjectType::Security, object_instance: 1, property_id: pid::security::SECURITY_MODE },
                data,
                ..
            }), .. } if data.as_slice() == [0, 0, 1])).expect("Security Mode enable exists");
    assert_eq!(enable_security_mode, complete_loading + 1);
    let ProcedureOperation::FunctionProperty(FunctionPropertyOperation::Invoke { effect, .. }) =
        &operations[enable_security_mode].operation
    else {
        unreachable!("selected security-mode command")
    };
    assert_eq!(effect, &LoadEffect::Invalidate {
        location: ImageLocation {
            space: ImageSpace::Property { object: SECURITY_OBJECT, property_id: pid::security::SECURITY_MODE },
            offset: 0,
        },
        length: 1,
    });

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
        BTreeSet::from([pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, pid::security::GO_SECURITY_FLAGS,])
    );
    assert!(!public_pids.contains(&pid::security::GROUP_KEY_TABLE));

    let public_debug = format!("{:?} {:?}", image.image, operations);
    assert!(!public_debug.contains("a7"));
    assert!(!public_debug.contains("A7"));

    let (secret_write, secret_target) = operations
        .iter()
        .find_map(|operation| match operation {
            ProcedureStep {
                operation: ProcedureOperation::Write { data: OperationData::Secret(payload), target, .. },
                ..
            } => Some((*payload, target)),
            _ => None,
        })
        .expect("group-key write is represented by a secret reference");
    assert_eq!(payloads.group_keys(secret_write).expect("compiled row identities"), [group_address]);
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

    let secret = payloads.resolve(secret_write).expect("secret resolves");
    assert_eq!(&secret[..2], &[0, 1]);
    assert_eq!(&secret[2..], &key);
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
fn group_key_exposure_identities_follow_encoded_rows_not_input_order() {
    let product = ProductData::from_mtxml_str(SYSTEM7_MTXML)
        .expect("fixture parses")
        .with_fixture_data_secure(true)
        .with_fixture_security_capacities(4, 4, 0);
    let first = GroupAddress::from_three_level(1, 0, 1);
    let second = GroupAddress::from_three_level(1, 0, 2);
    let mut project = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 10), Some(15));
    project.links =
        vec![GroupLink { group_address: second, com_object: 1 }, GroupLink { group_address: first, com_object: 1 }];
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
    let reference = operations
        .iter()
        .find_map(|step| match step.operation {
            ProcedureOperation::Write { data: OperationData::Secret(reference), .. } => Some(reference),
            _ => None,
        })
        .expect("compiled GKT transfer");
    let payload = &image.secret_payload;
    assert_eq!(payload.group_keys(reference).expect("bound row identities"), [first, second]);
    let encoded = payload.resolve(reference).expect("private rows");
    assert_eq!(&encoded[..18], [&[0, 1][..], &[0x11; 16]].concat());
    assert_eq!(&encoded[18..], [&[0, 2][..], &[0x22; 16]].concat());
}
