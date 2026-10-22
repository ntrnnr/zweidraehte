//! Project planning and durable recovery tests.
use crate::commissioning::catalog_testing::*;
use crate::configuration::{ProcedureParameter, ProcedureParameterValue};
use crate::security::KeyringDevice;
use zweidraehte_proto::address::IndividualAddress;

pub(in crate::project) mod preparation;

use crate::commissioning::{CommissioningIntent, DifferentialPolicy, DownloadMode, ProgramSections, TargetSelection};
use crate::configuration::ResolvedKeyMaterial;
use crate::project::error::Error;
use std::collections::{BTreeMap, BTreeSet};
use zweidraehte_ets_files::product::SelectedProduct;
use zweidraehte_project::{
    CredentialCommitment, DeviceProgrammingStatus, KeyEpoch, KeyId, KeyKind, KeyMetadata, KeyScope,
    MutableProjectState, ProgrammingManifest, ProgrammingSection, ProjectDeviceId, ProjectStore,
};
use zweidraehte_proto::address::GroupAddress;

use super::session::ProjectCommissioningSession;
use super::*;
use super::{
    add_credential_commitments, changed_program_sections, changed_sections, deployment_allows_siat_sender,
    device_programming_status, reject_deployed_group_key_change, status_with_requirements,
};
use zweidraehte_project::DeviceDeploymentEvidence;

#[test]
fn corroborating_key_sources_produce_one_proof_but_conflicting_versions_fail() {
    use zweidraehte_project::{KeyEncoding, KeyOrigin, KeyState};
    let metadata = KeyMetadata {
        id: KeyId { kind: KeyKind::GroupKey, scope: KeyScope::Group("lighting".into()) },
        epoch: None,
        origin: KeyOrigin::Generated,
        encoding: KeyEncoding::Hex,
        state: KeyState::Active,
        fingerprint: [9; 32],
    };
    let material = |values| ResolvedKeyMaterial::default().with_provenance(values);
    let mut one = ProgrammingManifest::default();
    add_credential_commitments(&mut one, &material(vec![metadata.clone()])).expect("one credential");
    let mut imported = metadata.clone();
    imported.origin = KeyOrigin::Imported;
    imported.encoding = KeyEncoding::Binary;
    let mut both = ProgrammingManifest::default();
    add_credential_commitments(&mut both, &material(vec![metadata.clone(), imported.clone()]))
        .expect("matching sources corroborate one credential");
    assert_eq!(both, one, "redundant provenance must not alter section hashes");
    imported.fingerprint = [10; 32];
    assert!(add_credential_commitments(&mut both, &material(vec![metadata.clone(), imported.clone()])).is_err());
    imported.fingerprint = metadata.fingerprint;
    imported.epoch = Some(KeyEpoch(1));
    assert!(add_credential_commitments(&mut both, &material(vec![metadata, imported])).is_err());
}

#[test]
fn migrated_unknown_image_still_blocks_deployed_group_key_changes() {
    use zweidraehte_project::{KeyEncoding, KeyOrigin, KeyState};
    let mut metadata = KeyMetadata {
        id: KeyId { kind: KeyKind::GroupKey, scope: KeyScope::Group("floor:room".into()) },
        epoch: Some(KeyEpoch(7)),
        origin: KeyOrigin::Generated,
        encoding: KeyEncoding::Hex,
        state: KeyState::Active,
        fingerprint: [9; 32],
    };
    let proof = CredentialCommitment::from_metadata(&metadata).expect("deployed group key");
    let legacy = serde_json::json!({"manifest": {"sections": {"group_communication": {
        "semantic:credential:group-key:group:floor:room:7": proof.commitment.to_vec()
    }}}, "commissioning": {"version": 1}});
    let migrated: DeviceDeploymentEvidence = serde_json::from_value(legacy).expect("old evidence migrates");
    assert!(migrated.commissioning.is_none());
    assert!(migrated.manifest.sections.is_empty());
    let mut state = MutableProjectState::new("state".into());
    state.deployments.insert("receiver".into(), migrated);
    let material = |metadata| ResolvedKeyMaterial::default().with_provenance(vec![metadata]);
    let nets = BTreeMap::from([(GroupAddress::from_three_level(1, 0, 1), "floor:room".into())]);
    assert!(reject_deployed_group_key_change(Some(&state), &material(metadata.clone()), &nets).is_ok());
    metadata.fingerprint = [10; 32];
    assert!(reject_deployed_group_key_change(Some(&state), &material(metadata), &nets).is_err());
}

pub(in crate::project) fn manifest(parameter: u8, group: u8) -> ProgrammingManifest {
    let mut manifest = ProgrammingManifest::default();
    for (section, _name, value) in [
        (ProgrammingSection::Address, "address", 1),
        (ProgrammingSection::ApplicationProgram1, "application", 1),
        (ProgrammingSection::Parameters, "parameters", parameter),
        (ProgrammingSection::GroupCommunication, "group", group),
        (ProgrammingSection::Configuration, "configuration", 1),
    ] {
        manifest.insert(section, [value; 32]);
    }
    manifest
}

pub(in crate::project) fn state_with(device: &ProjectDeviceId, manifest: ProgrammingManifest) -> MutableProjectState {
    let mut state = MutableProjectState::new("state".into());
    state.deployments.insert(device.0.clone(), DeviceDeploymentEvidence { manifest, ..Default::default() });
    state
}

#[test]
fn absent_sections_are_not_matching_deployment_evidence() {
    let device = ProjectDeviceId("unobserved-button".into());
    let desired = ProgrammingManifest::default();
    let state = state_with(&device, desired.clone());

    assert_eq!(device_programming_status(&device, Some(&state), &desired), DeviceProgrammingStatus::NONE);
}

#[test]
fn pending_image_preserves_only_independent_address_evidence() {
    let device = ProjectDeviceId("unobserved-button".into());
    let desired = manifest(1, 1);
    let state = state_with(&device, desired.clone());

    assert_eq!(status_with_requirements(&device, Some(&state), &desired, true), DeviceProgrammingStatus {
        individual_address: true,
        ..DeviceProgrammingStatus::NONE
    },);
    assert_eq!(status_with_requirements(&device, Some(&state), &desired, false), DeviceProgrammingStatus::ALL);
}

#[test]
fn comparison_reports_only_the_changed_compiler_section() {
    let device = ProjectDeviceId("button".into());
    let deployed = manifest(1, 1);
    let desired = manifest(2, 1);
    let state = state_with(&device, deployed);
    let status = device_programming_status(&device, Some(&state), &desired);

    assert_eq!(
        changed_sections(state.deployment(&device.0), &desired),
        BTreeSet::from([ProgrammingSection::Parameters]),
    );
    assert_eq!(changed_program_sections(state.deployment(&device.0), &desired), ProgramSections::PARAMETERS);
    assert!(status.individual_address);
    assert!(status.application_program);
    assert!(!status.parameters);
    assert!(status.group_communication);
    assert!(status.medium_configuration);
}

#[test]
fn siat_artifact_change_invalidates_group_communication_without_an_event() {
    let device = ProjectDeviceId("receiver".into());
    let deployed = manifest(1, 1);
    let desired = manifest(1, 2);
    let state = state_with(&device, deployed);

    let status = device_programming_status(&device, Some(&state), &desired);

    assert!(status.individual_address);
    assert!(status.application_program);
    assert!(status.parameters);
    assert!(!status.group_communication);
    assert!(status.medium_configuration);
}

#[test]
fn absent_application_program_two_is_not_required() {
    let device = ProjectDeviceId("button".into());
    let desired = manifest(1, 1);
    let state = state_with(&device, desired.clone());

    assert!(device_programming_status(&device, Some(&state), &desired).application_program);
}

#[test]
fn inconsistent_device_never_uses_matching_evidence() {
    let device = ProjectDeviceId("button".into());
    let desired = manifest(1, 1);
    let mut state = state_with(&device, desired.clone());
    state.inconsistent_devices.push(device.0.clone());

    assert_eq!(device_programming_status(&device, Some(&state), &desired), DeviceProgrammingStatus::NONE);
}

#[test]
fn application_unload_removes_a_sender_from_regenerated_siat() {
    let sender = ProjectDeviceId("sender".into());
    let mut state = state_with(&sender, manifest(1, 1));
    assert!(deployment_allows_siat_sender(&sender, Some(&state)));

    let deployment = state.deployments.get_mut(&sender.0).expect("sender evidence");
    deployment.manifest.sections.clear();
    assert!(deployment_allows_siat_sender(&sender, Some(&state)));

    state.deployments.get_mut(&sender.0).expect("sender evidence").application_unloaded = true;
    assert!(!deployment_allows_siat_sender(&sender, Some(&state)));
}

pub(in crate::project) struct SecureFixture {
    pub project: AuthoredProject,
    pub products: BTreeMap<ProjectDeviceId, ProjectProduct>,
    pub catalog: std::sync::Arc<MasterData>,
    pub catalogs: ProjectMasterData,
    pub keyring: Keyring,
    pub state: MutableProjectState,
    pub sender: IndividualAddress,
}

pub(in crate::project) fn secure_fixture() -> SecureFixture {
    let project = AuthoredProject::parse(
        r#"
ga lighting = 1/0/1
net lighting : 1.001 { security authentication_confidentiality }
area 1 bench {
    line 1 main {
        medium tp1
        device receiver {
            product package:"sha256:0000000000000000000000000000000000000000000000000000000000000000"
            catalog_item "switch"
            address 1.1.10
            serial "00FA:00000001"
            data_secure enabled
            object 1 { on lighting }
        }
        device sender {
            product package:"sha256:0000000000000000000000000000000000000000000000000000000000000000"
            catalog_item "switch"
            address 1.1.11
            serial "00FA:00000002"
            data_secure enabled
            object 1 { on lighting }
        }
    }
}
"#,
    )
    .expect("authored project parses");
    let xml = zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML
        .replace("http://knx.org/xml/project/20", "http://knx.org/xml/project/23")
        .replace(r#"Address="16896" Size="31" MemoryType="EEPROM" />"#, r#"Address="16896" Size="31" MemoryType="EEPROM"><Data>AgAAAAAAAAAAAAA=</Data></AbsoluteSegment>"#)
        .replace("<Parameters>", r#"<ParameterTypes>
          <ParameterType Id="M-00FA_A-0306-02-0000_PT-1" Name="Mode"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
        </ParameterTypes><Parameters>"#)
        .replace(r#"Text="Mode" Value="0""#, r#"Text="Mode" Value="7""#)
        .replace("</Parameters>", r#"</Parameters><ParameterRefs>
          <ParameterRef Id="mode-choice" RefId="M-00FA_A-0306-02-0000_P-1" Value="3" />
        </ParameterRefs>"#)
        .replace("<LdCtrlConnect />", r#"<LdCtrlConnect /><choose ParamRefId="mode-choice"><when test="3" /></choose>"#)
        .replace(r#"TransmitFlag="Disabled""#, r#"TransmitFlag="Enabled""#)
        .replace("<ApplicationProgram ", r#"<ApplicationProgram IsSecureEnabled="true" MaxSecurityIndividualAddressEntries="4" MaxSecurityGroupKeyTableEntries="4" MaxSecurityP2PKeyTableEntries="0" "#);
    let document = zweidraehte_ets_files::runtime::parser::parse_application_program(&xml).expect("product parses");
    let product = ProjectProduct::new(SelectedProduct::from_document(document, None, None).expect("product selection"));
    let products = project.devices.keys().map(|id| (id.clone(), product.clone())).collect();
    let catalog = parse_master_data(r#"<KNX xmlns="http://knx.org/xml/project/23"><MasterData Id="planning" Version="1"><MaskVersions>
      <MaskVersion Id="MV-0705" MaskVersion="1797" Name="System 7" ManagementModel="BimM112" MediumTypeRefId="MT-0"><HawkConfigurationData>
        <Features><Feature Name="FirstAppObjectIdx" Value="3"/></Features>
        <Resources><Resource Name="ManagementStyle"><Location AddressSpace="Constant" StartAddress="2"/><ResourceType Length="1"/></Resource><Resource Name="GroupObjectTable"><Location AddressSpace="StandardMemory" StartAddress="16896"/><ResourceType Length="31" Flavour="GroupObjectTable_M112"/><AccessRights Read="Configuration" Write="Configuration"/></Resource></Resources>
      </HawkConfigurationData></MaskVersion></MaskVersions></MasterData></KNX>"#).expect("catalog parses");
    let catalogs = ProjectMasterData::with_installation(catalog.clone());
    let sender = IndividualAddress::new(1, 1, 11);
    let keyring = Keyring::new("bench".into(), "test".into(), "test".into())
        .with_group_keys(BTreeMap::from([(0x0801, [0x33; 16])]))
        .with_devices(vec![
            KeyringDevice::new(IndividualAddress::new(1, 1, 10))
                .with_serial(Some([0, 0xFA, 0, 0, 0, 1]))
                .with_tool_key(Some([0x22; 16]))
                .with_fdsk(Some([0x11; 16])),
            KeyringDevice::new(sender)
                .with_serial(Some([0, 0xFA, 0, 0, 0, 2]))
                .with_tool_key(Some([0x44; 16]))
                .with_sequence_number(123),
        ]);
    let mut state = MutableProjectState::new("bench".into());
    state.devices.entry(format_serial(&[0, 0xFA, 0, 0, 0, 2])).or_default().outgoing_next = 124;
    SecureFixture { project, products, catalog, catalogs, keyring, state, sender }
}

#[test]
fn shared_product_definitions_keep_device_edits_independent() {
    use zweidraehte_ets_files::runtime::Device;
    use zweidraehte_ets_files::runtime::model::ParameterValue;

    let fixture = secure_fixture();
    let receiver = &fixture.products[&ProjectDeviceId("receiver".into())];
    let sender = &fixture.products[&ProjectDeviceId("sender".into())];
    assert!(std::ptr::eq(receiver.document(), sender.document()));
    assert!(std::ptr::eq(receiver.product(), sender.product()));

    let mut receiver_device = Device::new(receiver.program().clone(), None);
    let sender_device = Device::new(sender.program().clone(), None);
    receiver_device.set_parameter_value("mode-choice", ParameterValue::Integer(42));
    assert_eq!(receiver_device.get_parameter_value("mode-choice"), Some(&ParameterValue::Integer(42)));
    assert_eq!(sender_device.get_parameter_value("mode-choice"), Some(&ParameterValue::Integer(3)));
}

#[test]
fn status_preview_and_batch_share_evaluation_and_secure_peer_scope() {
    let SecureFixture { project, products, catalog: _, catalogs, keyring, state, sender } = secure_fixture();
    let planner =
        ProjectPlanner::new(&project, &products).with_state(&state).with_keyring(&keyring).with_master_data(&catalogs);
    let id = ProjectDeviceId("receiver".into());
    let selection = BTreeSet::from([id.clone()]);
    let view = planner.programming_view_for(&selection).expect("status evaluates secure peers");
    let batch = planner
        .plan_commissioning(
            &[id.clone()],
            BatchSelection::Selected,
            CommissioningIntent::Download(DownloadMode::Automatic),
        )
        .expect("batch evaluates");
    let planned = &batch.devices[0];
    assert_eq!(batch.devices.len(), 1, "peers are evaluated without becoming physical targets");
    assert_eq!(view.manifests[&id], planned.desired_manifest);
    assert_eq!(view.statuses[&id], planned.status);
    assert_eq!(view.requirements.get(&id).cloned().unwrap_or_default(), planned.image_requirements);
    let device = &planned.device;
    assert_eq!(device.parameters()[0].value, [7]);
    assert_eq!(device.procedure_parameters()["mode-choice"], ProcedureParameter {
        active: true,
        value: ProcedureParameterValue::Signed(3)
    });
    assert_eq!(device.max_apdu(), None);
    let keys = planned.device.key_material();
    assert_eq!(keys.tool_key(), Some(&[0x22; 16]));
    assert_eq!(keys.fdsk(), Some(&[0x11; 16]));
    assert_eq!(keys.application_security().expect("security configured").siat(), &[(sender, 123)]);
    let preview = planned.device.project_preview(&id, &project.devices[&id], None).expect("same device previews");
    let mut manifest = preview.manifest.clone();
    manifest.insert(
        ProgrammingSection::Address,
        zweidraehte_project::semantic_fingerprint(
            "individual-address",
            "desired",
            project.devices[&id].address.as_bytes(),
        ),
    );
    add_credential_commitments(&mut manifest, keys).expect("same credential commitments");
    assert_eq!(manifest, planned.desired_manifest);
    assert_eq!(preview.requirements(), planned.image_requirements);
    assert!(
        preview.projected_regions().any(|(_, region)| region.data().windows(16).any(|bytes| bytes == [0x33; 16])),
        "the group key is ordinary preview image content"
    );

    // A different semantic intent is evaluated anew: address assignment does
    // not retain the download's group keys, SIAT dependencies or image manifest.
    let mut address = planner
        .plan_commissioning(&[id.clone()], BatchSelection::Selected, CommissioningIntent::AssignAddress)
        .expect("address-only plan evaluates");
    assert!(address.siat_senders.is_empty());
    let device = address.device(&id).expect("selected receiver");
    assert!(device.device().key_material().secured_groups().is_empty());
    assert!(device.device().key_material().application_security().is_none_or(|security| security.siat().is_empty()));
    assert_ne!(device.desired_manifest(), planned.desired_manifest());
    let manifest = device.desired_manifest().clone();
    let previous = IndividualAddress::new(1, 1, 99);
    address.set_target(&id, TargetSelection::KnownPreviousAddress(previous)).expect("target override is allowed");
    address.set_policy(ProgrammingPolicy {
        allow_plaintext: false,
        differential: DifferentialPolicy::Disabled,
        ..Default::default()
    });
    let device = address.device(&id).expect("same receiver");
    assert_eq!(device.id(), &id);
    assert_eq!(device.desired_manifest(), &manifest);
    assert_eq!(device.commissioning().intent, CommissioningIntent::AssignAddress);
    assert!(matches!(device.commissioning().target, TargetSelection::KnownPreviousAddress(value) if value == previous));
    assert!(
        address.set_target(&ProjectDeviceId("missing".into()), TargetSelection::ExistingAddress(previous)).is_err()
    );

    // Imported SIAT may name a managed sender which has no authored net link.
    // Its management credentials are a read dependency, never another target.
    let mut imported_project = project.clone();
    let sender_id = ProjectDeviceId("sender".into());
    imported_project.devices.get_mut(&sender_id).expect("sender exists").objects.clear();
    let mut imported = keyring;
    imported.devices[1].sequence_number = 0;
    imported.interfaces = vec![
        zweidraehte_ets_files::keyring::KeyringInterface::new(
            zweidraehte_ets_files::keyring::KeyringInterfaceType::Tunneling,
            IndividualAddress::new(1, 1, 250),
        )
        .with_group_addresses(vec![(0x0801, vec![sender])]),
    ];
    let imported_batch = ProjectPlanner::new(&imported_project, &products)
        .with_keyring(&imported)
        .with_master_data(&catalogs)
        .plan_commissioning(&[id.clone()], BatchSelection::Selected, CommissioningIntent::Download(DownloadMode::Full))
        .expect("imported managed sender evaluates without becoming a target");
    assert_eq!(imported_batch.devices().len(), 1);
    assert_eq!(imported_batch.siat_senders.len(), 1);
    assert!(imported_batch.siat_senders[0].probe_key_material.is_some());

    let missing_sender_products = BTreeMap::from([(id.clone(), products[&id].clone())]);
    let missing = ProjectPlanner::new(&imported_project, &missing_sender_products)
        .with_keyring(&imported)
        .with_master_data(&catalogs)
        .plan_commissioning(&[id], BatchSelection::Selected, CommissioningIntent::Download(DownloadMode::Full));
    assert!(
        matches!(missing, Err(Error::MissingSenderInput { device, address }) if device == sender_id.0 && address == sender)
    );
}

#[test]
fn an_empty_operation_needs_no_product_catalog() {
    let project = AuthoredProject::parse("").expect("empty authored project");
    let products = BTreeMap::new();
    let planner = ProjectPlanner::new(&project, &products);
    assert_eq!(planner.programming_view().expect("empty view"), ProgrammingView::default());
}
