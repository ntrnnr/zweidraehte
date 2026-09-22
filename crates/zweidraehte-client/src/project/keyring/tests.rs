use super::*;
use crate::project::ProjectCommissioningSession;
use std::fs;
use std::num::NonZeroU8;
use zweidraehte_ets_files::keyring::{KeyringBackbone, KeyringInterface, KeyringInterfaceType};

const PROJECT: &str = r#"
ga secure = 0/0/1
ga secure_2 = 0/0/2
net secure : 1.001 { security authentication_confidentiality }
net secure_2 : 1.001 { security authentication_confidentiality }
external_sender visualisation {
    address 1.1.250
    data_secure enabled
    on secure
}
area 1 bench {
    line 1 main {
        medium tp1
        device button {
            product package:"sha256:0000000000000000000000000000000000000000000000000000000000000000"
            catalog_item "button"
            address 1.1.10
            serial "00FA:00000001"
            data_secure enabled
            object 0 { on secure }
        }
    }
}
"#;

fn project(source: &str) -> (tempfile::TempDir, ProjectStore) {
    let directory = tempfile::tempdir().expect("temporary directory");
    let project_path = directory.path().join("project.knx");
    fs::write(&project_path, source).expect("project writes");
    let mut store = ProjectStore::open(&project_path).expect("project opens");
    store = store.initialize().expect("project initializes");
    (directory, store)
}

fn keyring() -> Keyring {
    Keyring::new("test".into(), "test".into(), "test".into())
        .with_group_keys(BTreeMap::from([(1, [0x33; 16])]))
        .with_devices(vec![
            KeyringDevice::new(IndividualAddress::new(1, 1, 10))
                .with_serial(Some([0, 0xFA, 0, 0, 0, 1]))
                .with_tool_key(Some([0x22; 16]))
                .with_sequence_number(123),
        ])
}

#[test]
fn keyring_import_persists_project_keys_and_forward_sequence_observations() {
    let (_directory, store) = project(PROJECT);
    let project_path = store.project_path().to_path_buf();

    let fdsk = [0x11; 16];
    let tool_key = [0x22; 16];
    let group_key = [0x33; 16];
    let second_group_key = [0x44; 16];
    let keyring = Keyring::new("test".into(), "test".into(), "test".into())
        .with_group_keys(BTreeMap::from([(1, group_key), (2, second_group_key)]))
        .with_devices(vec![
            // Matching is deliberately by serial, not the stale IA.
            KeyringDevice::new(IndividualAddress::new(1, 1, 99))
                .with_tool_key(Some(tool_key))
                .with_fdsk(Some(fdsk))
                .with_serial(Some([0x00, 0xFA, 0, 0, 0, 1]))
                .with_sequence_number(123),
            KeyringDevice::new(IndividualAddress::new(1, 1, 250)).with_sequence_number(456),
        ]);

    let session = ProjectCommissioningSession::begin(store).expect("writer acquired");
    let plan = session.plan_keyring_import(&keyring).expect("keyring reconciles");
    assert_eq!((plan.summary().matched_devices, plan.summary().matched_groups), (1, 2));
    plan.apply().expect("keyring import persists");
    drop(session);

    let store = ProjectStore::open(&project_path).expect("project reopens");
    let keys = store.keys().expect("keys exist");
    let device_scope = KeyScope::Device("button".into());
    assert_eq!(
        keys.read(&KeyId { scope: device_scope.clone(), kind: KeyKind::Fdsk }, None)
            .expect("FDSK reads")
            .expect("FDSK exists")
            .value
            .key16()
            .expect("FDSK has key width"),
        fdsk
    );
    assert_eq!(
        keys.read(&KeyId { scope: device_scope, kind: KeyKind::ToolKey }, None)
            .expect("tool key reads")
            .expect("tool key exists")
            .value
            .key16()
            .expect("tool key has key width"),
        tool_key
    );
    assert_eq!(
        keys.read(&KeyId { scope: KeyScope::Group("secure".into()), kind: KeyKind::GroupKey }, None)
            .expect("group key reads")
            .expect("group key exists")
            .value
            .key16()
            .expect("group key has key width"),
        group_key
    );
    assert_eq!(
        keys.read(&KeyId { scope: KeyScope::Group("secure_2".into()), kind: KeyKind::GroupKey }, None)
            .expect("second group key reads")
            .expect("second group key exists")
            .value
            .key16()
            .expect("second group key has key width"),
        second_group_key
    );
    let state = store.state().expect("state exists");
    assert_eq!(state.devices["00FA:00000001"].outgoing_next, 124);
    assert_eq!(state.sender_floors[&SenderIdentity::UnmanagedAddress("1.1.250".into())], 456);

    let exported = super::super::build_project_keyring(store.authored(), state, keys, "test", "test", "test")
        .expect("project keyring exports");
    assert_eq!(exported.group_key(1), Some(&group_key));
    assert_eq!(exported.group_key(2), Some(&second_group_key));
    assert_eq!(
        exported
            .devices
            .iter()
            .find(|device| device.serial == Some([0x00, 0xFA, 0, 0, 0, 1]))
            .expect("managed device exports")
            .sequence_number,
        123
    );
}

#[test]
fn keyring_import_derives_and_persists_ip_secure_properties() {
    const PROJECT: &str = r#"
area 1 bench {
    line 1 main {
        medium ip
        domain "224.0.23.12"
        project_installation_id 42.3
        multicast_latency_tolerance 2000
        sync_latency_fraction 2

        device router {
            product package:"sha256:0000000000000000000000000000000000000000000000000000000000000000"
            catalog_item "router"
            address 1.1.10
            ip_assignment dhcp
            multicast_ttl 16
            friendly_name "Main IP router"
            additional_address 1.1.11
            ip_routing secure
            ip_device_management secure
            ip_tunnelling secure
            ip_password_user 1
            ip_password_user 2
            ip_tunnelling_user 2 1
            data_secure disabled
        }
    }
}

"#;
    let directory = tempfile::tempdir().expect("temporary directory");
    let project_path = directory.path().join("project.knx");
    fs::write(&project_path, PROJECT).expect("project writes");
    let mut store = ProjectStore::open(&project_path).expect("project opens");
    store = store.initialize().expect("project initializes");

    let backbone_key = [0x51; 16];
    let mut keyring = Keyring::new("test".into(), "test".into(), "test".into())
        .with_backbone(Some(KeyringBackbone::new(Some("224.0.23.12".into()), Some(2000)).with_key(Some(backbone_key))))
        .with_devices(vec![
            KeyringDevice::new(IndividualAddress::new(1, 1, 10))
                .with_management_password(Some("management-password".into()))
                .with_authentication(Some("device-code".into())),
        ])
        .with_interfaces(vec![
            KeyringInterface::new(KeyringInterfaceType::Tunneling, IndividualAddress::new(1, 1, 11))
                .with_host(Some(IndividualAddress::new(1, 1, 10)))
                .with_user_id(Some(2))
                .with_password(Some("tunnel-password".into()))
                .with_authentication(Some("device-code".into())),
        ]);

    let session = ProjectCommissioningSession::begin(store).expect("writer acquired");
    keyring.interfaces.push(
        KeyringInterface::new(KeyringInterfaceType::Tunneling, IndividualAddress::new(1, 1, 11))
            .with_host(Some(IndividualAddress::new(1, 1, 10)))
            .with_authentication(Some("conflicting-device-code".into())),
    );
    let error = session.plan_keyring_import(&keyring).expect_err("hosted interface disagrees with device");
    assert!(error.to_string().contains("conflicting ETS keyring values"));
    assert!(!format!("{error:?}").contains("conflicting-device-code"));
    keyring.interfaces.pop();
    let plan = session.plan_keyring_import(&keyring).expect("IP keyring reconciles");
    plan.apply().expect("IP keyring import persists");
    let store = ProjectStore::open(&project_path).expect("project reopens");
    let keys = store.keys().expect("keys exist");
    let read = |id| {
        keys.read(&id, None)
            .expect("IP key reads")
            .expect("IP key exists")
            .value
            .key16()
            .expect("IP key has fixed width")
    };
    assert_eq!(read(KeyId { scope: KeyScope::IpBackbone, kind: KeyKind::BackboneKey }), backbone_key);
    assert_eq!(
        read(KeyId { scope: KeyScope::IpInterface("router".into()), kind: KeyKind::DeviceAuthenticationCode }),
        derive_ip_device_authentication_code("device-code")
    );
    assert_eq!(
        read(KeyId {
            scope: KeyScope::IpUser { interface: "router".into(), user_id: NonZeroU8::new(1).expect("nonzero") },
            kind: KeyKind::IpPasswordHash,
        }),
        derive_ip_user_password_hash("management-password")
    );
    assert_eq!(
        read(KeyId {
            scope: KeyScope::IpUser { interface: "router".into(), user_id: NonZeroU8::new(2).expect("nonzero") },
            kind: KeyKind::IpPasswordHash,
        }),
        derive_ip_user_password_hash("tunnel-password")
    );
}

#[test]
fn matching_keeps_import_and_runtime_fallback_rules_explicit() {
    let address = IndividualAddress::new(1, 1, 10);
    let serial = [0, 0xFA, 0, 0, 0, 1];
    let mut keys = keyring().with_devices(vec![KeyringDevice::new(address)]);
    assert!(
        select_keyring_device(Some(&keys), Some(serial), address, DeviceMatchPolicy::Import)
            .expect("known serial is required for import")
            .is_none()
    );
    assert!(
        select_keyring_device(Some(&keys), Some(serial), address, DeviceMatchPolicy::Resolve)
            .expect("runtime can use a serial-less address match")
            .is_some()
    );

    keys.devices.push(KeyringDevice::new(IndividualAddress::new(1, 1, 99)).with_serial(Some(serial)));
    keys.devices[0].serial = Some([2; 6]);
    assert_eq!(
        select_keyring_device(Some(&keys), Some(serial), address, DeviceMatchPolicy::Import)
            .expect("import follows serial even if the desired address is occupied")
            .expect("match")
            .0,
        1
    );
    assert!(select_keyring_device(Some(&keys), Some(serial), address, DeviceMatchPolicy::Resolve).is_err());

    let mut known = Some(serial);
    assert!(merge_serial(&mut known, Some([2; 6]), "ETS keyring").is_err());
    assert_eq!(known, Some(serial));
    let mut unknown = None;
    merge_serial(&mut unknown, Some(serial), "ETS keyring").expect("keyring supplies missing serial");
    assert_eq!(unknown, Some(serial));
}

#[test]
fn duplicate_device_matches_are_rejected_by_both_policies() {
    let address = IndividualAddress::new(1, 1, 10);
    let serial = [0, 0xFA, 0, 0, 0, 1];
    for policy in [DeviceMatchPolicy::Import, DeviceMatchPolicy::Resolve] {
        for identity in [None, Some(serial)] {
            let keys = keyring().with_devices(vec![
                KeyringDevice::new(address).with_serial(identity),
                KeyringDevice::new(address).with_serial(identity),
            ]);
            assert!(select_keyring_device(Some(&keys), identity, address, policy).is_err());
        }
    }
}

#[test]
fn a_serial_match_cannot_bypass_a_repeated_desired_address() {
    let desired = IndividualAddress::new(1, 1, 10);
    let serial = [0, 0xFA, 0, 0, 0, 1];

    // The serial's own entry plus a second claim on the desired address, by
    // another serial or by none: the address check must not depend on which
    // entry comes first.
    for other_serial in [Some([0, 0xFA, 0, 0, 0, 2]), None] {
        let mut keys = keyring().with_devices(vec![
            KeyringDevice::new(desired).with_serial(Some(serial)),
            KeyringDevice::new(desired).with_serial(other_serial),
        ]);
        for _ in 0..2 {
            for requested in [Some(serial), None] {
                assert!(
                    select_keyring_device(Some(&keys), requested, desired, DeviceMatchPolicy::Resolve).is_err(),
                    "a repeated desired address is ambiguous"
                );
            }
            keys.devices.reverse();
        }
    }
}

#[test]
fn a_serial_match_may_readdress_unless_another_device_owns_the_address() {
    let desired = IndividualAddress::new(1, 1, 43);
    let serial = [0, 0xFA, 0, 0, 0, 1];
    let mut keys =
        keyring().with_devices(vec![KeyringDevice::new(IndividualAddress::new(1, 1, 42)).with_serial(Some(serial))]);

    let (_, selected) = select_keyring_device(Some(&keys), Some(serial), desired, DeviceMatchPolicy::Resolve)
        .expect("the desired address is unclaimed")
        .expect("the serial matches");
    assert_eq!(selected.individual_address, IndividualAddress::new(1, 1, 42));

    keys.devices.push(KeyringDevice::new(desired).with_serial(Some([0, 0xFA, 0, 0, 0, 2])));
    assert!(select_keyring_device(Some(&keys), Some(serial), desired, DeviceMatchPolicy::Resolve).is_err());
}

#[test]
fn unrelated_entries_and_serial_misses_remain_ignored() {
    let (_directory, store) = project(PROJECT);
    let session = ProjectCommissioningSession::begin(store).expect("writer");
    let keys = keyring()
        .with_devices(vec![
            KeyringDevice::new(IndividualAddress::new(1, 1, 10)).with_serial(Some([2; 6])),
            KeyringDevice::new(IndividualAddress::new(1, 1, 250)).with_sequence_number(456),
        ])
        .with_group_keys(BTreeMap::from([(1, [0x33; 16]), (3, [0x44; 16])]));
    let plan = session.plan_keyring_import(&keys).expect("unrelated entries are harmless");
    assert_eq!(plan.summary(), KeyringImportSummary {
        matched_devices: 0,
        matched_groups: 1,
        ignored_devices: 1,
        ignored_groups: 1,
    });
    let summary = plan.summary();
    assert_eq!(plan.apply().expect("only related material persists"), summary);
    session
        .inspect(|store| {
            assert_eq!(store.keys().expect("keys").list().expect("key metadata").len(), 1);
            assert_eq!(
                store.state().expect("state").sender_floors[&SenderIdentity::UnmanagedAddress("1.1.250".into())],
                456
            );
        })
        .expect("inspect imported state");
}

#[test]
fn conflicts_fail_during_planning_and_equal_imports_preserve_active_epochs() {
    let (_directory, store) = project(PROJECT);
    let mut store = store.into_writer().expect("key writer");
    store
        .keys_mut()
        .expect("keys")
        .put_group_key("secure", KeyEpoch(7), &"33".repeat(16), KeyOrigin::Manual, true)
        .expect("existing active epoch");
    let session = ProjectCommissioningSession::begin(store.into_store()).expect("writer");
    session.observe_device_outgoing("00FA:00000001".into(), 999).expect("newer sequence observation");
    for _ in 0..2 {
        let plan = session.plan_keyring_import(&keyring()).expect("equal credentials corroborate");
        plan.apply().expect("idempotent import");
    }
    session
        .inspect(|store| {
            let group = store
                .keys()
                .expect("keys")
                .read(&KeyId { scope: KeyScope::Group("secure".into()), kind: KeyKind::GroupKey }, None)
                .expect("read group")
                .expect("active group");
            assert_eq!(group.metadata.epoch, Some(KeyEpoch(7)));
            assert_eq!(group.metadata.origin, KeyOrigin::Manual);
            assert_eq!(store.state().expect("state").devices["00FA:00000001"].outgoing_next, 999);
        })
        .expect("inspect import");
    let before = session
        .inspect(|store| FileRevision::capture(ProjectStore::input_files(store.project_path())))
        .expect("inspect files")
        .expect("capture files");
    let conflicting = keyring().with_group_keys(BTreeMap::from([(1, [0x55; 16])]));
    assert!(matches!(session.plan_keyring_import(&conflicting), Err(Error::KeyMaterial(KeyStoreError::Conflict(_)))));
    before.verify(|| Error::KeyringImportInputsChanged).expect("rejected plan writes nothing");
}

#[test]
fn import_rejects_changes_to_any_durable_input_before_writing() {
    for input_index in 0..4 {
        let (_directory, store) = project(PROJECT);
        let path = store.project_path().to_path_buf();
        let session = ProjectCommissioningSession::begin(store).expect("writer");
        let plan = session.plan_keyring_import(&keyring()).expect("plan");
        let files = ProjectStore::input_files(&path).collect::<Vec<_>>();
        let mut changed = fs::read(&files[input_index]).expect("input file");
        changed.push(b'\n');
        fs::write(&files[input_index], changed).expect("external editor");
        let before = FileRevision::capture(files).expect("changed revision");
        assert!(matches!(plan.apply(), Err(Error::KeyringImportInputsChanged)));
        before.verify(|| Error::KeyringImportInputsChanged).expect("rejected application writes nothing");
    }
}

#[test]
fn plan_keeps_writer_exclusion_after_the_session_is_dropped() {
    for apply in [false, true] {
        let (_directory, store) = project(PROJECT);
        let path = store.project_path().to_path_buf();
        let session = ProjectCommissioningSession::begin(store).expect("writer");
        let plan = session.plan_keyring_import(&keyring()).expect("plan");
        drop(session);
        let competitor = ProjectStore::open(&path).expect("read-only observer");
        assert!(matches!(competitor.into_writer(), Err(ProjectStoreError::Locked)));
        if apply {
            plan.apply().expect("retained writer applies");
        } else {
            drop(plan);
        }
        assert!(ProjectStore::open(&path).expect("reader").into_writer().is_ok());
    }
}

#[test]
fn journal_failure_reports_committed_keys_and_supports_reconciliation() {
    let (_directory, store) = project(PROJECT);
    let path = store.project_path().to_path_buf();
    // Prepare against a writer whose journal has not been opened. This injects
    // a persistence failure while retaining real exclusion and unchanged files.
    let owner = Arc::new(std::sync::Mutex::new(store.into_writer().expect("writer")));
    let plan = {
        let writer = owner.lock().expect("owner");
        let files = FileRevision::capture(ProjectStore::input_files(&path)).expect("inputs");
        KeyringImportPlan::prepare(writer.store(), &keyring(), Arc::clone(&owner), files).expect("plan")
    };
    let session = ProjectCommissioningSession { store: owner };
    let error = plan.apply().expect_err("journal is unavailable");
    assert!(matches!(error, Error::KeyringImportPartial {
        observations_recorded: 0,
        source: ProjectStoreError::NotInitialized
    }));
    assert!(error.to_string().contains("keys were committed"));
    let reopened = ProjectStore::open(&path).expect("reopen partially imported files");
    assert_eq!(reopened.keys().expect("keys").list().expect("metadata").len(), 2);
    assert!(reopened.state().expect("state").devices.is_empty());

    session
        .plan_keyring_import(&keyring())
        .expect("reload and reconcile saved keys")
        .apply()
        .expect("resume observations");
    assert_eq!(
        ProjectStore::open(path).expect("reopen").state().expect("state").devices["00FA:00000001"].outgoing_next,
        124
    );
}

#[test]
fn import_diagnostics_expose_counts_without_credentials() {
    let (_directory, store) = project(PROJECT);
    let session = ProjectCommissioningSession::begin(store).expect("writer");
    let plan = session.plan_keyring_import(&keyring()).expect("plan");
    let diagnostic = format!("{plan:?}");
    assert!(diagnostic.contains("matched_devices: 1"));
    for record in &plan.records {
        assert!(!diagnostic.contains(&format!("{:?}", record.value.fingerprint())));
        assert!(!diagnostic.contains(&format!("{:?}", record.value.as_slice())));
    }
}

#[test]
fn ambiguous_senders_and_unrepresentable_sequences_fail_before_writes() {
    let (_directory, store) = project(PROJECT);
    let session = ProjectCommissioningSession::begin(store).expect("writer");
    let sender = KeyringDevice::new(IndividualAddress::new(1, 1, 250));
    for keys in [
        keyring().with_devices(vec![sender.clone(), sender.clone()]),
        keyring().with_devices(vec![sender.with_sequence_number(1 << 48)]),
        keyring().with_devices(vec![keyring().devices.remove(0).with_sequence_number(0xFFFF_FFFF_FFFF)]),
    ] {
        assert!(session.plan_keyring_import(&keys).is_err());
    }
    session
        .inspect(|store| assert!(store.keys().expect("keys").list().expect("metadata").is_empty()))
        .expect("unchanged keys");
}
