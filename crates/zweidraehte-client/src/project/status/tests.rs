use super::*;
use crate::commissioning::catalog_testing::*;
use crate::project::tests::secure_fixture;
use std::path::PathBuf;
use zweidraehte_project::{KeyOrigin, MutableProjectState};

#[test]
fn partial_scopes_merge_only_with_the_same_complete_input_revision() {
    let fixture = secure_fixture();
    let receiver = ProjectDeviceId::new("receiver").expect("literal is an identifier");
    let sender = ProjectDeviceId::new("sender").expect("literal is an identifier");
    let planner = ProjectPlanner::new(&fixture.project, &fixture.products)
        .with_state(&fixture.state)
        .with_keyring(&fixture.keyring)
        .with_master_data(&fixture.catalogs);
    let mut first = planner.programming_snapshot_for(&BTreeSet::from([receiver.clone()])).expect("receiver status");
    let second = planner.programming_snapshot_for(&BTreeSet::from([sender.clone()])).expect("sender status");
    assert_eq!(first.revision(), second.revision());
    first.merge(second);
    assert_eq!(first.scope(), &BTreeSet::from([receiver.clone(), sender.clone()]));
    assert!(first.view().statuses.contains_key(&sender));

    // state_id and format version deliberately stay fixed.
    let mut changed = fixture.state.clone();
    changed.client_next += 1;
    let newer = ProjectPlanner::new(&fixture.project, &fixture.products)
        .with_state(&changed)
        .with_keyring(&fixture.keyring)
        .with_master_data(&fixture.catalogs)
        .programming_snapshot_for(&BTreeSet::from([receiver.clone()]))
        .expect("new durable evidence");
    assert_ne!(first.revision(), newer.revision());
    first.merge(newer);
    assert_eq!(first.scope(), &BTreeSet::from([receiver]));
    assert!(!first.view().statuses.contains_key(&sender), "cross-revision rows must become unknown");
}

#[test]
fn snapshot_retains_the_catalog_resolution_diagnostic() {
    use crate::commissioning::{ProfileError, ProfileErrorKind};
    use std::error::Error as _;

    let fixture = secure_fixture();
    let catalog = parse_master_data(r#"<KNX xmlns="http://knx.org/xml/project/23"><MasterData Version="1" /></KNX>"#)
        .expect("inspectable empty catalog");
    let catalogs = ProjectMasterData::with_installation(catalog);
    let scope = fixture.project.devices.keys().cloned().collect();
    let error = ProjectPlanner::new(&fixture.project, &fixture.products)
        .with_keyring(&fixture.keyring)
        .with_master_data(&catalogs)
        .programming_snapshot_for(&scope)
        .expect_err("catalog cannot resolve the device mask");

    assert!(matches!(error, Error::Catalog(_)));
    let cause =
        error.source().expect("catalog diagnostic").downcast_ref::<ProfileError>().expect("typed profile diagnostic");
    assert_eq!(cause.kind(), ProfileErrorKind::Unsupported);
    assert!(cause.message().contains("DD0 0705"));
}

#[test]
fn revision_tracks_drafts_catalog_bytes_and_redacted_keyring_credentials() {
    let mut fixture = secure_fixture();
    let scope = fixture.project.devices.keys().cloned().collect();
    let snapshot = |project: &AuthoredProject, catalogs: &ProjectMasterData, keyring: &Keyring| {
        ProjectPlanner::new(project, &fixture.products)
            .with_keyring(keyring)
            .with_master_data(catalogs)
            .programming_snapshot_for(&scope)
            .expect("snapshot")
    };
    let original = snapshot(&fixture.project, &fixture.catalogs, &fixture.keyring);
    let mut draft = fixture.project.clone();
    draft.language = Some("de-DE".into());
    assert_eq!(draft.source(), fixture.project.source(), "model edits need not change source text");
    assert_ne!(original.revision(), snapshot(&draft, &fixture.catalogs, &fixture.keyring).revision());
    let changed_catalog = parse_master_data(
        &std::sync::Arc::clone(&fixture.catalog).source_xml().replace("Version=\"1\"", "Version=\"2\""),
    )
    .expect("another catalog revision");
    let changed_catalogs = ProjectMasterData::with_installation(changed_catalog);
    assert_ne!(original.revision(), snapshot(&fixture.project, &changed_catalogs, &fixture.keyring).revision());
    fixture.keyring.devices[0] = fixture.keyring.devices[0].clone().with_tool_key(Some([0x55; 16]));
    let changed = snapshot(&fixture.project, &fixture.catalogs, &fixture.keyring);
    assert_ne!(original.revision(), changed.revision());
    assert!(!format!("{changed:?}").contains("5555555555555555"));
}

fn empty_project() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("project directory");
    let path = directory.path().join("project.knx");
    std::fs::write(&path, "# status test\n").expect("project source");
    (directory, path)
}

fn request(path: &Path) -> ProjectStatusRequest<'_> {
    ProjectStatusRequest { project_path: path, draft: None, scope: None, master_data: None, keyring_path: None }
}

#[test]
fn acquisition_is_read_only_and_checks_changes_during_loading_and_before_delivery() {
    let (directory, path) = empty_project();
    let mut cache = ProjectStatusCache::default();
    let inputs = cache.load(request(&path), || Ok(None), |_, _, _| {}).expect("read-only inputs");
    let snapshot = inputs.snapshot().expect("empty snapshot");
    assert!(!directory.path().join(".zweidraehte").exists());
    let changed = cache.load(
        request(&path),
        || {
            std::fs::write(&path, "# changed while loading\n").expect("external change");
            Ok(None)
        },
        |_, _, _| {},
    );
    assert!(matches!(changed, Err(Error::StatusInputsChanged)));
    assert!(
        matches!(snapshot.verify_current(), Err(Error::StatusInputsChanged)),
        "a queued response is rechecked on delivery"
    );
}

#[test]
fn draft_base_key_changes_and_partial_operation_evidence_invalidate_status() {
    let (_directory, path) = empty_project();
    let mut store = ProjectStore::open(&path).expect("project");
    store = store.initialize().expect("state");
    let mut cache = ProjectStatusCache::default();
    let first = cache.load(request(&path), || Ok(None), |_, _, _| {}).expect("inputs").snapshot().expect("snapshot");
    let mut writer = store.into_writer().expect("key writer");
    writer
        .keys_mut()
        .expect("keys")
        .put_device_tool_key("button", &"55".repeat(16), KeyOrigin::Manual)
        .expect("key edit");
    let store = writer.into_store();
    assert!(first.verify_current().is_err());
    let second = cache
        .load(request(&path), || Ok(None), |_, _, _| {})
        .expect("changed key inputs")
        .snapshot()
        .expect("changed key snapshot");
    assert_ne!(first.revision(), second.revision());

    let session = super::super::ProjectCommissioningSession::begin(store).expect("writer");
    session.observe_device_outgoing("00FA:00000001".into(), 500).expect("persist partial observation");
    session.finish().expect("compact");
    let third = cache
        .load(request(&path), || Ok(None), |_, _, _| {})
        .expect("evidence inputs")
        .snapshot()
        .expect("evidence snapshot");
    assert_ne!(second.revision(), third.revision());

    let draft =
        ProjectStore::open(&path).expect("saved project").authored().reparse("# unsaved intent\n").expect("draft");
    let mut accepted = request(&path);
    accepted.draft = Some((&draft, "# status test\n"));
    let inputs = cache.load(accepted, || Ok(None), |_, _, _| {}).expect("unsaved intent");
    assert_ne!(third.revision(), inputs.snapshot().expect("draft status").revision());
    assert_eq!(inputs.store().authored().source(), "# status test\n", "acquisition never saves a draft");
    let mut request = request(&path);
    request.draft = Some((&draft, "# obsolete saved source\n"));
    assert!(matches!(cache.load(request, || Ok(None), |_, _, _| {}), Err(Error::StatusInputsChanged)));
}

#[test]
fn same_state_identity_and_version_do_not_hide_changed_observations() {
    let first = MutableProjectState::new("same".into());
    let mut second = first.clone();
    second.inconsistent_devices.push("button".into());
    let project = AuthoredProject::parse("# no devices\n").expect("source");
    let products = BTreeMap::new();
    let scope = BTreeSet::new();
    let snapshot = |state| {
        ProjectPlanner::new(&project, &products)
            .with_state(state)
            .programming_snapshot_for(&scope)
            .expect("empty revision")
    };
    assert_ne!(snapshot(&first).revision(), snapshot(&second).revision());
}
