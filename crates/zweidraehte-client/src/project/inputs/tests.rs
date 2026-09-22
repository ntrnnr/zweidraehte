use super::*;
use crate::commissioning::{DifferentialPolicy, DownloadMode, ProgrammingModePolling, UnloadMode};
use crate::project::tests::secure_fixture;
use crate::project::{ProjectStatusCache, ProjectStatusInputs, ProjectStatusRequest, SerialAddressingSupport};
use std::fs;
use zweidraehte_project::ProjectStoreError;

fn empty_project() -> (tempfile::TempDir, ProjectOperationInputs) {
    let directory = tempfile::tempdir().expect("project directory");
    let path = directory.path().join("project.knx");
    fs::write(&path, "# project\n").expect("source");
    let inputs = ProjectOperationInputs::load(
        ProjectStore::open(&path).expect("reader"),
        ProjectInputRequest {
            selected: &[],
            selection: BatchSelection::All,
            intent: CommissioningIntent::AssignAddress,
            sources: Default::default(),
        },
        || Ok(None),
    )
    .expect("read-only acquisition");
    (directory, inputs)
}

fn secure_inputs(
    selection: BatchSelection,
    intent: CommissioningIntent,
) -> (tempfile::TempDir, ProjectOperationInputs) {
    let fixture = secure_fixture();
    let directory = tempfile::tempdir().expect("project directory");
    let path = directory.path().join("project.knx");
    fs::write(&path, fixture.project.source()).expect("source");
    let store = ProjectStore::open(&path).expect("reader").initialize().expect("initialize");
    let selected = vec![ProjectDeviceId("receiver".into())];
    let scope = ProjectPlanner::product_scope(store.authored(), &selected, selection, intent);
    // Reuse semantic product fixtures; their package-reader contract is tested
    // by ETS-files. Filesystem acquisition itself is exercised independently.
    let inputs = ProjectOperationInputs {
        store,
        resources: ProductInputs { products: fixture.products, catalogs: fixture.catalogs },
        keyring: Some(fixture.keyring),
        selected,
        selection,
        intent,
        scope,
        files: FileRevision::capture(ProjectStore::input_files(&path)).expect("revision"),
    };
    (directory, inputs)
}

#[test]
fn acquisition_and_planning_require_explicit_initialization_and_retain_exclusion() {
    let (directory, mut inputs) = empty_project();
    let plan = inputs.plan().expect("empty plan");
    assert_eq!(inputs.requirements(&plan), [ProjectSetupRequirement::InitializeProject]);
    assert!(!directory.path().join(".zweidraehte").exists());
    assert!(!directory.path().join("keys.toml").exists());
    assert!(matches!(inputs.begin_session(), Err(Error::ProjectSetup(ProjectSetupRequirement::InitializeProject))));

    inputs.initialize().expect("authorized initialization");
    assert_eq!(inputs.state_requirement(), None);
    let session = inputs.begin_session().expect("acquire writer");
    assert!(matches!(inputs.begin_session(), Err(Error::ProjectStore(ProjectStoreError::Locked))));
    drop(session);
    inputs.begin_session().expect("released writer");
}

#[test]
fn operation_acquisition_rejects_changed_saved_source_and_loader_inputs() {
    let (_directory, inputs) = empty_project();
    let path = inputs.store().project_path();
    let request = ProjectInputRequest {
        selected: &[],
        selection: BatchSelection::All,
        intent: CommissioningIntent::AssignAddress,
        sources: Default::default(),
    };
    let stale = ProjectStore::open(path).expect("old source");
    fs::write(path, "# newer source\n").expect("external editor");
    assert!(matches!(ProjectOperationInputs::load(stale, request, || Ok(None)), Err(Error::OperationInputsChanged)));
    let current = ProjectStore::open(path).expect("current source");
    let changed = ProjectOperationInputs::load(current, request, || {
        fs::write(path, "# changed during loading\n").expect("external editor");
        Ok(None)
    });
    assert!(matches!(changed, Err(Error::OperationInputsChanged)));
}

#[test]
fn partial_initialization_requires_recovery_without_creating_missing_files() {
    for missing_index in [1, 2] {
        let (_directory, mut inputs) = empty_project();
        inputs.initialize().expect("initialize");
        let path = inputs.store().project_path();
        let missing = ProjectStore::input_files(path).nth(missing_index).expect("sidecar path");
        fs::remove_file(&missing).expect("lost sidecar");
        if missing_index == 2 {
            // A surviving journal with no snapshot is corrupt, not merely
            // uninitialized. Exercise loss of the complete state here.
            fs::remove_file(ProjectStore::input_files(path).nth(3).expect("journal path")).expect("lost journal");
        }
        let inputs = ProjectOperationInputs::load(
            ProjectStore::open(path).expect("partial project"),
            ProjectInputRequest {
                selected: &[],
                selection: BatchSelection::All,
                intent: CommissioningIntent::AssignAddress,
                sources: Default::default(),
            },
            || Ok(None),
        )
        .expect("read-only acquisition");

        assert_eq!(inputs.state_requirement(), Some(ProjectSetupRequirement::RecoverProject));
        assert!(matches!(inputs.begin_session(), Err(Error::ProjectSetup(ProjectSetupRequirement::RecoverProject))));
        assert!(!missing.exists());
    }
}

#[test]
fn queued_inputs_cannot_silently_accept_new_credentials_or_state() {
    for input in 0..4 {
        let (_directory, mut inputs) = empty_project();
        inputs.initialize().expect("initialize");
        let path = ProjectStore::input_files(inputs.store().project_path()).nth(input).expect("input path");
        let mut bytes = fs::read(&path).expect("original input");
        bytes.push(b'\n');
        fs::write(&path, bytes).expect("external edit");
        assert!(matches!(inputs.begin_session(), Err(Error::OperationInputsChanged)));
        assert!(
            ProjectStore::open(inputs.store().project_path()).expect("reader").into_writer().is_ok(),
            "failed setup releases the writer"
        );
    }
}

#[test]
fn keyring_revision_survives_explicit_project_initialization() {
    let (_directory, inputs) = empty_project();
    let path = inputs.store().project_path();
    let keyring_path = path.with_file_name("import.knxkeys");
    fs::write(&keyring_path, "decrypted by caller").expect("keyring input");
    let mut inputs = ProjectOperationInputs::load(
        ProjectStore::open(path).expect("reader"),
        ProjectInputRequest {
            selected: &[],
            selection: BatchSelection::All,
            intent: CommissioningIntent::AssignAddress,
            sources: ProjectInputSources { keyring_path: Some(&keyring_path), ..Default::default() },
        },
        || Ok(None),
    )
    .expect("inputs");
    inputs.initialize().expect("initialize");
    fs::write(keyring_path, "different credentials").expect("external keyring edit");
    assert!(matches!(inputs.begin_session(), Err(Error::OperationInputsChanged)));
}

#[test]
fn operation_and_status_loading_share_read_only_empty_scope_policy() {
    let (directory, inputs) = empty_project();
    let unused = directory.path().join("unused-master.xml");
    let mut cache = ProjectStatusCache::default();
    let status = ProjectStatusInputs::load(
        ProjectStatusRequest {
            project_path: inputs.store().project_path(),
            draft: None,
            scope: None,
            master_data: Some(&unused),
            keyring_path: None,
        },
        &mut cache,
        || Ok(None),
        |_, _, _| {},
    )
    .expect("empty status");
    assert!(inputs.plan().expect("plan").devices().is_empty());
    assert!(status.snapshot().expect("snapshot").scope().is_empty());
    assert!(!directory.path().join(".zweidraehte").exists());
}

#[test]
fn owned_and_borrowed_planning_keep_selection_intent_catalogs_and_requirements() {
    for selection in [BatchSelection::Selected, BatchSelection::All, BatchSelection::AllStale] {
        for intent in [
            CommissioningIntent::AssignAddress,
            CommissioningIntent::AssignAddressAndDownload(DownloadMode::Automatic),
            CommissioningIntent::Download(DownloadMode::Full),
            CommissioningIntent::Unload(UnloadMode::Application),
        ] {
            let (_directory, inputs) = secure_inputs(selection, intent);
            let owned = inputs.plan().expect("owned plan");
            let borrowed =
                inputs.planner().plan_commissioning(&inputs.selected, selection, intent).expect("borrowed plan");
            assert_eq!(owned.devices().len(), if selection == BatchSelection::Selected { 1 } else { 2 });
            assert_eq!(inputs.requirements(&owned), inputs.requirements(&borrowed));
            for (left, right) in owned.devices().iter().zip(borrowed.devices()) {
                assert_eq!(left.id(), right.id());
                assert_eq!(left.commissioning().intent, intent);
                assert_eq!(left.commissioning().intent, right.commissioning().intent);
                assert_eq!(left.commissioning().target, right.commissioning().target);
                assert_eq!(left.desired_manifest(), right.desired_manifest());
                assert_eq!(left.serial_addressing(), SerialAddressingSupport::Supported);
                let catalog =
                    inputs.programming_inputs().catalogs.for_product(left.device().product()).expect("catalog");
                assert!(std::sync::Arc::ptr_eq(
                    &catalog.document(),
                    left.device().product().master_data().expect("bound catalog")
                ));
            }
        }
    }
}

#[test]
fn explicit_previous_address_survives_reconfiguration_and_removes_physical_requirement() {
    let (_directory, inputs) = secure_inputs(BatchSelection::Selected, CommissioningIntent::AssignAddress);
    let mut plan = inputs.plan().expect("plan");
    let id = inputs.selected[0].clone();
    plan.set_target(&id, TargetSelection::ProgrammingButton(ProgrammingModePolling::default())).expect("button");
    assert!(inputs.requirements(&plan).contains(&ProjectSetupRequirement::PhysicalTarget { device: id.clone() }));
    let previous = crate::IndividualAddress::new(1, 1, 42);
    plan.set_target(&id, TargetSelection::KnownPreviousAddress(previous)).expect("previous address");
    plan.configure(Default::default(), true, DifferentialPolicy::Disabled);
    assert_eq!(
        plan.device(&id).expect("device").commissioning().target,
        TargetSelection::KnownPreviousAddress(previous)
    );
    assert!(
        !inputs
            .requirements(&plan)
            .iter()
            .any(|requirement| matches!(requirement, ProjectSetupRequirement::PhysicalTarget { .. }))
    );
}

#[test]
fn bcu1_and_unknown_masks_keep_serial_metadata_without_selecting_serial_management() {
    use crate::commissioning::ProgrammingCatalog;
    use zweidraehte_ets_files::product::SelectedProduct;

    for (mask, model, expected) in [
        ("MV-0012", "Bcu1", SerialAddressingSupport::Unsupported),
        ("MV-FFFF", "Future", SerialAddressingSupport::Unknown),
        ("", "SystemB", SerialAddressingSupport::Unknown),
    ] {
        for intent in [CommissioningIntent::AssignAddress, CommissioningIntent::Unload(UnloadMode::Application)] {
            let (_directory, mut inputs) = secure_inputs(BatchSelection::Selected, intent);
            let id = inputs.selected[0].clone();
            let mut document = inputs.resources.products[&id].document().clone();
            document.manufacturer_data.manufacturer.application_programs.programs[0].mask_version = mask.into();
            let product = ProjectProduct::new(SelectedProduct::from_document(document, None, None).expect("product"));
            inputs.resources.products.insert(id.clone(), product);
            let catalog = ProgrammingCatalog::from_xml(&format!(
                r#"
                <KNX xmlns="http://knx.org/xml/project/23"><MasterData Version="1"><MaskVersions>
                  <MaskVersion Id="{}" MaskVersion="65535" Name="target" ManagementModel="{model}"/>
                </MaskVersions></MasterData></KNX>"#,
                if mask.is_empty() { "MV-07B0" } else { mask }
            ))
            .expect("catalog");
            inputs.resources.catalogs = ProjectProgrammingCatalogs::with_fallback(catalog);

            let plan = inputs.plan().expect("management-only plan");
            let device = plan.device(&id).expect("target");
            assert!(device.serial_number().is_some(), "metadata remains available");
            assert_eq!(device.serial_addressing(), expected);
            assert_eq!(device.serial_target(), None);
            if intent.mutates_address() {
                assert!(matches!(device.commissioning().target, TargetSelection::ProgrammingButton(_)));
                assert!(inputs.requirements(&plan).contains(&ProjectSetupRequirement::PhysicalTarget { device: id }));
            } else {
                assert_eq!(
                    device.commissioning().target,
                    TargetSelection::ExistingAddress(crate::IndividualAddress::new(1, 1, 10))
                );
            }
        }
    }
}

#[test]
fn missing_credentials_and_tool_key_generation_are_typed() {
    let (_directory, mut inputs) = secure_inputs(BatchSelection::Selected, CommissioningIntent::AssignAddress);
    let receiver = crate::IndividualAddress::new(1, 1, 10);
    inputs.keyring = Some(Keyring::new("fixture".into(), "test".into(), "test".into()));
    assert!(matches!(inputs.plan(), Err(Error::ProjectSetup(ProjectSetupRequirement::ManagementCredential { device }))
        if device == ProjectDeviceId("receiver".into())));
    inputs.keyring = Some(
        inputs
            .keyring
            .take()
            .expect("keyring")
            .with_devices(vec![crate::security::KeyringDevice::new(receiver).with_fdsk(Some([0x11; 16]))]),
    );
    let plan = inputs.plan().expect("FDSK permits initial commissioning");
    assert!(
        inputs
            .requirements(&plan)
            .contains(&ProjectSetupRequirement::GenerateToolKey { device: ProjectDeviceId("receiver".into()) })
    );
}
