use super::*;
use crate::commissioning::{AddressAssignment, CommissioningIntent, Diagnostic, DownloadMode};
use crate::project::persistence::tests::persistence_fixture;
use crate::project::{ProjectDeviceCommissioningReport, ProjectMasterData};
use crate::{BusError, ConnectorInfo, IndividualAddress, KnxConnector};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use zweidraehte_project::{ProjectStore, ProjectStoreError};

const SERIAL: [u8; 6] = [0, 0xFA, 0, 0, 0, 1];
const PROJECT: &str = r#"area 1 bench { line 1 main { medium tp1
    device button { product package:"sha256:0000000000000000000000000000000000000000000000000000000000000000" catalog_item "button" address 1.1.10 }
    device relay { product package:"sha256:0000000000000000000000000000000000000000000000000000000000000000" catalog_item "relay" address 1.1.11 serial "00FA:00000002" }
} }"#;

fn store() -> (tempfile::TempDir, ProjectStore) {
    let directory = tempfile::tempdir().expect("project directory");
    let path = directory.path().join("project.knx");
    std::fs::write(&path, PROJECT).expect("project source");
    let mut store = ProjectStore::open(path).expect("project opens");
    store = store.initialize().expect("project initializes");
    (directory, store)
}

struct ClosingConnector {
    closed: Arc<AtomicUsize>,
    fail: bool,
}

impl KnxConnector for ClosingConnector {
    async fn send_cemi(&mut self, _: &[u8]) -> BusResult<()> {
        panic!("fixture requires no telegrams")
    }
    async fn recv_cemi(&mut self) -> BusResult<Vec<u8>> {
        std::future::pending().await
    }
    async fn close(&mut self) -> BusResult<()> {
        self.closed.fetch_add(1, Ordering::Relaxed);
        if self.fail { Err(BusError::Timeout) } else { Ok(()) }
    }
}

fn bus(security: SecurityStore, closed: Arc<AtomicUsize>, fail: bool) -> KnxBus {
    KnxBus::with_connector_and_security(
        ClosingConnector { closed, fail },
        ConnectorInfo { assigned_address: IndividualAddress::new(1, 1, 250), max_apdu: 254 },
        security,
    )
}

fn completed() -> ProjectDeviceCommissioningReport {
    let (_, report) = persistence_fixture(CommissioningIntent::Download(DownloadMode::Full));
    ProjectDeviceCommissioningReport { id: ProjectDeviceId("relay".into()), report }
}

fn assigned_effects() -> ExecutionEffects {
    let mut effects = ExecutionEffects::with_status(MutationStatus::PartiallyApplied);
    effects.confirm_address(AddressAssignment {
        changed: true,
        previous: IndividualAddress::new(15, 15, 255),
        current: IndividualAddress::new(1, 1, 10),
        serial_number: Some(SERIAL),
    });
    effects
}

#[tokio::test]
async fn finalization_keeps_partial_assignment_and_every_cleanup_failure() {
    for primary_failure in [false, true] {
        let (directory, store) = store();
        let path = store.project_path().to_path_buf();
        let session = ProjectCommissioningSession::begin(store).expect("writer");
        let closed = Arc::new(AtomicUsize::new(0));
        let operation =
            ProjectOperation::connect(session, None, |security| async { Ok(bus(security, closed.clone(), true)) })
                .await
                .expect("connected operation");

        let physical = completed();
        let result = if primary_failure {
            Err(Error::ProjectBatch(Box::new(ProjectBatchFailure {
                device: Some(ProjectDeviceId("button".into())),
                stage: ProjectBatchFailureStage::Commissioning,
                report: ProjectBatchReport::from_devices(vec![physical]),
                source: Some(Box::new(
                    CommissioningError::after_execution(
                        Diagnostic::new("application fails after assignment"),
                        assigned_effects(),
                    )
                    .into(),
                )),
                state_errors: Vec::new(),
                finalization: vec![],
            })))
        } else {
            let mut assignment = completed();
            assignment.id = ProjectDeviceId("button".into());
            assignment.report.effects = assigned_effects();
            Ok(ProjectBatchReport::from_devices(vec![physical, assignment]))
        };
        // Independent failures must neither replace the physical reports nor
        // prevent later cleanup. Both failures are genuine filesystem errors.
        std::fs::write(directory.path().join("project.knx"), format!("{PROJECT}\n")).expect("external editor");
        let snapshot = directory.path().join(".zweidraehte/snapshot.json");
        std::fs::remove_file(&snapshot).expect("remove snapshot");
        std::fs::create_dir(&snapshot).expect("block snapshot publication");
        let Error::ProjectBatch(failure) = operation.finish(result).await.expect_err("cleanup fails") else {
            panic!("typed batch failure");
        };
        assert_eq!(failure.report.devices.len(), if primary_failure { 1 } else { 2 });
        assert!(failure.report.affected_devices.contains(&ProjectDeviceId("button".into())));
        assert_eq!(failure.report.learned_targets[&ProjectDeviceId("button".into())].serial_number, Some(SERIAL));
        assert!(failure.report.serial_updates.is_empty());
        assert_eq!(failure.source.is_some(), primary_failure);
        assert!(matches!(&failure.finalization[..], [
            ProjectFinalizationFailure::AuthoredSerial {
                source: Error::ProjectStore(ProjectStoreError::AuthoredProjectChanged(_)),
                ..
            },
            ProjectFinalizationFailure::Disconnect(_),
            ProjectFinalizationFailure::Compact(_),
        ]));
        assert_eq!(closed.load(Ordering::Relaxed), 1);
        // A file-only edit can test exclusion even with the damaged snapshot;
        // acquiring a full writer would correctly reject that unreadable state.
        ProjectStore::write_authored(&path, Some(&format!("{PROJECT}\n")), PROJECT)
            .expect("all owned capabilities release exclusion");
    }
}

#[tokio::test]
async fn assignment_is_saved_even_when_the_remaining_application_fails() {
    let (_directory, store) = store();
    let path = store.project_path().to_path_buf();
    let session = ProjectCommissioningSession::begin(store).expect("writer");
    let closed = Arc::new(AtomicUsize::new(0));
    let operation =
        ProjectOperation::connect(session, None, |security| async { Ok(bus(security, closed.clone(), false)) })
            .await
            .expect("connect operation");
    let failure = ProjectBatchFailure {
        device: Some(ProjectDeviceId("button".into())),
        stage: ProjectBatchFailureStage::Commissioning,
        report: ProjectBatchReport::from_devices(vec![completed()]),
        source: Some(Box::new(
            CommissioningError::after_execution(Diagnostic::new("application fails"), assigned_effects()).into(),
        )),
        state_errors: vec![],
        finalization: vec![],
    };
    let Error::ProjectBatch(failure) =
        operation.finish(Err(Error::ProjectBatch(Box::new(failure)))).await.expect_err("application error survives")
    else {
        panic!("typed batch failure");
    };
    assert!(failure.finalization.is_empty());
    assert_eq!(failure.report.devices.len(), 1);
    assert_eq!(failure.report.serial_updates[&ProjectDeviceId("button".into())], Some(SERIAL));
    let store = ProjectStore::open(path).expect("reopen authored state");
    assert_eq!(store.authored().devices[&ProjectDeviceId("button".into())].serial, Some(SERIAL));
    assert_eq!(store.authored().devices[&ProjectDeviceId("relay".into())].serial, Some([0, 0xFA, 0, 0, 0, 2]));
    assert_eq!(closed.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn connect_failure_and_cancelled_request_finalize_without_connecting_again() {
    let (directory, store) = store();
    let session = ProjectCommissioningSession::begin(store).expect("writer");
    session.advance_client_sequence(500).expect("pending observation");
    let result = ProjectOperation::connect(session, None, |_| async { Err(BusError::Timeout) }).await;
    assert!(matches!(result, Err(Error::ProjectBatch(_))));
    let store = ProjectStore::open(directory.path().join("project.knx")).expect("reopen");
    assert_eq!(store.state().expect("state").client_next, 500);
    assert_eq!(std::fs::metadata(directory.path().join(".zweidraehte/journal.jsonl")).expect("journal").len(), 0);

    let session = ProjectCommissioningSession::begin(store).expect("writer released after failed connect");
    let policy = crate::project::ProgrammingPolicy { generate_missing_tool_keys: true, ..Default::default() };
    let plan = ProgrammingBatchPlan {
        impact: Default::default(),
        devices: vec![],
        siat_senders: vec![],
        policy,
        skip_current: false,
    };
    let mut cancellation = crate::commissioning::CommissioningCancellation::default();
    cancellation.cancel();
    let products = Default::default();
    let catalogs = ProjectMasterData::default();
    let result = execute_batch(
        session,
        plan,
        |_| async { panic!("cancelled request must not connect") },
        ProjectProgrammingInputs { products: &products, master_data: &catalogs, keyring: None },
        &mut cancellation,
    )
    .await;
    assert!(matches!(result, Err(Error::ProjectBatch(failure)) if failure.report.devices.is_empty()));
}
