use super::*;
use crate::commissioning::CommissioningCancellation;
use crate::project::persistence::tests::{PERSISTENCE_PRODUCT_XML, persistence_fixture};
use crate::{BusResult, ConnectorInfo, KnxBus, KnxConnector};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use zweidraehte_ets_files::product::SelectedProduct;
use zweidraehte_ets_files::runtime::parse_application_program;

struct CountingConnector(Arc<AtomicUsize>);

impl KnxConnector for CountingConnector {
    async fn send_cemi(&mut self, _: &[u8]) -> BusResult<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn recv_cemi(&mut self) -> BusResult<Vec<u8>> {
        std::future::pending().await
    }
    async fn close(&mut self) -> BusResult<()> {
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn cancellation_before_preparation_sends_no_sender_probe() {
    let (planned, _) = persistence_fixture(CommissioningIntent::Download(DownloadMode::Full));
    let plan = ProgrammingBatchPlan {
        impact: Default::default(),
        devices: vec![planned],
        siat_senders: vec![ManagedSiatSender {
            device: ProjectDeviceId("sender".into()),
            address: crate::IndividualAddress::new(1, 1, 24),
            query: true,
            zero_sequence_policy: ZeroSiatSequencePolicy::Untouched,
            probe_key_material: Some(
                ResolvedKeyMaterial::new(Some([0, 0xFA, 0, 0, 0, 2])).with_tool_key(Some([0x44; 16])),
            ),
        }],
        commissioner_options: Default::default(),
        skip_current: false,
    };
    let sent = Arc::new(AtomicUsize::new(0));
    let bus = KnxBus::with_connector(CountingConnector(sent.clone()), ConnectorInfo {
        assigned_address: crate::IndividualAddress::new(1, 1, 250),
        max_apdu: 254,
    });
    let cancellation = CommissioningCancellation::default();
    cancellation.cancel();
    assert!(plan.prepare(&bus, &cancellation).await.is_err());
    assert_eq!(sent.load(Ordering::Relaxed), 0, "cancelled preparation must not contact a sender");
    bus.disconnect().await.expect("test bus closes");
}

#[tokio::test]
async fn queued_programming_persists_before_next_preflight_and_retains_reports() {
    use crate::bus::driver::{BusCommand, ConnectionId, TlOpenResult};
    use crate::bus::frames;
    use crate::commissioning::{CommissioningEvent, CommissioningStage};
    use zweidraehte_proto::messages::apdu::device::DeviceDescriptorResponse;
    use zweidraehte_proto::messages::knx::{ApciCode, KnxMessageBuffer, Tpci};

    for failure in [None, Some("preparation"), Some("cancellation"), Some("journal")] {
        let directory = tempfile::tempdir().expect("project directory");
        let path = directory.path().join("project.knx");
        let devices = [("first", 10), ("second", 11)]
            .into_iter()
            .map(|(id, address)| {
                format!(
                    "device {id} {{ product package:\"sha256:{}\" catalog_item \"button\" address 1.1.{address} }}",
                    "0".repeat(64),
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        std::fs::write(&path, format!("area 1 bench {{ line 1 devices {{ medium tp1 {devices} }} }}"))
            .expect("project source");
        let mut store = ProjectStore::open(&path).expect("project opens");
        store = store.initialize().expect("state initializes");
        let (fixture, _) = persistence_fixture(CommissioningIntent::Download(DownloadMode::Full));
        let selected = SelectedProduct::from_document(
            parse_application_program(PERSISTENCE_PRODUCT_XML).expect("fixture document"),
            None,
            None,
        )
        .expect("fixture selection")
        .bind_master_data(fixture.device.product().master_data().expect("fixture catalogue").clone())
        .expect("fixture catalogue binds");
        let product = ProjectProduct::new(selected);
        let products = store.authored().devices.keys().map(|id| (id.clone(), product.clone())).collect();
        let catalogs = ProjectProgrammingCatalogs::default();
        let mut initial = ProjectPlanner::new(store.authored(), store.state(), &products, None, None)
            .plan_commissioning(&[], BatchSelection::All, CommissioningIntent::Download(DownloadMode::Full))
            .expect("static queue validates");
        initial.configure(Default::default(), true, DifferentialPolicy::Disabled);
        let second = ProjectDeviceId("second".into());
        initial
            .set_target(&second, TargetSelection::KnownPreviousAddress(crate::IndividualAddress::new(1, 1, 11)))
            .expect("target override");
        let session = ProjectCommissioningSession::begin(store).expect("session owns writer");
        let (bus, mut rx) = KnxBus::scripted(ConnectorInfo {
            assigned_address: crate::IndividualAddress::new(1, 1, 250),
            max_apdu: 15,
        });
        let cancellation = CommissioningCancellation::default();
        let observer = session.store.clone();
        let mut saw_second = false;
        let peer = async {
            let mut target = crate::IndividualAddress::new(1, 1, 10);
            while let Some(command) = rx.recv().await {
                match command {
                    BusCommand::RemoveDeviceSecurity { tx, .. } | BusCommand::SetDeviceSecurity { tx, .. } => {
                        let _ = tx.send(());
                    }
                    BusCommand::TlOpen { dest, tx, .. } => {
                        target = dest;
                        if dest == crate::IndividualAddress::new(1, 1, 11) {
                            saw_second = true;
                            assert!(
                                observer
                                    .lock()
                                    .expect("read persisted outcome")
                                    .state()
                                    .expect("state")
                                    .deployment("first")
                                    .is_some()
                            );
                            if failure == Some("preparation") {
                                let _ = tx.send(Err(crate::BusError::Timeout));
                                continue;
                            }
                        }
                        let _ = tx.send(Ok(TlOpenResult {
                            connection: ConnectionId::TEST,
                            secure_management: false,
                            remote_next_sequence: None,
                        }));
                    }
                    BusCommand::TlRequest { frame, tx, .. } => {
                        let request = KnxMessageBuffer::from_buffer(frame);
                        assert_eq!(request.get_apci_code(), ApciCode::DeviceDescriptorRead);
                        let reply = frames::build_individual_frame(
                            target,
                            crate::IndividualAddress::new(1, 1, 250),
                            Tpci::DataConnected(0),
                            ApciCode::DeviceDescriptorResponse,
                            DeviceDescriptorResponse::TYPE0_MSG_LEN,
                            |buf| DeviceDescriptorResponse::write_type0(buf, &[0, 0x12]),
                        );
                        let _ = tx.send(Ok(reply));
                    }
                    BusCommand::TlClose { tx, .. } => {
                        let _ = tx.send(Ok(()));
                    }
                    BusCommand::Shutdown { tx } => {
                        let _ = tx.send(Ok(()));
                        break;
                    }
                    _ => panic!("unexpected queue fixture bus command"),
                }
            }
        };
        let client = async {
            let mut progress = |id: &ProjectDeviceId, event| {
                if id.0 == "first" && matches!(event, CommissioningEvent::Stage(CommissioningStage::Complete)) {
                    if failure == Some("cancellation") {
                        cancellation.cancel();
                    }
                    if failure == Some("journal") {
                        let owner = observer.clone();
                        let _ = std::thread::spawn(move || {
                            let _guard = owner.lock().expect("lock");
                            panic!("injected journal lock failure");
                        })
                        .join();
                    }
                }
            };
            let result = super::super::operation::ProjectOperationRequest::new(initial)
                .execute(
                    session,
                    |_| async { Ok(bus) },
                    ProjectProgrammingInputs { products: &products, catalogs: &catalogs, keyring: None },
                    &cancellation,
                    &mut progress,
                    |device| {
                        if device.id() == &second {
                            assert!(matches!(
                                device.planned().commissioning().target,
                                TargetSelection::KnownPreviousAddress(_)
                            ));
                        }
                        Ok(())
                    },
                )
                .await;
            match (failure, result) {
                (None, Ok(report)) => assert_eq!(report.devices.len(), 2),
                (Some(mode), Err(Error::ProjectBatch(error))) => {
                    assert_eq!(error.report.devices.len(), 1);
                    assert_eq!(error.report.devices[0].id.0, "first");
                    assert!(error.report.affected_devices.contains(&ProjectDeviceId("first".into())));
                    assert_eq!(error.finalization.len(), usize::from(mode == "journal"));
                    assert_eq!(
                        error.stage,
                        if mode == "journal" {
                            ProjectBatchFailureStage::SuccessPersistence
                        } else {
                            ProjectBatchFailureStage::Preparation
                        }
                    );
                }
                (_, other) => panic!("unexpected queue result: {other:?}"),
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            tokio::join!(client, peer);
        })
        .await
        .expect("queue fixture completes");
        assert_eq!(saw_second, failure.is_none() || failure == Some("preparation"));
    }
}
