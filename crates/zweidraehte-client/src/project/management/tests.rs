use super::*;
use crate::ConnectorInfo;
use crate::bus::driver::{BusCommand, ConnectionId, TlOpenResult};
use crate::bus::frames;
use crate::project::tests::secure_fixture;
use std::collections::BTreeMap;
use tokio::sync::mpsc;
use zweidraehte_project::{ParamValue, ParameterAssignment, ProjectStoreError};
use zweidraehte_proto::messages::apdu::property_ext::{PropertyExtValueHeader, PropertyExtValueResponse};
use zweidraehte_proto::messages::knx::{ApciCode, KnxMessageBuffer, Tpci};

fn recovery_fixture() -> (tempfile::TempDir, ProjectCommissioningSession, AuthoredProject, Vec<ProjectManagementTarget>)
{
    let fixture = secure_fixture();
    let directory = tempfile::tempdir().expect("project directory");
    let path = directory.path().join("project.knx");
    std::fs::write(&path, fixture.project.source()).expect("project source");
    let store = ProjectStore::open(&path).expect("project").initialize().expect("initialized");
    let project = store.authored().clone();
    let targets = project
        .devices
        .values()
        .map(|device| {
            ProjectManagementTarget::resolve(
                device,
                store.keys().expect("keys"),
                Some(&fixture.keyring),
                SerialAddressingSupport::Unknown,
            )
            .expect("management target")
        })
        .collect();
    let session = ProjectCommissioningSession::begin_recovery(store).expect("recovery writer");
    (directory, session, project, targets)
}

#[test]
fn management_resolution_ignores_invalid_application_edits_and_missing_group_keys() {
    let fixture = secure_fixture();
    let (directory, session, _, _) = recovery_fixture();
    let mut project = fixture.project.clone();
    let id = ProjectDeviceId("receiver".into());
    let device = project.devices.get_mut(&id).expect("receiver");
    device.parameters.push(ParameterAssignment {
        id: "not-a-product-parameter".into(),
        value: ParamValue::Text("invalid".into()),
        span: device.span,
    });
    let keyring = fixture.keyring.with_group_keys(BTreeMap::new());
    assert!(fixture.products[&id].evaluate(&project, &project.devices[&id]).is_err(), "desired application is invalid");
    let target = session
        .inspect(|store| {
            ProjectManagementTarget::resolve(
                &project.devices[&id],
                store.keys().expect("keys"),
                Some(&keyring),
                SerialAddressingSupport::Supported,
            )
        })
        .expect("inspect")
        .expect("independent management credentials");
    assert_eq!(target.serial_number(), Some([0, 0xfa, 0, 0, 0, 1]));
    assert!(target.has_credentials());
    assert!(!format!("{target:?}").contains(&"22".repeat(16)), "debug must redact credentials");
    drop(session);
    assert!(ProjectStore::open(directory.path().join("project.knx")).expect("reader").into_writer().is_ok());
}

#[derive(Default)]
struct PeerOptions {
    unavailable: Option<IndividualAddress>,
    bad_property: Option<(u16, u16)>,
    fail_disconnect: bool,
    fail_device_close: bool,
    fail_sync_persistence: bool,
}

async fn recovery_peer(mut rx: mpsc::Receiver<BusCommand>, options: PeerOptions) {
    let client = IndividualAddress::new(1, 1, 250);
    let mut current = IndividualAddress::new(1, 1, 10);
    while let Some(command) = rx.recv().await {
        match command {
            BusCommand::SetDeviceSecurity { tx, .. } => {
                tx.send(()).expect("security reply");
            }
            BusCommand::TlOpen { dest, force_sync, tx } => {
                assert!(force_sync, "synchronization must not reuse a cached handshake");
                current = dest;
                let result = if options.fail_sync_persistence {
                    Err(BusError::Io(std::io::Error::other("sequence journal unavailable")))
                } else if options.unavailable == Some(dest) {
                    Err(BusError::Timeout)
                } else {
                    Ok(TlOpenResult {
                        connection: ConnectionId::TEST,
                        secure_management: true,
                        remote_next_sequence: Some(400),
                    })
                };
                assert!(tx.send(result).is_ok());
            }
            BusCommand::TlRequest { frame, tx, .. } => {
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(request.get_apci_code(), ApciCode::PropertyExtValueRead);
                let header = PropertyExtValueHeader::parse(request.buf()).expect("extended property request");
                assert_eq!(header.object_type, u16::from(InterfaceObjectType::Security));
                let value = if options.bad_property == Some((header.prop_id, header.start_idx)) {
                    vec![0]
                } else {
                    match (header.prop_id, header.start_idx) {
                        (pid::security::SEQUENCE_NUMBER_SENDING, 1) => vec![0, 0, 0, 0, 1, 0x91], // 401
                        (pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 0) => vec![0, 2],
                        (pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 1) => {
                            [client.as_bytes(), &[0, 0, 0, 0, 2, 0xed]].concat()
                        } // 749
                        (pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 2) => vec![0x11, 11, 0, 0, 0, 0, 0, 120],
                        _ => panic!("unexpected property"),
                    }
                };
                let response = frames::build_individual_frame(
                    current,
                    client,
                    Tpci::DataConnected(0),
                    ApciCode::PropertyExtValueResponse,
                    PropertyExtValueResponse::msg_len(value.len()),
                    |buf| {
                        PropertyExtValueResponse::write(
                            buf,
                            header.object_type,
                            1,
                            header.prop_id,
                            1,
                            header.start_idx,
                            &value,
                        )
                    },
                );
                tx.send(Ok(response)).expect("property reply");
            }
            BusCommand::TlClose { tx, .. } => {
                assert!(tx.send(if options.fail_device_close { Err(BusError::Timeout) } else { Ok(()) }).is_ok());
            }
            BusCommand::Shutdown { tx } => {
                assert!(tx.send(if options.fail_disconnect { Err(BusError::Timeout) } else { Ok(()) }).is_ok());
                break;
            }
            _ => panic!("unexpected management command"),
        }
    }
}

async fn operation(session: ProjectCommissioningSession) -> (ProjectOperation, mpsc::Receiver<BusCommand>) {
    let (bus, rx) =
        KnxBus::scripted(ConnectorInfo { assigned_address: IndividualAddress::new(1, 1, 250), max_apdu: 64 });
    let operation = ProjectOperation::connect(session, None, |_| async { Ok(bus) }).await.expect("operation");
    (operation, rx)
}

#[tokio::test]
async fn unavailable_receivers_require_an_explicit_floor_and_keep_observed_state() {
    for floor in [None, Some(900)] {
        let (directory, session, project, targets) = recovery_fixture();
        let (operation, rx) = operation(session).await;
        let run = async {
            let mut report = ProjectSynchronizationReport::default();
            let result = operation
                .synchronize_targets(
                    &project,
                    &targets,
                    ProjectSynchronization::Recover { client_floor: floor },
                    &mut report,
                )
                .await;
            operation.finish_management(report, result, true).await
        };
        let (result, ()) = tokio::join!(
            run,
            recovery_peer(rx, PeerOptions {
                unavailable: Some(IndividualAddress::new(1, 1, 11)),
                ..Default::default()
            })
        );
        let report = match &result {
            Ok(report) => report,
            Err(failure) => &failure.report,
        };
        assert_eq!(report.devices.len(), 2);
        assert!(report.devices[0].complete);
        assert_eq!(report.devices[0].outgoing_next, Some(401));
        assert_eq!(report.devices[0].siat_rows, 2);
        assert!(report.devices[1].unavailable.is_some());
        assert_eq!(result.is_ok(), floor.is_some());
        if let Err(failure) = result {
            assert!(matches!(failure.source, Some(Error::RecoveryIncomplete { .. })));
        }
        let store = ProjectStore::open(directory.path().join("project.knx")).expect("persisted project");
        let state = store.state().expect("state");
        assert_eq!(state.client_next, floor.unwrap_or(750));
        assert_eq!(state.recovery_required, floor.is_none());
        let receiver = &state.devices[&format_serial(&[0, 0xfa, 0, 0, 0, 1])];
        assert_eq!(receiver.outgoing_next, 401);
        assert!(store.into_writer().is_ok(), "finalization releases exclusion");
    }
}

#[tokio::test]
async fn malformed_recovery_properties_keep_partial_observations_and_remain_blocked() {
    for bad_property in [
        (pid::security::SEQUENCE_NUMBER_SENDING, 1),
        (pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 0),
        (pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 2),
    ] {
        let (directory, session, project, targets) = recovery_fixture();
        let (operation, rx) = operation(session).await;
        let run = async {
            let mut report = ProjectSynchronizationReport::default();
            let result = operation
                .synchronize_targets(
                    &project,
                    &targets,
                    ProjectSynchronization::Recover { client_floor: Some(900) },
                    &mut report,
                )
                .await;
            operation.finish_management(report, result, true).await
        };
        let (result, ()) = tokio::join!(
            run,
            recovery_peer(rx, PeerOptions {
                bad_property: Some(bad_property),
                fail_device_close: true,
                ..Default::default()
            })
        );
        let failure = result.expect_err("malformed observation blocks recovery even with a floor");
        assert!(matches!(failure.source, Some(Error::ManagementCleanup { .. })), "primary and close errors survive");
        assert!(!failure.report.devices[0].complete);
        if bad_property.0 != pid::security::SEQUENCE_NUMBER_SENDING {
            assert_eq!(failure.report.devices[0].outgoing_next, Some(401));
        }
        let store = ProjectStore::open(directory.path().join("project.knx")).expect("project");
        assert!(!store.secure_state_ready());
        assert_eq!(store.state().expect("state").client_next, 900);
    }
}

#[tokio::test]
async fn complete_observations_survive_disconnect_and_compaction_failures() {
    let (directory, session, project, targets) = recovery_fixture();
    let (operation, rx) = operation(session).await;
    let run = async {
        let mut report = ProjectSynchronizationReport::default();
        let result = operation
            .synchronize_targets(
                &project,
                &targets,
                ProjectSynchronization::Recover { client_floor: None },
                &mut report,
            )
            .await;
        assert!(result.is_ok());
        let path = directory.path().join(".zweidraehte/snapshot.json");
        std::fs::remove_file(&path).expect("remove snapshot");
        std::fs::create_dir(&path).expect("block snapshot publication");
        operation.finish_management(report, result, true).await
    };
    let (result, ()) =
        tokio::join!(run, recovery_peer(rx, PeerOptions { fail_disconnect: true, ..Default::default() }));
    let failure = result.expect_err("cleanup errors");
    assert!(failure.source.is_none());
    assert!(failure.report.devices.iter().all(|device| device.complete && device.outgoing_next == Some(401)));
    assert!(matches!(&failure.finalization[..], [
        ProjectFinalizationFailure::Disconnect(_),
        ProjectFinalizationFailure::Compact(_)
    ]));
}

#[tokio::test]
async fn invalid_explicit_floor_fails_before_sending_and_keeps_recovery_blocked() {
    let (directory, session, project, targets) = recovery_fixture();
    let (operation, mut rx) = operation(session).await;
    let run = async {
        let mut report = ProjectSynchronizationReport::default();
        let result = operation
            .synchronize_targets(
                &project,
                &targets,
                ProjectSynchronization::Recover { client_floor: Some(u64::MAX) },
                &mut report,
            )
            .await;
        operation.finish_management(report, result, true).await
    };
    let peer = async {
        let BusCommand::Shutdown { tx } = rx.recv().await.expect("shutdown") else {
            panic!("invalid floor must send no requests");
        };
        tx.send(Ok(())).expect("shutdown reply");
    };
    let (result, ()) = tokio::join!(run, peer);
    assert!(matches!(
        result.expect_err("invalid floor").source,
        Some(Error::ProjectStore(ProjectStoreError::SequenceExhausted))
    ));
    let store = ProjectStore::open(directory.path().join("project.knx")).expect("project");
    assert!(!store.secure_state_ready());
}

#[tokio::test]
async fn a_recovery_floor_cannot_bypass_sequence_persistence_failure() {
    let (directory, session, project, targets) = recovery_fixture();
    let (operation, rx) = operation(session).await;
    let run = async {
        let mut report = ProjectSynchronizationReport::default();
        let result = operation
            .synchronize_targets(
                &project,
                &targets,
                ProjectSynchronization::Recover { client_floor: Some(900) },
                &mut report,
            )
            .await;
        operation.finish_management(report, result, true).await
    };
    let (result, ()) =
        tokio::join!(run, recovery_peer(rx, PeerOptions { fail_sync_persistence: true, ..Default::default() }));
    let failure = result.expect_err("persistence failure is not an unavailable receiver");
    assert!(matches!(failure.source, Some(Error::Bus(BusError::Io(_)))));
    assert!(!failure.report.devices[0].complete);
    let store = ProjectStore::open(directory.path().join("project.knx")).expect("project");
    assert!(!store.secure_state_ready());
}

#[tokio::test]
async fn synchronization_does_not_load_unrelated_plain_products() {
    let fixture = secure_fixture();
    let directory = tempfile::tempdir().expect("project directory");
    let path = directory.path().join("project.knx");
    std::fs::write(&path, fixture.project.source().replace("data_secure enabled", "data_secure disabled"))
        .expect("project refers to products which are intentionally absent");
    let store = ProjectStore::open(&path).expect("project").initialize().expect("initialized");
    let session = ProjectCommissioningSession::begin(store).expect("writer");
    let (operation, mut rx) = operation(session).await;
    let unused_catalog = directory.path().join("missing-master.xml");
    let peer = async {
        let BusCommand::Shutdown { tx } = rx.recv().await.expect("shutdown") else {
            panic!("no secure receivers");
        };
        tx.send(Ok(())).expect("shutdown reply");
    };
    let (result, ()) =
        tokio::join!(operation.synchronize(None, Some(&unused_catalog), ProjectSynchronization::Synchronize), peer);
    assert!(result.expect("plain products do not gate secure synchronization").devices.is_empty());
    assert!(ProjectStore::open(&path).expect("reader").into_writer().is_ok());
}
