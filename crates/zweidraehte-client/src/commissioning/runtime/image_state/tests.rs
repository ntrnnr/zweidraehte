//! Scripted peers inspect encoded APDUs below the real DeviceConnection.
use crate::commissioning::runtime::TransferContext;
#[path = "tests/semantics.rs"]
mod semantics;
use super::super::*;
use super::*;
use crate::bus::BusError as Error;
use crate::bus::driver::{BusCommand, TlOpenResult};
use crate::bus::frames;
use crate::commissioning::catalog::profile::ObjectSelector;
use crate::commissioning::catalog::profile::ResourceId;
use crate::commissioning::compiler::secrets::CredentialTransition;
use crate::commissioning::image::{ImageLocation, ImageSpace, SparseDeviceImage};
use crate::commissioning::procedure::operands::{MemoryAddress, MemoryService, PropertyAddress};
use crate::commissioning::procedure::*;
use crate::commissioning::report::CommissioningEvent;
use crate::connector::ConnectorInfo;
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::mpsc;
use zweidraehte_proto::messages::apdu::memory::{MemoryAccess, MemoryResponse};
use zweidraehte_proto::messages::apdu::property::{PropertyValueHeader, PropertyValueResponse};
use zweidraehte_proto::messages::knx::{ApciCode, KnxMessageBuffer, Tpci, offsets};
use zweidraehte_proto::pid;

fn address() -> IndividualAddress {
    IndividualAddress::new(1, 1, 10)
}
fn bus() -> (KnxBus, mpsc::Receiver<BusCommand>) {
    KnxBus::scripted(ConnectorInfo { assigned_address: IndividualAddress::new(1, 1, 1), max_apdu: 15 })
}
fn config(verify_mode: bool) -> SessionConfig {
    SessionConfig {
        scan_window: Duration::ZERO,
        target_max_apdu: 15,
        verify_mode,
        authorization: AuthorizationPolicy::None,
        load_state_poll_attempts: 2,
        load_state_poll_interval: Duration::ZERO,
        minimum_restart_delay: Duration::ZERO,
        minimum_equal_run: 1,
    }
}
fn memory(address: u32) -> OperationTarget {
    OperationTarget::Memory { service: MemoryService::Classic, address: MemoryAddress::Fixed(address) }
}
fn property(start: u16) -> OperationTarget {
    OperationTarget::Property {
        address: PropertyAddress::Indexed { object_index: 3, property_id: 27 },
        start_element: start,
    }
}
fn location(offset: u32) -> ImageLocation {
    ImageLocation::standard_memory(offset)
}
fn property_location(offset: u32) -> ImageLocation {
    ImageLocation {
        space: crate::commissioning::image::ImageSpace::Property {
            object: crate::commissioning::catalog::profile::ObjectSelector::Index { index: 3 },
            property_id: 27,
        },
        offset,
    }
}
fn procedure(operations: Vec<ProcedureOperation>) -> NormalizedProcedure {
    let id = ProcedureSourceId::Generated { name: "scripted regression".into() };
    NormalizedProcedure {
        id: id.clone(),
        initial_state: ToolState::default(),
        stamp_output: DownloadStampOutput::default(),
        steps: operations
            .into_iter()
            .enumerate()
            .map(|(index, operation)| ProcedureStep {
                path: ControlPath {
                    mask_id: "MV-0705".into(),
                    variant_index: 0,
                    procedure: id.clone(),
                    contribution: None,
                    control_indices: vec![index],
                },
                source_control_code: None,
                sections: Default::default(),
                operation,
                on_error: Vec::new(),
                secure_only: false,
            })
            .collect(),
    }
}

#[tokio::test]
async fn compare_refresh_retains_working_image_binding_and_new_read_replaces_it() {
    let (bus, _) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    session.images.cache_read(memory(0x100), OperationExtent::bytes(1), Some(location(0x100)), vec![1]);
    session.images.cache_read(memory(0x100), OperationExtent::bytes(1), None, vec![2]);
    assert_eq!(session.images.cached_location(&location(0x100), 1), Some(&vec![2]));
    session.images.cache_read(memory(0x200), OperationExtent::bytes(1), Some(location(0x100)), vec![3]);
    assert_eq!(session.images.cached_location(&location(0x100), 1), Some(&vec![3]));
    assert_eq!(session.images.cache.len(), 1);
}

#[tokio::test]
async fn evidence_capture_freezes_values_and_absence_for_revalidation() {
    use crate::commissioning::runtime::commissioner::CommissioningCancellation;
    use crate::commissioning::runtime::prepare::revalidate::read_bound_evidence;
    use crate::commissioning::runtime::prepared::{BoundRead, ReadExpectation};
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut reads = vec![
        BoundRead {
            resource: ResourceId("identity".into()),
            service: ServiceRead { target: property(1), extent: OperationExtent::property(1, 1) },
            expected: ReadExpectation::Capture { optional: false },
        },
        BoundRead {
            resource: ResourceId("stamp".into()),
            service: ServiceRead { target: property(2), extent: OperationExtent::property(1, 1) },
            expected: ReadExpectation::Capture { optional: true },
        },
    ];
    let client = async {
        read_bound_evidence(&mut session, &mut reads, &CommissioningCancellation::default())
            .await
            .expect("initial read binds");
        assert_eq!(reads[0].expected, ReadExpectation::Exact(Some(vec![5])));
        assert_eq!(reads[1].expected, ReadExpectation::Exact(None));
        let error = read_bound_evidence(&mut session, &mut reads, &CommissioningCancellation::default())
            .await
            .expect_err("new presence invalidates evidence");
        assert!(error.to_string().contains("presence"));
    };
    let absent = Wire::Property {
        pid: 27,
        start: 2,
        count: 1,
        write: None,
        reply: Err(Error::PropertyValueUnavailable { object_index: 3, property_id: 27 }),
    };
    tokio::join!(
        client,
        peer(rx, vec![
            Wire::Open(false),
            prop_read(27, 1, 1, &[5]),
            absent,
            Wire::Close(Ok(())),
            Wire::Open(false),
            prop_read(27, 1, 1, &[5]),
            prop_read(27, 2, 1, &[9]),
            Wire::Close(Ok(()))
        ])
    );
}

#[tokio::test]
async fn multi_record_stamp_probe_chunks_and_revalidates_every_record() {
    use crate::commissioning::compiler::binding::tests::preparation_support::{
        authorization_profile, deployment_record, indexed_stamp_resource, partial_plan, set_feature, set_resources,
    };
    use crate::commissioning::evidence::{DeviceStamp, DifferentialDecision, DifferentialFallback, DifferentialPolicy};
    use crate::commissioning::input::ProgramSections;
    use crate::commissioning::runtime::commissioner::CommissioningCancellation;
    use crate::commissioning::runtime::prepare::installation::{
        baseline_stamp_reads, finish_baseline, prepare_baseline,
    };
    use crate::commissioning::runtime::prepare::revalidate::read_bound_evidence;
    use crate::commissioning::runtime::prepared::ReadExpectation;

    let mut profile = authorization_profile("System7", None);
    set_feature(&mut profile, "DownloadStamp", 1);
    set_feature(&mut profile, "FirstAppObjectIdx", 5);
    set_resources(&mut profile, vec![indexed_stamp_resource(
        "application",
        3,
        crate::commissioning::catalog::profile::ReadAccess::Runtime,
        false,
    )]);
    let plan = partial_plan(profile, ProgramSections::PARAMETERS);
    let mut value = vec![0x11; 8];
    value.extend([0x22; 8]);
    let deployment = deployment_record(plan.profile(), [0; 32], vec![DeviceStamp {
        resource: ResourceId("application".into()),
        value: value.clone(),
    }]);
    let baseline = prepare_baseline(&plan, DifferentialPolicy::FallBackToUndifferenced, Some(&deployment))
        .expect("local history is valid")
        .0
        .expect("both records require observation");
    let mut reads = baseline_stamp_reads(&plan, baseline).expect("probe ranges bind");
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let cancellation = CommissioningCancellation::default();
    let client = async {
        read_bound_evidence(&mut session, &mut reads, &cancellation).await.expect("both records are captured");
        assert_eq!(reads[0].expected, ReadExpectation::Exact(Some(value.clone())));
        let (decision, known) =
            finish_baseline(&plan, baseline, &reads, DifferentialPolicy::FallBackToUndifferenced, 1)
                .expect("matching records verify the baseline");
        assert_eq!(decision, DifferentialDecision::VerifiedUndifferenced {
            previous_image_fingerprint: deployment.image_fingerprint,
            device_stamps: deployment.device_stamps.clone(),
        });
        assert_eq!(known, Some(deployment.image.clone()));
        read_bound_evidence(&mut session, &mut reads, &cancellation).await.expect("execute rechecks both records");
        let error = read_bound_evidence(&mut session, &mut reads, &cancellation)
            .await
            .expect_err("a changed second record invalidates prepared evidence");
        assert!(error.to_string().contains("changed from its required value"));

        // A changed later record during initial preparation must also prevent
        // baseline reuse, even if its first record is still identical.
        let mut stale = reads.clone();
        value[8] = 0x33;
        stale[0].expected = ReadExpectation::Exact(Some(value.clone()));
        let (decision, known) =
            finish_baseline(&plan, baseline, &stale, DifferentialPolicy::FallBackToUndifferenced, 1)
                .expect("a stale baseline permits ordinary fallback");
        assert_eq!(decision, DifferentialDecision::FellBackToUndifferenced {
            reason: DifferentialFallback::StampMismatch,
        });
        assert!(known.is_none());
    };
    // At APDU 15 each response fits only one complete eight-byte record.
    tokio::join!(
        client,
        peer(rx, vec![
            Wire::Open(false),
            prop_read(27, 1, 1, &[0x11; 8]),
            prop_read(27, 2, 1, &[0x22; 8]),
            Wire::Close(Ok(())),
            Wire::Open(false),
            prop_read(27, 1, 1, &[0x11; 8]),
            prop_read(27, 2, 1, &[0x22; 8]),
            Wire::Close(Ok(())),
            Wire::Open(false),
            prop_read(27, 1, 1, &[0x11; 8]),
            prop_read(27, 2, 1, &[0x33; 8]),
            Wire::Close(Ok(())),
        ])
    );
}

#[tokio::test]
async fn optional_evidence_does_not_hide_read_or_cleanup_failures() {
    use crate::commissioning::runtime::commissioner::CommissioningCancellation;
    use crate::commissioning::runtime::prepare::revalidate::read_bound_evidence;
    use crate::commissioning::runtime::prepared::{BoundRead, ReadExpectation};
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut reads = vec![BoundRead {
        resource: ResourceId("stamp".into()),
        service: ServiceRead { target: property(1), extent: OperationExtent::property(1, 1) },
        expected: ReadExpectation::Capture { optional: true },
    }];
    let cancellation = CommissioningCancellation::default();
    let (result, ()) = tokio::join!(
        read_bound_evidence(&mut session, &mut reads, &cancellation),
        peer(rx, vec![
            Wire::Open(false),
            Wire::Property { pid: 27, start: 1, count: 1, write: None, reply: Err(Error::Timeout) },
            Wire::Close(Err(Error::Disconnected))
        ])
    );
    let error = result.expect_err("timeout is not absence");
    assert_eq!(error.transport, Some(crate::commissioning::error::TransportCause::Timeout));
    assert_eq!(error.cleanup_failures.len(), 1);
    assert_eq!(reads[0].expected, ReadExpectation::Capture { optional: true });
}
fn write(target: OperationTarget, data: OperationData, length: u32) -> ProcedureOperation {
    ProcedureOperation::Write {
        target,
        data,
        extent: OperationExtent::bytes(length),
        policy: WriteIntent::Explicit(WritePolicy::NoVerification),
    }
}

#[derive(Debug)]
enum Wire {
    Descriptor(u16),
    Authorize,
    Serial {
        instance: u16,
        value: Vec<u8>,
    },
    Restart(Result<(), Error>),
    Reset {
        code: u8,
        error: u8,
    },
    UserWrite {
        address: u32,
        data: Vec<u8>,
    },
    Function {
        command: bool,
        data: Vec<u8>,
    },
    Open(bool),
    OpenAt(IndividualAddress),
    AddressScan(Result<Vec<IndividualAddress>, Error>),
    AddressWrite {
        address: IndividualAddress,
        result: Result<(), Error>,
    },
    Close(Result<(), Error>),
    Property {
        start: u16,
        count: u16,
        pid: u16,
        write: Option<Vec<u8>>,
        reply: Result<Vec<u8>, Error>,
    },
    /// A standard property request on an explicit object index.
    ObjectProperty {
        object_index: u8,
        pid: u16,
        write: Option<Vec<u8>>,
        reply: Result<Vec<u8>, Error>,
    },
    /// An extended description read by object type and instance.
    ExtDescription {
        object_type: u16,
        object_instance: u16,
        pid: u16,
        pdt: u8,
    },
    /// `None` answers with the negative response for an absent property.
    Description {
        object_index: u8,
        pid: u16,
        pdt: Option<u8>,
    },
    Memory {
        address: u16,
        count: u8,
        write: Option<Vec<u8>>,
        reply: Result<Vec<u8>, Error>,
    },
    ExtendedMemory {
        address: u32,
        count: u8,
        write: Option<Vec<u8>>,
        reply: Result<Vec<u8>, Error>,
    },
}
fn prop_read(pid: u16, start: u16, count: u16, value: &[u8]) -> Wire {
    Wire::Property { pid, start, count, write: None, reply: Ok(value.to_vec()) }
}
fn prop_write(pid: u16, value: u8) -> Wire {
    Wire::Property { pid, start: 1, count: 1, write: Some(vec![value]), reply: Ok(vec![value]) }
}
fn mem_write(address: u16, value: &[u8]) -> Wire {
    Wire::Memory { address, count: value.len() as u8, write: Some(value.to_vec()), reply: Ok(Vec::new()) }
}
async fn peer(mut channel: mpsc::Receiver<BusCommand>, script: Vec<Wire>) {
    let mut connected_target = address();
    for expected in script {
        let mut command = channel.recv().await.expect("expected request reaches scripted peer");
        if matches!(expected, Wire::Open(_) | Wire::OpenAt(_)) {
            let BusCommand::SetDeviceSecurity { tx, .. } = command else {
                panic!("opening installs the selected credential");
            };
            tx.send(()).expect("credential installed");
            command = channel.recv().await.expect("open follows credential installation");
        }
        match (expected, command) {
            (Wire::AddressScan(result), BusCommand::Scan { frame, tx, .. }) => {
                use zweidraehte_proto::messages::apdu::device::APCI_ONLY_MSG_LEN;
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(request.get_apci_code(), ApciCode::IndividualAddressRead);
                let result = result.map(|addresses| {
                    addresses
                        .into_iter()
                        .map(|source| {
                            frames::build_individual_frame(
                                source,
                                address(),
                                Tpci::DataIndividual,
                                ApciCode::IndividualAddressResponse,
                                APCI_ONLY_MSG_LEN,
                                |_| {},
                            )
                        })
                        .collect()
                });
                assert!(tx.send(result).is_ok());
            }
            (Wire::AddressWrite { address, result }, BusCommand::SendOnly { frame, tx }) => {
                use zweidraehte_proto::messages::apdu::device::IndividualAddressWrite;
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(request.get_apci_code(), ApciCode::IndividualAddressWrite);
                assert_eq!(IndividualAddressWrite::address_bytes(request.buf()), Some(address.as_bytes()));
                assert!(tx.send(result).is_ok());
            }
            (Wire::OpenAt(expected), BusCommand::TlOpen { dest, force_sync, tx }) => {
                assert_eq!(dest, expected);
                assert!(!force_sync);
                connected_target = dest;
                assert!(
                    tx.send(Ok(TlOpenResult {
                        connection: crate::bus::driver::ConnectionId::TEST,
                        secure_management: false,
                        remote_next_sequence: None
                    }))
                    .is_ok()
                );
            }
            (Wire::Descriptor(dd0), BusCommand::TlRequest { frame, tx, .. }) => {
                use zweidraehte_proto::messages::apdu::device::{DeviceDescriptorRead, DeviceDescriptorResponse};
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(request.get_apci_code(), ApciCode::DeviceDescriptorRead);
                assert_eq!(DeviceDescriptorRead::parse(request.buf()).expect("descriptor request").descriptor_type, 0);
                let response = frames::build_individual_frame(
                    address(),
                    IndividualAddress::new(1, 1, 1),
                    Tpci::DataConnected(0),
                    ApciCode::DeviceDescriptorResponse,
                    DeviceDescriptorResponse::TYPE0_MSG_LEN,
                    |buf| DeviceDescriptorResponse::write_type0(buf, &dd0.to_be_bytes()),
                );
                assert!(tx.send(Ok(response)).is_ok());
            }
            (Wire::Authorize, BusCommand::TlRequest { frame, tx, .. }) => {
                use zweidraehte_proto::messages::apdu::auth::{AuthorizeRequest, AuthorizeResponse};
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(request.get_apci_code(), ApciCode::AuthorizeRequest);
                assert_eq!(AuthorizeRequest::parse(request.buf()).expect("authorization request").key, [1, 2, 3, 4]);
                let response = frames::build_individual_frame(
                    address(),
                    IndividualAddress::new(1, 1, 1),
                    Tpci::DataConnected(0),
                    ApciCode::AuthorizeResponse,
                    AuthorizeResponse::MSG_LEN,
                    |buf| AuthorizeResponse::write(buf, 3),
                );
                assert!(tx.send(Ok(response)).is_ok());
            }
            (Wire::Serial { instance, value }, BusCommand::TlRequest { frame, tx, .. }) => {
                use zweidraehte_proto::messages::apdu::property_ext::{
                    PropertyExtValueHeader, PropertyExtValueResponse,
                };
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(request.get_apci_code(), ApciCode::PropertyExtValueRead);
                let header = PropertyExtValueHeader::parse(request.buf()).expect("serial request");
                assert_eq!(
                    (header.object_type, header.object_instance, header.prop_id, header.start_idx, header.count),
                    (0, instance, pid::SERIAL_NUMBER, 1, 1)
                );
                let response = frames::build_individual_frame(
                    address(),
                    IndividualAddress::new(1, 1, 1),
                    Tpci::DataConnected(0),
                    ApciCode::PropertyExtValueResponse,
                    PropertyExtValueResponse::msg_len(value.len()),
                    |buf| PropertyExtValueResponse::write(buf, 0, instance, pid::SERIAL_NUMBER, 1, 1, &value),
                );
                assert!(tx.send(Ok(response)).is_ok());
            }
            (Wire::Function { command, data }, BusCommand::TlRequest { frame, tx, .. }) => {
                use zweidraehte_proto::messages::apdu::function_property::{
                    FunctionPropertyHeader, FunctionPropertyResponse,
                };
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(
                    request.get_apci_code(),
                    if command { ApciCode::FunctionPropertyCommand } else { ApciCode::FunctionPropertyStateRead }
                );
                let header = FunctionPropertyHeader::parse(request.buf()).expect("valid function request");
                assert_eq!((header.object_idx, header.prop_id), (3, 42));
                assert_eq!(header.data(request.buf()), data);
                let response = frames::build_individual_frame(
                    address(),
                    IndividualAddress::new(1, 1, 1),
                    Tpci::DataConnected(0),
                    ApciCode::FunctionPropertyStateResponse,
                    FunctionPropertyResponse::msg_len(1),
                    |buf| FunctionPropertyResponse::write(buf, 3, 42, 0, &[9]),
                );
                assert!(tx.send(Ok(response)).is_ok());
            }
            (Wire::Reset { code, error }, BusCommand::TlRequest { frame, tx, completion, .. }) => {
                use zweidraehte_proto::messages::apdu::restart::{RestartParsed, RestartResponse};
                let request = KnxMessageBuffer::from_buffer(frame);
                let reset = RestartParsed::parse(request.buf()).expect("reset request");
                assert!(reset.is_master_reset);
                assert_eq!((reset.erase_code, reset.channel), (code, 0));
                assert!(matches!(completion, crate::bus::driver::Completion::Response(_)));
                let response = frames::build_individual_frame(
                    address(),
                    IndividualAddress::new(1, 1, 1),
                    Tpci::DataConnected(0),
                    ApciCode::Restart,
                    RestartResponse::MSG_LEN,
                    |buf| RestartResponse::write(buf, error, 0),
                );
                assert!(tx.send(Ok(response)).is_ok());
            }
            (Wire::Restart(result), BusCommand::TlRequest { frame, tx, completion, .. }) => {
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(request.get_apci_code(), ApciCode::Restart);
                assert_eq!(completion, crate::bus::driver::Completion::Acknowledgement);
                assert!(tx.send(result.map(|()| Vec::new())).is_ok());
            }
            (Wire::UserWrite { address: expected, data }, BusCommand::TlRequest { frame, tx, completion, .. }) => {
                use zweidraehte_proto::messages::apdu::memory::UserMemoryAccess;
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(request.get_apci_code(), ApciCode::UserMemoryWrite);
                let access = UserMemoryAccess::parse_write(request.buf()).expect("valid user memory request");
                assert_eq!(access.full_address(), expected);
                assert_eq!(access.data, data);
                assert_eq!(completion, crate::bus::driver::Completion::Acknowledgement);
                assert!(tx.send(Ok(Vec::new())).is_ok());
            }
            (Wire::Open(secure_management), BusCommand::TlOpen { dest, force_sync, tx }) => {
                assert_eq!(dest, address());
                assert!(!force_sync);
                connected_target = dest;
                assert!(
                    tx.send(Ok(TlOpenResult {
                        connection: crate::bus::driver::ConnectionId::TEST,
                        secure_management,
                        remote_next_sequence: None
                    }))
                    .is_ok()
                );
            }
            (Wire::Close(result), BusCommand::TlClose { tx, .. }) => assert!(tx.send(result).is_ok()),
            (
                Wire::ExtDescription { object_type, object_instance, pid, pdt },
                BusCommand::TlRequest { frame, tx, .. },
            ) => {
                use zweidraehte_proto::messages::apdu::property_ext::{
                    PropertyExtDescriptionHeader, PropertyExtDescriptionResponse,
                };
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(request.get_apci_code(), ApciCode::PropertyExtDescriptionRead);
                let read = PropertyExtDescriptionHeader::parse(request.buf()).expect("extended description request");
                assert_eq!((read.object_type, read.object_instance, read.prop_id), (object_type, object_instance, pid));
                let description = zweidraehte_proto::properties::PropertyDescriptionResponse {
                    object_idx: 0,
                    prop_id: pid,
                    prop_idx: 0,
                    writeable: true,
                    pdt,
                    max_elements: 1,
                    read_level: 3,
                    write_level: 2,
                };
                let response = frames::build_individual_frame(
                    connected_target,
                    IndividualAddress::new(1, 1, 1),
                    Tpci::DataConnected(0),
                    ApciCode::PropertyExtDescriptionResponse,
                    PropertyExtDescriptionResponse::MSG_LEN,
                    |buf| PropertyExtDescriptionResponse::write(buf, object_type, object_instance, &description),
                );
                assert!(tx.send(Ok(response)).is_ok());
            }
            (Wire::Description { object_index, pid, pdt }, BusCommand::TlRequest { frame, tx, .. }) => {
                use zweidraehte_proto::messages::apdu::property::{
                    PropertyDescriptionRead, PropertyDescriptionResponse,
                };
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(request.get_apci_code(), ApciCode::PropertyDescriptionRead);
                let read = PropertyDescriptionRead::parse(request.buf()).expect("description request");
                assert_eq!((read.object_idx, read.prop_id, read.prop_idx), (u16::from(object_index), pid, 0));
                // Writable, one element, read level 3 and write level 2.
                let payload = match pdt {
                    Some(pdt) => [object_index, pid as u8, 0, 0x80 | pdt, 0, 1, 0x32],
                    None => PropertyDescriptionResponse::encode_error_payload(object_index, pid, 0),
                };
                let response = frames::build_individual_frame(
                    connected_target,
                    IndividualAddress::new(1, 1, 1),
                    Tpci::DataConnected(0),
                    ApciCode::PropertyDescriptionResponse,
                    PropertyDescriptionResponse::MSG_LEN,
                    |buf| buf[offsets::MSG_APCI + 2..].copy_from_slice(&payload),
                );
                assert!(tx.send(Ok(response)).is_ok());
            }
            (Wire::Property { start, count, pid, write, reply }, BusCommand::TlRequest { frame, tx, .. }) => {
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(
                    request.get_apci_code(),
                    if write.is_some() { ApciCode::PropertyValueWrite } else { ApciCode::PropertyValueRead }
                );
                let header = PropertyValueHeader::parse(request.buf()).expect("valid property request");
                assert_eq!((header.prop_id, header.start_idx, header.count), (pid, start, count));
                assert_eq!(header.object_idx, if pid == pid::DEVICE_CONTROL { 0 } else { 3 });
                if let Some(data) = write {
                    assert_eq!(header.data(request.buf()), data);
                }
                let response = reply.map(|data| {
                    frames::build_individual_frame(
                        connected_target,
                        IndividualAddress::new(1, 1, 1),
                        Tpci::DataConnected(0),
                        ApciCode::PropertyValueResponse,
                        PropertyValueResponse::msg_len(data.len()),
                        |buf| PropertyValueResponse::write(buf, header.object_idx as u8, pid, count, start, &data),
                    )
                });
                assert!(tx.send(response).is_ok());
            }
            (Wire::ObjectProperty { object_index, pid, write, reply }, BusCommand::TlRequest { frame, tx, .. }) => {
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(
                    request.get_apci_code(),
                    if write.is_some() { ApciCode::PropertyValueWrite } else { ApciCode::PropertyValueRead }
                );
                let header = PropertyValueHeader::parse(request.buf()).expect("valid property request");
                assert_eq!(
                    (header.object_idx, header.prop_id, header.start_idx, header.count),
                    (u16::from(object_index), pid, 1, 1)
                );
                if let Some(data) = write {
                    assert_eq!(header.data(request.buf()), data);
                }
                let response = reply.map(|data| {
                    frames::build_individual_frame(
                        connected_target,
                        IndividualAddress::new(1, 1, 1),
                        Tpci::DataConnected(0),
                        ApciCode::PropertyValueResponse,
                        PropertyValueResponse::msg_len(data.len()),
                        |buf| PropertyValueResponse::write(buf, object_index, pid, 1, 1, &data),
                    )
                });
                assert!(tx.send(response).is_ok());
            }
            (
                Wire::ExtendedMemory { address: expected, count, write, reply },
                BusCommand::TlRequest { frame, tx, completion, .. },
            ) => {
                use zweidraehte_proto::messages::apdu::memory::{MemoryExtendedAccess, MemoryExtendedResponse};
                use zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode;
                let request = KnxMessageBuffer::from_buffer(frame);
                assert_eq!(
                    request.get_apci_code(),
                    if write.is_some() { ApciCode::MemoryExtendedWrite } else { ApciCode::MemoryExtendedRead }
                );
                let access = MemoryExtendedAccess::parse(request.buf()).expect("valid extended-memory request");
                assert_eq!((access.address, access.count), (expected, count));
                assert_eq!(access.data, write.as_deref().unwrap_or_default());
                assert!(matches!(completion, crate::bus::driver::Completion::Response(_)));
                let response = reply.map(|data| {
                    frames::build_individual_frame(
                        address(),
                        IndividualAddress::new(1, 1, 1),
                        Tpci::DataConnected(0),
                        if write.is_some() {
                            ApciCode::MemoryExtendedWriteResponse
                        } else {
                            ApciCode::MemoryExtendedReadResponse
                        },
                        MemoryExtendedResponse::msg_len(data.len()),
                        |buf| MemoryExtendedResponse::write(buf, PropertyReturnCode::Success, expected, &data),
                    )
                });
                assert!(tx.send(response).is_ok());
            }
            (
                Wire::Memory { address: expected, count, write, reply },
                BusCommand::TlRequest { frame, tx, completion, .. },
            ) => {
                let request = KnxMessageBuffer::from_buffer(frame);
                let access = if let Some(data) = write {
                    assert_eq!(request.get_apci_code(), ApciCode::MemoryWrite);
                    let access = MemoryAccess::parse_write(request.buf()).expect("valid memory write");
                    assert_eq!(access.data, data);
                    access
                } else {
                    assert_eq!(request.get_apci_code(), ApciCode::MemoryRead);
                    MemoryAccess::parse_read(request.buf()).expect("valid memory read")
                };
                assert_eq!((access.address, access.count), (expected, count));
                let response = reply.map(|data| {
                    if matches!(completion, crate::bus::driver::Completion::Response(_)) {
                        frames::build_individual_frame(
                            address(),
                            IndividualAddress::new(1, 1, 1),
                            Tpci::DataConnected(0),
                            ApciCode::MemoryReadResponse,
                            MemoryResponse::msg_len(data.len()),
                            |buf| MemoryResponse::write(buf, count, expected, &data),
                        )
                    } else {
                        Vec::new()
                    }
                });
                assert!(tx.send(response).is_ok());
            }
            (expected, actual) => {
                let actual = match actual {
                    BusCommand::TlRequest { frame, .. } => {
                        let request = KnxMessageBuffer::from_buffer(frame);
                        format!("request {:?}", request.get_apci_code())
                    }
                    BusCommand::TlOpen { .. } => "open".to_owned(),
                    BusCommand::TlClose { .. } => "close".to_owned(),
                    _ => "other bus command".to_owned(),
                };
                panic!("expected {expected:?}, received {actual}");
            }
        }
    }
}

#[tokio::test]
async fn reconnect_reapplies_actual_verify_mode_and_restores_each_session() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(true), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::Disconnect,
        ProcedureOperation::Connect,
        ProcedureOperation::Disconnect,
    ]);
    controls.initial_state.memory_auto_verify = Some(true);
    let image = SparseDeviceImage::new();
    let script = vec![
        Wire::Open(false),
        prop_read(pid::DEVICE_CONTROL, 1, 1, &[0]),
        prop_write(pid::DEVICE_CONTROL, 4),
        prop_write(pid::DEVICE_CONTROL, 0),
        Wire::Close(Ok(())),
        Wire::Open(false),
        prop_read(pid::DEVICE_CONTROL, 1, 1, &[0]),
        prop_write(pid::DEVICE_CONTROL, 4),
        prop_write(pid::DEVICE_CONTROL, 0),
        Wire::Close(Ok(())),
    ];
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, script)
    );
    result.expect("both sessions restore and close");
}

#[tokio::test]
async fn secure_guard_precedes_any_verify_mode_mutation() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(true), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut controls = procedure(vec![ProcedureOperation::Connect, ProcedureOperation::Disconnect]);
    controls.steps[0].secure_only = true;
    controls.initial_state.memory_auto_verify = Some(true);
    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![Wire::Open(false), Wire::Close(Ok(()))])
    );
    assert!(result.expect_err("plaintext refused").message.contains("secure management"));
}

#[tokio::test]
async fn lost_mode_response_rechecks_physical_state_without_replacing_original() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(true), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let client = async {
        session.connect().await.expect("open");
        session.set_memory_verify_mode(true).await.expect_err("response is lost");
        session
            .write(
                &memory(0x120),
                &[9],
                OperationExtent::bytes(1),
                WritePolicy::NoVerification,
                TransferContext::Public,
            )
            .await
            .expect("mode recovered");
        session.disconnect().await.expect("original zero retained");
    };
    let script = vec![
        Wire::Open(false),
        prop_read(pid::DEVICE_CONTROL, 1, 1, &[0]),
        Wire::Property {
            pid: pid::DEVICE_CONTROL,
            start: 1,
            count: 1,
            write: Some(vec![4]),
            reply: Err(Error::Timeout),
        },
        prop_read(pid::DEVICE_CONTROL, 1, 1, &[4]),
        prop_write(pid::DEVICE_CONTROL, 0),
        mem_write(0x120, &[9]),
        Wire::Close(Ok(())),
    ];
    tokio::join!(client, peer(rx, script));
    assert!(session.mutated());
}

#[tokio::test]
async fn differential_ranges_keep_real_offsets_and_overlapping_inline_writes() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location(0x200), vec![1; 8]).expect("range");
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        write(memory(0x202), OperationData::Inline(vec![9]), 1),
        write(memory(0x200), OperationData::Image { location: location(0x200), length: 8 }, 8),
        ProcedureOperation::Disconnect,
    ]);
    session.images.known = image.clone();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![Wire::Open(false), mem_write(0x202, &[9]), mem_write(0x202, &[1]), Wire::Close(Ok(()))])
    );
    result.expect("only overwritten byte retransferred");
}

#[tokio::test]
async fn different_runtime_fallback_is_not_skipped_against_desired_bytes() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location(0x200), vec![1; 4]).expect("range");
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        write(
            memory(0x200),
            OperationData::Buffer { location: location(0x200), length: 4, fallback: Some(vec![2; 4]) },
            4,
        ),
        ProcedureOperation::Disconnect,
    ]);
    session.images.known = image.clone();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![Wire::Open(false), mem_write(0x200, &[2; 4]), Wire::Close(Ok(()))])
    );
    result.expect("runtime fallback transferred");
}

#[tokio::test]
async fn buffered_writes_use_the_image_when_inline_fallback_is_short() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location(0x200), vec![1; 4]).expect("first range");
    image.apply_owned(location(0x204), vec![2; 4]).expect("second range");
    image.apply_owned(location(0x208), vec![3; 4]).expect("third range");
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        write(
            memory(0x200),
            OperationData::Buffer { location: location(0x200), length: 4, fallback: Some(Vec::new()) },
            4,
        ),
        write(
            memory(0x204),
            OperationData::Buffer { location: location(0x204), length: 4, fallback: Some(vec![9; 2]) },
            4,
        ),
        write(
            memory(0x208),
            OperationData::Buffer { location: location(0x208), length: 4, fallback: Some(vec![7; 6]) },
            4,
        ),
        ProcedureOperation::Disconnect,
    ]);
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            mem_write(0x200, &[1; 4]),
            mem_write(0x204, &[2; 4]),
            mem_write(0x208, &[7; 4]),
            Wire::Close(Ok(())),
        ],)
    );
    result.expect("buffered writes use complete transfer payloads");
}

fn described(property_id: u8, action: DescribedPropertyAction) -> ProcedureOperation {
    ProcedureOperation::DescribedProperty(DescribedPropertyOperation {
        target: OperationTarget::Property {
            address: PropertyAddress::Indexed { object_index: 4, property_id },
            start_element: 1,
        },
        elements: 1,
        extended_description: false,
        widths: BTreeMap::from([(2, 1), (4, 2)]),
        action,
    })
}

#[tokio::test]
async fn described_property_controls_read_the_description_once_and_use_its_width() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let write = |property_id| {
        described(property_id, DescribedPropertyAction::Write {
            payload: vec![0x01],
            policy: WriteIntent::Explicit(WritePolicy::NoVerification),
        })
    };
    // A one-octet authored mask covers only the first compared octet.
    let compare = described(201, DescribedPropertyAction::Compare {
        reference: vec![0x98, 0x96, 0x03],
        mask: Some(vec![0xf0]),
        cache: CachePolicy::Bypass,
        invert: false,
        retry_interval_milliseconds: None,
        timeout_milliseconds: None,
    });
    let mut controls = procedure(vec![
        ProcedureOperation::Connect,
        write(67),
        write(67),
        compare,
        write(68),
        ProcedureOperation::ClearCache,
        write(67),
        write(69),
        ProcedureOperation::Disconnect,
    ]);
    // The reference reports a property the target does not describe as an
    // unavailable resource; this control's handler ignores exactly that.
    controls.steps[7].on_error =
        vec![ErrorHandler { cause: LoadControlCause::ResourceNotFound, action: ErrorAction::Ignore }];
    let image = SparseDeviceImage::new();
    let one_octet =
        || Wire::ObjectProperty { object_index: 4, pid: 67, write: Some(vec![0x01]), reply: Ok(vec![0x01]) };
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            // PID 67 is one octet wide: the authored byte is sent, and the
            // second write reuses the description.
            Wire::Description { object_index: 4, pid: 67, pdt: Some(2) },
            one_octet(),
            one_octet(),
            // PID 201 is two octets wide: the comparison reads and compares
            // only that prefix of the three-octet reference, ignoring the
            // masked low nibble of its first octet.
            Wire::Description { object_index: 4, pid: 201, pdt: Some(4) },
            Wire::ObjectProperty { object_index: 4, pid: 201, write: None, reply: Ok(vec![0x9f, 0x96]) },
            // PID 68 is two octets wide; one authored octet sends nothing.
            Wire::Description { object_index: 4, pid: 68, pdt: Some(4) },
            // Clearing cached object types forgets the descriptions.
            Wire::Description { object_index: 4, pid: 67, pdt: Some(2) },
            one_octet(),
            Wire::Description { object_index: 4, pid: 69, pdt: None },
            Wire::Close(Ok(())),
        ])
    );
    result.expect("described property controls follow their descriptions");
}

#[tokio::test]
async fn type_addressed_descriptions_follow_the_reference_lookup_by_type() {
    use zweidraehte_proto::dpt::InterfaceObjectType;

    let target = OperationTarget::Property {
        address: PropertyAddress::Extended {
            object_type: InterfaceObjectType::Router,
            object_instance: 1,
            property_id: 201,
        },
        start_element: 1,
    };
    let router = u16::from(InterfaceObjectType::Router);
    let object_type = |index, object_type: u16| Wire::ObjectProperty {
        object_index: index,
        pid: pid::OBJECT_TYPE,
        write: None,
        reply: Ok(object_type.to_be_bytes().to_vec()),
    };

    // Over a 15-octet connection the object is located and described by
    // index, even when the product admits extended property services. The
    // index description is then reused.
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    let (result, ()) = tokio::join!(
        async {
            session.connect_without_authorization_at(address()).await?;
            let first = session.described_property_type(&target, true).await?;
            let second = session.described_property_type(&target, false).await?;
            Ok::<_, Diagnostic>((first, second))
        },
        peer(rx, vec![Wire::Open(false), object_type(0, 0), object_type(1, router), Wire::Description {
            object_index: 1,
            pid: 201,
            pdt: Some(2)
        },]),
    );
    assert_eq!(result.expect("located description"), (2, 2));

    // A longer connection reads the description by type, and keeps it by
    // type.
    let (bus, rx) = KnxBus::scripted(ConnectorInfo { assigned_address: IndividualAddress::new(1, 1, 1), max_apdu: 55 });
    let mut session = ExecutionSession::new(
        &bus,
        address(),
        SessionConfig { target_max_apdu: 55, ..config(false) },
        ManagementAccess::Plaintext,
    )
    .expect("valid config");
    let (result, ()) = tokio::join!(
        async {
            session.connect_without_authorization_at(address()).await?;
            let first = session.described_property_type(&target, true).await?;
            let second = session.described_property_type(&target, true).await?;
            Ok::<_, Diagnostic>((first, second))
        },
        peer(rx, vec![Wire::Open(false), Wire::ExtDescription {
            object_type: router,
            object_instance: 1,
            pid: 201,
            pdt: 4
        },]),
    );
    assert_eq!(result.expect("extended description"), (4, 4));
}

#[tokio::test]
async fn described_image_writes_send_their_segment_clipped_to_the_description() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let segment = |property_id| ImageLocation {
        space: ImageSpace::Property { object: ObjectSelector::Index { index: 4 }, property_id },
        offset: 0,
    };
    let mut image = SparseDeviceImage::new();
    for (property_id, data) in [(70, vec![0x11, 0x22]), (71, vec![0x33])] {
        image.apply(
            &crate::commissioning::image::ImageSegment::owned(segment(property_id), data).expect("owned segment"),
        );
    }
    let write = |property_id: u8, length| {
        described(property_id, DescribedPropertyAction::WriteImage {
            location: segment(u16::from(property_id)),
            length,
            policy: WriteIntent::Explicit(WritePolicy::NoVerification),
        })
    };
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        write(70, 2),
        write(71, 1),
        write(72, 0),
        ProcedureOperation::Disconnect,
    ]);
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            // One octet per element: only the segment's first byte is sent.
            Wire::Description { object_index: 4, pid: 70, pdt: Some(2) },
            Wire::ObjectProperty { object_index: 4, pid: 70, write: Some(vec![0x11]), reply: Ok(vec![0x11]) },
            // Two octets per element, but the segment holds one: the write
            // stops at the segment's end.
            Wire::Description { object_index: 4, pid: 71, pdt: Some(4) },
            Wire::ObjectProperty { object_index: 4, pid: 71, write: Some(vec![0x33]), reply: Ok(vec![0x33]) },
            // Without a segment the description is still read, then nothing
            // is sent.
            Wire::Description { object_index: 4, pid: 72, pdt: Some(2) },
            Wire::Close(Ok(())),
        ])
    );
    result.expect("described image writes follow their descriptions and segments");
}

#[tokio::test]
async fn comparison_populates_and_reuses_exact_cache_until_clear() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let compare = ProcedureOperation::Compare {
        target: memory(0x200),
        comparison: Comparison::Exact {
            data: OperationData::Inline(vec![1]),
            mask: None,
            padding: ComparisonPadding::None,
        },
        extent: OperationExtent::bytes(1),
        cache: CachePolicy::UseAndPopulate,
        invert: false,
        retry_interval_milliseconds: None,
        timeout_milliseconds: None,
    };
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        compare.clone(),
        compare.clone(),
        ProcedureOperation::ClearCache,
        compare,
        ProcedureOperation::Disconnect,
    ]);
    let image = SparseDeviceImage::new();
    let read = || Wire::Memory { address: 0x200, count: 1, write: None, reply: Ok(vec![1]) };
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![Wire::Open(false), read(), read(), Wire::Close(Ok(()))])
    );
    result.expect("cache reused and cleared");
}

#[tokio::test]
async fn ignored_load_record_failure_skips_its_whole_implicit_transfer_group() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let record = LoadRecord {
        write: ServiceRead { target: memory(0x100), extent: OperationExtent::bytes(1) },
        bytes: vec![1],
        poll: None,
        effect: LoadEffect::None,
    };
    let mut controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::AbsoluteSegment {
            record,
            transfers: vec![MemoryTransfer {
                target: memory(0x200),
                data: OperationData::Inline(vec![2]),
                extent: OperationExtent::bytes(1),
                policy: WriteIntent::AbsoluteSegment,
            }],
        },
        write(memory(0x300), OperationData::Inline(vec![3]), 1),
        ProcedureOperation::Disconnect,
    ]);
    controls.steps[1]
        .on_error
        .push(ErrorHandler { cause: LoadControlCause::DeviceReturnCode(2), action: ErrorAction::Ignore });
    let image = SparseDeviceImage::new();
    let script = vec![
        Wire::Open(false),
        Wire::Memory { address: 0x100, count: 1, write: Some(vec![1]), reply: Err(Error::DeviceError(2)) },
        mem_write(0x300, &[3]),
        Wire::Close(Ok(())),
    ];
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, script)
    );
    result.expect("one authored failure boundary");
}

#[tokio::test]
async fn stamp_output_never_uses_unobserved_desired_bytes() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    image.apply_owned(property_location(0), vec![7; 4]).expect("range");
    let mut controls = procedure(vec![ProcedureOperation::Connect, ProcedureOperation::Disconnect]);
    controls.stamp_output = DownloadStampOutput::ImageProperties(vec![StampDescriptor {
        id: crate::commissioning::catalog::profile::ResourceId("stamp".into()),
        image_location: property_location(0),
        read: ServiceRead { target: property(1), extent: OperationExtent::property(4, 1) },
        optional: false,
    }]);
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![Wire::Open(false), Wire::Close(Ok(()))])
    );
    result.expect("procedure completes");
    assert!(session.images.completed_stamps().expect("no stamp observation").is_empty());
}

#[tokio::test]
async fn multi_record_stamp_publishes_every_observed_record() {
    // An application object's PID 27 holds one eight-byte record per load
    // segment. The profile binds one record; the procedure reads all of
    // them, and the published stamp keeps every record (M-000C_A-1341).
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let image = SparseDeviceImage::new();
    let regions = vec![native(property_location(0), 16)];
    let mut controls = procedure(vec![ProcedureOperation::Connect, load(0, 16, 8), ProcedureOperation::Disconnect]);
    controls.stamp_output = DownloadStampOutput::ImageProperties(vec![StampDescriptor {
        id: crate::commissioning::catalog::profile::ResourceId("ApplicationStamp".into()),
        image_location: property_location(0),
        read: ServiceRead { target: property(1), extent: OperationExtent::property(8, 1) },
        optional: false,
    }]);
    let records: Vec<u8> = (1..=16).collect();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &regions, &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            prop_read(27, 1, 1, &records[..8]),
            prop_read(27, 2, 1, &records[8..]),
            Wire::Close(Ok(()))
        ])
    );
    result.expect("both records read");
    let stamps = session.images.completed_stamps().expect("whole records publish");
    assert_eq!(stamps.len(), 1);
    assert_eq!(stamps[0].value, records);
}

fn native(location: ImageLocation, length: u32) -> crate::commissioning::image::NativeImageRegion {
    crate::commissioning::image::NativeImageRegion {
        source_id: Some("native-test".into()),
        memory_type: None,
        seed: Vec::new(),
        location,
        length,
    }
}
fn load(offset: u32, length: u32, width: u32) -> ProcedureOperation {
    ProcedureOperation::LoadImage {
        target: property((offset / width + 1) as u16),
        image_location: property_location(offset),
        extent: OperationExtent::property(length, (length / width) as u16),
        alignment: width,
    }
}

#[tokio::test]
async fn live_property_image_load_supplies_later_transfers_without_changing_desired_state() {
    // A live property may have no desired image allocation. Its observed value
    // still belongs in the working image for later image-backed transfers;
    // this is independent of the object's identity or property element width.
    for width in [1, 6, 8] {
        let (bus, rx) = bus();
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
        session.begin_execution();
        let desired = SparseDeviceImage::new();
        let observed = vec![0x3c; width as usize];
        let controls = procedure(vec![
            ProcedureOperation::Connect,
            load(0, width, width),
            ProcedureOperation::Write {
                target: OperationTarget::Property {
                    address: PropertyAddress::Indexed { object_index: 3, property_id: 28 },
                    start_element: 1,
                },
                data: OperationData::Image { location: property_location(0), length: width },
                extent: OperationExtent::property(width, 1),
                policy: WriteIntent::Explicit(WritePolicy::NoVerification),
            },
            ProcedureOperation::Disconnect,
        ]);
        let script = vec![
            Wire::Open(false),
            prop_read(27, 1, 1, &observed),
            Wire::Property { pid: 28, start: 1, count: 1, write: Some(observed.clone()), reply: Ok(observed.clone()) },
            Wire::Close(Ok(())),
        ];
        let (result, ()) = tokio::join!(
            ProcedureRunner::new(&mut session).execute(&desired, &[], &controls, || false, |_| {}),
            peer(rx, script)
        );
        result.expect("live property values feed the later transfer");
        assert_eq!(desired.byte(&property_location(0)), None);
        let working = session.images.working.range(&property_location(0), width).expect("observed property is owned");
        assert_eq!(working.data(), observed);
        assert!(working.mask().iter().all(|mask| *mask == 255));
    }
}

#[tokio::test]
async fn changing_leading_bound_retains_an_owned_byte_in_native_read() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    image.apply_owned(property_location(0), vec![0xa5; 9]).expect("prefix");
    let regions = vec![native(property_location(0), 16)];
    let controls = procedure(vec![ProcedureOperation::Connect, load(0, 16, 1), ProcedureOperation::Disconnect]);
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &regions, &controls, || false, |_| {}),
        peer(rx, vec![Wire::Open(false), prop_read(27, 9, 8, &[0x3c; 8]), Wire::Close(Ok(()))])
    );
    result.expect("native tail read");
    let merged = session.images.working.range(&property_location(0), 16).expect("whole native region now known");
    assert_eq!(&merged.data()[..9], &[0xa5; 9]);
    assert_eq!(&merged.data()[9..], &[0x3c; 7]);
}

#[tokio::test]
async fn independent_alignment_leaves_one_byte_for_the_next_native_read() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    let mut mask = vec![255; 16];
    mask[7] = 0;
    mask[8] = 0;
    image.apply(
        &crate::commissioning::image::ImageSegment::new(property_location(0), vec![0xa5; 16], mask)
            .expect("masked region"),
    );
    let regions = vec![native(property_location(0), 16)];
    let controls =
        procedure(vec![ProcedureOperation::Connect, load(0, 16, 8), load(0, 16, 8), ProcedureOperation::Disconnect]);
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &regions, &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            prop_read(27, 1, 1, &[0x3c; 8]),
            prop_read(27, 2, 1, &[0x4d; 8]),
            Wire::Close(Ok(()))
        ])
    );
    result.expect("both independently aligned reads");
    let merged = session.images.working.range(&property_location(0), 16).expect("complete working region");
    assert_eq!(merged.data()[7], 0x3c);
    assert_eq!(merged.data()[8], 0x4d);
    assert_eq!(image.byte(&property_location(7)), None);
}

#[tokio::test]
async fn adjacent_native_regions_clip_load_provenance() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let image = SparseDeviceImage::new();
    let regions = vec![native(property_location(0), 8), native(property_location(8), 8)];
    let controls = procedure(vec![ProcedureOperation::Connect, load(4, 12, 1), ProcedureOperation::Disconnect]);
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &regions, &controls, || false, |_| {}),
        peer(rx, vec![Wire::Open(false), prop_read(27, 5, 4, &[3; 4]), Wire::Close(Ok(()))])
    );
    result.expect("first native segment clipped");
    assert!(session.images.working.range(&property_location(4), 4).is_ok());
    assert!(session.images.working.byte(&property_location(8)).is_none());
}

#[tokio::test]
async fn failed_load_does_not_create_working_bytes_or_stamp_evidence() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let image = SparseDeviceImage::new();
    let regions = vec![native(property_location(0), 8)];
    let mut controls = procedure(vec![
        ProcedureOperation::Connect,
        load(0, 8, 8),
        ProcedureOperation::Write {
            target: property(1),
            data: OperationData::Image { location: property_location(0), length: 8 },
            extent: OperationExtent::property(8, 1),
            policy: WriteIntent::Explicit(WritePolicy::NoVerification),
        },
        ProcedureOperation::Disconnect,
    ]);
    controls.steps[1]
        .on_error
        .push(ErrorHandler { cause: LoadControlCause::DeviceReturnCode(2), action: ErrorAction::Ignore });
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &regions, &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            Wire::Property { start: 1, count: 1, pid: 27, write: None, reply: Err(Error::DeviceError(2)) },
            Wire::Close(Ok(()))
        ])
    );
    assert!(result.expect_err("unobserved working data refused").message.contains("not completely defined"));
    assert!(session.images.working.is_empty());
    assert!(session.images.stamp_observations.is_empty());
}

#[tokio::test]
async fn invalid_private_payload_fails_before_connecting() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut previous = SecretCommissioningPayload::default();
    let reference = previous.insert([7; 16].into()).expect("key");
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        write(memory(0x200), OperationData::Secret(reference), 16),
        ProcedureOperation::Disconnect,
    ]);
    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![])
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn confirmed_secret_transition_survives_cleanup_failure_without_caching_key_bytes() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let reference = session
        .secret_payload
        .insert_with_transitions([7; 16].into(), vec![CredentialTransition::ToolKey])
        .expect("key");
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        write(memory(0x200), OperationData::Secret(reference), 16),
        ProcedureOperation::Disconnect,
    ]);
    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            mem_write(0x200, &[7; 12]),
            mem_write(0x20c, &[7; 4]),
            Wire::Close(Err(Error::Timeout))
        ])
    );
    result.expect_err("close fails");
    assert_eq!(session.effects.credential_transitions(), vec![CredentialTransition::ToolKey]);
    assert!(session.images.known.is_empty());
}

#[tokio::test]
async fn uncertain_secret_write_never_reports_a_credential_transition() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let reference = session
        .secret_payload
        .insert_with_transitions([7; 16].into(), vec![CredentialTransition::ToolKey])
        .expect("key");
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        write(memory(0x200), OperationData::Secret(reference), 16),
        ProcedureOperation::Disconnect,
    ]);
    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            mem_write(0x200, &[7; 12]),
            Wire::Memory { address: 0x20c, count: 4, write: Some(vec![7; 4]), reply: Err(Error::Timeout) },
            Wire::Close(Ok(()))
        ])
    );
    result.expect_err("unconfirmed write");
    assert_eq!(session.effects.mutation_status(), crate::commissioning::MutationStatus::PartiallyApplied);
    assert!(session.effects.credential_transitions().is_empty());
}

#[test]
fn runtime_write_policy_obeys_verification_intent_and_ordered_overrides() {
    for feature in [false, true] {
        for override_mode in [None, Some(false), Some(true)] {
            for optimistic in [false, true] {
                let state = ToolState {
                    memory_auto_verify: override_mode,
                    optimistic_writes: optimistic,
                    ..Default::default()
                };
                let expected = if override_mode.unwrap_or(feature) {
                    WritePolicy::DeviceAutoVerify
                } else if optimistic {
                    WritePolicy::Optimistic
                } else {
                    WritePolicy::ReadBack
                };
                assert_eq!(WriteIntent::AbsoluteSegment.resolve(state, feature), expected);
                let relative = if override_mode.unwrap_or(feature) {
                    WritePolicy::DeviceAutoVerify
                } else {
                    WritePolicy::ReadBack
                };
                assert_eq!(WriteIntent::Relative { verify: true }.resolve(state, feature), relative);
                assert_eq!(
                    WriteIntent::Relative { verify: false }
                        .resolve(ToolState { verify_direct_writes: true, ..state }, feature),
                    WritePolicy::NoVerification
                );
            }
        }
    }
}

#[test]
fn preflight_includes_initial_mode_and_atomic_record_size() {
    let mut controls = procedure(vec![ProcedureOperation::Connect, ProcedureOperation::Disconnect]);
    controls.initial_state.memory_auto_verify = Some(false);
    assert_eq!(
        crate::commissioning::procedure::operands::required_plaintext_apdu(&controls, true).expect("sizing"),
        Some(6)
    );
    let record = LoadRecord {
        write: ServiceRead { target: memory(0x100), extent: OperationExtent::bytes(11) },
        bytes: vec![0; 11],
        poll: None,
        effect: LoadEffect::None,
    };
    assert_eq!(record.minimum_apdu().expect("atomic record"), 14);
}

#[tokio::test]
async fn undersized_apdu_rejects_load_record_before_any_fragment_is_sent() {
    let (bus, rx) = bus();
    let mut options = config(false);
    options.target_max_apdu = 13;
    let mut session =
        ExecutionSession::new(&bus, address(), options, ManagementAccess::Plaintext).expect("valid session");
    session.begin_execution();
    session.images.known.apply_owned(location(0x100), vec![7]).expect("prior observation");
    let record = LoadRecord {
        write: ServiceRead { target: memory(0x100), extent: OperationExtent::bytes(11) },
        bytes: vec![0; 11],
        poll: None,
        effect: LoadEffect::InvalidateAll,
    };
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::LoadRecord(record),
        ProcedureOperation::Disconnect,
    ]);
    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![Wire::Open(false), Wire::Close(Ok(()))])
    );
    assert!(result.expect_err("record cannot fragment").message.contains("atomic load record"));
    assert!(!session.mutated());
    assert_eq!(session.images.known.byte(&location(0x100)), Some((7, 255)));
}

#[tokio::test]
async fn failed_descriptor_redeclaration_retains_previous_constraints() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid session");
    session.begin_execution();
    let address = PropertyAddress::Indexed { object_index: 3, property_id: 27 };
    let declaration = |maximum| ProcedureOperation::DeclarePropertyDescriptor {
        address,
        property_data_type: "PDT_UNSIGNED_CHAR".into(),
        maximum_elements: maximum,
        read_access: 3,
        write_access: 3,
        writable: true,
    };
    let controls =
        procedure(vec![ProcedureOperation::Connect, declaration(1), declaration(2), ProcedureOperation::Disconnect]);
    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![Wire::Open(false), Wire::Close(Ok(()))])
    );
    assert!(result.is_err());
    assert_eq!(
        session.property_descriptors.get(&address.into()).expect("first descriptor retained").maximum_elements,
        1
    );
}

#[tokio::test]
async fn pointer_is_read_again_after_each_allocation() {
    use crate::commissioning::procedure::operands::PointerEncoding;
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid session");
    session.begin_execution();
    let target = OperationTarget::Memory {
        service: MemoryService::Classic,
        address: MemoryAddress::Pointer {
            space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 3 } },
            read: Box::new(ServiceRead { target: property(1), extent: OperationExtent::property(2, 1) }),
            offset: 3,
            encoding: PointerEncoding::Absolute,
        },
    };
    let record = LoadRecord {
        write: ServiceRead { target: memory(0x100), extent: OperationExtent::bytes(1) },
        bytes: vec![1],
        poll: None,
        effect: LoadEffect::InvalidateAll,
    };
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::LoadRecord(record.clone()),
        write(target.clone(), OperationData::Inline(vec![7]), 1),
        ProcedureOperation::LoadRecord(record),
        write(target, OperationData::Inline(vec![8]), 1),
        ProcedureOperation::Disconnect,
    ]);
    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            mem_write(0x100, &[1]),
            prop_read(27, 1, 1, &[2, 0]),
            mem_write(0x203, &[7]),
            mem_write(0x100, &[1]),
            prop_read(27, 1, 1, &[3, 0]),
            mem_write(0x303, &[8]),
            Wire::Close(Ok(()))
        ])
    );
    result.expect("fresh pointer used after each allocation");
}
