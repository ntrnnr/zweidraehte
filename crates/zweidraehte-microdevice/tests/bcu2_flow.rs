//! End-to-end conversations against the BCU2 micro stack: the
//! MV-0020-shaped management dialogue and the group communication
//! paths, driven frame-by-frame the way the bus would.

mod common;
use common::{CLIENT, DUT, apdu, canonical, connect, exchange};

use zweidraehte_microdevice::SecureBcu2 as DataSecureBcu2;
use zweidraehte_microdevice::device::{DeviceIdentity, Microdevice, PollInput};
use zweidraehte_microdevice::families::bcu2::{Bcu2CoDescriptor, Bcu2DeviceDefinition, Bcu2Family};
use zweidraehte_microdevice::family::MicroDeviceFamily;
use zweidraehte_microdevice::frame::{
    ApciCode, EXTENDED_FRAME, FrameBuf, FrameView, MAX_FRAME, SECURE_EXTENDED_FRAME, Tpci, data_frame, normalize,
    to_wire,
};
use zweidraehte_microdevice::security::{DataSecureState, MicroSecurityResources, SecurityModule};
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::encoding::tp1::{NPCI_HOP_COUNT_6, TP1_STD_CTRL_BASE};
use zweidraehte_proto::messages::apdu::load_control::{AbsSegment, LoadControlRecord, LoadEvent, LoadState};
use zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode;
use zweidraehte_proto::security::{DEFAULT_SENDING, SecurityTable, SequenceNumberStorage, SiatAccess};

static COS: &[Bcu2CoDescriptor] = &[
    // ASAP 0: 1-bit switch input, write+update enabled.
    Bcu2CoDescriptor { data_ptr: 0xC6, config: 0x9F, value_type: 0x00 },
    // ASAP 1: 1-bit status output, transmit+read enabled.
    Bcu2CoDescriptor { data_ptr: 0xC7, config: 0x4F, value_type: 0x00 },
];

static GAS: &[GroupAddress] = &[GroupAddress::from_three_level(1, 0, 1), GroupAddress::from_three_level(1, 0, 2)];

fn definition() -> Bcu2DeviceDefinition {
    Bcu2DeviceDefinition {
        manufacturer_id: 0x0083,
        app_manufacturer_id: 0x0083,
        device_type: 0x1234,
        version: 1,
        pei_type: 0,
        individual_address: DUT,
        max_group_addresses: 4,
        max_associations: 4,
        ram_flags_ptr: 0xD0,
        comm_objects: COS,
        group_addresses: GAS,
        associations: &[(1, 0), (2, 1)],
        app_params: None,
    }
}

fn device() -> Microdevice<Bcu2Family> {
    let def = definition();
    let identity = DeviceIdentity { serial_number: [0, 0x83, 0, 0, 0, 1], order_info: [0; 10], hardware_type: [0; 6] };
    let mut dev = Microdevice::new(def.build_eeprom(), identity, 1);
    // Factory image with the application marked loaded, like a
    // programmed device fresh off the line.
    dev.mgmt.lsm[0].state = LoadState::Loaded;
    dev.mgmt.lsm[1].state = LoadState::Loaded;
    dev.mgmt.lsm[2].state = LoadState::Loaded;
    dev
}

#[test]
fn dd0_user_save_pointer_and_authorize() {
    let mut dev = device();
    connect(&mut dev);

    // DD0 → 0020h.
    let rsp = exchange(&mut dev, 0, ApciCode::DeviceDescriptorRead, 0, &[], 0).expect("DD0 answered");
    assert_eq!(apdu(&rsp), &[0x43, 0x40, 0x00, 0x20]);

    // The ETS mask procedure's 0115h compatibility probe → 48h.
    let rsp = exchange(&mut dev, 1, ApciCode::MemoryRead, 1, &[0x01, 0x15], 0).expect("memory answered");
    assert_eq!(apdu(&rsp), &[0x46, 0x41, 0x01, 0x15, 0x48]);

    // A_Authorize with the FF key → level 0 (factory keys).
    let rsp = exchange(&mut dev, 2, ApciCode::AuthorizeRequest, 0, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF], 0)
        .expect("authorize answered");
    assert_eq!(apdu(&rsp)[1], 0xD2, "A_Authorize_Response");
    assert_eq!(apdu(&rsp)[2], 0x00, "granted level 0");

    // Like System 7's level 15, BCU2's free level 3 owns no key.
    let rsp = exchange(&mut dev, 3, ApciCode::KeyWrite, 0, &[0x03, 1, 2, 3, 4], 0).expect("key response");
    assert_eq!(apdu(&rsp)[2], 0xFF);
}

#[test]
fn option_reg_reads_inverted() {
    let mut dev = device();
    connect(&mut dev);
    // Raw cell is 00h (factory erased); the bus sees FFh.
    let rsp = exchange(&mut dev, 0, ApciCode::MemoryRead, 1, &[0x01, 0x00], 0).expect("answered");
    assert_eq!(apdu(&rsp)[4], 0xFF);
}

#[test]
fn lsm_cycle_via_property_path() {
    let mut dev = device();
    connect(&mut dev);
    let mut seq = 0u8;
    let mut send_record = |dev: &mut Microdevice<Bcu2Family>, obj: u8, record: &[u8]| -> Vec<u8> {
        let mut payload = vec![obj, 5, 0x10, 0x01];
        payload.extend_from_slice(record);
        let rsp = exchange(dev, seq, ApciCode::PropertyValueWrite, 0, &payload, 0).expect("property write answered");
        seq = (seq + 1) & 0x0F;
        rsp
    };

    // Unload machines 1..=3, then run machine 3 through a load cycle
    // with the record set the MV-0020 template sends.
    for obj in 1..=3u8 {
        let rsp = send_record(&mut dev, obj, &LoadControlRecord::event(LoadEvent::Unload));
        assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Unloaded), "unloaded readback");
    }
    let rsp = send_record(&mut dev, 3, &LoadControlRecord::event(LoadEvent::StartLoading));
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Loading));
    let seg = AbsSegment::eeprom(0x011E, 0x0080);
    let rsp = send_record(&mut dev, 3, &LoadControlRecord::abs_segment(&seg));
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Loading));
    let rsp = send_record(&mut dev, 3, &LoadControlRecord::task_segment(0x011E, 0, [0, 0x83, 0x12, 0x34, 1]));
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Loading));
    let rsp = send_record(&mut dev, 3, &LoadControlRecord::task_ptr(284, 285, 0));
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Loading));
    let rsp = send_record(&mut dev, 3, &LoadControlRecord::task_ctrl1(0, 0));
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Loading));
    let rsp = send_record(&mut dev, 3, &LoadControlRecord::task_ctrl2(0x5081, 282, 208, 208));
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Loading));
    let rsp = send_record(&mut dev, 3, &LoadControlRecord::event(LoadEvent::LoadCompleted));
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Loaded));

    // PID_TABLE_REFERENCE reads back the allocated segment address.
    let rsp = exchange(&mut dev, seq, ApciCode::PropertyValueRead, 0, &[3, 7, 0x10, 0x01], 0).expect("answered");
    assert_eq!(&apdu(&rsp)[6..10], &[0x00, 0x00, 0x01, 0x1E]);
}

#[test]
fn verify_mode_echoes_memory_writes() {
    let mut dev = device();
    connect(&mut dev);
    // Enable verify mode: PID_DEVICE_CONTROL bit 2.
    let rsp = exchange(&mut dev, 0, ApciCode::PropertyValueWrite, 0, &[0, 14, 0x10, 0x01, 0x04], 0).expect("answered");
    assert_eq!(apdu(&rsp)[6], 0x04, "device control readback");

    // A verified write answers with the bytes as stored.
    let rsp = exchange(&mut dev, 1, ApciCode::MemoryWrite, 2, &[0x01, 0x0D, 0x00, 0x00], 0);
    let rsp = rsp.expect("verify mode answers the write");
    assert_eq!(apdu(&rsp), &[0x46, 0x42, 0x01, 0x0D, 0x00, 0x00]);
    assert!(!dev.is_running(), "RunError 00h halts the application");

    // Clearing RunError back to FFh revives it.
    exchange(&mut dev, 2, ApciCode::MemoryWrite, 1, &[0x01, 0x0D, 0xFF], 0).expect("echoed");
    assert!(dev.is_running());
}

#[test]
fn restart_is_signalled_after_the_ack() {
    let mut dev = device();
    connect(&mut dev);
    let request =
        data_frame::<MAX_FRAME>(0x00, CLIENT, DUT.0, false, Tpci::DataConnected(0), ApciCode::Restart, 0, &[]);
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&request)), 0);
    assert!(out.restart.is_some(), "A_Restart must surface to the embedder");
    let ack_frame = canonical(&out.frames[0]);
    let ack = FrameView::parse(&ack_frame).expect("parsable");
    assert_eq!(ack.tpci(), Some(Tpci::Ack(0)));
}

#[test]
fn individual_address_write_needs_programming_mode() {
    let mut dev = device();
    let new_ia = IndividualAddress::new(2, 3, 4);
    let write = data_frame::<MAX_FRAME>(
        0x00,
        CLIENT,
        [0, 0],
        true,
        Tpci::DataGroup,
        ApciCode::IndividualAddressWrite,
        0,
        new_ia.as_bytes(),
    );
    dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&write)), 0);
    assert_eq!(dev.individual_address(), DUT, "ignored outside programming mode");

    dev.set_programming_mode(true);
    dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&write)), 0);
    assert_eq!(dev.individual_address(), new_ia);

    // And the read answers with a broadcast response.
    let read =
        data_frame::<MAX_FRAME>(0x00, CLIENT, [0, 0], true, Tpci::DataGroup, ApciCode::IndividualAddressRead, 0, &[]);
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&read)), 0);
    let rsp_frame = canonical(&out.frames[0]);
    let rsp = FrameView::parse(&rsp_frame).expect("parsable");
    assert!(rsp.is_group);
    assert_eq!(rsp.source, new_ia);
    assert_eq!(rsp.apci(), Some(ApciCode::IndividualAddressResponse.wire10_base()));
}

#[test]
fn serial_number_address_write_is_verified_by_read() {
    let mut dev = device();
    let serial = [0, 0x83, 0, 0, 0, 1];
    let new_ia = IndividualAddress::new(15, 15, 255);

    // ETS includes the four reserved octets after the serial and IA. A
    // shortened test telegram would miss the actual Falcon wire shape.
    let mut write_payload = serial.to_vec();
    write_payload.extend_from_slice(new_ia.as_bytes());
    write_payload.extend_from_slice(&[0; 4]);
    let write = data_frame::<MAX_FRAME>(
        0,
        CLIENT,
        [0, 0],
        true,
        Tpci::DataBroadcast,
        ApciCode::IndividualAddressSerialNumberWrite,
        0,
        &write_payload,
    );
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&write)), 0);
    assert!(out.frames.is_empty(), "the write has no application response");
    assert_eq!(dev.individual_address(), new_ia);

    let read = data_frame::<MAX_FRAME>(
        0,
        CLIENT,
        [0, 0],
        true,
        Tpci::DataBroadcast,
        ApciCode::IndividualAddressSerialNumberRead,
        0,
        &serial,
    );
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&read)), 1);
    let response = canonical(&out.frames[0]);
    let response = FrameView::parse(&response).expect("serial response");
    assert_eq!(response.source, new_ia);
    assert_eq!(response.dest_raw, [0, 0]);
    assert_eq!(response.apci(), Some(ApciCode::IndividualAddressSerialNumberResponse.wire10_base()));
    assert_eq!(&response.payload()[..6], &serial);
    assert_eq!(&response.payload()[6..], &[0; 4]);
}

#[test]
fn group_write_updates_the_object_and_read_answers() {
    let mut dev = device();

    // A bus write to 1/0/1 lands in ASAP 0's RAM slot.
    let write = data_frame::<MAX_FRAME>(
        0x0C,
        CLIENT,
        GroupAddress::from_three_level(1, 0, 1).0,
        true,
        Tpci::DataGroup,
        ApciCode::GroupValueWrite,
        1,
        &[],
    );
    dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&write)), 0);
    let mut value = [0u8; 1];
    assert_eq!(dev.read_value(0, &mut value), 1);
    assert_eq!(value[0], 1);
    assert!(dev.object_flags(0) & zweidraehte_microdevice::co_flags::UPDATE != 0);

    // A read of 1/0/2 answers with ASAP 1's value.
    dev.write_value(1, &[1]);
    let read = data_frame::<MAX_FRAME>(
        0x0C,
        CLIENT,
        GroupAddress::from_three_level(1, 0, 2).0,
        true,
        Tpci::DataGroup,
        ApciCode::GroupValueRead,
        0,
        &[],
    );
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&read)), 0);
    let rsp_frame = canonical(&out.frames[0]);
    let rsp = FrameView::parse(&rsp_frame).expect("parsable");
    assert!(rsp.is_group);
    assert_eq!(rsp.dest_group(), GroupAddress::from_three_level(1, 0, 2));
    assert_eq!(rsp.apci(), Some(ApciCode::GroupValueResponse.wire10_base() | 0x01));

    // A transmit request on ASAP 1 produces a group write on the next
    // timer tick.
    dev.set_transmit_request(1);
    let out = dev.poll(PollInput::Timer, 10);
    let tx_frame = canonical(&out.frames[0]);
    let tx = FrameView::parse(&tx_frame).expect("parsable");
    assert_eq!(tx.apci(), Some(ApciCode::GroupValueWrite.wire10_base() | 0x01));
    assert_eq!(tx.dest_group(), GroupAddress::from_three_level(1, 0, 2));
}

#[test]
fn halted_device_ignores_group_traffic() {
    let mut dev = device();
    dev.eeprom_image(); // silence unused-api lints in this test file
    // Halt via RunError.
    connect(&mut dev);
    exchange(&mut dev, 0, ApciCode::MemoryWrite, 1, &[0x01, 0x0D, 0x00], 0);
    let read = data_frame::<MAX_FRAME>(
        0x0C,
        CLIENT,
        GroupAddress::from_three_level(1, 0, 2).0,
        true,
        Tpci::DataGroup,
        ApciCode::GroupValueRead,
        0,
        &[],
    );
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&read)), 0);
    assert!(out.frames.is_empty(), "halted devices answer no group reads");
}

#[test]
#[cfg(feature = "std")]
fn snapshot_round_trip_preserves_persistent_state() {
    use zweidraehte_microdevice::snapshot::MicroSnapshot;
    let mut dev = device();
    connect(&mut dev);
    exchange(&mut dev, 0, ApciCode::MemoryWrite, 1, &[0x01, 0x1B, 0x42], 0);
    let snap = MicroSnapshot::capture(&dev);
    let bytes = postcard::to_allocvec(&snap).expect("serializes");
    let back: MicroSnapshot = postcard::from_bytes(&bytes).expect("deserializes");
    let identity = DeviceIdentity { serial_number: [0; 6], order_info: [0; 10], hardware_type: [0; 6] };
    let restored: Microdevice<Bcu2Family> = back.restore(identity, 1);
    assert_eq!(restored.eeprom_image()[0x1B], 0x42);
    assert_eq!(restored.mgmt.lsm[2].state, LoadState::Loaded);
    assert!(!restored.is_programming_mode(), "RAM state does not survive");
}

// ============================================================================
// The profile-module seam
// ============================================================================
//
// The bench MV-0021 reaches its Security Interface Object as
// `ObjectType=17 Instance=1` while its indexed roster stays at the four
// classic objects — 147 type-addressed exchanges across the two traces, and
// `ObjectIndex=` never above 3. That combination is the thing to pin: an
// object in the type/occurrence address space that acquires no index.
//
// The module here is a stand-in for the Security Interface Object, which
// arrives with its real property roster next. What it proves is the routing.

/// Object Type 17: the Security Interface Object.
const SECURITY_IO: u16 = 0x0011;

#[derive(Default)]
struct StubSecurityState {
    mode: u8,
}

struct StubSecurity;

impl SecurityModule for StubSecurity {
    type State = StubSecurityState;
    type ReplyContext = ();
    const ENABLED: bool = true;
    const OBJECT_TYPE: Option<u16> = Some(SECURITY_IO);

    fn plain_reply_context() {}

    fn property_descriptor(prop_id: u16) -> Option<(u16, zweidraehte_proto::properties::PropertyDescriptor)> {
        (prop_id == 51).then(|| {
            (
                0,
                zweidraehte_proto::properties::PropertyDescriptor::new(
                    51,
                    2,
                    1,
                    zweidraehte_proto::properties::PropertyAccess::ReadWrite,
                    3,
                    3,
                    zweidraehte_proto::access::AccessPolicy::OPEN,
                ),
            )
        })
    }

    fn property_descriptor_at(index: u16) -> Option<zweidraehte_proto::properties::PropertyDescriptor> {
        (index == 0).then(|| Self::property_descriptor(51).expect("PID 51 exists").1)
    }

    fn property_read<const N: usize>(
        state: &Self::State,
        prop_id: u16,
        count: u8,
        start: u16,
    ) -> Option<heapless::Vec<u8, N>> {
        let mut v = heapless::Vec::new();
        if start == 0 {
            // Element-count probe.
            let _ = v.extend_from_slice(&1u16.to_be_bytes());
            return (count != 0).then_some(v);
        }
        // PID_SECURITY_MODE (51).
        (prop_id == 51).then(|| {
            let _ = v.push(state.mode);
            v
        })
    }

    fn property_write(
        state: &mut Self::State,
        prop_id: u16,
        _count: u8,
        _start: u16,
        data: &[u8],
    ) -> PropertyReturnCode {
        if prop_id != 51 || data.is_empty() {
            return PropertyReturnCode::DataTypeConflict;
        }
        state.mode = data[0];
        PropertyReturnCode::Success
    }
}

type SecureBcu2 = Microdevice<Bcu2Family<0x0021>, EXTENDED_FRAME, StubSecurity>;

fn stub_identity() -> DeviceIdentity {
    DeviceIdentity { serial_number: [0, 0x83, 0, 0, 0, 1], order_info: [0; 10], hardware_type: [0; 6] }
}

fn secure_device() -> SecureBcu2 {
    let mut dev: SecureBcu2 = Microdevice::new(definition().build_eeprom_for_mask(0x0021), stub_identity(), 1);
    for machine in 0..3 {
        dev.mgmt.lsm[machine].state = LoadState::Loaded;
    }
    dev
}

fn ext_payload(object_type: u16, instance: u16, pid: u16, count: u8, start: u16, data: &[u8]) -> Vec<u8> {
    let ot = object_type.to_be_bytes();
    let mut p = vec![
        ot[0],
        ot[1],
        (instance >> 4) as u8,
        (((instance & 0x0F) << 4) | (pid >> 8)) as u8,
        pid as u8,
        count,
        (start >> 8) as u8,
        start as u8,
    ];
    p.extend_from_slice(data);
    p
}

fn function_ext_payload(object_type: u16, instance: u16, pid: u16, data: &[u8]) -> Vec<u8> {
    let ot = object_type.to_be_bytes();
    let mut p = vec![ot[0], ot[1], (instance >> 4) as u8, (((instance & 0x0F) << 4) | (pid >> 8)) as u8, pid as u8];
    p.extend_from_slice(data);
    p
}

/// Most BCU2 management exchanges remain connection-oriented. Property
/// procedures may also be connectionless, and the secure composition adds
/// the DD0 bootstrap observed in ETS; these helpers exercise the numbered
/// path independently.
fn tl_connect(dev: &mut SecureBcu2) {
    let connect =
        [TP1_STD_CTRL_BASE, CLIENT.0[0], CLIENT.0[1], DUT.0[0], DUT.0[1], NPCI_HOP_COUNT_6, Tpci::Connect.octet()];
    assert!(dev.poll(PollInput::Frame(&connect), 0).frames.is_empty(), "connect is accepted silently");
}

fn ext_exchange(dev: &mut SecureBcu2, apci: ApciCode, payload: &[u8], seq: u8, now: u32) -> Vec<u8> {
    let req = data_frame::<EXTENDED_FRAME>(0x00, CLIENT, DUT.0, false, Tpci::DataConnected(seq), apci, 0, payload);
    let out = dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&req)), now);
    assert_eq!(out.frames.len(), 2, "expected a T_ACK and one reply");

    let c = normalize::<EXTENDED_FRAME>(&out.frames[1]).expect("well-formed");
    let view = FrameView::parse(&c).expect("parsable");
    let Some(Tpci::DataConnected(rsp_seq)) = view.tpci() else {
        panic!("a numbered response was expected, got {:?}", view.tpci());
    };
    let reply = view.payload().to_vec();

    // Acknowledge it. The device sits in OPEN_WAIT until we do, and will not
    // send further data — a client that skips this sees the next request
    // acknowledged and unanswered, which is the transport layer working, not
    // the service failing.
    let ack =
        [TP1_STD_CTRL_BASE, CLIENT.0[0], CLIENT.0[1], DUT.0[0], DUT.0[1], NPCI_HOP_COUNT_6, Tpci::Ack(rsp_seq).octet()];
    assert!(dev.poll(PollInput::Frame(&ack), now + 1).frames.is_empty(), "a T_ACK draws no further frames");
    reply
}

#[test]
fn the_module_object_answers_by_type_without_taking_an_index() {
    let mut dev = secure_device();
    tl_connect(&mut dev);

    // It answers by type at occurrence 1 …
    let reply =
        ext_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 51, 1, 1, &[]), 0, 10);
    assert_eq!(reply[5], 1, "one element");
    assert_eq!(reply[8], 0x00, "PID_SECURITY_MODE reads back");

    // … and nowhere in the indexed roster. Every index the mask publishes
    // must still be one of the four classic objects.
    assert_eq!(Bcu2Family::<0x0021>::OBJECT_COUNT, 4, "the indexed roster does not grow");
    for idx in 0..Bcu2Family::<0x0021>::OBJECT_COUNT {
        assert_ne!(Bcu2Family::<0x0021>::object_type(idx), SECURITY_IO, "index {idx} must not be the Security IO");
    }
}

#[test]
fn the_module_object_has_exactly_one_occurrence() {
    let mut dev = secure_device();
    tl_connect(&mut dev);
    for (seq, instance) in [(0u8, 0u16), (1, 2)] {
        let reply = ext_exchange(
            &mut dev,
            ApciCode::PropertyExtValueRead,
            &ext_payload(SECURITY_IO, instance, 51, 1, 1, &[]),
            seq,
            10 + u32::from(seq),
        );
        assert_eq!(reply[8], 0xFD, "occurrence {instance} is not the module's");
    }
}

#[test]
fn a_write_reaches_the_modules_state() {
    let mut dev = secure_device();
    tl_connect(&mut dev);
    let reply = ext_exchange(
        &mut dev,
        ApciCode::PropertyExtValueWriteCon,
        &ext_payload(SECURITY_IO, 1, 51, 1, 1, &[0x01]),
        0,
        10,
    );
    assert_eq!(reply[8], 0x00, "E_SUCCESS");

    let reply =
        ext_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 51, 1, 1, &[]), 1, 20);
    assert_eq!(reply[8], 0x01, "the write landed in the module's state");
}

/// Without a module there is no second address space at all, which is what
/// keeps a plain BCU2 exactly as it was.
#[test]
fn without_a_module_the_type_address_space_is_empty() {
    let mut dev: Microdevice<Bcu2Family<0x0021>, EXTENDED_FRAME> =
        Microdevice::new(definition().build_eeprom_for_mask(0x0021), stub_identity(), 1);
    for machine in 0..3 {
        dev.mgmt.lsm[machine].state = LoadState::Loaded;
    }
    let connect =
        [TP1_STD_CTRL_BASE, CLIENT.0[0], CLIENT.0[1], DUT.0[0], DUT.0[1], NPCI_HOP_COUNT_6, Tpci::Connect.octet()];
    assert!(dev.poll(PollInput::Frame(&connect), 0).frames.is_empty());

    let req = data_frame::<EXTENDED_FRAME>(
        0x00,
        CLIENT,
        DUT.0,
        false,
        Tpci::DataConnected(0),
        ApciCode::PropertyExtValueRead,
        0,
        &ext_payload(SECURITY_IO, 1, 51, 1, 1, &[]),
    );
    let out = dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&req)), 10);
    let c = normalize::<EXTENDED_FRAME>(&out.frames[1]).expect("well-formed");
    let view = FrameView::parse(&c).expect("parsable");
    assert_eq!(view.payload()[8], 0xFD, "E_ADDRESS_VOID");
}

// ============================================================================
// The Security Interface Object
// ============================================================================
//
// The real module now, over `zweidraehte_proto::security::SecurityState` —
// the same state type the full stack runs on. Capacities match the bench
// MV-0021's product file where they matter: it declares 64 group-key entries
// and no P2P capacity at all.

/// A RAM-backed sequence store, deliberately test-only.
///
/// Real firmware needs a wear-resistant medium — the counter moves on every
/// secure frame — so shipping something that looks like a store but forgets
/// on power loss would invite exactly the mistake `MICRO_SECURE_PLAN.md`
/// lists as its first risk.
#[derive(Default, Clone)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
struct RamSeqStore {
    sending: Option<[u8; 6]>,
    tool: Option<[u8; 6]>,
    siat: Vec<(u16, [u8; 6])>,
    fail_tool_save: bool,
    fail_sending_load: bool,
    fail_sending_save: bool,
    fail_siat_clear: bool,
}

impl SequenceNumberStorage for RamSeqStore {
    type Error = ();

    fn load_sending_seq(&self) -> Result<[u8; 6], ()> {
        if self.fail_sending_load {
            return Err(());
        }
        Ok(self.sending.unwrap_or(DEFAULT_SENDING))
    }
    fn save_sending_seq(&mut self, seq: &[u8; 6]) -> Result<(), ()> {
        if self.fail_sending_save {
            return Err(());
        }
        self.sending = Some(*seq);
        Ok(())
    }
    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, ()> {
        Ok(self.siat.iter().find(|(ia, _)| *ia == peer_ia).map(|(_, s)| *s))
    }
    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), ()> {
        if let Some(entry) = self.siat.iter_mut().find(|(ia, _)| *ia == peer_ia) {
            entry.1 = *seq;
        }
        Ok(())
    }
    fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, ()> {
        Ok(self.tool)
    }
    fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), ()> {
        if self.fail_tool_save {
            return Err(());
        }
        self.tool = Some(*seq);
        Ok(())
    }
}

impl SiatAccess for RamSeqStore {
    type Error = ();

    fn siat_count(&self) -> u16 {
        self.siat.len() as u16
    }
    fn siat_index_of(&self, ia: u16) -> Option<u16> {
        self.siat.iter().position(|(a, _)| *a == ia).map(|i| i as u16 + 1)
    }
    fn siat_read_entry(&self, idx: u16) -> Option<(u16, [u8; 6])> {
        self.siat.get(idx as usize).copied()
    }
    fn siat_write_entry(&mut self, idx: u16, ia: u16, seq: [u8; 6]) -> Result<(), ()> {
        if self.siat.len() <= idx as usize {
            self.siat.resize(idx as usize + 1, (0, [0; 6]));
        }
        self.siat[idx as usize] = (ia, seq);
        Ok(())
    }
    fn siat_set_count(&mut self, count: u16) -> Result<(), ()> {
        self.siat.resize(count as usize, (0, [0; 6]));
        Ok(())
    }
    fn siat_clear(&mut self) -> Result<(), ()> {
        if self.fail_siat_clear {
            return Err(());
        }
        self.siat.clear();
        Ok(())
    }
}

impl MicroSecurityResources for RamSeqStore {
    fn fill_random(&mut self, random: &mut [u8; 6]) {
        *random = [0xA5; 6];
    }
}

const FDSK: [u8; 16] = [0x11; 16];

type SecureDev = DataSecureBcu2<RamSeqStore, 8, 4>;

fn data_secure_device() -> SecureDev {
    let mut dev: SecureDev = Microdevice::with_security(
        definition().build_eeprom_for_mask(0x0021),
        stub_identity(),
        1,
        DataSecureState::new(FDSK, RamSeqStore::default()),
    );
    for machine in 0..3 {
        dev.mgmt.lsm[machine].state = LoadState::Loaded;
    }
    dev
}

fn plain_connectionless(
    dev: &mut SecureDev,
    apci: ApciCode,
    small6: u8,
    payload: &[u8],
    now: u32,
) -> FrameBuf<EXTENDED_FRAME> {
    let request = data_frame::<EXTENDED_FRAME>(0x00, CLIENT, DUT.0, false, Tpci::DataIndividual, apci, small6, payload);
    let output = dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&request)), now);
    assert_eq!(output.frames.len(), 1, "connectionless request gets one reply");
    normalize::<EXTENDED_FRAME>(&output.frames[0]).expect("well-formed connectionless reply")
}

fn sec_exchange(dev: &mut SecureDev, apci: ApciCode, payload: &[u8], seq: u8, now: u32) -> Vec<u8> {
    let request_key = dev.security_state().security.tool_key();
    let security_seq = zweidraehte_proto::security::u64_to_seq6(u64::from(now.max(1)));
    let req = secure_tool_frame(apci, 0, payload, &request_key, &security_seq, seq);
    let out = dev.poll(PollInput::Frame(&req), now);
    assert_eq!(out.frames.len(), 2, "expected a T_ACK and one reply");
    // A Tool Key write takes effect before its confirmation is wrapped, so
    // resolve the key again after dispatch rather than caching the request's.
    let response_key = dev.security_state().security.tool_key();
    let c = unwrap_secure_response(&out.frames[1], &response_key);
    let view = FrameView::parse(&c).expect("parsable plaintext response");
    let Some(Tpci::DataConnected(rsp_seq)) = view.tpci() else { panic!("numbered response expected") };
    let reply = view.payload().to_vec();
    let ack =
        [TP1_STD_CTRL_BASE, CLIENT.0[0], CLIENT.0[1], DUT.0[0], DUT.0[1], NPCI_HOP_COUNT_6, Tpci::Ack(rsp_seq).octet()];
    assert!(dev.poll(PollInput::Frame(&ack), now + 1).frames.is_empty());
    reply
}

fn plain_sec_exchange(dev: &mut SecureDev, apci: ApciCode, payload: &[u8], seq: u8, now: u32) -> Vec<u8> {
    let req = data_frame::<EXTENDED_FRAME>(0x00, CLIENT, DUT.0, false, Tpci::DataConnected(seq), apci, 0, payload);
    let out = dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&req)), now);
    assert_eq!(out.frames.len(), 2, "expected a T_ACK and one plain reply");
    let canonical = normalize::<EXTENDED_FRAME>(&out.frames[1]).expect("well-formed");
    let view = FrameView::parse(&canonical).expect("parsable response");
    let Some(Tpci::DataConnected(rsp_seq)) = view.tpci() else { panic!("numbered response expected") };
    let reply = view.payload().to_vec();
    let ack =
        [TP1_STD_CTRL_BASE, CLIENT.0[0], CLIENT.0[1], DUT.0[0], DUT.0[1], NPCI_HOP_COUNT_6, Tpci::Ack(rsp_seq).octet()];
    assert!(dev.poll(PollInput::Frame(&ack), now + 1).frames.is_empty());
    reply
}

#[test]
fn mv0021_bootstrap_selects_plain_or_secure_management() {
    const {
        assert!(Bcu2Family::<0x0020>::CONNECTIONLESS_PROPERTIES);
        assert!(Bcu2Family::<0x0021>::CONNECTIONLESS_PROPERTIES);
        assert!(!Bcu2Family::<0x0020>::CONNECTIONLESS_DEVICE_DESCRIPTOR);
        assert!(!Bcu2Family::<0x0021>::CONNECTIONLESS_DEVICE_DESCRIPTOR);
    }

    let mut dev = data_secure_device();

    // The secure composition implements the optional connectionless DD0
    // extension ETS uses. PID 56 is a normal Property procedure and is
    // connectionless-capable on every BCU2 mask.
    let reply = plain_connectionless(&mut dev, ApciCode::DeviceDescriptorRead, 0, &[], 1);
    let view = FrameView::parse(&reply).expect("DD0 response parses");
    assert_eq!(view.tpci(), Some(Tpci::DataIndividual));
    assert_eq!(view.payload(), &[0x00, 0x21]);

    let reply = plain_connectionless(&mut dev, ApciCode::PropertyValueRead, 0, &[0, 56, 0x10, 0x01], 2);
    let view = FrameView::parse(&reply).expect("PID_MAX_APDULENGTH response parses");
    assert_eq!(view.payload(), &[0, 56, 0x10, 0x01, 0x00, 0x28]);

    let memory =
        data_frame::<EXTENDED_FRAME>(0x00, CLIENT, DUT.0, false, Tpci::DataIndividual, ApciCode::MemoryRead, 1, &[
            0x01, 0x15,
        ]);
    assert!(
        dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&memory)), 3).frames.is_empty(),
        "classic direct memory access is connection-oriented"
    );

    // Once Security Mode is on, FFFFh tells ETS to synchronize and retry
    // under the Tool Key. The APDU-length bootstrap remains public.
    dev.security_state().security.set_security_mode_enabled(true);
    let reply = plain_connectionless(&mut dev, ApciCode::DeviceDescriptorRead, 0, &[], 4);
    assert_eq!(FrameView::parse(&reply).expect("masked DD0 parses").payload(), &[0xFF, 0xFF]);

    let reply = plain_connectionless(&mut dev, ApciCode::PropertyValueRead, 0, &[0, 56, 0x10, 0x01], 5);
    assert_eq!(FrameView::parse(&reply).expect("public PID_MAX_APDULENGTH parses").payload(), &[
        0, 56, 0x10, 0x01, 0x00, 0x28
    ]);

    let output = dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&memory)), 6);
    assert!(output.frames.is_empty(), "connectionless classic memory remains unavailable");

    // 03/04/01 §6.2.6.3.5 assigns DD0 access policy 3FF/0CC: while
    // Security Mode is on, authentication without confidentiality is denied
    // just like plain access and therefore also returns FFFFh (TSSJ 3.7.2.6).
    let request = secure_connectionless_tool_frame_with_confidentiality(
        ApciCode::DeviceDescriptorRead,
        0,
        &[],
        &FDSK,
        &[0, 0, 0, 0, 0, 7],
        false,
    );
    let output = dev.poll(PollInput::Frame(&request), 7);
    assert_eq!(output.frames.len(), 1, "auth-only connectionless DD0 gets one response");
    let response = unwrap_secure_response(&output.frames[0], &FDSK);
    assert_eq!(FrameView::parse(&response).expect("auth-only DD0 response parses").payload(), &[0xFF, 0xFF]);

    let request = secure_connectionless_tool_frame(ApciCode::DeviceDescriptorRead, 0, &[], &FDSK, &[0, 0, 0, 0, 0, 8]);
    let output = dev.poll(PollInput::Frame(&request), 8);
    assert_eq!(output.frames.len(), 1, "secure connectionless DD0 gets one response");
    let response = unwrap_secure_response(&output.frames[0], &FDSK);
    let view = FrameView::parse(&response).expect("secure DD0 response parses");
    assert_eq!(view.tpci(), Some(Tpci::DataIndividual));
    assert_eq!(view.payload(), &[0x00, 0x21], "secure management sees the real mask");
}

fn sec_connect(dev: &mut SecureDev) {
    let connect =
        [TP1_STD_CTRL_BASE, CLIENT.0[0], CLIENT.0[1], DUT.0[0], DUT.0[1], NPCI_HOP_COUNT_6, Tpci::Connect.octet()];
    assert!(dev.poll(PollInput::Frame(&connect), 0).frames.is_empty());
}

fn secure_restart(
    dev: &mut SecureDev,
    small6: u8,
    erase_code: u8,
    now: u32,
) -> zweidraehte_microdevice::PollOutput<SECURE_EXTENDED_FRAME> {
    let key = dev.security_state().security.tool_key();
    let seq_nr = zweidraehte_proto::security::u64_to_seq6(u64::from(now.max(1)));
    let payload = (small6 != 0).then_some([erase_code, 0]);
    let request = secure_tool_frame(
        ApciCode::Restart,
        small6,
        payload.as_ref().map_or(&[], |value| value.as_slice()),
        &key,
        &seq_nr,
        0,
    );
    dev.poll(PollInput::Frame(&request), now)
}

#[test]
fn secure_basic_restart_signals_without_a_response() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let out = secure_restart(&mut dev, 0, 0, 10);

    assert_eq!(out.restart, Some(0));
    assert_eq!(out.frames.len(), 1, "only the transport acknowledgement is sent");
}

#[test]
fn secure_confirmed_restart_answers_and_restarts() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let out = secure_restart(&mut dev, 1, 0x01, 10);

    assert_eq!(out.restart, Some(0x01));
    assert_eq!(out.frames.len(), 2, "transport acknowledgement and restart response");
    let response = unwrap_secure_response(&out.frames[1], &FDSK);
    assert_eq!(FrameView::parse(&response).expect("restart response parses").payload(), &[0, 0, 0]);
}

#[test]
fn secure_factory_reset_wipes_state_and_reverts_to_the_fdsk() {
    let mut dev = data_secure_device();
    dev.security_state().security.set_tool_key([0x5A; 16]);
    sec_connect(&mut dev);

    let out = secure_restart(&mut dev, 1, 0x02, 10);

    assert_eq!(out.restart, Some(0x02));
    assert_eq!(dev.security_state().security.tool_key(), FDSK);
    for machine in 0..3 {
        assert_eq!(dev.mgmt.lsm[machine].state, LoadState::Unloaded);
    }
    let ia_offset = Bcu2Family::<0x0021>::ia_eeprom_offset();
    assert_eq!(&dev.eeprom()[ia_offset..ia_offset + 2], &[0xFF, 0xFF]);
    let response = unwrap_secure_response(&out.frames[1], &[0x5A; 16]);
    assert_eq!(FrameView::parse(&response).expect("restart response parses").payload(), &[0, 0, 0]);
}

#[test]
fn secure_factory_reset_keep_ia_preserves_the_address() {
    let mut dev = data_secure_device();
    let ia_offset = Bcu2Family::<0x0021>::ia_eeprom_offset();
    let before = [dev.eeprom()[ia_offset], dev.eeprom()[ia_offset + 1]];
    sec_connect(&mut dev);

    let out = secure_restart(&mut dev, 1, 0x07, 10);

    assert_eq!(out.restart, Some(0x07));
    assert_eq!(&dev.eeprom()[ia_offset..ia_offset + 2], &before);
}

#[test]
fn secure_profile_refuses_the_excluded_erase_codes() {
    for code in [0x03, 0x04] {
        let mut dev = data_secure_device();
        sec_connect(&mut dev);

        let out = secure_restart(&mut dev, 1, code, 10);

        assert!(out.restart.is_none(), "erase code {code:#04X} must not restart");
        let response = unwrap_secure_response(&out.frames[1], &FDSK);
        assert_eq!(
            FrameView::parse(&response).expect("restart response parses").payload()[0],
            0x02,
            "E_UNSUPPORTED_ERASE_CODE"
        );
    }
}

#[test]
fn the_security_object_identifies_itself() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);
    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 1, 1, 1, &[]), 0, 10);
    assert_eq!(&reply[8..], &[0x00, 0x11], "PID_OBJECT_TYPE reads 0011h");
}

/// PID_TOOL_KEY is write-only: 06 Profiles §9.1.2.6.4 gives it access
/// `008/008` and levels `X/2` — there is no read level at all. Answering a
/// read with the key would hand it to anyone who asks.
#[test]
fn the_tool_key_is_write_only() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let key = [0x5A; 16];
    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueWriteCon, &ext_payload(SECURITY_IO, 1, 56, 1, 1, &key), 0, 10);
    assert_eq!(reply[8], 0x00, "E_SUCCESS");

    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 56, 1, 1, &[]), 1, 20);
    assert_eq!(reply[5], 0, "count zero");
    assert_eq!(reply[8], 0xFC, "the existing property refuses read access");
}

/// The group key table is an array property: element 0 is the count probe,
/// elements are one-based, and each row is `GA_Index(2) + Key(16)`.
#[test]
fn the_group_key_table_addresses_by_element() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    // Empty to begin with.
    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 53, 1, 0, &[]), 0, 10);
    assert_eq!(&reply[8..], &[0x00, 0x00], "no entries yet");

    // Write one row, then read it back by element.
    let mut row = vec![0x00, 0x07];
    row.extend_from_slice(&[0xC0; 16]);
    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueWriteCon, &ext_payload(SECURITY_IO, 1, 53, 1, 1, &row), 1, 20);
    assert_eq!(reply[8], 0x00, "E_SUCCESS");

    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 53, 1, 0, &[]), 2, 30);
    assert_eq!(&reply[8..], &[0x00, 0x01], "one entry now");

    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 53, 1, 1, &[]), 3, 40);
    assert_eq!(&reply[8..], &row[..], "the row reads back verbatim");
}

/// PID 52 (P2P keys) and PID 62 (roles) are `Cc` in §9.1.2.6.4 — mandatory
/// only when non-tool point-to-point is supported. This device is
/// tool-access-only, so they are absent rather than present-and-empty, and
/// the bench MV-0021 exposes neither.
#[test]
fn the_point_to_point_properties_do_not_exist() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);
    for (seq, pid) in [(0u8, 52u16), (1, 62)] {
        let reply = sec_exchange(
            &mut dev,
            ApciCode::PropertyExtValueRead,
            &ext_payload(SECURITY_IO, 1, pid, 1, 1, &[]),
            seq,
            10 + u32::from(seq) * 10,
        );
        assert_eq!(reply[8], 0xFD, "PID {pid} is not implemented");
    }
}

/// `Loaded` is not reachable in one step. PID 5 takes load *events*, and the
/// RT1 transition table is what stands between a client and an armed-but-empty
/// Security IO: the tables are evaluated only in `Loaded` (03/05/01
/// §6.3.6-8), so a single write that lands there would be a way to arm them.
#[test]
fn loaded_is_not_reachable_in_one_write() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    // One running sequence number: the transport layer reads a repeat as a
    // retransmission and answers it with the acknowledgement alone.
    let mut seq = 0u8;
    let mut now = 10u32;
    let mut step = |dev: &mut SecureDev, apci, payload: &[u8]| {
        let reply = sec_exchange(dev, apci, payload, seq & 0x0F, now);
        seq = seq.wrapping_add(1);
        now += 10;
        reply
    };

    // Every single-octet write from Unloaded, including the one whose value
    // *names* the Loaded state.
    for byte in [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05] {
        step(&mut dev, ApciCode::PropertyExtValueWriteCon, &ext_payload(SECURITY_IO, 1, 5, 1, 1, &[byte]));
        let reply = step(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 5, 1, 1, &[]));
        assert_ne!(reply[8], u8::from(LoadState::Loaded), "byte {byte:#04X} must not reach Loaded from Unloaded");

        // Put it back to Unloaded for the next probe.
        step(
            &mut dev,
            ApciCode::PropertyExtValueWriteCon,
            &ext_payload(SECURITY_IO, 1, 5, 1, 1, &[LoadEvent::Unload.into()]),
        );
    }
}

/// The Security IO's load state machine. PID 5 is written with load
/// *events* — the RT1 machine's — and `Unload` empties the tables the S-AL
/// would otherwise evaluate.
#[test]
fn the_load_machine_cycles_and_unload_empties_the_tables() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    // StartLoading, then a group key row, then LoadCompleted.
    let reply = sec_exchange(
        &mut dev,
        ApciCode::PropertyExtValueWriteCon,
        &ext_payload(SECURITY_IO, 1, 5, 1, 1, &[LoadEvent::StartLoading.into()]),
        0,
        10,
    );
    assert_eq!(reply[8], 0x00, "E_SUCCESS");

    let mut row = vec![0x00, 0x07];
    row.extend_from_slice(&[0xC0; 16]);
    sec_exchange(&mut dev, ApciCode::PropertyExtValueWriteCon, &ext_payload(SECURITY_IO, 1, 53, 1, 1, &row), 1, 20);

    let mut siat_row = CLIENT.0.to_vec();
    siat_row.extend_from_slice(&[0, 0, 0, 0, 0, 9]);
    sec_exchange(
        &mut dev,
        ApciCode::PropertyExtValueWriteCon,
        &ext_payload(SECURITY_IO, 1, 54, 1, 1, &siat_row),
        2,
        30,
    );

    sec_exchange(
        &mut dev,
        ApciCode::PropertyExtValueWriteCon,
        &ext_payload(SECURITY_IO, 1, 5, 1, 1, &[LoadEvent::LoadCompleted.into()]),
        3,
        40,
    );
    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 5, 1, 1, &[]), 4, 50);
    assert_eq!(reply[8], u8::from(LoadState::Loaded), "loaded");

    // ETS uses the mandatory extended-function path for PDT_CONTROL. Its
    // ten-octet write must answer with both E_SUCCESS and the resulting
    // one-octet state; omitting that state makes Falcon reject the APDU.
    let reply = sec_exchange(
        &mut dev,
        ApciCode::FunctionPropertyExtCommand,
        &function_ext_payload(SECURITY_IO, 1, 5, &LoadControlRecord::event(LoadEvent::Unload)),
        5,
        60,
    );
    assert_eq!(&reply[5..], &[0x00, u8::from(LoadState::Unloaded)]);

    // Unload empties the tables …
    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 53, 1, 0, &[]), 6, 70);
    assert_eq!(&reply[8..], &[0x00, 0x00], "the group keys are gone");
    assert_eq!(dev.security_state().seq.siat_count(), 0, "the durable SIAT is gone");

    // … and deliberately leaves the tool key alone: a device whose Security
    // IO was just unloaded must stay reachable by the tool that did it.
    let key = [0x5A; 16];
    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueWriteCon, &ext_payload(SECURITY_IO, 1, 56, 1, 1, &key), 7, 80);
    assert_eq!(reply[8], 0x00, "the tool key is still writable after an unload");
}

#[test]
fn siat_rows_extend_the_table_after_ets_clears_its_count() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    // ETS replaces an array by clearing element zero and then streaming the
    // new rows. The first entry write therefore has to grow a zero-length
    // SIAT; it is not an overwrite of an already allocated element.
    let reply = sec_exchange(
        &mut dev,
        ApciCode::PropertyExtValueWriteCon,
        &ext_payload(SECURITY_IO, 1, 54, 1, 0, &[0, 0]),
        0,
        10,
    );
    assert_eq!(reply[8], 0x00, "count-zero clear succeeds");

    let rows = [
        0x00, 0x02, 0, 0, 0, 0, 0, 0, // 0.0.2, initial sequence zero
        0x10, 0x32, 0, 0, 0, 0, 0, 9, // 1.0.50
    ];
    let reply = sec_exchange(
        &mut dev,
        ApciCode::PropertyExtValueWriteCon,
        &ext_payload(SECURITY_IO, 1, 54, 2, 1, &rows),
        1,
        20,
    );

    assert_eq!(reply[8], 0x00, "the first replacement chunk succeeds");
    assert_eq!(dev.security_state().seq.siat_count(), 2);
    assert_eq!(dev.security_state().seq.siat_read_entry(0), Some((0x0002, [0; 6])));
    assert_eq!(dev.security_state().seq.siat_read_entry(1), Some((0x1032, [0, 0, 0, 0, 0, 9])));
}

#[test]
fn an_unload_is_not_published_when_the_siat_cannot_be_cleared() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);
    dev.security_state().security.set_load_state(LoadState::Loaded);
    dev.security_state_mut().seq.siat_write_entry(0, u16::from_be_bytes(CLIENT.0), [0; 6]).expect("SIAT row fits");
    dev.security_state_mut().seq.fail_siat_clear = true;

    let reply = sec_exchange(
        &mut dev,
        ApciCode::PropertyExtValueWriteCon,
        &ext_payload(SECURITY_IO, 1, 5, 1, 1, &[LoadEvent::Unload.into()]),
        0,
        10,
    );

    assert_eq!(reply[8], 0xF1, "the storage failure is reported as E_MEMORY_ERROR");
    assert_eq!(dev.security_state().security.load_state(), LoadState::Loaded);
    assert_eq!(dev.security_state().seq.siat_count(), 1, "the existing durable state is unchanged");
}

/// PID_SECURITY_MODE is a function property: `[Reserved, ServiceID,
/// ServiceInfo]` to set, `[Reserved, ReadServiceID]` to read back.
#[test]
fn the_security_mode_is_a_function_property() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let fp = |ot: u16, pid: u16, data: &[u8]| {
        let mut p = vec![(ot >> 8) as u8, ot as u8, 0x00, 0x10, pid as u8];
        p.extend_from_slice(data);
        p
    };

    // Off to begin with.
    let reply =
        sec_exchange(&mut dev, ApciCode::FunctionPropertyExtStateRead, &fp(SECURITY_IO, 51, &[0x00, 0x00]), 0, 10);
    assert_eq!(&reply[5..], &[0x00, 0x00, 0x00], "return code, service id, mode off");

    // Enable it.
    let reply =
        sec_exchange(&mut dev, ApciCode::FunctionPropertyExtCommand, &fp(SECURITY_IO, 51, &[0x00, 0x00, 0x01]), 1, 20);
    assert_eq!(reply[5], 0x00, "E_SUCCESS");
    assert!(dev.security_state().security.security_mode_enabled(), "mode now on");

    // Disable it (a plain exchange, so we need security off to read back).
    let reply =
        sec_exchange(&mut dev, ApciCode::FunctionPropertyExtCommand, &fp(SECURITY_IO, 51, &[0x00, 0x00, 0x00]), 2, 30);
    assert_eq!(reply[5], 0x00, "E_SUCCESS");

    let reply =
        sec_exchange(&mut dev, ApciCode::FunctionPropertyExtStateRead, &fp(SECURITY_IO, 51, &[0x00, 0x00]), 3, 40);
    assert_eq!(&reply[5..], &[0x00, 0x00, 0x00], "mode off again");

    // An undefined ServiceInfo is void request data.
    let reply =
        sec_exchange(&mut dev, ApciCode::FunctionPropertyExtCommand, &fp(SECURITY_IO, 51, &[0x00, 0x00, 0x09]), 4, 50);
    assert_eq!(reply[5], 0xF8, "E_DATA_VOID");
    assert_eq!(reply[6], 0x00, "the service id is echoed");

    // A non-zero Reserved octet is likewise refused.
    let reply =
        sec_exchange(&mut dev, ApciCode::FunctionPropertyExtCommand, &fp(SECURITY_IO, 51, &[0x01, 0x00, 0x01]), 5, 60);
    assert_eq!(reply[5], 0xF8, "E_DATA_VOID");
}

/// The failures log answers its counters through the same service.
#[test]
fn the_failure_log_reads_its_counters() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);
    let payload = vec![0x00, 0x11, 0x00, 0x10, 55, 0x00, 0x00];
    let reply = sec_exchange(&mut dev, ApciCode::FunctionPropertyExtStateRead, &payload, 0, 10);
    assert_eq!(reply[5], 0x00, "E_SUCCESS");
    assert_eq!(&reply[7..], &[0u8; 8], "four 16-bit counters, all zero on a fresh device");
}

/// A factory device answers under its FDSK: until ETS writes a tool key, the
/// FDSK *is* the tool key (03/05/01 §6.1.4). Defaulting it to zero instead
/// would ship a device nothing could reach.
#[test]
fn the_fdsk_stands_in_as_the_tool_key_until_one_is_written() {
    let dev = data_secure_device();
    assert_eq!(dev.security_state().security.tool_key(), FDSK);
}

/// PID_SEQUENCE_NUMBER_SENDING is one counter for all outgoing secure
/// communication (03/03/07 §5.3), served from the store rather than the
/// security tables.
#[test]
fn the_sending_sequence_number_reads_and_writes() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 59, 1, 1, &[]), 0, 10);
    assert_eq!(&reply[8..], &DEFAULT_SENDING, "a fresh device starts at the spec default");

    let next = [0x00, 0x00, 0x00, 0x00, 0x12, 0x34];
    let reply = sec_exchange(
        &mut dev,
        ApciCode::PropertyExtValueWriteCon,
        &ext_payload(SECURITY_IO, 1, 59, 1, 1, &next),
        1,
        20,
    );
    assert_eq!(reply[8], 0x00, "E_SUCCESS");

    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 59, 1, 1, &[]), 2, 30);
    assert_eq!(
        &reply[8..],
        &zweidraehte_proto::security::u64_to_seq6(zweidraehte_proto::security::seq6_to_u64(&next) + 1),
        "the write confirmation consumed the written outgoing number",
    );

    // Zero is never a valid sequence number: a remote S-AL ignores it
    // (§5.3.1), so accepting it would arm the device to send frames nobody
    // will take.
    let reply = sec_exchange(
        &mut dev,
        ApciCode::PropertyExtValueWriteCon,
        &ext_payload(SECURITY_IO, 1, 59, 1, 1, &[0u8; 6]),
        3,
        40,
    );
    assert_ne!(reply[8], 0x00, "sequence number zero is refused");
}

/// The SIAT is served live out of the sequence store — one element is a
/// sender address and its Last Valid SeqNr, not a second copy of either.
#[test]
fn the_siat_is_the_sequence_store() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 54, 1, 0, &[]), 0, 10);
    assert_eq!(&reply[8..], &[0x00, 0x00], "empty to begin with");

    // Two senders, written positionally the way ETS writes them.
    let mut rows = vec![0x11, 0x01];
    rows.extend_from_slice(&[0, 0, 0, 0, 0, 7]);
    rows.extend_from_slice(&[0x11, 0x02]);
    rows.extend_from_slice(&[0, 0, 0, 0, 0, 9]);
    let reply = sec_exchange(
        &mut dev,
        ApciCode::PropertyExtValueWriteCon,
        &ext_payload(SECURITY_IO, 1, 54, 2, 1, &rows),
        1,
        20,
    );
    assert_eq!(reply[8], 0x00, "E_SUCCESS");

    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 54, 1, 0, &[]), 2, 30);
    assert_eq!(&reply[8..], &[0x00, 0x02], "two entries");

    let reply =
        sec_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 54, 2, 1, &[]), 3, 40);
    assert_eq!(&reply[8..], &rows[..], "both rows read back verbatim");

    // The same number the property serves is the one the S-AL will consult
    // for replay decisions; there is no second copy to drift.
    assert_eq!(dev.security_state().seq.load_receiving_seq(0x1101).expect("store"), Some([0, 0, 0, 0, 0, 7]));
}

// ============================================================================
// The Secure Application Layer
// ============================================================================

use zweidraehte_proto::crypto::ccm;
use zweidraehte_proto::messages::apdu::secure;

fn secure_tool_frame(
    apci: ApciCode,
    small6: u8,
    payload: &[u8],
    key: &[u8; 16],
    seq_nr: &[u8; 6],
    tl_seq: u8,
) -> Vec<u8> {
    secure_individual_frame(apci, small6, payload, key, seq_nr, tl_seq, true)
}

fn secure_connectionless_tool_frame(
    apci: ApciCode,
    small6: u8,
    payload: &[u8],
    key: &[u8; 16],
    seq_nr: &[u8; 6],
) -> Vec<u8> {
    secure_connectionless_tool_frame_with_confidentiality(apci, small6, payload, key, seq_nr, true)
}

fn secure_connectionless_tool_frame_with_confidentiality(
    apci: ApciCode,
    small6: u8,
    payload: &[u8],
    key: &[u8; 16],
    seq_nr: &[u8; 6],
    confidentiality: bool,
) -> Vec<u8> {
    secure_individual_frame_with_tpci(apci, small6, payload, key, seq_nr, Tpci::DataIndividual, true, confidentiality)
}

fn secure_individual_frame(
    apci: ApciCode,
    small6: u8,
    payload: &[u8],
    key: &[u8; 16],
    seq_nr: &[u8; 6],
    tl_seq: u8,
    tool_access: bool,
) -> Vec<u8> {
    secure_individual_frame_with_tpci(
        apci,
        small6,
        payload,
        key,
        seq_nr,
        Tpci::DataConnected(tl_seq),
        tool_access,
        true,
    )
}

// Each field independently changes the S-A_Data wire image; bundling them
// would make this test builder harder to compare with the specification.
#[allow(clippy::too_many_arguments)]
fn secure_individual_frame_with_tpci(
    apci: ApciCode,
    small6: u8,
    payload: &[u8],
    key: &[u8; 16],
    seq_nr: &[u8; 6],
    tpci: Tpci,
    tool_access: bool,
    confidentiality: bool,
) -> Vec<u8> {
    let plain: FrameBuf<EXTENDED_FRAME> = data_frame(0x00, CLIENT, DUT.0, false, tpci, apci, small6, payload);
    let plain_len = plain.len();
    let scf_byte: u8 = (if tool_access { 0x80 } else { 0x00 }) | (if confidentiality { 0x10 } else { 0x00 }); // SAI=01, service=data

    let mut frame = Vec::from(plain.as_slice());
    frame.resize(plain_len + secure::OVERHEAD, 0);
    let layout = secure::wrap_plaintext(&mut frame, plain_len, scf_byte, seq_nr).expect("fits");

    let src = u16::from_be_bytes(CLIENT.0);
    let ccm_ctx = secure::SecureApduRef::parse(&frame).expect("valid").ccm_context(src);

    let mac = if confidentiality {
        ccm::encrypt_and_mac(key, &ccm_ctx, scf_byte, &mut frame[layout.payload_start..layout.payload_end])
    } else {
        ccm::compute_mac_auth_only(key, &ccm_ctx, scf_byte, &frame[layout.payload_start..layout.payload_end])
    };
    frame[layout.mac_start..layout.mac_start + 4].copy_from_slice(&mac);
    to_wire::<EXTENDED_FRAME>(&frame).to_vec()
}

fn unwrap_secure_response(frame: &[u8], key: &[u8; 16]) -> FrameBuf<EXTENDED_FRAME> {
    unwrap_secure_response_from(frame, key, DUT)
}

fn unwrap_secure_response_from(frame: &[u8], key: &[u8; 16], source: IndividualAddress) -> FrameBuf<EXTENDED_FRAME> {
    let mut canonical = normalize::<EXTENDED_FRAME>(frame).expect("well-formed secure response");
    let (scf_byte, scf, mac, context) = {
        let secure_ref = secure::SecureApduRef::parse(&canonical).expect("secure response");
        (
            secure_ref.scf_byte(),
            secure_ref.scf().expect("valid SCF"),
            secure_ref.mac(),
            secure_ref.ccm_context(u16::from_be_bytes(source.0)),
        )
    };
    let mut secure_mut = secure::SecureApduMut::parse(&mut canonical).expect("secure response");
    if scf.confidentiality {
        ccm::verify_and_decrypt(key, &context, scf_byte, secure_mut.payload_mut(), &mac)
            .expect("response authenticates with the current Tool Key");
    } else {
        ccm::verify_mac_auth_only(key, &context, scf_byte, secure_mut.payload(), &mac)
            .expect("response authenticates with the current Tool Key");
    }
    let len = secure_mut.unwrap_to_plaintext();
    canonical.truncate(len);
    canonical
}

#[test]
fn a_secure_tool_key_write_round_trips() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let new_key = [0x5A; 16];
    let payload = ext_payload(SECURITY_IO, 1, 56, 1, 1, &new_key);
    let seq_nr = [0, 0, 0, 0, 0, 42];
    let secure_frame = secure_tool_frame(ApciCode::PropertyExtValueWriteCon, 0, &payload, &FDSK, &seq_nr, 0);

    let out = dev.poll(PollInput::Frame(&secure_frame), 10);

    assert!(out.frames.len() >= 2, "expected ACK + secure response, got {}", out.frames.len());
    assert_eq!(dev.security_state().security.tool_key(), new_key, "the tool key was written");
}

/// A plain (non-secure) frame is still accepted when security mode is off.
#[test]
fn plain_management_works_when_security_mode_is_off() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);
    // A plain (non-secure) property read — should work since security mode is off.
    let reply =
        plain_sec_exchange(&mut dev, ApciCode::PropertyExtValueRead, &ext_payload(SECURITY_IO, 1, 1, 1, 1, &[]), 0, 10);
    assert_eq!(&reply[8..], &[0x00, 0x11], "PID_OBJECT_TYPE answers plain");
}

/// A replay (same sequence number twice) is silently dropped.
#[test]
fn a_replay_is_dropped() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let payload = ext_payload(SECURITY_IO, 1, 1, 1, 1, &[]);
    let seq_nr = [0, 0, 0, 0, 0, 1];
    let frame1 = secure_tool_frame(ApciCode::PropertyExtValueRead, 0, &payload, &FDSK, &seq_nr, 0);

    let out = dev.poll(PollInput::Frame(&frame1), 10);
    assert!(out.frames.len() >= 2, "first secure read gets ACK + response");

    // The transport layer accepts and acknowledges the outer numbered frame
    // before the S-AL rejects the replay.
    let frame2 = secure_tool_frame(ApciCode::PropertyExtValueRead, 0, &payload, &FDSK, &seq_nr, 1);
    let out2 = dev.poll(PollInput::Frame(&frame2), 20);
    assert_eq!(out2.frames.len(), 1, "replay gets only its transport ACK");
}

/// A secure read with a fresh sequence number after the first succeeds.
#[test]
fn a_fresh_sequence_number_is_accepted() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let payload = ext_payload(SECURITY_IO, 1, 1, 1, 1, &[]);

    let frame1 = secure_tool_frame(ApciCode::PropertyExtValueRead, 0, &payload, &FDSK, &[0, 0, 0, 0, 0, 1], 0);
    let out1 = dev.poll(PollInput::Frame(&frame1), 10);
    assert!(out1.frames.len() >= 2);

    // ACK the device's response so the TL leaves OPEN_WAIT.
    let ack = [TP1_STD_CTRL_BASE, CLIENT.0[0], CLIENT.0[1], DUT.0[0], DUT.0[1], NPCI_HOP_COUNT_6, Tpci::Ack(0).octet()];
    dev.poll(PollInput::Frame(&ack), 15);

    let frame2 = secure_tool_frame(ApciCode::PropertyExtValueRead, 0, &payload, &FDSK, &[0, 0, 0, 0, 0, 2], 1);
    let out2 = dev.poll(PollInput::Frame(&frame2), 20);
    assert!(out2.frames.len() >= 2, "fresh seq accepted");
}

/// Sequence number zero is always invalid.
#[test]
fn sequence_zero_is_dropped() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let payload = ext_payload(SECURITY_IO, 1, 1, 1, 1, &[]);
    let frame = secure_tool_frame(ApciCode::PropertyExtValueRead, 0, &payload, &FDSK, &[0, 0, 0, 0, 0, 0], 0);
    let out = dev.poll(PollInput::Frame(&frame), 10);
    assert_eq!(out.frames.len(), 1, "seq zero gets only its transport ACK");
}

/// A frame encrypted with the wrong key is dropped (MAC mismatch).
#[test]
fn wrong_key_is_dropped() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let payload = ext_payload(SECURITY_IO, 1, 1, 1, 1, &[]);
    let wrong_key = [0xDE; 16];
    let frame = secure_tool_frame(ApciCode::PropertyExtValueRead, 0, &payload, &wrong_key, &[0, 0, 0, 0, 0, 1], 0);
    let out = dev.poll(PollInput::Frame(&frame), 10);
    assert_eq!(out.frames.len(), 1, "wrong key gets only its transport ACK");
}

/// A well-formed frame whose MAC was changed after encryption is dropped.
#[test]
fn bad_mac_is_dropped() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let payload = ext_payload(SECURITY_IO, 1, 1, 1, 1, &[]);
    let mut frame = secure_tool_frame(ApciCode::PropertyExtValueRead, 0, &payload, &FDSK, &[0, 0, 0, 0, 0, 1], 0);
    *frame.last_mut().expect("secure frame has a MAC") ^= 0x01;
    let out = dev.poll(PollInput::Frame(&frame), 10);
    assert_eq!(out.frames.len(), 1, "bad MAC gets only its transport ACK");
}

/// P2P capacity is zero: even a cryptographically valid non-tool individual
/// frame has no role/key context and must be refused.
#[test]
fn non_tool_individual_data_is_dropped() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let payload = ext_payload(SECURITY_IO, 1, 1, 1, 1, &[]);
    let frame =
        secure_individual_frame(ApciCode::PropertyExtValueRead, 0, &payload, &FDSK, &[0, 0, 0, 0, 0, 1], 0, false);
    let out = dev.poll(PollInput::Frame(&frame), 10);
    assert_eq!(out.frames.len(), 1, "non-tool P2P gets only its transport ACK");
}

/// The only individual-security wrapper this profile exposes is the reply
/// path. A non-tool request context must neither mutate the plaintext nor
/// consume the device's sending sequence number.
#[test]
fn spontaneous_non_tool_individual_protection_is_refused_without_side_effects() {
    use zweidraehte_microdevice::DataSecure;
    use zweidraehte_microdevice::sal::{ReplyKey, ReplySecurity};
    use zweidraehte_proto::access::SecurityMode;

    let mut dev = data_secure_device();
    let before_sequence = dev.security_state().seq.load_sending_seq().expect("RAM store reads");
    let mut frame: FrameBuf<SECURE_EXTENDED_FRAME> =
        data_frame(0, DUT, CLIENT.0, false, Tpci::DataIndividual, ApciCode::PropertyExtValueResponse, 0, &[]);
    let plaintext = frame.clone();
    let reply = Some(ReplySecurity {
        security: SecurityMode::AuthConf,
        tool_access: false,
        system_broadcast: false,
        key: ReplyKey::Live,
    });

    assert!(!<DataSecure<RamSeqStore, 8, 4> as SecurityModule>::protect_reply(
        dev.security_state_mut(),
        reply,
        &mut frame,
    ));
    assert_eq!(frame, plaintext, "refusal leaves the caller's frame untouched");
    assert_eq!(dev.security_state().seq.load_sending_seq().expect("RAM store reads"), before_sequence);
}

/// System-broadcast is part of the secure communication mode, not merely
/// the outer KNX destination. A response must retain the request's SBC bit or
/// ETS authenticates it with a different CCM context and discards it.
#[test]
fn secure_reply_preserves_the_system_broadcast_mode() {
    use zweidraehte_microdevice::DataSecure;
    use zweidraehte_microdevice::sal::{ReplyKey, ReplySecurity};
    use zweidraehte_proto::access::SecurityMode;

    let mut dev = data_secure_device();
    let mut frame: FrameBuf<SECURE_EXTENDED_FRAME> = data_frame(
        0,
        DUT,
        [0, 0],
        true,
        Tpci::DataSystemBroadcast,
        ApciCode::SystemNetworkParameterResponse,
        0,
        &[0; 11],
    );
    let reply = Some(ReplySecurity {
        security: SecurityMode::AuthConf,
        tool_access: true,
        system_broadcast: true,
        key: ReplyKey::Live,
    });

    assert!(<DataSecure<RamSeqStore, 8, 4> as SecurityModule>::protect_reply(
        dev.security_state_mut(),
        reply,
        &mut frame,
    ));
    assert!(
        secure::SecureApduRef::parse(&frame)
            .expect("secure response parses")
            .scf()
            .expect("valid SCF")
            .system_broadcast
    );
}

/// The response to a secure request is itself encrypted, and a retransmit
/// is byte-identical (no new sequence number consumed).
#[test]
fn the_response_is_encrypted_and_retransmits_are_identical() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    let payload = ext_payload(SECURITY_IO, 1, 1, 1, 1, &[]);
    let frame = secure_tool_frame(ApciCode::PropertyExtValueRead, 0, &payload, &FDSK, &[0, 0, 0, 0, 0, 1], 0);
    let out = dev.poll(PollInput::Frame(&frame), 10);
    assert_eq!(out.frames.len(), 2, "ACK + encrypted response");

    // The response (frame 1) must be a SecureService frame.
    let resp = &out.frames[1];
    let canonical = normalize::<EXTENDED_FRAME>(resp).expect("well-formed");
    let apci10 = (((canonical[6] & 0x03) as u16) << 8) | canonical[7] as u16;
    assert_eq!(ApciCode::from_wire10(apci10), ApciCode::SecureService, "response is encrypted");

    // A TL retransmit (NACK the response) must produce the exact same bytes.
    let nack =
        [TP1_STD_CTRL_BASE, CLIENT.0[0], CLIENT.0[1], DUT.0[0], DUT.0[1], NPCI_HOP_COUNT_6, Tpci::Nack(0).octet()];
    let out2 = dev.poll(PollInput::Frame(&nack), 20);
    assert_eq!(out2.frames.len(), 1, "retransmit produces one frame");
    assert_eq!(out2.frames[0].as_slice(), resp.as_slice(), "retransmit is byte-identical");
}

/// With security mode enabled, a plain (non-secure) property read is
/// refused — §9.1.2.4 footnote a: application parameters shall not be
/// accessible in plain while Security Mode is enabled.
#[test]
fn plain_access_is_refused_when_security_mode_is_on() {
    let mut dev = data_secure_device();

    // Enable security mode through the function property.
    sec_connect(&mut dev);
    let ip: [u8; 3] = [0x00, 0x10, 51]; // instance=1, PID=51 (SECURITY_MODE)
    let fp_payload = vec![0x00, 0x11, ip[0], ip[1], ip[2], 0x00, 0x00, 0x01];
    sec_exchange(&mut dev, ApciCode::FunctionPropertyExtCommand, &fp_payload, 0, 10);
    assert!(dev.security_state().security.security_mode_enabled(), "mode is now on");

    // A plain property read against the Device Object should now fail.
    // The device is still connected, so send a numbered read.
    let req = data_frame::<EXTENDED_FRAME>(
        0x00,
        CLIENT,
        DUT.0,
        false,
        Tpci::DataConnected(1),
        ApciCode::PropertyValueRead,
        0,
        &[0x00, 11u8, 0x10, 0x01],
    );
    let out = dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&req)), 20);
    // The regular property service renders denial as its standard negative
    // response (element count zero); it must not expose the value.
    assert_eq!(out.frames.len(), 2, "ACK plus negative property response");
    let response = normalize::<EXTENDED_FRAME>(&out.frames[1]).expect("well-formed");
    let response = FrameView::parse(&response).expect("parsable");
    assert_eq!(response.payload()[2] >> 4, 0, "plain read returns no elements");
}

fn secure_group_frame(
    destination: GroupAddress,
    apci: ApciCode,
    small6: u8,
    key: &[u8; 16],
    sequence: &[u8; 6],
    confidentiality: bool,
) -> Vec<u8> {
    let plain: FrameBuf<EXTENDED_FRAME> =
        data_frame(0x0C, CLIENT, destination.0, true, Tpci::DataGroup, apci, small6, &[]);
    let plain_len = plain.len();
    let scf = if confidentiality { 0x10 } else { 0x00 };
    let mut frame = plain.to_vec();
    frame.resize(plain_len + secure::OVERHEAD, 0);
    let layout = secure::wrap_plaintext(&mut frame, plain_len, scf, sequence).expect("secure group frame fits");
    let context =
        secure::SecureApduRef::parse(&frame).expect("secure group frame").ccm_context(u16::from_be_bytes(CLIENT.0));
    let mac = if confidentiality {
        ccm::encrypt_and_mac(key, &context, scf, &mut frame[layout.payload_start..layout.payload_end])
    } else {
        ccm::compute_mac_auth_only(key, &context, scf, &frame[layout.payload_start..layout.payload_end])
    };
    frame[layout.mac_start..layout.mac_start + secure::MAC_LEN].copy_from_slice(&mac);
    to_wire::<EXTENDED_FRAME>(&frame).to_vec()
}

fn configure_secure_group(dev: &mut SecureDev, asap: u8, group_index: u16, key: [u8; 16], flags: u8) {
    let state = dev.security_state_mut();
    state.security.set_load_state(LoadState::Loaded);
    let mut key_row = [0u8; 18];
    key_row[..2].copy_from_slice(&group_index.to_be_bytes());
    key_row[2..].copy_from_slice(&key);
    state.security.grp_keys().borrow_mut().write_elements(group_index, &key_row).expect("group key row fits");
    state.security.go_flags().borrow_mut().write_elements(u16::from(asap) + 1, &[flags]).expect("GO flag row fits");
    state.seq.siat_write_entry(0, u16::from_be_bytes(CLIENT.0), [0; 6]).expect("SIAT entry fits");
}

#[test]
fn bench_pid61_trace_pins_zero_based_asap_mapping() {
    // `BCU2_app_sec_prog.log` writes the bench device's 71 PID 61 elements in
    // chunks 18/18/18/17 at starts 1/19/37/55. Only wire ASAP 0 is A+C; the
    // remaining slots are plain. Keeping this fixture independent of our
    // four-object DUT catches an accidental one-based shift in either table
    // addressing or the ASAP-to-slot mapping.
    const TRACE_FLAGS: [u8; 71] = {
        let mut flags = [0; 71];
        flags[0] = 0x03;
        flags
    };

    let mut table = SecurityTable::<71, 1>::new();
    table.write_elements(1, &TRACE_FLAGS[..18]).expect("first trace chunk fits");
    table.write_elements(19, &TRACE_FLAGS[18..36]).expect("second trace chunk fits");
    table.write_elements(37, &TRACE_FLAGS[36..54]).expect("third trace chunk fits");
    table.write_elements(55, &TRACE_FLAGS[54..]).expect("final trace chunk fits");

    assert_eq!(table.count(), 71);
    for (asap, expected) in TRACE_FLAGS.into_iter().enumerate() {
        assert_eq!(table.get(asap as u16).map(|entry| entry[0]), Some(expected), "wire ASAP {asap}");
    }
}

#[test]
fn group_security_is_an_exact_pre_mutation_gate() {
    let mut dev = data_secure_device();
    let group = GroupAddress::from_three_level(1, 0, 1);
    let key = [0x33; 16];
    configure_secure_group(&mut dev, 0, 1, key, 0x03);

    let plain =
        data_frame::<EXTENDED_FRAME>(0x0C, CLIENT, group.0, true, Tpci::DataGroup, ApciCode::GroupValueWrite, 1, &[]);
    dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&plain)), 10);
    let mut value = [0u8; 1];
    dev.read_value(0, &mut value);
    assert_eq!(value[0], 0, "plain telegram cannot mutate an A+C object");

    let auth_only = secure_group_frame(group, ApciCode::GroupValueWrite, 1, &key, &[0, 0, 0, 0, 0, 1], false);
    dev.poll(PollInput::Frame(&auth_only), 20);
    dev.read_value(0, &mut value);
    assert_eq!(value[0], 0, "auth-only is not treated as at-least secure enough");

    let auth_conf = secure_group_frame(group, ApciCode::GroupValueWrite, 1, &key, &[0, 0, 0, 0, 0, 2], true);
    dev.poll(PollInput::Frame(&auth_conf), 30);
    dev.read_value(0, &mut value);
    assert_eq!(value[0], 1, "exact A+C protection admits the write");
}

#[test]
fn required_secure_group_transmits_once_or_reports_an_error() {
    let mut dev = data_secure_device();
    let key = [0x44; 16];
    configure_secure_group(&mut dev, 1, 2, key, 0x03);
    dev.write_value(1, &[1]);
    dev.set_transmit_request(1);
    let out = dev.poll(PollInput::Timer, 10);
    assert_eq!(out.frames.len(), 1);
    let plaintext = unwrap_secure_response(&out.frames[0], &key);
    let view = FrameView::parse(&plaintext).expect("decrypted group write");
    assert_eq!(view.dest_group(), GroupAddress::from_three_level(1, 0, 2));
    assert_eq!(view.apci(), Some(ApciCode::GroupValueWrite.wire10_base() | 1));

    let mut missing_key = data_secure_device();
    missing_key.security_state().security.go_flags().borrow_mut().write_elements(2, &[0x03]).expect("flag fits");
    missing_key.set_transmit_request(1);
    let out = missing_key.poll(PollInput::Timer, 10);
    assert!(out.frames.is_empty(), "required security never falls back to plaintext");
    assert_eq!(
        zweidraehte_microdevice::co_flags::tx_state(missing_key.object_flags(1)),
        zweidraehte_microdevice::co_flags::TX_IDLE_ERROR,
    );
}

#[test]
fn receiving_sequence_persistence_precedes_property_side_effects() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);
    dev.security_state_mut().seq.fail_tool_save = true;
    let new_key = [0x77; 16];
    let request = secure_tool_frame(
        ApciCode::PropertyExtValueWriteCon,
        0,
        &ext_payload(SECURITY_IO, 1, 56, 1, 1, &new_key),
        &FDSK,
        &[0, 0, 0, 0, 0, 1],
        0,
    );
    let out = dev.poll(PollInput::Frame(&request), 10);
    assert_eq!(out.frames.len(), 1, "the outer frame is acknowledged, then dropped");
    assert_eq!(dev.security_state().security.tool_key(), FDSK, "the write was never dispatched");
}

#[test]
fn failed_response_protection_does_not_wedge_the_transport() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);
    let payload = ext_payload(SECURITY_IO, 1, 1, 1, 1, &[]);

    dev.security_state_mut().seq.fail_sending_load = true;
    let first = secure_tool_frame(ApciCode::PropertyExtValueRead, 0, &payload, &FDSK, &[0, 0, 0, 0, 0, 1], 0);
    let out = dev.poll(PollInput::Frame(&first), 10);
    assert_eq!(out.frames.len(), 1, "the accepted request gets T_ACK, but no unprotected response");

    dev.security_state_mut().seq.fail_sending_load = false;
    let second = secure_tool_frame(ApciCode::PropertyExtValueRead, 0, &payload, &FDSK, &[0, 0, 0, 0, 0, 2], 1);
    let out = dev.poll(PollInput::Frame(&second), 20);
    assert_eq!(out.frames.len(), 2, "the failed wrap left the connection ready for the next request");
    let response = unwrap_secure_response(&out.frames[1], &FDSK);
    assert_eq!(FrameView::parse(&response).expect("response").tpci(), Some(Tpci::DataConnected(0)));
}

#[test]
fn a_request_without_a_reply_cannot_secure_the_next_plain_response() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);
    let secure_unconfirmed = secure_tool_frame(
        ApciCode::PropertyExtValueWriteUnCon,
        0,
        &ext_payload(SECURITY_IO, 1, 58, 1, 1, &[1]),
        &FDSK,
        &[0, 0, 0, 0, 0, 1],
        0,
    );
    let out = dev.poll(PollInput::Frame(&secure_unconfirmed), 10);
    assert_eq!(out.frames.len(), 1, "unconfirmed write only draws a TL ACK");

    let plain = data_frame::<EXTENDED_FRAME>(
        0,
        CLIENT,
        DUT.0,
        false,
        Tpci::DataConnected(1),
        ApciCode::PropertyExtValueRead,
        0,
        &ext_payload(SECURITY_IO, 1, 1, 1, 1, &[]),
    );
    let out = dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&plain)), 20);
    assert_eq!(out.frames.len(), 2);
    let response = normalize::<EXTENDED_FRAME>(&out.frames[1]).expect("plain response");
    assert_ne!(
        ApciCode::from_wire10((((response[6] & 0x03) as u16) << 8) | u16::from(response[7])),
        ApciCode::SecureService,
        "security context does not leak across requests",
    );
}

fn secure_broadcast_tool_frame(apci: ApciCode, payload: &[u8], key: &[u8; 16], sequence: &[u8; 6]) -> Vec<u8> {
    let plain: FrameBuf<EXTENDED_FRAME> = data_frame(0, CLIENT, [0, 0], true, Tpci::DataBroadcast, apci, 0, payload);
    let plain_len = plain.len();
    let scf = 0x98; // Tool, A+C, System Broadcast, S-A_Data.
    let mut frame = plain.to_vec();
    frame.resize(plain_len + secure::OVERHEAD, 0);
    let layout = secure::wrap_plaintext(&mut frame, plain_len, scf, sequence).expect("secure broadcast fits");
    let context =
        secure::SecureApduRef::parse(&frame).expect("secure broadcast").ccm_context(u16::from_be_bytes(CLIENT.0));
    let mac = ccm::encrypt_and_mac(key, &context, scf, &mut frame[layout.payload_start..layout.payload_end]);
    frame[layout.mac_start..layout.mac_start + secure::MAC_LEN].copy_from_slice(&mac);
    to_wire::<EXTENDED_FRAME>(&frame).to_vec()
}

#[test]
fn secure_broadcast_can_assign_the_matching_serial_number() {
    let mut dev = data_secure_device();
    let serial = stub_identity().serial_number;
    let new_ia = IndividualAddress::new(2, 3, 4);
    let mut payload = serial.to_vec();
    payload.extend_from_slice(new_ia.as_bytes());
    payload.extend_from_slice(&[0; 4]);
    let request =
        secure_broadcast_tool_frame(ApciCode::IndividualAddressSerialNumberWrite, &payload, &FDSK, &[0, 0, 0, 0, 0, 1]);
    let out = dev.poll(PollInput::Frame(&request), 10);
    assert!(out.frames.is_empty());
    assert_eq!(dev.individual_address(), new_ia);

    let read =
        secure_broadcast_tool_frame(ApciCode::IndividualAddressSerialNumberRead, &serial, &FDSK, &[0, 0, 0, 0, 0, 2]);
    let out = dev.poll(PollInput::Frame(&read), 20);
    assert_eq!(out.frames.len(), 1, "the secure read gets one secure broadcast response");
    let response = unwrap_secure_response_from(&out.frames[0], &FDSK, new_ia);
    let response = FrameView::parse(&response).expect("decrypted serial response");
    assert_eq!(response.source, new_ia);
    assert_eq!(response.dest_raw, [0, 0]);
    assert_eq!(response.apci(), Some(ApciCode::IndividualAddressSerialNumberResponse.wire10_base()));
    assert_eq!(&response.payload()[..6], &serial);
    assert_eq!(&response.payload()[6..], &[0; 4]);
}

fn sync_request(serial_number: [u8; 6], sequence: [u8; 6], challenge: [u8; 6]) -> Vec<u8> {
    sync_request_with_access(serial_number, sequence, challenge, true)
}

fn sync_request_with_access(
    serial_number: [u8; 6],
    sequence: [u8; 6],
    challenge: [u8; 6],
    tool_access: bool,
) -> Vec<u8> {
    let scf = if tool_access { 0x9A } else { 0x1A }; // A+C, System Broadcast, S-A_Sync_Req.
    let mut frame = [0u8; secure::sync::FRAME_LEN];
    let mac_offset = secure::build_sync_request(
        &mut frame,
        TP1_STD_CTRL_BASE,
        u16::from_be_bytes(CLIENT.0),
        0,
        0xE0,
        Tpci::DataBroadcast.octet(),
        scf,
        &sequence,
        &serial_number,
        &challenge,
    );
    let context = secure::SyncReqRef::parse(&frame).expect("sync request").ccm_context();
    let mac = ccm::encrypt_and_mac_sync_req(
        &FDSK,
        &context,
        scf,
        &serial_number,
        &mut frame[secure::sync::CHALLENGE..secure::sync::CHALLENGE + 6],
    );
    frame[mac_offset..mac_offset + secure::MAC_LEN].copy_from_slice(&mac);
    to_wire::<EXTENDED_FRAME>(&frame).to_vec()
}

fn connected_sync_request(sequence: [u8; 6], challenge: [u8; 6], tl_seq: u8) -> Vec<u8> {
    let scf = 0x92; // Tool + A+C, S-A_Sync_Req without SBC.
    let mut frame = [0u8; secure::sync::FRAME_LEN];
    let mac_offset = secure::build_sync_request(
        &mut frame,
        TP1_STD_CTRL_BASE,
        u16::from_be_bytes(CLIENT.0),
        u16::from_be_bytes(DUT.0),
        NPCI_HOP_COUNT_6,
        Tpci::DataConnected(tl_seq).octet(),
        scf,
        &sequence,
        &[0; 6],
        &challenge,
    );
    let context = secure::SyncReqRef::parse(&frame).expect("sync request").ccm_context();
    let mac = ccm::encrypt_and_mac_sync_req(
        &FDSK,
        &context,
        scf,
        &[0; 6],
        &mut frame[secure::sync::CHALLENGE..secure::sync::CHALLENGE + 6],
    );
    frame[mac_offset..mac_offset + secure::MAC_LEN].copy_from_slice(&mac);
    to_wire::<EXTENDED_FRAME>(&frame).to_vec()
}

#[test]
fn non_tool_sync_is_dropped() {
    let mut dev = data_secure_device();
    let request =
        sync_request_with_access(stub_identity().serial_number, [0, 0, 0, 0, 0, 1], [1, 2, 3, 4, 5, 6], false);

    assert!(dev.poll(PollInput::Frame(&request), 10).frames.is_empty());
}

#[test]
fn broadcast_sync_reconciles_sequences_and_is_rate_limited() {
    let mut dev = data_secure_device();
    let challenge = [1, 2, 3, 4, 5, 6];
    let request = sync_request(stub_identity().serial_number, [0, 0, 0, 0, 0, 5], challenge);
    let out = dev.poll(PollInput::Frame(&request), 10);
    assert_eq!(out.frames.len(), 1, "sync response is connectionless");
    assert_eq!(dev.security_state().seq.tool, Some([0, 0, 0, 0, 0, 4]));

    let response = normalize::<EXTENDED_FRAME>(&out.frames[0]).expect("sync response");
    let sync = secure::SyncResRef::parse(&response).expect("sync response");
    let xor = sync.challenge_xor_random();
    let mut random = [0u8; 6];
    for i in 0..6 {
        random[i] = challenge[i] ^ xor[i];
    }
    assert_eq!(random, [0xA5; 6], "entropy comes from MicroSecurityResources");
    let mut payload = sync.payload_enc();
    let mac = sync.mac();
    let scf = sync.scf_byte();
    ccm::verify_and_decrypt_sync_res(
        &FDSK,
        &random,
        sync.src(),
        sync.dst(),
        sync.addr_type(),
        sync.tpci_apci(),
        scf,
        &mut payload,
        &mac,
    )
    .expect("sync response authenticates");
    assert_eq!(&payload[..6], &DEFAULT_SENDING);
    assert_eq!(&payload[6..], &[0, 0, 0, 0, 0, 5]);

    let second = sync_request(stub_identity().serial_number, [0, 0, 0, 0, 0, 6], challenge);
    assert!(dev.poll(PollInput::Frame(&second), 20).frames.is_empty(), "one-second rate limit");
    assert_eq!(dev.poll(PollInput::Frame(&second), 1_011).frames.len(), 1, "accepted after the window");
}

#[test]
fn connected_sync_uses_the_devices_transport_sequence_and_retransmit_slot() {
    let mut dev = data_secure_device();
    sec_connect(&mut dev);

    // Advance only the request direction. ETS can legitimately send a sync
    // after an unconfirmed request, so the two TL sequence numbers need not
    // match even though ordinary request/response traffic keeps them aligned.
    let unconfirmed = secure_tool_frame(
        ApciCode::PropertyExtValueWriteUnCon,
        0,
        &ext_payload(SECURITY_IO, 1, 58, 1, 1, &[1]),
        &FDSK,
        &[0, 0, 0, 0, 0, 1],
        0,
    );
    assert_eq!(dev.poll(PollInput::Frame(&unconfirmed), 10).frames.len(), 1, "unconfirmed request gets only T_ACK");

    let challenge = [1, 2, 3, 4, 5, 6];
    let request = connected_sync_request([0, 0, 0, 0, 0, 5], challenge, 1);
    let out = dev.poll(PollInput::Frame(&request), 20);
    assert_eq!(out.frames.len(), 2, "connected sync gets T_ACK and S-A_Sync_Res");

    let response = normalize::<EXTENDED_FRAME>(&out.frames[1]).expect("sync response");
    let view = FrameView::parse(&response).expect("sync response frame");
    assert_eq!(view.tpci(), Some(Tpci::DataConnected(0)), "the response uses the device's independent TL sequence");
    let sync = secure::SyncResRef::parse(&response).expect("sync response");
    let xor = sync.challenge_xor_random();
    let mut random = [0u8; 6];
    for i in 0..6 {
        random[i] = challenge[i] ^ xor[i];
    }
    let mut payload = sync.payload_enc();
    ccm::verify_and_decrypt_sync_res(
        &FDSK,
        &random,
        sync.src(),
        sync.dst(),
        sync.addr_type(),
        sync.tpci_apci(),
        sync.scf_byte(),
        &mut payload,
        &sync.mac(),
    )
    .expect("connected sync response authenticates");
    assert_eq!(&payload[..6], &DEFAULT_SENDING);
    assert_eq!(&payload[6..], &[0, 0, 0, 0, 0, 5]);

    let nack =
        [TP1_STD_CTRL_BASE, CLIENT.0[0], CLIENT.0[1], DUT.0[0], DUT.0[1], NPCI_HOP_COUNT_6, Tpci::Nack(0).octet()];
    let retransmit = dev.poll(PollInput::Frame(&nack), 21);
    assert_eq!(retransmit.frames.len(), 1);
    assert_eq!(retransmit.frames[0], out.frames[1], "the TL retains the protected sync response");
}

#[test]
#[cfg(feature = "std")]
fn secure_snapshot_round_trip_preserves_config_and_sequences_without_debugging_keys() {
    use zweidraehte_microdevice::snapshot::SecureMicroSnapshot;

    let mut dev = data_secure_device();
    dev.security_state().security.set_tool_key([0x66; 16]);
    dev.security_state_mut().seq.sending = Some([0, 0, 0, 0, 4, 2]);
    let snapshot = SecureMicroSnapshot::capture(&dev);
    let debug = format!("{snapshot:?}");
    assert!(!debug.contains("102, 102"), "Tool Key bytes are redacted");
    assert!(!debug.contains("17, 17"), "FDSK bytes are redacted");
    let bytes = postcard::to_allocvec(&snapshot).expect("serializes");
    let restored_snapshot: SecureMicroSnapshot<RamSeqStore, 8, 4> = postcard::from_bytes(&bytes).expect("deserializes");
    let restored: SecureDev = restored_snapshot.restore(stub_identity(), 1);
    assert_eq!(restored.security_state().security.tool_key(), [0x66; 16]);
    assert_eq!(restored.security_state().seq.sending, Some([0, 0, 0, 0, 4, 2]));
}
