//! End-to-end conversations against the BCU2 micro stack: the
//! MV-0020-shaped management dialogue and the group communication
//! paths, driven frame-by-frame the way the bus would.

use zweidraehte_microdevice::device::{DeviceIdentity, Microdevice, PollInput};
use zweidraehte_microdevice::families::bcu2::{Bcu2CoDescriptor, Bcu2DeviceDefinition, Bcu2Family};
use zweidraehte_microdevice::frame::{FrameBuf, FrameView, Tpci, apci, data_frame, tpci_numbered};
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::messages::apdu::load_control::{AbsSegment, LoadControlRecord, LoadEvent, LoadState};

const CLIENT: IndividualAddress = IndividualAddress::new(0, 0, 1);
const DUT: IndividualAddress = IndividualAddress::new(1, 1, 10);

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

/// Drive one frame in and collect the response frames.
fn step(dev: &mut Microdevice<Bcu2Family>, frame: &[u8], now: u32) -> Vec<FrameBuf> {
    dev.poll(PollInput::Frame(frame), now).frames.into_iter().collect()
}

fn connect(dev: &mut Microdevice<Bcu2Family>) {
    let t_connect = [0xB0, 0x00, 0x01, 0x11, 0x0A, 0x60, 0x80];
    let replies = step(dev, &t_connect, 0);
    assert!(replies.is_empty(), "Style 1 accepts a connect silently");
}

/// Send numbered data, expect T_ACK plus optionally a numbered reply;
/// acknowledge the reply like a well-behaved client.
fn exchange(
    dev: &mut Microdevice<Bcu2Family>,
    seq: u8,
    apci10: u16,
    small6: u8,
    payload: &[u8],
    now: u32,
) -> Option<Vec<u8>> {
    let request = data_frame(0x00, CLIENT, DUT.0, false, tpci_numbered(seq), apci10, small6, payload);
    let replies = step(dev, &request, now);
    assert!(!replies.is_empty(), "expected at least a T_ACK");
    let ack = FrameView::parse(&replies[0]).expect("parsable ack");
    assert_eq!(ack.tpci(), Tpci::ControlAck { nak: false, seq }, "first reply is the T_ACK");

    let response = replies.get(1).map(|r| {
        let view = FrameView::parse(r).expect("parsable response");
        let Tpci::Numbered { seq: rsp_seq } = view.tpci() else {
            panic!("data response expected, got {:?}", view.tpci());
        };
        // Client acks the device's numbered response.
        let client_ack = [0xB0, 0x00, 0x01, 0x11, 0x0A, 0x60, 0xC2 | (rsp_seq << 2)];
        let extra = step(dev, &client_ack, now);
        assert!(extra.is_empty(), "T_ACK draws no further frames");
        r.to_vec()
    });
    assert!(replies.len() <= 2, "one request never yields more than ack + response");
    response
}

/// The response's APDU bytes: octet 6 onward.
fn apdu(frame: &[u8]) -> &[u8] {
    &frame[6..]
}

#[test]
fn dd0_and_management_style_and_authorize() {
    let mut dev = device();
    connect(&mut dev);

    // DD0 → 0020h.
    let rsp = exchange(&mut dev, 0, apci::DEVICE_DESCRIPTOR_READ, 0, &[], 0).expect("DD0 answered");
    assert_eq!(apdu(&rsp), &[0x43, 0x40, 0x00, 0x20]);

    // ManagementStyle at 0115h → 48h.
    let rsp = exchange(&mut dev, 1, apci::MEMORY_READ, 1, &[0x01, 0x15], 0).expect("memory answered");
    assert_eq!(apdu(&rsp), &[0x46, 0x41, 0x01, 0x15, 0x48]);

    // A_Authorize with the FF key → level 0 (factory keys).
    let rsp = exchange(&mut dev, 2, apci::AUTHORIZE_REQUEST, 0, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF], 0)
        .expect("authorize answered");
    assert_eq!(apdu(&rsp)[1], 0xD2, "A_Authorize_Response");
    assert_eq!(apdu(&rsp)[2], 0x00, "granted level 0");
}

#[test]
fn option_reg_reads_inverted() {
    let mut dev = device();
    connect(&mut dev);
    // Raw cell is 00h (factory erased); the bus sees FFh.
    let rsp = exchange(&mut dev, 0, apci::MEMORY_READ, 1, &[0x01, 0x00], 0).expect("answered");
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
        let rsp = exchange(dev, seq, apci::PROPERTY_VALUE_WRITE, 0, &payload, 0).expect("property write answered");
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
    let rsp = exchange(&mut dev, seq, apci::PROPERTY_VALUE_READ, 0, &[3, 7, 0x10, 0x01], 0).expect("answered");
    assert_eq!(&apdu(&rsp)[6..10], &[0x00, 0x00, 0x01, 0x1E]);
}

#[test]
fn verify_mode_echoes_memory_writes() {
    let mut dev = device();
    connect(&mut dev);
    // Enable verify mode: PID_DEVICE_CONTROL bit 2.
    let rsp = exchange(&mut dev, 0, apci::PROPERTY_VALUE_WRITE, 0, &[0, 14, 0x10, 0x01, 0x04], 0).expect("answered");
    assert_eq!(apdu(&rsp)[6], 0x04, "device control readback");

    // A verified write answers with the bytes as stored.
    let rsp = exchange(&mut dev, 1, apci::MEMORY_WRITE, 2, &[0x01, 0x0D, 0x00, 0x00], 0);
    let rsp = rsp.expect("verify mode answers the write");
    assert_eq!(apdu(&rsp), &[0x46, 0x42, 0x01, 0x0D, 0x00, 0x00]);
    assert!(!dev.is_running(), "RunError 00h halts the application");

    // Clearing RunError back to FFh revives it.
    exchange(&mut dev, 2, apci::MEMORY_WRITE, 1, &[0x01, 0x0D, 0xFF], 0).expect("echoed");
    assert!(dev.is_running());
}

#[test]
fn restart_is_signalled_after_the_ack() {
    let mut dev = device();
    connect(&mut dev);
    let request = data_frame(0x00, CLIENT, DUT.0, false, tpci_numbered(0), apci::RESTART, 0, &[]);
    let out = dev.poll(PollInput::Frame(&request), 0);
    assert!(out.restart, "A_Restart must surface to the embedder");
    let ack = FrameView::parse(&out.frames[0]).expect("parsable");
    assert_eq!(ack.tpci(), Tpci::ControlAck { nak: false, seq: 0 });
}

#[test]
fn individual_address_write_needs_programming_mode() {
    let mut dev = device();
    let new_ia = IndividualAddress::new(2, 3, 4);
    let write = data_frame(0x00, CLIENT, [0, 0], true, 0x00, apci::INDIVIDUAL_ADDRESS_WRITE, 0, new_ia.as_bytes());
    dev.poll(PollInput::Frame(&write), 0);
    assert_eq!(dev.individual_address(), DUT, "ignored outside programming mode");

    dev.set_programming_mode(true);
    dev.poll(PollInput::Frame(&write), 0);
    assert_eq!(dev.individual_address(), new_ia);

    // And the read answers with a broadcast response.
    let read = data_frame(0x00, CLIENT, [0, 0], true, 0x00, apci::INDIVIDUAL_ADDRESS_READ, 0, &[]);
    let out = dev.poll(PollInput::Frame(&read), 0);
    let rsp = FrameView::parse(&out.frames[0]).expect("parsable");
    assert!(rsp.is_group);
    assert_eq!(rsp.source, new_ia);
    assert_eq!(rsp.apci(), Some(apci::INDIVIDUAL_ADDRESS_RESPONSE));
}

#[test]
fn group_write_updates_the_object_and_read_answers() {
    let mut dev = device();

    // A bus write to 1/0/1 lands in ASAP 0's RAM slot.
    let write =
        data_frame(0x0C, CLIENT, GroupAddress::from_three_level(1, 0, 1).0, true, 0x00, apci::GROUP_VALUE_WRITE, 1, &[
        ]);
    dev.poll(PollInput::Frame(&write), 0);
    let mut value = [0u8; 1];
    assert_eq!(dev.read_value(0, &mut value), 1);
    assert_eq!(value[0], 1);
    assert!(dev.object_flags(0) & zweidraehte_microdevice::co_flags::UPDATE != 0);

    // A read of 1/0/2 answers with ASAP 1's value.
    dev.write_value(1, &[1]);
    let read =
        data_frame(0x0C, CLIENT, GroupAddress::from_three_level(1, 0, 2).0, true, 0x00, apci::GROUP_VALUE_READ, 0, &[]);
    let out = dev.poll(PollInput::Frame(&read), 0);
    let rsp = FrameView::parse(&out.frames[0]).expect("parsable");
    assert!(rsp.is_group);
    assert_eq!(rsp.dest_group(), GroupAddress::from_three_level(1, 0, 2));
    assert_eq!(rsp.apci(), Some(apci::GROUP_VALUE_RESPONSE | 0x01));

    // A transmit request on ASAP 1 produces a group write on the next
    // timer tick.
    dev.set_transmit_request(1);
    let out = dev.poll(PollInput::Timer, 10);
    let tx = FrameView::parse(&out.frames[0]).expect("parsable");
    assert_eq!(tx.apci(), Some(apci::GROUP_VALUE_WRITE | 0x01));
    assert_eq!(tx.dest_group(), GroupAddress::from_three_level(1, 0, 2));
}

#[test]
fn halted_device_ignores_group_traffic() {
    let mut dev = device();
    dev.eeprom_image(); // silence unused-api lints in this test file
    // Halt via RunError.
    connect(&mut dev);
    exchange(&mut dev, 0, apci::MEMORY_WRITE, 1, &[0x01, 0x0D, 0x00], 0);
    let read =
        data_frame(0x0C, CLIENT, GroupAddress::from_three_level(1, 0, 2).0, true, 0x00, apci::GROUP_VALUE_READ, 0, &[]);
    let out = dev.poll(PollInput::Frame(&read), 0);
    assert!(out.frames.is_empty(), "halted devices answer no group reads");
}

#[test]
#[cfg(feature = "std")]
fn snapshot_round_trip_preserves_persistent_state() {
    use zweidraehte_microdevice::snapshot::MicroSnapshot;
    let mut dev = device();
    connect(&mut dev);
    exchange(&mut dev, 0, apci::MEMORY_WRITE, 1, &[0x01, 0x1B, 0x42], 0);
    let snap = MicroSnapshot::capture(&dev);
    let bytes = postcard::to_allocvec(&snap).expect("serializes");
    let back: MicroSnapshot = postcard::from_bytes(&bytes).expect("deserializes");
    let identity = DeviceIdentity { serial_number: [0; 6], order_info: [0; 10], hardware_type: [0; 6] };
    let restored: Microdevice<Bcu2Family> = back.restore(identity, 1);
    assert_eq!(restored.eeprom_image()[0x1B], 0x42);
    assert_eq!(restored.mgmt.lsm[2].state, LoadState::Loaded);
    assert!(!restored.is_programming_mode(), "RAM state does not survive");
}
