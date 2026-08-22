//! End-to-end conversations against the BCU1 micro stack: the
//! MV-0012-shaped management dialogue — plain memory access with
//! client-side read-back, none of the BCU2 services — and the group
//! communication paths over the RT1 tables, driven frame-by-frame the
//! way the bus would.

mod common;
use common::{CLIENT, DUT, apdu, canonical, connect, exchange};

use zweidraehte_microdevice::device::{DeviceIdentity, Microdevice, PollInput};
use zweidraehte_microdevice::families::bcu1::{Bcu1CoDescriptor, Bcu1DeviceDefinition, Bcu1Family};
use zweidraehte_microdevice::frame::{ApciCode, FrameView, MAX_FRAME, Tpci, data_frame, to_wire};
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

static COS: &[Bcu1CoDescriptor] = &[
    // ASAP 0: 1-bit switch input, write+update enabled. RT1 keeps
    // config bit 7 fixed at 1.
    Bcu1CoDescriptor { data_ptr: 0xCE, config: 0x9F, value_type: 0x00 },
    // ASAP 1: 1-bit status output, transmit+read enabled (bit 7 set as
    // RT1 requires).
    Bcu1CoDescriptor { data_ptr: 0xCF, config: 0xCF, value_type: 0x00 },
];

static GAS: &[GroupAddress] = &[GroupAddress::from_three_level(1, 0, 1), GroupAddress::from_three_level(1, 0, 2)];

fn definition() -> Bcu1DeviceDefinition {
    Bcu1DeviceDefinition {
        app_manufacturer: 0x83,
        device_type: 0x1234,
        version: 1,
        pei_type: 0,
        individual_address: DUT,
        max_group_addresses: 4,
        max_associations: 4,
        ram_flags_ptr: 0xD7,
        comm_objects: COS,
        group_addresses: GAS,
        associations: &[(1, 0), (2, 1)],
    }
}

fn device() -> Microdevice<Bcu1Family> {
    // No load states to seed: a BCU1 image with DevTyp ≠ 0 and
    // RunError FFh simply is a programmed device.
    let def = definition();
    let identity = DeviceIdentity { serial_number: [0, 0x83, 0, 0, 0, 1], order_info: [0; 10], hardware_type: [0; 6] };
    Microdevice::new(def.build_eeprom(), identity, 1)
}

#[test]
fn dd0_answers_and_bcu2_services_are_ignored() {
    let mut dev = device();
    connect(&mut dev);

    // DD0 → 0012h.
    let rsp = exchange(&mut dev, 0, ApciCode::DeviceDescriptorRead, 0, &[], 0).expect("DD0 answered");
    assert_eq!(apdu(&rsp), &[0x43, 0x40, 0x00, 0x12]);

    // A_Authorize, A_Key_Write and the property services are BCU2
    // additions this mask does not decode: T_ACK, no reply.
    let rsp = exchange(&mut dev, 1, ApciCode::AuthorizeRequest, 0, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF], 0);
    assert!(rsp.is_none(), "no A_Authorize on BCU1");
    let rsp = exchange(&mut dev, 2, ApciCode::KeyWrite, 0, &[0x00, 0x11, 0x22, 0x33, 0x44], 0);
    assert!(rsp.is_none(), "no A_Key_Write on BCU1");
    let rsp = exchange(&mut dev, 3, ApciCode::PropertyValueRead, 0, &[0, 14, 0x10, 0x01], 0);
    assert!(rsp.is_none(), "no property services on BCU1");
    let rsp = exchange(&mut dev, 4, ApciCode::PropertyDescriptionRead, 0, &[0, 14, 0], 0);
    assert!(rsp.is_none(), "no property services on BCU1");

    // A_ADC_Read is BCU1-era and does answer (liveness probe).
    let rsp = exchange(&mut dev, 5, ApciCode::AdcRead, 1, &[0x08], 0).expect("ADC answered");
    assert_eq!(apdu(&rsp)[2], 0x08, "read count echoed");
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
fn memory_write_lands_and_the_device_maintains_ee_exor() {
    let mut dev = device();
    connect(&mut dev);

    // The boot image seeds a checksum consistent with its contents.
    let rsp = exchange(&mut dev, 0, ApciCode::MemoryRead, 1, &[0x01, 0xFF], 0).expect("answered");
    let seeded = apdu(&rsp)[4];
    let expected: u8 = dev.eeprom_image()[0x08..0xFF].iter().fold(0, |x, &b| x ^ b);
    assert_eq!(seeded, expected, "EE_EXOR covers 0108h..(CheckLim-1)");

    // A write inside the checked range lands (no echo — BCU1 verify is
    // the client reading back) and the checksum follows it. 0180h is a
    // factory-zero cell behind the tables.
    let rsp = exchange(&mut dev, 1, ApciCode::MemoryWrite, 1, &[0x01, 0x80, 0x42], 0);
    assert!(rsp.is_none(), "no verify-mode echo on BCU1");
    let rsp = exchange(&mut dev, 2, ApciCode::MemoryRead, 1, &[0x01, 0x80], 0).expect("answered");
    assert_eq!(apdu(&rsp)[4], 0x42, "client read-back sees the write");
    let rsp = exchange(&mut dev, 3, ApciCode::MemoryRead, 1, &[0x01, 0xFF], 0).expect("answered");
    assert_eq!(apdu(&rsp)[4], seeded ^ 0x42, "checksum updated with the delta");
}

#[test]
fn address_table_length_1_mutes_group_traffic() {
    let mut dev = device();

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
    assert!(!out.frames.is_empty(), "programmed device answers the group read");

    // The download mutes the device by writing GA-table length 1
    // ("IA only") at 0116h.
    connect(&mut dev);
    exchange(&mut dev, 0, ApciCode::MemoryWrite, 1, &[0x01, 0x16, 0x01], 0);
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&read)), 0);
    assert!(out.frames.is_empty(), "length 1 accepts no group frames");

    // Restoring the length unmutes.
    exchange(&mut dev, 1, ApciCode::MemoryWrite, 1, &[0x01, 0x16, 0x03], 0);
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&read)), 0);
    assert!(!out.frames.is_empty());
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
fn app_presence_and_run_error_gate_group_traffic() {
    let mut dev = device();
    assert!(dev.is_running());
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

    // The unload sequence zeroes DevTyp + Version — with no load state
    // machines, DevTyp ≠ 0 is what "application present" means.
    connect(&mut dev);
    exchange(&mut dev, 0, ApciCode::MemoryWrite, 3, &[0x01, 0x05, 0x00, 0x00, 0x00], 0);
    assert!(!dev.is_running(), "DevTyp 0 un-marks the application");
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&read)), 0);
    assert!(out.frames.is_empty(), "unloaded devices answer no group reads");

    // Restore DevTyp, halt via RunError instead.
    exchange(&mut dev, 1, ApciCode::MemoryWrite, 2, &[0x01, 0x05, 0x12, 0x34], 0);
    assert!(dev.is_running());
    exchange(&mut dev, 2, ApciCode::MemoryWrite, 1, &[0x01, 0x0D, 0x00], 0);
    assert!(!dev.is_running(), "RunError 00h halts the application");
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&read)), 0);
    assert!(out.frames.is_empty(), "halted devices answer no group reads");
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
#[cfg(feature = "std")]
fn snapshot_round_trip_preserves_persistent_state() {
    use zweidraehte_microdevice::snapshot::MicroSnapshot;
    let mut dev = device();
    connect(&mut dev);
    exchange(&mut dev, 0, ApciCode::MemoryWrite, 1, &[0x01, 0x19, 0x42], 0);
    let snap = MicroSnapshot::capture(&dev);
    let bytes = postcard::to_allocvec(&snap).expect("serializes");
    let back: MicroSnapshot = postcard::from_bytes(&bytes).expect("deserializes");
    let identity = DeviceIdentity { serial_number: [0; 6], order_info: [0; 10], hardware_type: [0; 6] };
    let restored: Microdevice<Bcu1Family> = back.restore(identity, 1);
    assert_eq!(restored.eeprom_image()[0x19], 0x42);
    assert!(!restored.is_programming_mode(), "RAM state does not survive");
}
