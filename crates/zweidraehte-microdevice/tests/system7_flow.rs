//! End-to-end conversations against the System 7 micro stack: the
//! 0705h management dialogue over both load-control paths, the run
//! state machine, and RT8 group communication, driven frame-by-frame
//! the way the bus would.

mod common;
use common::{CLIENT, DUT, apdu, connect, exchange};

use zweidraehte_microdevice::device::{DeviceIdentity, Microdevice, PollInput};
use zweidraehte_microdevice::families::system7::{System7CoDescriptor, System7DeviceDefinition, System7Family};
use zweidraehte_microdevice::frame::{ApciCode, FrameView, Tpci, data_frame};
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::messages::apdu::load_control::{AbsSegment, LoadControlRecord, LoadState, RunState};

/// The DUT product: 1 KiB of user EEPROM from 4000h, the group object
/// table published at 4200h.
type Fam = System7Family<0x400, 0x4200>;

static COS: &[System7CoDescriptor] = &[
    // ASAP 0: 1-bit switch input, write+update enabled.
    System7CoDescriptor { data_ptr: 0x00C6, config: 0x9F, value_type: 0x00 },
    // ASAP 1: 1-bit status output, transmit+read enabled.
    System7CoDescriptor { data_ptr: 0x00C7, config: 0x4F, value_type: 0x00 },
];

static GAS: &[GroupAddress] = &[GroupAddress::from_three_level(1, 0, 1), GroupAddress::from_three_level(1, 0, 2)];

fn definition() -> System7DeviceDefinition {
    System7DeviceDefinition {
        manufacturer_id: 0x0083,
        device_type: 0x0705,
        version: 1,
        individual_address: DUT,
        max_group_addresses: 8,
        max_associations: 8,
        ram_flags_ptr: 0x00D0,
        comm_objects: COS,
        group_addresses: GAS,
        associations: &[(1, 0), (2, 1)],
        ast_offset: 0x100,
        app_offset: 0x300,
        app_params: &[],
    }
}

fn device() -> Microdevice<Fam> {
    let def = definition();
    let identity = DeviceIdentity {
        serial_number: [0, 0x83, 0x07, 0x05, 0, 1],
        order_info: [0; 10],
        hardware_type: [0, 0x83, 0, 0, 0x07, 0x05],
    };
    let mut dev = Microdevice::new(Fam::build_eeprom(&def), identity, 1);
    // Factory image with the tables and application marked loaded,
    // like a programmed device fresh off the line. App2 stays empty.
    for (machine, table_ref) in Fam::factory_table_refs(&def).into_iter().enumerate().take(3) {
        dev.mgmt.lsm[machine].state = LoadState::Loaded;
        dev.mgmt.lsm[machine].table_ref = table_ref;
    }
    dev
}

#[test]
fn dd0_and_sixteen_level_authorization() {
    let mut dev = device();
    connect(&mut dev);

    // DD0 → 0705h.
    let rsp = exchange(&mut dev, 0, ApciCode::DeviceDescriptorRead, 0, &[], 0).expect("DD0 answered");
    assert_eq!(apdu(&rsp), &[0x43, 0x40, 0x07, 0x05]);

    // Factory FF key → level 0; a wrong key → free access level 15.
    let rsp =
        exchange(&mut dev, 1, ApciCode::AuthorizeRequest, 0, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF], 0).expect("answered");
    assert_eq!(apdu(&rsp)[2], 0x00, "granted level 0");
    let rsp =
        exchange(&mut dev, 2, ApciCode::AuthorizeRequest, 0, &[0x00, 0x12, 0x34, 0x56, 0x78], 0).expect("answered");
    assert_eq!(apdu(&rsp)[2], 0x0F, "wrong key falls to free level 15");

    // A_Key_Write to the free level is refused with FFh: level 15 owns
    // no key by construction.
    let rsp = exchange(&mut dev, 3, ApciCode::KeyWrite, 0, &[0x0F, 0x01, 0x02, 0x03, 0x04], 0).expect("answered");
    assert_eq!(apdu(&rsp)[2], 0xFF, "the free level cannot be keyed");
}

#[test]
fn option_reg_is_plain_and_lives_at_0100h() {
    let mut dev = device();
    connect(&mut dev);
    // Factory reads 00h (unlike BCU2's inverted FFh) and a write reads
    // back uninverted.
    let rsp = exchange(&mut dev, 0, ApciCode::MemoryRead, 1, &[0x01, 0x00], 0).expect("answered");
    assert_eq!(apdu(&rsp)[4], 0x00);
    exchange(&mut dev, 1, ApciCode::MemoryWrite, 1, &[0x01, 0x00, 0x55], 0);
    let rsp = exchange(&mut dev, 2, ApciCode::MemoryRead, 1, &[0x01, 0x00], 0).expect("answered");
    assert_eq!(apdu(&rsp)[4], 0x55);
}

#[test]
fn memory_mapped_lsm_cycle_on_app2() {
    let mut dev = device();
    connect(&mut dev);
    let mut seq = 0u8;
    fn mem_write(dev: &mut Microdevice<Fam>, seq: &mut u8, addr: u16, data: &[u8]) {
        let mut payload = addr.to_be_bytes().to_vec();
        payload.extend_from_slice(data);
        exchange(dev, *seq, ApciCode::MemoryWrite, data.len() as u8, &payload, 0);
        *seq = (*seq + 1) & 0x0F;
    }

    // StartLoading machine 4 (App2) through the 0104h window.
    mem_write(&mut dev, &mut seq, 0x0104, &[0x41]);
    assert_eq!(dev.mgmt.lsm[3].state, LoadState::Loading);

    // AllocAbsDataSeg in the memory spelling: the segment ID octet
    // rides between segment type and start address and must be
    // stripped before the shared parser sees the record.
    let prop_record = LoadControlRecord::abs_segment(&AbsSegment::eeprom(0x4300, 0x0040));
    let mut mem_record = vec![0x43, prop_record[1], 0x00];
    mem_record.extend_from_slice(&prop_record[2..]);
    mem_write(&mut dev, &mut seq, 0x0104, &mem_record);
    assert_eq!(dev.mgmt.lsm[3].state, LoadState::Loading);
    assert_eq!(dev.mgmt.lsm[3].table_ref, 0x4300);

    // LoadCompleted, then read the four status bytes at B6EAh:
    // ADT/AST/App Loaded, App2 now Loaded too.
    mem_write(&mut dev, &mut seq, 0x0104, &[0x42]);
    let rsp = exchange(&mut dev, seq, ApciCode::MemoryRead, 4, &[0xB6, 0xEA], 0).expect("status answered");
    assert_eq!(&apdu(&rsp)[4..8], &[0x01, 0x01, 0x01, 0x01]);
    seq = (seq + 1) & 0x0F;

    // PID_TABLE_REFERENCE on object 4 reads the allocated address.
    let rsp = exchange(&mut dev, seq, ApciCode::PropertyValueRead, 0, &[4, 7, 0x10, 0x01], 0).expect("answered");
    assert_eq!(&apdu(&rsp)[6..10], &[0x00, 0x00, 0x43, 0x00]);
    seq = (seq + 1) & 0x0F;

    // Unload through the window; the status byte drops to Unloaded.
    mem_write(&mut dev, &mut seq, 0x0104, &[0x44]);
    let rsp = exchange(&mut dev, seq, ApciCode::MemoryRead, 4, &[0xB6, 0xEA], 0).expect("status answered");
    assert_eq!(&apdu(&rsp)[4..8], &[0x01, 0x01, 0x01, 0x00]);

    // The status bytes are write-protected.
    mem_write(&mut dev, &mut seq, 0xB6EA, &[0x05]);
    assert_eq!(dev.mgmt.lsm[0].state, LoadState::Loaded);
}

#[test]
fn property_path_lsm_still_works() {
    let mut dev = device();
    connect(&mut dev);
    // Unload the ADT via PID_LOAD_STATE_CONTROL on object 1 — the ETS
    // path. The RT8 count byte collapses to 0 and mutes the device;
    // the IA survives.
    let rsp =
        exchange(&mut dev, 0, ApciCode::PropertyValueWrite, 0, &[1, 5, 0x10, 0x01, 0x04], 0).expect("write answered");
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Unloaded));
    assert_eq!(dev.eeprom_image()[0], 0, "GA count zeroed");
    assert_eq!(dev.individual_address(), DUT, "the IA survives the unload");

    let read = data_frame(
        0x0C,
        CLIENT,
        GroupAddress::from_three_level(1, 0, 2).0,
        true,
        Tpci::DataGroup,
        ApciCode::GroupValueRead,
        0,
        &[],
    );
    let out = dev.poll(PollInput::Frame(&read), 0);
    assert!(out.frames.is_empty(), "a muted device answers no group reads");
}

#[test]
fn run_state_stop_terminates_instead_of_halting() {
    let mut dev = device();
    connect(&mut dev);

    // Loaded application reads Running.
    let rsp = exchange(&mut dev, 0, ApciCode::PropertyValueRead, 0, &[3, 6, 0x10, 0x01], 0).expect("answered");
    assert_eq!(apdu(&rsp)[6], u8::from(RunState::Running));

    // RUNCONTROL_STOP → Terminated (03/05/01 §4.24.2.3.3 Table 97:
    // no HALTED intermediate reachable from the bus on this profile),
    // and group traffic stops.
    let rsp = exchange(&mut dev, 1, ApciCode::PropertyValueWrite, 0, &[3, 6, 0x10, 0x01, 0x02], 0).expect("answered");
    assert_eq!(apdu(&rsp)[6], u8::from(RunState::Terminated));
    assert!(!dev.is_running());
    let read = data_frame(
        0x0C,
        CLIENT,
        GroupAddress::from_three_level(1, 0, 2).0,
        true,
        Tpci::DataGroup,
        ApciCode::GroupValueRead,
        0,
        &[],
    );
    let out = dev.poll(PollInput::Frame(&read), 0);
    assert!(out.frames.is_empty(), "a terminated application answers no group reads");

    // RUNCONTROL_RESTART revives it.
    let rsp = exchange(&mut dev, 2, ApciCode::PropertyValueWrite, 0, &[3, 6, 0x10, 0x01, 0x01], 0).expect("answered");
    assert_eq!(apdu(&rsp)[6], u8::from(RunState::Running));
    assert!(dev.is_running());

    // The unloaded App2 reads Halted.
    let rsp = exchange(&mut dev, 3, ApciCode::PropertyValueRead, 0, &[4, 6, 0x10, 0x01], 0).expect("answered");
    assert_eq!(apdu(&rsp)[6], u8::from(RunState::Halted));
}

#[test]
fn individual_address_write_lands_in_the_adt() {
    let mut dev = device();
    let new_ia = IndividualAddress::new(2, 3, 4);
    let write =
        data_frame(0x00, CLIENT, [0, 0], true, Tpci::DataGroup, ApciCode::IndividualAddressWrite, 0, new_ia.as_bytes());
    dev.poll(PollInput::Frame(&write), 0);
    assert_eq!(dev.individual_address(), DUT, "ignored outside programming mode");

    dev.set_programming_mode(true);
    dev.poll(PollInput::Frame(&write), 0);
    assert_eq!(dev.individual_address(), new_ia);
    // RT8 defines the IA as ADT bytes 1–2 (4001h–4002h).
    assert_eq!(&dev.eeprom_image()[1..3], new_ia.as_bytes());
}

#[test]
fn rt8_group_communication() {
    let mut dev = device();

    // A bus write to 1/0/1 lands in ASAP 0's RAM slot.
    let write = data_frame(
        0x0C,
        CLIENT,
        GroupAddress::from_three_level(1, 0, 1).0,
        true,
        Tpci::DataGroup,
        ApciCode::GroupValueWrite,
        1,
        &[],
    );
    dev.poll(PollInput::Frame(&write), 0);
    let mut value = [0u8; 1];
    assert_eq!(dev.read_value(0, &mut value), 1);
    assert_eq!(value[0], 1);

    // A transmit request on ASAP 1 produces a group write through its
    // sending association on the next timer tick.
    dev.write_value(1, &[1]);
    dev.set_transmit_request(1);
    let out = dev.poll(PollInput::Timer, 10);
    let tx = FrameView::parse(&out.frames[0]).expect("parsable");
    assert_eq!(tx.apci(), Some(ApciCode::GroupValueWrite.wire10_base() | 0x01));
    assert_eq!(tx.dest_group(), GroupAddress::from_three_level(1, 0, 2));
}

#[test]
#[cfg(feature = "std")]
fn snapshot_round_trip_preserves_option_reg() {
    use zweidraehte_microdevice::snapshot::MicroSnapshot;
    let mut dev = device();
    connect(&mut dev);
    exchange(&mut dev, 0, ApciCode::MemoryWrite, 1, &[0x01, 0x00, 0x5A], 0);
    let snap = MicroSnapshot::capture(&dev);
    let bytes = postcard::to_allocvec(&snap).expect("serializes");
    let back: MicroSnapshot = postcard::from_bytes(&bytes).expect("deserializes");
    let identity = DeviceIdentity { serial_number: [0; 6], order_info: [0; 10], hardware_type: [0; 6] };
    let restored: Microdevice<Fam> = back.restore(identity, 1);
    assert_eq!(restored.mgmt.option_reg, 0x5A);
    assert_eq!(restored.mgmt.lsm[2].state, LoadState::Loaded);
    assert_eq!(restored.individual_address(), DUT);
}
