//! End-to-end conversations against the System 7 micro stack: the
//! 0705h management dialogue over both load-control paths, the run
//! state machine, and RT8 group communication, driven frame-by-frame
//! the way the bus would.

mod common;
use common::{CLIENT, DUT, apdu, canonical, connect, data_frame, exchange, to_wire};

use zweidraehte_microdevice::MemoryAccessPolicy;
use zweidraehte_microdevice::device::{DeviceIdentity, Microdevice, PollInput};
use zweidraehte_microdevice::families::system7::{System7CoDescriptor, System7DeviceDefinition, System7Family};
use zweidraehte_microdevice::frame::{ApciCode, EXTENDED_FRAME, FrameView, MAX_FRAME, Tpci, max_apdu, normalize};
use zweidraehte_proto::access::AccessLevel;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::encoding::tp1::{NPCI_HOP_COUNT_6, TP1_STD_CTRL_BASE};
use zweidraehte_proto::memory::{MemoryPermission, MemoryRegion};
use zweidraehte_proto::messages::apdu::load_control::{AbsSegment, LoadControlRecord, LoadState, RunState};
use zweidraehte_proto::pid;

/// The DUT product: 1 KiB of user EEPROM from 4000h, the group object
/// table published at 4200h.
type Fam = System7Family<0x400, 0x4200, 0x0083, 0x0705, 1, 0>;

/// Test-only policy mirroring the conformance fixture's adjacent open,
/// direction-protected, and level-guarded regions. Keeping it here proves
/// that a product can select protection without putting fixture addresses in
/// the shipping System 7 profile.
struct ProtectedMemoryPolicy;

impl MemoryAccessPolicy for ProtectedMemoryPolicy {
    const REGIONS: &'static [MemoryRegion] = &[
        MemoryRegion::open(0x0000, 0x100),
        MemoryRegion::open(0x0100, 1),
        MemoryRegion::open(0x0104, 12),
        MemoryRegion::open(0x0700, 0x100),
        MemoryRegion::open(0x4000, 0x400),
        MemoryRegion::open(0x4400, 0x100),
        MemoryRegion::read_only(0x4500, 0x10, MemoryPermission::Open),
        MemoryRegion::write_only(0x4510, 0x10, MemoryPermission::Open),
        MemoryRegion::new(
            0x4520,
            0xE0,
            MemoryPermission::Level(AccessLevel::Configuration),
            MemoryPermission::Level(AccessLevel::Configuration),
        ),
        MemoryRegion::new(
            0x4600,
            0x100,
            MemoryPermission::Level(AccessLevel::ProductManufacturer),
            MemoryPermission::Level(AccessLevel::ProductManufacturer),
        ),
        MemoryRegion::read_only(0xB6EA, 4, MemoryPermission::Open),
    ];
}

type ProtectedFam = System7Family<0x700, 0x4200, 0x0083, 0x0705, 1, 0, ProtectedMemoryPolicy>;

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
        pei_type: 0,
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

fn identity() -> DeviceIdentity {
    DeviceIdentity {
        serial_number: [0, 0x83, 0x07, 0x05, 0, 1],
        order_info: [0; 10],
        hardware_type: [0, 0x83, 0, 0, 0x07, 0x05],
    }
}

fn device() -> Microdevice<Fam> {
    let def = definition();
    let mut dev = Microdevice::new(Fam::build_eeprom(&def), identity(), 1);
    // Factory image with the tables and application marked loaded,
    // like a programmed device fresh off the line. The optional interface
    // program stays empty.
    for (machine, table_ref) in Fam::factory_table_refs(&def).into_iter().enumerate().take(3) {
        dev.mgmt.lsm[machine].state = LoadState::Loaded;
        dev.mgmt.lsm[machine].table_ref = table_ref;
    }
    dev
}

fn protected_memory_device() -> Microdevice<ProtectedFam> {
    let mut eeprom = ProtectedFam::build_eeprom(&definition());
    eeprom[0x400] = 0x0F;
    eeprom[0x4FF] = 0x22;
    eeprom[0x500] = 0x11;
    eeprom[0x520] = 0xAA;
    eeprom[0x600] = 0xFF;
    let mut dev = Microdevice::new(eeprom, identity(), 1);
    dev.mgmt.auth_keys[0] = [0xAA; 4];
    dev.mgmt.auth_keys[1] = [0xBB; 4];
    dev.mgmt.reset_connection_auth::<ProtectedFam>();
    assert_eq!(dev.mgmt.auth_level, 2, "the default key grants configuration access");
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
fn property_descriptions_and_values_share_one_roster() {
    let mut dev = device();
    connect(&mut dev);

    // By-PID lookup returns the roster index, not the request's placeholder
    // index. DeviceControl deliberately shares index 1 and its descriptor
    // with the full System 7 stack.
    let rsp = exchange(&mut dev, 0, ApciCode::PropertyDescriptionRead, 0, &[0, 14, 0], 0).expect("described");
    assert_eq!(&apdu(&rsp)[2..], &[0x00, 0x0E, 0x01, 0xB3, 0x30, 0x01, 0x33]);

    // The same roster entry selects the value behavior.
    let rsp = exchange(&mut dev, 1, ApciCode::PropertyValueRead, 0, &[0, 14, 0x10, 0x01], 0).expect("read");
    assert_eq!(&apdu(&rsp)[6..], &[0x00]);

    // By-index enumeration returns the actual PID and metadata for a
    // family-backed value. HardwareType is index 3 in the compact roster.
    let rsp = exchange(&mut dev, 2, ApciCode::PropertyDescriptionRead, 0, &[0, 0, 3], 0).expect("enumerated");
    assert_eq!(&apdu(&rsp)[2..], &[0x00, 0x4E, 0x03, 0x96, 0x60, 0x01, 0x31]);
    let rsp = exchange(&mut dev, 3, ApciCode::PropertyValueRead, 0, &[0, 78, 0x10, 0x01], 0).expect("read");
    assert_eq!(&apdu(&rsp)[6..], &[0x00, 0x83, 0x00, 0x00, 0x07, 0x05]);

    // A family-backed property that used to be readable but described as
    // nonexistent now carries its real descriptor.
    let rsp = exchange(&mut dev, 4, ApciCode::PropertyDescriptionRead, 0, &[0, 56, 0], 0).expect("described");
    assert_eq!(&apdu(&rsp)[2..], &[0x00, 0x38, 0x07, 0x04, 0x40, 0x01, 0x30]);
    let rsp = exchange(&mut dev, 5, ApciCode::PropertyValueRead, 0, &[0, 56, 0x10, 0x01], 0).expect("read");
    assert_eq!(&apdu(&rsp)[6..], &15u16.to_be_bytes());

    // Annex A.2.3 makes Manufacturer ID mandatory for MV-0705. It is
    // compile-time product identity, but still participates in the same
    // enumerable roster as stored values.
    let rsp = exchange(&mut dev, 6, ApciCode::PropertyDescriptionRead, 0, &[0, 12, 0], 0).expect("described");
    assert_eq!(&apdu(&rsp)[2..], &[0x00, 0x0C, 0x08, 0x04, 0x40, 0x01, 0x30]);
    let rsp = exchange(&mut dev, 7, ApciCode::PropertyValueRead, 0, &[0, 12, 0x10, 0x01], 0).expect("read");
    assert_eq!(&apdu(&rsp)[6..], &[0x00, 0x83]);

    // The two address components share the same virtual IA backing as the
    // RT8 address table and the full System 7 Device Object.
    let rsp = exchange(&mut dev, 8, ApciCode::PropertyValueRead, 0, &[0, 57, 0x10, 0x01], 0).expect("read");
    assert_eq!(&apdu(&rsp)[6..], &[DUT.0[0]]);
    let rsp = exchange(&mut dev, 9, ApciCode::PropertyValueRead, 0, &[0, 58, 0x10, 0x01], 0).expect("read");
    assert_eq!(&apdu(&rsp)[6..], &[DUT.0[1]]);

    // Unknown PID lookup and an exhausted index scan both return the
    // zero-descriptor form, with the caller's lookup key preserved.
    let rsp = exchange(&mut dev, 10, ApciCode::PropertyDescriptionRead, 0, &[0, 0xFE, 0], 0).expect("negative reply");
    assert_eq!(&apdu(&rsp)[2..], &[0x00, 0xFE, 0x00, 0, 0, 0, 0]);
    let rsp = exchange(&mut dev, 11, ApciCode::PropertyDescriptionRead, 0, &[0, 0, 11], 0).expect("end of roster");
    assert_eq!(&apdu(&rsp)[2..], &[0x00, 0x00, 0x0B, 0, 0, 0, 0]);

    // A negative value response keeps the complete 12-bit start index;
    // only the count nibble is cleared. This catches payload/header codecs
    // that accidentally zero the entire packed high octet.
    let rsp =
        exchange(&mut dev, 12, ApciCode::PropertyValueWrite, 0, &[0, 0xFE, 0x1A, 0xBC, 0], 0).expect("negative reply");
    assert_eq!(&apdu(&rsp)[2..], &[0x00, 0xFE, 0x0A, 0xBC]);
}

#[test]
fn mandatory_system7_program_properties_and_table_reference_are_backed() {
    let mut dev = device();
    connect(&mut dev);

    let rsp = exchange(&mut dev, 0, ApciCode::PropertyValueRead, 0, &[3, 13, 0x10, 0x01], 0).expect("read");
    assert_eq!(&apdu(&rsp)[6..], &[0x00, 0x83, 0x07, 0x05, 0x01]);

    let rsp = exchange(&mut dev, 1, ApciCode::PropertyValueRead, 0, &[3, 16, 0x10, 0x01], 0).expect("read");
    assert_eq!(&apdu(&rsp)[6..], &[0x00]);

    let rsp =
        exchange(&mut dev, 2, ApciCode::AuthorizeRequest, 0, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF], 0).expect("authorized");
    assert_eq!(apdu(&rsp)[2], 0);

    let rsp =
        exchange(&mut dev, 3, ApciCode::PropertyValueWrite, 0, &[1, 7, 0x10, 0x01, 0, 0, 0x44, 0], 0).expect("write");
    assert_eq!(&apdu(&rsp)[6..], &[0, 0, 0x44, 0]);
    assert_eq!(dev.mgmt.lsm[0].table_ref, 0x4400);

    let rsp = exchange(&mut dev, 4, ApciCode::PropertyValueRead, 0, &[1, 7, 0x10, 0x01], 0).expect("read");
    assert_eq!(&apdu(&rsp)[6..], &[0, 0, 0x44, 0]);

    // Hardware Type is the remaining mandatory MV-0705 identity Property.
    // Unlike Program Version and PEI Type, Annex A.2.3 requires a write at
    // product-manufacturer level rather than merely permitting one.
    let hardware_type = [0x00, 0x83, 0x12, 0x34, 0x56, 0x78];
    let mut write = [0u8; 10];
    write[..4].copy_from_slice(&[0, 78, 0x10, 0x01]);
    write[4..].copy_from_slice(&hardware_type);
    let rsp = exchange(&mut dev, 5, ApciCode::PropertyValueWrite, 0, &write, 0).expect("write");
    assert_eq!(&apdu(&rsp)[6..], &hardware_type);
    assert_eq!(dev.hardware_type(), &hardware_type);
}

#[test]
fn property_access_is_request_scoped() {
    let mut dev = device();

    // Move the default FFFFFFFFh key below DeviceControl's write level 3,
    // while keeping a distinct level-0 key for the connected tool.
    dev.mgmt.auth_keys[0] = [0xAA; 4];
    dev.mgmt.auth_keys[1] = [0xBB; 4];
    dev.mgmt.auth_keys[2] = [0xCC; 4];
    dev.mgmt.auth_keys[3] = [0xDD; 4];
    dev.mgmt.reset_connection_auth::<Fam>();
    assert_eq!(dev.mgmt.auth_level, 4, "the default key now grants level 4");

    // A_Authorize is connection-oriented. An unnumbered request neither
    // answers nor changes the level the next connection starts with.
    let authorize =
        data_frame::<MAX_FRAME>(0x00, CLIENT, DUT.0, false, Tpci::DataIndividual, ApciCode::AuthorizeRequest, 0, &[
            0x00, 0xAA, 0xAA, 0xAA, 0xAA,
        ]);
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&authorize)), 0);
    assert!(out.frames.is_empty(), "connectionless authorize is ignored");
    assert_eq!(dev.mgmt.auth_level, 4);

    connect(&mut dev);
    let rsp =
        exchange(&mut dev, 0, ApciCode::AuthorizeRequest, 0, &[0x00, 0xAA, 0xAA, 0xAA, 0xAA], 0).expect("authorized");
    assert_eq!(apdu(&rsp)[2], 0, "the connected tool gets level 0");

    // A connectionless write uses the default-key level, not the active
    // connection's level 0, and is therefore denied with count zero.
    let write =
        data_frame::<MAX_FRAME>(0x00, CLIENT, DUT.0, false, Tpci::DataIndividual, ApciCode::PropertyValueWrite, 0, &[
            0, 14, 0x10, 0x01, 0x04,
        ]);
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&write)), 0);
    assert_eq!(out.frames.len(), 1);
    let view_frame = canonical(&out.frames[0]);
    let view = FrameView::parse(&view_frame).expect("parsable response");
    assert_eq!(view.tpci(), Some(Tpci::DataIndividual));
    assert_eq!(&apdu(&out.frames[0])[2..], &[0, 14, 0, 1]);
    assert_eq!(dev.mgmt.device_control, 0, "denied write has no side effect");

    // The same write succeeds through the authorized connection.
    let rsp =
        exchange(&mut dev, 1, ApciCode::PropertyValueWrite, 0, &[0, 14, 0x10, 0x01, 0x04], 0).expect("write answered");
    assert_eq!(apdu(&rsp)[6], 0x04);
    assert_eq!(dev.mgmt.device_control, 0x04);
}

#[test]
fn memory_access_is_region_and_connection_scoped() {
    let mut dev = protected_memory_device();

    // A_Memory services are connection-oriented even on System 7, whose
    // device-oriented property services also accept unnumbered requests.
    let unnumbered =
        data_frame::<MAX_FRAME>(0x00, CLIENT, DUT.0, false, Tpci::DataIndividual, ApciCode::MemoryRead, 1, &[
            0x45, 0x20,
        ]);
    assert!(dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&unnumbered)), 0).frames.is_empty());

    connect(&mut dev);

    // The default key grants level 2: the configuration block is visible,
    // while the product-manufacturer block answers with count zero.
    let rsp = exchange(&mut dev, 0, ApciCode::MemoryRead, 1, &[0x45, 0x20], 0).expect("level-2 read answered");
    assert_eq!(apdu(&rsp)[4], 0xAA);
    let rsp = exchange(&mut dev, 1, ApciCode::MemoryRead, 1, &[0x46, 0x00], 0).expect("denial answered");
    assert_eq!(apdu(&rsp)[1] & 0x3F, 0);

    // Verify mode makes rejected writes observable without changing memory.
    dev.mgmt.device_control = 0x04;
    let rsp = exchange(&mut dev, 2, ApciCode::MemoryWrite, 1, &[0x46, 0x00, 0x55], 0).expect("denial answered");
    assert_eq!(apdu(&rsp)[1] & 0x3F, 0);
    assert_eq!(dev.eeprom_image()[0x600], 0xFF);

    let rsp = exchange(&mut dev, 3, ApciCode::MemoryRead, 1, &[0x45, 0x00], 0).expect("read-only region read");
    assert_eq!(apdu(&rsp)[4], 0x11);
    let rsp = exchange(&mut dev, 4, ApciCode::MemoryWrite, 1, &[0x45, 0x00, 0x33], 0).expect("read-only denial");
    assert_eq!(apdu(&rsp)[1] & 0x3F, 0);
    assert_eq!(dev.eeprom_image()[0x500], 0x11);

    let rsp = exchange(&mut dev, 5, ApciCode::MemoryRead, 1, &[0x45, 0x10], 0).expect("write-only denial");
    assert_eq!(apdu(&rsp)[1] & 0x3F, 0);
    let rsp = exchange(&mut dev, 6, ApciCode::MemoryWrite, 1, &[0x45, 0x10, 0x44], 0).expect("write confirmed");
    assert_eq!(apdu(&rsp)[1] & 0x3F, 1);
    assert_eq!(apdu(&rsp)[4], 0x44);

    // An operation is atomic with respect to regions: it cannot begin in
    // open memory and spill into a differently protected neighbour.
    let rsp = exchange(&mut dev, 7, ApciCode::MemoryRead, 2, &[0x44, 0xFF], 0).expect("straddle denied");
    assert_eq!(apdu(&rsp)[1] & 0x3F, 0);

    // Oversized standard-frame reads fail instead of being truncated to a
    // different operation.
    let rsp = exchange(&mut dev, 8, ApciCode::MemoryRead, 13, &[0x44, 0x00], 0).expect("oversize answered");
    assert_eq!(apdu(&rsp)[1] & 0x3F, 0);

    let rsp =
        exchange(&mut dev, 9, ApciCode::AuthorizeRequest, 0, &[0x00, 0xAA, 0xAA, 0xAA, 0xAA], 0).expect("authorized");
    assert_eq!(apdu(&rsp)[2], 0);
    let rsp = exchange(&mut dev, 10, ApciCode::MemoryRead, 1, &[0x46, 0x00], 0).expect("level-1 read answered");
    assert_eq!(apdu(&rsp)[4], 0xFF);
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
fn memory_mapped_lsm_cycle_on_interface_program() {
    let mut dev = device();
    connect(&mut dev);
    let mut seq = 0u8;
    fn mem_write(dev: &mut Microdevice<Fam>, seq: &mut u8, addr: u16, data: &[u8]) {
        let mut payload = addr.to_be_bytes().to_vec();
        payload.extend_from_slice(data);
        exchange(dev, *seq, ApciCode::MemoryWrite, data.len() as u8, &payload, 0);
        *seq = (*seq + 1) & 0x0F;
    }

    // StartLoading machine 4 (Interface Program) through the 0104h window.
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
    // ADT/AST/application Loaded, Interface Program now Loaded too.
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
    let rsp =
        exchange(&mut dev, 0, ApciCode::AuthorizeRequest, 0, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF], 0).expect("authorized");
    assert_eq!(apdu(&rsp)[2], 0);
    // Unload the ADT via PID_LOAD_STATE_CONTROL on object 1 — the ETS
    // path. The RT8 length collapses to the IA-only mute value 1;
    // the IA survives.
    let rsp =
        exchange(&mut dev, 1, ApciCode::PropertyValueWrite, 0, &[1, 5, 0x10, 0x01, 0x04], 0).expect("write answered");
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Unloaded));
    assert_eq!(dev.eeprom_image()[0], 1, "only the IA slot remains in the table length");
    assert_eq!(dev.individual_address(), DUT, "the IA survives the unload");

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
    assert!(out.frames.is_empty(), "a muted device answers no group reads");
}

#[test]
fn run_state_stop_terminates_instead_of_halting() {
    let mut dev = device();
    connect(&mut dev);

    // Loaded application reads Running.
    let rsp = exchange(&mut dev, 0, ApciCode::PropertyValueRead, 0, &[3, 6, 0x10, 0x01], 0).expect("answered");
    assert_eq!(apdu(&rsp)[6], u8::from(RunState::Running));

    let rsp =
        exchange(&mut dev, 1, ApciCode::AuthorizeRequest, 0, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF], 0).expect("authorized");
    assert_eq!(apdu(&rsp)[2], 0);

    // RUNCONTROL_STOP → Terminated (03/05/01 §4.24.2.3.3 Table 97:
    // no HALTED intermediate reachable from the bus on this profile),
    // and group traffic stops.
    let rsp = exchange(&mut dev, 2, ApciCode::PropertyValueWrite, 0, &[3, 6, 0x10, 0x01, 0x02], 0).expect("answered");
    assert_eq!(apdu(&rsp)[6], u8::from(RunState::Terminated));
    assert!(!dev.is_running());
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
    assert!(out.frames.is_empty(), "a terminated application answers no group reads");

    // RUNCONTROL_RESTART revives it.
    let rsp = exchange(&mut dev, 3, ApciCode::PropertyValueWrite, 0, &[3, 6, 0x10, 0x01, 0x01], 0).expect("answered");
    assert_eq!(apdu(&rsp)[6], u8::from(RunState::Running));
    assert!(dev.is_running());

    // The unloaded Interface Program reads Halted.
    let rsp = exchange(&mut dev, 4, ApciCode::PropertyValueRead, 0, &[4, 6, 0x10, 0x01], 0).expect("answered");
    assert_eq!(apdu(&rsp)[6], u8::from(RunState::Halted));
}

#[test]
fn individual_address_write_lands_in_the_adt() {
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
    // RT8 defines the IA as ADT bytes 1–2 (4001h–4002h).
    assert_eq!(&dev.eeprom_image()[1..3], new_ia.as_bytes());
}

#[test]
fn rt8_group_communication() {
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

    // A transmit request on ASAP 1 produces a group write through its
    // sending association on the next timer tick.
    dev.write_value(1, &[1]);
    dev.set_transmit_request(1);
    let out = dev.poll(PollInput::Timer, 10);
    let tx_frame = canonical(&out.frames[0]);
    let tx = FrameView::parse(&tx_frame).expect("parsable");
    assert_eq!(tx.apci(), Some(ApciCode::GroupValueWrite.wire10_base() | 0x01));
    assert_eq!(tx.dest_group(), GroupAddress::from_three_level(1, 0, 2));
}

#[test]
#[cfg(feature = "std")]
fn snapshot_round_trip_preserves_system7_configuration() {
    use zweidraehte_microdevice::snapshot::MicroSnapshot;
    let mut dev = device();
    connect(&mut dev);
    exchange(&mut dev, 0, ApciCode::MemoryWrite, 1, &[0x01, 0x00, 0x5A], 0);
    let hardware_type = [0x00, 0x83, 0x12, 0x34, 0x56, 0x78];
    let mut write = [0u8; 10];
    write[..4].copy_from_slice(&[0, 78, 0x10, 0x01]);
    write[4..].copy_from_slice(&hardware_type);
    exchange(&mut dev, 1, ApciCode::PropertyValueWrite, 0, &write, 0).expect("hardware type writes");
    dev.mgmt.auth_keys[0] = [0xAA; 4];
    dev.mgmt.auth_keys[1] = [0xBB; 4];
    let snap = MicroSnapshot::capture(&dev);
    let bytes = postcard::to_allocvec(&snap).expect("serializes");
    let back: MicroSnapshot = postcard::from_bytes(&bytes).expect("deserializes");
    let identity = DeviceIdentity { serial_number: [0; 6], order_info: [0; 10], hardware_type: [0; 6] };
    let restored: Microdevice<Fam> = back.restore(identity, 1);
    assert_eq!(restored.mgmt.option_reg, 0x5A);
    assert_eq!(restored.mgmt.lsm[2].state, LoadState::Loaded);
    assert_eq!(restored.individual_address(), DUT);
    assert_eq!(restored.hardware_type(), &hardware_type);
    assert_eq!(restored.mgmt.auth_level, 2, "restored keys determine disconnected access");
}

/// Transport layer 2.5.1 verbatim: a T_Connect carrying appended octets,
/// followed by a correct Device Descriptor Read, five times with a growing
/// tail, then a T_Disconnect.
///
/// The EITT run hung here, so this pins the sequence as plain frames the
/// device must survive without wedging.
#[test]
fn malformed_connects_with_appended_octets_do_not_wedge_the_device() {
    let mut dev = device();
    let injects: [&[u8]; 11] = [
        &[0xB0, 0xAF, 0xFE, 0x10, 0x01, 0x61, 0x80, 0x11],
        &[0xBC, 0xAF, 0xFE, 0x10, 0x01, 0x61, 0x43, 0x00],
        &[0xB0, 0xAF, 0xFE, 0x10, 0x01, 0x62, 0x80, 0x11, 0x22],
        &[0xBC, 0xAF, 0xFE, 0x10, 0x01, 0x61, 0x47, 0x00],
        &[0xB0, 0xAF, 0xFE, 0x10, 0x01, 0x63, 0x80, 0x11, 0x22, 0x33],
        &[0xBC, 0xAF, 0xFE, 0x10, 0x01, 0x61, 0x4B, 0x00],
        &[0xB0, 0xAF, 0xFE, 0x10, 0x01, 0x64, 0x80, 0x11, 0x22, 0x33, 0x44],
        &[0xBC, 0xAF, 0xFE, 0x10, 0x01, 0x61, 0x4F, 0x00],
        &[0xB0, 0xAF, 0xFE, 0x10, 0x01, 0x65, 0x80, 0x11, 0x22, 0x33, 0x44, 0x55],
        &[0xBC, 0xAF, 0xFE, 0x10, 0x01, 0x61, 0x53, 0x00],
        &[0xB0, 0xAF, 0xFE, 0x10, 0x01, 0x60, 0x81],
    ];
    for (i, wire) in injects.iter().enumerate() {
        let out = dev.poll(PollInput::Frame(wire), i as u32 * 40);
        for frame in &out.frames {
            assert!(frame.len() >= 7, "step {i} emitted a runt frame");
        }
    }
}

/// The extended-frame profile: a device sized for the 40-octet APDU a secure
/// BCU2 advertises, driven over the same family as the plain one.
///
/// This is what stops the capacity parameters from being flexibility nobody
/// has compiled — and it pins the two halves that have to agree, the length
/// the device *advertises* and the length it can actually answer with.
#[test]
fn the_extended_profile_advertises_and_serves_a_long_apdu() {
    let def = definition();
    let mut dev: Microdevice<Fam, EXTENDED_FRAME> = Microdevice::new(Fam::build_eeprom(&def), identity(), 1);
    for (machine, table_ref) in Fam::factory_table_refs(&def).into_iter().enumerate().take(3) {
        dev.mgmt.lsm[machine].state = LoadState::Loaded;
        dev.mgmt.lsm[machine].table_ref = table_ref;
    }

    // A connectionless Device Descriptor Read still travels as an ordinary
    // standard frame: being able to send extended frames does not mean
    // sending short ones that way.
    let read = data_frame::<EXTENDED_FRAME>(
        0x00,
        CLIENT,
        DUT.0,
        false,
        Tpci::DataIndividual,
        ApciCode::DeviceDescriptorRead,
        0,
        &[],
    );
    let out = dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&read)), 0);
    assert_eq!(out.frames.len(), 1);
    assert_ne!(out.frames[0][0] & 0x80, 0, "a short reply stays a standard frame");
    let canonical = normalize::<EXTENDED_FRAME>(&out.frames[0]).expect("well-formed reply");
    let view = FrameView::parse(&canonical).expect("parsable");
    assert_eq!(view.payload(), &[0x07, 0x05], "mask 0705h");

    // PID_MAX_APDULENGTH must report the profile's ceiling, because that is
    // what a management client sizes its writes by.
    let read = data_frame::<EXTENDED_FRAME>(
        0x00,
        CLIENT,
        DUT.0,
        false,
        Tpci::DataIndividual,
        ApciCode::PropertyValueRead,
        0,
        &[0x00, pid::device::MAX_APDU_LENGTH as u8, 0x10, 0x01],
    );
    let out = dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&read)), 10);
    let canonical = normalize::<EXTENDED_FRAME>(&out.frames[0]).expect("well-formed reply");
    let view = FrameView::parse(&canonical).expect("parsable");
    assert_eq!(&view.payload()[4..], &max_apdu(EXTENDED_FRAME).to_be_bytes(), "advertises the profile ceiling");

    // And it can answer with one: a memory read longer than the standard
    // APDU could ever carry, which has to leave as an extended frame.
    // `A_Memory_Read` is connection-oriented, so open the connection first.
    let connect =
        [TP1_STD_CTRL_BASE, CLIENT.0[0], CLIENT.0[1], DUT.0[0], DUT.0[1], NPCI_HOP_COUNT_6, Tpci::Connect.octet()];
    assert!(dev.poll(PollInput::Frame(&connect), 30).frames.is_empty(), "connect is accepted silently");

    let long = 20u8;
    let read = data_frame::<EXTENDED_FRAME>(
        0x00,
        CLIENT,
        DUT.0,
        false,
        Tpci::DataConnected(0),
        ApciCode::MemoryRead,
        long,
        &[0x40, 0x00],
    );
    let out = dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&read)), 40);
    assert_eq!(out.frames.len(), 2, "a T_ACK and the response");
    assert_eq!(out.frames[1][0] & 0x80, 0, "a 20-octet memory read answers in an extended frame");
    let canonical = normalize::<EXTENDED_FRAME>(&out.frames[1]).expect("well-formed reply");
    let view = FrameView::parse(&canonical).expect("parsable");
    assert_eq!(view.payload().len(), 2 + long as usize, "address plus the requested octets");
}

/// The same read against the plain profile is refused rather than truncated:
/// 20 octets do not fit a 15-octet APDU, and answering with fewer would claim
/// success for a different operation.
#[test]
fn the_plain_profile_refuses_a_read_longer_than_its_apdu() {
    let mut dev = device();
    let connect =
        [TP1_STD_CTRL_BASE, CLIENT.0[0], CLIENT.0[1], DUT.0[0], DUT.0[1], NPCI_HOP_COUNT_6, Tpci::Connect.octet()];
    assert!(dev.poll(PollInput::Frame(&connect), 0).frames.is_empty());

    let read =
        data_frame::<MAX_FRAME>(0x00, CLIENT, DUT.0, false, Tpci::DataConnected(0), ApciCode::MemoryRead, 20, &[
            0x40, 0x00,
        ]);
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&read)), 10);
    assert_eq!(out.frames.len(), 2, "a T_ACK and the refusal");
    let canonical = normalize::<MAX_FRAME>(&out.frames[1]).expect("well-formed");
    let view = FrameView::parse(&canonical).expect("parsable");
    assert_eq!(view.payload().len(), 2, "address echoed, count zero, no data");
}

// ============================================================================
// Extended property services
// ============================================================================
//
// These address an object by type plus one-based occurrence instead of by
// index (03/03/07 §3.4.5.1), which is the only way to reach an object a
// family keeps out of its indexed roster — the shape a secure BCU2 needs for
// its Security Interface Object. Everything after the resolution is the
// classic property path, so the strongest assertion available is that both
// spellings of the same request return the same bytes.
//
// They belong to the extended profile: `A_PropertyExtDescription_Response` is
// a fixed 16-octet APDU, so a standard-frame device could implement six of
// the seven services §9.1.2.3.2 makes mandatory and not the seventh.

type WideDevice = Microdevice<Fam, EXTENDED_FRAME>;

fn wide_device() -> WideDevice {
    let def = definition();
    let mut dev: WideDevice = Microdevice::new(Fam::build_eeprom(&def), identity(), 1);
    for (machine, table_ref) in Fam::factory_table_refs(&def).into_iter().enumerate().take(3) {
        dev.mgmt.lsm[machine].state = LoadState::Loaded;
        dev.mgmt.lsm[machine].table_ref = table_ref;
    }
    dev
}

/// `(object_instance | property_id)` packed into the three octets the
/// extended services carry them in.
fn pack_instance_pid(instance: u16, pid: u16) -> [u8; 3] {
    [(instance >> 4) as u8, ((((instance & 0x0F) << 4) | (pid >> 8)) as u8), pid as u8]
}

fn ext_read_payload(object_type: u16, instance: u16, pid: u16, count: u8, start: u16) -> [u8; 8] {
    let ot = object_type.to_be_bytes();
    let ip = pack_instance_pid(instance, pid);
    let st = start.to_be_bytes();
    [ot[0], ot[1], ip[0], ip[1], ip[2], count, st[0], st[1]]
}

/// Drive one connectionless request against the plain profile and return the
/// single reply's payload.
fn connectionless(dev: &mut Microdevice<Fam>, apci: ApciCode, payload: &[u8], now: u32) -> Vec<u8> {
    let req = data_frame::<MAX_FRAME>(0x00, CLIENT, DUT.0, false, Tpci::DataIndividual, apci, 0, payload);
    let out = dev.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&req)), now);
    assert_eq!(out.frames.len(), 1, "expected exactly one reply");
    let canonical = canonical(&out.frames[0]);
    let view = FrameView::parse(&canonical).expect("parsable");
    view.payload().to_vec()
}

/// The same, against the extended profile.
fn connectionless_wide(dev: &mut WideDevice, apci: ApciCode, payload: &[u8], now: u32) -> Vec<u8> {
    let req = data_frame::<EXTENDED_FRAME>(0x00, CLIENT, DUT.0, false, Tpci::DataIndividual, apci, 0, payload);
    let out = dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&req)), now);
    assert_eq!(out.frames.len(), 1, "expected exactly one reply");
    let canonical = normalize::<EXTENDED_FRAME>(&out.frames[0]).expect("well-formed");
    let view = FrameView::parse(&canonical).expect("parsable");
    view.payload().to_vec()
}

#[test]
fn an_extended_read_returns_what_the_indexed_read_returns() {
    let mut plain = device();
    let mut wide = wide_device();
    // PID_SERIAL_NUMBER on the Device Object, reached both ways.
    let pid = pid::SERIAL_NUMBER;
    let classic = connectionless(&mut plain, ApciCode::PropertyValueRead, &[0x00, pid as u8, 0x10, 0x01], 0);
    let extended =
        connectionless_wide(&mut wide, ApciCode::PropertyExtValueRead, &ext_read_payload(0, 1, pid, 1, 1), 0);
    // Classic response: obj, pid, count|start, start, then data.
    // Extended response: type(2), instance|pid(3), count, start(2), then data.
    assert_eq!(&extended[8..], &classic[4..], "same property, same bytes");
    assert!(!extended[8..].is_empty(), "the serial number is not empty");
}

#[test]
fn an_extended_read_of_an_absent_object_type_is_an_address_error() {
    let mut wide = wide_device();
    // Object Type 17 is the Security Interface Object; this device has none.
    let reply = connectionless_wide(
        &mut wide,
        ApciCode::PropertyExtValueRead,
        &ext_read_payload(17, 1, pid::SERIAL_NUMBER, 1, 1),
        0,
    );
    assert_eq!(reply[5], 0, "an error response carries count zero");
    assert_eq!(reply[8], 0xFD, "E_ADDRESS_VOID");
}

#[test]
fn occurrence_zero_never_resolves() {
    let mut wide = wide_device();
    let reply = connectionless_wide(
        &mut wide,
        ApciCode::PropertyExtValueRead,
        &ext_read_payload(0, 0, pid::SERIAL_NUMBER, 1, 1),
        0,
    );
    assert_eq!(reply[8], 0xFD, "instance 0 is not a valid occurrence");
}

#[test]
fn an_extended_confirmed_write_answers_with_a_return_code() {
    let mut wide = wide_device();
    // PID_PROGMODE on the Device Object is writable; set programming mode on.
    let mut payload = ext_read_payload(0, 1, pid::device::PROGMODE, 1, 1).to_vec();
    payload.push(0x01);
    let reply = connectionless_wide(&mut wide, ApciCode::PropertyExtValueWriteCon, &payload, 0);
    assert_eq!(reply[8], 0x00, "E_SUCCESS");
    assert!(wide.is_programming_mode(), "the write took effect");
}

/// A standard-frame profile does not implement the extended services at all,
/// so it ignores them the way it ignores any APCI it does not decode — no
/// reply, and no pretence of partial support.
#[test]
fn a_standard_profile_ignores_the_extended_services() {
    let mut plain = device();
    let req = data_frame::<MAX_FRAME>(
        0x00,
        CLIENT,
        DUT.0,
        false,
        Tpci::DataIndividual,
        ApciCode::PropertyExtValueRead,
        0,
        &ext_read_payload(0, 1, pid::SERIAL_NUMBER, 1, 1),
    );
    let out = plain.poll(PollInput::Frame(&to_wire::<MAX_FRAME>(&req)), 0);
    assert!(out.frames.is_empty());
}

/// `A_PropertyExtDescription_Response` is a fixed 23 canonical octets — a
/// 16-octet APDU — which is the concrete reason the extended services and the
/// extended APDU are one choice rather than two.
#[test]
fn an_extended_description_read_matches_the_indexed_one() {
    let mut plain = device();
    let mut wide = wide_device();

    let pid = pid::SERIAL_NUMBER;
    let classic = connectionless(&mut plain, ApciCode::PropertyDescriptionRead, &[0x00, pid as u8, 0x00], 0);
    let ip = pack_instance_pid(1, pid);
    let extended = connectionless_wide(
        &mut wide,
        ApciCode::PropertyExtDescriptionRead,
        &[0x00, 0x00, ip[0], ip[1], ip[2], 0x00, 0x00],
        0,
    );

    // The two encodings are not byte-comparable: the classic response packs
    // the PDT's low nibble into the top of its 12-bit max-elements field
    // (03/03/07 Figure 44), while the extended one keeps a plain 16-bit
    // count. So compare the decoded fields.
    //
    // Classic payload: [obj, pid, prop_idx, W|PDT, max_hi, max_lo, access].
    // Extended payload is frame-relative `MSG_APCI + 2`, so the descriptor
    // fields land at 11 (W|PDT), 12..14 (max) and 14 (access).
    assert_eq!(extended[11], classic[3], "writeable flag and PDT");
    let classic_max = u16::from_be_bytes([classic[4], classic[5]]) & 0x0FFF;
    let extended_max = u16::from_be_bytes([extended[12], extended[13]]);
    assert_eq!(extended_max, classic_max, "max elements");
    assert_eq!(extended[14], classic[6], "read and write access levels");
}

// ============================================================================
// Extended memory services
// ============================================================================
//
// Three address octets, a full-octet count, and an explicit return code
// instead of the classic services' zero-count convention. This is the path an
// ETS download to a secure device actually uses.

fn ext_memory_payload(count: u8, address: u32, data: &[u8]) -> Vec<u8> {
    let mut p = vec![count, (address >> 16) as u8, (address >> 8) as u8, address as u8];
    p.extend_from_slice(data);
    p
}

#[test]
fn an_extended_memory_write_lands_and_reads_back() {
    let mut wide = wide_device();
    // 4400h is an open region in this fixture's memory policy.
    let written = [0xDE, 0xAD, 0xBE, 0xEF];
    let reply = connectionless_wide(
        &mut wide,
        ApciCode::MemoryExtendedWrite,
        &ext_memory_payload(written.len() as u8, 0x43F0, &written),
        0,
    );
    assert_eq!(reply[0], 0x00, "E_SUCCESS");
    assert_eq!(&reply[1..4], &[0x00, 0x43, 0xF0], "the full address is echoed");

    let reply = connectionless_wide(
        &mut wide,
        ApciCode::MemoryExtendedRead,
        &ext_memory_payload(written.len() as u8, 0x43F0, &[]),
        10,
    );
    assert_eq!(reply[0], 0x00, "E_SUCCESS");
    assert_eq!(&reply[4..], &written, "reads back what was written");
}

#[test]
fn an_extended_write_whose_count_lies_is_refused() {
    let mut wide = wide_device();
    // Declares five octets, carries one. Writing either length would be
    // guessing which the sender meant.
    let reply =
        connectionless_wide(&mut wide, ApciCode::MemoryExtendedWrite, &ext_memory_payload(5, 0x43F0, &[0xAA]), 0);
    assert_eq!(reply[0], 0xFE, "E_DATA_TYPE_CONFLICT");
}

#[test]
fn an_address_beyond_the_families_space_is_refused_not_truncated() {
    let mut wide = wide_device();
    // 0x0143F0 truncates to 0x43F0 — a real, writable address. Dropping the
    // top octet would write somewhere the client never named.
    let reply =
        connectionless_wide(&mut wide, ApciCode::MemoryExtendedWrite, &ext_memory_payload(1, 0x0143F0, &[0xAA]), 0);
    assert_eq!(reply[0], 0xFD, "E_ADDRESS_VOID");

    let readback =
        connectionless_wide(&mut wide, ApciCode::MemoryExtendedRead, &ext_memory_payload(1, 0x43F0, &[]), 10);
    assert_ne!(readback[4], 0xAA, "nothing was written at the truncated address");
}

#[test]
fn an_extended_read_of_a_write_only_region_reports_its_direction() {
    // The direction-protected windows live in the protected policy, so this
    // one needs a wide device over that family rather than the standard one.
    let mut dev: Microdevice<ProtectedFam, EXTENDED_FRAME> =
        Microdevice::new(ProtectedFam::build_eeprom(&definition()), identity(), 1);
    for (machine, table_ref) in ProtectedFam::factory_table_refs(&definition()).into_iter().enumerate().take(3) {
        dev.mgmt.lsm[machine].state = LoadState::Loaded;
        dev.mgmt.lsm[machine].table_ref = table_ref;
    }
    // 4510h is write-only there.
    let req = data_frame::<EXTENDED_FRAME>(
        0x00,
        CLIENT,
        DUT.0,
        false,
        Tpci::DataIndividual,
        ApciCode::MemoryExtendedRead,
        0,
        &ext_memory_payload(1, 0x4510, &[]),
    );
    let out = dev.poll(PollInput::Frame(&to_wire::<EXTENDED_FRAME>(&req)), 0);
    let canonical = normalize::<EXTENDED_FRAME>(&out.frames[0]).expect("well-formed");
    let view = FrameView::parse(&canonical).expect("parsable");
    // 03/03/07 distinguishes a direction violation from a failed access
    // level check so management clients can diagnose the request precisely.
    assert_eq!(view.payload()[0], 0xFA, "E_ACCESS_WRITE_ONLY");
}

#[test]
fn an_unsupported_function_property_answers_rather_than_going_silent() {
    let mut wide = wide_device();
    // No object here serves a function property yet; the service still has
    // to answer, with a response carrying no data.
    let ip = pack_instance_pid(1, pid::device::PROGMODE);
    let reply =
        connectionless_wide(&mut wide, ApciCode::FunctionPropertyExtStateRead, &[0x00, 0x00, ip[0], ip[1], ip[2]], 0);
    assert_eq!(reply.len(), 5, "type, instance|pid, and nothing else");
}
