//! The micro-System-7 DUT fixture: the `zweidraehte-microdevice`
//! System 7 family's device definition and factory snapshot.
//!
//! The System 7 sibling of [`super::bcu2_stack`]: the same no-async
//! micro stack in a plain blocking process (see
//! `src/bin/dut_micro_system7.rs`), instantiated for mask 0705h. What
//! lives here is the *product*: the group object roster, table
//! capacities, segment placement and identity that both the running
//! DUT and the generated product file (`micro_system7_product`) are
//! built from.

use zweidraehte_microdevice::device::DeviceIdentity;
use zweidraehte_microdevice::families::system7::{System7CoDescriptor, System7DeviceDefinition, System7Family};
use zweidraehte_microdevice::family::MemoryAccessPolicy;
use zweidraehte_microdevice::snapshot::MicroSnapshot;
use zweidraehte_proto::access::AccessLevel;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::memory::{MemoryPermission, MemoryRegion};
use zweidraehte_proto::messages::apdu::load_control::LoadState;

/// Certification-only memory permissions for the Management template.
///
/// The regular micro System 7 type still uses its product-sized EEPROM and
/// standard policy. This host fixture backs the complete 4000h..7FFFh span so
/// the vendor template can exercise its open, direction-protected and
/// authorization-protected windows without adding runtime policy data to any
/// firmware image.
pub struct MicroSystem7ConformanceMemoryPolicy;

impl MemoryAccessPolicy for MicroSystem7ConformanceMemoryPolicy {
    const REGIONS: &'static [MemoryRegion] = &[
        MemoryRegion::open(0x0000, 0x0100),
        MemoryRegion::open(0x0100, 0x0010),
        MemoryRegion::open(0x0700, 0x0100),
        MemoryRegion::open(0x4000, 0x1100),
        MemoryRegion::read_only(0x5100, 0x0010, MemoryPermission::Open),
        MemoryRegion::write_only(0x5110, 0x0010, MemoryPermission::Open),
        MemoryRegion::new(
            0x5120,
            0x00E0,
            MemoryPermission::Level(AccessLevel::Configuration),
            MemoryPermission::Level(AccessLevel::Configuration),
        ),
        MemoryRegion::new(
            0x5200,
            0x0100,
            MemoryPermission::Level(AccessLevel::ProductManufacturer),
            MemoryPermission::Level(AccessLevel::ProductManufacturer),
        ),
        MemoryRegion::open(0x5300, 0x2D00),
        MemoryRegion::read_only(0xB6EA, 4, MemoryPermission::Open),
    ];
}

/// The DUT's family: 16 KiB of certification backing from 4000h, with the
/// real fixture tables still at 4000h..43FFh and its COT at 4200h.
pub type MicroSystem7DutFamily =
    System7Family<0x4000, 0x4200, 0x00FA, 0x0B70, 1, 0, MicroSystem7ConformanceMemoryPolicy>;

/// The BDUT address every hand-written suite uses (1.0.1).
pub fn dut_ia() -> IndividualAddress {
    IndividualAddress::new(1, 0, 1)
}

/// The suite convention serial. Distinct from the full-fat System 7
/// DUT (`FE ED 07 05 CA FE`) so a mixed log is attributable.
pub const SERIAL_NUMBER: [u8; 6] = [0xFE, 0xED, 0x07, 0x05, 0xBE, 0xEF];

/// `PID_HARDWARE_TYPE` — the identity the generated product's
/// `LdCtrlCompareProp` guard checks before a download.
pub const HARDWARE_TYPE: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x17];

/// Config octet with every flag: UE | TE | ROI off | WE | RE | CE,
/// low transmission priority (Table 87 coding).
const ALL_FLAGS_LOW_PRIO: u8 = 0xDF;
/// The same plus the read-on-init flag. The micro stack has no
/// read-on-init scan (SESSION.md tracks it), but the table data
/// mirrors the full-fat fixture so the profiles stay congruent.
const ALL_FLAGS_ROI_LOW_PRIO: u8 = 0xFF;

/// The DUT's group objects: the full-fat System 7 conformance roster
/// (see `system7_stack::conformance_config`), carried onto the micro
/// stack so the same EITT profile variables and GUID-anchored patches
/// resolve. ASAPs 1..=7 with System 7 slot 0 spare; value slots in page-0
/// user RAM (00C6h+), RAM flags at 00D0h.
///
/// - ASAP 1: GO0, 1-bit — the main test object
/// - ASAP 2: GO1, 4-bit (short-format response material)
/// - ASAP 3: GO2, 1-byte
/// - ASAP 4: GO3, 1-byte, read-on-init
/// - ASAP 5: GO4, 1-byte, read-on-init
/// - ASAP 6: GO5, 1-byte — the network-layer long-format object
/// - ASAP 7: GO6, 1-bit — the transport-layer object
pub static COM_OBJECTS: &[System7CoDescriptor] = &[
    System7CoDescriptor { data_ptr: 0x0000, config: 0x00, value_type: 0x00 }, // spare slot 0
    System7CoDescriptor { data_ptr: 0x00C6, config: ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
    System7CoDescriptor { data_ptr: 0x00C7, config: ALL_FLAGS_LOW_PRIO, value_type: 0x03 },
    System7CoDescriptor { data_ptr: 0x00C8, config: ALL_FLAGS_LOW_PRIO, value_type: 0x07 },
    System7CoDescriptor { data_ptr: 0x00C9, config: ALL_FLAGS_ROI_LOW_PRIO, value_type: 0x07 },
    System7CoDescriptor { data_ptr: 0x00CA, config: ALL_FLAGS_ROI_LOW_PRIO, value_type: 0x07 },
    System7CoDescriptor { data_ptr: 0x00CB, config: ALL_FLAGS_LOW_PRIO, value_type: 0x07 },
    System7CoDescriptor { data_ptr: 0x00CC, config: ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
];

/// Factory group addresses, TSAPs 1..=7 in table order — ascending, as
/// RT8 mandates, and identical to the full-fat fixture: 1/0/1 for the
/// network layer, the group-object template's defaults 1000h..1005h,
/// and 5/5/5 for the transport layer.
static GROUP_ADDRESSES: &[GroupAddress] = &[
    GroupAddress([0x08, 0x01]),
    GroupAddress([0x10, 0x00]),
    GroupAddress([0x10, 0x01]),
    GroupAddress([0x10, 0x02]),
    GroupAddress([0x10, 0x03]),
    GroupAddress([0x10, 0x05]),
    GroupAddress([0x2D, 0x05]),
];

static ASSOCIATIONS: &[(u8, u8)] = &[(1, 6), (2, 1), (3, 2), (4, 3), (5, 4), (6, 5), (7, 7)];

pub fn definition() -> System7DeviceDefinition {
    System7DeviceDefinition {
        manufacturer_id: 0x00FA,
        device_type: 0x0B70,
        version: 1,
        pei_type: 0,
        individual_address: dut_ia(),
        max_group_addresses: 8,
        max_associations: 8,
        ram_flags_ptr: 0x00D0,
        comm_objects: COM_OBJECTS,
        group_addresses: GROUP_ADDRESSES,
        associations: ASSOCIATIONS,
        ast_offset: 0x100,
        app_offset: 0x300,
        app_params: &[],
    }
}

pub fn identity() -> DeviceIdentity {
    DeviceIdentity { serial_number: SERIAL_NUMBER, order_info: [0; 10], hardware_type: HARDWARE_TYPE }
}

/// The factory boot image: tables populated, application loaded and
/// running — a commissioned device, which is what the group and
/// transport suites expect to find. The optional Interface Program stays empty.
pub fn factory_snapshot() -> MicroSnapshot {
    let def = definition();
    let refs = MicroSystem7DutFamily::factory_table_refs(&def);
    MicroSnapshot {
        eeprom: MicroSystem7DutFamily::build_eeprom(&def).to_vec(),
        auth_keys: vec![[0xFF; 4]; 16],
        lsm_states: [
            LoadState::Loaded.into(),
            LoadState::Loaded.into(),
            LoadState::Loaded.into(),
            LoadState::Unloaded.into(),
        ],
        table_refs: refs,
        device_control: 0,
        option_reg: 0,
        hardware_type: Some(HARDWARE_TYPE),
    }
}
