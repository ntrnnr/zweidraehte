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
use zweidraehte_microdevice::snapshot::MicroSnapshot;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::messages::apdu::load_control::LoadState;

/// The DUT's family: 1 KiB of user EEPROM backed from 4000h, the M112
/// group object table published at 4200h. Everything the client's
/// download engine addresses (ADT 4000h, AST 4100h, COT 4200h, app
/// segment 4300h) lives inside the backing.
pub type MicroSystem7DutFamily = System7Family<0x400, 0x4200>;

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

/// The DUT's group objects, mirroring the BCU2 smoke fixture: value
/// slots in page-0 user RAM (00C6h+), RAM flags at 00D0h.
///
/// - ASAP 0: 1-bit, all flags — the main test object
/// - ASAP 1: 1-byte, all flags
/// - ASAP 2: 3-byte, all flags (invalid-length material)
/// - ASAP 3: 1-bit, transmit/read only — a status object
pub static COM_OBJECTS: &[System7CoDescriptor] = &[
    System7CoDescriptor { data_ptr: 0x00C6, config: ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
    System7CoDescriptor { data_ptr: 0x00C7, config: ALL_FLAGS_LOW_PRIO, value_type: 0x06 },
    System7CoDescriptor { data_ptr: 0x00C8, config: ALL_FLAGS_LOW_PRIO, value_type: 0x08 },
    System7CoDescriptor { data_ptr: 0x00CB, config: 0x4F, value_type: 0x00 },
];

/// Factory group addresses, TSAPs 1..=4 in table order. Raw values
/// 1000h.. (ascending, as RT8 mandates) so the suite templates can
/// spell them as literal octets.
static GROUP_ADDRESSES: &[GroupAddress] =
    &[GroupAddress([0x10, 0x00]), GroupAddress([0x10, 0x01]), GroupAddress([0x10, 0x02]), GroupAddress([0x10, 0x03])];

static ASSOCIATIONS: &[(u8, u8)] = &[(1, 0), (2, 1), (3, 2), (4, 3)];

pub fn definition() -> System7DeviceDefinition {
    System7DeviceDefinition {
        manufacturer_id: 0x00FA,
        device_type: 0x0B70,
        version: 1,
        individual_address: dut_ia(),
        max_group_addresses: 8,
        max_associations: 8,
        ram_flags_ptr: 0x00D0,
        comm_objects: COM_OBJECTS,
        group_addresses: GROUP_ADDRESSES,
        associations: ASSOCIATIONS,
        ast_offset: 0x100,
        app_offset: 0x300,
    }
}

pub fn identity() -> DeviceIdentity {
    DeviceIdentity { serial_number: SERIAL_NUMBER, order_info: [0; 10], hardware_type: HARDWARE_TYPE }
}

/// The factory boot image: tables populated, application loaded and
/// running — a commissioned device, which is what the group and
/// transport suites expect to find. App2 stays empty.
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
    }
}
