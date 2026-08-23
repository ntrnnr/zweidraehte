//! Minimal BCU1 EITT fixture for the polling micro stack.
//!
//! BCU1 has no Interface Objects or load state machines. The fixture only
//! supplies the two application objects needed by the Network- and
//! Transport-Layer templates: one octet for the routed response and one bit
//! for the transport probe.

use zweidraehte_microdevice::device::DeviceIdentity;
use zweidraehte_microdevice::families::bcu1::{Bcu1CoDescriptor, Bcu1DeviceDefinition};
use zweidraehte_microdevice::snapshot::MicroSnapshot;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::messages::apdu::load_control::LoadState;

pub fn dut_ia() -> IndividualAddress {
    IndividualAddress::new(1, 0, 1)
}

pub const SERIAL_NUMBER: [u8; 6] = [0xFE, 0xED, 0x00, 0x12, 0xBE, 0xEF];

// RT1 requires config bit 7. Both objects otherwise enable every group
// direction needed by the two templates.
static COM_OBJECTS: &[Bcu1CoDescriptor] =
    &[Bcu1CoDescriptor { data_ptr: 0xC6, config: 0x9F, value_type: 0x06 }, Bcu1CoDescriptor {
        data_ptr: 0xC7,
        config: 0xDF,
        value_type: 0x00,
    }];

static GROUP_ADDRESSES: &[GroupAddress] = &[GroupAddress([0x10, 0x01]), GroupAddress([0x10, 0x00])];
static ASSOCIATIONS: &[(u8, u8)] = &[(1, 0), (2, 1)];

pub fn definition() -> Bcu1DeviceDefinition {
    Bcu1DeviceDefinition {
        app_manufacturer: 0xFA,
        device_type: 0x0B10,
        version: 1,
        pei_type: 0,
        individual_address: dut_ia(),
        max_group_addresses: 4,
        max_associations: 4,
        ram_flags_ptr: 0xD0,
        comm_objects: COM_OBJECTS,
        group_addresses: GROUP_ADDRESSES,
        associations: ASSOCIATIONS,
    }
}

pub fn identity() -> DeviceIdentity {
    DeviceIdentity { serial_number: SERIAL_NUMBER, order_info: [0; 10], hardware_type: [0; 6] }
}

pub fn factory_snapshot() -> MicroSnapshot {
    MicroSnapshot {
        eeprom: definition().build_eeprom().to_vec(),
        auth_keys: Vec::new(),
        // BCU1 has no LSMs; these serialized compatibility slots are unused.
        lsm_states: [LoadState::Unloaded.into(); 4],
        table_refs: [0; 4],
        device_control: 0,
        option_reg: 0,
        hardware_type: None,
    }
}
