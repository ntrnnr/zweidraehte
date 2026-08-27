//! Minimal BCU1 EITT fixture for the polling micro stack.
//!
//! BCU1 has no Interface Objects or load state machines. Its application is
//! the vendor Group Objects template's UINT1 fixture plus independent objects
//! for the Network- and Transport-Layer templates.

use zweidraehte_microdevice::device::DeviceIdentity;
use zweidraehte_microdevice::families::bcu1::{Bcu1CoDescriptor, Bcu1DeviceDefinition};
use zweidraehte_microdevice::snapshot::MicroSnapshot;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::messages::apdu::load_control::LoadState;
use zweidraehte_proto::tables::association::UNUSED_SENDING_TSAP;

pub fn dut_ia() -> IndividualAddress {
    IndividualAddress::new(1, 0, 1)
}

pub const SERIAL_NUMBER: [u8; 6] = [0xFE, 0xED, 0x00, 0x12, 0xBE, 0xEF];

// RT1 fixes config bit 7. The main object and its shadows otherwise enable
// every group direction; bit 5 remains clear because it is RT1's segment
// selector, not Read-on-Init.
static COM_OBJECTS: &[Bcu1CoDescriptor] = &[
    Bcu1CoDescriptor { data_ptr: 0x00, config: 0x83, value_type: 0x00 },
    Bcu1CoDescriptor { data_ptr: 0xC6, config: 0xDF, value_type: 0x00 },
    Bcu1CoDescriptor { data_ptr: 0xC7, config: 0xDF, value_type: 0x03 },
    Bcu1CoDescriptor { data_ptr: 0xC8, config: 0xDF, value_type: 0x06 },
    Bcu1CoDescriptor { data_ptr: 0xC9, config: 0xDF, value_type: 0x06 },
    Bcu1CoDescriptor { data_ptr: 0xCA, config: 0xDF, value_type: 0x06 },
    Bcu1CoDescriptor { data_ptr: 0xCB, config: 0xDF, value_type: 0x06 },
    Bcu1CoDescriptor { data_ptr: 0xCC, config: 0xDF, value_type: 0x00 },
    Bcu1CoDescriptor { data_ptr: 0xCD, config: 0xDF, value_type: 0x00 },
    Bcu1CoDescriptor { data_ptr: 0xCE, config: 0xDF, value_type: 0x00 },
    Bcu1CoDescriptor { data_ptr: 0xCD, config: 0xDF, value_type: 0x00 },
    Bcu1CoDescriptor { data_ptr: 0xCE, config: 0xDF, value_type: 0x00 },
];

static GROUP_ADDRESSES: &[GroupAddress] = &[
    GroupAddress([0x08, 0x01]),
    GroupAddress([0x10, 0x00]),
    GroupAddress([0x10, 0x01]),
    GroupAddress([0x10, 0x02]),
    GroupAddress([0x10, 0x03]),
    GroupAddress([0x10, 0x05]),
    GroupAddress([0x2D, 0x05]),
    GroupAddress([0x09, 0x00]),
    GroupAddress([0x09, 0x02]),
    GroupAddress([0x09, 0x03]),
    GroupAddress([0x09, 0x04]),
    GroupAddress([0x09, 0x05]),
    GroupAddress([0x09, 0x06]),
    GroupAddress([0x09, 0x07]),
];

#[rustfmt::skip]
static ASSOCIATIONS: &[(u8, u8)] = &[
    (UNUSED_SENDING_TSAP, 0),
    (2, 1),
    (3, 2),
    (4, 3),
    (5, 4),
    (6, 5),
    (1, 6),
    (7, 7),
    (UNUSED_SENDING_TSAP, 8),
    (UNUSED_SENDING_TSAP, 9),
    (9, 10),
    (9, 11),
    (8, 8),
    (10, 8),
    (10, 9),
    (11, 8),
    (12, 9),
    (13, 8),
    (13, 9),
    (14, 8),
    (14, 9),
];

pub fn definition() -> Bcu1DeviceDefinition {
    Bcu1DeviceDefinition {
        app_manufacturer: 0xFA,
        device_type: 0x0B10,
        version: 1,
        pei_type: 0,
        individual_address: dut_ia(),
        max_group_addresses: 14,
        max_associations: 21,
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
