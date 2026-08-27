//! The BCU2 DUT fixture: the `zweidraehte-microdevice` stack's device
//! definition and factory snapshot.
//!
//! Unlike the other DUT fixtures this is not a `zweidraehte-device`
//! stack — the whole point of the BCU2 DUT is that it runs the
//! no-async micro stack in a plain blocking process (see
//! `src/bin/dut_bcu2.rs`). What lives here is the *product*: the group
//! object roster, table capacities and identity that both the running
//! DUT and the generated product file (`bcu2_product`) are built from.

use zweidraehte_microdevice::device::DeviceIdentity;
use zweidraehte_microdevice::families::bcu2::{Bcu2CoDescriptor, Bcu2DeviceDefinition, Bcu2Family};
use zweidraehte_microdevice::family::MemoryAccessPolicy;
use zweidraehte_microdevice::snapshot::MicroSnapshot;
use zweidraehte_proto::access::AccessLevel;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::memory::{MemoryPermission, MemoryRegion};
use zweidraehte_proto::messages::apdu::load_control::LoadState;
use zweidraehte_proto::tables::association::UNUSED_SENDING_TSAP;

/// The BDUT address every hand-written suite uses (1.0.1).
pub fn dut_ia() -> IndividualAddress {
    IndividualAddress::new(1, 0, 1)
}

/// The suite convention serial (`#BDUT_SERIAL_NUMBER`).
pub const SERIAL_NUMBER: [u8; 6] = [0xFE, 0xED, 0xBA, 0xBE, 0xCA, 0xFE];

/// Certification-only legacy authorization windows.
///
/// A product chooses its own protected areas through the same zero-sized
/// policy parameter. Keeping the EITT fixture here exercises the BCU2
/// authorization server without putting invented certification addresses or
/// branches into normal firmware.
pub struct Bcu2ConformanceMemoryPolicy;

impl MemoryAccessPolicy for Bcu2ConformanceMemoryPolicy {
    const REGIONS: &'static [MemoryRegion] = &[
        MemoryRegion::open(0x0000, 0x0100),
        MemoryRegion::open(0x0100, 0x0220),
        MemoryRegion::new(
            0x0320,
            0x00E0,
            MemoryPermission::Level(AccessLevel::Configuration),
            MemoryPermission::Level(AccessLevel::Configuration),
        ),
        MemoryRegion::new(
            0x0400,
            0x00E0,
            MemoryPermission::Level(AccessLevel::ProductManufacturer),
            MemoryPermission::Level(AccessLevel::ProductManufacturer),
        ),
        MemoryRegion::open(0x0900, 0x00D0),
    ];
}

pub type Family = Bcu2Family<0x0020, Bcu2ConformanceMemoryPolicy>;

/// Config octet with every supported flag, the RT2 segment selector clear,
/// and low transmission priority.
pub(super) const ALL_FLAGS_LOW_PRIO: u8 = 0xDF;
/// The vendor Group Objects template's UINT1 sample application plus the
/// independent network- and transport-layer probes. Value slots sit in user
/// RAM (00C6h+), the RAM flags at 00D0h — the classic page-0 arrangement.
///
/// - ASAP 0: spare, preserving the one-based sample-application numbering
/// - ASAP 1: GO0, 1-bit — the main test object
/// - ASAP 2: GO1, 4-bit — GO0's communication flags
/// - ASAP 3: GO2, 1-byte — GO0's configuration flags
/// - ASAP 4: GO3, 1-byte — GO0's value
/// - ASAP 5: spare one-byte object reserved by the sample roster
/// - ASAP 6: GO5, 1-byte — the network-layer long-format object
/// - ASAP 7: GO6, 1-bit — the transport-layer object
/// - ASAP 8-9: association-table test inputs
/// - ASAP 10-11: association-table status objects
static COM_OBJECTS: &[Bcu2CoDescriptor] = &[
    Bcu2CoDescriptor { data_ptr: 0x00, config: 0x03, value_type: 0x00 },
    Bcu2CoDescriptor { data_ptr: 0xC6, config: ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
    Bcu2CoDescriptor { data_ptr: 0xC7, config: ALL_FLAGS_LOW_PRIO, value_type: 0x03 },
    Bcu2CoDescriptor { data_ptr: 0xC8, config: ALL_FLAGS_LOW_PRIO, value_type: 0x06 },
    Bcu2CoDescriptor { data_ptr: 0xC9, config: ALL_FLAGS_LOW_PRIO, value_type: 0x06 },
    Bcu2CoDescriptor { data_ptr: 0xCA, config: ALL_FLAGS_LOW_PRIO, value_type: 0x06 },
    Bcu2CoDescriptor { data_ptr: 0xCB, config: ALL_FLAGS_LOW_PRIO, value_type: 0x06 },
    Bcu2CoDescriptor { data_ptr: 0xCC, config: ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
    Bcu2CoDescriptor { data_ptr: 0xCD, config: ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
    Bcu2CoDescriptor { data_ptr: 0xCE, config: ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
    Bcu2CoDescriptor { data_ptr: 0xCD, config: ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
    Bcu2CoDescriptor { data_ptr: 0xCE, config: ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
];

/// Factory group addresses, TSAPs 1..=7 in table order.
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

// RT2 uses association slot `ASAP` as the sending association. Keeping the
// rows in this order therefore makes slot 0 the spare row while slots 1..=7
// name their matching objects.
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

pub fn definition() -> Bcu2DeviceDefinition {
    Bcu2DeviceDefinition {
        manufacturer_id: 0x00FA,
        app_manufacturer_id: 0x00FA,
        device_type: 0x0B20,
        version: 1,
        pei_type: 0,
        individual_address: dut_ia(),
        max_group_addresses: 14,
        max_associations: 21,
        ram_flags_ptr: 0xD0,
        comm_objects: COM_OBJECTS,
        group_addresses: GROUP_ADDRESSES,
        associations: ASSOCIATIONS,
        app_params: None,
    }
}

pub fn identity() -> DeviceIdentity {
    DeviceIdentity { serial_number: SERIAL_NUMBER, order_info: [0; 10], hardware_type: [0; 6] }
}

/// The factory boot image: tables populated, application loaded and
/// running — a commissioned device, which is what the group and
/// transport suites expect to find.
pub fn factory_snapshot() -> MicroSnapshot {
    MicroSnapshot {
        eeprom: definition().build_eeprom().to_vec(),
        auth_keys: vec![[0xFF; 4]; 16],
        lsm_states: [
            LoadState::Loaded.into(),
            LoadState::Loaded.into(),
            LoadState::Loaded.into(),
            LoadState::Unloaded.into(),
        ],
        table_refs: [0x0116, 0, 0, 0],
        device_control: 0,
        option_reg: 0,
        hardware_type: None,
    }
}

#[cfg(test)]
mod tests {
    use zweidraehte_microdevice::device::PollInput;

    use super::*;

    #[test]
    fn malformed_transport_control_does_not_close_the_connection() {
        let mut device = factory_snapshot().restore::<Family>(identity(), 1);

        let connect = [0xB0, 0xAF, 0xFE, 0x10, 0x01, 0x60, 0x80];
        assert!(device.poll(PollInput::Frame(&connect), 0).frames.is_empty());

        let malformed_disconnect = [0xB0, 0xAF, 0xFE, 0x10, 0x01, 0x61, 0x81, 0x11];
        assert!(device.poll(PollInput::Frame(&malformed_disconnect), 200).frames.is_empty());

        let descriptor_read = [0xBC, 0xAF, 0xFE, 0x10, 0x01, 0x61, 0x43, 0x00];
        let response = device.poll(PollInput::Frame(&descriptor_read), 2_200);
        assert_eq!(response.frames.len(), 2);
        assert_eq!(response.frames[0].as_slice(), &[0xB0, 0x10, 0x01, 0xAF, 0xFE, 0x60, 0xC2]);
        assert_eq!(response.frames[1].as_slice(), &[0xBC, 0x10, 0x01, 0xAF, 0xFE, 0x63, 0x43, 0x40, 0x00, 0x20]);
    }
}
