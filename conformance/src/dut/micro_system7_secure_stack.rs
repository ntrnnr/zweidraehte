//! Data Secure composed onto the polling micro System 7 fixture.
//!
//! The base product remains mask 0705h and keeps its RT8 tables and absolute
//! memory layout. This module adds only the profile-module state: Security IO,
//! its Group Object Table host, security tables, and the durable sequence
//! resource.

use zweidraehte_microdevice::SecureSystem7;
use zweidraehte_microdevice::families::system7::{System7CoDescriptor, System7DeviceDefinition};
use zweidraehte_microdevice::snapshot::{MicroSnapshot, SecureMicroSnapshot};
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::messages::apdu::load_control::LoadState;

use super::fixture_common::{SECURE_FDSK, sec_table_sizes, security_snapshot};
use super::micro_secure_store::MicroSecureStore;
use super::micro_system7_stack::{self, MicroSystem7ConformanceMemoryPolicy, MicroSystem7DutFamily};
use crate::tests::security::variables::{GK1, GK2, GK3, GK4, GK5, TK1};

/// The conformance application needs key indices 1..=6.
pub const GROUP_KEY_CAPACITY: usize = 8;
/// One flag for each slot in the fixture's eight-entry COT.
pub const GROUP_OBJECT_CAPACITY: usize = 8;

pub type Device = SecureSystem7<
    MicroSecureStore,
    GROUP_KEY_CAPACITY,
    GROUP_OBJECT_CAPACITY,
    0x4000,
    0x4200,
    0x00FA,
    0x0B70,
    1,
    0,
    MicroSystem7ConformanceMemoryPolicy,
>;
pub type Snapshot = SecureMicroSnapshot<MicroSecureStore, GROUP_KEY_CAPACITY, GROUP_OBJECT_CAPACITY>;

/// Local factory state before ETS installs the Tool Key and Security tables.
pub fn factory_snapshot() -> Snapshot {
    let base: MicroSnapshot = micro_system7_stack::factory_snapshot();
    let security = security_snapshot::<GROUP_KEY_CAPACITY, 0, GROUP_OBJECT_CAPACITY>(
        SECURE_FDSK,
        LoadState::Unloaded,
        &[],
        &[],
        &[],
    );

    Snapshot { base, security, sequence: MicroSecureStore, fdsk: SECURE_FDSK }
}

// AN158 defines a four-object sample application that differs from the
// general System 7 fixture. In particular all four objects are bit-sized and
// their sending and receiving group addresses are fixed by the template.
// Keeping it here prevents certification-only links from leaking into the
// product firmware or its MTXML.
static EITT_GROUP_ADDRESSES: &[GroupAddress] = &[
    GroupAddress([0x09, 0x01]), // 1/1/1: GO0 receive, GK1
    GroupAddress([0x12, 0x02]), // 2/2/2: GO0 send, GK2
    GroupAddress([0x1B, 0x03]), // 3/3/3: GO1 receive, GK3
    GroupAddress([0x24, 0x04]), // 4/4/4: GO1 send, GK4
    GroupAddress([0x2D, 0x05]), // 5/5/5: GO2 plain
    GroupAddress([0x36, 0x06]), // 6/6/6: GO3, GK5
];

static EITT_COM_OBJECTS: &[System7CoDescriptor] = &[
    System7CoDescriptor { data_ptr: 0x00C6, config: 0xDF, value_type: 0x00 },
    System7CoDescriptor { data_ptr: 0x00C7, config: 0xDF, value_type: 0x00 },
    System7CoDescriptor { data_ptr: 0x00C8, config: 0xDF, value_type: 0x00 },
    System7CoDescriptor { data_ptr: 0x00C9, config: 0xDF, value_type: 0x00 },
];

// System 7 selects an object's sending group address by the first matching
// association. Put those rows first, followed by the two receive-only links.
static EITT_ASSOCIATIONS: &[(u8, u8)] = &[(2, 0), (4, 1), (5, 2), (6, 3), (1, 0), (3, 1)];

fn eitt_definition() -> System7DeviceDefinition {
    let mut definition = micro_system7_stack::definition();
    definition.comm_objects = EITT_COM_OBJECTS;
    definition.group_addresses = EITT_GROUP_ADDRESSES;
    definition.associations = EITT_ASSOCIATIONS;
    definition
}

/// EITT's operator-provisioned AN158 sample application.
///
/// This is the process boot image and the target of `full_reset`. A local
/// master reset deliberately uses [`factory_snapshot`] instead so the device
/// still returns to its FDSK and an unloaded Security IO.
pub fn boot_snapshot() -> Snapshot {
    let mut base = micro_system7_stack::factory_snapshot();
    base.eeprom = MicroSystem7DutFamily::build_eeprom(&eitt_definition()).to_vec();

    let mut group_entries = [0u8; 5 * 18];
    for (slot, (index, key)) in [(1u16, GK1), (2, GK2), (3, GK3), (4, GK4), (6, GK5)].into_iter().enumerate() {
        let offset = slot * 18;
        group_entries[offset..offset + 2].copy_from_slice(&index.to_be_bytes());
        group_entries[offset + 2..offset + 18].copy_from_slice(&key);
    }

    let security = security_snapshot::<GROUP_KEY_CAPACITY, 0, GROUP_OBJECT_CAPACITY>(
        TK1,
        LoadState::Loaded,
        &group_entries,
        &[],
        &[0x01, 0x03, 0x00, 0x02],
    );

    Snapshot { base, security, sequence: MicroSecureStore, fdsk: SECURE_FDSK }
}

const _: () = assert!(GROUP_KEY_CAPACITY >= 6);
const _: () = assert!(GROUP_OBJECT_CAPACITY >= 8);
const _: () = assert!(GROUP_KEY_CAPACITY <= sec_table_sizes::SIAT);

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_proto::security::SecurityState;

    #[test]
    fn local_factory_and_operator_boot_are_distinct_security_states() {
        let factory = factory_snapshot();
        let factory_security = SecurityState::from_config(factory.security.clone());

        assert_eq!(factory_security.tool_key(), SECURE_FDSK);
        assert!(!factory_security.security_mode_enabled());
        assert_eq!(factory_security.load_state(), LoadState::Unloaded);
        assert_eq!(
            usize::from(factory.base.eeprom[0x200]),
            micro_system7_stack::COM_OBJECTS.len(),
            "factory image uses the general fixture COT",
        );

        let boot = boot_snapshot();
        let boot_security = SecurityState::from_config(boot.security.clone());

        assert_eq!(boot_security.tool_key(), TK1);
        assert!(!boot_security.security_mode_enabled());
        assert_eq!(boot_security.load_state(), LoadState::Loaded);
        assert_eq!(boot.base.eeprom[0x200], 4, "EITT boot uses the AN158 sample COT");
    }
}
