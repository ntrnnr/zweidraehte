//! BCU2 micro-stack fixture composed with Data Secure.
//!
//! Its security capacities match the shipping secure BCU2 light switch. That
//! lets the configuration runner download the real product rather than a
//! reduced fixture whose MTXML promises a different device. Like the full
//! stack conformance DUTs, this process always boots the EITT sample
//! application; a local master reset is the separate path to an unprovisioned
//! security state.

use devices::light_switch::micro;
use zweidraehte_microdevice::families::bcu2::{Bcu2CoDescriptor, Bcu2DeviceDefinition};
use zweidraehte_microdevice::snapshot::{MicroSnapshot, SecureMicroSnapshot};
use zweidraehte_microdevice::{MemoryAccessPolicy, SecureBcu2};
use zweidraehte_proto::access::{AccessLevel, AccessPolicy};
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::memory::{MemoryPermission, MemoryRegion};
use zweidraehte_proto::messages::apdu::load_control::LoadState;
use zweidraehte_proto::security::{SecurityConfig, SiatAccess};

use super::bcu2_stack;
use super::fixture_common::{SECURE_FDSK, secure_seq_store};
use super::micro_secure_store::MicroSecureStore;
use crate::tests::security::variables::{GK1, GK2, GK3, GK4, GK5, TK1};

pub const GROUP_KEY_CAPACITY: usize = micro::BCU2_SECURE_GROUP_KEY_CAPACITY;
pub const SIAT_CAPACITY: usize = micro::BCU2_SECURE_SIAT_CAPACITY;
pub const GROUP_OBJECT_CAPACITY: usize = micro::BCU2_SECURE_GROUP_OBJECT_CAPACITY;
pub const P2P_KEY_CAPACITY: usize = micro::BCU2_SECURE_P2P_KEY_CAPACITY;

/// Memory layout required by AN177 plus the two AN193 policy probes.
///
/// The real BCU2 EEPROM remains the backing store. Only its permission
/// boundaries differ from a product build, selected through a zero-sized
/// family policy so certification scaffolding cannot leak into firmware.
pub struct Bcu2SecureConformanceMemoryPolicy;

impl Bcu2SecureConformanceMemoryPolicy {
    const DENY: AccessPolicy = AccessPolicy::new(0x000, 0x000);

    fn overlaps(address: u16, length: usize, region_start: u16, region_length: u16) -> bool {
        let request_start = u32::from(address);
        let request_end = request_start.saturating_add(u32::try_from(length).unwrap_or(u32::MAX));
        let region_start = u32::from(region_start);
        let region_end = region_start + u32::from(region_length);
        request_start < region_end && region_start < request_end
    }
}

impl MemoryAccessPolicy for Bcu2SecureConformanceMemoryPolicy {
    const REGIONS: &'static [MemoryRegion] = &[
        MemoryRegion::open(0x0000, 0x0100),
        MemoryRegion::open(0x0100, 0x0200),
        MemoryRegion::read_only(0x0300, 0x0010, MemoryPermission::Open),
        MemoryRegion::write_only(0x0310, 0x0010, MemoryPermission::Open),
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

    fn security_policy(address: u16, length: usize) -> AccessPolicy {
        // TSSJ 3.7.2.8 asks the PIXIT for examples of these policies. A
        // request touching a stricter window inherits that stricter policy;
        // it must not gain access merely by starting one octet before it.
        if Self::overlaps(address, length, 0x03D0, 0x0010) {
            Self::DENY
        } else if Self::overlaps(address, length, 0x03E0, 0x0010) {
            AccessPolicy::OPEN_OFF_TOOL_ON
        } else {
            AccessPolicy::READ_OPEN_WRITE_TOOL
        }
    }
}

pub type Device =
    SecureBcu2<MicroSecureStore, GROUP_KEY_CAPACITY, GROUP_OBJECT_CAPACITY, Bcu2SecureConformanceMemoryPolicy>;
pub type Snapshot = SecureMicroSnapshot<MicroSecureStore, GROUP_KEY_CAPACITY, GROUP_OBJECT_CAPACITY>;

// Keep the generated secure light-switch product at its shipping four-object
// capacity. The larger vendor Group Objects application is a separate boot
// image used only by the base-conformance process below.
#[rustfmt::skip]
static PRODUCT_GROUP_ADDRESSES: &[GroupAddress] = &[
    GroupAddress([0x10, 0x00]),
    GroupAddress([0x10, 0x01]),
    GroupAddress([0x10, 0x02]),
    GroupAddress([0x10, 0x03]),
];

static PRODUCT_COM_OBJECTS: &[Bcu2CoDescriptor] = &[
    Bcu2CoDescriptor { data_ptr: 0xC6, config: bcu2_stack::ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
    Bcu2CoDescriptor { data_ptr: 0xC7, config: bcu2_stack::ALL_FLAGS_LOW_PRIO, value_type: 0x06 },
    Bcu2CoDescriptor { data_ptr: 0xC8, config: bcu2_stack::ALL_FLAGS_LOW_PRIO, value_type: 0x08 },
    Bcu2CoDescriptor { data_ptr: 0xCB, config: 0x4F, value_type: 0x00 },
];

static PRODUCT_ASSOCIATIONS: &[(u8, u8)] = &[(1, 0), (2, 1), (3, 2), (4, 3)];

/// The secure application uses a distinct identity and retains the shipping
/// product's compact four-object roster.
pub fn definition() -> zweidraehte_microdevice::Bcu2DeviceDefinition {
    let mut definition = bcu2_stack::definition();
    definition.device_type = 0x0B21;
    definition.comm_objects = PRODUCT_COM_OBJECTS;
    definition.group_addresses = PRODUCT_GROUP_ADDRESSES;
    definition.associations = PRODUCT_ASSOCIATIONS;
    definition
}

/// Device state after a local factory reset, before tool-key provisioning.
///
/// This is deliberately not the conformance process's boot image. The latter
/// models the application an EITT operator loads before a run, while a local
/// reset must still revert the Tool Key to the FDSK and unload Security IO.
pub fn local_factory_snapshot() -> Snapshot {
    let mut base: MicroSnapshot = bcu2_stack::factory_snapshot();
    base.eeprom = definition().build_eeprom_for_mask(0x0021).to_vec();

    let security: SecurityConfig<GROUP_KEY_CAPACITY, P2P_KEY_CAPACITY, GROUP_OBJECT_CAPACITY> = SecurityConfig {
        // A local reset restores the device-specific factory key.
        tool_key: SECURE_FDSK,
        ..Default::default()
    };

    Snapshot { base, security, sequence: MicroSecureStore, fdsk: SECURE_FDSK }
}

/// Base-profile fixture for running the ordinary BCU2 test templates through
/// the secure composition.
///
/// The application and its mixed-width group objects are the same ones used
/// by mask 0020h. Only the mask, extended frame budget, and composed Security
/// IO differ. Security itself starts uncommissioned so the base templates can
/// exercise the services that remain plain while Security Mode is off.
pub fn base_profile_snapshot() -> Snapshot {
    let mut snapshot = local_factory_snapshot();
    snapshot.base.eeprom = bcu2_stack::definition().build_eeprom_for_mask(0x0021).to_vec();

    snapshot
}

// The AN158 collection defines this four-object application as bench setup,
// but its XML only commissions the Security IO after factory-resetting the
// DUT. Real EITT operation therefore includes an operator reload. Keeping the
// application here, in the conformance fixture, avoids teaching either the
// shipping firmware or its product database about certification-only GAs.
static EITT_GROUP_ADDRESSES: &[GroupAddress] = &[
    GroupAddress([0x09, 0x01]), // 1/1/1: GO0 receive, GK1
    GroupAddress([0x12, 0x02]), // 2/2/2: GO0 send, GK2
    GroupAddress([0x1B, 0x03]), // 3/3/3: GO1 receive, GK3
    GroupAddress([0x24, 0x04]), // 4/4/4: GO1 send, GK4
    GroupAddress([0x2D, 0x05]), // 5/5/5: GO2 plain
    GroupAddress([0x36, 0x06]), // 6/6/6: GO3, GK5
];

// AN158 describes all four objects as bit-sized `dpt_none` values. Reusing
// the product fixture's mixed-width smoke-test roster would add a data octet
// to GO1's response and test a different application than the template names.
static EITT_COM_OBJECTS: &[Bcu2CoDescriptor] = &[
    Bcu2CoDescriptor { data_ptr: 0xC6, config: bcu2_stack::ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
    Bcu2CoDescriptor { data_ptr: 0xC7, config: bcu2_stack::ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
    Bcu2CoDescriptor { data_ptr: 0xC8, config: bcu2_stack::ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
    Bcu2CoDescriptor { data_ptr: 0xC9, config: bcu2_stack::ALL_FLAGS_LOW_PRIO, value_type: 0x00 },
];

// BCU2 uses RT2: association slot `ASAP` is the sending association for that
// object. The first four rows are therefore positional; receive-only links
// follow them.
static EITT_ASSOCIATIONS: &[(u8, u8)] = &[(2, 0), (4, 1), (5, 2), (6, 3), (1, 0), (3, 1)];

fn eitt_definition() -> Bcu2DeviceDefinition {
    let mut definition = definition();
    definition.comm_objects = EITT_COM_OBJECTS;
    definition.group_addresses = EITT_GROUP_ADDRESSES;
    definition.associations = EITT_ASSOCIATIONS;
    definition
}

/// EITT's operator-provisioned AN158 sample application.
pub fn boot_snapshot() -> Snapshot {
    let mut base = bcu2_stack::factory_snapshot();
    base.eeprom = eitt_definition().build_eeprom_for_mask(0x0021).to_vec();

    // The operator-loaded sample application is complete. Preparation still
    // exercises Unload -> StartLoading -> LoadCompleted around its reload;
    // starting Loaded also makes later full-reset boundaries model the bench
    // state expected by persistence cases.
    let mut security: SecurityConfig<GROUP_KEY_CAPACITY, P2P_KEY_CAPACITY, GROUP_OBJECT_CAPACITY> = SecurityConfig {
        // EITT provisions this known tool key before secure exchanges.
        tool_key: TK1,
        // The sample application is already present in the boot image.
        load_state: LoadState::Loaded,
        ..Default::default()
    };

    let mut group_entries = [0u8; 5 * 18];
    for (slot, (index, key)) in [(1u16, GK1), (2, GK2), (3, GK3), (4, GK4), (6, GK5)].into_iter().enumerate() {
        let offset = slot * 18;
        group_entries[offset..offset + 2].copy_from_slice(&index.to_be_bytes());
        group_entries[offset + 2..offset + 18].copy_from_slice(&key);
    }
    security.grp_keys.write_entries(0, &group_entries).expect("five group keys fit");
    security.go_flags.write_entries(0, &[0x01, 0x03, 0x00, 0x02]).expect("four GO flags fit");

    Snapshot { base, security, sequence: MicroSecureStore, fdsk: SECURE_FDSK }
}

/// Seed the high-write SIAT half when the EITT factory image is first loaded.
/// It must happen only at a factory boundary: doing this on every boot would
/// resurrect entries a conformance case intentionally erased.
pub fn seed_boot_siat() {
    let mut store = secure_seq_store().borrow_mut();
    store.siat_write_entry(0, 0xAFFE, [0; 6]).expect("EDI SIAT entry fits");
    store.siat_write_entry(1, 0xAFFD, [0; 6]).expect("alternate EDI SIAT entry fits");
}

const _: () = assert!(GROUP_OBJECT_CAPACITY >= 4);
const _: () = assert!(SIAT_CAPACITY <= super::fixture_common::sec_table_sizes::SIAT);
