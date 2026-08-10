//! System 7 **Data Secure** DUT stack definition for conformance tests.
//!
//! The crossing of [`system7_stack`](super::system7_stack) (RT8 tables,
//! the absolute System 7 memory map with EEPROM-backed test regions, the
//! five-object base roster, 16 authorization levels) and
//! [`systemb_secure_stack`](super::systemb_secure_stack) (KNX Data Secure over the
//! shared-memory SIAT store, the Certification Object for AN163, the
//! secure GO-diagnostics strategy). It exists to run the vendor TSSJ
//! DataSecurity template against the System 7 family.
//!
//! # Fixture
//!
//! The communication-object set is the System B secure DUT's, verbatim —
//! all seventeen objects **including** the BYTE3 four. That is not
//! nostalgia: the AN170 GO-diagnostics addresses 3/1/6 and 3/1/7
//! associate to CO 7 (`GO2_BYTE3`), and the TSSJ `Data` strings pin GO
//! indexes literally, so dropping the BYTE3 objects would re-point AN170
//! at the wrong objects (or at nothing). Keeping the set identical also
//! keeps every group address, every TSAP, every group key and every GO
//! security flag congruent with the System B secure DUT — which is what
//! lets the data-security patch set anchor the same telegrams on both
//! families.
//!
//! The one family twist: `#[ets(index = ...)]` runs 1..17 here where the
//! System B fixture runs 0..16, because System 7 pins `FIRST_ASAP = 0`
//! (logical == wire) and the wire ASAPs must stay 1..17. M112 slot 0 is
//! a spare, exactly as on the plain System 7 DUT.
//!
//! # Object roster
//!
//! | Index | Object |
//! |---|---|
//! | 0–4 | Device, AddrTab, AssocTab, AppProg, AppProg2 (family base) |
//! | 5 | Security IO (OT 17) — `SEC_INTF_OBJ_INDEX = 05` in the profile |
//! | 6 | Group Object Table (OT 9) — host for PID_GO_DIAGNOSTICS |
//! | 7 | Certification Object (OT C351h) — AN163 roles + extended addressing |

use core::cell::RefCell;

use zweidraehte_device::HasSecurityMode;
use zweidraehte_device::prelude::*;
use zweidraehte_device::{
    SecureDeviceBuilder,
    bcus::system_7::{
        System7DeviceConfig, System7DeviceModel, System7DeviceState, System7MemoryMap, System7ProductLayout,
        System7StateInit, Tp1Augment, Tp1ExtensionConfig, Tp1ExtensionState, create_system_7_objects,
    },
    bcus::system_b::{DiagnosticsAugment, GroupObjectTableAugment, WithSecureGoSend},
    context::layer::LayerContext,
    device_model::{DeviceModelEvent, DeviceModelNotifier, DmNotificationSlot},
    layers::application::services::StandardSecureAlServices,
    layers::secure_application::WithP2p,
    layers::transport::TlStyle,
    objects::tables::{Application, HasLoadStateMachine, LoadEvent},
    restart::EraseCode,
    security::{SecureAugmentBundle, SecureExtensionConfig, SecureExtensionState, SecureResources},
    service::ServiceRegistry,
    storage::{HasDeviceConfig, StaticSecureIdentity},
};
use zweidraehte_proto::AccessContext;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};

use super::fixture_common::{
    CONFORMANCE_DD2, CONFORMANCE_USER_MANUFACTURER_INFO, CertificationObjectAugment, GetrandomRng, SECURE_FDSK,
    ShmSiatStore, TestParameters, sec_table_sizes,
};

// ============================================================================
// Communication objects — the System B secure fixture on RT8 tables
// ============================================================================
//
// Field-for-field the System B secure DUT's set (see `harness::systemb_stack`
// for the shadow-object rationale), at ets indices 1..17 so the wire
// ASAPs are identical under `FIRST_ASAP = 0`.

pub mod comm_objs {
    use zweidraehte_device::ets::EtsComObjects;
    use zweidraehte_device::objects::comm::ComObject;
    use zweidraehte_proto::dpt::{DPT_Colour_RGB, DPT_Switch, DPT_Value_1_Ucount};

    #[derive(EtsComObjects)]
    #[ets(bus_hook)]
    pub struct System7SecureComObjects {
        /// GO0: Main 1-bit object (UINT1) whose flags/value GO1-GO3 shadow.
        #[ets(index = 1)]
        pub go_0: ComObject<DPT_Switch>,

        /// GO1: GO0's communication flags.
        #[ets(index = 2)]
        pub go_1_comm_flags: ComObject<DPT_Value_1_Ucount>,

        /// GO2: GO0's configuration flags from the COT.
        #[ets(index = 3, initial = DPT_Value_1_Ucount::from(0xDFu8))]
        pub go_2_config_flags: ComObject<DPT_Value_1_Ucount>,

        /// GO3: GO0's value as 8-bit.
        #[ets(index = 4)]
        pub go_3_value: ComObject<DPT_Value_1_Ucount>,

        /// GO0_BYTE3: 3-byte main object. Its shadow set stays because
        /// the AN170 diagnostics GAs (3/1/6, 3/1/7) associate to
        /// GO2_BYTE3 and the template pins the GO indexes literally.
        #[ets(index = 5)]
        pub go_0_byte3: ComObject<DPT_Colour_RGB>,

        /// GO1_BYTE3: GO0_BYTE3's communication flags.
        #[ets(index = 6)]
        pub go_1_byte3_comm_flags: ComObject<DPT_Value_1_Ucount>,

        /// GO2_BYTE3: GO0_BYTE3's configuration flags — and the target
        /// of the Section 6.2 / AN170 GO-diagnostics group addresses.
        #[ets(index = 7, initial = DPT_Value_1_Ucount::from(0xDFu8))]
        pub go_2_byte3_config_flags: ComObject<DPT_Value_1_Ucount>,

        /// GO3_BYTE3: GO0_BYTE3's value as 3-byte.
        #[ets(index = 8)]
        pub go_3_byte3_value: ComObject<DPT_Colour_RGB>,

        /// GO4: read-on-init test object.
        #[ets(index = 9)]
        pub go_4: ComObject<DPT_Value_1_Ucount>,

        /// GO5: 8-bit object for network layer 3.1 (long-format response).
        #[ets(index = 10)]
        pub go_5_network_test: ComObject<DPT_Value_1_Ucount>,

        /// GO6: 1-bit object for transport layer 2.1 + security GO_SEC_2.
        #[ets(index = 11)]
        pub go_6_transport_test: ComObject<DPT_Switch>,

        /// GO_SEC_0: receives on 1/1/1, transmits on 2/2/2 (auth-only).
        #[ets(index = 12)]
        pub go_sec_0: ComObject<DPT_Switch>,

        /// GO_SEC_1: receives on 3/3/3, transmits on 4/4/4 (auth+conf).
        #[ets(index = 13)]
        pub go_sec_1: ComObject<DPT_Switch>,

        /// GO_SEC_3: receives on 6/6/6 (conf-only flag test).
        #[ets(index = 14)]
        pub go_sec_3: ComObject<DPT_Switch>,

        /// GO_DIAG_NO_C: 1-byte object without the C flag (6.2.6/6.2.14).
        #[ets(index = 15)]
        pub go_diag_no_c: ComObject<DPT_Value_1_Ucount>,

        /// GO_DIAG_NO_W: 1-byte object without the W flag (6.2.6).
        #[ets(index = 16)]
        pub go_diag_no_w: ComObject<DPT_Value_1_Ucount>,

        /// GO_DIAG_NO_T: 1-byte object without the T flag (6.2.14).
        #[ets(index = 17)]
        pub go_diag_no_t: ComObject<DPT_Value_1_Ucount>,
    }
}

use comm_objs::{Index as CoIndex, System7SecureComObjects};
use std::sync::atomic::{AtomicPtr, Ordering};
use zweidraehte_device::objects::comm::{ComObjectBusHook, ComObjectStatus};
use zweidraehte_device::objects::tables::CommunicationObjectTable;
use zweidraehte_device::prelude::ComObjectFlags;

// ============================================================================
// CoTab pointer for the shadow-object hook
// ============================================================================
//
// Same pattern as the other DUTs (`set_conformance_cot` /
// `set_system7_cot`): the hook needs the live CoTab from `&mut self`
// alone, so the DUT binary parks a pointer in a process-global static.

static COT_PTR: AtomicPtr<RefCell<conformance_config::CoTab>> = AtomicPtr::new(core::ptr::null_mut());

/// Publish the COT reference used by the shadow-object hook.
///
/// Call once from the System 7 secure DUT binary's `main` after stack
/// construction.
///
/// # Safety
/// The caller guarantees that `cot` remains a valid reference for the
/// duration of the process.
pub unsafe fn set_system7_secure_cot(cot: &RefCell<conformance_config::CoTab>) {
    COT_PTR.store(cot as *const _ as *mut _, Ordering::Release);
}

fn system7_secure_cot() -> Option<&'static RefCell<conformance_config::CoTab>> {
    let ptr = COT_PTR.load(Ordering::Acquire);
    // SAFETY: if non-null, the pointer was installed by
    // `set_system7_secure_cot` with the caller's guarantee that the
    // referent outlives the process.
    unsafe { ptr.as_ref() }
}

// BCU1-style shadow-object hook — the System B secure DUT's, with the
// COT wire-indexed at the same ASAPs (GO0 at 1, GO0_BYTE3 at 5).

impl ComObjectBusHook for System7SecureComObjects {
    fn prepare_read(&mut self, idx: u16) {
        match CoIndex::from_index(idx) {
            Some(CoIndex::Go1CommFlags) => {
                let flags = self.go_0.status.to_flags_byte();
                self.go_1_comm_flags.value.as_mut()[0] = flags;
            }
            Some(CoIndex::Go2ConfigFlags) => {
                // GO0 is at wire ASAP 1; the COT is wire-indexed.
                if let Some(cot) = system7_secure_cot()
                    && let Some(flags) = cot.borrow().object_flags(1)
                {
                    self.go_2_config_flags.value.as_mut()[0] = flags.to_byte();
                }
            }
            Some(CoIndex::Go3Value) => {
                let go0_value = self.go_0.value.as_ref()[0];
                self.go_3_value.value.as_mut()[0] = go0_value;
            }
            Some(CoIndex::Go1Byte3CommFlags) => {
                let flags = self.go_0_byte3.status.to_flags_byte();
                self.go_1_byte3_comm_flags.value.as_mut()[0] = flags;
            }
            Some(CoIndex::Go2Byte3ConfigFlags) => {
                // GO0_BYTE3 is at wire ASAP 5.
                if let Some(cot) = system7_secure_cot()
                    && let Some(flags) = cot.borrow().object_flags(5)
                {
                    self.go_2_byte3_config_flags.value.as_mut()[0] = flags.to_byte();
                }
            }
            Some(CoIndex::Go3Byte3Value) => {
                let go0_value = self.go_0_byte3.value.as_ref();
                self.go_3_byte3_value.value.as_mut().copy_from_slice(go0_value);
            }
            _ => {}
        }
    }

    fn handle_write(&mut self, idx: u16) {
        match CoIndex::from_index(idx) {
            Some(CoIndex::Go1CommFlags) => {
                let flags = self.go_1_comm_flags.value.as_ref()[0];
                self.go_0.status = ComObjectStatus::from_flags_byte(flags);
            }
            Some(CoIndex::Go2ConfigFlags) => {
                if let Some(cot) = system7_secure_cot() {
                    let new_flags = ComObjectFlags::from_byte(self.go_2_config_flags.value.as_ref()[0]);
                    cot.borrow_mut().set_object_flags(1, new_flags);
                }
            }
            Some(CoIndex::Go3Value) => {
                let new_value = self.go_3_value.value.as_ref()[0];
                self.go_0.value.as_mut()[0] = new_value;
            }
            Some(CoIndex::Go1Byte3CommFlags) => {
                let flags = self.go_1_byte3_comm_flags.value.as_ref()[0];
                self.go_0_byte3.status = ComObjectStatus::from_flags_byte(flags);
            }
            Some(CoIndex::Go2Byte3ConfigFlags) => {
                if let Some(cot) = system7_secure_cot() {
                    let new_flags = ComObjectFlags::from_byte(self.go_2_byte3_config_flags.value.as_ref()[0]);
                    cot.borrow_mut().set_object_flags(5, new_flags);
                }
            }
            Some(CoIndex::Go3Byte3Value) => {
                let new_value = self.go_3_byte3_value.value.as_ref();
                self.go_0_byte3.value.as_mut().copy_from_slice(new_value);
            }
            _ => {}
        }
    }
}

// ============================================================================
// Compile-time configuration — the System B secure layout on RT8 tables
// ============================================================================
//
// Same 18 group addresses in the same sorted order as the System B
// secure DUT, so the TSAP numbering — and with it the group-key table —
// is congruent. See `harness::systemb_stack` for the TSAP → CO map.

pub mod conformance_config {
    use zweidraehte_device::config::{CE, RE, ROI, TE, UE, WE};
    use zweidraehte_device::objects::tables::ComObjectType;
    use zweidraehte_device::system7_stack_config;

    system7_stack_config! {
        name: System7SecureConfig,
        individual_address: "1.0.1", // BDUT = 1.0.1, same as every other DUT

        group_addresses: {
            1 => "1/0/1",  // 0x0801 - network layer test 3.1
            2 => "1/1/1",  // 0x0901 - GO_SEC_0 receive
            3 => "2/0/0",  // 0x1000 - main object GO0
            4 => "2/0/1",  // 0x1001 - comm flags GO1
            5 => "2/0/2",  // 0x1002 - config flags GO2
            6 => "2/0/3",  // 0x1003 - value GO3
            7 => "2/0/5",  // 0x1005 - read on init GO4
            8 => "2/1/0",  // 0x1100 - GO0_BYTE3
            9 => "2/1/1",  // 0x1101 - GO1_BYTE3
            10 => "2/1/2", // 0x1102 - GO2_BYTE3
            11 => "2/1/3", // 0x1103 - GO3_BYTE3
            12 => "2/2/2", // 0x1202 - GO_SEC_0 transmit
            13 => "3/1/6", // 0x1906 - AN170 GO diagnostics (secure, GK6)
            14 => "3/1/7", // 0x1907 - AN170 GO diagnostics (plain)
            15 => "3/3/3", // 0x1B03 - GO_SEC_1 receive
            16 => "4/4/4", // 0x2404 - GO_SEC_1 transmit
            17 => "5/5/5", // 0x2D05 - transport layer 2.1 + GO_SEC_2
            18 => "6/6/6", // 0x3606 - GO_SEC_3 receive
        },

        comm_objects: {
            // GO0-GO3: 1-bit main object and shadows (ASAP 1-4).
            1 => (ComObjectType::Uint1 as u8, CE | TE | RE | WE | UE),
            2 => (ComObjectType::Uint4 as u8, CE | TE | RE | WE | UE),
            3 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE),
            4 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE | ROI),
            // BYTE3 set (ASAP 5-8) — AN170's diagnostics target is CO 7.
            5 => (ComObjectType::Byte3 as u8, CE | TE | RE | WE | UE),
            6 => (ComObjectType::Uint4 as u8, CE | TE | RE | WE | UE),
            7 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE),
            8 => (ComObjectType::Byte3 as u8, CE | TE | RE | WE | UE),
            // GO4-GO6 (ASAP 9-11).
            9 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE | ROI),
            10 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE),
            11 => (ComObjectType::Uint1 as u8, CE | TE | RE | WE | UE),
            // Security GO test objects (ASAP 12-14).
            12 => (ComObjectType::Uint1 as u8, CE | TE | RE | WE | UE),
            13 => (ComObjectType::Uint1 as u8, CE | TE | RE | WE | UE),
            14 => (ComObjectType::Uint1 as u8, CE | TE | RE | WE | UE),
            // Diagnostic flag-test objects (ASAP 15-17).
            15 => (ComObjectType::Byte1 as u8, TE | RE | WE | UE),
            16 => (ComObjectType::Byte1 as u8, CE | TE | RE | UE),
            17 => (ComObjectType::Byte1 as u8, CE | RE | WE | UE),
        },

        associations: {
            // Sending TSAP first for multi-GA objects — `sending_tsap()`
            // returns the first match in table order.
            1 => [10],
            12 => [12],
            2 => [12],
            3 => [1],
            4 => [2],
            5 => [3],
            6 => [4],
            7 => [9],
            8 => [5],
            9 => [6],
            14 => [7],
            10 => [7],
            13 => [7],
            11 => [8],
            16 => [13],
            15 => [13],
            17 => [11],
            18 => [14],
        },

        security: {
            p2p_key_capacity: 8,
            siat_capacity: 8,
            tool_key: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01",

            // The TSSJ template provisions keys by value, so these are
            // the Security Configuration Table's (TSSJ_SCT.csv) — the
            // same values as the System B secure DUT, at the same TSAPs
            // (the group-address list is identical, so the sorted TSAP
            // numbering is too). Sorted by TSAP for the S-AL's binary
            // search.
            group_keys: {
                2  => "AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA", // TSAP 2  (1/1/1) → GK1
                12 => "BB BB BB BB BB BB BB BB BB BB BB BB BB BB BB BB", // TSAP 12 (2/2/2) → GK2
                13 => "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF", // TSAP 13 (3/1/6) → GK6
                15 => "CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC", // TSAP 15 (3/3/3) → GK3
                16 => "DD DD DD DD DD DD DD DD DD DD DD DD DD DD DD DD", // TSAP 16 (4/4/4) → GK4
                18 => "EE EE EE EE EE EE EE EE EE EE EE EE EE EE EE EE", // TSAP 18 (6/6/6) → GK5
            },

            // GO security flags of the AN158 sample application — the
            // same objects as on System B, keyed by this family's wire
            // ASAPs (`FIRST_ASAP = 0`, so key == ASAP == table slot).
            go_flags: {
                12 => 0x01, // GO_SEC_0: A only
                13 => 0x03, // GO_SEC_1: A+C
                14 => 0x02, // GO_SEC_3: C only
            },
        },
    }
}

/// Where the movable tables live; the GA table is fixed at 4000h.
/// Same product-database choice as the plain System 7 DUT.
pub const AST_ADDRESS: u32 = 0x4100;
pub const COT_ADDRESS: u32 = 0x4200;

/// Table byte sizes and the security-table capacities derived from the
/// fixture's entry counts.
pub(crate) mod table_sizes {
    use super::conformance_config::System7SecureConfig;

    pub const ADT: usize = System7SecureConfig::ADDR8_SIZE;
    pub const AST: usize = System7SecureConfig::ASSO8_SIZE;
    pub const COT: usize = System7SecureConfig::COT_SIZE;

    /// Group key table capacity: one slot per address table entry.
    pub const GRP: usize = System7SecureConfig::NUM_GROUP_ADDRS;
    /// GO security flags capacity: one byte per communication object.
    pub const GO: usize = System7SecureConfig::NUM_COMM_OBJECTS;
}

// ============================================================================
// Device identity
// ============================================================================

pub mod device_info {
    use super::*;
    use zweidraehte_device::config::{MAX_APDU_LENGTH_EXTENDED, buffer_size_for_apdu};

    /// The System 7 secure DUT's device descriptor. Same mask and
    /// capacities as the plain System 7 DUT; a distinct application ID
    /// and hardware type so a mixed log is attributable.
    pub const DEVICE: DeviceDescriptor = DeviceDescriptor {
        mask_version: MaskVersion::System7Tp1,
        manufacturer_id: 0x00FA,
        hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x08],
        application_id: 0x0701,
        application_version: 0x01,
        max_address_table_entries: 254,
        max_association_table_entries: 254,
        max_com_objects: 254,
        pei_type: 0,
    };

    /// Serial number — the same as the plain System 7 DUT's, and what
    /// the profile's `SER_NUM` / `BDUT_SERIAL_NUMBER` carry. The secure
    /// sync services put it on the wire, so runner and DUT must agree.
    pub const SERIAL_NUMBER: [u8; 6] = [0xFE, 0xED, 0x07, 0x05, 0xCA, 0xFE];

    pub const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_EXTENDED;
    pub const BUFFER_SIZE: usize = buffer_size_for_apdu(MAX_APDU_LENGTH);
}

// ============================================================================
// Conformance state — secure family state plus EEPROM test regions
// ============================================================================

/// Same test-region sizes as the plain System 7 DUT.
pub const EEPROM_LINEAR_SIZE: usize = 256;
pub const EEPROM_LEVEL2_SIZE: usize = 224;
pub const EEPROM_LEVEL1_SIZE: usize = 256;
pub const USER_MEMORY_SIZE: usize = 16;

/// The secure extension state wrapping TP1, sized from the fixture.
type SecureS7ExtensionState =
    SecureExtensionState<Tp1ExtensionState, { table_sizes::GRP }, { sec_table_sizes::P2P }, { table_sizes::GO }>;

/// The inner System 7 device state with Data Secure.
type InnerState = System7DeviceState<
    { table_sizes::ADT },
    { table_sizes::AST },
    { table_sizes::COT },
    IpcSystem7SecureTestStack,
    SecureS7ExtensionState,
>;

/// Unified state for the System 7 secure conformance DUT.
pub struct SecureSystem7State {
    inner: InnerState,
    pub linear_memory: RefCell<[u8; EEPROM_LINEAR_SIZE]>,
    pub level2_memory: RefCell<[u8; EEPROM_LEVEL2_SIZE]>,
    pub level1_memory: RefCell<[u8; EEPROM_LEVEL1_SIZE]>,
    pub user_memory: RefCell<[u8; USER_MEMORY_SIZE]>,
    dm_slot: DmNotificationSlot,
}

impl SecureSystem7State {
    pub fn inner(&self) -> &InnerState {
        &self.inner
    }
}

// StackState is hand-written for the fixed compile-time APDU length —
// same rationale as every other conformance DUT.
impl StackState for SecureSystem7State {
    type Identity = <InnerState as StackState>::Identity;

    fn individual_address(&self) -> IndividualAddress {
        self.inner.individual_address()
    }
    fn set_individual_address(&self, addr: IndividualAddress) {
        self.inner.set_individual_address(addr);
    }
    fn identity(&self) -> &Self::Identity {
        self.inner.identity()
    }
    fn max_apdu_length(&self) -> u16 {
        device_info::MAX_APDU_LENGTH
    }
    fn set_max_apdu_length(&self, _length: u16) {
        // Fixed compile-time APDU length; no hardware-detection step.
    }
    fn is_programming_mode(&self) -> bool {
        self.inner.is_programming_mode()
    }
    fn set_programming_mode(&self, enabled: bool) {
        self.inner.set_programming_mode(enabled);
    }
}

// The pure-delegation trait bundle (family-agnostic despite the name).
zweidraehte_device::forward_device_state_traits!(impl SecureSystem7State => self.inner: InnerState);

impl DeviceModelNotifier for SecureSystem7State {
    fn notify(&self, event: DeviceModelEvent) {
        self.dm_slot.notify(event);
    }
    fn take_event(&self) -> Option<DeviceModelEvent> {
        self.dm_slot.take_event()
    }
}

// ============================================================================
// Memory map — the System 7 test map plus access-policy sub-regions
// ============================================================================

/// Memory map for the System 7 secure conformance DUT.
///
/// The plain System 7 test layout (regions inside the family's user
/// EEPROM, everything else falling through to [`System7MemoryMap`]) plus
/// the two access-policy sub-regions the TSSJ 3.8 memory cases need,
/// carved out of the level-2 block at the same tail position the
/// System B map uses (03D0h/03E0h at the end of its level-2 block):
///
/// - 5000h-50FFh: freely accessible, factory 0Fh
/// - 5100h-510Fh: read-only (computed pattern)
/// - 5110h-511Fh: write-only (reads fail; writes dropped)
/// - 5120h-51FFh: level-2 block, of which
///   - 51D0h-51DFh: access policy 000/000 — always denied
///   - 51E0h-51EFh: access policy 3FF/00C — open with Security Mode
///     off, Tool A+C only with it on
/// - 5200h-52FFh: level-1 block
/// - 7FF0h-7FFFh: user memory
///
/// The profile's `MEM_AP_000_000` / `MEM_AP_3FF_00C` variables point at
/// the two sub-regions (the template defaults, 0003D0h/0003E0h, are
/// unmapped on this family).
#[derive(Debug, Default, Clone, Copy)]
pub struct SecureSystem7MemoryMap;

impl SecureSystem7MemoryMap {
    pub const LINEAR_MEMORY_BASE: u16 = 0x5000;
    pub const READONLY_MEMORY_BASE: u16 = 0x5100;
    pub const READONLY_MEMORY_SIZE: u16 = 0x10;
    pub const WRITEONLY_MEMORY_BASE: u16 = 0x5110;
    pub const WRITEONLY_MEMORY_SIZE: u16 = 0x10;
    pub const LEVEL2_MEMORY_BASE: u16 = 0x5120;
    pub const LEVEL1_MEMORY_BASE: u16 = 0x5200;
    pub const USER_MEMORY_BASE: u16 = 0x7FF0;

    /// Access policy 000/000: nobody, ever.
    pub const AP_DENY_BASE: u16 = 0x51D0;
    /// Access policy 3FF/00C: everyone with Security Mode off, Tool A+C
    /// with it on.
    pub const AP_TOOL_BASE: u16 = 0x51E0;

    pub const fn new() -> Self {
        Self
    }

    /// Same partly-protected contract as the other conformance maps.
    fn partly_protected(address: u16, end_address: u16, writing: bool) -> Option<MemoryError> {
        const REGIONS: [(u16, u16); 6] = [
            (SecureSystem7MemoryMap::LINEAR_MEMORY_BASE, EEPROM_LINEAR_SIZE as u16),
            (SecureSystem7MemoryMap::READONLY_MEMORY_BASE, SecureSystem7MemoryMap::READONLY_MEMORY_SIZE),
            (SecureSystem7MemoryMap::WRITEONLY_MEMORY_BASE, SecureSystem7MemoryMap::WRITEONLY_MEMORY_SIZE),
            (SecureSystem7MemoryMap::LEVEL2_MEMORY_BASE, EEPROM_LEVEL2_SIZE as u16),
            (SecureSystem7MemoryMap::LEVEL1_MEMORY_BASE, EEPROM_LEVEL1_SIZE as u16),
            (SecureSystem7MemoryMap::USER_MEMORY_BASE, USER_MEMORY_SIZE as u16),
        ];

        let straddles = |base: u16, size: u16| address >= base && address < base + size && end_address > base + size;
        if !REGIONS.iter().any(|&(base, size)| straddles(base, size)) {
            return None;
        }

        let within = |octet: u16, base: u16, size: u16| octet >= base && octet < base + size;
        let tail = end_address.saturating_sub(1);
        for octet in [address, tail] {
            if writing && within(octet, Self::READONLY_MEMORY_BASE, Self::READONLY_MEMORY_SIZE) {
                return Some(MemoryError::WriteProtected);
            }
            if !writing && within(octet, Self::WRITEONLY_MEMORY_BASE, Self::WRITEONLY_MEMORY_SIZE) {
                return Some(MemoryError::WriteProtected);
            }
        }
        Some(MemoryError::AccessDenied)
    }
}

impl MemoryMap<SecureSystem7State> for SecureSystem7MemoryMap {
    fn read(
        &self,
        state: &SecureSystem7State,
        address: u16,
        data: &mut [u8],
        ctx: AccessContext,
    ) -> Result<usize, MemoryError> {
        let end_address = address.saturating_add(data.len() as u16);

        if address >= Self::LINEAR_MEMORY_BASE && end_address <= Self::LINEAR_MEMORY_BASE + EEPROM_LINEAR_SIZE as u16 {
            let offset = (address - Self::LINEAR_MEMORY_BASE) as usize;
            let mem = state.linear_memory.borrow();
            data.copy_from_slice(&mem[offset..offset + data.len()]);
            return Ok(data.len());
        }

        if address >= Self::READONLY_MEMORY_BASE
            && end_address <= Self::READONLY_MEMORY_BASE + Self::READONLY_MEMORY_SIZE
        {
            let offset = (address - Self::READONLY_MEMORY_BASE) as usize;
            for (i, byte) in data.iter_mut().enumerate() {
                *byte = (offset + i) as u8;
            }
            return Ok(data.len());
        }

        if address >= Self::WRITEONLY_MEMORY_BASE
            && end_address <= Self::WRITEONLY_MEMORY_BASE + Self::WRITEONLY_MEMORY_SIZE
        {
            return Err(MemoryError::WriteProtected);
        }

        // Access-policy sub-regions — checked before the enclosing
        // level-2 block so their policies take precedence.
        let security_on = state.security_mode_enabled();

        if address >= Self::AP_DENY_BASE && end_address <= Self::AP_DENY_BASE + 0x10 {
            return Err(MemoryError::AccessDenied);
        }

        if address >= Self::AP_TOOL_BASE && end_address <= Self::AP_TOOL_BASE + 0x10 {
            if !AccessPolicy::OPEN_OFF_TOOL_ON.can_read(&ctx, security_on) {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - Self::LEVEL2_MEMORY_BASE) as usize;
            let mem = state.level2_memory.borrow();
            data.copy_from_slice(&mem[offset..offset + data.len()]);
            return Ok(data.len());
        }

        if address >= Self::LEVEL2_MEMORY_BASE && end_address <= Self::LEVEL2_MEMORY_BASE + EEPROM_LEVEL2_SIZE as u16 {
            if !ctx.has_level(2) {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - Self::LEVEL2_MEMORY_BASE) as usize;
            let mem = state.level2_memory.borrow();
            data.copy_from_slice(&mem[offset..offset + data.len()]);
            return Ok(data.len());
        }

        if address >= Self::LEVEL1_MEMORY_BASE && end_address <= Self::LEVEL1_MEMORY_BASE + EEPROM_LEVEL1_SIZE as u16 {
            if !ctx.has_level(1) {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - Self::LEVEL1_MEMORY_BASE) as usize;
            let mem = state.level1_memory.borrow();
            data.copy_from_slice(&mem[offset..offset + data.len()]);
            return Ok(data.len());
        }

        if address >= Self::USER_MEMORY_BASE && end_address <= Self::USER_MEMORY_BASE + USER_MEMORY_SIZE as u16 {
            let offset = (address - Self::USER_MEMORY_BASE) as usize;
            let mem = state.user_memory.borrow();
            data.copy_from_slice(&mem[offset..offset + data.len()]);
            return Ok(data.len());
        }

        if let Some(e) = Self::partly_protected(address, end_address, false) {
            return Err(e);
        }

        System7MemoryMap::new().read(&state.inner, address, data, ctx)
    }

    fn write(
        &self,
        state: &SecureSystem7State,
        address: u16,
        data: &[u8],
        ctx: AccessContext,
    ) -> Result<usize, MemoryError> {
        let end_address = address.saturating_add(data.len() as u16);

        if address >= Self::LINEAR_MEMORY_BASE && end_address <= Self::LINEAR_MEMORY_BASE + EEPROM_LINEAR_SIZE as u16 {
            let offset = (address - Self::LINEAR_MEMORY_BASE) as usize;
            let mut mem = state.linear_memory.borrow_mut();
            mem[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        if address >= Self::READONLY_MEMORY_BASE
            && end_address <= Self::READONLY_MEMORY_BASE + Self::READONLY_MEMORY_SIZE
        {
            return Err(MemoryError::WriteProtected);
        }

        if address >= Self::WRITEONLY_MEMORY_BASE
            && end_address <= Self::WRITEONLY_MEMORY_BASE + Self::WRITEONLY_MEMORY_SIZE
        {
            return Ok(data.len());
        }

        let security_on = state.security_mode_enabled();

        if address >= Self::AP_DENY_BASE && end_address <= Self::AP_DENY_BASE + 0x10 {
            return Err(MemoryError::AccessDenied);
        }

        if address >= Self::AP_TOOL_BASE && end_address <= Self::AP_TOOL_BASE + 0x10 {
            if !AccessPolicy::OPEN_OFF_TOOL_ON.can_write(&ctx, security_on) {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - Self::LEVEL2_MEMORY_BASE) as usize;
            let mut mem = state.level2_memory.borrow_mut();
            mem[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        if address >= Self::LEVEL2_MEMORY_BASE && end_address <= Self::LEVEL2_MEMORY_BASE + EEPROM_LEVEL2_SIZE as u16 {
            if !ctx.has_level(2) {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - Self::LEVEL2_MEMORY_BASE) as usize;
            let mut mem = state.level2_memory.borrow_mut();
            mem[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        if address >= Self::LEVEL1_MEMORY_BASE && end_address <= Self::LEVEL1_MEMORY_BASE + EEPROM_LEVEL1_SIZE as u16 {
            if !ctx.has_level(1) {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - Self::LEVEL1_MEMORY_BASE) as usize;
            let mut mem = state.level1_memory.borrow_mut();
            mem[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        if address >= Self::USER_MEMORY_BASE && end_address <= Self::USER_MEMORY_BASE + USER_MEMORY_SIZE as u16 {
            let offset = (address - Self::USER_MEMORY_BASE) as usize;
            let mut mem = state.user_memory.borrow_mut();
            mem[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        if let Some(e) = Self::partly_protected(address, end_address, true) {
            return Err(e);
        }

        System7MemoryMap::new().write(&state.inner, address, data, ctx)
    }
}

// ============================================================================
// Stack definition
// ============================================================================

/// The security augment bundle: TP1 medium augment + Security IO, over
/// the shared-memory SIAT store.
type SecAugment<'a> = SecureAugmentBundle<
    'a,
    Tp1Augment<'a>,
    ShmSiatStore,
    { table_sizes::GRP },
    { sec_table_sizes::P2P },
    { table_sizes::GO },
>;

/// The System 7 secure DUT's augment chain. Ordering fixes the
/// additional-object indexes: Security at 5, Group Object Table at 6,
/// Certification Object at 7.
#[derive(ServiceRegistry)]
pub struct System7SecureAugments<'a> {
    #[service(augment)]
    pub sec: SecAugment<'a>,
    /// System 7 has no Group Object Table object in its base roster —
    /// this provides OT 9 as the host for PID_GO_DIAGNOSTICS
    /// (06 Profiles v02.02.01 §9.2.1.1.1.1).
    #[service(augment)]
    pub go_table: GroupObjectTableAugment,
    #[service(augment)]
    pub cert: CertificationObjectAugment,
    #[service(augment)]
    pub diag: DiagnosticsAugment<'a, WithSecureGoSend>,
}

/// Stack definition for the System 7 secure conformance DUT child
/// process. Hand-written for the same reason as every other DUT: the
/// conformance memory map is not the family map the standard-stack
/// macro pins.
#[derive(Debug, Clone, Copy)]
pub struct IpcSystem7SecureTestStack;

impl System7ProductLayout for IpcSystem7SecureTestStack {
    const COT_ADDRESS: u16 = COT_ADDRESS as u16;
}

impl StackDefinition for IpcSystem7SecureTestStack {
    const DEVICE: &'static DeviceDescriptor = &device_info::DEVICE;
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = Some(&CONFORMANCE_DD2);
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = Some(&CONFORMANCE_USER_MANUFACTURER_INFO);
    const MAX_APDU_LENGTH: u16 = device_info::MAX_APDU_LENGTH;
    const TL_STYLE: TlStyle = TlStyle::Style3;
    // Same numbering choice as the plain System 7 DUT: wire ASAPs 1..17
    // (logical == wire under `FIRST_ASAP = 0`, M112 slot 0 spare), so
    // the TSSJ template's literal GO indexes mean the same objects as on
    // the System B secure DUT.
    const FIRST_ASAP: u16 = 0;

    type P = TestParameters;
    type CO = System7SecureComObjects;
    type LLB = super::ipc::IpcLinkLayerBuilder;
    type ES = SecureS7ExtensionState;
    type Storage = &'static super::fixture_common::DutSecureStorage<Self>;
    type Identity = StaticSecureIdentity;
    type State = SecureSystem7State;
    type StateInit = System7StateInit<StaticSecureIdentity, System7SecureDutConfig, SecureResources<Tp1ExtensionState>>;
    type Mem = SecureSystem7MemoryMap;

    fn create_state(init: Self::StateInit) -> Self::State {
        match init.loaded_config {
            Some(snapshot) => SecureSystem7State::from_device_config(snapshot),
            None => SecureSystem7State::from_device_config(System7SecureDutConfig::default_snapshot()),
        }
    }

    type InterfaceObjects<'a> = zweidraehte_device::bcus::system_7::System7InterfaceObjectsFor<'a, Self>;
    type Augments<'a> = System7SecureAugments<'a>;

    fn create_interface_objects<'a>(
        state: &'a Self::State,
        _platform: &'a Self::Platform,
        layer_ctx: &'a LayerContext<Self>,
        augments: &'a Self::Augments<'a>,
    ) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        create_system_7_objects::<Self, _>(state, layer_ctx, augments)
    }

    type DeviceModel<'a> = System7DeviceModel<'a, Self>;

    fn create_device_model<'a>(
        state: &'a Self::State,
        layer_context: &'a LayerContext<Self>,
        interface_objects: &'a Self::InterfaceObjects<'static>,
    ) -> Self::DeviceModel<'a>
    where
        Self::State: 'a,
    {
        System7DeviceModel::new(state, layer_context, interface_objects)
    }

    fn create_augments<'a>(
        state: &'a Self::State,
        platform: &'a Self::Platform,
        layer_ctx: &'a LayerContext<Self>,
    ) -> Self::Augments<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        use zweidraehte_device::HasExtensionState;
        System7SecureAugments {
            sec: state.extension_state().create_secure_augment(platform, layer_ctx),
            go_table: GroupObjectTableAugment::new(),
            cert: CertificationObjectAugment::new(),
            diag: DiagnosticsAugment::<WithSecureGoSend>::new(&state.inner().operation_mode),
        }
    }

    type AlExtensions = StandardSecureAlServices;
    type LayerBuilder = SecureDeviceBuilder<WithP2p>;
    type Rng = GetrandomRng;
}

// ============================================================================
// Shared-memory snapshot + ConformanceStack wiring
// ============================================================================

/// The persisted snapshot type of the inner secure device state.
type InnerDeviceConfig = System7DeviceConfig<
    { table_sizes::ADT },
    { table_sizes::AST },
    { table_sizes::COT },
    TestParameters,
    SecureExtensionConfig<Tp1ExtensionConfig, { table_sizes::GRP }, { sec_table_sizes::P2P }, { table_sizes::GO }>,
>;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Full snapshot of the System 7 secure conformance state.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct System7SecureDutConfig {
    pub inner: InnerDeviceConfig,
    #[serde_as(as = "[_; EEPROM_LINEAR_SIZE]")]
    pub linear_memory: [u8; EEPROM_LINEAR_SIZE],
    #[serde_as(as = "[_; EEPROM_LEVEL2_SIZE]")]
    pub level2_memory: [u8; EEPROM_LEVEL2_SIZE],
    #[serde_as(as = "[_; EEPROM_LEVEL1_SIZE]")]
    pub level1_memory: [u8; EEPROM_LEVEL1_SIZE],
    #[serde_as(as = "[_; USER_MEMORY_SIZE]")]
    pub user_memory: [u8; USER_MEMORY_SIZE],
}

impl System7SecureDutConfig {
    /// The factory boot image the parent writes into shared memory
    /// before spawning the child: IA 1.0.1 inside the RT8
    /// address-table blob, tables at their product-database addresses,
    /// application loaded, the AN158 sample application's keys and GO
    /// flags
    /// provisioned (TSSJ writes keys by value; a factory reset reverts
    /// the tool key to the FDSK and the affected suite re-provisions).
    pub fn default_snapshot() -> Self {
        use conformance_config::System7SecureConfig;

        let (addr_tab, asso_tab, co_tab) = System7SecureConfig::create_tables(AST_ADDRESS, COT_ADDRESS);

        let mut app_table = Application::new();
        app_table.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app_table.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        let sec_config = System7SecureConfig::create_security_config();

        let mut inner = InnerDeviceConfig::factory_default();
        inner.address_table = addr_tab;
        inner.association_table = asso_tab;
        inner.group_object_table = co_tab;
        inner.application = app_table;
        inner.extension_config.security.grp_keys = sec_config.grp_keys;
        inner.extension_config.security.go_flags = sec_config.go_flags;
        inner.extension_config.security.tool_key = sec_config.tool_key;

        Self {
            inner,
            linear_memory: [0x0F; EEPROM_LINEAR_SIZE],
            level2_memory: [0xAA; EEPROM_LEVEL2_SIZE],
            level1_memory: [0xFF; EEPROM_LEVEL1_SIZE],
            user_memory: [0xFF; USER_MEMORY_SIZE],
        }
    }
}

impl SecureSystem7State {
    pub fn from_device_config(snapshot: System7SecureDutConfig) -> Self {
        let identity = StaticSecureIdentity::new(device_info::SERIAL_NUMBER, SECURE_FDSK);
        let resources = SecureResources::simple(SECURE_FDSK);
        let inner = InnerState::from_config(identity, snapshot.inner, resources);

        Self {
            inner,
            linear_memory: RefCell::new(snapshot.linear_memory),
            level2_memory: RefCell::new(snapshot.level2_memory),
            level1_memory: RefCell::new(snapshot.level1_memory),
            user_memory: RefCell::new(snapshot.user_memory),
            dm_slot: DmNotificationSlot::new(),
        }
    }

    pub fn to_device_config(&self) -> System7SecureDutConfig {
        System7SecureDutConfig {
            inner: self.inner.to_config(),
            linear_memory: *self.linear_memory.borrow(),
            level2_memory: *self.level2_memory.borrow(),
            level1_memory: *self.level1_memory.borrow(),
            user_memory: *self.user_memory.borrow(),
        }
    }
}

/// The `StateInit` value the DUT builds from a shared-memory snapshot.
pub fn state_init_from_snapshot(
    snapshot: System7SecureDutConfig,
) -> System7StateInit<StaticSecureIdentity, System7SecureDutConfig, SecureResources<Tp1ExtensionState>> {
    System7StateInit {
        identity: StaticSecureIdentity::new(device_info::SERIAL_NUMBER, SECURE_FDSK),
        loaded_config: Some(snapshot),
        resources: SecureResources::simple(SECURE_FDSK),
    }
}

impl crate::dut_common::ConformanceStack for IpcSystem7SecureTestStack {
    type DeviceConfig = System7SecureDutConfig;

    fn to_device_config(state: &Self::State) -> Self::DeviceConfig {
        state.to_device_config()
    }

    fn apply_erase_code(state: &Self::State, code: EraseCode) {
        if matches!(code, EraseCode::Other(_)) {
            log::warn!("apply_erase_code: unsupported {:?}", code);
        }
        state.inner().apply_erase_code(code);
    }
}
