//! System 7 DUT stack definition for conformance tests.
//!
//! Mirrors the plain [`IpcConformanceTestStack`] but on the System 7
//! family (mask 0705h): System 7 tables with the individual address inside
//! the address-table blob, `System7MemoryMap`'s absolute address space
//! (progmode byte at 0060h, OptionReg at 0100h, load-control window at
//! 0104h / B6EAh, GA table fixed at 4000h), the five-object interface
//! roster, and 16 authorization levels.
//!
//! The fixture is the non-secure subset of the System B DUT's: the
//! BCU1-style shadow objects the group-object template's UINT1
//! collection drives (GO0 plus its comm-flag / config-flag / value
//! shadows), the read-on-init object, the 8-bit object for network
//! layer 3.1, and the 1-bit object for the transport-layer cases —
//! at the same group addresses the templates default to. What System B
//! keeps for the secure templates (security GOs, diagnostics GOs, the
//! BYTE3 set) is left out: there is no Data Secure System 7 profile.
//!
//! The memory surface is the family map plus EEPROM-backed test
//! regions: System 7 user EEPROM spans 4000h–CFFFh (06 Profiles
//! v02.02.01 §4.2), and the management template needs an accessible
//! window with a known factory pattern plus level-guarded and
//! read-/write-only regions somewhere in it. (The family's RAM window
//! at 0700h cannot be the accessible window: the MemoryBit cases
//! expect literal read-backs computed from a 0Fh factory pattern, and
//! RAM zeroes on every respawn.) [`ConformanceSystem7MemoryMap`] wraps
//! [`System7MemoryMap`] and serves those regions at 5000h+ and the
//! user-memory window at its template-default 7FF0h; everything else
//! falls through to the family map, which stays the surface under test.
//!
//! [`IpcConformanceTestStack`]: super::systemb_stack::IpcConformanceTestStack

use core::cell::RefCell;

use zweidraehte_device::prelude::*;
use zweidraehte_device::{
    PlainDeviceBuilder,
    bcus::system_7::{
        ExtensionAugmentFor, SYSTEM7_MAX_ACCESS_LEVELS, System7DeviceConfig, System7DeviceModel, System7DeviceState,
        System7MemoryMap, System7ProductLayout, System7StateInit, Tp1ExtensionConfig, Tp1ExtensionState,
        create_system_7_objects,
    },
    context::layer::LayerContext,
    device_model::{DeviceModelEvent, DeviceModelNotifier, DmNotificationSlot},
    extension::Extension,
    layers::application::services::StandardAlServices,
    layers::transport::TlStyle,
    objects::tables::{Application, HasLoadStateMachine, LoadEvent},
    restart::EraseCode,
    storage::{HasDeviceConfig, StaticIdentity},
};
use zweidraehte_proto::AccessContext;
use zweidraehte_proto::access::AccessLevel;
use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};
use zweidraehte_proto::memory::{MemoryOperation, MemoryPermission, MemoryRegion, check_memory_access};

use super::fixture_common::{CONFORMANCE_DD2, CONFORMANCE_USER_MANUFACTURER_INFO, TestParameters};

// ============================================================================
// Communication objects — the non-secure System B fixture on RT8 tables
// ============================================================================
//
// Same shadow-object arrangement the System B DUT uses for the 1.4.1
// group-object cases (see `dut::systemb_stack` for the full rationale):
//
// - GO0 (ASAP 1): main 1-bit object
// - GO1 (ASAP 2): GO0's communication flags
// - GO2 (ASAP 3): GO0's configuration flags from the COT
// - GO3 (ASAP 4): GO0's value, and the read-on-init object for 1.4.1.6
// - GO4 (ASAP 5): standalone read-on-init object
// - GO5 (ASAP 6): 8-bit object for network layer 3.1
// - GO6 (ASAP 7): 1-bit object for transport layer 2.1

pub mod comm_objs {
    use zweidraehte_device::objects::comm::ComObject;
    use zweidraehte_ets_model::ets_com_objects;
    use zweidraehte_proto::dpt::{DPT_Switch, DPT_Value_1_Ucount};

    // `bus_hook` keeps the derive-generated `ComObjects` dispatch but lets
    // us write the `ComObjectBusHook` impl (the shadow-object mirroring)
    // ourselves — see the hook impl below the module.
    #[ets_com_objects]
    #[ets(bus_hook)]
    pub struct System7ComObjects {
        /// GO0: Main 1-bit object (UINT1) whose flags/value the shadows
        /// GO1-GO3 access.
        #[ets(index = 1)]
        pub go_0: DPT_Switch,

        /// GO1: GO0's communication flags (read request, transmission
        /// request, error, update).
        #[ets(index = 2)]
        pub go_1_comm_flags: DPT_Value_1_Ucount,

        /// GO2: GO0's configuration flags from the COT. Seeded with
        /// GO0's default flags byte so the shadow value is sensible
        /// before the first `prepare_read` recomputes it.
        #[ets(index = 3, initial = DPT_Value_1_Ucount::from(0xDFu8))]
        pub go_2_config_flags: DPT_Value_1_Ucount,

        /// GO3: GO0's value as 8-bit (read/write without touching flags).
        #[ets(index = 4)]
        pub go_3_value: DPT_Value_1_Ucount,

        /// GO4: Standalone read-on-init test object.
        #[ets(index = 5)]
        pub go_4: DPT_Value_1_Ucount,

        /// GO5: 8-bit object for network layer test 3.1 (an octet-wide
        /// object answers a read in the long frame format).
        #[ets(index = 6)]
        pub go_5_network_test: DPT_Value_1_Ucount,

        /// GO6: 1-bit object for transport layer test 2.1.
        #[ets(index = 7)]
        pub go_6_transport_test: DPT_Switch,
    }
}

use comm_objs::{Index as CoIndex, System7ComObjects};
use std::sync::atomic::{AtomicPtr, Ordering};
use zweidraehte_device::objects::comm::ComObjectBusHook;
use zweidraehte_device::objects::tables::CommunicationObjectTable;

// ============================================================================
// CoTab pointer for the ComObjectBusHook shadow objects
// ============================================================================
//
// Same pattern as `dut::systemb_stack::set_conformance_cot`: the shadow
// hook needs the live CoTab from `&mut self` alone, so the DUT binary
// parks a pointer to it in a process-global static. The System 7 DUT is
// its own process, so a second static per binary is fine.

static COT_PTR: AtomicPtr<RefCell<conformance_config::CoTab>> = AtomicPtr::new(core::ptr::null_mut());

/// Publish the COT reference used by the shadow-object hook.
///
/// Call once from the System 7 DUT binary's `main` after stack
/// construction.
///
/// # Safety
/// The caller guarantees that `cot` remains a valid reference for
/// the duration of the process.
pub unsafe fn set_system7_cot(cot: &RefCell<conformance_config::CoTab>) {
    COT_PTR.store(cot as *const _ as *mut _, Ordering::Release);
}

fn system7_cot() -> Option<&'static RefCell<conformance_config::CoTab>> {
    let ptr = COT_PTR.load(Ordering::Acquire);
    // SAFETY: if non-null, the pointer was installed by `set_system7_cot`
    // with the caller's guarantee that the referent outlives the process.
    unsafe { ptr.as_ref() }
}

// BCU1-style shadow-object hook: GO1/GO2/GO3 mirror GO0's runtime state
// for the 1.4.1 group-object cases. The AL calls `prepare_read` before a
// `GroupValue_Response` and `handle_write` after an accepted
// `GroupValue_Write`.

impl ComObjectBusHook for System7ComObjects {
    fn prepare_read(&mut self, idx: u16) {
        match CoIndex::from_index(idx) {
            Some(CoIndex::Go1CommFlags) => {
                let flags = self.go_0.status.to_flags_byte();
                self.go_1_comm_flags.value.as_mut()[0] = flags;
            }
            Some(CoIndex::Go2ConfigFlags) => {
                // GO0 is at wire ASAP 1 — this DUT's numbering starts at
                // 1 because the EITT templates pin its ASAPs (and with
                // FIRST_ASAP = 0, logical == wire). The COT is
                // wire-indexed.
                if let Some(cot) = system7_cot()
                    && let Some(flags) = cot.borrow().object_flags(1)
                {
                    self.go_2_config_flags.value.as_mut()[0] = flags.to_byte();
                }
            }
            Some(CoIndex::Go3Value) => {
                let go0_value = self.go_0.value.as_ref()[0];
                self.go_3_value.value.as_mut()[0] = go0_value;
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
                // GO0 is at wire ASAP 1 (see prepare_read above).
                if let Some(cot) = system7_cot() {
                    let new_flags = ComObjectFlags::from_byte(self.go_2_config_flags.value.as_ref()[0]);
                    cot.borrow_mut().set_object_flags(1, new_flags);
                }
            }
            Some(CoIndex::Go3Value) => {
                let new_value = self.go_3_value.value.as_ref()[0];
                self.go_0.value.as_mut()[0] = new_value;
            }
            _ => {}
        }
    }
}

// ============================================================================
// Compile-time configuration (RT8 tables)
// ============================================================================
//
// Address layout (RT8 mandates ascending group addresses):
// - TSAP 1: 0x0801 (1/0/1) → CO 6 (GO5, 8-bit for network layer 3.1)
// - TSAP 2: 0x1000 (2/0/0) → CO 1 (GO0, main 1-bit object)
// - TSAP 3: 0x1001 (2/0/1) → CO 2 (GO1, comm flags)
// - TSAP 4: 0x1002 (2/0/2) → CO 3 (GO2, config flags)
// - TSAP 5: 0x1003 (2/0/3) → CO 4 (GO3, value + read-on-init)
// - TSAP 6: 0x1005 (2/0/5) → CO 5 (GO4, read-on-init)
// - TSAP 7: 0x2D05 (5/5/5) → CO 7 (GO6, transport layer)
//
// 2/0/0 through 2/0/5 are the group-object template's own defaults for
// `GO_0_ADDR`..`GO_4_ADDR` (1000h..1005h); 1/0/1 and 5/5/5 match the
// System B fixture so the network- and transport-layer profile
// variables stay identical across the two profiles.

pub mod conformance_config {
    use zweidraehte_device::config::{CE, RE, ROI, TE, UE, WE};
    use zweidraehte_device::objects::tables::ComObjectType;
    use zweidraehte_device::system7_stack_config;

    system7_stack_config! {
        name: System7ConformanceConfig,
        individual_address: "1.0.1", // BDUT = 1.0.1 = 0x1001, same as the plain DUT

        group_addresses: {
            1 => "1/0/1", // 0x0801 - network layer test 3.1 (8-bit, long format)
            2 => "2/0/0", // 0x1000 - main object GO0
            3 => "2/0/1", // 0x1001 - comm flags GO1
            4 => "2/0/2", // 0x1002 - config flags GO2
            5 => "2/0/3", // 0x1003 - value GO3 (read-on-init for 1.4.1.6)
            6 => "2/0/5", // 0x1005 - read-on-init GO4
            7 => "5/5/5", // 0x2D05 - transport layer test 2.1
        },

        comm_objects: {
            // GO0: main 1-bit object, all flags enabled
            1 => (ComObjectType::Uint1 as u8, CE | TE | RE | WE | UE),
            // GO1: comm flags (4-bit, short format response)
            2 => (ComObjectType::Uint4 as u8, CE | TE | RE | WE | UE),
            // GO2: config flags (8-bit)
            3 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE),
            // GO3: value (8-bit); ROI for test 1.4.1.6
            4 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE | ROI),
            // GO4: read-on-init object
            5 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE | ROI),
            // GO5: 8-bit for network layer 3.1
            6 => (ComObjectType::Byte1 as u8, CE | TE | RE | WE | UE),
            // GO6: 1-bit for transport layer 2.1
            7 => (ComObjectType::Uint1 as u8, CE | TE | RE | WE | UE),
        },

        associations: {
            1 => [6],
            2 => [1],
            3 => [2],
            4 => [3],
            5 => [4],
            6 => [5],
            7 => [7],
        },
    }
}

/// Where the movable tables live in the DUT's absolute address space.
/// The GA table is fixed at 4000h by the profile; these two are our
/// product-database choice.
pub const AST_ADDRESS: u32 = 0x4100;
pub const COT_ADDRESS: u32 = 0x4200;

/// Table byte sizes for the `System7DeviceState` const generics —
/// derived from the fixture's actual entry counts, like the System B
/// DUT's `table_sizes`. The device descriptor advertises the profile
/// maximum (254) independently of these buffers.
pub mod table_sizes {
    use super::conformance_config::System7ConformanceConfig;

    pub const ADT: usize = System7ConformanceConfig::ADDR8_SIZE;
    pub const AST: usize = System7ConformanceConfig::ASSO8_SIZE;
    pub const COT: usize = System7ConformanceConfig::COT_SIZE;
}

// ============================================================================
// Device identity
// ============================================================================

pub mod device_info {
    use super::*;
    use zweidraehte_device::config::{MAX_APDU_LENGTH_EXTENDED, buffer_size_for_apdu};

    /// The System 7 DUT's device descriptor.
    pub const DEVICE: DeviceDescriptor = DeviceDescriptor {
        mask_version: MaskVersion::System7Tp1,
        manufacturer_id: 0x00FA,
        hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x07],
        application_id: 0x0700,
        application_version: 0x01,
        max_address_table_entries: 254,
        max_association_table_entries: 254,
        max_com_objects: 254,
        pei_type: 0,
    };

    /// Device serial number (6 bytes). Distinct from the System B DUT so
    /// a mixed log is attributable. Matches `BDUT_SERIAL_NUMBER` in the
    /// System 7 EITT profile.
    pub const SERIAL_NUMBER: [u8; 6] = [0xFE, 0xED, 0x07, 0x05, 0xCA, 0xFE];

    /// Support extended frames like the System B DUT does.
    pub const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_EXTENDED;

    /// Buffer size fitting a full extended frame.
    pub const BUFFER_SIZE: usize = buffer_size_for_apdu(MAX_APDU_LENGTH);
}

// ============================================================================
// Conformance state — family state plus EEPROM test regions
// ============================================================================

/// Size of the freely accessible EEPROM block (5000h-50FFh) — the
/// management template's "accessible memory", factory pattern 0Fh.
pub const EEPROM_LINEAR_SIZE: usize = 256;
/// Size of the level-2-guarded EEPROM block (5120h-51FFh). Shorter than
/// a full page: the read-only and write-only regions sit in front of it
/// (see `ConformanceSystem7MemoryMap`).
pub const EEPROM_LEVEL2_SIZE: usize = 224;
/// Size of the level-1-guarded EEPROM block (5200h-52FFh).
pub const EEPROM_LEVEL1_SIZE: usize = 256;
/// Size of the user memory region (7FF0h-7FFFh) for
/// A_UserMemory_Read/Write tests (M-2.31/M-2.32).
pub const USER_MEMORY_SIZE: usize = 16;

/// The inner System 7 device state for conformance testing.
type InnerState = System7DeviceState<
    { table_sizes::ADT },
    { table_sizes::AST },
    { table_sizes::COT },
    IpcSystem7TestStack,
    Tp1ExtensionState,
>;

/// Unified state for the System 7 conformance DUT.
///
/// Wraps [`System7DeviceState`] and adds the EEPROM-backed test regions
/// the management template's memory collections need. All standard trait
/// impls are thin forwarding impls delegating to the inner state.
pub struct ConformanceSystem7State {
    /// Base device state (runtime + RT8 tables + TP1 config).
    inner: InnerState,

    /// Freely accessible EEPROM block (5000h-50FFh), factory 0Fh.
    pub linear_memory: RefCell<[u8; EEPROM_LINEAR_SIZE]>,
    /// Level-2-guarded EEPROM block (5120h-51FFh), access level <= 2.
    pub level2_memory: RefCell<[u8; EEPROM_LEVEL2_SIZE]>,
    /// Level-1-guarded EEPROM block (5200h-52FFh), access level <= 1.
    pub level1_memory: RefCell<[u8; EEPROM_LEVEL1_SIZE]>,
    /// User memory region (7FF0h-7FFFh).
    pub user_memory: RefCell<[u8; USER_MEMORY_SIZE]>,

    /// DeviceModel notification slot.
    dm_slot: DmNotificationSlot,
}

impl ConformanceSystem7State {
    /// Access the inner device state directly.
    pub fn inner(&self) -> &InnerState {
        &self.inner
    }
}

// StackState is hand-written for the fixed compile-time APDU length —
// same rationale as the System B `ConformanceState`.
impl StackState for ConformanceSystem7State {
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
        // Fixed compile-time APDU length; the IPC link layer has no
        // hardware-detection step that would call this setter.
    }

    fn is_programming_mode(&self) -> bool {
        self.inner.is_programming_mode()
    }

    fn set_programming_mode(&self, enabled: bool) {
        self.inner.set_programming_mode(enabled);
    }
}

// The pure-delegation trait bundle. Named for System B, but generic over
// any state with the same fourteen-trait surface — which
// `System7DeviceState` shares.
zweidraehte_device::forward_device_state_traits!(impl ConformanceSystem7State => self.inner: InnerState);

impl DeviceModelNotifier for ConformanceSystem7State {
    fn notify(&self, event: DeviceModelEvent) {
        self.dm_slot.notify(event);
    }
    fn take_event(&self) -> Option<DeviceModelEvent> {
        self.dm_slot.take_event()
    }
}

// ============================================================================
// Conformance memory map — family map plus EEPROM test regions
// ============================================================================

/// Memory map for the System 7 conformance DUT.
///
/// Test-region layout, all inside the family's user EEPROM span
/// (4000h-CFFFh, 06 Profiles v02.02.01 §4.2):
///
/// - 5000h-50FFh: freely accessible, factory 0Fh (the management
///   template's MEMPOS window; the MemoryBit cases expect literal
///   read-backs computed from that pattern)
/// - 5100h-510Fh: read-only (computed pattern; writes fail)
/// - 5110h-511Fh: write-only (reads fail; writes dropped)
/// - 5120h-51FFh: level-2 block (access level <= 2)
/// - 5200h-52FFh: level-1 block (access level <= 1)
/// - 7FF0h-7FFFh: user memory (the management template's default
///   user-memory window, which happens to fall inside System 7 EEPROM —
///   keeping it there spares the profile an override)
///
/// The regions are adjacent for the same reason the System B map's are
/// (partly-protected accesses run off one region's end into the next,
/// starting with MemoryBit 2.10.2 overrunning the accessible window's
/// last octet); see `ConformanceMemoryMap` in `dut::systemb_stack`.
///
/// Everything else — progmode byte, OptionReg, load control, the RAM
/// window, the RT8 tables — falls through to [`System7MemoryMap`],
/// which remains the surface under test.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConformanceSystem7MemoryMap;

impl ConformanceSystem7MemoryMap {
    /// Base address of the freely accessible block.
    pub const LINEAR_MEMORY_BASE: u16 = 0x5000;
    /// Base address of the read-only region.
    pub const READONLY_MEMORY_BASE: u16 = 0x5100;
    /// Size of the read-only region.
    pub const READONLY_MEMORY_SIZE: u16 = 0x10;
    /// Base address of the write-only region.
    pub const WRITEONLY_MEMORY_BASE: u16 = 0x5110;
    /// Size of the write-only region.
    pub const WRITEONLY_MEMORY_SIZE: u16 = 0x10;
    /// Base address of the level-2-guarded block.
    pub const LEVEL2_MEMORY_BASE: u16 = 0x5120;
    /// Base address of the level-1-guarded block.
    pub const LEVEL1_MEMORY_BASE: u16 = 0x5200;
    /// Base address of the user memory region.
    pub const USER_MEMORY_BASE: u16 = 0x7FF0;

    const ACCESS_REGIONS: &'static [MemoryRegion] = &[
        MemoryRegion::open(Self::LINEAR_MEMORY_BASE, EEPROM_LINEAR_SIZE as u32),
        MemoryRegion::read_only(Self::READONLY_MEMORY_BASE, Self::READONLY_MEMORY_SIZE as u32, MemoryPermission::Open),
        MemoryRegion::write_only(
            Self::WRITEONLY_MEMORY_BASE,
            Self::WRITEONLY_MEMORY_SIZE as u32,
            MemoryPermission::Open,
        ),
        MemoryRegion::new(
            Self::LEVEL2_MEMORY_BASE,
            EEPROM_LEVEL2_SIZE as u32,
            MemoryPermission::Level(AccessLevel::Configuration),
            MemoryPermission::Level(AccessLevel::Configuration),
        ),
        MemoryRegion::new(
            Self::LEVEL1_MEMORY_BASE,
            EEPROM_LEVEL1_SIZE as u32,
            MemoryPermission::Level(AccessLevel::ProductManufacturer),
            MemoryPermission::Level(AccessLevel::ProductManufacturer),
        ),
        MemoryRegion::open(Self::USER_MEMORY_BASE, USER_MEMORY_SIZE as u32),
    ];

    pub const fn new() -> Self {
        Self
    }
}

impl MemoryMap<ConformanceSystem7State> for ConformanceSystem7MemoryMap {
    fn read(
        &self,
        state: &ConformanceSystem7State,
        address: u16,
        data: &mut [u8],
        ctx: AccessContext,
    ) -> Result<usize, MemoryError> {
        let end_address = address.saturating_add(data.len() as u16);

        if let Some(access) = check_memory_access(
            Self::ACCESS_REGIONS,
            address,
            data.len(),
            MemoryOperation::Read,
            ctx,
            SYSTEM7_MAX_ACCESS_LEVELS as u8,
        ) {
            access?;
        }

        // Accessible block: no access level restriction.
        if address >= Self::LINEAR_MEMORY_BASE && end_address <= Self::LINEAR_MEMORY_BASE + EEPROM_LINEAR_SIZE as u16 {
            let offset = (address - Self::LINEAR_MEMORY_BASE) as usize;
            let mem = state.linear_memory.borrow();
            data.copy_from_slice(&mem[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Read-only region: computed pattern, so nothing to persist.
        if address >= Self::READONLY_MEMORY_BASE
            && end_address <= Self::READONLY_MEMORY_BASE + Self::READONLY_MEMORY_SIZE
        {
            let offset = (address - Self::READONLY_MEMORY_BASE) as usize;
            for (i, byte) in data.iter_mut().enumerate() {
                *byte = (offset + i) as u8;
            }
            return Ok(data.len());
        }

        // Write-only region: reads always reject (rendered FAh,
        // E_ACCESS_WRITE_ONLY, by the application layer).
        if address >= Self::WRITEONLY_MEMORY_BASE
            && end_address <= Self::WRITEONLY_MEMORY_BASE + Self::WRITEONLY_MEMORY_SIZE
        {
            return Err(MemoryError::WriteProtected);
        }

        // Level-2 block: requires access level <= 2.
        if address >= Self::LEVEL2_MEMORY_BASE && end_address <= Self::LEVEL2_MEMORY_BASE + EEPROM_LEVEL2_SIZE as u16 {
            let offset = (address - Self::LEVEL2_MEMORY_BASE) as usize;
            let mem = state.level2_memory.borrow();
            data.copy_from_slice(&mem[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Level-1 block: requires access level <= 1.
        if address >= Self::LEVEL1_MEMORY_BASE && end_address <= Self::LEVEL1_MEMORY_BASE + EEPROM_LEVEL1_SIZE as u16 {
            let offset = (address - Self::LEVEL1_MEMORY_BASE) as usize;
            let mem = state.level1_memory.borrow();
            data.copy_from_slice(&mem[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // User memory: freely accessible.
        if address >= Self::USER_MEMORY_BASE && end_address <= Self::USER_MEMORY_BASE + USER_MEMORY_SIZE as u16 {
            let offset = (address - Self::USER_MEMORY_BASE) as usize;
            let mem = state.user_memory.borrow();
            data.copy_from_slice(&mem[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Everything else is the family map's business.
        System7MemoryMap::new().read(&state.inner, address, data, ctx)
    }

    fn write(
        &self,
        state: &ConformanceSystem7State,
        address: u16,
        data: &[u8],
        ctx: AccessContext,
    ) -> Result<usize, MemoryError> {
        let end_address = address.saturating_add(data.len() as u16);

        if let Some(access) = check_memory_access(
            Self::ACCESS_REGIONS,
            address,
            data.len(),
            MemoryOperation::Write,
            ctx,
            SYSTEM7_MAX_ACCESS_LEVELS as u8,
        ) {
            access?;
        }

        // Accessible block: no access level restriction.
        if address >= Self::LINEAR_MEMORY_BASE && end_address <= Self::LINEAR_MEMORY_BASE + EEPROM_LINEAR_SIZE as u16 {
            let offset = (address - Self::LINEAR_MEMORY_BASE) as usize;
            let mut mem = state.linear_memory.borrow_mut();
            mem[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        // Read-only region: writes always fail (rendered FBh,
        // E_READ_ONLY, by the application layer).
        if address >= Self::READONLY_MEMORY_BASE
            && end_address <= Self::READONLY_MEMORY_BASE + Self::READONLY_MEMORY_SIZE
        {
            return Err(MemoryError::WriteProtected);
        }

        // Write-only region: writes succeed silently.
        if address >= Self::WRITEONLY_MEMORY_BASE
            && end_address <= Self::WRITEONLY_MEMORY_BASE + Self::WRITEONLY_MEMORY_SIZE
        {
            return Ok(data.len());
        }

        // Level-2 block: requires access level <= 2.
        if address >= Self::LEVEL2_MEMORY_BASE && end_address <= Self::LEVEL2_MEMORY_BASE + EEPROM_LEVEL2_SIZE as u16 {
            let offset = (address - Self::LEVEL2_MEMORY_BASE) as usize;
            let mut mem = state.level2_memory.borrow_mut();
            mem[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        // Level-1 block: requires access level <= 1.
        if address >= Self::LEVEL1_MEMORY_BASE && end_address <= Self::LEVEL1_MEMORY_BASE + EEPROM_LEVEL1_SIZE as u16 {
            let offset = (address - Self::LEVEL1_MEMORY_BASE) as usize;
            let mut mem = state.level1_memory.borrow_mut();
            mem[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        // User memory: freely accessible.
        if address >= Self::USER_MEMORY_BASE && end_address <= Self::USER_MEMORY_BASE + USER_MEMORY_SIZE as u16 {
            let offset = (address - Self::USER_MEMORY_BASE) as usize;
            let mut mem = state.user_memory.borrow_mut();
            mem[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        // Everything else is the family map's business.
        System7MemoryMap::new().write(&state.inner, address, data, ctx)
    }
}

// ============================================================================
// Stack definition
// ============================================================================

/// Stack definition for the System 7 conformance DUT child process.
///
/// Hand-written rather than via `system_7_standard_stack!`: the macro
/// pins `Mem = System7MemoryMap`, and this DUT needs the conformance
/// wrapper map with the EEPROM test regions — the same reason the
/// System B DUT hand-writes its `StackDefinition`.
#[derive(Debug, Clone, Copy)]
pub struct IpcSystem7TestStack;

// The group object table window is a product constant on System 7 (no
// location resource exists for it); ours matches the product-database
// choice above.
impl System7ProductLayout for IpcSystem7TestStack {
    const COT_ADDRESS: u16 = COT_ADDRESS as u16;
}

impl StackDefinition for IpcSystem7TestStack {
    const DEVICE: &'static DeviceDescriptor = &device_info::DEVICE;
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = Some(&CONFORMANCE_DD2);
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = Some(&CONFORMANCE_USER_MANUFACTURER_INFO);
    const MAX_APDU_LENGTH: u16 = device_info::MAX_APDU_LENGTH;
    const TL_STYLE: TlStyle = TlStyle::Style3;
    // System 7 numbers objects from 0, but this DUT deliberately keeps
    // its objects at wire ASAP 1..7: the EITT templates pin those ASAPs
    // literally (trigger-kick patches, the LoadStateMachines RT8
    // association blob), so logical == wire here and System 7 slot 0 is a
    // spare.
    const FIRST_ASAP: u16 = 0;
    type P = TestParameters;
    type CO = System7ComObjects;
    type LLB = super::link::IpcLinkLayerBuilder;
    type ES = Tp1ExtensionState;
    type State = ConformanceSystem7State;
    type StateInit = System7StateInit<StaticIdentity, System7DutConfig>;
    type Mem = ConformanceSystem7MemoryMap;
    type Storage = &'static crate::dut::common::DutConfigStore<Self>;

    fn create_state(init: Self::StateInit) -> Self::State {
        match init.loaded_config {
            Some(snapshot) => ConformanceSystem7State::from_device_config(snapshot),
            None => ConformanceSystem7State::from_device_config(System7DutConfig::default_snapshot()),
        }
    }

    type InterfaceObjects<'a> = zweidraehte_device::bcus::system_7::System7InterfaceObjectsFor<'a, Self>;
    type Augments<'a> = ExtensionAugmentFor<'a, Self>;

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
        _layer_ctx: &'a LayerContext<Self>,
    ) -> Self::Augments<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        use zweidraehte_device::HasExtensionState;
        state.extension_state().create_augment::<Self>(platform)
    }

    type AlExtensions = StandardAlServices;
    type LayerBuilder = PlainDeviceBuilder;
}

// ============================================================================
// Shared-memory snapshot + ConformanceStack wiring
// ============================================================================

/// The persisted snapshot type of the inner `System7DeviceState`.
type InnerDeviceConfig = System7DeviceConfig<
    { table_sizes::ADT },
    { table_sizes::AST },
    { table_sizes::COT },
    TestParameters,
    Tp1ExtensionConfig,
>;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Full snapshot of the System 7 conformance state for shared memory:
/// the family's own `System7DeviceConfig` (with the individual address
/// riding inside the RT8 address-table blob) plus the EEPROM test
/// regions.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct System7DutConfig {
    /// Core device state, serialized via the stack's `to_config()` /
    /// `from_config()` pattern.
    pub inner: InnerDeviceConfig,

    /// EEPROM test regions used by the management template's memory
    /// collections. The read-only region's pattern is computed and the
    /// write-only region drops its data, so neither needs persisting.
    #[serde_as(as = "[_; EEPROM_LINEAR_SIZE]")]
    pub linear_memory: [u8; EEPROM_LINEAR_SIZE],
    #[serde_as(as = "[_; EEPROM_LEVEL2_SIZE]")]
    pub level2_memory: [u8; EEPROM_LEVEL2_SIZE],
    #[serde_as(as = "[_; EEPROM_LEVEL1_SIZE]")]
    pub level1_memory: [u8; EEPROM_LEVEL1_SIZE],
    #[serde_as(as = "[_; USER_MEMORY_SIZE]")]
    pub user_memory: [u8; USER_MEMORY_SIZE],
}

impl System7DutConfig {
    /// The factory boot image the parent writes into shared memory
    /// before spawning the child: IA 1.0.1 (inside the RT8
    /// address-table blob), pre-loaded tables at their
    /// product-database addresses, application loaded so the device
    /// model starts it on boot, EEPROM test regions at their factory
    /// patterns.
    pub fn default_snapshot() -> Self {
        use conformance_config::System7ConformanceConfig;

        let (addr_tab, asso_tab, co_tab) = System7ConformanceConfig::create_tables(AST_ADDRESS, COT_ADDRESS);

        let mut app_table = Application::new();
        app_table.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app_table.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        let mut inner = InnerDeviceConfig::factory_default();
        inner.address_table = addr_tab;
        inner.association_table = asso_tab;
        inner.group_object_table = co_tab;
        inner.application = app_table;

        Self {
            inner,
            linear_memory: [0x0F; EEPROM_LINEAR_SIZE],
            level2_memory: [0xAA; EEPROM_LEVEL2_SIZE],
            level1_memory: [0xFF; EEPROM_LEVEL1_SIZE],
            user_memory: [0xFF; USER_MEMORY_SIZE],
        }
    }
}

impl ConformanceSystem7State {
    /// Reconstruct the conformance state from a persisted snapshot.
    pub fn from_device_config(snapshot: System7DutConfig) -> Self {
        let identity = StaticIdentity::new(device_info::SERIAL_NUMBER);
        let inner = InnerState::from_config(identity, snapshot.inner, ());

        Self {
            inner,
            linear_memory: RefCell::new(snapshot.linear_memory),
            level2_memory: RefCell::new(snapshot.level2_memory),
            level1_memory: RefCell::new(snapshot.level1_memory),
            user_memory: RefCell::new(snapshot.user_memory),
            dm_slot: DmNotificationSlot::new(),
        }
    }

    /// Snapshot the current state for persistence — called by the
    /// child's restart handler right before exiting.
    pub fn to_device_config(&self) -> System7DutConfig {
        System7DutConfig {
            inner: self.inner.to_config(),
            linear_memory: *self.linear_memory.borrow(),
            level2_memory: *self.level2_memory.borrow(),
            level1_memory: *self.level1_memory.borrow(),
            user_memory: *self.user_memory.borrow(),
        }
    }
}

/// The `StateInit` value the DUT builds from a shared-memory snapshot.
pub fn state_init_from_snapshot(snapshot: System7DutConfig) -> System7StateInit<StaticIdentity, System7DutConfig> {
    System7StateInit::new(StaticIdentity::new(device_info::SERIAL_NUMBER), Some(snapshot))
}

impl crate::dut::common::ConformanceStack for IpcSystem7TestStack {
    type DeviceConfig = System7DutConfig;

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
