//! Secure DUT stack definition for Data Security conformance tests.
//!
//! Mirrors the non-secure [`ConformanceState`] and [`IpcConformanceTestStack`]
//! but uses [`SecureDeviceBuilder`] and [`SecureTp1ExtensionState`] to enable
//! KNX Data Secure support. The Security Interface Object appears at object
//! index 6 (after Device, ADT, AST, COT, APP, PEI).
//!
//! [`ConformanceState`]: super::stack::ConformanceState
//! [`IpcConformanceTestStack`]: super::stack::IpcConformanceTestStack

use core::cell::{Cell, RefCell};

use zweidraehte_device::bcus::system_b::{DiagnosticsAugment, WithSecureGoSend};
use zweidraehte_device::prelude::*;
use zweidraehte_device::{
    HasExtensionState, HasSecurityMode, Rng, SecureRng, StackDefinition,
    bcus::system_b::{
        DeviceConfig, SecureAugmentBundle, SecureExtensionConfig, SecureResources, SecureTp1DeviceState,
        SecureTp1ExtensionState, SystemBDeviceModel, SystemBInterfaceObjectsFor, Tp1Augment, Tp1ExtensionConfig,
        create_system_b_objects,
    },
    context::layer::LayerContext,
    device_model::{DeviceModelEvent, DeviceModelNotifier, DmNotificationSlot},
    layers::secure_application::WithP2p,
    memory::MemoryMap,
    objects::interface::{
        FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult,
        PropertyError, PropertyRead, WriteResponse, interface_object_augment, pid,
    },
    objects::tables::{
        Application, HasAddressTable, HasAssociationTable, HasCommunicationObjectTable, HasLoadStateMachine, LoadEvent,
    },
    restart::EraseCode,
    service::{ServiceCtx, ServiceRegistry},
    storage::HasDeviceConfig,
};
use zweidraehte_proto::AccessContext;
use zweidraehte_proto::access::{AccessPolicy, ClientRole, SecurityMode};
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::dpt::InterfaceObjectType;

use super::stack::{
    CONFORMANCE_DD2, CONFORMANCE_MEMORY_LAYOUT, CONFORMANCE_USER_MANUFACTURER_INFO, ConformanceMemoryMap,
    LEVEL1_MEMORY_SIZE, LEVEL2_MEMORY_SIZE, LINEAR_MEMORY_SIZE, TestParameters, USER_MEMORY_SIZE,
    comm_objs::ConformanceComObjects, conformance_config, device_info, table_sizes,
};

// ============================================================================
// Security-specific constants
// ============================================================================

/// Security table sizes for const generics.
///
/// `GRP` and `GO` are not declared here — `SecureTp1DeviceState`
/// derives them as entry counts from the `ADT_SIZE`/`COT_SIZE` byte
/// sizes. `P2P` is the P2P Key Table capacity. `SIAT` is **not** a const
/// on the secure device state — it is the `N` of the `SiatStore` (the
/// SIAT lives in the sequence store, here [`ShmSiatStore`]); the value
/// below is passed as that `N` and must cover the union of P2P +
/// group-secure senders (03/03/07 §5.3).
pub mod sec_table_sizes {
    /// Max P2P Key Table entries.
    pub const P2P: usize = 8;
    /// Max SIAT entries — the `SiatStore` capacity (union of P2P +
    /// group-secure senders).
    pub const SIAT: usize = 8;
}

/// Serial number for the secure DUT (matches XML: FE ED BA BE CA FE).
pub const SECURE_SERIAL_NUMBER: [u8; 6] = [0xFE, 0xED, 0xBA, 0xBE, 0xCA, 0xFE];

/// Factory Default Setup Key for the secure DUT.
///
/// Distinct from `TK1` (see `tests::security::variables::TK1`). The
/// default persisted SHM snapshot already carries `tool_key == TK1`
/// (the `knx_stack_config!` macro's `security.tool_key` field), so
/// tests that don't factory-reset the DUT see the pre-configured
/// TK1. Once a factory reset fires, the active tool key reverts to
/// this distinct FDSK, and each such test has to re-provision TK1
/// explicitly (sync + FDSK-encrypted `PID_TOOL_KEY` write) — the
/// pattern the reference XML uses for 3.8.13.1/8 etc.
pub const SECURE_FDSK: [u8; 16] = [0x11; 16];

// ============================================================================
// Secure Inner State Type
// ============================================================================

/// The SIAT/sequence store for the conformance DUT: the SIAT view over the
/// shared-memory key-value backend. `K = 0` persists the sending counter at its
/// exact value (no skip-ahead) so the value read back via PID 59 across
/// power-down / reset matches what the conformance suite asserts.
pub type ShmSiatStore = SiatStore<ShmSeqStorage, { sec_table_sizes::SIAT }, 0>;

type SecureInnerState = SecureTp1DeviceState<
    { table_sizes::ADT },
    { table_sizes::AST },
    { table_sizes::COT },
    IpcSecureConformanceTestStack,
    { sec_table_sizes::P2P },
>;

// ============================================================================
// SecureConformanceState
// ============================================================================

/// Secure conformance test state.
///
/// Same structure as [`ConformanceState`] but wraps a
/// [`SecureTp1DeviceState`] to enable Data Secure. The Security IO
/// appears at object index 6.
pub struct SecureConformanceState {
    inner: SecureInnerState,
    pub linear_memory: RefCell<[u8; LINEAR_MEMORY_SIZE]>,
    pub level2_memory: RefCell<[u8; LEVEL2_MEMORY_SIZE]>,
    pub level1_memory: RefCell<[u8; LEVEL1_MEMORY_SIZE]>,
    pub user_memory: RefCell<[u8; USER_MEMORY_SIZE]>,
    dm_slot: DmNotificationSlot,
}

impl SecureConformanceState {
    pub fn new(
        addr_tab: conformance_config::AddrTab,
        asso_tab: conformance_config::AssoTab,
        co_tab: conformance_config::CoTab,
        app_table: Application<TestParameters>,
    ) -> Self {
        let identity = StaticSecureIdentity::new(SECURE_SERIAL_NUMBER, SECURE_FDSK);
        let resources = SecureResources::simple(SECURE_FDSK);
        let inner = SecureInnerState::new(identity, ConformanceComObjects::new(), resources);

        // Set the secure conformance test individual address (1.0.1 = 0x1001).
        // Matches the plain conformance default so tests that hard-code the
        // BDUT IA (as a source-address match) pass against either DUT.
        inner.set_individual_address(IndividualAddress::new(1, 0, 1));

        // Load pre-built tables.
        *inner.adt.borrow_mut() = addr_tab;
        *inner.ast.borrow_mut() = asso_tab;
        *inner.cot.borrow_mut() = co_tab;
        *inner.app.borrow_mut() = app_table;

        Self {
            inner,
            linear_memory: RefCell::new([0x0F; LINEAR_MEMORY_SIZE]),
            level2_memory: RefCell::new([0xAA; LEVEL2_MEMORY_SIZE]),
            level1_memory: RefCell::new([0xFF; LEVEL1_MEMORY_SIZE]),
            user_memory: RefCell::new([0xFF; USER_MEMORY_SIZE]),
            dm_slot: DmNotificationSlot::new(),
        }
    }

    pub fn inner(&self) -> &SecureInnerState {
        &self.inner
    }
}

impl SecureConformanceState {
    /// Create a fully-populated secure conformance state with default tables
    /// and security configuration.
    ///
    /// This is the secure equivalent of what `Default` would provide.
    pub fn new_default() -> Self {
        // Build populated tables (same as the non-secure DUT) so that group
        // addressing, association lookup, and comm object access all work.
        let (addr_tab, asso_tab, co_tab) = conformance_config::ConformanceTestConfig::create_tables(
            ConformanceMemoryMap::ADT_BASE as u32,
            ConformanceMemoryMap::AST_BASE as u32,
            ConformanceMemoryMap::COT_BASE as u32,
        );
        let mut app_table = Application::<TestParameters>::new();
        app_table.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app_table.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        let state = Self::new(addr_tab, asso_tab, co_tab, app_table);

        // Apply security config from the macro (group keys, tool key, etc.).
        let sec_config = conformance_config::ConformanceTestConfig::create_security_config();
        *state.inner().extension_state().security.grp_keys().borrow_mut() = sec_config.grp_keys;
        *state.inner().extension_state().security.go_flags().borrow_mut() = sec_config.go_flags;
        state.inner().extension_state().security.set_tool_key(sec_config.tool_key);

        state
    }
}

// ============================================================================
// StackState Forwarding
// ============================================================================

impl StackState for SecureConformanceState {
    type Identity = <SecureInnerState as StackState>::Identity;

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
        // The conformance harness reports a fixed compile-time
        // `MAX_APDU_LENGTH` and the IPC link layer has no
        // hardware-detection step that would call this setter.
        // Intentionally inert.
    }
    fn is_programming_mode(&self) -> bool {
        self.inner.is_programming_mode()
    }
    fn set_programming_mode(&self, enabled: bool) {
        self.inner.set_programming_mode(enabled);
    }
}

// All pure-delegation trait impls (`HasSecurityMode`, `HasPersistence`,
// `HasAuthorization`, `HasExtensionState`, the table accessors,
// `HasCommObjects`, `HasGoSecurityView` — which the secure inner
// extension overrides to consult `PID_GO_SECURITY_FLAGS`, the P2P key
// table, etc. — `HasDiagnosticsContext`, `HasRoutingCount`,
// `HasConnectionAuth`) come from the bundle macro. `StackState` (fixed
// APDU length) and `DeviceModelNotifier` (dm_slot) are the two
// genuinely customised traits and stay hand-written.
zweidraehte_device::forward_system_b_state_traits!(impl SecureConformanceState => self.inner: SecureInnerState);

// ============================================================================
// Random byte source for KNX Data Secure (plugs into `StackDefinition::Rng`)
// ============================================================================
//
// The Secure Application Layer pulls randomness through
// `<D::Rng as Rng>::fill` rather than from the state type, so firmware
// can provide an RNG without a state newtype. The conformance DUT runs
// under Linux, so a libc `getrandom` call is both cheapest and strongest.

pub struct GetrandomRng;

impl Rng for GetrandomRng {
    fn fill(buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom failed");
    }
}

impl SecureRng for GetrandomRng {}

// ============================================================================
// DeviceModelNotifier
// ============================================================================

impl DeviceModelNotifier for SecureConformanceState {
    fn notify(&self, event: DeviceModelEvent) {
        self.dm_slot.notify(event);
    }
    fn take_event(&self) -> Option<DeviceModelEvent> {
        self.dm_slot.take_event()
    }
}

// ============================================================================
// MemoryMap — reuse the non-secure memory map
// ============================================================================

impl MemoryMap<SecureConformanceState> for ConformanceMemoryMap {
    fn read(
        &self,
        tables: &SecureConformanceState,
        address: u16,
        data: &mut [u8],
        ctx: AccessContext,
    ) -> Result<usize, MemoryError> {
        // Delegate to the same memory map logic, just with different state type.
        // The memory regions are identical.
        use MemoryError;
        use zweidraehte_device::objects::tables::TableMemory;

        let end_address = address.saturating_add(data.len() as u16);

        // Address Table
        let adt = tables.adt().borrow();
        let adt_data = adt.data_ref();
        let adt_end = ConformanceMemoryMap::ADT_BASE + adt_data.len() as u16;
        if address >= ConformanceMemoryMap::ADT_BASE && end_address <= adt_end {
            let offset = (address - ConformanceMemoryMap::ADT_BASE) as usize;
            data.copy_from_slice(&adt_data[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Association Table
        let ast = tables.ast().borrow();
        let ast_data = ast.data_ref();
        let ast_end = ConformanceMemoryMap::AST_BASE + ast_data.len() as u16;
        if address >= ConformanceMemoryMap::AST_BASE && end_address <= ast_end {
            let offset = (address - ConformanceMemoryMap::AST_BASE) as usize;
            data.copy_from_slice(&ast_data[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Communication Object Table
        let cot = tables.cot().borrow();
        let cot_data = cot.data_ref();
        let cot_end = ConformanceMemoryMap::COT_BASE + cot_data.len() as u16;
        if address >= ConformanceMemoryMap::COT_BASE && end_address <= cot_end {
            let offset = (address - ConformanceMemoryMap::COT_BASE) as usize;
            data.copy_from_slice(&cot_data[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Linear memory (freely accessible)
        if address >= ConformanceMemoryMap::LINEAR_MEMORY_BASE
            && end_address <= ConformanceMemoryMap::LINEAR_MEMORY_BASE + LINEAR_MEMORY_SIZE as u16
        {
            let offset = (address - ConformanceMemoryMap::LINEAR_MEMORY_BASE) as usize;
            data.copy_from_slice(&tables.linear_memory.borrow()[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // ================================================================
        // Security-aware sub-regions within Level 2 memory.
        // These must be checked BEFORE the general Level 2 region so
        // their access policies take precedence.
        // ================================================================

        let security_on = tables.extension_state().security_mode_enabled();

        // 0x03D0-0x03DF: Access Policy 000/000 — always denied.
        if address >= 0x03D0 && end_address <= 0x03E0 {
            return Err(MemoryError::AccessDenied);
        }

        // 0x03E0-0x03EF: Access Policy 3FF/00C — everyone when SM off,
        // only Tool A+C when SM on.
        if address >= 0x03E0 && end_address <= 0x03F0 {
            if !AccessPolicy::OPEN_OFF_TOOL_ON.can_read(&ctx, security_on) {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - ConformanceMemoryMap::LEVEL2_MEMORY_BASE) as usize;
            data.copy_from_slice(&tables.level2_memory.borrow()[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Level 2 memory
        if address >= ConformanceMemoryMap::LEVEL2_MEMORY_BASE
            && end_address <= ConformanceMemoryMap::LEVEL2_MEMORY_BASE + LEVEL2_MEMORY_SIZE as u16
        {
            if ctx.access_level > 2 {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - ConformanceMemoryMap::LEVEL2_MEMORY_BASE) as usize;
            data.copy_from_slice(&tables.level2_memory.borrow()[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Level 1 memory
        if address >= ConformanceMemoryMap::LEVEL1_MEMORY_BASE
            && end_address <= ConformanceMemoryMap::LEVEL1_MEMORY_BASE + LEVEL1_MEMORY_SIZE as u16
        {
            if ctx.access_level > 1 {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - ConformanceMemoryMap::LEVEL1_MEMORY_BASE) as usize;
            data.copy_from_slice(&tables.level1_memory.borrow()[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // User memory
        if address >= ConformanceMemoryMap::USER_MEMORY_BASE
            && end_address <= ConformanceMemoryMap::USER_MEMORY_BASE + USER_MEMORY_SIZE as u16
        {
            let offset = (address - ConformanceMemoryMap::USER_MEMORY_BASE) as usize;
            data.copy_from_slice(&tables.user_memory.borrow()[offset..offset + data.len()]);
            return Ok(data.len());
        }

        // Read-only memory region (5.1.4/5.1.5): 0x0300–0x030F. Reads return
        // a fixed pattern; writes return `WriteProtected` in the write
        // handler.
        if address >= ConformanceMemoryMap::READONLY_MEMORY_BASE
            && end_address <= ConformanceMemoryMap::READONLY_MEMORY_BASE + ConformanceMemoryMap::READONLY_MEMORY_SIZE
        {
            let offset = (address - ConformanceMemoryMap::READONLY_MEMORY_BASE) as usize;
            for (i, byte) in data.iter_mut().enumerate() {
                *byte = (offset + i) as u8;
            }
            return Ok(data.len());
        }

        // Write-only memory region (5.2.3/5.2.4): 0x0310–0x031F. Reads return
        // `WriteProtected`; writes succeed but the data is discarded
        // (the AL maps `WriteProtected` to return code 0xFB, which 5.2.3
        // accepts as the "alternative" return code along with 0xFA).
        if address >= ConformanceMemoryMap::WRITEONLY_MEMORY_BASE
            && end_address <= ConformanceMemoryMap::WRITEONLY_MEMORY_BASE + ConformanceMemoryMap::WRITEONLY_MEMORY_SIZE
        {
            return Err(MemoryError::WriteProtected);
        }

        // A partly protected access reports the protection it met, not
        // "address void" — see `ConformanceMemoryMap::partly_protected`.
        if let Some(e) = ConformanceMemoryMap::partly_protected(address, end_address, false) {
            return Err(e);
        }

        Err(MemoryError::NotAccessible)
    }

    fn write(
        &self,
        tables: &SecureConformanceState,
        address: u16,
        data: &[u8],
        ctx: AccessContext,
    ) -> Result<usize, MemoryError> {
        use MemoryError;
        use zweidraehte_device::objects::tables::TableMemory;

        let end_address = address.saturating_add(data.len() as u16);

        // Address Table
        let adt_end = ConformanceMemoryMap::ADT_BASE + tables.adt().borrow().data_ref().len() as u16;
        if address >= ConformanceMemoryMap::ADT_BASE && end_address <= adt_end {
            let offset = (address - ConformanceMemoryMap::ADT_BASE) as usize;
            tables.adt().borrow_mut().write(offset, data);
            return Ok(data.len());
        }

        // Association Table
        let ast_end = ConformanceMemoryMap::AST_BASE + tables.ast().borrow().data_ref().len() as u16;
        if address >= ConformanceMemoryMap::AST_BASE && end_address <= ast_end {
            let offset = (address - ConformanceMemoryMap::AST_BASE) as usize;
            tables.ast().borrow_mut().write(offset, data);
            return Ok(data.len());
        }

        // Communication Object Table
        let cot_end = ConformanceMemoryMap::COT_BASE + tables.cot().borrow().data_ref().len() as u16;
        if address >= ConformanceMemoryMap::COT_BASE && end_address <= cot_end {
            let offset = (address - ConformanceMemoryMap::COT_BASE) as usize;
            tables.cot().borrow_mut().write(offset, data);
            return Ok(data.len());
        }

        // Linear memory
        if address >= ConformanceMemoryMap::LINEAR_MEMORY_BASE
            && end_address <= ConformanceMemoryMap::LINEAR_MEMORY_BASE + LINEAR_MEMORY_SIZE as u16
        {
            let offset = (address - ConformanceMemoryMap::LINEAR_MEMORY_BASE) as usize;
            tables.linear_memory.borrow_mut()[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        // ================================================================
        // Security-aware sub-regions within Level 2 memory.
        // ================================================================

        let security_on = tables.extension_state().security_mode_enabled();

        // 0x03D0-0x03DF: Access Policy 000/000 — always denied.
        if address >= 0x03D0 && end_address <= 0x03E0 {
            return Err(MemoryError::AccessDenied);
        }

        // 0x03E0-0x03EF: Access Policy 3FF/00C — everyone when SM off,
        // only Tool A+C when SM on.
        if address >= 0x03E0 && end_address <= 0x03F0 {
            if !AccessPolicy::OPEN_OFF_TOOL_ON.can_write(&ctx, security_on) {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - ConformanceMemoryMap::LEVEL2_MEMORY_BASE) as usize;
            tables.level2_memory.borrow_mut()[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        // Level 2 memory
        if address >= ConformanceMemoryMap::LEVEL2_MEMORY_BASE
            && end_address <= ConformanceMemoryMap::LEVEL2_MEMORY_BASE + LEVEL2_MEMORY_SIZE as u16
        {
            if ctx.access_level > 2 {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - ConformanceMemoryMap::LEVEL2_MEMORY_BASE) as usize;
            tables.level2_memory.borrow_mut()[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        // Level 1 memory
        if address >= ConformanceMemoryMap::LEVEL1_MEMORY_BASE
            && end_address <= ConformanceMemoryMap::LEVEL1_MEMORY_BASE + LEVEL1_MEMORY_SIZE as u16
        {
            if ctx.access_level > 1 {
                return Err(MemoryError::AccessDenied);
            }
            let offset = (address - ConformanceMemoryMap::LEVEL1_MEMORY_BASE) as usize;
            tables.level1_memory.borrow_mut()[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        // User memory
        if address >= ConformanceMemoryMap::USER_MEMORY_BASE
            && end_address <= ConformanceMemoryMap::USER_MEMORY_BASE + USER_MEMORY_SIZE as u16
        {
            let offset = (address - ConformanceMemoryMap::USER_MEMORY_BASE) as usize;
            tables.user_memory.borrow_mut()[offset..offset + data.len()].copy_from_slice(data);
            return Ok(data.len());
        }

        // Read-only memory region (5.1.4): writes always reject. The AL
        // converts `WriteProtected` to return code 0xFB (E_READ_ONLY).
        if address >= ConformanceMemoryMap::READONLY_MEMORY_BASE
            && end_address <= ConformanceMemoryMap::READONLY_MEMORY_BASE + ConformanceMemoryMap::READONLY_MEMORY_SIZE
        {
            return Err(MemoryError::WriteProtected);
        }

        // Write-only memory region (5.2.3): writes silently succeed but
        // discard the data; reads were rejected in the read handler.
        if address >= ConformanceMemoryMap::WRITEONLY_MEMORY_BASE
            && end_address <= ConformanceMemoryMap::WRITEONLY_MEMORY_BASE + ConformanceMemoryMap::WRITEONLY_MEMORY_SIZE
        {
            return Ok(data.len());
        }

        // A partly protected access reports the protection it met, not
        // "address void" — see `ConformanceMemoryMap::partly_protected`.
        if let Some(e) = ConformanceMemoryMap::partly_protected(address, end_address, true) {
            return Err(e);
        }

        Err(MemoryError::NotAccessible)
    }
}

// ============================================================================
// Certification Object Augment (Section 3.6 — KNX Secure Access Roles)
// ============================================================================

/// Object type for the KNX Certification Object (manufacturer-specific).
///
/// Active only during KNX certification testing. 0xC351 is 50001, the
/// value the EITT templates carry as `USER_OBJ_TYPE1` — their "User
/// Interface Object (IO1)", described there as being "used for testing
/// both Roles and Extended Interface Object addressing".
const CERTIFICATION_OBJECT_TYPE: InterfaceObjectType = InterfaceObjectType::Other(0xC351);

/// Property IDs on the Certification Object.
///
/// PID 51 serves the role-based access tests (data security 3.6). The
/// other four are the template's `ACCESSIBLE_PROP1`..`PROP4`, whose
/// required shapes come from its own field comments — a device is
/// expected to supply one property of each kind so the extended property
/// services have something manufacturer-specific to address.
mod cert_pid {
    /// Role-based access testing. UINT8, read/write.
    pub const ROLES: u16 = 51; // 0x33
    /// `ACCESSIBLE_PROP1` — PDT_GENERIC_02, restricted write level.
    pub const GENERIC_02: u16 = 52; // 0x34
    /// `ACCESSIBLE_PROP3` — PDT_FUNCTION.
    pub const FUNCTION: u16 = 54; // 0x36
    /// `ACCESSIBLE_PROP4` — PDT_GENERIC_01, long enough to fill an APDU.
    pub const LONG_ARRAY: u16 = 55; // 0x37
    /// `ACCESSIBLE_PROP2` — PDT_GENERIC_01 with a validated range.
    pub const RANGED: u16 = 201; // 0xC9
}

/// How many elements [`cert_pid::LONG_ARRAY`] holds.
///
/// The template reads `MAX_APDU_FIT_DATA` (F5h = 245) elements from it
/// and expects a response filling the whole 254-octet APDU, then reads
/// `MAX_APDU_LENGTH` (FEh = 254) and expects F4h. The property has to be
/// long enough that the first read is about the APDU rather than about
/// running out of property.
const CERT_LONG_ARRAY_LEN: usize = 245;

/// Accepted range for [`cert_pid::RANGED`].
///
/// Data security 4.2.12 writes each boundary and expects a distinct
/// return code: 00h is below the minimum (F6h), FFh above the maximum
/// (F7h), and 80h is a hole inside the range that must still be refused
/// (F8h). The three codes are the point of the case, so the property
/// needs all three conditions to be separable.
const CERT_RANGED_MIN: u8 = 0x01;
const CERT_RANGED_MAX: u8 = 0xFE;
const CERT_RANGED_VOID: u8 = 0x80;

/// Access policy for the Certification Object's PID 51.
///
/// `sec_off = 0x3FF`: all access types when security mode is off.
/// `sec_on = 0x0FF`: RoleX/A R+W, RoleX/A+C R+W, Tool/A+C R+W, Tool/A R+W,
/// Unlisted denied. The per-role R vs W granularity is enforced by the
/// augment's custom `can_read`/`can_write` checks (run before macro
/// dispatch via the `read_with_ctx` / `write_with_ctx` closures cannot
/// see `req.ctx`, so the bespoke logic lives in `handle_extra_pid_*`).
const CERT_PID51_POLICY: AccessPolicy = AccessPolicy::new(0x3FF, 0x0FF);

/// Augment that adds a Certification Object (IOT 0xC351) for Section 3.6
/// role-based access control conformance tests.
///
/// The object has a single read/write UINT8 property (PID 51) whose
/// access is governed by per-role permissions:
///
/// | Role | Required Security | Read | Write |
/// |------|-------------------|------|-------|
/// | 0    | A                 | yes  | yes   |
/// | 1    | A+C               | yes  | yes   |
/// | 2    | A                 | yes  | no    |
/// | 3    | A+C               | yes  | no    |
/// | 4    | A                 | no   | yes   |
/// | 5    | A+C               | no   | yes   |
/// | none | —                 | no   | no    |
/// | Tool | A or A+C          | yes  | yes   |
///
/// The access levels are written as audiences (03/04/01 §4.3.2.2
/// Table 1) rather than numbers: this augment is composed onto both
/// secure DUTs, and a literal `3` would be a *privileged* level on the
/// 16-level System 7 device rather than "free".
///
/// PID 1 (OBJECT_TYPE) is auto-emitted by the macro from the
/// `additional_objects` entry. PID 51 is marked `manual` because the
/// per-request access check needs `req.ctx`, which the macro's standard
/// `read = |this| ...` closure form doesn't expose. The bespoke logic
/// lives in `handle_extra_pid_read` / `handle_extra_pid_write` below.
#[interface_object_augment(
    additional_objects = [CERTIFICATION_OBJECT_TYPE],
)]
pub struct CertificationObjectAugment {
    // PID 1 OBJECT_TYPE — fixed `0xC351` read.
    #[io(
        pid = pid::OBJECT_TYPE,
        pdt = zweidraehte_proto::dpt::PDT_UnsignedInt,
        access = RO,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL, // 3FF/0CC
        rl = Runtime, wl = SystemManufacturer,
        read = |_this: &Self| -> [u8; 2] { 0xC351u16.to_be_bytes() },
    )]
    _object_type_io: (),

    // PID 51 ROLES — role-based access; bespoke logic in
    // `handle_extra_pid_*` below.
    #[io(
        pid = cert_pid::ROLES,
        pdt = zweidraehte_proto::dpt::PDT_UnsignedChar,
        access = RW,
        policy = CERT_PID51_POLICY,
        rl = Runtime, wl = Runtime,
        manual,
    )]
    _roles_io: (),

    // ------------------------------------------------------------------
    // The template's ACCESSIBLE_PROP1..PROP4.
    //
    // All four are `manual`: the macro's `read = |this| ...` closure form
    // cannot see the request, and each of these needs something from it —
    // a start index and count for the array, the written value for the
    // range check, the access context for the level check.
    // ------------------------------------------------------------------
    // PID 52 — PDT_GENERIC_02, restricted at both ends. 4.1.10 reads it
    // unauthorised and expects a refusal, and 4.2.11 / 4.3.11 / 4.4.11
    // authorise with the level-0 key, write, re-key, and expect the next
    // write refused. Level 0 for both means only a fully authorised
    // client gets through, which is the "higher access level" those
    // cases are named for.
    #[io(
        pid = cert_pid::GENERIC_02,
        pdt = zweidraehte_proto::dpt::PDT_Generic02,
        access = RW,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL, // 3FF/0CC
        rl = SystemManufacturer, wl = SystemManufacturer,
        manual,
    )]
    _generic02_io: (),

    // PID 201 — PDT_GENERIC_01 with the validated range above.
    #[io(
        pid = cert_pid::RANGED,
        pdt = zweidraehte_proto::dpt::PDT_Generic01,
        access = RW,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL,
        rl = Runtime, wl = Runtime,
        manual,
    )]
    _ranged_io: (),

    // PID 54 — PDT_FUNCTION. Reached through the function-property
    // services; a plain value write to it must fail with FEh, which the
    // value handlers below produce by declining it as a type mismatch.
    #[io(
        pid = cert_pid::FUNCTION,
        pdt = zweidraehte_proto::dpt::PDT_Function,
        access = RW,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL,
        rl = Runtime, wl = Runtime,
        manual,
    )]
    _function_io: (),

    // PID 55 — PDT_GENERIC_01, `CERT_LONG_ARRAY_LEN` elements.
    #[io(
        pid = cert_pid::LONG_ARRAY,
        pdt = zweidraehte_proto::dpt::PDT_Generic01,
        access = RW,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL,
        rl = Runtime, wl = Runtime,
        array(max = CERT_LONG_ARRAY_LEN as u16),
        manual,
    )]
    _long_array_io: (),

    /// The stored value for PID 51 (single byte).
    value: Cell<u8>,
    /// PID 52's two octets.
    generic02: Cell<[u8; 2]>,
    /// PID 201's single octet, seeded inside the accepted range.
    ranged: Cell<u8>,
    /// PID 55's elements. `RefCell` rather than `Cell` because reads
    /// slice it rather than copying the whole array out.
    long_array: RefCell<[u8; CERT_LONG_ARRAY_LEN]>,
}

impl CertificationObjectAugment {
    pub fn new() -> Self {
        Self {
            value: Cell::new(0),
            generic02: Cell::new([0, 0]),
            ranged: Cell::new(CERT_RANGED_MIN),
            long_array: RefCell::new([0u8; CERT_LONG_ARRAY_LEN]),
        }
    }

    /// Check whether the given access context permits reading PID 51.
    fn can_read(ctx: &AccessContext) -> bool {
        match ctx.role {
            ClientRole::Tool => true,
            ClientRole::Roles(mask) => {
                // Roles 0,1 (R+W), Roles 2,3 (R only) — all can read.
                // Roles 4,5 (W only) — cannot read.
                // Additionally, the security level must match the role's
                // requirement: even roles (0,2,4) require A, odd (1,3,5)
                // require A+C.
                Self::has_matching_read_role(mask, ctx.security)
            }
            ClientRole::Unlisted => false,
        }
    }

    /// Check whether the given access context permits writing PID 51.
    fn can_write(ctx: &AccessContext) -> bool {
        match ctx.role {
            ClientRole::Tool => true,
            ClientRole::Roles(mask) => {
                // Roles 0,1 (R+W), Roles 4,5 (W only) — can write.
                // Roles 2,3 (R only) — cannot write.
                Self::has_matching_write_role(mask, ctx.security)
            }
            ClientRole::Unlisted => false,
        }
    }

    /// Check whether the received security level satisfies a role's required
    /// security level. A+C satisfies both A+C and A requirements (superset).
    fn security_satisfies(received: SecurityMode, required: SecurityMode) -> bool {
        match (received, required) {
            (SecurityMode::AuthConf, SecurityMode::AuthConf) => true,
            (SecurityMode::AuthConf, SecurityMode::AuthOnly) => true,
            (SecurityMode::AuthOnly, SecurityMode::AuthOnly) => true,
            _ => false,
        }
    }

    /// Check if any role in the bitmask grants read access at the given
    /// security level. A role grants read if:
    /// 1. The role bit is set in the mask
    /// 2. The role is in the read-capable set (0,1,2,3)
    /// 3. The security level satisfies the role's requirement
    fn has_matching_read_role(mask: u16, security: SecurityMode) -> bool {
        // Read-capable roles: 0 (A), 1 (A+C), 2 (A), 3 (A+C)
        for role in 0..4u16 {
            if mask & (1 << role) == 0 {
                continue;
            }
            let required = if role % 2 == 0 { SecurityMode::AuthOnly } else { SecurityMode::AuthConf };
            if Self::security_satisfies(security, required) {
                return true;
            }
        }
        false
    }

    /// Check if any role in the bitmask grants write access at the given
    /// security level. A role grants write if:
    /// 1. The role bit is set in the mask
    /// 2. The role is in the write-capable set (0,1,4,5)
    /// 3. The security level satisfies the role's requirement
    fn has_matching_write_role(mask: u16, security: SecurityMode) -> bool {
        // Write-capable roles: 0 (A), 1 (A+C), 4 (A), 5 (A+C)
        for role in [0u16, 1, 4, 5] {
            if mask & (1 << role) == 0 {
                continue;
            }
            let required = if role % 2 == 0 { SecurityMode::AuthOnly } else { SecurityMode::AuthConf };
            if Self::security_satisfies(security, required) {
                return true;
            }
        }
        false
    }
}

// ============================================================================
// Manual fallback methods for PID 51 (role-based access checks).
//
// PIDs marked `manual` in the struct attributes route here. Unhandled
// PIDs return `None` so the augment chain falls through.
// ============================================================================

impl CertificationObjectAugment {
    /// All Certification PIDs are statically known — no runtime-conditional
    /// descriptors. Returns `None` to fall through to the macro's static
    /// descriptor table.
    pub fn handle_extra_pid_descriptor(
        &self,
        _object_type: InterfaceObjectType,
        _prop_id: u16,
    ) -> Option<zweidraehte_proto::properties::PropertyDescriptor> {
        None
    }

    pub fn handle_extra_pid_read<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        match req.pid {
            cert_pid::ROLES => {
                if !Self::can_read(&req.ctx) {
                    return Some(Err(PropertyError::AccessDenied));
                }
                let val = [self.value.get()];
                Some(val.read_property(req.start_idx, req.count, buf))
            }
            cert_pid::GENERIC_02 => Some(self.generic02.get().read_property(req.start_idx, req.count, buf)),
            cert_pid::RANGED => Some([self.ranged.get()].read_property(req.start_idx, req.count, buf)),
            cert_pid::LONG_ARRAY => Some(self.read_long_array(req.start_idx, req.count, buf)),
            // PID 54 is PDT_FUNCTION. A value read of a function
            // property is not a thing, so it falls through to the same
            // type-conflict answer as a value write.
            cert_pid::FUNCTION => Some(Err(PropertyError::TypeMismatch)),
            _ => None,
        }
    }

    pub fn handle_extra_pid_write<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        match req.pid {
            cert_pid::ROLES => {
                if !Self::can_write(&req.ctx) {
                    return Some(Err(PropertyError::AccessDenied));
                }
                if req.data.len() != 1 {
                    return Some(Err(PropertyError::TypeMismatch));
                }
                self.value.set(req.data[0]);
                Some(Ok(WriteResponse::Echo))
            }
            cert_pid::GENERIC_02 => {
                if req.data.len() != 2 {
                    return Some(Err(PropertyError::TypeMismatch));
                }
                self.generic02.set([req.data[0], req.data[1]]);
                Some(Ok(WriteResponse::Echo))
            }
            cert_pid::RANGED => {
                if req.data.len() != 1 {
                    return Some(Err(PropertyError::TypeMismatch));
                }
                // The three rejections 4.2.12 distinguishes. Order
                // matters only in that the void value sits inside the
                // range, so it has to be checked after the bounds rather
                // than folded into them.
                let value = req.data[0];
                if value < CERT_RANGED_MIN {
                    return Some(Err(PropertyError::ValueBelowMin));
                }
                if value > CERT_RANGED_MAX {
                    return Some(Err(PropertyError::ValueAboveMax));
                }
                if value == CERT_RANGED_VOID {
                    return Some(Err(PropertyError::ValueOutOfRange));
                }
                self.ranged.set(value);
                Some(Ok(WriteResponse::Echo))
            }
            cert_pid::LONG_ARRAY => {
                let start = req.start_idx as usize;
                let mut store = self.long_array.borrow_mut();
                // `start_idx` is 1-based, and element 0 is the element
                // count, which is not writable.
                if start == 0 || start - 1 + req.data.len() > store.len() {
                    return Some(Err(PropertyError::InvalidStartIndex));
                }
                store[start - 1..start - 1 + req.data.len()].copy_from_slice(req.data);
                Some(Ok(WriteResponse::Echo))
            }
            // A value write to a PDT_FUNCTION property: 4.2.13 and
            // 4.3.12 expect FEh, which is what TypeMismatch maps to.
            cert_pid::FUNCTION => Some(Err(PropertyError::TypeMismatch)),
            _ => None,
        }
    }

    /// Array read for [`cert_pid::LONG_ARRAY`].
    ///
    /// The blanket `PropertyRead` impl is single-element — it refuses
    /// anything but `start_idx == 1, count == 1` — so an array property
    /// has to do the slicing itself. Same convention the tunnelling
    /// augment follows: `start_idx == 0` answers the element count as a
    /// big-endian u16, and `start_idx >= 1` is a 1-based offset.
    fn read_long_array(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        let store = self.long_array.borrow();

        if start_idx == 0 {
            if buf.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            buf[..2].copy_from_slice(&(store.len() as u16).to_be_bytes());
            return Ok(2);
        }
        if count == 0 {
            return Err(PropertyError::InvalidElementCount);
        }

        let start = (start_idx - 1) as usize;
        if start >= store.len() {
            return Err(PropertyError::InvalidStartIndex);
        }
        // Clamped rather than refused: a read running off the end
        // returns what is there, and it is the APDU budget that decides
        // whether the answer fits — 4.1.8 wants F4h from that check, not
        // an address error from this one.
        let end = (start + count as usize).min(store.len());
        let needed = end - start;
        if buf.len() < needed {
            return Err(PropertyError::BufferTooSmall);
        }
        buf[..needed].copy_from_slice(&store[start..end]);
        Ok(needed)
    }

    /// The function-property body for PID 54.
    ///
    /// Three octets, so that with the return code in front the response
    /// carries the four the template expects: 4.2.13, 4.3.12 and 4.6.1
    /// all match `?? ?? ?? ??`, which is return code plus three. The
    /// contents are free — the wildcards say the template only cares
    /// that the property answers as a function property at all — so this
    /// echoes the service ID and the stored byte rather than a constant,
    /// which makes a wrong-PID answer visible in a trace.
    fn function_body(&self, req: &FunctionPropertyRequest<'_>) -> [u8; 3] {
        let service_id = req.service_data.get(1).copied().unwrap_or(0);
        [service_id, self.value.get(), 0x00]
    }

    pub fn handle_extra_pid_function_command<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        match req.prop_id {
            cert_pid::FUNCTION => Some(FunctionPropertyResult::with_code(
                zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode::Success,
                &self.function_body(req),
            )),
            _ => None,
        }
    }

    pub fn handle_extra_pid_function_state_read<D: StackDefinition>(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        match req.prop_id {
            cert_pid::FUNCTION => Some(FunctionPropertyResult::with_code(
                zweidraehte_proto::messages::apdu::property_ext::PropertyReturnCode::Success,
                &self.function_body(req),
            )),
            _ => None,
        }
    }
}

// ============================================================================
// Stack Definition
// ============================================================================

/// Type alias for the security augment produced by the extension.
type SecAugment<'a> = SecureAugmentBundle<
    'a,
    Tp1Augment<'a>,
    ShmSiatStore,
    { table_sizes::ADT_ENTRIES },
    { sec_table_sizes::P2P },
    { table_sizes::COT_ENTRIES },
>;

/// Conformance-only "extras" beyond the security augment: the
/// certification object the spec validation suite checks, plus a
/// diagnostics augment that mirrors a real device's PID 56 surface.
/// Bundled into a small registry struct so it can be `flatten`-ed
/// into the outer device augment chain below.
#[derive(ServiceRegistry)]
pub struct ConformanceExtras<'a> {
    #[service(augment)]
    pub cert: CertificationObjectAugment,
    // This is a secure device, so diagnostics uses the `WithSecureGoSend`
    // strategy — the secure GO-diagnostics send-paths are wired up. (A
    // non-secure device would use the default `NoSecureGoSend`.)
    #[service(augment)]
    pub diag: DiagnosticsAugment<'a, WithSecureGoSend>,
}

/// Outer device augment chain: the secure-extension augment, plus the
/// flattened conformance extras. `#[service(flatten)]` inlines the
/// extras' two augments into this struct's `Augment<D>`
/// chain so they participate in the property hooks, IO list
/// aggregation, and lifecycle as if they were declared directly here.
#[derive(ServiceRegistry)]
pub struct SecureConformanceAugments<'a> {
    #[service(augment)]
    pub sec: SecAugment<'a>,
    #[service(flatten)]
    pub extras: ConformanceExtras<'a>,
}

/// Configuration for constructing a [`SecureConformanceState`].
///
/// Passed to [`IpcSecureConformanceTestStack::create_state`] to produce the full state.
pub enum SecureConformanceStateInit {
    /// Build fresh state from pre-built tables and application.
    Fresh {
        addr_tab: conformance_config::AddrTab,
        asso_tab: conformance_config::AssoTab,
        co_tab: conformance_config::CoTab,
        app_table: Application<TestParameters>,
    },
    /// Restore from a previously-persisted snapshot.
    Loaded { config: SecureConformanceDeviceConfig },
}

/// Secure conformance test stack definition.
///
/// Drop-in replacement for [`IpcConformanceTestStack`] that enables
/// KNX Data Secure via [`SecureDeviceBuilder`].
#[derive(Copy, Clone)]
pub struct IpcSecureConformanceTestStack;

impl StackDefinition for IpcSecureConformanceTestStack {
    const DEVICE: &'static DeviceDescriptor = &device_info::DEVICE;
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = Some(&CONFORMANCE_DD2);
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = Some(&CONFORMANCE_USER_MANUFACTURER_INFO);
    const MAX_APDU_LENGTH: u16 = device_info::MAX_APDU_LENGTH;
    const TL_STYLE: TlStyle = TlStyle::Style3;
    const FIRST_ASAP: u16 = 1;

    type P = TestParameters;
    type CO = super::stack::comm_objs::ConformanceComObjects;
    type LLB = super::ipc::IpcLinkLayerBuilder;
    type ES =
        SecureTp1ExtensionState<{ table_sizes::ADT_ENTRIES }, { sec_table_sizes::P2P }, { table_sizes::COT_ENTRIES }>;
    // The stores struct (here: just the shared-memory SIAT store), wired onto
    // the LayerContext so the secure layers pull it out through
    // `HasSeqStore`.
    type Storage = &'static ConformanceSecureStorage;
    type Identity = StaticSecureIdentity;
    type State = SecureConformanceState;
    type StateInit = SecureConformanceStateInit;
    type Mem = ConformanceMemoryMap;

    type InterfaceObjects<'a> = SystemBInterfaceObjectsFor<'a, Self>;
    type Augments<'a> = SecureConformanceAugments<'a>;

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
        create_system_b_objects::<Self, _>(state, layer_ctx, &CONFORMANCE_MEMORY_LAYOUT, augments)
    }

    type DeviceModel<'a> = SystemBDeviceModel<'a, Self>;

    fn create_device_model<'a>(
        state: &'a Self::State,
        layer_context: &'a LayerContext<Self>,
        interface_objects: &'a Self::InterfaceObjects<'static>,
    ) -> Self::DeviceModel<'a>
    where
        Self::State: 'a,
    {
        SystemBDeviceModel::new(state, layer_context, interface_objects)
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
        SecureConformanceAugments {
            sec: state.extension_state().create_secure_augment(platform, layer_ctx),
            extras: ConformanceExtras {
                cert: CertificationObjectAugment::new(),
                diag: DiagnosticsAugment::<WithSecureGoSend>::new(&state.inner.operation_mode),
            },
        }
    }

    fn create_state(init: Self::StateInit) -> Self::State {
        match init {
            SecureConformanceStateInit::Fresh { addr_tab, asso_tab, co_tab, app_table } => {
                SecureConformanceState::new(addr_tab, asso_tab, co_tab, app_table)
            }
            SecureConformanceStateInit::Loaded { config } => SecureConformanceState::from_device_config(config),
        }
    }

    type AlExtensions = (StandardAlServices, PropertyExtValueService);
    type LayerBuilder = SecureDeviceBuilder<WithP2p>;
    type Rng = GetrandomRng;
}

// ============================================================================
// ConformanceStack Integration
// ============================================================================
//
// Wires the secure stack into the generic DUT helpers in
// `crate::dut_common`. Mirrors the plain-stack implementation in
// `super::stack`, differing only in the inner state type the erase-code
// dispatch targets.

impl crate::dut_common::ConformanceStack for IpcSecureConformanceTestStack {
    type DeviceConfig = SecureConformanceDeviceConfig;

    fn to_device_config(state: &Self::State) -> Self::DeviceConfig {
        state.to_device_config()
    }

    fn apply_erase_code(state: &Self::State, code: EraseCode) {
        crate::dut_common::apply_erase_code_to_system_b(state.inner(), code);
    }
}

// ============================================================================
// Sequence Number Storage
// ============================================================================

use zweidraehte_device::layers::application::services::{PropertyExtValueService, StandardAlServices};
use zweidraehte_device::storage::backends::{ByteIo, PackedSeqStore, region_len};
use zweidraehte_device::storage::region::FramSiatRegion;
use zweidraehte_device::storage::{HasSeqStore, SiatStore, seq};

/// An [`ByteIo`] over the `mmap(MAP_SHARED)` seq region, addressed by a raw
/// pointer.
///
/// Reads and writes go directly to the mapping, so they are immediately visible
/// to the parent and survive child-process restarts (the parent holds the
/// memfd). The packed layout and all the offset/peer-table logic live in
/// [`PackedSeqStore`]; this is purely the medium, the host-side twin of the
/// embedded `FramRegion`.
pub struct ShmRegion {
    ptr: *mut u8,
}

// SAFETY: The embassy executor is single-threaded — no concurrent access.
unsafe impl Send for ShmRegion {}
unsafe impl Sync for ShmRegion {}

impl ShmRegion {
    /// # Safety
    /// `ptr` must be valid for the lifetime of this region and point to at
    /// least [`packed_seq::region_len(16)`](zweidraehte_device::storage::backends::region_len)
    /// writable bytes in a `MAP_SHARED` region.
    pub unsafe fn from_ptr(ptr: *mut u8) -> Self {
        Self { ptr }
    }
}

impl ByteIo for ShmRegion {
    type Error = core::convert::Infallible;

    fn read_at(&self, off: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        unsafe { core::ptr::copy_nonoverlapping(self.ptr.add(off as usize), buf.as_mut_ptr(), buf.len()) };
        Ok(())
    }

    fn write_at(&mut self, off: u32, data: &[u8]) -> Result<(), Self::Error> {
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(off as usize), data.len()) };
        Ok(())
    }
}

/// The SIAT region the shared-memory store binds: the same write-in-place
/// [`FramSiatRegion`] (`"KNXR"` magic) a FRAM device uses, sized to the
/// 256-byte tail `SharedMemory` carves out (`region_len(16)` = 146 fits). It
/// owns the whole tail at offset 0 (via `new()`), so it never appears in a
/// `REGIONS` array — and its `BATCH` parameter is moot (the harness builds
/// its `SiatStore` by hand with K = 0 for exact per-write persistence).
type ShmSiatRegion = FramSiatRegion<256, 16>;

/// Shared-memory sequence/SIAT store: [`PackedSeqStore`] over a [`ShmRegion`].
///
/// The mmap region is zero-filled by the kernel (and re-zeroed by
/// `clear_seq_region` between suites), which the layout relies on: no magic
/// yet means the store boots to defaults, and the peer-count field reads 0
/// on first boot before any write.
pub type ShmSeqStorage = PackedSeqStore<ShmRegion, ShmSiatRegion, 16>;

// The bound region must cover the packed 16-slot layout within the shm tail.
const _: () = assert!(region_len(16) <= 256);

/// Static pointer to the seq region in shared memory.
/// Set by `dut_secure.rs` before stack creation.
static SEQ_PTR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// The DUT's hand-written stores struct — the conformance twin of the
/// stores structs (`SecureStorage` etc.) on real devices. Holds only
/// the shared-memory SIAT store; the DUT's config persistence goes through
/// its own shm snapshot path, not the storage task.
pub struct ConformanceSecureStorage {
    pub seq: core::cell::RefCell<ShmSiatStore>,
}

impl HasSeqStore for ConformanceSecureStorage {
    type Seq = ShmSiatStore;
    fn seq_store(&self) -> &core::cell::RefCell<ShmSiatStore> {
        &self.seq
    }
}

// The storage-side half of a restart erase, exactly what the macro-emitted
// handle composes for a `seq:` store on real devices. The DUT's restart path
// (`dut_common::flush_and_exit`) drives it through the same trait the
// generic storage task uses.
impl StorageHooks for ConformanceSecureStorage {
    fn erase(&self, code: EraseCode) {
        seq::erase_seq_on_factory_reset(&mut *self.seq.borrow_mut(), code);
    }
}

/// Boot the SIAT store from the shm mapping and place it in its static home.
/// Call once per DUT process, after [`set_seq_shm_ptr`], before
/// `zweidraehte_device::new()`.
pub fn init_secure_storage() -> &'static ConformanceSecureStorage {
    static STORAGE: static_cell::StaticCell<ConformanceSecureStorage> = static_cell::StaticCell::new();
    let seq =
        SiatStore::boot(IpcSecureConformanceTestStack::create_seq_storage()).expect("shm seq store boot is infallible");
    &*STORAGE.init(ConformanceSecureStorage { seq: core::cell::RefCell::new(seq) })
}

impl IpcSecureConformanceTestStack {
    /// Build the shared-memory sequence storage from the pointer
    /// installed by [`set_seq_shm_ptr`].
    ///
    /// The conformance harness is the one stack whose storage can be
    /// built "from nothing" (a process-global shared-memory mapping);
    /// hardware devices construct theirs in `main` from peripherals
    /// and thread it through `StateInit` → `SecureResources`.
    pub fn create_seq_storage() -> ShmSeqStorage {
        let ptr = *SEQ_PTR.get().expect("set_seq_shm_ptr() must be called before stack creation");
        ShmSeqStorage::new(unsafe { ShmRegion::from_ptr(ptr as *mut u8) })
    }
}

/// Set the shared memory seq pointer. Must be called once before the
/// stack is created.
pub fn set_seq_shm_ptr(ptr: *mut u8) {
    SEQ_PTR.set(ptr as usize).expect("SEQ_PTR already set");
}

// ============================================================================
// Shared Memory Persistence
// ============================================================================

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Persisted state type for the secure inner state.
type SecureInnerDeviceConfig = DeviceConfig<
    { table_sizes::ADT },
    { table_sizes::AST },
    { table_sizes::COT },
    TestParameters,
    SecureExtensionConfig<
        Tp1ExtensionConfig,
        { table_sizes::ADT_ENTRIES },
        { sec_table_sizes::P2P },
        { table_sizes::COT_ENTRIES },
    >,
>;

/// Full snapshot for the secure conformance DUT.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SecureConformanceDeviceConfig {
    pub inner: SecureInnerDeviceConfig,
    #[serde_as(as = "[_; LINEAR_MEMORY_SIZE]")]
    pub linear_memory: [u8; LINEAR_MEMORY_SIZE],
    #[serde_as(as = "[_; LEVEL2_MEMORY_SIZE]")]
    pub level2_memory: [u8; LEVEL2_MEMORY_SIZE],
    #[serde_as(as = "[_; LEVEL1_MEMORY_SIZE]")]
    pub level1_memory: [u8; LEVEL1_MEMORY_SIZE],
    #[serde_as(as = "[_; USER_MEMORY_SIZE]")]
    pub user_memory: [u8; USER_MEMORY_SIZE],
}

impl SecureConformanceDeviceConfig {
    /// Build the default persisted snapshot without constructing runtime state.
    ///
    /// This produces the same serialized form as the old `Default` impl did,
    /// but assembles the `DeviceConfig` directly.
    pub fn default_snapshot() -> Self {
        let (addr_tab, asso_tab, co_tab) = conformance_config::ConformanceTestConfig::create_tables(
            ConformanceMemoryMap::ADT_BASE as u32,
            ConformanceMemoryMap::AST_BASE as u32,
            ConformanceMemoryMap::COT_BASE as u32,
        );
        let mut app_table = Application::<TestParameters>::new();
        app_table.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app_table.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        let sec_config = conformance_config::ConformanceTestConfig::create_security_config();

        let mut inner = SecureInnerDeviceConfig::factory_default();
        inner.individual_address = IndividualAddress::new(1, 0, 1);
        inner.address_table = addr_tab;
        inner.association_table = asso_tab;
        inner.group_object_table = co_tab;
        inner.application = app_table;
        inner.extension_config.security.grp_keys = sec_config.grp_keys;
        inner.extension_config.security.go_flags = sec_config.go_flags;
        inner.extension_config.security.tool_key = sec_config.tool_key;

        Self {
            inner,
            linear_memory: [0x0F; LINEAR_MEMORY_SIZE],
            level2_memory: [0xAA; LEVEL2_MEMORY_SIZE],
            level1_memory: [0xFF; LEVEL1_MEMORY_SIZE],
            user_memory: [0xFF; USER_MEMORY_SIZE],
        }
    }
}

impl SecureConformanceState {
    pub fn from_device_config(snapshot: SecureConformanceDeviceConfig) -> Self {
        let identity = StaticSecureIdentity::new(SECURE_SERIAL_NUMBER, SECURE_FDSK);
        let resources = SecureResources::simple(SECURE_FDSK);
        let inner = SecureInnerState::from_config(identity, snapshot.inner, resources);

        Self {
            inner,
            linear_memory: RefCell::new(snapshot.linear_memory),
            level2_memory: RefCell::new(snapshot.level2_memory),
            level1_memory: RefCell::new(snapshot.level1_memory),
            user_memory: RefCell::new(snapshot.user_memory),
            dm_slot: DmNotificationSlot::new(),
        }
    }

    pub fn to_device_config(&self) -> SecureConformanceDeviceConfig {
        SecureConformanceDeviceConfig {
            inner: self.inner.to_config(),
            linear_memory: *self.linear_memory.borrow(),
            level2_memory: *self.level2_memory.borrow(),
            level1_memory: *self.level1_memory.borrow(),
            user_memory: *self.user_memory.borrow(),
        }
    }
}
