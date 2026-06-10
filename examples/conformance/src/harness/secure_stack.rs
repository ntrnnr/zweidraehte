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

use zweidraehte_device::bcus::system_b::{DiagnosticsAugment, SecureGoSendPresent};
use zweidraehte_device::prelude::*;
use zweidraehte_device::{
    HasExtensionState, HasSecurityMode, StackDefinition,
    bcus::system_b::{
        DeviceConfig, ExtensionAugmentFor, HasDeviceConfig, SecureExtensionConfig, SecureResources,
        SecureTp1DeviceState, SecureTp1ExtensionState, SystemBInterfaceObjectsFor, Tp1ExtensionConfig,
        create_system_b_objects,
    },
    context::layer::LayerContext,
    device_model::{DeviceModelEvent, DeviceModelNotifier, DmNotificationSlot},
    memory::MemoryMap,
    objects::interface::{
        FullPropertyReadRequest, FullPropertyWriteRequest, HasRoutingCount, PropertyError, PropertyRead, WriteResponse,
    },
    objects::tables::{
        Application, HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable,
        HasLoadStateMachine, HasPeiApplication, LoadEvent,
    },
};
use zweidraehte_proto::AccessContext;
use zweidraehte_proto::HasConnectionAuth;
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
/// `GRP` and `GO` are no longer needed — `SecureTp1DeviceState` derives
/// them from `ADT_SIZE` and `COT_SIZE` respectively. `P2P` (P2P Key
/// Table) and `SIAT` (Security Individual Address Table) are
/// independent per 03/03/07 §5.3.
pub mod sec_table_sizes {
    /// Max P2P Key Table entries.
    pub const P2P: usize = 8;
    /// Max SIAT entries (union of P2P + group-secure senders).
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
pub const SECURE_FDSK: [u8; 16] =
    [0xF0, 0xD5, 0x1A, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF];

// ============================================================================
// Secure Inner State Type
// ============================================================================

type SecureInnerState = SecureTp1DeviceState<
    { table_sizes::ADT },
    { table_sizes::AST },
    { table_sizes::COT },
    IpcSecureConformanceTestStack,
    ShmSeqStorage,
    { sec_table_sizes::P2P },
    { sec_table_sizes::SIAT },
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
        let resources = SecureResources {
            inner: (),
            seq_storage: IpcSecureConformanceTestStack::create_seq_storage(),
            fdsk: SECURE_FDSK,
        };
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

impl HasSecurityMode for SecureConformanceState {
    fn security_mode_enabled(&self) -> bool {
        self.inner.security_mode_enabled()
    }
    fn log_access_denied(&self, source_addr: u16) {
        self.inner.log_access_denied(source_addr);
    }
    fn has_group_key(&self, tsap: u16) -> bool {
        self.inner.has_group_key(tsap)
    }
}

// ============================================================================
// Trait Forwarding
// ============================================================================

// ============================================================================
// HasPersistence Forwarding
// ============================================================================

impl HasPersistence for SecureConformanceState {
    fn mark_dirty(&self) {
        self.inner.mark_dirty();
    }
}

// ============================================================================
// Random byte source for KNX Data Secure (plugs into `StackDefinition::Rng`)
// ============================================================================
//
// The Secure Application Layer pulls randomness through
// `<D::Rng as Rng>::fill` rather than from the state type, so firmware
// can provide an RNG without a state newtype. The conformance DUT runs
// under Linux, so a libc `getrandom` call is both cheapest and strongest.

pub struct GetrandomRng;

impl zweidraehte_device::Rng for GetrandomRng {
    fn fill(buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom failed");
    }
}

impl zweidraehte_device::SecureRng for GetrandomRng {}

// ============================================================================
// HasAuthorization Forwarding
// ============================================================================

impl HasAuthorization for SecureConformanceState {
    fn max_access_levels(&self) -> u8 {
        self.inner.max_access_levels()
    }
    fn default_access_level(&self) -> u8 {
        self.inner.default_access_level()
    }
    fn authorize(&self, key: &[u8; 4]) -> u8 {
        self.inner.authorize(key)
    }
    fn key_write(&self, level: u8, key: &[u8; 4], ctx: AccessContext) -> u8 {
        self.inner.key_write(level, key, ctx)
    }
}

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
// HasExtensionState
// ============================================================================

impl HasExtensionState for SecureConformanceState {
    type ES = <SecureInnerState as HasExtensionState>::ES;
    fn extension_state(&self) -> &Self::ES {
        self.inner.extension_state()
    }
}

// ============================================================================
// Table Accessors
// ============================================================================

impl HasAddressTable for SecureConformanceState {
    type ADT = <SecureInnerState as HasAddressTable>::ADT;

    fn adt(&self) -> &RefCell<Self::ADT> {
        self.inner.adt()
    }
}

impl HasAssociationTable for SecureConformanceState {
    type AST = <SecureInnerState as HasAssociationTable>::AST;

    fn ast(&self) -> &RefCell<Self::AST> {
        self.inner.ast()
    }
}

impl HasCommunicationObjectTable for SecureConformanceState {
    type COT = <SecureInnerState as HasCommunicationObjectTable>::COT;

    fn cot(&self) -> &RefCell<Self::COT> {
        self.inner.cot()
    }
}

impl zweidraehte_device::objects::comm::HasCommObjects for SecureConformanceState {
    type CO = super::stack::comm_objs::ConformanceComObjects;

    fn comm_objects(&self) -> &RefCell<Self::CO> {
        self.inner.comm_objects()
    }
}

// The secure conformance harness wraps a `SystemBDeviceState` whose
// extension state is `SecureExtensionState<...>`. Forward the policy
// queries down to the inner state — the secure extension's overrides
// then consult `PID_GO_SECURITY_FLAGS`, the P2P key table, etc.
impl zweidraehte_device::objects::comm::HasGoSecurityView for SecureConformanceState {
    fn required_security_for_asap(&self, asap: u16) -> zweidraehte_proto::messages::knx::RequiredSecurity {
        self.inner.required_security_for_asap(asap)
    }

    fn required_security_for_p2p(&self, peer_ia: u16) -> zweidraehte_proto::messages::knx::RequiredSecurity {
        self.inner.required_security_for_p2p(peer_ia)
    }

    fn required_security_for_broadcast(&self) -> zweidraehte_proto::messages::knx::RequiredSecurity {
        self.inner.required_security_for_broadcast()
    }

    fn required_security_for_tool_access(&self) -> zweidraehte_proto::messages::knx::RequiredSecurity {
        self.inner.required_security_for_tool_access()
    }
}

impl zweidraehte_device::HasDiagnosticsContext for SecureConformanceState {
    type Diagnostics = zweidraehte_device::bcus::system_b::OperationModeState;

    fn diagnostics(&self) -> &Self::Diagnostics {
        self.inner.diagnostics()
    }
}

impl HasApplication for SecureConformanceState {
    type APP = <SecureInnerState as HasApplication>::APP;

    fn app(&self) -> &RefCell<Self::APP> {
        self.inner.app()
    }
}

impl HasPeiApplication for SecureConformanceState {
    type PEI = <SecureInnerState as HasPeiApplication>::PEI;

    fn pei(&self) -> &RefCell<Self::PEI> {
        self.inner.pei()
    }
}

impl HasRoutingCount for SecureConformanceState {
    fn routing_count(&self) -> u8 {
        self.inner.routing_count()
    }

    fn set_routing_count(&self, value: u8) {
        self.inner.set_routing_count(value)
    }
}

impl HasConnectionAuth for SecureConformanceState {
    fn connection_access(&self, slot: u8) -> AccessContext {
        self.inner.connection_access(slot)
    }
    fn set_connection_access(&self, slot: u8, ctx: AccessContext) {
        self.inner.set_connection_access(slot, ctx);
    }
    fn reset_connection_access(&self, slot: u8, default_level: u8) {
        self.inner.reset_connection_access(slot, default_level);
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
    ) -> Result<usize, zweidraehte_device::memory::MemoryError> {
        // Delegate to the same memory map logic, just with different state type.
        // The memory regions are identical.
        use zweidraehte_device::memory::MemoryError;
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

        // Read-only memory region (5.1.4): 0x0500–0x050F. Reads return
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

        // Write-only memory region (5.2.3): 0x0510–0x051F. Reads return
        // `WriteProtected`; writes succeed but the data is discarded
        // (the AL maps `WriteProtected` to return code 0xFB, which 5.2.3
        // accepts as the "alternative" return code along with 0xFA).
        if address >= ConformanceMemoryMap::WRITEONLY_MEMORY_BASE
            && end_address <= ConformanceMemoryMap::WRITEONLY_MEMORY_BASE + ConformanceMemoryMap::WRITEONLY_MEMORY_SIZE
        {
            return Err(MemoryError::WriteProtected);
        }

        Err(MemoryError::NotAccessible)
    }

    fn write(
        &self,
        tables: &SecureConformanceState,
        address: u16,
        data: &[u8],
        ctx: AccessContext,
    ) -> Result<usize, zweidraehte_device::memory::MemoryError> {
        use zweidraehte_device::memory::MemoryError;
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

        Err(MemoryError::NotAccessible)
    }
}

// ============================================================================
// Certification Object Augment (Section 3.6 — KNX Secure Access Roles)
// ============================================================================

/// Object type for the KNX Certification Object (manufacturer-specific).
///
/// Active only during KNX certification testing. Provides PID 51 (0x33) as
/// a single UINT8 property with role-based access policies.
const CERTIFICATION_OBJECT_TYPE: InterfaceObjectType = InterfaceObjectType::Other(0xC351);

/// Property ID used for role-based access testing.
mod cert_pid {
    pub const ROLES: u16 = 51; // 0x33
}

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
/// PID 1 (OBJECT_TYPE) is auto-emitted by the macro from the
/// `additional_objects` entry. PID 51 is marked `manual` because the
/// per-request access check needs `req.ctx`, which the macro's standard
/// `read = |this| ...` closure form doesn't expose. The bespoke logic
/// lives in `handle_extra_pid_read` / `handle_extra_pid_write` below.
#[zweidraehte_device::objects::interface::interface_object_augment(
    additional_objects = [CERTIFICATION_OBJECT_TYPE],
)]
pub struct CertificationObjectAugment {
    // PID 1 OBJECT_TYPE — fixed `0xC351` read.
    #[io(
        pid = zweidraehte_device::objects::interface::pid::OBJECT_TYPE,
        pdt = zweidraehte_proto::dpt::PDT_UnsignedInt,
        access = RO,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL, // 3FF/0CC
        rl = 3, wl = 0,
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
        rl = 3, wl = 3,
        manual,
    )]
    _roles_io: (),

    /// The stored value for PID 51 (single byte).
    value: Cell<u8>,
}

impl CertificationObjectAugment {
    pub fn new() -> Self {
        Self { value: Cell::new(0) }
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
        _ctx: &zweidraehte_device::service::ServiceCtx<'_, D>,
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
            _ => None,
        }
    }

    pub fn handle_extra_pid_write<D: StackDefinition>(
        &self,
        _ctx: &zweidraehte_device::service::ServiceCtx<'_, D>,
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
            _ => None,
        }
    }

    pub fn handle_extra_pid_function_command<D: StackDefinition>(
        &self,
        _ctx: &zweidraehte_device::service::ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        _req: &zweidraehte_device::objects::interface::FunctionPropertyRequest<'_>,
    ) -> Option<zweidraehte_device::objects::interface::FunctionPropertyResult> {
        None
    }

    pub fn handle_extra_pid_function_state_read<D: StackDefinition>(
        &self,
        _ctx: &zweidraehte_device::service::ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        _req: &zweidraehte_device::objects::interface::FunctionPropertyRequest<'_>,
    ) -> Option<zweidraehte_device::objects::interface::FunctionPropertyResult> {
        None
    }
}

// ============================================================================
// Stack Definition
// ============================================================================

/// Type alias for the security augment produced by the extension.
type SecAugment<'a> = ExtensionAugmentFor<'a, IpcSecureConformanceTestStack>;

/// Conformance-only "extras" beyond the security augment: the
/// certification object the spec validation suite checks, plus a
/// diagnostics augment that mirrors a real device's PID 56 surface.
/// Bundled into a small registry struct so it can be `flatten`-ed
/// into the outer device augment chain below.
#[derive(zweidraehte_device::service::ServiceRegistry)]
pub struct ConformanceExtras<'a> {
    #[service(augment)]
    pub cert: CertificationObjectAugment,
    // This is a secure device, so diagnostics uses the `SecureGoSendPresent`
    // strategy — the secure GO-diagnostics send-paths are wired up. (A
    // non-secure device would use the default `SecureGoSendAbsent`.)
    #[service(augment)]
    pub diag: DiagnosticsAugment<'a, SecureGoSendPresent>,
}

/// Outer device augment chain: the secure-extension augment, plus the
/// flattened conformance extras. `#[service(flatten)]` inlines the
/// extras' two augments into this struct's `Augment<D>`
/// chain so they participate in the property hooks, IO list
/// aggregation, and lifecycle as if they were declared directly here.
#[derive(zweidraehte_device::service::ServiceRegistry)]
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
    Loaded { config: SecureConformanceDeviceConfig, seq_storage: ShmSeqStorage },
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
    const TL_STYLE: zweidraehte_device::layers::transport::TlStyle =
        zweidraehte_device::layers::transport::TlStyle::Style3;

    type P = TestParameters;
    type CO = super::stack::comm_objs::ConformanceComObjects;
    type LLB = super::ipc::IpcLinkLayerBuilder;
    type ES = SecureTp1ExtensionState<
        ShmSeqStorage,
        { table_sizes::ADT },
        { sec_table_sizes::P2P },
        { sec_table_sizes::SIAT },
        { table_sizes::COT },
    >;
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

    fn create_augments<'a>(
        state: &'a Self::State,
        platform: &'a Self::Platform,
        _layer_ctx: &'a zweidraehte_device::context::layer::LayerContext<Self>,
    ) -> Self::Augments<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        use zweidraehte_device::HasExtensionState;
        use zweidraehte_device::bcus::system_b::Extension;
        SecureConformanceAugments {
            sec: state.extension_state().create_augment::<Self>(platform),
            extras: ConformanceExtras {
                cert: CertificationObjectAugment::new(),
                diag: DiagnosticsAugment::<SecureGoSendPresent>::new(&state.inner.operation_mode),
            },
        }
    }

    fn create_state(init: Self::StateInit) -> Self::State {
        match init {
            SecureConformanceStateInit::Fresh { addr_tab, asso_tab, co_tab, app_table } => {
                SecureConformanceState::new(addr_tab, asso_tab, co_tab, app_table)
            }
            SecureConformanceStateInit::Loaded { config, seq_storage } => {
                SecureConformanceState::from_device_config(config, seq_storage)
            }
        }
    }

    type AlExtensions = (
        zweidraehte_device::layers::application::services::SystemBAlServices,
        zweidraehte_device::layers::application::services::PropertyExtValueService,
    );
    type LayerBuilder = SecureDeviceBuilder<zweidraehte_device::layers::secure_application::WithP2p>;
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

    fn apply_erase_code(state: &Self::State, code: zweidraehte_device::restart::EraseCode) {
        crate::dut_common::apply_erase_code_to_system_b(state.inner(), code);
    }
}

// ============================================================================
// Sequence Number Storage
// ============================================================================

use zweidraehte_device::storage::{HasSequenceStorage, SequenceNumberStorage};

/// Sequence number storage backed by shared memory.
///
/// Reads and writes directly to the `mmap(MAP_SHARED)` region at a fixed
/// offset. Writes are immediately visible to the parent and survive child
/// process restarts (the parent holds the memfd).
///
/// Layout at `ptr`: `[magic: 4B "SEQ\0"] [sending: 6B]`
pub struct ShmSeqStorage {
    ptr: *mut u8,
}

const SEQ_MAGIC: [u8; 4] = *b"SEQ\0";

// SAFETY: The embassy executor is single-threaded — no concurrent access.
unsafe impl Send for ShmSeqStorage {}
unsafe impl Sync for ShmSeqStorage {}

impl ShmSeqStorage {
    /// Create from a raw pointer to the 16-byte seq region in shared memory.
    ///
    /// # Safety
    /// `ptr` must be valid for the lifetime of this storage and point to
    /// at least 16 writable bytes in a `MAP_SHARED` region.
    pub unsafe fn from_ptr(ptr: *mut u8) -> Self {
        Self { ptr }
    }

    fn has_magic(&self) -> bool {
        let mut magic = [0u8; 4];
        unsafe { core::ptr::copy_nonoverlapping(self.ptr, magic.as_mut_ptr(), 4) };
        magic == SEQ_MAGIC
    }

    fn write_magic(&mut self) {
        unsafe { core::ptr::copy_nonoverlapping(SEQ_MAGIC.as_ptr(), self.ptr, 4) };
    }

    fn peer_count(&self) -> usize {
        let mut count = [0u8; 2];
        unsafe { core::ptr::copy_nonoverlapping(self.ptr.add(SHM_PEER_COUNT_OFFSET), count.as_mut_ptr(), 2) };
        u16::from_be_bytes(count) as usize
    }

    fn set_peer_count(&mut self, count: usize) {
        let bytes = (count as u16).to_be_bytes();
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(SHM_PEER_COUNT_OFFSET), 2) };
    }
}

// Shared memory layout for sequence number storage:
//
// Offset 0:   magic(4)            "SEQ\0"
// Offset 4:   sending(6)          single Sequence Number Sending
// Offset 10:  tool_receiving(6)   Tool access receiving SeqNr (last valid)
// Offset 16:  peer_count(2)       Number of peer entries
// Offset 18:  peer_entries[N]     N entries of: peer_ia(2) + last_valid_seq(6) = 8 bytes each
//
// Max 16 peers → total = 4+6+6+2+(16*8) = 146 bytes.
const SHM_SENDING_OFFSET: usize = 4;
const SHM_TOOL_RECV_OFFSET: usize = 10;
const SHM_PEER_COUNT_OFFSET: usize = 16;
const SHM_PEER_ENTRIES_OFFSET: usize = 18;
const SHM_PEER_ENTRY_SIZE: usize = 8;
const SHM_MAX_PEERS: usize = 16;

impl SequenceNumberStorage for ShmSeqStorage {
    type Error = core::convert::Infallible;

    fn load_sending_seq(&self) -> Result<[u8; 6], Self::Error> {
        if !self.has_magic() {
            return Ok([0, 0, 0, 0, 0, 1]);
        }
        let mut seq = [0u8; 6];
        unsafe {
            core::ptr::copy_nonoverlapping(self.ptr.add(SHM_SENDING_OFFSET), seq.as_mut_ptr(), 6);
        }
        Ok(seq)
    }

    fn save_sending_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.write_magic();
        unsafe {
            core::ptr::copy_nonoverlapping(seq.as_ptr(), self.ptr.add(SHM_SENDING_OFFSET), 6);
        }
        Ok(())
    }

    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error> {
        if !self.has_magic() {
            return Ok(None);
        }
        let count = self.peer_count();
        let ia_bytes = peer_ia.to_be_bytes();
        for i in 0..count {
            let offset = SHM_PEER_ENTRIES_OFFSET + i * SHM_PEER_ENTRY_SIZE;
            let mut entry = [0u8; 8];
            unsafe { core::ptr::copy_nonoverlapping(self.ptr.add(offset), entry.as_mut_ptr(), 8) };
            if entry[0] == ia_bytes[0] && entry[1] == ia_bytes[1] {
                let mut seq = [0u8; 6];
                seq.copy_from_slice(&entry[2..8]);
                return Ok(Some(seq));
            }
        }
        Ok(None)
    }

    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.write_magic();
        let count = self.peer_count();
        let ia_bytes = peer_ia.to_be_bytes();

        // Try to update existing entry.
        for i in 0..count {
            let offset = SHM_PEER_ENTRIES_OFFSET + i * SHM_PEER_ENTRY_SIZE;
            let mut ia = [0u8; 2];
            unsafe { core::ptr::copy_nonoverlapping(self.ptr.add(offset), ia.as_mut_ptr(), 2) };
            if ia == ia_bytes {
                unsafe { core::ptr::copy_nonoverlapping(seq.as_ptr(), self.ptr.add(offset + 2), 6) };
                return Ok(());
            }
        }

        // Append new entry if space available.
        if count < SHM_MAX_PEERS {
            let offset = SHM_PEER_ENTRIES_OFFSET + count * SHM_PEER_ENTRY_SIZE;
            unsafe {
                core::ptr::copy_nonoverlapping(ia_bytes.as_ptr(), self.ptr.add(offset), 2);
                core::ptr::copy_nonoverlapping(seq.as_ptr(), self.ptr.add(offset + 2), 6);
            }
            self.set_peer_count(count + 1);
        }
        Ok(())
    }

    fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, Self::Error> {
        if !self.has_magic() {
            return Ok(None);
        }
        let mut seq = [0u8; 6];
        unsafe { core::ptr::copy_nonoverlapping(self.ptr.add(SHM_TOOL_RECV_OFFSET), seq.as_mut_ptr(), 6) };
        // All-zero means unset (initial state).
        if seq == [0u8; 6] { Ok(None) } else { Ok(Some(seq)) }
    }

    fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.write_magic();
        unsafe { core::ptr::copy_nonoverlapping(seq.as_ptr(), self.ptr.add(SHM_TOOL_RECV_OFFSET), 6) };
        Ok(())
    }
}

/// Static pointer to the seq region in shared memory.
/// Set by `dut_secure.rs` before stack creation.
static SEQ_PTR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

impl HasSequenceStorage for IpcSecureConformanceTestStack {
    type SeqStorage = ShmSeqStorage;

    fn create_seq_storage() -> Self::SeqStorage {
        let ptr = *SEQ_PTR.get().expect("set_seq_shm_ptr() must be called before stack creation");
        unsafe { ShmSeqStorage::from_ptr(ptr as *mut u8) }
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
        { table_sizes::ADT },
        { sec_table_sizes::P2P },
        { sec_table_sizes::SIAT },
        { table_sizes::COT },
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
    pub fn from_device_config(snapshot: SecureConformanceDeviceConfig, seq_storage: ShmSeqStorage) -> Self {
        let identity = StaticSecureIdentity::new(SECURE_SERIAL_NUMBER, SECURE_FDSK);
        let resources = SecureResources { inner: (), seq_storage, fdsk: SECURE_FDSK };
        let inner = SecureInnerState::from_config(identity, snapshot.inner, resources);

        // Seed per-peer receiving sequence numbers from SIAT entries into
        // the wear-resistant storage. This ensures that seqnrs written by
        // ETS during configuration are available for runtime validation.
        let ext = inner.extension_state();
        ext.security.seed_receiving_seqs(&mut *ext.seq_storage.borrow_mut());

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
