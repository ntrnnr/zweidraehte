//! Secure DUT stack definition for Data Security conformance tests.
//!
//! Mirrors the non-secure [`ConformanceState`] and [`IpcConformanceTestStack`]
//! but uses [`SecureDeviceBuilder`] and [`SecureTp1ExtensionState`] to enable
//! KNX Data Secure support. The Security Interface Object appears at object
//! index 6 (after Device, ADT, AST, COT, APP, PEI).
//!
//! [`ConformanceState`]: super::systemb_stack::ConformanceState
//! [`IpcConformanceTestStack`]: super::systemb_stack::IpcConformanceTestStack

use core::cell::RefCell;

use super::fixture_common::{
    CONFORMANCE_DD2, CONFORMANCE_USER_MANUFACTURER_INFO, CertificationObjectAugment, GetrandomRng, SECURE_FDSK,
    ShmSiatStore, TestParameters, sec_table_sizes,
};
use zweidraehte_device::bcus::system_b::{DiagnosticsAugment, WithSecureGoSend};
use zweidraehte_device::layers::application::services::{PropertyExtValueService, StandardAlServices};
use zweidraehte_device::prelude::*;
use zweidraehte_device::{
    HasExtensionState, HasSecurityMode, StackDefinition,
    bcus::system_b::{
        DeviceConfig, SecureAugmentBundle, SecureExtensionConfig, SecureResources, SecureTp1DeviceState,
        SecureTp1ExtensionState, SystemBDeviceModel, SystemBInterfaceObjectsFor, Tp1Augment, Tp1ExtensionConfig,
        create_system_b_objects,
    },
    context::layer::LayerContext,
    device_model::{DeviceModelEvent, DeviceModelNotifier, DmNotificationSlot},
    layers::secure_application::WithP2p,
    memory::MemoryMap,
    objects::tables::{
        Application, HasAddressTable, HasAssociationTable, HasCommunicationObjectTable, HasLoadStateMachine, LoadEvent,
    },
    restart::EraseCode,
    service::ServiceRegistry,
    storage::HasDeviceConfig,
};
use zweidraehte_proto::AccessContext;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::address::IndividualAddress;

use super::systemb_stack::{
    CONFORMANCE_MEMORY_LAYOUT, ConformanceMemoryMap, LEVEL1_MEMORY_SIZE, LEVEL2_MEMORY_SIZE, LINEAR_MEMORY_SIZE,
    USER_MEMORY_SIZE, comm_objs::ConformanceComObjects, conformance_config, device_info, table_sizes,
};

// ============================================================================
// Security-specific constants
// ============================================================================

/// Serial number for the secure DUT (matches XML: FE ED BA BE CA FE).
pub const SECURE_SERIAL_NUMBER: [u8; 6] = [0xFE, 0xED, 0xBA, 0xBE, 0xCA, 0xFE];

// ============================================================================
// Secure Inner State Type
// ============================================================================

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
zweidraehte_device::forward_device_state_traits!(impl SecureConformanceState => self.inner: SecureInnerState);

// ============================================================================
// Random byte source for KNX Data Secure (plugs into `StackDefinition::Rng`)
// ============================================================================
//
// The Secure Application Layer pulls randomness through
// `<D::Rng as Rng>::fill` rather than from the state type, so firmware
// can provide an RNG without a state newtype. The conformance DUT runs
// under Linux, so a libc `getrandom` call is both cheapest and strongest.

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
    Loaded { config: SystemBSecureDutConfig },
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
    type CO = super::systemb_stack::comm_objs::ConformanceComObjects;
    type LLB = super::ipc::IpcLinkLayerBuilder;
    type ES =
        SecureTp1ExtensionState<{ table_sizes::ADT_ENTRIES }, { sec_table_sizes::P2P }, { table_sizes::COT_ENTRIES }>;
    // The stores struct (here: just the shared-memory SIAT store), wired onto
    // the LayerContext so the secure layers pull it out through
    // `HasSeqStore`.
    type Storage = &'static super::fixture_common::DutSecureStorage<Self>;
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
// `super::systemb_stack`, differing only in the inner state type the erase-code
// dispatch targets.

impl crate::dut_common::ConformanceStack for IpcSecureConformanceTestStack {
    type DeviceConfig = SystemBSecureDutConfig;

    fn to_device_config(state: &Self::State) -> Self::DeviceConfig {
        state.to_device_config()
    }

    fn apply_erase_code(state: &Self::State, code: EraseCode) {
        crate::dut_common::apply_erase_code_to_system_b(state.inner(), code);
    }
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
pub struct SystemBSecureDutConfig {
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

impl SystemBSecureDutConfig {
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
    pub fn from_device_config(snapshot: SystemBSecureDutConfig) -> Self {
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

    pub fn to_device_config(&self) -> SystemBSecureDutConfig {
        SystemBSecureDutConfig {
            inner: self.inner.to_config(),
            linear_memory: *self.linear_memory.borrow(),
            level2_memory: *self.level2_memory.borrow(),
            level1_memory: *self.level1_memory.borrow(),
            user_memory: *self.user_memory.borrow(),
        }
    }
}
