//! Secure DUT stack definition for Data Security conformance tests.
//!
//! Mirrors the non-secure [`ConformanceState`] and [`IpcConformanceTestStack`]
//! but uses [`SecureDeviceBuilder`] and [`SecureTp1ExtensionState`] to enable
//! KNX Data Secure support. The Security Interface Object appears at object
//! index 6 (after Device, ADT, AST, COT, APP, PEI).
//!
//! [`ConformanceState`]: super::stack::ConformanceState
//! [`IpcConformanceTestStack`]: super::stack::IpcConformanceTestStack

use core::cell::RefCell;

use zweidraehte_device::prelude::*;
use zweidraehte_device::{
    AccessContext, HasConnectionAuth,
    address::IndividualAddress,
    bcus::system_b::{
        HasExtensionState, HasPersistedState, PersistedState, SecureExtensionConfig, SecureTp1DeviceState,
        SecureTp1ExtensionState, Tp1ExtensionConfig,
    },
    device_model::{DeviceModelEvent, DeviceModelNotifier, DmNotificationSlot},
    memory::MemoryMap,
    objects::interface::HasRoutingCount,
    objects::tables::{
        Application, HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable,
        HasPeiApplication,
    },
    storage::StaticIdentity,
};

use super::stack::{
    CONFORMANCE_DD2, CONFORMANCE_MEMORY_LAYOUT, CONFORMANCE_USER_MANUFACTURER_INFO, ConformanceMemoryMap,
    LEVEL1_MEMORY_SIZE, LEVEL2_MEMORY_SIZE, LINEAR_MEMORY_SIZE, TestParameters, USER_MEMORY_SIZE, conformance_config,
    device_info, table_sizes,
};

// ============================================================================
// Security-specific constants
// ============================================================================

/// Security table sizes for const generics.
pub mod sec_table_sizes {
    /// Max group key entries (covers all 11 group addresses + headroom).
    pub const GRP: usize = 16;
    /// Max GO security flag entries (covers all 11 comm objects + headroom).
    pub const GO: usize = 16;
}

/// Serial number for the secure DUT (matches XML: FE ED BA BE CA FE).
pub const SECURE_SERIAL_NUMBER: [u8; 6] = [0xFE, 0xED, 0xBA, 0xBE, 0xCA, 0xFE];

/// Factory Default Setup Key for the secure DUT.
/// Uses the same key as KNX spec Annex C examples for easy validation.
pub const SECURE_FDSK: [u8; 16] =
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

// ============================================================================
// Secure Inner State Type
// ============================================================================

type SecureInnerState = SecureTp1DeviceState<
    { table_sizes::ADT },
    { table_sizes::AST },
    { table_sizes::COT },
    TestParameters,
    { sec_table_sizes::GRP },
    { sec_table_sizes::GO },
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
        let identity = StaticIdentity::with_fdsk(SECURE_SERIAL_NUMBER, SECURE_FDSK);
        let inner = SecureInnerState::new(&identity);

        // Set the secure conformance test individual address (1.1.1 = 0x1101).
        inner.set_individual_address(IndividualAddress::new(1, 1, 1));

        // Store the FDSK in the security extension state so that the S-AL
        // can use it as the effective tool key before TK1 is commissioned.
        inner.extension_state().security.set_fdsk(Some(SECURE_FDSK));

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

impl Default for SecureConformanceState {
    fn default() -> Self {
        use zweidraehte_device::objects::tables::Table;
        Self::new(Table::new(), Table::new(), Table::new(), Application::new())
    }
}

// ============================================================================
// StackState Forwarding
// ============================================================================

impl StackState for SecureConformanceState {
    fn individual_address(&self) -> IndividualAddress {
        self.inner.individual_address()
    }
    fn set_individual_address(&self, addr: IndividualAddress) {
        self.inner.set_individual_address(addr);
    }
    fn serial_number(&self) -> &[u8; 6] {
        self.inner.serial_number()
    }
    fn max_apdu_length(&self) -> u16 {
        device_info::MAX_APDU_LENGTH
    }
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
    fn is_programming_mode(&self) -> bool {
        self.inner.is_programming_mode()
    }
    fn set_programming_mode(&self, enabled: bool) {
        self.inner.set_programming_mode(enabled);
    }
    fn mark_dirty(&self) {
        self.inner.mark_dirty();
    }
    fn security_mode_enabled(&self) -> bool {
        self.inner.security_mode_enabled()
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

        Err(MemoryError::NotAccessible)
    }
}

// ============================================================================
// Stack Definition
// ============================================================================

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
    type ES = SecureTp1ExtensionState<{ sec_table_sizes::GRP }, { sec_table_sizes::GO }>;
    type State = SecureConformanceState;
    type Mem = ConformanceMemoryMap;

    type InterfaceObjects<'a> = zweidraehte_device::bcus::system_b::SystemBInterfaceObjectsFor<'a, Self>;

    fn create_interface_objects<'a>(state: &'a Self::State, platform: &'a Self::Platform) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
    {
        zweidraehte_device::bcus::system_b::create_system_b_objects_from_extension::<Self>(
            state,
            platform,
            &CONFORMANCE_MEMORY_LAYOUT,
        )
    }

    type AlExtension = zweidraehte_device::layers::al_ext_property_ext::PropertyExtValueExtension;
    type LayerBuilder = SecureDeviceBuilder;
}

// ============================================================================
// Shared Memory Persistence
// ============================================================================

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Persisted state type for the secure inner state.
type SecureInnerPersistedState = PersistedState<
    { table_sizes::ADT },
    { table_sizes::AST },
    { table_sizes::COT },
    TestParameters,
    SecureExtensionConfig<Tp1ExtensionConfig>,
>;

/// Full snapshot for the secure conformance DUT.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SecureConformancePersistedState {
    pub inner: SecureInnerPersistedState,
    #[serde_as(as = "[_; LINEAR_MEMORY_SIZE]")]
    pub linear_memory: [u8; LINEAR_MEMORY_SIZE],
    #[serde_as(as = "[_; LEVEL2_MEMORY_SIZE]")]
    pub level2_memory: [u8; LEVEL2_MEMORY_SIZE],
    #[serde_as(as = "[_; LEVEL1_MEMORY_SIZE]")]
    pub level1_memory: [u8; LEVEL1_MEMORY_SIZE],
    #[serde_as(as = "[_; USER_MEMORY_SIZE]")]
    pub user_memory: [u8; USER_MEMORY_SIZE],
}

impl SecureConformanceState {
    pub fn from_persisted_snapshot(snapshot: SecureConformancePersistedState) -> Self {
        let identity = StaticIdentity::with_fdsk(SECURE_SERIAL_NUMBER, SECURE_FDSK);
        let inner = SecureInnerState::from_persisted(&identity, snapshot.inner);

        // FDSK is not persisted — set it from the static identity.
        inner.extension_state().security.set_fdsk(Some(SECURE_FDSK));

        Self {
            inner,
            linear_memory: RefCell::new(snapshot.linear_memory),
            level2_memory: RefCell::new(snapshot.level2_memory),
            level1_memory: RefCell::new(snapshot.level1_memory),
            user_memory: RefCell::new(snapshot.user_memory),
            dm_slot: DmNotificationSlot::new(),
        }
    }

    pub fn to_persisted_snapshot(&self) -> SecureConformancePersistedState {
        SecureConformancePersistedState {
            inner: self.inner.to_persisted(),
            linear_memory: *self.linear_memory.borrow(),
            level2_memory: *self.level2_memory.borrow(),
            level1_memory: *self.level1_memory.borrow(),
            user_memory: *self.user_memory.borrow(),
        }
    }
}
