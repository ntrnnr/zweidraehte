//! Unified device state for System B devices.
//!
//! This module provides [`SystemBDeviceState`], which combines:
//! - Runtime state (individual address, auth keys)
//! - ETS-loaded tables (ADT, AST, COT, APP)
//! - Configuration (routing count)
//! - Dirty tracking (the binary owns storage separately)
//! - Extension state (IP config, augment state, or `()` for plain TP1)
//!
//! This is the single source of truth for all device state.

use core::cell::{Cell, RefCell};

use const_default::ConstDefault;

use crate::{
    AccessContext, MAX_ACCESS_LEVELS, NUM_AUTH_KEYS, StackState,
    address::IndividualAddress,
    device_model::{DeviceModelEvent, DeviceModelNotifier, DmNotificationSlot},
    objects::{
        interface::{HasDomainAddress, HasMaxRetryCount, HasRoutingCount},
        tables::{
            HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasLoadStateMachine,
            HasPeiApplication, HasRunStateMachine, Table,
            addr7::AddrTab7Impl,
            app::{Application, PeiApplication},
            asso6::AssoTab6Impl,
            co7::CoTab7Impl,
        },
    },
};

use super::{ExtensionState, HasPersistedState, PersistedState};
use crate::storage::DeviceIdentity;

// ============================================================================
// HasExtensionState trait
// ============================================================================

/// Trait for accessing the extension state on a device state.
///
/// This enables context trait impls and other generic code to access
/// the extension state (e.g., `IpExtensionState`) through a trait bound
/// rather than knowing the concrete `SystemBDeviceState` type.
pub trait HasExtensionState {
    /// The extension state type.
    type ES;

    /// Get a reference to the extension state.
    fn extension_state(&self) -> &Self::ES;
}

// ============================================================================
// Unified Device State
// ============================================================================

/// Unified device state for System B devices.
///
/// Combines runtime state, ETS-loaded tables, and link-layer-specific
/// persistent state into a single type that implements both [`StackState`]
/// and the `Has*Table` traits.
///
/// # Contents
///
/// **Runtime State:**
/// - Individual address
/// - Authorization keys (levels 0-2)
/// - Routing count
///
/// **ETS-Loaded Tables:**
/// - Address Table (ADT): Maps TSAP → Group Address
/// - Association Table (AST): Maps TSAP → ASAP
/// - Group Object Table (COT): Communication object type + flags
/// - Application Program (APP): Application data + Load/Run state machines
///
/// **Link-Layer State:**
/// - For KNX/IP devices: IP configuration (friendly name, configured IP, etc.)
/// - For TP1 devices: [`Tp1ExtensionState`] (PID_MAX_RETRY_COUNT)
///
/// # Persistence
///
/// State can be converted to/from [`PersistedState`] for storage.
/// Use [`from_persisted`](Self::from_persisted) to restore from storage,
/// and [`to_persisted`](Self::to_persisted) to prepare for saving.
///
/// # Generic Parameters
///
/// - `ADT_SIZE`: Address table size in bytes (2 + MAX_ADDR * 2)
/// - `AST_SIZE`: Association table size in bytes (2 + MAX_ASSO * 4)
/// - `COT_SIZE`: Group object table size in bytes (2 + MAX_CO * 2)
/// - `P`: Application parameters type
/// - `ES`: Extension state — link-layer config and/or augment state (e.g.,
///   [`IpExtensionState`] for KNX/IP, [`Tp1ExtensionState`] for TP1, `()` for plain TP1)
pub struct SystemBDeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault,
    ES: ExtensionState = (),
    const MAX_CONN: usize = 1,
> {
    // ========================================================================
    // Runtime State
    // ========================================================================
    /// Individual address.
    individual_address: Cell<IndividualAddress>,

    /// Device serial number (6 bytes).
    ///
    /// Factory-programmed, unique per physical device.
    /// Format: 2 bytes manufacturer ID + 4 bytes device-specific.
    serial_number: [u8; 6],

    /// Authorization keys for levels 0-2.
    auth_keys: RefCell<[[u8; 4]; NUM_AUTH_KEYS]>,

    /// Routing count (hop count) for outgoing messages.
    routing_count: Cell<u8>,

    /// Programming mode flag (volatile — does not survive restarts).
    programming_mode: Cell<bool>,

    // ========================================================================
    // ETS-Loaded Tables
    // ========================================================================
    /// Address table (TSAP → Group Address mapping).
    pub adt: RefCell<Table<AddrTab7Impl<ADT_SIZE>>>,

    /// Association table (TSAP → ASAP mapping).
    pub ast: RefCell<Table<AssoTab6Impl<AST_SIZE>>>,

    /// Group object table (CO type + flags).
    pub cot: RefCell<Table<CoTab7Impl<COT_SIZE>>>,

    /// Application program (data + Load/Run state machines).
    pub app: RefCell<Application<P>>,

    /// PEI (Physical External Interface) program (Load/Run state machines).
    ///
    /// Vestigial spec artifact — ETS loads/unloads this during programming, but no
    /// device behavior depends on its state. Intentionally initialized to halted.
    /// See [`PeiApplication`] for details.
    pub pei: RefCell<PeiApplication>,

    /// Application program version (written by ETS).
    pub program_version: RefCell<[u8; 5]>,

    /// PEI program version (written by ETS).
    ///
    /// Always `[0; 5]` on modern devices since no actual PEI program exists.
    pub pei_program_version: RefCell<[u8; 5]>,

    // ========================================================================
    // Extension State
    // ========================================================================
    /// Extension state: link-layer config and/or augment state.
    ///
    /// For KNX/IP devices this is [`IpExtensionState`]. For TP1 devices
    /// this is [`Tp1ExtensionState`] (PID_MAX_RETRY_COUNT is mandatory
    /// on TP1). Defaults to `()` for test/mock scenarios without extensions.
    extension_state: ES,

    // ========================================================================
    // Access Control
    // ========================================================================
    /// Per-connection access levels. Written by the AL (authorize), read by
    /// both AL and TL. Not persisted — resets to `MIN_ACCESS` on each
    /// connection open.
    access_store: crate::ConnectionAuthLevels<MAX_CONN>,

    // ========================================================================
    // Dirty Tracking
    // ========================================================================
    /// Dirty flag indicating unsaved changes.
    ///
    /// Set by `mark_dirty()` whenever persistent state changes.
    /// The binary is responsible for checking `is_dirty()` and saving
    /// state via its own storage backend.
    dirty: Cell<bool>,

    // ========================================================================
    // DeviceModel Notification
    // ========================================================================
    /// Single-slot notification buffer for [`DeviceModelEvent`]s.
    ///
    /// Interface objects post events here during property writes; the
    /// [`DeviceModel`](crate::device_model::DeviceModel) drains them
    /// after each dispatch cycle.
    dm_slot: DmNotificationSlot,
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault,
    ES: ExtensionState,
    const MAX_CONN: usize,
> SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES, MAX_CONN>
{
    /// Create new device state with factory defaults.
    ///
    /// - Individual address: 15.15.255
    /// - Auth keys: All set to `[0xFF, 0xFF, 0xFF, 0xFF]` (default key)
    /// - Routing count: 6 (default per KNX spec)
    /// - All tables: Unloaded
    /// - Extension state: Factory defaults via `ES::from_config(Default::default())`
    ///
    /// # Arguments
    ///
    /// - `identity`: Factory-programmed device identity (serial number, etc.)
    pub fn new(identity: &impl DeviceIdentity) -> Self {
        Self {
            individual_address: Cell::new(IndividualAddress::new(15, 15, 255)),
            serial_number: *identity.serial_number(),
            auth_keys: RefCell::new([[0xFF; 4]; NUM_AUTH_KEYS]),
            routing_count: Cell::new(6),
            programming_mode: Cell::new(false),
            adt: RefCell::new(Table::new()),
            ast: RefCell::new(Table::new()),
            cot: RefCell::new(Table::new()),
            app: RefCell::new(Application::new()),
            pei: RefCell::new(PeiApplication::new()),
            program_version: RefCell::new([0; 5]),
            pei_program_version: RefCell::new([0; 5]),
            access_store: crate::ConnectionAuthLevels::new(),
            extension_state: ES::from_config(ES::Config::default()),
            dirty: Cell::new(false),
            dm_slot: DmNotificationSlot::new(),
        }
    }

    /// Get the extension state (link-layer config and/or augment state).
    pub fn extension_state(&self) -> &ES {
        &self.extension_state
    }

    /// Check if there are unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty.get()
    }

    /// Mark state as dirty (needs save).
    pub fn mark_dirty(&self) {
        self.dirty.set(true);
    }

    /// Clear the dirty flag.
    pub fn clear_dirty(&self) {
        self.dirty.set(false);
    }

    /// Get the current individual address.
    pub fn get_individual_address(&self) -> IndividualAddress {
        self.individual_address.get()
    }

    /// Get a copy of the auth keys.
    pub fn get_auth_keys(&self) -> [[u8; 4]; NUM_AUTH_KEYS] {
        *self.auth_keys.borrow()
    }

    /// Get the routing count.
    pub fn get_routing_count(&self) -> u8 {
        self.routing_count.get()
    }

    /// Set the routing count.
    pub fn set_routing_count(&self, count: u8) {
        self.routing_count.set(count);
        self.mark_dirty();
    }

    /// Check if all tables are loaded.
    pub fn all_loaded(&self) -> bool {
        self.adt.borrow().is_loaded()
            && self.ast.borrow().is_loaded()
            && self.cot.borrow().is_loaded()
            && self.app.borrow().is_loaded()
    }

    /// Check if the application is running.
    pub fn is_running(&self) -> bool {
        self.app.borrow().is_running()
    }

    // ========================================================================
    // Reset Methods (for RestartHandler)
    // ========================================================================

    /// Reset individual address to factory default (15.15.255).
    pub fn reset_individual_address(&self) {
        self.individual_address.set(IndividualAddress::new(15, 15, 255));
        self.mark_dirty();
    }

    /// Reset address table to unloaded state.
    pub fn reset_address_table(&self) {
        *self.adt.borrow_mut() = Table::new();
        self.mark_dirty();
    }

    /// Reset association table to unloaded state.
    pub fn reset_association_table(&self) {
        *self.ast.borrow_mut() = Table::new();
        self.mark_dirty();
    }

    /// Reset group object table to unloaded state.
    pub fn reset_group_object_table(&self) {
        *self.cot.borrow_mut() = Table::new();
        self.mark_dirty();
    }

    /// Reset application program to unloaded state.
    pub fn reset_application(&self) {
        *self.app.borrow_mut() = Application::new();
        *self.program_version.borrow_mut() = [0; 5];
        self.mark_dirty();
    }

    /// Reset parameters to defaults.
    ///
    /// Resets the application parameters to their default values while keeping
    /// the load state of the application program intact.
    pub fn reset_parameters(&self) {
        // Reset application parameters but keep program load state
        let mut app = self.app.borrow_mut();
        *app.params_mut() = P::DEFAULT;
        self.mark_dirty();
    }

    /// Reset all tables (ADT, AST, COT) to unloaded state.
    pub fn reset_all_tables(&self) {
        self.reset_address_table();
        self.reset_association_table();
        self.reset_group_object_table();
    }

    /// Reset auth keys to factory default (all 0xFF).
    pub fn reset_auth_keys(&self) {
        *self.auth_keys.borrow_mut() = [[0xFF; 4]; NUM_AUTH_KEYS];
        self.mark_dirty();
    }

    /// Perform a full factory reset (everything except serial number).
    ///
    /// Also resets the link-layer state to factory defaults.
    pub fn factory_reset(&self) {
        self.reset_individual_address();
        self.reset_all_tables();
        self.reset_application();
        self.reset_auth_keys();
        self.routing_count.set(6); // Default routing count
        self.programming_mode.set(false);
        *self.pei.borrow_mut() = PeiApplication::new();
        *self.pei_program_version.borrow_mut() = [0; 5];
        self.extension_state.factory_reset();
        self.mark_dirty();
    }

    /// Perform factory reset but keep the individual address.
    pub fn factory_reset_keep_ia(&self) {
        let ia = self.individual_address.get();
        self.factory_reset();
        self.individual_address.set(ia);
    }
}

// ============================================================================
// HasPersistedState Implementation
// ============================================================================

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault + Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
    ES: ExtensionState,
    const MAX_CONN: usize,
> HasPersistedState for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES, MAX_CONN>
{
    type Persisted = PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES::Config>;

    fn to_persisted(&self) -> Self::Persisted {
        PersistedState {
            version: PersistedState::<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES::Config>::VERSION,
            individual_address: self.individual_address.get(),
            auth_keys: *self.auth_keys.borrow(),
            routing_count: self.routing_count.get(),
            address_table: (*self.adt.borrow()).clone(),
            association_table: (*self.ast.borrow()).clone(),
            group_object_table: (*self.cot.borrow()).clone(),
            application: (*self.app.borrow()).clone(),
            pei_program: (*self.pei.borrow()).clone(),
            program_version: *self.program_version.borrow(),
            pei_program_version: *self.pei_program_version.borrow(),
            extension_config: self.extension_state.to_config(),
        }
    }

    fn from_persisted(identity: &impl DeviceIdentity, persisted: Self::Persisted) -> Self {
        // Destructure to move extension_config out by value (no Clone needed).
        let PersistedState {
            individual_address,
            auth_keys,
            routing_count,
            address_table,
            association_table,
            group_object_table,
            application,
            pei_program,
            program_version,
            pei_program_version,
            extension_config,
            version: _, // Consumed but unused — migration would check this.
        } = persisted;

        Self {
            individual_address: Cell::new(individual_address),
            serial_number: *identity.serial_number(),
            auth_keys: RefCell::new(auth_keys),
            routing_count: Cell::new(routing_count),
            programming_mode: Cell::new(false),
            adt: RefCell::new(address_table),
            ast: RefCell::new(association_table),
            cot: RefCell::new(group_object_table),
            app: RefCell::new(application),
            pei: RefCell::new(pei_program),
            program_version: RefCell::new(program_version),
            pei_program_version: RefCell::new(pei_program_version),
            access_store: crate::ConnectionAuthLevels::new(),
            extension_state: ES::from_config(extension_config),
            dirty: Cell::new(false),
            dm_slot: DmNotificationSlot::new(),
        }
    }
}

// ============================================================================
// RestartHandler Implementation
// ============================================================================

use crate::restart::{EraseCode, RestartError, RestartHandler};

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, ES: ExtensionState>
    RestartHandler for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES>
{
    fn supports_erase_code(&self, code: EraseCode) -> bool {
        // System B devices support all standard erase codes
        matches!(
            code,
            EraseCode::Basic
                | EraseCode::Confirmed
                | EraseCode::FactoryReset
                | EraseCode::ResetIA
                | EraseCode::ResetAP
                | EraseCode::ResetParam
                | EraseCode::ResetLinks
                | EraseCode::FactoryResetKeepIA
        )
    }

    fn execute_reset(&mut self, code: EraseCode, _channel: u8) -> Result<u16, RestartError> {
        match code {
            EraseCode::Basic | EraseCode::Confirmed => {
                // Just restart, no data reset needed
                Ok(0)
            }
            EraseCode::FactoryReset => {
                self.factory_reset();
                Ok(0)
            }
            EraseCode::ResetIA => {
                self.reset_individual_address();
                Ok(0)
            }
            EraseCode::ResetAP => {
                self.reset_application();
                Ok(0)
            }
            EraseCode::ResetParam => {
                self.reset_parameters();
                Ok(0)
            }
            EraseCode::ResetLinks => {
                self.reset_address_table();
                self.reset_association_table();
                Ok(0)
            }
            EraseCode::FactoryResetKeepIA => {
                self.factory_reset_keep_ia();
                Ok(0)
            }
            EraseCode::Other(_) => Err(RestartError::UnsupportedEraseCode),
        }
    }

    fn flush_storage(&mut self) -> Result<(), RestartError> {
        // Storage flushing is handled by the storage backend
        // The mark_dirty() calls above ensure the dirty flag is set
        // User code should call the storage's flush method
        Ok(())
    }
}

// ============================================================================
// StackState Implementation
// ============================================================================

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, ES: ExtensionState>
    StackState for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES>
{
    fn individual_address(&self) -> IndividualAddress {
        self.individual_address.get()
    }

    fn set_individual_address(&self, addr: IndividualAddress) {
        self.individual_address.set(addr);
        self.mark_dirty();
    }

    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }

    fn max_access_levels(&self) -> u8 {
        MAX_ACCESS_LEVELS as u8
    }

    fn default_access_level(&self) -> u8 {
        self.authorize(&[0xFF, 0xFF, 0xFF, 0xFF])
    }

    fn authorize(&self, key: &[u8; 4]) -> u8 {
        let keys = self.auth_keys.borrow();
        for level in 0..NUM_AUTH_KEYS {
            if &keys[level] == key {
                return level as u8;
            }
        }
        (MAX_ACCESS_LEVELS - 1) as u8
    }

    fn key_write(&self, level: u8, key: &[u8; 4], ctx: AccessContext) -> u8 {
        if level as usize >= NUM_AUTH_KEYS {
            return 0xFF;
        }
        if ctx.access_level > level {
            return 0xFF;
        }
        self.auth_keys.borrow_mut()[level as usize] = *key;
        self.mark_dirty();
        level
    }

    fn is_programming_mode(&self) -> bool {
        self.programming_mode.get()
    }

    fn set_programming_mode(&self, enabled: bool) {
        self.programming_mode.set(enabled);
    }

    fn mark_dirty(&self) {
        SystemBDeviceState::mark_dirty(self);
    }

    fn set_link_layer_capabilities(&self, capabilities: u16) {
        self.extension_state.set_link_layer_capabilities(capabilities);
    }
}

// ============================================================================
// DeviceModelNotifier Implementation
// ============================================================================

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, ES: ExtensionState>
    DeviceModelNotifier for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES>
{
    fn notify(&self, event: DeviceModelEvent) {
        self.dm_slot.notify(event);
    }

    fn take_event(&self) -> Option<DeviceModelEvent> {
        self.dm_slot.take_event()
    }
}

// ============================================================================
// Table Accessor Trait Implementations
// ============================================================================

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, ES: ExtensionState>
    HasAddressTable for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES>
{
    type ADT = Table<AddrTab7Impl<ADT_SIZE>>;

    fn adt(&self) -> &RefCell<Self::ADT> {
        &self.adt
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, ES: ExtensionState>
    HasAssociationTable for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES>
{
    type AST = Table<AssoTab6Impl<AST_SIZE>>;

    fn ast(&self) -> &RefCell<Self::AST> {
        &self.ast
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, ES: ExtensionState>
    HasCommunicationObjectTable for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES>
{
    type COT = Table<CoTab7Impl<COT_SIZE>>;

    fn cot(&self) -> &RefCell<Self::COT> {
        &self.cot
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, ES: ExtensionState>
    HasApplication for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES>
{
    type APP = Application<P>;

    fn app(&self) -> &RefCell<Self::APP> {
        &self.app
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, ES: ExtensionState>
    HasPeiApplication for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES>
{
    type PEI = PeiApplication;

    fn pei(&self) -> &RefCell<Self::PEI> {
        &self.pei
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, ES: ExtensionState>
    HasRoutingCount for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES>
{
    fn routing_count(&self) -> u8 {
        self.routing_count.get()
    }

    fn set_routing_count(&self, value: u8) {
        self.routing_count.set(value);
        self.mark_dirty();
    }
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault,
    ES: ExtensionState + HasMaxRetryCount,
> HasMaxRetryCount for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES>
{
    fn max_retry_count(&self) -> u8 {
        self.extension_state.max_retry_count()
    }

    fn set_max_retry_count(&self, value: u8) {
        self.extension_state.set_max_retry_count(value);
        self.mark_dirty();
    }
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault,
    ES: ExtensionState + HasDomainAddress,
> HasDomainAddress for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES>
{
    const DOMAIN_ADDRESS_LENGTH: usize = ES::DOMAIN_ADDRESS_LENGTH;

    fn domain_address(&self, buf: &mut [u8]) {
        self.extension_state.domain_address(buf);
    }

    fn set_domain_address(&self, addr: &[u8]) {
        self.extension_state.set_domain_address(addr);
        self.mark_dirty();
    }
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault,
    ES: ExtensionState,
    const MAX_CONN: usize,
> crate::HasConnectionAuth for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES, MAX_CONN>
{
    fn connection_access(&self, slot: u8) -> crate::AccessContext {
        self.access_store.get(slot)
    }

    fn set_connection_access(&self, slot: u8, ctx: crate::AccessContext) {
        self.access_store.set(slot, ctx);
    }

    fn reset_connection_access(&self, slot: u8, default_level: u8) {
        self.access_store.reset(slot, default_level);
    }
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault,
    ES: ExtensionState,
    const MAX_CONN: usize,
> HasExtensionState for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, ES, MAX_CONN>
{
    type ES = ES;

    fn extension_state(&self) -> &ES {
        &self.extension_state
    }
}
