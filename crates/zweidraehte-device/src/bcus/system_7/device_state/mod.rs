//! Unified device state for System 7 devices.
//!
//! This module provides [`System7DeviceState`], the System 7 counterpart
//! of `SystemBDeviceState`. Same responsibilities — runtime state,
//! ETS-loaded tables, dirty tracking, extension state — with the
//! family's structural differences:
//!
//! - **The individual address lives inside the RT8 address table**
//!   (offset 1–2; see [`addr8`](crate::objects::tables::addr8)). The
//!   `StackState` accessors delegate there, so the service path and the
//!   download path share one storage, as on real BIM M112 hardware.
//! - **16 access levels**: keys for levels 0–14, level 15 is free
//!   access (06 Profiles v02.02.01 §4.2 row 12).
//! - **Application Program 2 instead of a PEI program** at interface
//!   object index 4. It fills `HasPeiApplication`'s structural role (a
//!   second load/run state machine) — the wire-visible object type is
//!   decided by the interface-object container, not by this trait
//!   choice.
//! - **A RAM window** backing the profile's "resources from 0700h"
//!   region, served via `A_Memory_*` by the System 7 memory map.

use core::cell::{Cell, RefCell};

use subtle::ConstantTimeEq;

use crate::{
    HasAuthorization, HasPersistence, StackDefinition, StackState,
    device_model::{DeviceModelEvent, DeviceModelNotifier, DmNotificationSlot},
    extension::ExtensionState,
    objects::{
        comm::{ComObjects, HasCommObjects, HasGoSecurityView},
        interface::{HasMaxRetryCount, HasRoutingCount},
        tables::{
            AbsoluteAlloc, HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable,
            HasLoadStateMachine, HasPeiApplication, Table, addr8::AddrTab8Impl, app::Application, asso8::AssoTab8Impl,
            co_m112::CoTabM112Impl,
        },
    },
    restart::EraseCode,
};
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::{AccessContext, HasConnectionAuth};

use crate::storage::HasDeviceConfig;
use crate::{HasDiagnosticsContext, HasExtensionState, HasSecurityMode};

use super::{SYSTEM7_MAX_ACCESS_LEVELS, SYSTEM7_NUM_AUTH_KEYS, System7DeviceConfig, System7StateInit};
use crate::bcus::system_b::OperationModeState;

/// Size of the RAM window at 0700h.
///
/// The spec fixes only the base ("resources from 0700h",
/// 06 Profiles v02.02.01 §4.2.9); the extent is chip-dependent. 256
/// bytes covers what the certification bench pokes at without carrying
/// dead weight on small targets.
pub const SYSTEM7_RAM_SIZE: usize = 256;

/// Unified device state for System 7 devices.
///
/// # Generic Parameters
///
/// - `ADT_SIZE`: RT8 address table size in bytes (3 + MAX_ADDR * 2)
/// - `AST_SIZE`: RT8 association table size in bytes (1 + MAX_ASSO * 2)
/// - `COT_SIZE`: group object table size in bytes (2 + MAX_CO * 2)
/// - `D`: Stack definition — provides `D::P` (parameters) and `D::CO`
///   (communication objects)
/// - `ES`: Extension state (e.g.
///   [`Tp1ExtensionState`](crate::bcus::system_7::Tp1ExtensionState),
///   `()` for mock scenarios)
pub struct System7DeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D: StackDefinition,
    ES: ExtensionState = (),
    const MAX_CONN: usize = 1,
> {
    // ========================================================================
    // Runtime State
    // ========================================================================
    /// Factory-programmed device identity.
    identity: D::Identity,

    /// Authorization keys for levels 0-14. Level 15 has no key.
    auth_keys: RefCell<[[u8; 4]; SYSTEM7_NUM_AUTH_KEYS]>,

    /// Routing count (hop count) for outgoing messages.
    routing_count: Cell<u8>,

    /// Programming mode flag (volatile — does not survive restarts).
    ///
    /// Exposed both as `PID_PROGMODE` and as bit 0 of the memory byte at
    /// 0060h (Resources §4.26.3) by the memory map.
    programming_mode: Cell<bool>,

    /// OptionReg (Resources §4.25), exposed at memory 0100h.
    option_reg: Cell<u8>,

    /// Runtime maximum APDU length (PID 56); see
    /// `SystemBDeviceState::max_apdu_length` for the clamping contract.
    max_apdu_length: Cell<u16>,

    /// RAM window backing the "resources from 0700h" region. Volatile,
    /// never persisted — cleared on every boot like real RAM.
    pub ram: RefCell<[u8; SYSTEM7_RAM_SIZE]>,

    // ========================================================================
    // ETS-Loaded Tables
    // ========================================================================
    /// RT8 address table, fixed at 4000h. **Also holds the device's
    /// individual address** at offset 1–2.
    pub adt: RefCell<Table<AddrTab8Impl<ADT_SIZE>, AbsoluteAlloc>>,

    /// RT8 association table, located via `PID_TABLE_REFERENCE`.
    pub ast: RefCell<Table<AssoTab8Impl<AST_SIZE>, AbsoluteAlloc>>,

    /// Group object table (CO type + flags). Internal — no interface
    /// object exposes it; ETS writes it inside the application segment.
    pub cot: RefCell<Table<CoTabM112Impl<COT_SIZE>, AbsoluteAlloc>>,

    /// Application program (interface object index 3).
    pub app: RefCell<Application<D::P, AbsoluteAlloc>>,

    /// Application Program 2 (interface object index 4). Same object
    /// type as the application, no parameters of its own.
    pub app2: RefCell<Application<(), AbsoluteAlloc>>,

    /// Application program version (written by ETS).
    pub program_version: RefCell<[u8; 5]>,

    /// Application Program 2 version (written by ETS).
    pub program2_version: RefCell<[u8; 5]>,

    // ========================================================================
    // Communication Objects
    // ========================================================================
    /// Group object values and runtime status.
    pub comm_objs: RefCell<D::CO>,

    // ========================================================================
    // Diagnostics
    // ========================================================================
    /// Operation mode state for diagnostic mode support.
    pub operation_mode: OperationModeState,

    // ========================================================================
    // Extension State
    // ========================================================================
    /// Extension state: link-layer config and/or augment state.
    extension_state: ES,

    // ========================================================================
    // Access Control
    // ========================================================================
    /// Per-connection access levels. Not persisted — reset on each
    /// connection open.
    access_store: zweidraehte_proto::ConnectionAuthLevels<MAX_CONN>,

    // ========================================================================
    // Dirty Tracking
    // ========================================================================
    /// Dirty flag indicating unsaved changes.
    dirty: Cell<bool>,

    // ========================================================================
    // DeviceModel Notification
    // ========================================================================
    /// Single-slot notification buffer for [`DeviceModelEvent`]s.
    dm_slot: DmNotificationSlot,
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D: StackDefinition,
    ES: ExtensionState,
    const MAX_CONN: usize,
> System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES, MAX_CONN>
{
    /// Create new device state with factory defaults.
    ///
    /// - Individual address: 15.15.255, seeded into the address table's
    ///   IA slot (`FF FF`, matching erased EEPROM on real silicon)
    /// - Auth keys: all 15 set to `[0xFF; 4]` (default key)
    /// - Routing count: 6 (default per KNX spec)
    /// - All tables: Unloaded
    pub fn new(identity: D::Identity, comm_objs: D::CO, extension_resources: ES::Resources) -> Self {
        let extension_state = ES::from_config(ES::Config::default(), extension_resources);
        let mut adt = Table::new();
        adt.set_individual_address(IndividualAddress::new(15, 15, 255));
        Self {
            identity,
            auth_keys: RefCell::new([[0xFF; 4]; SYSTEM7_NUM_AUTH_KEYS]),
            routing_count: Cell::new(6),
            programming_mode: Cell::new(false),
            option_reg: Cell::new(0),
            max_apdu_length: Cell::new(D::MAX_APDU_LENGTH),
            ram: RefCell::new([0; SYSTEM7_RAM_SIZE]),
            adt: RefCell::new(adt),
            ast: RefCell::new(Table::new()),
            cot: RefCell::new(Table::new()),
            app: RefCell::new(Application::new()),
            app2: RefCell::new(Application::new()),
            program_version: RefCell::new([0; 5]),
            program2_version: RefCell::new([0; 5]),
            comm_objs: RefCell::new(comm_objs),
            operation_mode: OperationModeState::new(),
            extension_state,
            access_store: zweidraehte_proto::ConnectionAuthLevels::new(),
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

    /// Get the OptionReg value (memory 0100h).
    pub fn option_reg(&self) -> u8 {
        self.option_reg.get()
    }

    /// Set the OptionReg value (memory 0100h).
    pub fn set_option_reg(&self, value: u8) {
        self.option_reg.set(value);
        self.mark_dirty();
    }

    /// Check if all tables are loaded.
    pub fn all_loaded(&self) -> bool {
        self.adt.borrow().is_loaded()
            && self.ast.borrow().is_loaded()
            && self.cot.borrow().is_loaded()
            && self.app.borrow().is_loaded()
    }

    // ========================================================================
    // Reset Methods (erase-code handling for restart requests)
    // ========================================================================

    /// Reset individual address to factory default (15.15.255) — written
    /// into the address table's IA slot.
    pub fn reset_individual_address(&self) {
        self.adt.borrow_mut().set_individual_address(IndividualAddress::new(15, 15, 255));
        self.mark_dirty();
    }

    /// Reset address table to unloaded state, **preserving the IA slot**.
    ///
    /// `ResetLinks` (03/05/02 §3.7.1.2 Table 4) clears the group
    /// addresses but must not re-address the device; the IA only falls
    /// with `ResetIA` / a factory reset.
    pub fn reset_address_table(&self) {
        let ia = self.adt.borrow().individual_address();
        let mut adt = self.adt.borrow_mut();
        *adt = Table::new();
        adt.set_individual_address(ia);
        drop(adt);
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

    /// Reset parameters to defaults, keeping the application's load state.
    pub fn reset_parameters(&self) {
        use const_default::ConstDefault;
        let mut app = self.app.borrow_mut();
        *app.params_mut() = D::P::DEFAULT;
        self.mark_dirty();
    }

    /// Reset all tables (ADT, AST, COT) to unloaded state. The IA slot
    /// in the address table survives (see
    /// [`reset_address_table`](Self::reset_address_table)).
    pub fn reset_all_tables(&self) {
        self.reset_address_table();
        self.reset_association_table();
        self.reset_group_object_table();
    }

    /// Reset auth keys to factory default (all 0xFF).
    pub fn reset_auth_keys(&self) {
        *self.auth_keys.borrow_mut() = [[0xFF; 4]; SYSTEM7_NUM_AUTH_KEYS];
        self.mark_dirty();
    }

    /// Perform a full factory reset (everything except serial number).
    pub fn factory_reset(&self) {
        self.factory_reset_with(EraseCode::FactoryReset);
    }

    /// Perform factory reset but keep the individual address.
    pub fn factory_reset_keep_ia(&self) {
        let ia = self.adt.borrow().individual_address();
        self.factory_reset_with(EraseCode::FactoryResetKeepIA);
        self.adt.borrow_mut().set_individual_address(ia);
    }

    /// The body both factory resets share, told which erase code it is
    /// acting for so the extension state can honour the per-code rules.
    fn factory_reset_with(&self, code: EraseCode) {
        self.reset_all_tables();
        self.reset_individual_address();
        self.reset_application();
        self.reset_auth_keys();
        self.routing_count.set(6);
        self.programming_mode.set(false);
        self.option_reg.set(0);
        *self.app2.borrow_mut() = Application::new();
        *self.program2_version.borrow_mut() = [0; 5];
        self.extension_state.on_erase(code);
        self.mark_dirty();
    }

    /// Apply an A_Restart master-reset erase code to this state.
    ///
    /// Same per-code dispatch as `SystemBDeviceState::apply_erase_code`.
    pub fn apply_erase_code(&self, code: EraseCode) {
        match code {
            EraseCode::Basic | EraseCode::Confirmed => {}
            EraseCode::FactoryReset => self.factory_reset(),
            EraseCode::ResetIA => self.reset_individual_address(),
            EraseCode::ResetAP => self.reset_application(),
            EraseCode::ResetParam => self.reset_parameters(),
            EraseCode::ResetLinks => {
                self.reset_address_table();
                self.reset_association_table();
                self.extension_state.on_erase(code);
            }
            EraseCode::FactoryResetKeepIA => self.factory_reset_keep_ia(),
            EraseCode::Other(_) => {}
        }
    }
}

// ============================================================================
// HasDeviceConfig / from_config
// ============================================================================

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D: StackDefinition<P: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>>,
    ES: ExtensionState,
    const MAX_CONN: usize,
> HasDeviceConfig for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES, MAX_CONN>
{
    type Config = System7DeviceConfig<ADT_SIZE, AST_SIZE, COT_SIZE, D::P, ES::Config>;

    fn to_config(&self) -> Self::Config {
        System7DeviceConfig {
            version: System7DeviceConfig::<ADT_SIZE, AST_SIZE, COT_SIZE, D::P, ES::Config>::VERSION,
            auth_keys: *self.auth_keys.borrow(),
            routing_count: self.routing_count.get(),
            option_reg: self.option_reg.get(),
            // The IA travels inside the address-table blob.
            address_table: (*self.adt.borrow()).clone(),
            association_table: (*self.ast.borrow()).clone(),
            group_object_table: (*self.cot.borrow()).clone(),
            application: (*self.app.borrow()).clone(),
            application2: (*self.app2.borrow()).clone(),
            program_version: *self.program_version.borrow(),
            program2_version: *self.program2_version.borrow(),
            extension_config: self.extension_state.to_config(),
        }
    }
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D: StackDefinition<P: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>>,
    ES: ExtensionState,
    const MAX_CONN: usize,
> System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES, MAX_CONN>
{
    /// Restore device state from a persisted [`System7DeviceConfig`]
    /// snapshot. Comm objects are runtime-only and created fresh.
    pub fn from_config(
        identity: D::Identity,
        config: System7DeviceConfig<ADT_SIZE, AST_SIZE, COT_SIZE, D::P, ES::Config>,
        extension_resources: ES::Resources,
    ) -> Self {
        let System7DeviceConfig {
            auth_keys,
            routing_count,
            option_reg,
            address_table,
            association_table,
            group_object_table,
            application,
            application2,
            program_version,
            program2_version,
            extension_config,
            version: _,
        } = config;

        Self {
            identity,
            auth_keys: RefCell::new(auth_keys),
            routing_count: Cell::new(routing_count),
            programming_mode: Cell::new(false),
            option_reg: Cell::new(option_reg),
            max_apdu_length: Cell::new(D::MAX_APDU_LENGTH),
            ram: RefCell::new([0; SYSTEM7_RAM_SIZE]),
            adt: RefCell::new(address_table),
            ast: RefCell::new(association_table),
            cot: RefCell::new(group_object_table),
            app: RefCell::new(application),
            app2: RefCell::new(application2),
            program_version: RefCell::new(program_version),
            program2_version: RefCell::new(program2_version),
            comm_objs: RefCell::new(D::CO::new()),
            operation_mode: OperationModeState::new(),
            extension_state: ES::from_config(extension_config, extension_resources),
            access_store: zweidraehte_proto::ConnectionAuthLevels::new(),
            dirty: Cell::new(false),
            dm_slot: DmNotificationSlot::new(),
        }
    }

    /// Build state from a [`System7StateInit`] envelope.
    pub fn from_init(
        init: System7StateInit<
            D::Identity,
            System7DeviceConfig<ADT_SIZE, AST_SIZE, COT_SIZE, D::P, ES::Config>,
            ES::Resources,
        >,
    ) -> Self {
        match init.loaded_config {
            Some(config) => Self::from_config(init.identity, config, init.resources),
            None => Self::new(init.identity, D::CO::new(), init.resources),
        }
    }
}

// ============================================================================
// StackState
// ============================================================================

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D: StackDefinition,
    ES: ExtensionState + HasSecurityMode,
> StackState for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
{
    type Identity = D::Identity;

    fn individual_address(&self) -> IndividualAddress {
        self.adt.borrow().individual_address()
    }

    fn set_individual_address(&self, addr: IndividualAddress) {
        self.adt.borrow_mut().set_individual_address(addr);
        self.mark_dirty();
    }

    fn identity(&self) -> &Self::Identity {
        &self.identity
    }

    fn is_programming_mode(&self) -> bool {
        self.programming_mode.get()
    }

    fn set_programming_mode(&self, enabled: bool) {
        self.programming_mode.set(enabled);
    }

    fn max_apdu_length(&self) -> u16 {
        self.max_apdu_length.get()
    }

    fn set_max_apdu_length(&self, length: u16) {
        self.max_apdu_length.set(length);
    }
}

// ============================================================================
// Capability traits
// ============================================================================

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D: StackDefinition,
    ES: ExtensionState + HasSecurityMode,
> HasSecurityMode for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
{
    fn security_mode_enabled(&self) -> bool {
        self.extension_state.security_mode_enabled()
    }

    fn log_access_denied(&self, source_addr: u16) {
        self.extension_state.log_access_denied(source_addr);
    }

    fn has_group_key(&self, tsap: u16) -> bool {
        self.extension_state.has_group_key(tsap)
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, D: StackDefinition, ES: ExtensionState>
    HasPersistence for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
{
    fn mark_dirty(&self) {
        System7DeviceState::mark_dirty(self);
    }

    fn is_dirty(&self) -> bool {
        System7DeviceState::is_dirty(self)
    }

    fn clear_dirty(&self) {
        System7DeviceState::clear_dirty(self);
    }

    fn apply_erase_code(&self, code: EraseCode) {
        System7DeviceState::apply_erase_code(self, code);
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, D: StackDefinition, ES: ExtensionState>
    HasAuthorization for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
{
    const MAX_ACCESS_LEVELS: u8 = SYSTEM7_MAX_ACCESS_LEVELS as u8;

    fn default_access_level(&self) -> u8 {
        self.authorize(&[0xFF, 0xFF, 0xFF, 0xFF])
    }

    fn authorize(&self, key: &[u8; 4]) -> u8 {
        let keys = self.auth_keys.borrow();
        // Constant-time scan — same rationale as the System B
        // implementation: don't leak which level matched via timing.
        for level in 0..SYSTEM7_NUM_AUTH_KEYS {
            if bool::from(keys[level].ct_eq(key)) {
                return level as u8;
            }
        }
        (SYSTEM7_MAX_ACCESS_LEVELS - 1) as u8
    }

    fn key_write(&self, level: u8, key: &[u8; 4], ctx: AccessContext) -> u8 {
        if level as usize >= SYSTEM7_NUM_AUTH_KEYS {
            return 0xFF;
        }
        if ctx.access_level > level {
            return 0xFF;
        }
        self.auth_keys.borrow_mut()[level as usize] = *key;
        self.mark_dirty();
        level
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, D: StackDefinition, ES: ExtensionState>
    DeviceModelNotifier for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
{
    fn notify(&self, event: DeviceModelEvent) {
        self.dm_slot.notify(event);
    }

    fn take_event(&self) -> Option<DeviceModelEvent> {
        self.dm_slot.take_event()
    }
}

// ============================================================================
// Table Accessor Traits
// ============================================================================

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, D: StackDefinition, ES: ExtensionState>
    HasAddressTable for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
{
    type ADT = Table<AddrTab8Impl<ADT_SIZE>, AbsoluteAlloc>;

    fn adt(&self) -> &RefCell<Self::ADT> {
        &self.adt
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, D: StackDefinition, ES: ExtensionState>
    HasAssociationTable for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
{
    type AST = Table<AssoTab8Impl<AST_SIZE>, AbsoluteAlloc>;

    fn ast(&self) -> &RefCell<Self::AST> {
        &self.ast
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, D: StackDefinition, ES: ExtensionState>
    HasCommunicationObjectTable for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
{
    type COT = Table<CoTabM112Impl<COT_SIZE>, AbsoluteAlloc>;

    fn cot(&self) -> &RefCell<Self::COT> {
        &self.cot
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, D: StackDefinition, ES: ExtensionState>
    HasApplication for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
{
    type APP = Application<D::P, AbsoluteAlloc>;

    fn app(&self) -> &RefCell<Self::APP> {
        &self.app
    }
}

// Application Program 2 fills the "second program object" role the trait
// models; System 7 has no PEI. The interface-object container presents
// it as an ApplicationProgram object at index 4.
impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, D: StackDefinition, ES: ExtensionState>
    HasPeiApplication for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
{
    type PEI = Application<(), AbsoluteAlloc>;

    fn pei(&self) -> &RefCell<Self::PEI> {
        &self.app2
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, D: StackDefinition, ES: ExtensionState>
    HasCommObjects for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
{
    type CO = D::CO;

    fn comm_objects(&self) -> &RefCell<Self::CO> {
        &self.comm_objs
    }
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D: StackDefinition,
    ES: ExtensionState + HasGoSecurityView,
> HasGoSecurityView for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
{
    fn required_security_for_asap(&self, asap: u16) -> zweidraehte_proto::messages::knx::RequiredSecurity {
        self.extension_state.required_security_for_asap(asap)
    }

    fn required_security_for_p2p(&self, peer_ia: u16) -> zweidraehte_proto::messages::knx::RequiredSecurity {
        self.extension_state.required_security_for_p2p(peer_ia)
    }

    fn required_security_for_broadcast(&self) -> zweidraehte_proto::messages::knx::RequiredSecurity {
        self.extension_state.required_security_for_broadcast()
    }

    fn required_security_for_tool_access(&self) -> zweidraehte_proto::messages::knx::RequiredSecurity {
        self.extension_state.required_security_for_tool_access()
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, D: StackDefinition, ES: ExtensionState>
    HasDiagnosticsContext for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
{
    type Diagnostics = OperationModeState;

    fn diagnostics(&self) -> &Self::Diagnostics {
        &self.operation_mode
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, D: StackDefinition, ES: ExtensionState>
    HasRoutingCount for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
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
    D: StackDefinition,
    ES: ExtensionState + HasMaxRetryCount,
> HasMaxRetryCount for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
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
    D: StackDefinition,
    ES: ExtensionState,
    const MAX_CONN: usize,
> HasConnectionAuth for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES, MAX_CONN>
{
    fn connection_access(&self, slot: u8) -> AccessContext {
        self.access_store.get(slot)
    }

    fn set_connection_access(&self, slot: u8, ctx: AccessContext) {
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
    D: StackDefinition,
    ES: ExtensionState,
    const MAX_CONN: usize,
> HasExtensionState for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES, MAX_CONN>
{
    type ES = ES;

    fn extension_state(&self) -> &ES {
        &self.extension_state
    }
}
