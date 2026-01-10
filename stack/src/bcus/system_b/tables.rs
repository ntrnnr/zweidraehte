//! Persistent state container for System B devices.
//!
//! This module provides [`SystemBState`], a container for all the persistent
//! state required by a System B device, including tables and configuration.

use core::cell::RefCell;

use const_default::ConstDefault;

use crate::{
    address::IndividualAddress,
    memory::{HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasRoutingCount},
    objects::tables::{
        LoadableTable, RunnableTable, Table, addr7::AddrTab7Impl, app::Application, asso6::AssoTab6Impl,
        co7::CoTab7Impl,
    },
};

use super::{PersistedIpConfig, PersistedState};

/// Persistent state container for System B devices.
///
/// Contains all state that must survive power cycles:
///
/// ## Tables
/// - Address Table (ADT): Maps TSAP → Group Address
/// - Association Table (AST): Maps TSAP → ASAP
/// - Group Object Table (COT): Communication object type + flags
/// - Application Program (APP): Application data + Load/Run state machines
///
/// ## Configuration
/// - Individual address
/// - Authorization keys (levels 0-2)
/// - IP configuration (for 57B0 devices)
///
/// # Persistence
///
/// State can be converted to/from [`PersistedState`] for storage.
/// Use [`from_persisted`](Self::from_persisted) to restore from storage,
/// and [`to_persisted`](Self::to_persisted) to prepare for saving.
///
/// # Generic Parameters
///
/// The size parameters are the actual byte sizes (not entry counts):
/// - `ADT_SIZE`: Address table size in bytes (2 + MAX_ADDR * 2)
/// - `AST_SIZE`: Association table size in bytes (2 + MAX_ASSO * 4)
/// - `COT_SIZE`: Group object table size in bytes (2 + MAX_CO * 2)
/// - `P`: Application parameters type (stored in application table)
///
/// Use [`SystemBDeviceExt::ADT_SIZE`](super::SystemBDeviceExt) etc. to compute
/// sizes from entry counts.
pub struct SystemBState<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault = ()> {
    // ========================================================================
    // Configuration (persisted)
    // ========================================================================
    /// Device individual address.
    pub individual_address: IndividualAddress,

    /// Authorization keys for levels 0-2.
    /// Level 3 has no key (it's the fallback when no key matches).
    pub auth_keys: [[u8; 4]; 3],

    /// Routing count (hop count) for outgoing messages.
    /// Value 0-7, default is 6 per KNX specification.
    pub routing_count: u8,

    /// IP-specific configuration (only for 57B0 devices).
    pub ip_config: Option<PersistedIpConfig>,

    // ========================================================================
    // Tables (persisted)
    // ========================================================================
    /// Address table (TSAP → Group Address mapping).
    pub adt: RefCell<Table<AddrTab7Impl<ADT_SIZE>>>,

    /// Association table (TSAP → ASAP mapping).
    pub ast: RefCell<Table<AssoTab6Impl<AST_SIZE>>>,

    /// Group object table (CO type + flags).
    pub cot: RefCell<Table<CoTab7Impl<COT_SIZE>>>,

    /// Application program (data + Load/Run state machines).
    pub app: RefCell<Application<P>>,
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault>
    SystemBState<ADT_SIZE, AST_SIZE, COT_SIZE, P>
{
    /// Create new state with factory defaults.
    ///
    /// - Individual address: 15.15.255 (unassigned)
    /// - Auth keys: All default (0xFFFFFFFF)
    /// - Tables: Unloaded
    pub fn new() -> Self {
        Self {
            individual_address: IndividualAddress::new(15, 15, 255),
            auth_keys: [[0xFF; 4]; 3],
            routing_count: 6,
            ip_config: None,
            adt: RefCell::new(Table::new()),
            ast: RefCell::new(Table::new()),
            cot: RefCell::new(Table::new()),
            app: RefCell::new(Application::new()),
        }
    }

    /// Create new state with factory defaults and IP configuration.
    ///
    /// Same as [`new`](Self::new) but initializes IP config with defaults.
    pub fn new_ip() -> Self {
        Self { ip_config: Some(PersistedIpConfig::default()), ..Self::new() }
    }

    /// Create state from persisted storage.
    ///
    /// Restores all configuration and table data from storage.
    /// The application's run state is always set to `Halted` - it must
    /// be explicitly restarted after boot.
    pub fn from_persisted(persisted: PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, P>) -> Self {
        Self {
            individual_address: persisted.individual_address,
            auth_keys: persisted.auth_keys,
            routing_count: persisted.routing_count,
            ip_config: persisted.ip_config,
            adt: RefCell::new(persisted.address_table),
            ast: RefCell::new(persisted.association_table),
            cot: RefCell::new(persisted.group_object_table),
            app: RefCell::new(persisted.application),
        }
    }

    /// Export state to persisted format for storage.
    ///
    /// Clones the current state for persistence.
    pub fn to_persisted(&self) -> PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, P>
    where
        P: Clone,
    {
        PersistedState {
            version: PersistedState::<ADT_SIZE, AST_SIZE, COT_SIZE, P>::VERSION,
            individual_address: self.individual_address,
            auth_keys: self.auth_keys,
            routing_count: self.routing_count,
            address_table: (*self.adt.borrow()).clone(),
            association_table: (*self.ast.borrow()).clone(),
            group_object_table: (*self.cot.borrow()).clone(),
            application: (*self.app.borrow()).clone(),
            ip_config: self.ip_config.clone(),
        }
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
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault> Default
    for SystemBState<ADT_SIZE, AST_SIZE, COT_SIZE, P>
{
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Trait Implementations for Stack Integration
// ============================================================================

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault> HasAddressTable
    for SystemBState<ADT_SIZE, AST_SIZE, COT_SIZE, P>
{
    type ADT = Table<AddrTab7Impl<ADT_SIZE>>;

    fn adt(&self) -> &RefCell<Self::ADT> {
        &self.adt
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault> HasAssociationTable
    for SystemBState<ADT_SIZE, AST_SIZE, COT_SIZE, P>
{
    type AST = Table<AssoTab6Impl<AST_SIZE>>;

    fn ast(&self) -> &RefCell<Self::AST> {
        &self.ast
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault> HasCommunicationObjectTable
    for SystemBState<ADT_SIZE, AST_SIZE, COT_SIZE, P>
{
    type COT = Table<CoTab7Impl<COT_SIZE>>;

    fn cot(&self) -> &RefCell<Self::COT> {
        &self.cot
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault> HasApplication
    for SystemBState<ADT_SIZE, AST_SIZE, COT_SIZE, P>
{
    type APP = Application<P>;

    fn app(&self) -> &RefCell<Self::APP> {
        &self.app
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault> HasRoutingCount
    for SystemBState<ADT_SIZE, AST_SIZE, COT_SIZE, P>
{
    fn routing_count(&self) -> u8 {
        self.routing_count
    }
}

