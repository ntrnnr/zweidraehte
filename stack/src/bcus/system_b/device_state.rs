//! Unified device state for System B devices.
//!
//! This module provides [`SystemBDeviceState`], which combines:
//! - Runtime state (individual address, auth keys)
//! - ETS-loaded tables (ADT, AST, COT, APP)
//! - Configuration (routing count)
//! - Storage management (dirty tracking, persistence)
//!
//! This is the single source of truth for all device state.

use core::cell::{Cell, RefCell};
use core::marker::PhantomData;
use core::net::Ipv4Addr;

use const_default::ConstDefault;

use crate::{
    IpPlatform, IpStackState, MAX_ACCESS_LEVELS, NUM_AUTH_KEYS, StackState,
    address::IndividualAddress,
    memory::{HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasRoutingCount},
    objects::tables::{
        HasLoadStateMachine, HasRunStateMachine, Table, addr7::AddrTab7Impl, app::Application, asso6::AssoTab6Impl,
        co7::CoTab7Impl,
    },
};

use super::{DeviceStorage, KnxIpDevice, PersistedIpConfig, PersistedState, SystemBDevice};

/// Unified device state for System B devices.
///
/// Combines runtime state and ETS-loaded tables into a single type that
/// implements both [`StackState`] and the `Has*Table` traits.
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
/// - `D`: Device type implementing [`SystemBDevice`]
pub struct SystemBDeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault,
    D: SystemBDevice,
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

    // ========================================================================
    // Storage Management
    // ========================================================================
    /// Storage backend for persistence.
    storage: RefCell<D::Storage>,

    /// Dirty flag indicating unsaved changes.
    dirty: Cell<bool>,

    _phantom: PhantomData<D>,
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: SystemBDevice>
    SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
{
    /// Create new device state with factory defaults.
    ///
    /// - Individual address: 15.15.255
    /// - Auth keys: All set to `[0xFF, 0xFF, 0xFF, 0xFF]` (default key)
    /// - Routing count: 6 (default per KNX spec)
    /// - All tables: Unloaded
    ///
    /// # Arguments
    ///
    /// - `storage`: Storage backend for persistence
    /// - `serial_number`: Factory-programmed serial number (6 bytes)
    pub fn new(storage: D::Storage, serial_number: [u8; 6]) -> Self {
        Self {
            individual_address: Cell::new(IndividualAddress::new(15, 15, 255)),
            serial_number,
            auth_keys: RefCell::new([[0xFF; 4]; NUM_AUTH_KEYS]),
            routing_count: Cell::new(6),
            adt: RefCell::new(Table::new()),
            ast: RefCell::new(Table::new()),
            cot: RefCell::new(Table::new()),
            app: RefCell::new(Application::new()),
            storage: RefCell::new(storage),
            dirty: Cell::new(false),
            _phantom: PhantomData,
        }
    }

    /// Create device state from persisted storage.
    ///
    /// Restores all state and table data from storage.
    /// The application's run state is always set to `Halted` - it must
    /// be explicitly restarted after boot.
    ///
    /// # Arguments
    ///
    /// - `storage`: Storage backend for persistence
    /// - `serial_number`: Factory-programmed serial number (6 bytes)
    /// - `persisted`: Previously persisted state to restore
    pub fn from_persisted(
        storage: D::Storage,
        serial_number: [u8; 6],
        persisted: PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, P>,
    ) -> Self {
        Self {
            individual_address: Cell::new(persisted.individual_address),
            serial_number,
            auth_keys: RefCell::new(persisted.auth_keys),
            routing_count: Cell::new(persisted.routing_count),
            adt: RefCell::new(persisted.address_table),
            ast: RefCell::new(persisted.association_table),
            cot: RefCell::new(persisted.group_object_table),
            app: RefCell::new(persisted.application),
            storage: RefCell::new(storage),
            dirty: Cell::new(false),
            _phantom: PhantomData,
        }
    }

    /// Export state to persisted format for storage.
    pub fn to_persisted(&self, ip_config: Option<PersistedIpConfig>) -> PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, P>
    where
        P: Clone,
    {
        PersistedState {
            version: PersistedState::<ADT_SIZE, AST_SIZE, COT_SIZE, P>::VERSION,
            individual_address: self.individual_address.get(),
            auth_keys: *self.auth_keys.borrow(),
            routing_count: self.routing_count.get(),
            address_table: (*self.adt.borrow()).clone(),
            association_table: (*self.ast.borrow()).clone(),
            group_object_table: (*self.cot.borrow()).clone(),
            application: (*self.app.borrow()).clone(),
            ip_config,
        }
    }

    /// Check if there are unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty.get()
    }

    /// Mark state as dirty (needs save).
    pub fn mark_dirty(&self) {
        self.dirty.set(true);
        self.storage.borrow_mut().mark_dirty();
    }

    /// Clear the dirty flag.
    pub fn clear_dirty(&self) {
        self.dirty.set(false);
    }

    /// Get a reference to the storage backend.
    pub fn storage(&self) -> &RefCell<D::Storage> {
        &self.storage
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
}

// ============================================================================
// StackState Implementation
// ============================================================================

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: SystemBDevice> StackState
    for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
where
    D::Storage: Default,
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

    fn key_write(&self, level: u8, key: &[u8; 4], current_access_level: u8) -> u8 {
        if level as usize >= NUM_AUTH_KEYS {
            return 0xFF;
        }
        if current_access_level > level {
            return 0xFF;
        }
        self.auth_keys.borrow_mut()[level as usize] = *key;
        self.mark_dirty();
        level
    }
}

// ============================================================================
// Table Accessor Trait Implementations
// ============================================================================

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: SystemBDevice>
    HasAddressTable for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
{
    type ADT = Table<AddrTab7Impl<ADT_SIZE>>;

    fn adt(&self) -> &RefCell<Self::ADT> {
        &self.adt
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: SystemBDevice>
    HasAssociationTable for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
{
    type AST = Table<AssoTab6Impl<AST_SIZE>>;

    fn ast(&self) -> &RefCell<Self::AST> {
        &self.ast
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: SystemBDevice>
    HasCommunicationObjectTable for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
{
    type COT = Table<CoTab7Impl<COT_SIZE>>;

    fn cot(&self) -> &RefCell<Self::COT> {
        &self.cot
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: SystemBDevice>
    HasApplication for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
{
    type APP = Application<P>;

    fn app(&self) -> &RefCell<Self::APP> {
        &self.app
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: SystemBDevice>
    HasRoutingCount for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
{
    fn routing_count(&self) -> u8 {
        self.routing_count.get()
    }
}

// ============================================================================
// IP Device State Extension
// ============================================================================

/// Unified device state for KNX/IP devices (57B0).
///
/// Extends [`SystemBDeviceState`] with IP-specific configuration that can be
/// modified via the IP Parameter Object.
pub struct IpSystemBDeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault,
    D: KnxIpDevice,
> {
    /// Base device state with tables.
    base: SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>,

    /// Platform for querying current network values.
    platform: D::Platform,

    // ========================================================================
    // Persistent IP configuration
    // ========================================================================
    friendly_name: RefCell<[u8; 30]>,
    friendly_name_len: Cell<usize>,
    configured_ip: Cell<Ipv4Addr>,
    configured_subnet: Cell<Ipv4Addr>,
    configured_gateway: Cell<Ipv4Addr>,
    ip_assignment_method: Cell<u8>,
    routing_multicast: Cell<Ipv4Addr>,
    ttl: Cell<u8>,
    project_installation_id: Cell<u16>,
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: KnxIpDevice>
    IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
{
    /// Create new IP device state with factory defaults.
    ///
    /// # Arguments
    ///
    /// - `storage`: Storage backend for persistence
    /// - `platform`: Platform for querying network state
    /// - `serial_number`: Factory-programmed serial number (6 bytes)
    pub fn new(storage: D::Storage, platform: D::Platform, serial_number: [u8; 6]) -> Self {
        let base = SystemBDeviceState::new(storage, serial_number);
        let ip_config = PersistedIpConfig::default();

        Self {
            base,
            platform,
            friendly_name: RefCell::new(ip_config.friendly_name),
            friendly_name_len: Cell::new(ip_config.friendly_name_len as usize),
            configured_ip: Cell::new(Ipv4Addr::from(ip_config.configured_ip)),
            configured_subnet: Cell::new(Ipv4Addr::from(ip_config.configured_subnet)),
            configured_gateway: Cell::new(Ipv4Addr::from(ip_config.configured_gateway)),
            ip_assignment_method: Cell::new(ip_config.ip_assignment_method),
            routing_multicast: Cell::new(Ipv4Addr::from(ip_config.routing_multicast)),
            ttl: Cell::new(ip_config.ttl),
            project_installation_id: Cell::new(ip_config.project_installation_id),
        }
    }

    /// Create IP device state from persisted values.
    ///
    /// # Arguments
    ///
    /// - `storage`: Storage backend for persistence
    /// - `platform`: Platform for querying network state
    /// - `serial_number`: Factory-programmed serial number (6 bytes)
    /// - `persisted`: Previously persisted state to restore
    pub fn from_persisted(
        storage: D::Storage,
        platform: D::Platform,
        serial_number: [u8; 6],
        persisted: PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, P>,
    ) -> Self {
        let ip_config = persisted.ip_config.clone().unwrap_or_default();
        let base = SystemBDeviceState::from_persisted(storage, serial_number, persisted);

        Self {
            base,
            platform,
            friendly_name: RefCell::new(ip_config.friendly_name),
            friendly_name_len: Cell::new(ip_config.friendly_name_len as usize),
            configured_ip: Cell::new(Ipv4Addr::from(ip_config.configured_ip)),
            configured_subnet: Cell::new(Ipv4Addr::from(ip_config.configured_subnet)),
            configured_gateway: Cell::new(Ipv4Addr::from(ip_config.configured_gateway)),
            ip_assignment_method: Cell::new(ip_config.ip_assignment_method),
            routing_multicast: Cell::new(Ipv4Addr::from(ip_config.routing_multicast)),
            ttl: Cell::new(ip_config.ttl),
            project_installation_id: Cell::new(ip_config.project_installation_id),
        }
    }

    /// Get the base device state.
    pub fn base(&self) -> &SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D> {
        &self.base
    }

    /// Get the platform.
    pub fn platform(&self) -> &D::Platform {
        &self.platform
    }

    /// Check if there are unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.base.is_dirty()
    }

    /// Mark state as dirty.
    pub fn mark_dirty(&self) {
        self.base.mark_dirty();
    }

    /// Export state to persisted format.
    pub fn to_persisted(&self) -> PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, P>
    where
        P: Clone,
    {
        self.base.to_persisted(Some(self.build_ip_config()))
    }

    /// Build the IP config for persistence.
    pub fn build_ip_config(&self) -> PersistedIpConfig {
        PersistedIpConfig {
            friendly_name: *self.friendly_name.borrow(),
            friendly_name_len: self.friendly_name_len.get() as u8,
            configured_ip: self.configured_ip.get().octets(),
            configured_subnet: self.configured_subnet.get().octets(),
            configured_gateway: self.configured_gateway.get().octets(),
            ip_assignment_method: self.ip_assignment_method.get(),
            routing_multicast: self.routing_multicast.get().octets(),
            ttl: self.ttl.get(),
            project_installation_id: self.project_installation_id.get(),
        }
    }

    /// Get the routing count.
    pub fn get_routing_count(&self) -> u8 {
        self.base.get_routing_count()
    }

    /// Set the routing count.
    pub fn set_routing_count(&self, count: u8) {
        self.base.set_routing_count(count);
    }

    /// Check if all tables are loaded.
    pub fn all_loaded(&self) -> bool {
        self.base.all_loaded()
    }

    /// Check if the application is running.
    pub fn is_running(&self) -> bool {
        self.base.is_running()
    }
}

// Delegate StackState to base
impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: KnxIpDevice> StackState
    for IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
where
    D::Storage: Default,
    D::Platform: Default,
{
    fn individual_address(&self) -> IndividualAddress {
        self.base.individual_address()
    }

    fn set_individual_address(&self, addr: IndividualAddress) {
        self.base.set_individual_address(addr);
    }

    fn serial_number(&self) -> &[u8; 6] {
        self.base.serial_number()
    }

    fn max_access_levels(&self) -> u8 {
        self.base.max_access_levels()
    }

    fn default_access_level(&self) -> u8 {
        self.base.default_access_level()
    }

    fn authorize(&self, key: &[u8; 4]) -> u8 {
        self.base.authorize(key)
    }

    fn key_write(&self, level: u8, key: &[u8; 4], current_access_level: u8) -> u8 {
        self.base.key_write(level, key, current_access_level)
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: KnxIpDevice> IpStackState
    for IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
where
    D::Storage: Default,
    D::Platform: Default,
{
    fn current_ip_address(&self) -> Ipv4Addr {
        self.platform.current_ip_address()
    }

    fn current_subnet_mask(&self) -> Ipv4Addr {
        self.platform.current_subnet_mask()
    }

    fn current_default_gateway(&self) -> Ipv4Addr {
        self.platform.current_default_gateway()
    }

    fn mac_address(&self) -> [u8; 6] {
        self.platform.mac_address()
    }

    fn current_ip_assignment_method(&self) -> u8 {
        self.platform.current_ip_assignment_method()
    }

    fn ip_capabilities(&self) -> u8 {
        self.platform.ip_capabilities()
    }

    fn knxnetip_device_capabilities(&self) -> u16 {
        self.platform.knxnetip_device_capabilities()
    }

    fn configured_ip_address(&self) -> Ipv4Addr {
        self.configured_ip.get()
    }

    fn set_configured_ip_address(&self, addr: Ipv4Addr) {
        self.configured_ip.set(addr);
        self.mark_dirty();
    }

    fn configured_subnet_mask(&self) -> Ipv4Addr {
        self.configured_subnet.get()
    }

    fn set_configured_subnet_mask(&self, mask: Ipv4Addr) {
        self.configured_subnet.set(mask);
        self.mark_dirty();
    }

    fn configured_default_gateway(&self) -> Ipv4Addr {
        self.configured_gateway.get()
    }

    fn set_configured_default_gateway(&self, gateway: Ipv4Addr) {
        self.configured_gateway.set(gateway);
        self.mark_dirty();
    }

    fn ip_assignment_method(&self) -> u8 {
        self.ip_assignment_method.get()
    }

    fn set_ip_assignment_method(&self, method: u8) {
        self.ip_assignment_method.set(method);
        self.mark_dirty();
    }

    fn routing_multicast_address(&self) -> Ipv4Addr {
        self.routing_multicast.get()
    }

    fn set_routing_multicast_address(&self, addr: Ipv4Addr) {
        self.routing_multicast.set(addr);
        self.mark_dirty();
    }

    fn ttl(&self) -> u8 {
        self.ttl.get()
    }

    fn set_ttl(&self, ttl: u8) {
        self.ttl.set(ttl);
        self.mark_dirty();
    }

    fn friendly_name_len(&self) -> usize {
        self.friendly_name_len.get()
    }

    fn friendly_name(&self, buf: &mut [u8]) -> usize {
        let name = self.friendly_name.borrow();
        let len = self.friendly_name_len.get().min(buf.len());
        buf[..len].copy_from_slice(&name[..len]);
        len
    }

    fn set_friendly_name(&self, name: &[u8]) {
        let mut fname = self.friendly_name.borrow_mut();
        let len = name.len().min(30);
        fname[..len].copy_from_slice(&name[..len]);
        fname[len..].fill(0);
        self.friendly_name_len.set(len);
        self.mark_dirty();
    }

    fn project_installation_id(&self) -> u16 {
        self.project_installation_id.get()
    }

    fn set_project_installation_id(&self, id: u16) {
        self.project_installation_id.set(id);
        self.mark_dirty();
    }
}

// Delegate table accessors to base
impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: KnxIpDevice>
    HasAddressTable for IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
{
    type ADT = Table<AddrTab7Impl<ADT_SIZE>>;

    fn adt(&self) -> &RefCell<Self::ADT> {
        self.base.adt()
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: KnxIpDevice>
    HasAssociationTable for IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
{
    type AST = Table<AssoTab6Impl<AST_SIZE>>;

    fn ast(&self) -> &RefCell<Self::AST> {
        self.base.ast()
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: KnxIpDevice>
    HasCommunicationObjectTable for IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
{
    type COT = Table<CoTab7Impl<COT_SIZE>>;

    fn cot(&self) -> &RefCell<Self::COT> {
        self.base.cot()
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: KnxIpDevice>
    HasApplication for IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
{
    type APP = Application<P>;

    fn app(&self) -> &RefCell<Self::APP> {
        self.base.app()
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, D: KnxIpDevice>
    HasRoutingCount for IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, D>
{
    fn routing_count(&self) -> u8 {
        self.base.routing_count()
    }
}
