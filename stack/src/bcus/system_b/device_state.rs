//! Unified device state for System B devices.
//!
//! This module provides [`SystemBDeviceState`], which combines:
//! - Runtime state (individual address, auth keys)
//! - ETS-loaded tables (ADT, AST, COT, APP)
//! - Configuration (routing count)
//! - Dirty tracking (the binary owns storage separately)
//! - Link-layer-specific persistent state (IP config for KNX/IP, `()` for TP1)
//!
//! This is the single source of truth for all device state.

use core::cell::{Cell, RefCell};
use core::net::Ipv4Addr;

use const_default::ConstDefault;

use crate::{
    IpConfig, IpPlatform, IpPlatformConfig, IpStackState, MAX_ACCESS_LEVELS, NUM_AUTH_KEYS, StackState,
    address::IndividualAddress,
    objects::interface::HasRoutingCount,
    objects::tables::{HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasPeiApplication},
    objects::tables::{
        HasLoadStateMachine, HasRunStateMachine, Table, addr7::AddrTab7Impl, app::{Application, PeiApplication}, asso6::AssoTab6Impl,
        co7::CoTab7Impl,
    },
};

use super::{DeviceIdentity, LinkLayerState, PersistedIpConfig, PersistedState};

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
/// - For TP1 devices: nothing (`()`)
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
/// - `LS`: Link-layer-specific persistent runtime state (e.g.,
///   [`IpLinkLayerState`] for KNX/IP, `()` for TP1)
pub struct SystemBDeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault,
    LS: LinkLayerState = (),
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

    /// PEI (Platform Extension Interface) program (Load/Run state machines).
    pub pei: RefCell<PeiApplication>,

    /// Application program version (written by ETS).
    pub program_version: RefCell<[u8; 5]>,

    /// PEI program version (written by ETS).
    pub pei_program_version: RefCell<[u8; 5]>,

    // ========================================================================
    // Link-Layer State
    // ========================================================================
    /// Link-layer-specific persistent runtime state.
    ///
    /// For KNX/IP devices this is [`IpLinkLayerState`] with `Cell`/`RefCell`
    /// fields for interior mutability. For TP1 devices this is `()`.
    link_layer_state: LS,

    // ========================================================================
    // Dirty Tracking
    // ========================================================================
    /// Dirty flag indicating unsaved changes.
    ///
    /// Set by `mark_dirty()` whenever persistent state changes.
    /// The binary is responsible for checking `is_dirty()` and saving
    /// state via its own storage backend.
    dirty: Cell<bool>,
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, LS: LinkLayerState>
    SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, LS>
{
    /// Create new device state with factory defaults.
    ///
    /// - Individual address: 15.15.255
    /// - Auth keys: All set to `[0xFF, 0xFF, 0xFF, 0xFF]` (default key)
    /// - Routing count: 6 (default per KNX spec)
    /// - All tables: Unloaded
    /// - Link-layer state: Factory defaults via `LS::from_config(Default::default())`
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
            link_layer_state: LS::from_config(LS::Config::default()),
            dirty: Cell::new(false),
        }
    }

    /// Create device state from persisted storage.
    ///
    /// Restores all state and table data from storage. The link-layer state
    /// is constructed from the persisted `link_layer_config` via
    /// [`LinkLayerState::from_config`].
    ///
    /// The application's run state is always set to `Halted` — it must
    /// be explicitly restarted after boot.
    ///
    /// # Arguments
    ///
    /// - `identity`: Factory-programmed device identity (serial number, etc.)
    /// - `persisted`: Previously persisted state to restore
    pub fn from_persisted(
        identity: &impl DeviceIdentity,
        persisted: PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, P, LS::Config>,
    ) -> Self {
        // Destructure to move link_layer_config out by value (no Clone needed).
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
            link_layer_config,
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
            link_layer_state: LS::from_config(link_layer_config),
            dirty: Cell::new(false),
        }
    }

    /// Export state to persisted format for storage.
    pub fn to_persisted(&self) -> PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, P, LS::Config>
    where
        P: Clone,
    {
        PersistedState {
            version: PersistedState::<ADT_SIZE, AST_SIZE, COT_SIZE, P, LS::Config>::VERSION,
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
            link_layer_config: self.link_layer_state.to_config(),
        }
    }

    /// Get the link-layer-specific persistent runtime state.
    pub fn link_layer_state(&self) -> &LS {
        &self.link_layer_state
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
        self.link_layer_state.factory_reset();
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
// RestartHandler Implementation
// ============================================================================

use crate::restart::{EraseCode, RestartError, RestartHandler};

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, LS: LinkLayerState>
    RestartHandler for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, LS>
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

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, LS: LinkLayerState>
    StackState for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, LS>
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

    fn is_programming_mode(&self) -> bool {
        self.programming_mode.get()
    }

    fn set_programming_mode(&self, enabled: bool) {
        self.programming_mode.set(enabled);
    }

    fn mark_dirty(&self) {
        SystemBDeviceState::mark_dirty(self);
    }
}

// ============================================================================
// Table Accessor Trait Implementations
// ============================================================================

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, LS: LinkLayerState>
    HasAddressTable for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, LS>
{
    type ADT = Table<AddrTab7Impl<ADT_SIZE>>;

    fn adt(&self) -> &RefCell<Self::ADT> {
        &self.adt
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, LS: LinkLayerState>
    HasAssociationTable for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, LS>
{
    type AST = Table<AssoTab6Impl<AST_SIZE>>;

    fn ast(&self) -> &RefCell<Self::AST> {
        &self.ast
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, LS: LinkLayerState>
    HasCommunicationObjectTable for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, LS>
{
    type COT = Table<CoTab7Impl<COT_SIZE>>;

    fn cot(&self) -> &RefCell<Self::COT> {
        &self.cot
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, LS: LinkLayerState>
    HasApplication for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, LS>
{
    type APP = Application<P>;

    fn app(&self) -> &RefCell<Self::APP> {
        &self.app
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, LS: LinkLayerState>
    HasPeiApplication for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, LS>
{
    type PEI = PeiApplication;

    fn pei(&self) -> &RefCell<Self::PEI> {
        &self.pei
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, LS: LinkLayerState>
    HasRoutingCount for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, LS>
{
    fn routing_count(&self) -> u8 {
        self.routing_count.get()
    }
}

// ============================================================================
// IP Link-Layer State
// ============================================================================

/// Runtime state for KNX/IP-specific persistent configuration.
///
/// This struct provides interior-mutable access to all IP parameters
/// that are persisted and configurable via ETS / the IP Parameter Object.
/// It bridges the serializable [`PersistedIpConfig`] and the runtime
/// representation with `Cell`/`RefCell` fields.
///
/// The platform `P` is used to query current network state
/// (actual IP address, MAC address, etc.) from the operating system.
pub struct IpLinkLayerState<P: IpPlatform + IpPlatformConfig> {
    /// Platform for querying current network values and applying config.
    platform: P,

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

impl<P: IpPlatform + IpPlatformConfig> IpLinkLayerState<P> {
    /// Get the platform (for querying current network state).
    pub fn platform(&self) -> &P {
        &self.platform
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

    /// Apply the current IP configuration to the platform's network stack.
    ///
    /// Called after loading config from storage or when ETS writes IP
    /// configuration properties. On embedded platforms this switches
    /// between DHCP and static IP. On Linux this is a no-op.
    pub fn apply_current_config(&self) {
        let config = IpConfig {
            assignment_method: self.ip_assignment_method.get(),
            address: self.configured_ip.get(),
            subnet_mask: self.configured_subnet.get(),
            default_gateway: self.configured_gateway.get(),
        };

        if let Err(e) = self.platform.apply_ip_config(&config) {
            #[cfg(feature = "log")]
            log::error!("Failed to apply IP config: {:?}", e);
            #[cfg(feature = "defmt")]
            defmt::error!("Failed to apply IP config: {}", defmt::Debug2Format(&e));
        }
    }
}

impl<P: IpPlatform + IpPlatformConfig + Default> LinkLayerState for IpLinkLayerState<P> {
    type Config = PersistedIpConfig;

    fn from_config(config: PersistedIpConfig) -> Self {
        let state = Self {
            platform: P::default(),
            friendly_name: RefCell::new(config.friendly_name),
            friendly_name_len: Cell::new(config.friendly_name_len as usize),
            configured_ip: Cell::new(Ipv4Addr::from(config.configured_ip)),
            configured_subnet: Cell::new(Ipv4Addr::from(config.configured_subnet)),
            configured_gateway: Cell::new(Ipv4Addr::from(config.configured_gateway)),
            ip_assignment_method: Cell::new(config.ip_assignment_method),
            routing_multicast: Cell::new(Ipv4Addr::from(config.routing_multicast)),
            ttl: Cell::new(config.ttl),
            project_installation_id: Cell::new(config.project_installation_id),
        };
        // Apply the restored config to the platform's network stack.
        state.apply_current_config();
        state
    }

    fn to_config(&self) -> PersistedIpConfig {
        self.build_ip_config()
    }

    fn factory_reset(&self) {
        let defaults = PersistedIpConfig::default();
        *self.friendly_name.borrow_mut() = defaults.friendly_name;
        self.friendly_name_len.set(defaults.friendly_name_len as usize);
        self.configured_ip.set(Ipv4Addr::from(defaults.configured_ip));
        self.configured_subnet.set(Ipv4Addr::from(defaults.configured_subnet));
        self.configured_gateway.set(Ipv4Addr::from(defaults.configured_gateway));
        self.ip_assignment_method.set(defaults.ip_assignment_method);
        self.routing_multicast.set(Ipv4Addr::from(defaults.routing_multicast));
        self.ttl.set(defaults.ttl);
        self.project_installation_id.set(defaults.project_installation_id);
    }
}

// ============================================================================
// IP Device State Type Alias
// ============================================================================

/// Type alias for KNX/IP device state.
///
/// This is [`SystemBDeviceState`] specialized with [`IpLinkLayerState`]
/// for KNX/IP devices. It provides all the base device state plus
/// IP-specific configuration accessible through the `link_layer_state()`
/// method and the [`IpStackState`] trait implementation.
///
/// # Generic Parameters
///
/// - `ADT_SIZE`, `AST_SIZE`, `COT_SIZE`: Table sizes (see [`SystemBDeviceState`])
/// - `P`: Application parameters type
/// - `Plat`: Platform type implementing [`IpPlatform`] for network queries
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte::bcus::system_b::{
///     IpSystemBDeviceState, StaticIdentity,
/// };
///
/// const SERIAL: [u8; 6] = [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF];
/// let identity = StaticIdentity::new(SERIAL);
/// let state: IpSystemBDeviceState<ADT, AST, COT, Params, MyPlatform> =
///     IpSystemBDeviceState::new(&identity);
///
/// // Access IP config through link_layer_state():
/// let platform = state.link_layer_state().platform();
/// ```
pub type IpSystemBDeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P,
    Plat,
> = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, IpLinkLayerState<Plat>>;

// ============================================================================
// IpStackState Implementation for IP Devices
// ============================================================================

/// [`IpStackState`] is implemented for any [`SystemBDeviceState`] whose
/// link-layer state is [`IpLinkLayerState`]. This means all IP-specific
/// property reads/writes (configured IP, friendly name, etc.) route
/// through the link-layer state.
///
/// The `mark_dirty()` calls on setters ensure changes are tracked
/// for persistence.
impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, P: ConstDefault, Plat: IpPlatform + IpPlatformConfig + Default> IpStackState
    for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, IpLinkLayerState<Plat>>
{
    fn current_ip_address(&self) -> Ipv4Addr {
        self.link_layer_state.platform.current_ip_address()
    }

    fn current_subnet_mask(&self) -> Ipv4Addr {
        self.link_layer_state.platform.current_subnet_mask()
    }

    fn current_default_gateway(&self) -> Ipv4Addr {
        self.link_layer_state.platform.current_default_gateway()
    }

    fn mac_address(&self) -> [u8; 6] {
        self.link_layer_state.platform.mac_address()
    }

    fn current_ip_assignment_method(&self) -> u8 {
        self.link_layer_state.platform.current_ip_assignment_method()
    }

    fn ip_capabilities(&self) -> u8 {
        self.link_layer_state.platform.ip_capabilities()
    }

    fn knxnetip_device_capabilities(&self) -> u16 {
        self.link_layer_state.platform.knxnetip_device_capabilities()
    }

    fn configured_ip_address(&self) -> Ipv4Addr {
        self.link_layer_state.configured_ip.get()
    }

    fn set_configured_ip_address(&self, addr: Ipv4Addr) {
        self.link_layer_state.configured_ip.set(addr);
        self.mark_dirty();
        self.link_layer_state.apply_current_config();
    }

    fn configured_subnet_mask(&self) -> Ipv4Addr {
        self.link_layer_state.configured_subnet.get()
    }

    fn set_configured_subnet_mask(&self, mask: Ipv4Addr) {
        self.link_layer_state.configured_subnet.set(mask);
        self.mark_dirty();
        self.link_layer_state.apply_current_config();
    }

    fn configured_default_gateway(&self) -> Ipv4Addr {
        self.link_layer_state.configured_gateway.get()
    }

    fn set_configured_default_gateway(&self, gateway: Ipv4Addr) {
        self.link_layer_state.configured_gateway.set(gateway);
        self.mark_dirty();
        self.link_layer_state.apply_current_config();
    }

    fn ip_assignment_method(&self) -> u8 {
        self.link_layer_state.ip_assignment_method.get()
    }

    fn set_ip_assignment_method(&self, method: u8) {
        self.link_layer_state.ip_assignment_method.set(method);
        self.mark_dirty();
        self.link_layer_state.apply_current_config();
    }

    fn routing_multicast_address(&self) -> Ipv4Addr {
        self.link_layer_state.routing_multicast.get()
    }

    fn set_routing_multicast_address(&self, addr: Ipv4Addr) {
        self.link_layer_state.routing_multicast.set(addr);
        self.mark_dirty();
    }

    fn ttl(&self) -> u8 {
        self.link_layer_state.ttl.get()
    }

    fn set_ttl(&self, ttl: u8) {
        self.link_layer_state.ttl.set(ttl);
        self.mark_dirty();
    }

    fn friendly_name_len(&self) -> usize {
        self.link_layer_state.friendly_name_len.get()
    }

    fn friendly_name(&self, buf: &mut [u8]) -> usize {
        let name = self.link_layer_state.friendly_name.borrow();
        let len = self.link_layer_state.friendly_name_len.get().min(buf.len());
        buf[..len].copy_from_slice(&name[..len]);
        len
    }

    fn set_friendly_name(&self, name: &[u8]) {
        let mut fname = self.link_layer_state.friendly_name.borrow_mut();
        let len = name.len().min(30);
        fname[..len].copy_from_slice(&name[..len]);
        fname[len..].fill(0);
        self.link_layer_state.friendly_name_len.set(len);
        self.mark_dirty();
    }

    fn project_installation_id(&self) -> u16 {
        self.link_layer_state.project_installation_id.get()
    }

    fn set_project_installation_id(&self, id: u16) {
        self.link_layer_state.project_installation_id.set(id);
        self.mark_dirty();
    }
}
