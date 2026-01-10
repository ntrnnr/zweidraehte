//! Device state management with persistence support.
//!
//! This module provides state types that implement [`StackState`] and
//! [`IpStackState`] while automatically persisting changes to storage.

use core::cell::{Cell, RefCell};
use core::marker::PhantomData;
use core::net::Ipv4Addr;

use crate::{
    IpPlatform, IpStackState, StackState,
    address::IndividualAddress,
    NUM_AUTH_KEYS, MAX_ACCESS_LEVELS,
};

use super::{
    DeviceStorage, KnxIpDevice, PersistedIpConfig, SystemBDevice,
};

/// Device state for System B devices.
///
/// This type implements [`StackState`] and manages both runtime and
/// persistent state. Changes to persistent values (individual address,
/// auth keys) are automatically marked dirty for later saving.
///
/// # Persistence
///
/// On construction, state is initialized with factory defaults:
/// - Individual address: 15.15.255
/// - Auth keys: All set to `[0xFF, 0xFF, 0xFF, 0xFF]` (default key)
/// - Programming mode: false
/// - Current access level: 3 (minimum)
///
/// The actual persistence of complete state (including tables) is handled
/// by the device builder which coordinates between DeviceState, SystemBTables,
/// and the storage backend.
///
/// Changes to persistent values call [`mark_dirty`](DeviceStorage::mark_dirty)
/// on the storage backend.
pub struct DeviceState<D: SystemBDevice> {
    // ========================================================================
    // Persistent state (loaded from storage, saved on change)
    // ========================================================================
    /// Individual address (persisted).
    pub(crate) individual_address: Cell<IndividualAddress>,

    /// Authorization keys for levels 0-2 (persisted).
    /// Level 3 has no key - it's the fallback when no key matches.
    pub(crate) auth_keys: RefCell<[[u8; 4]; NUM_AUTH_KEYS]>,

    // ========================================================================
    // Runtime state (volatile, reset on boot)
    // ========================================================================
    /// Current access level for connection (volatile).
    current_access_level: Cell<u8>,

    // ========================================================================
    // Storage management
    // ========================================================================
    /// Storage backend for persistence.
    pub(crate) storage: RefCell<D::Storage>,

    /// Dirty flag indicating unsaved changes.
    pub(crate) dirty: Cell<bool>,

    _phantom: PhantomData<D>,
}

impl<D: SystemBDevice> DeviceState<D> {
    /// Create new device state with factory defaults.
    ///
    /// Use `from_persisted` to restore from storage instead.
    pub fn new(storage: D::Storage) -> Self {
        Self {
            individual_address: Cell::new(IndividualAddress::new(15, 15, 255)),
            auth_keys: RefCell::new([[0xFF; 4]; NUM_AUTH_KEYS]),
            current_access_level: Cell::new((MAX_ACCESS_LEVELS - 1) as u8),
            storage: RefCell::new(storage),
            dirty: Cell::new(false),
            _phantom: PhantomData,
        }
    }

    /// Create device state from persisted values.
    ///
    /// This is called by the device builder after loading PersistedState.
    pub fn from_persisted(
        storage: D::Storage,
        individual_address: IndividualAddress,
        auth_keys: [[u8; 4]; 3],
    ) -> Self {
        Self {
            individual_address: Cell::new(individual_address),
            auth_keys: RefCell::new(auth_keys),
            current_access_level: Cell::new((MAX_ACCESS_LEVELS - 1) as u8),
            storage: RefCell::new(storage),
            dirty: Cell::new(false),
            _phantom: PhantomData,
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
}

impl<D: SystemBDevice> StackState for DeviceState<D>
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
        // From compile-time constant
        &D::SERIAL_NUMBER
    }

    fn max_access_levels(&self) -> u8 {
        MAX_ACCESS_LEVELS as u8
    }

    fn current_access_level(&self) -> u8 {
        self.current_access_level.get()
    }

    fn set_current_access_level(&self, level: u8) {
        self.current_access_level.set(level.min((MAX_ACCESS_LEVELS - 1) as u8));
    }

    fn default_access_level(&self) -> u8 {
        // Default access level is determined by finding the first key
        // that matches the default key (0xFFFFFFFF)
        self.authorize(&[0xFF, 0xFF, 0xFF, 0xFF])
    }

    fn authorize(&self, key: &[u8; 4]) -> u8 {
        let keys = self.auth_keys.borrow();

        // Check if key matches any configured key (levels 0-2 only)
        for level in 0..NUM_AUTH_KEYS {
            if &keys[level] == key {
                return level as u8;
            }
        }

        // No match = level 3 (minimum access)
        (MAX_ACCESS_LEVELS - 1) as u8
    }

    fn key_write(&self, level: u8, key: &[u8; 4], current_access_level: u8) -> u8 {
        // Level 3 has no key (it's the fallback)
        if level as usize >= NUM_AUTH_KEYS {
            return 0xFF;
        }

        // Can only write to levels >= current level
        if current_access_level > level {
            return 0xFF;
        }

        self.auth_keys.borrow_mut()[level as usize] = *key;
        self.mark_dirty();
        level
    }
}

// ============================================================================
// IP Device State
// ============================================================================

/// Device state for KNX/IP devices (57B0).
///
/// Extends [`DeviceState`] with IP-specific configuration that can be
/// modified via the IP Parameter Object.
///
/// # IP Configuration Persistence
///
/// All IP settings (friendly name, configured addresses, TTL, etc.) are
/// persisted. They can be set via:
/// - ETS programming (via IP Parameter Object properties)
/// - Direct API calls (for testing/configuration tools)
pub struct IpDeviceState<D: KnxIpDevice> {
    /// Base device state.
    base: DeviceState<D>,

    /// Platform for querying current network values.
    platform: D::Platform,

    // ========================================================================
    // Persistent IP configuration
    // ========================================================================
    /// Friendly name (up to 30 bytes).
    friendly_name: RefCell<[u8; 30]>,
    friendly_name_len: Cell<usize>,

    /// Configured (static) IP address.
    configured_ip: Cell<Ipv4Addr>,

    /// Configured subnet mask.
    configured_subnet: Cell<Ipv4Addr>,

    /// Configured default gateway.
    configured_gateway: Cell<Ipv4Addr>,

    /// IP assignment method.
    ip_assignment_method: Cell<u8>,

    /// Routing multicast address.
    routing_multicast: Cell<Ipv4Addr>,

    /// Multicast TTL.
    ttl: Cell<u8>,

    /// Project installation ID.
    project_installation_id: Cell<u16>,
}

impl<D: KnxIpDevice> IpDeviceState<D> {
    /// Create new IP device state with factory defaults.
    pub fn new(storage: D::Storage, platform: D::Platform) -> Self {
        let base = DeviceState::new(storage);
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
    /// This is called by the device builder after loading PersistedState.
    pub fn from_persisted(
        storage: D::Storage,
        platform: D::Platform,
        individual_address: IndividualAddress,
        auth_keys: [[u8; 4]; 3],
        ip_config: Option<PersistedIpConfig>,
    ) -> Self {
        let base = DeviceState::from_persisted(storage, individual_address, auth_keys);
        let ip_config = ip_config.unwrap_or_default();

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
    pub fn base(&self) -> &DeviceState<D> {
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
}

// Delegate StackState to base
impl<D: KnxIpDevice> StackState for IpDeviceState<D>
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

    fn current_access_level(&self) -> u8 {
        self.base.current_access_level()
    }

    fn set_current_access_level(&self, level: u8) {
        self.base.set_current_access_level(level);
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

impl<D: KnxIpDevice> IpStackState for IpDeviceState<D>
where
    D::Storage: Default,
    D::Platform: Default,
{
    // ========================================================================
    // Current values (from platform)
    // ========================================================================

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

    // ========================================================================
    // Configured values (persisted)
    // ========================================================================

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
        // Clear remaining bytes
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

// ============================================================================
// Default implementations
// ============================================================================

impl<D: SystemBDevice> Default for DeviceState<D>
where
    D::Storage: Default,
{
    fn default() -> Self {
        Self::new(D::Storage::default())
    }
}

impl<D: KnxIpDevice> Default for IpDeviceState<D>
where
    D::Storage: Default,
    D::Platform: Default,
{
    fn default() -> Self {
        Self::new(D::Storage::default(), D::Platform::default())
    }
}
