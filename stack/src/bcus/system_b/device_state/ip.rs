//! IP link-layer state and `IpStackState` implementation for KNX/IP devices.

use core::cell::{Cell, RefCell};
use core::net::Ipv4Addr;

use const_default::ConstDefault;

use crate::{
    IpConfig, IpPlatform, IpPlatformConfig, IpStackState,
    address::IndividualAddress,
};
use super::{LinkLayerState, SystemBDeviceState};
use crate::bcus::system_b::PersistedIpConfig;

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
///
/// The const generic `N` is the maximum number of additional individual
/// addresses (tunneling slots). Non-tunneling devices use the default
/// `N = 0`, paying zero storage for addresses they never use.
pub struct IpLinkLayerState<P: IpPlatform + IpPlatformConfig, const N: usize = 0> {
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
    additional_individual_addresses: RefCell<heapless::Vec<IndividualAddress, N>>,
}

impl<P: IpPlatform + IpPlatformConfig, const N: usize> IpLinkLayerState<P, N> {
    /// Get the platform (for querying current network state).
    pub fn platform(&self) -> &P {
        &self.platform
    }

    /// Build the IP config for persistence.
    pub fn build_ip_config(&self) -> PersistedIpConfig<N> {
        let additional = self.additional_individual_addresses.borrow();
        let mut additional_raw = [[0u8; 2]; N];
        for (idx, addr) in additional.iter().enumerate() {
            additional_raw[idx].copy_from_slice(addr.as_bytes());
        }

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
            additional_individual_addresses: additional_raw,
            additional_individual_addresses_len: additional.len() as u8,
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

impl<P: IpPlatform + IpPlatformConfig + Default, const N: usize> LinkLayerState for IpLinkLayerState<P, N> {
    type Config = PersistedIpConfig<N>;

    fn from_config(config: PersistedIpConfig<N>) -> Self {
        let mut additional = heapless::Vec::<IndividualAddress, N>::new();
        for raw in config
            .additional_individual_addresses
            .iter()
            .take((config.additional_individual_addresses_len as usize).min(N))
        {
            let _ = additional.push(IndividualAddress::from_bytes(raw));
        }

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
            additional_individual_addresses: RefCell::new(additional),
        };
        // Apply the restored config to the platform's network stack.
        state.apply_current_config();
        state
    }

    fn to_config(&self) -> PersistedIpConfig<N> {
        self.build_ip_config()
    }

    fn factory_reset(&self) {
        let defaults: PersistedIpConfig<N> = PersistedIpConfig::default();
        *self.friendly_name.borrow_mut() = defaults.friendly_name;
        self.friendly_name_len.set(defaults.friendly_name_len as usize);
        self.configured_ip.set(Ipv4Addr::from(defaults.configured_ip));
        self.configured_subnet.set(Ipv4Addr::from(defaults.configured_subnet));
        self.configured_gateway.set(Ipv4Addr::from(defaults.configured_gateway));
        self.ip_assignment_method.set(defaults.ip_assignment_method);
        self.routing_multicast.set(Ipv4Addr::from(defaults.routing_multicast));
        self.ttl.set(defaults.ttl);
        self.project_installation_id.set(defaults.project_installation_id);
        self.additional_individual_addresses.borrow_mut().clear();
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
/// - `N`: Maximum number of additional individual addresses (tunneling slots).
///   Non-tunneling devices use the default `N = 0`.
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
/// // Non-tunneling device (N defaults to 0):
/// let state: IpSystemBDeviceState<ADT, AST, COT, Params, MyPlatform> =
///     IpSystemBDeviceState::new(&identity);
/// // Tunneling device with 4 slots:
/// let state: IpSystemBDeviceState<ADT, AST, COT, Params, MyPlatform, 4> =
///     IpSystemBDeviceState::new(&identity);
/// ```
pub type IpSystemBDeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P,
    Plat,
    const N: usize = 0,
> = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, IpLinkLayerState<Plat, N>>;

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
impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault,
    Plat: IpPlatform + IpPlatformConfig + Default,
    const N: usize,
    const MAX_CONN: usize,
> IpStackState for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, IpLinkLayerState<Plat, N>, MAX_CONN>
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

    fn additional_individual_address_capacity(&self) -> usize {
        N
    }

    fn write_additional_individual_addresses(&self, buf: &mut [IndividualAddress]) -> usize {
        let stored = self.link_layer_state.additional_individual_addresses.borrow();
        let count = stored.len().min(buf.len());
        buf[..count].copy_from_slice(&stored[..count]);
        count
    }

    fn set_additional_individual_addresses(&self, addresses: &[IndividualAddress]) -> Result<(), ()> {
        if addresses.len() > N {
            return Err(());
        }
        let mut vec = heapless::Vec::<IndividualAddress, N>::new();
        for &addr in addresses {
            vec.push(addr).map_err(|_| ())?;
        }
        *self.link_layer_state.additional_individual_addresses.borrow_mut() = vec;
        self.mark_dirty();
        Ok(())
    }
}
