//! IP extension: persistent config, runtime state, IpStackState, and augment.
//!
//! Everything related to KNX/IP extension state lives here:
//!
//! - [`PersistedIpConfig`] — serializable IP configuration
//! - [`IpExtensionState`] — runtime state with interior mutability
//! - [`ExtensionState`] impl — persistence bridge
//! - [`IpStackState`] impl — IP property accessors
//! - [`InterfaceObjectAugment`] impl — provides the IP Parameter Object
//!   (Type 11) and handles all IP PIDs including tunneling
//!
//! The augment impl is in a separate submodule (`augment`) for readability,
//! but it's all one concept: the IP extension.

mod augment;

use core::cell::{Cell, RefCell};
use core::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::bcus::system_b::{ExtensionConfig, ExtensionState, SystemBDeviceState};
use crate::{IpConfig, IpPlatform, IpPlatformConfig, IpStackState, address::IndividualAddress};

// ============================================================================
// Persisted IP Config
// ============================================================================

/// Persisted IP configuration (for KNX/IP devices).
///
/// All IP-specific settings that can be configured via ETS or
/// the IP Parameter Object. Implements [`ExtensionConfig`] so it
/// can be used as the `E` parameter of
/// [`PersistedState`](crate::bcus::system_b::PersistedState).
///
/// The const generic `N` is the maximum number of additional individual
/// addresses (tunneling slots). Non-tunneling devices use the default
/// `N = 0`, paying zero storage for addresses they never use.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedIpConfig<const N: usize = 0> {
    /// Friendly name for discovery (up to 30 bytes).
    pub friendly_name: [u8; 30],

    /// Length of the friendly name.
    pub friendly_name_len: u8,

    /// Configured (static) IP address.
    pub configured_ip: [u8; 4],

    /// Configured subnet mask.
    pub configured_subnet: [u8; 4],

    /// Configured default gateway.
    pub configured_gateway: [u8; 4],

    /// IP assignment method (bitfield: Manual=1, BootP=2, DHCP=4, AutoIP=8).
    pub ip_assignment_method: u8,

    /// Routing multicast address.
    pub routing_multicast: [u8; 4],

    /// Multicast TTL value.
    pub ttl: u8,

    /// Project installation ID.
    pub project_installation_id: u16,

    /// Additional individual addresses for tunneling-capable profiles.
    #[serde_as(as = "[[_; 2]; N]")]
    pub additional_individual_addresses: [[u8; 2]; N],

    /// Number of valid entries in `additional_individual_addresses`.
    pub additional_individual_addresses_len: u8,
}

impl<const N: usize> Default for PersistedIpConfig<N> {
    fn default() -> Self {
        Self {
            friendly_name: [0; 30],
            friendly_name_len: 0,
            configured_ip: [0, 0, 0, 0],
            configured_subnet: [255, 255, 255, 0],
            configured_gateway: [0, 0, 0, 0],
            ip_assignment_method: 0x04, // DHCP
            routing_multicast: [224, 0, 23, 12],
            ttl: 16,
            project_installation_id: 0,
            additional_individual_addresses: [[0; 2]; N],
            additional_individual_addresses_len: 0,
        }
    }
}

impl<const N: usize> ExtensionConfig for PersistedIpConfig<N> {}

impl<const N: usize> PersistedIpConfig<N> {
    /// Get the configured IP address as an `Ipv4Addr`.
    pub fn configured_ip_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.configured_ip)
    }

    /// Get the routing multicast address as an `Ipv4Addr`.
    pub fn routing_multicast_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.routing_multicast)
    }
}

// ============================================================================
// IP Assignment Result
// ============================================================================

/// Outcome of the IP assignment procedure
/// ([`IpExtensionState::resolve_ip_assignment()`]).
///
/// Returned so the caller (typically the device boot sequence) can log
/// or react to what happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAssignmentResult {
    /// Static IP was applied from persisted config.
    StaticApplied,

    /// DHCP is active (was already running as boot default, no change).
    DhcpActive,

    /// Configured static IP was invalid (0.0.0.0 address or subnet),
    /// fell back to DHCP (boot default).
    StaticInvalidFallbackDhcp,

    /// No supported assignment method configured. The raw bitfield value
    /// is included for diagnostics.
    Unsupported(u8),
}

// ============================================================================
// Runtime State
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
///
/// `IpExtensionState` implements:
/// - [`ExtensionState`] — persistence (serialize/deserialize/factory reset)
/// - [`IpStackState`] — IP property accessors for context traits
/// - [`InterfaceObjectAugment`] — provides the IP Parameter Object (Type 11)
pub struct IpExtensionState<P: IpPlatform + IpPlatformConfig, const N: usize = 0> {
    /// Platform for querying current network values and applying config.
    platform: P,

    // ========================================================================
    // Persistent IP configuration
    // ========================================================================
    friendly_name: Cell<[u8; 30]>,
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

impl<P: IpPlatform + IpPlatformConfig, const N: usize> IpExtensionState<P, N> {
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
            friendly_name: self.friendly_name.get(),
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

    /// Push the current configured IP/subnet/gateway to the platform.
    ///
    /// This is a low-level helper used internally by
    /// [`resolve_ip_assignment()`](Self::resolve_ip_assignment). Prefer
    /// calling `resolve_ip_assignment()` at boot — it validates the
    /// persisted config and follows the KNX IP assignment procedure
    /// before deciding whether to apply.
    fn apply_current_config(&self) {
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

    /// Run the KNX IP assignment procedure (KNX spec Core 8.5, Figure 42).
    ///
    /// Examines the persisted `ip_assignment_method` bitfield and applies
    /// the appropriate configuration to the platform. Call this once at
    /// boot after loading persisted state from storage.
    ///
    /// # IP Assignment Method Bitfield
    ///
    /// | Bit | Value | Method               |
    /// |-----|-------|----------------------|
    /// |  0  | 0x01  | Manual (static IP)   |
    /// |  1  | 0x02  | BootP                |
    /// |  2  | 0x04  | DHCP                 |
    /// |  3  | 0x08  | AutoIP (RFC 3927)    |
    ///
    /// # Assignment Procedure
    ///
    /// The full spec procedure includes DHCP timeout detection and AutoIP
    /// fallback. This implementation handles the common cases synchronously:
    ///
    /// 1. **Manual bit set + valid address/subnet** → apply static config.
    /// 2. **Manual bit set + invalid address** → fall back to DHCP.
    /// 3. **DHCP bit set (no Manual)** → DHCP is already the boot default.
    /// 4. **Other** → unsupported, stays on whatever is running.
    ///
    /// The async DHCP timeout → AutoIP fallback path (spec steps 4-5, 8-9)
    /// is not yet implemented. AutoIP requires ARP probing which embassy-net
    /// does not support natively.
    pub fn resolve_ip_assignment(&self) -> IpAssignmentResult {
        let method = self.ip_assignment_method.get();

        // ====================================================================
        // Manual/static takes priority when its bit is set.
        // ====================================================================
        if method & 0x01 != 0 {
            let addr = self.configured_ip.get();
            let mask = self.configured_subnet.get();

            if addr.is_unspecified() || mask.is_unspecified() {
                // Static config is incomplete. Per the spec, if DHCP is also
                // enabled we try DHCP (already the boot default). Without
                // DHCP the spec says to try AutoIP, but that's not supported
                // yet — so we fall back to DHCP regardless.
                // TODO: AutoIP fallback (spec steps 4-5).
                return IpAssignmentResult::StaticInvalidFallbackDhcp;
            }

            // Valid static config — apply it to the platform.
            self.apply_current_config();
            return IpAssignmentResult::StaticApplied;
        }

        // ====================================================================
        // No Manual bit. DHCP is the boot default — nothing to change.
        // ====================================================================
        if method & 0x04 != 0 {
            return IpAssignmentResult::DhcpActive;
        }

        // TODO: BootP (0x02) — not supported.
        // TODO: AutoIP (0x08) as primary method — needs embassy-net link-local.

        IpAssignmentResult::Unsupported(method)
    }
}

// ============================================================================
// ExtensionState
// ============================================================================

impl<P: IpPlatform + IpPlatformConfig + Default, const N: usize> ExtensionState for IpExtensionState<P, N> {
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

        // Restore field values from the persisted config but do NOT call
        // apply_current_config() here. The caller is responsible for applying
        // the IP config to the platform at the appropriate time — typically
        // only when the assignment method is Manual/static. Applying during
        // from_config() would overwrite a DHCP lease that was already acquired
        // before state was loaded from flash (common on embedded platforms
        // where DHCP runs during hardware init, before persisted state is
        // deserialized).
        Self {
            platform: P::default(),
            friendly_name: Cell::new(config.friendly_name),
            friendly_name_len: Cell::new(config.friendly_name_len as usize),
            configured_ip: Cell::new(Ipv4Addr::from(config.configured_ip)),
            configured_subnet: Cell::new(Ipv4Addr::from(config.configured_subnet)),
            configured_gateway: Cell::new(Ipv4Addr::from(config.configured_gateway)),
            ip_assignment_method: Cell::new(config.ip_assignment_method),
            routing_multicast: Cell::new(Ipv4Addr::from(config.routing_multicast)),
            ttl: Cell::new(config.ttl),
            project_installation_id: Cell::new(config.project_installation_id),
            additional_individual_addresses: RefCell::new(additional),
        }
    }

    fn to_config(&self) -> PersistedIpConfig<N> {
        self.build_ip_config()
    }

    fn factory_reset(&self) {
        let defaults: PersistedIpConfig<N> = PersistedIpConfig::default();
        self.friendly_name.set(defaults.friendly_name);
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
/// This is [`SystemBDeviceState`] specialized with [`IpExtensionState`]
/// as the extension state for KNX/IP devices.
///
/// # Generic Parameters
///
/// - `ADT_SIZE`, `AST_SIZE`, `COT_SIZE`: Table sizes (see [`SystemBDeviceState`])
/// - `P`: Application parameters type
/// - `Plat`: Platform type implementing [`IpPlatform`] for network queries
/// - `N`: Maximum number of additional individual addresses (tunneling slots).
///   Non-tunneling devices use the default `N = 0`.
pub type IpSystemBDeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P,
    Plat,
    const N: usize = 0,
> = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, IpExtensionState<Plat, N>>;

// ============================================================================
// IpStackState — used by context traits via HasExtensionState
// ============================================================================

impl<P: IpPlatform + IpPlatformConfig, const N: usize> IpStackState for IpExtensionState<P, N> {
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
    }

    fn configured_subnet_mask(&self) -> Ipv4Addr {
        self.configured_subnet.get()
    }

    fn set_configured_subnet_mask(&self, mask: Ipv4Addr) {
        self.configured_subnet.set(mask);
    }

    fn configured_default_gateway(&self) -> Ipv4Addr {
        self.configured_gateway.get()
    }

    fn set_configured_default_gateway(&self, gateway: Ipv4Addr) {
        self.configured_gateway.set(gateway);
    }

    fn ip_assignment_method(&self) -> u8 {
        self.ip_assignment_method.get()
    }

    fn set_ip_assignment_method(&self, method: u8) {
        self.ip_assignment_method.set(method);
    }

    fn routing_multicast_address(&self) -> Ipv4Addr {
        self.routing_multicast.get()
    }

    fn set_routing_multicast_address(&self, addr: Ipv4Addr) {
        self.routing_multicast.set(addr);
    }

    fn ttl(&self) -> u8 {
        self.ttl.get()
    }

    fn set_ttl(&self, ttl: u8) {
        self.ttl.set(ttl);
    }

    fn friendly_name_len(&self) -> usize {
        self.friendly_name_len.get()
    }

    fn friendly_name(&self) -> [u8; 30] {
        self.friendly_name.get()
    }

    fn set_friendly_name(&self, name: &[u8]) {
        let mut fname = [0u8; 30];
        let len = name.len().min(30);
        fname[..len].copy_from_slice(&name[..len]);
        self.friendly_name.set(fname);
        self.friendly_name_len.set(len);
    }

    fn project_installation_id(&self) -> u16 {
        self.project_installation_id.get()
    }

    fn set_project_installation_id(&self, id: u16) {
        self.project_installation_id.set(id);
    }

    fn additional_individual_address_capacity(&self) -> usize {
        N
    }

    fn write_additional_individual_addresses(&self, buf: &mut [IndividualAddress]) -> usize {
        let stored = self.additional_individual_addresses.borrow();
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
        *self.additional_individual_addresses.borrow_mut() = vec;
        Ok(())
    }
}

// ============================================================================
// HasDomainAddress — IP domain address is the routing multicast address
// ============================================================================

impl<P: IpPlatform + IpPlatformConfig, const N: usize> crate::state::HasDomainAddress
    for IpExtensionState<P, N>
{
    /// KNX/IP domain address is 4 bytes (IPv4 routing multicast address).
    ///
    /// Per the KNX IP Communication Medium spec (03_02_06, section
    /// 4.3.5.3.4), `A_DomainAddressSerialNumber_Write` carries a 4-octet
    /// domain address which is the routing multicast address
    /// (PID_ROUTING_MULTICAST_ADDRESS).
    const DOMAIN_ADDRESS_LENGTH: usize = 4;

    fn domain_address(&self, buf: &mut [u8]) {
        buf[..4].copy_from_slice(&self.routing_multicast.get().octets());
    }

    fn set_domain_address(&self, addr: &[u8]) {
        let octets: [u8; 4] = addr[..4].try_into().expect("domain address must be 4 bytes for IP");
        self.routing_multicast.set(Ipv4Addr::from(octets));
    }
}

