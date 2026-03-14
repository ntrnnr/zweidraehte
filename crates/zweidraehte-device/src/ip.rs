//! KNX/IP state extension
//!
//! This module contains IP-specific stack state, constants, and platform
//! re-exports used by KNXnet/IP devices.

use core::net::Ipv4Addr;

use crate::address::IndividualAddress;
use crate::StackState;

/// Extended stack state for KNXnet/IP devices.
///
/// This trait extends [`StackState`] with IP-specific configuration and
/// platform queries needed by [`IpParameterObject`](crate::objects::interface::IpParameterObject).
///
/// The trait separates:
/// - **Current values** (read from platform/OS): `current_ip_address()`, `current_subnet_mask()`, etc.
/// - **Configured values** (ETS-programmable, persisted): `configured_ip_address()`, etc.
///
/// # Example
///
/// ```rust,ignore
/// use core::cell::RefCell;
/// use core::net::Ipv4Addr;
/// use zweidraehte_device::{StackState, IpStackState, address::IndividualAddress};
///
/// pub struct MyIpDeviceState {
///     // Base state
///     individual_address: RefCell<IndividualAddress>,
///     // IP state
///     configured_ip: RefCell<Ipv4Addr>,
///     configured_subnet: RefCell<Ipv4Addr>,
///     configured_gateway: RefCell<Ipv4Addr>,
///     friendly_name: RefCell<[u8; 30]>,
///     // Platform reference for current values
///     // ...
/// }
/// ```
pub trait IpStackState {
    // ========================================================================
    // Current values (read from platform/OS - typically read-only)
    // ========================================================================

    /// Get the current IP address from the platform/OS.
    ///
    /// This reflects the actual IP address the device is using, which may
    /// differ from the configured address if using DHCP.
    fn current_ip_address(&self) -> Ipv4Addr;

    /// Get the current subnet mask from the platform/OS.
    fn current_subnet_mask(&self) -> Ipv4Addr;

    /// Get the current default gateway from the platform/OS.
    fn current_default_gateway(&self) -> Ipv4Addr;

    /// Get the MAC address of the network interface.
    fn mac_address(&self) -> [u8; 6];

    // ========================================================================
    // Configured values (ETS-programmable, persisted)
    // ========================================================================

    /// Get the configured (static) IP address.
    ///
    /// This is the address configured via ETS, used when IP assignment
    /// method is set to manual/static.
    fn configured_ip_address(&self) -> Ipv4Addr;

    /// Set the configured IP address.
    fn set_configured_ip_address(&self, addr: Ipv4Addr);

    /// Get the configured subnet mask.
    fn configured_subnet_mask(&self) -> Ipv4Addr;

    /// Set the configured subnet mask.
    fn set_configured_subnet_mask(&self, mask: Ipv4Addr);

    /// Get the configured default gateway.
    fn configured_default_gateway(&self) -> Ipv4Addr;

    /// Set the configured default gateway.
    fn set_configured_default_gateway(&self, gateway: Ipv4Addr);

    /// Get the IP assignment method.
    ///
    /// - Bit 0: Manual (static IP)
    /// - Bit 1: BootP
    /// - Bit 2: DHCP
    /// - Bit 3: AutoIP
    fn ip_assignment_method(&self) -> u8;

    /// Set the IP assignment method.
    fn set_ip_assignment_method(&self, method: u8);

    /// Get the current IP assignment method in use.
    fn current_ip_assignment_method(&self) -> u8;

    /// Get IP capabilities supported by this device.
    ///
    /// Bitfield indicating which assignment methods are supported.
    fn ip_capabilities(&self) -> u8;

    /// Get the routing multicast address.
    ///
    /// Default is 224.0.23.12 (KNX multicast address).
    fn routing_multicast_address(&self) -> Ipv4Addr;

    /// Set the routing multicast address.
    fn set_routing_multicast_address(&self, addr: Ipv4Addr);

    /// Get the multicast TTL value.
    ///
    /// Default is 16 per KNX specification.
    fn ttl(&self) -> u8;

    /// Set the multicast TTL value.
    fn set_ttl(&self, ttl: u8);

    /// Get the friendly name length.
    fn friendly_name_len(&self) -> usize;

    /// Copy the friendly name into the provided buffer.
    ///
    /// Returns the number of bytes copied.
    fn friendly_name(&self, buf: &mut [u8]) -> usize;

    /// Set the friendly name.
    fn set_friendly_name(&self, name: &[u8]);

    /// Get the KNXnet/IP device capabilities.
    ///
    /// Bit 0: Device Management
    /// Bit 1: Tunneling
    /// Bit 2: Routing
    /// Bit 3: Remote Logging
    /// Bit 4: Remote Configuration & Diagnosis
    /// Bit 5: Object Server
    fn knxnetip_device_capabilities(&self) -> u16;

    /// Get the project installation ID.
    ///
    /// 2 bytes: project number (bits 15-4) + installation number (bits 3-0)
    fn project_installation_id(&self) -> u16;

    /// Set the project installation ID.
    fn set_project_installation_id(&self, id: u16);

    /// Maximum number of additional individual addresses this device supports.
    ///
    /// Returns 0 for devices that don't support tunneling. Used by property
    /// descriptors to report the array capacity.
    fn additional_individual_address_capacity(&self) -> usize {
        0
    }

    /// Write additional individual addresses into `buf`.
    ///
    /// Returns the number of addresses written (`<= buf.len()`).
    fn write_additional_individual_addresses(&self, _buf: &mut [IndividualAddress]) -> usize {
        0
    }

    /// Replace additional individual addresses.
    fn set_additional_individual_addresses(&self, _addresses: &[IndividualAddress]) -> Result<(), ()> {
        Err(())
    }
}

/// Default KNX multicast address: 224.0.23.12
pub const DEFAULT_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);

/// Default KNX/IP port
pub const KNX_PORT: u16 = 3671;

/// Platform abstraction for querying current network state.
///
/// Implement this trait to provide platform-specific network information
/// (current IP address, MAC address, etc.) for KNX/IP devices.
pub use zweidraehte_platform::NetworkInfo as IpPlatform;

/// Platform abstraction for applying IP configuration changes.
///
/// On embedded platforms this reconfigures the network stack (e.g.,
/// switching between DHCP and static IP). On Linux this is a no-op.
pub use zweidraehte_platform::{IpConfig, NetworkConfig as IpPlatformConfig};

/// Convenience trait alias for types that implement both [`StackState`] and
/// [`IpStackState`].
///
/// This exists because `define_interface_object!` only accepts a single
/// trait bound, so [`IpParameterObject`](crate::objects::interface::IpParameterObject) uses `S: IpDevice` instead of
/// `S: StackState + IpStackState`.
pub trait IpDevice: StackState + IpStackState {}
impl<T: StackState + IpStackState> IpDevice for T {}
