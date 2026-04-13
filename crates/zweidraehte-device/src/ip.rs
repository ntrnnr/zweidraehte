//! KNX/IP state extension
//!
//! This module contains IP-specific stack state traits, constants, and platform
//! re-exports used by KNXnet/IP devices.
//!
//! The IP state is split into two traits:
//!
//! - [`IpStackState`] — persisted/configured values (ETS-programmable, stored in
//!   [`IpExtensionState`](crate::bcus::system_b::IpExtensionState)). These are
//!   available anywhere the extension state is accessible.
//!
//! - [`IpPlatformState`] — current runtime values queried from the platform/OS
//!   (actual IP, MAC, capabilities). These require a platform reference and are
//!   only available in contexts that have one (augment, context traits).

use core::net::Ipv4Addr;

use zweidraehte_proto::address::IndividualAddress;

// ============================================================================
// IpStackState — persisted/configured IP parameters
// ============================================================================

/// Persisted IP configuration state for KNXnet/IP devices.
///
/// This trait provides access to ETS-programmable IP parameters that are
/// stored in the device's extension state and survive power cycles.
///
/// For current runtime values (actual IP from OS/DHCP, MAC address, device
/// capabilities), see [`IpPlatformState`].
pub trait IpStackState {
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

    /// Get the friendly name as a fixed-size buffer.
    ///
    /// The actual name length is given by [`friendly_name_len`](Self::friendly_name_len).
    /// Bytes beyond the length are zero-padded.
    fn friendly_name(&self) -> [u8; 30];

    /// Set the friendly name.
    fn set_friendly_name(&self, name: &[u8]);

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

// ============================================================================
// IpPlatformState — current runtime values from the platform/OS
// ============================================================================

/// Current runtime network state from the platform/OS.
///
/// This trait provides read-only access to values that come from the
/// operating system or network stack (actual IP address, MAC, capabilities).
/// These are not persisted — they reflect the live state.
///
/// Implemented by [`IpAugment`](crate::bcus::system_b::IpAugment) which
/// combines an [`IpExtensionState`](crate::bcus::system_b::IpExtensionState)
/// reference (for config) with a platform reference (for current values).
pub trait IpPlatformState: IpStackState {
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

    /// Get the current IP assignment method in use.
    fn current_ip_assignment_method(&self) -> u8;

    /// Get IP capabilities supported by this device.
    ///
    /// Bitfield indicating which assignment methods are supported.
    fn ip_capabilities(&self) -> u8;
}

// ============================================================================
// Constants
// ============================================================================

/// Default KNX multicast address: 224.0.23.12
pub const DEFAULT_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);

/// Default KNX/IP port
pub const KNX_PORT: u16 = 3671;

// ============================================================================
// Platform re-exports
// ============================================================================

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
