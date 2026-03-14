//! Persisted IP configuration for KNX/IP devices.

use core::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::LinkLayerConfig;

/// Persisted IP configuration (for KNX/IP devices).
///
/// All IP-specific settings that can be configured via ETS or
/// the IP Parameter Object. Implements [`LinkLayerConfig`] so it
/// can be used as the `L` parameter of [`PersistedState`](super::PersistedState).
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

impl<const N: usize> LinkLayerConfig for PersistedIpConfig<N> {}

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
