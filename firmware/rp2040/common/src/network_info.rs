//! Network information and configuration backed by embassy-net.
//!
//! Implements [`NetworkInfo`] (read-only queries) and [`NetworkConfig`]
//! (apply changes) by reading/writing the embassy-net stack configuration.
//!
//! Construct via [`EmbassyNetworkInfo::new()`] and pass to
//! [`zweidraehte_device::new()`] as the platform.

use core::cell::Cell;
use core::net::Ipv4Addr;

use embassy_net::{Ipv4Cidr, Stack, StaticConfigV4};

use zweidraehte_platform::traits::{IpConfig, NetworkConfig, NetworkInfo};

// ================================================================================
// IP assignment method constants (KNX spec bitfield)
// ================================================================================

/// Manual/static IP assignment (KNX IP assignment method bit 0).
pub const IP_ASSIGN_MANUAL: u8 = 0x01;

/// DHCP IP assignment (KNX IP assignment method bit 2).
pub const IP_ASSIGN_DHCP: u8 = 0x04;

// ================================================================================
// EmbassyNetworkInfo
// ================================================================================

/// Network information and configuration backed by embassy-net.
///
/// Holds the embassy-net stack handle and the MAC address. Provides both
/// read-only network info and the ability to reconfigure IP settings at
/// runtime.
///
/// # Construction
///
/// Build from a stack handle, MAC address, and the initial IP assignment
/// method used to create the stack:
///
/// ```rust,ignore
/// let platform = EmbassyNetworkInfo::new(stack, mac, IP_ASSIGN_DHCP);
/// let (knx_stack, runner) = zweidraehte_device::new(
///     resources, ll_builder, state, platform, mem_map,
/// );
/// ```
pub struct EmbassyNetworkInfo {
    stack: Stack<'static>,
    mac: [u8; 6],
    /// Tracks which assignment method is currently active.
    ///
    /// Initialized from the method used to create the embassy-net stack,
    /// then updated by `apply_ip_config()` when the device switches between
    /// DHCP and static at runtime.
    assignment_method: Cell<u8>,
}

impl EmbassyNetworkInfo {
    /// Create from a stack handle, MAC address, and the IP assignment
    /// method that was used to create the embassy-net stack.
    ///
    /// Use [`IP_ASSIGN_DHCP`] when the stack was created with
    /// `ConfigV4::Dhcp`, or [`IP_ASSIGN_MANUAL`] when created with
    /// `ConfigV4::Static`.
    pub fn new(stack: Stack<'static>, mac: [u8; 6], initial_method: u8) -> Self {
        Self { stack, mac, assignment_method: Cell::new(initial_method) }
    }
}

// ================================================================================
// Helper conversions
// ================================================================================

/// Convert a CIDR prefix length to a subnet mask.
fn prefix_to_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = !0u32 << (32 - prefix_len);
    Ipv4Addr::new((mask >> 24) as u8, (mask >> 16) as u8, (mask >> 8) as u8, mask as u8)
}

/// Convert a subnet mask to a CIDR prefix length.
pub fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    let bits = u32::from_be_bytes(mask.octets());
    bits.leading_ones() as u8
}

// ================================================================================
// NetworkInfo implementation
// ================================================================================

impl NetworkInfo for EmbassyNetworkInfo {
    fn current_ip_address(&self) -> Ipv4Addr {
        self.stack.config_v4().map(|c| c.address.address()).unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    fn current_subnet_mask(&self) -> Ipv4Addr {
        self.stack.config_v4().map(|c| prefix_to_mask(c.address.prefix_len())).unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    fn current_default_gateway(&self) -> Ipv4Addr {
        self.stack.config_v4().and_then(|c| c.gateway).unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn current_ip_assignment_method(&self) -> u8 {
        self.assignment_method.get()
    }

    fn ip_capabilities(&self) -> u8 {
        // Manual (0x01) + DHCP (0x04) supported.
        // BootP (0x02) and AutoIP (0x08) not implemented.
        0x05
    }
}

// ================================================================================
// NetworkConfig implementation
// ================================================================================

/// Error applying network configuration.
#[derive(Debug, defmt::Format)]
pub enum NetworkConfigError {
    /// The requested assignment method is not supported.
    UnsupportedMethod(u8),
}

impl NetworkConfig for EmbassyNetworkInfo {
    type Error = NetworkConfigError;

    fn apply_ip_config(&self, config: &IpConfig) -> Result<(), Self::Error> {
        if config.assignment_method & IP_ASSIGN_DHCP != 0 {
            // DHCP requested.
            // Embassy-net doesn't expose a "start DHCP" API on the stack
            // directly — DHCP is configured at stack creation. To switch
            // back to DHCP at runtime we'd need to store a reference to
            // the DhcpConfig or recreate the config. For now, just record
            // the method and let the next reboot apply it.
            //
            // TODO: Runtime DHCP switching requires either:
            //   1. Storing the stack's ConfigV4 setter, or
            //   2. Triggering a soft restart to re-init with DHCP.
            self.assignment_method.set(IP_ASSIGN_DHCP);
        } else if config.assignment_method & IP_ASSIGN_MANUAL != 0 {
            // Manual/static IP requested.
            let prefix = mask_to_prefix(config.subnet_mask);
            let cidr = Ipv4Cidr::new(config.address, prefix);
            let gateway =
                if config.default_gateway != Ipv4Addr::UNSPECIFIED { Some(config.default_gateway) } else { None };

            let static_config = StaticConfigV4 { address: cidr, gateway, dns_servers: Default::default() };
            self.stack.set_config_v4(embassy_net::ConfigV4::Static(static_config));
            self.assignment_method.set(IP_ASSIGN_MANUAL);
        } else {
            return Err(NetworkConfigError::UnsupportedMethod(config.assignment_method));
        }

        Ok(())
    }
}
