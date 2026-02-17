//! Network information and configuration for the Pico W platform.
//!
//! Implements [`NetworkInfo`] (read-only queries) and [`NetworkConfig`]
//! (apply changes) by reading/writing the embassy-net stack configuration.

use core::cell::Cell;
use core::net::Ipv4Addr;

use embassy_net::{Ipv4Cidr, Stack, StaticConfigV4};

use platform::traits::{IpConfig, NetworkConfig, NetworkInfo};

// ================================================================================
// PicoWNetworkInfo
// ================================================================================

/// Network information and configuration for the Pico W.
///
/// Holds the embassy-net stack handle and the MAC address (obtained from
/// the CYW43 WiFi driver at init). Provides both read-only network info
/// and the ability to reconfigure IP settings at runtime.
pub struct PicoWNetworkInfo {
    stack: Stack<'static>,
    mac: [u8; 6],
    /// Tracks which assignment method is currently active.
    /// The stack's `config_v4()` doesn't expose whether DHCP or static
    /// was used, so we track it ourselves.
    assignment_method: Cell<u8>,
}

impl PicoWNetworkInfo {
    /// Create from a stack handle and the WiFi MAC address.
    ///
    /// `initial_method` should be the assignment method used at boot
    /// (typically DHCP = 0x04).
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
    Ipv4Addr::new(
        (mask >> 24) as u8,
        (mask >> 16) as u8,
        (mask >> 8) as u8,
        mask as u8,
    )
}

/// Convert a subnet mask to a CIDR prefix length.
fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    let bits = u32::from_be_bytes(mask.octets());
    bits.leading_ones() as u8
}

// ================================================================================
// NetworkInfo implementation
// ================================================================================

impl NetworkInfo for PicoWNetworkInfo {
    fn current_ip_address(&self) -> Ipv4Addr {
        self.stack
            .config_v4()
            .map(|c| c.address.address())
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    fn current_subnet_mask(&self) -> Ipv4Addr {
        self.stack
            .config_v4()
            .map(|c| prefix_to_mask(c.address.prefix_len()))
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    fn current_default_gateway(&self) -> Ipv4Addr {
        self.stack
            .config_v4()
            .and_then(|c| c.gateway)
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
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

    fn knxnetip_device_capabilities(&self) -> u16 {
        // Core (bit 0) + Device Management (bit 1) + Routing (bit 3)
        // No tunneling on embedded for now — constrained resources.
        0x000B
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

impl NetworkConfig for PicoWNetworkInfo {
    type Error = NetworkConfigError;

    fn apply_ip_config(&self, config: &IpConfig) -> Result<(), Self::Error> {
        if config.assignment_method & 0x04 != 0 {
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
            self.assignment_method.set(0x04);
        } else if config.assignment_method & 0x01 != 0 {
            // Manual/static IP requested.
            let prefix = mask_to_prefix(config.subnet_mask);
            let cidr = Ipv4Cidr::new(config.address, prefix);
            let gateway = if config.default_gateway != Ipv4Addr::UNSPECIFIED {
                Some(config.default_gateway)
            } else {
                None
            };

            let static_config = StaticConfigV4 {
                address: cidr,
                gateway,
                dns_servers: Default::default(),
            };
            self.stack.set_config_v4(embassy_net::ConfigV4::Static(static_config));
            self.assignment_method.set(0x01);
        } else {
            return Err(NetworkConfigError::UnsupportedMethod(config.assignment_method));
        }

        Ok(())
    }
}
