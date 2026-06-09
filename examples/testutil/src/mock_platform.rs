//! Shared mock [`IpPlatform`] for KNX/IP device demos and tests.
//!
//! Both the System B demo and the MDT Push Button Lite replication need
//! a stand-in platform that reports static network values and no-ops the
//! `apply_ip_config` call (on Linux the OS owns networking). The two
//! definitions were byte-identical apart from the default mock IP's last
//! octet, so they live here once and are re-exported from each device
//! module for path stability.

use core::net::Ipv4Addr;

use zweidraehte_device::prelude::IpPlatform;
use zweidraehte_platform::{IpConfig, NetworkConfig};

/// A fixed-configuration [`IpPlatform`] for demos and tests.
///
/// Reports static IP / subnet / gateway / MAC and treats
/// [`apply_ip_config`](NetworkConfig::apply_ip_config) as a no-op, since
/// the host OS manages networking. Construct via [`Default`] for the
/// canonical demo address or [`with_ip`](Self::with_ip) to vary it.
#[derive(Debug, Clone)]
pub struct MockIpPlatform {
    pub ip_address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub mac_address: [u8; 6],
}

impl MockIpPlatform {
    /// Build a mock platform with a specific IP address, keeping the
    /// canonical subnet (`255.255.255.0`), gateway (`192.168.1.1`), and
    /// MAC. Use this when a test needs two distinct mock devices.
    pub fn with_ip(ip_address: Ipv4Addr) -> Self {
        Self { ip_address, ..Self::default() }
    }
}

impl Default for MockIpPlatform {
    fn default() -> Self {
        Self {
            ip_address: Ipv4Addr::new(192, 168, 1, 200),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            mac_address: [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
        }
    }
}

impl IpPlatform for MockIpPlatform {
    fn current_ip_address(&self) -> Ipv4Addr {
        self.ip_address
    }
    fn current_subnet_mask(&self) -> Ipv4Addr {
        self.subnet_mask
    }
    fn current_default_gateway(&self) -> Ipv4Addr {
        self.gateway
    }
    fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }
    fn current_ip_assignment_method(&self) -> u8 {
        0x02
    }
    fn ip_capabilities(&self) -> u8 {
        0x07
    }
}

impl NetworkConfig for MockIpPlatform {
    type Error = core::convert::Infallible;

    fn apply_ip_config(&self, _config: &IpConfig) -> Result<(), Self::Error> {
        Ok(()) // No-op — OS manages networking on Linux.
    }
}
