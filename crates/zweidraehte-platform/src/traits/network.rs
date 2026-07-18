use core::fmt::Debug;
use core::net::Ipv4Addr;

// ============================================================================
// Network Information (read-only)
// ============================================================================

/// Platform trait for querying current network configuration.
///
/// Provides runtime network information (IP, subnet, gateway, MAC, etc.)
/// from the operating system or network stack. Used by the KNX/IP layer
/// to populate interface object properties.
pub trait NetworkInfo {
    /// Get the current IP address from the OS/network stack.
    fn current_ip_address(&self) -> Ipv4Addr;

    /// Get the current subnet mask from the OS/network stack.
    fn current_subnet_mask(&self) -> Ipv4Addr;

    /// Get the current default gateway from the OS/network stack.
    fn current_default_gateway(&self) -> Ipv4Addr;

    /// Get the MAC address of the network interface.
    fn mac_address(&self) -> [u8; 6];

    /// Get the current IP assignment method in use (manual, DHCP, etc.)
    fn current_ip_assignment_method(&self) -> u8;

    /// Get the IP capabilities supported by this platform.
    ///
    /// PID_IP_CAPABILITIES bitset per 03/08/03 §2.5.7 — the IP address
    /// assignment methods the device itself can apply (manual assignment
    /// is always available and has no bit):
    /// - Bit 0: BootP
    /// - Bit 1: DHCP
    /// - Bit 2: AutoIP
    fn ip_capabilities(&self) -> u8;
}

// ============================================================================
// Network Configuration (apply changes)
// ============================================================================

/// IP configuration to apply to the platform's network stack.
///
/// Used by [`NetworkConfig::apply_ip_config`] to switch between DHCP,
/// static IP, or other assignment methods at runtime.
#[derive(Debug, Clone, Copy)]
pub struct IpConfig {
    /// IP assignment method bitfield (Manual=1, BootP=2, DHCP=4, AutoIP=8).
    pub assignment_method: u8,
    /// Static IP address (used when assignment method is Manual).
    pub address: Ipv4Addr,
    /// Static subnet mask (used when assignment method is Manual).
    pub subnet_mask: Ipv4Addr,
    /// Static default gateway (used when assignment method is Manual).
    pub default_gateway: Ipv4Addr,
}

/// Platform trait for applying IP configuration changes.
///
/// On Linux, the OS manages networking independently, so this is a no-op.
/// On embedded platforms (e.g., Pico W with embassy-net), this reconfigures
/// the network stack to switch between DHCP and static IP assignment.
///
/// The stack calls this when:
/// - Loading persisted config at boot
/// - ETS writes the IP assignment method or static IP parameters
pub trait NetworkConfig {
    type Error: Debug;

    /// Apply IP configuration to the platform's network stack.
    ///
    /// The implementation should switch between DHCP / static / AutoIP
    /// based on the `assignment_method` bitfield in `config`.
    fn apply_ip_config(&self, config: &IpConfig) -> Result<(), Self::Error>;
}

/// No-op implementation for platforms where the OS manages networking.
impl NetworkConfig for () {
    type Error = core::convert::Infallible;

    fn apply_ip_config(&self, _config: &IpConfig) -> Result<(), Self::Error> {
        Ok(())
    }
}
