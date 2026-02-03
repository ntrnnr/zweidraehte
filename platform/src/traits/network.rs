use core::net::Ipv4Addr;

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
    fn ip_capabilities(&self) -> u8;

    /// Get the KNXnet/IP device capabilities.
    fn knxnetip_device_capabilities(&self) -> u16;
}
