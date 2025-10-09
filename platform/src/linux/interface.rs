use super::{Error, Result};
use crate::address::Ipv4Address;
use nix::ifaddrs::getifaddrs;

/// Get the IPv4 address of a network interface by its name
pub fn get_interface_address(interface_name: &str) -> Result<Ipv4Address> {
    let ifaddrs = getifaddrs().map_err(|e| Error::Other(format!("Failed to get interface addresses: {}", e)))?;

    for ifaddr in ifaddrs {
        if ifaddr.interface_name == interface_name {
            if let Some(address) = ifaddr.address {
                // Check if this is an IPv4 address
                if let Some(sockaddr) = address.as_sockaddr_in() {
                    return Ok(sockaddr.ip().into());
                }
            }
        }
    }

    Err(Error::Other(format!("Interface '{}' not found or has no IPv4 address", interface_name)))
}
