//! Read-only [`NetworkInfo`] platform backed by the Linux kernel.
//!
//! On Linux the OS owns network configuration (systemd-networkd,
//! NetworkManager, ...), so a KNX/IP device running in userspace should
//! *report* the host's actual addresses but never reconfigure them. This
//! platform queries the kernel live on every getter call — property reads
//! are rare and `getifaddrs` is cheap, and live queries stay correct
//! across DHCP lease changes without a refresh mechanism.
//!
//! Applications that do want KNX-driven reconfiguration (e.g. an appliance
//! that owns its interface via systemd-networkd or NetworkManager) should
//! implement [`NetworkInfo`] + [`NetworkConfig`] themselves instead.
//!
//! Despite the name, this builds and runs on macOS too — it is gated on the
//! `linux` *feature*, and `getifaddrs` is POSIX. Only the default gateway is
//! genuinely Linux-only (`/proc/net/route`); elsewhere it reads as 0.0.0.0.

use core::net::Ipv4Addr;

use nix::ifaddrs::getifaddrs;

use crate::traits::{IpConfig, NetworkConfig, NetworkInfo};

/// Read-only [`NetworkInfo`] platform for a named Linux interface.
///
/// Reports the interface's live IP address, subnet mask, default gateway,
/// and MAC address straight from the kernel. [`NetworkConfig`] is a no-op
/// — the OS manages networking, the device only observes it.
///
/// The trait getters are infallible, so query failures (interface gone,
/// no IPv4 address yet) fall back to `0.0.0.0` / an all-zero MAC and log
/// a warning.
#[derive(Debug, Clone)]
pub struct LinuxIpPlatform {
    interface_name: String,
    assignment_method: u8,
}

impl LinuxIpPlatform {
    /// A read-only platform reporting on `interface_name` (e.g. `"eth0"`).
    ///
    /// The reported assignment method defaults to DHCP — the kernel does
    /// not record how an address was assigned, and DHCP is the common case
    /// for hosts whose OS manages networking. Override with
    /// [`with_assignment_method`](Self::with_assignment_method) if the
    /// host uses static addressing.
    pub fn new(interface_name: impl Into<String>) -> Self {
        Self { interface_name: interface_name.into(), assignment_method: ASSIGNMENT_METHOD_DHCP }
    }

    /// Override the reported PID_CURRENT_IP_ASSIGNMENT_METHOD value
    /// (03/08/03 §2.5.5: 1 = manual, 2 = BootP, 4 = DHCP, 8 = AutoIP;
    /// exactly one bit set).
    pub fn with_assignment_method(mut self, assignment_method: u8) -> Self {
        self.assignment_method = assignment_method;
        self
    }

    /// Walk the kernel's interface list and extract a value from the
    /// entries matching our interface. Shared plumbing for the
    /// address/netmask/MAC getters: they differ only in which sockaddr
    /// family they pick out of the per-interface entries.
    fn query_ifaddrs<T>(
        &self,
        what: &str,
        extract: impl Fn(&nix::ifaddrs::InterfaceAddress) -> Option<T>,
    ) -> Option<T> {
        let ifaddrs = match getifaddrs() {
            Ok(ifaddrs) => ifaddrs,
            Err(e) => {
                log::warn!("getifaddrs failed while querying {what} of {}: {e}", self.interface_name);
                return None;
            }
        };

        let found = ifaddrs.filter(|ifaddr| ifaddr.interface_name == self.interface_name).find_map(|a| extract(&a));
        if found.is_none() {
            log::warn!("interface {} not found or has no {what}", self.interface_name);
        }
        found
    }
}

/// PID_CURRENT_IP_ASSIGNMENT_METHOD value for DHCP (03/08/03 §2.5.5).
const ASSIGNMENT_METHOD_DHCP: u8 = 0x04;

impl NetworkInfo for LinuxIpPlatform {
    fn current_ip_address(&self) -> Ipv4Addr {
        self.query_ifaddrs("IPv4 address", |ifaddr| Some(ifaddr.address?.as_sockaddr_in()?.ip()))
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    fn current_subnet_mask(&self) -> Ipv4Addr {
        // The netmask entry accompanies the IPv4 address entry, so gate on
        // the address being AF_INET to skip the AF_PACKET/AF_INET6 rows.
        self.query_ifaddrs("IPv4 netmask", |ifaddr| {
            ifaddr.address?.as_sockaddr_in()?;
            Some(ifaddr.netmask?.as_sockaddr_in()?.ip())
        })
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    fn current_default_gateway(&self) -> Ipv4Addr {
        // Only Linux is served here: the lookup goes through `/proc/net/route`
        // (see below), which no BSD-family host has. macOS builds this module
        // too — it is gated on the `linux` *feature*, not the target — and
        // reporting 0.0.0.0 there is the honest answer, quietly: a property
        // read that fires per ETS poll must not spam the log with a limitation
        // that will not change.
        #[cfg(target_os = "linux")]
        return default_gateway_from_proc(&self.interface_name).unwrap_or(Ipv4Addr::UNSPECIFIED);
        #[cfg(not(target_os = "linux"))]
        return Ipv4Addr::UNSPECIFIED;
    }

    fn mac_address(&self) -> [u8; 6] {
        // The MAC lives in the interface's AF_PACKET entry.
        self.query_ifaddrs("MAC address", |ifaddr| ifaddr.address?.as_link_addr()?.addr()).unwrap_or([0; 6])
    }

    fn current_ip_assignment_method(&self) -> u8 {
        self.assignment_method
    }

    fn ip_capabilities(&self) -> u8 {
        // 03/08/03 §2.5.7: bits 0/1/2 advertise BootP/DHCP/AutoIP as
        // *settable by the device* (manual is implicitly always listed).
        // This platform never reconfigures the host, so it offers none.
        0x00
    }
}

/// No-op: the OS owns network configuration on Linux.
impl NetworkConfig for LinuxIpPlatform {
    type Error = core::convert::Infallible;

    fn apply_ip_config(&self, _config: &IpConfig) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Read the default gateway for `interface_name` from `/proc/net/route`.
///
/// There is no getifaddrs-style libc API for routes; the classic answer is
/// a netlink RTM_GETROUTE dump, which is a lot of machinery for one value.
/// `/proc/net/route` is a stable kernel ABI: whitespace-separated columns
/// `Iface Destination Gateway Flags ...`, addresses printed as hex of the
/// in-memory (little-endian) representation of the network-byte-order
/// `u32` — so `192.168.1.1` appears as `0101A8C0` and `to_le_bytes()`
/// recovers the octet order.
#[cfg(target_os = "linux")]
fn default_gateway_from_proc(interface_name: &str) -> Option<Ipv4Addr> {
    let route_table = match std::fs::read_to_string("/proc/net/route") {
        Ok(contents) => contents,
        Err(e) => {
            log::warn!("failed to read /proc/net/route while querying default gateway of {interface_name}: {e}");
            return None;
        }
    };

    for line in route_table.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(iface), Some(destination), Some(gateway)) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        // The default route has destination 0.0.0.0.
        if iface == interface_name
            && destination == "00000000"
            && let Ok(raw) = u32::from_str_radix(gateway, 16)
        {
            return Some(Ipv4Addr::from(raw.to_le_bytes()));
        }
    }

    log::warn!("no default route found for interface {interface_name}");
    None
}
