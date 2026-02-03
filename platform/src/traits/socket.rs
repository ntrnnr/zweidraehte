use core::fmt::Debug;
use core::net::{Ipv4Addr, SocketAddrV4};

use embassy_time::Duration;

/// Options for creating a UDP multicast socket.
#[derive(Debug, Clone)]
pub struct UdpSocketOptions {
    /// Address to bind to (typically `Ipv4Addr::UNSPECIFIED`).
    pub address: Ipv4Addr,
    /// Port to bind to.
    pub port: u16,
    /// Read timeout (None = no timeout, relies on async).
    pub read_timeout: Option<Duration>,
    /// Write timeout (None = no timeout, relies on async).
    pub write_timeout: Option<Duration>,
    /// Multicast TTL.
    pub multicast_ttl: u32,
    /// Whether to enable multicast loopback.
    pub loopback: bool,
    /// Network interface name to bind to.
    pub interface: Option<&'static str>,
}

impl Default for UdpSocketOptions {
    fn default() -> Self {
        Self {
            address: Ipv4Addr::UNSPECIFIED,
            port: 0,
            read_timeout: None,
            write_timeout: None,
            multicast_ttl: 32,
            loopback: true,
            interface: None,
        }
    }
}

/// Async UDP socket abstraction for KNX/IP.
///
/// Provides async send/receive operations for UDP datagrams, plus
/// multicast group management. Implementations exist for Linux
/// (using async_io + socket2) and can be added for embedded targets.
pub trait AsyncUdpSocket: Sized {
    type Error: Debug;

    /// Bind a new socket with the given options.
    fn bind(options: UdpSocketOptions) -> Result<Self, Self::Error>;

    /// Join a multicast group on the specified interface.
    fn join_multicast(&self, group: Ipv4Addr, interface: Ipv4Addr) -> Result<(), Self::Error>;

    /// Enable or disable SO_BROADCAST.
    fn set_broadcast(&self, broadcast: bool) -> Result<(), Self::Error>;

    /// Get the local endpoint this socket is bound to.
    fn local_endpoint(&self) -> SocketAddrV4;

    /// Receive a datagram, returning (bytes_read, source_addr).
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV4), Self::Error>;

    /// Send a datagram to the specified address.
    async fn send_to(&self, buf: &[u8], addr: SocketAddrV4) -> Result<usize, Self::Error>;
}

/// IP transport abstraction grouping socket types for a platform.
///
/// This trait provides a single type parameter for all IP-related socket types,
/// making it easy to add TCP support later without changing consumer signatures.
pub trait IpTransport {
    type UdpSocket: AsyncUdpSocket;
}
