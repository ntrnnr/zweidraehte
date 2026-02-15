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

// ============================================================================
// TCP
// ============================================================================

/// Options for creating a TCP listener socket.
#[derive(Debug, Clone)]
pub struct TcpListenerOptions {
    /// Address to bind to (typically `Ipv4Addr::UNSPECIFIED`).
    pub address: Ipv4Addr,
    /// Port to bind to.
    pub port: u16,
    /// Network interface name to bind to.
    pub interface: Option<&'static str>,
}

/// Async TCP listener that accepts incoming connections.
///
/// The listener binds to a local address/port and accepts incoming TCP
/// connections. Each accepted connection produces a stream (implementing
/// `embedded_io_async::Read + Write`) and the peer's socket address.
pub trait AsyncTcpListener: Sized {
    type Error: Debug;
    type Stream: embedded_io_async::Read<Error: Debug>
        + embedded_io_async::Write<Error: Debug>
        + embedded_io_async::ErrorType;

    /// Bind and start listening on the given address/port.
    fn bind(options: TcpListenerOptions) -> Result<Self, Self::Error>;

    /// Accept a new incoming TCP connection.
    ///
    /// Returns the bidirectional stream and the peer's socket address.
    async fn accept(&self) -> Result<(Self::Stream, SocketAddrV4), Self::Error>;

    /// Get the local endpoint this listener is bound to.
    fn local_endpoint(&self) -> SocketAddrV4;
}

/// A TCP listener that never accepts connections.
///
/// For platforms that don't support TCP (e.g., embedded no_std targets),
/// this type satisfies the `AsyncTcpListener` bound on `IpTransport`
/// without requiring a real TCP implementation.
pub struct NeverTcpListener {
    _priv: core::convert::Infallible,
}

/// A TCP stream type that can never be constructed.
///
/// Companion to [`NeverTcpListener`] — since the listener can never be
/// created, this stream type is never instantiated either.
pub struct NeverTcpStream {
    _priv: core::convert::Infallible,
}

impl embedded_io_async::ErrorType for NeverTcpStream {
    type Error = core::convert::Infallible;
}

impl embedded_io_async::Read for NeverTcpStream {
    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self._priv {}
    }
}

impl embedded_io_async::Write for NeverTcpStream {
    async fn write(&mut self, _buf: &[u8]) -> Result<usize, Self::Error> {
        match self._priv {}
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        match self._priv {}
    }
}

/// Error type for [`NeverTcpListener`].
#[derive(Debug)]
pub struct NeverTcpError;

impl AsyncTcpListener for NeverTcpListener {
    type Error = NeverTcpError;
    type Stream = NeverTcpStream;

    fn bind(_options: TcpListenerOptions) -> Result<Self, Self::Error> {
        Err(NeverTcpError)
    }

    async fn accept(&self) -> Result<(Self::Stream, SocketAddrV4), Self::Error> {
        match self._priv {}
    }

    fn local_endpoint(&self) -> SocketAddrV4 {
        match self._priv {}
    }
}

// ============================================================================
// IP Transport
// ============================================================================

/// IP transport abstraction grouping socket types for a platform.
///
/// Bundles all IP-related socket types (UDP and TCP) into a single trait,
/// so consumers are generic over one type parameter rather than many.
pub trait IpTransport {
    type UdpSocket: AsyncUdpSocket;
    type TcpListener: AsyncTcpListener<Stream = Self::TcpStream>;
    type TcpStream: embedded_io_async::Read<Error: Debug>
        + embedded_io_async::Write<Error: Debug>
        + embedded_io_async::ErrorType;
}
