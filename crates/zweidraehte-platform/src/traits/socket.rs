use core::fmt::Debug;
use core::net::{Ipv4Addr, SocketAddrV4};

use embassy_time::Duration;

/// Options for creating a UDP multicast socket.
#[derive(Debug, Clone)]
pub struct UdpSocketOptions {
    /// Socket address to bind to (typically `Ipv4Addr::UNSPECIFIED` with a specific port).
    pub bind_addr: SocketAddrV4,
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
            bind_addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
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
///
/// The `Context` associated type carries platform-specific state needed
/// to create sockets (e.g., an embassy-net `Stack` handle on embedded,
/// or `()` on Linux where sockets are self-contained).
pub trait AsyncUdpSocket: Sized {
    #[cfg(not(feature = "defmt"))]
    type Error: Debug;
    #[cfg(feature = "defmt")]
    type Error: Debug + defmt::Format;

    /// Platform-specific state needed to create sockets.
    ///
    /// On Linux this is `()` since sockets are created via OS syscalls.
    /// On embedded targets this might be an embassy-net `Stack` handle.
    type Context;

    /// Bind a new socket with the given options.
    fn bind(ctx: &Self::Context, options: UdpSocketOptions) -> Result<Self, Self::Error>;

    /// Join a multicast group on the specified interface.
    fn join_multicast(&self, group: Ipv4Addr, interface: Ipv4Addr) -> Result<(), Self::Error>;

    /// Leave a multicast group on the specified interface.
    ///
    /// Used by the KNX/IP link layer when
    /// `PID_ROUTING_MULTICAST_ADDRESS` (03/02/06 §4.3.5.3.5.1) is
    /// rewritten at runtime: the old routing group is left and the
    /// new one joined without restarting the stack.
    ///
    /// Platforms that cannot dynamically leave groups may implement
    /// this as `Ok(())` — callers treat a successful return as
    /// "stop delivering packets from this group up to the
    /// process". A stale membership is cosmetic, not a correctness
    /// bug for the spec behaviour (the inbound `recv_from` path
    /// still dispatches by socket, and the routing server will
    /// simply ignore frames that no longer match its configured
    /// multicast address).
    fn leave_multicast(&self, group: Ipv4Addr, interface: Ipv4Addr) -> Result<(), Self::Error>;

    /// Enable or disable SO_BROADCAST.
    fn set_broadcast(&self, broadcast: bool) -> Result<(), Self::Error>;

    /// Get the local endpoint this socket is bound to.
    fn local_endpoint(&self) -> SocketAddrV4;

    /// Receive a datagram, returning (bytes_read, source_addr, local_dest_ip).
    ///
    /// The third element is the local IP address the packet was addressed to
    /// (i.e., the destination IP from the sender's perspective). This allows
    /// distinguishing unicast from multicast traffic on shared sockets.
    /// Platforms that cannot report this return `None`.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV4, Option<Ipv4Addr>), Self::Error>;

    /// Send a datagram to the specified address.
    async fn send_to(&self, buf: &[u8], addr: SocketAddrV4) -> Result<usize, Self::Error>;
}

// ============================================================================
// TCP
// ============================================================================

/// Options for creating a TCP listener socket.
#[derive(Debug, Clone)]
pub struct TcpListenerOptions {
    /// Socket address to bind to.
    pub bind_addr: SocketAddrV4,
    /// Network interface name to bind to.
    pub interface: Option<&'static str>,
}

/// Async TCP listener that accepts incoming connections.
///
/// The listener binds to a local address/port and accepts incoming TCP
/// connections. Each accepted connection produces a stream (implementing
/// `embedded_io_async::Read + Write`) and the peer's socket address.
pub trait AsyncTcpListener: Sized {
    #[cfg(not(feature = "defmt"))]
    type Error: Debug;
    #[cfg(feature = "defmt")]
    type Error: Debug + defmt::Format;
    #[cfg(not(feature = "defmt"))]
    type Stream: embedded_io_async::Read<Error: Debug>
        + embedded_io_async::Write<Error: Debug>
        + embedded_io_async::ErrorType;
    #[cfg(feature = "defmt")]
    type Stream: embedded_io_async::Read<Error: Debug + defmt::Format>
        + embedded_io_async::Write<Error: Debug + defmt::Format>
        + embedded_io_async::ErrorType<Error: defmt::Format>;

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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
