//! Embassy-net UDP socket and IP transport implementation.
//!
//! This module is transport-agnostic — it works with any network driver
//! that plugs into embassy-net (CYW43 WiFi, W5500 Ethernet, etc.).

use core::cell::{Cell, RefCell};
use core::net::{Ipv4Addr, SocketAddrV4};

use embassy_net::udp::{self, UdpSocket};
use embassy_net::{IpEndpoint, Stack};

use zweidraehte_platform::traits::{
    AsyncUdpSocket, IpTransport, NeverTcpListener, NeverTcpStream, UdpSocketOptions,
};

// ================================================================================
// Static UDP Buffer Pool
// ================================================================================

// KNX/IP needs up to 5 sockets (discovery, control, data, routing, routing control).
// Each socket gets 1KB rx + 1KB tx buffers, allocated from a static pool.
const MAX_UDP_SOCKETS: usize = 5;
const UDP_RX_BUF_SIZE: usize = 1024;
const UDP_TX_BUF_SIZE: usize = 1024;
// Per-socket metadata buffer: embassy-net tracks packet boundaries here.
const UDP_RX_META_SIZE: usize = 16;
const UDP_TX_META_SIZE: usize = 16;

struct UdpBuffers {
    rx_meta: [udp::PacketMetadata; UDP_RX_META_SIZE],
    rx_buf: [u8; UDP_RX_BUF_SIZE],
    tx_meta: [udp::PacketMetadata; UDP_TX_META_SIZE],
    tx_buf: [u8; UDP_TX_BUF_SIZE],
}

impl UdpBuffers {
    const fn new() -> Self {
        Self {
            rx_meta: [udp::PacketMetadata::EMPTY; UDP_RX_META_SIZE],
            rx_buf: [0u8; UDP_RX_BUF_SIZE],
            tx_meta: [udp::PacketMetadata::EMPTY; UDP_TX_META_SIZE],
            tx_buf: [0u8; UDP_TX_BUF_SIZE],
        }
    }
}

// One buffer set per socket slot. Each slot is an independent `UnsafeCell`
// so that borrowing slot N doesn't create a reference aliasing slot M.
// This is sound even on multi-core: the monotonic counter in
// `alloc_socket_slot()` guarantees each slot is handed out exactly once.
struct BufferSlot(core::cell::UnsafeCell<UdpBuffers>);

// SAFETY: Each slot is allocated exactly once (monotonic counter) so no
// two callers ever hold `&mut` to the same slot simultaneously.
unsafe impl Sync for BufferSlot {}

impl BufferSlot {
    const fn new() -> Self {
        Self(core::cell::UnsafeCell::new(UdpBuffers::new()))
    }
}

static UDP_BUFFERS: [BufferSlot; MAX_UDP_SOCKETS] =
    [const { BufferSlot::new() }; MAX_UDP_SOCKETS];

/// Tracks which buffer slots are in use.
static NEXT_SOCKET_SLOT: critical_section::Mutex<Cell<usize>> =
    critical_section::Mutex::new(Cell::new(0));

fn alloc_socket_slot() -> usize {
    critical_section::with(|cs| {
        let slot = NEXT_SOCKET_SLOT.borrow(cs).get();
        assert!(slot < MAX_UDP_SOCKETS, "out of UDP socket buffer slots");
        NEXT_SOCKET_SLOT.borrow(cs).set(slot + 1);
        slot
    })
}

// ================================================================================
// EmbassyUdpSocket
// ================================================================================

/// UDP socket implementation backed by embassy-net.
///
/// Uses `RefCell` for interior mutability because embassy-net's
/// `recv_from_with` requires `&mut self`, but our [`AsyncUdpSocket`]
/// trait uses `&self`. The KNX/IP stack never calls recv and send
/// concurrently on the same socket, so this is safe.
pub struct EmbassyUdpSocket {
    socket: RefCell<UdpSocket<'static>>,
    stack: Stack<'static>,
    local_port: u16,
}

/// Error type for embassy-net UDP operations.
#[derive(Debug, defmt::Format)]
pub enum UdpError {
    /// Socket bind failed.
    BindError,
    /// Multicast join failed.
    MulticastError,
    /// Send failed.
    SendError(udp::SendError),
}

impl AsyncUdpSocket for EmbassyUdpSocket {
    type Error = UdpError;
    type Context = Stack<'static>;

    fn bind(stack: &Stack<'static>, options: UdpSocketOptions) -> Result<Self, Self::Error> {
        let slot = alloc_socket_slot();

        // SAFETY: Each slot is allocated exactly once (monotonic counter),
        // and the socket holds a &'static mut reference for its lifetime.
        // Per-slot UnsafeCell means this doesn't alias other slots.
        let bufs = unsafe { &mut *UDP_BUFFERS[slot].0.get() };

        let mut socket = UdpSocket::new(
            *stack,
            &mut bufs.rx_meta,
            &mut bufs.rx_buf,
            &mut bufs.tx_meta,
            &mut bufs.tx_buf,
        );

        socket.bind(options.bind_addr.port()).map_err(|_| UdpError::BindError)?;

        Ok(Self { socket: RefCell::new(socket), stack: *stack, local_port: options.bind_addr.port() })
    }

    fn join_multicast(&self, group: Ipv4Addr, _interface: Ipv4Addr) -> Result<(), Self::Error> {
        self.stack
            .join_multicast_group(group)
            .map_err(|_| UdpError::MulticastError)
    }

    fn set_broadcast(&self, _broadcast: bool) -> Result<(), Self::Error> {
        // Embassy-net doesn't have a per-socket broadcast flag.
        // Broadcast sending works by default.
        Ok(())
    }

    fn local_endpoint(&self) -> SocketAddrV4 {
        let ip = self.stack
            .config_v4()
            .map(|c| c.address.address())
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        SocketAddrV4::new(ip, self.local_port)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV4, Option<Ipv4Addr>), Self::Error> {
        let mut socket = self.socket.borrow_mut();
        let result = socket
            .recv_from_with(|data, meta| {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                let addr = match meta.endpoint.addr {
                    embassy_net::IpAddress::Ipv4(v4) => v4,
                    #[allow(unreachable_patterns)]
                    _ => Ipv4Addr::UNSPECIFIED,
                };

                // Extract the local destination IP from the packet metadata.
                // This tells us whether the packet was addressed to a unicast
                // or multicast IP, enabling traffic type enforcement.
                let local_addr = meta.local_address.and_then(|a| match a {
                    embassy_net::IpAddress::Ipv4(v4) => Some(v4),
                    #[allow(unreachable_patterns)]
                    _ => None,
                });

                (len, SocketAddrV4::new(addr, meta.endpoint.port), local_addr)
            })
            .await;
        Ok(result)
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddrV4) -> Result<usize, Self::Error> {
        let ep = IpEndpoint::new(
            embassy_net::IpAddress::Ipv4(*addr.ip()),
            addr.port(),
        );
        self.socket.borrow().send_to(buf, ep).await.map_err(UdpError::SendError)?;
        Ok(buf.len())
    }
}

// ================================================================================
// EmbassyIpTransport
// ================================================================================

/// IP transport for embassy-net based platforms.
///
/// Uses embassy-net UDP sockets and stubs out TCP (KNX/IP Secure is
/// not a priority for embedded; use [`NeverTcpListener`] to satisfy
/// the trait bound without pulling in a TCP implementation).
pub struct EmbassyIpTransport;

impl IpTransport for EmbassyIpTransport {
    type UdpSocket = EmbassyUdpSocket;
    type TcpListener = NeverTcpListener;
    type TcpStream = NeverTcpStream;
}
