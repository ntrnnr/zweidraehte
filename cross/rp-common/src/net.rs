//! Embassy-net UDP socket and IP transport implementation.
//!
//! This module is transport-agnostic — it works with any network driver
//! that plugs into embassy-net (CYW43 WiFi, W5500 Ethernet, etc.).
//!
//! ## Buffer pools
//!
//! Both UDP and TCP socket storage live in caller-owned static pools
//! ([`UdpPool<N>`] and [`TcpPool<N>`]) so each binary can size them
//! independently — light switches don't pay for TCP buffers, and an
//! interface device can dial both `N`s up to match its tunnel count.
//!
//! ## Slot allocation
//!
//! - UDP sockets are bound once at startup and never closed; the UDP
//!   pool uses a simple monotonic counter.
//! - TCP sockets are accepted, idle-timed-out, and re-accepted in a
//!   loop. The TCP pool uses a bitmap free-list so closed sockets
//!   release their slot for reuse. Soundness rests on drop order:
//!   [`EmbassyTcpStream`] declares its embassy `TcpSocket` before its
//!   slot guard, so the socket drops first (smoltcp removes the handle
//!   and releases its buffer pointers) before the guard re-marks the
//!   slot free.

use core::cell::{Cell, RefCell};
use core::net::{Ipv4Addr, SocketAddrV4};

use embassy_net::tcp::{AcceptError, TcpSocket};
use embassy_net::udp::{self, UdpSocket};
use embassy_net::{IpEndpoint, Stack};

use zweidraehte_platform::traits::{
    AsyncTcpListener, AsyncUdpSocket, IpTransport, NeverTcpListener, NeverTcpStream, TcpListenerOptions,
    UdpSocketOptions,
};

// ================================================================================
// UDP buffer pool — caller-owned, monotonic
// ================================================================================

const UDP_RX_BUF_SIZE: usize = 1024;
const UDP_TX_BUF_SIZE: usize = 1024;
// Per-socket metadata buffer: embassy-net tracks packet boundaries here.
const UDP_RX_META_SIZE: usize = 16;
const UDP_TX_META_SIZE: usize = 16;

/// One UDP socket's worth of buffer storage. Public so the type can
/// appear in the [`UdpPool<N>`] generic, but the fields are private —
/// the buffers are only ever read/written through embassy's `UdpSocket`.
pub struct UdpBuffers {
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

// One buffer set per socket slot. Each slot is its own `UnsafeCell` so
// borrowing slot N doesn't create a reference aliasing slot M. This is
// sound because the monotonic counter in `UdpPool::alloc_slot` hands
// each slot out at most once.
struct UdpBufferSlot(core::cell::UnsafeCell<UdpBuffers>);

// SAFETY: each slot is handed out at most once via the owning pool's
// counter, so no two callers ever hold `&mut` references into the same
// slot.
unsafe impl Sync for UdpBufferSlot {}

impl UdpBufferSlot {
    const fn new() -> Self {
        Self(core::cell::UnsafeCell::new(UdpBuffers::new()))
    }
}

/// Static UDP buffer pool sized at compile time by the calling binary.
///
/// `N` is the number of UDP sockets the binary will bind. The KNX/IP
/// link-layer builder dedupes endpoints by port, so the actual count
/// is small (light switches: ~3 — discovery + control + routing;
/// interface devices: ~1 — discovery+remote-config dedupe to one).
///
/// Sockets are bound once via `UdpManager::bind_all` and held for the
/// program's lifetime — this allocator is monotonic and never
/// decrements.
pub struct UdpPool<const N: usize> {
    slots: [UdpBufferSlot; N],
    next: critical_section::Mutex<Cell<usize>>,
}

impl<const N: usize> UdpPool<N> {
    /// Construct an empty pool. Intended for `static` initialisers.
    pub const fn new() -> Self {
        Self { slots: [const { UdpBufferSlot::new() }; N], next: critical_section::Mutex::new(Cell::new(0)) }
    }

    fn alloc_slot(&'static self) -> &'static mut UdpBuffers {
        critical_section::with(|cs| {
            let slot = self.next.borrow(cs).get();
            assert!(slot < N, "out of UDP socket buffer slots");
            self.next.borrow(cs).set(slot + 1);
            // SAFETY: monotonic counter ensures each slot is handed
            // out at most once; per-slot `UnsafeCell` prevents aliasing.
            unsafe { &mut *self.slots[slot].0.get() }
        })
    }
}

impl<const N: usize> Default for UdpPool<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ================================================================================
// TCP buffer pool — caller-owned, bitmap free-list
// ================================================================================

const TCP_RX_BUF_SIZE: usize = 1024;
const TCP_TX_BUF_SIZE: usize = 1024;

struct TcpBuffers {
    rx_buf: [u8; TCP_RX_BUF_SIZE],
    tx_buf: [u8; TCP_TX_BUF_SIZE],
}

impl TcpBuffers {
    const fn new() -> Self {
        Self { rx_buf: [0u8; TCP_RX_BUF_SIZE], tx_buf: [0u8; TCP_TX_BUF_SIZE] }
    }
}

struct TcpBufferSlot(core::cell::UnsafeCell<TcpBuffers>);

// SAFETY: the bitmap free-list in [`TcpPool`] guarantees a slot is
// handed out to at most one caller at a time. Slots return to the
// free-list only via `PoolSlotGuard::drop`, which runs *after* the
// embassy `TcpSocket` has been dropped (see `EmbassyTcpStream` field
// order), so the buffer pointers smoltcp held are gone before the
// slot is reissued.
unsafe impl Sync for TcpBufferSlot {}

impl TcpBufferSlot {
    const fn new() -> Self {
        Self(core::cell::UnsafeCell::new(TcpBuffers::new()))
    }
}

/// Object-safe slot release back-channel used by [`PoolSlotGuard`].
///
/// Held as `&'static dyn ReleaseSlot` so that [`EmbassyTcpStream`]
/// stays free of a pool-size const generic. The vtable cost is one
/// extra pointer per accepted stream — negligible compared to the
/// `TcpSocket` itself.
trait ReleaseSlot: Sync {
    fn release(&self, idx: u8);
}

/// RAII guard that returns a slot index to the pool's free-list on drop.
///
/// Public because [`EmbassyTcpStream`] holds one as a field; not
/// constructible by external code (no `pub` fields, no `pub` ctor).
pub struct PoolSlotGuard {
    pool: &'static dyn ReleaseSlot,
    idx: u8,
}

impl Drop for PoolSlotGuard {
    fn drop(&mut self) {
        self.pool.release(self.idx);
    }
}

/// Static TCP buffer pool sized at compile time by the calling binary.
///
/// `N` is the maximum number of concurrent TCP connections. Slots are
/// reused: when an [`EmbassyTcpStream`] drops, its [`PoolSlotGuard`]
/// returns the slot index to a bitmap free-list and the next `accept()`
/// can pick it up.
///
/// Currently capped at `N ≤ 32` because the free-list is a single
/// `u32`. Generalise to `[Cell<u32>; (N + 31) / 32]` if a future
/// device needs more.
pub struct TcpPool<const N: usize> {
    slots: [TcpBufferSlot; N],
    /// Bit `i` set ⇒ slot `i` is free. Initialised to `(1 << N) - 1`
    /// at construction, so all slots start free.
    free_bits: critical_section::Mutex<Cell<u32>>,
}

impl<const N: usize> TcpPool<N> {
    /// Construct a pool with all slots free.
    ///
    /// Compile-time asserts `N ≤ 32` so the free-list fits in one word.
    pub const fn new() -> Self {
        const { assert!(N <= 32, "TcpPool<N>: N must be <= 32 (bitmap fits in u32)") };
        // `(1 << N) - 1` for N=32 would shift by 32 (UB on u32). Use
        // a saturating form instead.
        let initial: u32 = if N == 32 { u32::MAX } else { (1u32 << N) - 1 };
        Self { slots: [const { TcpBufferSlot::new() }; N], free_bits: critical_section::Mutex::new(Cell::new(initial)) }
    }

    /// Allocate one slot, returning a [`PoolSlotGuard`] plus the rx/tx
    /// buffer slices, or `None` if the pool is full.
    ///
    /// The guard owns the slot for as long as it lives; drop it
    /// (typically by dropping the surrounding [`EmbassyTcpStream`]) to
    /// return the slot to the free-list.
    fn alloc_slot(&'static self) -> Option<(PoolSlotGuard, &'static mut [u8], &'static mut [u8])> {
        critical_section::with(|cs| {
            let bits = self.free_bits.borrow(cs).get();
            if bits == 0 {
                return None;
            }
            // Lowest free slot index. `trailing_zeros` returns a value
            // in `0..32`; with the `bits != 0` guard above, this is
            // always a valid slot index `< N`.
            let idx = bits.trailing_zeros() as u8;
            self.free_bits.borrow(cs).set(bits & !(1u32 << idx));
            // SAFETY: the bit was set, so the slot is free; clearing
            // the bit before returning the buffers ensures no other
            // caller can racy-allocate the same slot. Per-slot
            // `UnsafeCell` prevents aliasing across slots.
            let bufs = unsafe { &mut *self.slots[idx as usize].0.get() };
            let guard = PoolSlotGuard { pool: self, idx };
            Some((guard, &mut bufs.rx_buf[..], &mut bufs.tx_buf[..]))
        })
    }
}

impl<const N: usize> ReleaseSlot for TcpPool<N> {
    fn release(&self, idx: u8) {
        critical_section::with(|cs| {
            let bits = self.free_bits.borrow(cs).get();
            self.free_bits.borrow(cs).set(bits | (1u32 << idx));
        });
    }
}

impl<const N: usize> Default for TcpPool<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ================================================================================
// Contexts (UDP-only and UDP+TCP)
// ================================================================================

/// embassy-net context for the UDP-only transport [`EmbassyIpTransport`].
///
/// Carries the network stack handle plus a reference to the binary-
/// owned [`UdpPool<N>`].
#[derive(Clone, Copy)]
pub struct EmbassyUdpContext<const N: usize> {
    pub stack: Stack<'static>,
    pub udp_pool: &'static UdpPool<N>,
}

/// embassy-net context for the UDP+TCP transport [`EmbassyIpTransportTcp`].
///
/// The `IpTransport` trait constrains `TcpListener::Context` to equal
/// `UdpSocket::Context`, so a single value carries both pool
/// references through to whichever socket is being created.
#[derive(Clone, Copy)]
pub struct EmbassyTcpContext<const N_UDP: usize, const N_TCP: usize> {
    pub stack: Stack<'static>,
    pub udp_pool: &'static UdpPool<N_UDP>,
    pub tcp_pool: &'static TcpPool<N_TCP>,
}

// ================================================================================
// Shared UDP socket internals
// ================================================================================

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

/// Inner UDP socket state shared by both [`EmbassyUdpSocket`] and
/// [`EmbassyUdpSocketTcp`]. Holds the embassy `UdpSocket` plus a
/// stack handle for multicast membership and local-endpoint lookup.
///
/// Uses `RefCell` for interior mutability because embassy-net's
/// `recv_from_with` requires `&mut self`, but our [`AsyncUdpSocket`]
/// trait uses `&self`. The KNX/IP stack never calls recv and send
/// concurrently on the same socket, so this is safe.
struct UdpInner {
    socket: RefCell<UdpSocket<'static>>,
    stack: Stack<'static>,
    local_port: u16,
}

impl UdpInner {
    fn bind_with_buffers(
        stack: Stack<'static>,
        bufs: &'static mut UdpBuffers,
        options: UdpSocketOptions,
    ) -> Result<Self, UdpError> {
        let mut socket =
            UdpSocket::new(stack, &mut bufs.rx_meta, &mut bufs.rx_buf, &mut bufs.tx_meta, &mut bufs.tx_buf);
        socket.bind(options.bind_addr.port()).map_err(|_| UdpError::BindError)?;
        Ok(Self { socket: RefCell::new(socket), stack, local_port: options.bind_addr.port() })
    }

    fn join_multicast(&self, group: Ipv4Addr) -> Result<(), UdpError> {
        self.stack.join_multicast_group(group).map_err(|_| UdpError::MulticastError)
    }

    fn leave_multicast(&self, group: Ipv4Addr) -> Result<(), UdpError> {
        self.stack.leave_multicast_group(group).map_err(|_| UdpError::MulticastError)
    }

    fn local_endpoint_v4(&self) -> SocketAddrV4 {
        let ip = self.stack.config_v4().map(|c| c.address.address()).unwrap_or(Ipv4Addr::UNSPECIFIED);
        SocketAddrV4::new(ip, self.local_port)
    }

    async fn recv_from_v4(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, SocketAddrV4, Option<Ipv4Addr>), UdpError> {
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

    async fn send_to_v4(&self, buf: &[u8], addr: SocketAddrV4) -> Result<usize, UdpError> {
        let ep = IpEndpoint::new(embassy_net::IpAddress::Ipv4(*addr.ip()), addr.port());
        self.socket.borrow().send_to(buf, ep).await.map_err(UdpError::SendError)?;
        Ok(buf.len())
    }
}

// ================================================================================
// EmbassyUdpSocket — used by EmbassyIpTransport<N_UDP>
// ================================================================================

/// UDP socket implementation backed by embassy-net.
///
/// `Context = EmbassyUdpContext<N>`, allocating from the binary-owned
/// [`UdpPool<N>`].
pub struct EmbassyUdpSocket<const N: usize> {
    inner: UdpInner,
}

impl<const N: usize> AsyncUdpSocket for EmbassyUdpSocket<N> {
    type Error = UdpError;
    type Context = EmbassyUdpContext<N>;

    fn bind(ctx: &Self::Context, options: UdpSocketOptions) -> Result<Self, Self::Error> {
        let bufs = ctx.udp_pool.alloc_slot();
        let inner = UdpInner::bind_with_buffers(ctx.stack, bufs, options)?;
        Ok(Self { inner })
    }

    fn join_multicast(&self, group: Ipv4Addr, _interface: Ipv4Addr) -> Result<(), Self::Error> {
        self.inner.join_multicast(group)
    }

    fn leave_multicast(&self, group: Ipv4Addr, _interface: Ipv4Addr) -> Result<(), Self::Error> {
        self.inner.leave_multicast(group)
    }

    fn set_broadcast(&self, _broadcast: bool) -> Result<(), Self::Error> {
        // Embassy-net doesn't have a per-socket broadcast flag.
        // Broadcast sending works by default.
        Ok(())
    }

    fn local_endpoint(&self) -> SocketAddrV4 {
        self.inner.local_endpoint_v4()
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV4, Option<Ipv4Addr>), Self::Error> {
        self.inner.recv_from_v4(buf).await
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddrV4) -> Result<usize, Self::Error> {
        self.inner.send_to_v4(buf, addr).await
    }
}

// ================================================================================
// EmbassyIpTransport — UDP only
// ================================================================================

/// IP transport for embassy-net based platforms — UDP only.
///
/// Used by binaries whose KNX/IP feature set is `NoTcp` (e.g. light
/// switches doing routing only). The `TcpListener` slot is filled by
/// [`NeverTcpListener`]; no TCP buffer pool is linked into the binary.
///
/// `N_UDP` is the size of the binary-owned [`UdpPool`]; the binary
/// passes `&pool` through [`EmbassyUdpContext`] to the link layer.
pub struct EmbassyIpTransport<const N_UDP: usize>;

impl<const N_UDP: usize> IpTransport for EmbassyIpTransport<N_UDP> {
    type UdpSocket = EmbassyUdpSocket<N_UDP>;
    type TcpListener = NeverTcpListener<EmbassyUdpContext<N_UDP>>;
    type TcpStream = NeverTcpStream;
}

// ================================================================================
// EmbassyUdpSocketTcp — used by EmbassyIpTransportTcp<N_UDP, N_TCP>
// ================================================================================

/// UDP socket variant used by [`EmbassyIpTransportTcp`].
///
/// Same buffer-pool / send-recv logic as [`EmbassyUdpSocket`], but
/// advertising the combined [`EmbassyTcpContext`] so it can satisfy
/// the `IpTransport` trait's shared-context constraint with the TCP
/// listener.
pub struct EmbassyUdpSocketTcp<const N_UDP: usize, const N_TCP: usize> {
    inner: UdpInner,
}

impl<const N_UDP: usize, const N_TCP: usize> AsyncUdpSocket for EmbassyUdpSocketTcp<N_UDP, N_TCP> {
    type Error = UdpError;
    type Context = EmbassyTcpContext<N_UDP, N_TCP>;

    fn bind(ctx: &Self::Context, options: UdpSocketOptions) -> Result<Self, Self::Error> {
        let bufs = ctx.udp_pool.alloc_slot();
        let inner = UdpInner::bind_with_buffers(ctx.stack, bufs, options)?;
        Ok(Self { inner })
    }

    fn join_multicast(&self, group: Ipv4Addr, _interface: Ipv4Addr) -> Result<(), Self::Error> {
        self.inner.join_multicast(group)
    }

    fn leave_multicast(&self, group: Ipv4Addr, _interface: Ipv4Addr) -> Result<(), Self::Error> {
        self.inner.leave_multicast(group)
    }

    fn set_broadcast(&self, _broadcast: bool) -> Result<(), Self::Error> {
        Ok(())
    }

    fn local_endpoint(&self) -> SocketAddrV4 {
        self.inner.local_endpoint_v4()
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV4, Option<Ipv4Addr>), Self::Error> {
        self.inner.recv_from_v4(buf).await
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddrV4) -> Result<usize, Self::Error> {
        self.inner.send_to_v4(buf, addr).await
    }
}

// ================================================================================
// EmbassyTcpListener / EmbassyTcpStream
// ================================================================================

/// TCP listener backed by embassy-net.
///
/// Embassy-net has no separate listener type — `TcpSocket::accept`
/// turns an existing socket into a one-shot listener bound to a port.
/// Our listener stores the bind config plus a `&'static TcpPool<N_TCP>`
/// reference taken from the context; each `accept()` allocates one
/// slot from the pool, builds a `TcpSocket` against its buffers, and
/// returns the connected socket as an [`EmbassyTcpStream`].
pub struct EmbassyTcpListener<const N_UDP: usize, const N_TCP: usize> {
    stack: Stack<'static>,
    pool: &'static TcpPool<N_TCP>,
    bind_addr: SocketAddrV4,
    _udp: core::marker::PhantomData<fn() -> [(); N_UDP]>,
}

/// Connected TCP stream returned by [`EmbassyTcpListener::accept`].
///
/// **Field order matters.** `socket` is declared first so it drops
/// first: smoltcp removes its handle and releases the buffer pointers
/// before `_guard` runs its `Drop` and re-marks the slot free. Rust
/// drops fields in declaration order (RFC 1857).
pub struct EmbassyTcpStream {
    socket: TcpSocket<'static>,
    _guard: PoolSlotGuard,
}

/// Error type for embassy-net TCP listener operations.
#[derive(Debug, defmt::Format)]
pub enum TcpError {
    /// Buffer pool exhausted (all `N_TCP` slots taken).
    OutOfSlots,
    /// embassy-net `accept` failed.
    Accept(AcceptError),
}

impl<const N_UDP: usize, const N_TCP: usize> AsyncTcpListener for EmbassyTcpListener<N_UDP, N_TCP> {
    type Error = TcpError;
    type Stream = EmbassyTcpStream;
    type Context = EmbassyTcpContext<N_UDP, N_TCP>;

    fn bind(ctx: &Self::Context, options: TcpListenerOptions) -> Result<Self, Self::Error> {
        // No socket is created at bind time; embassy-net allocates the
        // socket on each `accept()`. We capture the stack handle plus
        // the binary-owned pool here.
        Ok(Self {
            stack: ctx.stack,
            pool: ctx.tcp_pool,
            bind_addr: options.bind_addr,
            _udp: core::marker::PhantomData,
        })
    }

    async fn accept(&self) -> Result<(Self::Stream, SocketAddrV4), Self::Error> {
        let (guard, rx_buf, tx_buf) = self.pool.alloc_slot().ok_or(TcpError::OutOfSlots)?;
        let mut socket = TcpSocket::new(self.stack, rx_buf, tx_buf);
        socket.accept(self.bind_addr.port()).await.map_err(TcpError::Accept)?;

        // After a successful accept, `remote_endpoint` is populated.
        // Fall back to UNSPECIFIED if embassy-net surprises us — the
        // KNX/IP runtime only uses this for logging.
        let peer = match socket.remote_endpoint() {
            Some(IpEndpoint { addr: embassy_net::IpAddress::Ipv4(v4), port }) => SocketAddrV4::new(v4, port),
            _ => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        };

        Ok((EmbassyTcpStream { socket, _guard: guard }, peer))
    }

    fn local_endpoint(&self) -> SocketAddrV4 {
        self.bind_addr
    }
}

// embassy-net 0.8 bundles `embedded-io 0.7`, while the rest of the
// workspace is on `embedded-io 0.6`. Re-implement the v0.6 traits on
// top of embassy's `TcpSocket` rather than relying on its v0.7 impls —
// and wrap the v0.7 error in a local type that implements v0.6's
// `Error`.

/// v0.6-compatible error wrapper around [`embassy_net::tcp::Error`].
#[derive(Debug, defmt::Format)]
pub struct EmbassyTcpStreamError(pub embassy_net::tcp::Error);

impl embedded_io_async::Error for EmbassyTcpStreamError {
    fn kind(&self) -> embedded_io_async::ErrorKind {
        match self.0 {
            embassy_net::tcp::Error::ConnectionReset => embedded_io_async::ErrorKind::ConnectionReset,
        }
    }
}

impl embedded_io_async::ErrorType for EmbassyTcpStream {
    type Error = EmbassyTcpStreamError;
}

impl embedded_io_async::Read for EmbassyTcpStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.socket.read(buf).await.map_err(EmbassyTcpStreamError)
    }
}

impl embedded_io_async::Write for EmbassyTcpStream {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.socket.write(buf).await.map_err(EmbassyTcpStreamError)
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.socket.flush().await.map_err(EmbassyTcpStreamError)
    }
}

// ================================================================================
// EmbassyIpTransportTcp — UDP + real TCP
// ================================================================================

/// IP transport for embassy-net based platforms with a real TCP listener.
///
/// `N_UDP` and `N_TCP` are the sizes of the binary-owned
/// [`UdpPool`] and [`TcpPool`] respectively. Pick `N_TCP` to cover
/// the worst case of *concurrently open* TCP connections (e.g. one
/// per tunneling slot if every client opens its own stream rather
/// than multiplexing per 03/08/02).
pub struct EmbassyIpTransportTcp<const N_UDP: usize, const N_TCP: usize>;

impl<const N_UDP: usize, const N_TCP: usize> IpTransport for EmbassyIpTransportTcp<N_UDP, N_TCP> {
    type UdpSocket = EmbassyUdpSocketTcp<N_UDP, N_TCP>;
    type TcpListener = EmbassyTcpListener<N_UDP, N_TCP>;
    type TcpStream = EmbassyTcpStream;
}

// ================================================================================
// Tests
// ================================================================================

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// `static`-living pool used to satisfy the `&'static self` receiver
    /// on `alloc_slot` / `release` from a host-side test.
    static POOL: TcpPool<2> = TcpPool::new();

    #[test]
    fn alloc_then_release_then_realloc() {
        // Allocate slot 0, release it, allocate again — expect the
        // free-list to surface slot 0 a second time.
        let (g0, _, _) = POOL.alloc_slot().expect("slot 0");
        drop(g0);
        let (g0_again, _, _) = POOL.alloc_slot().expect("slot 0 reused");
        // Index isn't observable, but we know the pool now has only
        // one free slot left.
        let (g1, _, _) = POOL.alloc_slot().expect("slot 1");
        assert!(POOL.alloc_slot().is_none(), "pool should be exhausted");
        drop(g0_again);
        drop(g1);
        // After both drop, the pool is fully free again.
        let (_a, _, _) = POOL.alloc_slot().expect("free again after drops");
        let (_b, _, _) = POOL.alloc_slot().expect("free again after drops");
        assert!(POOL.alloc_slot().is_none(), "pool re-exhausted");
    }
}
