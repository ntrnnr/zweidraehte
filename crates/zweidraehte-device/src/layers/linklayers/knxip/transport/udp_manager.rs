//! UDP socket manager for KNX/IP.
//!
//! Owns the UDP socket handles and their descriptors (multicast groups,
//! broadcast flags, bind addresses). Presents a unified event interface
//! via [`UdpManager::next_event()`] that the main loop `select`s alongside
//! [`TcpManager::next_event()`].
//!
//! All public methods take `&self` because the underlying socket operations
//! (`recv_from`, `send_to`) only require shared references. This avoids
//! borrow conflicts in the main loop where a `next_event` future coexists
//! with `send_to` calls triggered by response draining.

use core::cell::RefCell;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::pin::Pin;

use embassy_futures::select::select_slice;
use heapless::Vec;

use zweidraehte_platform::{AsyncUdpSocket, IpTransport, UdpSocketOptions};

use zweidraehte_proto::messages::buffers::{Buffer, DynBufferManager, MessageBuffer};

use super::super::EndpointType;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of multicast groups per socket.
const MAX_MULTICAST_GROUPS: usize = 2;

// ============================================================================
// Socket descriptor
// ============================================================================

/// Metadata about a UDP socket: what it's bound to, which multicast
/// groups it has joined, and whether broadcast is enabled.
#[derive(Debug, Clone)]
pub struct SocketDescriptor {
    /// The endpoint this socket is bound to (typically 0.0.0.0:port).
    bind_endpoint: EndpointType,

    /// Multicast groups joined on this socket.
    multicast_groups: Vec<Ipv4Addr, MAX_MULTICAST_GROUPS>,

    /// Whether broadcast is enabled on this socket.
    broadcast_enabled: bool,
}

impl SocketDescriptor {
    /// Create a new socket descriptor.
    pub const fn new(bind_endpoint: EndpointType) -> Self {
        Self { bind_endpoint, multicast_groups: Vec::new(), broadcast_enabled: false }
    }

    /// Get the bind endpoint.
    #[allow(dead_code)] // Future: not yet used
    pub fn bind_endpoint(&self) -> &EndpointType {
        &self.bind_endpoint
    }

    /// Get the port this socket is bound to.
    pub fn port(&self) -> u16 {
        self.bind_endpoint.port()
    }

    /// Add a multicast group to join.
    pub fn add_multicast_group(&mut self, addr: Ipv4Addr) -> Result<(), ()> {
        if !self.multicast_groups.contains(&addr) { self.multicast_groups.push(addr).map_err(|_| ()) } else { Ok(()) }
    }

    /// Remove a multicast group from the joined set.
    ///
    /// Returns `true` if the group was present and removed. Used by
    /// runtime rebind (03/02/06 §4.3.5.3.5.1) to keep the descriptor
    /// in sync with the socket's actual OS-level membership after
    /// `leave_multicast`.
    pub fn remove_multicast_group(&mut self, addr: Ipv4Addr) -> bool {
        let before = self.multicast_groups.len();
        self.multicast_groups.retain(|&a| a != addr);
        self.multicast_groups.len() != before
    }

    /// Enable broadcast on this socket.
    pub fn enable_broadcast(&mut self) {
        self.broadcast_enabled = true;
    }

    /// Check if broadcast is enabled.
    pub fn is_broadcast_enabled(&self) -> bool {
        self.broadcast_enabled
    }

    /// Get the multicast groups.
    pub fn multicast_groups(&self) -> &[Ipv4Addr] {
        &self.multicast_groups
    }
}

// ============================================================================
// UDP events
// ============================================================================

/// Event produced by the UDP manager for the main event loop.
pub enum UdpEvent {
    /// A complete UDP datagram was received on a socket.
    Frame {
        socket_idx: usize,
        source: SocketAddrV4,
        /// The local IP address the packet was addressed to (destination IP
        /// from the sender's perspective). `None` if the platform doesn't
        /// report this information. Used to distinguish unicast from
        /// multicast traffic.
        destination: Option<Ipv4Addr>,
        buffer: Buffer<'static>,
    },
    /// A receive error occurred on a socket. Non-fatal; the socket
    /// remains usable.
    Error { socket_idx: usize },
}

// ============================================================================
// UDP Manager
// ============================================================================

/// Manages UDP sockets for KNX/IP.
///
/// Owns the socket handles and their descriptors. Provides a
/// [`next_event()`](Self::next_event) interface analogous to
/// [`TcpManager::next_event()`](tcp_manager::TcpManager::next_event)
/// and a [`send_to()`](Self::send_to) method for outbound datagrams.
pub struct UdpManager<T: IpTransport, const MAX_SOCKETS: usize> {
    sockets: [Option<T::UdpSocket>; MAX_SOCKETS],
    /// `RefCell` lets the runtime rebind (03/02/06 §4.3.5.3.5.1)
    /// update joined-group bookkeeping through `&self`. Borrows are
    /// brief: `next_event` never touches `descriptors`, so the
    /// rebind path and the event loop cannot contend.
    descriptors: RefCell<Vec<SocketDescriptor, MAX_SOCKETS>>,
    /// Local IP address for filtering out our own multicast echoes.
    local_addr: Ipv4Addr,
}

impl<T: IpTransport, const MAX_SOCKETS: usize> UdpManager<T, MAX_SOCKETS> {
    /// Create a new UDP manager with pre-built socket descriptors.
    ///
    /// Sockets are not yet bound; call [`bind_all()`](Self::bind_all)
    /// to create and configure them.
    pub fn new(local_addr: Ipv4Addr, descriptors: Vec<SocketDescriptor, MAX_SOCKETS>) -> Self {
        Self { sockets: core::array::from_fn(|_| None), descriptors: RefCell::new(descriptors), local_addr }
    }

    /// Bind all sockets based on the stored descriptors.
    ///
    /// For each descriptor, creates a UDP socket, joins multicast groups,
    /// and enables broadcast as specified. Sockets that fail to bind are
    /// logged and left as `None`; the manager remains usable with the
    /// remaining sockets.
    pub fn bind_all(
        &mut self,
        socket_ctx: &<T::UdpSocket as zweidraehte_platform::AsyncUdpSocket>::Context,
        interface_name: &'static str,
        interface_addr: Ipv4Addr,
    ) {
        // `get_mut` on `&mut RefCell<T>` gives `&mut T` with no borrow
        // tracking — ideal for one-shot startup that doesn't race
        // with the runtime loop yet.
        let descriptors = self.descriptors.get_mut();
        for (i, desc) in descriptors.iter().enumerate() {
            let port = desc.port();

            let options = UdpSocketOptions {
                bind_addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
                interface: Some(interface_name),
                ..Default::default()
            };

            match T::UdpSocket::bind(socket_ctx, options) {
                Ok(socket) => {
                    for &mcast_addr in desc.multicast_groups() {
                        debug!(
                            "  Socket {}: Joining multicast group {} on interface {}",
                            i, mcast_addr, interface_name
                        );
                        if let Err(e) = socket.join_multicast(mcast_addr, interface_addr) {
                            error!("Failed to join multicast group {}: {:?}", mcast_addr, e);
                        }
                    }

                    if desc.is_broadcast_enabled() {
                        debug!("  Socket {}: Enabling SO_BROADCAST", i);
                        let _ = socket.set_broadcast(true);
                    }

                    info!("  Socket {}: Bound to 0.0.0.0:{} on interface {}", i, port, interface_name);
                    self.sockets[i] = Some(socket);
                }
                Err(e) => {
                    error!("Failed to create socket for port {}: {:?}", port, e);
                }
            }
        }
    }

    /// Number of socket descriptors (bound or not).
    pub fn socket_count(&self) -> usize {
        self.descriptors.borrow().len()
    }

    /// Snapshot-copy the current descriptor list. Returns a
    /// heap-free `Vec` with the same capacity; inexpensive because
    /// `MAX_SOCKETS` is tiny (≤ 4 in practice).
    #[allow(dead_code)] // Future: not yet used
    pub fn descriptors(&self) -> Vec<SocketDescriptor, MAX_SOCKETS> {
        self.descriptors.borrow().clone()
    }

    /// Rebind the routing multicast group on every socket bound to
    /// `KNX_PORT` (03/02/06 §4.3.5.3.5.1).
    ///
    /// The manager is the source of truth for which non-System-Setup
    /// groups are currently joined, so callers only pass the target:
    /// we discover the previous group from our own descriptor state.
    ///
    /// For each socket bound to `KNX_PORT`:
    ///
    /// 1. Find the joined group that isn't
    ///    [`SYSTEM_SETUP_MULTICAST_ADDRESS`] — that's the current
    ///    routing group. The System Setup group is **never** left
    ///    (03/02/06 §4.1.3: Discovery, Remote Config and IP System
    ///    Broadcast all rely on it).
    /// 2. If that group is `new` already, skip — nothing to do.
    /// 3. Otherwise `leave_multicast` the old group (if any) and
    ///    `join_multicast` the new one, keeping the descriptor's
    ///    group list in sync.
    ///
    /// Errors from individual socket operations are logged but do
    /// not abort the rebind — the join still proceeds even if the
    /// leave fails, and vice versa.
    pub fn rebind_routing_multicast(&self, new: Ipv4Addr, interface: Ipv4Addr) {
        let mut descriptors = self.descriptors.borrow_mut();

        for (i, desc) in descriptors.iter_mut().enumerate() {
            if desc.port() != crate::KNX_PORT {
                continue;
            }

            let Some(socket) = self.sockets[i].as_ref() else {
                continue;
            };

            // The "current routing group" is whatever non-System-Setup
            // entry is in the descriptor. At most one exists in
            // practice: `bind_all` joins either just System Setup (for
            // default config) or System Setup plus one routing group.
            let current = desc.multicast_groups().iter().copied().find(|&a| a != crate::SYSTEM_SETUP_MULTICAST_ADDRESS);

            if current == Some(new) {
                continue;
            }

            if let Some(old) = current {
                if let Err(e) = socket.leave_multicast(old, interface) {
                    warn!("KNX/IP socket {}: leave_multicast({}) failed: {:?}", i, old, e);
                }
                desc.remove_multicast_group(old);
            }

            if new != crate::SYSTEM_SETUP_MULTICAST_ADDRESS && !desc.multicast_groups().contains(&new) {
                match socket.join_multicast(new, interface) {
                    Ok(()) => {
                        let _ = desc.add_multicast_group(new);
                        info!("KNX/IP socket {}: joined multicast group {}", i, new);
                    }
                    Err(e) => {
                        error!("KNX/IP socket {}: join_multicast({}) failed: {:?}", i, new, e);
                    }
                }
            }
        }
    }

    /// Send a datagram on a specific socket.
    pub async fn send_to(&self, socket_idx: usize, data: &[u8], destination: SocketAddrV4) -> Result<(), ()> {
        trace!(
            "KNX/IP TX {} bytes on socket {} to {}: {:?}",
            data.len(),
            socket_idx,
            destination,
            zweidraehte_util::fmt::Bytes(data)
        );

        if let Some(Some(socket)) = self.sockets.get(socket_idx) {
            match socket.send_to(data, destination).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!("Failed to send on socket {}: {:?}", socket_idx, e);
                    Err(())
                }
            }
        } else {
            error!("Socket {} not available", socket_idx);
            Err(())
        }
    }

    /// Wait for the next UDP event from any bound socket.
    ///
    /// Receives from all sockets concurrently using `select_slice`.
    /// Multicast echoes (packets from our own local address) are silently
    /// filtered — the method loops internally until a non-echo packet
    /// arrives.
    ///
    /// Pends forever if no sockets are bound.
    pub async fn next_event(&self, buffer_manager: &DynBufferManager<'static>) -> UdpEvent {
        if self.descriptors.borrow().is_empty() {
            // No sockets to poll — pend forever so the select in the
            // main loop naturally falls through to TCP or other arms.
            core::future::pending::<UdpEvent>().await;
            unreachable!();
        }

        loop {
            // Build a receive future for each socket slot. Slots without
            // a bound socket pend forever, so select_slice ignores them.
            let recv = |socket_idx: usize| {
                let bm = buffer_manager;
                async move {
                    if let Some(Some(socket)) = self.sockets.get(socket_idx) {
                        let mut buffer = bm.alloc().await;
                        buffer.resize(buffer.capacity(), 0);
                        match socket.recv_from(&mut buffer[..]).await {
                            Ok((len, source, destination)) => {
                                trace!(
                                    "KNX/IP RX {} bytes on socket {} from {} (dest {:?}): {:?}",
                                    len,
                                    socket_idx,
                                    source,
                                    destination,
                                    zweidraehte_util::fmt::Bytes(&buffer[..len])
                                );
                                buffer.set_len(len);
                                Ok((buffer, source, destination))
                            }
                            Err(e) => {
                                error!("Failed to receive on socket {}: {:?}", socket_idx, e);
                                Err(())
                            }
                        }
                    } else {
                        // Socket failed to bind — pend forever so this
                        // slot is ignored by select_slice.
                        core::future::pending::<Result<(Buffer<'static>, SocketAddrV4, Option<Ipv4Addr>), ()>>().await
                    }
                }
            };

            let mut socket_futures = Vec::<_, MAX_SOCKETS>::new();
            let descriptor_count = self.descriptors.borrow().len();
            for i in 0..descriptor_count {
                let _ = socket_futures.push(recv(i));
            }

            // SAFETY: socket_futures is a local variable that won't be moved after pinning.
            let (result, socket_idx) = select_slice(unsafe { Pin::new_unchecked(socket_futures.as_mut_slice()) }).await;

            match result {
                Ok((buffer, source, destination)) => {
                    // Filter multicast echoes: packets originating from
                    // our own address are dropped silently.
                    if *source.ip() == self.local_addr {
                        debug!("KNX/IP ignoring own multicast echo: {}", source);
                        // Buffer is dropped here (returned to the pool),
                        // loop back to rebuild futures and poll again.
                        continue;
                    }

                    debug!(
                        "Received {} bytes on socket {} from {} (dest {:?})",
                        buffer.len(),
                        socket_idx,
                        source,
                        destination
                    );
                    return UdpEvent::Frame { socket_idx, source, destination, buffer };
                }
                Err(()) => {
                    return UdpEvent::Error { socket_idx };
                }
            }
        }
    }
}

// ============================================================================
// Unit tests for rebind_routing_multicast
// ============================================================================
//
// The rebind logic must be exercised in isolation from real sockets.
// A test-only `MockUdpSocket` records every `join_multicast` and
// `leave_multicast` call into a shared log; the assertions then
// verify the expected sequence across the four scenarios listed in
// the plan (start from SYSTEM_SETUP, start from non-default, rotate
// between two non-defaults, redundant no-op).

#[cfg(test)]
mod rebind_tests {
    use super::*;
    use alloc::rc::Rc;
    use alloc::vec;
    use alloc::vec::Vec as StdVec;
    use core::cell::RefCell;
    use zweidraehte_platform::{AsyncTcpListener, IpTransport, NeverTcpListener, NeverTcpStream};

    extern crate alloc;

    const IFACE: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const SYS: Ipv4Addr = crate::SYSTEM_SETUP_MULTICAST_ADDRESS;
    const ALT_A: Ipv4Addr = Ipv4Addr::new(239, 0, 0, 1);
    const ALT_B: Ipv4Addr = Ipv4Addr::new(239, 0, 0, 2);

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Op {
        Join(Ipv4Addr),
        Leave(Ipv4Addr),
    }

    #[derive(Debug)]
    struct MockUdpSocket {
        log: Rc<RefCell<StdVec<Op>>>,
    }

    #[derive(Debug)]
    struct MockError;

    impl AsyncUdpSocket for MockUdpSocket {
        type Error = MockError;
        type Context = Rc<RefCell<StdVec<Op>>>;

        fn bind(ctx: &Self::Context, _options: UdpSocketOptions) -> Result<Self, Self::Error> {
            Ok(MockUdpSocket { log: Rc::clone(ctx) })
        }

        fn join_multicast(&self, group: Ipv4Addr, _interface: Ipv4Addr) -> Result<(), Self::Error> {
            self.log.borrow_mut().push(Op::Join(group));
            Ok(())
        }

        fn leave_multicast(&self, group: Ipv4Addr, _interface: Ipv4Addr) -> Result<(), Self::Error> {
            self.log.borrow_mut().push(Op::Leave(group));
            Ok(())
        }

        fn set_broadcast(&self, _broadcast: bool) -> Result<(), Self::Error> {
            Ok(())
        }

        fn local_endpoint(&self) -> SocketAddrV4 {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, crate::KNX_PORT)
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddrV4, Option<Ipv4Addr>), Self::Error> {
            // Never polled in these tests.
            core::future::pending().await
        }

        async fn send_to(&self, _buf: &[u8], _addr: SocketAddrV4) -> Result<usize, Self::Error> {
            unreachable!("send_to not used in rebind tests")
        }
    }

    struct MockTransport;

    impl IpTransport for MockTransport {
        type UdpSocket = MockUdpSocket;
        type TcpListener = NeverTcpListener;
        type TcpStream = NeverTcpStream;
    }

    /// Build a `UdpManager` with a single socket on `KNX_PORT`
    /// pre-joined to `initial_groups`, with `log` capturing future
    /// join/leave calls. Prior calls made during `bind_all` are
    /// drained from the log before the test resumes.
    fn setup(initial_groups: &[Ipv4Addr]) -> (UdpManager<MockTransport, 4>, Rc<RefCell<StdVec<Op>>>) {
        let log: Rc<RefCell<StdVec<Op>>> = Rc::new(RefCell::new(StdVec::new()));

        let mut descriptors = Vec::<SocketDescriptor, 4>::new();
        let mut desc = SocketDescriptor::new(EndpointType::new(Ipv4Addr::UNSPECIFIED, crate::KNX_PORT));
        for g in initial_groups {
            let _ = desc.add_multicast_group(*g);
        }
        let _ = descriptors.push(desc);

        let mut mgr = UdpManager::<MockTransport, 4>::new(IFACE, descriptors);
        mgr.bind_all(&log, "lo", IFACE);

        // Forget joins recorded during bind_all; the tests only care
        // about what `rebind_routing_multicast` emits.
        log.borrow_mut().clear();

        (mgr, log)
    }

    fn joined_groups(mgr: &UdpManager<MockTransport, 4>) -> StdVec<Ipv4Addr> {
        mgr.descriptors.borrow()[0].multicast_groups().iter().copied().collect()
    }

    #[test]
    fn rebind_from_system_setup_only_joins_new() {
        let (mgr, log) = setup(&[SYS]);
        mgr.rebind_routing_multicast(ALT_A, IFACE);
        // No prior non-default group, so only a join is recorded.
        assert_eq!(*log.borrow(), vec![Op::Join(ALT_A)]);
        assert_eq!(joined_groups(&mgr), vec![SYS, ALT_A]);
    }

    #[test]
    fn rebind_back_to_system_setup_only_leaves_old() {
        let (mgr, log) = setup(&[SYS, ALT_A]);
        mgr.rebind_routing_multicast(SYS, IFACE);
        // Target is SYS (already joined) — we just drop ALT_A.
        assert_eq!(*log.borrow(), vec![Op::Leave(ALT_A)]);
        assert_eq!(joined_groups(&mgr), vec![SYS]);
    }

    #[test]
    fn rebind_between_non_defaults_leaves_then_joins() {
        let (mgr, log) = setup(&[SYS, ALT_A]);
        mgr.rebind_routing_multicast(ALT_B, IFACE);
        assert_eq!(*log.borrow(), vec![Op::Leave(ALT_A), Op::Join(ALT_B)]);
        assert_eq!(joined_groups(&mgr), vec![SYS, ALT_B]);
    }

    #[test]
    fn rebind_to_same_address_is_noop() {
        let (mgr, log) = setup(&[SYS, ALT_A]);
        mgr.rebind_routing_multicast(ALT_A, IFACE);
        assert!(log.borrow().is_empty());
        assert_eq!(joined_groups(&mgr), vec![SYS, ALT_A]);
    }
}
