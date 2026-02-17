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

use platform::{AsyncUdpSocket, IpTransport, UdpSocketOptions};

use crate::messages::buffers::{Buffer, DynBufferManager, MessageBuffer};

use super::EndpointType;

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
/// [`TcpManager::next_event()`](super::tcp_manager::TcpManager::next_event)
/// and a [`send_to()`](Self::send_to) method for outbound datagrams.
pub struct UdpManager<T: IpTransport, const MAX_SOCKETS: usize> {
    sockets: [Option<T::UdpSocket>; MAX_SOCKETS],
    descriptors: Vec<SocketDescriptor, MAX_SOCKETS>,
    /// Local IP address for filtering out our own multicast echoes.
    local_addr: Ipv4Addr,
}

impl<T: IpTransport, const MAX_SOCKETS: usize> UdpManager<T, MAX_SOCKETS> {
    /// Create a new UDP manager with pre-built socket descriptors.
    ///
    /// Sockets are not yet bound; call [`bind_all()`](Self::bind_all)
    /// to create and configure them.
    pub fn new(local_addr: Ipv4Addr, descriptors: Vec<SocketDescriptor, MAX_SOCKETS>) -> Self {
        Self {
            sockets: core::array::from_fn(|_| None),
            descriptors,
            local_addr,
        }
    }

    /// Bind all sockets based on the stored descriptors.
    ///
    /// For each descriptor, creates a UDP socket, joins multicast groups,
    /// and enables broadcast as specified. Sockets that fail to bind are
    /// logged and left as `None`; the manager remains usable with the
    /// remaining sockets.
    pub fn bind_all(
        &mut self,
        socket_ctx: &<T::UdpSocket as platform::AsyncUdpSocket>::Context,
        interface_name: &'static str,
        interface_addr: Ipv4Addr,
    ) {
        for (i, desc) in self.descriptors.iter().enumerate() {
            let port = desc.port();

            let options = UdpSocketOptions {
                address: Ipv4Addr::UNSPECIFIED,
                port,
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
        self.descriptors.len()
    }

    /// Get socket descriptors (needed for server-to-socket mapping).
    pub fn descriptors(&self) -> &[SocketDescriptor] {
        &self.descriptors
    }

    /// Send a datagram on a specific socket.
    pub async fn send_to(&self, socket_idx: usize, data: &[u8], destination: SocketAddrV4) -> Result<(), ()> {
        trace!("KNX/IP TX {} bytes on socket {} to {}: {:?}", data.len(), socket_idx, destination, crate::fmt::Bytes(data));

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
    pub async fn next_event(&self, buffer_manager: &RefCell<DynBufferManager<'static>>) -> UdpEvent {
        if self.descriptors.is_empty() {
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
                        let mut buffer = bm.borrow().alloc().await;
                        buffer.resize(buffer.capacity(), 0);
                        match socket.recv_from(&mut buffer[..]).await {
                            Ok((len, source)) => {
                                trace!(
                                    "KNX/IP RX {} bytes on socket {} from {}: {:?}",
                                    len,
                                    socket_idx,
                                    source,
                                    crate::fmt::Bytes(&buffer[..len])
                                );
                                buffer.set_len(len);
                                Ok((buffer, source))
                            }
                            Err(e) => {
                                error!("Failed to receive on socket {}: {:?}", socket_idx, e);
                                Err(())
                            }
                        }
                    } else {
                        // Socket failed to bind — pend forever so this
                        // slot is ignored by select_slice.
                        core::future::pending::<Result<(Buffer<'static>, SocketAddrV4), ()>>().await
                    }
                }
            };

            let mut socket_futures = Vec::<_, MAX_SOCKETS>::new();
            for i in 0..self.descriptors.len() {
                let _ = socket_futures.push(recv(i));
            }

            // SAFETY: socket_futures is a local variable that won't be moved after pinning.
            let (result, socket_idx) = select_slice(unsafe { Pin::new_unchecked(socket_futures.as_mut_slice()) }).await;

            match result {
                Ok((buffer, source)) => {
                    // Filter multicast echoes: packets originating from
                    // our own address are dropped silently.
                    if *source.ip() == self.local_addr {
                        debug!("KNX/IP ignoring own multicast echo: {}", source);
                        // Buffer is dropped here (returned to the pool),
                        // loop back to rebuild futures and poll again.
                        continue;
                    }

                    debug!("Received {} bytes on socket {} from {}", buffer.len(), socket_idx, source);
                    return UdpEvent::Frame { socket_idx, source, buffer };
                }
                Err(()) => {
                    return UdpEvent::Error { socket_idx };
                }
            }
        }
    }
}
