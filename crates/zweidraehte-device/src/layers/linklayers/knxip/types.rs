//! Shared protocol types for the KNX/IP link layer.
//!
//! These types are used across the entire link layer — by the event loop,
//! connection manager, connectionless services, feature traits, and builder.

use core::net::SocketAddrV4;

use embassy_sync::channel::DynamicSender;
use heapless::Vec;

use super::KnxNetIpContext;
use crate::layers::linklayers::address_check::DeviceAddressChecker;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::knx::DestinationAddress;
use zweidraehte_proto::messages::{
    buffers::{Buffer, DynBufferManager},
    builder::IndicationMessage,
    knx::KnxMessageBuffer,
    knxip::{KNXnetIPServiceType, substructs},
};

// ============================================================================
// Server Error
// ============================================================================

/// Error type for KNX/IP operations.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServerError {
    InvalidMessage,
    ParseError,
    Unsupported,
    InternalError,
    /// Server is busy/throttled and cannot process the request yet.
    /// The u16 value indicates how many milliseconds the caller should wait before retrying.
    Busy(u16),
    /// Frame APDU exceeds the configured maximum APDU length.
    /// Contains (received_length, max_allowed).
    FrameTooLarge(u16, u16),
}

// ============================================================================
// Response Target & Packet Origin
// ============================================================================

/// Where a response should be sent.
#[derive(Debug, Clone, Copy)]
pub enum ResponseTarget {
    /// Send as a UDP datagram to the given address on the given socket.
    Udp { destination: SocketAddrV4, socket_idx: usize },
    /// Write to an active TCP connection identified by its slot index.
    Tcp { tcp_idx: usize },
}

/// Origin of an incoming packet — allows the connection manager and
/// services to build a matching [`ResponseTarget`] without knowing
/// the transport details.
#[derive(Debug, Clone, Copy)]
pub enum PacketOrigin {
    /// Received as a UDP datagram.
    Udp {
        source: SocketAddrV4,
        socket_idx: usize,
        /// The local IP address the packet was addressed to. `None` if
        /// the platform doesn't report this. Used for unicast/multicast
        /// traffic type enforcement.
        destination: Option<core::net::Ipv4Addr>,
    },
    /// Received on a TCP connection.
    Tcp { peer: SocketAddrV4, tcp_idx: usize },
}

impl PacketOrigin {
    /// The peer's address, regardless of transport.
    pub fn peer_addr(&self) -> SocketAddrV4 {
        match *self {
            PacketOrigin::Udp { source, .. } => source,
            PacketOrigin::Tcp { peer, .. } => peer,
        }
    }

    /// Build a [`ResponseTarget`] that replies on the same transport.
    ///
    /// For UDP, the destination is the packet source address on the same
    /// socket. For TCP, it routes back on the same TCP connection.
    pub fn reply_target(&self) -> ResponseTarget {
        match *self {
            PacketOrigin::Udp { source, socket_idx, .. } => ResponseTarget::Udp { destination: source, socket_idx },
            PacketOrigin::Tcp { tcp_idx, .. } => ResponseTarget::Tcp { tcp_idx },
        }
    }
}

/// A response that is ready to be sent.
#[derive(Debug)]
pub struct PendingResponse {
    /// The buffer containing the response data.
    pub buffer: Buffer<'static>,

    /// Where to send this response.
    pub target: ResponseTarget,
}

// ============================================================================
// Server Context
// ============================================================================

/// Per-dispatch resources borrowed from one concrete device context.
///
/// A device has one provider implementation for its lifetime. Preserve that
/// type through services so fixed composition is monomorphized; values such
/// as addresses, keys and programming mode are still read live.
///
/// Service availability belongs to the runtime's feature slots. This bundle
/// carries providers and packet-local data without duplicating feature gates.
pub struct ServerContext<'a, CTX: KnxNetIpContext> {
    context: &'a CTX,
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    additional_addresses: &'a [IndividualAddress],
    tunneling_slot_info: Option<(u16, &'a [substructs::TunnelingSlotInfo])>,
    /// Index of the UDP socket on which this indication arrived.
    ///
    /// Services that send UDP responses must use this index so that replies
    /// leave on the same socket the request arrived on. When the device
    /// listens on multiple sockets (e.g. unicast + multicast), a response
    /// sourced from the wrong socket would carry the wrong local IP address
    /// and may be filtered by the client or the network.
    ///
    /// Currently the device always creates a single UDP socket, so this is
    /// always 0 in practice. The field is threaded through now so that
    /// multi-socket support can be enabled without changing the service API.
    pub socket_idx: usize,
    /// TCP stream index when this indication arrived over TCP, `None` for
    /// UDP.
    ///
    /// The control endpoint accepts both transports (03/08/02 §2.2), and a
    /// response must leave on the transport the request came in on: a client
    /// blocked reading its TCP stream never sees a UDP reply. Services that
    /// answer connectionlessly consult [`response_target`](Self::response_target)
    /// rather than assuming UDP.
    tcp_idx: Option<usize>,
}

impl<'a, CTX: KnxNetIpContext> ServerContext<'a, CTX> {
    /// Borrow the device context and this dispatch's channel and slot snapshot.
    pub fn new(
        context: &'a CTX,
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        additional_addresses: &'a [IndividualAddress],
        tunneling_slot_info: Option<(u16, &'a [substructs::TunnelingSlotInfo])>,
        socket_idx: usize,
    ) -> Self {
        Self { context, ind_tx, additional_addresses, tunneling_slot_info, socket_idx, tcp_idx: None }
    }

    /// Mark this indication as having arrived over the TCP stream `tcp_idx`.
    ///
    /// Left unset for UDP arrivals, which is the default.
    pub fn with_tcp_origin(mut self, tcp_idx: Option<usize>) -> Self {
        self.tcp_idx = tcp_idx;
        self
    }

    /// Where a connectionless response to this indication must be sent.
    ///
    /// Mirrors the request's transport: back down the originating TCP stream
    /// when the request arrived over TCP (03/08/02 §7.6 expects the
    /// DESCRIPTION_RESPONSE on the client's own TCP connection), otherwise to
    /// `destination` on the UDP socket the request arrived on.
    pub fn response_target(&self, destination: SocketAddrV4) -> ResponseTarget {
        match self.tcp_idx {
            Some(tcp_idx) => ResponseTarget::Tcp { tcp_idx },
            None => ResponseTarget::Udp { destination, socket_idx: self.socket_idx },
        }
    }

    /// Get the maximum APDU length this device can handle.
    pub fn max_apdu_length(&self) -> u16 {
        self.context.max_apdu_length()
    }

    /// Get the device info context. Services can call
    /// `device_info().device_information()` to build a fresh
    /// [`DeviceInformation`](zweidraehte_proto::messages::knxip::substructs::DeviceInformation) reflecting the current device state.
    pub fn device_info(&self) -> &CTX {
        self.context
    }

    /// Get the live IP diagnostics provider.
    pub fn ip_diagnostics(&self) -> &CTX {
        self.context
    }

    /// Get the IP configuration writer for the remote configuration service.
    pub fn ip_config_write(&self) -> &CTX {
        self.context
    }

    /// Get the restart publisher for the remote reset service.
    pub fn restart_ctx(&self) -> &CTX {
        self.context
    }

    /// Get additional individual addresses (tunneling slots).
    pub fn additional_individual_addresses(&self) -> &[IndividualAddress] {
        self.additional_addresses
    }

    /// Get the KNX address context for primary and tunneling addresses.
    pub fn knx_addresses(&self) -> &CTX {
        self.context
    }

    /// Get the tunneling slot info snapshot, if tunneling is enabled.
    ///
    /// Returns `(max_apdu_len, slots)` where each slot has an address
    /// and a status word (bit 0 = occupied).
    pub fn tunneling_slot_info(&self) -> Option<(u16, &[substructs::TunnelingSlotInfo])> {
        self.tunneling_slot_info
    }

    /// Apply the same live destination policy used by TP1 and RF.
    pub fn accepts_destination(&self, dest: DestinationAddress) -> bool {
        DeviceAddressChecker::new(self.context).accepts_destination(dest)
    }

    /// Get the KNX IP Secure configuration view, if the device is secure.
    pub fn ip_secure(&self) -> Option<&CTX::SecureState> {
        self.context.ip_secure_view()
    }

    /// Send an indication to the network layer (L_Data.ind).
    pub async fn send_to_network_layer(&self, message: KnxMessageBuffer<Buffer<'static>>) {
        let indication = IndicationMessage::indication(message);
        self.ind_tx.send(indication).await;
    }

    /// Allocate a buffer for responses.
    pub async fn alloc_buffer(&self) -> Buffer<'static> {
        self.context.buffer_manager().alloc().await
    }

    /// Get direct access to the buffer manager.
    pub fn buffer_manager(&self) -> &DynBufferManager<'static> {
        self.context.buffer_manager()
    }
}

// ============================================================================
// HPAI Resolution
// ============================================================================

/// Resolve an HPAI to a destination address, using the packet source when
/// the HPAI address is unspecified (`0.0.0.0`). The HPAI port is always
/// used — only the IP address is substituted.
///
/// Per KNX spec 3/8/2 §8.6.3.3: when a client sends a control HPAI with
/// IP address 0.0.0.0 and/or port 0, the server shall use the corresponding
/// values from the IP source address of the received request packet.
/// This supports NAT traversal scenarios where the client cannot know its
/// externally visible address/port.
pub(crate) fn resolve_hpai(
    hpai: &zweidraehte_proto::messages::knxip::substructs::HPAI,
    packet_source: SocketAddrV4,
) -> SocketAddrV4 {
    let addr = hpai.address();
    let ip = if addr.is_unspecified() { *packet_source.ip() } else { addr };
    let port = if hpai.port() == 0 { packet_source.port() } else { hpai.port() };
    SocketAddrV4::new(ip, port)
}

// ============================================================================
// KnxNetIpServer Trait
// ============================================================================

/// Trait that all connectionless KNX/IP services implement.
pub(crate) trait KnxNetIpServer {
    /// Handle KNX/IP message received from the network.
    ///
    /// # Arguments
    /// * `service_type` - The KNX/IP service type
    /// * `data` - Raw message payload (without KNX/IP header)
    /// * `source` - Source address of the packet
    /// * `context` - Provides access to buffer manager and network layer channel
    ///
    /// # Returns
    /// * `Ok(responses)` - Vector of responses to send (can be 0, 1, or multiple)
    /// * `Err(e)` - Error handling the message
    async fn on_indication<'a>(
        &mut self,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        source: SocketAddrV4,
        context: &ServerContext<'a, impl KnxNetIpContext>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError>;

    /// Handle KNX message from the stack that needs to be transmitted.
    ///
    /// # Arguments
    /// * `message` - The KNX message to transmit
    /// * `context` - Provides access to buffer manager and network layer channel
    ///
    /// # Returns
    /// * `Ok(responses)` - Vector of KNX/IP packets to send
    /// * `Err(e)` - Error handling the message
    async fn on_request<'a>(
        &mut self,
        message: &KnxMessageBuffer<Buffer<'static>>,
        context: &ServerContext<'a, impl KnxNetIpContext>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError>;
}
