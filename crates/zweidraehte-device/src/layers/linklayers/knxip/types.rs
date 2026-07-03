//! Shared protocol types for the KNX/IP link layer.
//!
//! These types are used across the entire link layer — by the event loop,
//! connection manager, connectionless services, feature traits, and builder.

use core::net::SocketAddrV4;

use embassy_sync::channel::DynamicSender;
use heapless::Vec;

use core::cell::RefCell;

use crate::context::IndividualAddressContext;
use crate::layers::linklayers::knxip::context::{
    DeviceInfoContext, IpConfigWriteContext, IpDiagnosticsContext, RemoteRestartContext,
};
use crate::objects::tables::{AddressTable, HasLoadStateMachine};
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
// Address Filter
// ============================================================================

/// Determines whether an incoming frame should be accepted by the local
/// device stack, based on its destination address.
///
/// This is the KNX/IP equivalent of TPUART's `AddressChecker` — it filters
/// incoming multicast routing frames by destination address before they
/// reach the network layer. Unlike `AddressChecker`, which operates on raw
/// TP1 header bytes, this trait works with already-parsed addresses.
pub trait AddressFilter {
    fn accepts(&self, dest: DestinationAddress) -> bool;
}

/// Address filter for KNX/IP routing devices.
///
/// Accepts frames addressed to the device's individual address, group
/// addresses present in the loaded address table, and broadcasts. This
/// is the same logic as `DeviceAddressChecker::should_ack` for TPUART.
pub struct RoutingAddressFilter<'a, ADT> {
    individual_address: IndividualAddress,
    address_table: &'a RefCell<ADT>,
}

impl<'a, ADT> RoutingAddressFilter<'a, ADT> {
    pub fn new(individual_address: IndividualAddress, address_table: &'a RefCell<ADT>) -> Self {
        Self { individual_address, address_table }
    }
}

impl<ADT: AddressTable + HasLoadStateMachine> AddressFilter for RoutingAddressFilter<'_, ADT> {
    fn accepts(&self, dest: DestinationAddress) -> bool {
        match dest {
            DestinationAddress::Individual(addr) => addr == self.individual_address,
            DestinationAddress::Group(ga) => {
                let table = self.address_table.borrow();
                table.is_loaded() && (table.entry_count() == 0 || table.contains(ga))
            }
            DestinationAddress::Broadcast | DestinationAddress::SystemBroadcast => true,
            // ConnectionNr is an internal TSAP index used between the application
            // and transport layers — it never reaches the link layer address filter.
            DestinationAddress::ConnectionNr(_) => false,
        }
    }
}

// ============================================================================
// Server Context
// ============================================================================

/// Context provided to services and the connection manager for accessing
/// stack resources.
///
/// Constructed fresh on every dispatch from [`KnxNetIp`](super::runtime::KnxNetIp)'s
/// context reference. Services access device information, IP diagnostics,
/// and KNX addresses through the individual context trait accessors.
pub struct ServerContext<'a> {
    /// Buffer manager for allocating message buffers.
    buffer_manager: &'a DynBufferManager<'static>,
    /// Channel to send indications up to the network layer.
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    /// Maximum APDU length this device can handle.
    max_apdu_length: u16,
    /// Device info context for building `DeviceInformation` on demand.
    device_info: &'a dyn DeviceInfoContext,
    /// IP diagnostics context for remote config responses.
    /// Present when remote config server is enabled.
    ip_diagnostics: Option<&'a dyn IpDiagnosticsContext>,
    /// IP configuration write side, for `REMOTE_BASIC_CONFIGURATION_REQUEST`.
    /// Present when the remote config server is enabled (same gate as
    /// `ip_diagnostics`).
    ip_config_write: Option<&'a dyn IpConfigWriteContext>,
    /// Restart-request publisher, for `REMOTE_RESET_REQUEST`. Present when
    /// the remote config server is enabled.
    restart_ctx: Option<&'a dyn RemoteRestartContext>,
    /// Additional individual addresses (tunneling slots), borrowed from
    /// a caller-owned buffer with the correct capacity `N`.
    additional_addresses: &'a [IndividualAddress],
    /// KNX address context for primary + tunneling addresses.
    knx_addresses: &'a dyn IndividualAddressContext,
    /// Snapshot of tunneling slot status from the connection manager.
    /// Present when a tunneling handler is registered. Used by the
    /// discovery server to build the TunnelingInfo DIB.
    tunneling_slot_info: Option<(u16, &'a [substructs::TunnelingSlotInfo])>,
    /// Address filter for incoming routing frames. When present, frames
    /// not addressed to this device are silently dropped before reaching
    /// the network layer. `None` for tunneling-only servers that forward
    /// all traffic.
    address_filter: Option<&'a dyn AddressFilter>,
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
    /// KNX IP Secure configuration (PIDs 91–97), for the discovery
    /// server's SecuredServiceFamilies DIB. `None` on non-secure devices.
    ip_secure: Option<&'a dyn crate::ip::IpSecureStateView>,
}

impl<'a> ServerContext<'a> {
    /// Create a new server context.
    pub fn new(
        buffer_manager: &'a DynBufferManager<'static>,
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        max_apdu_length: u16,
        device_info: &'a dyn DeviceInfoContext,
        ip_diagnostics: Option<&'a dyn IpDiagnosticsContext>,
        ip_config_write: Option<&'a dyn IpConfigWriteContext>,
        restart_ctx: Option<&'a dyn RemoteRestartContext>,
        additional_addresses: &'a [IndividualAddress],
        knx_addresses: &'a dyn IndividualAddressContext,
        tunneling_slot_info: Option<(u16, &'a [substructs::TunnelingSlotInfo])>,
        address_filter: Option<&'a dyn AddressFilter>,
        socket_idx: usize,
        ip_secure: Option<&'a dyn crate::ip::IpSecureStateView>,
    ) -> Self {
        Self {
            buffer_manager,
            ind_tx,
            max_apdu_length,
            device_info,
            ip_diagnostics,
            ip_config_write,
            restart_ctx,
            additional_addresses,
            knx_addresses,
            tunneling_slot_info,
            address_filter,
            socket_idx,
            ip_secure,
        }
    }

    /// Get the maximum APDU length this device can handle.
    pub fn max_apdu_length(&self) -> u16 {
        self.max_apdu_length
    }

    /// Get the device info context. Services can call
    /// `device_info().device_information()` to build a fresh
    /// [`DeviceInformation`](zweidraehte_proto::messages::knxip::substructs::DeviceInformation) reflecting the current device state.
    pub fn device_info(&self) -> &dyn DeviceInfoContext {
        self.device_info
    }

    /// Get the IP diagnostics context, if available.
    ///
    /// Returns `None` if the remote config server is not enabled.
    pub fn ip_diagnostics(&self) -> Option<&dyn IpDiagnosticsContext> {
        self.ip_diagnostics
    }

    /// Get the IP configuration write context, if available.
    ///
    /// Returns `None` if the remote config server is not enabled. Used by
    /// `REMOTE_BASIC_CONFIGURATION_REQUEST` to apply incoming IP config DIBs.
    pub fn ip_config_write(&self) -> Option<&dyn IpConfigWriteContext> {
        self.ip_config_write
    }

    /// Get the restart-request publisher, if available.
    ///
    /// Returns `None` if the remote config server is not enabled. Used by
    /// `REMOTE_RESET_REQUEST` to raise a restart on the shared restart channel.
    pub fn restart_ctx(&self) -> Option<&dyn RemoteRestartContext> {
        self.restart_ctx
    }

    /// Get additional individual addresses (tunneling slots).
    pub fn additional_individual_addresses(&self) -> &[IndividualAddress] {
        self.additional_addresses
    }

    /// Get the KNX address context for primary and tunneling addresses.
    pub fn knx_addresses(&self) -> &dyn IndividualAddressContext {
        self.knx_addresses
    }

    /// Get the tunneling slot info snapshot, if tunneling is enabled.
    ///
    /// Returns `(max_apdu_len, slots)` where each slot has an address
    /// and a status word (bit 0 = occupied).
    pub fn tunneling_slot_info(&self) -> Option<(u16, &[substructs::TunnelingSlotInfo])> {
        self.tunneling_slot_info
    }

    /// Get the address filter, if configured.
    ///
    /// Present for routing devices; absent for tunneling-only servers.
    pub fn address_filter(&self) -> Option<&dyn AddressFilter> {
        self.address_filter
    }

    /// Get the KNX IP Secure configuration view, if the device is secure.
    pub fn ip_secure(&self) -> Option<&dyn crate::ip::IpSecureStateView> {
        self.ip_secure
    }

    /// Send an indication to the network layer (L_Data.ind).
    pub async fn send_to_network_layer(&self, message: KnxMessageBuffer<Buffer<'static>>) {
        let indication = IndicationMessage::indication(message);
        self.ind_tx.send(indication).await;
    }

    /// Allocate a buffer for responses.
    pub async fn alloc_buffer(&self) -> Buffer<'static> {
        self.buffer_manager.alloc().await
    }

    /// Get direct access to the buffer manager.
    pub fn buffer_manager(&self) -> &DynBufferManager<'static> {
        self.buffer_manager
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
        context: &ServerContext<'a>,
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
        context: &ServerContext<'a>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError>;
}
