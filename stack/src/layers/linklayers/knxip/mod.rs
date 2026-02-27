use core::{
    future::pending,
    net::{Ipv4Addr, SocketAddrV4},
};

use embassy_futures::select::{Either3, Either4, select3, select4};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicReceiver, DynamicSender},
};
use embassy_time::{Duration, Instant, Timer};
use heapless::Vec;

use platform::{IpTransport, TcpListenerOptions};

use crate::{
    MAX_ADDITIONAL_INDIVIDUAL_ADDRESSES,
    context::{
        ApplicationLayerContext, BufferManagerContext, DeviceInfoContext, IpAdditionalIndividualAddressContext,
        IpDiagnosticsContext, KnxIndividualAddressContext, PropertyServiceContext,
    },
    layers::{Inbox, LinkLayerBuilder, LinkLayerBuilderBase},
    messages::{
        buffers::*,
        builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage, RequestMessage},
        knx::*,
        knxip::*,
    },
};

use self::{
    tcp_manager::{TcpEvent, TcpManager},
    udp_manager::{SocketDescriptor, UdpEvent, UdpManager},
};

pub mod features;
pub mod servers;

use features::{RemoteConfigFeature, RoutingFeature, TcpFeature, TunnelingFeature};
mod tcp_framing;
mod tcp_manager;
mod udp_manager;

/// Type-erased context for KnxNetIp.
///
/// Bundles all context traits the KNX/IP link layer needs into a single
/// trait object, so `build()` takes one `&dyn KnxNetIpContext` instead
/// of 6+ individual `&dyn` references.
pub(crate) trait KnxNetIpContext:
    BufferManagerContext
    + PropertyServiceContext
    + DeviceInfoContext
    + IpDiagnosticsContext
    + IpAdditionalIndividualAddressContext
    + KnxIndividualAddressContext
    + ApplicationLayerContext
{
}

impl<T> KnxNetIpContext for T where
    T: BufferManagerContext
        + PropertyServiceContext
        + DeviceInfoContext
        + IpDiagnosticsContext
        + IpAdditionalIndividualAddressContext
        + KnxIndividualAddressContext
        + ApplicationLayerContext
{
}

/// Protocol type for KNX/IP endpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Udp,
    Tcp, // To be implemented later
}

/// Endpoint that KNX/IP servers can listen on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointType {
    protocol: Protocol,
    socket_addr: SocketAddrV4,
}

impl EndpointType {
    /// Create a new UDP endpoint
    pub const fn new_udp(address: Ipv4Addr, port: u16) -> Self {
        Self { protocol: Protocol::Udp, socket_addr: SocketAddrV4::new(address, port) }
    }

    /// Create a new TCP endpoint (to be implemented)
    pub const fn new_tcp(address: Ipv4Addr, port: u16) -> Self {
        Self { protocol: Protocol::Tcp, socket_addr: SocketAddrV4::new(address, port) }
    }

    /// Create a UDP endpoint listening on all interfaces (0.0.0.0)
    pub const fn new_udp_any(port: u16) -> Self {
        Self::new_udp(Ipv4Addr::new(0, 0, 0, 0), port)
    }

    /// Create a UDP broadcast endpoint (255.255.255.255)
    pub const fn new_udp_broadcast(port: u16) -> Self {
        Self::new_udp(Ipv4Addr::new(255, 255, 255, 255), port)
    }

    /// Create a UDP multicast endpoint
    pub const fn new_udp_multicast(multicast_addr: Ipv4Addr, port: u16) -> Self {
        Self::new_udp(multicast_addr, port)
    }

    /// Get the protocol
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Get the socket address
    pub const fn socket_addr(&self) -> SocketAddrV4 {
        self.socket_addr
    }

    /// Get the IP address
    pub const fn address(&self) -> Ipv4Addr {
        *self.socket_addr.ip()
    }

    /// Get the port
    pub const fn port(&self) -> u16 {
        self.socket_addr.port()
    }

    /// Check if this is a broadcast address (255.255.255.255)
    pub const fn is_broadcast(&self) -> bool {
        let octets = self.socket_addr.ip().octets();
        octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255
    }

    /// Check if this is a multicast address (224.0.0.0 to 239.255.255.255)
    /// Multicast addresses have the uppermost 4 bits set to 1110 (0xE0-0xEF)
    pub const fn is_multicast(&self) -> bool {
        let octets = self.socket_addr.ip().octets();
        (octets[0] & 0xF0) == 0xE0
    }

    /// Check if this is listening on all interfaces (0.0.0.0)
    pub const fn is_any(&self) -> bool {
        let octets = self.socket_addr.ip().octets();
        octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0
    }

    /// Check if this is a UDP endpoint
    pub const fn is_udp(&self) -> bool {
        matches!(self.protocol, Protocol::Udp)
    }

    /// Check if this is a TCP endpoint
    pub const fn is_tcp(&self) -> bool {
        matches!(self.protocol, Protocol::Tcp)
    }

    /// Check if two endpoints match for message dispatching
    ///
    /// This implements the C++ matching logic:
    /// - Ports must match
    /// - If `self` (registered endpoint) is 0.0.0.0, it matches any address
    /// - If `other` (received packet destination) is multicast and `self` is multicast, they must match exactly
    /// - Otherwise, addresses must match exactly
    ///
    /// Note: `self` is typically the registered endpoint, `other` is the socket/destination
    pub const fn matches(&self, other: &EndpointType) -> bool {
        // Check protocol matches
        let protocol_matches = match (self.protocol, other.protocol) {
            (Protocol::Udp, Protocol::Udp) => true,
            (Protocol::Tcp, Protocol::Tcp) => true,
            _ => false,
        };

        if !protocol_matches || self.socket_addr.port() != other.socket_addr.port() {
            return false;
        }

        // If registered endpoint is 0.0.0.0 (any), match everything on this port
        if self.is_any() {
            return true;
        }

        // Exact address match
        let self_octets = self.socket_addr.ip().octets();
        let other_octets = other.socket_addr.ip().octets();
        if self_octets[0] == other_octets[0]
            && self_octets[1] == other_octets[1]
            && self_octets[2] == other_octets[2]
            && self_octets[3] == other_octets[3]
        {
            return true;
        }

        // No match
        false
    }
}

impl Default for EndpointType {
    fn default() -> Self {
        Self::new_udp(Ipv4Addr::new(0, 0, 0, 0), 0)
    }
}

/// Error type for server operations
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

/// Where a response should be sent.
#[derive(Debug, Clone, Copy)]
pub enum ResponseTarget {
    /// Send as a UDP datagram to the given address on the given socket.
    Udp { destination: SocketAddrV4, socket_idx: usize },
    /// Write to an active TCP connection identified by its slot index.
    Tcp { tcp_idx: usize },
}

/// Origin of an incoming packet — allows servers to build a matching
/// [`ResponseTarget`] without knowing the transport details.
#[derive(Debug, Clone, Copy)]
pub enum PacketOrigin {
    /// Received as a UDP datagram.
    Udp {
        source: SocketAddrV4,
        socket_idx: usize,
        /// The local IP address the packet was addressed to. `None` if
        /// the platform doesn't report this. Used for unicast/multicast
        /// traffic type enforcement.
        destination: Option<Ipv4Addr>,
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

/// A response that is ready to be sent
#[derive(Debug)]
pub struct PendingResponse {
    /// The buffer containing the response data
    pub buffer: Buffer<'static>,

    /// Where to send this response
    pub target: ResponseTarget,
}

/// Context provided to servers for accessing stack resources.
///
/// Constructed fresh on every server dispatch from [`KnxNetIp`]'s context
/// reference. Servers access device information, IP diagnostics, and
/// KNX addresses through the individual context trait accessors.
pub struct ServerContext<'a> {
    /// Buffer manager for allocating message buffers
    buffer_manager: &'a DynBufferManager<'static>,
    /// Channel to send indications up to the network layer
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    /// Maximum APDU length this device can handle
    max_apdu_length: u16,
    /// Device info context for building `DeviceInformation` on demand.
    device_info: &'a dyn DeviceInfoContext,
    /// IP diagnostics context for remote config responses.
    /// Present when remote config server is enabled.
    ip_diagnostics: Option<&'a dyn IpDiagnosticsContext>,
    /// Additional-address context for KNX_ADDRESSES DIB data.
    ip_additional_addresses: &'a dyn IpAdditionalIndividualAddressContext,
    /// KNX address context for primary + tunneling addresses.
    knx_addresses: &'a dyn KnxIndividualAddressContext,
    /// Snapshot of tunneling slot status from the connection manager.
    /// Present when a tunneling handler is registered. Used by the
    /// discovery server to build the TunnelingInfo DIB.
    tunneling_slot_info:
        Option<(u16, heapless::Vec<substructs::TunnelingSlotInfo, MAX_ADDITIONAL_INDIVIDUAL_ADDRESSES>)>,
}

impl<'a> ServerContext<'a> {
    /// Create a new server context
    pub fn new(
        buffer_manager: &'a DynBufferManager<'static>,
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        max_apdu_length: u16,
        device_info: &'a dyn DeviceInfoContext,
        ip_diagnostics: Option<&'a dyn IpDiagnosticsContext>,
        ip_additional_addresses: &'a dyn IpAdditionalIndividualAddressContext,
        knx_addresses: &'a dyn KnxIndividualAddressContext,
        tunneling_slot_info: Option<(
            u16,
            heapless::Vec<substructs::TunnelingSlotInfo, MAX_ADDITIONAL_INDIVIDUAL_ADDRESSES>,
        )>,
    ) -> Self {
        Self {
            buffer_manager,
            ind_tx,
            max_apdu_length,
            device_info,
            ip_diagnostics,
            ip_additional_addresses,
            knx_addresses,
            tunneling_slot_info,
        }
    }

    /// Get the maximum APDU length this device can handle
    pub fn max_apdu_length(&self) -> u16 {
        self.max_apdu_length
    }

    /// Get the device info context. Servers can call
    /// `device_info().device_information()` to build a fresh
    /// [`DeviceInformation`] reflecting the current device state.
    pub fn device_info(&self) -> &dyn DeviceInfoContext {
        self.device_info
    }

    /// Get the IP diagnostics context, if available.
    ///
    /// Returns `None` if the remote config server is not enabled.
    pub fn ip_diagnostics(&self) -> Option<&dyn IpDiagnosticsContext> {
        self.ip_diagnostics
    }

    /// Get additional-address context.
    pub fn ip_additional_individual_addresses(&self) -> &dyn IpAdditionalIndividualAddressContext {
        self.ip_additional_addresses
    }

    /// Get the KNX address context for primary and tunneling addresses.
    pub fn knx_addresses(&self) -> &dyn KnxIndividualAddressContext {
        self.knx_addresses
    }

    /// Get the tunneling slot info snapshot, if tunneling is enabled.
    ///
    /// Returns `(max_apdu_len, slots)` where each slot has an address
    /// and a status word (bit 0 = occupied).
    pub fn tunneling_slot_info(
        &self,
    ) -> Option<&(u16, heapless::Vec<substructs::TunnelingSlotInfo, MAX_ADDITIONAL_INDIVIDUAL_ADDRESSES>)> {
        self.tunneling_slot_info.as_ref()
    }

    /// Send an indication to the network layer (L_Data.ind)
    pub async fn send_to_network_layer(&self, message: KnxMessageBuffer<Buffer<'static>>) {
        let indication = IndicationMessage::indication(message);
        self.ind_tx.send(indication).await;
    }

    /// Allocate a buffer for responses
    pub async fn alloc_buffer(&self) -> Buffer<'static> {
        self.buffer_manager.alloc().await
    }

    /// Get direct access to the buffer manager
    pub fn buffer_manager(&self) -> &DynBufferManager<'static> {
        self.buffer_manager
    }
}

/// Static resources for KNX/IP link layer.
///
/// Provides externally-owned storage that must outlive the
/// [`KnxNetIp`] link layer instance. Currently holds the response
/// channel through which servers queue outbound messages.
pub struct KnxNetIpResources {
    /// Response channel for queuing outbound messages.
    response_channel: Channel<NoopRawMutex, PendingResponse, 16>,
}

impl KnxNetIpResources {
    /// Create a new resource container.
    pub const fn new() -> Self {
        Self { response_channel: Channel::new() }
    }

    /// Get a reference to the response channel.
    pub(super) fn response_channel(&self) -> &Channel<NoopRawMutex, PendingResponse, 16> {
        &self.response_channel
    }
}

// ============================================================================
// Subnet Link (IP Interface composite mode)
// ============================================================================

/// A cEMI subnetwork indication to forward to tunnel clients.
///
/// The composite bridge loop converts TPUART indications to cEMI and
/// sends them here; the KNX/IP run loop calls
/// [`ConnectionManager::forward_bus_indication()`] to deliver them to
/// matching tunnel connections.
pub struct SubnetIndication {
    pub cemi_data: Buffer<'static>,
}

/// KNX/IP server's link to the KNX subnetwork for IP Interface composite mode.
///
/// When a KNX/IP server runs as part of a composite IP Interface link
/// layer, it needs bidirectional communication with the subnetwork:
///
/// - **`subnet_ind_rx`**: Receive subnetwork indications (cEMI) from the
///   bridge loop. KNX/IP forwards these to matching tunnel clients.
/// - **`subnet_inject_tx`**: Send tunnel-injected frames back to the bridge
///   loop for subnetwork TX. This replaces `ind_tx` for `AckAndInject` so
///   that tunnel-originated frames go to the physical bus instead of the
///   device's own network layer.
pub struct SubnetLink<'a> {
    pub subnet_ind_rx: DynamicReceiver<'a, SubnetIndication>,
    pub subnet_inject_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
}

/// Builder for KnxNetIp link layer.
///
/// The discovery server (Core service family) and device management
/// (connection type 0x03) are always enabled — both are mandatory for
/// every KNXnet/IP device per KNX spec 3/8/1 Table 2.
///
/// Configure optional features using type-state builder methods:
/// - [`enable_routing_server()`](Self::enable_routing_server) — KNX/IP routing multicast
/// - [`enable_remote_config_server()`](Self::enable_remote_config_server) — Remote diagnostics
/// - [`enable_tunneling()`](Self::enable_tunneling) — KNX/IP tunneling connections
/// - [`enable_tcp()`](Self::enable_tcp) — TCP transport
///
/// Each `enable_*()` method is a compile-time type-state transition that
/// changes the `F` parameter. Disabled features use zero-size types and
/// their code is eliminated entirely by LLVM.
///
/// # Example
///
/// ```ignore
/// let builder = KnxNetIpBuilder::<LinuxIpTransport, _, 2>::new("eth0", interface_addr, endpoint, ())
///     .enable_routing_server()
///     .enable_remote_config_server();
/// ```
pub struct KnxNetIpBuilder<
    T: IpTransport,
    F: features::FeatureSet = features::DefaultFeatures,
    const MAX_SOCKETS: usize = 4,
    const MAX_TCP_STREAMS: usize = 1,
    const MAX_CHANNELS: usize = 1,
> {
    interface_name: &'static str,
    local_addr: Ipv4Addr,
    control_endpoint: SocketAddrV4,
    routing_multicast_addr: Ipv4Addr,
    socket_ctx: <T::UdpSocket as platform::AsyncUdpSocket>::Context,
    _features: core::marker::PhantomData<F>,
}

impl<T: IpTransport, const MAX_SOCKETS: usize, const MAX_TCP_STREAMS: usize, const MAX_CHANNELS: usize>
    KnxNetIpBuilder<T, features::DefaultFeatures, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
{
    /// Create a new builder with the network interface to bind to.
    ///
    /// Starts with all optional features disabled. Use `enable_*()` methods
    /// to enable features at compile time.
    ///
    /// The discovery server is always enabled (mandatory per KNX spec 3/8/2
    /// §4.2). The `control_endpoint` HPAI is advertised in search and
    /// description responses.
    pub fn new(
        interface_name: &'static str,
        local_addr: Ipv4Addr,
        control_endpoint: SocketAddrV4,
        socket_ctx: <T::UdpSocket as platform::AsyncUdpSocket>::Context,
    ) -> Self {
        Self {
            interface_name,
            local_addr,
            control_endpoint,
            routing_multicast_addr: crate::DEFAULT_MULTICAST_ADDR,
            socket_ctx,
            _features: core::marker::PhantomData,
        }
    }
}

impl<
    T: IpTransport,
    F: features::FeatureSet,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
> KnxNetIpBuilder<T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
{
    /// Override the routing multicast address.
    ///
    /// Defaults to `224.0.23.12` (the standard KNX multicast address).
    /// Custom addresses are used in some installations to separate routing
    /// domains or avoid conflicts with other KNX/IP routers on the same
    /// network segment.
    pub fn routing_multicast_addr(mut self, addr: Ipv4Addr) -> Self {
        self.routing_multicast_addr = addr;
        self
    }
}

// ============================================================================
// Type-state enable methods
// ============================================================================
//
// Each method consumes the builder and returns a new one with the
// corresponding feature marker changed from No* to With*. The method
// only exists on the No* variant, preventing double-enable.

impl<
    T: IpTransport,
    RC: features::RemoteConfigFeature,
    TUN: features::TunnelingFeature,
    TCP: features::TcpFeature,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
> KnxNetIpBuilder<T, features::Features<features::NoRouting, RC, TUN, TCP>, MS, MTS, MC>
{
    /// Enable the routing server (RoutingIndication / RoutingBusy / RoutingLostMessage).
    ///
    /// The routing server listens on the KNX multicast address for routing
    /// messages and implements congestion control per KNX Specification
    /// 3/8/2. Uses the default multicast address (`224.0.23.12`) unless
    /// overridden with [`routing_multicast_addr`](Self::routing_multicast_addr).
    pub fn enable_routing_server(
        self,
    ) -> KnxNetIpBuilder<T, features::Features<features::WithRouting, RC, TUN, TCP>, MS, MTS, MC> {
        KnxNetIpBuilder {
            interface_name: self.interface_name,
            local_addr: self.local_addr,
            control_endpoint: self.control_endpoint,
            routing_multicast_addr: self.routing_multicast_addr,
            socket_ctx: self.socket_ctx,
            _features: core::marker::PhantomData,
        }
    }
}

impl<
    T: IpTransport,
    R: features::RoutingFeature,
    TUN: features::TunnelingFeature,
    TCP: features::TcpFeature,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
> KnxNetIpBuilder<T, features::Features<R, features::NoRemoteConfig, TUN, TCP>, MS, MTS, MC>
{
    /// Enable the Remote Diagnostic and Configuration server (KNX 3/8/7).
    ///
    /// Handles connectionless remote diagnostics on multicast/broadcast:
    /// `RemoteDiagnosticRequest` (0x0740), `RemoteBasicConfigurationRequest`
    /// (0x0742), and `RemoteResetRequest` (0x0743).
    ///
    /// All three services are mandatory for KNX/IP certification (§6.2).
    /// The server listens on the KNX multicast address (`224.0.23.12:3671`).
    pub fn enable_remote_config_server(
        self,
    ) -> KnxNetIpBuilder<T, features::Features<R, features::WithRemoteConfig, TUN, TCP>, MS, MTS, MC> {
        KnxNetIpBuilder {
            interface_name: self.interface_name,
            local_addr: self.local_addr,
            control_endpoint: self.control_endpoint,
            routing_multicast_addr: self.routing_multicast_addr,
            socket_ctx: self.socket_ctx,
            _features: core::marker::PhantomData,
        }
    }
}

impl<
    T: IpTransport,
    R: features::RoutingFeature,
    RC: features::RemoteConfigFeature,
    TCP: features::TcpFeature,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
> KnxNetIpBuilder<T, features::Features<R, RC, features::NoTunneling, TCP>, MS, MTS, MC>
{
    /// Enable tunneling connections (ConnectionType 0x04).
    ///
    /// When enabled, KNX/IP clients can establish tunneling connections
    /// to transparently access the KNX bus. Each connection is assigned
    /// one of the device's additional individual addresses (from
    /// `PID_ADDITIONAL_INDIVIDUAL_ADDRESSES`). The number of concurrent
    /// tunneling connections equals the number of configured additional
    /// addresses.
    pub fn enable_tunneling(
        self,
    ) -> KnxNetIpBuilder<T, features::Features<R, RC, features::WithTunneling, TCP>, MS, MTS, MC> {
        KnxNetIpBuilder {
            interface_name: self.interface_name,
            local_addr: self.local_addr,
            control_endpoint: self.control_endpoint,
            routing_multicast_addr: self.routing_multicast_addr,
            socket_ctx: self.socket_ctx,
            _features: core::marker::PhantomData,
        }
    }
}

impl<
    T: IpTransport,
    R: features::RoutingFeature,
    RC: features::RemoteConfigFeature,
    TUN: features::TunnelingFeature,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
> KnxNetIpBuilder<T, features::Features<R, RC, TUN, features::NoTcp>, MS, MTS, MC>
{
    /// Enable TCP support for connection-oriented services.
    ///
    /// When enabled, a TCP listener is bound on the same port as the
    /// control endpoint. Clients (e.g., ETS) can establish TCP connections
    /// for Device Management and Tunneling. The Core service family
    /// version is bumped to v2 to indicate TCP support (KNX spec 3/8/2
    /// §9.2).
    pub fn enable_tcp(
        self,
    ) -> KnxNetIpBuilder<T, features::Features<R, RC, TUN, features::WithTcp>, MS, MTS, MC> {
        KnxNetIpBuilder {
            interface_name: self.interface_name,
            local_addr: self.local_addr,
            control_endpoint: self.control_endpoint,
            routing_multicast_addr: self.routing_multicast_addr,
            socket_ctx: self.socket_ctx,
            _features: core::marker::PhantomData,
        }
    }
}

// ============================================================================
// Build
// ============================================================================

impl<
    T: IpTransport,
    F: features::FeatureSet,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
> KnxNetIpBuilder<T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
{
    /// Build the KnxNetIp link layer.
    ///
    /// This method:
    /// 1. Auto-derives supported services from enabled feature traits
    /// 2. Creates typed server instances (zero-size when disabled)
    /// 3. Deduplicates and creates UDP sockets
    /// 4. Creates the connection manager with compile-time handler selection
    /// 5. Returns the final `KnxNetIp` instance
    pub(crate) fn build<'res>(
        self,
        resources: &'res mut KnxNetIpResources,
        context: &'res dyn KnxNetIpContext,
        ind_tx: DynamicSender<'res, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'res, ConfirmationMessage<Buffer<'static>>>,
        subnet_link: Option<SubnetLink<'res>>,
    ) -> KnxNetIp<'res, T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS> {
        // ====================================================================
        // Auto-derive supported services from feature traits
        // ====================================================================

        let mut supported_services = Vec::<substructs::SupportedService, 5>::new();

        // Core v1: discovery, description, connection management over UDP.
        // Core v2 additionally requires TCP support (§9.2).
        let core_version = if F::Tcp::is_enabled() { 2 } else { 1 };
        let _ = supported_services
            .push(substructs::SupportedService { family: substructs::ServiceFamily::Core, version: core_version });

        // Device Management v2: mandatory for all KNXnet/IP device classes (3/8/1 Table 2).
        let _ = supported_services
            .push(substructs::SupportedService { family: substructs::ServiceFamily::DeviceManagement, version: 2 });

        if let Some(svc) = F::Routing::supported_service() {
            let _ = supported_services.push(svc);
        }
        if let Some(svc) = F::Tunneling::supported_service() {
            let _ = supported_services.push(svc);
        }
        if let Some(svc) = F::RemoteConfig::supported_service() {
            let _ = supported_services.push(svc);
        }

        // ====================================================================
        // Collect endpoints for socket deduplication
        // ====================================================================
        //
        // Each feature contributes its required endpoints. The discovery
        // server always needs multicast + unicast on KNX_PORT. Routing and
        // remote config may share the multicast socket.

        let mut all_endpoints = Vec::<EndpointType, 8>::new();

        // Discovery endpoints (always present)
        let _ = all_endpoints.push(EndpointType::new_udp(crate::DEFAULT_MULTICAST_ADDR, crate::KNX_PORT));
        let _ = all_endpoints.push(EndpointType::new_udp_any(crate::KNX_PORT));

        // Routing endpoints (empty vec when disabled)
        for ep in F::Routing::endpoints(self.routing_multicast_addr) {
            let _ = all_endpoints.push(ep);
        }

        // Remote config endpoints (empty vec when disabled)
        for ep in F::RemoteConfig::endpoints() {
            let _ = all_endpoints.push(ep);
        }

        // ====================================================================
        // Deduplicate endpoints into sockets
        // ====================================================================

        let mut socket_descriptors = Vec::<SocketDescriptor, MAX_SOCKETS>::new();

        for endpoint in &all_endpoints {
            let port = endpoint.port();
            let existing_idx = socket_descriptors.iter().position(|desc| desc.port() == port);

            if let Some(idx) = existing_idx {
                if endpoint.is_multicast() {
                    let _ = socket_descriptors[idx].add_multicast_group(endpoint.address());
                }
                if endpoint.is_broadcast() {
                    socket_descriptors[idx].enable_broadcast();
                }
            } else {
                let bind_addr = EndpointType::new_udp(Ipv4Addr::UNSPECIFIED, port);
                let mut desc = SocketDescriptor::new(bind_addr);

                if endpoint.is_multicast() {
                    let _ = desc.add_multicast_group(endpoint.address());
                }
                if endpoint.is_broadcast() {
                    desc.enable_broadcast();
                }

                let _ = socket_descriptors.push(desc);
            }
        }

        // Build socket index lists for each feature's server. A server
        // "owns" the sockets whose ports match its registered endpoints.
        let discovery_socket_indices = {
            let mut indices = Vec::<usize, 4>::new();
            // Discovery listens on multicast + unicast on KNX_PORT
            for desc_idx in 0..socket_descriptors.len() {
                if socket_descriptors[desc_idx].port() == crate::KNX_PORT
                    && !indices.contains(&desc_idx)
                {
                    let _ = indices.push(desc_idx);
                }
            }
            indices
        };

        let routing_socket_indices = {
            let mut indices = Vec::<usize, 4>::new();
            for ep in F::Routing::endpoints(self.routing_multicast_addr) {
                if let Some(idx) = socket_descriptors.iter().position(|d| d.port() == ep.port())
                    && !indices.contains(&idx)
                {
                    let _ = indices.push(idx);
                }
            }
            indices
        };

        let remote_config_socket_indices = {
            let mut indices = Vec::<usize, 4>::new();
            for ep in F::RemoteConfig::endpoints() {
                if let Some(idx) = socket_descriptors.iter().position(|d| d.port() == ep.port())
                    && !indices.contains(&idx)
                {
                    let _ = indices.push(idx);
                }
            }
            indices
        };

        info!(
            "KnxNetIp builder: {} unique socket(s)",
            socket_descriptors.len()
        );

        let interface_addr = self.local_addr;

        // ====================================================================
        // UDP manager — owns sockets and their descriptors
        // ====================================================================

        let mut udp_manager = UdpManager::new(interface_addr, socket_descriptors);
        udp_manager.bind_all(&self.socket_ctx, self.interface_name, interface_addr);

        // ====================================================================
        // Create typed servers (zero-size when feature is disabled)
        // ====================================================================

        let control_hpai = substructs::HPAI::ipv4_udp(*self.control_endpoint.ip(), self.control_endpoint.port());
        let discovery = servers::DiscoveryServer::new(control_hpai, supported_services);

        let routing = F::Routing::create_server(self.routing_multicast_addr, crate::KNX_PORT);
        let remote_config = F::RemoteConfig::create_server();

        // ====================================================================
        // Connection manager — handler type selected by TunnelingFeature
        // ====================================================================

        let handlers = F::Tunneling::build_handlers(context);
        let connection_manager = servers::ConnectionManager::new(handlers);

        // ====================================================================
        // TCP manager
        // ====================================================================

        let mut tcp_manager = TcpManager::new();

        if F::Tcp::is_enabled() {
            let tcp_options =
                TcpListenerOptions { bind_addr: self.control_endpoint, interface: Some(self.interface_name) };
            match tcp_manager.bind(tcp_options) {
                Ok(()) => {
                    info!("TCP listener bound on {} (interface {})", self.control_endpoint, self.interface_name);
                }
                Err(_e) => {
                    error!("Failed to bind TCP listener on {}: {:?}", self.control_endpoint, _e);
                }
            }
        }

        KnxNetIp {
            resources,
            udp_manager,
            discovery,
            discovery_socket_indices,
            routing,
            routing_socket_indices,
            remote_config,
            remote_config_socket_indices,
            _interface_name: self.interface_name,
            ind_tx,
            conf_tx,
            retry_queue: Vec::new(),
            connection_manager,
            context,
            tcp_manager,
            subnet_link,
        }
    }
}

impl<
    T: IpTransport + 'static,
    F: features::FeatureSet,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
> LinkLayerBuilderBase for KnxNetIpBuilder<T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
{
    type Resources = KnxNetIpResources;

    fn create_resources(&self) -> Self::Resources {
        KnxNetIpResources::new()
    }
}

impl<
    CTX: KnxNetIpContext,
    T: IpTransport + 'static,
    F: features::FeatureSet + 'static,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
> LinkLayerBuilder<CTX> for KnxNetIpBuilder<T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
{
    fn build_and_run<'a>(
        self,
        resources: &'a mut Self::Resources,
        context: &'a CTX,
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl Inbox<RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        let mut link_layer = self.build(resources, context, ind_tx, conf_tx, None);
        async move { link_layer.run(req_rx).await }
    }
}

/// A request that is pending retry after being rate-limited
struct PendingRequest {
    /// The message to retry
    message: RequestMessage<Buffer<'static>>,
    /// When to retry sending this message
    retry_after: Instant,
    /// Number of times this message has been retried
    retry_count: u8,
}

/// Maximum number of messages that can be queued for retry
const MAX_RETRY_QUEUE_SIZE: usize = 16;

/// Maximum number of retry attempts before giving up
const MAX_RETRY_ATTEMPTS: u8 = 5;

/// Build a [`ServerContext`] from individual [`KnxNetIp`] fields.
///
/// Free function instead of a method so the borrow checker can see that
/// server fields are disjoint from the context and channel fields.
/// The `RC` type parameter controls whether IP diagnostics are exposed.
fn make_server_context<'a, RC: RemoteConfigFeature>(
    context: &'a dyn KnxNetIpContext,
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    tunneling_slot_info: Option<(
        u16,
        heapless::Vec<substructs::TunnelingSlotInfo, MAX_ADDITIONAL_INDIVIDUAL_ADDRESSES>,
    )>,
) -> ServerContext<'a> {
    let ip_diagnostics: Option<&dyn IpDiagnosticsContext> =
        if RC::exposes_diagnostics() { Some(context) } else { None };
    let ip_additional_addresses: &dyn IpAdditionalIndividualAddressContext = context;
    ServerContext::new(
        context.buffer_manager(),
        ind_tx,
        context.max_apdu_length(),
        context,
        ip_diagnostics,
        ip_additional_addresses,
        context,
        tunneling_slot_info,
    )
}

pub struct KnxNetIp<
    'res,
    T: IpTransport,
    F: features::FeatureSet = features::DefaultFeatures,
    const MAX_SOCKETS: usize = 4,
    const MAX_TCP_STREAMS: usize = 1,
    const MAX_CHANNELS: usize = 1,
> {
    /// Reference to externally-owned resources (response channel).
    resources: &'res KnxNetIpResources,
    /// UDP socket manager. Owns sockets and their descriptors.
    udp_manager: UdpManager<T, MAX_SOCKETS>,

    // ---- Typed server fields (zero-size when feature is disabled) ----

    /// Discovery server — always present (mandatory per KNX spec).
    discovery: servers::DiscoveryServer,
    /// Socket indices the discovery server listens on.
    discovery_socket_indices: Vec<usize, 4>,

    /// Routing server — `()` when `NoRouting`.
    routing: <F::Routing as features::RoutingFeature>::Server,
    /// Socket indices for the routing server (empty when disabled).
    routing_socket_indices: Vec<usize, 4>,

    /// Remote config server — `()` when `NoRemoteConfig`.
    remote_config: <F::RemoteConfig as features::RemoteConfigFeature>::Server,
    /// Socket indices for the remote config server (empty when disabled).
    remote_config_socket_indices: Vec<usize, 4>,

    /// Interface name for logging.
    _interface_name: &'static str,
    /// Channel to send indications (received frames) up to the network layer.
    ind_tx: DynamicSender<'res, IndicationMessage<Buffer<'static>>>,
    /// Channel to send confirmations (transmission results) up to the network layer.
    conf_tx: DynamicSender<'res, ConfirmationMessage<Buffer<'static>>>,
    /// Queue of messages waiting to be retried after rate limiting.
    retry_queue: Vec<PendingRequest, MAX_RETRY_QUEUE_SIZE>,
    /// Connection manager for connection-oriented services.
    /// The handler type `H` is selected by `TunnelingFeature::Handlers`.
    connection_manager: servers::ConnectionManager<
        <F::Tunneling as features::TunnelingFeature>::Handlers<'res>,
        MAX_CHANNELS,
    >,
    /// Type-erased stack context providing buffer management, device info,
    /// IP diagnostics, KNX addresses, property service, and application
    /// layer access.
    context: &'res dyn KnxNetIpContext,
    /// TCP connection manager. Always present; without a bound listener
    /// it is a no-op.
    tcp_manager: TcpManager<T, MAX_TCP_STREAMS, MAX_CHANNELS>,
    /// Bus bridge for IP Interface composite mode.
    ///
    /// When `Some`, this KNX/IP instance is part of a composite link layer
    /// bridging to a TP1 bus. `AckAndInject` frames are routed to
    /// `subnet_inject_tx` instead of the real `ind_tx`, and bus indications
    /// arrive via `subnet_ind_rx` for forwarding to tunnel clients.
    subnet_link: Option<SubnetLink<'res>>,
}

impl<'res, T: IpTransport, F: features::FeatureSet, const MAX_SOCKETS: usize, const MAX_TCP_STREAMS: usize, const MAX_CHANNELS: usize>
    KnxNetIp<'res, T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
{
    /// Process expired retry requests.
    ///
    /// Only the routing server supports outgoing requests (`on_request`).
    /// When routing is disabled (`NoRouting`), `supports_requests()` returns
    /// false and `on_request()` returns `Err(Unsupported)`, so retries are
    /// no-ops that the compiler eliminates.
    async fn process_retry_queue(&mut self, response_channel: &Channel<NoopRawMutex, PendingResponse, 16>) {
        if !F::Routing::supports_requests() {
            // No server supports outgoing requests — drain any stale entries.
            // (Should be empty, but defensive.)
            self.retry_queue.clear();
            return;
        }

        let now = Instant::now();
        let mut i = 0;
        while i < self.retry_queue.len() {
            if now >= self.retry_queue[i].retry_after {
                let mut pending = self.retry_queue.swap_remove(i);

                debug!("Retrying message (attempt {}/{})", pending.retry_count + 1, MAX_RETRY_ATTEMPTS);

                let tunnel_slots = self.connection_manager.tunneling_slot_info();
                let context = make_server_context::<F::RemoteConfig>(
                    self.context,
                    self.ind_tx,
                    tunnel_slots,
                );

                match F::Routing::on_request(&mut self.routing, &pending.message, &context).await {
                    Ok(responses) => {
                        for response in responses {
                            response_channel.send(response).await;
                        }
                        let inner = pending.message.into_inner();
                        self.conf_tx.send(inner.confirm().build()).await;
                    }
                    Err(ServerError::Busy(wait_time)) => {
                        pending.retry_count += 1;
                        if pending.retry_count < MAX_RETRY_ATTEMPTS {
                            pending.retry_after = Instant::now() + Duration::from_millis(wait_time as u64);
                            debug!(
                                "Still busy, requeuing (attempt {}/{}, wait {}ms)",
                                pending.retry_count, MAX_RETRY_ATTEMPTS, wait_time
                            );
                            if self.retry_queue.push(pending).is_err() {
                                error!("Retry queue full after swap_remove, dropping message");
                            }
                        } else {
                            warn!("Max retry attempts reached, giving up on message");
                            let inner = pending.message.into_inner();
                            self.conf_tx.send(inner.error().build()).await;
                        }
                    }
                    Err(e) => {
                        error!("Server error during retry: {:?}", e);
                        let inner = pending.message.into_inner();
                        self.conf_tx.send(inner.error().build()).await;
                    }
                }
            } else {
                i += 1;
            }
        }
    }

    /// Get the next retry time, if any messages are queued
    fn get_next_retry_time(&self) -> Option<Instant> {
        self.retry_queue.iter().map(|r| r.retry_after).min()
    }

    /// Dispatch a received KNX/IP frame to the connection manager or
    /// connectionless servers based on the service type category.
    ///
    /// Shared between UDP and TCP receive paths. The `origin` identifies
    /// the transport and peer so that responses are routed correctly and
    /// TCP connections can be tracked.
    async fn dispatch_frame(
        &mut self,
        buffer: &[u8],
        origin: PacketOrigin,
        response_channel: &Channel<NoopRawMutex, PendingResponse, 16>,
    ) {
        let source = origin.peer_addr();
        let socket_idx = match origin {
            PacketOrigin::Udp { socket_idx, .. } => socket_idx,
            PacketOrigin::Tcp { .. } => 0,
        };

        match peek_service_type(buffer) {
            Ok(service_type) => {
                debug!("  Service type: {:?}", service_type);

                // Enforce traffic type constraints: certain service types
                // must only arrive via unicast or multicast.
                {
                    use crate::messages::knxip::TrafficRule;
                    let rule = service_type.traffic_rule();

                    match &origin {
                        // UDP: check destination IP to distinguish unicast
                        // from multicast. Skip if the platform doesn't
                        // report destination (None).
                        PacketOrigin::Udp { destination: Some(dest), .. } => {
                            let is_multicast = dest.octets()[0] & 0xF0 == 0xE0;
                            let allowed = match rule {
                                TrafficRule::UnicastOnly => !is_multicast,
                                TrafficRule::MulticastOnly => is_multicast,
                                TrafficRule::Any => true,
                            };
                            if !allowed {
                                warn!(
                                    "Dropping {:?} from {}: expected {} but destination was {}",
                                    service_type,
                                    source,
                                    if is_multicast { "unicast" } else { "multicast" },
                                    dest,
                                );
                                return;
                            }
                        }

                        // TCP is inherently unicast — reject multicast-only
                        // service types.
                        PacketOrigin::Tcp { .. } => {
                            if rule == TrafficRule::MulticastOnly {
                                warn!(
                                    "Dropping {:?} from {} on TCP: multicast-only service type",
                                    service_type, source,
                                );
                                return;
                            }
                        }

                        // UDP without destination info — can't enforce.
                        PacketOrigin::Udp { destination: None, .. } => {}
                    }
                }

                match service_type.category() {
                    // Connection lifecycle and connection-oriented data go
                    // to the connection manager.
                    ServiceCategory::ConnectionLifecycle | ServiceCategory::ConnectionData => {
                        // In composite (IP Interface) mode, tunnel-injected
                        // frames (`AckAndInject`) must go to the physical bus
                        // via `subnet_inject_tx` rather than the device's own
                        // network layer. Device management frames use
                        // `Responses` (not `AckAndInject`), so swapping for
                        // all connection data is safe.
                        let inject_tx = match &self.subnet_link {
                            Some(bridge) => bridge.subnet_inject_tx,
                            None => self.ind_tx,
                        };
                        match self
                            .connection_manager
                            .on_indication(service_type, buffer, origin, self.context.buffer_manager(), inject_tx)
                            .await
                        {
                            Ok(result) => {
                                for response in result.responses {
                                    response_channel.send(response).await;
                                }
                                self.apply_tcp_channel_events(result.tcp_events);
                            }
                            Err(e) => {
                                debug!("Connection manager error for {:?}: {:?}", service_type, e);
                            }
                        }
                    }

                    // Connectionless messages go directly to servers.
                    ServiceCategory::Connectionless => {
                        self.dispatch_to_servers(service_type, buffer, source, socket_idx, response_channel).await;
                    }
                }
            }
            Err(e) => {
                warn!("Failed to parse KNX/IP service type from {}: {:?}", source, e);
            }
        }
    }

    /// Route a connectionless service type to the matching typed server.
    ///
    /// Dispatches directly to typed server fields instead of iterating a
    /// `Vec<ServerInstance>`. When a feature is disabled, its `handles()`
    /// returns `false` and `on_indication()` is a no-op that LLVM eliminates.
    async fn dispatch_to_servers(
        &mut self,
        service_type: KNXnetIPServiceType,
        buffer: &[u8],
        source: SocketAddrV4,
        socket_idx: usize,
        response_channel: &Channel<NoopRawMutex, PendingResponse, 16>,
    ) {
        let tunnel_slots = self.connection_manager.tunneling_slot_info();

        // Helper closure to build server context — captures immutable fields
        // that are disjoint from the mutable server fields.
        let make_ctx = |ind_tx| {
            make_server_context::<F::RemoteConfig>(self.context, ind_tx, tunnel_slots.clone())
        };

        // Discovery server (always present)
        {
            use servers::KnxNetIpServer;
            let discovery_service_types = [
                KNXnetIPServiceType::SearchRequest,
                KNXnetIPServiceType::SearchRequestExtended,
                KNXnetIPServiceType::DescriptionRequest,
            ];
            if discovery_service_types.contains(&service_type)
                && self.discovery_socket_indices.contains(&socket_idx)
            {
                let context = make_ctx(self.ind_tx);
                match self.discovery.on_indication(service_type, buffer, source, &context).await {
                    Ok(responses) => {
                        for response in responses {
                            response_channel.send(response).await;
                        }
                    }
                    Err(e) => {
                        error!("Discovery error handling {:?}: {:?}", service_type, e);
                    }
                }
            }
        }

        // Routing server (compiles to nothing when NoRouting)
        if F::Routing::handles(service_type, socket_idx, &self.routing_socket_indices) {
            let context = make_ctx(self.ind_tx);
            match F::Routing::on_indication(&mut self.routing, service_type, buffer, source, &context).await {
                Ok(responses) => {
                    for response in responses {
                        response_channel.send(response).await;
                    }
                }
                Err(e) => {
                    error!("Routing error handling {:?}: {:?}", service_type, e);
                }
            }
        }

        // Remote config server (compiles to nothing when NoRemoteConfig)
        if F::RemoteConfig::handles(service_type, socket_idx, &self.remote_config_socket_indices) {
            let context = make_ctx(self.ind_tx);
            match F::RemoteConfig::on_indication(&mut self.remote_config, service_type, buffer, source, &context).await
            {
                Ok(responses) => {
                    for response in responses {
                        response_channel.send(response).await;
                    }
                }
                Err(e) => {
                    error!("Remote config error handling {:?}: {:?}", service_type, e);
                }
            }
        }
    }

    /// Apply TCP channel tracking events to the TCP manager.
    fn apply_tcp_channel_events(&mut self, events: Vec<servers::TcpChannelEvent, 2>) {
        use servers::TcpChannelEvent;
        for event in events {
            match event {
                TcpChannelEvent::Added { tcp_idx, channel_id } => {
                    if let Some(tcp_conn) = self.tcp_manager.connection_mut(tcp_idx) {
                        tcp_conn.add_channel(channel_id);
                    }
                }
                TcpChannelEvent::Removed { tcp_idx, channel_id } => {
                    if let Some(tcp_conn) = self.tcp_manager.connection_mut(tcp_idx) {
                        tcp_conn.remove_channel(channel_id);
                    }
                }
            }
        }
    }
}

impl<'res, T: IpTransport, F: features::FeatureSet, const MAX_SOCKETS: usize, const MAX_TCP_STREAMS: usize, const MAX_CHANNELS: usize>
    KnxNetIp<'res, T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
{
    /// Run the KNX/IP link layer event loop.
    ///
    /// Concurrently waits for:
    /// - Requests from the network layer (via `req_rx`), which are processed
    ///   and confirmed via `self.conf_tx`
    /// - UDP/TCP transport events (received frames), which are dispatched to
    ///   servers or the connection manager and forwarded up via `self.ind_tx`
    /// - Queued response channel messages ready to send on the wire
    /// - Timer events (retry queue, heartbeat, TCP idle)
    pub(crate) async fn run<M>(&mut self, mut req_rx: M) -> !
    where
        M: Inbox<RequestMessage<Buffer<'static>>>,
    {
        info!(
            "KnxNetIp Link Layer starting with {} socket(s)",
            self.udp_manager.socket_count()
        );

        let response_channel = self.resources.response_channel();

        loop {
            // First, drain any pending responses to free their buffers
            // This is important because retry queue processing may need these buffers
            while let Ok(pending_response) = response_channel.try_receive() {
                let data = &pending_response.buffer[..];

                match pending_response.target {
                    ResponseTarget::Udp { destination, socket_idx } => {
                        debug!(
                            "Sending {} byte response to {} on socket {} (drain)",
                            data.len(),
                            destination,
                            socket_idx
                        );
                        let _ = self.udp_manager.send_to(socket_idx, data, destination).await;
                    }
                    ResponseTarget::Tcp { tcp_idx } => {
                        debug!("Sending {} byte response on TCP connection {} (drain)", data.len(), tcp_idx);
                        if self.tcp_manager.write_to(tcp_idx, data).await.is_err() {
                            warn!("TCP write failed on connection {}, closing", tcp_idx);
                            self.tcp_manager.close(tcp_idx);
                            self.connection_manager.on_tcp_closed(tcp_idx);
                        }
                    }
                }
                // pending_response is dropped here, freeing its buffer
            }

            // Process any expired retry requests
            self.process_retry_queue(response_channel).await;

            // Run connection manager heartbeat check if connections are active
            if self.connection_manager.has_active_connections() {
                let tcp_events = self.connection_manager.on_tick();
                for event in tcp_events {
                    if let servers::TcpChannelEvent::Removed { tcp_idx, channel_id } = event
                        && let Some(tcp_conn) = self.tcp_manager.connection_mut(tcp_idx)
                    {
                        tcp_conn.remove_channel(channel_id);
                    }
                }
            }

            // Check TCP idle timeouts alongside the heartbeat.
            if self.tcp_manager.has_active_connections() {
                let tcp_idle_events = self.tcp_manager.check_idle_timeouts();
                for event in tcp_idle_events {
                    if let TcpEvent::Closed { tcp_idx, .. } = &event {
                        self.connection_manager.on_tcp_closed(*tcp_idx);
                    }
                }
            }

            // ================================================================
            // Main select: UDP + TCP transport, req_rx, responses, timer
            // ================================================================
            //
            // The first arm nests a `select` to combine UDP events with
            // TCP events. Both managers present an identical `next_event`
            // interface, keeping the select symmetric.
            let buffer_manager = self.context.buffer_manager();

            // Timer: earliest of retry time, heartbeat tick, and TCP
            // idle timeout (10s when idle TCP connections exist).
            let heartbeat_time =
                if self.connection_manager.has_active_connections() || self.tcp_manager.has_active_connections() {
                    Some(Instant::now() + Duration::from_secs(10))
                } else {
                    None
                };

            let next_timer = match (self.get_next_retry_time(), heartbeat_time) {
                (Some(a), Some(b)) => Some(if a < b { a } else { b }),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };

            // Third transport arm: bus bridge indications from the TP1 bus.
            // In standalone mode (no bridge), this pends forever.
            let subnet_ind_future = async {
                match &mut self.subnet_link {
                    Some(bridge) => bridge.subnet_ind_rx.receive().await,
                    None => pending::<SubnetIndication>().await,
                }
            };

            let transport_future = select3(
                self.udp_manager.next_event(buffer_manager),
                self.tcp_manager.next_event(buffer_manager),
                subnet_ind_future,
            );

            let result = match next_timer {
                Some(timer_at) => {
                    select4(transport_future, req_rx.next(), response_channel.receive(), Timer::at(timer_at)).await
                }
                None => select4(transport_future, req_rx.next(), response_channel.receive(), pending::<()>()).await,
            };

            match result {
                // Timer expired (retry queue, heartbeat, or TCP idle)
                Either4::Fourth(()) => {
                    trace!("KNX/IP timer expired");
                    continue;
                }

                // ============================================================
                // Transport events (UDP, TCP, or bus bridge indication)
                // ============================================================
                Either4::First(transport_event) => match transport_event {
                    // UDP datagram received (multicast echoes already filtered)
                    Either3::First(UdpEvent::Frame { socket_idx, source, destination, buffer }) => {
                        let origin = PacketOrigin::Udp { source, socket_idx, destination };
                        self.dispatch_frame(&buffer, origin, response_channel).await;
                    }

                    // UDP socket receive error
                    Either3::First(UdpEvent::Error { socket_idx }) => {
                        error!("Socket {} receive error", socket_idx);
                    }

                    // TCP frame received
                    Either3::Second(TcpEvent::Frame { tcp_idx, peer, buffer }) => {
                        debug!("TCP connection {}: received {} byte frame from {}", tcp_idx, buffer.len(), peer);

                        let origin = PacketOrigin::Tcp { peer, tcp_idx };
                        self.dispatch_frame(&buffer, origin, response_channel).await;
                    }

                    // TCP connection closed
                    Either3::Second(TcpEvent::Closed { tcp_idx, .. }) => {
                        info!("TCP connection {} closed, tearing down KNX/IP channels", tcp_idx);
                        self.connection_manager.on_tcp_closed(tcp_idx);
                    }

                    // Bus bridge: TP1 bus indication to forward to tunnel clients
                    Either3::Third(subnet_indication) => {
                        let forwarded = self
                            .connection_manager
                            .forward_bus_indication(&subnet_indication.cemi_data, self.context.buffer_manager());

                        for response in forwarded {
                            response_channel.send(response).await;
                        }
                    }
                },

                // Request from the network layer (L_Data.req)
                Either4::Second(msg) => {
                    trace!("KNX/IP received request: {:?}", msg);

                    match msg.service_type() {
                        ServiceType::L_Data_Req if F::Routing::supports_requests() => {
                            debug!("KnxNetIp Link Layer sending L_Data_Req: {:?}", msg);

                            let tunnel_slots = self.connection_manager.tunneling_slot_info();
                            let context = make_server_context::<F::RemoteConfig>(
                                self.context,
                                self.ind_tx,
                                tunnel_slots,
                            );

                            match F::Routing::on_request(&mut self.routing, &msg, &context).await {
                                Ok(responses) => {
                                    for response in responses {
                                        response_channel.send(response).await;
                                    }
                                    let inner = msg.into_inner();
                                    self.conf_tx.send(inner.confirm().build()).await;
                                }
                                Err(ServerError::Busy(wait_time)) => {
                                    if self.retry_queue.len() < MAX_RETRY_QUEUE_SIZE {
                                        let retry_after =
                                            Instant::now() + Duration::from_millis(wait_time as u64);
                                        let pending = PendingRequest {
                                            message: msg,
                                            retry_after,
                                            retry_count: 0,
                                        };

                                        if self.retry_queue.push(pending).is_ok() {
                                            debug!(
                                                "Queued message for retry in {}ms (queue size: {})",
                                                wait_time,
                                                self.retry_queue.len()
                                            );
                                        } else {
                                            error!("Retry queue push failed unexpectedly");
                                        }
                                    } else {
                                        warn!(
                                            "Retry queue full ({} messages), cannot queue message",
                                            MAX_RETRY_QUEUE_SIZE
                                        );
                                        let inner = msg.into_inner();
                                        self.conf_tx.send(inner.error().build()).await;
                                    }
                                }
                                Err(e) => {
                                    error!("Server error sending request: {:?}", e);
                                    let inner = msg.into_inner();
                                    self.conf_tx.send(inner.error().build()).await;
                                }
                            }
                        }
                        _ => {
                            // Unsupported service type or no server supports requests
                            self.conf_tx.send(msg.into_inner().error().build()).await;
                        }
                    }
                }

                // Response ready to send
                Either4::Third(pending_response) => {
                    let data = &pending_response.buffer[..];

                    match pending_response.target {
                        ResponseTarget::Udp { destination, socket_idx } => {
                            debug!("Sending {} byte response to {} on socket {}", data.len(), destination, socket_idx);
                            let _ = self.udp_manager.send_to(socket_idx, data, destination).await;
                        }
                        ResponseTarget::Tcp { tcp_idx } => {
                            debug!("Sending {} byte response on TCP connection {}", data.len(), tcp_idx);
                            if self.tcp_manager.write_to(tcp_idx, data).await.is_err() {
                                warn!("TCP write failed on connection {}, closing", tcp_idx);
                                self.tcp_manager.close(tcp_idx);
                                self.connection_manager.on_tcp_closed(tcp_idx);
                            }
                        }
                    }
                }
            }
        }
    }
}
