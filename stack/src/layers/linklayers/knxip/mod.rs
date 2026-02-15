use core::{
    cell::RefCell,
    future::pending,
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddrV4},
};

use embassy_futures::select::{Either, Either4, select, select_slice, select4};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicSender},
};
use embassy_time::{Duration, Instant, Timer};
use heapless::Vec;

use platform::{AsyncUdpSocket, IpTransport, TcpListenerOptions, UdpSocketOptions};

use self::tcp_manager::{TcpEvent, TcpManager};

use crate::{
    layers::{Inbox, Layer, LayerOp, LinkLayerBuilder, LinkLayerBuilderBase},
    messages::{
        buffers::*,
        builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage, RequestMessage},
        knx::*,
        knxip::*,
    },
};

pub mod servers;
mod tcp_framing;
mod tcp_manager;

use crate::context::{
    ApplicationLayerContext, BufferManagerContext, DeviceInfoContext, IpDiagnosticsContext, KnxAddressContext,
    PropertyServiceContext,
};

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
    + KnxAddressContext
    + ApplicationLayerContext
{
}

impl<T> KnxNetIpContext for T where
    T: BufferManagerContext
        + PropertyServiceContext
        + DeviceInfoContext
        + IpDiagnosticsContext
        + KnxAddressContext
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
    Udp { source: SocketAddrV4, socket_idx: usize },
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
            PacketOrigin::Udp { source, socket_idx } => ResponseTarget::Udp { destination: source, socket_idx },
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
    buffer_manager: &'a RefCell<DynBufferManager<'static>>,
    /// Channel to send messages up to the network layer
    network_layer_tx: DynamicSender<'a, LayerOp<Buffer<'static>>>,
    /// Maximum APDU length this device can handle
    max_apdu_length: u16,
    /// Device info context for building `DeviceInformation` on demand.
    device_info: &'a dyn DeviceInfoContext,
    /// IP diagnostics context for remote config responses.
    /// Present when remote config server is enabled.
    ip_diagnostics: Option<&'a dyn IpDiagnosticsContext>,
    /// KNX address context for primary + tunneling addresses.
    knx_addresses: &'a dyn KnxAddressContext,
}

impl<'a> ServerContext<'a> {
    /// Create a new server context
    pub fn new(
        buffer_manager: &'a RefCell<DynBufferManager<'static>>,
        network_layer_tx: DynamicSender<'a, LayerOp<Buffer<'static>>>,
        max_apdu_length: u16,
        device_info: &'a dyn DeviceInfoContext,
        ip_diagnostics: Option<&'a dyn IpDiagnosticsContext>,
        knx_addresses: &'a dyn KnxAddressContext,
    ) -> Self {
        Self { buffer_manager, network_layer_tx, max_apdu_length, device_info, ip_diagnostics, knx_addresses }
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

    /// Get the KNX address context for primary and tunneling addresses.
    pub fn knx_addresses(&self) -> &dyn KnxAddressContext {
        self.knx_addresses
    }

    /// Send an indication to the network layer (L_Data.ind)
    pub async fn send_to_network_layer(&self, message: KnxMessageBuffer<Buffer<'static>>) {
        let indication = IndicationMessage::indication(message);
        self.network_layer_tx.send(LayerOp::Indication(indication)).await;
    }

    /// Allocate a buffer for responses
    pub async fn alloc_buffer(&self) -> Buffer<'static> {
        self.buffer_manager.borrow().alloc().await
    }

    /// Get direct access to the buffer manager
    pub fn buffer_manager(&self) -> &RefCell<DynBufferManager<'static>> {
        self.buffer_manager
    }
}

/// Maximum number of multicast groups per socket
const MAX_MULTICAST_GROUPS: usize = 2;

/// Metadata about a UDP socket
#[derive(Debug, Clone)]
pub struct SocketDescriptor {
    /// The endpoint this socket is bound to (typically 0.0.0.0:port)
    bind_endpoint: EndpointType,

    /// Multicast groups joined on this socket
    multicast_groups: Vec<Ipv4Addr, MAX_MULTICAST_GROUPS>,

    /// Whether broadcast is enabled on this socket
    broadcast_enabled: bool,
}

impl SocketDescriptor {
    /// Create a new socket descriptor
    pub const fn new(bind_endpoint: EndpointType) -> Self {
        Self { bind_endpoint, multicast_groups: Vec::new(), broadcast_enabled: false }
    }

    /// Get the bind endpoint
    pub fn bind_endpoint(&self) -> &EndpointType {
        &self.bind_endpoint
    }

    /// Get the port this socket is bound to
    pub fn port(&self) -> u16 {
        self.bind_endpoint.port()
    }

    /// Add a multicast group to join
    pub fn add_multicast_group(&mut self, addr: Ipv4Addr) -> Result<(), ()> {
        if !self.multicast_groups.contains(&addr) { self.multicast_groups.push(addr).map_err(|_| ()) } else { Ok(()) }
    }

    /// Enable broadcast on this socket
    pub fn enable_broadcast(&mut self) {
        self.broadcast_enabled = true;
    }

    /// Check if broadcast is enabled
    pub fn is_broadcast_enabled(&self) -> bool {
        self.broadcast_enabled
    }

    /// Get the multicast groups
    pub fn multicast_groups(&self) -> &[Ipv4Addr] {
        &self.multicast_groups
    }
}

/// Static resources for KNX/IP link layer.
///
/// `MAX_TCP` controls the maximum number of concurrent TCP connections.
/// Set to 0 to disable TCP entirely (saves memory on constrained targets).
pub struct KnxNetIpResources<T: IpTransport, const MAX_SOCKETS: usize> {
    /// Storage for UDP socket handles
    sockets: MaybeUninit<[Option<T::UdpSocket>; MAX_SOCKETS]>,

    /// Response channel for queuing outbound messages
    response_channel: MaybeUninit<Channel<NoopRawMutex, PendingResponse, 16>>,
}

impl<T: IpTransport, const MAX_SOCKETS: usize> KnxNetIpResources<T, MAX_SOCKETS> {
    /// Create a new uninitialized resource container
    pub const fn new() -> Self {
        Self { sockets: MaybeUninit::uninit(), response_channel: MaybeUninit::uninit() }
    }
}

/// Maximum number of connectionless servers (discovery + routing)
const MAX_SERVERS: usize = 3;

/// Builder for KnxNetIp link layer.
///
/// The discovery server (Core service family) and device management
/// (connection type 0x03) are always enabled — both are mandatory for
/// every KNXnet/IP device per KNX spec 3/8/1 Table 2.
///
/// Configure optional servers using the builder methods:
/// - [`enable_routing_server()`](Self::enable_routing_server) — KNX/IP routing multicast
/// - [`enable_remote_config_server()`](Self::enable_remote_config_server) — Remote diagnostics (optional per spec)
///
/// The list of supported service families advertised in discovery responses
/// is auto-derived from which servers are enabled.
///
/// # Example
///
/// ```ignore
/// let builder = KnxNetIpBuilder::<LinuxIpTransport, 2>::new("eth0", interface_addr, control_endpoint)
///     .enable_routing_server();
/// ```
pub struct KnxNetIpBuilder<T: IpTransport, const MAX_SOCKETS: usize, const MAX_TCP: usize = 1> {
    interface_name: &'static str,
    local_addr: Ipv4Addr,
    control_endpoint: substructs::HPAI,
    enable_routing: bool,
    enable_remote_config: bool,
    enable_tcp: bool,
    _transport: core::marker::PhantomData<T>,
}

impl<T: IpTransport, const MAX_SOCKETS: usize, const MAX_TCP: usize> KnxNetIpBuilder<T, MAX_SOCKETS, MAX_TCP> {
    /// Create a new builder with the network interface to bind to.
    ///
    /// The discovery server is always enabled (mandatory per KNX spec 3/8/2
    /// §4.2). The `control_endpoint` HPAI is advertised in search and
    /// description responses.
    ///
    /// # Arguments
    /// * `interface_name` - The name of the network interface (e.g., "eth0", "wlan0")
    /// * `local_addr` - The local IP address of this interface (for multicast join and echo filtering)
    /// * `control_endpoint` - The HPAI to advertise as this device's control endpoint
    ///
    /// # Type Parameters
    /// * `T` - The IP transport implementation providing socket types
    /// * `MAX_SOCKETS` - Maximum number of UDP sockets to create
    /// * `MAX_TCP` - Maximum number of concurrent TCP connections
    pub const fn new(interface_name: &'static str, local_addr: Ipv4Addr, control_endpoint: substructs::HPAI) -> Self {
        Self {
            interface_name,
            local_addr,
            control_endpoint,
            enable_routing: false,
            enable_remote_config: false,
            enable_tcp: false,
            _transport: core::marker::PhantomData,
        }
    }

    /// Enable the routing server (RoutingIndication / RoutingBusy / RoutingLostMessage).
    ///
    /// The routing server listens on the default KNX multicast address
    /// (`224.0.23.12:3671`) for routing messages and implements congestion
    /// control per KNX Specification 3/8/2.
    pub fn enable_routing_server(mut self) -> Self {
        self.enable_routing = true;
        self
    }

    /// Enable the Remote Diagnostic and Configuration server (KNX 3/8/7).
    ///
    /// Handles connectionless remote diagnostics on multicast/broadcast:
    /// `RemoteDiagnosticRequest` (0x0740), `RemoteBasicConfigurationRequest`
    /// (0x0742), and `RemoteResetRequest` (0x0743).
    ///
    /// All three services are mandatory for KNX/IP certification (§6.2).
    /// The server listens on the KNX multicast address (`224.0.23.12:3671`).
    pub fn enable_remote_config_server(mut self) -> Self {
        self.enable_remote_config = true;
        self
    }

    /// Enable TCP support for connection-oriented services.
    ///
    /// When enabled, a TCP listener is bound on the same port as the
    /// control endpoint. Clients (e.g., ETS) can establish TCP connections
    /// for Device Management and Tunneling. The Core service family
    /// version is bumped to v2 to indicate TCP support (KNX spec 3/8/2
    /// §9.2).
    pub fn enable_tcp(mut self) -> Self {
        self.enable_tcp = true;
        self
    }

    /// Build the KnxNetIp link layer.
    ///
    /// This method:
    /// 1. Auto-derives supported services from enabled features
    /// 2. Creates server instances with the correct service types and endpoints
    /// 3. Deduplicates and creates UDP sockets
    /// 4. Creates the connection manager with device management handler
    /// 5. Returns the final KnxNetIp instance
    fn build<'res>(
        self,
        resources: &'res mut KnxNetIpResources<T, MAX_SOCKETS>,
        context: &'res dyn KnxNetIpContext,
        network_layer_tx: DynamicSender<'res, LayerOp<Buffer<'static>>>,
    ) -> KnxNetIp<'res, T, MAX_SOCKETS, MAX_TCP> {
        // Initialize response channel
        let _response_channel = resources.response_channel.write(Channel::new());

        // ====================================================================
        // Auto-derive supported services from enabled features
        // ====================================================================

        let mut supported_services = Vec::<substructs::SupportedService, 5>::new();

        // Core v1: discovery, description, connection management over UDP.
        // Core v2 additionally requires TCP support (§9.2).
        let core_version = if self.enable_tcp { 2 } else { 1 };
        let _ = supported_services
            .push(substructs::SupportedService { family: substructs::ServiceFamily::Core, version: core_version });

        // Device Management v2: mandatory for all KNXnet/IP device classes (3/8/1 Table 2).
        // v2 requires cEMI Transport Layer support (T_Data_Individual, T_Data_Connected)
        // in addition to v1's M_PropRead/M_PropWrite/M_Reset (3/8/3 §4.2.5), which we implement.
        let _ = supported_services
            .push(substructs::SupportedService { family: substructs::ServiceFamily::DeviceManagement, version: 2 });

        if self.enable_routing {
            let _ = supported_services
                .push(substructs::SupportedService { family: substructs::ServiceFamily::Routing, version: 1 });
        }

        if self.enable_remote_config {
            let _ = supported_services.push(substructs::SupportedService {
                family: substructs::ServiceFamily::RemoteConfigAndDiag,
                version: 1,
            });
        }

        // ====================================================================
        // Build server instances from enabled features
        // ====================================================================

        // Collect endpoints for socket deduplication. Each entry is
        // (server_index, endpoint) where server_index matches the order
        // servers are pushed into server_instances below.
        let mut server_endpoints: Vec<(usize, Vec<EndpointType, 4>), MAX_SERVERS> = Vec::new();
        let mut server_instances = Vec::<servers::ServerInstance, MAX_SERVERS>::new();
        let mut server_idx = 0;

        // Discovery server is always enabled (mandatory per KNX spec 3/8/2 §4.2).
        {
            let server = servers::DiscoveryServer::new(self.control_endpoint, supported_services);

            let mut service_types = Vec::new();
            let _ = service_types.push(KNXnetIPServiceType::SearchRequest);
            let _ = service_types.push(KNXnetIPServiceType::SearchRequestExtended);
            let _ = service_types.push(KNXnetIPServiceType::DescriptionRequest);

            // Discovery listens on multicast (system setup) + unicast (any:3671)
            let mut endpoints = Vec::new();
            let _ = endpoints.push(EndpointType::new_udp(crate::DEFAULT_MULTICAST_ADDR, crate::KNX_PORT));
            let _ = endpoints.push(EndpointType::new_udp_any(crate::KNX_PORT));

            let _ = server_instances.push(servers::ServerInstance {
                service_types,
                socket_indices: Vec::new(), // filled in below after socket dedup
                handler: server.into(),
            });
            let _ = server_endpoints.push((server_idx, endpoints));
            server_idx += 1;
        }

        if self.enable_routing {
            let server = servers::RoutingServer::new(crate::DEFAULT_MULTICAST_ADDR, crate::KNX_PORT);

            let mut service_types = Vec::new();
            let _ = service_types.push(KNXnetIPServiceType::RoutingIndication);
            let _ = service_types.push(KNXnetIPServiceType::RoutingBusy);
            let _ = service_types.push(KNXnetIPServiceType::RoutingLostMessage);
            let _ = service_types.push(KNXnetIPServiceType::RoutingSystemBroadcast);

            let mut endpoints = Vec::new();
            let _ = endpoints.push(EndpointType::new_udp(crate::DEFAULT_MULTICAST_ADDR, crate::KNX_PORT));

            let _ = server_instances.push(servers::ServerInstance {
                service_types,
                socket_indices: Vec::new(),
                handler: server.into(),
            });
            let _ = server_endpoints.push((server_idx, endpoints));
            server_idx += 1;
        }

        if self.enable_remote_config {
            let server = servers::RemoteConfigurationServer::new();

            let mut service_types = Vec::new();
            let _ = service_types.push(KNXnetIPServiceType::RemoteDiagnosticRequest);
            let _ = service_types.push(KNXnetIPServiceType::RemoteBasicConfigurationRequest);
            let _ = service_types.push(KNXnetIPServiceType::RemoteResetRequest);

            // Remote config listens on multicast (same as discovery/routing)
            let mut endpoints = Vec::new();
            let _ = endpoints.push(EndpointType::new_udp(crate::DEFAULT_MULTICAST_ADDR, crate::KNX_PORT));

            let _ = server_instances.push(servers::ServerInstance {
                service_types,
                socket_indices: Vec::new(),
                handler: server.into(),
            });
            let _ = server_endpoints.push((server_idx, endpoints));
            #[allow(unused_assignments)]
            {
                server_idx += 1;
            }
        }

        // ====================================================================
        // Deduplicate endpoints into sockets
        // ====================================================================

        let mut socket_descriptors = Vec::<SocketDescriptor, MAX_SOCKETS>::new();

        for (_srv_idx, endpoints) in &server_endpoints {
            for endpoint in endpoints {
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
        }

        // Map each server to its socket indices
        for (srv_idx, endpoints) in &server_endpoints {
            for endpoint in endpoints {
                let port = endpoint.port();
                if let Some(sock_idx) = socket_descriptors.iter().position(|desc| desc.port() == port) {
                    if !server_instances[*srv_idx].socket_indices.contains(&sock_idx) {
                        let _ = server_instances[*srv_idx].socket_indices.push(sock_idx);
                    }
                }
            }
        }

        info!(
            "KnxNetIp builder: {} server(s) using {} unique socket(s)",
            server_instances.len(),
            socket_descriptors.len()
        );

        let interface_addr = self.local_addr;

        // ====================================================================
        // Create actual UDP sockets
        // ====================================================================

        let sockets_array = resources.sockets.write(core::array::from_fn(|_| None));

        for (i, desc) in socket_descriptors.iter().enumerate() {
            let port = desc.port();

            let options = UdpSocketOptions {
                address: Ipv4Addr::UNSPECIFIED,
                port,
                interface: Some(self.interface_name),
                ..Default::default()
            };

            match T::UdpSocket::bind(options) {
                Ok(socket) => {
                    for &mcast_addr in desc.multicast_groups() {
                        debug!(
                            "  Socket {}: Joining multicast group {} on interface {}",
                            i, mcast_addr, self.interface_name
                        );
                        if let Err(e) = socket.join_multicast(mcast_addr, interface_addr) {
                            error!("Failed to join multicast group {}: {:?}", mcast_addr, e);
                        }
                    }

                    if desc.is_broadcast_enabled() {
                        debug!("  Socket {}: Enabling SO_BROADCAST", i);
                        let _ = socket.set_broadcast(true);
                    }

                    info!("  Socket {}: Bound to 0.0.0.0:{} on interface {}", i, port, self.interface_name);
                    sockets_array[i] = Some(socket);
                }
                Err(e) => {
                    error!("Failed to create socket for port {}: {:?}", port, e);
                }
            }
        }

        for (idx, instance) in server_instances.iter().enumerate() {
            debug!("  Server {}: Handles {:?} on sockets {:?}", idx, instance.service_types, instance.socket_indices);
        }

        // ====================================================================
        // Connection manager
        // ====================================================================

        // Device Management is mandatory for all KNXnet/IP device classes
        // (KNX spec 3/8/1 Table 2).
        let mut connection_manager = servers::ConnectionManager::new();
        let handler = servers::DeviceMgmtConnectionHandler::new(
            context.property_handler(),
            context.application_layer_sender(),
            context.buffer_manager(),
        );
        connection_manager.add_handler(
            crate::messages::knxip::substructs::ConnectionType::DeviceManagement,
            servers::ConnectionTypeHandlerEnum::DeviceManagement(handler),
        );

        // ====================================================================
        // TCP manager
        // ====================================================================

        let mut tcp_manager = TcpManager::new();

        if self.enable_tcp {
            let tcp_port = self.control_endpoint.port();
            let tcp_options = TcpListenerOptions {
                address: Ipv4Addr::UNSPECIFIED,
                port: tcp_port,
                interface: Some(self.interface_name),
            };
            match tcp_manager.bind(tcp_options) {
                Ok(()) => {
                    info!("TCP listener bound on port {} (interface {})", tcp_port, self.interface_name);
                }
                Err(_e) => {
                    error!("Failed to bind TCP listener on port {}: {:?}", tcp_port, _e);
                }
            }
        }

        KnxNetIp {
            resources,
            socket_descriptors,
            server_instances,
            _interface_name: self.interface_name,
            local_addr: interface_addr,
            network_layer_tx,
            retry_queue: Vec::new(),
            connection_manager,
            context,
            enable_remote_config: self.enable_remote_config,
            tcp_manager,
        }
    }
}

impl<T: IpTransport + 'static, const MAX_SOCKETS: usize, const MAX_TCP: usize> LinkLayerBuilderBase
    for KnxNetIpBuilder<T, MAX_SOCKETS, MAX_TCP>
{
    type Resources = KnxNetIpResources<T, MAX_SOCKETS>;

    fn create_resources(&self) -> Self::Resources {
        KnxNetIpResources::new()
    }
}

impl<CTX: KnxNetIpContext, T: IpTransport + 'static, const MAX_SOCKETS: usize, const MAX_TCP: usize>
    LinkLayerBuilder<CTX> for KnxNetIpBuilder<T, MAX_SOCKETS, MAX_TCP>
{
    fn build_and_run<'a>(
        self,
        resources: &'a mut Self::Resources,
        context: &'a CTX,
        network_layer: DynamicSender<'a, LayerOp<crate::messages::buffers::Buffer<'static>>>,
        inbox: impl Inbox<LayerOp<crate::messages::buffers::Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        let mut link_layer = self.build(resources, context, network_layer);
        async move { link_layer.process(inbox).await }
    }
}

/// A request that is pending retry after being rate-limited
struct PendingRequest {
    /// The message to retry
    message: RequestMessage<Buffer<'static>>,
    /// Channel to send the response back to
    response_tx: DynamicSender<'static, ConfirmationMessage<Buffer<'static>>>,
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
/// `context` and `network_layer_tx` are disjoint from `server_instances`.
fn make_server_context<'a>(
    context: &'a dyn KnxNetIpContext,
    enable_remote_config: bool,
    network_layer_tx: DynamicSender<'a, LayerOp<Buffer<'static>>>,
) -> ServerContext<'a> {
    let ip_diagnostics: Option<&dyn IpDiagnosticsContext> = if enable_remote_config { Some(context) } else { None };
    ServerContext::new(
        context.buffer_manager(),
        network_layer_tx,
        context.max_apdu_length(),
        context,
        ip_diagnostics,
        context,
    )
}

pub struct KnxNetIp<'res, T: IpTransport, const MAX_SOCKETS: usize, const MAX_TCP: usize = 1> {
    /// Reference to socket resources
    resources: &'res KnxNetIpResources<T, MAX_SOCKETS>,
    /// Socket descriptors (metadata about each socket)
    socket_descriptors: Vec<SocketDescriptor, MAX_SOCKETS>,
    /// Server instances
    server_instances: Vec<servers::ServerInstance, MAX_SERVERS>,
    /// Interface name for logging
    _interface_name: &'static str,
    /// Local interface IP address (used to filter out our own multicast echoes)
    local_addr: Ipv4Addr,
    /// Channel to send messages to the network layer
    network_layer_tx: DynamicSender<'res, LayerOp<Buffer<'static>>>,
    /// Queue of messages waiting to be retried after rate limiting
    retry_queue: Vec<PendingRequest, MAX_RETRY_QUEUE_SIZE>,
    /// Connection manager for connection-oriented services.
    /// Always present; without registered handlers it's a no-op.
    connection_manager: servers::ConnectionManager<'res>,
    /// Type-erased stack context providing buffer management, device info,
    /// IP diagnostics, KNX addresses, property service, and application
    /// layer access.
    context: &'res dyn KnxNetIpContext,
    /// Whether the remote config server is enabled (controls whether
    /// `IpDiagnosticsContext` is exposed to servers via `ServerContext`).
    enable_remote_config: bool,
    /// TCP connection manager. Always present; without a bound listener
    /// it is a no-op.
    tcp_manager: TcpManager<T, MAX_TCP>,
}

impl<'res, T: IpTransport, const MAX_SOCKETS: usize, const MAX_TCP: usize> KnxNetIp<'res, T, MAX_SOCKETS, MAX_TCP> {
    /// Process expired retry requests
    async fn process_retry_queue(&mut self, response_channel: &Channel<NoopRawMutex, PendingResponse, 16>) {
        let now = Instant::now();

        // Process all expired retry entries
        // Note: We iterate backwards and use swap_remove for efficiency
        let mut i = 0;
        while i < self.retry_queue.len() {
            if now >= self.retry_queue[i].retry_after {
                let mut pending = self.retry_queue.swap_remove(i);

                debug!("Retrying message (attempt {}/{})", pending.retry_count + 1, MAX_RETRY_ATTEMPTS);

                // Try to send the message
                let mut requeue = false;
                let mut send_error = false;
                let mut send_success = false;

                for server in &mut self.server_instances {
                    if server.handler.supports_requests() {
                        let context =
                            make_server_context(self.context, self.enable_remote_config, self.network_layer_tx);
                        match server.handler.on_request(&*pending.message, &context).await {
                            Ok(responses) => {
                                // Success! Send responses and confirmation
                                for response in responses {
                                    response_channel.send(response).await;
                                }
                                send_success = true;
                                break;
                            }
                            Err(ServerError::Busy(wait_time)) => {
                                // Still busy, check if we should retry again
                                pending.retry_count += 1;
                                if pending.retry_count < MAX_RETRY_ATTEMPTS {
                                    pending.retry_after = Instant::now() + Duration::from_millis(wait_time as u64);
                                    debug!(
                                        "Still busy, requeuing (attempt {}/{}, wait {}ms)",
                                        pending.retry_count, MAX_RETRY_ATTEMPTS, wait_time
                                    );
                                    requeue = true;
                                    break;
                                } else {
                                    warn!("Max retry attempts reached, giving up on message");
                                    send_error = true;
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("Server error during retry: {:?}", e);
                                send_error = true;
                                break;
                            }
                        }
                    }
                }

                if requeue {
                    // Re-insert at the end
                    if self.retry_queue.push(pending).is_err() {
                        // Couldn't requeue - this shouldn't happen since we just removed an item
                        // But if it does, we need to recover the pending request to send error
                        error!("Retry queue full after swap_remove, dropping message");
                        // Note: pending was moved into push, we can't access it here
                        // This is actually OK - the message will be dropped
                    }
                } else if send_success {
                    // Send confirmation
                    let inner = pending.message.into_inner();
                    pending.response_tx.send(inner.confirm().build()).await;
                } else if send_error {
                    let inner = pending.message.into_inner();
                    pending.response_tx.send(inner.error().build()).await;
                } else {
                    // No server could handle it - send error
                    let inner = pending.message.into_inner();
                    pending.response_tx.send(inner.error().build()).await;
                }
            } else {
                // This entry is not expired yet, move to next
                i += 1;
            }
        }
    }

    /// Get the next retry time, if any messages are queued
    fn get_next_retry_time(&self) -> Option<Instant> {
        self.retry_queue.iter().map(|r| r.retry_after).min()
    }

    /// Send a packet on a specific socket
    async fn send_on_socket(&self, socket_idx: usize, data: &[u8], destination: SocketAddrV4) -> Result<(), ()> {
        trace!("KNX/IP TX {} bytes on socket {} to {}: {:x?}", data.len(), socket_idx, destination, data);

        let sockets = unsafe { self.resources.sockets.assume_init_ref() };

        if let Some(Some(socket)) = sockets.get(socket_idx) {
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

    /// Dispatch a received KNX/IP frame through the connection manager
    /// and connectionless servers.
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

                // Try the connection manager first. It handles
                // connection lifecycle and data frames for active
                // connections. If unrecognized, fall through to
                // connectionless servers.
                match self
                    .connection_manager
                    .on_indication(service_type, buffer, origin, self.context.buffer_manager(), self.network_layer_tx)
                    .await
                {
                    Ok(result) => {
                        for response in result.responses {
                            response_channel.send(response).await;
                        }
                        // Apply TCP channel tracking side-effects
                        self.apply_tcp_channel_events(result.tcp_events);
                    }
                    Err(ServerError::InvalidMessage) => {
                        // Fall through to connectionless servers.
                        for server in &mut self.server_instances {
                            if server.handles(service_type, socket_idx) {
                                let context =
                                    make_server_context(self.context, self.enable_remote_config, self.network_layer_tx);

                                match server.handler.on_indication(service_type, buffer, source, &context).await {
                                    Ok(responses) => {
                                        for response in responses {
                                            response_channel.send(response).await;
                                        }
                                    }
                                    Err(e) => {
                                        error!("Server error handling {:?}: {:?}", service_type, e);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Connection manager error for {:?}: {:?}", service_type, e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to parse KNX/IP service type from {}: {:?}", source, e);
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

impl<'res, T: IpTransport, const MAX_SOCKETS: usize, const MAX_TCP: usize> Layer<'res>
    for KnxNetIp<'res, T, MAX_SOCKETS, MAX_TCP>
{
    type Buffer = Buffer<'static>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Buffer>>,
    {
        info!(
            "KnxNetIp Link Layer starting with {} server(s), {} socket(s)",
            self.server_instances.len(),
            self.socket_descriptors.len()
        );

        // Get the response channel
        let response_channel = unsafe { self.resources.response_channel.assume_init_ref() };

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
                        if !self.socket_descriptors.is_empty() {
                            let _ = self.send_on_socket(socket_idx, data, destination).await;
                        }
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
                    if let servers::TcpChannelEvent::Removed { tcp_idx, channel_id } = event {
                        if let Some(tcp_conn) = self.tcp_manager.connection_mut(tcp_idx) {
                            tcp_conn.remove_channel(channel_id);
                        }
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
            // Main select: UDP + TCP transport, inbox, responses, timer
            // ================================================================
            //
            // The first arm nests a `select` to combine UDP socket receives
            // with TCP events (accept + read). This avoids needing select5.
            let result = {
                // Borrow individual fields to avoid conflicting borrows
                // between recv_from_socket (borrows resources + context)
                // and tcp_manager.next_event (borrows tcp_manager mutably).
                let sockets = unsafe { self.resources.sockets.assume_init_ref() };
                let buffer_manager = self.context.buffer_manager();

                // Create UDP receive futures using raw socket access
                // (avoids borrowing self through recv_from_socket).
                let recv = |socket_idx: usize| {
                    let bm = buffer_manager;
                    async move {
                        if let Some(Some(socket)) = sockets.get(socket_idx) {
                            let mut buffer = bm.borrow().alloc().await;
                            buffer.resize(buffer.capacity(), 0);
                            match socket.recv_from(&mut buffer[..]).await {
                                Ok((len, source)) => {
                                    trace!(
                                        "KNX/IP RX {} bytes on socket {} from {}: {:x?}",
                                        len,
                                        socket_idx,
                                        source,
                                        &buffer[..len]
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
                            error!("Socket {} not available", socket_idx);
                            Err(())
                        }
                    }
                };

                let mut socket_futures = Vec::<_, MAX_SOCKETS>::new();
                for i in 0..self.socket_descriptors.len() {
                    let _ = socket_futures.push(recv(i));
                }

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

                // Nest select: UDP receives + TCP events in the first arm
                let transport_future =
                    select(select_slice(socket_futures.as_mut_slice()), self.tcp_manager.next_event(buffer_manager));

                match next_timer {
                    Some(timer_at) => {
                        select4(transport_future, inbox.next(), response_channel.receive(), Timer::at(timer_at)).await
                    }
                    None => select4(transport_future, inbox.next(), response_channel.receive(), pending::<()>()).await,
                }
            };

            match result {
                // Timer expired (retry queue, heartbeat, or TCP idle)
                Either4::Fourth(()) => {
                    trace!("KNX/IP timer expired");
                    continue;
                }

                // ============================================================
                // Transport events (UDP or TCP)
                // ============================================================
                Either4::First(transport_event) => match transport_event {
                    // UDP socket received a packet
                    Either::First((Ok((buffer, source)), socket_idx)) => {
                        debug!("Received {} bytes on socket {} from {}", buffer.len(), socket_idx, source);

                        // Filter out our own multicast echoes
                        if *source.ip() == self.local_addr {
                            debug!("KNX/IP ignoring own multicast echo: {}", source);
                            continue;
                        }

                        let origin = PacketOrigin::Udp { source, socket_idx };
                        self.dispatch_frame(&buffer, origin, response_channel).await;
                    }

                    // UDP socket receive error
                    Either::First((Err(()), socket_idx)) => {
                        error!("Socket {} receive error", socket_idx);
                    }

                    // TCP frame received
                    Either::Second(TcpEvent::Frame { tcp_idx, peer, buffer }) => {
                        debug!("TCP connection {}: received {} byte frame from {}", tcp_idx, buffer.len(), peer);

                        let origin = PacketOrigin::Tcp { peer, tcp_idx };
                        self.dispatch_frame(&buffer, origin, response_channel).await;
                    }

                    // TCP connection closed
                    Either::Second(TcpEvent::Closed { tcp_idx, .. }) => {
                        info!("TCP connection {} closed, tearing down KNX/IP channels", tcp_idx);
                        self.connection_manager.on_tcp_closed(tcp_idx);
                    }
                },

                // Inbox received a layer operation
                Either4::Second(layer_op) => {
                    trace!("KNX/IP received layer op: {:?}", layer_op);

                    match layer_op {
                        LayerOp::Indication(_) => {
                            // Link layer typically doesn't receive indications from upper layers
                            error!("KnxNetIp Link Layer received unexpected indication");
                        }
                        LayerOp::Request { message: msg, response_tx } => {
                            // Handle transmission requests
                            match msg.service_type() {
                                ServiceType::L_Data_Req => {
                                    debug!("KnxNetIp Link Layer sending L_Data_Req: {:x?}", msg);

                                    // Find a server that supports outgoing requests
                                    // Note: The server is responsible for protocol-specific transformations
                                    // (e.g., routing server converts to L_Data_Ind for cEMI encoding)
                                    let mut msg_opt = Some(msg);
                                    let mut handled = false;
                                    for server in &mut self.server_instances {
                                        if server.handler.supports_requests() {
                                            // Create server context with buffer manager and network layer channel
                                            let context = make_server_context(
                                                self.context,
                                                self.enable_remote_config,
                                                self.network_layer_tx,
                                            );
                                            match server
                                                .handler
                                                .on_request(&**msg_opt.as_ref().unwrap(), &context)
                                                .await
                                            {
                                                Ok(responses) => {
                                                    for response in responses {
                                                        response_channel.send(response).await;
                                                    }
                                                    // Send confirmation
                                                    let inner = msg_opt.take().unwrap().into_inner();
                                                    response_tx.send(inner.confirm().build()).await;
                                                    handled = true;
                                                    break;
                                                }
                                                Err(ServerError::Busy(wait_time)) => {
                                                    // Server is rate-limited, queue for retry
                                                    if self.retry_queue.len() < MAX_RETRY_QUEUE_SIZE {
                                                        let retry_after =
                                                            Instant::now() + Duration::from_millis(wait_time as u64);
                                                        let pending = PendingRequest {
                                                            message: msg_opt.take().unwrap(),
                                                            response_tx,
                                                            retry_after,
                                                            retry_count: 0,
                                                        };

                                                        if self.retry_queue.push(pending).is_ok() {
                                                            debug!(
                                                                "Queued message for retry in {}ms (queue size: {})",
                                                                wait_time,
                                                                self.retry_queue.len()
                                                            );
                                                            handled = true;
                                                            break;
                                                        }
                                                    } else {
                                                        warn!(
                                                            "Retry queue full ({} messages), cannot queue message",
                                                            MAX_RETRY_QUEUE_SIZE
                                                        );
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("Server error sending request: {:?}", e);
                                                }
                                            }
                                        }
                                    }

                                    if !handled {
                                        // No server could handle it - send error
                                        let inner = msg_opt.take().unwrap().into_inner();
                                        response_tx.send(inner.error().build()).await;
                                    }
                                }
                                _ => {
                                    // Return error for unsupported service types
                                    response_tx.send(msg.into_inner().error().build()).await;
                                }
                            }
                        }
                    }
                }

                // Response ready to send
                Either4::Third(pending_response) => {
                    let data = &pending_response.buffer[..];

                    match pending_response.target {
                        ResponseTarget::Udp { destination, socket_idx } => {
                            debug!("Sending {} byte response to {} on socket {}", data.len(), destination, socket_idx);
                            if !self.socket_descriptors.is_empty() {
                                let _ = self.send_on_socket(socket_idx, data, destination).await;
                            } else {
                                error!("No sockets available to send response");
                            }
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
