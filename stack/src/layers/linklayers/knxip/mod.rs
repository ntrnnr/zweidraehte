use core::{
    cell::RefCell,
    future::pending,
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddrV4},
};

use embassy_futures::select::{Either4, select_slice, select4};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicSender},
};
use embassy_time::{Duration, Instant, Timer};
use heapless::Vec;

use platform::{AsyncUdpMulticastSocket, UdpMulticastSocketOptions, get_interface_address};

use crate::{
    context::BufferManagerContext,
    layers::{Inbox, Layer, LayerOp, LinkLayerBuilder},
    messages::{
        buffers::*,
        builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage, RequestMessage},
        knx::*,
        knxip::*,
    },
};

pub mod servers;
use servers::KnxNetIpServer;

/// Protocol type for KNX/IP endpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Udp,
    Tcp, // To be implemented later
}

/// Endpoint that KNX/IP servers can listen on
// FIXME: instead of Ipv4Addr and port, use SocketAddrV4?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointType {
    protocol: Protocol,
    address: Ipv4Addr,
    port: u16,
}

impl EndpointType {
    /// Create a new UDP endpoint
    pub const fn new_udp(address: Ipv4Addr, port: u16) -> Self {
        Self { protocol: Protocol::Udp, address, port }
    }

    /// Create a new TCP endpoint (to be implemented)
    pub const fn new_tcp(address: Ipv4Addr, port: u16) -> Self {
        Self { protocol: Protocol::Tcp, address, port }
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

    /// Get the IP address
    pub const fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Get the port
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Check if this is a broadcast address (255.255.255.255)
    pub const fn is_broadcast(&self) -> bool {
        let octets = self.address.octets();
        octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255
    }

    /// Check if this is a multicast address (224.0.0.0 to 239.255.255.255)
    /// Multicast addresses have the uppermost 4 bits set to 1110 (0xE0-0xEF)
    pub const fn is_multicast(&self) -> bool {
        let octets = self.address.octets();
        (octets[0] & 0xF0) == 0xE0
    }

    /// Check if this is listening on all interfaces (0.0.0.0)
    pub const fn is_any(&self) -> bool {
        let octets = self.address.octets();
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

        if !protocol_matches || self.port != other.port {
            return false;
        }

        // If registered endpoint is 0.0.0.0 (any), match everything on this port
        if self.is_any() {
            return true;
        }

        // Exact address match
        if self.address.octets()[0] == other.address.octets()[0]
            && self.address.octets()[1] == other.address.octets()[1]
            && self.address.octets()[2] == other.address.octets()[2]
            && self.address.octets()[3] == other.address.octets()[3]
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
}

/// A response that is ready to be sent
#[derive(Debug)]
pub struct PendingResponse {
    /// The buffer containing the response data
    pub buffer: Buffer<'static>,
    /// The destination address
    pub destination: SocketAddrV4,
}

/// Context provided to servers for accessing stack resources
pub struct ServerContext<'a> {
    /// Buffer manager for allocating message buffers
    buffer_manager: &'a RefCell<DynBufferManager<'static>>,
    /// Channel to send messages up to the network layer
    network_layer_tx: DynamicSender<'a, LayerOp<Buffer<'static>>>,
}

impl<'a> ServerContext<'a> {
    /// Create a new server context
    pub fn new(
        buffer_manager: &'a RefCell<DynBufferManager<'static>>,
        network_layer_tx: DynamicSender<'a, LayerOp<Buffer<'static>>>,
    ) -> Self {
        Self { buffer_manager, network_layer_tx }
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

/// Static resources for KNX/IP link layer
pub struct KnxNetIpResources<const MAX_SOCKETS: usize> {
    /// Storage for UDP socket handles
    sockets: MaybeUninit<[Option<AsyncUdpMulticastSocket>; MAX_SOCKETS]>,
    /// Response channel for queuing outbound messages
    response_channel: MaybeUninit<Channel<NoopRawMutex, PendingResponse, 16>>,
}

impl<const MAX_SOCKETS: usize> KnxNetIpResources<MAX_SOCKETS> {
    /// Create a new uninitialized resource container
    pub const fn new() -> Self {
        Self { sockets: MaybeUninit::uninit(), response_channel: MaybeUninit::uninit() }
    }
}

/// Builder configuration for adding servers
#[derive(Debug, Clone)]
struct ServerConfig {
    service_types: Vec<KNXnetIPServiceType, 4>,
    endpoints: Vec<EndpointType, 4>,
}

/// Builder for KnxNetIp link layer
pub struct KnxNetIpBuilder<const MAX_SOCKETS: usize, const MAX_SERVERS: usize> {
    servers: Vec<servers::ServerHandler, MAX_SERVERS>,
    server_configs: Vec<ServerConfig, MAX_SERVERS>,
    interface_name: &'static str,
}

impl<const MAX_SOCKETS: usize, const MAX_SERVERS: usize> KnxNetIpBuilder<MAX_SOCKETS, MAX_SERVERS> {
    /// Create a new builder with the network interface to bind to
    ///
    /// # Arguments
    /// * `interface_name` - The name of the network interface (e.g., "eth0", "wlan0")
    ///
    /// # Type Parameters
    /// * `MAX_SOCKETS` - Maximum number of UDP sockets to create
    /// * `MAX_SERVERS` - Maximum number of servers to register
    pub const fn new(interface_name: &'static str) -> Self {
        Self { servers: Vec::new(), server_configs: Vec::new(), interface_name }
    }

    /// Add a server with its service types and endpoints
    ///
    /// # Arguments
    /// * `server` - The server implementation
    /// * `service_types` - Array of service types this server handles
    /// * `endpoints` - Array of endpoints this server listens on
    pub fn add_server<S: Into<servers::ServerHandler>>(
        mut self,
        server: S,
        service_types: &[KNXnetIPServiceType],
        endpoints: &[EndpointType],
    ) -> Self {
        let handler = server.into();

        let mut st_vec = Vec::new();
        for &st in service_types {
            let _ = st_vec.push(st);
        }

        let mut ep_vec = Vec::new();
        for &ep in endpoints {
            let _ = ep_vec.push(ep);
        }

        let _ = self.servers.push(handler);
        let _ = self.server_configs.push(ServerConfig { service_types: st_vec, endpoints: ep_vec });

        self
    }

    /// Build the KnxNetIp link layer
    ///
    /// This method:
    /// 1. Deduplicates sockets based on ports
    /// 2. Maps servers to socket indices
    /// 3. Initializes sockets with multicast groups and broadcast
    /// 4. Creates the final KnxNetIp instance
    pub fn build<'res>(
        self,
        resources: &'res mut KnxNetIpResources<MAX_SOCKETS>,
        buffer_manager: &'res RefCell<DynBufferManager<'static>>,
        network_layer_tx: DynamicSender<'res, LayerOp<Buffer<'static>>>,
    ) -> KnxNetIp<'res, MAX_SOCKETS, MAX_SERVERS> {
        // Initialize response channel
        let response_channel = resources.response_channel.write(Channel::new());

        // Deduplicate endpoints by port
        let mut socket_descriptors = Vec::<SocketDescriptor, MAX_SOCKETS>::new();

        for config in &self.server_configs {
            for endpoint in &config.endpoints {
                let port = endpoint.port();

                // Check if we already have a socket for this port
                let existing_idx = socket_descriptors.iter().position(|desc| desc.port() == port);

                if let Some(idx) = existing_idx {
                    // Socket exists - add multicast groups if needed
                    if endpoint.is_multicast() {
                        let _ = socket_descriptors[idx].add_multicast_group(endpoint.address());
                    }
                    if endpoint.is_broadcast() {
                        socket_descriptors[idx].enable_broadcast();
                    }
                } else {
                    // New socket needed
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

        info!("KnxNetIp builder: {} server(s) using {} unique socket(s)", self.servers.len(), socket_descriptors.len());

        // Get interface address for multicast
        let interface_addr = match get_interface_address(self.interface_name) {
            Ok(addr) => {
                info!("Using network interface '{}' with IP address {}", self.interface_name, addr);
                addr
            }
            Err(e) => {
                error!("Failed to get address for interface '{}': {:?}", self.interface_name, e);
                error!("Falling back to UNSPECIFIED (0.0.0.0) - multicast may not work correctly");
                Ipv4Addr::UNSPECIFIED
            }
        };

        // Initialize socket array
        let sockets_array = resources.sockets.write([const { None }; MAX_SOCKETS]);

        // Create actual sockets
        for (i, desc) in socket_descriptors.iter().enumerate() {
            let port = desc.port();

            let options = UdpMulticastSocketOptions {
                address: Ipv4Addr::UNSPECIFIED,
                port,
                interface: Some(self.interface_name.into()),
                ..Default::default()
            };

            match AsyncUdpMulticastSocket::bind(options) {
                Ok(socket) => {
                    // Join multicast groups
                    for &mcast_addr in desc.multicast_groups() {
                        debug!(
                            "  Socket {}: Joining multicast group {} on interface {}",
                            i, mcast_addr, self.interface_name
                        );
                        if let Err(e) = socket.join_multicast(mcast_addr.into(), interface_addr) {
                            error!("Failed to join multicast group {}: {:?}", mcast_addr, e);
                        }
                    }

                    // Enable broadcast if needed
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

        // Build server instances with socket mappings
        let mut server_instances = Vec::<servers::ServerInstance, MAX_SERVERS>::new();

        for (idx, (handler, config)) in self.servers.into_iter().zip(self.server_configs.iter()).enumerate() {
            let mut socket_indices = Vec::new();

            // Find which sockets this server should listen on
            for endpoint in &config.endpoints {
                let port = endpoint.port();
                if let Some(sock_idx) = socket_descriptors.iter().position(|desc| desc.port() == port) {
                    if !socket_indices.contains(&sock_idx) {
                        let _ = socket_indices.push(sock_idx);
                    }
                }
            }

            let instance =
                servers::ServerInstance { service_types: config.service_types.clone(), socket_indices, handler };

            debug!("  Server {}: Handles {:?} on sockets {:?}", idx, instance.service_types, instance.socket_indices);

            let _ = server_instances.push(instance);
        }

        KnxNetIp {
            resources,
            socket_descriptors,
            server_instances,
            buffer_manager,
            interface_name: self.interface_name,
            local_addr: interface_addr,
            network_layer_tx,
            retry_queue: Vec::new(),
        }
    }
}

/// Implement LinkLayerBuilder for KnxNetIpBuilder
impl<const MAX_SOCKETS: usize, const MAX_SERVERS: usize> LinkLayerBuilder
    for KnxNetIpBuilder<MAX_SOCKETS, MAX_SERVERS>
{
    type Resources = KnxNetIpResources<MAX_SOCKETS>;

    fn build_and_run<'a, CTX>(
        self,
        resources: &'a mut Self::Resources,
        context: &'a CTX,
        network_layer: DynamicSender<'a, LayerOp<crate::messages::buffers::Buffer<'static>>>,
        inbox: impl Inbox<LayerOp<crate::messages::buffers::Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a
    where
        CTX: crate::context::BufferManagerContext,
    {
        // Build the link layer instance
        let mut link_layer = self.build(resources, context.buffer_manager(), network_layer);

        // Run the link layer's process loop
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

pub struct KnxNetIp<'res, const MAX_SOCKETS: usize, const MAX_SERVERS: usize> {
    /// Reference to socket resources
    resources: &'res KnxNetIpResources<MAX_SOCKETS>,
    /// Socket descriptors (metadata about each socket)
    socket_descriptors: Vec<SocketDescriptor, MAX_SOCKETS>,
    /// Server instances
    server_instances: Vec<servers::ServerInstance, MAX_SERVERS>,
    /// Buffer manager reference
    buffer_manager: &'res RefCell<DynBufferManager<'static>>,
    /// Interface name for logging
    interface_name: &'static str,
    /// Local interface IP address (used to filter out our own multicast echoes)
    local_addr: Ipv4Addr,
    /// Channel to send messages to the network layer
    network_layer_tx: DynamicSender<'res, LayerOp<Buffer<'static>>>,
    /// Queue of messages waiting to be retried after rate limiting
    retry_queue: Vec<PendingRequest, MAX_RETRY_QUEUE_SIZE>,
}

impl<'res, const MAX_SOCKETS: usize, const MAX_SERVERS: usize> KnxNetIp<'res, MAX_SOCKETS, MAX_SERVERS> {
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
                        let context = ServerContext::new(self.buffer_manager, self.network_layer_tx);
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
                    // Restore L_Data_Req service type before building confirmation
                    // (we changed it to L_Data_Ind for the routing protocol)
                    // FIXME: I don't like this approach of modifying the message like this
                    let mut inner = pending.message.into_inner();
                    inner.set_service_type(ServiceType::L_Data_Req);
                    pending.response_tx.send(inner.confirm().build()).await;
                } else if send_error {
                    let mut inner = pending.message.into_inner();
                    inner.set_service_type(ServiceType::L_Data_Req);
                    pending.response_tx.send(inner.error().build()).await;
                } else {
                    // No server could handle it - send error
                    let mut inner = pending.message.into_inner();
                    inner.set_service_type(ServiceType::L_Data_Req);
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
            match socket.send_to(data, *destination.ip(), destination.port()).await {
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

    /// Receive from a socket into a buffer
    async fn recv_from_socket(&self, socket_idx: usize) -> Result<(Buffer<'static>, SocketAddrV4), ()> {
        let sockets = unsafe { self.resources.sockets.assume_init_ref() };

        if let Some(Some(socket)) = sockets.get(socket_idx) {
            // Allocate buffer
            let mut buffer = self.buffer_manager.borrow().alloc().await;
            buffer.resize(buffer.capacity(), 0);

            // Receive data
            match socket.recv_from(&mut buffer[..]).await {
                Ok((len, addr, port)) => {
                    trace!(
                        "KNX/IP RX {} bytes on socket {} from {}:{}: {:x?}",
                        len,
                        socket_idx,
                        addr,
                        port,
                        &buffer[..len]
                    );
                    buffer.set_len(len);
                    Ok((buffer, SocketAddrV4::new(addr, port)))
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
}

impl<'res, const MAX_SOCKETS: usize, const MAX_SERVERS: usize> Layer<'res>
    for KnxNetIp<'res, MAX_SOCKETS, MAX_SERVERS>
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
                let destination = pending_response.destination;
                let data = &pending_response.buffer[..];

                debug!("Sending {} byte response to {} (drain)", data.len(), destination);

                if !self.socket_descriptors.is_empty() {
                    let _ = self.send_on_socket(0, data, destination).await;
                }
                // pending_response is dropped here, freeing its buffer
            }

            // Process any expired retry requests
            self.process_retry_queue(response_channel).await;

            // Select between socket receives, inbox messages, pending responses, and retry timer
            // Note: We create socket futures inline to avoid borrow checker issues
            let result = {
                // Create futures for receiving from all sockets
                let mut socket_futures = Vec::<_, MAX_SOCKETS>::new();
                for i in 0..self.socket_descriptors.len() {
                    let _ = socket_futures.push(self.recv_from_socket(i));
                }

                // Create timer future - either a scheduled timer or a never-completing future
                match self.get_next_retry_time() {
                    Some(next_retry) => {
                        select4(
                            select_slice(socket_futures.as_mut_slice()),
                            inbox.next(),
                            response_channel.receive(),
                            Timer::at(next_retry),
                        )
                        .await
                    }
                    None => {
                        select4(
                            select_slice(socket_futures.as_mut_slice()),
                            inbox.next(),
                            response_channel.receive(),
                            pending::<()>(),
                        )
                        .await
                    }
                }
            };

            match result {
                // Retry timer expired
                Either4::Fourth(()) => {
                    // Retry processing already happened at start of loop
                    trace!("KNX/IP retry timer expired");
                    continue;
                }
                // Socket received a packet
                Either4::First((Ok((buffer, source)), socket_idx)) => {
                    debug!("Received {} bytes on socket {} from {}", buffer.len(), socket_idx, source);

                    // Filter out our own multicast echoes
                    if *source.ip() == self.local_addr {
                        debug!("KNX/IP ignoring own multicast echo: {}", source);
                        continue;
                    }

                    // Peek at the service type from the KNX/IP header
                    match peek_service_type(&buffer[..]) {
                        Ok(service_type) => {
                            debug!("  Service type: {:?}", service_type);

                            // Find all servers that handle this service type on this socket
                            for server in &mut self.server_instances {
                                if server.handles(service_type, socket_idx) {
                                    // Create server context with buffer manager and network layer channel
                                    let context = ServerContext::new(self.buffer_manager, self.network_layer_tx);

                                    match server
                                        .handler
                                        .on_indication(service_type, &buffer[..], source, &context)
                                        .await
                                    {
                                        Ok(responses) => {
                                            for response in responses {
                                                // Queue responses for sending
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
                            warn!("Failed to parse KNX/IP service type from {}: {:?}", source, e);
                        }
                    }

                    // Buffer is automatically returned to the pool when dropped
                }

                // Socket receive error
                Either4::First((Err(()), socket_idx)) => {
                    error!("Socket {} receive error", socket_idx);
                    // Continue processing other sockets
                }

                // Inbox received a layer operation
                Either4::Second(layer_op) => {
                    trace!("KNX/IP received layer op: {:?}", layer_op);

                    match layer_op {
                        LayerOp::Indication(_msg) => {
                            // Link layer typically doesn't receive indications from upper layers
                            error!("KnxNetIp Link Layer received unexpected indication");
                        }
                        LayerOp::Request { message: msg, response_tx } => {
                            // Handle transmission requests
                            match msg.service_type() {
                                ServiceType::L_Data_Req => {
                                    debug!("KnxNetIp Link Layer sending L_Data_Req: {:x?}", msg);

                                    // Convert L_Data_Req to L_Data_Ind for KNX/IP routing
                                    // Messages originating from this device should be sent as indications
                                    // Extract inner KnxMessageBuffer to modify service type
                                    let mut inner_msg = msg.into_inner();
                                    inner_msg.set_service_type(ServiceType::L_Data_Ind);
                                    // Re-wrap as RequestMessage for the servers
                                    let msg = RequestMessage::request(inner_msg);

                                    // Find a server that supports outgoing requests
                                    let mut msg_opt = Some(msg);
                                    let mut handled = false;
                                    for server in &mut self.server_instances {
                                        if server.handler.supports_requests() {
                                            // Create server context with buffer manager and network layer channel
                                            let context =
                                                ServerContext::new(self.buffer_manager, self.network_layer_tx);
                                            match server
                                                .handler
                                                .on_request(&**msg_opt.as_ref().unwrap(), &context)
                                                .await
                                            {
                                                Ok(responses) => {
                                                    for response in responses {
                                                        response_channel.send(response).await;
                                                    }
                                                    // Send confirmation - restore L_Data_Req service type
                                                    // (we changed it to L_Data_Ind for the routing protocol)
                                                    // FIXME: I don't like this approach of modifying the message like this
                                                    let mut inner = msg_opt.take().unwrap().into_inner();
                                                    inner.set_service_type(ServiceType::L_Data_Req);
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
                                        // Restore L_Data_Req service type before building confirmation
                                        // FIXME: I don't like this approach of modifying the message like this
                                        let mut inner = msg_opt.take().unwrap().into_inner();
                                        inner.set_service_type(ServiceType::L_Data_Req);
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
                    let destination = pending_response.destination;
                    let data = &pending_response.buffer[..];

                    debug!("Sending {} byte response to {}", data.len(), destination);

                    // Find which socket to send on (use first socket for now - could be smarter)
                    if !self.socket_descriptors.is_empty() {
                        let _ = self.send_on_socket(0, data, destination).await;
                    } else {
                        error!("No sockets available to send response");
                    }
                }
            }
        }
    }
}
