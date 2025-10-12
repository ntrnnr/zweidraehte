use crate::{
    context::BufferManagerContext,
    layers::{Inbox, Layer, LayerOp, LinkLayerBuilder},
    messages::{
        buffers::{Buffer, DynBufferManager, MessageBuffer},
        knx::*,
    },
};

pub mod servers;

use core::{cell::RefCell, net::Ipv4Addr, pin::pin};

use embassy_futures::select::select_slice;
use embassy_sync::channel::DynamicSender;
use heapless::Vec;
use servers::KnxServer;

// FIXME: NO ALLOC!
extern crate alloc;
use alloc::string::String;

use platform::{AsyncUdpMulticastSocket, UdpMulticastSocketOptions, get_interface_address};

/// Protocol type for KNX/IP endpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Udp,
    Tcp, // To be implemented later
}

/// Endpoint that KNX/IP servers can listen on
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

    /// Check if two endpoints match (same protocol, address, and port)
    pub const fn matches(&self, other: &EndpointType) -> bool {
        // Check protocol matches
        let protocol_matches = match (self.protocol, other.protocol) {
            (Protocol::Udp, Protocol::Udp) => true,
            (Protocol::Tcp, Protocol::Tcp) => true,
            _ => false,
        };

        protocol_matches
            && self.port == other.port
            && self.address.octets()[0] == other.address.octets()[0]
            && self.address.octets()[1] == other.address.octets()[1]
            && self.address.octets()[2] == other.address.octets()[2]
            && self.address.octets()[3] == other.address.octets()[3]
    }
}

impl Default for EndpointType {
    fn default() -> Self {
        Self::new_udp(Ipv4Addr::new(0, 0, 0, 0), 0)
    }
}

/// Registration of a server's interest in a service code on an endpoint
#[derive(Debug, Clone, Copy, Default)]
pub struct ServerRegistration {
    pub server_id: usize,
    pub service_code: u16, // KNX/IP service type identifier
    pub endpoint: EndpointType,
}

/// Wrapper around a socket that manages receive buffers using the buffer manager
///
/// This wrapper implements `Future` for receiving packets and provides a method
/// for sending packets. Received data is stored in buffers allocated from the
/// buffer manager.
pub struct ManagedSocket<'a> {
    socket: AsyncUdpMulticastSocket,
    buffer_manager: &'a RefCell<DynBufferManager<'static>>,
    endpoint: EndpointType,
}

impl<'a> ManagedSocket<'a> {
    /// Create a new managed socket
    pub fn new(
        socket: AsyncUdpMulticastSocket,
        buffer_manager: &'a RefCell<DynBufferManager<'static>>,
        endpoint: EndpointType,
    ) -> Self {
        Self { socket, buffer_manager, endpoint }
    }

    /// Send a packet to the specified destination
    pub async fn send_to(&self, data: &[u8], addr: Ipv4Addr, port: u16) -> Result<usize, platform::Error> {
        self.socket.send_to(data, addr, port).await
    }

    /// Get the endpoint this socket is bound to
    pub fn endpoint(&self) -> &EndpointType {
        &self.endpoint
    }

    /// Receive a packet into a buffer allocated from the buffer manager
    ///
    /// Returns a tuple of (buffer, source_address, source_port)
    pub async fn recv_from(&self) -> Result<(Buffer<'static>, Ipv4Addr, u16), platform::Error> {
        // Allocate a buffer for receiving
        let mut buffer = self.buffer_manager.borrow().alloc().await;
        buffer.resize(buffer.capacity(), 0);

        // Receive data into the buffer (buffer derefs to &mut [u8])
        let (len, addr, port) = self.socket.recv_from(&mut buffer[..]).await?;

        // Set buffer length to actual received length
        buffer.set_len(len);

        Ok((buffer, addr, port))
    }
}

impl<'a> core::fmt::Debug for ManagedSocket<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ManagedSocket").field("endpoint", &self.endpoint).finish_non_exhaustive()
    }
}

pub struct KnxNetIpBuilder<const N_SERVERS: usize, const N_REGISTRATIONS: usize> {
    servers: [servers::ServerType; N_SERVERS],
    registrations: [ServerRegistration; N_REGISTRATIONS],
    interface_name: &'static str,
}

impl KnxNetIpBuilder<0, 0> {
    /// Create a new builder with the network interface to bind to
    ///
    /// # Arguments
    /// * `interface_name` - The name of the network interface (e.g., "eth0", "wlan0")
    pub fn new(interface_name: &'static str) -> Self {
        Self { servers: [], registrations: [], interface_name }
    }
}

impl<const N_SERVERS: usize, const N_REGISTRATIONS: usize> KnxNetIpBuilder<N_SERVERS, N_REGISTRATIONS> {
    /// Add a server which automatically registers all its interests
    ///
    /// The server declares what service codes and endpoints it's interested in,
    /// and this method automatically creates registrations for all of them.
    pub fn add_server<S: KnxServer>(
        self,
        server: S,
    ) -> KnxNetIpBuilder<{ N_SERVERS + 1 }, { N_REGISTRATIONS + S::N_INTERESTS }>
    where
        servers::ServerType: From<S>,
    {
        let server_id = N_SERVERS;

        // Convert to ServerType enum
        let server_type = servers::ServerType::from(server);

        // Get the server's interests
        let interests = server_type.interests();

        // Add the server
        let mut new_servers: [servers::ServerType; N_SERVERS + 1] = [server_type; N_SERVERS + 1];
        let mut i = 0;
        while i < N_SERVERS {
            new_servers[i] = self.servers[i];
            i += 1;
        }
        new_servers[N_SERVERS] = server_type;

        // Create new registrations array with space for existing + new interests
        let mut new_registrations: [ServerRegistration; N_REGISTRATIONS + S::N_INTERESTS] =
            [ServerRegistration::default(); N_REGISTRATIONS + S::N_INTERESTS];

        // Copy existing registrations
        let mut i = 0;
        while i < N_REGISTRATIONS {
            new_registrations[i] = self.registrations[i];
            i += 1;
        }

        // Add new registrations from server's interests
        let mut i = 0;
        while i < S::N_INTERESTS {
            new_registrations[N_REGISTRATIONS + i] = ServerRegistration {
                server_id,
                service_code: interests[i].service_code,
                endpoint: interests[i].endpoint,
            };
            i += 1;
        }

        KnxNetIpBuilder { servers: new_servers, registrations: new_registrations, interface_name: self.interface_name }
    }

    /// Build the final KnxNetIp components with deduplicated endpoints
    ///
    /// This method deduplicates endpoints at build time based on actual bind addresses.
    /// Multiple local HPAIs may map to the same bind address (e.g., 0.0.0.0, 255.255.255.255
    /// both bind to 0.0.0.0).
    ///
    /// Returns a tuple of (servers, registrations, managed_sockets) that can be used to construct
    /// a KnxNetIp instance.
    fn build<'a>(
        self,
        buffer_manager: &'a RefCell<DynBufferManager<'static>>,
    ) -> (
        [servers::ServerType; N_SERVERS],
        [ServerRegistration; N_REGISTRATIONS],
        Vec<ManagedSocket<'a>, N_REGISTRATIONS>,
    ) {
        // Deduplicate based on bind addresses (not local HPAIs)
        // Multiple logical endpoints may share the same socket
        let mut local_hpais = [EndpointType::new_udp(Ipv4Addr::new(0, 0, 0, 0), 0); N_REGISTRATIONS];
        let mut bind_addresses = [EndpointType::new_udp(Ipv4Addr::new(0, 0, 0, 0), 0); N_REGISTRATIONS];
        let mut needs_broadcast = [false; N_REGISTRATIONS];
        let mut endpoint_count = 0;

        for reg in &self.registrations {
            // All endpoints bind to 0.0.0.0 for the given port
            // Multicast groups will be joined on the same socket
            let proposed_bind_address = EndpointType::new_udp(Ipv4Addr::new(0, 0, 0, 0), reg.endpoint.port());

            // Check if we already have a socket for this port
            let mut found_index = None;
            for i in 0..endpoint_count {
                if bind_addresses[i].port() == proposed_bind_address.port() {
                    found_index = Some(i);
                    break;
                }
            }

            if let Some(idx) = found_index {
                // Socket already exists for this port
                // Track if we need to enable broadcast
                if reg.endpoint.is_broadcast() {
                    needs_broadcast[idx] = true;
                }
                // Multicast groups will be joined later
            } else if endpoint_count < N_REGISTRATIONS {
                // New port - create a new socket
                local_hpais[endpoint_count] = reg.endpoint;
                bind_addresses[endpoint_count] = proposed_bind_address;
                needs_broadcast[endpoint_count] = reg.endpoint.is_broadcast();
                endpoint_count += 1;
            }
        }

        info!(
            "KnxNetIp builder: {} registrations consolidated into {} unique port(s)",
            N_REGISTRATIONS, endpoint_count
        );

        // Log each unique port and what it will handle
        for i in 0..endpoint_count {
            let port = bind_addresses[i].port();
            debug!("  Port {}: Will bind to 0.0.0.0:{} on interface {}", i, port, self.interface_name);
        }

        // Get the interface address for multicast joining
        let interface_addr = match get_interface_address(self.interface_name) {
            Ok(addr) => {
                info!(
                    "Using network interface '{}' with IP address {} (via SO_BINDTODEVICE)",
                    self.interface_name, addr
                );
                addr
            }
            Err(e) => {
                error!("Failed to get address for interface '{}': {:?}", self.interface_name, e);
                error!("Falling back to UNSPECIFIED (0.0.0.0) - multicast may not work correctly");
                Ipv4Addr::UNSPECIFIED
            }
        };

        // Collect all unique multicast groups per port
        let mut multicast_groups: [Vec<Ipv4Addr, N_REGISTRATIONS>; N_REGISTRATIONS] =
            [const { Vec::new() }; N_REGISTRATIONS];

        for reg in &self.registrations {
            if reg.endpoint.is_multicast() {
                // Find which socket index this port corresponds to
                for i in 0..endpoint_count {
                    if bind_addresses[i].port() == reg.endpoint.port() {
                        let mcast_addr = reg.endpoint.address();
                        // Only add if not already in the list (deduplicate)
                        if !multicast_groups[i].contains(&mcast_addr) {
                            let _ = multicast_groups[i].push(mcast_addr);
                        }
                        break;
                    }
                }
            }
        }

        // Create managed sockets for each unique port
        let mut managed_sockets: Vec<ManagedSocket<'a>, N_REGISTRATIONS> = Vec::new();

        for i in 0..endpoint_count {
            let bind_addr = &bind_addresses[i];
            let port = bind_addr.port();

            // Create socket options - bind to 0.0.0.0 and use SO_BINDTODEVICE
            let options = UdpMulticastSocketOptions {
                address: Ipv4Addr::UNSPECIFIED,
                port,
                interface: Some(String::from(self.interface_name)),
                ..Default::default()
            };

            // Create and configure the socket
            match AsyncUdpMulticastSocket::bind(options) {
                Ok(socket) => {
                    // Join all multicast groups for this port
                    if !multicast_groups[i].is_empty() {
                        for mcast_addr in &multicast_groups[i] {
                            debug!(
                                "  Socket {}: Joining multicast group {} on interface {} ({})",
                                i, mcast_addr, self.interface_name, interface_addr
                            );
                            if let Err(e) = socket.join_multicast((*mcast_addr).into(), interface_addr) {
                                error!("Failed to join multicast group {}: {:?}", mcast_addr, e);
                            }
                        }
                    }

                    if needs_broadcast[i] {
                        debug!("  Socket {}: Enabling SO_BROADCAST for broadcast traffic", i);
                        socket.set_broadcast(true).unwrap();
                    }

                    // Log socket binding with multicast groups
                    if multicast_groups[i].is_empty() {
                        info!(
                            "  Socket {}: Bound to 0.0.0.0:{} on interface {} (broadcast: {})",
                            i, port, self.interface_name, needs_broadcast[i]
                        );
                    } else {
                        // Build a comma-separated list of multicast addresses
                        let mut mcast_list = String::new();
                        for (idx, addr) in multicast_groups[i].iter().enumerate() {
                            if idx > 0 {
                                mcast_list.push_str(", ");
                            }
                            use core::fmt::Write;
                            let _ = write!(mcast_list, "{}", addr);
                        }
                        info!(
                            "  Socket {}: Bound to 0.0.0.0:{} on interface {} (multicast: [{}], broadcast: {})",
                            i, port, self.interface_name, mcast_list, needs_broadcast[i]
                        );
                    }

                    // Wrap the socket in a ManagedSocket and add to the list
                    // Use the bind address as the endpoint (0.0.0.0:port)
                    let managed = ManagedSocket::new(socket, buffer_manager, *bind_addr);
                    let _ = managed_sockets.push(managed);
                }
                Err(e) => {
                    error!("Failed to create socket for port {}: {:?}", port, e);
                    // Continue without this socket - error will be logged
                }
            }
        }

        (self.servers, self.registrations, managed_sockets)
    }
}

pub struct KnxNetIp<'a, const N_SERVERS: usize, const N_REGISTRATIONS: usize> {
    network_layer: embassy_sync::channel::DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    servers: [servers::ServerType; N_SERVERS],
    registrations: [ServerRegistration; N_REGISTRATIONS],
    sockets: Vec<ManagedSocket<'a>, N_REGISTRATIONS>,
}

impl<'a, const N_SERVERS: usize, const N_REGISTRATIONS: usize> core::fmt::Debug
    for KnxNetIp<'a, N_SERVERS, N_REGISTRATIONS>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KnxNetIp")
            .field("servers", &self.servers)
            .field("registrations", &self.registrations)
            .field("sockets", &self.sockets.len())
            .finish_non_exhaustive()
    }
}

impl<'a, const N_SERVERS: usize, const N_REGISTRATIONS: usize> KnxNetIp<'a, N_SERVERS, N_REGISTRATIONS> {
    /// Dispatch a message received on a specific endpoint to interested servers
    fn dispatch_message(&self, service_code: u16, endpoint: &EndpointType, data: &[u8]) {
        let mut dispatched = false;

        for reg in &self.registrations {
            if reg.service_code == service_code && reg.endpoint.matches(endpoint) {
                trace!("Dispatching service code 0x{:04x} to server {}", service_code, reg.server_id);

                if let Err(e) = self.servers[reg.server_id].handle_message(service_code, data) {
                    error!("Server {} failed to handle message: {:?}", reg.server_id, e);
                } else {
                    dispatched = true;
                }
            }
        }

        if !dispatched {
            trace!("No server registered for service code 0x{:04x} on endpoint {:?}", service_code, endpoint);
        }
    }
}

impl<'a, const N_SERVERS: usize, const N_REGISTRATIONS: usize> Layer<'a> for KnxNetIp<'a, N_SERVERS, N_REGISTRATIONS> {
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Message>>,
    {
        // Endpoints are already deduplicated and sockets created in the builder
        info!("KnxNetIp Link Layer starting with {} servers, {} registrations", N_SERVERS, N_REGISTRATIONS);

        loop {
            let mut s: Vec<_, N_REGISTRATIONS> = self.sockets.iter_mut().map(|s| s.recv_from()).collect();
            let a = select_slice(s.as_mut_slice()).await;
            if let (Ok((buffer, addr, port)), idx) = a {
                debug!("Received data on socket {}: {}:{} -> {} {:?}", idx, addr, port, buffer.len(), &buffer[..]);
            }
        }

        loop {
            // TODO: Use select to wait for:
            //   1. Incoming packets on any socket
            //   2. Layer operations from inbox
            //
            // For incoming packets:
            //   - Determine which endpoint it came from
            //   - Parse KNX/IP header to get service code
            //   - Call dispatch_message(service_code, endpoint, data)
            //
            // For layer operations:
            //   - Handle as below

            let layer_op = inbox.next().await;
            trace!("KnxNetIp Link Layer received layer op: {:?}", layer_op);

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
                            // TODO: Encapsulate in KNX/IP frame and send via appropriate socket
                            // For now, just send confirmation
                            let mut conf_msg = msg;
                            conf_msg.ctrl_field_mut().set_c(Confirm::NoError);
                            response_tx.send(conf_msg).await;
                        }
                        _ => {
                            // Return error for unsupported service types
                            let mut error_msg = msg;
                            error_msg.ctrl_field_mut().set_c(Confirm::Err);
                            response_tx.send(error_msg).await;
                        }
                    }
                }
            }
        }
    }
}

// Implement LinkLayerBuilder trait for KnxNetIpBuilder
impl<const N_SERVERS: usize, const N_REGISTRATIONS: usize> LinkLayerBuilder
    for KnxNetIpBuilder<N_SERVERS, N_REGISTRATIONS>
{
    fn build_and_run<'a, CTX>(
        self,
        context: &'a CTX,
        network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
        inbox: impl Inbox<LayerOp<KnxMessageBuffer<Buffer<'static>>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a
    where
        CTX: BufferManagerContext,
    {
        // Build the KnxNetIp components with ManagedSockets from the builder configuration
        let buffer_manager = context.buffer_manager();
        let (servers, registrations, managed_sockets) = self.build(buffer_manager);

        // Create the KnxNetIp instance directly
        let mut link_layer = KnxNetIp { network_layer, servers, registrations, sockets: managed_sockets };

        // Return a future that runs the link layer
        async move { link_layer.process(inbox).await }
    }
}
