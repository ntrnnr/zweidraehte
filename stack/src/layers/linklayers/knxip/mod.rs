use crate::{
    layers::{Inbox, Layer, LayerOp},
    messages::{buffers::Buffer, knx::*},
};

pub mod servers;

use core::net::Ipv4Addr;
use servers::KnxServer;

extern crate alloc;
use alloc::string::String;

use platform::{AsyncUdpMulticastSocket, UdpMulticastSocketOptions, address::Ipv4Address, get_interface_address};

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
    address: Ipv4Addr, // FIXME: this should be Ipv4Address from platform
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

    /// Build the final KnxNetIp instance with deduplicated endpoints
    ///
    /// This method deduplicates endpoints at build time based on actual bind addresses.
    /// Multiple local HPAIs may map to the same bind address (e.g., 0.0.0.0, 255.255.255.255
    /// both bind to 0.0.0.0).
    pub fn build(self) -> KnxNetIp<N_SERVERS, N_REGISTRATIONS> {
        // Deduplicate based on bind addresses (not local HPAIs)
        // Multiple logical endpoints may share the same socket
        let mut local_hpais = [EndpointType::new_udp(Ipv4Addr::new(0, 0, 0, 0), 0); N_REGISTRATIONS];
        let mut bind_addresses = [EndpointType::new_udp(Ipv4Addr::new(0, 0, 0, 0), 0); N_REGISTRATIONS];
        let mut needs_broadcast = [false; N_REGISTRATIONS];
        let mut endpoint_count = 0;

        for reg in &self.registrations {
            // Determine what bind address this endpoint would use
            let proposed_bind_address = if reg.endpoint.is_multicast() {
                // Multicast: bind to the specific multicast address
                reg.endpoint
            } else {
                // All others (unicast, broadcast, any): bind to 0.0.0.0
                EndpointType::new_udp(Ipv4Addr::new(0, 0, 0, 0), reg.endpoint.port())
            };

            // Check if we already have a socket for this bind address
            let mut found_index = None;
            for i in 0..endpoint_count {
                if bind_addresses[i].matches(&proposed_bind_address) {
                    found_index = Some(i);
                    break;
                }
            }

            if let Some(idx) = found_index {
                // Socket already exists - check if we need to enable broadcast on it
                if reg.endpoint.is_broadcast() {
                    needs_broadcast[idx] = true;
                }
            } else if endpoint_count < N_REGISTRATIONS {
                // New unique bind address - add it
                local_hpais[endpoint_count] = reg.endpoint;
                bind_addresses[endpoint_count] = proposed_bind_address;
                needs_broadcast[endpoint_count] = reg.endpoint.is_broadcast();
                endpoint_count += 1;
            }
        }

        info!("KnxNetIp builder found {} unique endpoints from {} registrations", endpoint_count, N_REGISTRATIONS);

        // Log each unique endpoint with its bind strategy
        for i in 0..endpoint_count {
            let local_hpai = &local_hpais[i];
            let bind_addr = &bind_addresses[i];

            let ep_type = if local_hpai.is_broadcast() {
                "broadcast"
            } else if local_hpai.is_multicast() {
                "multicast"
            } else if local_hpai.is_any() {
                "any interface"
            } else {
                "unicast"
            };
            let protocol = if local_hpai.is_udp() { "UDP" } else { "TCP" };

            if local_hpai.is_multicast() {
                debug!(
                    "  Endpoint {}: {} {}:{} ({}) - binding to {} and joining multicast group",
                    i,
                    protocol,
                    local_hpai.address(),
                    local_hpai.port(),
                    ep_type,
                    bind_addr.address()
                );
            } else {
                let broadcast_flag = if needs_broadcast[i] { " with SO_BROADCAST" } else { "" };
                debug!(
                    "  Endpoint {}: {} {}:{} ({}) - binding to 0.0.0.0:{}{}",
                    i,
                    protocol,
                    local_hpai.address(),
                    local_hpai.port(),
                    ep_type,
                    bind_addr.port(),
                    broadcast_flag
                );
            }
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
                Ipv4Address::UNSPECIFIED
            }
        };

        // Create sockets for each unique endpoint
        let mut sockets: [Option<AsyncUdpMulticastSocket>; N_REGISTRATIONS] = [const { None }; N_REGISTRATIONS];

        for i in 0..endpoint_count {
            let bind_addr = &bind_addresses[i];
            let local_hpai = &local_hpais[i];

            // Create socket options - bind to 0.0.0.0 (or multicast addr) and use SO_BINDTODEVICE
            let mut options = UdpMulticastSocketOptions {
                address: bind_addr.address().into(),
                port: bind_addr.port(),
                interface: Some(String::from(self.interface_name)),
                ..Default::default()
            };

            // Create and configure the socket
            match AsyncUdpMulticastSocket::bind(options) {
                Ok(socket) => {
                    // For multicast, join the multicast group using the interface's IP address
                    if local_hpai.is_multicast() {
                        debug!(
                            "  Socket {}: Created multicast socket, joining group {} on interface {} ({})",
                            i,
                            local_hpai.address(),
                            self.interface_name,
                            interface_addr
                        );
                        if let Err(e) = socket.join_multicast(local_hpai.address().into(), interface_addr) {
                            error!("Failed to join multicast group: {:?}", e);
                        }
                    }

                    if needs_broadcast[i] {
                        debug!("  Socket {}: Socket will receive broadcast traffic", i);
                        socket.set_broadcast(true).unwrap();
                    }

                    info!(
                        "  Socket {}: Bound to {}:{} on interface {}",
                        i,
                        bind_addr.address(),
                        bind_addr.port(),
                        self.interface_name
                    );
                    sockets[i] = Some(socket);
                }
                Err(e) => {
                    error!("Failed to create socket for endpoint {}: {:?}", i, e);
                    // Continue without this socket - error will be logged
                }
            }
        }

        KnxNetIp { servers: self.servers, registrations: self.registrations, sockets }
    }
}

#[derive(Debug)]
pub struct KnxNetIp<const N_SERVERS: usize, const N_REGISTRATIONS: usize> {
    servers: [servers::ServerType; N_SERVERS],
    registrations: [ServerRegistration; N_REGISTRATIONS],
    sockets: [Option<AsyncUdpMulticastSocket>; N_REGISTRATIONS],
}

impl<const N_SERVERS: usize, const N_REGISTRATIONS: usize> KnxNetIp<N_SERVERS, N_REGISTRATIONS> {
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

use heapless::Vec;

impl<'a, const N_SERVERS: usize, const N_REGISTRATIONS: usize> Layer<'a> for KnxNetIp<N_SERVERS, N_REGISTRATIONS> {
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Message>>,
    {
        // Endpoints are already deduplicated and sockets created in the builder
        info!("KnxNetIp Link Layer starting with {} servers, {} registrations", N_SERVERS, N_REGISTRATIONS);

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
