pub mod connection_manager;
pub mod discovery;
pub mod remote_config;
pub mod routing;

pub use connection_manager::{
    ConnectionManager, ConnectionManagerResult, ConnectionTransport, ConnectionTypeHandler,
    ConnectionTypeHandlerEnum, DeviceMgmtConnectionHandler, TcpChannelEvent,
};
pub use discovery::DiscoveryServer;
pub use remote_config::RemoteConfigurationServer;
pub use routing::RoutingServer;

use core::net::SocketAddrV4;
use heapless::Vec;

use crate::messages::{buffers::Buffer, knx::KnxMessageBuffer, knxip::KNXnetIPServiceType};

use super::{PendingResponse, ResponseTarget, ServerContext, ServerError};

/// Resolve an HPAI to a destination address, using the packet source when
/// the HPAI address is unspecified (`0.0.0.0`). The HPAI port is always
/// used — only the IP address is substituted.
///
/// Per KNX spec 3/8/2 §8.6.3.3: when a client sends a control HPAI with
/// IP address 0.0.0.0, the server shall use the IP source address of the
/// received request packet.
pub(super) fn resolve_hpai(
    hpai: &crate::messages::knxip::substructs::HPAI,
    packet_source: SocketAddrV4,
) -> SocketAddrV4 {
    let addr = hpai.address();
    if addr.is_unspecified() {
        SocketAddrV4::new(*packet_source.ip(), hpai.port())
    } else {
        SocketAddrV4::new(addr, hpai.port())
    }
}

/// Enum wrapping all possible KNX/IP server types
/// This allows us to store heterogeneous servers without using trait objects
#[derive(Debug)]
pub enum ServerHandler {
    Discovery(DiscoveryServer),
    Routing(RoutingServer),
    RemoteConfiguration(RemoteConfigurationServer),
}

impl ServerHandler {
    /// Handle incoming KNX/IP message received from the network
    pub async fn on_indication<'a>(
        &mut self,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        source: SocketAddrV4,
        context: &ServerContext<'a>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        match self {
            ServerHandler::Discovery(s) => s.on_indication(service_type, data, source, context).await,
            ServerHandler::Routing(s) => s.on_indication(service_type, data, source, context).await,
            ServerHandler::RemoteConfiguration(s) => s.on_indication(service_type, data, source, context).await,
        }
    }

    /// Handle KNX message from the stack that needs to be transmitted
    pub async fn on_request<'a>(
        &mut self,
        message: &KnxMessageBuffer<Buffer<'static>>,
        context: &ServerContext<'a>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        match self {
            ServerHandler::Discovery(s) => s.on_request(message, context).await,
            ServerHandler::Routing(s) => s.on_request(message, context).await,
            ServerHandler::RemoteConfiguration(s) => s.on_request(message, context).await,
        }
    }

    /// Check if this server can handle outgoing requests
    pub fn supports_requests(&self) -> bool {
        match self {
            ServerHandler::Discovery(s) => s.supports_requests(),
            ServerHandler::Routing(s) => s.supports_requests(),
            ServerHandler::RemoteConfiguration(s) => s.supports_requests(),
        }
    }
}

impl From<DiscoveryServer> for ServerHandler {
    fn from(server: DiscoveryServer) -> Self {
        ServerHandler::Discovery(server)
    }
}

impl From<RoutingServer> for ServerHandler {
    fn from(server: RoutingServer) -> Self {
        ServerHandler::Routing(server)
    }
}

impl From<RemoteConfigurationServer> for ServerHandler {
    fn from(server: RemoteConfigurationServer) -> Self {
        ServerHandler::RemoteConfiguration(server)
    }
}

/// Maximum number of service types per server instance
const MAX_SERVICE_TYPES: usize = 4;

/// Maximum number of sockets a server can listen on
const MAX_SERVER_SOCKETS: usize = 4;

/// Describes a server instance and what it handles
#[derive(Debug)]
pub struct ServerInstance {
    /// Which service types this server handles
    pub service_types: Vec<KNXnetIPServiceType, MAX_SERVICE_TYPES>,
    /// Which socket indices this server listens on (can be multiple)
    pub socket_indices: Vec<usize, MAX_SERVER_SOCKETS>,
    /// The actual server implementation
    pub handler: ServerHandler,
}

impl ServerInstance {
    /// Check if this server handles the given service type on the given socket
    pub fn handles(&self, service_type: KNXnetIPServiceType, socket_idx: usize) -> bool {
        self.service_types.contains(&service_type) && self.socket_indices.contains(&socket_idx)
    }
}

/// Trait that all KNX/IP servers must implement
pub trait KnxNetIpServer {
    /// Handle KNX/IP message received from the network
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

    /// Handle KNX message from the stack that needs to be transmitted
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

    /// Can this server handle outgoing messages?
    fn supports_requests(&self) -> bool {
        false
    }
}
