pub mod connection_manager;
pub mod discovery;
pub mod remote_config;
pub mod routing;

pub use connection_manager::{
    CompositeHandlers, ConnectedHandler, ConnectionHandlers, ConnectionManager,
    ConnectionManagerResult, ConnectionTransport, ConnectionTypeHandler,
    DeviceMgmtConnectionHandler, NoDevMgmt, NoTunnel, TcpChannelEvent,
    TunnelConnectionHandler, TunnelingConnectedHandler, WithDevMgmt, WithTunnel,
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
/// IP address 0.0.0.0 and/or port 0, the server shall use the corresponding
/// values from the IP source address of the received request packet.
/// This supports NAT traversal scenarios where the client cannot know its
/// externally visible address/port.
pub(super) fn resolve_hpai(
    hpai: &crate::messages::knxip::substructs::HPAI,
    packet_source: SocketAddrV4,
) -> SocketAddrV4 {
    let addr = hpai.address();
    let ip = if addr.is_unspecified() {
        *packet_source.ip()
    } else {
        addr
    };
    let port = if hpai.port() == 0 {
        packet_source.port()
    } else {
        hpai.port()
    };
    SocketAddrV4::new(ip, port)
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
