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

// Re-export shared types so existing `use super::` paths in server files
// continue to work during the transition.
pub use super::types::{
    KnxNetIpServer, PacketOrigin, PendingResponse, ResponseTarget, ServerContext, ServerError,
};
pub(crate) use super::types::resolve_hpai;
