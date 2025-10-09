pub mod discovery;
pub mod remote_config;
pub mod routing;

pub use discovery::DiscoveryServer;
pub use remote_config::RemoteConfigurationServer;
pub use routing::RoutingServer;

use super::EndpointType;

/// Enum wrapping all possible KNX/IP server types
/// This allows us to store heterogeneous servers without using trait objects
#[derive(Debug, Clone, Copy)]
pub enum ServerType {
    Discovery(DiscoveryServer),
    Routing(RoutingServer),
    RemoteConfiguration(RemoteConfigurationServer),
}

impl ServerType {
    /// Get the number of interests for this server type
    pub const fn n_interests(&self) -> usize {
        match self {
            ServerType::Discovery(_) => DiscoveryServer::N_INTERESTS,
            ServerType::Routing(_) => RoutingServer::N_INTERESTS,
            ServerType::RemoteConfiguration(_) => RemoteConfigurationServer::N_INTERESTS,
        }
    }

    /// Get the interests for this server
    pub fn interests(&self) -> &[ServerInterest] {
        match self {
            ServerType::Discovery(s) => s.interests(),
            ServerType::Routing(s) => s.interests(),
            ServerType::RemoteConfiguration(s) => s.interests(),
        }
    }

    /// Handle a message
    pub fn handle_message(&self, service_code: u16, data: &[u8]) -> Result<(), ServerError> {
        match self {
            ServerType::Discovery(s) => s.handle_message(service_code, data),
            ServerType::Routing(s) => s.handle_message(service_code, data),
            ServerType::RemoteConfiguration(s) => s.handle_message(service_code, data),
        }
    }
}

impl From<DiscoveryServer> for ServerType {
    fn from(server: DiscoveryServer) -> Self {
        ServerType::Discovery(server)
    }
}

impl From<RoutingServer> for ServerType {
    fn from(server: RoutingServer) -> Self {
        ServerType::Routing(server)
    }
}

impl From<RemoteConfigurationServer> for ServerType {
    fn from(server: RemoteConfigurationServer) -> Self {
        ServerType::RemoteConfiguration(server)
    }
}

/// Error type for server operations
#[derive(Debug)]
pub enum ServerError {
    InvalidMessage,
    ParseError,
    Unsupported,
    InternalError,
}

/// A server interest registration: service code on a specific endpoint
#[derive(Debug, Clone, Copy)]
pub struct ServerInterest {
    pub service_code: u16,
    pub endpoint: EndpointType,
}

impl ServerInterest {
    pub const fn new(service_code: u16, endpoint: EndpointType) -> Self {
        Self { service_code, endpoint }
    }
}

/// Trait that all KNX/IP subservers must implement
pub trait KnxServer {
    /// The number of interests this server has
    const N_INTERESTS: usize;

    /// Get the list of interests (service codes and endpoints) for this server
    ///
    /// Each server declares what service codes it wants to handle on which endpoints.
    /// The interests are determined based on the local HPAI provided to the server.
    fn interests(&self) -> &[ServerInterest; Self::N_INTERESTS];

    /// Handle an incoming message for a specific service code
    ///
    /// # Arguments
    /// * `service_code` - The KNX/IP service type identifier
    /// * `data` - The message data (without the KNX/IP header)
    ///
    /// # Returns
    /// * `Ok(())` if the message was handled successfully
    /// * `Err(ServerError)` if there was an error handling the message
    ///
    /// # Note
    /// This method takes `&self` instead of `&mut self`. Servers that need to maintain
    /// mutable state should use interior mutability patterns (Cell, RefCell, or atomic types).
    fn handle_message(&self, service_code: u16, data: &[u8]) -> Result<(), ServerError>;
}
