pub(crate) mod discovery;
pub(crate) mod remote_config;
pub(crate) mod routing;

pub(crate) use discovery::DiscoveryServer;

// Re-export shared types so `use super::` in individual service files
// resolves to these without needing `super::super::types::` paths.
pub(crate) use super::types::resolve_hpai;
pub(crate) use super::types::{KnxNetIpServer, PendingResponse, ResponseTarget, ServerContext, ServerError};
