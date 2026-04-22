//! Compile-time feature traits for the KNX/IP link layer.
//!
//! Each optional feature (routing, remote config, tunneling, TCP) is
//! represented by a trait with two marker-type implementations: an
//! enabled variant that delegates to the real server/handler/manager,
//! and a disabled variant whose associated types are zero-size and whose
//! methods are trivial no-ops that LLVM eliminates entirely.
//!
//! The [`Features`] struct bundles all four feature selections into a
//! single type parameter `F` on [`KnxNetIpBuilder`](super::KnxNetIpBuilder) and [`KnxNetIp`](super::KnxNetIp),
//! keeping the generic signatures manageable.
//!
//! # Binary size impact
//!
//! When a feature is disabled, its `Server`/`Handler`/`Manager` type is
//! `()` (zero bytes). All dispatch methods return empty results or
//! `pending()` futures with `Infallible` event types. The compiler
//! monomorphizes the containing structs and event loops per-configuration,
//! so disabled feature code is never linked into the final binary.

use core::marker::PhantomData;
use core::net::{Ipv4Addr, SocketAddrV4};

use heapless::Vec;

use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::knx::KnxMessageBuffer;
use zweidraehte_proto::messages::knxip::KNXnetIPServiceType;
use zweidraehte_proto::messages::knxip::substructs::{self, SupportedService};

use super::services::remote_config::RemoteConfigurationServer;
use super::services::routing::RoutingServer;
use super::{EndpointType, PendingResponse, ServerContext, ServerError};

// ============================================================================
// Feature Set Trait + Features Bundle
// ============================================================================

/// Bundles all four feature selections into associated types.
///
/// Implemented by [`Features<R, RC, TUN, TCP>`] for all valid
/// combinations of feature markers.
pub trait FeatureSet {
    type Routing: RoutingFeature;
    type RemoteConfig: RemoteConfigFeature;
    type Tunneling: TunnelingFeature;
    type Tcp: TcpFeature;

    /// PID_KNXNETIP_DEVICE_CAPABILITIES bitfield derived from enabled features.
    ///
    /// | Bit | Capability                        |
    /// |-----|-----------------------------------|
    /// |  0  | Device Management (always set)    |
    /// |  1  | Tunneling                         |
    /// |  2  | Routing                           |
    /// |  3  | Remote Logging (not implemented)  |
    /// |  4  | Remote Config & Diagnosis         |
    /// |  5  | Object Server (not implemented)   |
    const KNXNETIP_DEVICE_CAPABILITIES: u16 = 0x0001 // Device Management always present
        | if Self::Routing::ENABLED { 1 << 2 } else { 0 }
        | if Self::Tunneling::ENABLED { 1 << 1 } else { 0 }
        | if Self::RemoteConfig::ENABLED { 1 << 4 } else { 0 };
}

/// Bundle of feature marker types, parameterizing the KNX/IP link layer.
///
/// All four type parameters default to the disabled variant, so
/// `Features` (with no arguments) means "everything off."
pub struct Features<
    R: RoutingFeature = NoRouting,
    RC: RemoteConfigFeature = NoRemoteConfig,
    TUN: TunnelingFeature = NoTunneling,
    TCP: TcpFeature = NoTcp,
> {
    _phantom: PhantomData<(R, RC, TUN, TCP)>,
}

impl<R: RoutingFeature, RC: RemoteConfigFeature, TUN: TunnelingFeature, TCP: TcpFeature> FeatureSet
    for Features<R, RC, TUN, TCP>
{
    type Routing = R;
    type RemoteConfig = RC;
    type Tunneling = TUN;
    type Tcp = TCP;
}

/// All features disabled.
pub type DefaultFeatures = Features<NoRouting, NoRemoteConfig, NoTunneling, NoTcp>;

// ============================================================================
// Common Feature Configurations
// ============================================================================

/// KNX/IP Device (UDP only): routing + remote config.
///
/// Standard feature set for a KNX/IP routing device without TCP support.
pub type KnxIpDeviceUdp = Features<WithRouting, WithRemoteConfig, NoTunneling, NoTcp>;

/// KNX/IP Device (UDP + TCP): routing + remote config + TCP.
///
/// Standard feature set for a KNX/IP routing device with TCP support
/// (Core service family v2).
pub type KnxIpDeviceTcp = Features<WithRouting, WithRemoteConfig, NoTunneling, WithTcp>;

/// KNX/IP Interface (UDP only): tunneling + remote config.
///
/// Standard feature set for a KNX/IP tunneling interface without TCP.
/// `N` is the maximum number of tunneling slots (additional individual addresses).
pub type KnxIpInterfaceUdp<const N: usize> = Features<NoRouting, WithRemoteConfig, WithTunneling<N>, NoTcp>;

/// KNX/IP Interface (UDP + TCP): tunneling + remote config + TCP.
///
/// Standard feature set for a KNX/IP tunneling interface with TCP support
/// (Core service family v2).
/// `N` is the maximum number of tunneling slots (additional individual addresses).
pub type KnxIpInterfaceTcp<const N: usize> = Features<NoRouting, WithRemoteConfig, WithTunneling<N>, WithTcp>;

// ============================================================================
// Routing Feature
// ============================================================================

/// Compile-time feature slot for KNX/IP Routing.
///
/// The enabled variant ([`WithRouting`]) stores a [`RoutingServer`] and
/// delegates all dispatch calls. The disabled variant ([`NoRouting`])
/// uses `Server = ()` and returns empty results from all methods.
pub trait RoutingFeature: 'static {
    const ENABLED: bool;
    type Server;

    fn create_server(multicast_addr: Ipv4Addr, port: u16) -> Self::Server;
    fn supported_service() -> Option<SupportedService>;
    fn endpoints(multicast_addr: Ipv4Addr) -> Vec<EndpointType, 4>;
    fn service_types() -> Vec<KNXnetIPServiceType, 4>;
    fn supports_requests() -> bool;

    // Dispatch: receiving frames from the network.
    fn on_indication(
        server: &mut Self::Server,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        source: SocketAddrV4,
        context: &ServerContext<'_>,
    ) -> impl core::future::Future<Output = Result<Vec<PendingResponse, 4>, ServerError>>;

    // Dispatch: sending frames from the stack to the network.
    fn on_request(
        server: &mut Self::Server,
        message: &KnxMessageBuffer<Buffer<'static>>,
        context: &ServerContext<'_>,
    ) -> impl core::future::Future<Output = Result<Vec<PendingResponse, 4>, ServerError>>;

    /// Whether the server handles this service type on this socket.
    fn handles(service_type: KNXnetIPServiceType, socket_idx: usize, server_socket_indices: &[usize]) -> bool;

    /// Retarget the outbound routing multicast group. Called by the
    /// runtime rebind path after `PID_ROUTING_MULTICAST_ADDRESS`
    /// changes (03/02/06 §4.3.5.3.5.1). Disabled-routing impls
    /// default to a no-op.
    fn set_multicast_addr(_server: &Self::Server, _addr: Ipv4Addr) {}
}

/// Routing is enabled — delegates to [`RoutingServer`].
pub struct WithRouting;

impl RoutingFeature for WithRouting {
    const ENABLED: bool = true;
    type Server = RoutingServer;

    fn create_server(multicast_addr: Ipv4Addr, port: u16) -> Self::Server {
        RoutingServer::new(multicast_addr, port)
    }

    fn supported_service() -> Option<SupportedService> {
        Some(SupportedService { family: substructs::ServiceFamily::Routing, version: 1 })
    }

    fn endpoints(multicast_addr: Ipv4Addr) -> Vec<EndpointType, 4> {
        let mut eps = Vec::new();
        let _ = eps.push(EndpointType::new(multicast_addr, crate::KNX_PORT));
        eps
    }

    fn service_types() -> Vec<KNXnetIPServiceType, 4> {
        let mut st = Vec::new();
        let _ = st.push(KNXnetIPServiceType::RoutingIndication);
        let _ = st.push(KNXnetIPServiceType::RoutingBusy);
        let _ = st.push(KNXnetIPServiceType::RoutingLostMessage);
        let _ = st.push(KNXnetIPServiceType::RoutingSystemBroadcast);
        st
    }

    fn supports_requests() -> bool {
        true
    }

    async fn on_indication(
        server: &mut Self::Server,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        source: SocketAddrV4,
        context: &ServerContext<'_>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        use super::services::KnxNetIpServer;
        server.on_indication(service_type, data, source, context).await
    }

    async fn on_request(
        server: &mut Self::Server,
        message: &KnxMessageBuffer<Buffer<'static>>,
        context: &ServerContext<'_>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        use super::services::KnxNetIpServer;
        server.on_request(message, context).await
    }

    fn handles(service_type: KNXnetIPServiceType, socket_idx: usize, server_socket_indices: &[usize]) -> bool {
        Self::service_types().contains(&service_type) && server_socket_indices.contains(&socket_idx)
    }

    fn set_multicast_addr(server: &Self::Server, addr: Ipv4Addr) {
        server.set_multicast_addr(addr);
    }
}

/// Routing is disabled — zero-cost no-op.
pub struct NoRouting;

impl RoutingFeature for NoRouting {
    const ENABLED: bool = false;
    type Server = ();

    fn create_server(_multicast_addr: Ipv4Addr, _port: u16) -> Self::Server {}
    fn supported_service() -> Option<SupportedService> {
        None
    }
    fn endpoints(_multicast_addr: Ipv4Addr) -> Vec<EndpointType, 4> {
        Vec::new()
    }
    fn service_types() -> Vec<KNXnetIPServiceType, 4> {
        Vec::new()
    }
    fn supports_requests() -> bool {
        false
    }

    async fn on_indication(
        _server: &mut Self::Server,
        _service_type: KNXnetIPServiceType,
        _data: &[u8],
        _source: SocketAddrV4,
        _context: &ServerContext<'_>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        Ok(Vec::new())
    }

    async fn on_request(
        _server: &mut Self::Server,
        _message: &KnxMessageBuffer<Buffer<'static>>,
        _context: &ServerContext<'_>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        Err(ServerError::Unsupported)
    }

    fn handles(_service_type: KNXnetIPServiceType, _socket_idx: usize, _server_socket_indices: &[usize]) -> bool {
        false
    }
}

// ============================================================================
// Remote Config Feature
// ============================================================================

/// Compile-time feature slot for Remote Diagnostics & Configuration.
pub trait RemoteConfigFeature: 'static {
    const ENABLED: bool;
    type Server;

    fn create_server() -> Self::Server;
    fn supported_service() -> Option<SupportedService>;
    fn endpoints() -> Vec<EndpointType, 4>;
    fn service_types() -> Vec<KNXnetIPServiceType, 4>;

    /// Whether ip_diagnostics context should be exposed to servers.
    fn exposes_diagnostics() -> bool;

    fn on_indication(
        server: &mut Self::Server,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        source: SocketAddrV4,
        context: &ServerContext<'_>,
    ) -> impl core::future::Future<Output = Result<Vec<PendingResponse, 4>, ServerError>>;

    fn handles(service_type: KNXnetIPServiceType, socket_idx: usize, server_socket_indices: &[usize]) -> bool;
}

/// Remote config is enabled — delegates to [`RemoteConfigurationServer`].
pub struct WithRemoteConfig;

impl RemoteConfigFeature for WithRemoteConfig {
    const ENABLED: bool = true;
    type Server = RemoteConfigurationServer;

    fn create_server() -> Self::Server {
        RemoteConfigurationServer::new()
    }

    fn supported_service() -> Option<SupportedService> {
        Some(SupportedService { family: substructs::ServiceFamily::RemoteConfigAndDiag, version: 1 })
    }

    fn endpoints() -> Vec<EndpointType, 4> {
        // Remote Config listens on the spec-fixed System Setup
        // multicast — independent of PID_ROUTING_MULTICAST_ADDRESS.
        let mut eps = Vec::new();
        let _ = eps.push(EndpointType::new(crate::SYSTEM_SETUP_MULTICAST_ADDRESS, crate::KNX_PORT));
        eps
    }

    fn service_types() -> Vec<KNXnetIPServiceType, 4> {
        let mut st = Vec::new();
        let _ = st.push(KNXnetIPServiceType::RemoteDiagnosticRequest);
        let _ = st.push(KNXnetIPServiceType::RemoteBasicConfigurationRequest);
        let _ = st.push(KNXnetIPServiceType::RemoteResetRequest);
        st
    }

    fn exposes_diagnostics() -> bool {
        true
    }

    async fn on_indication(
        server: &mut Self::Server,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        source: SocketAddrV4,
        context: &ServerContext<'_>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        use super::services::KnxNetIpServer;
        server.on_indication(service_type, data, source, context).await
    }

    fn handles(service_type: KNXnetIPServiceType, socket_idx: usize, server_socket_indices: &[usize]) -> bool {
        Self::service_types().contains(&service_type) && server_socket_indices.contains(&socket_idx)
    }
}

/// Remote config is disabled — zero-cost no-op.
pub struct NoRemoteConfig;

impl RemoteConfigFeature for NoRemoteConfig {
    const ENABLED: bool = false;
    type Server = ();

    fn create_server() -> Self::Server {}
    fn supported_service() -> Option<SupportedService> {
        None
    }
    fn endpoints() -> Vec<EndpointType, 4> {
        Vec::new()
    }
    fn service_types() -> Vec<KNXnetIPServiceType, 4> {
        Vec::new()
    }
    fn exposes_diagnostics() -> bool {
        false
    }

    async fn on_indication(
        _server: &mut Self::Server,
        _service_type: KNXnetIPServiceType,
        _data: &[u8],
        _source: SocketAddrV4,
        _context: &ServerContext<'_>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        Ok(Vec::new())
    }

    fn handles(_service_type: KNXnetIPServiceType, _socket_idx: usize, _server_socket_indices: &[usize]) -> bool {
        false
    }
}

// ============================================================================
// Tunneling Feature
// ============================================================================

/// Compile-time feature slot for KNX/IP Tunneling.
///
/// Controls whether the connection manager includes a
/// [`TunnelConnectionHandler`](super::connections::TunnelConnectionHandler) and whether tunneling connections can
/// be accepted. The associated `Tunnel` type selects the concrete
/// [`TunnelingConnectedHandler`](super::connections::TunnelingConnectedHandler) implementation for the tunneling slot
/// in [`CompositeHandlers`](super::connections::CompositeHandlers).
#[allow(private_interfaces)] // build_handlers takes &dyn KnxNetIpContext (pub(crate)), but that's fine — only called internally
pub trait TunnelingFeature: 'static {
    const ENABLED: bool;

    /// Maximum number of tunneling slots (additional individual addresses).
    ///
    /// Used to size Vecs in the connection manager and server context.
    /// `0` when tunneling is disabled.
    const CAPACITY: usize;

    type Tunnel: super::connections::ConnectedHandler;

    fn supported_service() -> Option<SupportedService>;

    /// Build the composite handler collection for the connection manager.
    ///
    /// Device Management is always enabled (`WithDevMgmt`); the tunneling
    /// slot is selected by `Self::Tunnel`.
    ///
    /// The `cemi_sender` is the link-layer-side endpoint for sending cEMI
    /// events to the [`CemiTransportLayer`](crate::layers::transport::cemi::CemiTransportLayer).
    fn build_handlers<'a>(
        context: &'a dyn super::KnxNetIpContext,
        cemi_sender: embassy_sync::channel::DynamicSender<'a, crate::layers::transport::cemi::CemiEvent>,
    ) -> super::connections::CompositeHandlers<'a, super::connections::WithDevMgmt, Self::Tunnel>;
}

/// Tunneling is enabled.
///
/// The const generic `N` is the maximum number of tunneling slots
/// (additional individual addresses).
pub struct WithTunneling<const N: usize>;

#[allow(private_interfaces)]
impl<const N: usize> TunnelingFeature for WithTunneling<N> {
    const ENABLED: bool = true;
    const CAPACITY: usize = N;
    type Tunnel = super::connections::WithTunnel<N>;

    fn supported_service() -> Option<SupportedService> {
        Some(SupportedService { family: substructs::ServiceFamily::Tunneling, version: 1 })
    }

    fn build_handlers<'a>(
        context: &'a dyn super::KnxNetIpContext,
        cemi_sender: embassy_sync::channel::DynamicSender<'a, crate::layers::transport::cemi::CemiEvent>,
    ) -> super::connections::CompositeHandlers<'a, super::connections::WithDevMgmt, Self::Tunnel> {
        let dev_mgmt = super::connections::DeviceMgmtConnectionHandler::new(
            context.property_handler(),
            context.buffer_manager(),
            cemi_sender,
        );

        let mut additional_addresses = [zweidraehte_proto::address::IndividualAddress::default(); N];
        let addr_count = context.write_additional_individual_addresses(&mut additional_addresses);
        let ext_info = context.extended_device_information();
        let tunnel = super::connections::TunnelConnectionHandler::<N>::new(
            &additional_addresses[..addr_count],
            ext_info.device_descriptor_type0,
            context.manufacturer_code(),
            ext_info.max_local_apdu_len,
        );

        super::connections::CompositeHandlers::new(dev_mgmt, tunnel)
    }
}

/// Tunneling is disabled.
pub struct NoTunneling;

#[allow(private_interfaces)]
impl TunnelingFeature for NoTunneling {
    const ENABLED: bool = false;
    const CAPACITY: usize = 0;
    type Tunnel = super::connections::NoTunnel;

    fn supported_service() -> Option<SupportedService> {
        None
    }

    fn build_handlers<'a>(
        context: &'a dyn super::KnxNetIpContext,
        cemi_sender: embassy_sync::channel::DynamicSender<'a, crate::layers::transport::cemi::CemiEvent>,
    ) -> super::connections::CompositeHandlers<'a, super::connections::WithDevMgmt, Self::Tunnel> {
        let dev_mgmt = super::connections::DeviceMgmtConnectionHandler::new(
            context.property_handler(),
            context.buffer_manager(),
            cemi_sender,
        );

        super::connections::CompositeHandlers::new(dev_mgmt, ())
    }
}

// ============================================================================
// TCP Feature
// ============================================================================

/// Compile-time feature slot for TCP transport.
///
/// Controls whether a TCP listener is bound and whether TCP connections
/// can be accepted. When disabled, the TCP manager type is `()` and the
/// TCP event loop arm uses `pending()` with `Infallible` events.
pub trait TcpFeature: 'static {
    /// Whether TCP is enabled (affects Core service family version).
    fn is_enabled() -> bool;
}

/// TCP is enabled.
pub struct WithTcp;

impl TcpFeature for WithTcp {
    fn is_enabled() -> bool {
        true
    }
}

/// TCP is disabled.
pub struct NoTcp;

impl TcpFeature for NoTcp {
    fn is_enabled() -> bool {
        false
    }
}
