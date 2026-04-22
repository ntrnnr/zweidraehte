use core::net::{Ipv4Addr, SocketAddrV4};

use embassy_sync::channel::DynamicSender;
use heapless::Vec;

use zweidraehte_platform::{IpTransport, TcpListenerOptions};

use crate::layers::{Inbox, LinkLayerBuilder, LinkLayerBuilderBase};
use zweidraehte_proto::messages::{
    buffers::Buffer,
    builder::{ConfirmationMessage, IndicationMessage, RequestMessage},
    knxip::substructs,
};

use super::runtime::KnxNetIp;
use super::{
    EndpointType, KnxNetIpContext, KnxNetIpResources, SubnetLink, connections, features, services,
    transport::{SocketDescriptor, TcpManager, UdpManager},
};
use features::{RemoteConfigFeature, RoutingFeature, TcpFeature, TunnelingFeature};

/// Builder for KnxNetIp link layer.
///
/// The discovery server (Core service family) and device management
/// (connection type 0x03) are always enabled — both are mandatory for
/// every KNXnet/IP device per KNX spec 3/8/1 Table 2.
///
/// Configure optional features using type-state builder methods:
/// - [`enable_routing_server()`](Self::enable_routing_server) — KNX/IP routing multicast
/// - [`enable_remote_config_server()`](Self::enable_remote_config_server) — Remote diagnostics
/// - [`enable_tunneling()`](Self::enable_tunneling) — KNX/IP tunneling connections
/// - [`enable_tcp()`](Self::enable_tcp) — TCP transport
///
/// Each `enable_*()` method is a compile-time type-state transition that
/// changes the `F` parameter. Disabled features use zero-size types and
/// their code is eliminated entirely by LLVM.
///
/// # Example
///
/// ```ignore
/// let builder = KnxNetIpBuilder::<LinuxIpTransport, _, 2>::new("eth0", interface_addr, endpoint, ())
///     .enable_routing_server()
///     .enable_remote_config_server();
/// ```
pub struct KnxNetIpBuilder<
    T: IpTransport,
    F: features::FeatureSet = features::DefaultFeatures,
    const MAX_SOCKETS: usize = 4,
    const MAX_TCP_STREAMS: usize = 1,
    const MAX_CHANNELS: usize = 1,
> {
    interface_name: &'static str,
    local_addr: Ipv4Addr,
    control_endpoint: SocketAddrV4,
    routing_multicast_addr: Ipv4Addr,
    socket_ctx: <T::UdpSocket as zweidraehte_platform::AsyncUdpSocket>::Context,
    _features: core::marker::PhantomData<F>,
}

impl<T: IpTransport, const MAX_SOCKETS: usize, const MAX_TCP_STREAMS: usize, const MAX_CHANNELS: usize>
    KnxNetIpBuilder<T, features::DefaultFeatures, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
{
    /// Create a new builder with the network interface to bind to.
    ///
    /// Starts with all optional features disabled. Use `enable_*()` methods
    /// to enable features at compile time.
    ///
    /// The discovery server is always enabled (mandatory per KNX spec 3/8/2
    /// §4.2). The `control_endpoint` HPAI is advertised in search and
    /// description responses.
    pub fn new(
        interface_name: &'static str,
        local_addr: Ipv4Addr,
        control_endpoint: SocketAddrV4,
        socket_ctx: <T::UdpSocket as zweidraehte_platform::AsyncUdpSocket>::Context,
    ) -> Self {
        Self {
            interface_name,
            local_addr,
            control_endpoint,
            routing_multicast_addr: crate::DEFAULT_MULTICAST_ADDR,
            socket_ctx,
            _features: core::marker::PhantomData,
        }
    }
}

impl<
    T: IpTransport,
    F: features::FeatureSet,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
> KnxNetIpBuilder<T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
{
    /// Override the routing multicast address.
    ///
    /// Defaults to `224.0.23.12` (the standard KNX multicast address).
    /// Custom addresses are used in some installations to separate routing
    /// domains or avoid conflicts with other KNX/IP routers on the same
    /// network segment.
    pub fn routing_multicast_addr(mut self, addr: Ipv4Addr) -> Self {
        self.routing_multicast_addr = addr;
        self
    }
}

// ============================================================================
// Type-state enable methods
// ============================================================================
//
// Each method consumes the builder and returns a new one with the
// corresponding feature marker changed from No* to With*. The method
// only exists on the No* variant, preventing double-enable.

impl<
    T: IpTransport,
    RC: features::RemoteConfigFeature,
    TUN: features::TunnelingFeature,
    TCP: features::TcpFeature,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
> KnxNetIpBuilder<T, features::Features<features::NoRouting, RC, TUN, TCP>, MS, MTS, MC>
{
    /// Enable the routing server (RoutingIndication / RoutingBusy / RoutingLostMessage).
    ///
    /// The routing server listens on the KNX multicast address for routing
    /// messages and implements congestion control per KNX Specification
    /// 3/8/2. Uses the default multicast address (`224.0.23.12`) unless
    /// overridden with [`routing_multicast_addr`](Self::routing_multicast_addr).
    pub fn enable_routing_server(
        self,
    ) -> KnxNetIpBuilder<T, features::Features<features::WithRouting, RC, TUN, TCP>, MS, MTS, MC> {
        KnxNetIpBuilder {
            interface_name: self.interface_name,
            local_addr: self.local_addr,
            control_endpoint: self.control_endpoint,
            routing_multicast_addr: self.routing_multicast_addr,
            socket_ctx: self.socket_ctx,
            _features: core::marker::PhantomData,
        }
    }
}

impl<
    T: IpTransport,
    R: features::RoutingFeature,
    TUN: features::TunnelingFeature,
    TCP: features::TcpFeature,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
> KnxNetIpBuilder<T, features::Features<R, features::NoRemoteConfig, TUN, TCP>, MS, MTS, MC>
{
    /// Enable the Remote Diagnostic and Configuration server (KNX 3/8/7).
    ///
    /// Handles connectionless remote diagnostics on multicast/broadcast:
    /// `RemoteDiagnosticRequest` (0x0740), `RemoteBasicConfigurationRequest`
    /// (0x0742), and `RemoteResetRequest` (0x0743).
    ///
    /// All three services are mandatory for KNX/IP certification (§6.2).
    /// The server listens on the KNX multicast address (`224.0.23.12:3671`).
    pub fn enable_remote_config_server(
        self,
    ) -> KnxNetIpBuilder<T, features::Features<R, features::WithRemoteConfig, TUN, TCP>, MS, MTS, MC> {
        KnxNetIpBuilder {
            interface_name: self.interface_name,
            local_addr: self.local_addr,
            control_endpoint: self.control_endpoint,
            routing_multicast_addr: self.routing_multicast_addr,
            socket_ctx: self.socket_ctx,
            _features: core::marker::PhantomData,
        }
    }
}

impl<
    T: IpTransport,
    R: features::RoutingFeature,
    RC: features::RemoteConfigFeature,
    TCP: features::TcpFeature,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
> KnxNetIpBuilder<T, features::Features<R, RC, features::NoTunneling, TCP>, MS, MTS, MC>
{
    /// Enable tunneling connections (ConnectionType 0x04).
    ///
    /// When enabled, KNX/IP clients can establish tunneling connections
    /// to transparently access the KNX bus. Each connection is assigned
    /// one of the device's additional individual addresses (from
    /// `PID_ADDITIONAL_INDIVIDUAL_ADDRESSES`). The number of concurrent
    /// tunneling connections equals the number of configured additional
    /// addresses.
    ///
    /// The const generic `N` sets the maximum number of tunneling slots.
    /// This must match the `N` on `IpExtensionState` / `IpSystemBDeviceState`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// builder.enable_tunneling::<4>()
    /// ```
    pub fn enable_tunneling<const N: usize>(
        self,
    ) -> KnxNetIpBuilder<T, features::Features<R, RC, features::WithTunneling<N>, TCP>, MS, MTS, MC> {
        KnxNetIpBuilder {
            interface_name: self.interface_name,
            local_addr: self.local_addr,
            control_endpoint: self.control_endpoint,
            routing_multicast_addr: self.routing_multicast_addr,
            socket_ctx: self.socket_ctx,
            _features: core::marker::PhantomData,
        }
    }
}

impl<
    T: IpTransport,
    R: features::RoutingFeature,
    RC: features::RemoteConfigFeature,
    TUN: features::TunnelingFeature,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
> KnxNetIpBuilder<T, features::Features<R, RC, TUN, features::NoTcp>, MS, MTS, MC>
{
    /// Enable TCP support for connection-oriented services.
    ///
    /// When enabled, a TCP listener is bound on the same port as the
    /// control endpoint. Clients (e.g., ETS) can establish TCP connections
    /// for Device Management and Tunneling. The Core service family
    /// version is bumped to v2 to indicate TCP support (KNX spec 3/8/2
    /// §9.2).
    pub fn enable_tcp(self) -> KnxNetIpBuilder<T, features::Features<R, RC, TUN, features::WithTcp>, MS, MTS, MC> {
        KnxNetIpBuilder {
            interface_name: self.interface_name,
            local_addr: self.local_addr,
            control_endpoint: self.control_endpoint,
            routing_multicast_addr: self.routing_multicast_addr,
            socket_ctx: self.socket_ctx,
            _features: core::marker::PhantomData,
        }
    }
}

// ============================================================================
// Build
// ============================================================================

impl<
    T: IpTransport,
    F: features::FeatureSet,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
> KnxNetIpBuilder<T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
where
    <F::Tunneling as features::TunnelingFeature>::Tunnel:
        connections::TunnelingConnectedHandler<{ <F::Tunneling as features::TunnelingFeature>::CAPACITY }>,
{
    /// Build the KnxNetIp link layer.
    ///
    /// This method:
    /// 1. Auto-derives supported services from enabled feature traits
    /// 2. Creates typed server instances (zero-size when disabled)
    /// 3. Deduplicates and creates UDP sockets
    /// 4. Creates the connection manager with compile-time handler selection
    /// 5. Returns the final `KnxNetIp` instance
    pub(crate) fn build<'res>(
        self,
        resources: &'res KnxNetIpResources,
        context: &'res dyn KnxNetIpContext,
        cemi_ll: crate::layers::transport::cemi::CemiTransportLayerEndpoints<'res>,
        ind_tx: DynamicSender<'res, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'res, ConfirmationMessage<Buffer<'static>>>,
        subnet_link: Option<SubnetLink<'res>>,
        address_filter: Option<&'res dyn super::types::AddressFilter>,
    ) -> KnxNetIp<'res, T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS> {
        // ====================================================================
        // Auto-derive supported services from feature traits
        // ====================================================================

        let mut supported_services = Vec::<substructs::SupportedService, 5>::new();

        // Core v1: discovery, description, connection management over UDP.
        // Core v2 additionally requires TCP support (§9.2).
        let core_version = if F::Tcp::is_enabled() { 2 } else { 1 };
        let _ = supported_services
            .push(substructs::SupportedService { family: substructs::ServiceFamily::Core, version: core_version });

        // Device Management v2: mandatory for all KNXnet/IP device classes (3/8/1 Table 2).
        let _ = supported_services
            .push(substructs::SupportedService { family: substructs::ServiceFamily::DeviceManagement, version: 2 });

        if let Some(svc) = F::Routing::supported_service() {
            let _ = supported_services.push(svc);
        }
        if let Some(svc) = F::Tunneling::supported_service() {
            let _ = supported_services.push(svc);
        }
        if let Some(svc) = F::RemoteConfig::supported_service() {
            let _ = supported_services.push(svc);
        }

        // ====================================================================
        // Collect endpoints for socket deduplication
        // ====================================================================
        //
        // Each feature contributes its required endpoints. The discovery
        // server always needs multicast + unicast on KNX_PORT. Routing and
        // remote config may share the multicast socket.

        let mut all_endpoints = Vec::<EndpointType, 8>::new();

        // Discovery endpoints (always present). Spec-fixed at the
        // System Setup multicast per 03/02/06 §2.1 / 03/08/02 §4.2
        // — never moves with PID_ROUTING_MULTICAST_ADDRESS.
        let _ = all_endpoints.push(EndpointType::new(crate::SYSTEM_SETUP_MULTICAST_ADDRESS, crate::KNX_PORT));
        let _ = all_endpoints.push(EndpointType::new_any(crate::KNX_PORT));

        // Routing endpoints (empty vec when disabled)
        for ep in F::Routing::endpoints(self.routing_multicast_addr) {
            let _ = all_endpoints.push(ep);
        }

        // Remote config endpoints (empty vec when disabled)
        for ep in F::RemoteConfig::endpoints() {
            let _ = all_endpoints.push(ep);
        }

        // ====================================================================
        // Deduplicate endpoints into sockets
        // ====================================================================

        let mut socket_descriptors = Vec::<SocketDescriptor, MAX_SOCKETS>::new();

        for endpoint in &all_endpoints {
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
                let bind_addr = EndpointType::new(Ipv4Addr::UNSPECIFIED, port);
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

        // Build socket index lists for each feature's server. A server
        // "owns" the sockets whose ports match its registered endpoints.
        let discovery_socket_indices = {
            let mut indices = Vec::<usize, 4>::new();
            // Discovery listens on multicast + unicast on KNX_PORT
            for desc_idx in 0..socket_descriptors.len() {
                if socket_descriptors[desc_idx].port() == crate::KNX_PORT && !indices.contains(&desc_idx) {
                    let _ = indices.push(desc_idx);
                }
            }
            indices
        };

        let routing_socket_indices = {
            let mut indices = Vec::<usize, 4>::new();
            for ep in F::Routing::endpoints(self.routing_multicast_addr) {
                if let Some(idx) = socket_descriptors.iter().position(|d| d.port() == ep.port())
                    && !indices.contains(&idx)
                {
                    let _ = indices.push(idx);
                }
            }
            indices
        };

        let remote_config_socket_indices = {
            let mut indices = Vec::<usize, 4>::new();
            for ep in F::RemoteConfig::endpoints() {
                if let Some(idx) = socket_descriptors.iter().position(|d| d.port() == ep.port())
                    && !indices.contains(&idx)
                {
                    let _ = indices.push(idx);
                }
            }
            indices
        };

        info!("KnxNetIp builder: {} unique socket(s)", socket_descriptors.len());

        let interface_addr = self.local_addr;

        // ====================================================================
        // UDP manager — owns sockets and their descriptors
        // ====================================================================

        let mut udp_manager = UdpManager::new(interface_addr, socket_descriptors);
        udp_manager.bind_all(&self.socket_ctx, self.interface_name, interface_addr);

        // ====================================================================
        // Create typed servers (zero-size when feature is disabled)
        // ====================================================================

        let control_hpai = substructs::HPAI::ipv4_udp(*self.control_endpoint.ip(), self.control_endpoint.port());
        let discovery = services::DiscoveryServer::new(control_hpai, supported_services);

        let routing = F::Routing::create_server(self.routing_multicast_addr, crate::KNX_PORT);
        let remote_config = F::RemoteConfig::create_server();

        // ====================================================================
        // Connection manager — handler type selected by TunnelingFeature
        // ====================================================================

        let handlers = F::Tunneling::build_handlers(context, cemi_ll.event_sender);
        let connection_manager = connections::ConnectionManager::new(handlers);

        // ====================================================================
        // TCP manager
        // ====================================================================

        let mut tcp_manager = TcpManager::new();

        if F::Tcp::is_enabled() {
            let tcp_options =
                TcpListenerOptions { bind_addr: self.control_endpoint, interface: Some(self.interface_name) };
            match tcp_manager.bind(tcp_options) {
                Ok(()) => {
                    info!("TCP listener bound on {} (interface {})", self.control_endpoint, self.interface_name);
                }
                Err(_e) => {
                    error!("Failed to bind TCP listener on {}: {:?}", self.control_endpoint, _e);
                }
            }
        }

        KnxNetIp {
            resources,
            udp_manager,
            discovery,
            discovery_socket_indices,
            routing,
            routing_socket_indices,
            remote_config,
            remote_config_socket_indices,
            ind_tx,
            conf_tx,
            retry_queue: Vec::new(),
            connection_manager,
            context,
            cemi_response_receiver: Some(cemi_ll.response_receiver),
            tcp_manager,
            subnet_link,
            address_filter,
            interface_addr,
        }
    }
}

impl<
    T: IpTransport + 'static,
    F: features::FeatureSet,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
> LinkLayerBuilderBase for KnxNetIpBuilder<T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
{
    type Resources = KnxNetIpResources;
    type LLEndpoints<'a> = crate::layers::transport::cemi::CemiTransportLayerEndpoints<'a>;

    fn create_resources(&self) -> Self::Resources {
        KnxNetIpResources::new()
    }
}

impl<
    T: IpTransport + 'static,
    F: features::FeatureSet,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
> crate::layers::LinkLayerCapabilities for KnxNetIpBuilder<T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
{
    const KNXNETIP_DEVICE_CAPABILITIES: u16 = F::KNXNETIP_DEVICE_CAPABILITIES;
}

impl<
    CTX: KnxNetIpContext + crate::context::AddressTableContext,
    T: IpTransport + 'static,
    F: features::FeatureSet + 'static,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
> LinkLayerBuilder<CTX> for KnxNetIpBuilder<T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
where
    <F::Tunneling as features::TunnelingFeature>::Tunnel:
        connections::TunnelingConnectedHandler<{ <F::Tunneling as features::TunnelingFeature>::CAPACITY }>,
{
    fn build_and_run<'a>(
        self,
        resources: &'a mut Self::Resources,
        context: &'a CTX,
        ll_endpoints: crate::layers::transport::cemi::CemiTransportLayerEndpoints<'a>,
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl Inbox<RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        // Construct address filter while we still have the concrete context
        // type (before type-erasure to &dyn KnxNetIpContext). Same pattern
        // as TPUART's AutoAddressChecker → DeviceAddressChecker.
        let address_filter =
            super::types::RoutingAddressFilter::new(context.individual_address(), context.address_table());
        async move {
            let mut link_layer =
                self.build(resources, context, ll_endpoints, ind_tx, conf_tx, None, Some(&address_filter));
            link_layer.run(req_rx).await
        }
    }
}
