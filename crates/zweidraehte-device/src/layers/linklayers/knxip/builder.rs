use core::marker::PhantomData;
use core::net::{Ipv4Addr, SocketAddrV4};

use embassy_sync::channel::DynamicSender;
use heapless::Vec;

use zweidraehte_platform::{IpTransport, TcpListenerOptions};

use crate::{
    DEFAULT_MULTICAST_ADDR, KNX_PORT, SYSTEM_SETUP_MULTICAST_ADDRESS,
    context::AddressTableContext,
    layers::transport::cemi::CemiTransportLayerEndpoints,
    layers::{Inbox, LinkLayerBuilder, LinkLayerBuilderBase, LinkLayerCapabilities},
};
use zweidraehte_proto::messages::{
    buffers::Buffer,
    builder::{ConfirmationMessage, IndicationMessage, RequestMessage},
    knxip::substructs,
};

use super::definition::KnxNetIpDefinition;
use super::runtime::KnxNetIp;
use super::{
    EndpointType, KnxNetIpContext, KnxNetIpResources, SubnetLink, connections, features, services,
    transport::{SocketDescriptor, UdpManager},
};
use features::{FeatureSet, RemoteConfigFeature, RoutingFeature, TcpFeature, TunnelingFeature};

/// Builder for the KNX/IP link layer.
///
/// Parameterised by a single [`KnxNetIpDefinition`] `D`. The
/// numeric `const` parameters default off `D::*` so the typical
/// call site is just `KnxNetIpBuilder::<MyDevice>`; override
/// individual consts only when the trait defaults don't fit.
///
/// The discovery server (Core) and Device Management (connection type
/// 0x03) are always enabled — both are mandatory per KNX 3/8/1
/// Table 2. Every other optional feature comes from
/// `D::Features` (routing, tunneling, remote-config, TCP, IP Secure).
///
/// # Example
///
/// ```ignore
/// #[derive(Copy, Clone)]
/// struct MyDevice;
/// impl KnxNetIpDefinition for MyDevice {
///     type Transport = LinuxIpTransport;
///     type Features  = KnxIpDeviceTcp;
/// }
///
/// let builder = KnxNetIpBuilder::<MyDevice>::new(
///     "eth0", local_ipv4, control_endpoint, ());
/// ```
pub struct KnxNetIpBuilder<
    D: KnxNetIpDefinition,
    const MAX_SOCKETS: usize = { <D as KnxNetIpDefinition>::MAX_UDP_SOCKETS },
    const MAX_TCP_STREAMS: usize = { <D as KnxNetIpDefinition>::MAX_TCP_STREAMS },
    const MAX_CHANNELS: usize = { <D as KnxNetIpDefinition>::MAX_TCP_CHANNELS },
    const TUNNEL_CAPACITY: usize = { <D as KnxNetIpDefinition>::TUNNEL_CAPACITY },
    const MAX_CONNECTIONS: usize = { <D as KnxNetIpDefinition>::MAX_CONNECTIONS },
> {
    interface_name: &'static str,
    local_addr: Ipv4Addr,
    control_endpoint: SocketAddrV4,
    routing_multicast_addr: Ipv4Addr,
    socket_ctx: <<D::Transport as IpTransport>::UdpSocket as zweidraehte_platform::AsyncUdpSocket>::Context,
    _def: PhantomData<D>,
}

impl<
    D: KnxNetIpDefinition,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
    const TUNNEL_CAPACITY: usize,
    const MAX_CONNECTIONS: usize,
> KnxNetIpBuilder<D, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS, TUNNEL_CAPACITY, MAX_CONNECTIONS>
{
    /// Create a new builder with the network interface to bind to.
    ///
    /// The discovery server is always enabled (mandatory per KNX spec
    /// 3/8/2 §4.2). The `control_endpoint` HPAI is advertised in
    /// search and description responses. Routing multicast defaults to
    /// `224.0.23.12`; override with [`routing_multicast_addr`](Self::routing_multicast_addr).
    pub fn new(
        interface_name: &'static str,
        local_addr: Ipv4Addr,
        control_endpoint: SocketAddrV4,
        socket_ctx: <<D::Transport as IpTransport>::UdpSocket as zweidraehte_platform::AsyncUdpSocket>::Context,
    ) -> Self {
        Self {
            interface_name,
            local_addr,
            control_endpoint,
            routing_multicast_addr: DEFAULT_MULTICAST_ADDR,
            socket_ctx,
            _def: PhantomData,
        }
    }

    /// Override the routing multicast address.
    ///
    /// Defaults to `224.0.23.12` (the standard KNX multicast address).
    /// Custom addresses are used in some installations to separate
    /// routing domains or avoid conflicts with other KNX/IP routers on
    /// the same network segment.
    pub fn routing_multicast_addr(mut self, addr: Ipv4Addr) -> Self {
        self.routing_multicast_addr = addr;
        self
    }
}

// ============================================================================
// Build
// ============================================================================

impl<
    D: KnxNetIpDefinition,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
    const TUNNEL_CAPACITY: usize,
    const MAX_CONNECTIONS: usize,
> KnxNetIpBuilder<D, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS, TUNNEL_CAPACITY, MAX_CONNECTIONS>
where
    <<D::Features as FeatureSet>::Tunneling as TunnelingFeature>::Tunnel:
        connections::TunnelingConnectedHandler<TUNNEL_CAPACITY>,
{
    /// Build the KnxNetIp link layer.
    ///
    /// 1. Auto-derives supported services from the feature set.
    /// 2. Creates typed server instances (zero-size when disabled).
    /// 3. Deduplicates and creates UDP sockets.
    /// 4. Creates the connection manager with compile-time handler selection.
    /// 5. Returns the final `KnxNetIp` instance.
    pub(crate) fn build<'res>(
        self,
        resources: &'res KnxNetIpResources,
        context: &'res dyn KnxNetIpContext,
        cemi_ll: CemiTransportLayerEndpoints<'res>,
        ind_tx: DynamicSender<'res, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'res, ConfirmationMessage<Buffer<'static>>>,
        subnet_link: Option<SubnetLink<'res>>,
        address_filter: Option<&'res dyn super::types::AddressFilter>,
    ) -> KnxNetIp<
        'res,
        D::Transport,
        D::Features,
        MAX_SOCKETS,
        MAX_TCP_STREAMS,
        MAX_CHANNELS,
        TUNNEL_CAPACITY,
        MAX_CONNECTIONS,
    > {
        // ====================================================================
        // Auto-derive supported services from feature traits
        // ====================================================================

        let mut supported_services = Vec::<substructs::SupportedService, 5>::new();

        // Core v1: discovery, description, connection management over UDP.
        // Core v2 additionally requires TCP support (§9.2).
        let core_version = if <D::Features as FeatureSet>::Tcp::is_enabled() { 2 } else { 1 };
        let _ = supported_services
            .push(substructs::SupportedService { family: substructs::ServiceFamily::Core, version: core_version });

        // Device Management v2: mandatory for all KNXnet/IP device classes (3/8/1 Table 2).
        let _ = supported_services
            .push(substructs::SupportedService { family: substructs::ServiceFamily::DeviceManagement, version: 2 });

        if let Some(svc) = <<D::Features as FeatureSet>::Routing as RoutingFeature>::supported_service() {
            let _ = supported_services.push(svc);
        }
        if let Some(svc) = <<D::Features as FeatureSet>::Tunneling as TunnelingFeature>::supported_service() {
            let _ = supported_services.push(svc);
        }
        if let Some(svc) = <<D::Features as FeatureSet>::RemoteConfig as RemoteConfigFeature>::supported_service() {
            let _ = supported_services.push(svc);
        }

        // ====================================================================
        // Collect endpoints for socket deduplication
        // ====================================================================

        let mut all_endpoints = Vec::<EndpointType, 8>::new();

        // Discovery endpoints (always present). Spec-fixed at the
        // System Setup multicast per 03/02/06 §2.1 / 03/08/02 §4.2
        // — never moves with PID_ROUTING_MULTICAST_ADDRESS.
        let _ = all_endpoints.push(EndpointType::new(SYSTEM_SETUP_MULTICAST_ADDRESS, KNX_PORT));
        let _ = all_endpoints.push(EndpointType::new_any(KNX_PORT));

        // Routing endpoints (empty vec when disabled)
        for ep in <<D::Features as FeatureSet>::Routing as RoutingFeature>::endpoints(self.routing_multicast_addr) {
            let _ = all_endpoints.push(ep);
        }

        // Remote config endpoints (empty vec when disabled)
        for ep in <<D::Features as FeatureSet>::RemoteConfig as RemoteConfigFeature>::endpoints() {
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
            for desc_idx in 0..socket_descriptors.len() {
                if socket_descriptors[desc_idx].port() == KNX_PORT && !indices.contains(&desc_idx) {
                    let _ = indices.push(desc_idx);
                }
            }
            indices
        };

        let routing_socket_indices = {
            let mut indices = Vec::<usize, 4>::new();
            for ep in <<D::Features as FeatureSet>::Routing as RoutingFeature>::endpoints(self.routing_multicast_addr) {
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
            for ep in <<D::Features as FeatureSet>::RemoteConfig as RemoteConfigFeature>::endpoints() {
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

        let mut udp_manager = UdpManager::<D::Transport, MAX_SOCKETS>::new(interface_addr, socket_descriptors);
        udp_manager.bind_all(&self.socket_ctx, self.interface_name, interface_addr);

        // ====================================================================
        // Create typed servers (zero-size when feature is disabled)
        // ====================================================================

        let control_hpai = substructs::HPAI::ipv4_udp(*self.control_endpoint.ip(), self.control_endpoint.port());
        let discovery = services::DiscoveryServer::new(control_hpai, supported_services);

        let routing = <<D::Features as FeatureSet>::Routing as RoutingFeature>::create_server(
            self.routing_multicast_addr,
            KNX_PORT,
        );
        let remote_config = <<D::Features as FeatureSet>::RemoteConfig as RemoteConfigFeature>::create_server();

        // ====================================================================
        // Connection manager — handler type selected by TunnelingFeature
        // ====================================================================

        let handlers =
            <<D::Features as FeatureSet>::Tunneling as TunnelingFeature>::build_handlers(context, cemi_ll.event_sender);
        let connection_manager = connections::ConnectionManager::new(handlers);

        // ====================================================================
        // TCP manager — `Manager` associated type on `TcpFeature` is
        // `TcpManager<...>` for `WithTcp` and the zero-sized
        // `NoTcpManager` for `NoTcp`. The bind call also goes through
        // the trait so it folds to a no-op in the disabled case.
        // ====================================================================

        let mut tcp_manager =
            <<D::Features as FeatureSet>::Tcp as TcpFeature>::new::<D::Transport, MAX_TCP_STREAMS, MAX_CHANNELS, 512>();

        if <D::Features as FeatureSet>::Tcp::ENABLED {
            let tcp_options =
                TcpListenerOptions { bind_addr: self.control_endpoint, interface: Some(self.interface_name) };
            <<D::Features as FeatureSet>::Tcp as TcpFeature>::bind(&mut tcp_manager, &self.socket_ctx, tcp_options);
            info!("TCP listener bound on {} (interface {})", self.control_endpoint, self.interface_name);
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

// ============================================================================
// LinkLayerBuilder integration
// ============================================================================

impl<
    D: KnxNetIpDefinition + 'static,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
    const TUNNEL_CAPACITY: usize,
    const MAX_CONNECTIONS: usize,
> LinkLayerBuilderBase
    for KnxNetIpBuilder<D, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS, TUNNEL_CAPACITY, MAX_CONNECTIONS>
{
    type Resources = KnxNetIpResources;
    type LLEndpoints<'a> = CemiTransportLayerEndpoints<'a>;

    fn create_resources(&self) -> Self::Resources {
        KnxNetIpResources::new()
    }
}

impl<
    D: KnxNetIpDefinition + 'static,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
    const TUNNEL_CAPACITY: usize,
    const MAX_CONNECTIONS: usize,
> LinkLayerCapabilities
    for KnxNetIpBuilder<D, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS, TUNNEL_CAPACITY, MAX_CONNECTIONS>
{
    const KNXNETIP_DEVICE_CAPABILITIES: u16 = <D::Features as FeatureSet>::KNXNETIP_DEVICE_CAPABILITIES;
}

impl<
    CTX: KnxNetIpContext + AddressTableContext,
    D: KnxNetIpDefinition + 'static,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
    const TUNNEL_CAPACITY: usize,
    const MAX_CONNECTIONS: usize,
> LinkLayerBuilder<CTX>
    for KnxNetIpBuilder<D, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS, TUNNEL_CAPACITY, MAX_CONNECTIONS>
where
    <<D::Features as FeatureSet>::Tunneling as TunnelingFeature>::Tunnel:
        connections::TunnelingConnectedHandler<TUNNEL_CAPACITY>,
{
    fn build_and_run<'a>(
        self,
        resources: &'a mut Self::Resources,
        context: &'a CTX,
        ll_endpoints: CemiTransportLayerEndpoints<'a>,
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
