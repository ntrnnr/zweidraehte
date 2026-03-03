use core::future::pending;
use core::net::SocketAddrV4;

use embassy_futures::select::{Either4, select4};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicSender},
};
use embassy_time::{Duration, Instant, Timer};
use heapless::Vec;

use platform::IpTransport;

use crate::{
    context::IpDiagnosticsContext,
    layers::Inbox,
    messages::{
        buffers::Buffer,
        builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage, RequestMessage},
        knx::*,
        knxip::*,
    },
};

use super::{
    KnxNetIpContext, KnxNetIpResources, PacketOrigin, PendingResponse, ResponseTarget, ServerContext, ServerError,
    SubnetIndication, SubnetLink,
    connections,
    features::{self, RemoteConfigFeature, RoutingFeature},
    services,
    transport::{TcpEvent, TcpManager, UdpEvent, UdpManager},
};

/// A request that is pending retry after being rate-limited
pub(super) struct PendingRequest {
    /// The message to retry
    message: RequestMessage<Buffer<'static>>,
    /// When to retry sending this message
    retry_after: Instant,
    /// Number of times this message has been retried
    retry_count: u8,
}

/// Maximum number of messages that can be queued for retry
const MAX_RETRY_QUEUE_SIZE: usize = 16;

/// Maximum number of retry attempts before giving up
const MAX_RETRY_ATTEMPTS: u8 = 5;

/// Build a [`ServerContext`] from individual [`KnxNetIp`] fields.
///
/// Free function instead of a method so the borrow checker can see that
/// server fields are disjoint from the context and channel fields.
/// The `RC` type parameter controls whether IP diagnostics are exposed.
///
/// The caller materialises the additional-address and tunneling-slot data
/// into local buffers (with the correct capacity `N`) and passes slices.
fn make_server_context<'a, RC: RemoteConfigFeature>(
    context: &'a dyn KnxNetIpContext,
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    additional_addresses: &'a [crate::address::IndividualAddress],
    tunneling_slot_info: Option<(u16, &'a [substructs::TunnelingSlotInfo])>,
) -> ServerContext<'a> {
    let ip_diagnostics: Option<&dyn IpDiagnosticsContext> =
        if RC::exposes_diagnostics() { Some(context) } else { None };
    ServerContext::new(
        context.buffer_manager(),
        ind_tx,
        context.max_apdu_length(),
        context,
        ip_diagnostics,
        additional_addresses,
        context,
        tunneling_slot_info,
    )
}

pub struct KnxNetIp<
    'res,
    T: IpTransport,
    F: features::FeatureSet = features::DefaultFeatures,
    const MAX_SOCKETS: usize = 4,
    const MAX_TCP_STREAMS: usize = 1,
    const MAX_CHANNELS: usize = 1,
> where
    [(); <F::Tunneling as features::TunnelingFeature>::CAPACITY]:,
    <F::Tunneling as features::TunnelingFeature>::Tunnel:
        connections::TunnelingConnectedHandler<{ <F::Tunneling as features::TunnelingFeature>::CAPACITY }>,
{
    /// Reference to externally-owned resources (response channel).
    pub(super) resources: &'res KnxNetIpResources,
    /// UDP socket manager. Owns sockets and their descriptors.
    pub(super) udp_manager: UdpManager<T, MAX_SOCKETS>,

    // ---- Typed server fields (zero-size when feature is disabled) ----
    /// Discovery server — always present (mandatory per KNX spec).
    pub(super) discovery: services::DiscoveryServer,
    /// Socket indices the discovery server listens on.
    pub(super) discovery_socket_indices: Vec<usize, 4>,

    /// Routing server — `()` when `NoRouting`.
    pub(super) routing: <F::Routing as features::RoutingFeature>::Server,
    /// Socket indices for the routing server (empty when disabled).
    pub(super) routing_socket_indices: Vec<usize, 4>,

    /// Remote config server — `()` when `NoRemoteConfig`.
    pub(super) remote_config: <F::RemoteConfig as features::RemoteConfigFeature>::Server,
    /// Socket indices for the remote config server (empty when disabled).
    pub(super) remote_config_socket_indices: Vec<usize, 4>,

    /// Channel to send indications (received frames) up to the network layer.
    pub(super) ind_tx: DynamicSender<'res, IndicationMessage<Buffer<'static>>>,
    /// Channel to send confirmations (transmission results) up to the network layer.
    pub(super) conf_tx: DynamicSender<'res, ConfirmationMessage<Buffer<'static>>>,
    /// Queue of messages waiting to be retried after rate limiting.
    pub(super) retry_queue: Vec<PendingRequest, MAX_RETRY_QUEUE_SIZE>,
    /// Connection manager for connection-oriented services.
    /// The handler collection is a `CompositeHandlers` with the tunneling
    /// slot selected by `TunnelingFeature::Tunnel`.
    pub(super) connection_manager: connections::ConnectionManager<
        connections::CompositeHandlers<'res, connections::WithDevMgmt, <F::Tunneling as features::TunnelingFeature>::Tunnel>,
        { <F::Tunneling as features::TunnelingFeature>::CAPACITY },
        MAX_CHANNELS,
    >,
    /// Type-erased stack context providing buffer management, device info,
    /// IP diagnostics, KNX addresses, and property service access.
    pub(super) context: &'res dyn KnxNetIpContext,
    /// Receiver for cEMI response frames from the layer stack's
    /// [`CemiTransportLayer`](crate::layers::transport::cemi::CemiTransportLayer).
    /// `Some` when a cEMI TL bridge is active (KNX/IP device stacks),
    /// `None` otherwise.
    pub(super) cemi_response_receiver: Option<embassy_sync::channel::DynamicReceiver<'res, Buffer<'static>>>,
    /// TCP connection manager. Always present; without a bound listener
    /// it is a no-op.
    pub(super) tcp_manager: TcpManager<T, MAX_TCP_STREAMS, MAX_CHANNELS>,
    /// Bus bridge for IP Interface composite mode.
    ///
    /// When `Some`, this KNX/IP instance is part of a composite link layer
    /// bridging to a TP1 bus. `AckAndInject` frames are routed to
    /// `subnet_inject_tx` instead of the real `ind_tx`, and bus indications
    /// arrive via `subnet_ind_rx` for forwarding to tunnel clients.
    pub(super) subnet_link: Option<SubnetLink<'res>>,
}

impl<
    'res,
    T: IpTransport,
    F: features::FeatureSet,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
> KnxNetIp<'res, T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
where
    <F::Tunneling as features::TunnelingFeature>::Tunnel:
        connections::TunnelingConnectedHandler<{ <F::Tunneling as features::TunnelingFeature>::CAPACITY }>,
    connections::CompositeHandlers<'res, connections::WithDevMgmt, <F::Tunneling as features::TunnelingFeature>::Tunnel>:
        connections::ConnectionHandlers<{ <F::Tunneling as features::TunnelingFeature>::CAPACITY }>,
{
    /// Process expired retry requests.
    ///
    /// Only the routing server supports outgoing requests (`on_request`).
    /// When routing is disabled (`NoRouting`), `supports_requests()` returns
    /// false and `on_request()` returns `Err(Unsupported)`, so retries are
    /// no-ops that the compiler eliminates.
    async fn process_retry_queue(&mut self, response_channel: &Channel<NoopRawMutex, PendingResponse, 16>) {
        if !F::Routing::supports_requests() {
            // No server supports outgoing requests — drain any stale entries.
            // (Should be empty, but defensive.)
            self.retry_queue.clear();
            return;
        }

        let now = Instant::now();
        let mut i = 0;
        while i < self.retry_queue.len() {
            if now >= self.retry_queue[i].retry_after {
                let mut pending = self.retry_queue.swap_remove(i);

                debug!("Retrying message (attempt {}/{})", pending.retry_count + 1, MAX_RETRY_ATTEMPTS);

                let mut addr_buf = [crate::address::IndividualAddress::default();
                    <F::Tunneling as features::TunnelingFeature>::CAPACITY];
                let addr_count =
                    crate::context::IpAdditionalIndividualAddressContext::write_additional_individual_addresses(
                        self.context,
                        &mut addr_buf,
                    );
                let tunnel_slots = self.connection_manager.tunneling_slot_info();
                let tunnel_ref = tunnel_slots.as_ref().map(|(len, v)| (*len, v.as_slice()));
                let context = make_server_context::<F::RemoteConfig>(
                    self.context,
                    self.ind_tx,
                    &addr_buf[..addr_count],
                    tunnel_ref,
                );

                match F::Routing::on_request(&mut self.routing, &pending.message, &context).await {
                    Ok(responses) => {
                        for response in responses {
                            response_channel.send(response).await;
                        }
                        let inner = pending.message.into_inner();
                        self.conf_tx.send(inner.confirm().build()).await;
                    }
                    Err(ServerError::Busy(wait_time)) => {
                        pending.retry_count += 1;
                        if pending.retry_count < MAX_RETRY_ATTEMPTS {
                            pending.retry_after = Instant::now() + Duration::from_millis(wait_time as u64);
                            debug!(
                                "Still busy, requeuing (attempt {}/{}, wait {}ms)",
                                pending.retry_count, MAX_RETRY_ATTEMPTS, wait_time
                            );
                            if self.retry_queue.push(pending).is_err() {
                                error!("Retry queue full after swap_remove, dropping message");
                            }
                        } else {
                            warn!("Max retry attempts reached, giving up on message");
                            let inner = pending.message.into_inner();
                            self.conf_tx.send(inner.error().build()).await;
                        }
                    }
                    Err(e) => {
                        error!("Server error during retry: {:?}", e);
                        let inner = pending.message.into_inner();
                        self.conf_tx.send(inner.error().build()).await;
                    }
                }
            } else {
                i += 1;
            }
        }
    }

    /// Get the next retry time, if any messages are queued
    fn get_next_retry_time(&self) -> Option<Instant> {
        self.retry_queue.iter().map(|r| r.retry_after).min()
    }

    /// Dispatch a received KNX/IP frame to the connection manager or
    /// connectionless servers based on the service type category.
    ///
    /// Shared between UDP and TCP receive paths. The `origin` identifies
    /// the transport and peer so that responses are routed correctly and
    /// TCP connections can be tracked.
    async fn dispatch_frame(
        &mut self,
        buffer: &[u8],
        origin: PacketOrigin,
        response_channel: &Channel<NoopRawMutex, PendingResponse, 16>,
    ) {
        let source = origin.peer_addr();
        let socket_idx = match origin {
            PacketOrigin::Udp { socket_idx, .. } => socket_idx,
            PacketOrigin::Tcp { .. } => 0,
        };

        match peek_service_type(buffer) {
            Ok(service_type) => {
                debug!("  Service type: {:?}", service_type);

                // Enforce traffic type constraints: certain service types
                // must only arrive via unicast or multicast.
                {
                    use crate::messages::knxip::TrafficRule;
                    let rule = service_type.traffic_rule();

                    match &origin {
                        // UDP: check destination IP to distinguish unicast
                        // from multicast. Skip if the platform doesn't
                        // report destination (None).
                        PacketOrigin::Udp { destination: Some(dest), .. } => {
                            let is_multicast = dest.octets()[0] & 0xF0 == 0xE0;
                            let allowed = match rule {
                                TrafficRule::UnicastOnly => !is_multicast,
                                TrafficRule::MulticastOnly => is_multicast,
                                TrafficRule::Any => true,
                            };
                            if !allowed {
                                warn!(
                                    "Dropping {:?} from {}: expected {} but destination was {}",
                                    service_type,
                                    source,
                                    if is_multicast { "unicast" } else { "multicast" },
                                    dest,
                                );
                                return;
                            }
                        }

                        // TCP is inherently unicast — reject multicast-only
                        // service types.
                        PacketOrigin::Tcp { .. } => {
                            if rule == TrafficRule::MulticastOnly {
                                warn!(
                                    "Dropping {:?} from {} on TCP: multicast-only service type",
                                    service_type, source,
                                );
                                return;
                            }
                        }

                        // UDP without destination info — can't enforce.
                        PacketOrigin::Udp { destination: None, .. } => {}
                    }
                }

                match service_type.category() {
                    // Connection lifecycle and connection-oriented data go
                    // to the connection manager.
                    ServiceCategory::ConnectionLifecycle | ServiceCategory::ConnectionData => {
                        let inject_tx = self.subnet_inject_tx();
                        match self
                            .connection_manager
                            .on_indication(service_type, buffer, origin, self.context.buffer_manager(), inject_tx)
                            .await
                        {
                            Ok(result) => {
                                for response in result.responses {
                                    response_channel.send(response).await;
                                }
                                self.apply_tcp_channel_events(&result.tcp_events);
                            }
                            Err(e) => {
                                debug!("Connection manager error for {:?}: {:?}", service_type, e);
                            }
                        }
                    }

                    // Connectionless messages go directly to servers.
                    ServiceCategory::Connectionless => {
                        self.dispatch_to_servers(service_type, buffer, source, socket_idx, response_channel).await;
                    }
                }
            }
            Err(e) => {
                warn!("Failed to parse KNX/IP service type from {}: {:?}", source, e);
            }
        }
    }

    /// Route a connectionless service type to the matching typed server.
    ///
    /// Dispatches directly to typed server fields instead of iterating a
    /// `Vec<ServerInstance>`. When a feature is disabled, its `handles()`
    /// returns `false` and `on_indication()` is a no-op that LLVM eliminates.
    async fn dispatch_to_servers(
        &mut self,
        service_type: KNXnetIPServiceType,
        buffer: &[u8],
        source: SocketAddrV4,
        socket_idx: usize,
        response_channel: &Channel<NoopRawMutex, PendingResponse, 16>,
    ) {
        let mut addr_buf =
            [crate::address::IndividualAddress::default(); <F::Tunneling as features::TunnelingFeature>::CAPACITY];
        let addr_count = crate::context::IpAdditionalIndividualAddressContext::write_additional_individual_addresses(
            self.context,
            &mut addr_buf,
        );
        let additional_addresses = &addr_buf[..addr_count];
        let tunnel_slots = self.connection_manager.tunneling_slot_info();
        let tunnel_ref = tunnel_slots.as_ref().map(|(len, v)| (*len, v.as_slice()));

        // Helper closure to build server context — captures immutable fields
        // that are disjoint from the mutable server fields.
        let make_ctx =
            |ind_tx| make_server_context::<F::RemoteConfig>(self.context, ind_tx, additional_addresses, tunnel_ref);

        // Discovery server (always present)
        {
            use services::KnxNetIpServer;
            let discovery_service_types = [
                KNXnetIPServiceType::SearchRequest,
                KNXnetIPServiceType::SearchRequestExtended,
                KNXnetIPServiceType::DescriptionRequest,
            ];
            if discovery_service_types.contains(&service_type) && self.discovery_socket_indices.contains(&socket_idx) {
                let context = make_ctx(self.ind_tx);
                match self.discovery.on_indication(service_type, buffer, source, &context).await {
                    Ok(responses) => {
                        for response in responses {
                            response_channel.send(response).await;
                        }
                    }
                    Err(e) => {
                        error!("Discovery error handling {:?}: {:?}", service_type, e);
                    }
                }
            }
        }

        // Routing server (compiles to nothing when NoRouting)
        if F::Routing::handles(service_type, socket_idx, &self.routing_socket_indices) {
            let context = make_ctx(self.ind_tx);
            match F::Routing::on_indication(&mut self.routing, service_type, buffer, source, &context).await {
                Ok(responses) => {
                    for response in responses {
                        response_channel.send(response).await;
                    }
                }
                Err(e) => {
                    error!("Routing error handling {:?}: {:?}", service_type, e);
                }
            }
        }

        // Remote config server (compiles to nothing when NoRemoteConfig)
        if F::RemoteConfig::handles(service_type, socket_idx, &self.remote_config_socket_indices) {
            let context = make_ctx(self.ind_tx);
            match F::RemoteConfig::on_indication(&mut self.remote_config, service_type, buffer, source, &context).await
            {
                Ok(responses) => {
                    for response in responses {
                        response_channel.send(response).await;
                    }
                }
                Err(e) => {
                    error!("Remote config error handling {:?}: {:?}", service_type, e);
                }
            }
        }
    }

    /// Apply TCP channel tracking events to the TCP manager.
    fn apply_tcp_channel_events(&mut self, events: &[connections::TcpChannelEvent]) {
        use connections::TcpChannelEvent;
        for event in events {
            match event {
                TcpChannelEvent::Added { tcp_idx, channel_id } => {
                    if let Some(tcp_conn) = self.tcp_manager.connection_mut(*tcp_idx) {
                        tcp_conn.add_channel(*channel_id);
                    }
                }
                TcpChannelEvent::Removed { tcp_idx, channel_id } => {
                    if let Some(tcp_conn) = self.tcp_manager.connection_mut(*tcp_idx) {
                        tcp_conn.remove_channel(*channel_id);
                    }
                }
            }
        }
    }

    /// Send a pending response over the appropriate transport (UDP or TCP).
    ///
    /// On TCP write failure, the connection is closed and all KNX/IP
    /// channels on that TCP connection are torn down.
    async fn send_response(&mut self, response: PendingResponse) {
        let data = &response.buffer[..];

        match response.target {
            ResponseTarget::Udp { destination, socket_idx } => {
                debug!("Sending {} byte response to {} on socket {}", data.len(), destination, socket_idx);
                let _ = self.udp_manager.send_to(socket_idx, data, destination).await;
            }
            ResponseTarget::Tcp { tcp_idx } => {
                debug!("Sending {} byte response on TCP connection {}", data.len(), tcp_idx);
                if self.tcp_manager.write_to(tcp_idx, data).await.is_err() {
                    warn!("TCP write failed on connection {}, closing", tcp_idx);
                    self.tcp_manager.close(tcp_idx);
                    self.connection_manager.on_tcp_closed(tcp_idx);
                }
            }
        }
    }

    /// Get the injection TX channel for tunnel-originated frames.
    ///
    /// In composite (IP Interface) mode, tunnel-injected frames go to the
    /// physical bus via `subnet_inject_tx`. In standalone mode, they go to
    /// the device's own network layer via `ind_tx`.
    fn subnet_inject_tx(&self) -> DynamicSender<'res, IndicationMessage<Buffer<'static>>> {
        match &self.subnet_link {
            Some(bridge) => bridge.subnet_inject_tx,
            None => self.ind_tx,
        }
    }
}

impl<
    'res,
    T: IpTransport,
    F: features::FeatureSet,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
> KnxNetIp<'res, T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>
where
    <F::Tunneling as features::TunnelingFeature>::Tunnel:
        connections::TunnelingConnectedHandler<{ <F::Tunneling as features::TunnelingFeature>::CAPACITY }>,
    connections::CompositeHandlers<'res, connections::WithDevMgmt, <F::Tunneling as features::TunnelingFeature>::Tunnel>:
        connections::ConnectionHandlers<{ <F::Tunneling as features::TunnelingFeature>::CAPACITY }>,
{
    /// Run the KNX/IP link layer event loop.
    ///
    /// Concurrently waits for:
    /// - Requests from the network layer (via `req_rx`), which are processed
    ///   and confirmed via `self.conf_tx`
    /// - UDP/TCP transport events (received frames), which are dispatched to
    ///   servers or the connection manager and forwarded up via `self.ind_tx`
    /// - Queued response channel messages ready to send on the wire
    /// - Timer events (retry queue, heartbeat, TCP idle)
    pub(crate) async fn run<M>(&mut self, mut req_rx: M) -> !
    where
        M: Inbox<RequestMessage<Buffer<'static>>>,
    {
        info!("KnxNetIp Link Layer starting with {} socket(s)", self.udp_manager.socket_count());

        let response_channel = self.resources.response_channel();

        loop {
            // First, drain any pending responses to free their buffers
            // This is important because retry queue processing may need these buffers
            while let Ok(pending_response) = response_channel.try_receive() {
                self.send_response(pending_response).await;
            }

            // Process any expired retry requests
            self.process_retry_queue(response_channel).await;

            // Run connection manager heartbeat and ACK timeout checks if
            // connections are active.
            if self.connection_manager.has_active_connections() {
                let tcp_events = self.connection_manager.on_tick();
                self.apply_tcp_channel_events(&tcp_events);

                // Check for unacknowledged server→client frames and
                // retransmit or disconnect as needed.
                let buffer_manager = self.context.buffer_manager();
                let ack_result = self.connection_manager.check_ack_timeouts(buffer_manager);

                for retransmit in ack_result.retransmissions {
                    self.send_response(retransmit).await;
                }

                for (channel_id, target) in ack_result.disconnects {
                    // Build and send DISCONNECT_REQUEST to the client's
                    // control endpoint.
                    use crate::messages::knxip::substructs::HPAI;
                    use crate::util::packets::SerializeBuffer;

                    if let Some(mut buffer) = buffer_manager.try_alloc() {
                        let control_hpai = HPAI::ipv4_udp(core::net::Ipv4Addr::UNSPECIFIED, 0);
                        let builder = DisconnectRequestBuilder::new(channel_id, control_hpai);
                        buffer.serialize(&builder);
                        self.send_response(PendingResponse { buffer, target }).await;
                    }
                }

                self.apply_tcp_channel_events(&ack_result.tcp_events);
            }

            // Check TCP idle timeouts alongside the heartbeat.
            if self.tcp_manager.has_active_connections() {
                let tcp_idle_events = self.tcp_manager.check_idle_timeouts();
                for event in tcp_idle_events {
                    if let TcpEvent::Closed { tcp_idx, .. } = &event {
                        self.connection_manager.on_tcp_closed(*tcp_idx);
                    }
                }
            }

            // ================================================================
            // Main select: UDP + TCP transport, req_rx, responses, timer
            // ================================================================
            //
            // The first arm nests a `select` to combine UDP events with
            // TCP events. Both managers present an identical `next_event`
            // interface, keeping the select symmetric.
            let buffer_manager = self.context.buffer_manager();

            // Timer: earliest of retry time, heartbeat tick, and TCP
            // idle timeout (10s when idle TCP connections exist).
            let heartbeat_time =
                if self.connection_manager.has_active_connections() || self.tcp_manager.has_active_connections() {
                    Some(Instant::now() + Duration::from_secs(1))
                } else {
                    None
                };

            let next_timer = match (self.get_next_retry_time(), heartbeat_time) {
                (Some(a), Some(b)) => Some(if a < b { a } else { b }),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };

            // Third transport arm: bus bridge indications from the TP1 bus.
            // In standalone mode (no bridge), this pends forever.
            let subnet_ind_future = async {
                match &mut self.subnet_link {
                    Some(bridge) => bridge.subnet_ind_rx.receive().await,
                    None => pending::<SubnetIndication>().await,
                }
            };

            // Fourth transport arm: cEMI TL responses from the Application
            // Layer, intercepted by the CemiTransportLayer. When no DevMgmt
            // connection is active (no receiver), pends forever.
            let cemi_response_future = async {
                match &self.cemi_response_receiver {
                    Some(rx) => rx.receive().await,
                    None => pending::<Buffer<'static>>().await,
                }
            };

            let transport_future = select4(
                self.udp_manager.next_event(buffer_manager),
                self.tcp_manager.next_event(buffer_manager),
                subnet_ind_future,
                cemi_response_future,
            );

            let result = match next_timer {
                Some(timer_at) => {
                    select4(transport_future, req_rx.next(), response_channel.receive(), Timer::at(timer_at)).await
                }
                None => select4(transport_future, req_rx.next(), response_channel.receive(), pending::<()>()).await,
            };

            match result {
                // Timer expired (retry queue, heartbeat, or TCP idle)
                Either4::Fourth(()) => {
                    trace!("KNX/IP timer expired");
                    continue;
                }

                // ============================================================
                // Transport events (UDP, TCP, bus bridge, or cEMI response)
                // ============================================================
                Either4::First(transport_event) => match transport_event {
                    // UDP datagram received (multicast echoes already filtered)
                    Either4::First(UdpEvent::Frame { socket_idx, source, destination, buffer }) => {
                        let origin = PacketOrigin::Udp { source, socket_idx, destination };
                        self.dispatch_frame(&buffer, origin, response_channel).await;
                    }

                    // UDP socket receive error
                    Either4::First(UdpEvent::Error { socket_idx }) => {
                        error!("Socket {} receive error", socket_idx);
                    }

                    // TCP frame received
                    Either4::Second(TcpEvent::Frame { tcp_idx, peer, buffer }) => {
                        debug!("TCP connection {}: received {} byte frame from {}", tcp_idx, buffer.len(), peer);

                        let origin = PacketOrigin::Tcp { peer, tcp_idx };
                        self.dispatch_frame(&buffer, origin, response_channel).await;
                    }

                    // TCP connection closed
                    Either4::Second(TcpEvent::Closed { tcp_idx, .. }) => {
                        info!("TCP connection {} closed, tearing down KNX/IP channels", tcp_idx);
                        self.connection_manager.on_tcp_closed(tcp_idx);
                    }

                    // Bus bridge: TP1 bus indication to forward to tunnel clients
                    Either4::Third(subnet_indication) => {
                        let forwarded = self
                            .connection_manager
                            .forward_bus_indication(&subnet_indication.cemi_data, self.context.buffer_manager());

                        for response in forwarded {
                            response_channel.send(response).await;
                        }
                    }

                    // cEMI TL response from the Application Layer. Convert
                    // from internal format to cEMI TL wire format and send
                    // as a DeviceConfigurationRequest to the ETS client.
                    Either4::Fourth(cemi_buf) => {
                        let bm = self.context.buffer_manager();
                        if let Some(response) = self.connection_manager.send_devmgmt_cemi_frame(&cemi_buf, bm) {
                            self.send_response(response).await;
                        } else {
                            warn!("cEMI TL: no active DevMgmt connection for response, dropping");
                        }
                    }
                },

                // Request from the network layer (L_Data.req)
                Either4::Second(msg) => {
                    trace!("KNX/IP received request: {:?}", msg);

                    match msg.service_type() {
                        ServiceType::L_Data_Req if F::Routing::supports_requests() => {
                            debug!("KnxNetIp Link Layer sending L_Data_Req: {:?}", msg);

                            let mut addr_buf2 = [crate::address::IndividualAddress::default();
                                <F::Tunneling as features::TunnelingFeature>::CAPACITY];
                            let addr_count2 =
                                crate::context::IpAdditionalIndividualAddressContext::write_additional_individual_addresses(
                                    self.context, &mut addr_buf2,
                                );
                            let tunnel_slots = self.connection_manager.tunneling_slot_info();
                            let tunnel_ref2 = tunnel_slots.as_ref().map(|(len, v)| (*len, v.as_slice()));
                            let context = make_server_context::<F::RemoteConfig>(
                                self.context,
                                self.ind_tx,
                                &addr_buf2[..addr_count2],
                                tunnel_ref2,
                            );

                            match F::Routing::on_request(&mut self.routing, &msg, &context).await {
                                Ok(responses) => {
                                    for response in responses {
                                        response_channel.send(response).await;
                                    }
                                    let inner = msg.into_inner();
                                    self.conf_tx.send(inner.confirm().build()).await;
                                }
                                Err(ServerError::Busy(wait_time)) => {
                                    if self.retry_queue.len() < MAX_RETRY_QUEUE_SIZE {
                                        let retry_after = Instant::now() + Duration::from_millis(wait_time as u64);
                                        let pending = PendingRequest { message: msg, retry_after, retry_count: 0 };

                                        if self.retry_queue.push(pending).is_ok() {
                                            debug!(
                                                "Queued message for retry in {}ms (queue size: {})",
                                                wait_time,
                                                self.retry_queue.len()
                                            );
                                        } else {
                                            error!("Retry queue push failed unexpectedly");
                                        }
                                    } else {
                                        warn!(
                                            "Retry queue full ({} messages), cannot queue message",
                                            MAX_RETRY_QUEUE_SIZE
                                        );
                                        let inner = msg.into_inner();
                                        self.conf_tx.send(inner.error().build()).await;
                                    }
                                }
                                Err(e) => {
                                    error!("Server error sending request: {:?}", e);
                                    let inner = msg.into_inner();
                                    self.conf_tx.send(inner.error().build()).await;
                                }
                            }
                        }
                        _ => {
                            // Unsupported service type or no server supports requests
                            self.conf_tx.send(msg.into_inner().error().build()).await;
                        }
                    }
                }

                // Response ready to send
                Either4::Third(pending_response) => {
                    self.send_response(pending_response).await;
                }
            }
        }
    }
}
