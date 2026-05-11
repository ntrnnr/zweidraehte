//! Frame routing and response dispatch for KNX/IP.
//!
//! Contains the inbound frame routing logic (`dispatch_frame`,
//! `dispatch_to_servers`), outbound response sending (`send_response`),
//! retry queue management, and TCP channel tracking. These are all
//! `impl KnxNetIp` methods split out from `runtime.rs` to keep the
//! event loop focused on `select`-based concurrency.

use core::net::SocketAddrV4;

use crate::layers::linklayers::knxip::context::{IpAdditionalIndividualAddressContext, IpDiagnosticsContext};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicSender},
};
use embassy_time::{Duration, Instant};
use zweidraehte_proto::messages::{
    buffers::Buffer,
    builder::{ConfirmationExt, IndicationMessage, RequestMessage},
    knxip::*,
};

use super::{
    KnxNetIpContext, PacketOrigin, PendingResponse, ResponseTarget, ServerContext, ServerError, connections,
    features::{self, RemoteConfigFeature, RoutingFeature},
    services,
};

use super::runtime::KnxNetIp;

// ============================================================================
// Retry Queue
// ============================================================================

/// A request that is pending retry after being rate-limited.
pub(super) struct PendingRequest {
    /// The message to retry.
    pub(super) message: RequestMessage<Buffer<'static>>,
    /// When to retry sending this message.
    pub(super) retry_after: Instant,
    /// Number of times this message has been retried.
    pub(super) retry_count: u8,
}

/// Maximum number of messages that can be queued for retry.
pub(super) const MAX_RETRY_QUEUE_SIZE: usize = 16;

/// Maximum number of retry attempts before giving up.
pub(super) const MAX_RETRY_ATTEMPTS: u8 = 5;

// ============================================================================
// Server Context Construction
// ============================================================================

/// Build a [`ServerContext`] from individual [`KnxNetIp`] fields.
///
/// Free function instead of a method so the borrow checker can see that
/// server fields are disjoint from the context and channel fields.
/// The `RC` type parameter controls whether IP diagnostics are exposed.
///
/// The caller materialises the additional-address and tunneling-slot data
/// into local buffers (with the correct capacity `N`) and passes slices.
pub(super) fn make_server_context<'a, RC: RemoteConfigFeature>(
    context: &'a dyn KnxNetIpContext,
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    additional_addresses: &'a [zweidraehte_proto::address::IndividualAddress],
    tunneling_slot_info: Option<(u16, &'a [substructs::TunnelingSlotInfo])>,
    address_filter: Option<&'a dyn super::types::AddressFilter>,
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
        address_filter,
    )
}

// ============================================================================
// Dispatch & Response Methods
// ============================================================================

impl<
    'res,
    T: zweidraehte_platform::IpTransport,
    F: features::FeatureSet,
    const MAX_SOCKETS: usize,
    const MAX_TCP_STREAMS: usize,
    const MAX_CHANNELS: usize,
    const TUNNEL_CAPACITY: usize,
    const MAX_CONNECTIONS: usize,
> KnxNetIp<'res, T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS, TUNNEL_CAPACITY, MAX_CONNECTIONS>
where
    <F::Tunneling as features::TunnelingFeature>::Tunnel: connections::TunnelingConnectedHandler<TUNNEL_CAPACITY>,
    connections::CompositeHandlers<
        'res,
        connections::WithDevMgmt,
        <F::Tunneling as features::TunnelingFeature>::Tunnel,
    >: connections::ConnectionHandlers<TUNNEL_CAPACITY>,
{
    /// Process expired retry requests.
    ///
    /// Only the routing server supports outgoing requests (`on_request`).
    /// When routing is disabled (`NoRouting`), `supports_requests()` returns
    /// false and `on_request()` returns `Err(Unsupported)`, so retries are
    /// no-ops that the compiler eliminates.
    pub(super) async fn process_retry_queue(&mut self, response_channel: &Channel<NoopRawMutex, PendingResponse, 16>) {
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

                let mut addr_buf = [zweidraehte_proto::address::IndividualAddress::default(); TUNNEL_CAPACITY];
                let addr_count = IpAdditionalIndividualAddressContext::write_additional_individual_addresses(
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
                    self.address_filter,
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

    /// Get the next retry time, if any messages are queued.
    pub(super) fn get_next_retry_time(&self) -> Option<Instant> {
        self.retry_queue.iter().map(|r| r.retry_after).min()
    }

    /// Dispatch a received KNX/IP frame to the connection manager or
    /// connectionless services based on the service type category.
    ///
    /// Shared between UDP and TCP receive paths. The `origin` identifies
    /// the transport and peer so that responses are routed correctly and
    /// TCP connections can be tracked.
    pub(super) async fn dispatch_frame(
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
                    use zweidraehte_proto::messages::knxip::TrafficRule;
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

                    // Connectionless messages go directly to services.
                    ServiceCategory::Connectionless => {
                        self.dispatch_to_services(service_type, buffer, source, socket_idx, response_channel).await;
                    }
                }
            }
            Err(e) => {
                warn!("Failed to parse KNX/IP service type from {}: {:?}", source, e);
            }
        }
    }

    /// Route a connectionless service type to the matching typed service.
    ///
    /// Dispatches directly to typed service fields instead of iterating a
    /// `Vec<ServerInstance>`. When a feature is disabled, its `handles()`
    /// returns `false` and `on_indication()` is a no-op that LLVM eliminates.
    async fn dispatch_to_services(
        &mut self,
        service_type: KNXnetIPServiceType,
        buffer: &[u8],
        source: SocketAddrV4,
        socket_idx: usize,
        response_channel: &Channel<NoopRawMutex, PendingResponse, 16>,
    ) {
        let mut addr_buf = [zweidraehte_proto::address::IndividualAddress::default(); TUNNEL_CAPACITY];
        let addr_count =
            IpAdditionalIndividualAddressContext::write_additional_individual_addresses(self.context, &mut addr_buf);
        let additional_addresses = &addr_buf[..addr_count];
        let tunnel_slots = self.connection_manager.tunneling_slot_info();
        let tunnel_ref = tunnel_slots.as_ref().map(|(len, v)| (*len, v.as_slice()));

        // Helper closure to build server context — captures immutable fields
        // that are disjoint from the mutable server fields.
        let address_filter = self.address_filter;
        let make_ctx = |ind_tx| {
            make_server_context::<F::RemoteConfig>(
                self.context,
                ind_tx,
                additional_addresses,
                tunnel_ref,
                address_filter,
            )
        };

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
    pub(super) fn apply_tcp_channel_events(&mut self, events: &[connections::TcpChannelEvent]) {
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
    pub(super) async fn send_response(&mut self, response: PendingResponse) {
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
    pub(super) fn subnet_inject_tx(&self) -> DynamicSender<'res, IndicationMessage<Buffer<'static>>> {
        match &self.subnet_link {
            Some(bridge) => bridge.subnet_inject_tx,
            None => self.ind_tx,
        }
    }
}
