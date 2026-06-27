//! Frame routing, response dispatch, retry queue, and TCP channel
//! tracking for KNX/IP. All entries here are `impl KnxNetIp` methods
//! that the runtime event loop calls into.

use core::net::SocketAddrV4;

use crate::actor::ActorRequest;
use crate::layers::linklayers::knxip::context::{
    IpAdditionalIndividualAddressContext, IpConfigWriteContext, IpDiagnosticsContext, RemoteRestartContext,
};
use crate::persist::PersistRequest;
use embassy_sync::{
    blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex},
    channel::{Channel, DynamicSender},
};
use embassy_time::{Duration, Instant};
use zweidraehte_proto::messages::{
    buffers::{Buffer, MessageBuffer},
    builder::{ConfirmationExt, IndicationMessage, RequestMessage},
    knxip::*,
};

use super::{
    KnxNetIpContext, PacketOrigin, PendingResponse, ResponseTarget, ServerContext, ServerError, connections,
    features::{self, RemoteConfigFeature, RoutingFeature, TcpFeature},
    secure::{self, IpSecureFeature, SecureEnv, SecureFrameOutcome},
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
/// `socket_idx` is the index of the UDP socket on which the triggering
/// indication arrived; it is stored in the context so service handlers
/// can send their response on the correct socket.
pub(super) fn make_server_context<'a, RC: RemoteConfigFeature>(
    context: &'a dyn KnxNetIpContext,
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    additional_addresses: &'a [zweidraehte_proto::address::IndividualAddress],
    tunneling_slot_info: Option<(u16, &'a [substructs::TunnelingSlotInfo])>,
    address_filter: Option<&'a dyn super::types::AddressFilter>,
    socket_idx: usize,
) -> ServerContext<'a> {
    // The remote-config write/reset capabilities are gated identically to
    // the diagnostics read side: present exactly when the remote-config
    // server is enabled. `context` (a `&dyn KnxNetIpContext`) implements all
    // three, so the same handle backs each `Some`.
    let ip_diagnostics: Option<&dyn IpDiagnosticsContext> =
        if RC::exposes_diagnostics() { Some(context) } else { None };
    let ip_config_write: Option<&dyn IpConfigWriteContext> =
        if RC::exposes_diagnostics() { Some(context) } else { None };
    let restart_ctx: Option<&dyn RemoteRestartContext> = if RC::exposes_diagnostics() { Some(context) } else { None };
    ServerContext::new(
        context.buffer_manager(),
        ind_tx,
        context.max_apdu_length(),
        context,
        ip_diagnostics,
        ip_config_write,
        restart_ctx,
        additional_addresses,
        context,
        tunneling_slot_info,
        address_filter,
        socket_idx,
        context.ip_secure_view(),
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
    const TCP_BUF_SZ: usize,
> KnxNetIp<'res, T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS, TUNNEL_CAPACITY, MAX_CONNECTIONS, TCP_BUF_SZ>
where
    <F::Tunneling as features::TunnelingFeature>::Tunnel: connections::TunnelingConnectedHandler<TUNNEL_CAPACITY>,
    connections::CompositeHandlers<
        'res,
        connections::WithDevMgmt,
        <F::Tunneling as features::TunnelingFeature>::Tunnel,
    >: connections::ConnectionHandlers<TUNNEL_CAPACITY>,
{
    /// Snapshot the additional individual addresses and tunneling slot
    /// info needed to build a [`ServerContext`].
    ///
    /// Returns owned storage so the caller can borrow disjoint slices
    /// from it while still mutably borrowing other `self` fields (e.g.
    /// `self.routing`).
    pub(super) fn address_and_tunnel_snapshot(
        &self,
    ) -> (
        [zweidraehte_proto::address::IndividualAddress; TUNNEL_CAPACITY],
        usize,
        Option<(u16, heapless::Vec<substructs::TunnelingSlotInfo, TUNNEL_CAPACITY>)>,
    ) {
        let mut addr_buf = [zweidraehte_proto::address::IndividualAddress::default(); TUNNEL_CAPACITY];
        let addr_count =
            IpAdditionalIndividualAddressContext::write_additional_individual_addresses(self.context, &mut addr_buf);
        let tunnel_slots = self.connection_manager.tunneling_slot_info();
        (addr_buf, addr_count, tunnel_slots)
    }

    /// Assemble the read-only environment for the IP Secure handlers.
    ///
    /// Borrows through the `'res` context reference (not `&self`), so
    /// the caller can keep mutating link-layer state (e.g. `mc_timer`)
    /// while the environment is alive.
    pub(super) fn secure_env(&self) -> SecureEnv<'res> {
        SecureEnv {
            config: self.context.ip_secure_view(),
            serial_number: self.context.knx_serial_number(),
            rng_fill: self.rng_fill,
            now: Instant::now(),
        }
    }

    /// 03/08/09 §2.2.4.2 durability gate: if the multicast timer flagged
    /// a pending watermark persist, round-trip a gated
    /// [`PersistRequest::McTimerWatermark`] through user code's storage
    /// task and only return once the save is confirmed. The single
    /// await point of the whole persistence gate — call it before any
    /// frame carrying a timer value beyond the watermark leaves the
    /// device, and once per runtime loop for receive-side advances.
    pub(super) async fn drain_mc_persist(&mut self) {
        if <F::IpSecure as IpSecureFeature>::mc_take_persist_pending(&mut self.mc_timer)
            && let Some(gate) = self.context.persist_gate_sender()
        {
            // CriticalSectionRawMutex: the storage task may live on a
            // different executor than the link layer.
            ActorRequest::<CriticalSectionRawMutex, _, _>::request(&gate, PersistRequest::McTimerWatermark).await;
        }
    }

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

                let (addr_buf, addr_count, tunnel_slots) = self.address_and_tunnel_snapshot();
                let tunnel_ref = tunnel_slots.as_ref().map(|(len, v)| (*len, v.as_slice()));
                // Retries are outgoing routing frames, not replies to an
                // incoming UDP packet, so no source socket is meaningful here.
                let context = make_server_context::<F::RemoteConfig>(
                    self.context,
                    self.ind_tx,
                    &addr_buf[..addr_count],
                    tunnel_ref,
                    self.address_filter,
                    0,
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

        // ================================================================
        // IP Secure pre-stage: session handshake frames are consumed
        // here; SECURE_WRAPPER frames are authenticated and decrypted,
        // and the plaintext inner frame continues through the normal
        // dispatch below with the session identity attached. UDP-side
        // secure routing frames (TIMER_NOTIFY, multicast wrappers with
        // session id 0000h) divert to the multicast timer sync instead
        // of the session machinery. The whole block folds away for
        // `NoIpSecure`.
        // ================================================================
        let mut secure_inner: Option<Buffer<'static>> = None;
        let mut secure_session: Option<(u16, u8)> = None;
        let mut secure_multicast = false;
        if <F::IpSecure as IpSecureFeature>::ENABLED
            && let Ok(secure_service) = peek_service_type(buffer)
            && secure::secure_service_types::is_secure(u16::from(secure_service))
        {
            let env = self.secure_env();
            // §2.2.1.4.5: secure routing traffic only counts when it
            // arrives on the routing endpoint (the UDP socket joined to
            // the routing multicast group).
            let on_routing_socket = matches!(
                origin,
                PacketOrigin::Udp { socket_idx, .. } if self.routing_socket_indices.contains(&socket_idx)
            );

            if secure_service == KNXnetIPServiceType::TimerNotify {
                // §2.2.2.4.1: TIMER_NOTIFY lives on the routing
                // multicast endpoint; arrivals anywhere else (TCP, other
                // sockets) are dropped. Never forwarded to services.
                if on_routing_socket {
                    <F::IpSecure as IpSecureFeature>::handle_timer_notify(&mut self.mc_timer, buffer, &env);
                }
                return;
            }

            if secure_service == KNXnetIPServiceType::SecureWrapper && on_routing_socket {
                // Multicast wrapper (backbone key, session id 0000h).
                // Decryption scratch comes from the buffer pool, not the
                // stack, so the non-secure future stays small.
                let Some(mut scratch) = self.context.buffer_manager().try_alloc() else {
                    warn!("No buffer for IP Secure frame processing, dropped");
                    return;
                };
                scratch.set_len(scratch.capacity());
                match <F::IpSecure as IpSecureFeature>::handle_multicast_wrapper(
                    &mut self.mc_timer,
                    buffer,
                    &env,
                    &mut scratch[..],
                ) {
                    Some(len) => {
                        scratch.set_len(len);
                        secure_multicast = true;
                        secure_inner = Some(scratch);
                    }
                    None => return,
                }
            } else {
                // Unicast session path (TCP). UDP arrivals carry
                // `tcp_idx = None` and are discarded inside (§2.2.3.3).
                let tcp_idx = match origin {
                    PacketOrigin::Tcp { tcp_idx, .. } => Some(tcp_idx),
                    PacketOrigin::Udp { .. } => None,
                };
                let Some(mut scratch) = self.context.buffer_manager().try_alloc() else {
                    warn!("No buffer for IP Secure frame processing, dropped");
                    return;
                };
                scratch.set_len(scratch.capacity());

                let mut handshake_responses = secure::SecureResponses::new();
                let outcome = <F::IpSecure as IpSecureFeature>::handle_secure_frame(
                    &mut self.secure_sessions,
                    buffer,
                    tcp_idx,
                    &env,
                    &mut scratch[..],
                    &mut handshake_responses,
                );
                for frame in &handshake_responses {
                    if let Some(buf) = self.context.buffer_manager().try_alloc_from_slice(frame) {
                        response_channel.send(PendingResponse { buffer: buf, target: origin.reply_target() }).await;
                    }
                }
                match outcome {
                    SecureFrameOutcome::Handled { closed_session } => {
                        if let Some(session_id) = closed_session {
                            let tcp_events = self.connection_manager.close_secure_session_connections(session_id);
                            self.apply_tcp_channel_events(&tcp_events);
                        }
                        return;
                    }
                    SecureFrameOutcome::Inner { len, session_id, user_id } => {
                        scratch.set_len(len);
                        secure_session = Some((session_id, user_id));
                        secure_inner = Some(scratch);
                    }
                }
            }
        }
        let buffer: &[u8] = match &secure_inner {
            Some(inner) => &inner[..],
            None => buffer,
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

                // §2.2.1.4.5: a multicast SECURE_WRAPPER may only carry
                // KNXnet/IP Routing Service Family messages — anything
                // else wrapped with the backbone key is discarded.
                if secure_multicast && !multicast_wrapper_inner_allowed(service_type) {
                    warn!(
                        "Dropping {:?} from {}: not a routing service inside a multicast wrapper",
                        service_type, source
                    );
                    return;
                }

                // Secured-service-family enforcement (03/08/09
                // §2.2.1.4): once a family is marked secured in
                // PID_SECURED_SERVICE_FAMILIES, its services are only
                // accepted through an authenticated SECURE_WRAPPER —
                // plain arrivals are discarded. Discovery stays plain.
                if <F::IpSecure as IpSecureFeature>::ENABLED
                    && secure_session.is_none()
                    && !secure_multicast
                    && let Some(config) = self.context.ip_secure_view()
                    && let Some(family) = secured_family_of(service_type, buffer)
                    && config.secured_service_family(family) != 0
                {
                    warn!("Dropping plain {:?} from {}: service family is secured", service_type, source);
                    return;
                }

                match service_type.category() {
                    // Connection lifecycle and connection-oriented data go
                    // to the connection manager.
                    ServiceCategory::ConnectionLifecycle | ServiceCategory::ConnectionData => {
                        let inject_tx = self.subnet_inject_tx();
                        match self
                            .connection_manager
                            .on_indication(
                                service_type,
                                buffer,
                                origin,
                                self.context.buffer_manager(),
                                inject_tx,
                                secure_session.map(|(session_id, _)| session_id),
                            )
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
        let (addr_buf, addr_count, tunnel_slots) = self.address_and_tunnel_snapshot();
        let additional_addresses = &addr_buf[..addr_count];
        let tunnel_ref = tunnel_slots.as_ref().map(|(len, v)| (*len, v.as_slice()));

        // Helper closure to build server context — captures immutable fields
        // that are disjoint from the mutable server fields.
        // `socket_idx` is captured so that responses are routed back on the
        // same UDP socket the request arrived on.
        let address_filter = self.address_filter;
        let make_ctx = |ind_tx| {
            make_server_context::<F::RemoteConfig>(
                self.context,
                ind_tx,
                additional_addresses,
                tunnel_ref,
                address_filter,
                socket_idx,
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

    /// Apply TCP channel tracking events to the TCP manager. For
    /// `NoTcp` builds the dispatch methods fold to no-ops.
    pub(super) fn apply_tcp_channel_events(&mut self, events: &[connections::TcpChannelEvent]) {
        use connections::TcpChannelEvent;
        for event in events {
            match event {
                TcpChannelEvent::Added { tcp_idx, channel_id } => {
                    <F::Tcp as TcpFeature>::add_channel(&mut self.tcp_manager, *tcp_idx, *channel_id);
                }
                TcpChannelEvent::Removed { tcp_idx, channel_id } => {
                    <F::Tcp as TcpFeature>::remove_channel(&mut self.tcp_manager, *tcp_idx, *channel_id);
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
                // Secure routing interception point (§2.2.1.4.5): with
                // the Routing family secured, *all* sent Routing.ind
                // frames must ride a multicast SECURE_WRAPPER — and
                // none may go out plain, so a failed wrap (key missing,
                // mc_timer not yet authentic) drops the frame instead
                // of falling back. System broadcast frames stay plain
                // by design (see `secured_family_of`).
                let mut wrapped: Option<Buffer<'static>> = None;
                if <F::IpSecure as IpSecureFeature>::ENABLED
                    && peek_service_type(data) == Ok(KNXnetIPServiceType::RoutingIndication)
                    && let Some(config) = self.context.ip_secure_view()
                    && config.secured_service_family(substructs::ServiceFamily::Routing) != 0
                {
                    let env = self.secure_env();
                    let Some(mut out) = self.context.buffer_manager().try_alloc() else {
                        warn!("No buffer to wrap secure routing frame, dropped");
                        return;
                    };
                    out.set_len(out.capacity());
                    let Some(len) = <F::IpSecure as IpSecureFeature>::wrap_multicast_outgoing(
                        &mut self.mc_timer,
                        data,
                        &env,
                        &mut out[..],
                    ) else {
                        debug!("Routing frame not wrappable (secure routing not ready), dropped");
                        return;
                    };
                    // §2.2.4.2: the wrap may have advanced the
                    // persistence watermark; the frame is in `out` but
                    // not yet on the wire — make the watermark durable
                    // before the send below.
                    self.drain_mc_persist().await;
                    out.set_len(len);
                    wrapped = Some(out);
                }
                let data = wrapped.as_ref().map(|b| &b[..]).unwrap_or(data);

                debug!("Sending {} byte response to {} on socket {}", data.len(), destination, socket_idx);
                let _ = self.udp_manager.send_to(socket_idx, data, destination).await;
            }
            ResponseTarget::Tcp { tcp_idx } => {
                // IP Secure interception point: every plain frame leaving on
                // a TCP stream that owns an authenticated session is wrapped
                // here, regardless of which subsystem produced it (connect
                // responses, tunneling indications, devmgmt frames, ACK
                // retransmits — a retransmit deliberately gets a fresh
                // wrapper sequence number). Frames already in the secure
                // family (handshake replies, wrapped status, timeout
                // notifications) pass through untouched.
                let mut wrapped: Option<Buffer<'static>> = None;
                if <F::IpSecure as IpSecureFeature>::ENABLED
                    && peek_service_type(data).is_ok_and(|st| !secure::secure_service_types::is_secure(u16::from(st)))
                    && <F::IpSecure as IpSecureFeature>::session_for_tcp(&self.secure_sessions, tcp_idx).is_some()
                {
                    let serial = self.context.knx_serial_number();
                    let Some(mut out) = self.context.buffer_manager().try_alloc() else {
                        warn!("No buffer to wrap secure response on TCP {}, dropped", tcp_idx);
                        return;
                    };
                    out.set_len(out.capacity());
                    let Some(len) = <F::IpSecure as IpSecureFeature>::wrap_outgoing(
                        &mut self.secure_sessions,
                        tcp_idx,
                        data,
                        &serial,
                        &mut out[..],
                    ) else {
                        warn!("Failed to wrap secure response on TCP {}, dropped", tcp_idx);
                        return;
                    };
                    out.set_len(len);
                    wrapped = Some(out);
                }
                let data = wrapped.as_ref().map(|b| &b[..]).unwrap_or(data);

                debug!("Sending {} byte response on TCP connection {}", data.len(), tcp_idx);
                if <F::Tcp as TcpFeature>::write_to(&mut self.tcp_manager, tcp_idx, data).await.is_err() {
                    warn!("TCP write failed on connection {}, closing", tcp_idx);
                    let _ = <F::Tcp as TcpFeature>::close(&mut self.tcp_manager, tcp_idx);
                    self.connection_manager.on_tcp_closed(tcp_idx);
                    let _ = <F::IpSecure as IpSecureFeature>::on_tcp_closed(&mut self.secure_sessions, tcp_idx);
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

// ============================================================================
// Secured-service-family mapping
// ============================================================================

/// Which securable service family (PID_SECURED_SERVICE_FAMILIES entry)
/// a service type belongs to, for plain-frame rejection. `None` means
/// the service is never gated: discovery and the Core lifecycle
/// services stay reachable in plain (connection-session binding handles
/// cross-context CONNECTIONSTATE/DISCONNECT references separately).
///
/// CONNECT_REQUEST is classified by its CRI connection type, because a
/// single Core service opens connections of different families.
///
/// Within the Routing family, only ROUTING_INDICATION is gated —
/// §2.2.1.4.5 phrases the secure/plain exclusion exclusively in terms
/// of `Routing.ind`:
/// - ROUTING_SYSTEM_BROADCAST stays plain even with routing secured.
///   03/02/06 §4.3.5.3.1 redefines only "broadcast frames" as wrapped
///   `Routing.ind` under routing security and leaves IP System
///   Broadcast Frames untouched; the §4.3.5.3.5.2 re-keying procedure
///   (21-octet `A_DomainAddressSerialNumber_Write` carrying a *new*
///   backbone key) depends on receiving them plain. Their sensitive
///   payloads are protected one layer up by KNX Data Secure.
/// - ROUTING_BUSY / ROUTING_LOST_MESSAGE are advisory flow-control
///   frames carrying no KNX data; the spec does not extend the
///   exclusion to them, and dropping plain ones would break congestion
///   control with routers that emit them unwrapped.
fn secured_family_of(service_type: KNXnetIPServiceType, frame: &[u8]) -> Option<substructs::ServiceFamily> {
    use KNXnetIPServiceType::*;
    use zweidraehte_proto::util::packets::ParseBuffer;

    match service_type {
        DeviceConfigurationRequest | DeviceConfigurationAck => Some(substructs::ServiceFamily::DeviceManagement),
        TunnelingRequest
        | TunnelingAck
        | TunnelingFeatureGet
        | TunnelingFeatureResponse
        | TunnelingFeatureSet
        | TunnelingFeatureInfo => Some(substructs::ServiceFamily::Tunneling),
        RoutingIndication => Some(substructs::ServiceFamily::Routing),
        ConnectRequest => {
            let mut buf = frame;
            match buf.parse::<zweidraehte_proto::messages::knxip::ConnectRequest>().ok()?.cri.connection_type() {
                substructs::ConnectionType::DeviceManagement => Some(substructs::ServiceFamily::DeviceManagement),
                substructs::ConnectionType::Tunnel => Some(substructs::ServiceFamily::Tunneling),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Which services may arrive inside a *multicast* SECURE_WRAPPER
/// (backbone key, session id 0000h). §2.2.1.4.5 restricts multicast
/// wrappers to the KNXnet/IP Routing Service Family; system broadcast
/// is excluded because it always travels plain (see
/// [`secured_family_of`]).
fn multicast_wrapper_inner_allowed(service_type: KNXnetIPServiceType) -> bool {
    use KNXnetIPServiceType::*;
    matches!(service_type, RoutingIndication | RoutingBusy | RoutingLostMessage)
}
