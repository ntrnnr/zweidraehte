use core::future::pending;
use core::net::Ipv4Addr;

use embassy_futures::select::{Either, Either4, select, select4};
use embassy_sync::channel::DynamicSender;
use embassy_time::{Duration, Instant, Timer};
use heapless::Vec;

use zweidraehte_platform::IpTransport;

use crate::layers::Inbox;
use zweidraehte_proto::messages::{
    buffers::Buffer,
    builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage, RequestMessage},
    knx::*,
    knxip::*,
};

use super::{
    KnxNetIpContext, KnxNetIpResources, PacketOrigin, PendingResponse, ServerError, SubnetIndication, SubnetLink,
    connections,
    dispatch::{self, MAX_RETRY_QUEUE_SIZE, PendingRequest},
    features::{self, RoutingFeature, TcpFeature},
    services,
    transport::{TcpEvent, UdpEvent, UdpManager},
};

pub struct KnxNetIp<
    'res,
    T: IpTransport,
    F: features::FeatureSet = features::DefaultFeatures,
    const MAX_SOCKETS: usize = 4,
    const MAX_TCP_STREAMS: usize = 1,
    const MAX_CHANNELS: usize = 1,
    const TUNNEL_CAPACITY: usize = 0,
    const MAX_CONNECTIONS: usize = 1,
> where
    <F::Tunneling as features::TunnelingFeature>::Tunnel: connections::TunnelingConnectedHandler<TUNNEL_CAPACITY>,
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
        connections::CompositeHandlers<
            'res,
            connections::WithDevMgmt,
            <F::Tunneling as features::TunnelingFeature>::Tunnel,
        >,
        TUNNEL_CAPACITY,
        MAX_CONNECTIONS,
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
    pub(super) tcp_manager: <F::Tcp as TcpFeature>::Manager<T, MAX_TCP_STREAMS, MAX_CHANNELS, 512>,
    /// Bus bridge for IP Interface composite mode.
    ///
    /// When `Some`, this KNX/IP instance is part of a composite link layer
    /// bridging to a TP1 bus. `AckAndInject` frames are routed to
    /// `subnet_inject_tx` instead of the real `ind_tx`, and bus indications
    /// arrive via `subnet_ind_rx` for forwarding to tunnel clients.
    pub(super) subnet_link: Option<SubnetLink<'res>>,
    /// Address filter for incoming routing frames. Drops frames not
    /// addressed to this device before they reach the network layer.
    pub(super) address_filter: Option<&'res dyn super::types::AddressFilter>,
    /// Local IPv4 address used for multicast membership operations.
    ///
    /// Cached at construction from the builder's `local_addr` so the
    /// runtime can re-issue `IP_ADD_MEMBERSHIP` / `IP_DROP_MEMBERSHIP`
    /// from the rebind path without asking the platform for an
    /// interface lookup each time.
    pub(super) interface_addr: Ipv4Addr,
}

impl<
    'res,
    T: IpTransport,
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
                    use zweidraehte_proto::messages::knxip::substructs::HPAI;
                    use zweidraehte_proto::util::packets::SerializeBuffer;

                    if let Some(mut buffer) = buffer_manager.try_alloc() {
                        let control_hpai = HPAI::ipv4_udp(core::net::Ipv4Addr::UNSPECIFIED, 0);
                        let builder = DisconnectRequestBuilder::new(channel_id, control_hpai);
                        buffer.serialize(&builder);
                        self.send_response(PendingResponse { buffer, target }).await;
                    }
                }
            }

            // TCP idle-timeout sweep (03/08/02 §8.4.3): a TCP connection
            // with no active inner KNX/IP channel is closed after
            // `TCP_CONNECTION_TIMEOUT` (10 s default). Runs alongside the
            // UDP heartbeat. `NoTcp` folds the calls to `false` / empty.
            if <F::Tcp as TcpFeature>::has_active_connections(&self.tcp_manager) {
                let tcp_idle_events = <F::Tcp as TcpFeature>::check_idle_timeouts(&mut self.tcp_manager);
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
            let heartbeat_time = if self.connection_manager.has_active_connections()
                || <F::Tcp as TcpFeature>::has_active_connections(&self.tcp_manager)
            {
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
                <F::Tcp as TcpFeature>::next_event(&mut self.tcp_manager, buffer_manager),
                subnet_ind_future,
                cemi_response_future,
            );

            // Fourth arm combines the periodic timer with the
            // `IpExtensionState` rebind channel. `IpExtensionState::set_*`
            // pushes the new IPv4 multicast group onto this channel from
            // the write-handler side; the runtime reacts here by calling
            // [`UdpManager::rebind_routing_multicast`] on its live
            // sockets (03/02/06 §4.3.5.3.5.1). Either firing continues
            // the loop: the timer reschedules, the rebind runs the IGMP
            // leave/join and falls back into the select.
            let rebind_rx = self.context.routing_multicast_rebind_channel().receiver();
            let timer_or_rebind = async {
                let timer_future = async {
                    match next_timer {
                        Some(timer_at) => Timer::at(timer_at).await,
                        None => pending::<()>().await,
                    }
                };
                select(timer_future, rebind_rx.receive()).await
            };

            let result = select4(transport_future, req_rx.next(), response_channel.receive(), timer_or_rebind).await;

            match result {
                // Timer expired (retry queue / heartbeat / TCP idle)
                Either4::Fourth(Either::First(())) => {
                    trace!("KNX/IP timer expired");
                    continue;
                }
                // Rebind request from `IpExtensionState::set_*`
                Either4::Fourth(Either::Second(new_addr)) => {
                    self.apply_routing_multicast_rebind(new_addr);
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

                // Request from the network layer (L_Data.req).
                //
                // Only routing can transmit an L_Data.req to the IP side
                // — tunneling clients send frames to the bus directly via
                // DevMgmt's `AckAndInject` path, and DevMgmt frames from
                // the Application Layer are produced through the cEMI TL
                // bridge (handled in `Either4::Fourth` above), not here.
                Either4::Second(msg) => {
                    trace!("KNX/IP received request: {:?}", msg);

                    match msg.service_type() {
                        ServiceType::L_Data_Req if F::Routing::supports_requests() => {
                            debug!("KnxNetIp Link Layer sending L_Data_Req: {:?}", msg);

                            let (addr_buf, addr_count, tunnel_slots) = self.address_and_tunnel_snapshot();
                            let tunnel_ref = tunnel_slots.as_ref().map(|(len, v)| (*len, v.as_slice()));
                            let context = dispatch::make_server_context::<F::RemoteConfig>(
                                self.context,
                                self.ind_tx,
                                &addr_buf[..addr_count],
                                tunnel_ref,
                                self.address_filter,
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

    /// React to a routing-multicast-address change pushed by
    /// `IpExtensionState::set_routing_multicast_address` or
    /// `IpExtensionState::set_domain_address` (03/02/06 §4.3.5.3.5.1).
    ///
    /// The UDP manager owns the list of currently-joined groups and
    /// knows which one is the routing group, so we only forward the
    /// target. Retargeting the routing server keeps outbound
    /// `ROUTING_INDICATION` frames aimed at the new group.
    fn apply_routing_multicast_rebind(&self, new: Ipv4Addr) {
        debug!("KNX/IP: rebind routing multicast -> {}", new);
        self.udp_manager.rebind_routing_multicast(new, self.interface_addr);
        F::Routing::set_multicast_addr(&self.routing, new);
    }
}
