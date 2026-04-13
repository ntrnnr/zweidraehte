//! KNX/IP Connection Manager
//!
//! Handles the connection lifecycle for all connection-oriented KNX/IP services:
//! - CONNECT_REQUEST / CONNECT_RESPONSE
//! - CONNECTIONSTATE_REQUEST / CONNECTIONSTATE_RESPONSE
//! - DISCONNECT_REQUEST / DISCONNECT_RESPONSE
//!
//! Data frames (DeviceConfigurationRequest, TunnelingRequest, etc.) are routed
//! to the appropriate handler via the [`ConnectionHandlers`] trait.
//!
//! ## Compile-time handler selection
//!
//! The connection manager is parameterized on `H: ConnectionHandlers`, which
//! determines at compile time which connection types are supported.
//!
//! Each connection type slot is independently selectable via the
//! [`ConnectedHandler`] trait pattern — enabled variants delegate to real
//! handlers, disabled variants are zero-size no-ops that LLVM eliminates:
//!
//! - Device Management: [`WithDevMgmt`] / [`NoDevMgmt`]
//! - Tunneling: [`WithTunnel`] / [`NoTunnel`]
//!
//! These are composed into [`CompositeHandlers<DM, TUN>`], which implements
//! [`ConnectionHandlers`] with a single dispatch that routes by connection
//! type to the appropriate slot.
//!
//! Individual connection type handlers implement [`ConnectionTypeHandler`]:
//! - `device_mgmt` — Device Management (ConnectionType 0x03)
//! - `tunnel` — Tunneling (ConnectionType 0x04)

pub(crate) mod context;
mod device_mgmt;
mod handlers;
pub(crate) mod traits;
mod tunnel;

pub(crate) use context::{ConnectionContext, ConnectionTransport, PendingAck};
pub(crate) use device_mgmt::DeviceMgmtConnectionHandler;
pub(crate) use handlers::{
    CompositeHandlers, ConnectedHandler, NoTunnel, TunnelingConnectedHandler, WithDevMgmt, WithTunnel,
};
pub(crate) use traits::{
    AcceptedConnection, AckTimeoutResult, ConnectionHandlers, ConnectionManagerResult, ConnectionTypeHandler,
    DataFrameAction, TcpChannelEvent,
};
pub(crate) use tunnel::TunnelConnectionHandler;

use core::net::Ipv4Addr;

use embassy_sync::channel::DynamicSender;
use embassy_time::{Duration, Instant};
use heapless::Vec;

use zweidraehte_proto::messages::buffers::{Buffer, DynBufferManager};
use zweidraehte_proto::messages::builder::IndicationMessage;
use zweidraehte_proto::messages::knx::{CemiFormat, KnxMessageBuffer};
use zweidraehte_proto::messages::knxip::substructs::{CRD, ConnectionType, HPAI};
use zweidraehte_proto::messages::knxip::{
    ConnectRequest, ConnectResponseBuilder, ConnectionStatus, ConnectionstateRequest, ConnectionstateResponseBuilder,
    DisconnectRequest, DisconnectResponseBuilder, KNXnetIPServiceType,
};
use zweidraehte_proto::util::packets::{ParseBuffer, SerializeBuffer};

use super::types::{PacketOrigin, PendingResponse, ResponseTarget, ServerError, resolve_hpai};
use traits::MAX_RESPONSES;

// ============================================================================
// Connection Manager
// ============================================================================

/// KNX/IP Connection Manager.
///
/// Handles connection lifecycle (connect/disconnect/connectionstate) and routes
/// data frames to the [`ConnectionHandlers`] implementation. Lives as a
/// standalone field on `KnxNetIp`, bypassing the server dispatch.
///
/// The `H` type parameter determines which connection types are supported.
/// Typically this is [`CompositeHandlers`]`<DM, TUN>` with independently
/// selected handler slots (e.g. [`WithDevMgmt`]/[`NoDevMgmt`],
/// [`WithTunnel`]/[`NoTunnel`]).
///
/// `N` is the maximum number of tunneling slots (additional individual
/// addresses). Used for sizing response Vecs in tunneling-related methods.
///
/// Created inside `KnxNetIpBuilder::build()` using the property handler
/// obtained from the [`PropertyServiceContext`](crate::context::PropertyServiceContext).
pub struct ConnectionManager<H, const N: usize = 0, const MAX_CONNECTIONS: usize = 1>
where
    H: ConnectionHandlers<N>,
{
    connections: [Option<ConnectionContext>; MAX_CONNECTIONS],
    handlers: H,
    heartbeat_timeout: Duration,
    next_channel_id: u8,
}

impl<H: ConnectionHandlers<N>, const N: usize, const MAX_CONNECTIONS: usize> ConnectionManager<H, N, MAX_CONNECTIONS> {
    /// Create a new connection manager with the given handler collection.
    pub fn new(handlers: H) -> Self {
        Self {
            connections: core::array::from_fn(|_| None),
            handlers,
            heartbeat_timeout: Duration::from_secs(120),
            next_channel_id: 1,
        }
    }

    /// Handle an incoming KNX/IP message for a connection-oriented service.
    ///
    /// The caller must only pass service types with category
    /// [`ServiceCategory::ConnectionLifecycle`](zweidraehte_proto::messages::knxip::ServiceCategory::ConnectionLifecycle) or [`ServiceCategory::ConnectionData`](zweidraehte_proto::messages::knxip::ServiceCategory::ConnectionData).
    /// Connectionless service types are handled separately by the server instances.
    ///
    /// Connection lifecycle messages (Connect, Disconnect, Connectionstate) are
    /// handled directly. Connection-oriented data frames are routed to the
    /// appropriate [`ConnectionTypeHandler`] via channel ID lookup.
    pub async fn on_indication(
        &mut self,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        origin: PacketOrigin,
        buffer_manager: &DynBufferManager<'static>,
        ind_tx: DynamicSender<'_, IndicationMessage<Buffer<'static>>>,
    ) -> Result<ConnectionManagerResult, ServerError> {
        match service_type {
            // Connection lifecycle — handled directly by the connection manager
            KNXnetIPServiceType::ConnectRequest => self.handle_connect_request(data, origin, buffer_manager).await,
            KNXnetIPServiceType::ConnectionstateRequest => {
                self.handle_connectionstate_request(data, origin, buffer_manager).await
            }
            KNXnetIPServiceType::DisconnectRequest => {
                self.handle_disconnect_request(data, origin, buffer_manager).await
            }

            // Everything else: route to the handler via channel ID lookup
            _ => {
                let responses = self.dispatch_to_handler(service_type, data, buffer_manager, ind_tx).await?;
                Ok(ConnectionManagerResult::responses_only(responses))
            }
        }
    }

    /// Route a data frame to the appropriate handler based on channel ID.
    ///
    /// The 4-byte connection header (at offset 6, after the KNXnet/IP header)
    /// contains the channel ID at byte 7 (offset 6 + 1). We use this to look
    /// up the connection, find its type, and delegate to the matching handler.
    async fn dispatch_to_handler(
        &mut self,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        buffer_manager: &DynBufferManager<'static>,
        ind_tx: DynamicSender<'_, IndicationMessage<Buffer<'static>>>,
    ) -> Result<Vec<PendingResponse, MAX_RESPONSES>, ServerError> {
        // Connection header starts at offset 6 (after KNXnet/IP header).
        // Byte layout: struct_length(1), channel_id(1), sequence_or_reserved(1), status_or_reserved(1)
        if data.len() < 6 + 4 {
            return Err(ServerError::InvalidMessage);
        }

        let channel_id = data[7]; // offset 6 + 1

        // Find the connection and its type
        let conn_idx =
            self.connections.iter().position(|slot| slot.as_ref().is_some_and(|ctx| ctx.channel_id == channel_id));

        let Some(conn_idx) = conn_idx else {
            debug!("Data frame for unknown channel {}, service {:?}", channel_id, service_type);
            return Err(ServerError::InvalidMessage);
        };

        let connection_type = self.connections[conn_idx].as_ref().expect("just verified Some").connection_type;

        // Verify the handler collection supports this service type for this connection type
        if !self.handlers.handles_service_type(connection_type, service_type) {
            debug!("No handler for service type {:?} on connection type {:?}", service_type, connection_type);
            return Err(ServerError::InvalidMessage);
        }

        // Determine if this is a data frame (request) or an ACK.
        // Convention: ACK service types are the request type + 1
        // (e.g., DeviceConfigurationRequest=0x0310, DeviceConfigurationAck=0x0311;
        //        TunnelingRequest=0x0420, TunnelingAck=0x0421).
        let service_type_raw: u16 = service_type.into();
        let is_ack = (service_type_raw & 0x01) != 0;

        if is_ack {
            let conn = self.connections[conn_idx].as_mut().expect("just verified Some");
            self.handlers.on_data_ack(channel_id, connection_type, service_type, data, conn)?;
            Ok(Vec::new())
        } else {
            let conn = self.connections[conn_idx].as_mut().expect("just verified Some");
            let action = self
                .handlers
                .on_data_frame(channel_id, connection_type, service_type, data, conn, buffer_manager)
                .await?;

            match action {
                DataFrameAction::Responses(handler_responses) => {
                    let mut responses = Vec::new();
                    for r in handler_responses {
                        let _ = responses.push(r);
                    }
                    Ok(responses)
                }
                DataFrameAction::AckOnly(ack) => {
                    let mut responses = Vec::new();
                    let _ = responses.push(ack);
                    Ok(responses)
                }
                DataFrameAction::AckAndInject { ack, cemi_buffer } => {
                    // Save cEMI data for cross-client forwarding before
                    // `from_cemi()` consumes the buffer. The forwarded copy
                    // has its message code changed from L_Data.req (0x11) to
                    // L_Data.ind (0x29) since other clients receive it as an
                    // indication, not a request.
                    let mut forwarding_cemi = [0u8; 256];
                    let cemi_len = cemi_buffer.len().min(forwarding_cemi.len());
                    forwarding_cemi[..cemi_len].copy_from_slice(&cemi_buffer[..cemi_len]);
                    if cemi_len > 0 {
                        forwarding_cemi[0] = 0x29; // L_Data.ind
                    }

                    // Convert cEMI buffer to internal format and inject into
                    // the network layer as an indication — same pattern as
                    // the routing server (routing.rs).
                    let cemi_msg: KnxMessageBuffer<Buffer<'static>, CemiFormat> =
                        KnxMessageBuffer::from_cemi(cemi_buffer);
                    let internal_msg = cemi_msg.into_internal();
                    let indication = IndicationMessage::indication(internal_msg);
                    ind_tx.send(indication).await;

                    let mut responses = Vec::new();
                    let _ = responses.push(ack);

                    // Forward to other active tunnel clients so they see
                    // frames originated by sibling connections. Without this,
                    // the TPUART echo filter would prevent them from ever
                    // seeing the frame.
                    let forwarded =
                        self.forward_bus_indication_excluding(&forwarding_cemi[..cemi_len], channel_id, buffer_manager);
                    for response in forwarded {
                        let _ = responses.push(response);
                    }

                    Ok(responses)
                }
            }
        }
    }

    /// Periodic tick for heartbeat timeout checking.
    ///
    /// Should be called every ~10 seconds from the main loop. Returns
    /// no responses — timed-out connections are silently closed since the
    /// client is presumed dead.
    pub fn on_tick(&mut self) -> Vec<TcpChannelEvent, MAX_CONNECTIONS> {
        let now = Instant::now();
        let mut tcp_events = Vec::new();

        for slot in &mut self.connections {
            if let Some(ctx) = slot
                && now - ctx.last_activity > self.heartbeat_timeout
            {
                info!(
                    "Connection {} timed out (no heartbeat for {}s), closing",
                    ctx.channel_id,
                    self.heartbeat_timeout.as_secs()
                );
                let channel_id = ctx.channel_id;
                let connection_type = ctx.connection_type;
                let transport = ctx.transport;
                *slot = None;

                // Notify the handler
                self.handlers.close_connection(channel_id, connection_type);

                if let ConnectionTransport::Tcp { tcp_idx } = transport {
                    let _ = tcp_events.push(TcpChannelEvent::Removed { tcp_idx, channel_id });
                }
            }
        }

        tcp_events
    }

    /// Check for ACK timeouts on all connections.
    ///
    /// For each connection with a pending server→client frame:
    /// - If the ACK timeout has elapsed and retries remain, queue a
    ///   retransmission and reset the timer.
    /// - If retries are exhausted, send a DISCONNECT_REQUEST and tear
    ///   down the connection.
    ///
    /// Timeout and retry limits per connection type (KNX spec):
    /// - Tunneling: 1s timeout, 1 retry (03/08/04 §2.6.1)
    /// - Device Management: 10s timeout, 3 retries (03/08/03 §2.3.2)
    ///
    /// TCP connections are skipped — they have no ACK mechanism.
    pub fn check_ack_timeouts(
        &mut self,
        buffer_manager: &DynBufferManager<'static>,
    ) -> AckTimeoutResult<MAX_CONNECTIONS> {
        let now = Instant::now();
        let mut retransmissions = Vec::new();
        let mut disconnects = Vec::new();
        // ACK timeouts only affect UDP connections, so no TCP events are
        // produced here. (TCP connections skip ACKs entirely.)
        let tcp_events = Vec::new();

        for slot in &mut self.connections {
            let Some(ctx) = slot.as_mut() else { continue };

            // TCP connections have no ACK mechanism.
            if matches!(ctx.transport, ConnectionTransport::Tcp { .. }) {
                continue;
            }

            let Some(pending) = &mut ctx.pending_ack else { continue };

            let (timeout, max_retries) = match ctx.connection_type {
                ConnectionType::Tunnel => (Duration::from_secs(1), 1u8),
                ConnectionType::DeviceManagement => (Duration::from_secs(10), 3u8),
                _ => continue,
            };

            if now - pending.sent_at < timeout {
                continue;
            }

            if pending.attempt < max_retries {
                // Retransmit: clone the buffer and resend.
                if let Some(retransmit_buffer) = buffer_manager.try_alloc_from_slice(&pending.buffer) {
                    pending.attempt += 1;
                    pending.sent_at = now;
                    info!(
                        "ACK timeout: channel={}, seq={}, attempt {}/{} — retransmitting",
                        ctx.channel_id, pending.sequence_counter, pending.attempt, max_retries,
                    );
                    let _ = retransmissions.push(PendingResponse { buffer: retransmit_buffer, target: pending.target });
                } else {
                    warn!(
                        "ACK timeout: channel={}, seq={} — no buffer for retransmit, giving up",
                        ctx.channel_id, pending.sequence_counter,
                    );
                    // Can't retransmit without a buffer. Treat as exhausted
                    // to avoid silently stalling the connection forever.
                    pending.attempt = max_retries;
                    pending.sent_at = now;
                }
            } else {
                // Retries exhausted — disconnect.
                warn!(
                    "ACK timeout: channel={}, seq={} — {} retries exhausted, disconnecting",
                    ctx.channel_id, pending.sequence_counter, max_retries,
                );

                let channel_id = ctx.channel_id;
                let connection_type = ctx.connection_type;
                let control_endpoint = ctx.control_endpoint;
                let socket_idx = ctx.socket_idx;

                // Build DISCONNECT_REQUEST to the client's control endpoint.
                let control_target = ResponseTarget::Udp { destination: control_endpoint, socket_idx };
                let _ = disconnects.push((channel_id, control_target));

                // Tear down the connection.
                *slot = None;
                self.handlers.close_connection(channel_id, connection_type);
            }
        }

        AckTimeoutResult { retransmissions, disconnects, tcp_events }
    }

    /// Check if there are any active connections (used by main loop to
    /// decide whether to run the heartbeat timer).
    pub fn has_active_connections(&self) -> bool {
        self.connections.iter().any(|slot| slot.is_some())
    }

    /// Send a cEMI TL response frame through the active Device Management
    /// connection.
    ///
    /// Called by the KNX/IP runtime when the Application Layer produces a
    /// `T_Data_Req` that was intercepted by the [`CemiTransportLayer`](crate::layers::transport::cemi::CemiTransportLayer)
    /// and forwarded via the `cemi_response` channel.
    ///
    /// The `internal_buf` contains the AL's response in internal message
    /// format: `ctrl(1) + src(2) + dst(2) + npdu(1) + tpci/apci/data`.
    /// This method converts it to cEMI TL wire format and wraps it in a
    /// `DeviceConfigurationRequest`.
    ///
    /// Returns `Some(PendingResponse)` if the frame was built successfully,
    /// `None` if no DevMgmt connection is active or buffers ran out.
    pub fn send_devmgmt_cemi_frame(
        &mut self,
        internal_buf: &Buffer<'static>,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Option<PendingResponse> {
        use zweidraehte_proto::encoding::cemi::{CemiMessageCode, CemiTransportBuilder};
        use zweidraehte_proto::messages::knxip::DeviceConfigurationRequestBuilder;

        // Find the active Device Management connection.
        let conn =
            self.connections.iter_mut().flatten().find(|c| c.connection_type == ConnectionType::DeviceManagement)?;

        // Convert internal format to cEMI TL wire format.
        //
        // Internal format: ctrl(1) + src(2) + dst(2) + npdu(1) + tpdu(N)
        // The TPDU starts at byte 6 of the internal format.
        let data = internal_buf.as_ref();
        if data.len() < 7 {
            warn!("cEMI TL response: internal buffer too short ({} bytes)", data.len());
            return None;
        }

        let tpdu = &data[6..];
        debug!(
            "cEMI TL response: internal ({} bytes): {:?}, TPDU ({} bytes): {:?}",
            data.len(),
            zweidraehte_util::fmt::Bytes(data),
            tpdu.len(),
            zweidraehte_util::fmt::Bytes(tpdu)
        );

        // Serialize the cEMI TL payload using the standard builder.
        // Message code: T_Data_Connected.ind (0x89) — the device acts as
        // the "bus" toward the cEMI client, indicating data to it. ETS
        // expects .ind, not .con (which is for bus-level confirmations).
        let cemi_builder = CemiTransportBuilder { message_code: CemiMessageCode::TDataConnectedInd, tpdu };
        let mut cemi_payload = [0u8; 256];
        let mut cemi_buf: &mut [u8] = &mut cemi_payload;
        let (cemi_data, _) = cemi_buf.serialize(&cemi_builder);

        // Build DeviceConfigurationRequest wrapping the cEMI payload.
        let send_seq = conn.send_sequence_counter;
        conn.send_sequence_counter = send_seq.wrapping_add(1);

        let req_builder = DeviceConfigurationRequestBuilder::with_payload(conn.channel_id, send_seq, cemi_data);

        let mut resp_buffer = buffer_manager.try_alloc()?;
        resp_buffer.serialize(&req_builder);
        let target = conn.response_target();

        // For UDP connections, save a copy for retransmission.
        if matches!(conn.transport, ConnectionTransport::Udp)
            && let Some(retransmit_buffer) = buffer_manager.try_alloc_from_slice(&resp_buffer)
        {
            conn.pending_ack = Some(PendingAck {
                sequence_counter: send_seq,
                buffer: retransmit_buffer,
                target,
                sent_at: Instant::now(),
                attempt: 0,
            });
        }

        conn.last_activity = Instant::now();

        Some(PendingResponse { buffer: resp_buffer, target })
    }

    /// Snapshot the current tunneling slot status for use in DIBs.
    ///
    /// Returns `Some((max_apdu_len, slots))` if a tunneling handler is
    /// registered, `None` otherwise. Delegates to the [`ConnectionHandlers`]
    /// implementation — `DevMgmtOnly` always returns `None`.
    pub fn tunneling_slot_info(
        &self,
    ) -> Option<(u16, heapless::Vec<zweidraehte_proto::messages::knxip::substructs::TunnelingSlotInfo, N>)> {
        self.handlers.tunneling_slot_info()
    }

    /// Forward a bus indication (cEMI L_Data.ind) to matching tunnel clients.
    ///
    /// Called by the composite link layer when a frame is received from
    /// the TP1 bus. The handler collection determines which active connections
    /// should receive the frame based on the cEMI destination:
    /// - Group-addressed / broadcast → all active tunnel connections
    /// - Individually-addressed → only the connection whose assigned IA
    ///   matches the destination
    ///
    /// When `H = DevMgmtOnly`, `channels_for_bus_indication` returns empty
    /// and no tunneling code is linked.
    ///
    /// Each matching connection gets a `TunnelingRequest` with the
    /// per-connection server-side send sequence counter. The returned
    /// responses should be sent on the wire by the caller.
    pub fn forward_bus_indication(
        &mut self,
        cemi_data: &[u8],
        buffer_manager: &DynBufferManager<'static>,
    ) -> Vec<PendingResponse, N> {
        let mut responses = Vec::new();

        let target_channels = self.handlers.channels_for_bus_indication(cemi_data);
        if target_channels.is_empty() {
            return responses;
        }

        // For each target channel, build a TunnelingRequest with the
        // connection's send sequence counter.
        for channel_id in target_channels {
            self.send_tunneling_request(channel_id, cemi_data, buffer_manager, &mut responses);
        }

        responses
    }

    /// Forward a cEMI indication to matching tunnel clients, excluding the
    /// originating channel.
    ///
    /// Used for cross-client forwarding: when tunnel client A sends a group
    /// write, the frame is injected to the TP1 bus, but the TPUART echo
    /// filter prevents it from returning as a `SubnetIndication`. This
    /// method ensures sibling tunnel clients (B, C, ...) still see the frame.
    ///
    /// The cEMI data should already have its message code set to L_Data.ind
    /// (0x29) by the caller.
    fn forward_bus_indication_excluding(
        &mut self,
        cemi_data: &[u8],
        exclude_channel: u8,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Vec<PendingResponse, N> {
        let mut responses = Vec::new();

        let target_channels = self.handlers.channels_for_bus_indication(cemi_data);
        if target_channels.is_empty() {
            return responses;
        }

        for channel_id in target_channels {
            if channel_id == exclude_channel {
                continue;
            }

            self.send_tunneling_request(channel_id, cemi_data, buffer_manager, &mut responses);
        }

        responses
    }

    /// Build and send a `TunnelingRequest` to a single tunnel client,
    /// recording a retransmit copy for UDP connections.
    fn send_tunneling_request(
        &mut self,
        channel_id: u8,
        cemi_data: &[u8],
        buffer_manager: &DynBufferManager<'static>,
        responses: &mut Vec<PendingResponse, N>,
    ) {
        let Some(conn) = self.find_connection_mut(channel_id) else {
            return;
        };

        let send_seq = conn.send_sequence_counter;
        conn.send_sequence_counter = send_seq.wrapping_add(1);
        let target = conn.response_target();
        let is_udp = matches!(conn.transport, ConnectionTransport::Udp);

        if let Some(response) = H::build_tunneling_request(channel_id, send_seq, cemi_data, target, buffer_manager) {
            // For UDP connections, save a copy for retransmission if the
            // client doesn't ACK within the timeout.
            if is_udp && let Some(retransmit_buffer) = buffer_manager.try_alloc_from_slice(&response.buffer) {
                let conn = self.find_connection_mut(channel_id).expect("connection verified above");
                conn.pending_ack = Some(PendingAck {
                    sequence_counter: send_seq,
                    buffer: retransmit_buffer,
                    target,
                    sent_at: Instant::now(),
                    attempt: 0,
                });
            }

            let _ = responses.push(response);
        } else {
            warn!("No buffer for tunnel forward (channel {})", channel_id);
        }
    }

    /// Called when a TCP connection is closed (peer disconnect or I/O error).
    ///
    /// Tears down all KNX/IP connections that were running over this TCP
    /// stream. Per KNX spec 3/8/2 §8.4.3: when the TCP connection is
    /// closed, all inner KNX/IP connections are considered terminated.
    pub fn on_tcp_closed(&mut self, tcp_idx: usize) {
        for slot in &mut self.connections {
            let should_close = slot.as_ref().is_some_and(
                |ctx| matches!(ctx.transport, ConnectionTransport::Tcp { tcp_idx: idx } if idx == tcp_idx),
            );

            if should_close {
                let ctx = slot.take().expect("just checked Some");
                info!("TCP connection {} closed, tearing down KNX/IP channel {}", tcp_idx, ctx.channel_id);

                self.handlers.close_connection(ctx.channel_id, ctx.connection_type);
            }
        }
    }

    // ========================================================================
    // Private: ConnectRequest
    // ========================================================================

    async fn handle_connect_request(
        &mut self,
        data: &[u8],
        origin: PacketOrigin,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<ConnectionManagerResult, ServerError> {
        let mut buf = data;
        let request = match buf.parse::<ConnectRequest>() {
            Ok(req) => req,
            Err(_) => {
                debug!("Failed to parse ConnectRequest ({} bytes)", data.len());
                return self
                    .send_connect_response(0, ConnectionStatus::DataConnectionError, None, origin, buffer_manager)
                    .await;
            }
        };

        let cri_connection_type = request.cri.connection_type();

        // Allocate a connection slot
        let slot_idx = self.connections.iter().position(|s| s.is_none());
        let Some(slot_idx) = slot_idx else {
            debug!("No more connection slots available");
            return self
                .send_connect_response(0, ConnectionStatus::NoMoreConnections, None, origin, buffer_manager)
                .await;
        };

        let channel_id = self.allocate_channel_id();

        // Ask the handler collection to accept. The trait impl returns
        // ConnectionTypeNotSupported if the connection type isn't available.
        let accepted = match self.handlers.accept_connection(channel_id, cri_connection_type, &request.cri) {
            Ok(accepted) => accepted,
            Err(status) => {
                return self.send_connect_response(channel_id, status, None, origin, buffer_manager).await;
            }
        };

        // Determine transport and TCP channel tracking based on origin.
        let source = origin.peer_addr();
        let (transport, socket_idx, tcp_event) = match origin {
            PacketOrigin::Tcp { tcp_idx, .. } => {
                // Per KNX spec 3/8/2 §8.6.3.5: TCP ConnectRequests must use
                // Route Back HPAI (0.0.0.0:0 with IPv4TCP protocol) for both
                // control and data endpoints.
                let is_route_back = |hpai: &HPAI| -> bool {
                    matches!(hpai, HPAI::Ipv4Tcp { addr, port } if addr.is_unspecified() && *port == 0)
                };

                if !is_route_back(&request.control_endpoint) || !is_route_back(&request.data_endpoint) {
                    debug!("TCP ConnectRequest with non-Route-Back HPAI, rejecting");
                    return self
                        .send_connect_response(
                            channel_id,
                            ConnectionStatus::DataConnectionError,
                            None,
                            origin,
                            buffer_manager,
                        )
                        .await;
                }

                (
                    ConnectionTransport::Tcp { tcp_idx },
                    0, // socket_idx is unused for TCP
                    Some(TcpChannelEvent::Added { tcp_idx, channel_id }),
                )
            }
            PacketOrigin::Udp { socket_idx, .. } => (ConnectionTransport::Udp, socket_idx, None),
        };

        // NAT detection: if HPAI is 0.0.0.0:0, use packet source address.
        // For TCP connections the HPAIs are Route Back and not used for routing,
        // but we store the peer address for logging/diagnostics.
        let control_endpoint = resolve_hpai(&request.control_endpoint, source);
        let data_endpoint = resolve_hpai(&request.data_endpoint, source);

        info!(
            "Accepting {:?} connection: channel_id={}, transport={:?}, control={}, data={}",
            cri_connection_type, channel_id, transport, control_endpoint, data_endpoint
        );

        // Store the connection
        self.connections[slot_idx] = Some(ConnectionContext {
            channel_id,
            connection_type: cri_connection_type,
            control_endpoint,
            data_endpoint,
            recv_sequence_counter: 0,
            send_sequence_counter: 0,
            last_activity: Instant::now(),
            socket_idx,
            transport,
            pending_ack: None,
        });

        // Build ConnectResponse with success
        let mut result = self
            .send_connect_response(channel_id, ConnectionStatus::NoError, Some(accepted.crd), origin, buffer_manager)
            .await?;

        if let Some(event) = tcp_event {
            let _ = result.tcp_events.push(event);
        }

        Ok(result)
    }

    /// Build and send a ConnectResponse.
    ///
    /// For success responses, `crd` contains the connection response data.
    /// For error responses, `crd` is `None` — the builder omits the CRD and
    /// uses a minimal HPAI.
    ///
    /// The response is routed back via the same transport the request arrived
    /// on. For TCP, the data endpoint HPAI uses the IPv4TCP protocol code
    /// (Route Back). For UDP, it uses IPv4UDP with 0.0.0.0:0 (NAT-friendly).
    async fn send_connect_response(
        &self,
        channel_id: u8,
        status: ConnectionStatus,
        crd: Option<CRD>,
        origin: PacketOrigin,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<ConnectionManagerResult, ServerError> {
        let data_endpoint = match origin {
            PacketOrigin::Tcp { .. } => HPAI::ipv4_tcp(Ipv4Addr::UNSPECIFIED, 0),
            PacketOrigin::Udp { .. } => HPAI::ipv4_udp(Ipv4Addr::UNSPECIFIED, 0),
        };

        let builder = ConnectResponseBuilder::new(channel_id, status, data_endpoint, crd);
        let mut buffer = buffer_manager.alloc().await;
        buffer.serialize(&builder);

        let mut responses = Vec::new();
        let _ = responses.push(PendingResponse { buffer, target: origin.reply_target() });
        Ok(ConnectionManagerResult::responses_only(responses))
    }

    // ========================================================================
    // Private: ConnectionstateRequest
    // ========================================================================

    async fn handle_connectionstate_request(
        &mut self,
        data: &[u8],
        origin: PacketOrigin,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<ConnectionManagerResult, ServerError> {
        let mut buf = data;
        let request = match buf.parse::<ConnectionstateRequest>() {
            Ok(req) => req,
            Err(_) => return Err(ServerError::ParseError),
        };

        let channel_id = request.communication_channel_id;

        // Find the connection and determine response target.
        // Known connections reply via their stored transport; unknown channels
        // reply via the same transport the request arrived on.
        let (status, target) = match self.find_connection_mut(channel_id) {
            Some(ctx) => {
                ctx.last_activity = Instant::now();
                (ConnectionStatus::NoError, ctx.response_target())
            }
            None => {
                debug!("Connectionstate request for unknown channel {}", channel_id);
                (ConnectionStatus::NoSuchConnectionID, origin.reply_target())
            }
        };

        // Build response — non-critical, remote side will retry the keepalive.
        let mut responses = Vec::new();
        if let Some(mut buffer) = buffer_manager.try_alloc() {
            let builder = ConnectionstateResponseBuilder::new(channel_id, status);
            buffer.serialize(&builder);
            let _ = responses.push(PendingResponse { buffer, target });
        } else {
            warn!("Buffer pool exhausted — skipping ConnectionstateResponse for channel {}", channel_id);
        }
        Ok(ConnectionManagerResult::responses_only(responses))
    }

    // ========================================================================
    // Private: DisconnectRequest
    // ========================================================================

    async fn handle_disconnect_request(
        &mut self,
        data: &[u8],
        origin: PacketOrigin,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<ConnectionManagerResult, ServerError> {
        let mut buf = data;
        let request = match buf.parse::<DisconnectRequest>() {
            Ok(req) => req,
            Err(_) => return Err(ServerError::ParseError),
        };

        let channel_id = request.communication_channel_id;

        // Find and remove the connection
        let (status, target, tcp_event) = match self.remove_connection(channel_id) {
            Some(ctx) => {
                info!("Disconnecting channel {}", channel_id);

                // Notify the handler
                self.handlers.close_connection(channel_id, ctx.connection_type);

                let target = ctx.response_target();
                let tcp_event = match ctx.transport {
                    ConnectionTransport::Tcp { tcp_idx } => Some(TcpChannelEvent::Removed { tcp_idx, channel_id }),
                    ConnectionTransport::Udp => None,
                };
                (ConnectionStatus::NoError, target, tcp_event)
            }
            None => {
                // Idempotent: respond with NoError even if not found
                debug!("Disconnect request for unknown channel {}", channel_id);
                (ConnectionStatus::NoError, origin.reply_target(), None)
            }
        };

        // Build response — non-critical, connection times out on remote side anyway.
        let mut responses = Vec::new();
        if let Some(mut buffer) = buffer_manager.try_alloc() {
            let builder = DisconnectResponseBuilder::new(channel_id, status);
            buffer.serialize(&builder);
            let _ = responses.push(PendingResponse { buffer, target });
        } else {
            warn!("Buffer pool exhausted — skipping DisconnectResponse for channel {}", channel_id);
        }

        let mut tcp_events = Vec::new();
        if let Some(event) = tcp_event {
            let _ = tcp_events.push(event);
        }

        Ok(ConnectionManagerResult { responses, tcp_events })
    }

    // ========================================================================
    // Private: Helpers
    // ========================================================================

    fn find_connection_mut(&mut self, channel_id: u8) -> Option<&mut ConnectionContext> {
        self.connections.iter_mut().filter_map(|slot| slot.as_mut()).find(|ctx| ctx.channel_id == channel_id)
    }

    fn remove_connection(&mut self, channel_id: u8) -> Option<ConnectionContext> {
        for slot in &mut self.connections {
            if let Some(ctx) = slot
                && ctx.channel_id == channel_id
            {
                return slot.take();
            }
        }
        None
    }

    fn allocate_channel_id(&mut self) -> u8 {
        // Simple incrementing allocation. Channel ID 0 is reserved.
        let id = self.next_channel_id;
        self.next_channel_id = self.next_channel_id.wrapping_add(1);
        if self.next_channel_id == 0 {
            self.next_channel_id = 1;
        }
        id
    }
}
