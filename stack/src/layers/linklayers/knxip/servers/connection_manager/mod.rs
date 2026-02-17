//! KNX/IP Connection Manager
//!
//! Handles the connection lifecycle for all connection-oriented KNX/IP services:
//! - CONNECT_REQUEST / CONNECT_RESPONSE
//! - CONNECTIONSTATE_REQUEST / CONNECTIONSTATE_RESPONSE
//! - DISCONNECT_REQUEST / DISCONNECT_RESPONSE
//!
//! Data frames (DeviceConfigurationRequest, TunnelingRequest, etc.) are routed
//! to the appropriate [`ConnectionTypeHandler`] based on the connection's type.
//!
//! The connection manager lives as a standalone field on [`KnxNetIp`], separate
//! from the [`ServerHandler`] enum. It receives a `&dyn PropertyServiceHandler`
//! at construction time (inside `build_and_run`, where the stack context provides
//! the interface objects). This avoids propagating generics through the server
//! infrastructure.
//!
//! ## Module structure
//!
//! Each connection type handler lives in its own submodule:
//! - [`device_mgmt`] — Device Management (ConnectionType 0x03)

mod device_mgmt;

pub use device_mgmt::DeviceMgmtConnectionHandler;

use core::cell::RefCell;
use core::net::{Ipv4Addr, SocketAddrV4};

use embassy_sync::channel::DynamicSender;
use embassy_time::{Duration, Instant};
use heapless::Vec;

use crate::layers::LayerOp;
use crate::messages::buffers::{Buffer, DynBufferManager};
use crate::messages::builder::IndicationMessage;
use crate::messages::knx::{CemiFormat, KnxMessageBuffer};
use crate::messages::knxip::substructs::{CRD, CRI, ConnectionType, HPAI};
use crate::messages::knxip::{
    ConnectRequest, ConnectResponseBuilder, ConnectionStatus, ConnectionstateRequest, ConnectionstateResponseBuilder,
    DisconnectRequest, DisconnectResponseBuilder, KNXnetIPServiceType,
};
use crate::util::packets::{ParseBuffer, SerializeBuffer};

use super::super::{PacketOrigin, ResponseTarget};
use super::{PendingResponse, ServerError};

// ============================================================================
// Connection Type Handler Trait
// ============================================================================

/// Result of a successfully accepted connection.
pub struct AcceptedConnection {
    /// CRD to include in the ConnectResponse.
    pub crd: CRD,
}

/// What the connection manager should do after a handler processes a data frame.
pub enum DataFrameAction {
    /// Send response frames to the client (ACK + optional data response).
    /// Used by device management: ACK + M_PropRead.con / M_PropWrite.con.
    Responses(Vec<PendingResponse, 4>),
    /// ACK the client and inject a cEMI frame into the KNX stack.
    /// Used by tunneling: ACK + L_Data forwarded to network layer.
    /// The `Buffer` contains raw cEMI data (allocated by the handler from
    /// the buffer manager). The connection manager converts it via
    /// `KnxMessageBuffer::from_cemi().into_internal()` before sending to
    /// the network layer.
    AckAndInject { ack: PendingResponse, cemi_buffer: Buffer<'static> },
    /// Just ACK (e.g., retransmission that was already processed).
    AckOnly(PendingResponse),
}

/// Trait for connection-type-specific logic.
///
/// Each connection type (Device Management, Tunneling, etc.) implements this
/// trait. The connection manager delegates connection acceptance and data
/// frame processing through this interface.
///
/// Handlers own their service-type-specific protocol framing: they parse
/// their own request messages (e.g., `DeviceConfigurationRequest`), validate
/// sequence counters, build ACK responses, and process the payload. The
/// connection manager only handles connection lifecycle (connect, disconnect,
/// connectionstate) and executes the [`DataFrameAction`] returned by handlers.
///
/// Intentionally has **no generic parameters** — concrete handlers hold their
/// own resources (e.g., a reference to a `dyn PropertyServiceHandler`) internally.
pub trait ConnectionTypeHandler {
    /// Called when a ConnectRequest arrives for this connection type.
    ///
    /// The handler inspects the CRI and decides whether to accept (returning
    /// a CRD) or reject (returning an error status).
    fn accept_connection(&mut self, channel_id: u8, cri: &CRI) -> Result<AcceptedConnection, ConnectionStatus>;

    /// Called when a connection is closed (disconnect or heartbeat timeout).
    fn close_connection(&mut self, channel_id: u8);

    /// Handle an incoming data frame for this connection type.
    ///
    /// Receives the full KNX/IP packet (including header), the mutable
    /// connection context (for reading/updating sequence counters and
    /// endpoints), and the buffer manager for allocating response buffers.
    ///
    /// Returns a [`DataFrameAction`] telling the connection manager what
    /// to do: send responses, inject into the stack, or just ACK.
    async fn on_data_frame(
        &mut self,
        channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Result<DataFrameAction, ServerError>;

    /// Handle an incoming ACK for a frame we sent to the client.
    fn on_data_ack(&mut self, channel_id: u8, data: &[u8], conn: &mut ConnectionContext) -> Result<(), ServerError>;

    /// Which service types this handler processes (both requests and ACKs).
    fn handled_service_types(&self) -> &[KNXnetIPServiceType];
}

// ============================================================================
// Connection Type Handler Enum
// ============================================================================

/// Enum wrapping all connection type handlers.
///
/// This enum dispatches trait method calls to the appropriate inner handler.
/// Since handlers use `&dyn PropertyServiceHandler` internally, no generics
/// are needed here.
pub enum ConnectionTypeHandlerEnum<'a> {
    /// Device Management connection handler (ConnectionType 0x03)
    DeviceManagement(DeviceMgmtConnectionHandler<'a>),
    // Future: Tunnel(TunnelConnectionHandler<'a>),
}

impl ConnectionTypeHandler for ConnectionTypeHandlerEnum<'_> {
    fn accept_connection(&mut self, channel_id: u8, cri: &CRI) -> Result<AcceptedConnection, ConnectionStatus> {
        match self {
            ConnectionTypeHandlerEnum::DeviceManagement(h) => h.accept_connection(channel_id, cri),
        }
    }

    fn close_connection(&mut self, channel_id: u8) {
        match self {
            ConnectionTypeHandlerEnum::DeviceManagement(h) => h.close_connection(channel_id),
        }
    }

    async fn on_data_frame(
        &mut self,
        channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Result<DataFrameAction, ServerError> {
        match self {
            ConnectionTypeHandlerEnum::DeviceManagement(h) => {
                h.on_data_frame(channel_id, data, conn, buffer_manager).await
            }
        }
    }

    fn on_data_ack(&mut self, channel_id: u8, data: &[u8], conn: &mut ConnectionContext) -> Result<(), ServerError> {
        match self {
            ConnectionTypeHandlerEnum::DeviceManagement(h) => h.on_data_ack(channel_id, data, conn),
        }
    }

    fn handled_service_types(&self) -> &[KNXnetIPServiceType] {
        match self {
            ConnectionTypeHandlerEnum::DeviceManagement(h) => h.handled_service_types(),
        }
    }
}

// ============================================================================
// Connection Context
// ============================================================================

/// The transport over which a KNX/IP connection was established.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConnectionTransport {
    /// Connection runs over UDP — responses go to the data endpoint.
    Udp,
    /// Connection runs over TCP — responses go back on the same stream.
    Tcp { tcp_idx: usize },
}

/// Per-connection state tracked by the connection manager.
///
/// Exposed to [`ConnectionTypeHandler`] implementations so they can
/// read/update sequence counters and access endpoint information.
pub struct ConnectionContext {
    pub channel_id: u8,
    pub connection_type: ConnectionType,
    pub control_endpoint: SocketAddrV4,
    pub data_endpoint: SocketAddrV4,
    pub recv_sequence_counter: u8,
    pub send_sequence_counter: u8,
    pub last_activity: Instant,
    pub socket_idx: usize,
    /// Which transport this connection uses.
    pub transport: ConnectionTransport,
}

impl ConnectionContext {
    /// Build a [`ResponseTarget`] for sending data frames to the client.
    ///
    /// For UDP, routes to the data endpoint on the originating socket.
    /// For TCP, routes back on the TCP connection.
    pub fn response_target(&self) -> ResponseTarget {
        match self.transport {
            ConnectionTransport::Udp => {
                ResponseTarget::Udp { destination: self.data_endpoint, socket_idx: self.socket_idx }
            }
            ConnectionTransport::Tcp { tcp_idx } => ResponseTarget::Tcp { tcp_idx },
        }
    }
}

// ============================================================================
// TCP Channel Tracking
// ============================================================================

/// Side-effect for TCP channel tracking.
///
/// Returned from connection manager methods so the main loop can update
/// `TcpConnectionState.channel_ids` without the connection manager needing
/// a reference to the TCP manager.
#[derive(Debug)]
pub enum TcpChannelEvent {
    /// A KNX/IP channel was created on a TCP connection.
    Added { tcp_idx: usize, channel_id: u8 },
    /// A KNX/IP channel was removed from a TCP connection.
    Removed { tcp_idx: usize, channel_id: u8 },
}

/// Result of a connection manager operation.
///
/// Bundles responses to send with optional TCP channel tracking events
/// that the main loop must apply to the TCP manager.
pub struct ConnectionManagerResult {
    pub responses: Vec<PendingResponse, 4>,
    pub tcp_events: Vec<TcpChannelEvent, 2>,
}

impl ConnectionManagerResult {
    fn responses_only(responses: Vec<PendingResponse, 4>) -> Self {
        Self { responses, tcp_events: Vec::new() }
    }
}

// ============================================================================
// Connection Manager
// ============================================================================

/// KNX/IP Connection Manager.
///
/// Handles connection lifecycle (connect/disconnect/connectionstate) and routes
/// data frames to registered [`ConnectionTypeHandler`]s. Lives as a standalone
/// field on `KnxNetIp`, bypassing the `ServerHandler` enum dispatch.
///
/// Created inside [`KnxNetIpBuilder::build()`] using the property handler
/// obtained from the [`PropertyServiceContext`]. A connection manager with no
/// registered handlers is effectively a no-op: ConnectRequests will be rejected
/// with `ConnectionTypeNotSupported`.
pub struct ConnectionManager<'a, const MAX_CONNECTIONS: usize = 4> {
    connections: [Option<ConnectionContext>; MAX_CONNECTIONS],
    handlers: Vec<(ConnectionType, ConnectionTypeHandlerEnum<'a>), 4>,
    heartbeat_timeout: Duration,
    next_channel_id: u8,
}

impl<'a, const MAX_CONNECTIONS: usize> ConnectionManager<'a, MAX_CONNECTIONS> {
    /// Create a new connection manager with no registered handlers.
    ///
    /// Without handlers, all ConnectRequests will be rejected. Use
    /// [`add_handler`](Self::add_handler) to register connection type handlers.
    pub fn new() -> Self {
        Self {
            connections: core::array::from_fn(|_| None),
            handlers: Vec::new(),
            heartbeat_timeout: Duration::from_secs(120),
            next_channel_id: 1,
        }
    }

    /// Register a handler for a connection type.
    pub fn add_handler(&mut self, connection_type: ConnectionType, handler: ConnectionTypeHandlerEnum<'a>) {
        let _ = self.handlers.push((connection_type, handler));
    }

    /// Handle an incoming KNX/IP message for a connection-oriented service.
    ///
    /// Connection lifecycle messages (Connect, Disconnect, Connectionstate) are
    /// handled directly. All other service types are routed to the appropriate
    /// [`ConnectionTypeHandler`] based on the connection's type, by peeking at
    /// the channel ID in the 4-byte connection header at offset 6.
    ///
    /// The `network_layer_tx` is used to inject cEMI frames into the stack when
    /// a handler returns [`DataFrameAction::AckAndInject`] (e.g., tunneling).
    pub async fn on_indication(
        &mut self,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        origin: PacketOrigin,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
        network_layer_tx: DynamicSender<'_, LayerOp<Buffer<'static>>>,
    ) -> Result<ConnectionManagerResult, ServerError> {
        match service_type {
            // Connection lifecycle — handled directly by the connection manager
            KNXnetIPServiceType::ConnectRequest => {
                self.handle_connect_request(data, origin, buffer_manager).await
            }
            KNXnetIPServiceType::ConnectionstateRequest => {
                self.handle_connectionstate_request(data, origin, buffer_manager).await
            }
            KNXnetIPServiceType::DisconnectRequest => {
                self.handle_disconnect_request(data, origin, buffer_manager).await
            }

            // Everything else: route to the handler via channel ID lookup
            _ => {
                let responses =
                    self.dispatch_to_handler(service_type, data, buffer_manager, network_layer_tx).await?;
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
        buffer_manager: &RefCell<DynBufferManager<'static>>,
        network_layer_tx: DynamicSender<'_, LayerOp<Buffer<'static>>>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        // Connection header starts at offset 6 (after KNXnet/IP header).
        // Byte layout: struct_length(1), channel_id(1), sequence_or_reserved(1), status_or_reserved(1)
        //
        // Return InvalidMessage (not ParseError) for short packets so the caller
        // can fall through to connectionless server dispatch.
        if data.len() < 6 + 4 {
            return Err(ServerError::InvalidMessage);
        }

        let channel_id = data[7]; // offset 6 + 1

        // Find the connection and its type
        let conn_idx =
            self.connections.iter().position(|slot| slot.as_ref().map_or(false, |ctx| ctx.channel_id == channel_id));

        let Some(conn_idx) = conn_idx else {
            debug!("Data frame for unknown channel {}, service {:?}", channel_id, service_type);
            return Err(ServerError::InvalidMessage);
        };

        let connection_type = self.connections[conn_idx].as_ref().expect("just verified Some").connection_type;

        // Find the handler for this connection type and verify it handles this service type
        let handler_idx = self.handlers.iter().position(|(ct, handler)| {
            *ct == connection_type && handler.handled_service_types().contains(&service_type)
        });

        let Some(handler_idx) = handler_idx else {
            // No handler recognizes this service type for the matched connection.
            // This likely means the channel ID "match" was spurious — the packet
            // is a connectionless message (e.g., DescriptionRequest) whose bytes
            // at the connection header offset happened to coincide with an active
            // channel ID. Return InvalidMessage to fall through to connectionless
            // server dispatch.
            debug!("No handler for service type {:?} on connection type {:?}", service_type, connection_type);
            return Err(ServerError::InvalidMessage);
        };

        // Determine if this is a data frame (request) or an ACK.
        // Convention: ACK service types are the request type + 1
        // (e.g., DeviceConfigurationRequest=0x0310, DeviceConfigurationAck=0x0311;
        //        TunnelingRequest=0x0420, TunnelingAck=0x0421).
        let service_type_raw: u16 = service_type.into();
        let is_ack = (service_type_raw & 0x01) != 0;

        if is_ack {
            // ACK: delegate to on_data_ack
            let conn = self.connections[conn_idx].as_mut().expect("just verified Some");
            self.handlers[handler_idx].1.on_data_ack(channel_id, data, conn)?;
            Ok(Vec::new())
        } else {
            // Data frame: delegate to on_data_frame
            let conn = self.connections[conn_idx].as_mut().expect("just verified Some");
            let action = self.handlers[handler_idx].1.on_data_frame(channel_id, data, conn, buffer_manager).await?;

            // Execute the action
            match action {
                DataFrameAction::Responses(responses) => Ok(responses),
                DataFrameAction::AckOnly(ack) => {
                    let mut responses = Vec::new();
                    let _ = responses.push(ack);
                    Ok(responses)
                }
                DataFrameAction::AckAndInject { ack, cemi_buffer } => {
                    // Convert cEMI buffer to internal format and inject into
                    // the network layer as an indication — same pattern as
                    // the routing server (routing.rs).
                    let cemi_msg: KnxMessageBuffer<Buffer<'static>, CemiFormat> =
                        KnxMessageBuffer::from_cemi(cemi_buffer);
                    let internal_msg = cemi_msg.into_internal();
                    let indication = IndicationMessage::indication(internal_msg);
                    network_layer_tx.send(LayerOp::Indication(indication)).await;

                    let mut responses = Vec::new();
                    let _ = responses.push(ack);
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
            if let Some(ctx) = slot {
                if now - ctx.last_activity > self.heartbeat_timeout {
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
                    if let Some((_, handler)) = self.handlers.iter_mut().find(|(ct, _)| *ct == connection_type) {
                        handler.close_connection(channel_id);
                    }

                    if let ConnectionTransport::Tcp { tcp_idx } = transport {
                        let _ = tcp_events.push(TcpChannelEvent::Removed { tcp_idx, channel_id });
                    }
                }
            }
        }

        tcp_events
    }

    /// Check if there are any active connections (used by main loop to
    /// decide whether to run the heartbeat timer).
    pub fn has_active_connections(&self) -> bool {
        self.connections.iter().any(|slot| slot.is_some())
    }

    /// Called when a TCP connection is closed (peer disconnect or I/O error).
    ///
    /// Tears down all KNX/IP connections that were running over this TCP
    /// stream. Per KNX spec 3/8/2 §8.4.3: when the TCP connection is
    /// closed, all inner KNX/IP connections are considered terminated.
    pub fn on_tcp_closed(&mut self, tcp_idx: usize) {
        for slot in &mut self.connections {
            let should_close = slot.as_ref().map_or(false, |ctx| {
                matches!(ctx.transport, ConnectionTransport::Tcp { tcp_idx: idx } if idx == tcp_idx)
            });

            if should_close {
                let ctx = slot.take().expect("just checked Some");
                info!("TCP connection {} closed, tearing down KNX/IP channel {}", tcp_idx, ctx.channel_id);

                if let Some((_, handler)) = self.handlers.iter_mut().find(|(ct, _)| *ct == ctx.connection_type) {
                    handler.close_connection(ctx.channel_id);
                }
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
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Result<ConnectionManagerResult, ServerError> {
        let mut buf = &data[..];
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

        // Find handler index for this connection type. We look up by index to
        // avoid holding a mutable borrow on self.handlers while also needing
        // self.connections and self.allocate_channel_id().
        let handler_idx = self.handlers.iter().position(|(ct, _)| *ct == cri_connection_type);

        let Some(handler_idx) = handler_idx else {
            debug!("No handler registered for connection type {:?}", cri_connection_type);
            return self
                .send_connect_response(
                    0,
                    ConnectionStatus::ConnectionTypeNotSupported,
                    None,
                    origin,
                    buffer_manager,
                )
                .await;
        };

        // Allocate a connection slot
        let slot_idx = self.connections.iter().position(|s| s.is_none());
        let Some(slot_idx) = slot_idx else {
            debug!("No more connection slots available");
            return self
                .send_connect_response(0, ConnectionStatus::NoMoreConnections, None, origin, buffer_manager)
                .await;
        };

        let channel_id = self.allocate_channel_id();

        // Ask the handler to accept
        let accepted = match self.handlers[handler_idx].1.accept_connection(channel_id, &request.cri) {
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
        let control_endpoint = self.resolve_endpoint(&request.control_endpoint, source);
        let data_endpoint = self.resolve_endpoint(&request.data_endpoint, source);

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
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Result<ConnectionManagerResult, ServerError> {
        let data_endpoint = match origin {
            PacketOrigin::Tcp { .. } => HPAI::ipv4_tcp(Ipv4Addr::UNSPECIFIED, 0),
            PacketOrigin::Udp { .. } => HPAI::ipv4_udp(Ipv4Addr::UNSPECIFIED, 0),
        };

        let builder = ConnectResponseBuilder::new(channel_id, status, data_endpoint, crd);
        let mut buffer = buffer_manager.borrow().alloc().await;
        buffer.serialize(&builder);

        let mut responses = Vec::new();
        let _ = responses.push(PendingResponse {
            buffer,
            target: origin.reply_target(),
        });
        Ok(ConnectionManagerResult::responses_only(responses))
    }

    // ========================================================================
    // Private: ConnectionstateRequest
    // ========================================================================

    async fn handle_connectionstate_request(
        &mut self,
        data: &[u8],
        origin: PacketOrigin,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Result<ConnectionManagerResult, ServerError> {
        let mut buf = &data[..];
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

        // Build response
        let builder = ConnectionstateResponseBuilder::new(channel_id, status);
        let mut buffer = buffer_manager.borrow().alloc().await;
        buffer.serialize(&builder);

        let mut responses = Vec::new();
        let _ = responses.push(PendingResponse { buffer, target });
        Ok(ConnectionManagerResult::responses_only(responses))
    }

    // ========================================================================
    // Private: DisconnectRequest
    // ========================================================================

    async fn handle_disconnect_request(
        &mut self,
        data: &[u8],
        origin: PacketOrigin,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Result<ConnectionManagerResult, ServerError> {
        let mut buf = &data[..];
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
                if let Some((_, handler)) = self.handlers.iter_mut().find(|(ct, _)| *ct == ctx.connection_type) {
                    handler.close_connection(channel_id);
                }

                let target = ctx.response_target();
                let tcp_event = match ctx.transport {
                    ConnectionTransport::Tcp { tcp_idx } => {
                        Some(TcpChannelEvent::Removed { tcp_idx, channel_id })
                    }
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

        // Build response
        let builder = DisconnectResponseBuilder::new(channel_id, status);
        let mut buffer = buffer_manager.borrow().alloc().await;
        buffer.serialize(&builder);

        let mut responses = Vec::new();
        let _ = responses.push(PendingResponse { buffer, target });

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
            if let Some(ctx) = slot {
                if ctx.channel_id == channel_id {
                    return slot.take();
                }
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

    /// Resolve an HPAI endpoint, applying NAT detection.
    ///
    /// Per KNX spec 3/8/2 §8.6.3.3: when a client sends an HPAI with
    /// IP address `0.0.0.0`, the server shall use the IP source address of the
    /// received request packet. The HPAI port is always used — only the IP
    /// address is substituted.
    fn resolve_endpoint(&self, hpai: &HPAI, packet_source: SocketAddrV4) -> SocketAddrV4 {
        let addr = hpai.address();
        if addr.is_unspecified() {
            SocketAddrV4::new(*packet_source.ip(), hpai.port())
        } else {
            SocketAddrV4::new(addr, hpai.port())
        }
    }
}
