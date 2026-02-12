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

use core::cell::RefCell;
use core::net::{Ipv4Addr, SocketAddrV4};

use embassy_time::{Duration, Instant};
use heapless::Vec;

use embassy_sync::channel::DynamicSender;

use crate::layers::LayerOp;
use crate::messages::buffers::{Buffer, DynBufferManager, MessageBuffer};
use crate::messages::builder::IndicationMessage;
use crate::messages::knx::{CemiFormat, KnxMessageBuffer};
use crate::messages::knxip::{
    ConnectionStatus, ConnectionstateRequest, ConnectionstateResponseBuilder,
    DeviceConfigurationAck, DeviceConfigurationAckBuilder, DeviceConfigurationRequest,
    DeviceConfigurationRequestBuilder, DisconnectRequest, DisconnectResponseBuilder,
    KNXnetIPServiceType,
};
use crate::messages::knxip::substructs::{ConnectionType, HPAI};
use crate::objects::interface::PropertyServiceHandler;
use crate::util::packets::{ParseBuffer, SerializeBuffer};

use super::{PendingResponse, ServerError};

// ============================================================================
// Connection Type Handler Trait
// ============================================================================

/// Result of a successfully accepted connection.
pub struct AcceptedConnection {
    /// CRD bytes to include in the ConnectResponse.
    /// The handler serializes these — the connection manager treats them as opaque.
    pub crd_bytes: Vec<u8, 16>,
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
    AckAndInject {
        ack: PendingResponse,
        cemi_buffer: Buffer<'static>,
    },
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
    /// The handler inspects the CRI data and decides whether to accept
    /// (returning CRD bytes) or reject (returning an error status).
    fn accept_connection(
        &mut self,
        channel_id: u8,
        cri_data: &[u8],
    ) -> Result<AcceptedConnection, ConnectionStatus>;

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
    fn on_data_ack(
        &mut self,
        channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
    ) -> Result<(), ServerError>;

    /// Which service types this handler processes (both requests and ACKs).
    fn handled_service_types(&self) -> &[KNXnetIPServiceType];
}

// ============================================================================
// Device Management Connection Handler
// ============================================================================

/// cEMI Local Management message codes
mod cemi_local {
    pub const M_PROP_READ_REQ: u8 = 0xFC;
    pub const M_PROP_READ_CON: u8 = 0xFB;
    pub const M_PROP_WRITE_REQ: u8 = 0xF6;
    pub const M_PROP_WRITE_CON: u8 = 0xF5;
}

/// Handler for Device Management connections (ConnectionType 0x03).
///
/// Processes cEMI Local Management frames (M_PropRead/M_PropWrite) by
/// delegating to a [`PropertyServiceHandler`]. Uses a trait object reference
/// so that no generics leak out of this module.
pub struct DeviceMgmtConnectionHandler<'a> {
    property_handler: &'a dyn PropertyServiceHandler,
}

impl<'a> DeviceMgmtConnectionHandler<'a> {
    /// Create a new Device Management connection handler.
    pub fn new(property_handler: &'a dyn PropertyServiceHandler) -> Self {
        Self { property_handler }
    }

    /// Parse and process a cEMI Local Management frame, returning a response frame.
    ///
    /// Frame format:
    /// - Byte 0: message code (0xFC = M_PropRead.req, 0xF6 = M_PropWrite.req)
    /// - Bytes 1-2: object type (u16 big-endian)
    /// - Byte 3: object instance (1-based)
    /// - Byte 4: property ID
    /// - Bytes 5-6: count (4 bits) | start index (12 bits)
    /// - Bytes 7+: data (for writes)
    fn process_cemi_frame(&self, payload: &[u8]) -> Result<Vec<u8, 64>, ConnectionStatus> {
        if payload.len() < 7 {
            debug!("cEMI Local Management frame too short: {} bytes", payload.len());
            return Err(ConnectionStatus::DataConnectionError);
        }

        let message_code = payload[0];
        let _object_type = u16::from_be_bytes([payload[1], payload[2]]);
        let object_instance = payload[3];
        let property_id = payload[4];
        let count_start = u16::from_be_bytes([payload[5], payload[6]]);
        let count = (count_start >> 12) as u16;
        let start_index = count_start & 0x0FFF;

        // TODO: Proper object type → index translation. Currently uses
        // object_instance - 1 as the index, which works when each object
        // type has exactly one instance (the common case).
        let object_idx = if object_instance > 0 { (object_instance - 1) as u16 } else { 0 };

        match message_code {
            cemi_local::M_PROP_READ_REQ => {
                self.handle_prop_read(payload, object_idx, property_id, start_index, count)
            }
            cemi_local::M_PROP_WRITE_REQ => {
                self.handle_prop_write(payload, object_idx, property_id, start_index, count)
            }
            _ => {
                debug!("Unsupported cEMI Local Management message code: 0x{:02x}", message_code);
                Err(ConnectionStatus::DataConnectionError)
            }
        }
    }

    /// Build a DeviceConfigurationAck as a `PendingResponse`.
    async fn build_ack(
        &self,
        channel_id: u8,
        sequence_counter: u8,
        status: ConnectionStatus,
        conn: &ConnectionContext,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> PendingResponse {
        let builder = DeviceConfigurationAckBuilder::new(channel_id, sequence_counter, status);
        let mut buffer = buffer_manager.borrow().alloc().await;
        buffer.serialize(&builder);
        PendingResponse {
            buffer,
            destination: conn.data_endpoint,
            socket_idx: conn.socket_idx,
        }
    }

    fn handle_prop_read(
        &self,
        original: &[u8],
        object_idx: u16,
        property_id: u8,
        start_index: u16,
        count: u16,
    ) -> Result<Vec<u8, 64>, ConnectionStatus> {
        let mut response = Vec::<u8, 64>::new();

        // Response header: same structure but with M_PropRead.con message code
        let _ = response.push(cemi_local::M_PROP_READ_CON);
        let _ = response.extend_from_slice(&original[1..5]); // object type + instance + property ID

        // Read the property value into a temp buffer
        let mut data_buf = [0u8; 52]; // Leave room for the 7-byte header in the 64-byte response
        // Access level 0 = full access for ETS device management connections.
        // TODO: Revisit when secure tunneling is implemented.
        match self.property_handler.property_value_read(
            object_idx,
            property_id,
            start_index,
            count,
            &mut data_buf,
            0,
        ) {
            Ok(bytes_read) => {
                // Success: count + start index as requested
                let _ = response.extend_from_slice(&original[5..7]);
                let _ = response.extend_from_slice(&data_buf[..bytes_read]);
            }
            Err(_e) => {
                // Error: count=0 signals error, keep start index
                debug!(
                    "Property read error: obj={} pid={} start={}: {:?}",
                    object_idx, property_id, start_index, _e
                );
                let error_count_start = start_index; // count=0, keep start index
                let _ = response.extend_from_slice(&error_count_start.to_be_bytes());
            }
        }

        Ok(response)
    }

    fn handle_prop_write(
        &self,
        original: &[u8],
        object_idx: u16,
        property_id: u8,
        start_index: u16,
        _count: u16,
    ) -> Result<Vec<u8, 64>, ConnectionStatus> {
        let write_data = &original[7..];

        let mut response = Vec::<u8, 64>::new();

        // Response header: M_PropWrite.con message code
        let _ = response.push(cemi_local::M_PROP_WRITE_CON);
        let _ = response.extend_from_slice(&original[1..5]); // object type + instance + property ID

        match self.property_handler.property_value_write(
            object_idx,
            property_id,
            start_index,
            write_data,
            0,
        ) {
            Ok(_write_response) => {
                // Success: echo back the count + start index and the written data
                let _ = response.extend_from_slice(&original[5..7]);
                let _ = response.extend_from_slice(write_data);
            }
            Err(_e) => {
                // Error: count=0 signals error
                debug!(
                    "Property write error: obj={} pid={} start={}: {:?}",
                    object_idx, property_id, start_index, _e
                );
                let error_count_start = start_index; // count=0, keep start index
                let _ = response.extend_from_slice(&error_count_start.to_be_bytes());
            }
        }

        Ok(response)
    }
}

impl ConnectionTypeHandler for DeviceMgmtConnectionHandler<'_> {
    fn accept_connection(
        &mut self,
        _channel_id: u8,
        _cri_data: &[u8],
    ) -> Result<AcceptedConnection, ConnectionStatus> {
        // Device Management CRI has no additional fields beyond the header.
        // Accept unconditionally — the connection manager enforces max connections.
        //
        // CRD is just the 2-byte header: struct_len=0x02, struct_type=0x03
        let mut crd_bytes = Vec::new();
        let _ = crd_bytes.push(0x02); // struct_len
        let _ = crd_bytes.push(ConnectionType::DeviceManagement.into()); // struct_type
        Ok(AcceptedConnection { crd_bytes })
    }

    fn close_connection(&mut self, _channel_id: u8) {
        // No per-connection resources to release for device management
    }

    async fn on_data_frame(
        &mut self,
        _channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Result<DataFrameAction, ServerError> {
        // Parse the DeviceConfigurationRequest header
        let mut buf = &data[..];
        let request = match buf.parse::<DeviceConfigurationRequest>() {
            Ok(req) => req,
            Err(_) => return Err(ServerError::ParseError),
        };

        let sequence_counter = request.sequence_counter;
        let expected_seq = conn.recv_sequence_counter;

        // Validate sequence counter
        let is_retransmission = sequence_counter == expected_seq.wrapping_sub(1);
        let is_expected = sequence_counter == expected_seq;

        if !is_expected && !is_retransmission {
            debug!(
                "Sequence counter mismatch: got {}, expected {} (channel {})",
                sequence_counter, expected_seq, conn.channel_id
            );
            let ack = self.build_ack(
                conn.channel_id, sequence_counter,
                ConnectionStatus::DataConnectionError,
                conn, buffer_manager,
            ).await;
            return Ok(DataFrameAction::AckOnly(ack));
        }

        // Extract cEMI payload: everything after KNXnet/IP header (6) + connection header (4)
        let cemi_offset = 6 + 4;
        let cemi_payload = if data.len() > cemi_offset { &data[cemi_offset..] } else { &[] };

        // Process the frame (only if not a retransmission)
        let response_cemi = if is_expected {
            conn.recv_sequence_counter = expected_seq.wrapping_add(1);
            conn.last_activity = Instant::now();

            match self.process_cemi_frame(cemi_payload) {
                Ok(response) => Some(response),
                Err(status) => {
                    let ack = self.build_ack(
                        conn.channel_id, sequence_counter, status,
                        conn, buffer_manager,
                    ).await;
                    return Ok(DataFrameAction::AckOnly(ack));
                }
            }
        } else {
            // Retransmission: just re-ACK, don't re-process
            None
        };

        // Build responses
        let mut responses = Vec::new();

        // 1. ACK
        let ack_builder = DeviceConfigurationAckBuilder::new(
            conn.channel_id, sequence_counter, ConnectionStatus::NoError,
        );
        let mut ack_buffer = buffer_manager.borrow().alloc().await;
        ack_buffer.serialize(&ack_builder);
        let _ = responses.push(PendingResponse {
            buffer: ack_buffer,
            destination: conn.data_endpoint,
            socket_idx: conn.socket_idx,
        });

        // 2. If handler returned a response, send it as a DeviceConfigurationRequest
        //    (server → client direction)
        if let Some(cemi_response) = response_cemi {
            let send_seq = conn.send_sequence_counter;
            conn.send_sequence_counter = send_seq.wrapping_add(1);

            let req_builder = DeviceConfigurationRequestBuilder::new(
                conn.channel_id, send_seq,
            );

            let mut resp_buffer = buffer_manager.borrow().alloc().await;
            resp_buffer.serialize(&req_builder);
            let header_len = resp_buffer.len();
            let total_len = header_len + cemi_response.len();

            // Append cEMI payload after the header
            let buf = resp_buffer.as_mut();
            buf[header_len..total_len].copy_from_slice(&cemi_response);

            // Patch total_length in the KNXnet/IP header (bytes 4-5)
            let total_bytes = (total_len as u16).to_be_bytes();
            buf[4] = total_bytes[0];
            buf[5] = total_bytes[1];

            resp_buffer.set_len(total_len);

            let _ = responses.push(PendingResponse {
                buffer: resp_buffer,
                destination: conn.data_endpoint,
                socket_idx: conn.socket_idx,
            });
        }

        Ok(DataFrameAction::Responses(responses))
    }

    fn on_data_ack(
        &mut self,
        _channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
    ) -> Result<(), ServerError> {
        let mut buf = &data[..];
        let ack = match buf.parse::<DeviceConfigurationAck>() {
            Ok(a) => a,
            Err(_) => return Err(ServerError::ParseError),
        };

        conn.last_activity = Instant::now();
        // TODO: Implement retransmission tracking — verify this ACK matches
        // our last sent sequence number, and handle timeout/retransmission
        // if the ACK doesn't arrive.
        trace!(
            "DeviceConfigurationAck: channel={}, seq={}, status={:?}",
            ack.communication_channel_id, ack.sequence_counter, ack.status
        );
        Ok(())
    }

    fn handled_service_types(&self) -> &[KNXnetIPServiceType] {
        &[
            KNXnetIPServiceType::DeviceConfigurationRequest,
            KNXnetIPServiceType::DeviceConfigurationAck,
        ]
    }
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
    fn accept_connection(
        &mut self,
        channel_id: u8,
        cri_data: &[u8],
    ) -> Result<AcceptedConnection, ConnectionStatus> {
        match self {
            ConnectionTypeHandlerEnum::DeviceManagement(h) => h.accept_connection(channel_id, cri_data),
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

    fn on_data_ack(
        &mut self,
        channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
    ) -> Result<(), ServerError> {
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
pub struct ConnectionManager<
    'a,
    const MAX_CONNECTIONS: usize = 4,
> {
    connections: [Option<ConnectionContext>; MAX_CONNECTIONS],
    handlers: Vec<(ConnectionType, ConnectionTypeHandlerEnum<'a>), 4>,
    heartbeat_timeout: Duration,
    next_channel_id: u8,
}

impl<'a, const MAX_CONNECTIONS: usize>
    ConnectionManager<'a, MAX_CONNECTIONS>
{
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
    pub fn add_handler(
        &mut self,
        connection_type: ConnectionType,
        handler: ConnectionTypeHandlerEnum<'a>,
    ) {
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
        source: SocketAddrV4,
        socket_idx: usize,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
        network_layer_tx: DynamicSender<'_, LayerOp<Buffer<'static>>>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        match service_type {
            // Connection lifecycle — handled directly by the connection manager
            KNXnetIPServiceType::ConnectRequest => {
                self.handle_connect_request(data, source, socket_idx, buffer_manager).await
            }
            KNXnetIPServiceType::ConnectionstateRequest => {
                self.handle_connectionstate_request(data, buffer_manager).await
            }
            KNXnetIPServiceType::DisconnectRequest => {
                self.handle_disconnect_request(data, buffer_manager).await
            }

            // Everything else: route to the handler via channel ID lookup
            _ => {
                self.dispatch_to_handler(service_type, data, buffer_manager, network_layer_tx).await
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
        let conn_idx = self.connections.iter().position(|slot| {
            slot.as_ref().map_or(false, |ctx| ctx.channel_id == channel_id)
        });

        let Some(conn_idx) = conn_idx else {
            debug!("Data frame for unknown channel {}, service {:?}", channel_id, service_type);
            return Err(ServerError::InvalidMessage);
        };

        let connection_type = self.connections[conn_idx]
            .as_ref()
            .expect("just verified Some")
            .connection_type;

        // Find the handler for this connection type and verify it handles this service type
        let handler_idx = self.handlers.iter().position(|(ct, handler)| {
            *ct == connection_type && handler.handled_service_types().contains(&service_type)
        });

        let Some(handler_idx) = handler_idx else {
            debug!(
                "No handler for service type {:?} on connection type {:?}",
                service_type, connection_type
            );
            return Ok(Vec::new());
        };

        // Determine if this is a data frame (request) or an ACK.
        // Convention: ACK service types are the request type + 1
        // (e.g., DeviceConfigurationRequest=0x0310, DeviceConfigurationAck=0x0311;
        //        TunnelingRequest=0x0420, TunnelingAck=0x0421).
        let service_type_raw: u16 = service_type.into();
        let is_ack = (service_type_raw & 0x01) != 0;

        if is_ack {
            // ACK: delegate to on_data_ack
            let conn = self.connections[conn_idx]
                .as_mut()
                .expect("just verified Some");
            self.handlers[handler_idx].1.on_data_ack(channel_id, data, conn)?;
            Ok(Vec::new())
        } else {
            // Data frame: delegate to on_data_frame
            let conn = self.connections[conn_idx]
                .as_mut()
                .expect("just verified Some");
            let action = self.handlers[handler_idx]
                .1
                .on_data_frame(channel_id, data, conn, buffer_manager)
                .await?;

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
    pub fn on_tick(&mut self) {
        let now = Instant::now();

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
                    *slot = None;

                    // Notify the handler
                    if let Some((_, handler)) = self
                        .handlers
                        .iter_mut()
                        .find(|(ct, _)| *ct == connection_type)
                    {
                        handler.close_connection(channel_id);
                    }
                }
            }
        }
    }

    /// Check if there are any active connections (used by main loop to
    /// decide whether to run the heartbeat timer).
    pub fn has_active_connections(&self) -> bool {
        self.connections.iter().any(|slot| slot.is_some())
    }

    // ========================================================================
    // Private: ConnectRequest
    // ========================================================================

    async fn handle_connect_request(
        &mut self,
        data: &[u8],
        source: SocketAddrV4,
        socket_idx: usize,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        // We need to parse the ConnectRequest manually since the existing parser
        // hardcodes TunnelingCRI. We parse:
        //   - KNXnet/IP header (6 bytes)
        //   - Control HPAI (8 bytes)
        //   - Data HPAI (8 bytes)
        //   - CRI (variable — first 2 bytes are header with connection type)

        if data.len() < 6 + 8 + 8 + 2 {
            debug!("ConnectRequest too short: {} bytes", data.len());
            return self.send_connect_error(
                0, ConnectionStatus::DataConnectionError,
                source, socket_idx, buffer_manager,
            ).await;
        }

        let knxip_header_len = 6;
        let remaining = &data[knxip_header_len..];

        // Parse control HPAI (8 bytes)
        let mut buf = remaining;
        let control_hpai = match buf.parse::<HPAI>() {
            Ok(hpai) => hpai,
            Err(_) => {
                return self.send_connect_error(
                    0, ConnectionStatus::DataConnectionError,
                    source, socket_idx, buffer_manager,
                ).await;
            }
        };

        // Parse data HPAI (8 bytes)
        let mut buf2 = &remaining[8..];
        let data_hpai = match buf2.parse::<HPAI>() {
            Ok(hpai) => hpai,
            Err(_) => {
                return self.send_connect_error(
                    0, ConnectionStatus::DataConnectionError,
                    source, socket_idx, buffer_manager,
                ).await;
            }
        };

        // CRI starts after the two HPAIs
        let cri_offset = 8 + 8; // two HPAIs
        let cri_data = &remaining[cri_offset..];

        if cri_data.len() < 2 {
            return self.send_connect_error(
                0, ConnectionStatus::ConnectionTypeNotSupported,
                source, socket_idx, buffer_manager,
            ).await;
        }

        let cri_connection_type: ConnectionType = cri_data[1].into();

        // Find handler index for this connection type. We look up by index to
        // avoid holding a mutable borrow on self.handlers while also needing
        // self.connections and self.allocate_channel_id().
        let handler_idx = self
            .handlers
            .iter()
            .position(|(ct, _)| *ct == cri_connection_type);

        let Some(handler_idx) = handler_idx else {
            debug!("No handler registered for connection type {:?}", cri_connection_type);
            return self.send_connect_error(
                0, ConnectionStatus::ConnectionTypeNotSupported,
                source, socket_idx, buffer_manager,
            ).await;
        };

        // Allocate a connection slot
        let slot_idx = self.connections.iter().position(|s| s.is_none());
        let Some(slot_idx) = slot_idx else {
            debug!("No more connection slots available");
            return self.send_connect_error(
                0, ConnectionStatus::NoMoreConnections,
                source, socket_idx, buffer_manager,
            ).await;
        };

        let channel_id = self.allocate_channel_id();

        // Ask the handler to accept
        let accepted = match self.handlers[handler_idx].1.accept_connection(channel_id, &cri_data[2..]) {
            Ok(accepted) => accepted,
            Err(status) => {
                return self.send_connect_error(
                    channel_id, status,
                    source, socket_idx, buffer_manager,
                ).await;
            }
        };

        // NAT detection: if HPAI is 0.0.0.0:0, use packet source address
        let control_endpoint = self.resolve_endpoint(&control_hpai, source);
        let data_endpoint = self.resolve_endpoint(&data_hpai, source);

        info!(
            "Accepting {:?} connection: channel_id={}, control={}, data={}",
            cri_connection_type, channel_id, control_endpoint, data_endpoint
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
        });

        // Build ConnectResponse with success
        // We need to build a raw response since ConnectResponseBuilder expects
        // TunnelingCRDBuilder, but we have raw CRD bytes from the handler.
        self.build_connect_response(
            channel_id,
            ConnectionStatus::NoError,
            &accepted.crd_bytes,
            control_endpoint,
            socket_idx,
            buffer_manager,
        ).await
    }

    async fn send_connect_error(
        &self,
        channel_id: u8,
        status: ConnectionStatus,
        destination: SocketAddrV4,
        socket_idx: usize,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        // Error ConnectResponse: just header + status, no HPAI/CRD needed
        self.build_connect_response(
            channel_id,
            status,
            &[],
            destination,
            socket_idx,
            buffer_manager,
        ).await
    }

    /// Build a ConnectResponse manually.
    ///
    /// We build this by hand instead of using `ConnectResponseBuilder` because
    /// that builder is hardcoded to `TunnelingCRDBuilder`. Our CRD comes as
    /// raw bytes from the connection type handler.
    async fn build_connect_response(
        &self,
        channel_id: u8,
        status: ConnectionStatus,
        crd_bytes: &[u8],
        destination: SocketAddrV4,
        socket_idx: usize,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        let mut buffer = buffer_manager.borrow().alloc().await;

        // Build the response frame:
        //   KNXnet/IP header (6 bytes)
        //   channel_id (1 byte) + status (1 byte)
        //   data HPAI (8 bytes) — only if success
        //   CRD bytes — only if success

        let is_success = status == ConnectionStatus::NoError;
        let hpai_len = if is_success { 8 } else { 0 };
        let total_len: u16 = 6 + 2 + hpai_len + crd_bytes.len() as u16;

        let buf = buffer.as_mut();
        let mut offset = 0;

        // KNXnet/IP header
        buf[offset] = 0x06; // header size
        offset += 1;
        buf[offset] = 0x10; // version 1.0
        offset += 1;
        let service_bytes = u16::from(KNXnetIPServiceType::ConnectResponse).to_be_bytes();
        buf[offset..offset + 2].copy_from_slice(&service_bytes);
        offset += 2;
        buf[offset..offset + 2].copy_from_slice(&total_len.to_be_bytes());
        offset += 2;

        // Channel ID + status
        buf[offset] = channel_id;
        offset += 1;
        buf[offset] = status.into();
        offset += 1;

        if is_success {
            // Data HPAI — we use 0.0.0.0:0 to let the client use the packet source
            // (same NAT-friendly pattern)
            buf[offset] = 0x08; // HPAI struct len
            offset += 1;
            buf[offset] = 0x01; // IPv4 UDP
            offset += 1;
            buf[offset..offset + 4].copy_from_slice(&[0, 0, 0, 0]); // address
            offset += 4;
            buf[offset..offset + 2].copy_from_slice(&[0, 0]); // port
            offset += 2;

            // CRD
            buf[offset..offset + crd_bytes.len()].copy_from_slice(crd_bytes);
            offset += crd_bytes.len();
        }

        buffer.set_len(offset);

        let mut responses = Vec::new();
        let _ = responses.push(PendingResponse {
            buffer,
            destination,
            socket_idx,
        });
        Ok(responses)
    }

    // ========================================================================
    // Private: ConnectionstateRequest
    // ========================================================================

    async fn handle_connectionstate_request(
        &mut self,
        data: &[u8],
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        let mut buf = &data[..];
        let request = match buf.parse::<ConnectionstateRequest>() {
            Ok(req) => req,
            Err(_) => return Err(ServerError::ParseError),
        };

        let channel_id = request.communication_channel_id;

        // Find the connection
        let (status, destination, socket_idx) = match self.find_connection_mut(channel_id) {
            Some(ctx) => {
                ctx.last_activity = Instant::now();
                (ConnectionStatus::NoError, ctx.control_endpoint, ctx.socket_idx)
            }
            None => {
                debug!("Connectionstate request for unknown channel {}", channel_id);
                // We still need to respond — use the HPAI from the request
                let dest = SocketAddrV4::new(
                    request.control_endpoint.address(),
                    request.control_endpoint.port(),
                );
                (ConnectionStatus::NoSuchConnectionID, dest, 0)
            }
        };

        // Build response
        let builder = ConnectionstateResponseBuilder::new(channel_id, status);
        let mut buffer = buffer_manager.borrow().alloc().await;
        buffer.serialize(&builder);

        let mut responses = Vec::new();
        let _ = responses.push(PendingResponse {
            buffer,
            destination,
            socket_idx,
        });
        Ok(responses)
    }

    // ========================================================================
    // Private: DisconnectRequest
    // ========================================================================

    async fn handle_disconnect_request(
        &mut self,
        data: &[u8],
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        let mut buf = &data[..];
        let request = match buf.parse::<DisconnectRequest>() {
            Ok(req) => req,
            Err(_) => return Err(ServerError::ParseError),
        };

        let channel_id = request.communication_channel_id;

        // Find and remove the connection
        let (status, destination, socket_idx) = match self.remove_connection(channel_id) {
            Some(ctx) => {
                info!("Disconnecting channel {}", channel_id);

                // Notify the handler
                if let Some((_, handler)) = self
                    .handlers
                    .iter_mut()
                    .find(|(ct, _)| *ct == ctx.connection_type)
                {
                    handler.close_connection(channel_id);
                }

                (ConnectionStatus::NoError, ctx.control_endpoint, ctx.socket_idx)
            }
            None => {
                // Idempotent: respond with NoError even if not found
                debug!("Disconnect request for unknown channel {}", channel_id);
                let dest = SocketAddrV4::new(
                    request.control_endpoint.address(),
                    request.control_endpoint.port(),
                );
                (ConnectionStatus::NoError, dest, 0)
            }
        };

        // Build response
        let builder = DisconnectResponseBuilder::new(channel_id, status);
        let mut buffer = buffer_manager.borrow().alloc().await;
        buffer.serialize(&builder);

        let mut responses = Vec::new();
        let _ = responses.push(PendingResponse {
            buffer,
            destination,
            socket_idx,
        });
        Ok(responses)
    }

    // ========================================================================
    // Private: Helpers
    // ========================================================================

    fn find_connection_mut(&mut self, channel_id: u8) -> Option<&mut ConnectionContext> {
        self.connections
            .iter_mut()
            .filter_map(|slot| slot.as_mut())
            .find(|ctx| ctx.channel_id == channel_id)
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
    /// Per KNX spec: if the HPAI address is 0.0.0.0:0, the server should use
    /// the UDP packet source address instead (the client is behind NAT).
    fn resolve_endpoint(&self, hpai: &HPAI, packet_source: SocketAddrV4) -> SocketAddrV4 {
        let addr = hpai.address();
        let port = hpai.port();

        if addr == Ipv4Addr::UNSPECIFIED && port == 0 {
            packet_source
        } else {
            SocketAddrV4::new(addr, port)
        }
    }
}
