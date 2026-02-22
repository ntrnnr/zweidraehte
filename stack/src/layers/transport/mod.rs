//! Transport Layer for KNX Stack
//!
//! The transport layer provides both connectionless and connection-oriented
//! communication services per KNX specification 03/03/04.
//!
//! # Connectionless Services
//!
//! These services are handled without maintaining connection state:
//! - `T_GroupData`: Multicast group communication via Address Table
//! - `T_Broadcast`: Domain-wide broadcast
//! - `T_SystemBroadcast`: System-wide broadcast
//! - `T_DataUnack`: Unacknowledged point-to-point (when supported)
//!
//! # Connection-Oriented Services
//!
//! These services maintain per-connection state with sequence numbers:
//! - `T_Connect`: Establish a connection
//! - `T_Disconnect`: Close a connection
//! - `T_Data`: Acknowledged point-to-point data transfer
//! - `T_Ack` / `T_Nack`: Acknowledgment handling
//!
//! # Architecture
//!
//! The transport layer uses a hybrid architecture:
//! - **State Machine**: Pure functions that process events and return actions
//! - **Connection Table**: Fixed-size storage for connection state
//! - **Global Timer**: Periodic scanning for timeout handling

// FIXME: do we want the connection timeout, ack timeout and max_repetitions to be configurable? Are there PIDs available for interface objects?

mod connection;
mod state_machine;

pub use connection::{Connection, ConnectionState, ConnectionTable};
pub use state_machine::{ActionBuffer, MAX_REPETITIONS, ProcessResult, TlAction, TlEvent, TlStyle, process_event};

use core::cell::RefCell;

use embassy_futures::select::{Either, select};
use embassy_sync::channel::DynamicSender;
use embassy_time::{Duration, Instant, Timer};

use crate::{
    AccessContext, StackDefinition, StackState,
    address::IndividualAddress,
    messages::{
        buffers::Buffer,
        builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage, RequestMessage},
        knx::{DestinationAddress, KnxMessageBuffer, Priority, ServiceType, Tpci},
    },
    objects::tables::{AddressTable, HasAddressTable, HasLoadStateMachine},
};

use super::{ActorRequest, Inbox, Layer, LayerOp};

// ============================================================================
// Configuration
// ============================================================================

/// Default ACK timeout in milliseconds (per KNX spec: 3 seconds)
pub const ACK_TIMEOUT_MS: u64 = 3000;

/// Default connection timeout in milliseconds (per KNX spec: 6 seconds)
pub const CONNECTION_TIMEOUT_MS: u64 = 6000;

/// Very far future instant for "no timeout" scenarios
fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(86400 * 365) // 1 year
}

/// Timeout type for distinguishing ACK vs connection timeouts
enum TimeoutType {
    Ack,
    Connection,
}

// ============================================================================
// Transport Layer
// ============================================================================

/// Transport layer for the KNX stack
///
/// Handles both connectionless and connection-oriented communication.
/// The connection table size is configurable via const generics.
///
/// # Type Parameters
/// - `D`: Stack definition providing table types
/// - `MAX_INCOMING`: Maximum number of incoming connections (default: 1)
/// - `MAX_OUTGOING`: Maximum number of outgoing connections (default: 0)
pub struct TransportLayer<'a, D: StackDefinition, const MAX_INCOMING: usize = 1, const MAX_OUTGOING: usize = 0> {
    /// Buffer manager for allocating messages
    buffer_manager: &'a RefCell<crate::messages::buffers::DynBufferManager<'static>>,
    /// Unified device state (contains tables and runtime state)
    state: &'a D::State,
    /// Channel to send messages to the network layer
    network_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
    /// Channel to send messages to the application layer
    application_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
    /// Connection table for stateful connections
    connections: ConnectionTable<MAX_INCOMING, MAX_OUTGOING>,
    /// State machine style (determines error recovery behavior)
    style: TlStyle,
}

impl<'a, D: StackDefinition, const MAX_INCOMING: usize, const MAX_OUTGOING: usize>
    TransportLayer<'a, D, MAX_INCOMING, MAX_OUTGOING>
{
    /// Create a new Transport Layer
    pub fn new(
        buffer_manager: &'a RefCell<crate::messages::buffers::DynBufferManager<'static>>,
        state: &'a D::State,
        network_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
        application_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
        style: TlStyle,
    ) -> Self {
        Self { buffer_manager, state, network_layer, application_layer, connections: ConnectionTable::new(), style }
    }
}

impl<'a, D: StackDefinition, const MAX_INCOMING: usize, const MAX_OUTGOING: usize>
    TransportLayer<'a, D, MAX_INCOMING, MAX_OUTGOING>
where
    D::State: HasAddressTable,
{
    // ========================================================================
    // Indication Handling (from Network Layer)
    // ========================================================================

    /// Handle an indication from the network layer
    async fn handle_indication(&mut self, mut msg: IndicationMessage<Buffer<'static>>) {
        debug!("TL indication: {:?}", msg);

        match msg.service_type() {
            // ─────────────────────────────────────────────────────────────────
            // Connectionless services
            // ─────────────────────────────────────────────────────────────────
            ServiceType::N_GroupData_Ind => {
                if let Some(Tpci::DataGroup) = msg.get_tpci()
                    && let DestinationAddress::Group(g) = msg.get_dest_addr()
                    && self.state.adt().borrow().is_loaded()
                    && let Some(conn_nr) = self.state.adt().borrow().get_tsap(g)
                {
                    msg.set_connection_nr(conn_nr);
                    msg.set_service_type(ServiceType::T_GroupData_Ind);
                    let default_level = self.state.default_access_level();
                    msg.set_access_ctx(AccessContext::new(default_level));
                    debug!("TL -> AL: {:?}", msg);
                    self.application_layer.send(LayerOp::Indication(msg)).await;
                }
            }

            ServiceType::N_Broadcast_Ind => {
                if let Some(Tpci::DataBroadcast) = msg.get_tpci() {
                    msg.set_service_type(ServiceType::T_Broadcast_Ind);
                    let default_level = self.state.default_access_level();
                    msg.set_access_ctx(AccessContext::new(default_level));
                    debug!("TL -> AL: {:?}", msg);
                    self.application_layer.send(LayerOp::Indication(msg)).await;
                }
            }

            ServiceType::N_SystemBroadcast_Ind => {
                if let Some(Tpci::DataSystemBroadcast) = msg.get_tpci() {
                    msg.set_service_type(ServiceType::T_SystemBroadcast_Ind);
                    let default_level = self.state.default_access_level();
                    msg.set_access_ctx(AccessContext::new(default_level));
                    debug!("TL -> AL: {:?}", msg);
                    self.application_layer.send(LayerOp::Indication(msg)).await;
                }
            }

            // ─────────────────────────────────────────────────────────────────
            // Connection-oriented services (point-to-point)
            // ─────────────────────────────────────────────────────────────────
            ServiceType::N_Data_Ind => {
                self.handle_connection_indication(msg).await;
            }

            _ => {
                warn!("TL unhandled indication: {:?}", msg.service_type());
            }
        }
    }

    /// Handle connection-oriented indications (N_Data_Ind)
    async fn handle_connection_indication(&mut self, mut msg: IndicationMessage<Buffer<'static>>) {
        use crate::messages::knx::offsets::MSG_TPCI;

        let tpci = match msg.get_tpci() {
            Some(t) => t,
            None => {
                warn!("Invalid TPCI in N_Data_Ind");
                return;
            }
        };

        let source = match msg.get_source_addr() {
            addr => addr,
        };

        trace!("TL connection from {}: TPCI={:?}", source, tpci);

        // Control packets (Connect, Disconnect, ACK, NACK) must have exactly 7 bytes
        // (CTRL + SRC[2] + DEST[2] + NPDU + TPCI, no additional data)
        // Malformed control packets with extra bytes must be ignored (KNX conformance test 2.5)
        const CONTROL_PACKET_LEN: usize = MSG_TPCI + 1; // 7 bytes

        // Create the appropriate event based on TPCI
        let event = match tpci {
            Tpci::Connect => {
                if msg.len() != CONTROL_PACKET_LEN {
                    warn!("TL ignoring malformed T_Connect (len={}, expected={})", msg.len(), CONTROL_PACKET_LEN);
                    return;
                }
                TlEvent::ReceivedConnect { source }
            }
            Tpci::Disconnect => {
                if msg.len() != CONTROL_PACKET_LEN {
                    warn!("TL ignoring malformed T_Disconnect (len={}, expected={})", msg.len(), CONTROL_PACKET_LEN);
                    return;
                }
                TlEvent::ReceivedDisconnect { source }
            }
            Tpci::Ack(seq_no) => {
                if msg.len() != CONTROL_PACKET_LEN {
                    warn!("TL ignoring malformed T_ACK (len={}, expected={})", msg.len(), CONTROL_PACKET_LEN);
                    return;
                }
                TlEvent::ReceivedAck { source, seq_no }
            }
            Tpci::Nack(seq_no) => {
                if msg.len() != CONTROL_PACKET_LEN {
                    warn!("TL ignoring malformed T_NACK (len={}, expected={})", msg.len(), CONTROL_PACKET_LEN);
                    return;
                }
                TlEvent::ReceivedNack { source, seq_no }
            }
            Tpci::DataConnected(seq_no) => TlEvent::ReceivedData { source, seq_no },
            Tpci::DataIndividual => {
                // Unnumbered individual data — forward to application.
                // Set the default access level since there's no connection
                // state to track authorization (connectionless = default key
                // level, same as a fresh connection).
                msg.set_service_type(ServiceType::T_DataUnack_Ind);
                let default_level = self.state.default_access_level();
                msg.set_access_ctx(AccessContext::new(default_level));
                self.application_layer.send(LayerOp::Indication(msg)).await;
                return;
            }
            _ => {
                warn!("TL unexpected TPCI for N_Data_Ind: {:?}", tpci);
                return;
            }
        };

        // For connect events, we need to allocate a connection slot
        let conn = if matches!(event, TlEvent::ReceivedConnect { .. }) {
            // Allocate new connection and set the default access level
            let mut conn = self.connections.allocate_incoming(source);
            if let Some(c) = conn.as_mut() {
                // Set access context to the default (first unset key level)
                let default_level = self.state.default_access_level();
                debug!("TL setting connection access level to {} (default)", default_level);
                c.access_ctx = AccessContext::new(default_level);
            }
            conn
        } else {
            self.connections.find_incoming(source)
        };

        let conn = match conn {
            Some(c) => c,
            None => {
                // No connection slot found
                // For T_Connect from a different source when already connected,
                // we need to reject it with T_Disconnect (KNX spec requirement)
                if matches!(event, TlEvent::ReceivedConnect { .. }) {
                    debug!("TL rejecting connection from {} - already connected", source);
                    self.send_disconnect(source).await;
                    return;
                }
                // Per KNX conformance tests (2.5.1), we should NOT send a T_Disconnect
                // when receiving data for a non-existent connection - just ignore it
                debug!("TL no connection slot for {} - ignoring", source);
                return;
            }
        };

        // Process the event through the state machine
        let result = process_event(conn, event, self.style);

        // Store the message if we need to forward data
        let msg_for_data = if matches!(event, TlEvent::ReceivedData { .. }) { Some(msg) } else { None };

        // Execute actions
        self.execute_actions(result, source, msg_for_data).await;
    }

    // ========================================================================
    // Request Handling (from Application Layer)
    // ========================================================================

    /// Handle a request from the application layer
    async fn handle_request(&mut self, msg: RequestMessage<Buffer<'static>>) -> ConfirmationMessage<Buffer<'static>> {
        debug!("TL request: {:?}", msg);

        // Extract inner message for processing
        let msg = msg.into_inner();

        match msg.service_type() {
            // ─────────────────────────────────────────────────────────────────
            // Connectionless requests
            // ─────────────────────────────────────────────────────────────────
            ServiceType::T_GroupData_Req => self.handle_group_data_request(msg).await,
            ServiceType::T_Broadcast_Req => self.handle_broadcast_request(msg).await,
            ServiceType::T_SystemBroadcast_Req => self.handle_system_broadcast_request(msg).await,

            // ─────────────────────────────────────────────────────────────────
            // Connectionless point-to-point (unacknowledged)
            // ─────────────────────────────────────────────────────────────────
            ServiceType::T_DataUnack_Req => self.handle_data_unack_request(msg).await,

            // ─────────────────────────────────────────────────────────────────
            // Connection-oriented requests
            // ─────────────────────────────────────────────────────────────────
            ServiceType::T_Connect_Req => self.handle_connect_request(msg).await,
            ServiceType::T_Disconnect_Req => self.handle_disconnect_request(msg).await,
            ServiceType::T_Data_Req => self.handle_data_request(msg).await,

            // ─────────────────────────────────────────────────────────────────
            // Unhandled
            // ─────────────────────────────────────────────────────────────────
            _ => {
                warn!("TL unhandled request: {:?}", msg.service_type());
                msg.error().build()
            }
        }
    }

    // ========================================================================
    // Connectionless Request Handlers
    // ========================================================================

    async fn handle_group_data_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> ConfirmationMessage<Buffer<'static>> {
        trace!("T_GroupData_Req: {:?}", msg);

        if self.state.adt().borrow().is_loaded()
            && let Some(dst_addr) = self.state.adt().borrow().get_address(msg.get_connection_nr())
        {
            trace!("TL conn_nr -> group addr: {}", dst_addr);
            let original_conn_nr = msg.get_connection_nr();

            msg.set_tpci(Tpci::DataGroup);
            msg.set_dest_addr(DestinationAddress::Group(dst_addr));
            msg.set_service_type(ServiceType::N_GroupData_Req);

            debug!("TL -> NL: {:?}", msg);
            let mut confirmation = self.network_layer.request(RequestMessage::request(msg)).await;

            confirmation.set_service_type(ServiceType::T_GroupData_Con);
            confirmation.set_connection_nr(original_conn_nr);
            confirmation
        } else {
            warn!("TL ADT not loaded or invalid conn_nr: {}", msg.get_connection_nr());
            msg.error().build()
        }
    }

    async fn handle_broadcast_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> ConfirmationMessage<Buffer<'static>> {
        msg.set_tpci(Tpci::DataBroadcast);
        msg.set_service_type(ServiceType::N_Broadcast_Req);
        debug!("TL -> NL: {:?}", msg);

        let mut confirmation = self.network_layer.request(RequestMessage::request(msg)).await;
        confirmation.set_service_type(ServiceType::T_Broadcast_Con);
        confirmation
    }

    async fn handle_system_broadcast_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> ConfirmationMessage<Buffer<'static>> {
        msg.set_tpci(Tpci::DataSystemBroadcast);
        msg.set_service_type(ServiceType::N_SystemBroadcast_Req);
        debug!("TL -> NL: {:?}", msg);

        let mut confirmation = self.network_layer.request(RequestMessage::request(msg)).await;
        confirmation.set_service_type(ServiceType::T_SystemBroadcast_Con);
        confirmation
    }

    async fn handle_data_unack_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> ConfirmationMessage<Buffer<'static>> {
        // Connectionless point-to-point data - no connection state needed
        msg.set_tpci(Tpci::DataIndividual);
        msg.set_service_type(ServiceType::N_Data_Req);
        debug!("TL -> NL (unack): {:?}", msg);

        let mut confirmation = self.network_layer.request(RequestMessage::request(msg)).await;
        confirmation.set_service_type(ServiceType::T_DataUnack_Con);
        confirmation
    }

    // ========================================================================
    // Connection-Oriented Request Handlers
    // ========================================================================

    async fn handle_connect_request(
        &mut self,
        msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> ConfirmationMessage<Buffer<'static>> {
        let dest = match msg.get_dest_addr() {
            DestinationAddress::Individual(addr) => addr,
            _ => return msg.error().build(),
        };

        // Allocate an outgoing connection
        let conn = match self.connections.allocate_outgoing(dest) {
            Some(c) => c,
            None => return msg.error().build(),
        };

        // Process connect request through state machine
        let actions = process_event(conn, TlEvent::RequestConnect { dest }, self.style);
        self.execute_actions(actions, dest, None).await;

        msg.confirm().build()
    }

    async fn handle_disconnect_request(
        &mut self,
        msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> ConfirmationMessage<Buffer<'static>> {
        let dest = match msg.get_dest_addr() {
            DestinationAddress::Individual(addr) => addr,
            _ => return msg.error().build(),
        };

        // Find the connection
        if let Some(conn) = self.connections.find_any(dest) {
            let actions = process_event(conn, TlEvent::RequestDisconnect { dest }, self.style);
            self.execute_actions(actions, dest, None).await;
        }

        msg.confirm().build()
    }

    async fn handle_data_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> ConfirmationMessage<Buffer<'static>> {
        let dest = match msg.get_dest_addr() {
            DestinationAddress::Individual(addr) => addr,
            _ => return msg.error().build(),
        };

        // Find the connection
        let conn = match self.connections.find_any(dest) {
            Some(c) => c,
            None => return msg.error().build(),
        };

        // Update connection's access context from the message if explicitly set
        // by the application layer (e.g., after A_Authorize_Response). Messages
        // that don't call set_access_level() have the UNSET sentinel, which we
        // skip to avoid overwriting the connection's current level.
        let msg_access_ctx = msg.access_ctx();
        if msg_access_ctx.is_set() {
            conn.access_ctx = msg_access_ctx;
        }

        let seq_no = conn.seq_no_send;
        let actions = process_event(conn, TlEvent::RequestData { dest }, self.style);

        // A11 (QueueEvent): The state machine says to defer this request
        // because we're in OPEN_WAIT. Store the message for later — it will
        // be sent when the pending message is acknowledged (A8 →
        // SendQueuedOutgoing).
        let should_queue = actions.actions.iter().any(|a| matches!(a, TlAction::QueueEvent { .. }));
        if should_queue {
            debug!("TL queuing outgoing data request to {} (A11, connection in OPEN_WAIT)", dest);
            if let Some(conn) = self.connections.find_any(dest) {
                conn.queued_outgoing = Some(msg);
            }
            // Execute remaining actions (state transition, timers)
            self.execute_actions_no_send(actions, dest).await;

            // Return a confirmation (the actual send will happen later).
            // Allocate a minimal buffer — the confirmation only needs enough
            // space for the CTRL1 field that .build() writes into.
            let confirm_buf = self.buffer_manager.borrow().alloc_with_size(7).await;
            let confirmation = KnxMessageBuffer::new(confirm_buf, ServiceType::T_Data_Req);
            return confirmation.confirm().build();
        }

        // Normal path: prepare and send the message immediately.
        msg.set_tpci(Tpci::DataConnected(seq_no));
        msg.set_dest_addr(DestinationAddress::Individual(dest));
        msg.set_service_type(ServiceType::N_Data_Req);

        // Store the original message for potential retransmission.
        // We keep the original buffer as pending_msg and send a copy.
        // This order is important to avoid deadlock: we first store the original,
        // then allocate a copy. If we tried to allocate while still holding
        // the original for sending, we could exhaust the buffer pool.
        let service_type = msg.service_type();
        if let Some(conn) = self.connections.find_any(dest) {
            conn.pending_msg = Some(msg);
        }

        // Now allocate a fresh buffer for sending (original is safely stored)
        let send_buffer = {
            let pending = self.connections.find_any(dest).and_then(|c| c.pending_msg.as_ref());
            if let Some(pm) = pending {
                self.buffer_manager.borrow().alloc_from_slice(&*pm.buf()).await
            } else {
                // Should not happen, but handle gracefully
                return KnxMessageBuffer::new(self.buffer_manager.borrow().alloc_with_size(0).await, service_type)
                    .error()
                    .build();
            }
        };
        let send_msg = KnxMessageBuffer::new(send_buffer, service_type);

        // Execute other actions (start timer, etc.)
        self.execute_actions_no_send(actions, dest).await;

        // Send the copy
        trace!("Transport layer sending data to Network layer: {:?}", send_msg);
        let mut confirmation = self.network_layer.request(RequestMessage::request(send_msg)).await;

        // We don't return confirmation immediately - we wait for ACK
        // For now, return immediate confirmation (TODO: proper async confirmation)
        confirmation.set_service_type(ServiceType::T_Data_Con);
        confirmation
    }

    // ========================================================================
    // Timeout Handling
    // ========================================================================

    /// Check for and handle all timeouts (ACK and connection)
    async fn check_timeouts(&mut self) {
        let now = Instant::now();

        // Process incoming connections
        loop {
            // Find the first timed-out incoming connection (either ACK or connection timeout)
            let timed_out = self.connections.incoming_mut().iter().enumerate().find_map(|(i, c)| {
                if c.is_ack_timed_out(now) {
                    Some((i, c.remote_addr, TimeoutType::Ack))
                } else if c.is_conn_timed_out(now) {
                    Some((i, c.remote_addr, TimeoutType::Connection))
                } else {
                    None
                }
            });

            match timed_out {
                Some((idx, addr, timeout_type)) => {
                    let conn = &mut self.connections.incoming_mut()[idx];
                    let event = match timeout_type {
                        TimeoutType::Ack => TlEvent::AckTimeout,
                        TimeoutType::Connection => TlEvent::ConnectionTimeout,
                    };
                    let actions = process_event(conn, event, self.style);
                    self.execute_actions(actions, addr, None).await;
                }
                None => break,
            }
        }

        // Same for outgoing connections
        loop {
            let timed_out = self.connections.outgoing_mut().iter().enumerate().find_map(|(i, c)| {
                if c.is_ack_timed_out(now) {
                    Some((i, c.remote_addr, TimeoutType::Ack))
                } else if c.is_conn_timed_out(now) {
                    Some((i, c.remote_addr, TimeoutType::Connection))
                } else {
                    None
                }
            });

            match timed_out {
                Some((idx, addr, timeout_type)) => {
                    let conn = &mut self.connections.outgoing_mut()[idx];
                    let event = match timeout_type {
                        TimeoutType::Ack => TlEvent::AckTimeout,
                        TimeoutType::Connection => TlEvent::ConnectionTimeout,
                    };
                    let actions = process_event(conn, event, self.style);
                    self.execute_actions(actions, addr, None).await;
                }
                None => break,
            }
        }
    }

    /// Get the next timeout deadline
    fn next_timeout_deadline(&self) -> Instant {
        self.connections.next_timeout_deadline().unwrap_or_else(far_future)
    }

    // ========================================================================
    // Action Execution
    // ========================================================================

    /// Execute actions returned by the state machine and apply the state
    /// transition.
    ///
    /// Actions are executed FIRST (while the connection is still in its
    /// pre-transition state), then the state transition is applied. This
    /// ordering is critical because action handlers look up connections by
    /// address, and connections in `Closed` state are filtered out of those
    /// lookups.
    ///
    /// Takes ownership of `msg_for_data` since it may need to be forwarded
    /// to the application layer.
    async fn execute_actions(
        &mut self,
        result: ProcessResult,
        remote_addr: IndividualAddress,
        mut msg_for_data: Option<IndicationMessage<Buffer<'static>>>,
    ) {
        for action in result.actions.iter() {
            match action {
                TlAction::SendConnect { dest } => {
                    self.send_connect(dest).await;
                }
                TlAction::SendDisconnect { dest } => {
                    self.send_disconnect(dest).await;
                }
                TlAction::SendAck { dest, seq_no } => {
                    self.send_ack(dest, seq_no).await;
                }
                TlAction::SendNack { dest, seq_no } => {
                    self.send_nack(dest, seq_no).await;
                }
                TlAction::IndicateConnected { source } => {
                    info!("TL connection established with {}", source);
                    // TODO: Send T_Connect.ind to application layer if needed
                }
                TlAction::IndicateDisconnected { source } => {
                    info!("TL connection closed with {}", source);
                    // TODO: Send T_Disconnect.ind to application layer if needed
                }
                TlAction::IndicateData { source: _ } => {
                    if let Some(mut msg) = msg_for_data.take() {
                        msg.set_service_type(ServiceType::T_Data_Ind);
                        // Set access context from connection state
                        if let Some(conn) = self.connections.find_any_including_closed(remote_addr) {
                            msg.set_access_ctx(conn.access_ctx);
                        }
                        self.application_layer.send(LayerOp::Indication(msg)).await;
                    }
                }
                TlAction::QueueEvent { source: _ } => {
                    // A11: Queue the current event for later processing.
                    //
                    // When triggered by incoming data (msg_for_data is Some): store
                    // the message for later delivery to the app layer.
                    //
                    // When triggered by an outgoing data request (E15): the actual
                    // queuing is handled by the caller (handle_data_request) which
                    // checks for this action before sending. Here msg_for_data is
                    // None so the block is a no-op.
                    if let Some(msg) = msg_for_data.take() {
                        if let Some(conn) = self.connections.find_any_including_closed(remote_addr) {
                            match self.buffer_manager.borrow().try_alloc_from_slice(&*msg.buf()) {
                                Some(queued_buffer) => {
                                    let queued_msg = KnxMessageBuffer::new(queued_buffer, msg.service_type());
                                    conn.queued_incoming = Some(queued_msg);
                                    debug!("TL queued incoming data from {} for later delivery", remote_addr);
                                }
                                None => {
                                    warn!("TL dropping incoming data from {} (no free buffers to queue)", remote_addr);
                                }
                            }
                        }
                    }
                }
                TlAction::DeliverQueuedData { source: _ } => {
                    // Deliver any queued incoming data to the application layer
                    if let Some(conn) = self.connections.find_any_including_closed(remote_addr) {
                        let access_ctx = conn.access_ctx;
                        if let Some(mut queued_msg) = conn.queued_incoming.take() {
                            queued_msg.set_service_type(ServiceType::T_Data_Ind);
                            queued_msg.set_access_ctx(access_ctx);
                            debug!("TL delivering queued data from {}", remote_addr);
                            self.application_layer
                                .send(LayerOp::Indication(IndicationMessage::indication(queued_msg)))
                                .await;
                        }
                    }
                }
                TlAction::ConfirmData { dest, success } => {
                    debug!("TL data confirmation for {}: {}", dest, success);
                    // TODO: Complete pending request with confirmation
                }
                TlAction::ConfirmConnect { dest, success } => {
                    debug!("TL connect confirmation for {}: {}", dest, success);
                }
                TlAction::ConfirmDisconnect { dest } => {
                    debug!("TL disconnect confirmation for {}", dest);
                    // TODO: Complete pending disconnect request with confirmation
                }
                TlAction::StartAckTimer => {
                    if let Some(conn) = self.connections.find_any_including_closed(remote_addr) {
                        let deadline = Instant::now() + Duration::from_millis(ACK_TIMEOUT_MS);
                        conn.start_ack_timeout(deadline);
                    }
                }
                TlAction::StopAckTimer => {
                    if let Some(conn) = self.connections.find_any_including_closed(remote_addr) {
                        conn.stop_ack_timeout();
                    }
                }
                TlAction::StartConnTimer => {
                    if let Some(conn) = self.connections.find_any_including_closed(remote_addr) {
                        let deadline = Instant::now() + Duration::from_millis(CONNECTION_TIMEOUT_MS);
                        conn.start_conn_timeout(deadline);
                    }
                }
                TlAction::StopConnTimer => {
                    if let Some(conn) = self.connections.find_any_including_closed(remote_addr) {
                        conn.stop_conn_timeout();
                    }
                }
                TlAction::Retransmit { dest } => {
                    debug!("TL retransmitting to {}", dest);
                    // Get the pending message from the connection and retransmit.
                    // Use try_alloc to avoid blocking — if no buffer is available,
                    // skip this retransmit; the ACK timeout will fire again.
                    if let Some(conn) = self.connections.find_any_including_closed(dest) {
                        if let Some(ref pending_msg) = conn.pending_msg {
                            match self.buffer_manager.borrow().try_alloc_from_slice(&*pending_msg.buf()) {
                                Some(retransmit_buffer) => {
                                    let retransmit_msg = KnxMessageBuffer::new(retransmit_buffer, pending_msg.service_type());
                                    debug!("TL retransmitting: {:?}", retransmit_msg);
                                    let _confirmation =
                                        self.network_layer.request(RequestMessage::request(retransmit_msg)).await;
                                }
                                None => {
                                    warn!("TL skipping retransmit to {} (no free buffers)", dest);
                                }
                            }
                        }
                    }
                }
                TlAction::StorePendingMessage => {
                    // Handled in the caller
                }
                TlAction::SendData { dest: _ } => {
                    // Handled in the caller (handle_data_request)
                }
                TlAction::ClearPendingMessage => {
                    // Clear the pending message to free the buffer
                    if let Some(conn) = self.connections.find_any_including_closed(remote_addr) {
                        if conn.pending_msg.take().is_some() {
                            debug!("TL cleared pending message for {}", remote_addr);
                        }
                    }
                }
            }
        }

        // Apply the deferred state transition AFTER all actions have executed.
        // Actions use find_any_including_closed() to locate the connection
        // regardless of its current state, since it may be transitioning from
        // Closed (new connection) or to Closed (disconnecting).
        result.apply_state_by_addr(&mut self.connections, remote_addr);

        // If there's queued outgoing data (deferred by A11 during OPEN_WAIT),
        // send it now that we're back in OPEN_IDLE. We perform A7 (store +
        // send data) inline rather than re-entering handle_data_request,
        // which would cause recursive async (needs boxing).
        if let Some(conn) = self.connections.find_any(remote_addr) {
            if conn.state == ConnectionState::OpenIdle && conn.queued_outgoing.is_some() {
                let mut msg = conn.queued_outgoing.take().expect("just checked is_some");
                debug!("TL sending queued outgoing data to {}", remote_addr);

                // A7: Store + send data with SeqNoSend; clear rep_count;
                // start ack timer; restart conn timer; → OPEN_WAIT
                let seq_no = conn.seq_no_send;
                conn.rep_count = 0;

                msg.set_tpci(Tpci::DataConnected(seq_no));
                msg.set_dest_addr(DestinationAddress::Individual(remote_addr));
                msg.set_service_type(ServiceType::N_Data_Req);
                conn.pending_msg = Some(msg);

                conn.start_ack_timeout(Instant::now() + Duration::from_millis(ACK_TIMEOUT_MS));
                conn.start_conn_timeout(Instant::now() + Duration::from_millis(CONNECTION_TIMEOUT_MS));
                conn.state = ConnectionState::OpenWait;

                // Send a copy (original stored for retransmission)
                if let Some(ref pending) = conn.pending_msg {
                    let send_buffer = self.buffer_manager.borrow().alloc_from_slice(&*pending.buf()).await;
                    let send_msg = KnxMessageBuffer::new(send_buffer, pending.service_type());
                    let _confirmation = self.network_layer.request(RequestMessage::request(send_msg)).await;
                }
            }
        }
    }

    /// Execute actions without handling data sending (for request handlers)
    async fn execute_actions_no_send(&mut self, result: ProcessResult, remote_addr: IndividualAddress) {
        self.execute_actions(result, remote_addr, None).await;
    }

    // ========================================================================
    // PDU Sending Helpers
    // ========================================================================

    /// Send a T_Connect PDU to establish a connection
    async fn send_connect(&mut self, dest: IndividualAddress) {
        use crate::messages::builder::MessageBuilder;

        // Control PDUs need only the basic header (7 bytes up to and including TPCI)
        const CONTROL_PDU_LEN: usize = 7;

        let msg_buf = self.buffer_manager.borrow().alloc_with_size(CONTROL_PDU_LEN).await;

        let msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::N_Data_Req,
            Priority::System,
            DestinationAddress::Individual(dest),
        )
        .with_transport_control(Tpci::Connect)
        .build();

        debug!("TL sending T_Connect to {}", dest);
        let _confirmation = self.network_layer.request(msg).await;
    }

    /// Send a T_Disconnect PDU to close a connection
    async fn send_disconnect(&mut self, dest: IndividualAddress) {
        use crate::messages::builder::MessageBuilder;

        const CONTROL_PDU_LEN: usize = 7;

        let msg_buf = self.buffer_manager.borrow().alloc_with_size(CONTROL_PDU_LEN).await;

        let msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::N_Data_Req,
            Priority::System,
            DestinationAddress::Individual(dest),
        )
        .with_transport_control(Tpci::Disconnect)
        .build();

        debug!("TL sending T_Disconnect to {}", dest);
        let _confirmation = self.network_layer.request(msg).await;
    }

    /// Send a T_ACK PDU to acknowledge received data
    async fn send_ack(&mut self, dest: IndividualAddress, seq_no: u8) {
        use crate::messages::builder::MessageBuilder;

        const CONTROL_PDU_LEN: usize = 7;

        let msg_buf = self.buffer_manager.borrow().alloc_with_size(CONTROL_PDU_LEN).await;

        let msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::N_Data_Req,
            Priority::System,
            DestinationAddress::Individual(dest),
        )
        .with_transport_control(Tpci::Ack(seq_no))
        .build();

        debug!("TL sending T_ACK({}) to {}", seq_no, dest);
        let _confirmation = self.network_layer.request(msg).await;
    }

    /// Send a T_NACK PDU to signal an error in received data
    async fn send_nack(&mut self, dest: IndividualAddress, seq_no: u8) {
        use crate::messages::builder::MessageBuilder;

        const CONTROL_PDU_LEN: usize = 7;

        let msg_buf = self.buffer_manager.borrow().alloc_with_size(CONTROL_PDU_LEN).await;

        let msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::N_Data_Req,
            Priority::System,
            DestinationAddress::Individual(dest),
        )
        .with_transport_control(Tpci::Nack(seq_no))
        .build();

        debug!("TL sending T_NACK({}) to {}", seq_no, dest);
        let _confirmation = self.network_layer.request(msg).await;
    }
}

// ============================================================================
// Layer Implementation
// ============================================================================

impl<'a, D: StackDefinition, const MAX_INCOMING: usize, const MAX_OUTGOING: usize> Layer<'a>
    for TransportLayer<'a, D, MAX_INCOMING, MAX_OUTGOING>
where
    D::State: HasAddressTable,
{
    type Buffer = Buffer<'static>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Buffer>>,
    {
        loop {
            // Calculate next timeout deadline
            let deadline = self.next_timeout_deadline();

            // Wait for either a message or timeout
            match select(inbox.next(), Timer::at(deadline)).await {
                Either::First(layer_op) => {
                    trace!("TL received: {:?}", layer_op);

                    match layer_op {
                        LayerOp::Indication(msg) => {
                            self.handle_indication(msg).await;
                        }
                        LayerOp::Request { message: msg, response_tx } => {
                            let response = self.handle_request(msg).await;
                            response_tx.send(response).await;
                        }
                    }
                }
                Either::Second(_) => {
                    // Timeout occurred - check for expired connections
                    self.check_timeouts().await;
                }
            }
        }
    }
}

// ============================================================================
// Backwards Compatibility (original simple layer without connections)
// ============================================================================

/// Alias for transport layer with single incoming connection (typical device)
pub type DeviceTransportLayer<'a, D> = TransportLayer<'a, D, 1, 0>;

/// Alias for connectionless-only transport layer
pub type ConnectionlessTransportLayer<'a, D> = TransportLayer<'a, D, 0, 0>;
