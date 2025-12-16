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

mod connection;
mod state_machine;

pub use connection::{Connection, ConnectionState, ConnectionTable};
pub use state_machine::{ActionBuffer, MAX_REPETITIONS, TlAction, TlEvent, process_event};

use core::cell::RefCell;

use embassy_futures::select::{Either, select};
use embassy_sync::channel::DynamicSender;
use embassy_time::{Duration, Instant, Timer};

use crate::{
    StackDefinition,
    address::IndividualAddress,
    messages::{
        buffers::Buffer,
        knx::{Confirm, DestinationAddress, KnxMessageBuffer, ServiceType, Tpci},
    },
    objects::tables::{AddressTable, LoadableTable},
};

use super::{ActorRequest, Inbox, Layer, LayerOp};

// ============================================================================
// Configuration
// ============================================================================

/// Default ACK timeout in milliseconds (per KNX spec: 3 seconds)
pub const ACK_TIMEOUT_MS: u64 = 3000;

/// Very far future instant for "no timeout" scenarios
fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(86400 * 365) // 1 year
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
    /// Address table for group address ↔ TSAP mapping
    adt: &'a RefCell<D::ADT>,
    /// Channel to send messages to the network layer
    network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    /// Channel to send messages to the application layer
    application_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    /// Connection table for stateful connections
    connections: ConnectionTable<MAX_INCOMING, MAX_OUTGOING>,
}

impl<'a, D: StackDefinition, const MAX_INCOMING: usize, const MAX_OUTGOING: usize>
    TransportLayer<'a, D, MAX_INCOMING, MAX_OUTGOING>
{
    /// Create a new Transport Layer
    pub fn new(
        adt: &'a RefCell<D::ADT>,
        network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
        application_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    ) -> Self {
        Self { adt, network_layer, application_layer, connections: ConnectionTable::new() }
    }

    // ========================================================================
    // Indication Handling (from Network Layer)
    // ========================================================================

    /// Handle an indication from the network layer
    async fn handle_indication(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
        debug!("TL indication: {:?}", msg);

        match msg.service_type() {
            // ─────────────────────────────────────────────────────────────────
            // Connectionless services
            // ─────────────────────────────────────────────────────────────────
            ServiceType::N_GroupData_Ind => {
                if let Some(Tpci::DataGroup) = msg.get_tpci()
                    && let DestinationAddress::Group(g) = msg.get_dest_addr()
                    && self.adt.borrow().is_loaded()
                    && let Some(conn_nr) = self.adt.borrow().get_tsap(g)
                {
                    msg.set_connection_nr(conn_nr);
                    msg.set_service_type(ServiceType::T_GroupData_Ind);
                    debug!("TL -> AL: {:x?}", msg);
                    self.application_layer.send(LayerOp::Indication(msg)).await;
                }
            }

            ServiceType::N_Broadcast_Ind => {
                if let Some(Tpci::DataBroadcast) = msg.get_tpci() {
                    msg.set_service_type(ServiceType::T_Broadcast_Ind);
                    debug!("TL -> AL: {:x?}", msg);
                    self.application_layer.send(LayerOp::Indication(msg)).await;
                }
            }

            ServiceType::N_SystemBroadcast_Ind => {
                if let Some(Tpci::DataSystemBroadcast) = msg.get_tpci() {
                    msg.set_service_type(ServiceType::T_SystemBroadcast_Ind);
                    debug!("TL -> AL: {:x?}", msg);
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
    async fn handle_connection_indication(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
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

        // Create the appropriate event based on TPCI
        let event = match tpci {
            Tpci::Connect => TlEvent::ReceivedConnect { source },
            Tpci::Disconnect => TlEvent::ReceivedDisconnect { source },
            Tpci::DataConnected(seq_no) => TlEvent::ReceivedData { source, seq_no },
            Tpci::Ack(seq_no) => TlEvent::ReceivedAck { source, seq_no },
            Tpci::Nack(seq_no) => TlEvent::ReceivedNack { source, seq_no },
            Tpci::DataIndividual => {
                // Unnumbered individual data - forward to application
                msg.set_service_type(ServiceType::T_DataUnack_Ind);
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
            self.connections.allocate_incoming(source)
        } else {
            self.connections.find_incoming(source)
        };

        let conn = match conn {
            Some(c) => c,
            None => {
                debug!("TL no connection slot for {}", source);
                // If we received data for a non-existent connection, send disconnect
                if matches!(event, TlEvent::ReceivedData { .. }) {
                    self.send_disconnect(source).await;
                }
                return;
            }
        };

        // Process the event through the state machine
        let actions = process_event(conn, event);

        // Store the message if we need to forward data
        let msg_for_data = if matches!(event, TlEvent::ReceivedData { .. }) { Some(msg) } else { None };

        // Execute actions
        self.execute_actions(actions, source, msg_for_data).await;
    }

    // ========================================================================
    // Request Handling (from Application Layer)
    // ========================================================================

    /// Handle a request from the application layer
    async fn handle_request(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) -> KnxMessageBuffer<Buffer<'static>> {
        debug!("TL request: {:?}", msg);

        match msg.service_type() {
            // ─────────────────────────────────────────────────────────────────
            // Connectionless requests
            // ─────────────────────────────────────────────────────────────────
            ServiceType::T_GroupData_Req => self.handle_group_data_request(msg).await,
            ServiceType::T_Broadcast_Req => self.handle_broadcast_request(msg).await,
            ServiceType::T_SystemBroadcast_Req => self.handle_system_broadcast_request(msg).await,

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
                let mut response = msg;
                response.ctrl_field_mut().set_c(Confirm::Err);
                response
            }
        }
    }

    // ========================================================================
    // Connectionless Request Handlers
    // ========================================================================

    async fn handle_group_data_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> KnxMessageBuffer<Buffer<'static>> {
        trace!("T_GroupData_Req: {:?}", msg);

        if self.adt.borrow().is_loaded()
            && let Some(dst_addr) = self.adt.borrow().get_address(msg.get_connection_nr())
        {
            trace!("TL conn_nr -> group addr: {}", dst_addr);
            let original_conn_nr = msg.get_connection_nr();

            msg.set_tpci(Tpci::DataGroup);
            msg.set_dest_addr(DestinationAddress::Group(dst_addr));
            msg.set_service_type(ServiceType::N_GroupData_Req);

            debug!("TL -> NL: {:x?}", msg);
            let mut confirmation = self.network_layer.request(msg).await;

            confirmation.set_service_type(ServiceType::T_GroupData_Con);
            confirmation.set_connection_nr(original_conn_nr);
            confirmation
        } else {
            warn!("TL ADT not loaded or invalid conn_nr: {}", msg.get_connection_nr());
            msg.set_service_type(ServiceType::T_GroupData_Con);
            msg.ctrl_field_mut().set_c(Confirm::Err);
            msg
        }
    }

    async fn handle_broadcast_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> KnxMessageBuffer<Buffer<'static>> {
        msg.set_tpci(Tpci::DataBroadcast);
        msg.set_service_type(ServiceType::N_Broadcast_Req);
        debug!("TL -> NL: {:x?}", msg);

        let mut confirmation = self.network_layer.request(msg).await;
        confirmation.set_service_type(ServiceType::T_Broadcast_Con);
        confirmation
    }

    async fn handle_system_broadcast_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> KnxMessageBuffer<Buffer<'static>> {
        msg.set_tpci(Tpci::DataSystemBroadcast);
        msg.set_service_type(ServiceType::N_SystemBroadcast_Req);
        debug!("TL -> NL: {:x?}", msg);

        let mut confirmation = self.network_layer.request(msg).await;
        confirmation.set_service_type(ServiceType::T_SystemBroadcast_Con);
        confirmation
    }

    // ========================================================================
    // Connection-Oriented Request Handlers
    // ========================================================================

    async fn handle_connect_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> KnxMessageBuffer<Buffer<'static>> {
        let dest = match msg.get_dest_addr() {
            DestinationAddress::Individual(addr) => addr,
            _ => {
                msg.set_service_type(ServiceType::T_Connect_Con);
                msg.ctrl_field_mut().set_c(Confirm::Err);
                return msg;
            }
        };

        // Allocate an outgoing connection
        let conn = match self.connections.allocate_outgoing(dest) {
            Some(c) => c,
            None => {
                msg.set_service_type(ServiceType::T_Connect_Con);
                msg.ctrl_field_mut().set_c(Confirm::Err);
                return msg;
            }
        };

        // Process connect request through state machine
        let actions = process_event(conn, TlEvent::RequestConnect { dest });
        self.execute_actions(actions, dest, None).await;

        msg.set_service_type(ServiceType::T_Connect_Con);
        msg.ctrl_field_mut().set_c(Confirm::NoError);
        msg
    }

    async fn handle_disconnect_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> KnxMessageBuffer<Buffer<'static>> {
        let dest = match msg.get_dest_addr() {
            DestinationAddress::Individual(addr) => addr,
            _ => {
                msg.set_service_type(ServiceType::T_Disconnect_Con);
                msg.ctrl_field_mut().set_c(Confirm::Err);
                return msg;
            }
        };

        // Find the connection
        if let Some(conn) = self.connections.find_any(dest) {
            let actions = process_event(conn, TlEvent::RequestDisconnect { dest });
            self.execute_actions(actions, dest, None).await;
        }

        msg.set_service_type(ServiceType::T_Disconnect_Con);
        msg.ctrl_field_mut().set_c(Confirm::NoError);
        msg
    }

    async fn handle_data_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> KnxMessageBuffer<Buffer<'static>> {
        let dest = match msg.get_dest_addr() {
            DestinationAddress::Individual(addr) => addr,
            _ => {
                msg.set_service_type(ServiceType::T_Data_Con);
                msg.ctrl_field_mut().set_c(Confirm::Err);
                return msg;
            }
        };

        // Find the connection
        let conn = match self.connections.find_any(dest) {
            Some(c) => c,
            None => {
                msg.set_service_type(ServiceType::T_Data_Con);
                msg.ctrl_field_mut().set_c(Confirm::Err);
                return msg;
            }
        };

        // Store the message for retransmission before processing
        // (We'll do this in execute_actions when we see StorePendingMessage)
        let seq_no = conn.seq_no_send;
        let actions = process_event(conn, TlEvent::RequestData { dest });

        // We need to handle StorePendingMessage specially - store the message in the connection
        for action in actions.iter() {
            if matches!(action, TlAction::StorePendingMessage) {
                // Clone the message buffer for storage
                // Note: We're storing the original message; caller should keep a copy if needed
                if let Some(conn) = self.connections.find_any(dest) {
                    // The message is moved into pending_msg for retransmission
                    // For now we'll handle this differently - see below
                }
                break;
            }
        }

        // For data requests, we need to prepare and send the message
        msg.set_tpci(Tpci::DataConnected(seq_no));
        msg.set_dest_addr(DestinationAddress::Individual(dest));
        msg.set_service_type(ServiceType::N_Data_Req);

        // Store for potential retransmission
        if let Some(conn) = self.connections.find_any(dest) {
            // We should store a copy, but since Buffer is a smart pointer,
            // we can't easily clone it. Instead, we'll need to re-allocate.
            // For now, we'll send immediately and handle retransmission later.
            // TODO: Proper message storage for retransmission
        }

        // Execute other actions (start timer, etc.)
        self.execute_actions_no_send(actions, dest).await;

        // Send the data
        trace!("Transport layer sending data to Network layer: {:x?}", msg);
        let mut confirmation = self.network_layer.request(msg).await;

        // We don't return confirmation immediately - we wait for ACK
        // For now, return immediate confirmation (TODO: proper async confirmation)
        confirmation.set_service_type(ServiceType::T_Data_Con);
        confirmation
    }

    // ========================================================================
    // Timeout Handling
    // ========================================================================

    /// Check for and handle connection timeouts
    async fn check_timeouts(&mut self) {
        let now = Instant::now();

        // Collect timed-out incoming connection indices and process them
        // We need to do this in two phases to avoid borrow checker issues
        loop {
            // Find the first timed-out incoming connection
            let timed_out = self
                .connections
                .incoming_mut()
                .iter()
                .enumerate()
                .find(|(_, c)| c.is_timed_out(now))
                .map(|(i, c)| (i, c.remote_addr));

            match timed_out {
                Some((idx, addr)) => {
                    let conn = &mut self.connections.incoming_mut()[idx];
                    let actions = process_event(conn, TlEvent::AckTimeout);
                    self.execute_actions(actions, addr, None).await;
                }
                None => break,
            }
        }

        // Same for outgoing connections
        loop {
            let timed_out = self
                .connections
                .outgoing_mut()
                .iter()
                .enumerate()
                .find(|(_, c)| c.is_timed_out(now))
                .map(|(i, c)| (i, c.remote_addr));

            match timed_out {
                Some((idx, addr)) => {
                    let conn = &mut self.connections.outgoing_mut()[idx];
                    let actions = process_event(conn, TlEvent::AckTimeout);
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

    /// Execute actions returned by the state machine
    ///
    /// Takes ownership of `msg_for_data` since it may need to be forwarded
    /// to the application layer.
    async fn execute_actions(
        &mut self,
        actions: ActionBuffer,
        remote_addr: IndividualAddress,
        mut msg_for_data: Option<KnxMessageBuffer<Buffer<'static>>>,
    ) {
        for action in actions.iter() {
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
                        self.application_layer.send(LayerOp::Indication(msg)).await;
                    }
                }
                TlAction::ConfirmData { dest, success } => {
                    debug!("TL data confirmation for {}: {}", dest, success);
                    // TODO: Complete pending request with confirmation
                }
                TlAction::ConfirmConnect { dest, success } => {
                    debug!("TL connect confirmation for {}: {}", dest, success);
                }
                TlAction::StartAckTimer => {
                    if let Some(conn) = self.connections.find_any(remote_addr) {
                        let deadline = Instant::now() + Duration::from_millis(ACK_TIMEOUT_MS);
                        conn.start_timeout(deadline);
                    }
                }
                TlAction::StopAckTimer => {
                    if let Some(conn) = self.connections.find_any(remote_addr) {
                        conn.stop_timeout();
                    }
                }
                TlAction::Retransmit { dest } => {
                    debug!("TL retransmitting to {}", dest);
                    // TODO: Retransmit pending message
                    if let Some(conn) = self.connections.find_any(dest) {
                        if let Some(ref msg) = conn.pending_msg {
                            // Would retransmit here
                            trace!("Would retransmit pending message");
                        }
                    }
                }
                TlAction::StorePendingMessage => {
                    // Handled in the caller
                }
                TlAction::SendData { dest } => {
                    // Handled in the caller (handle_data_request)
                }
            }
        }
    }

    /// Execute actions without handling data sending (for request handlers)
    async fn execute_actions_no_send(&mut self, actions: ActionBuffer, remote_addr: IndividualAddress) {
        self.execute_actions(actions, remote_addr, None).await;
    }

    // ========================================================================
    // PDU Sending Helpers
    // ========================================================================

    async fn send_connect(&mut self, dest: IndividualAddress) {
        // TODO: Allocate buffer and send T_Connect PDU
        trace!("Would send T_Connect to {}", dest);
    }

    async fn send_disconnect(&mut self, dest: IndividualAddress) {
        // TODO: Allocate buffer and send T_Disconnect PDU
        trace!("Would send T_Disconnect to {}", dest);
    }

    async fn send_ack(&mut self, dest: IndividualAddress, seq_no: u8) {
        // TODO: Allocate buffer and send T_ACK PDU
        trace!("Would send T_ACK({}) to {}", seq_no, dest);
    }

    async fn send_nack(&mut self, dest: IndividualAddress, seq_no: u8) {
        // TODO: Allocate buffer and send T_NACK PDU
        trace!("Would send T_NACK({}) to {}", seq_no, dest);
    }
}

// ============================================================================
// Layer Implementation
// ============================================================================

impl<'a, D: StackDefinition, const MAX_INCOMING: usize, const MAX_OUTGOING: usize> Layer<'a>
    for TransportLayer<'a, D, MAX_INCOMING, MAX_OUTGOING>
{
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Message>>,
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
