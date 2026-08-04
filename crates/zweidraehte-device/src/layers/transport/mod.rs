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
//! - **Router Integration**: Timer-driven timeout handling via `next_deadline()`/`poll()`

// FIXME: do we want the connection timeout, ack timeout and max_repetitions to be configurable? Are there PIDs available for interface objects?

#[cfg(feature = "knxip")]
pub mod cemi;
mod connection;
mod state_machine;

/// Pseudo individual address used as the "source" of cEMI TL frames.
///
/// cEMI TL frames carry no addressing — the 6 reserved bytes are all zeros —
/// so the cEMI Transport Layer synthesises frames with `0.0.0` in both the
/// source and destination fields. `0.0.0` is never a valid bus source address,
/// which makes it an unambiguous marker for "this came from the local
/// device-management client rather than the bus".
///
/// It lives here rather than in [`cemi`] because the Secure Application Layer
/// must recognise it even in builds without the `knxip` feature (a TP1 or RF
/// Data Secure device compiles the same Secure AL). KNX Data Secure binds the
/// source and destination into the CCM nonce, so a peer on this path computes
/// its MACs with `0.0.0` as the device's address and responses must be signed
/// the same way — see `secure_application::p2p_security`.
pub const CEMI_PSEUDO_ADDR: zweidraehte_proto::address::IndividualAddress =
    zweidraehte_proto::address::IndividualAddress::new(0, 0, 0);

pub use connection::{Connection, ConnectionState, ConnectionTable};
pub use state_machine::{
    ActionBuffer, MAX_REPETITIONS, ProcessResult, ProcessResultExt, TlAction, TlEvent, TlStyle, process_event,
};

use embassy_time::{Duration, Instant};

use crate::{
    HasAuthorization, StackDefinition,
    context::StackContext,
    context::layer::LayerContext,
    objects::tables::{AddressTable, HasAddressTable, HasLoadStateMachine},
    service::Layer,
};
use zweidraehte_proto::AccessSource;
use zweidraehte_proto::HasConnectionAuth;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::{
    buffers::Buffer,
    builder::ConfirmationExt,
    knx::{DestinationAddress, KnxMessageBuffer, Priority, ServiceType, Tpci},
};

// ============================================================================
// Configuration
// ============================================================================

/// Default ACK timeout in milliseconds (per KNX spec: 3 seconds)
pub const ACK_TIMEOUT_MS: u64 = 3000;

/// Default connection timeout in milliseconds (per KNX spec: 6 seconds)
pub const CONNECTION_TIMEOUT_MS: u64 = 6000;

/// Timeout type for distinguishing ACK vs connection timeouts
enum TimeoutType {
    Ack,
    Connection,
}

// ============================================================================
// Pending NL Request Tracking
// ============================================================================

/// Tracks what kind of request is pending at the network layer, so the TL
/// can correctly dispatch the NL confirmation when it arrives.
///
/// Since requests to NL are sent fire-and-forget and confirmations arrive
/// asynchronously on a separate channel, the TL must remember what each
/// pending confirmation corresponds to. NL processes requests in order, so
/// confirmations arrive in the same order as requests — a FIFO is sufficient.
#[derive(Debug)]
enum PendingNlRequest {
    /// Connectionless request (group, broadcast, etc.) whose confirmation
    /// must be transformed and forwarded to the AL.
    Connectionless {
        /// The T_*_Con service type to set on the confirmation
        confirmation_service_type: ServiceType,
        /// The connection number (TSAP) to restore on the confirmation
        connection_nr: u16,
    },
    /// Connected data (T_Data) whose NL confirmation needs forwarding to AL.
    ConnectedData,
    /// Fire-and-forget (ACK, NACK, connect, disconnect, retransmit, queued
    /// outgoing) — the NL confirmation is consumed and dropped.
    FireAndForget,
}

// ============================================================================
// Transport Layer
// ============================================================================

/// Transport layer for the KNX stack.
///
/// Handles both connectionless and connection-oriented communication.
/// The connection table size is configurable via const generics.
///
/// In the router architecture, TL is a synchronous [`Layer`] that the
/// router dispatches messages to based on ServiceType. TL pushes
/// transformed messages to the outbox for further routing. Timer-driven
/// timeout handling is integrated via [`next_deadline`](Layer::next_deadline)
/// and [`poll`](Layer::poll).
///
/// # Type Parameters
/// - `D`: Stack definition providing table types
/// - `MAX_INCOMING`: Maximum number of incoming connections (default: 1)
/// - `MAX_OUTGOING`: Maximum number of outgoing connections (default: 0)
pub struct TransportLayer<'a, D: StackDefinition, const MAX_INCOMING: usize = 1, const MAX_OUTGOING: usize = 0> {
    /// Unified device state (contains tables and runtime state)
    state: &'a D::State,

    lctx: &'a LayerContext<D>,

    /// Connection table for stateful connections
    connections: ConnectionTable<MAX_INCOMING, MAX_OUTGOING>,
    /// State machine style (determines error recovery behavior)
    style: TlStyle,

    /// FIFO of pending NL requests, matching the order in which confirmations
    /// will arrive. Capacity 4 covers the worst case of `execute_actions`
    /// sending multiple PDUs (e.g., ACK + retransmit + queued outgoing).
    pending_nl: heapless::Deque<PendingNlRequest, 4>,

    /// Effective ACK timeout. Defaults to `ACK_TIMEOUT_MS` (3s per KNX spec).
    /// With the `conformance` feature, scaled down by the `KNX_TIME_DIVISOR`
    /// environment variable for fast IPC-based conformance testing.
    ack_timeout: Duration,
    /// Effective connection timeout. Defaults to `CONNECTION_TIMEOUT_MS` (6s).
    conn_timeout: Duration,
}

impl<'a, D: StackDefinition, const MAX_INCOMING: usize, const MAX_OUTGOING: usize>
    TransportLayer<'a, D, MAX_INCOMING, MAX_OUTGOING>
{
    /// Create a new Transport Layer from a [`StackContext`].
    ///
    /// With the `conformance` feature enabled, reads `KNX_TIME_DIVISOR` from
    /// the environment to scale protocol timeouts for fast IPC-based testing.
    /// If absent or unparseable, spec-compliant timeouts are used.
    pub fn new(ctx: &'a StackContext<'a, D>) -> Self {
        let state = ctx.state();
        let lctx = ctx.layer_context();
        let style = D::TL_STYLE;

        #[cfg(feature = "conformance")]
        let (ack_timeout, conn_timeout) = {
            extern crate std;
            let divisor: u64 =
                std::env::var("KNX_TIME_DIVISOR").ok().and_then(|s| s.parse().ok()).filter(|&d| d > 0).unwrap_or(1);
            if divisor > 1 {
                log::info!(
                    "TL time scaling: divisor={}, ACK={}ms, conn={}ms",
                    divisor,
                    ACK_TIMEOUT_MS / divisor,
                    CONNECTION_TIMEOUT_MS / divisor
                );
            }
            (Duration::from_millis(ACK_TIMEOUT_MS / divisor), Duration::from_millis(CONNECTION_TIMEOUT_MS / divisor))
        };
        #[cfg(not(feature = "conformance"))]
        let (ack_timeout, conn_timeout) =
            (Duration::from_millis(ACK_TIMEOUT_MS), Duration::from_millis(CONNECTION_TIMEOUT_MS));

        Self {
            state,
            lctx,
            connections: ConnectionTable::new(),
            style,
            pending_nl: heapless::Deque::new(),
            ack_timeout,
            conn_timeout,
        }
    }

    // =========================================================================
    // cEMI Transport Layer support
    // =========================================================================
    //
    // These methods are called by CemiTransportLayer to manage contention
    // between bus-originated and cEMI-originated connection-oriented traffic.

    /// Lock incoming connections, causing `allocate_incoming()` to reject
    /// new bus connections with `T_Disconnect`.
    pub fn lock_incoming(&mut self) {
        self.connections.lock_incoming();
    }

    /// Unlock incoming connections, re-enabling bus connection acceptance.
    pub fn unlock_incoming(&mut self) {
        self.connections.unlock_incoming();
    }

    /// Force-close all active incoming bus connections.
    ///
    /// Sends `T_Disconnect` to each remote device and issues
    /// `T_Disconnect.ind` to the application layer via the outbox.
    pub fn force_close_incoming(&mut self) {
        let disconnected = self.connections.force_close_all_incoming();
        for addr in &disconnected {
            info!("TL: force-closing incoming connection from {} (cEMI TL takeover)", addr);
        }
        for addr in disconnected {
            // Notify the remote device
            self.send_disconnect(addr);
            // Notify the application layer
            self.send_disconnect_indication(addr);
        }
    }
}

impl<D: StackDefinition, const MAX_INCOMING: usize, const MAX_OUTGOING: usize> Layer<D>
    for TransportLayer<'_, D, MAX_INCOMING, MAX_OUTGOING>
{
    const HANDLES: &'static [ServiceType] = &[
        // Indications from NL (upward — connectionless)
        ServiceType::N_GroupData_Ind,
        ServiceType::N_Broadcast_Ind,
        ServiceType::N_SystemBroadcast_Ind,
        // Indications from NL (upward — connection-oriented)
        ServiceType::N_Data_Ind,
        // Confirmations from NL (upward)
        ServiceType::N_Data_Con,
        ServiceType::N_GroupData_Con,
        ServiceType::N_Broadcast_Con,
        ServiceType::N_SystemBroadcast_Con,
        // Requests from AL (downward — connectionless)
        ServiceType::T_GroupData_Req,
        ServiceType::T_Broadcast_Req,
        ServiceType::T_SystemBroadcast_Req,
        ServiceType::T_DataUnack_Req,
        // Requests from AL (downward — connection-oriented)
        ServiceType::T_Connect_Req,
        ServiceType::T_Disconnect_Req,
        ServiceType::T_Data_Req,
    ];

    fn process(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) {
        match msg.service_type() {
            // =================================================================
            // Indications from Network Layer (upward)
            // =================================================================
            ServiceType::N_GroupData_Ind
            | ServiceType::N_Broadcast_Ind
            | ServiceType::N_SystemBroadcast_Ind
            | ServiceType::N_Data_Ind => {
                self.handle_indication(msg);
            }

            // =================================================================
            // Confirmations from Network Layer (upward)
            // =================================================================
            ServiceType::N_Data_Con
            | ServiceType::N_GroupData_Con
            | ServiceType::N_Broadcast_Con
            | ServiceType::N_SystemBroadcast_Con => {
                self.handle_nl_confirmation(msg);
            }

            // =================================================================
            // Requests from Application Layer (downward)
            // =================================================================
            ServiceType::T_GroupData_Req
            | ServiceType::T_Broadcast_Req
            | ServiceType::T_SystemBroadcast_Req
            | ServiceType::T_DataUnack_Req
            | ServiceType::T_Connect_Req
            | ServiceType::T_Disconnect_Req
            | ServiceType::T_Data_Req => {
                self.handle_request(msg);
            }

            // Unreachable: the dispatch table only routes HANDLES to us.
            _ => unreachable!(),
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.connections.next_timeout_deadline()
    }

    fn poll(&mut self) {
        self.check_timeouts();
    }
}

// ============================================================================
// Indication Handling (from Network Layer)
// ============================================================================

impl<D: StackDefinition, const MAX_INCOMING: usize, const MAX_OUTGOING: usize>
    TransportLayer<'_, D, MAX_INCOMING, MAX_OUTGOING>
{
    /// Handle an indication from the network layer.
    fn handle_indication(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
        debug!("TL indication: {:?}", msg);

        match msg.service_type() {
            // ─────────────────────────────────────────────────────────────────
            // Connectionless services
            // ─────────────────────────────────────────────────────────────────
            ServiceType::N_GroupData_Ind => {
                // Look up the TSAP from the address table.
                let tsap = if let Some(Tpci::DataGroup) = msg.get_tpci()
                    && let DestinationAddress::Group(g) = msg.get_dest_addr()
                {
                    let adt = self.state.adt().borrow();
                    if adt.is_loaded() { adt.tsap(g) } else { None }
                } else {
                    None
                };

                if let Some(conn_nr) = tsap {
                    msg.set_connection_nr(conn_nr);
                    msg.set_service_type(ServiceType::T_GroupData_Ind);
                    debug!("TL -> AL: {:?}", msg);
                    self.lctx.push_outbox(msg);
                }
            }

            ServiceType::N_Broadcast_Ind => {
                if let Some(Tpci::DataBroadcast) = msg.get_tpci() {
                    msg.set_service_type(ServiceType::T_Broadcast_Ind);
                    debug!("TL -> AL: {:?}", msg);
                    self.lctx.push_outbox(msg);
                }
            }

            ServiceType::N_SystemBroadcast_Ind => {
                if let Some(Tpci::DataSystemBroadcast) = msg.get_tpci() {
                    msg.set_service_type(ServiceType::T_SystemBroadcast_Ind);
                    debug!("TL -> AL: {:?}", msg);
                    self.lctx.push_outbox(msg);
                }
            }

            // ─────────────────────────────────────────────────────────────────
            // Connection-oriented services (point-to-point)
            // ─────────────────────────────────────────────────────────────────
            ServiceType::N_Data_Ind => {
                self.handle_connection_indication(msg);
            }

            _ => {
                warn!("TL unhandled indication: {:?}", msg.service_type());
            }
        }
    }

    /// Handle connection-oriented indications (N_Data_Ind).
    fn handle_connection_indication(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
        use zweidraehte_proto::messages::knx::offsets::MSG_TPCI;

        let tpci = match msg.get_tpci() {
            Some(t) => t,
            None => {
                warn!("Invalid TPCI in N_Data_Ind");
                return;
            }
        };

        let source = msg.get_source_addr();

        trace!("TL connection from {}: TPCI={:?}", source, tpci);

        // Control packets (Connect, Disconnect, ACK, NACK) must have exactly 7 bytes
        // (CTRL + SRC[2] + DEST[2] + NPDU + TPCI, no additional data).
        // Malformed control packets with extra bytes must be ignored (KNX conformance test 2.5).
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
                // Connectionless: AccessSource::Default is already set.
                msg.set_service_type(ServiceType::T_DataUnack_Ind);
                self.lctx.push_outbox(msg);
                return;
            }
            _ => {
                warn!("TL unexpected TPCI for N_Data_Ind: {:?}", tpci);
                return;
            }
        };

        // For connect events, we need to allocate a connection slot
        let conn = if matches!(event, TlEvent::ReceivedConnect { .. }) {
            // Allocate new connection and reset its access level in the shared store
            let mut conn = self.connections.allocate_incoming(source);
            if let Some(c) = conn.as_mut() {
                let default_level = self.state.default_access_level();
                debug!("TL setting connection access level to {} (default)", default_level);
                self.state.reset_connection_access(c.slot_index, default_level);
            }
            conn
        } else {
            self.connections.find_incoming(source)
        };

        let conn = match conn {
            Some(c) => c,
            None => {
                // No connection slot found.
                // For T_Connect from a different source when already connected,
                // reject it with T_Disconnect (KNX spec requirement).
                if matches!(event, TlEvent::ReceivedConnect { .. }) {
                    debug!("TL rejecting connection from {} - already connected", source);
                    self.send_disconnect(source);
                    return;
                }
                // Per KNX conformance tests (2.5.1), we should NOT send a T_Disconnect
                // when receiving data for a non-existent connection — just ignore it.
                debug!("TL no connection slot for {} - ignoring", source);
                return;
            }
        };

        // Process the event through the state machine
        let result = process_event(conn, event, self.style);

        // Store the message if we need to forward data
        let msg_for_data = if matches!(event, TlEvent::ReceivedData { .. }) { Some(msg) } else { None };

        // Execute actions
        self.execute_actions(result, source, msg_for_data);
    }

    // ========================================================================
    // Request Handling (from Application Layer)
    // ========================================================================

    /// Handle a request from the application layer.
    ///
    /// Transforms T_*_Req into N_*_Req and pushes to the outbox for NL,
    /// tracking what kind of confirmation to expect.
    fn handle_request(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) {
        debug!("TL request: {:?}", msg);

        match msg.service_type() {
            // ─────────────────────────────────────────────────────────────────
            // Connectionless requests
            // ─────────────────────────────────────────────────────────────────
            ServiceType::T_GroupData_Req => self.handle_group_data_request(msg),
            ServiceType::T_Broadcast_Req => self.handle_broadcast_request(msg),
            ServiceType::T_SystemBroadcast_Req => self.handle_system_broadcast_request(msg),

            // ─────────────────────────────────────────────────────────────────
            // Connectionless point-to-point (unacknowledged)
            // ─────────────────────────────────────────────────────────────────
            ServiceType::T_DataUnack_Req => self.handle_data_unack_request(msg),

            // ─────────────────────────────────────────────────────────────────
            // Connection-oriented requests
            // ─────────────────────────────────────────────────────────────────
            ServiceType::T_Connect_Req => self.handle_connect_request(msg),
            ServiceType::T_Disconnect_Req => self.handle_disconnect_request(msg),
            ServiceType::T_Data_Req => self.handle_data_request(msg),

            // ─────────────────────────────────────────────────────────────────
            // Unhandled — send error confirmation directly to AL
            // ─────────────────────────────────────────────────────────────────
            _ => {
                warn!("TL unhandled request: {:?}", msg.service_type());
                self.lctx.push_outbox(msg.error().build().into_inner());
            }
        }
    }

    // ========================================================================
    // Connectionless Request Handlers
    // ========================================================================

    fn handle_group_data_request(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
        trace!("T_GroupData_Req: {:?}", msg);

        let dst_addr = {
            let adt = self.state.adt().borrow();
            if adt.is_loaded() { adt.address(msg.get_connection_nr()) } else { None }
        };

        if let Some(dst_addr) = dst_addr {
            trace!("TL conn_nr -> group addr: {}", dst_addr);
            let original_conn_nr = msg.get_connection_nr();

            msg.set_tpci(Tpci::DataGroup);
            msg.set_dest_addr(DestinationAddress::Group(dst_addr));
            msg.set_service_type(ServiceType::N_GroupData_Req);

            // Track that we expect a connectionless confirmation back
            let _ = self.pending_nl.push_back(PendingNlRequest::Connectionless {
                confirmation_service_type: ServiceType::T_GroupData_Con,
                connection_nr: original_conn_nr,
            });

            debug!("TL -> NL: {:?}", msg);
            self.lctx.push_outbox(msg);
        } else {
            // No valid address — send error confirmation directly to AL
            warn!("TL ADT not loaded or invalid conn_nr: {}", msg.get_connection_nr());
            self.lctx.push_outbox(msg.error().build().into_inner());
        }
    }

    fn handle_broadcast_request(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
        msg.set_tpci(Tpci::DataBroadcast);
        msg.set_service_type(ServiceType::N_Broadcast_Req);

        let _ = self.pending_nl.push_back(PendingNlRequest::Connectionless {
            confirmation_service_type: ServiceType::T_Broadcast_Con,
            connection_nr: 0,
        });

        debug!("TL -> NL: {:?}", msg);
        self.lctx.push_outbox(msg);
    }

    fn handle_system_broadcast_request(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
        msg.set_tpci(Tpci::DataSystemBroadcast);
        msg.set_service_type(ServiceType::N_SystemBroadcast_Req);

        let _ = self.pending_nl.push_back(PendingNlRequest::Connectionless {
            confirmation_service_type: ServiceType::T_SystemBroadcast_Con,
            connection_nr: 0,
        });

        debug!("TL -> NL: {:?}", msg);
        self.lctx.push_outbox(msg);
    }

    fn handle_data_unack_request(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
        msg.set_tpci(Tpci::DataIndividual);
        msg.set_service_type(ServiceType::N_Data_Req);

        let _ = self.pending_nl.push_back(PendingNlRequest::Connectionless {
            confirmation_service_type: ServiceType::T_DataUnack_Con,
            connection_nr: 0,
        });

        debug!("TL -> NL (unack): {:?}", msg);
        self.lctx.push_outbox(msg);
    }

    // ========================================================================
    // Connection-Oriented Request Handlers
    // ========================================================================

    fn handle_connect_request(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) {
        let dest = match msg.get_dest_addr() {
            DestinationAddress::Individual(addr) => addr,
            _ => {
                self.lctx.push_outbox(msg.error().build().into_inner());
                return;
            }
        };

        // Allocate an outgoing connection
        let conn = match self.connections.allocate_outgoing(dest) {
            Some(c) => c,
            None => {
                self.lctx.push_outbox(msg.error().build().into_inner());
                return;
            }
        };

        // Process connect request through state machine
        let actions = process_event(conn, TlEvent::RequestConnect { dest }, self.style);
        self.execute_actions(actions, dest, None);

        // Send immediate confirmation to AL (connect is locally confirmed)
        self.lctx.push_outbox(msg.confirm().build().into_inner());
    }

    fn handle_disconnect_request(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) {
        let dest = match msg.get_dest_addr() {
            DestinationAddress::Individual(addr) => addr,
            _ => {
                self.lctx.push_outbox(msg.error().build().into_inner());
                return;
            }
        };

        // Find the connection
        if let Some(conn) = self.connections.find_any(dest) {
            let actions = process_event(conn, TlEvent::RequestDisconnect { dest }, self.style);
            self.execute_actions(actions, dest, None);
        }

        // Send immediate confirmation to AL
        self.lctx.push_outbox(msg.confirm().build().into_inner());
    }

    fn handle_data_request(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
        let dest = match msg.get_dest_addr() {
            DestinationAddress::Individual(addr) => addr,
            _ => {
                self.lctx.push_outbox(msg.error().build().into_inner());
                return;
            }
        };

        // Find the connection
        let conn = match self.connections.find_any(dest) {
            Some(c) => c,
            None => {
                self.lctx.push_outbox(msg.error().build().into_inner());
                return;
            }
        };

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
            self.execute_actions(actions, dest, None);

            // Send immediate confirmation to AL (the actual send will happen later).
            // Use try_alloc — if no buffer available, the confirmation is skipped.
            // The data will still be sent when the pending ACK arrives.
            if let Some(confirm_buf) = self.lctx.buffer_manager.try_alloc_with_size(7) {
                let confirmation = KnxMessageBuffer::new(confirm_buf, ServiceType::T_Data_Req);
                self.lctx.push_outbox(confirmation.confirm().build().into_inner());
            } else {
                warn!("TL no buffer for queued data confirmation");
            }
            return;
        }

        // Normal path: prepare and send the message immediately.
        msg.set_tpci(Tpci::DataConnected(seq_no));
        msg.set_dest_addr(DestinationAddress::Individual(dest));
        msg.set_service_type(ServiceType::N_Data_Req);

        // Store the original message for potential retransmission.
        // We keep the original buffer as pending_msg and send a copy.
        let service_type = msg.service_type();
        if let Some(conn) = self.connections.find_any(dest) {
            conn.pending_msg = Some(msg);
        }

        // Now allocate a fresh buffer for sending (original is safely stored).
        // Use try_alloc — if no buffer available, the pending message is stored
        // and will be retransmitted when the ACK timeout fires.
        let send_msg = {
            let pending = self.connections.find_any(dest).and_then(|c| c.pending_msg.as_ref());
            if let Some(pm) = pending {
                self.lctx
                    .buffer_manager
                    .try_alloc_from_slice(pm.buf())
                    .map(|buf| KnxMessageBuffer::new(buf, service_type))
            } else {
                None
            }
        };

        // Execute other actions (start timer, etc.)
        self.execute_actions(actions, dest, None);

        if let Some(send_msg) = send_msg {
            // Track that we need to forward this confirmation to AL
            let _ = self.pending_nl.push_back(PendingNlRequest::ConnectedData);

            // Send the copy to NL
            trace!("Transport layer sending data to Network layer: {:?}", send_msg);
            self.lctx.push_outbox(send_msg);
        } else {
            warn!("TL no buffer for data send copy to {} — will retry on timeout", dest);
        }
    }

    // ========================================================================
    // Timeout Handling
    // ========================================================================

    /// Check for and handle all timeouts (ACK and connection).
    fn check_timeouts(&mut self) {
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
                    self.execute_actions(actions, addr, None);
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
                    self.execute_actions(actions, addr, None);
                }
                None => break,
            }
        }
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
    fn execute_actions(
        &mut self,
        result: ProcessResult,
        remote_addr: IndividualAddress,
        mut msg_for_data: Option<KnxMessageBuffer<Buffer<'static>>>,
    ) {
        for action in result.actions.iter() {
            match action {
                TlAction::SendConnect { dest } => {
                    self.send_connect(dest);
                }
                TlAction::SendDisconnect { dest } => {
                    self.send_disconnect(dest);
                }
                TlAction::SendAck { dest, seq_no } => {
                    self.send_ack(dest, seq_no);
                }
                TlAction::SendNack { dest, seq_no } => {
                    self.send_nack(dest, seq_no);
                }
                TlAction::IndicateConnected { source } => {
                    info!("TL connection established with {}", source);
                    self.send_connect_indication(source);
                }
                TlAction::IndicateDisconnected { source } => {
                    info!("TL connection closed with {}", source);
                    self.send_disconnect_indication(source);
                }
                TlAction::IndicateData { source: _ } => {
                    if let Some(mut msg) = msg_for_data.take() {
                        msg.set_service_type(ServiceType::T_Data_Ind);
                        // Tag with connection slot so AL can look up access level,
                        // and embed the outgoing TL sequence number so the S-AL can
                        // include the correct TPCI in the CCM B0 block when encrypting
                        // the response (spec 03/03/07 §5.1.3.2 Figure 101).
                        if let Some(conn) = self.connections.find_any_including_closed(remote_addr) {
                            msg.set_access_source(AccessSource::Connection(conn.slot_index));
                            // The seq the *response* will carry, not the one the
                            // counter shows now: while an earlier response is
                            // still awaiting its T_ACK, this indication's answer
                            // parks in `queued_outgoing` and is released only
                            // after that ACK has advanced `seq_no_send` — so the
                            // MAC must be computed over the advanced value, or
                            // the release-time TPCI rewrite breaks it (TSS J 3.9,
                            // "response must be parked and sent later with
                            // security").
                            let pending = conn.pending_msg.is_some() as u8;
                            msg.set_outgoing_tl_seq((conn.seq_no_send + pending) & 0x0F);
                        }
                        self.lctx.push_outbox(msg);
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
                    if let Some(msg) = msg_for_data.take()
                        && let Some(conn) = self.connections.find_any_including_closed(remote_addr)
                    {
                        match self.lctx.buffer_manager.try_alloc_from_slice(msg.buf()) {
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
                TlAction::DeliverQueuedData { source: _ } => {
                    // Deliver any queued incoming data to the application layer
                    if let Some(conn) = self.connections.find_any_including_closed(remote_addr) {
                        let slot = conn.slot_index;
                        if let Some(mut queued_msg) = conn.queued_incoming.take() {
                            queued_msg.set_service_type(ServiceType::T_Data_Ind);
                            queued_msg.set_access_source(AccessSource::Connection(slot));
                            queued_msg.set_outgoing_tl_seq(conn.seq_no_send);
                            debug!("TL delivering queued data from {}", remote_addr);
                            self.lctx.push_outbox(queued_msg);
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
                        let deadline = Instant::now() + self.ack_timeout;
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
                        let deadline = Instant::now() + self.conn_timeout;
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
                    if let Some(conn) = self.connections.find_any_including_closed(dest)
                        && let Some(ref pending_msg) = conn.pending_msg
                    {
                        match self.lctx.buffer_manager.try_alloc_from_slice(pending_msg.buf()) {
                            Some(retransmit_buffer) => {
                                let retransmit_msg =
                                    KnxMessageBuffer::new(retransmit_buffer, pending_msg.service_type());
                                debug!("TL retransmitting: {:?}", retransmit_msg);
                                let _ = self.pending_nl.push_back(PendingNlRequest::FireAndForget);
                                self.lctx.push_outbox(retransmit_msg);
                            }
                            None => {
                                warn!("TL skipping retransmit to {} (no free buffers)", dest);
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
                    if let Some(conn) = self.connections.find_any_including_closed(remote_addr)
                        && conn.pending_msg.take().is_some()
                    {
                        debug!("TL cleared pending message for {}", remote_addr);
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
        // which would cause infinite recursion.
        if let Some(conn) = self.connections.find_any(remote_addr)
            && conn.state == ConnectionState::OpenIdle
            && conn.queued_outgoing.is_some()
        {
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

            conn.start_ack_timeout(Instant::now() + self.ack_timeout);
            conn.start_conn_timeout(Instant::now() + self.conn_timeout);
            conn.state = ConnectionState::OpenWait;

            // Send a copy (original stored for retransmission).
            // Use try_alloc — if unavailable, the ACK timeout will retry.
            if let Some(ref pending) = conn.pending_msg {
                match self.lctx.buffer_manager.try_alloc_from_slice(pending.buf()) {
                    Some(send_buffer) => {
                        let send_msg = KnxMessageBuffer::new(send_buffer, pending.service_type());
                        let _ = self.pending_nl.push_back(PendingNlRequest::FireAndForget);
                        self.lctx.push_outbox(send_msg);
                    }
                    None => {
                        warn!("TL no buffer for queued outgoing send to {} — will retry on timeout", remote_addr);
                    }
                }
            }
        }
    }

    // ========================================================================
    // NL Confirmation Handling
    // ========================================================================

    /// Handle a confirmation from the network layer.
    ///
    /// Matches against the pending NL request FIFO to determine whether to
    /// forward the confirmation to AL or just drop it (fire-and-forget).
    fn handle_nl_confirmation(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
        debug!("TL NL confirmation: {:?}", msg);

        match self.pending_nl.pop_front() {
            Some(PendingNlRequest::Connectionless { confirmation_service_type, connection_nr }) => {
                msg.set_service_type(confirmation_service_type);
                if connection_nr != 0 {
                    msg.set_connection_nr(connection_nr);
                }
                self.lctx.push_outbox(msg);
            }
            Some(PendingNlRequest::ConnectedData) => {
                msg.set_service_type(ServiceType::T_Data_Con);
                self.lctx.push_outbox(msg);
            }
            Some(PendingNlRequest::FireAndForget) => {
                // Confirmation for a fire-and-forget request — just drop it
                trace!("TL dropping fire-and-forget NL confirmation");
            }
            None => {
                warn!("TL received NL confirmation with no pending request");
            }
        }
    }

    // ========================================================================
    // PDU Sending Helpers
    // ========================================================================

    /// Send a T_Connect PDU to establish a connection (fire-and-forget).
    ///
    /// Uses `try_alloc` — if no buffer is available, the connect is skipped.
    /// The connection timeout will eventually clean up the failed connection.
    fn send_connect(&mut self, dest: IndividualAddress) {
        use zweidraehte_proto::messages::builder::MessageBuilder;

        // Control PDUs need only the basic header (7 bytes up to and including TPCI)
        const CONTROL_PDU_LEN: usize = 7;

        let Some(msg_buf) = self.lctx.buffer_manager.try_alloc_with_size(CONTROL_PDU_LEN) else {
            warn!("TL no buffer for T_Connect to {}", dest);
            return;
        };

        let msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::N_Data_Req,
            Priority::System,
            DestinationAddress::Individual(dest),
        )
        .with_transport_control(Tpci::Connect)
        .build();

        debug!("TL sending T_Connect to {}", dest);
        let _ = self.pending_nl.push_back(PendingNlRequest::FireAndForget);
        self.lctx.push_outbox(msg.into_inner());
    }

    /// Send a T_Disconnect PDU to close a connection (fire-and-forget).
    ///
    /// Uses `try_alloc` — if no buffer is available, the disconnect is skipped.
    fn send_disconnect(&mut self, dest: IndividualAddress) {
        use zweidraehte_proto::messages::builder::MessageBuilder;

        const CONTROL_PDU_LEN: usize = 7;

        let Some(msg_buf) = self.lctx.buffer_manager.try_alloc_with_size(CONTROL_PDU_LEN) else {
            warn!("TL no buffer for T_Disconnect to {}", dest);
            return;
        };

        let msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::N_Data_Req,
            Priority::System,
            DestinationAddress::Individual(dest),
        )
        .with_transport_control(Tpci::Disconnect)
        .build();

        debug!("TL sending T_Disconnect to {}", dest);
        let _ = self.pending_nl.push_back(PendingNlRequest::FireAndForget);
        self.lctx.push_outbox(msg.into_inner());
    }

    /// Synthesize a `T_Disconnect.ind` for the application layer.
    ///
    /// Used when force-closing incoming connections (e.g. when activating
    /// cEMI Transport Layer mode). This goes upward to AL, not to the wire.
    pub(crate) fn send_disconnect_indication(&mut self, source: IndividualAddress) {
        use zweidraehte_proto::messages::builder::MessageBuilder;

        const CONTROL_PDU_LEN: usize = 7;

        let Some(msg_buf) = self.lctx.buffer_manager.try_alloc_with_size(CONTROL_PDU_LEN) else {
            warn!("TL no buffer for T_Disconnect.ind from {}", source);
            return;
        };

        let mut msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::N_Data_Req,
            Priority::System,
            DestinationAddress::Individual(source),
        )
        .with_transport_control(Tpci::Disconnect)
        .build();

        msg.set_service_type(ServiceType::T_Disconnect_Ind);
        self.lctx.push_outbox(msg.into_inner());
    }

    /// Synthesize a `T_Connect.ind` for the application layer.
    ///
    /// Used when activating cEMI Transport Layer mode to signal a
    /// synthetic connection to AL from the cEMI path.
    pub(crate) fn send_connect_indication(&mut self, source: IndividualAddress) {
        use zweidraehte_proto::messages::builder::MessageBuilder;

        const CONTROL_PDU_LEN: usize = 7;

        let Some(msg_buf) = self.lctx.buffer_manager.try_alloc_with_size(CONTROL_PDU_LEN) else {
            warn!("TL no buffer for T_Connect.ind from {}", source);
            return;
        };

        let mut msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::N_Data_Req,
            Priority::System,
            DestinationAddress::Individual(source),
        )
        .with_transport_control(Tpci::Connect)
        .build();

        msg.set_service_type(ServiceType::T_Connect_Ind);
        self.lctx.push_outbox(msg.into_inner());
    }

    /// Send a T_ACK PDU to acknowledge received data (fire-and-forget).
    ///
    /// Uses `try_alloc` — if no buffer is available, the ACK is skipped.
    /// The remote will retransmit on timeout.
    fn send_ack(&mut self, dest: IndividualAddress, seq_no: u8) {
        use zweidraehte_proto::messages::builder::MessageBuilder;

        const CONTROL_PDU_LEN: usize = 7;

        let Some(msg_buf) = self.lctx.buffer_manager.try_alloc_with_size(CONTROL_PDU_LEN) else {
            warn!("TL no buffer for T_ACK({}) to {}", seq_no, dest);
            return;
        };

        let msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::N_Data_Req,
            Priority::System,
            DestinationAddress::Individual(dest),
        )
        .with_transport_control(Tpci::Ack(seq_no))
        .build();

        debug!("TL sending T_ACK({}) to {}", seq_no, dest);
        let _ = self.pending_nl.push_back(PendingNlRequest::FireAndForget);
        self.lctx.push_outbox(msg.into_inner());
    }

    /// Send a T_NACK PDU to signal an error in received data (fire-and-forget).
    ///
    /// Uses `try_alloc` — if no buffer is available, the NACK is skipped.
    fn send_nack(&mut self, dest: IndividualAddress, seq_no: u8) {
        use zweidraehte_proto::messages::builder::MessageBuilder;

        const CONTROL_PDU_LEN: usize = 7;

        let Some(msg_buf) = self.lctx.buffer_manager.try_alloc_with_size(CONTROL_PDU_LEN) else {
            warn!("TL no buffer for T_NACK({}) to {}", seq_no, dest);
            return;
        };

        let msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::N_Data_Req,
            Priority::System,
            DestinationAddress::Individual(dest),
        )
        .with_transport_control(Tpci::Nack(seq_no))
        .build();

        debug!("TL sending T_NACK({}) to {}", seq_no, dest);
        let _ = self.pending_nl.push_back(PendingNlRequest::FireAndForget);
        self.lctx.push_outbox(msg.into_inner());
    }
}
