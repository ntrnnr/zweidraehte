//! Table-driven state machine for connection-oriented transport layer
//!
//! Implements all four state machine styles defined in KNX spec 03/03/04
//! section 5.4:
//!
//! - **Style 1**: Full error recovery with NACK and retransmit (strict)
//! - **Style 2**: Lenient — ignores unexpected frames instead of disconnecting
//! - **Style 3**: Adds CONNECTING state for client-initiated connections
//! - **Style 1 Rationalised**: Minimal — no NACK, no retransmit, disconnect on error
//!
//! The state machine is separated from async I/O to keep it testable and pure.
//! Each style is encoded as a static transition table mapping
//! `(state, event) → (next_state, action)`, directly mirroring the spec's
//! representation.
//!
//! # Architecture
//!
//! ```text
//! TlEvent ──→ classify_event() ──→ SpecEvent
//!                                      │
//!                          transition table lookup
//!                                      │
//!                                      ▼
//!                               (SpecAction, next_state)
//!                                      │
//!                          execute_action() maps to
//!                                      │
//!                                      ▼
//!                              ActionBuffer<TlAction>
//! ```

use zweidraehte_proto::address::IndividualAddress;

use super::connection::{Connection, ConnectionState};

// ============================================================================
// Configuration
// ============================================================================

/// Maximum number of retransmissions before disconnecting.
/// Per KNX spec section 4, the device retransmits 3 times (4 total
/// transmissions) before giving up and disconnecting.
pub const MAX_REPETITIONS: u8 = 3;

// ============================================================================
// Transport Layer Style (public API)
// ============================================================================

/// Transport layer state machine style per KNX spec 03/03/04 section 5.4.
///
/// The device manufacturer must choose a style explicitly. Each style
/// differs in error recovery behavior:
///
/// - `Style1`: Full NACK + retransmit. Strict error handling.
/// - `Style2`: Lenient — ignores unexpected frames instead of disconnecting.
/// - `Style3`: Like Style 1 but adds a CONNECTING state for client connections.
/// - `Style1Rationalised`: No NACK, no retransmit. Disconnects on any error.
///   Only one timer (connection timeout). Suitable for resource-constrained devices.
///
/// The choice is not free: 06 Profiles v02.02.01 §4.1.2 "TL - connection
/// oriented" mandates one style per profile — Style 2 for BCU 1 / System 1,
/// Style 1 for BCU 2 / System 2, and Style 3 for BIM M112 / System B /
/// masks 5705h / 57B0h. AN160 mandates Style 3 for the RF S-Mode profiles
/// as well, so every System B device here uses `Style3`.
///
/// A server-only device (`TL_MAX_OUTGOING = 0`) running `Style3` never
/// enters CONNECTING — that state is only reachable through a local
/// T_Connect.req — so it runs exactly the CLOSED / OPEN_IDLE / OPEN_WAIT
/// subset of the Style 3 table, at no extra RAM cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlStyle {
    Style1,
    Style2,
    Style3,
    Style1Rationalised,
}

impl TlStyle {
    /// Whether this style supports client-initiated outgoing connections.
    ///
    /// Only `Style3` carries the CONNECTING state needed to open connections
    /// to remote peers. A device with `TL_MAX_OUTGOING > 0` that does not
    /// pick `Style3` cannot actually initiate connections and the
    /// [`Runner`](crate::Runner) rejects that combination at startup.
    pub const fn supports_outgoing_connections(self) -> bool {
        matches!(self, Self::Style3)
    }
}

// ============================================================================
// Events (public API)
// ============================================================================

/// Events that can occur in the transport layer state machine.
///
/// These events are derived from incoming messages (from network layer),
/// outgoing requests (from application layer), timer events, and
/// network layer confirmations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlEvent {
    // ─────────────────────────────────────────────────────────────────────────
    // From network layer (incoming PDUs)
    // ─────────────────────────────────────────────────────────────────────────
    /// Received T_Connect from remote device
    ReceivedConnect { source: IndividualAddress },

    /// Received T_Disconnect from remote device
    ReceivedDisconnect { source: IndividualAddress },

    /// Received numbered data (T_Data_Connected) from remote device
    ReceivedData { source: IndividualAddress, seq_no: u8 },

    /// Received ACK from remote device
    ReceivedAck { source: IndividualAddress, seq_no: u8 },

    /// Received NACK from remote device
    ReceivedNack { source: IndividualAddress, seq_no: u8 },

    // ─────────────────────────────────────────────────────────────────────────
    // From application layer (outgoing requests)
    // ─────────────────────────────────────────────────────────────────────────
    /// Application wants to establish a connection (CLIENT ONLY, spec E25)
    RequestConnect { dest: IndividualAddress },

    /// Application wants to close a connection (CLIENT ONLY, spec E26)
    RequestDisconnect { dest: IndividualAddress },

    /// Application wants to send data on a connection (spec E15)
    RequestData { dest: IndividualAddress },

    // ─────────────────────────────────────────────────────────────────────────
    // Timer events
    // ─────────────────────────────────────────────────────────────────────────
    /// ACK timeout expired (in OPEN_WAIT state, spec E17/E18)
    AckTimeout,

    /// Connection timeout expired (spec E16)
    ConnectionTimeout,

    // ─────────────────────────────────────────────────────────────────────────
    // Network layer confirmations (spec E19/E20)
    // ─────────────────────────────────────────────────────────────────────────
    /// N_Data_Individual.con for a T_CONNECT_REQ_PDU we sent.
    /// `success = true` → E19 (IAK = OK), `success = false` → E20 (IAK = NOT OK)
    ConnectConfirm { success: bool },
}

// ============================================================================
// Actions (public API)
// ============================================================================

/// Actions to be performed by the transport layer after processing an event.
///
/// The transport layer's async wrapper is responsible for executing these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlAction {
    // ─────────────────────────────────────────────────────────────────────────
    // To network layer (outgoing PDUs)
    // ─────────────────────────────────────────────────────────────────────────
    /// Send T_Connect to remote device
    SendConnect { dest: IndividualAddress },

    /// Send T_Disconnect to remote device
    SendDisconnect { dest: IndividualAddress },

    /// Send numbered data with the current sequence number
    /// (caller retrieves seq_no from connection state)
    SendData { dest: IndividualAddress },

    /// Send ACK to remote device
    SendAck { dest: IndividualAddress, seq_no: u8 },

    /// Send NACK to remote device
    SendNack { dest: IndividualAddress, seq_no: u8 },

    // ─────────────────────────────────────────────────────────────────────────
    // To application layer (indications/confirmations)
    // ─────────────────────────────────────────────────────────────────────────
    /// Indicate that a connection has been established (T_Connect.ind)
    IndicateConnected { source: IndividualAddress },

    /// Indicate that a connection has been closed (T_Disconnect.ind)
    IndicateDisconnected { source: IndividualAddress },

    /// Indicate that data has been received (T_Data_Connected.ind)
    /// (caller should forward the actual message)
    IndicateData { source: IndividualAddress },

    /// A11: Queue the current event for later processing.
    ///
    /// For incoming data (E04 in OPEN_WAIT in some styles): stores the message
    /// for delivery when transitioning to OPEN_IDLE.
    ///
    /// For outgoing data requests (E15 in OPEN_WAIT): signals to the caller
    /// (`handle_data_request`) that the message should be queued rather than
    /// sent immediately. The caller stores it in `Connection::queued_outgoing`.
    QueueEvent { source: IndividualAddress },

    /// Deliver any queued incoming data to the application layer.
    /// Called when transitioning from OPEN_WAIT to OPEN_IDLE (A8).
    DeliverQueuedData { source: IndividualAddress },

    /// Confirm connection request to user (T_Connect.con)
    ConfirmConnect { dest: IndividualAddress, success: bool },

    /// Confirm data transmission to user (T_Data_Connected.con)
    ConfirmData { dest: IndividualAddress, success: bool },

    /// Confirm disconnect request to user (T_Disconnect.con)
    ConfirmDisconnect { dest: IndividualAddress },

    // ─────────────────────────────────────────────────────────────────────────
    // Internal actions
    // ─────────────────────────────────────────────────────────────────────────
    /// Start the ACK timeout timer
    StartAckTimer,

    /// Stop the ACK timeout timer
    StopAckTimer,

    /// Start the connection timeout timer
    StartConnTimer,

    /// Stop the connection timeout timer
    StopConnTimer,

    /// Retransmit the pending message
    Retransmit { dest: IndividualAddress },

    /// Store the current message for possible retransmission
    StorePendingMessage,

    /// Clear the pending message (on successful ACK)
    ClearPendingMessage,
}

// ============================================================================
// Action Buffer
// ============================================================================

/// A small fixed-size buffer for actions returned by the state machine.
///
/// Most state transitions produce 1-5 actions, so we use a small
/// fixed-size array to avoid heap allocation.
#[derive(Debug)]
pub struct ActionBuffer {
    actions: [Option<TlAction>; 6],
    count: usize,
}

impl ActionBuffer {
    /// Create a new empty action buffer
    pub const fn new() -> Self {
        Self { actions: [None; 6], count: 0 }
    }

    /// Add an action to the buffer
    pub fn push(&mut self, action: TlAction) -> bool {
        if self.count < self.actions.len() {
            self.actions[self.count] = Some(action);
            self.count += 1;
            true
        } else {
            false
        }
    }

    /// Iterate over the actions in the buffer
    pub fn iter(&self) -> impl Iterator<Item = TlAction> + '_ {
        self.actions[..self.count].iter().filter_map(|a| *a)
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get the number of actions in the buffer
    pub fn len(&self) -> usize {
        self.count
    }
}

impl Default for ActionBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of processing a transport layer event.
///
/// Contains the actions to execute and the next connection state.
/// The caller must execute actions FIRST, then apply the state transition
/// via [`apply_state`](ProcessResult::apply_state). This ordering is
/// critical because action execution may need to look up the connection
/// by address, and connections in `Closed` state are not findable.
#[derive(Debug)]
pub struct ProcessResult {
    /// Actions to execute (sends, timer ops, indications, etc.)
    pub actions: ActionBuffer,
    /// Next connection state to apply after actions are executed.
    ///
    /// `None` means no state change (e.g. event was ignored or not applicable).
    pub next_state: Option<ConnectionState>,
}

impl ProcessResult {
    /// Create a no-op result (no actions, no state change)
    fn noop() -> Self {
        Self { actions: ActionBuffer::new(), next_state: None }
    }

    /// Apply the state transition to the connection.
    ///
    /// Must be called AFTER all actions have been executed.
    pub fn apply_state(self, conn: &mut Connection) {
        if let Some(next_state) = self.next_state {
            conn.state = next_state;
        }
    }

    /// Apply the state transition by looking up the connection by address.
    ///
    /// Uses `find_any_including_closed` because during the deferred transition
    /// window the connection may be in any state — including `Closed` (for
    /// transitions that start from `Closed`, like accepting a new connection).
    pub fn apply_state_by_addr<const I: usize, const O: usize>(
        &self,
        connections: &mut super::connection::ConnectionTable<I, O>,
        addr: IndividualAddress,
    ) {
        if let Some(next_state) = self.next_state
            && let Some(conn) = connections.find_any_including_closed(addr)
        {
            conn.state = next_state;
        }
    }
}

// ============================================================================
// Spec-Level Types (internal to this module)
// ============================================================================

/// Spec-defined event labels (section 5.2).
///
/// These directly correspond to the event labels in the spec's transition
/// tables. The `classify_event` function maps `TlEvent` + connection context
/// to one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)] // KNX spec: E21-E24, E27 not yet triggered
enum SpecEvent {
    /// N_DATA_INDIVIDUAL.ind, T_CONNECT_REQ_PDU (source == connection_address)
    E00 = 0,
    /// N_DATA_INDIVIDUAL.ind, T_CONNECT_REQ_PDU (source != connection_address)
    E01,
    /// N_DATA_INDIVIDUAL.ind, T_DISCONNECT_REQ_PDU (source == connection_address)
    E02,
    /// N_DATA_INDIVIDUAL.ind, T_DISCONNECT_REQ_PDU (source != connection_address)
    E03,
    /// N_DATA_INDIVIDUAL.ind, T_DATA_CONNECTED_REQ_PDU (source == CA, seq == SeqNoRcv)
    E04,
    /// N_DATA_INDIVIDUAL.ind, T_DATA_CONNECTED_REQ_PDU (source == CA, seq == prev(SeqNoRcv))
    E05,
    /// N_DATA_INDIVIDUAL.ind, T_DATA_CONNECTED_REQ_PDU (source == CA, seq wrong)
    E06,
    /// N_DATA_INDIVIDUAL.ind, T_DATA_CONNECTED_REQ_PDU (source != CA)
    E07,
    /// N_DATA_INDIVIDUAL.ind, T_ACK_PDU (source == CA, seq == SeqNoSend)
    E08,
    /// N_DATA_INDIVIDUAL.ind, T_ACK_PDU (source == CA, seq != SeqNoSend)
    E09,
    /// N_DATA_INDIVIDUAL.ind, T_ACK_PDU (source != CA)
    E10,
    /// N_DATA_INDIVIDUAL.ind, T_NAK_PDU (source == CA, seq != SeqNoSend)
    E11,
    /// N_DATA_INDIVIDUAL.ind, T_NAK_PDU (source == CA) — Style 1R only, no seq check
    E11b,
    /// N_DATA_INDIVIDUAL.ind, T_NAK_PDU (source == CA, seq == SeqNoSend, rep < max)
    E12,
    /// N_DATA_INDIVIDUAL.ind, T_NAK_PDU (source == CA, seq == SeqNoSend, rep >= max)
    E13,
    /// N_DATA_INDIVIDUAL.ind, T_NAK_PDU (source != CA)
    E14,
    /// T_DATA_CONNECTED.req (application wants to send data)
    E15,
    /// CONNECTION_TIME_OUT.ind
    E16,
    /// ACKNOWLEDGE_TIME_OUT.ind (rep_count < max_rep_count)
    E17,
    /// ACKNOWLEDGE_TIME_OUT.ind (rep_count >= max_rep_count)
    E18,
    /// N_DATA_INDIVIDUAL.con T_CONNECT_REQ_PDU, IAK = OK (CLIENT ONLY)
    E19,
    /// N_DATA_INDIVIDUAL.con T_CONNECT_REQ_PDU, IAK = NOT OK (CLIENT ONLY)
    E20,
    /// N_DATA_INDIVIDUAL.con T_DISCONNECT_REQ_PDU
    E21,
    /// N_DATA_INDIVIDUAL.con T_DATA_CONNECTED_REQ_PDU
    E22,
    /// N_DATA_INDIVIDUAL.con T_ACK_PDU
    E23,
    /// N_DATA_INDIVIDUAL.con T_NAK_PDU
    E24,
    /// T_CONNECT.req (CLIENT ONLY)
    E25,
    /// T_DISCONNECT.req (CLIENT ONLY)
    E26,
    /// All other, not yet defined TPCI
    E27,
}

impl SpecEvent {
    const COUNT: usize = 29;
}

/// Spec-defined action labels (section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SpecAction {
    /// Do nothing
    A0 = 0,
    /// Accept connection: set CA, reset seq, indicate connected, start conn timer
    A1,
    /// ACK + indicate data: send ACK, inc SeqNoRcv, indicate data, restart conn timer
    A2,
    /// ACK repeated: send ACK with received seq, restart conn timer
    A3,
    /// NACK wrong seq: send NACK, restart conn timer
    A4,
    /// Indicate disconnect: stop ack timer, stop conn timer, indicate disconnected
    A5,
    /// Send disconnect + indicate: send disconnect, stop timers, indicate disconnected
    A6,
    /// Store + send data: store msg, send data, clear rep, start ack timer, restart conn timer
    A7,
    /// ACK received (with confirm): stop ack timer, inc SeqNoSend, confirm data, restart conn timer, deliver queued
    A8,
    /// ACK received (no confirm): stop ack timer, inc SeqNoSend, restart conn timer (Style 2)
    A8b,
    /// Retransmit: resend stored msg, inc rep, start ack timer, restart conn timer
    A9,
    /// Reject connection: send disconnect to source
    A10,
    /// Queue event: store event back and handle after next event
    A11,
    /// Initiate connection: set CA, reset seq, send connect, start conn timer
    A12,
    /// Confirm connection: send T_Connect.con to user
    A13,
    /// Cancel + disconnect + confirm: send disconnect, stop timers, confirm disconnect
    A14,
    /// Cancel + disconnect (no user indication, Style 2)
    A14b,
    /// Confirm disconnect: stop timers, confirm disconnect
    A15,
    /// Sentinel: event does not exist in this style (Style 1R)
    DoesNotExist,
}

/// One cell in the transition table.
#[derive(Debug, Clone, Copy)]
struct Transition {
    next_state: ConnectionState,
    action: SpecAction,
}

impl Transition {
    const fn new(next_state: ConnectionState, action: SpecAction) -> Self {
        Self { next_state, action }
    }
}

/// Context extracted from the triggering event, passed to action execution.
///
/// Captures the addresses and sequence number from the original `TlEvent`
/// so that `execute_action` can emit correctly parameterised `TlAction`s
/// without needing the original event.
struct EventContext {
    /// Source address (for received events) or destination (for requests)
    addr: IndividualAddress,
    /// Sequence number from the event (if applicable)
    seq_no: u8,
}

impl EventContext {
    fn from_event(event: &TlEvent) -> Self {
        match *event {
            TlEvent::ReceivedConnect { source } => Self { addr: source, seq_no: 0 },
            TlEvent::ReceivedDisconnect { source } => Self { addr: source, seq_no: 0 },
            TlEvent::ReceivedData { source, seq_no } => Self { addr: source, seq_no },
            TlEvent::ReceivedAck { source, seq_no } => Self { addr: source, seq_no },
            TlEvent::ReceivedNack { source, seq_no } => Self { addr: source, seq_no },
            TlEvent::RequestConnect { dest } => Self { addr: dest, seq_no: 0 },
            TlEvent::RequestDisconnect { dest } => Self { addr: dest, seq_no: 0 },
            TlEvent::RequestData { dest } => Self { addr: dest, seq_no: 0 },
            TlEvent::AckTimeout => Self { addr: IndividualAddress::new(0, 0, 0), seq_no: 0 },
            TlEvent::ConnectionTimeout => Self { addr: IndividualAddress::new(0, 0, 0), seq_no: 0 },
            TlEvent::ConnectConfirm { .. } => Self { addr: IndividualAddress::new(0, 0, 0), seq_no: 0 },
        }
    }
}

// ============================================================================
// Event Classification
// ============================================================================

/// Map a raw `TlEvent` + connection context → spec-level `SpecEvent`.
///
/// Returns `None` if the event does not apply to this style (e.g.,
/// ACK timeout events in Style 1R where they don't exist).
fn classify_event(conn: &Connection, event: &TlEvent, style: TlStyle) -> Option<SpecEvent> {
    match *event {
        // ─────────────────────────────────────────────────────────────────
        // T_CONNECT_REQ_PDU received
        // ─────────────────────────────────────────────────────────────────
        TlEvent::ReceivedConnect { source } => {
            // In CLOSED, there is no connection_address, so every source
            // is treated as "matching" — we always accept via E00.
            // When source matches the existing remote_addr, it's also E00
            // (reconnect from same peer). These two conditions yield the
            // same event intentionally — they are logically distinct cases
            // that happen to map to the same spec event.
            if conn.state == ConnectionState::Closed || source == conn.remote_addr {
                Some(SpecEvent::E00)
            } else {
                Some(SpecEvent::E01)
            }
        }

        // ─────────────────────────────────────────────────────────────────
        // T_DISCONNECT_REQ_PDU received
        // ─────────────────────────────────────────────────────────────────
        TlEvent::ReceivedDisconnect { source } => {
            if conn.state == ConnectionState::Closed || source == conn.remote_addr {
                Some(SpecEvent::E02)
            } else {
                Some(SpecEvent::E03)
            }
        }

        // ─────────────────────────────────────────────────────────────────
        // T_DATA_CONNECTED_REQ_PDU received
        // ─────────────────────────────────────────────────────────────────
        TlEvent::ReceivedData { source, seq_no } => {
            if conn.state == ConnectionState::Closed || source != conn.remote_addr {
                Some(SpecEvent::E07)
            } else if seq_no == conn.seq_no_recv {
                Some(SpecEvent::E04)
            } else if seq_no == conn.prev_seq_recv() {
                Some(SpecEvent::E05)
            } else {
                Some(SpecEvent::E06)
            }
        }

        // ─────────────────────────────────────────────────────────────────
        // T_ACK_PDU received
        // ─────────────────────────────────────────────────────────────────
        TlEvent::ReceivedAck { source, seq_no } => {
            if conn.state == ConnectionState::Closed || source != conn.remote_addr {
                Some(SpecEvent::E10)
            } else if seq_no == conn.seq_no_send {
                Some(SpecEvent::E08)
            } else {
                Some(SpecEvent::E09)
            }
        }

        // ─────────────────────────────────────────────────────────────────
        // T_NAK_PDU received
        // ─────────────────────────────────────────────────────────────────
        TlEvent::ReceivedNack { source, seq_no } => {
            if style == TlStyle::Style1Rationalised {
                // Style 1R uses E11b (no seq check) and has no E12/E13
                if conn.state == ConnectionState::Closed || source != conn.remote_addr {
                    Some(SpecEvent::E14)
                } else {
                    Some(SpecEvent::E11b)
                }
            } else {
                if conn.state == ConnectionState::Closed || source != conn.remote_addr {
                    Some(SpecEvent::E14)
                } else if seq_no != conn.seq_no_send {
                    Some(SpecEvent::E11)
                } else if conn.rep_count < MAX_REPETITIONS {
                    Some(SpecEvent::E12)
                } else {
                    Some(SpecEvent::E13)
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────
        // Application requests
        // ─────────────────────────────────────────────────────────────────
        TlEvent::RequestData { .. } => Some(SpecEvent::E15),
        TlEvent::RequestConnect { .. } => Some(SpecEvent::E25),
        TlEvent::RequestDisconnect { .. } => Some(SpecEvent::E26),

        // ─────────────────────────────────────────────────────────────────
        // Timeouts
        // ─────────────────────────────────────────────────────────────────
        TlEvent::ConnectionTimeout => Some(SpecEvent::E16),

        TlEvent::AckTimeout => {
            // Style 1R has no ACK timer — events E17/E18 don't exist
            if style == TlStyle::Style1Rationalised {
                None
            } else if conn.rep_count < MAX_REPETITIONS {
                Some(SpecEvent::E17)
            } else {
                Some(SpecEvent::E18)
            }
        }

        // ─────────────────────────────────────────────────────────────────
        // Network layer confirmations (E19/E20)
        // ─────────────────────────────────────────────────────────────────
        TlEvent::ConnectConfirm { success } => {
            if success {
                Some(SpecEvent::E19)
            } else {
                Some(SpecEvent::E20)
            }
        }
    }
}

// ============================================================================
// Action Execution
// ============================================================================

/// Execute a spec action, mutating connection state and returning `TlAction`s.
///
/// This function is shared across all styles — the style-specific behavior
/// is entirely captured by which action the transition table selects.
fn execute_action(action: SpecAction, conn: &mut Connection, ctx: &EventContext) -> ActionBuffer {
    let mut buf = ActionBuffer::new();
    let addr = ctx.addr;
    let seq = ctx.seq_no;

    match action {
        // A0: Do nothing
        SpecAction::A0 => {}

        // A1: Accept incoming connection
        // connection_address = source; SeqNoSend=0; SeqNoRcv=0;
        // Send T_Connect.ind to user; Start connection timeout timer
        SpecAction::A1 => {
            conn.remote_addr = addr;
            conn.seq_no_send = 0;
            conn.seq_no_recv = 0;
            conn.rep_count = 0;
            buf.push(TlAction::StartConnTimer);
            buf.push(TlAction::IndicateConnected { source: addr });
        }

        // A2: ACK + indicate data
        // Send ACK(SeqNoRcv); inc SeqNoRcv; indicate data to user; restart conn timer
        SpecAction::A2 => {
            let ack_seq = conn.seq_no_recv;
            conn.inc_seq_recv();
            buf.push(TlAction::SendAck { dest: addr, seq_no: ack_seq });
            buf.push(TlAction::IndicateData { source: addr });
            buf.push(TlAction::StartConnTimer);
        }

        // A3: ACK repeated frame
        // Send ACK(sequence of received message); restart conn timer
        SpecAction::A3 => {
            buf.push(TlAction::SendAck { dest: addr, seq_no: seq });
            buf.push(TlAction::StartConnTimer);
        }

        // A4: NACK wrong sequence
        // Send NACK(sequence of received message); restart conn timer
        SpecAction::A4 => {
            buf.push(TlAction::SendNack { dest: addr, seq_no: seq });
            buf.push(TlAction::StartConnTimer);
        }

        // A5: Indicate disconnect (passive, from remote or error)
        // Send T_Disconnect.ind to user; stop ack timer; stop conn timer
        SpecAction::A5 => {
            buf.push(TlAction::StopAckTimer);
            buf.push(TlAction::StopConnTimer);
            buf.push(TlAction::IndicateDisconnected { source: conn.remote_addr });
        }

        // A6: Send disconnect + indicate
        // Send T_Disconnect to remote; Send T_Disconnect.ind to user;
        // stop ack timer; stop conn timer
        SpecAction::A6 => {
            buf.push(TlAction::SendDisconnect { dest: conn.remote_addr });
            buf.push(TlAction::StopAckTimer);
            buf.push(TlAction::StopConnTimer);
            buf.push(TlAction::IndicateDisconnected { source: conn.remote_addr });
        }

        // A7: Store + send data
        // Store T_Data_Connected.req; send data with SeqNoSend;
        // clear rep_count; start ack timer; restart conn timer
        SpecAction::A7 => {
            conn.rep_count = 0;
            buf.push(TlAction::StorePendingMessage);
            buf.push(TlAction::SendData { dest: conn.remote_addr });
            buf.push(TlAction::StartAckTimer);
            buf.push(TlAction::StartConnTimer);
        }

        // A8: ACK received (with data confirm)
        // Stop ack timer; inc SeqNoSend; confirm data(ok) to user;
        // restart conn timer; deliver queued data
        SpecAction::A8 => {
            conn.inc_seq_send();
            buf.push(TlAction::StopAckTimer);
            buf.push(TlAction::ClearPendingMessage);
            buf.push(TlAction::ConfirmData { dest: conn.remote_addr, success: true });
            buf.push(TlAction::StartConnTimer);
            if conn.has_queued_incoming() {
                buf.push(TlAction::DeliverQueuedData { source: conn.remote_addr });
            }
            // Queued outgoing data (from A11) is handled by execute_actions
            // after the state transition to OPEN_IDLE is applied.
        }

        // A8b: ACK received (no data confirm, Style 2)
        // Stop ack timer; inc SeqNoSend; restart conn timer
        SpecAction::A8b => {
            conn.inc_seq_send();
            buf.push(TlAction::StopAckTimer);
            buf.push(TlAction::ClearPendingMessage);
            buf.push(TlAction::StartConnTimer);
        }

        // A9: Retransmit
        // Send stored message; inc rep_count; start ack timer; restart conn timer
        SpecAction::A9 => {
            conn.rep_count += 1;
            buf.push(TlAction::Retransmit { dest: conn.remote_addr });
            buf.push(TlAction::StartAckTimer);
            buf.push(TlAction::StartConnTimer);
        }

        // A10: Reject connection from different source
        // Send T_Disconnect to the source (not connection_address)
        SpecAction::A10 => {
            buf.push(TlAction::SendDisconnect { dest: addr });
        }

        // A11: Queue event for later processing
        // Store event back; handle after next event.
        // For E15 (outgoing data request) in OPEN_WAIT: signals the caller to
        // queue the outgoing message instead of sending it.
        // For E26 (disconnect request) in OPEN_WAIT (Style 2): also queues.
        SpecAction::A11 => {
            buf.push(TlAction::QueueEvent { source: addr });
        }

        // A12: Initiate outgoing connection
        // connection_address = dest; SeqNoSend=0; SeqNoRcv=0;
        // Send T_Connect to remote; start conn timer
        SpecAction::A12 => {
            conn.remote_addr = addr;
            conn.seq_no_send = 0;
            conn.seq_no_recv = 0;
            conn.rep_count = 0;
            buf.push(TlAction::SendConnect { dest: addr });
            buf.push(TlAction::StartConnTimer);
        }

        // A13: Confirm connection success
        // Send T_Connect.con(ok) to user
        SpecAction::A13 => {
            buf.push(TlAction::ConfirmConnect { dest: conn.remote_addr, success: true });
        }

        // A14: Cancel connection + disconnect + confirm disconnect
        // Send T_Disconnect to remote; stop timers; send T_Disconnect.con to user
        SpecAction::A14 => {
            buf.push(TlAction::SendDisconnect { dest: conn.remote_addr });
            buf.push(TlAction::StopAckTimer);
            buf.push(TlAction::StopConnTimer);
            buf.push(TlAction::ConfirmDisconnect { dest: conn.remote_addr });
        }

        // A14b: Cancel connection + disconnect (no user indication, Style 2)
        // Send T_Disconnect to remote; stop timers
        SpecAction::A14b => {
            buf.push(TlAction::SendDisconnect { dest: conn.remote_addr });
            buf.push(TlAction::StopAckTimer);
            buf.push(TlAction::StopConnTimer);
        }

        // A15: Confirm disconnect (no connection existed)
        // Stop timers; send T_Disconnect.con to user
        SpecAction::A15 => {
            buf.push(TlAction::StopAckTimer);
            buf.push(TlAction::StopConnTimer);
            buf.push(TlAction::ConfirmDisconnect { dest: conn.remote_addr });
        }

        SpecAction::DoesNotExist => {
            // Event does not exist in this style — do nothing
        }
    }

    buf
}

// ============================================================================
// Transition Tables
// ============================================================================
//
// Each table is a flat array indexed by [event][state].
// Transcribed directly from the spec PDF (section 5.4).
//
// Table layout: STYLE_X_TABLE[event_index][state_index]
// where state_index = ConnectionState as u8 (0=Closed, 1=OpenIdle, 2=OpenWait, 3=Connecting)

use ConnectionState::*;
use SpecAction::*;

// Shorthand
const fn t(s: ConnectionState, a: SpecAction) -> Transition {
    Transition::new(s, a)
}

/// "Does not exist" — for cells that can't be reached (e.g., Connecting in 3-state machines)
const DNE: Transition = t(Closed, DoesNotExist);

// ─────────────────────────────────────────────────────────────────────────────
// Style 1 (spec 5.4.1) — 3 states, strict error handling
//
// E00 has two rows in the spec: same-source and different-source.
// In CLOSED, there's no connection_address, so we use the first row
// (same-source → OPEN_IDLE/A1). The second row (different-source →
// CLOSED/A10) applies to OPEN_IDLE/OPEN_WAIT when source != CA,
// which is classified as E01 by classify_event.
// ─────────────────────────────────────────────────────────────────────────────
#[rustfmt::skip]
static STYLE_1_TABLE: [[Transition; ConnectionState::COUNT]; SpecEvent::COUNT] = [
    //          CLOSED              OPEN_IDLE           OPEN_WAIT           CONNECTING
    /* E00  */ [t(OpenIdle, A1),    t(Closed,   A6),    t(Closed,   A6),    DNE],
    /* E01  */ [t(OpenIdle, A1),    t(OpenIdle, A10),   t(OpenWait, A10),   DNE],
    /* E02  */ [t(Closed,   A0),    t(Closed,   A5),    t(Closed,   A5),    DNE],
    /* E03  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E04  */ [t(Closed,   A10),   t(OpenIdle, A2),    t(OpenWait, A2),    DNE],
    /* E05  */ [t(Closed,   A10),   t(OpenIdle, A3),    t(OpenWait, A3),    DNE],
    /* E06  */ [t(Closed,   A10),   t(OpenIdle, A4),    t(OpenWait, A4),    DNE],
    /* E07  */ [t(Closed,   A10),   t(OpenIdle, A10),   t(OpenWait, A10),   DNE],
    /* E08  */ [t(Closed,   A10),   t(Closed,   A6),    t(OpenIdle, A8),    DNE],
    /* E09  */ [t(Closed,   A10),   t(Closed,   A6),    t(Closed,   A6),    DNE],
    /* E10  */ [t(Closed,   A10),   t(OpenIdle, A10),   t(OpenWait, A10),   DNE],
    /* E11  */ [t(Closed,   A10),   t(Closed,   A6),    t(Closed,   A6),    DNE],
    /* E11b */ [DNE,                DNE,                DNE,                DNE],
    /* E12  */ [t(Closed,   A10),   t(Closed,   A6),    t(OpenWait, A9),    DNE],
    /* E13  */ [t(Closed,   A10),   t(Closed,   A6),    t(Closed,   A6),    DNE],
    /* E14  */ [t(Closed,   A10),   t(OpenIdle, A10),   t(OpenWait, A10),   DNE],
    /* E15  */ [t(Closed,   A5),    t(OpenWait, A7),    t(Closed,   A6),    DNE],
    /* E16  */ [t(Closed,   A0),    t(Closed,   A6),    t(Closed,   A6),    DNE],
    /* E17  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A9),    DNE],
    /* E18  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(Closed,   A6),    DNE],
    /* E19  */ [t(Closed,   A0),    t(OpenIdle, A13),   t(OpenWait, A13),   DNE],
    /* E20  */ [t(Closed,   A0),    t(Closed,   A5),    t(Closed,   A5),    DNE],
    /* E21  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E22  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E23  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E24  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E25  */ [t(OpenIdle, A12),   t(Closed,   A6),    t(Closed,   A6),    DNE],
    /* E26  */ [t(Closed,   A15),   t(Closed,   A14),   t(Closed,   A14),   DNE],
    /* E27  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
];

// ─────────────────────────────────────────────────────────────────────────────
// Style 2 (spec 5.4.2) — 3 states, lenient error handling
// ─────────────────────────────────────────────────────────────────────────────
#[rustfmt::skip]
static STYLE_2_TABLE: [[Transition; ConnectionState::COUNT]; SpecEvent::COUNT] = [
    //          CLOSED              OPEN_IDLE           OPEN_WAIT           CONNECTING
    /* E00  */ [t(OpenIdle, A1),    t(OpenIdle, A0),    t(OpenIdle, A0),    DNE],
    /* E01  */ [t(OpenIdle, A1),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E02  */ [t(Closed,   A0),    t(Closed,   A5),    t(Closed,   A5),    DNE],
    /* E03  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E04  */ [t(Closed,   A0),    t(OpenIdle, A2),    t(OpenWait, A2),    DNE],
    /* E05  */ [t(Closed,   A0),    t(OpenIdle, A3),    t(OpenWait, A3),    DNE],
    /* E06  */ [t(Closed,   A0),    t(OpenIdle, A4),    t(OpenWait, A4),    DNE],
    /* E07  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E08  */ [t(Closed,   A0),    t(Closed,   A6),    t(OpenIdle, A8b),   DNE],
    /* E09  */ [t(Closed,   A0),    t(Closed,   A6),    t(OpenWait, A0),    DNE],
    /* E10  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E11  */ [t(Closed,   A0),    t(Closed,   A6),    t(OpenWait, A0),    DNE],
    /* E11b */ [DNE,                DNE,                DNE,                DNE],
    /* E12  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A9),    DNE],
    /* E13  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(Closed,   A6),    DNE],
    /* E14  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E15  */ [t(Closed,   A0),    t(OpenWait, A7),    t(OpenWait, A11),   DNE],
    /* E16  */ [t(Closed,   A0),    t(Closed,   A6),    t(Closed,   A6),    DNE],
    /* E17  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A9),    DNE],
    /* E18  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(Closed,   A6),    DNE],
    /* E19  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E20  */ [t(Closed,   A0),    t(Closed,   A5),    t(Closed,   A5),    DNE],
    /* E21  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E22  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E23  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E24  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E25  */ [t(OpenIdle, A12),   t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E26  */ [t(Closed,   A0),    t(Closed,   A14b),  t(OpenWait, A11),   DNE],
    /* E27  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
];

// ─────────────────────────────────────────────────────────────────────────────
// Style 3 (spec 5.4.3) — 4 states, includes CONNECTING
// ─────────────────────────────────────────────────────────────────────────────
#[rustfmt::skip]
static STYLE_3_TABLE: [[Transition; ConnectionState::COUNT]; SpecEvent::COUNT] = [
    //          CLOSED              OPEN_IDLE           OPEN_WAIT           CONNECTING
    /* E00  */ [t(OpenIdle, A1),    t(OpenIdle, A0),    t(OpenWait, A0),    t(Connecting, A0)],
    /* E01  */ [t(OpenIdle, A1),    t(OpenIdle, A10),   t(OpenWait, A10),   t(Connecting, A10)],
    /* E02  */ [t(Closed,   A0),    t(Closed,   A5),    t(Closed,   A5),    t(Closed,     A5)],
    /* E03  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    t(Connecting, A0)],
    /* E04  */ [t(Closed,   A0),    t(OpenIdle, A2),    t(OpenWait, A2),    t(Closed,     A6)],
    /* E05  */ [t(Closed,   A0),    t(OpenIdle, A3),    t(OpenWait, A3),    t(Connecting, A3)],
    /* E06  */ [t(Closed,   A0),    t(OpenIdle, A4),    t(OpenWait, A4),    t(Connecting, A6)],
    /* E07  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    t(Connecting, A10)],
    /* E08  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenIdle, A8),    t(Closed,     A6)],
    /* E09  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(Closed,   A6),    t(Closed,     A6)],
    /* E10  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    t(Connecting, A10)],
    /* E11  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    t(Closed,     A6)],
    /* E11b */ [DNE,                DNE,                DNE,                DNE],
    /* E12  */ [t(Closed,   A0),    t(Closed,   A6),    t(OpenWait, A9),    t(Closed,     A6)],
    /* E13  */ [t(Closed,   A0),    t(Closed,   A6),    t(Closed,   A6),    t(Closed,     A6)],
    /* E14  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    t(Connecting, A10)],
    /* E15  */ [t(Closed,   A0),    t(OpenWait, A7),    t(OpenWait, A11),   t(Connecting, A11)],
    /* E16  */ [t(Closed,   A0),    t(Closed,   A6),    t(Closed,   A6),    t(Closed,     A6)],
    /* E17  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A9),    t(Connecting, A0)],
    /* E18  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(Closed,   A6),    t(Connecting, A0)],
    /* E19  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    t(OpenIdle,   A13)],
    /* E20  */ [t(Closed,   A0),    t(Closed,   A5),    t(OpenWait, A0),    t(Closed,     A5)],
    /* E21  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    t(Connecting, A0)],
    /* E22  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    t(Connecting, A0)],
    /* E23  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    t(Connecting, A0)],
    /* E24  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    t(Connecting, A0)],
    /* E25  */ [t(Connecting, A12), t(Closed,   A6),    t(Closed,   A6),    t(Closed,     A6)],
    /* E26  */ [t(Closed,   A15),   t(Closed,   A14),   t(Closed,   A14),   t(Closed,     A14)],
    /* E27  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    t(Connecting, A0)],
];

// ─────────────────────────────────────────────────────────────────────────────
// Style 1 Rationalised (spec 5.4.4.3) — 3 states, minimal error handling
//
// Key differences from Style 1:
// - E06 OPEN_IDLE/OPEN_WAIT: CLOSED/A6 (disconnect on wrong seq, no NACK)
// - E11b replaces E11 (no seq check on NACK)
// - E12/E13/E17/E18/E24: DoesNotExist
// - E15 OPEN_WAIT: OPEN_WAIT/A11 (queue instead of disconnect)
// ─────────────────────────────────────────────────────────────────────────────
#[rustfmt::skip]
static STYLE_1R_TABLE: [[Transition; ConnectionState::COUNT]; SpecEvent::COUNT] = [
    //          CLOSED              OPEN_IDLE           OPEN_WAIT           CONNECTING
    /* E00  */ [t(OpenIdle, A1),    t(Closed,   A6),    t(Closed,   A6),    DNE],
    /* E01  */ [t(OpenIdle, A1),    t(OpenIdle, A10),   t(OpenWait, A10),   DNE],
    /* E02  */ [t(Closed,   A0),    t(Closed,   A5),    t(Closed,   A5),    DNE],
    /* E03  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E04  */ [t(Closed,   A10),   t(OpenIdle, A2),    t(OpenWait, A2),    DNE],
    /* E05  */ [t(Closed,   A10),   t(OpenIdle, A3),    t(OpenWait, A3),    DNE],
    /* E06  */ [t(Closed,   A10),   t(Closed,   A6),    t(Closed,   A6),    DNE],
    /* E07  */ [t(Closed,   A10),   t(OpenIdle, A10),   t(OpenWait, A10),   DNE],
    /* E08  */ [t(Closed,   A10),   t(Closed,   A6),    t(OpenIdle, A8),    DNE],
    /* E09  */ [t(Closed,   A10),   t(Closed,   A6),    t(Closed,   A6),    DNE],
    /* E10  */ [t(Closed,   A10),   t(OpenIdle, A10),   t(OpenWait, A10),   DNE],
    /* E11  */ [DNE,                DNE,                DNE,                DNE],
    /* E11b */ [t(Closed,   A10),   t(Closed,   A6),    t(Closed,   A6),    DNE],
    /* E12  */ [DNE,                DNE,                DNE,                DNE],
    /* E13  */ [DNE,                DNE,                DNE,                DNE],
    /* E14  */ [t(Closed,   A10),   t(OpenIdle, A10),   t(OpenWait, A10),   DNE],
    /* E15  */ [t(Closed,   A5),    t(OpenWait, A7),    t(OpenWait, A11),   DNE],
    /* E16  */ [t(Closed,   A0),    t(Closed,   A6),    t(Closed,   A6),    DNE],
    /* E17  */ [DNE,                DNE,                DNE,                DNE],
    /* E18  */ [DNE,                DNE,                DNE,                DNE],
    /* E19  */ [t(Closed,   A0),    t(OpenIdle, A13),   t(OpenWait, A13),   DNE],
    /* E20  */ [t(Closed,   A0),    t(Closed,   A5),    t(Closed,   A5),    DNE],
    /* E21  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E22  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E23  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
    /* E24  */ [DNE,                DNE,                DNE,                DNE],
    /* E25  */ [t(OpenIdle, A12),   t(Closed,   A6),    t(Closed,   A6),    DNE],
    /* E26  */ [t(Closed,   A15),   t(Closed,   A14),   t(Closed,   A14),   DNE],
    /* E27  */ [t(Closed,   A0),    t(OpenIdle, A0),    t(OpenWait, A0),    DNE],
];

// ============================================================================
// Table Lookup
// ============================================================================

impl TlStyle {
    /// Look up the transition for a given state and event.
    fn lookup(self, state: ConnectionState, event: SpecEvent) -> Transition {
        let table = match self {
            TlStyle::Style1 => &STYLE_1_TABLE,
            TlStyle::Style2 => &STYLE_2_TABLE,
            TlStyle::Style3 => &STYLE_3_TABLE,
            TlStyle::Style1Rationalised => &STYLE_1R_TABLE,
        };
        table[event as usize][state as usize]
    }
}

// ============================================================================
// Public API: process_event
// ============================================================================

/// Process an event for a connection and return the actions to perform.
///
/// This is a pure function that takes the current connection state, an event,
/// and the selected state machine style. It updates the connection state and
/// returns a list of actions to be performed by the transport layer.
///
/// # Arguments
/// * `conn` - Mutable reference to the connection state
/// * `event` - The event to process
/// * `style` - The state machine style to use
///
/// # Returns
/// A buffer of actions to be performed
pub fn process_event(conn: &mut Connection, event: TlEvent, style: TlStyle) -> ProcessResult {
    let ctx = EventContext::from_event(&event);

    // Classify the raw event into a spec-level event
    let spec_event = match classify_event(conn, &event, style) {
        Some(e) => e,
        None => return ProcessResult::noop(),
    };

    // Look up the transition
    let transition = style.lookup(conn.state, spec_event);

    // "Does not exist" events produce no actions
    if transition.action == SpecAction::DoesNotExist {
        return ProcessResult::noop();
    }

    // Execute the action (mutates conn fields like seq numbers, rep_count, etc.)
    let actions = execute_action(transition.action, conn, &ctx);

    // Return actions and deferred state transition. The caller must
    // execute actions FIRST, then call apply_state(). This ordering
    // matters because action execution (e.g. stopping timers, clearing
    // buffers) looks up the connection by address, and Closed connections
    // are filtered out of those lookups.
    ProcessResult { actions, next_state: Some(transition.next_state) }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn new_connection() -> Connection {
        Connection::new()
    }

    /// Process an event and immediately apply the state transition.
    ///
    /// This is a test convenience — in production, the caller executes
    /// actions before applying state (to avoid the find_any/Closed issue).
    fn process(conn: &mut Connection, event: TlEvent, style: TlStyle) -> ActionBuffer {
        let ProcessResult { actions, next_state } = process_event(conn, event, style);
        if let Some(s) = next_state {
            conn.state = s;
        }
        actions
    }

    fn connect(conn: &mut Connection, source: IndividualAddress, style: TlStyle) {
        process(conn, TlEvent::ReceivedConnect { source }, style);
        assert_eq!(conn.state, ConnectionState::OpenIdle);
        assert_eq!(conn.remote_addr, source);
    }

    fn send_data(conn: &mut Connection, dest: IndividualAddress, style: TlStyle) {
        process(conn, TlEvent::RequestData { dest }, style);
        assert_eq!(conn.state, ConnectionState::OpenWait);
    }

    // =====================================================================
    // Style 1 tests
    // =====================================================================

    #[test]
    fn style1_incoming_connect() {
        let mut conn = new_connection();
        let source = IndividualAddress::new(1, 2, 3);

        let actions = process(&mut conn, TlEvent::ReceivedConnect { source }, TlStyle::Style1);

        assert_eq!(conn.state, ConnectionState::OpenIdle);
        assert_eq!(conn.remote_addr, source);
        assert_eq!(actions.len(), 2);

        let v: Vec<_> = actions.iter().collect();
        assert_eq!(v[0], TlAction::StartConnTimer);
        assert_eq!(v[1], TlAction::IndicateConnected { source });
    }

    #[test]
    fn style1_receive_data_correct_seq() {
        let mut conn = new_connection();
        let source = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, source, TlStyle::Style1);

        let actions = process(&mut conn, TlEvent::ReceivedData { source, seq_no: 0 }, TlStyle::Style1);

        assert_eq!(conn.seq_no_recv, 1);
        assert_eq!(actions.len(), 3);

        let v: Vec<_> = actions.iter().collect();
        assert_eq!(v[0], TlAction::SendAck { dest: source, seq_no: 0 });
        assert_eq!(v[1], TlAction::IndicateData { source });
        assert_eq!(v[2], TlAction::StartConnTimer);
    }

    #[test]
    fn style1_send_data_and_ack() {
        let mut conn = new_connection();
        let dest = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, dest, TlStyle::Style1);

        let actions = process(&mut conn, TlEvent::RequestData { dest }, TlStyle::Style1);
        assert_eq!(conn.state, ConnectionState::OpenWait);

        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::StorePendingMessage));
        assert!(v.contains(&TlAction::SendData { dest }));
        assert!(v.contains(&TlAction::StartAckTimer));

        // Receive ACK
        let actions = process(&mut conn, TlEvent::ReceivedAck { source: dest, seq_no: 0 }, TlStyle::Style1);

        assert_eq!(conn.state, ConnectionState::OpenIdle);
        assert_eq!(conn.seq_no_send, 1);

        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::StopAckTimer));
        assert!(v.contains(&TlAction::ClearPendingMessage));
        assert!(v.contains(&TlAction::ConfirmData { dest, success: true }));
        assert!(v.contains(&TlAction::StartConnTimer));
    }

    #[test]
    fn style1_ack_timeout_retransmit() {
        let mut conn = new_connection();
        let dest = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, dest, TlStyle::Style1);
        send_data(&mut conn, dest, TlStyle::Style1);

        let actions = process(&mut conn, TlEvent::AckTimeout, TlStyle::Style1);
        assert_eq!(conn.state, ConnectionState::OpenWait);
        assert_eq!(conn.rep_count, 1);

        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::Retransmit { dest }));
        assert!(v.contains(&TlAction::StartAckTimer));
    }

    #[test]
    fn style1_max_retries_disconnect() {
        let mut conn = new_connection();
        let dest = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, dest, TlStyle::Style1);
        send_data(&mut conn, dest, TlStyle::Style1);

        // 3 retransmits (E17), then 4th timeout hits max (E18)
        process(&mut conn, TlEvent::AckTimeout, TlStyle::Style1);
        process(&mut conn, TlEvent::AckTimeout, TlStyle::Style1);
        process(&mut conn, TlEvent::AckTimeout, TlStyle::Style1);
        let actions = process(&mut conn, TlEvent::AckTimeout, TlStyle::Style1);

        assert_eq!(conn.state, ConnectionState::Closed);

        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::SendDisconnect { dest }));
        assert!(v.contains(&TlAction::IndicateDisconnected { source: dest }));
    }

    #[test]
    fn style1_wrong_seq_nack() {
        let mut conn = new_connection();
        let source = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, source, TlStyle::Style1);

        // Receive data with wrong seq (expected 0, send 5)
        let actions = process(&mut conn, TlEvent::ReceivedData { source, seq_no: 5 }, TlStyle::Style1);

        // Style 1 sends NACK (A4), stays in OPEN_IDLE
        assert_eq!(conn.state, ConnectionState::OpenIdle);
        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::SendNack { dest: source, seq_no: 5 }));
        assert!(v.contains(&TlAction::StartConnTimer));
    }

    #[test]
    fn style1_ack_in_open_idle_disconnects() {
        let mut conn = new_connection();
        let source = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, source, TlStyle::Style1);

        // Unexpected ACK in OPEN_IDLE with correct seq → E08 → CLOSED/A6
        let actions = process(&mut conn, TlEvent::ReceivedAck { source, seq_no: 0 }, TlStyle::Style1);

        assert_eq!(conn.state, ConnectionState::Closed);
        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::SendDisconnect { dest: source }));
        assert!(v.contains(&TlAction::IndicateDisconnected { source }));
    }

    #[test]
    fn style1_reconnect_same_source_disconnects() {
        let mut conn = new_connection();
        let source = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, source, TlStyle::Style1);

        // Same source reconnects in OPEN_IDLE → E00 → CLOSED/A6
        let actions = process(&mut conn, TlEvent::ReceivedConnect { source }, TlStyle::Style1);

        assert_eq!(conn.state, ConnectionState::Closed);
        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::SendDisconnect { dest: source }));
    }

    #[test]
    fn style1_different_source_connect_rejected() {
        let mut conn = new_connection();
        let source = IndividualAddress::new(1, 2, 3);
        let other = IndividualAddress::new(4, 5, 6);
        connect(&mut conn, source, TlStyle::Style1);

        // Different source tries to connect → E01 → A10 (reject)
        let actions = process(&mut conn, TlEvent::ReceivedConnect { source: other }, TlStyle::Style1);

        assert_eq!(conn.state, ConnectionState::OpenIdle);
        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::SendDisconnect { dest: other }));
    }

    // =====================================================================
    // Style 1R tests
    // =====================================================================

    #[test]
    fn style1r_wrong_seq_disconnects() {
        let mut conn = new_connection();
        let source = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, source, TlStyle::Style1Rationalised);

        // Wrong seq in OPEN_IDLE → E06 → CLOSED/A6 (Style 1R disconnects, no NACK)
        let actions = process(&mut conn, TlEvent::ReceivedData { source, seq_no: 5 }, TlStyle::Style1Rationalised);

        assert_eq!(conn.state, ConnectionState::Closed);
        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::SendDisconnect { dest: source }));
        // Should NOT contain any NACK
        assert!(!v.iter().any(|a| matches!(a, TlAction::SendNack { .. })));
    }

    #[test]
    fn style1r_ack_timeout_ignored() {
        let mut conn = new_connection();
        let dest = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, dest, TlStyle::Style1Rationalised);
        send_data(&mut conn, dest, TlStyle::Style1Rationalised);

        // ACK timeout doesn't exist in Style 1R
        let result = process_event(&mut conn, TlEvent::AckTimeout, TlStyle::Style1Rationalised);
        assert!(result.actions.is_empty());
        assert!(result.next_state.is_none());
        // State unchanged — still in OPEN_WAIT
        assert_eq!(conn.state, ConnectionState::OpenWait);
    }

    #[test]
    fn style1r_data_in_open_wait_queued() {
        let mut conn = new_connection();
        let source = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, source, TlStyle::Style1Rationalised);
        send_data(&mut conn, source, TlStyle::Style1Rationalised);

        // Receive data in OPEN_WAIT → E15 → A11 (queue, not disconnect)
        // Wait — E15 is RequestData. Let me re-check: incoming data with correct seq in
        // OPEN_WAIT is E04 → A2 (ACK + indicate data) for Style 1R. But the spec says
        // Style 1R E15 OPEN_WAIT → A11. E15 is the *request* to send data, not received data.
        // The difference is: E04 (received data, correct seq) OPEN_WAIT → A2 in 1R.
        // E15 (request to send) OPEN_WAIT → A11 (queue) in 1R.
        let actions = process(&mut conn, TlEvent::RequestData { dest: source }, TlStyle::Style1Rationalised);

        assert_eq!(conn.state, ConnectionState::OpenWait);
        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::QueueEvent { source }));
    }

    // =====================================================================
    // Style 2 tests
    // =====================================================================

    #[test]
    fn style2_reconnect_same_source_ignored() {
        let mut conn = new_connection();
        let source = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, source, TlStyle::Style2);

        // Same source reconnects → E00 OPEN_IDLE → A0 (do nothing, stay connected)
        let actions = process(&mut conn, TlEvent::ReceivedConnect { source }, TlStyle::Style2);

        assert_eq!(conn.state, ConnectionState::OpenIdle);
        assert!(actions.is_empty());
    }

    #[test]
    fn style2_unexpected_ack_ignored() {
        let mut conn = new_connection();
        let source = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, source, TlStyle::Style2);

        // ACK with correct seq in OPEN_IDLE → E08 → CLOSED/A6 in Style 2 too
        // Wait, checking the table: Style 2 E08 OPEN_IDLE = CLOSED/A6. Same as Style 1.
        let actions = process(&mut conn, TlEvent::ReceivedAck { source, seq_no: 0 }, TlStyle::Style2);

        assert_eq!(conn.state, ConnectionState::Closed);
        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::SendDisconnect { dest: source }));
    }

    #[test]
    fn style2_ack_in_open_wait_no_confirm() {
        let mut conn = new_connection();
        let dest = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, dest, TlStyle::Style2);
        send_data(&mut conn, dest, TlStyle::Style2);

        // ACK with correct seq in OPEN_WAIT → E08 → A8b (no data confirm)
        let actions = process(&mut conn, TlEvent::ReceivedAck { source: dest, seq_no: 0 }, TlStyle::Style2);

        assert_eq!(conn.state, ConnectionState::OpenIdle);
        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::StopAckTimer));
        assert!(v.contains(&TlAction::ClearPendingMessage));
        assert!(v.contains(&TlAction::StartConnTimer));
        // Should NOT contain ConfirmData
        assert!(!v.iter().any(|a| matches!(a, TlAction::ConfirmData { .. })));
    }

    #[test]
    fn style2_nack_in_open_wait_ignored() {
        let mut conn = new_connection();
        let dest = IndividualAddress::new(1, 2, 3);
        connect(&mut conn, dest, TlStyle::Style2);
        send_data(&mut conn, dest, TlStyle::Style2);

        // NACK with wrong seq in OPEN_WAIT → E11 → A0 (ignore, Style 2)
        let actions = process(&mut conn, TlEvent::ReceivedNack { source: dest, seq_no: 15 }, TlStyle::Style2);

        assert_eq!(conn.state, ConnectionState::OpenWait);
        assert!(actions.is_empty());
    }

    // =====================================================================
    // Style 3 tests
    // =====================================================================

    #[test]
    fn style3_outgoing_connect_goes_to_connecting() {
        let mut conn = new_connection();
        let dest = IndividualAddress::new(1, 2, 3);

        let actions = process(&mut conn, TlEvent::RequestConnect { dest }, TlStyle::Style3);

        assert_eq!(conn.state, ConnectionState::Connecting);
        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::SendConnect { dest }));
        assert!(v.contains(&TlAction::StartConnTimer));
    }

    #[test]
    fn style3_connect_confirm_ok_transitions_to_open_idle() {
        let mut conn = new_connection();
        let dest = IndividualAddress::new(1, 2, 3);

        process(&mut conn, TlEvent::RequestConnect { dest }, TlStyle::Style3);
        assert_eq!(conn.state, ConnectionState::Connecting);

        // E19 in CONNECTING → OPEN_IDLE/A13
        let actions = process(&mut conn, TlEvent::ConnectConfirm { success: true }, TlStyle::Style3);

        assert_eq!(conn.state, ConnectionState::OpenIdle);
        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::ConfirmConnect { dest, success: true }));
    }

    #[test]
    fn style3_connect_confirm_fail_transitions_to_closed() {
        let mut conn = new_connection();
        let dest = IndividualAddress::new(1, 2, 3);

        process(&mut conn, TlEvent::RequestConnect { dest }, TlStyle::Style3);
        assert_eq!(conn.state, ConnectionState::Connecting);

        // E20 in CONNECTING → CLOSED/A5
        let actions = process(&mut conn, TlEvent::ConnectConfirm { success: false }, TlStyle::Style3);

        assert_eq!(conn.state, ConnectionState::Closed);
        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::IndicateDisconnected { source: dest }));
    }

    #[test]
    fn style3_connection_timeout_in_connecting() {
        let mut conn = new_connection();
        let dest = IndividualAddress::new(1, 2, 3);

        process(&mut conn, TlEvent::RequestConnect { dest }, TlStyle::Style3);
        assert_eq!(conn.state, ConnectionState::Connecting);

        // E16 in CONNECTING → CLOSED/A6
        let actions = process(&mut conn, TlEvent::ConnectionTimeout, TlStyle::Style3);

        assert_eq!(conn.state, ConnectionState::Closed);
        let v: Vec<_> = actions.iter().collect();
        assert!(v.contains(&TlAction::SendDisconnect { dest }));
    }

    // =====================================================================
    // Cross-style: connection timeout in OPEN_IDLE
    // =====================================================================

    #[test]
    fn connection_timeout_disconnects_all_styles() {
        for style in [TlStyle::Style1, TlStyle::Style2, TlStyle::Style3, TlStyle::Style1Rationalised] {
            let mut conn = new_connection();
            let source = IndividualAddress::new(1, 2, 3);
            connect(&mut conn, source, style);

            let actions = process(&mut conn, TlEvent::ConnectionTimeout, style);
            assert_eq!(conn.state, ConnectionState::Closed, "style: {:?}", style);

            let v: Vec<_> = actions.iter().collect();
            assert!(v.contains(&TlAction::SendDisconnect { dest: source }), "style: {:?}", style);
        }
    }

    // =====================================================================
    // Cross-style: disconnect from remote
    // =====================================================================

    #[test]
    fn remote_disconnect_all_styles() {
        for style in [TlStyle::Style1, TlStyle::Style2, TlStyle::Style3, TlStyle::Style1Rationalised] {
            let mut conn = new_connection();
            let source = IndividualAddress::new(1, 2, 3);
            connect(&mut conn, source, style);

            let actions = process(&mut conn, TlEvent::ReceivedDisconnect { source }, style);
            assert_eq!(conn.state, ConnectionState::Closed, "style: {:?}", style);

            let v: Vec<_> = actions.iter().collect();
            assert!(v.contains(&TlAction::IndicateDisconnected { source }), "style: {:?}", style);
        }
    }
}
