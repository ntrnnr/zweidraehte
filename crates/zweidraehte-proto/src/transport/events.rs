//! Event and action vocabulary of the transport layer state machine.

use crate::address::IndividualAddress;

use super::connection_core::{ConnectionCore, ConnectionState};

// ============================================================================
// Configuration
// ============================================================================

/// Maximum number of retransmissions before disconnecting.
/// Per KNX spec section 4, the device retransmits 3 times (4 total
/// transmissions) before giving up and disconnecting.
pub const MAX_REPETITIONS: u8 = 3;

// ============================================================================
// Transport Layer Style
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
/// as well, so every System B device here uses `Style3`. A management
/// client opening connections to remote devices must also run `Style3` —
/// it is the only style with the CONNECTING state.
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
    /// pick `Style3` cannot actually initiate connections; the device
    /// stack's runner rejects that combination at startup.
    pub const fn supports_outgoing_connections(self) -> bool {
        matches!(self, Self::Style3)
    }
}

// ============================================================================
// Events
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
// Actions
// ============================================================================

/// Actions to be performed by the transport layer after processing an event.
///
/// The embedding runtime (device stack or client) is responsible for
/// executing these.
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
    /// that the message should be queued rather than sent immediately.
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

// ============================================================================
// Process Result
// ============================================================================

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
    pub(super) fn noop() -> Self {
        Self { actions: ActionBuffer::new(), next_state: None }
    }

    /// Apply the state transition to the connection.
    ///
    /// Must be called AFTER all actions have been executed.
    pub fn apply_state<C: ConnectionCore>(self, conn: &mut C) {
        if let Some(next_state) = self.next_state {
            conn.set_state(next_state);
        }
    }
}
