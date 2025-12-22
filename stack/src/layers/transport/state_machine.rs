//! State machine logic for connection-oriented transport layer
//!
//! This module contains the pure state machine logic for handling
//! connection-oriented transport layer communication per KNX spec 03/03/04.
//!
//! The state machine is separated from async I/O to make it testable
//! and to keep the logic clean.

use crate::address::IndividualAddress;

use super::connection::{Connection, ConnectionState};

// ============================================================================
// Configuration
// ============================================================================

/// Maximum number of retransmissions before disconnecting.
/// Per KNX spec, the device retransmits 3 times (4 total transmissions)
/// before giving up and disconnecting.
pub const MAX_REPETITIONS: u8 = 3;

// ============================================================================
// Events
// ============================================================================

/// Events that can occur in the transport layer state machine
///
/// These events are derived from incoming messages (from network layer),
/// outgoing requests (from application layer), and timer events.
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
    /// Application wants to establish a connection
    RequestConnect { dest: IndividualAddress },

    /// Application wants to close a connection
    RequestDisconnect { dest: IndividualAddress },

    /// Application wants to send data on a connection
    RequestData { dest: IndividualAddress },

    // ─────────────────────────────────────────────────────────────────────────
    // Timer events
    // ─────────────────────────────────────────────────────────────────────────
    /// ACK timeout expired (in OPEN_WAIT state)
    AckTimeout,

    /// Connection timeout expired (in OPEN_IDLE state with no activity)
    ConnectionTimeout,
}

// ============================================================================
// Actions
// ============================================================================

/// Actions to be performed by the transport layer
///
/// These actions are returned by the state machine after processing an event.
/// The transport layer is responsible for executing these actions.
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
    /// Indicate that a connection has been established (incoming)
    IndicateConnected { source: IndividualAddress },

    /// Indicate that a connection has been closed
    IndicateDisconnected { source: IndividualAddress },

    /// Indicate that data has been received
    /// (caller should forward the actual message)
    IndicateData { source: IndividualAddress },

    /// Queue incoming data for later delivery (when in OPEN_WAIT)
    /// The message will be stored and delivered when transitioning to OPEN_IDLE
    QueueIncomingData { source: IndividualAddress },

    /// Deliver any queued incoming data to the application layer
    /// Called when transitioning from OPEN_WAIT to OPEN_IDLE
    DeliverQueuedData { source: IndividualAddress },

    /// Confirm connection request success/failure
    ConfirmConnect { dest: IndividualAddress, success: bool },

    /// Confirm data transmission success/failure
    ConfirmData { dest: IndividualAddress, success: bool },

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
}

// ============================================================================
// Action Buffer
// ============================================================================

/// A small fixed-size buffer for actions returned by the state machine
///
/// Most state transitions produce 1-4 actions, so we use a small
/// fixed-size array to avoid heap allocation.
#[derive(Debug)]
pub struct ActionBuffer {
    actions: [Option<TlAction>; 5],
    count: usize,
}

impl ActionBuffer {
    /// Create a new empty action buffer
    pub const fn new() -> Self {
        Self { actions: [None; 5], count: 0 }
    }

    /// Add an action to the buffer
    ///
    /// Returns `true` if the action was added, `false` if the buffer is full.
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
// State Machine
// ============================================================================

/// Process an event for a connection and return the actions to perform
///
/// This is a pure function that takes the current connection state and
/// an event, updates the connection state, and returns a list of actions
/// to be performed by the transport layer.
///
/// # Arguments
/// * `conn` - Mutable reference to the connection state
/// * `event` - The event to process
///
/// # Returns
/// A buffer of actions to be performed
pub fn process_event(conn: &mut Connection, event: TlEvent) -> ActionBuffer {
    let mut actions = ActionBuffer::new();

    match (&conn.state, event) {
        // =====================================================================
        // CLOSED state transitions
        // =====================================================================

        // Remote device initiates connection
        (ConnectionState::Closed, TlEvent::ReceivedConnect { source }) => {
            conn.state = ConnectionState::OpenIdle;
            conn.remote_addr = source;
            conn.seq_no_send = 0;
            conn.seq_no_recv = 0;
            conn.rep_count = 0;
            actions.push(TlAction::StartConnTimer);
            actions.push(TlAction::IndicateConnected { source });
        }

        // We want to initiate a connection
        (ConnectionState::Closed, TlEvent::RequestConnect { dest }) => {
            conn.state = ConnectionState::OpenIdle; // For now, assume immediate success
            conn.remote_addr = dest;
            conn.seq_no_send = 0;
            conn.seq_no_recv = 0;
            conn.rep_count = 0;
            actions.push(TlAction::StartConnTimer);
            actions.push(TlAction::SendConnect { dest });
            // Note: For proper implementation, we'd go to a "Connecting" state
            // and wait for an implicit ACK. KNX T_Connect doesn't have an explicit
            // response - success is implied if communication works.
        }

        // Ignore other events in closed state
        (ConnectionState::Closed, _) => {}

        // =====================================================================
        // OPEN_IDLE state transitions
        // =====================================================================

        // Received numbered data with correct sequence number
        (ConnectionState::OpenIdle, TlEvent::ReceivedData { source, seq_no })
            if source == conn.remote_addr && seq_no == conn.seq_no_recv =>
        {
            conn.inc_seq_recv();
            actions.push(TlAction::StartConnTimer); // Reset connection timeout
            actions.push(TlAction::SendAck { dest: source, seq_no });
            actions.push(TlAction::IndicateData { source });
        }

        // Received numbered data with previous sequence number (repeated frame)
        (ConnectionState::OpenIdle, TlEvent::ReceivedData { source, seq_no })
            if source == conn.remote_addr && seq_no == conn.prev_seq_recv() =>
        {
            // Just send ACK again, don't forward duplicate data
            actions.push(TlAction::StartConnTimer); // Reset connection timeout
            actions.push(TlAction::SendAck { dest: source, seq_no });
        }

        // Received numbered data with wrong sequence number
        (ConnectionState::OpenIdle, TlEvent::ReceivedData { source, seq_no }) if source == conn.remote_addr => {
            // Wrong sequence number - send NACK but stay connected
            // Per KNX spec, wrong sequence number in OPEN_IDLE results in NACK
            // The connection remains open and will timeout after 6 seconds of inactivity
            actions.push(TlAction::StartConnTimer); // Reset connection timeout
            actions.push(TlAction::SendNack { dest: source, seq_no });
            warn!("TL received wrong sequence number: expected {}, got {} - sending NACK", conn.seq_no_recv, seq_no);
        }

        // Application wants to send data
        (ConnectionState::OpenIdle, TlEvent::RequestData { dest }) if dest == conn.remote_addr => {
            conn.state = ConnectionState::OpenWait;
            conn.rep_count = 0;
            actions.push(TlAction::StopConnTimer); // Stop connection timeout when entering OPEN_WAIT
            actions.push(TlAction::StorePendingMessage);
            actions.push(TlAction::SendData { dest });
            actions.push(TlAction::StartAckTimer);
        }

        // Application wants to disconnect
        (ConnectionState::OpenIdle, TlEvent::RequestDisconnect { dest }) if dest == conn.remote_addr => {
            conn.reset();
            actions.push(TlAction::StopConnTimer);
            actions.push(TlAction::SendDisconnect { dest });
        }

        // Remote device disconnects
        (ConnectionState::OpenIdle, TlEvent::ReceivedDisconnect { source }) if source == conn.remote_addr => {
            conn.reset();
            actions.push(TlAction::StopConnTimer);
            actions.push(TlAction::IndicateDisconnected { source });
        }

        // Received connect while already connected from same source - reset connection timers
        (ConnectionState::OpenIdle, TlEvent::ReceivedConnect { source }) if source == conn.remote_addr => {
            // Re-initialize the connection
            conn.seq_no_send = 0;
            conn.seq_no_recv = 0;
            conn.rep_count = 0;
            actions.push(TlAction::StartConnTimer); // Reset connection timeout
            actions.push(TlAction::IndicateConnected { source });
        }

        // Received connect from a DIFFERENT source while already connected - reject it
        (ConnectionState::OpenIdle, TlEvent::ReceivedConnect { source }) => {
            // KNX spec: reject connection attempts from other devices while connected
            // Send T_Disconnect to the new source, keep existing connection
            actions.push(TlAction::SendDisconnect { dest: source });
        }

        // Connection timeout expired in OPEN_IDLE - disconnect
        (ConnectionState::OpenIdle, TlEvent::ConnectionTimeout) => {
            let addr = conn.remote_addr;
            conn.reset();
            actions.push(TlAction::SendDisconnect { dest: addr });
            actions.push(TlAction::IndicateDisconnected { source: addr });
        }

        // Received NACK with correct sequence number in OPEN_IDLE - disconnect immediately
        // Per KNX spec, receiving a NACK when we haven't sent anything indicates an error
        (ConnectionState::OpenIdle, TlEvent::ReceivedNack { source, seq_no })
            if source == conn.remote_addr && seq_no == conn.seq_no_send =>
        {
            conn.reset();
            actions.push(TlAction::StopConnTimer);
            actions.push(TlAction::SendDisconnect { dest: source });
            actions.push(TlAction::IndicateDisconnected { source });
        }

        // =====================================================================
        // OPEN_WAIT state transitions
        // =====================================================================

        // Received ACK with correct sequence number
        (ConnectionState::OpenWait, TlEvent::ReceivedAck { source, seq_no })
            if source == conn.remote_addr && seq_no == conn.seq_no_send =>
        {
            conn.state = ConnectionState::OpenIdle;
            conn.inc_seq_send();
            actions.push(TlAction::StopAckTimer);
            actions.push(TlAction::StartConnTimer); // Start connection timeout when returning to OPEN_IDLE
            actions.push(TlAction::ConfirmData { dest: source, success: true });
            // Deliver any queued incoming data now that we're back in OPEN_IDLE
            if conn.has_queued_incoming() {
                actions.push(TlAction::DeliverQueuedData { source });
            }
        }

        // Received NACK - retransmit immediately
        (ConnectionState::OpenWait, TlEvent::ReceivedNack { source, seq_no })
            if source == conn.remote_addr && seq_no == conn.seq_no_send =>
        {
            conn.rep_count += 1;
            if conn.rep_count > MAX_REPETITIONS {
                // Too many retries - disconnect
                let addr = conn.remote_addr;
                conn.reset();
                actions.push(TlAction::StopAckTimer);
                actions.push(TlAction::SendDisconnect { dest: addr });
                actions.push(TlAction::ConfirmData { dest: addr, success: false });
                actions.push(TlAction::IndicateDisconnected { source: addr });
            } else {
                // Retransmit
                actions.push(TlAction::Retransmit { dest: source });
                actions.push(TlAction::StartAckTimer);
            }
        }

        // ACK timeout expired
        (ConnectionState::OpenWait, TlEvent::AckTimeout) => {
            conn.rep_count += 1;
            if conn.rep_count > MAX_REPETITIONS {
                // Too many retries - disconnect
                let addr = conn.remote_addr;
                conn.reset();
                actions.push(TlAction::SendDisconnect { dest: addr });
                actions.push(TlAction::ConfirmData { dest: addr, success: false });
                actions.push(TlAction::IndicateDisconnected { source: addr });
            } else {
                // Retransmit
                actions.push(TlAction::Retransmit { dest: conn.remote_addr });
                actions.push(TlAction::StartAckTimer);
            }
        }

        // Received data while waiting for ACK - ACK it and queue for later delivery
        // We queue the data instead of delivering it immediately, so the application
        // layer doesn't process it until we've confirmed our pending send
        (ConnectionState::OpenWait, TlEvent::ReceivedData { source, seq_no })
            if source == conn.remote_addr && seq_no == conn.seq_no_recv =>
        {
            conn.inc_seq_recv();
            actions.push(TlAction::SendAck { dest: source, seq_no });
            actions.push(TlAction::QueueIncomingData { source });
        }

        // Received repeated data while waiting for ACK (seq == previous seq)
        // This is a retransmission - ACK it but don't process again
        (ConnectionState::OpenWait, TlEvent::ReceivedData { source, seq_no })
            if source == conn.remote_addr && seq_no == conn.prev_seq_recv() =>
        {
            // ACK the repeated message but don't indicate to upper layer again
            actions.push(TlAction::SendAck { dest: source, seq_no });
        }

        // Received data with wrong sequence number while waiting for ACK
        // Send NACK but stay in OPEN_WAIT (continue waiting for our ACK)
        (ConnectionState::OpenWait, TlEvent::ReceivedData { source, seq_no }) if source == conn.remote_addr => {
            // Wrong sequence number - send NACK but don't disconnect
            actions.push(TlAction::SendNack { dest: source, seq_no });
            warn!("TL received wrong sequence number in OPEN_WAIT: expected {}, got {} - sending NACK", conn.seq_no_recv, seq_no);
        }

        // Remote device disconnects while we're waiting
        (ConnectionState::OpenWait, TlEvent::ReceivedDisconnect { source }) if source == conn.remote_addr => {
            let addr = conn.remote_addr;
            conn.reset();
            actions.push(TlAction::StopAckTimer);
            actions.push(TlAction::ConfirmData { dest: addr, success: false });
            actions.push(TlAction::IndicateDisconnected { source });
        }

        // Application wants to disconnect while waiting
        (ConnectionState::OpenWait, TlEvent::RequestDisconnect { dest }) if dest == conn.remote_addr => {
            conn.reset();
            actions.push(TlAction::StopAckTimer);
            actions.push(TlAction::SendDisconnect { dest });
            actions.push(TlAction::ConfirmData { dest, success: false });
        }

        // Received connect from a DIFFERENT source while in OPEN_WAIT - reject it
        (ConnectionState::OpenWait, TlEvent::ReceivedConnect { source }) if source != conn.remote_addr => {
            // KNX spec: reject connection attempts from other devices while connected
            // Send T_Disconnect to the new source, keep existing connection
            actions.push(TlAction::SendDisconnect { dest: source });
        }

        // =====================================================================
        // Default: ignore unhandled events
        // =====================================================================
        _ => {}
    }

    actions
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

    #[test]
    fn test_incoming_connect() {
        let mut conn = new_connection();
        let source = IndividualAddress::new(1, 2, 3);

        let actions = process_event(&mut conn, TlEvent::ReceivedConnect { source });

        assert_eq!(conn.state, ConnectionState::OpenIdle);
        assert_eq!(conn.remote_addr, source);
        assert_eq!(actions.len(), 2);

        let mut iter = actions.iter();
        assert_eq!(iter.next(), Some(TlAction::StartConnTimer));
        assert_eq!(iter.next(), Some(TlAction::IndicateConnected { source }));
    }

    #[test]
    fn test_receive_data_correct_seq() {
        let mut conn = new_connection();
        let source = IndividualAddress::new(1, 2, 3);

        // First establish connection
        process_event(&mut conn, TlEvent::ReceivedConnect { source });

        // Then receive data with seq 0
        let actions = process_event(&mut conn, TlEvent::ReceivedData { source, seq_no: 0 });

        assert_eq!(conn.seq_no_recv, 1);
        assert_eq!(actions.len(), 3);

        let mut iter = actions.iter();
        assert_eq!(iter.next(), Some(TlAction::StartConnTimer)); // Reset connection timeout
        assert_eq!(iter.next(), Some(TlAction::SendAck { dest: source, seq_no: 0 }));
        assert_eq!(iter.next(), Some(TlAction::IndicateData { source }));
    }

    #[test]
    fn test_send_data_and_ack() {
        let mut conn = new_connection();
        let dest = IndividualAddress::new(1, 2, 3);

        // Establish connection
        process_event(&mut conn, TlEvent::ReceivedConnect { source: dest });

        // Request to send data
        let actions = process_event(&mut conn, TlEvent::RequestData { dest });

        assert_eq!(conn.state, ConnectionState::OpenWait);
        assert_eq!(actions.len(), 4);

        let mut iter = actions.iter();
        assert_eq!(iter.next(), Some(TlAction::StopConnTimer)); // Stop connection timeout when entering OPEN_WAIT
        assert_eq!(iter.next(), Some(TlAction::StorePendingMessage));
        assert_eq!(iter.next(), Some(TlAction::SendData { dest }));
        assert_eq!(iter.next(), Some(TlAction::StartAckTimer));

        // Receive ACK
        let actions = process_event(&mut conn, TlEvent::ReceivedAck { source: dest, seq_no: 0 });

        assert_eq!(conn.state, ConnectionState::OpenIdle);
        assert_eq!(conn.seq_no_send, 1);

        let mut iter = actions.iter();
        assert_eq!(iter.next(), Some(TlAction::StopAckTimer));
        assert_eq!(iter.next(), Some(TlAction::StartConnTimer)); // Restart connection timeout
        assert_eq!(iter.next(), Some(TlAction::ConfirmData { dest, success: true }));
    }

    #[test]
    fn test_timeout_retransmit() {
        let mut conn = new_connection();
        let dest = IndividualAddress::new(1, 2, 3);

        // Establish and send
        process_event(&mut conn, TlEvent::ReceivedConnect { source: dest });
        process_event(&mut conn, TlEvent::RequestData { dest });

        // First timeout
        let actions = process_event(&mut conn, TlEvent::AckTimeout);
        assert_eq!(conn.state, ConnectionState::OpenWait);
        assert_eq!(conn.rep_count, 1);

        let mut iter = actions.iter();
        assert_eq!(iter.next(), Some(TlAction::Retransmit { dest }));
        assert_eq!(iter.next(), Some(TlAction::StartAckTimer));
    }

    #[test]
    fn test_max_retries_disconnect() {
        let mut conn = new_connection();
        let dest = IndividualAddress::new(1, 2, 3);

        // Establish and send
        process_event(&mut conn, TlEvent::ReceivedConnect { source: dest });
        process_event(&mut conn, TlEvent::RequestData { dest });

        // Timeout MAX_REPETITIONS times (3 retransmissions), then 4th timeout triggers disconnect
        process_event(&mut conn, TlEvent::AckTimeout); // rep_count = 1, retransmit
        process_event(&mut conn, TlEvent::AckTimeout); // rep_count = 2, retransmit
        process_event(&mut conn, TlEvent::AckTimeout); // rep_count = 3, retransmit
        let actions = process_event(&mut conn, TlEvent::AckTimeout); // rep_count = 4 > 3, disconnect

        assert_eq!(conn.state, ConnectionState::Closed);

        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.contains(&TlAction::SendDisconnect { dest }));
        assert!(action_vec.contains(&TlAction::ConfirmData { dest, success: false }));
    }
}
