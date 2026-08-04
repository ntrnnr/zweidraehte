//! Per-connection state the transport layer state machine operates on.

use crate::address::IndividualAddress;

// ============================================================================
// Connection State
// ============================================================================

/// Connection state per KNX spec 03/03/04 section 5.1
///
/// The `#[repr(u8)]` is used for indexing into the transition tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ConnectionState {
    /// No active connection
    #[default]
    Closed = 0,
    /// Connection established, waiting for data or ready to send
    OpenIdle = 1,
    /// Sent data, waiting for ACK/NACK
    OpenWait = 2,
    /// Client only. Waiting for an IACK after trying to connect to a
    /// remote partner. Only used by Style 3.
    Connecting = 3,
}

impl ConnectionState {
    /// Total number of states (for transition table sizing)
    pub const COUNT: usize = 4;
}

// ============================================================================
// ConnectionCore
// ============================================================================

/// The connection bookkeeping [`process_event`](super::process_event) needs.
///
/// The state machine reads and writes exactly these fields: the state, the
/// remote (connection) address, both 4-bit sequence numbers, the repetition
/// counter, and whether incoming data is queued for deferred delivery
/// (A8's `DeliverQueuedData`). Everything else an embedder keeps per
/// connection — timers, pending message buffers, access levels — stays
/// outside the trait, because the state machine only ever *instructs* the
/// embedder about those via [`TlAction`](super::TlAction)s.
pub trait ConnectionCore {
    fn state(&self) -> ConnectionState;
    fn set_state(&mut self, state: ConnectionState);

    fn remote_addr(&self) -> IndividualAddress;
    fn set_remote_addr(&mut self, addr: IndividualAddress);

    fn seq_no_send(&self) -> u8;
    fn set_seq_no_send(&mut self, seq: u8);

    fn seq_no_recv(&self) -> u8;
    fn set_seq_no_recv(&mut self, seq: u8);

    fn rep_count(&self) -> u8;
    fn set_rep_count(&mut self, count: u8);

    /// Whether an incoming data message is queued for deferred delivery.
    ///
    /// Drives the `DeliverQueuedData` action on A8; embedders without a
    /// queue (e.g. a client that never defers) return `false`.
    fn has_queued_incoming(&self) -> bool;

    /// Increment sequence number for sending (wraps at 15)
    fn inc_seq_send(&mut self) {
        self.set_seq_no_send((self.seq_no_send() + 1) & 0x0F);
    }

    /// Increment sequence number for receiving (wraps at 15)
    fn inc_seq_recv(&mut self) {
        self.set_seq_no_recv((self.seq_no_recv() + 1) & 0x0F);
    }

    /// Get the previous receive sequence number
    fn prev_seq_recv(&self) -> u8 {
        self.seq_no_recv().wrapping_sub(1) & 0x0F
    }
}

// ============================================================================
// BasicConnection
// ============================================================================

/// Minimal [`ConnectionCore`] implementation: just the fields the state
/// machine touches, nothing else.
///
/// This is the connection type for embedders that keep timers and pending
/// messages elsewhere — the management client and the state machine's own
/// tests. The device stack instead implements [`ConnectionCore`] on its
/// `Connection` slot type, which carries timer deadlines and message
/// buffers alongside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicConnection {
    pub state: ConnectionState,
    pub remote_addr: IndividualAddress,
    pub seq_no_send: u8,
    pub seq_no_recv: u8,
    pub rep_count: u8,
    /// See [`ConnectionCore::has_queued_incoming`]. Embedders that queue
    /// incoming data during OPEN_WAIT set this alongside their queue.
    pub has_queued_incoming: bool,
}

impl BasicConnection {
    /// Create a new connection in the closed state
    pub const fn new() -> Self {
        Self {
            state: ConnectionState::Closed,
            remote_addr: IndividualAddress::new(0, 0, 0),
            seq_no_send: 0,
            seq_no_recv: 0,
            rep_count: 0,
            has_queued_incoming: false,
        }
    }

    /// Reset the connection to closed state
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for BasicConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionCore for BasicConnection {
    fn state(&self) -> ConnectionState {
        self.state
    }
    fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }
    fn remote_addr(&self) -> IndividualAddress {
        self.remote_addr
    }
    fn set_remote_addr(&mut self, addr: IndividualAddress) {
        self.remote_addr = addr;
    }
    fn seq_no_send(&self) -> u8 {
        self.seq_no_send
    }
    fn set_seq_no_send(&mut self, seq: u8) {
        self.seq_no_send = seq;
    }
    fn seq_no_recv(&self) -> u8 {
        self.seq_no_recv
    }
    fn set_seq_no_recv(&mut self, seq: u8) {
        self.seq_no_recv = seq;
    }
    fn rep_count(&self) -> u8 {
        self.rep_count
    }
    fn set_rep_count(&mut self, count: u8) {
        self.rep_count = count;
    }
    fn has_queued_incoming(&self) -> bool {
        self.has_queued_incoming
    }
}
