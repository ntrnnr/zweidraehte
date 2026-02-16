//! Connection state management for transport layer
//!
//! This module provides the connection state types and connection table
//! for managing connection-oriented transport layer communication per
//! KNX specification 03/03/04.

use crate::{
    address::IndividualAddress,
    messages::{buffers::Buffer, knx::KnxMessageBuffer},
};
use embassy_time::Instant;

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
// Connection
// ============================================================================

/// A single transport layer connection slot
///
/// Manages the state for one connection-oriented communication session.
/// For device transport layers, typically only one incoming connection is
/// supported (from a configurator/ETS).
#[derive(Debug)]
pub struct Connection {
    /// Current connection state
    pub state: ConnectionState,
    /// Remote device address
    pub remote_addr: IndividualAddress,
    /// Sequence number for sending (0-15)
    pub seq_no_send: u8,
    /// Expected sequence number for receiving (0-15)
    pub seq_no_recv: u8,
    /// Repetition counter for retransmissions
    pub rep_count: u8,
    /// Timeout deadline for ACK (when in OpenWait state)
    pub ack_timeout_deadline: Option<Instant>,
    /// Timeout deadline for connection (when in OpenIdle state with no activity)
    pub conn_timeout_deadline: Option<Instant>,
    /// Stored message buffer for possible retransmission (outgoing)
    pub pending_msg: Option<KnxMessageBuffer<Buffer<'static>>>,
    /// Queued incoming data message received while in OPEN_WAIT state
    /// Will be delivered to application layer when transitioning to OPEN_IDLE
    pub queued_incoming: Option<KnxMessageBuffer<Buffer<'static>>>,
    /// Current access level for this connection (0 = max access, 3 = min access)
    /// Reset to default (max access level - 1, typically 3) when connection opens.
    /// Modified by A_Authorize_Request.
    pub access_level: u8,
}

impl Default for Connection {
    fn default() -> Self {
        Self::new()
    }
}

/// Default access level for new connections (minimum access = level 3)
pub const DEFAULT_CONNECTION_ACCESS_LEVEL: u8 = 3;

impl Connection {
    /// Create a new connection in the closed state
    pub const fn new() -> Self {
        Self {
            state: ConnectionState::Closed,
            remote_addr: IndividualAddress::new(0, 0, 0),
            seq_no_send: 0,
            seq_no_recv: 0,
            rep_count: 0,
            ack_timeout_deadline: None,
            conn_timeout_deadline: None,
            pending_msg: None,
            queued_incoming: None,
            access_level: DEFAULT_CONNECTION_ACCESS_LEVEL,
        }
    }

    /// Reset the connection to closed state
    pub fn reset(&mut self) {
        self.state = ConnectionState::Closed;
        self.seq_no_send = 0;
        self.seq_no_recv = 0;
        self.rep_count = 0;
        self.ack_timeout_deadline = None;
        self.conn_timeout_deadline = None;
        self.pending_msg = None;
        self.queued_incoming = None;
        self.access_level = DEFAULT_CONNECTION_ACCESS_LEVEL;
    }

    /// Check if there is queued incoming data
    pub fn has_queued_incoming(&self) -> bool {
        self.queued_incoming.is_some()
    }

    /// Check if the ACK timeout has expired
    pub fn is_ack_timed_out(&self, now: Instant) -> bool {
        self.ack_timeout_deadline.map(|d| now >= d).unwrap_or(false)
    }

    /// Check if the connection timeout has expired
    pub fn is_conn_timed_out(&self, now: Instant) -> bool {
        self.conn_timeout_deadline.map(|d| now >= d).unwrap_or(false)
    }

    /// Start the ACK timeout timer
    pub fn start_ack_timeout(&mut self, deadline: Instant) {
        self.ack_timeout_deadline = Some(deadline);
    }

    /// Stop the ACK timeout timer
    pub fn stop_ack_timeout(&mut self) {
        self.ack_timeout_deadline = None;
    }

    /// Start the connection timeout timer
    pub fn start_conn_timeout(&mut self, deadline: Instant) {
        self.conn_timeout_deadline = Some(deadline);
    }

    /// Stop the connection timeout timer
    pub fn stop_conn_timeout(&mut self) {
        self.conn_timeout_deadline = None;
    }

    /// Increment sequence number for sending (wraps at 15)
    pub fn inc_seq_send(&mut self) {
        self.seq_no_send = (self.seq_no_send + 1) & 0x0F;
    }

    /// Increment sequence number for receiving (wraps at 15)
    pub fn inc_seq_recv(&mut self) {
        self.seq_no_recv = (self.seq_no_recv + 1) & 0x0F;
    }

    /// Get the previous receive sequence number
    pub fn prev_seq_recv(&self) -> u8 {
        self.seq_no_recv.wrapping_sub(1) & 0x0F
    }
}

// ============================================================================
// Connection Table
// ============================================================================

/// Fixed-size connection table for managing multiple connections
///
/// Separates incoming connections (initiated by remote devices) from
/// outgoing connections (initiated by us). For a typical KNX device,
/// `MAX_INCOMING` is usually 1 and `MAX_OUTGOING` is 0.
///
/// For a router or gateway, these values could be higher.
pub struct ConnectionTable<const MAX_INCOMING: usize, const MAX_OUTGOING: usize> {
    /// Incoming connections (initiated by remote devices)
    incoming: [Connection; MAX_INCOMING],
    /// Outgoing connections (initiated by us)
    outgoing: [Connection; MAX_OUTGOING],
}

impl<const MAX_INCOMING: usize, const MAX_OUTGOING: usize> ConnectionTable<MAX_INCOMING, MAX_OUTGOING> {
    /// Create a new empty connection table
    pub const fn new() -> Self {
        Self {
            incoming: [const { Connection::new() }; MAX_INCOMING],
            outgoing: [const { Connection::new() }; MAX_OUTGOING],
        }
    }

    /// Find an existing incoming connection by remote address
    pub fn find_incoming(&mut self, addr: IndividualAddress) -> Option<&mut Connection> {
        self.incoming.iter_mut().find(|c| c.state != ConnectionState::Closed && c.remote_addr == addr)
    }

    /// Find an existing outgoing connection by remote address
    pub fn find_outgoing(&mut self, addr: IndividualAddress) -> Option<&mut Connection> {
        self.outgoing.iter_mut().find(|c| c.state != ConnectionState::Closed && c.remote_addr == addr)
    }

    /// Find any connection (incoming or outgoing) by remote address
    pub fn find_any(&mut self, addr: IndividualAddress) -> Option<&mut Connection> {
        // Check incoming first
        for conn in self.incoming.iter_mut() {
            if conn.state != ConnectionState::Closed && conn.remote_addr == addr {
                return Some(conn);
            }
        }
        // Then check outgoing
        for conn in self.outgoing.iter_mut() {
            if conn.state != ConnectionState::Closed && conn.remote_addr == addr {
                return Some(conn);
            }
        }
        None
    }

    /// Find any connection by remote address, regardless of state.
    ///
    /// Unlike `find_any`, this also returns connections in `Closed` state.
    /// Used for applying deferred state transitions where the connection may
    /// be temporarily in an intermediate state.
    pub fn find_any_including_closed(&mut self, addr: IndividualAddress) -> Option<&mut Connection> {
        for conn in self.incoming.iter_mut() {
            if conn.remote_addr == addr {
                return Some(conn);
            }
        }
        for conn in self.outgoing.iter_mut() {
            if conn.remote_addr == addr {
                return Some(conn);
            }
        }
        None
    }

    /// Allocate a new incoming connection slot for the given address
    ///
    /// Returns `None` if no free slots are available.
    pub fn allocate_incoming(&mut self, addr: IndividualAddress) -> Option<&mut Connection> {
        // First check if we already have a connection to this address
        if let Some(idx) =
            self.incoming.iter().position(|c| c.state != ConnectionState::Closed && c.remote_addr == addr)
        {
            return Some(&mut self.incoming[idx]);
        }

        // Try to find a free slot
        if let Some(idx) = self.incoming.iter().position(|c| c.state == ConnectionState::Closed) {
            self.incoming[idx].reset();
            self.incoming[idx].remote_addr = addr;
            return Some(&mut self.incoming[idx]);
        }

        None
    }

    /// Allocate a new outgoing connection slot for the given address
    ///
    /// Returns `None` if no free slots are available.
    pub fn allocate_outgoing(&mut self, addr: IndividualAddress) -> Option<&mut Connection> {
        // First check if we already have a connection to this address
        if let Some(idx) =
            self.outgoing.iter().position(|c| c.state != ConnectionState::Closed && c.remote_addr == addr)
        {
            return Some(&mut self.outgoing[idx]);
        }

        // Try to find a free slot
        if let Some(idx) = self.outgoing.iter().position(|c| c.state == ConnectionState::Closed) {
            self.outgoing[idx].reset();
            self.outgoing[idx].remote_addr = addr;
            return Some(&mut self.outgoing[idx]);
        }

        None
    }

    /// Get the next timeout deadline across all connections
    ///
    /// Returns `None` if no connections have pending timeouts.
    /// Considers both ACK timeouts and connection timeouts.
    pub fn next_timeout_deadline(&self) -> Option<Instant> {
        let all_deadlines = self
            .incoming
            .iter()
            .chain(self.outgoing.iter())
            .flat_map(|c| [c.ack_timeout_deadline, c.conn_timeout_deadline])
            .flatten();

        all_deadlines.min()
    }

    /// Iterate over all connections that have any timeout (ACK or connection)
    ///
    /// Returns mutable references to connections whose timeout deadline
    /// has passed. The caller should process timeouts and update state.
    pub fn iter_timed_out(&mut self, now: Instant) -> impl Iterator<Item = &mut Connection> {
        self.incoming
            .iter_mut()
            .chain(self.outgoing.iter_mut())
            .filter(move |c| c.is_ack_timed_out(now) || c.is_conn_timed_out(now))
    }

    /// Get mutable access to all incoming connections
    pub fn incoming_mut(&mut self) -> &mut [Connection; MAX_INCOMING] {
        &mut self.incoming
    }

    /// Get mutable access to all outgoing connections
    pub fn outgoing_mut(&mut self) -> &mut [Connection; MAX_OUTGOING] {
        &mut self.outgoing
    }
}

impl<const MAX_INCOMING: usize, const MAX_OUTGOING: usize> Default for ConnectionTable<MAX_INCOMING, MAX_OUTGOING> {
    fn default() -> Self {
        Self::new()
    }
}
