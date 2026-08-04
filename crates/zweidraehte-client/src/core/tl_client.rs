//! Client-side transport-layer connection core.
//!
//! Wraps the shared state machine from [`zweidraehte_proto::transport`] for
//! the client role: Style 3 (the only style with the CONNECTING state), one
//! outgoing connection. The driver executes the returned
//! [`TlAction`](zweidraehte_proto::transport::TlAction)s — sending T_*
//! frames, arming the two timers, resolving user futures — and applies the
//! deferred state transition afterwards, per the state machine's contract.

use std::time::Duration;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::transport::{BasicConnection, ConnectionState, ProcessResult, TlEvent, TlStyle, process_event};

/// T_ACK timeout before retransmission (03/03/04 §5.5.4: 3 s).
pub const TL_ACK_TIMEOUT: Duration = Duration::from_secs(3);

/// Connection idle timeout (03/03/04 §5.5.4: 6 s).
pub const TL_CONNECTION_TIMEOUT: Duration = Duration::from_secs(6);

/// One client-side transport connection driven through the shared tables.
#[derive(Debug, Default)]
pub struct TlClientCore {
    pub conn: BasicConnection,
}

impl TlClientCore {
    pub fn new() -> Self {
        Self { conn: BasicConnection::new() }
    }

    /// Feed one event through the Style 3 state machine.
    ///
    /// The caller must execute the returned actions before applying the
    /// state transition (`result.apply_state(&mut core.conn)`).
    pub fn feed(&mut self, event: TlEvent) -> ProcessResult {
        process_event(&mut self.conn, event, TlStyle::Style3)
    }

    pub fn state(&self) -> ConnectionState {
        self.conn.state
    }

    pub fn is_closed(&self) -> bool {
        self.conn.state == ConnectionState::Closed
    }

    pub fn remote(&self) -> IndividualAddress {
        self.conn.remote_addr
    }

    /// The sequence number the next outgoing T_Data_Connected will carry.
    pub fn send_seq(&self) -> u8 {
        self.conn.seq_no_send
    }
}
