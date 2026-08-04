//! Transport layer state machine — shared with client implementations.
//!
//! The table-driven state machine for KNX spec 03/03/04 §5.4 lives in
//! [`zweidraehte_proto::transport`] so that management clients can drive
//! the same tables from the connecting side (Style 3's CONNECTING state).
//! The device stack embeds it through the [`ConnectionCore`] impl on
//! [`Connection`](super::connection::Connection) and the device-specific
//! [`ProcessResultExt`] helper below.

pub use zweidraehte_proto::transport::{
    ActionBuffer, MAX_REPETITIONS, ProcessResult, TlAction, TlEvent, TlStyle, process_event,
};

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::transport::ConnectionCore;

use super::connection::ConnectionTable;

/// Device-side extension of [`ProcessResult`]: apply the deferred state
/// transition through the [`ConnectionTable`] rather than a direct
/// connection reference.
pub trait ProcessResultExt {
    /// Apply the state transition by looking up the connection by address.
    ///
    /// Uses `find_any_including_closed` because during the deferred transition
    /// window the connection may be in any state — including `Closed` (for
    /// transitions that start from `Closed`, like accepting a new connection).
    fn apply_state_by_addr<const I: usize, const O: usize>(
        &self,
        connections: &mut ConnectionTable<I, O>,
        addr: IndividualAddress,
    );
}

impl ProcessResultExt for ProcessResult {
    fn apply_state_by_addr<const I: usize, const O: usize>(
        &self,
        connections: &mut ConnectionTable<I, O>,
        addr: IndividualAddress,
    ) {
        if let Some(next_state) = self.next_state
            && let Some(conn) = connections.find_any_including_closed(addr)
        {
            conn.set_state(next_state);
        }
    }
}
