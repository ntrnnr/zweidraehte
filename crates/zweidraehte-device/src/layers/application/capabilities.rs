//! Application-layer capability traits.
//!
//! Capabilities let augments and other stack components request
//! application-level services without knowing the wire format. A component
//! that wants to emit a group-value write does not need to build a
//! `T_GroupData_Req` telegram by hand — it calls
//! [`GroupValueSender::request_group_write`] on whichever type provides the
//! capability.
//!
//! Today the built-in capability provider is
//! [`GroupDataProvider`](super::group_data::GroupDataProvider). Additional
//! capabilities will appear here as they're introduced; they all follow the
//! [`HasX`] pattern used elsewhere in the codebase (e.g.
//! [`HasAddressTable`](crate::objects::tables::HasAddressTable)).

// ============================================================================
// GroupValueSender
// ============================================================================

/// Ability to request outgoing group-value reads and writes by ASAP.
///
/// The provider is responsible for the full send pipeline: checking load
/// and run state, resolving the TSAP via the association table, building
/// the `T_GroupData_Req` telegram, pushing it to the outbox, and
/// bookkeeping the pending send for the eventual transport-layer
/// confirmation. Callers just name the communication object.
pub trait GroupValueSender {
    /// Request a group-value write for the communication object at `asap`.
    ///
    /// Returns `true` when the request was accepted (even if the send was
    /// quietly suppressed by run/load state or a missing association);
    /// `false` means the application is not running and the request must
    /// be retried later.
    fn request_group_write(&self, asap: u16) -> bool;

    /// Request a group-value read for the communication object at `asap`.
    ///
    /// Same return semantics as [`request_group_write`](Self::request_group_write).
    fn request_group_read(&self, asap: u16) -> bool;
}
