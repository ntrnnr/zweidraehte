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

use zweidraehte_proto::messages::knx::Priority;

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

// ============================================================================
// GroupValueAddressedSender
// ============================================================================

// Re-export the canonical `GroupValueEncoding` from the proto crate; it
// lives there alongside the `GroupValueWriteRequest` serializer that
// consumes it so the encoding choice and the byte-layout it drives are
// co-located.
pub use zweidraehte_proto::messages::apdu::group_value::GroupValueEncoding;

/// Ability to emit a `A_GroupValue_{Write,Read}` telegram to a known TSAP.
///
/// Unlike [`GroupValueSender`] (which looks up the TSAP from the
/// association table and drives the `ComObjectStatus` state machine),
/// this capability pushes a telegram directly. The caller has already
/// resolved the destination TSAP and chosen the value to send — the
/// provider just builds the wire representation and queues it on the
/// outbox.
///
/// Used by diagnostic paths (GO diagnostics services 0x01–0x03) where
/// the normal status-gated send flow would be wrong: either the target
/// is a bare group address rather than a local communication object, or
/// the transmission must bypass the `ComObjectStatus::WriteRequest`
/// check. Sends go on the immediate outbox in handler-call order; per
/// EITT semantics (manual §11.2.3.6) the management response and the
/// resulting bus telegram form an unordered block within the test
/// window, so wire-order between them is not constrained.
pub trait GroupValueAddressedSender {
    /// Build and queue a `A_GroupValue_Write` to `tsap` carrying `data`
    /// encoded as `encoding`, at `priority`.
    fn send_group_write_tsap(&self, tsap: u16, priority: Priority, encoding: GroupValueEncoding, data: &[u8]);

    /// Build and queue a `A_GroupValue_Read` to `tsap` at `priority`.
    fn send_group_read_tsap(&self, tsap: u16, priority: Priority);
}

// ============================================================================
// SecureGroupValueAddressedSender
// ============================================================================

/// Selects the KNX Data Secure level for an outgoing secure telegram.
///
/// Passed to [`SecureGroupValueAddressedSender`] methods; the diagnostic
/// paths that build a telegram on the caller's behalf (e.g.
/// `PID_GO_DIAGNOSTICS` WriteServiceID `0x01` / `0x03`) decode it from
/// the request's security flag bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RequestedSecurity {
    /// Authenticated only (SCF `SecType=auth`).
    AuthOnly,
    /// Authenticated and encrypted (SCF `SecType=conf`).
    AuthConf,
}

/// Ability to emit a KNX Data Secure wrapped `A_GroupValue_{Write,Read}`
/// telegram to a known TSAP.
///
/// Mirrors [`GroupValueAddressedSender`] for the secure path. The
/// provider looks up the group key for the destination TSAP, reserves
/// a sending sequence number, builds the full secure
/// `T_GroupData_Req` (SCF + SeqNr + encrypted payload + MAC), and
/// queues it on the outbox. Bypasses the
/// [`SecureApplicationLayer`](crate::layers::secure_application::SecureApplicationLayer)'s
/// "respond-to-incoming-secure" path because the triggering command
/// typically arrives plaintext.
///
/// Only available on stacks whose state provides the full set of
/// secure-side capabilities (see the provider impl's bounds).
pub trait SecureGroupValueAddressedSender {
    /// Build and queue a secure `A_GroupValue_Write` to `tsap`.
    fn send_group_write_tsap_secure(
        &self,
        tsap: u16,
        priority: Priority,
        encoding: GroupValueEncoding,
        data: &[u8],
        security: RequestedSecurity,
    );

    /// Build and queue a secure `A_GroupValue_Read` to `tsap`.
    fn send_group_read_tsap_secure(&self, tsap: u16, priority: Priority, security: RequestedSecurity);
}
