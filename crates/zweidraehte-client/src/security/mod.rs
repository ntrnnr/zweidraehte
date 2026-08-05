//! KNX Data Secure for the client (tool) role.
//!
//! A device with Data Secure activated only accepts management services
//! wrapped in Secure APDUs under its tool key (03/03/07 §5.3). This
//! module provides the tool side of that exchange:
//!
//! - [`SecurityStore`] — the bus-level keyring: which devices are
//!   secure, under which key (tool key or FDSK), with which serial.
//! - [`SecureChannel`] — per-connection sans-io wrap/unwrap state: the
//!   two sequence counters and the CCM calls around them.
//! - [`SeqNumberStore`] — persistence for the sequence counters, so the
//!   tool's sending sequence number survives restarts as 03/03/07
//!   §5.1.3 requires. [`MemSeqStore`] is the non-persistent default;
//!   [`JsonSeqStore`] the shipped file-backed implementation.
//!
//! The crypto itself lives in `zweidraehte_proto::crypto::{ccm, scf}`
//! and is shared with the device stack and the conformance harness.

pub mod channel;
pub mod file_store;
pub mod keyring;
pub mod store;

pub use channel::SecureChannel;
pub use file_store::JsonSeqStore;
pub use keyring::{DeviceSecurityMode, SecurityEntry, SecurityStore};
pub use store::{MemSeqStore, SeqNumberStore};

/// Errors from secure frame processing.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SecureError {
    #[error("MAC verification failed (tampered frame or wrong key)")]
    MacMismatch,

    #[error("sequence number replay (received {received} < expected {expected})")]
    Replay { received: u64, expected: u64 },

    #[error("invalid Security Control Field")]
    InvalidScf,

    #[error("unexpected secure service type (not S-A_Data)")]
    UnexpectedService,

    #[error("secure frame too short")]
    TooShort,

    #[error("security entry has mode Secure but neither tool key nor FDSK")]
    MissingKey,
}
