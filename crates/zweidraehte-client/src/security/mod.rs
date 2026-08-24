//! KNX Data Secure for the client (tool) role.
//!
//! A device with Data Secure activated only accepts management services
//! wrapped in Secure APDUs under its tool key (03/03/07 §5.3). This
//! module provides the tool side of that exchange:
//!
//! - [`SecurityStore`] — the bus-level keyring: which devices are
//!   secure, under which key (tool key or FDSK), with which serial.
//! - [`SecureChannel`] — per-connection sans-io wrap/unwrap and CCM state.
//! - [`SeqNumberStore`] — persistence for the sequence counters, so the
//!   client's one sending sequence number and incoming floors survive restarts as 03/03/07
//!   §5.1.3 requires. [`MemSeqStore`] is the non-persistent default;
//!   [`JsonSeqStore`] is the legacy standalone file-backed implementation;
//!   project frontends use [`ProjectSeqStore`].
//!
//! The crypto itself lives in `zweidraehte_proto::crypto::{ccm, scf}`
//! and is shared with the device stack and the conformance harness.

pub mod channel;
pub mod file_store;
pub mod keyring;
pub mod knxkeys;
pub mod material;
pub mod project_store;
pub mod resolve;
pub mod store;

pub use channel::{SecureChannel, group_unwrap, group_wrap};
pub use file_store::JsonSeqStore;
pub use keyring::{DeviceSecurityMode, SecurityEntry, SecurityStore, knx_sequence_timestamp_floor};
pub use knxkeys::{Keyring, KeyringDevice, KnxKeysError};
pub use material::{
    DecodedFdsk, KeyEncoding, KeyEpoch, KeyId, KeyKind, KeyMaterialSource, KeyMaterialStore, KeyMetadata, KeyOrigin,
    KeyRecord, KeyScope, KeyState, KeyStoreError, SecretBytes, format_serial, parse_fdsk, parse_key16, parse_serial,
};
pub use project_store::ProjectSeqStore;
pub use resolve::{EtsKeyringSource, ResolvedKeyMaterial, resolve_project_key_material};
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

    #[error("tool-access flag on a group frame")]
    ToolAccessOnGroup,

    #[error("security entry has mode Secure but neither tool key nor FDSK")]
    MissingKey,
}
