//! Advisory persistence notifications from the stack to the storage task.
//!
//! The stack marks configuration changes via
//! [`HasPersistence::mark_dirty`](crate::HasPersistence::mark_dirty); the
//! storage task's periodic dirty poll persists them within
//! [`DIRTY_SAVE_POLL`](crate::storage::DIRTY_SAVE_POLL). Some moments are
//! worth saving *now* rather than up to a poll period later — those travel
//! as plain [`PersistRequest`] values on the `LayerContext` persist channel,
//! drained by
//! [`Stack::receive_persist_request()`](crate::Stack::receive_persist_request).
//!
//! Advisory only: the sender never blocks on the save, and the dirty flag
//! still gates the actual write. Anything with a hard durability ordering
//! (the IP Secure mc_timer watermark, 03/08/09 §2.2.4.2) does not queue a
//! message — the KNX/IP Secure link layer writes its store directly through
//! the storage handle on its context.

/// Why the stack suggests an on-demand save.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistRequest {
    /// The load state machines completed an ETS download
    /// (`LS_LOADING` → `LS_LOADED`) — a natural moment to save the freshly
    /// written configuration without waiting for the trailing restart or
    /// the next dirty poll.
    EtsDownloadComplete,
}
