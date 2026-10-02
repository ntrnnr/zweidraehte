//! The KNX IP Secure multicast-timer watermark, kept with the sequence
//! counters.
//!
//! 03/08/09 §2.2.4.2 persists the multicast timer so that it never runs
//! backwards across a power loss: after a reboot the device resumes from the
//! watermark plus the persistence interval instead of from 0, which would
//! leave a replay window open until it adopts the group's timer. Like the
//! Data Secure sending counter it is a durable, monotonic 48-bit counter, so
//! it lives in the same store: [`SiatStore`](crate::SiatStore) on flash and
//! [`PackedSeqStore`](crate::PackedSeqStore) on byte media both implement
//! [`McTimerWatermark`].
//!
//! Keeping it is opt-in, per store type: only a KNX IP Secure routing device
//! has a watermark, and a Data Secure device without IP Secure should pay
//! neither the code nor the bytes for it. A store that does not keep one
//! reads `None`, ignores saves, and lets every caller's branch on
//! [`KEEPS_MC_TIMER`](McTimerWatermark::KEEPS_MC_TIMER) compile away.

use zweidraehte_proto::security::SequenceNumberStorage;

/// A durable mc_timer watermark next to the sequence counters.
pub trait McTimerWatermark: SequenceNumberStorage {
    /// Whether this store type keeps a watermark. A KNX IP Secure routing
    /// device must use one that does, or its watermark is never persisted.
    const KEEPS_MC_TIMER: bool;

    /// The persisted watermark, or `None` if none was written since the
    /// store was created or last cleared, or the store keeps none.
    fn load_mc_timer(&self) -> Result<Option<u64>, Self::Error>;

    /// Persist `value` (its low 48 bits).
    fn save_mc_timer(&mut self, value: u64) -> Result<(), Self::Error>;

    /// Forget the watermark: it belongs to the backbone key a factory reset
    /// wipes (§2.2.4.2).
    fn clear_mc_timer(&mut self) -> Result<(), Self::Error>;
}
