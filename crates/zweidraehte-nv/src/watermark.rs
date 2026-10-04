//! Legacy multicast-timer fields inside sequence stores.
//!
//! Older RP2040 and Linux secure-routing firmware kept the watermark beside
//! Data Secure counters. Boot migration reads and clears that field before
//! the independent [`McTimerStore`](crate::McTimerStore) becomes live. The
//! field and its optional layout remain readable so an update does not reset
//! the timer of an already commissioned device.

use zweidraehte_proto::security::SequenceNumberStorage;

/// Access to the old watermark field next to the sequence counters.
pub trait McTimerWatermark: SequenceNumberStorage {
    /// Whether the old packed/log format has a watermark field.
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
