//! RP2040 internal-flash region for the IP-Secure mc_timer watermark.
//!
//! 03/08/09 §2.2.4.2 requires a secure-routing device to persist its multicast
//! timer watermark before emitting (or after adopting) a timer value beyond the
//! persistence window, so the timer can never run backwards across a power
//! loss. The value is a single 48-bit millisecond counter.
//!
//! Persisting it inside the device-config blob means a 4 KiB erase+rewrite (and
//! an all-task XIP stall) on every forced save — and a peer that repeatedly
//! jumps the timer forward can force one such save per frame, a flash wear-DoS.
//! This region gives the watermark its **own** two-sector wear-levelled window
//! (see [`crate::storage`]) so a save is one ~12-byte append instead.
//!
//! The *store logic* — the wear-levelled backend, the singleton-key codec,
//! and the
//! [`McTimerStoreBackend`](zweidraehte_device::storage::McTimerStoreBackend)
//! impl — is medium-agnostic and derives from the region
//! ([`McTimerRegion`]'s `Stored` impl in the core crate). This module
//! supplies only the RP-sized region alias. A device that wants the
//! watermark on another medium declares the byte-medium sibling
//! (`FramMcTimerRegion`) instead — no new store.

use zweidraehte_device::storage::region::McTimerRegion;

use crate::storage::SECTOR_SIZE;

/// The mc_timer region every RP IP-Secure device places: two flash sectors —
/// the wear log needs a rotation spare — under the region's own `KNXM`
/// magic, so a scan never mistakes a stale sequence record for an mc_timer
/// record.
pub type RpMcTimerRegion = McTimerRegion<{ 2 * SECTOR_SIZE }>;
