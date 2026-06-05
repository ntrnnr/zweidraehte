//! KNX-RF link-layer Frame-Number (LFN) duplicate suppression.
//!
//! Per KNX 03/02/05 §6.1.4.3, every RF transmitter inserts a 3-bit Link-layer
//! Frame Number (LFN) into each frame and increments it per new frame; a frame
//! may be retransmitted with the *same* LFN to improve delivery odds. The
//! receiver must therefore **discard subsequent telegrams carrying the identical
//! LFN from the same sender**, and store the newly received LFN when it differs.
//!
//! "Same sender" is keyed by the block-1 `SN/DoA` field (interpreted per AET)
//! together with the source Individual Address, forming a
//! `(SerialNumber, SourceAddress, LFN)` history tuple. We track the *last* LFN
//! seen per sender plus the time it was seen, and age entries out after
//! [`HISTORY_TTL_MS`]. The TTL matters: an immediate retransmission carries the
//! same LFN and must be dropped, but a sender that legitimately reuses that LFN
//! much later (after a reboot, or a normal mod-8 cycle separated by a quiet gap)
//! must be accepted — without aging, per-sender last-LFN alone would wrongly
//! drop it. The table is a fixed ring; the oldest entry is evicted on overflow.
//!
//! The history is time-source-agnostic: callers pass a monotonic millisecond
//! timestamp into [`LfnHistory::is_duplicate`] (the link layer uses
//! `embassy_time::Instant::now()`), keeping this module pure and host-testable.

/// Number of distinct senders tracked.
const HISTORY_SLOTS: usize = 7;

/// How long an entry remains valid for duplicate detection. After this the same
/// LFN from the same sender is treated as a fresh frame (KNX 03/02/05
/// §6.1.4.3).
pub const HISTORY_TTL_MS: u64 = 3_000;

/// One tracked sender: its identity (6-octet SN/DoA + 2-octet source address),
/// the last LFN observed, and when it was last seen (monotonic ms).
#[derive(Clone, Copy)]
struct Entry {
    /// SN/DoA (6) followed by source address high/low (2).
    key: [u8; 8],
    last_lfn: u8,
    last_seen_ms: u64,
    used: bool,
}

impl Entry {
    const EMPTY: Self = Self { key: [0; 8], last_lfn: 0, last_seen_ms: 0, used: false };
}

/// Fixed-size per-sender LFN history for duplicate suppression.
pub struct LfnHistory {
    slots: [Entry; HISTORY_SLOTS],
    /// Next slot to overwrite when inserting a previously unseen sender.
    next: usize,
}

impl LfnHistory {
    /// Create an empty history.
    pub const fn new() -> Self {
        Self { slots: [Entry::EMPTY; HISTORY_SLOTS], next: 0 }
    }

    /// Record a frame received at `now_ms` and report whether it is a
    /// **duplicate**: the identical LFN from a sender whose last (non-expired)
    /// frame carried the same LFN.
    ///
    /// A duplicate leaves state unchanged and returns `true`. A fresh frame (new
    /// LFN, an expired entry, or an unseen sender) updates the sender's last LFN
    /// and timestamp and returns `false`.
    pub fn is_duplicate(&mut self, sn_or_doa: &[u8; 6], src: u16, lfn: u8, now_ms: u64) -> bool {
        let mut key = [0u8; 8];
        key[..6].copy_from_slice(sn_or_doa);
        key[6] = (src >> 8) as u8;
        key[7] = src as u8;

        if let Some(entry) = self.slots.iter_mut().find(|e| e.used && e.key == key) {
            let expired = now_ms.saturating_sub(entry.last_seen_ms) > HISTORY_TTL_MS;
            if !expired && entry.last_lfn == lfn {
                return true; // immediate repeat within the TTL — drop
            }
            // Fresh: a new LFN, or the previous sighting aged out.
            entry.last_lfn = lfn;
            entry.last_seen_ms = now_ms;
            return false;
        }

        // Unseen sender: claim the next ring slot (evicting the oldest).
        self.slots[self.next] = Entry { key, last_lfn: lfn, last_seen_ms: now_ms, used: true };
        self.next = (self.next + 1) % HISTORY_SLOTS;
        false
    }
}

impl Default for LfnHistory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENDER_A: [u8; 6] = [0x00, 0xfa, 0xb6, 0xab, 0xb2, 0x86];
    const SENDER_B: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    #[test]
    fn immediate_repeat_is_duplicate() {
        let mut h = LfnHistory::new();
        assert!(!h.is_duplicate(&SENDER_A, 0x1201, 3, 0), "first frame is fresh");
        assert!(h.is_duplicate(&SENDER_A, 0x1201, 3, 10), "same LFN repeat is a duplicate");
        assert!(h.is_duplicate(&SENDER_A, 0x1201, 3, 20), "and stays a duplicate");
    }

    #[test]
    fn differing_lfn_is_fresh() {
        let mut h = LfnHistory::new();
        assert!(!h.is_duplicate(&SENDER_A, 0x1201, 3, 0));
        assert!(!h.is_duplicate(&SENDER_A, 0x1201, 4, 10), "incremented LFN is fresh");
        // Cycled back to 3 after intervening 4 — fresh, since last seen was 4.
        assert!(!h.is_duplicate(&SENDER_A, 0x1201, 3, 20));
    }

    #[test]
    fn same_lfn_after_ttl_is_fresh() {
        let mut h = LfnHistory::new();
        assert!(!h.is_duplicate(&SENDER_A, 0x1201, 3, 0));
        assert!(h.is_duplicate(&SENDER_A, 0x1201, 3, HISTORY_TTL_MS), "same LFN within TTL is a duplicate");
        // Past the TTL the same LFN is accepted again (e.g. sender rebooted).
        assert!(!h.is_duplicate(&SENDER_A, 0x1201, 3, HISTORY_TTL_MS + 1), "same LFN after TTL is fresh");
    }

    #[test]
    fn senders_are_tracked_independently() {
        let mut h = LfnHistory::new();
        assert!(!h.is_duplicate(&SENDER_A, 0x1201, 3, 0));
        assert!(!h.is_duplicate(&SENDER_B, 0x1201, 3, 0), "different SN/DoA is a different sender");
        // Same SN/DoA but different source address is also a distinct sender.
        assert!(!h.is_duplicate(&SENDER_A, 0x1300, 3, 0));
        assert!(h.is_duplicate(&SENDER_A, 0x1201, 3, 10), "original sender's repeat still detected");
    }
}
