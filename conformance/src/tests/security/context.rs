//! Runner-side security context for tracking keys and sequence numbers.
//!
//! This state lives in the test runner (parent process) and is used to
//! wrap/unwrap secure telegrams. It mirrors what ETS would track during
//! a secure management session.

use std::collections::BTreeMap;

/// Runner-side security context.
///
/// Tracks named keys and sequence number counters for the EITT (test
/// tool) side of secure communication.
pub struct SecurityTestContext {
    /// Named keys: "TK1", "TK2", "GK1"–"GK6", "P2PK1"–"P2PK8", "FDSK".
    keys: BTreeMap<String, [u8; 16]>,

    /// EITT's sending sequence number (used when SeqSource::Tool).
    /// Incremented after each outgoing secure frame.
    pub tool_seq_nr: u64,

    /// DUT's expected next sequence number (used when SeqSource::Table).
    /// Updated when we receive a secure frame from the DUT.
    pub table_seq_nr: u64,

    /// Per-key sending sequence numbers for P2P peers.
    ///
    /// When the test runner impersonates a P2P peer (not the tool), it
    /// uses a separate sending counter per key name. Keyed by the key
    /// name (e.g., "P2PK1").
    peer_send_seq: BTreeMap<String, u64>,

    /// Per-key expected DUT sequence numbers for P2P peers.
    ///
    /// The DUT uses a separate counter for each P2P peer. Keyed by key
    /// name (e.g., "P2PK1").
    peer_table_seq: BTreeMap<String, u64>,
}

impl SecurityTestContext {
    /// Create a new context with the given key map.
    pub fn new(keys: BTreeMap<String, [u8; 16]>) -> Self {
        Self {
            keys,
            tool_seq_nr: 1, // Must be non-zero per spec.
            table_seq_nr: 1,
            peer_send_seq: BTreeMap::new(),
            peer_table_seq: BTreeMap::new(),
        }
    }

    /// Look up a key by name. Panics if not found.
    pub fn key(&self, name: &str) -> [u8; 16] {
        *self.keys.get(name).unwrap_or_else(|| panic!("Unknown security key: {}", name))
    }

    /// Get the next tool sequence number as 6 bytes and increment.
    pub fn next_tool_seq(&mut self) -> [u8; 6] {
        let val = self.tool_seq_nr;
        self.tool_seq_nr += 1;
        seq_to_bytes(val)
    }

    /// Get the current table sequence number as 6 bytes (no increment).
    pub fn current_table_seq(&self) -> [u8; 6] {
        seq_to_bytes(self.table_seq_nr)
    }

    /// Update the table sequence number after receiving a frame from the DUT.
    pub fn update_table_seq(&mut self, received: u64) {
        if received >= self.table_seq_nr {
            self.table_seq_nr = received + 1;
        }
    }

    /// Get the next P2P peer sending sequence number for a given key name
    /// and increment.
    pub fn next_peer_seq(&mut self, key_name: &str) -> [u8; 6] {
        let val = self.peer_send_seq.entry(key_name.into()).or_insert(1);
        let seq = seq_to_bytes(*val);
        *val += 1;
        seq
    }

    /// Get the current DUT sequence number for a P2P peer (no increment).
    pub fn current_peer_table_seq(&self, key_name: &str) -> [u8; 6] {
        let val = self.peer_table_seq.get(key_name).copied().unwrap_or(1);
        seq_to_bytes(val)
    }

    /// Update the DUT's sequence number for a P2P peer after receiving a
    /// sync response or data frame from the DUT.
    pub fn update_peer_table_seq(&mut self, key_name: &str, received: u64) {
        let entry = self.peer_table_seq.entry(key_name.into()).or_insert(1);
        if received >= *entry {
            *entry = received + 1;
        }
    }

    /// Set the P2P peer sending sequence number for a given key name.
    pub fn set_peer_seq(&mut self, key_name: &str, val: u64) {
        self.peer_send_seq.insert(key_name.into(), val);
    }

    /// Set the DUT's expected sequence number for a P2P peer.
    pub fn set_peer_table_seq(&mut self, key_name: &str, val: u64) {
        self.peer_table_seq.insert(key_name.into(), val);
    }

    /// Read a counter without consuming it.
    ///
    /// What an S-A_Sync_Req advertises: the number we intend to use
    /// next, not one we are spending. Every source resolves to its
    /// current value, so a request sent straight after a reset carries
    /// the value the reset left behind rather than a stale number.
    pub fn peek_sequence(&self, source: &crate::SeqSource) -> u64 {
        match source {
            crate::SeqSource::Tool => self.tool_seq_nr,
            crate::SeqSource::Table => self.table_seq_nr,
            crate::SeqSource::Fixed(val) => *val,
            crate::SeqSource::Peer(name) => self.peer_send_seq.get(name).copied().unwrap_or(1),
            crate::SeqSource::PeerTable(name) => self.peer_table_seq.get(name).copied().unwrap_or(1),
            // The EITT lowering resolves this before the engine sees it.
            crate::SeqSource::Unpinned(name) => {
                unreachable!("unresolved sequence variable {name} reached the engine")
            }
        }
    }

    /// Record what a telegram actually went out with.
    ///
    /// The sending counters are "next to use", so after a telegram they
    /// have to sit one past whatever it carried. Normally that is what
    /// `next_tool_seq` and `next_peer_seq` already did, and this is a
    /// no-op; it matters when a `SeqNumOfs` moved the number away from
    /// the counter, because EITT stores the number it *sent* (manual
    /// §12.21.4) and so must we.
    ///
    /// Forwards only, so the deliberate backwards offsets — the replay
    /// tests — leave the counter alone. The receiving counters
    /// (`Table`, `PeerTable`) are not touched: they track what the
    /// device sends us, not what we send it.
    pub fn note_sent(&mut self, source: &crate::SeqSource, sent: &[u8; 6]) {
        let next = seq_from_bytes(sent).saturating_add(1);
        match source {
            crate::SeqSource::Tool => {
                if next > self.tool_seq_nr {
                    self.tool_seq_nr = next;
                }
            }
            crate::SeqSource::Peer(name) => {
                let entry = self.peer_send_seq.entry(name.clone()).or_insert(1);
                if next > *entry {
                    *entry = next;
                }
            }
            _ => {}
        }
    }

    /// Put one counter at a chosen value.
    ///
    /// The template's `@@[sn`, which 3.3.15 uses to move the tool
    /// counter somewhere a sync then has to reconcile.
    pub fn set_sequence(&mut self, counter: crate::SecuritySeqCounter, value: u64) {
        match counter {
            crate::SecuritySeqCounter::Tool => self.tool_seq_nr = value,
            crate::SecuritySeqCounter::Table => self.table_seq_nr = value,
        }
    }

    /// Reset all sequence-number tracking back to factory defaults.
    ///
    /// Two callers want this. A full DUT reset (destructive factory
    /// reset, shared memory rebuilt, child respawned) leaves the device
    /// expecting the `seq = 1` baseline a fresh one starts from. So does
    /// the template's `@@[rn`, which resets EITT's own Security
    /// Sequencenumber Table and nothing else — the device keeps whatever
    /// it has stored, and the sync request that follows is what
    /// reconciles the two.
    ///
    /// One, not zero: EITT's table starts at 1 (manual §12.21.4, "it is
    /// possible to set a fixed start value for automatically created
    /// sequence numbers (default value is 1)"), and a device rejects a
    /// secure frame carrying sequence number zero outright.
    pub fn reset_peer_state(&mut self) {
        self.tool_seq_nr = 1;
        self.table_seq_nr = 1;
        self.peer_send_seq.clear();
        self.peer_table_seq.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SeqSource;

    fn ctx() -> SecurityTestContext {
        SecurityTestContext::new(BTreeMap::new())
    }

    #[test]
    fn a_forward_offset_carries_the_counter_with_it() {
        let mut c = ctx();
        // Two telegrams, the second offset by +2 the way 3.1.11 sends
        // them: takes 1, then takes 2 and sends 4.
        assert_eq!(seq_from_bytes(&c.next_tool_seq()), 1);
        c.note_sent(&SeqSource::Tool, &seq_to_bytes(1));
        let taken = seq_from_bytes(&c.next_tool_seq());
        assert_eq!(taken, 2);
        c.note_sent(&SeqSource::Tool, &seq_to_bytes(taken + 2));
        // The device stored 4, so the next number we send has to be 5.
        // Leaving the counter at 3 is what made the following case
        // replay a number the device already had.
        assert_eq!(seq_from_bytes(&c.next_tool_seq()), 5);
    }

    #[test]
    fn a_backward_offset_leaves_the_counter_alone() {
        let mut c = ctx();
        for _ in 0..5 {
            let v = seq_from_bytes(&c.next_tool_seq());
            c.note_sent(&SeqSource::Tool, &seq_to_bytes(v));
        }
        // 3.1.22 deliberately replays an old number; the counter must
        // not rewind behind it or everything after would be a replay too.
        c.note_sent(&SeqSource::Tool, &seq_to_bytes(2));
        assert_eq!(seq_from_bytes(&c.next_tool_seq()), 6);
    }

    #[test]
    fn peeking_a_counter_does_not_spend_it() {
        let mut c = ctx();
        c.set_sequence(crate::SecuritySeqCounter::Tool, 42);
        assert_eq!(c.peek_sequence(&SeqSource::Tool), 42);
        assert_eq!(c.peek_sequence(&SeqSource::Tool), 42);
        // Which is what a sync request advertises — the next number to
        // use, still unused.
        assert_eq!(seq_from_bytes(&c.next_tool_seq()), 42);
    }

    #[test]
    fn a_reset_puts_the_counters_back_to_one_not_zero() {
        let mut c = ctx();
        c.set_sequence(crate::SecuritySeqCounter::Tool, 5_000_000_000);
        c.reset_peer_state();
        // EITT's table starts at 1 (manual §12.21.4, "default value
        // is 1"), and a device rejects sequence number zero outright, so
        // a sync request sent straight after a reset must advertise 1.
        assert_eq!(c.peek_sequence(&SeqSource::Tool), 1);
    }
}

/// Convert a 64-bit counter to a 6-byte big-endian sequence number.
pub fn seq_to_bytes(val: u64) -> [u8; 6] {
    let full = val.to_be_bytes();
    let mut seq = [0u8; 6];
    seq.copy_from_slice(&full[2..8]);
    seq
}

/// Convert a 6-byte big-endian sequence number to a 64-bit counter.
pub fn seq_from_bytes(bytes: &[u8; 6]) -> u64 {
    let mut full = [0u8; 8];
    full[2..8].copy_from_slice(bytes);
    u64::from_be_bytes(full)
}
