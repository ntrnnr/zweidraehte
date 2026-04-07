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
