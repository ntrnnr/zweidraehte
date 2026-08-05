//! Persistence for Data Secure sequence counters.

use std::collections::HashMap;

/// Persistent backing for per-device sequence-number counters.
///
/// Keyed by the 6-byte device serial number — the individual address is
/// reassignable, the serial is factory-stable. Both counters start at 1
/// for unknown devices: sequence number 0 is rejected by every
/// receiver, and 1 is what a factory-fresh device expects.
///
/// `tool_seq` is our sending Sequence Number for Tool Access (the value
/// that must never repeat under the same key); `table_seq` is the next
/// sequence number we accept from the device.
pub trait SeqNumberStore: Send {
    /// Our next sending sequence number for `serial`. 1 if unknown.
    fn load_tool_seq(&self, serial: &[u8; 6]) -> u64;

    /// Persist our sending counter (called once the frame is on the bus).
    fn save_tool_seq(&mut self, serial: &[u8; 6], seq: u64) -> std::io::Result<()>;

    /// The next sequence number we accept from `serial`. 1 if unknown.
    fn load_table_seq(&self, serial: &[u8; 6]) -> u64;

    /// Persist the device counter (called after each verified frame).
    fn save_table_seq(&mut self, serial: &[u8; 6], seq: u64) -> std::io::Result<()>;
}

/// In-memory sequence store: counters survive reconnects within one
/// process but not a restart. Fine for tests and throwaway tooling; a
/// restarted tool then recovers valid counters through the S-A_Sync
/// handshake at the next secure connect.
#[derive(Default)]
pub struct MemSeqStore {
    tool: HashMap<[u8; 6], u64>,
    table: HashMap<[u8; 6], u64>,
}

impl MemSeqStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SeqNumberStore for MemSeqStore {
    fn load_tool_seq(&self, serial: &[u8; 6]) -> u64 {
        self.tool.get(serial).copied().unwrap_or(1)
    }

    fn save_tool_seq(&mut self, serial: &[u8; 6], seq: u64) -> std::io::Result<()> {
        let slot = self.tool.entry(*serial).or_insert(1);
        *slot = (*slot).max(seq);
        Ok(())
    }

    fn load_table_seq(&self, serial: &[u8; 6]) -> u64 {
        self.table.get(serial).copied().unwrap_or(1)
    }

    fn save_table_seq(&mut self, serial: &[u8; 6], seq: u64) -> std::io::Result<()> {
        let slot = self.table.entry(*serial).or_insert(1);
        *slot = (*slot).max(seq);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERIAL: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x01];

    #[test]
    fn unknown_serial_returns_1_not_0() {
        let store = MemSeqStore::new();
        assert_eq!(store.load_tool_seq(&SERIAL), 1);
        assert_eq!(store.load_table_seq(&SERIAL), 1);
    }

    #[test]
    fn forward_only_update_does_not_regress() {
        let mut store = MemSeqStore::new();
        store.save_tool_seq(&SERIAL, 100).expect("in-memory save cannot fail");
        store.save_tool_seq(&SERIAL, 50).expect("in-memory save cannot fail");
        assert_eq!(store.load_tool_seq(&SERIAL), 100);
    }
}
