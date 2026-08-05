//! Persistence for Data Secure sequence counters.

use std::collections::HashMap;

use zweidraehte_proto::address::IndividualAddress;

/// Persistent backing for Data Secure sequence-number counters.
///
/// The per-device counters are keyed by the 6-byte device serial number
/// — the individual address is reassignable, the serial is
/// factory-stable. Both counters start at 1 for unknown devices:
/// sequence number 0 is rejected by every receiver, and 1 is what a
/// factory-fresh device expects.
///
/// `tool_seq` is our sending Sequence Number for Tool Access (the value
/// that must never repeat under the same key); `table_seq` is the next
/// sequence number we accept from the device.
///
/// Group traffic adds two more kinds of counter:
///
/// - `own_seq` — the client's *single* secure sending sequence number
///   for non-tool traffic (03/03/07 keeps one Sequence Number Sending
///   per station, not one per key or per group address). It must never
///   regress: receivers track our last valid number per IA and there is
///   no group-addressed sync service to recover from a rewind.
/// - `sender_seq` — the per-sender replay floor for incoming secure
///   group frames, keyed by the sender's individual address (the same
///   identity a device uses for its SIAT slots; a group frame carries
///   no serial to key by).
pub trait SeqNumberStore: Send {
    /// Our next sending sequence number for `serial`. 1 if unknown.
    fn load_tool_seq(&self, serial: &[u8; 6]) -> u64;

    /// Persist our sending counter (called once the frame is on the bus).
    fn save_tool_seq(&mut self, serial: &[u8; 6], seq: u64) -> std::io::Result<()>;

    /// The next sequence number we accept from `serial`. 1 if unknown.
    fn load_table_seq(&self, serial: &[u8; 6]) -> u64;

    /// Persist the device counter (called after each verified frame).
    fn save_table_seq(&mut self, serial: &[u8; 6], seq: u64) -> std::io::Result<()>;

    /// The client's own non-tool sending sequence number. 1 if never
    /// stored.
    fn load_own_seq(&self) -> u64;

    /// Persist the own sending counter (called when a value is consumed).
    fn save_own_seq(&mut self, seq: u64) -> std::io::Result<()>;

    /// The next sequence number accepted from group sender `ia`. 1 if
    /// unknown.
    fn load_sender_seq(&self, ia: IndividualAddress) -> u64;

    /// Persist a sender's replay floor (called after each verified
    /// group frame).
    fn save_sender_seq(&mut self, ia: IndividualAddress, seq: u64) -> std::io::Result<()>;
}

/// In-memory sequence store: counters survive reconnects within one
/// process but not a restart. Fine for tests and throwaway tooling; a
/// restarted tool then recovers valid counters through the S-A_Sync
/// handshake at the next secure connect (tool traffic) and the
/// timestamp-floor seeding of the own counter (group traffic).
#[derive(Default)]
pub struct MemSeqStore {
    tool: HashMap<[u8; 6], u64>,
    table: HashMap<[u8; 6], u64>,
    own: u64,
    senders: HashMap<IndividualAddress, u64>,
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

    fn load_own_seq(&self) -> u64 {
        self.own.max(1)
    }

    fn save_own_seq(&mut self, seq: u64) -> std::io::Result<()> {
        self.own = self.own.max(seq);
        Ok(())
    }

    fn load_sender_seq(&self, ia: IndividualAddress) -> u64 {
        self.senders.get(&ia).copied().unwrap_or(1)
    }

    fn save_sender_seq(&mut self, ia: IndividualAddress, seq: u64) -> std::io::Result<()> {
        let slot = self.senders.entry(ia).or_insert(1);
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
        assert_eq!(store.load_own_seq(), 1);
        assert_eq!(store.load_sender_seq(IndividualAddress::new(1, 0, 203)), 1);
    }

    #[test]
    fn forward_only_update_does_not_regress() {
        let mut store = MemSeqStore::new();
        store.save_tool_seq(&SERIAL, 100).expect("in-memory save cannot fail");
        store.save_tool_seq(&SERIAL, 50).expect("in-memory save cannot fail");
        assert_eq!(store.load_tool_seq(&SERIAL), 100);

        store.save_own_seq(200).expect("in-memory save cannot fail");
        store.save_own_seq(150).expect("in-memory save cannot fail");
        assert_eq!(store.load_own_seq(), 200);

        let ia = IndividualAddress::new(1, 0, 203);
        store.save_sender_seq(ia, 300).expect("in-memory save cannot fail");
        store.save_sender_seq(ia, 250).expect("in-memory save cannot fail");
        assert_eq!(store.load_sender_seq(ia), 300);
    }
}
