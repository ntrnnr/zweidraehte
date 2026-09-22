//! Persistence for KNX Data Secure sequence state.

use std::collections::HashMap;

use zweidraehte_proto::address::IndividualAddress;

/// Persistent backing for Data Secure sequence numbers.
///
/// Application Layer §5.3.1 gives one station one sending sequence
/// number across tool and group communication. Reserving a value is the
/// only sending operation exposed here: its successor must be durable
/// before the caller may forward the protected frame to the transport
/// layer.
pub trait SeqNumberStore: Send {
    /// The next value the client may send. 1 if no value is known.
    fn load_client_seq(&self) -> u64;

    /// Persist the next client value. Implementations only move forward.
    fn save_client_seq(&mut self, next: u64) -> std::io::Result<()>;

    /// Reserve and durably consume one value at or above `floor`.
    fn reserve_client_seq(&mut self, floor: u64) -> std::io::Result<u64> {
        let current = self.load_client_seq().max(floor).max(1);
        let successor = current
            .checked_add(1)
            .filter(|value| *value <= 0xFFFF_FFFF_FFFF)
            .ok_or_else(|| std::io::Error::other("KNX sequence-number space exhausted"))?;
        self.save_client_seq(successor)?;
        Ok(current)
    }

    /// Reserve a value for authenticated management traffic. Project-backed
    /// stores override this during explicit state recovery; other stores use
    /// the ordinary single-counter reservation.
    fn reserve_management_client_seq(&mut self, floor: u64) -> std::io::Result<u64> {
        self.reserve_client_seq(floor)
    }

    /// The next authenticated number accepted from a managed device.
    fn load_device_seq(&self, serial: &[u8; 6]) -> u64;

    /// Persist a managed device's authenticated incoming floor.
    fn save_device_seq(&mut self, serial: &[u8; 6], next: u64) -> std::io::Result<()>;

    /// The next number accepted from an unmanaged group sender.
    fn load_sender_seq(&self, ia: IndividualAddress) -> u64;

    /// Persist an unmanaged sender's authenticated incoming floor.
    fn save_sender_seq(&mut self, ia: IndividualAddress, next: u64) -> std::io::Result<()>;
}

#[derive(Default)]
pub struct MemSeqStore {
    client: u64,
    devices: HashMap<[u8; 6], u64>,
    senders: HashMap<IndividualAddress, u64>,
}

impl MemSeqStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SeqNumberStore for MemSeqStore {
    fn load_client_seq(&self) -> u64 {
        self.client.max(1)
    }

    fn save_client_seq(&mut self, next: u64) -> std::io::Result<()> {
        self.client = self.client.max(next);
        Ok(())
    }

    fn load_device_seq(&self, serial: &[u8; 6]) -> u64 {
        self.devices.get(serial).copied().unwrap_or(1)
    }

    fn save_device_seq(&mut self, serial: &[u8; 6], next: u64) -> std::io::Result<()> {
        let slot = self.devices.entry(*serial).or_insert(1);
        *slot = (*slot).max(next);
        Ok(())
    }

    fn load_sender_seq(&self, ia: IndividualAddress) -> u64 {
        self.senders.get(&ia).copied().unwrap_or(1)
    }

    fn save_sender_seq(&mut self, ia: IndividualAddress, next: u64) -> std::io::Result<()> {
        let slot = self.senders.entry(ia).or_insert(1);
        *slot = (*slot).max(next);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERIAL: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x01];

    #[test]
    fn unknown_identifiers_start_at_one() {
        let store = MemSeqStore::new();
        assert_eq!(store.load_client_seq(), 1);
        assert_eq!(store.load_device_seq(&SERIAL), 1);
        assert_eq!(store.load_sender_seq(IndividualAddress::new(1, 0, 203)), 1);
    }

    #[test]
    fn one_counter_serves_tool_and_group_reservations() {
        let mut store = MemSeqStore::new();
        assert_eq!(store.reserve_client_seq(10).expect("reserve succeeds"), 10);
        assert_eq!(store.reserve_client_seq(1).expect("reserve succeeds"), 11);
        assert_eq!(store.load_client_seq(), 12);
    }

    #[test]
    fn observations_never_regress() {
        let mut store = MemSeqStore::new();
        store.save_device_seq(&SERIAL, 100).expect("in-memory save cannot fail");
        store.save_device_seq(&SERIAL, 50).expect("in-memory save cannot fail");
        assert_eq!(store.load_device_seq(&SERIAL), 100);

        let ia = IndividualAddress::new(1, 0, 203);
        store.save_sender_seq(ia, 300).expect("in-memory save cannot fail");
        store.save_sender_seq(ia, 250).expect("in-memory save cannot fail");
        assert_eq!(store.load_sender_seq(ia), 300);
    }
}
