//! Bus-level keyring: which devices are secure, under which key.

use std::collections::HashMap;

use zweidraehte_proto::address::IndividualAddress;

use super::SecureError;
use super::channel::SecureChannel;
use super::store::{MemSeqStore, SeqNumberStore};

/// Whether a device is currently spoken to securely.
///
/// This is explicit rather than inferred from key presence: a
/// secure-capable device whose security mode is switched off answers
/// plain management only, even though its FDSK is printed on the label.
/// The keyring can hold that FDSK (for later commissioning) without
/// forcing secure communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceSecurityMode {
    /// Plain management — no wrapping, no sync handshake.
    Plain,
    /// Data Secure management under the active key.
    Secure,
}

/// Security material for one device.
///
/// FDSK and tool key are distinct slots because they are valid at
/// different points in a device's life: factory-fresh (and after a
/// master reset with erase code `FactoryReset`) the FDSK *is* the tool
/// key; once commissioned, the written tool key replaces it. On the
/// wire both are used identically. The active key is the tool key when
/// present, otherwise the FDSK — the same precedence the device itself
/// applies (FDSK fallback while no tool key is set).
#[derive(Debug, Clone)]
pub struct SecurityEntry {
    pub mode: DeviceSecurityMode,
    pub tool_key: Option<[u8; 16]>,
    pub fdsk: Option<[u8; 16]>,
    /// KNX serial number — the stable identity the sequence counters
    /// are persisted under.
    pub serial: [u8; 6],
}

impl SecurityEntry {
    /// Secure device with a commissioned tool key.
    pub fn secure_with_tool_key(tool_key: [u8; 16], serial: [u8; 6]) -> Self {
        Self { mode: DeviceSecurityMode::Secure, tool_key: Some(tool_key), fdsk: None, serial }
    }

    /// Factory-fresh secure device — the FDSK acts as the tool key.
    pub fn secure_with_fdsk(fdsk: [u8; 16], serial: [u8; 6]) -> Self {
        Self { mode: DeviceSecurityMode::Secure, tool_key: None, fdsk: Some(fdsk), serial }
    }

    /// Device spoken to plain (e.g. secure-capable but security mode
    /// disabled). Any keys carried alongside are inert.
    pub fn plain(serial: [u8; 6]) -> Self {
        Self { mode: DeviceSecurityMode::Plain, tool_key: None, fdsk: None, serial }
    }

    /// The key secure traffic runs under: tool key if set, else FDSK.
    pub fn active_key(&self) -> Option<[u8; 16]> {
        self.tool_key.or(self.fdsk)
    }
}

/// Bus-level keyring plus the sequence-counter store.
///
/// Owned by the bus task; mutated through `BusCommand::SetDeviceSecurity`.
pub struct SecurityStore {
    entries: HashMap<IndividualAddress, SecurityEntry>,
    seq_store: Box<dyn SeqNumberStore>,
}

impl SecurityStore {
    /// Empty keyring with in-memory (non-persistent) sequence counters.
    pub fn new() -> Self {
        Self::with_store(Box::new(MemSeqStore::new()))
    }

    /// Empty keyring over a caller-provided sequence store (e.g.
    /// [`super::JsonSeqStore`]).
    pub fn with_store(seq_store: Box<dyn SeqNumberStore>) -> Self {
        Self { entries: HashMap::new(), seq_store }
    }

    /// Register or replace a device's security entry.
    pub fn set_device_security(&mut self, ia: IndividualAddress, entry: SecurityEntry) {
        self.entries.insert(ia, entry);
    }

    pub fn get_entry(&self, ia: IndividualAddress) -> Option<&SecurityEntry> {
        self.entries.get(&ia)
    }

    /// Build the per-connection secure channel for `ia`, loading its
    /// counters from the sequence store.
    ///
    /// `Ok(None)` means the connection is plain (no entry, or mode
    /// `Plain`). `Err(MissingKey)` means the entry demands security but
    /// carries no key — failing the connect is better than a silent
    /// plaintext downgrade.
    pub fn make_channel(&self, ia: IndividualAddress) -> Result<Option<SecureChannel>, SecureError> {
        let Some(entry) = self.entries.get(&ia) else {
            return Ok(None);
        };
        if entry.mode == DeviceSecurityMode::Plain {
            return Ok(None);
        }
        let key = entry.active_key().ok_or(SecureError::MissingKey)?;
        let tool_seq = self.seq_store.load_tool_seq(&entry.serial);
        let table_seq = self.seq_store.load_table_seq(&entry.serial);
        Ok(Some(SecureChannel::new(key, entry.serial, tool_seq, table_seq)))
    }

    /// Persist our sending counter; a failing store is logged, not
    /// fatal — the exchange already happened.
    pub fn save_tool_seq(&mut self, serial: &[u8; 6], seq: u64) {
        if let Err(e) = self.seq_store.save_tool_seq(serial, seq) {
            log::warn!("failed to persist tool seq for {serial:02x?}: {e}");
        }
    }

    /// Persist the device counter; failures logged as above.
    pub fn save_table_seq(&mut self, serial: &[u8; 6], seq: u64) {
        if let Err(e) = self.seq_store.save_table_seq(serial, seq) {
            log::warn!("failed to persist table seq for {serial:02x?}: {e}");
        }
    }
}

impl Default for SecurityStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [0x11; 16];
    const FDSK: [u8; 16] = [0x22; 16];
    const SERIAL: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x01];

    fn ia() -> IndividualAddress {
        IndividualAddress::from_bytes(&[0x11, 0x2A])
    }

    #[test]
    fn no_entry_means_plain() {
        let store = SecurityStore::new();
        assert!(store.make_channel(ia()).expect("no entry is not an error").is_none());
    }

    #[test]
    fn plain_mode_yields_no_channel_even_with_key() {
        let mut store = SecurityStore::new();
        let mut entry = SecurityEntry::plain(SERIAL);
        entry.fdsk = Some(FDSK);
        store.set_device_security(ia(), entry);
        assert!(store.make_channel(ia()).expect("plain mode is not an error").is_none());
    }

    #[test]
    fn tool_key_takes_precedence_over_fdsk() {
        let mut store = SecurityStore::new();
        let mut entry = SecurityEntry::secure_with_tool_key(KEY, SERIAL);
        entry.fdsk = Some(FDSK);
        store.set_device_security(ia(), entry);
        let ch = store.make_channel(ia()).expect("keyed entry").expect("secure mode");
        assert_eq!(ch.key(), &KEY);
    }

    #[test]
    fn secure_without_key_is_an_error() {
        let mut store = SecurityStore::new();
        let entry = SecurityEntry { mode: DeviceSecurityMode::Secure, tool_key: None, fdsk: None, serial: SERIAL };
        store.set_device_security(ia(), entry);
        assert!(matches!(store.make_channel(ia()), Err(SecureError::MissingKey)));
    }

    #[test]
    fn channel_loads_counters_from_store() {
        let mut seq_store = MemSeqStore::new();
        seq_store.save_tool_seq(&SERIAL, 42).expect("in-memory save cannot fail");
        seq_store.save_table_seq(&SERIAL, 17).expect("in-memory save cannot fail");

        let mut store = SecurityStore::with_store(Box::new(seq_store));
        store.set_device_security(ia(), SecurityEntry::secure_with_fdsk(FDSK, SERIAL));

        let ch = store.make_channel(ia()).expect("keyed entry").expect("secure mode");
        assert_eq!(ch.peek_tool_seq(), 42);
    }
}
