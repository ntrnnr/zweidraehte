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
    /// are persisted under. `None` (e.g. a keyring device exported
    /// without its serial) means the counters are not persisted; the
    /// sync handshake recovers them on every connect.
    pub serial: Option<[u8; 6]>,
}

impl SecurityEntry {
    /// Secure device with a commissioned tool key.
    pub fn secure_with_tool_key(tool_key: [u8; 16], serial: [u8; 6]) -> Self {
        Self { mode: DeviceSecurityMode::Secure, tool_key: Some(tool_key), fdsk: None, serial: Some(serial) }
    }

    /// Factory-fresh secure device — the FDSK acts as the tool key.
    pub fn secure_with_fdsk(fdsk: [u8; 16], serial: [u8; 6]) -> Self {
        Self { mode: DeviceSecurityMode::Secure, tool_key: None, fdsk: Some(fdsk), serial: Some(serial) }
    }

    /// Device spoken to plain (e.g. secure-capable but security mode
    /// disabled). Any keys carried alongside are inert.
    pub fn plain(serial: [u8; 6]) -> Self {
        Self { mode: DeviceSecurityMode::Plain, tool_key: None, fdsk: None, serial: Some(serial) }
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
    /// Group keys by raw group address. A group address appearing here
    /// makes its traffic secure in both directions: outgoing telegrams
    /// are wrapped, incoming plaintext is dropped (downgrade
    /// protection, same gate a device applies to its secured group
    /// objects).
    group_keys: HashMap<u16, [u8; 16]>,
    /// The client's single secure sending sequence number for non-tool
    /// (group) traffic — one counter per station per 03/03/07, not one
    /// per key. Seeded to at least the current time in milliseconds
    /// since 2018-01-05T00:00:00Z so it never regresses even without a
    /// persistent store, and even if the tunnel IA we send under was
    /// previously used by another tool: receivers keep a last-valid
    /// number per sender IA, and there is no group-addressed sync
    /// service to recover a rewound counter.
    own_sending_seq: u64,
    seq_store: Box<dyn SeqNumberStore>,
}

/// Milliseconds since the KNX Data Secure epoch 2018-01-05T00:00:00Z —
/// the conventional wall-clock floor for a tool's sending sequence
/// number (ETS and xknx seed the same way).
fn timestamp_floor() -> u64 {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    const KNX_EPOCH: Duration = Duration::from_secs(1_515_110_400); // 2018-01-05T00:00:00Z
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(KNX_EPOCH).saturating_sub(KNX_EPOCH).as_millis() as u64
}

impl SecurityStore {
    /// Empty keyring with in-memory (non-persistent) sequence counters.
    pub fn new() -> Self {
        Self::with_store(Box::new(MemSeqStore::new()))
    }

    /// Empty keyring over a caller-provided sequence store (e.g.
    /// [`super::JsonSeqStore`]).
    pub fn with_store(seq_store: Box<dyn SeqNumberStore>) -> Self {
        let own_sending_seq = seq_store.load_own_seq().max(timestamp_floor());
        Self { entries: HashMap::new(), group_keys: HashMap::new(), own_sending_seq, seq_store }
    }

    /// Register or replace a device's security entry.
    pub fn set_device_security(&mut self, ia: IndividualAddress, entry: SecurityEntry) {
        self.entries.insert(ia, entry);
    }

    /// Re-key the address lookup after a serial-number IA write. Secure
    /// counters stay associated with the entry's serial number.
    pub fn move_device_security(&mut self, previous: IndividualAddress, current: IndividualAddress) {
        if previous == current {
            return;
        }
        if let Some(entry) = self.entries.remove(&previous) {
            self.entries.insert(current, entry);
        }
    }

    /// Remove a device entry so the next connection is explicitly plain.
    pub fn remove_device_security(&mut self, ia: IndividualAddress) {
        self.entries.remove(&ia);
    }

    /// Commit a tool-key rotation after its response authenticated under the
    /// new key. Keep the FDSK so a caller can still recover after a factory
    /// reset.
    pub(crate) fn commit_tool_key(&mut self, ia: IndividualAddress, tool_key: [u8; 16]) {
        if let Some(entry) = self.entries.get_mut(&ia) {
            entry.mode = DeviceSecurityMode::Secure;
            entry.tool_key = Some(tool_key);
        }
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
        Ok(Some(match entry.serial {
            Some(serial) => {
                let tool_seq = self.seq_store.load_tool_seq(&serial);
                let table_seq = self.seq_store.load_table_seq(&serial);
                SecureChannel::new(key, serial, tool_seq, table_seq)
            }
            None => SecureChannel::new_unpersisted(key, 1, 1),
        }))
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

    /// Register or replace the group key for a raw group address.
    pub fn set_group_key(&mut self, ga: u16, key: [u8; 16]) {
        self.group_keys.insert(ga, key);
    }

    /// The group key for a raw group address, if that address is
    /// secured.
    pub fn get_group_key(&self, ga: u16) -> Option<&[u8; 16]> {
        self.group_keys.get(&ga)
    }

    /// Consume one value from the client-wide secure sending counter.
    ///
    /// The successor is persisted immediately — before the frame is
    /// even sent — because a consumed number must never be reused under
    /// the same keys; losing an unsent number to a crash is harmless
    /// (the store is forward-only and the timestamp floor covers a
    /// failed write).
    pub fn next_group_seq(&mut self) -> u64 {
        let seq = self.own_sending_seq;
        self.own_sending_seq += 1;
        if let Err(e) = self.seq_store.save_own_seq(self.own_sending_seq) {
            log::warn!("failed to persist own sending seq: {e}");
        }
        seq
    }

    /// The next sequence number accepted from group sender `ia`
    /// (replay floor).
    pub fn sender_seq_floor(&self, ia: IndividualAddress) -> u64 {
        self.seq_store.load_sender_seq(ia)
    }

    /// Persist a sender's replay floor after a verified group frame;
    /// failures logged, not fatal.
    // TODO: watermark batching if per-frame JSON rewrites ever matter
    // on a busy secured bus (the device batches its *sending* counter
    // the same way).
    pub fn save_sender_seq(&mut self, ia: IndividualAddress, seq: u64) {
        if let Err(e) = self.seq_store.save_sender_seq(ia, seq) {
            log::warn!("failed to persist sender seq for {ia}: {e}");
        }
    }

    /// Insert a `Secure` entry for every keyring device that carries a
    /// key, replacing existing entries for the same IA, and take over
    /// every group key.
    ///
    /// For devices with a serial, the keyring's `SequenceNumber` (the
    /// device's last observed sending number at export) seeds the
    /// sequence store as `table_seq = SequenceNumber + 1` — forward-only,
    /// and the sync handshake on connect corrects it either way. The
    /// same value seeds the per-sender group replay floor, which has no
    /// sync to correct it. Devices with neither tool key nor FDSK are
    /// skipped: there is nothing to secure with.
    ///
    /// The keyring interfaces' per-tunnel-slot sender lists are not
    /// consumed.
    ///
    /// Returns how many device entries were added.
    pub fn import_keyring(&mut self, keyring: &super::knxkeys::Keyring) -> usize {
        // TODO: enforce keyring sender lists on incoming group traffic
        // if a use case appears — devices themselves accept any SIAT
        // sender, so this would be stricter than the installed base.
        for (&ga, key) in &keyring.group_keys {
            self.set_group_key(ga, *key);
        }
        let mut added = 0;
        for device in &keyring.devices {
            if device.sequence_number > 0 {
                let floor = device.sequence_number + 1;
                if let Some(serial) = device.serial {
                    self.save_table_seq(&serial, floor);
                }
                self.save_sender_seq(device.individual_address, floor);
            }
            if device.tool_key.is_none() && device.fdsk.is_none() {
                continue;
            }
            self.set_device_security(device.individual_address, SecurityEntry {
                mode: DeviceSecurityMode::Secure,
                tool_key: device.tool_key,
                fdsk: device.fdsk,
                serial: device.serial,
            });
            added += 1;
        }
        added
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
    fn committing_tool_key_preserves_factory_key_and_serial() {
        let mut store = SecurityStore::new();
        store.set_device_security(ia(), SecurityEntry::secure_with_fdsk(FDSK, SERIAL));

        store.commit_tool_key(ia(), KEY);

        let entry = store.get_entry(ia()).expect("entry survives rotation");
        assert_eq!(entry.tool_key, Some(KEY));
        assert_eq!(entry.fdsk, Some(FDSK));
        assert_eq!(entry.serial, Some(SERIAL));
        assert_eq!(entry.mode, DeviceSecurityMode::Secure);
    }

    #[test]
    fn secure_without_key_is_an_error() {
        let mut store = SecurityStore::new();
        let entry =
            SecurityEntry { mode: DeviceSecurityMode::Secure, tool_key: None, fdsk: None, serial: Some(SERIAL) };
        store.set_device_security(ia(), entry);
        assert!(matches!(store.make_channel(ia()), Err(SecureError::MissingKey)));
    }

    #[test]
    fn import_keyring_fills_entries_and_seeds_seq() {
        use crate::security::knxkeys::{Keyring, KeyringDevice};

        let devices = vec![
            // Fully exported: tool key + FDSK + serial + seq.
            KeyringDevice {
                individual_address: IndividualAddress::new(1, 0, 203),
                tool_key: Some(KEY),
                fdsk: Some(FDSK),
                serial: Some(SERIAL),
                sequence_number: 1000,
                management_password: None,
                authentication: None,
            },
            // No serial: entry still lands, counters unpersisted.
            KeyringDevice {
                individual_address: IndividualAddress::new(1, 0, 201),
                tool_key: Some(KEY),
                fdsk: None,
                serial: None,
                sequence_number: 500,
                management_password: None,
                authentication: None,
            },
            // No key material at all: skipped.
            KeyringDevice {
                individual_address: IndividualAddress::new(1, 0, 7),
                tool_key: None,
                fdsk: None,
                serial: None,
                sequence_number: 0,
                management_password: None,
                authentication: None,
            },
        ];
        let mut group_keys = std::collections::BTreeMap::new();
        group_keys.insert(0x0901u16, [0x42u8; 16]);
        group_keys.insert(0x1202u16, [0x43u8; 16]);
        let keyring = Keyring {
            project: "test".into(),
            created_by: "6.4.1".into(),
            created: "2026-08-05T00:00:00".into(),
            backbone: None,
            interfaces: Vec::new(),
            group_keys,
            devices,
        };

        let mut store = SecurityStore::new();
        assert_eq!(store.import_keyring(&keyring), 2, "keyless device is skipped");

        assert_eq!(store.get_group_key(0x0901), Some(&[0x42u8; 16]));
        assert_eq!(store.get_group_key(0x1202), Some(&[0x43u8; 16]));
        assert_eq!(store.get_group_key(0x1B03), None);

        // Sender replay floors seeded from the exported sequence
        // numbers — keyed by IA, independent of key material.
        assert_eq!(store.sender_seq_floor(IndividualAddress::new(1, 0, 203)), 1001);
        assert_eq!(store.sender_seq_floor(IndividualAddress::new(1, 0, 201)), 501);
        assert_eq!(store.sender_seq_floor(IndividualAddress::new(1, 0, 7)), 1, "no seq exported");

        let full = store.get_entry(IndividualAddress::new(1, 0, 203)).expect("keyed device imported");
        assert_eq!(full.mode, DeviceSecurityMode::Secure);
        assert_eq!(full.tool_key, Some(KEY));
        assert_eq!(full.fdsk, Some(FDSK));

        let ch = store.make_channel(IndividualAddress::new(1, 0, 203)).expect("keyed").expect("secure");
        assert_eq!(ch.key(), &KEY, "tool key preferred over FDSK");

        // The keyring seq number seeded the store: table_seq = seq + 1.
        assert_eq!(store.seq_store.load_table_seq(&SERIAL), 1001);

        assert!(store.get_entry(IndividualAddress::new(1, 0, 201)).is_some());
        assert!(store.get_entry(IndividualAddress::new(1, 0, 7)).is_none());
    }

    #[test]
    fn own_seq_starts_at_timestamp_floor_and_is_monotonic() {
        let mut store = SecurityStore::new();

        // ms since 2018-01-05 — in 2026 this is comfortably above
        // 2×10¹¹ and can only have come from the timestamp floor
        // (the fresh MemSeqStore holds nothing).
        let first = store.next_group_seq();
        assert!(first > 200_000_000_000, "seeded from wall clock, got {first}");

        let second = store.next_group_seq();
        let third = store.next_group_seq();
        assert_eq!(second, first + 1);
        assert_eq!(third, first + 2);
    }

    #[test]
    fn own_seq_resumes_from_persisted_value_when_higher() {
        let mut seq_store = MemSeqStore::new();
        let far_future = u64::MAX / 2;
        seq_store.save_own_seq(far_future).expect("in-memory save cannot fail");

        let mut store = SecurityStore::with_store(Box::new(seq_store));
        assert_eq!(store.next_group_seq(), far_future, "persisted value above the timestamp floor wins");
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
