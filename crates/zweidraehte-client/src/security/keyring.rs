//! Bus-level keyring: which devices are secure, under which key.

use std::collections::HashMap;

use tokio::time::{Duration, Instant};

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_util::secret::SecretBytes;

use super::SecureError;
use super::channel::SecureChannel;
use super::store::{MemSeqStore, SeqNumberStore};

/// The short window suppresses immediately repeated synchronization exchanges
/// without treating persisted counters as proof of current agreement. Two
/// seconds also clears the device's one-second sync-response rate limit.
const SECURE_SYNC_FRESHNESS: Duration = Duration::from_secs(2);

struct SynchronizedCredential {
    key: SecretBytes,
    synchronized_at: Instant,
}

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
#[derive(Clone)]
pub struct SecurityEntry {
    mode: DeviceSecurityMode,
    tool_key: Option<SecretBytes>,
    fdsk: Option<SecretBytes>,
    /// KNX serial number — the stable identity the sequence counters
    /// are persisted under. `None` (e.g. a keyring device exported
    /// without its serial) means the counters are not persisted; the
    /// sync handshake recovers them on every connect.
    serial: Option<[u8; 6]>,
}

impl core::fmt::Debug for SecurityEntry {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SecurityEntry")
            .field("mode", &self.mode)
            .field("tool_key", &self.tool_key.as_ref().map(|_| "[REDACTED]"))
            .field("fdsk", &self.fdsk.as_ref().map(|_| "[REDACTED]"))
            .field("serial", &self.serial)
            .finish()
    }
}

impl SecurityEntry {
    /// Secure device with a commissioned tool key.
    pub fn secure_with_tool_key(tool_key: [u8; 16], serial: [u8; 6]) -> Self {
        Self { mode: DeviceSecurityMode::Secure, tool_key: Some(tool_key.into()), fdsk: None, serial: Some(serial) }
    }

    /// Factory-fresh secure device — the FDSK acts as the tool key.
    pub fn secure_with_fdsk(fdsk: [u8; 16], serial: [u8; 6]) -> Self {
        Self { mode: DeviceSecurityMode::Secure, tool_key: None, fdsk: Some(fdsk.into()), serial: Some(serial) }
    }

    /// Device spoken to plain (e.g. secure-capable but security mode
    /// disabled). Any keys carried alongside are inert.
    pub fn plain(serial: [u8; 6]) -> Self {
        Self { mode: DeviceSecurityMode::Plain, tool_key: None, fdsk: None, serial: Some(serial) }
    }

    /// Build an entry with both commissioning credentials. Secure entries are
    /// rejected when neither credential is present, preventing an accidental
    /// plaintext-or-fail configuration from being represented.
    pub fn with_credentials(
        mode: DeviceSecurityMode,
        tool_key: Option<[u8; 16]>,
        fdsk: Option<[u8; 16]>,
        serial: Option<[u8; 6]>,
    ) -> Result<Self, SecureError> {
        if mode == DeviceSecurityMode::Secure && tool_key.is_none() && fdsk.is_none() {
            return Err(SecureError::MissingKey);
        }
        Ok(Self { mode, tool_key: tool_key.map(Into::into), fdsk: fdsk.map(Into::into), serial })
    }

    pub fn mode(&self) -> DeviceSecurityMode {
        self.mode
    }

    pub fn tool_key(&self) -> Option<&[u8; 16]> {
        self.tool_key.as_ref().map(|key| key.key16_ref().expect("tool keys have fixed width"))
    }

    pub fn fdsk(&self) -> Option<&[u8; 16]> {
        self.fdsk.as_ref().map(|key| key.key16_ref().expect("FDSKs have fixed width"))
    }

    pub fn serial(&self) -> Option<[u8; 6]> {
        self.serial
    }

    /// The key secure traffic runs under: tool key if set, else FDSK.
    pub fn active_key(&self) -> Option<&[u8; 16]> {
        self.tool_key().or_else(|| self.fdsk())
    }
}

/// Bus-level keyring plus the sequence-counter store.
///
/// Owned by the bus task; mutated through `BusCommand::SetDeviceSecurity`.
pub struct SecurityStore {
    entries: HashMap<IndividualAddress, SecurityEntry>,
    /// Recently synchronized credentials. This deliberately does not survive
    /// process restart and expires quickly: durable sequence floors prevent
    /// number reuse, but do not prove that the peer still agrees with them.
    synchronized_credentials: HashMap<[u8; 6], SynchronizedCredential>,
    /// Group keys by raw group address. A group address appearing here
    /// makes its traffic secure in both directions: outgoing telegrams
    /// are wrapped, incoming plaintext is dropped (downgrade
    /// protection, same gate a device applies to its secured group
    /// objects).
    group_keys: HashMap<u16, SecretBytes>,
    seq_store: Box<dyn SeqNumberStore>,
}

/// Milliseconds since the KNX Data Secure epoch 2018-01-05T00:00:00Z —
/// the conventional wall-clock floor for a tool's sending sequence
/// number (ETS and xknx seed the same way).
pub fn knx_sequence_timestamp_floor() -> u64 {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    const KNX_EPOCH: Duration = Duration::from_secs(1_515_110_400); // 2018-01-05T00:00:00Z
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(KNX_EPOCH).saturating_sub(KNX_EPOCH).as_millis() as u64
}

impl SecurityStore {
    /// Empty keyring with in-memory (non-persistent) sequence counters.
    pub fn new() -> Self {
        Self::with_store(Box::new(MemSeqStore::new()))
    }

    /// Empty keyring over a caller-provided sequence store.
    pub fn with_store(seq_store: Box<dyn SeqNumberStore>) -> Self {
        Self {
            entries: HashMap::new(),
            synchronized_credentials: HashMap::new(),
            group_keys: HashMap::new(),
            seq_store,
        }
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
            entry.tool_key = Some(tool_key.into());
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
                let table_seq = self.seq_store.load_device_seq(&serial);
                SecureChannel::new(*key, serial, table_seq)
            }
            None => SecureChannel::new_unpersisted(*key, 1),
        }))
    }

    /// Whether an immediately repeated connection can reuse a recent sync.
    pub(crate) fn has_fresh_sync(&self, ia: IndividualAddress) -> bool {
        let Some(entry) = self.entries.get(&ia) else { return false };
        let Some(serial) = entry.serial else { return false };
        let Some(active_key) = entry.active_key() else { return false };
        if entry.mode != DeviceSecurityMode::Secure {
            return false;
        }

        self.synchronized_credentials.get(&serial).is_some_and(|credential| {
            credential.key.key16_ref().expect("synchronized keys have fixed width") == active_key
                && credential.synchronized_at.elapsed() < SECURE_SYNC_FRESHNESS
        })
    }

    /// Whether this exact credential has authoritative counters and may send
    /// outside the point-to-point connection which established them.
    pub(crate) fn can_send_with(&self, ia: IndividualAddress, key: &[u8; 16]) -> bool {
        let Some(entry) = self.entries.get(&ia) else { return false };
        let Some(serial) = entry.serial else { return false };
        if entry.mode != DeviceSecurityMode::Secure || entry.active_key() != Some(key) {
            return false;
        }

        self.synchronized_credentials
            .get(&serial)
            .is_some_and(|credential| credential.key.key16_ref().expect("synchronized keys have fixed width") == key)
    }

    /// Cache the active credential briefly after both sequence directions are
    /// established successfully.
    pub(crate) fn mark_synchronized(&mut self, ia: IndividualAddress) {
        let Some(entry) = self.entries.get(&ia) else { return };
        let (Some(serial), Some(active_key)) = (entry.serial, entry.active_key()) else { return };
        self.synchronized_credentials
            .insert(serial, SynchronizedCredential { key: (*active_key).into(), synchronized_at: Instant::now() });
    }

    /// The client-wide next sending value advertised in S-A_Sync.
    pub fn client_sequence(&self) -> u64 {
        self.seq_store.load_client_seq().max(knx_sequence_timestamp_floor())
    }

    /// Durably reserve the next value shared by management and group traffic.
    pub fn reserve_sending_sequence(&mut self) -> std::io::Result<u64> {
        self.seq_store.reserve_client_seq(knx_sequence_timestamp_floor())
    }

    /// Durably reserve the shared client counter for tool access. A
    /// project-backed store may allow this restricted path while recovering
    /// state, after secure sync established the receiver's floor.
    pub fn reserve_management_sequence(&mut self) -> std::io::Result<u64> {
        self.seq_store.reserve_management_client_seq(knx_sequence_timestamp_floor())
    }

    /// A verified sync response may move the client floor forward, never back.
    pub fn advance_client_sequence(&mut self, next: u64) -> std::io::Result<u64> {
        let selected = self.client_sequence().max(next);
        self.seq_store.save_client_seq(selected)?;
        Ok(selected)
    }

    /// Persist a managed device's authenticated incoming floor before delivery.
    pub fn save_device_seq(&mut self, serial: &[u8; 6], seq: u64) -> std::io::Result<()> {
        self.seq_store.save_device_seq(serial, seq)
    }

    /// The next authenticated number expected from one managed device.
    ///
    /// Programming PID 59 must not move behind an observation that was
    /// already authenticated and committed by an earlier session.
    pub fn device_sequence_floor(&self, serial: &[u8; 6]) -> u64 {
        self.seq_store.load_device_seq(serial)
    }

    /// Register or replace the group key for a raw group address.
    pub fn set_group_key(&mut self, ga: u16, key: [u8; 16]) {
        self.group_keys.insert(ga, key.into());
    }

    /// The group key for a raw group address, if that address is
    /// secured.
    pub fn get_group_key(&self, ga: u16) -> Option<&[u8; 16]> {
        self.group_keys.get(&ga).map(|key| key.key16_ref().expect("group keys have fixed width"))
    }

    /// The next sequence number accepted from group sender `ia`
    /// (replay floor).
    pub fn sender_seq_floor(&self, ia: IndividualAddress) -> u64 {
        self.entries
            .get(&ia)
            .and_then(|entry| entry.serial)
            .map_or_else(|| self.seq_store.load_sender_seq(ia), |serial| self.seq_store.load_device_seq(&serial))
    }

    /// Persist a sender's replay floor after a verified group frame;
    /// failures logged, not fatal.
    // TODO: watermark batching if per-frame JSON rewrites ever matter
    // on a busy secured bus (the device batches its *sending* counter
    // the same way).
    pub fn save_sender_seq(&mut self, ia: IndividualAddress, seq: u64) -> std::io::Result<()> {
        if let Some(serial) = self.entries.get(&ia).and_then(|entry| entry.serial) {
            self.seq_store.save_device_seq(&serial, seq)
        } else {
            self.seq_store.save_sender_seq(ia, seq)
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
        let entry = SecurityEntry::with_credentials(DeviceSecurityMode::Plain, None, Some(FDSK), Some(SERIAL))
            .expect("plain entries permit retained credentials");
        store.set_device_security(ia(), entry);
        assert!(store.make_channel(ia()).expect("plain mode is not an error").is_none());
    }

    #[test]
    fn tool_key_takes_precedence_over_fdsk() {
        let mut store = SecurityStore::new();
        let entry = SecurityEntry::with_credentials(DeviceSecurityMode::Secure, Some(KEY), Some(FDSK), Some(SERIAL))
            .expect("tool key and FDSK form a valid secure entry");
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
        assert_eq!(entry.tool_key(), Some(&KEY));
        assert_eq!(entry.fdsk(), Some(&FDSK));
        assert_eq!(entry.serial(), Some(SERIAL));
        assert_eq!(entry.mode(), DeviceSecurityMode::Secure);
    }

    #[tokio::test(start_paused = true)]
    async fn only_a_recent_sync_suppresses_the_next_handshake() {
        let mut store = SecurityStore::new();
        store.set_device_security(ia(), SecurityEntry::secure_with_fdsk(FDSK, SERIAL));
        store.seq_store.save_client_seq(42).expect("client floor seeds");
        store.seq_store.save_device_seq(&SERIAL, 17).expect("device floor seeds");

        assert!(!store.has_fresh_sync(ia()), "persisted counters do not prove current agreement");

        store.mark_synchronized(ia());
        assert!(store.has_fresh_sync(ia()), "an immediately repeated connection may reuse the sync");

        tokio::time::advance(SECURE_SYNC_FRESHNESS).await;
        assert!(!store.has_fresh_sync(ia()), "the synchronization cache expires after two seconds");
        assert!(store.can_send_with(ia(), &FDSK), "expiry requires a new connection sync, not retroactive distrust");

        store.set_device_security(ia(), SecurityEntry::secure_with_tool_key(KEY, SERIAL));
        assert!(!store.has_fresh_sync(ia()), "durable Tool-Key counters do not suppress synchronization");
        assert!(!store.can_send_with(ia(), &KEY), "a different credential must synchronize before broadcast use");
    }

    #[test]
    fn secure_without_key_is_an_error() {
        assert!(matches!(
            SecurityEntry::with_credentials(DeviceSecurityMode::Secure, None, None, Some(SERIAL)),
            Err(SecureError::MissingKey)
        ));
    }

    #[test]
    fn security_entry_debug_redacts_credentials() {
        let entry = SecurityEntry::with_credentials(
            DeviceSecurityMode::Secure,
            Some(*b"tool-key-canary!"),
            Some(*b"fdsk-key-canary!"),
            Some(SERIAL),
        )
        .expect("credentials are valid");
        let diagnostic = format!("{entry:?}");
        assert!(!diagnostic.contains("tool-key-canary"));
        assert!(!diagnostic.contains("fdsk-key-canary"));
        assert!(diagnostic.contains("[REDACTED]"));
    }

    #[test]
    fn client_seq_starts_at_timestamp_floor_and_is_monotonic() {
        let mut store = SecurityStore::new();

        // ms since 2018-01-05 — in 2026 this is comfortably above
        // 2×10¹¹ and can only have come from the timestamp floor
        // (the fresh MemSeqStore holds nothing).
        let first = store.reserve_sending_sequence().expect("sequence persists");
        assert!(first > 200_000_000_000, "seeded from wall clock, got {first}");

        let second = store.reserve_sending_sequence().expect("sequence persists");
        let third = store.reserve_sending_sequence().expect("sequence persists");
        assert_eq!(second, first + 1);
        assert_eq!(third, first + 2);
    }

    #[test]
    fn client_seq_resumes_from_persisted_value_when_higher() {
        let mut seq_store = MemSeqStore::new();
        let far_future = 0xFF00_0000_0000;
        seq_store.save_client_seq(far_future).expect("in-memory save cannot fail");

        let mut store = SecurityStore::with_store(Box::new(seq_store));
        assert_eq!(
            store.reserve_sending_sequence().expect("sequence persists"),
            far_future,
            "persisted value above the timestamp floor wins"
        );
    }

    #[test]
    fn channel_loads_counters_from_store() {
        let mut seq_store = MemSeqStore::new();
        seq_store.save_client_seq(42).expect("in-memory save cannot fail");
        seq_store.save_device_seq(&SERIAL, 17).expect("in-memory save cannot fail");

        let mut store = SecurityStore::with_store(Box::new(seq_store));
        store.set_device_security(ia(), SecurityEntry::secure_with_fdsk(FDSK, SERIAL));

        // Capture the lower bound before channel construction. Comparing to
        // a fresh wall-clock reading afterwards is flaky at a millisecond
        // boundary even when the channel selected the correct floor.
        let floor = knx_sequence_timestamp_floor();
        let mut ch = store.make_channel(ia()).expect("keyed entry").expect("secure mode");
        assert!(store.client_sequence() >= floor);
        assert_eq!(ch.apply_remote_sync(1), 17, "channel inherits only the receive floor");
    }
}
