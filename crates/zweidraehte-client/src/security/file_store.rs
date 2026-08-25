//! JSON file-backed sequence-counter store.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fs4::FileExt;
use serde::{Deserialize, Serialize};
use zweidraehte_proto::address::IndividualAddress;

use super::store::SeqNumberStore;

/// Previous files had per-device `tool_seq` plus a separate `own_seq`.
/// Read them once and merge every sending value forward into
/// `client_next`; writes only emit the current shape.
#[derive(Default, Deserialize)]
struct ReadFormat {
    #[serde(default)]
    client_next: u64,
    #[serde(default)]
    device_seq: HashMap<String, u64>,
    #[serde(default)]
    tool_seq: HashMap<String, u64>,
    #[serde(default)]
    table_seq: HashMap<String, u64>,
    #[serde(default)]
    own_seq: u64,
    #[serde(default)]
    sender_seq: HashMap<String, u64>,
}

#[derive(Serialize)]
struct WriteFormat {
    client_next: u64,
    device_seq: HashMap<String, u64>,
    sender_seq: HashMap<String, u64>,
}

/// Sequence store persisted as a small JSON file.
///
/// The whole file is rewritten on every mutation — one u64 pair per
/// device keeps it tiny — via a temp file + rename so a crash mid-write
/// leaves the previous version intact. The successor is durable before a
/// frame is forwarded, preventing reuse after a process or power failure.
pub struct JsonSeqStore {
    path: PathBuf,
    /// The data file is atomically replaced, so locking that inode would
    /// silently stop protecting the new file. Retain a stable sidecar lock
    /// for the complete lifetime of this mutable store instead.
    _lock: File,
    client: u64,
    devices: HashMap<[u8; 6], u64>,
    senders: HashMap<IndividualAddress, u64>,
}

fn serial_hex(serial: &[u8; 6]) -> String {
    serial.iter().map(|b| format!("{b:02x}")).collect()
}

fn serial_from_hex(s: &str) -> Option<[u8; 6]> {
    if s.len() != 12 {
        return None;
    }
    let mut serial = [0u8; 6];
    for (i, chunk) in serial.iter_mut().enumerate() {
        *chunk = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(serial)
}

fn ia_hex(ia: IndividualAddress) -> String {
    format!("{:02x}{:02x}", ia.0[0], ia.0[1])
}

fn ia_from_hex(s: &str) -> Option<IndividualAddress> {
    if s.len() != 4 {
        return None;
    }
    let raw = u16::from_str_radix(s, 16).ok()?;
    Some(IndividualAddress::from_bytes(&raw.to_be_bytes()))
}

impl JsonSeqStore {
    /// Open (or create) the store at `path`. Unknown devices start both
    /// counters at 1.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let lock =
            OpenOptions::new().read(true).write(true).create(true).truncate(false).open(with_suffix(&path, ".lock"))?;
        FileExt::try_lock(&lock).map_err(|error| match error {
            fs4::TryLockError::WouldBlock => {
                std::io::Error::new(std::io::ErrorKind::WouldBlock, "the sequence store is already open for writing")
            }
            fs4::TryLockError::Error(error) => error,
        })?;
        let (client, devices, senders) = match std::fs::read(&path) {
            Ok(bytes) => {
                let parsed: ReadFormat = serde_json::from_slice(&bytes)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let convert = |m: HashMap<String, u64>| {
                    m.into_iter().filter_map(|(k, v)| serial_from_hex(&k).map(|s| (s, v))).collect()
                };
                let mut devices: HashMap<[u8; 6], u64> = convert(parsed.device_seq);
                for (serial, next) in convert(parsed.table_seq) {
                    devices.entry(serial).and_modify(|old| *old = (*old).max(next)).or_insert(next);
                }
                let client = parsed.tool_seq.into_values().fold(parsed.client_next.max(parsed.own_seq), u64::max);
                let senders =
                    parsed.sender_seq.into_iter().filter_map(|(k, v)| ia_from_hex(&k).map(|ia| (ia, v))).collect();
                (client, devices, senders)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, HashMap::new(), HashMap::new()),
            Err(e) => return Err(e),
        };
        Ok(Self { path, _lock: lock, client, devices, senders })
    }

    fn flush(&self) -> std::io::Result<()> {
        let format = WriteFormat {
            client_next: self.client,
            device_seq: self.devices.iter().map(|(s, v)| (serial_hex(s), *v)).collect(),
            sender_seq: self.senders.iter().map(|(ia, v)| (ia_hex(*ia), *v)).collect(),
        };
        let json = serde_json::to_vec_pretty(&format).expect("string-keyed maps of u64 always serialize");

        // Temp file + rename: the store never holds a half-written file.
        let tmp = with_suffix(&self.path, ".tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&json)?;
            f.sync_data()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        let parent = self.path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
        std::fs::File::open(parent)?.sync_all()
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

impl SeqNumberStore for JsonSeqStore {
    fn has_client_seq(&self) -> bool {
        self.client > 0
    }

    fn load_client_seq(&self) -> u64 {
        self.client.max(1)
    }

    fn save_client_seq(&mut self, next: u64) -> std::io::Result<()> {
        if next <= self.client {
            return Ok(());
        }
        self.client = next;
        self.flush()
    }

    fn load_device_seq(&self, serial: &[u8; 6]) -> u64 {
        self.devices.get(serial).copied().unwrap_or(1)
    }

    fn has_device_seq(&self, serial: &[u8; 6]) -> bool {
        self.devices.contains_key(serial)
    }

    fn save_device_seq(&mut self, serial: &[u8; 6], next: u64) -> std::io::Result<()> {
        let slot = self.devices.entry(*serial).or_insert(1);
        if next <= *slot {
            return Ok(());
        }
        *slot = next;
        self.flush()
    }

    fn load_sender_seq(&self, ia: IndividualAddress) -> u64 {
        self.senders.get(&ia).copied().unwrap_or(1)
    }

    fn save_sender_seq(&mut self, ia: IndividualAddress, seq: u64) -> std::io::Result<()> {
        let slot = self.senders.entry(ia).or_insert(1);
        if seq <= *slot {
            return Ok(());
        }
        *slot = seq;
        self.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERIAL: [u8; 6] = [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78];

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("zweidraehte-seqstore-{name}-{}.json", std::process::id()))
    }

    #[test]
    fn counters_persist_across_reopen() {
        let path = temp_path("reopen");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = JsonSeqStore::open(&path).expect("create fresh store");
            store.save_client_seq(42).expect("write to temp dir");
            store.save_device_seq(&SERIAL, 17).expect("write to temp dir");
        }

        let store = JsonSeqStore::open(&path).expect("reopen existing store");
        assert_eq!(store.load_client_seq(), 42);
        assert_eq!(store.load_device_seq(&SERIAL), 17);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn concurrent_writer_is_rejected_until_the_owner_drops() {
        let path = temp_path("locked");
        let _ = std::fs::remove_file(&path);

        let owner = JsonSeqStore::open(&path).expect("first writer acquires the lock");
        let error = match JsonSeqStore::open(&path) {
            Ok(_) => panic!("second writer must not share sequence state"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);

        drop(owner);
        JsonSeqStore::open(&path).expect("dropping the owner releases the lock");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(with_suffix(&path, ".lock"));
    }

    #[test]
    fn forward_only_update_does_not_regress() {
        let path = temp_path("forward");
        let _ = std::fs::remove_file(&path);

        let mut store = JsonSeqStore::open(&path).expect("create fresh store");
        store.save_client_seq(100).expect("write to temp dir");
        store.save_client_seq(50).expect("write to temp dir");
        assert_eq!(store.load_client_seq(), 100);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_serial_returns_1_not_0() {
        let path = temp_path("unknown");
        let _ = std::fs::remove_file(&path);

        let store = JsonSeqStore::open(&path).expect("create fresh store");
        assert_eq!(store.load_client_seq(), 1);
        assert_eq!(store.load_device_seq(&SERIAL), 1);
        assert_eq!(store.load_sender_seq(IndividualAddress::new(1, 0, 203)), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn group_counters_persist_across_reopen() {
        let path = temp_path("group");
        let _ = std::fs::remove_file(&path);
        let ia = IndividualAddress::new(1, 0, 203);

        {
            let mut store = JsonSeqStore::open(&path).expect("create fresh store");
            store.save_client_seq(1_000_000).expect("write to temp dir");
            store.save_sender_seq(ia, 42).expect("write to temp dir");
            // Forward-only.
            store.save_client_seq(5).expect("write to temp dir");
            store.save_sender_seq(ia, 7).expect("write to temp dir");
        }

        let store = JsonSeqStore::open(&path).expect("reopen existing store");
        assert_eq!(store.load_client_seq(), 1_000_000);
        assert_eq!(store.load_sender_seq(ia), 42);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pre_group_file_format_still_loads() {
        // A file written before group support has neither `own_seq` nor
        // `sender_seq` — serde defaults must fill them in.
        let path = temp_path("oldformat");
        std::fs::write(&path, r#"{"tool_seq":{"00fa12345678":9},"table_seq":{}}"#).expect("write to temp dir");

        let store = JsonSeqStore::open(&path).expect("old format parses");
        assert_eq!(store.load_client_seq(), 9);

        let _ = std::fs::remove_file(&path);
    }
}
