//! JSON file-backed sequence-counter store.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::store::SeqNumberStore;

/// On-disk representation: hex serial → counter value.
#[derive(Default, Serialize, Deserialize)]
struct FileFormat {
    #[serde(default)]
    tool_seq: HashMap<String, u64>,
    #[serde(default)]
    table_seq: HashMap<String, u64>,
}

/// Sequence store persisted as a small JSON file.
///
/// The whole file is rewritten on every mutation — one u64 pair per
/// device keeps it tiny — via a temp file + rename so a crash mid-write
/// leaves the previous version intact. Losing the *latest* tool_seq to
/// a crash is recovered by the S-A_Sync handshake on the next connect;
/// what the file protects against is starting over from 1.
pub struct JsonSeqStore {
    path: PathBuf,
    tool: HashMap<[u8; 6], u64>,
    table: HashMap<[u8; 6], u64>,
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

impl JsonSeqStore {
    /// Open (or create) the store at `path`. Unknown devices start both
    /// counters at 1.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (tool, table) = match std::fs::read(&path) {
            Ok(bytes) => {
                let parsed: FileFormat = serde_json::from_slice(&bytes)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let convert = |m: HashMap<String, u64>| {
                    m.into_iter().filter_map(|(k, v)| serial_from_hex(&k).map(|s| (s, v))).collect()
                };
                (convert(parsed.tool_seq), convert(parsed.table_seq))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (HashMap::new(), HashMap::new()),
            Err(e) => return Err(e),
        };
        Ok(Self { path, tool, table })
    }

    fn flush(&self) -> std::io::Result<()> {
        let format = FileFormat {
            tool_seq: self.tool.iter().map(|(s, v)| (serial_hex(s), *v)).collect(),
            table_seq: self.table.iter().map(|(s, v)| (serial_hex(s), *v)).collect(),
        };
        let json = serde_json::to_vec_pretty(&format).expect("string-keyed maps of u64 always serialize");

        // Temp file + rename: the store never holds a half-written file.
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&json)?;
            f.sync_data()?;
        }
        std::fs::rename(&tmp, &self.path)
    }
}

impl SeqNumberStore for JsonSeqStore {
    fn load_tool_seq(&self, serial: &[u8; 6]) -> u64 {
        self.tool.get(serial).copied().unwrap_or(1)
    }

    fn save_tool_seq(&mut self, serial: &[u8; 6], seq: u64) -> std::io::Result<()> {
        let slot = self.tool.entry(*serial).or_insert(1);
        if seq <= *slot {
            return Ok(());
        }
        *slot = seq;
        self.flush()
    }

    fn load_table_seq(&self, serial: &[u8; 6]) -> u64 {
        self.table.get(serial).copied().unwrap_or(1)
    }

    fn save_table_seq(&mut self, serial: &[u8; 6], seq: u64) -> std::io::Result<()> {
        let slot = self.table.entry(*serial).or_insert(1);
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
            store.save_tool_seq(&SERIAL, 42).expect("write to temp dir");
            store.save_table_seq(&SERIAL, 17).expect("write to temp dir");
        }

        let store = JsonSeqStore::open(&path).expect("reopen existing store");
        assert_eq!(store.load_tool_seq(&SERIAL), 42);
        assert_eq!(store.load_table_seq(&SERIAL), 17);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn forward_only_update_does_not_regress() {
        let path = temp_path("forward");
        let _ = std::fs::remove_file(&path);

        let mut store = JsonSeqStore::open(&path).expect("create fresh store");
        store.save_tool_seq(&SERIAL, 100).expect("write to temp dir");
        store.save_tool_seq(&SERIAL, 50).expect("write to temp dir");
        assert_eq!(store.load_tool_seq(&SERIAL), 100);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_serial_returns_1_not_0() {
        let path = temp_path("unknown");
        let _ = std::fs::remove_file(&path);

        let store = JsonSeqStore::open(&path).expect("create fresh store");
        assert_eq!(store.load_tool_seq(&SERIAL), 1);
        assert_eq!(store.load_table_seq(&SERIAL), 1);

        let _ = std::fs::remove_file(&path);
    }
}
