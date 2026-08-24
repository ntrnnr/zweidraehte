//! Comment-preserving key-material persistence for transitional mods files.
//!
//! The future project DSL will keep secrets in an authoritative project
//! store. Until then, this adapter makes a generated tool key durable in the
//! existing single-device TOML without reserializing unrelated fields or
//! silently overwriting edits made after the file was opened.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use toml_edit::{DocumentMut, Item, Table, value};

use super::material::{
    KeyEncoding, KeyEpoch, KeyId, KeyKind, KeyMaterialSource, KeyMaterialStore, KeyMaterialTransaction, KeyMetadata,
    KeyOrigin, KeyRecord, KeyScope, KeyState, KeyStoreError, SecretBytes, format_serial, parse_fdsk, parse_key16,
    parse_serial,
};
use crate::programming::GeneratedToolKeySink;

/// Writable view of one mods file, guarded by an optimistic content check.
pub struct ModsFileKeyStore {
    path: PathBuf,
    original: String,
    document: DocumentMut,
}

impl ModsFileKeyStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, KeyStoreError> {
        let path = path.as_ref().to_path_buf();
        let original = std::fs::read_to_string(&path)
            .map_err(|error| KeyStoreError::Persistence(format!("cannot read {}: {error}", path.display())))?;
        let document = original
            .parse::<DocumentMut>()
            .map_err(|error| KeyStoreError::Malformed(format!("{} is not valid TOML: {error}", path.display())))?;
        Ok(Self { path, original, document })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn records(&self) -> Result<Vec<KeyRecord>, KeyStoreError> {
        let mut records = Vec::new();
        let device_scope = KeyScope::Device(self.device_identity());
        let Some(security) = self.document.get("security").and_then(Item::as_table) else {
            return Ok(records);
        };

        if let Some(input) = security.get("fdsk").and_then(Item::as_str) {
            let decoded = parse_fdsk(input)?;
            records.push(record(
                KeyId { scope: device_scope.clone(), kind: KeyKind::Fdsk },
                decoded.key,
                KeyOrigin::Manual,
                decoded.encoding,
            ));
        }
        if let Some(input) = security.get("tool_key").and_then(Item::as_str) {
            records.push(record(
                KeyId { scope: device_scope, kind: KeyKind::ToolKey },
                parse_key16(input)?,
                KeyOrigin::Manual,
                KeyEncoding::Hex,
            ));
        }
        if let Some(groups) = security.get("group").and_then(Item::as_array_of_tables) {
            for group in groups {
                let Some(address) = group.get("group_address").and_then(Item::as_str) else { continue };
                let Some(input) = group.get("key").and_then(Item::as_str) else { continue };
                records.push(record(
                    KeyId { scope: KeyScope::Group(address.to_string()), kind: KeyKind::GroupKey },
                    parse_key16(input)?,
                    KeyOrigin::Manual,
                    KeyEncoding::Hex,
                ));
            }
        }
        Ok(records)
    }

    fn device_identity(&self) -> String {
        self.document
            .get("device")
            .and_then(Item::as_table)
            .and_then(|device| device.get("serial_number"))
            .and_then(Item::as_str)
            .and_then(|serial| parse_serial(serial).ok())
            .map(|serial| format!("serial:{}", format_serial(&serial)))
            .unwrap_or_else(|| "mods-device".to_string())
    }

    fn replace(&mut self, document: DocumentMut) -> Result<(), KeyStoreError> {
        let current = std::fs::read_to_string(&self.path).map_err(|error| {
            KeyStoreError::Persistence(format!("cannot re-read {} before replacing it: {error}", self.path.display()))
        })?;
        if current != self.original {
            return Err(KeyStoreError::Persistence(format!(
                "{} changed after it was loaded; refusing to overwrite it",
                self.path.display()
            )));
        }

        let rendered = document.to_string();
        if rendered == self.original {
            self.document = document;
            return Ok(());
        }
        let metadata = std::fs::metadata(&self.path)
            .map_err(|error| KeyStoreError::Persistence(format!("cannot inspect {}: {error}", self.path.display())))?;
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = self.path.file_name().and_then(|name| name.to_str()).unwrap_or("mods.toml");
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce)
            .map_err(|error| KeyStoreError::Persistence(format!("cannot name an atomic temporary file: {error}")))?;
        let temporary = parent.join(format!(".{file_name}.{:016X}.tmp", u64::from_be_bytes(nonce)));

        let write_result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
            file.set_permissions(metadata.permissions())?;
            file.write_all(rendered.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&temporary, &self.path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&temporary);
            return Err(KeyStoreError::Persistence(format!(
                "cannot atomically replace {}: {error}",
                self.path.display()
            )));
        }

        self.original = rendered;
        self.document = document;
        Ok(())
    }
}

impl KeyMaterialSource for ModsFileKeyStore {
    fn list(&self) -> Result<Vec<KeyMetadata>, KeyStoreError> {
        Ok(self.records()?.into_iter().map(|record| record.metadata).collect())
    }

    fn read(&self, id: &KeyId, epoch: Option<KeyEpoch>) -> Result<Option<KeyRecord>, KeyStoreError> {
        if epoch.is_some() {
            return Ok(None);
        }
        Ok(self.records()?.into_iter().find(|record| record.metadata.id == *id))
    }
}

impl KeyMaterialStore for ModsFileKeyStore {
    fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut dyn KeyMaterialTransaction) -> Result<T, KeyStoreError>,
    ) -> Result<T, KeyStoreError> {
        let mut transaction = ModsTransaction { document: self.document.clone() };
        let result = operation(&mut transaction)?;
        self.replace(transaction.document)?;
        Ok(result)
    }
}

impl GeneratedToolKeySink for ModsFileKeyStore {
    fn persist_generated_tool_key(&mut self, serial: Option<[u8; 6]>, tool_key: [u8; 16]) -> Result<(), KeyStoreError> {
        let subject =
            serial.map(|serial| format!("serial:{}", format_serial(&serial))).unwrap_or_else(|| self.device_identity());
        let record = record(
            KeyId { scope: KeyScope::Device(subject), kind: KeyKind::ToolKey },
            tool_key,
            KeyOrigin::Generated,
            KeyEncoding::Hex,
        );
        self.transaction(|transaction| transaction.put(record))
    }
}

struct ModsTransaction {
    document: DocumentMut,
}

impl ModsTransaction {
    fn security(&mut self) -> &mut Table {
        if !self.document.contains_key("security") {
            self.document["security"] = Item::Table(Table::new());
        }
        self.document["security"].as_table_mut().expect("security was created as a table")
    }

    fn set_device_key(&mut self, field: &str, bytes: &[u8]) {
        self.security()[field] = value(hex(bytes));
    }

    fn set_group_key(&mut self, address: &str, bytes: &[u8]) -> Result<(), KeyStoreError> {
        let groups = self
            .security()
            .get_mut("group")
            .and_then(Item::as_array_of_tables_mut)
            .ok_or_else(|| KeyStoreError::Unavailable(format!("mods declares no security group {address}")))?;
        let group = groups
            .iter_mut()
            .find(|group| group.get("group_address").and_then(Item::as_str) == Some(address))
            .ok_or_else(|| KeyStoreError::Unavailable(format!("mods declares no security group {address}")))?;
        group["key"] = value(hex(bytes));
        Ok(())
    }

    fn remove_key(&mut self, id: &KeyId) -> Result<(), KeyStoreError> {
        match (&id.scope, id.kind) {
            (KeyScope::Device(_), KeyKind::Fdsk) => {
                self.security().remove("fdsk");
                Ok(())
            }
            (KeyScope::Device(_), KeyKind::ToolKey) => {
                self.security().remove("tool_key");
                Ok(())
            }
            (KeyScope::Group(address), KeyKind::GroupKey) => {
                let groups =
                    self.security().get_mut("group").and_then(Item::as_array_of_tables_mut).ok_or_else(|| {
                        KeyStoreError::Unavailable(format!("mods declares no security group {address}"))
                    })?;
                let group = groups
                    .iter_mut()
                    .find(|group| group.get("group_address").and_then(Item::as_str) == Some(address))
                    .ok_or_else(|| KeyStoreError::Unavailable(format!("mods declares no security group {address}")))?;
                group.remove("key");
                Ok(())
            }
            _ => Err(KeyStoreError::Unavailable("this key kind is not writable in mods".to_string())),
        }
    }
}

impl KeyMaterialTransaction for ModsTransaction {
    fn put(&mut self, record: KeyRecord) -> Result<(), KeyStoreError> {
        if record.metadata.epoch.is_some() {
            return Err(KeyStoreError::Unavailable("mods does not support key epochs".to_string()));
        }
        match (&record.metadata.id.scope, record.metadata.id.kind) {
            (KeyScope::Device(_), KeyKind::Fdsk) => {
                self.set_device_key("fdsk", record.value.as_slice());
                Ok(())
            }
            (KeyScope::Device(_), KeyKind::ToolKey) => {
                self.set_device_key("tool_key", record.value.as_slice());
                Ok(())
            }
            (KeyScope::Group(address), KeyKind::GroupKey) => self.set_group_key(address, record.value.as_slice()),
            _ => Err(KeyStoreError::Unavailable("this key kind is not writable in mods".to_string())),
        }
    }

    fn set_active_epoch(&mut self, _id: &KeyId, epoch: KeyEpoch) -> Result<(), KeyStoreError> {
        if epoch == KeyEpoch(0) {
            Ok(())
        } else {
            Err(KeyStoreError::Unavailable("mods does not support key epochs".to_string()))
        }
    }

    fn retire(&mut self, _id: &KeyId, _epoch: KeyEpoch) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::Unavailable("mods does not retain retired keys".to_string()))
    }

    fn remove(&mut self, id: &KeyId, epoch: KeyEpoch) -> Result<(), KeyStoreError> {
        if epoch != KeyEpoch(0) {
            return Err(KeyStoreError::Unavailable("mods does not support key epochs".to_string()));
        }
        self.remove_key(id)
    }
}

fn record(id: KeyId, key: [u8; 16], origin: KeyOrigin, encoding: KeyEncoding) -> KeyRecord {
    let value = SecretBytes::new(key);
    KeyRecord {
        metadata: KeyMetadata {
            id,
            epoch: None,
            origin,
            encoding,
            state: KeyState::Active,
            fingerprint: value.fingerprint(),
        },
        value,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOOL_KEY: [u8; 16] = [0x42; 16];

    fn input() -> &'static str {
        r#"# installation comment
[device]
individual_address = "1.1.42" # keep this comment
serial_number = "00FA:12345678"

[[links]]
com_object = 1
group_address = "1/0/1"
"#
    }

    #[test]
    fn generated_tool_key_is_inserted_atomically_without_losing_comments() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("device.toml");
        std::fs::write(&path, input()).expect("write fixture");
        let mut store = ModsFileKeyStore::open(&path).expect("open mods store");

        store
            .persist_generated_tool_key(Some([0x00, 0xFA, 0x12, 0x34, 0x56, 0x78]), TOOL_KEY)
            .expect("persist tool key");

        let rendered = std::fs::read_to_string(&path).expect("read result");
        assert!(rendered.contains("# installation comment"));
        assert!(rendered.contains("# keep this comment"));
        assert!(rendered.contains("tool_key = \"42424242424242424242424242424242\""));
        let parsed = rendered.parse::<DocumentMut>().expect("result remains valid TOML");
        assert_eq!(parsed["security"]["tool_key"].as_str(), Some("42424242424242424242424242424242"));
    }

    #[test]
    fn concurrent_file_edit_is_not_overwritten() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("device.toml");
        std::fs::write(&path, input()).expect("write fixture");
        let mut store = ModsFileKeyStore::open(&path).expect("open mods store");
        std::fs::write(&path, "# replaced externally\n").expect("external edit");

        assert!(matches!(store.persist_generated_tool_key(None, TOOL_KEY), Err(KeyStoreError::Persistence(_))));
        assert_eq!(std::fs::read_to_string(&path).expect("read external edit"), "# replaced externally\n");
    }
}
