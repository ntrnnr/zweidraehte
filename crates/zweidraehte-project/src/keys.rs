use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use toml_edit::{DocumentMut, Item, Table, value};
use zeroize::Zeroize;
use zweidraehte_proto::util::crc::fdsk_crc4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyKind {
    Fdsk,
    ToolKey,
    GroupKey,
    DeviceAuthenticationCode,
    BackboneKey,
    TunnellingKey,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyScope {
    Project,
    Device(String),
    Group(String),
    IpBackbone,
    IpInterface(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId {
    pub scope: KeyScope,
    pub kind: KeyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyEpoch(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyOrigin {
    Manual,
    Generated,
    Imported,
    DeviceLabel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyEncoding {
    Hex,
    KnxFdsk,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    Pending,
    Active,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMetadata {
    pub id: KeyId,
    pub epoch: Option<KeyEpoch>,
    pub origin: KeyOrigin,
    pub encoding: KeyEncoding,
    pub state: KeyState,
    pub fingerprint: [u8; 32],
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Shorten a secret buffer while zeroizing the discarded suffix.
    pub fn truncate(&mut self, len: usize) {
        if len >= self.0.len() {
            return;
        }
        self.0[len..].zeroize();
        self.0.truncate(len);
    }

    pub fn key16(&self) -> Result<[u8; 16], KeyStoreError> {
        self.0.as_slice().try_into().map_err(|_| KeyStoreError::InvalidLength { expected: 16, actual: self.0.len() })
    }

    pub fn key16_ref(&self) -> Result<&[u8; 16], KeyStoreError> {
        self.0.as_slice().try_into().map_err(|_| KeyStoreError::InvalidLength { expected: 16, actual: self.0.len() })
    }

    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.0)
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.0).into()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<String> for SecretBytes {
    fn from(value: String) -> Self {
        Self::new(value.into_bytes())
    }
}

impl<const N: usize> From<[u8; N]> for SecretBytes {
    fn from(value: [u8; N]) -> Self {
        Self::new(value)
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        // Preserve the length so callers can verify or reuse an explicitly
        // cleared buffer. `Vec<u8>`'s blanket implementation also empties the
        // vector after clearing its allocation, which hides that postcondition.
        self.0.as_mut_slice().zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub metadata: KeyMetadata,
    pub value: SecretBytes,
    /// Serial embedded in a KNX FDSK label, when that spelling was used.
    pub embedded_serial: Option<[u8; 6]>,
}

pub trait KeyMaterialSource {
    fn list(&self) -> Result<Vec<KeyMetadata>, KeyStoreError>;
    fn read(&self, id: &KeyId, epoch: Option<KeyEpoch>) -> Result<Option<KeyRecord>, KeyStoreError>;
}

pub trait KeyMaterialStore: KeyMaterialSource {
    fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut dyn KeyMaterialTransaction) -> Result<T, KeyStoreError>,
    ) -> Result<T, KeyStoreError>;
}

pub trait KeyMaterialTransaction {
    fn put(&mut self, record: KeyRecord) -> Result<(), KeyStoreError>;
    fn set_active_epoch(&mut self, id: &KeyId, epoch: KeyEpoch) -> Result<(), KeyStoreError>;
    fn retire(&mut self, id: &KeyId, epoch: KeyEpoch) -> Result<(), KeyStoreError>;
    fn remove(&mut self, id: &KeyId, epoch: KeyEpoch) -> Result<(), KeyStoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("key material is unavailable: {0}")]
    Unavailable(String),
    #[error("conflicting values for {0:?}")]
    Conflict(KeyId),
    #[error("expected {expected} key bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("key material is malformed: {0}")]
    Malformed(String),
    #[error("key-material persistence failed: {0}")]
    Persistence(String),
}

#[derive(Clone, PartialEq, Eq)]
pub struct DecodedFdsk {
    pub serial: Option<[u8; 6]>,
    key: SecretBytes,
    pub encoding: KeyEncoding,
}

impl DecodedFdsk {
    pub fn key(&self) -> &[u8; 16] {
        self.key.key16_ref().expect("decoded FDSKs have fixed width")
    }
}

impl fmt::Debug for DecodedFdsk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedFdsk")
            .field("serial", &self.serial)
            .field("key", &"[REDACTED]")
            .field("encoding", &self.encoding)
            .finish()
    }
}

pub fn parse_serial(input: &str) -> Result<[u8; 6], KeyStoreError> {
    let compact = input.trim().replace(':', "");
    parse_hex_array::<6>(&compact, "serial number")
}

pub fn format_serial(serial: &[u8; 6]) -> String {
    format!("{:02X}{:02X}:{:02X}{:02X}{:02X}{:02X}", serial[0], serial[1], serial[2], serial[3], serial[4], serial[5])
}

pub fn parse_key16(input: &str) -> Result<[u8; 16], KeyStoreError> {
    parse_hex_array::<16>(input.trim(), "128-bit key")
}

pub fn parse_fdsk(input: &str) -> Result<DecodedFdsk, KeyStoreError> {
    let input = input.trim();
    if input.len() == 32 {
        return Ok(DecodedFdsk { serial: None, key: parse_key16(input)?.into(), encoding: KeyEncoding::Hex });
    }
    let decoded = decode_fdsk_label(input)?;
    Ok(DecodedFdsk {
        serial: Some(decoded[..6].try_into().expect("decoded FDSK serial has fixed width")),
        key: SecretBytes::new(decoded[6..22].to_vec()),
        encoding: KeyEncoding::KnxFdsk,
    })
}

#[derive(Debug, Deserialize)]
struct KeyFile {
    version: u32,
    state_id: String,
    #[serde(default)]
    device: BTreeMap<String, DeviceKeys>,
    #[serde(default)]
    group: BTreeMap<String, GroupKeys>,
}

#[derive(Debug, Default, Deserialize)]
struct DeviceKeys {
    fdsk: Option<StoredKey>,
    tool_key: Option<StoredKey>,
}

#[derive(Debug, Deserialize)]
struct GroupKeys {
    active_epoch: u32,
    #[serde(default)]
    epochs: BTreeMap<String, StoredKey>,
}

#[derive(Debug, Deserialize)]
struct StoredKey {
    kind: String,
    encoding: KeyEncoding,
    value: String,
    origin: KeyOrigin,
    #[serde(default = "active_state")]
    state: KeyState,
}

fn active_state() -> KeyState {
    KeyState::Active
}

/// Comment-preserving authoritative key file for one project.
pub struct ProjectKeyStore {
    path: PathBuf,
    original: String,
    document: DocumentMut,
}

impl ProjectKeyStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, KeyStoreError> {
        let path = path.into();
        let original = fs::read_to_string(&path)
            .map_err(|error| KeyStoreError::Unavailable(format!("cannot read {}: {error}", path.display())))?;
        let document = original
            .parse::<DocumentMut>()
            .map_err(|error| KeyStoreError::Malformed(format!("{}: {error}", path.display())))?;
        let store = Self { path, original, document };
        store.decoded()?;
        Ok(store)
    }

    pub fn create(path: impl Into<PathBuf>, state_id: &str) -> Result<Self, KeyStoreError> {
        let path = path.into();
        if path.exists() {
            return Err(KeyStoreError::Persistence(format!("refusing to replace existing {}", path.display())));
        }
        let mut document = DocumentMut::new();
        document["version"] = value(1);
        document["state_id"] = value(state_id);
        let original = document.to_string();
        atomic_replace(&path, &original)?;
        Ok(Self { path, original, document })
    }

    pub fn state_id(&self) -> Result<String, KeyStoreError> {
        Ok(self.decoded()?.state_id)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn generate_tool_key(&mut self, device: &str) -> Result<[u8; 16], KeyStoreError> {
        let id = KeyId { scope: KeyScope::Device(device.to_string()), kind: KeyKind::ToolKey };
        if self.read(&id, None)?.is_some() {
            return Err(KeyStoreError::Conflict(id));
        }
        let mut key = [0; 16];
        getrandom::fill(&mut key).map_err(|error| KeyStoreError::Unavailable(format!("OS random source: {error}")))?;
        let record = record(id, None, KeyOrigin::Generated, KeyEncoding::Hex, KeyState::Active, key);
        self.transaction(|transaction| transaction.put(record))?;
        Ok(key)
    }

    /// Store an FDSK under a logical project device without exposing the
    /// TOML table layout to editors and importers.
    pub fn put_device_fdsk(&mut self, device: &str, encoded: &str, origin: KeyOrigin) -> Result<(), KeyStoreError> {
        let decoded = parse_fdsk(encoded)?;
        let value = decoded.key;
        let record = KeyRecord {
            metadata: KeyMetadata {
                id: KeyId { scope: KeyScope::Device(device.to_string()), kind: KeyKind::Fdsk },
                epoch: None,
                origin,
                encoding: decoded.encoding,
                state: KeyState::Active,
                fingerprint: value.fingerprint(),
            },
            value,
            embedded_serial: decoded.serial,
        };
        self.transaction(|transaction| transaction.put(record))
    }

    /// Store an explicitly supplied tool key. Tool-key generation remains a
    /// separate operation so callers cannot accidentally turn manual input
    /// into an ephemeral credential.
    pub fn put_device_tool_key(&mut self, device: &str, encoded: &str, origin: KeyOrigin) -> Result<(), KeyStoreError> {
        let key = parse_key16(encoded)?;
        let record = record(
            KeyId { scope: KeyScope::Device(device.to_string()), kind: KeyKind::ToolKey },
            None,
            origin,
            KeyEncoding::Hex,
            KeyState::Active,
            key,
        );
        self.transaction(|transaction| transaction.put(record))
    }

    /// Add one immutable group-key epoch and optionally select it. Reusing an
    /// epoch with different bytes is a conflict; rotation therefore remains
    /// an explicit future workflow rather than an accidental overwrite.
    pub fn put_group_key(
        &mut self,
        group: &str,
        epoch: KeyEpoch,
        encoded: &str,
        origin: KeyOrigin,
        make_active: bool,
    ) -> Result<(), KeyStoreError> {
        let key = parse_key16(encoded)?;
        let id = KeyId { scope: KeyScope::Group(group.to_string()), kind: KeyKind::GroupKey };
        let record = record(id.clone(), Some(epoch), origin, KeyEncoding::Hex, KeyState::Active, key);
        self.transaction(|transaction| {
            transaction.put(record)?;
            if make_active {
                transaction.set_active_epoch(&id, epoch)?;
            }
            Ok(())
        })
    }

    fn decoded(&self) -> Result<KeyFile, KeyStoreError> {
        let decoded: KeyFile = toml_edit::de::from_str(&self.document.to_string())
            .map_err(|error| KeyStoreError::Malformed(format!("{}: {error}", self.path.display())))?;
        if decoded.version != 1 {
            return Err(KeyStoreError::Malformed(format!("unsupported keys.toml version {}", decoded.version)));
        }
        if decoded.state_id.trim().is_empty() {
            return Err(KeyStoreError::Malformed("keys.toml has an empty state_id".into()));
        }
        Ok(decoded)
    }

    fn persist_document(&mut self, document: DocumentMut) -> Result<(), KeyStoreError> {
        let current = fs::read_to_string(&self.path)
            .map_err(|error| KeyStoreError::Persistence(format!("cannot re-read {}: {error}", self.path.display())))?;
        if current != self.original {
            return Err(KeyStoreError::Persistence(format!(
                "{} changed after it was opened; reload before writing",
                self.path.display()
            )));
        }
        let rendered = document.to_string();
        atomic_replace(&self.path, &rendered)?;
        self.original = rendered;
        self.document = document;
        Ok(())
    }
}

impl KeyMaterialSource for ProjectKeyStore {
    fn list(&self) -> Result<Vec<KeyMetadata>, KeyStoreError> {
        let file = self.decoded()?;
        let mut result = Vec::new();
        for (device, keys) in file.device {
            if let Some(key) = keys.fdsk {
                result.push(
                    decode_record(KeyId { scope: KeyScope::Device(device.clone()), kind: KeyKind::Fdsk }, None, key)?
                        .metadata,
                );
            }
            if let Some(key) = keys.tool_key {
                result.push(
                    decode_record(KeyId { scope: KeyScope::Device(device), kind: KeyKind::ToolKey }, None, key)?
                        .metadata,
                );
            }
        }
        for (group, keys) in file.group {
            for (epoch, key) in keys.epochs {
                let epoch = epoch
                    .parse::<u32>()
                    .map_err(|_| KeyStoreError::Malformed(format!("group `{group}` has invalid epoch `{epoch}`")))?;
                result.push(
                    decode_record(
                        KeyId { scope: KeyScope::Group(group.clone()), kind: KeyKind::GroupKey },
                        Some(KeyEpoch(epoch)),
                        key,
                    )?
                    .metadata,
                );
            }
        }
        result.sort_by(|left, right| (&left.id, left.epoch).cmp(&(&right.id, right.epoch)));
        Ok(result)
    }

    fn read(&self, id: &KeyId, epoch: Option<KeyEpoch>) -> Result<Option<KeyRecord>, KeyStoreError> {
        let file = self.decoded()?;
        let mut resolved_epoch = epoch;
        let stored = match (&id.scope, id.kind) {
            (KeyScope::Device(device), KeyKind::Fdsk) => file.device.get(device).and_then(|keys| keys.fdsk.as_ref()),
            (KeyScope::Device(device), KeyKind::ToolKey) => {
                file.device.get(device).and_then(|keys| keys.tool_key.as_ref())
            }
            (KeyScope::Group(group), KeyKind::GroupKey) => {
                let Some(keys) = file.group.get(group) else { return Ok(None) };
                let selected = epoch.unwrap_or(KeyEpoch(keys.active_epoch));
                resolved_epoch = Some(selected);
                keys.epochs.get(&selected.0.to_string())
            }
            _ => return Ok(None),
        };
        let record = stored.cloned().map(|stored| decode_record(id.clone(), resolved_epoch, stored)).transpose()?;
        if epoch.is_none()
            && matches!(&id.scope, KeyScope::Group(_))
            && record.as_ref().is_some_and(|record| record.metadata.state != KeyState::Active)
        {
            return Err(KeyStoreError::Malformed(format!(
                "active epoch for {:?} does not name an active key",
                id.scope
            )));
        }
        Ok(record)
    }
}

impl KeyMaterialStore for ProjectKeyStore {
    fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut dyn KeyMaterialTransaction) -> Result<T, KeyStoreError>,
    ) -> Result<T, KeyStoreError> {
        let mut staged = self.document.clone();
        let result = operation(&mut DocumentTransaction { document: &mut staged })?;
        self.persist_document(staged)?;
        Ok(result)
    }
}

struct DocumentTransaction<'a> {
    document: &'a mut DocumentMut,
}

impl KeyMaterialTransaction for DocumentTransaction<'_> {
    fn put(&mut self, record: KeyRecord) -> Result<(), KeyStoreError> {
        if let Some(existing) = read_document_record(self.document, &record.metadata.id, record.metadata.epoch)? {
            if existing.value != record.value {
                return Err(KeyStoreError::Conflict(record.metadata.id));
            }
            return Ok(());
        }
        let table = key_table_mut(self.document, &record.metadata.id, record.metadata.epoch)?;
        let (encoding, encoded) = encode_record(&record)?;
        table["kind"] = value(kind_name(record.metadata.id.kind));
        table["encoding"] = value(encoding_name(encoding));
        table["value"] = value(encoded);
        table["origin"] = value(origin_name(record.metadata.origin));
        table["state"] = value(state_name(record.metadata.state));
        Ok(())
    }

    fn set_active_epoch(&mut self, id: &KeyId, epoch: KeyEpoch) -> Result<(), KeyStoreError> {
        let KeyScope::Group(group) = &id.scope else {
            return Err(KeyStoreError::Malformed("only group keys have active epochs".into()));
        };
        if id.kind != KeyKind::GroupKey {
            return Err(KeyStoreError::Malformed("only group keys have active epochs".into()));
        }
        group_table_mut(self.document, group)?["active_epoch"] = value(i64::from(epoch.0));
        Ok(())
    }

    fn retire(&mut self, id: &KeyId, epoch: KeyEpoch) -> Result<(), KeyStoreError> {
        key_table_mut(self.document, id, Some(epoch))?["state"] = value("retired");
        Ok(())
    }

    fn remove(&mut self, id: &KeyId, epoch: KeyEpoch) -> Result<(), KeyStoreError> {
        let KeyScope::Group(group) = &id.scope else {
            return Err(KeyStoreError::Malformed("only epoch group keys may be removed".into()));
        };
        group_table_mut(self.document, group)?["epochs"]
            .as_table_mut()
            .ok_or_else(|| KeyStoreError::Malformed(format!("group `{group}` has no epochs table")))?
            .remove(&epoch.0.to_string());
        Ok(())
    }
}

fn read_document_record(
    document: &DocumentMut,
    id: &KeyId,
    epoch: Option<KeyEpoch>,
) -> Result<Option<KeyRecord>, KeyStoreError> {
    let file: KeyFile = toml_edit::de::from_str(&document.to_string())
        .map_err(|error| KeyStoreError::Malformed(format!("keys.toml transaction: {error}")))?;
    let stored = match (&id.scope, id.kind) {
        (KeyScope::Device(device), KeyKind::Fdsk) => file.device.get(device).and_then(|keys| keys.fdsk.as_ref()),
        (KeyScope::Device(device), KeyKind::ToolKey) => file.device.get(device).and_then(|keys| keys.tool_key.as_ref()),
        (KeyScope::Group(group), KeyKind::GroupKey) => {
            let Some(epoch) = epoch else {
                return Err(KeyStoreError::Malformed("a group-key record needs an epoch".into()));
            };
            file.group.get(group).and_then(|keys| keys.epochs.get(&epoch.0.to_string()))
        }
        _ => return Ok(None),
    };
    stored.cloned().map(|stored| decode_record(id.clone(), epoch, stored)).transpose()
}

fn key_table_mut<'a>(
    document: &'a mut DocumentMut,
    id: &KeyId,
    epoch: Option<KeyEpoch>,
) -> Result<&'a mut Item, KeyStoreError> {
    match (&id.scope, id.kind) {
        (KeyScope::Device(device), KeyKind::Fdsk) => device_key_table_mut(document, device, "fdsk"),
        (KeyScope::Device(device), KeyKind::ToolKey) => device_key_table_mut(document, device, "tool_key"),
        (KeyScope::Group(group), KeyKind::GroupKey) => {
            let epoch = epoch.ok_or_else(|| KeyStoreError::Malformed("a group-key record needs an epoch".into()))?;
            let group = group_table_mut(document, group)?;
            let epochs = explicit_table(&mut group["epochs"])?;
            let item = epochs.entry(&epoch.0.to_string()).or_insert(Item::Table(Table::new()));
            explicit_table(item)?;
            Ok(item)
        }
        _ => Err(KeyStoreError::Malformed("this key kind is reserved but not implemented".into())),
    }
}

fn device_key_table_mut<'a>(
    document: &'a mut DocumentMut,
    device: &str,
    key: &str,
) -> Result<&'a mut Item, KeyStoreError> {
    let devices = explicit_table(&mut document["device"])?;
    let device = devices.entry(device).or_insert(Item::Table(Table::new()));
    let device = explicit_table(device)?;
    let item = device.entry(key).or_insert(Item::Table(Table::new()));
    explicit_table(item)?;
    Ok(item)
}

fn group_table_mut<'a>(document: &'a mut DocumentMut, group: &str) -> Result<&'a mut Table, KeyStoreError> {
    let groups = explicit_table(&mut document["group"])?;
    let group = groups.entry(group).or_insert(Item::Table(Table::new()));
    explicit_table(group)
}

fn explicit_table(item: &mut Item) -> Result<&mut Table, KeyStoreError> {
    if item.is_none() {
        *item = Item::Table(Table::new());
    }
    item.as_table_mut().ok_or_else(|| KeyStoreError::Malformed("expected a table in keys.toml".into()))
}

fn decode_record(id: KeyId, epoch: Option<KeyEpoch>, stored: StoredKey) -> Result<KeyRecord, KeyStoreError> {
    if stored.kind != kind_name(id.kind) {
        return Err(KeyStoreError::Malformed(format!("key {:?} declares kind `{}`", id, stored.kind)));
    }
    let (bytes, embedded_serial) = match stored.encoding {
        KeyEncoding::Hex => (decode_hex(&stored.value)?, None),
        KeyEncoding::KnxFdsk => {
            let decoded = parse_fdsk(&stored.value)?;
            (decoded.key().to_vec(), decoded.serial)
        }
        KeyEncoding::Binary => {
            return Err(KeyStoreError::Malformed("binary key encoding is not valid in plaintext TOML".into()));
        }
    };
    let value = SecretBytes::new(bytes);
    if value.as_slice().len() != 16 {
        return Err(KeyStoreError::InvalidLength { expected: 16, actual: value.as_slice().len() });
    }
    let fingerprint = value.fingerprint();
    Ok(KeyRecord {
        metadata: KeyMetadata {
            id,
            epoch,
            origin: stored.origin,
            encoding: stored.encoding,
            state: stored.state,
            fingerprint,
        },
        value,
        embedded_serial,
    })
}

fn record(
    id: KeyId,
    epoch: Option<KeyEpoch>,
    origin: KeyOrigin,
    encoding: KeyEncoding,
    state: KeyState,
    bytes: [u8; 16],
) -> KeyRecord {
    let value = SecretBytes::new(bytes);
    KeyRecord {
        metadata: KeyMetadata { id, epoch, origin, encoding, state, fingerprint: value.fingerprint() },
        value,
        embedded_serial: None,
    }
}

fn kind_name(kind: KeyKind) -> &'static str {
    match kind {
        KeyKind::Fdsk => "fdsk",
        KeyKind::ToolKey => "tool_key",
        KeyKind::GroupKey => "group_key",
        KeyKind::DeviceAuthenticationCode => "device_authentication_code",
        KeyKind::BackboneKey => "backbone_key",
        KeyKind::TunnellingKey => "tunnelling_key",
    }
}

fn encoding_name(encoding: KeyEncoding) -> &'static str {
    match encoding {
        KeyEncoding::Hex => "hex",
        KeyEncoding::KnxFdsk => "knx_fdsk",
        KeyEncoding::Binary => "binary",
    }
}

fn origin_name(origin: KeyOrigin) -> &'static str {
    match origin {
        KeyOrigin::Manual => "manual",
        KeyOrigin::Generated => "generated",
        KeyOrigin::Imported => "imported",
        KeyOrigin::DeviceLabel => "device_label",
    }
}

fn state_name(state: KeyState) -> &'static str {
    match state {
        KeyState::Pending => "pending",
        KeyState::Active => "active",
        KeyState::Retired => "retired",
    }
}

fn encode_record(record: &KeyRecord) -> Result<(KeyEncoding, String), KeyStoreError> {
    let hex = || record.value.as_slice().iter().map(|byte| format!("{byte:02X}")).collect();
    match (record.metadata.encoding, record.embedded_serial) {
        (KeyEncoding::KnxFdsk, Some(serial)) => {
            Ok((KeyEncoding::KnxFdsk, encode_fdsk_label(serial, record.value.key16()?)))
        }
        // Binary is an import vocabulary, not a valid plaintext spelling.
        // An FDSK without its label serial likewise cannot be reconstructed.
        (KeyEncoding::Binary | KeyEncoding::KnxFdsk, None) => Ok((KeyEncoding::Hex, hex())),
        (KeyEncoding::Hex, _) => Ok((KeyEncoding::Hex, hex())),
        (KeyEncoding::Binary, Some(_)) => Ok((KeyEncoding::Hex, hex())),
    }
}

fn encode_fdsk_label(serial: [u8; 6], key: [u8; 16]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut payload = [0; 23];
    payload[..6].copy_from_slice(&serial);
    payload[6..22].copy_from_slice(&key);
    payload[22] = fdsk_crc4(&payload[..22]) << 4;

    let mut output = String::with_capacity(41);
    for symbol_index in 0_usize..36 {
        if symbol_index > 0 && symbol_index.is_multiple_of(6) {
            output.push('-');
        }
        let mut symbol = 0;
        for bit in 0..5 {
            let absolute = symbol_index * 5 + bit;
            let set = payload[absolute / 8] & (1 << (7 - absolute % 8)) != 0;
            symbol |= u8::from(set) << (4 - bit);
        }
        output.push(char::from(ALPHABET[usize::from(symbol)]));
    }
    output
}

fn decode_hex(input: &str) -> Result<Vec<u8>, KeyStoreError> {
    if !input.len().is_multiple_of(2) || !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(KeyStoreError::Malformed("hex key contains invalid characters or an odd number of digits".into()));
    }
    (0..input.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&input[index..index + 2], 16)
                .map_err(|_| KeyStoreError::Malformed("hex key contains invalid characters".into()))
        })
        .collect()
}

fn decode_fdsk_label(input: &str) -> Result<[u8; 23], KeyStoreError> {
    if input.len() != 41
        || input.bytes().enumerate().any(|(index, byte)| (index + 1).is_multiple_of(7) != (byte == b'-'))
    {
        return Err(KeyStoreError::Malformed("FDSK must be 32 hex digits or a 41-character KNX label".into()));
    }
    let symbols: Vec<u8> = input.bytes().filter(|byte| *byte != b'-').map(decode_base32).collect::<Result<_, _>>()?;
    let mut decoded = [0; 23];
    for (symbol_index, symbol) in symbols.into_iter().enumerate() {
        for bit in 0..5 {
            if symbol & (1 << (4 - bit)) != 0 {
                let absolute = symbol_index * 5 + bit;
                decoded[absolute / 8] |= 1 << (7 - absolute % 8);
            }
        }
    }
    if fdsk_crc4(&decoded[..22]) != decoded[22] >> 4 {
        return Err(KeyStoreError::Malformed("FDSK label check digit does not match".into()));
    }
    Ok(decoded)
}

fn decode_base32(byte: u8) -> Result<u8, KeyStoreError> {
    match byte.to_ascii_uppercase() {
        b'A'..=b'Z' => Ok(byte.to_ascii_uppercase() - b'A'),
        b'2'..=b'7' => Ok(byte - b'2' + 26),
        _ => Err(KeyStoreError::Malformed("FDSK label contains a non-Base32 character".into())),
    }
}

fn parse_hex_array<const N: usize>(input: &str, what: &str) -> Result<[u8; N], KeyStoreError> {
    if input.len() != N * 2 || !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(KeyStoreError::Malformed(format!("{what} must contain exactly {} hex digits", N * 2)));
    }
    let mut output = [0; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16)
            .map_err(|_| KeyStoreError::Malformed(format!("{what} contains invalid hex")))?;
    }
    Ok(output)
}

fn atomic_replace(path: &Path, contents: &str) -> Result<(), KeyStoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| KeyStoreError::Persistence(format!("{} has no parent directory", path.display())))?;
    fs::create_dir_all(parent)
        .map_err(|error| KeyStoreError::Persistence(format!("cannot create {}: {error}", parent.display())))?;
    let mut suffix = [0; 8];
    getrandom::fill(&mut suffix).map_err(|error| KeyStoreError::Unavailable(format!("OS random source: {error}")))?;
    let temporary = parent.join(format!(".keys.{:016x}.tmp", u64::from_le_bytes(suffix)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| KeyStoreError::Persistence(format!("cannot create {}: {error}", temporary.display())))?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| KeyStoreError::Persistence(format!("cannot write {}: {error}", temporary.display())))?;
    fs::rename(&temporary, path)
        .map_err(|error| KeyStoreError::Persistence(format!("cannot replace {}: {error}", path.display())))?;
    FileSync::sync_directory(parent)
        .map_err(|error| KeyStoreError::Persistence(format!("cannot sync {}: {error}", parent.display())))?;
    Ok(())
}

struct FileSync;

impl FileSync {
    fn sync_directory(path: &Path) -> std::io::Result<()> {
        std::fs::File::open(path)?.sync_all()
    }
}

impl Clone for StoredKey {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind.clone(),
            encoding: self.encoding,
            value: self.value.clone(),
            origin: self.origin,
            state: self.state,
        }
    }
}

impl fmt::Debug for ProjectKeyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ProjectKeyStore").field("path", &self.path).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_buffers_redact_and_zeroize_explicitly() {
        let canary = b"credential-canary";
        let mut secret = SecretBytes::new(canary.to_vec());
        let diagnostic = format!("{secret:?}");
        assert!(!diagnostic.contains("credential-canary"));

        secret.zeroize();
        assert_eq!(secret.as_slice(), vec![0; canary.len()]);
    }

    #[test]
    fn decoded_fdsk_debug_redacts_the_key() {
        let decoded = parse_fdsk("00112233445566778899AABBCCDDEEFF").expect("FDSK parses");
        let diagnostic = format!("{decoded:?}");
        assert!(!diagnostic.contains("00112233445566778899AABBCCDDEEFF"));
        assert!(diagnostic.contains("[REDACTED]"));
    }

    #[test]
    fn generated_tool_key_preserves_unrelated_comments() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("keys.toml");
        fs::write(&path, "# keep me\nversion = 1\nstate_id = \"state\"\n").expect("fixture writes");
        let mut store = ProjectKeyStore::open(&path).expect("key store opens");
        let generated = store.generate_tool_key("button").expect("key is generated");
        assert_ne!(generated, [0; 16]);
        let rendered = fs::read_to_string(path).expect("key store reads");
        assert!(rendered.starts_with("# keep me\n"));
        assert!(rendered.contains("[device.button.tool_key]"));
        assert!(
            !format!("{store:?}").contains(&generated.iter().map(|byte| format!("{byte:02X}")).collect::<String>())
        );
    }

    #[test]
    fn optimistic_write_rejects_an_external_edit() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("keys.toml");
        fs::write(&path, "version = 1\nstate_id = \"state\"\n").expect("fixture writes");
        let mut store = ProjectKeyStore::open(&path).expect("key store opens");
        fs::write(&path, "version = 1\nstate_id = \"different\"\n").expect("external edit writes");
        let error = store.generate_tool_key("button").expect_err("stale store is rejected");
        assert!(matches!(error, KeyStoreError::Persistence(_)));
    }

    #[test]
    fn fdsk_label_recovers_serial_and_checks_its_crc() {
        const LABEL: &str = "AD5N5L-N654AA-CAQDAQ-CQMBYI-BEFAWD-ANBYHX";
        let decoded = parse_fdsk(LABEL).expect("known label decodes");
        assert_eq!(decoded.serial, Some([0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(decoded.key(), &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        ]);
        assert_eq!(encode_fdsk_label(decoded.serial.expect("label has serial"), *decoded.key()), LABEL);
        assert!(parse_fdsk("AD5N5L-N654AA-CAQDAQ-CQMBYI-BEFAWD-ANBYHA").is_err());
    }

    #[test]
    fn imported_binary_keys_are_persisted_as_valid_hex() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("keys.toml");
        fs::write(&path, "version = 1\nstate_id = \"state\"\n").expect("fixture writes");
        let mut store = ProjectKeyStore::open(&path).expect("key store opens");
        let id = KeyId { scope: KeyScope::Device("button".into()), kind: KeyKind::ToolKey };
        let imported = record(id.clone(), None, KeyOrigin::Imported, KeyEncoding::Binary, KeyState::Active, [0x12; 16]);
        store.transaction(|transaction| transaction.put(imported)).expect("key persists");

        let reopened = ProjectKeyStore::open(&path).expect("written key store reopens");
        assert_eq!(
            reopened.read(&id, None).expect("key reads").expect("key exists").value.key16().expect("key16"),
            [0x12; 16]
        );
        assert!(fs::read_to_string(path).expect("key file reads").contains("encoding = \"hex\""));
    }

    #[test]
    fn active_group_epoch_must_point_at_an_active_key() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("keys.toml");
        fs::write(
            &path,
            "version = 1\nstate_id = \"state\"\n\n[group.lighting]\nactive_epoch = 1\n\n[group.lighting.epochs.1]\nkind = \"group_key\"\nencoding = \"hex\"\nvalue = \"00112233445566778899AABBCCDDEEFF\"\norigin = \"manual\"\nstate = \"retired\"\n",
        )
        .expect("fixture writes");
        let store = ProjectKeyStore::open(path).expect("syntax opens");
        let id = KeyId { scope: KeyScope::Group("lighting".into()), kind: KeyKind::GroupKey };
        assert!(store.read(&id, None).is_err());
        assert!(store.read(&id, Some(KeyEpoch(1))).expect("historical key reads").is_some());
    }

    #[test]
    fn logical_key_identity_cannot_be_overwritten_with_different_bytes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("keys.toml");
        fs::write(&path, "version = 1\nstate_id = \"state\"\n").expect("fixture writes");
        let mut store = ProjectKeyStore::open(&path).expect("key store opens");
        store
            .put_device_tool_key("button", "00112233445566778899AABBCCDDEEFF", KeyOrigin::Manual)
            .expect("first value persists");
        store
            .put_device_tool_key("button", "00112233445566778899AABBCCDDEEFF", KeyOrigin::Imported)
            .expect("equal value merges");
        let error = store
            .put_device_tool_key("button", "FFEEDDCCBBAA99887766554433221100", KeyOrigin::Manual)
            .expect_err("different value conflicts");
        assert!(matches!(error, KeyStoreError::Conflict(_)));
    }

    #[test]
    fn convenience_api_persists_fdsk_and_active_group_epoch() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("keys.toml");
        fs::write(&path, "version = 1\nstate_id = \"state\"\n").expect("fixture writes");
        let mut store = ProjectKeyStore::open(&path).expect("key store opens");
        store
            .put_device_fdsk("button", "AD5N5L-N654AA-CAQDAQ-CQMBYI-BEFAWD-ANBYHX", KeyOrigin::DeviceLabel)
            .expect("FDSK persists");
        store
            .put_group_key("lighting", KeyEpoch(1), "00112233445566778899AABBCCDDEEFF", KeyOrigin::Manual, true)
            .expect("group key persists");

        let fdsk = store
            .read(&KeyId { scope: KeyScope::Device("button".into()), kind: KeyKind::Fdsk }, None)
            .expect("FDSK reads")
            .expect("FDSK exists");
        assert_eq!(fdsk.embedded_serial, Some([0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF]));
        let group = store
            .read(&KeyId { scope: KeyScope::Group("lighting".into()), kind: KeyKind::GroupKey }, None)
            .expect("group key reads")
            .expect("group key exists");
        assert_eq!(group.metadata.epoch, Some(KeyEpoch(1)));
    }
}
