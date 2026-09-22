//! Key identity and provenance shared by configuration and deployment evidence.
//!
//! These values carry no filesystem authority. Credential access, transactions
//! and persistence errors belong to `storage`.

use std::num::NonZeroU8;

use serde::{Deserialize, Serialize};
use zweidraehte_proto::dpt::KNXSerialNumber;
use zweidraehte_util::secret::SecretBytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    Fdsk,
    ToolKey,
    GroupKey,
    DeviceAuthenticationCode,
    BackboneKey,
    IpPasswordHash,
    TunnellingKey,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum KeyScope {
    Project,
    Device(String),
    Group(String),
    IpBackbone,
    IpInterface(String),
    IpUser { interface: String, user_id: NonZeroU8 },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyId {
    pub scope: KeyScope,
    pub kind: KeyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub metadata: KeyMetadata,
    pub value: SecretBytes,
    /// Serial embedded in a KNX FDSK label, when that spelling was used.
    pub embedded_serial: Option<[u8; 6]>,
}

pub fn format_serial(serial: &[u8; 6]) -> String {
    KNXSerialNumber::from(*serial).to_string()
}
