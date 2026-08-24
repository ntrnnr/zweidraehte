//! Format-neutral key-material vocabulary and human input codecs.
//!
//! Commissioning consumes these records; it does not care whether they
//! came from a single-device mods file, an ETS `.knxkeys` export, or a
//! future DSL project's authoritative store. Protocol sequence counters
//! intentionally remain in [`super::SeqNumberStore`] instead.

use core::fmt;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;
use zweidraehte_proto::util::crc::fdsk_crc4;

/// The semantic use of a key, independent of its persistence format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyKind {
    Fdsk,
    ToolKey,
    GroupKey,
    DeviceAuthenticationCode,
    BackboneKey,
    TunnellingKey,
}

/// Stable logical scope of a key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyScope {
    Project,
    Device(String),
    Group(String),
    IpBackbone,
    IpInterface(String),
}

/// Store-independent key identity. Epochs live on records so rotations
/// can retain two values for one logical identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId {
    pub scope: KeyScope,
    pub kind: KeyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyEpoch(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyOrigin {
    Manual,
    Generated,
    Imported,
    DeviceLabel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEncoding {
    Hex,
    KnxFdsk,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Pending,
    Active,
    Retired,
}

/// Non-secret information safe for diagnostics, lock files, and
/// deployment records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMetadata {
    pub id: KeyId,
    pub epoch: Option<KeyEpoch>,
    pub origin: KeyOrigin,
    pub encoding: KeyEncoding,
    pub state: KeyState,
    pub fingerprint: [u8; 32],
}

/// Secret byte storage which clears its allocation on drop and never
/// includes bytes in its `Debug` representation.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn key16(&self) -> Result<[u8; 16], KeyStoreError> {
        self.0.as_slice().try_into().map_err(|_| KeyStoreError::InvalidLength { expected: 16, actual: self.0.len() })
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.0).into()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub metadata: KeyMetadata,
    pub value: SecretBytes,
}

/// Read-only source used for imports such as ETS keyrings.
pub trait KeyMaterialSource {
    fn list(&self) -> Result<Vec<KeyMetadata>, KeyStoreError>;
    fn read(&self, id: &KeyId, epoch: Option<KeyEpoch>) -> Result<Option<KeyRecord>, KeyStoreError>;
}

/// Writable authoritative key material. The transaction boundary is
/// deliberately part of the interface: generated credentials must be
/// durable before a commissioning operation can use them.
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

/// An FDSK decoded from either raw hex or the printable KNX label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedFdsk {
    pub serial: Option<[u8; 6]>,
    pub key: [u8; 16],
    pub encoding: KeyEncoding,
}

/// Parse the two serial spellings used by our tools: `MMMMDDDDDDDD`
/// and `MMMM:DDDDDDDD`.
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

/// Decode raw 32-character hex, or the six-group printable FDSK label
/// generated by `zweidraehte_proto::provisioning::fdsk_string`.
pub fn parse_fdsk(input: &str) -> Result<DecodedFdsk, KeyStoreError> {
    let input = input.trim();
    if input.len() == 32 && input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(DecodedFdsk { serial: None, key: parse_key16(input)?, encoding: KeyEncoding::Hex });
    }

    if input.len() != 41
        || input.bytes().enumerate().any(|(index, byte)| (index + 1).is_multiple_of(7) != (byte == b'-'))
    {
        return Err(KeyStoreError::Malformed(
            "FDSK must be 32 hex digits or six groups of six Base32 characters".to_string(),
        ));
    }

    let symbols: Vec<u8> = input.bytes().filter(|byte| *byte != b'-').map(decode_base32).collect::<Result<_, _>>()?;
    let mut decoded = [0u8; 23];
    for (symbol_index, symbol) in symbols.into_iter().enumerate() {
        for bit in 0..5 {
            if symbol & (1 << (4 - bit)) == 0 {
                continue;
            }
            let absolute = symbol_index * 5 + bit;
            decoded[absolute / 8] |= 1 << (7 - absolute % 8);
        }
    }

    let expected = fdsk_crc4(&decoded[..22]);
    let actual = decoded[22] >> 4;
    if expected != actual {
        return Err(KeyStoreError::Malformed("FDSK label check digit does not match".to_string()));
    }

    Ok(DecodedFdsk {
        serial: Some(decoded[..6].try_into().expect("slice has the serial width")),
        key: decoded[6..22].try_into().expect("slice has the key width"),
        encoding: KeyEncoding::KnxFdsk,
    })
}

fn decode_base32(byte: u8) -> Result<u8, KeyStoreError> {
    match byte.to_ascii_uppercase() {
        b'A'..=b'Z' => Ok(byte.to_ascii_uppercase() - b'A'),
        b'2'..=b'7' => Ok(byte - b'2' + 26),
        _ => Err(KeyStoreError::Malformed("FDSK label contains a non-Base32 character".to_string())),
    }
}

fn parse_hex_array<const N: usize>(input: &str, what: &str) -> Result<[u8; N], KeyStoreError> {
    if input.len() != N * 2 || !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(KeyStoreError::Malformed(format!("{what} must contain exactly {} hex digits", N * 2)));
    }
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16)
            .map_err(|_| KeyStoreError::Malformed(format!("{what} contains invalid hex")))?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_proto::provisioning::fdsk_string;

    #[test]
    fn fdsk_label_round_trips_and_checks_its_crc() {
        let serial = [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78];
        let key = [0xA5; 16];
        let label = String::from_utf8(fdsk_string(&serial, &key).to_vec()).expect("label is ASCII");

        let parsed = parse_fdsk(&label).expect("label parses");
        assert_eq!(parsed.serial, Some(serial));
        assert_eq!(parsed.key, key);

        let mut damaged = label.into_bytes();
        damaged[0] = if damaged[0] == b'A' { b'B' } else { b'A' };
        let damaged = String::from_utf8(damaged).expect("still ASCII");
        assert!(matches!(parse_fdsk(&damaged), Err(KeyStoreError::Malformed(_))));
    }

    #[test]
    fn raw_fdsk_and_serial_inputs_are_strict() {
        let fdsk = parse_fdsk("00112233445566778899aabbccddeeff").expect("hex FDSK parses");
        assert_eq!(fdsk.serial, None);
        assert_eq!(fdsk.key[0], 0x00);
        assert_eq!(fdsk.key[15], 0xFF);
        assert_eq!(parse_serial("00FA:12345678").expect("display serial parses"), [0, 0xFA, 0x12, 0x34, 0x56, 0x78]);
        assert!(parse_serial("00FA:1234").is_err());
    }

    #[test]
    fn secret_debug_is_redacted_and_fingerprint_is_stable() {
        let secret = SecretBytes::new([0x42; 16]);
        assert_eq!(format!("{secret:?}"), "SecretBytes([REDACTED])");
        assert_eq!(secret.fingerprint(), Sha256::digest([0x42; 16]).as_slice());
    }
}
