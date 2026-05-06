//! File-backed device identity for Linux production devices.
//!
//! Reads the serial number from a JSON file on disk at construction time
//! and holds it in memory. The file is read once — the [`DeviceIdentity`]
//! implementation is infallible after construction.
//!
//! # File Format
//!
//! ```json
//! {
//!   "serial_number": "00FADEADBEEF"
//! }
//! ```
//!
//! The serial number is a 12-character hex string (6 bytes). Both upper-
//! and lowercase hex digits are accepted when reading.
//!
//! # Provisioning
//!
//! Use [`FileIdentity::provision`] to create the identity file for a new
//! device, or [`FileIdentity::load_or_provision`] for development
//! convenience. See the method docs for details.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zweidraehte_device::storage::DeviceIdentity;

// ============================================================================
// Error Type
// ============================================================================

/// Error type for file identity operations.
#[derive(Debug)]
pub enum FileIdentityError {
    /// I/O error during file operations.
    Io(io::Error),
    /// JSON or hex parsing error.
    ///
    /// Covers both malformed JSON and invalid serial number hex strings
    /// (wrong length, non-hex characters).
    Json(serde_json::Error),
    /// Identity file already exists (during provisioning).
    ///
    /// Use [`FileIdentity::load`] to read the existing file, or delete
    /// it manually if you intend to re-provision.
    AlreadyExists(PathBuf),
}

impl From<io::Error> for FileIdentityError {
    fn from(e: io::Error) -> Self {
        FileIdentityError::Io(e)
    }
}

impl From<serde_json::Error> for FileIdentityError {
    fn from(e: serde_json::Error) -> Self {
        FileIdentityError::Json(e)
    }
}

impl std::fmt::Display for FileIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileIdentityError::Io(e) => write!(f, "I/O error: {}", e),
            FileIdentityError::Json(e) => write!(f, "JSON error: {}", e),
            FileIdentityError::AlreadyExists(p) => {
                write!(f, "identity file already exists: {}", p.display())
            }
        }
    }
}

impl std::error::Error for FileIdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FileIdentityError::Io(e) => Some(e),
            FileIdentityError::Json(e) => Some(e),
            FileIdentityError::AlreadyExists(_) => None,
        }
    }
}

// ============================================================================
// Serde Helper
// ============================================================================

/// On-disk representation of the identity file.
///
/// The serial number is stored as a 12-character hex string in JSON
/// (e.g. `"00FADEADBEEF"`) but deserialized directly into `[u8; 6]`.
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    #[serde(with = "hex_serial")]
    serial_number: [u8; 6],
}

/// Custom serde module for serializing `[u8; 6]` as a hex string.
///
/// Serializes as uppercase 12-character hex. Deserializes from any
/// mixed-case 12-character hex string.
mod hex_serial {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 6], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex: String = bytes.iter().map(|b| format!("{:02X}", b)).collect();
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 6], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        if hex.len() != 12 {
            return Err(serde::de::Error::custom(format!("expected 12 hex characters, got {}", hex.len())));
        }

        let mut result = [0u8; 6];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let pair =
                std::str::from_utf8(chunk).map_err(|_| serde::de::Error::custom("invalid UTF-8 in hex string"))?;
            result[i] = u8::from_str_radix(pair, 16)
                .map_err(|_| serde::de::Error::custom(format!("invalid hex byte: '{}'", pair)))?;
        }

        Ok(result)
    }
}

// ============================================================================
// FileIdentity
// ============================================================================

/// File-backed device identity for Linux production devices.
///
/// Reads the serial number from a JSON file on disk at construction time
/// and holds it in memory. The file is read once — the [`DeviceIdentity`]
/// implementation is infallible after construction.
///
/// # Example
///
/// ```rust,ignore
/// use testutil::storage::FileIdentity;
///
/// // Production: load from an existing provisioned file
/// let identity = FileIdentity::load("device_identity.json")?;
/// let state = DemoState::new(storage, &identity);
///
/// // Development: provision a default serial if file is missing
/// let identity = FileIdentity::load_or_provision(
///     "device_identity.json",
///     [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF],
/// )?;
/// ```
pub struct FileIdentity {
    serial_number: [u8; 6],
}

impl FileIdentity {
    /// Load device identity from an existing JSON file.
    ///
    /// Returns an error if the file does not exist, cannot be read,
    /// or contains an invalid serial number.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, FileIdentityError> {
        let path = path.as_ref();
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let identity_file: IdentityFile = serde_json::from_str(&contents)?;

        log::info!("Loaded device identity from {:?}", path);
        Ok(Self { serial_number: identity_file.serial_number })
    }

    /// Create an identity file with the given serial number.
    ///
    /// Writes the file atomically (temp file + rename) to prevent
    /// corruption. Fails if the file already exists — this prevents
    /// accidental overwrite of a production-provisioned identity.
    pub fn provision(path: impl AsRef<Path>, serial_number: [u8; 6]) -> Result<Self, FileIdentityError> {
        let path = path.as_ref();

        // Refuse to overwrite an existing identity file.
        match path.try_exists() {
            Ok(true) => return Err(FileIdentityError::AlreadyExists(path.to_path_buf())),
            Ok(false) => {}
            Err(e) => return Err(FileIdentityError::Io(e)),
        }

        let identity_file = IdentityFile { serial_number };
        let json = serde_json::to_string_pretty(&identity_file)?;

        // Atomic write: temp file → sync → rename
        let tmp_path = path.with_extension("json.tmp");
        let mut file = File::create(&tmp_path)?;
        file.write_all(json.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&tmp_path, path)?;

        log::info!("Provisioned device identity at {:?}", path);
        Ok(Self { serial_number })
    }

    /// Load the identity file if it exists, or provision it with the
    /// given default serial number.
    ///
    /// Convenience method for development: production deployments should
    /// use [`provision`](Self::provision) during manufacturing and
    /// [`load`](Self::load) at runtime.
    pub fn load_or_provision(
        path: impl AsRef<Path>,
        default_serial_number: [u8; 6],
    ) -> Result<Self, FileIdentityError> {
        let path = path.as_ref();
        match Self::load(path) {
            Ok(identity) => Ok(identity),
            Err(FileIdentityError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
                Self::provision(path, default_serial_number)
            }
            Err(e) => Err(e),
        }
    }
}

impl DeviceIdentity for FileIdentity {
    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Generate a unique temp file path for each test to avoid interference.
    fn temp_identity_path() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("knx_test_identity_{}_{}.json", pid, id))
    }

    /// Clean up a temp file, ignoring errors.
    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(path.with_extension("json.tmp"));
    }

    #[test]
    fn round_trip_provision_then_load() {
        let path = temp_identity_path();
        cleanup(&path);

        let serial = [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF];
        let provisioned = FileIdentity::provision(&path, serial).expect("provision");
        assert_eq!(*provisioned.serial_number(), serial);

        let loaded = FileIdentity::load(&path).expect("load");
        assert_eq!(*loaded.serial_number(), serial);

        cleanup(&path);
    }

    /// Helper: deserialize an IdentityFile from a JSON string.
    fn parse_identity(json: &str) -> Result<IdentityFile, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn hex_parsing_uppercase() {
        let id: IdentityFile = parse_identity(r#"{"serial_number": "00FADEADBEEF"}"#).expect("parse");
        assert_eq!(id.serial_number, [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn hex_parsing_lowercase() {
        let id: IdentityFile = parse_identity(r#"{"serial_number": "00fadeadbeef"}"#).expect("parse");
        assert_eq!(id.serial_number, [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn hex_parsing_mixed_case() {
        let id: IdentityFile = parse_identity(r#"{"serial_number": "00FadeadBEEF"}"#).expect("parse");
        assert_eq!(id.serial_number, [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn hex_parsing_wrong_length_short() {
        let result = parse_identity(r#"{"serial_number": "00FADE"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn hex_parsing_wrong_length_long() {
        let result = parse_identity(r#"{"serial_number": "00FADEADBEEF0011"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn hex_parsing_non_hex_chars() {
        let result = parse_identity(r#"{"serial_number": "00FADEXDBEEF"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn hex_serde_round_trip() {
        let original = IdentityFile { serial_number: [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF] };
        let json = serde_json::to_string(&original).expect("serialize");
        assert!(json.contains("00FADEADBEEF"));
        let parsed: IdentityFile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.serial_number, original.serial_number);
    }

    #[test]
    fn provision_refuses_overwrite() {
        let path = temp_identity_path();
        cleanup(&path);

        let serial = [0x00, 0xFA, 0x11, 0x22, 0x33, 0x44];
        FileIdentity::provision(&path, serial).expect("first provision");

        let result = FileIdentity::provision(&path, [0xFF; 6]);
        assert!(matches!(result, Err(FileIdentityError::AlreadyExists(_))));

        // Original serial is preserved.
        let loaded = FileIdentity::load(&path).expect("load");
        assert_eq!(*loaded.serial_number(), serial);

        cleanup(&path);
    }

    #[test]
    fn load_missing_file() {
        let path = temp_identity_path();
        cleanup(&path);

        let result = FileIdentity::load(&path);
        assert!(matches!(result, Err(FileIdentityError::Io(ref e)) if e.kind() == io::ErrorKind::NotFound));
    }

    #[test]
    fn load_or_provision_creates_when_missing() {
        let path = temp_identity_path();
        cleanup(&path);

        let serial = [0x00, 0xFA, 0xAA, 0xBB, 0xCC, 0xDD];
        let identity = FileIdentity::load_or_provision(&path, serial).expect("load_or_provision");
        assert_eq!(*identity.serial_number(), serial);

        // File should now exist.
        assert!(path.exists());

        cleanup(&path);
    }

    #[test]
    fn load_or_provision_loads_existing() {
        let path = temp_identity_path();
        cleanup(&path);

        let original = [0x00, 0xFA, 0x11, 0x22, 0x33, 0x44];
        FileIdentity::provision(&path, original).expect("provision");

        // load_or_provision should load the existing file, ignoring the default.
        let different_default = [0xFF; 6];
        let identity = FileIdentity::load_or_provision(&path, different_default).expect("load_or_provision");
        assert_eq!(*identity.serial_number(), original);

        cleanup(&path);
    }

    #[test]
    fn file_content_is_readable_json() {
        let path = temp_identity_path();
        cleanup(&path);

        let serial = [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF];
        FileIdentity::provision(&path, serial).expect("provision");

        let contents = fs::read_to_string(&path).expect("read");
        assert!(contents.contains("\"serial_number\": \"00FADEADBEEF\""));

        cleanup(&path);
    }
}
