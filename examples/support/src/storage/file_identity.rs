//! File-backed device identity for Linux production devices.
//!
//! Reads the identity from a JSON file on disk at construction time and holds
//! it in memory. The file is read once — the [`DeviceIdentity`] implementation
//! is infallible after construction.
//!
//! Two flavours: [`FileIdentity`] carries just the serial number;
//! [`FileSecureIdentity`] adds the Factory Default Setup Key that Data Secure
//! / IP Secure devices need, so the key lives beside the device rather than
//! baked into the binary.
//!
//! # File Format
//!
//! ```json
//! {
//!   "serial_number": "00FADEADBEEF"
//! }
//! ```
//!
//! and, for the secure variant:
//!
//! ```json
//! {
//!   "serial_number": "00FA00000009",
//!   "fdsk": "00112233445566778899AABBCCDDEEFF"
//! }
//! ```
//!
//! Byte arrays are stored as hex strings (two characters per byte). Both
//! upper- and lowercase hex digits are accepted when reading.
//!
//! # Provisioning
//!
//! Use [`FileIdentity::provision`] / [`FileSecureIdentity::provision`] to
//! create the identity file for a new device, or the `load_or_provision`
//! twins for development convenience. See the method docs for details.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zweidraehte_device::storage::{DeviceIdentity, SecureDeviceIdentity};

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

/// Custom serde module for serializing a fixed-size byte array as a hex
/// string.
///
/// Serializes as uppercase hex (two characters per byte). Deserializes from
/// any mixed-case hex string of exactly the expected length. Const-generic
/// over the array length so the 6-byte serial number and the 16-byte FDSK
/// share one implementation.
mod hex_serial {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex: String = bytes.iter().map(|b| format!("{:02X}", b)).collect();
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        if hex.len() != N * 2 {
            return Err(serde::de::Error::custom(format!("expected {} hex characters, got {}", N * 2, hex.len())));
        }

        let mut result = [0u8; N];
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
/// use support::storage::FileIdentity;
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
// FileSecureIdentity
// ============================================================================

/// On-disk representation of the secure identity file: serial number plus
/// the Factory Default Setup Key, both as uppercase hex strings.
#[derive(Serialize, Deserialize)]
struct SecureIdentityFile {
    #[serde(with = "hex_serial")]
    serial_number: [u8; 6],
    #[serde(with = "hex_serial")]
    fdsk: [u8; 16],
}

/// File-backed **secure** device identity — the Data Secure / IP Secure twin
/// of [`FileIdentity`].
///
/// Carries the serial number *and* the Factory Default Setup Key (FDSK), the
/// two values ETS needs to commission a secure device. Keeping them in a file
/// rather than a build-time constant means the key is not baked into the
/// binary and can be changed (or made unique per device) without a rebuild.
///
/// # File Format
///
/// ```json
/// {
///   "serial_number": "00FA00000009",
///   "fdsk": "00112233445566778899AABBCCDDEEFF"
/// }
/// ```
///
/// # Security
///
/// The FDSK is secret material: whoever can read this file can commission the
/// device. It is stored in plaintext, so protect it with file permissions —
/// this is a development convenience, not a secure element. A real product
/// provisions a unique FDSK per device during manufacturing and prints it on
/// the device label / QR code for ETS.
pub struct FileSecureIdentity {
    serial_number: [u8; 6],
    fdsk: [u8; 16],
}

impl FileSecureIdentity {
    /// Load a secure identity from an existing JSON file.
    ///
    /// Returns an error if the file does not exist, cannot be read, or holds
    /// an invalid serial number / FDSK.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, FileIdentityError> {
        let path = path.as_ref();
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let identity_file: SecureIdentityFile = serde_json::from_str(&contents)?;

        log::info!("Loaded secure device identity from {:?}", path);
        Ok(Self { serial_number: identity_file.serial_number, fdsk: identity_file.fdsk })
    }

    /// Create a secure identity file with the given serial number and FDSK.
    ///
    /// Writes atomically (temp file + rename). Fails if the file already
    /// exists, so a provisioned identity — and with it the commissioned FDSK —
    /// is never silently overwritten.
    pub fn provision(
        path: impl AsRef<Path>,
        serial_number: [u8; 6],
        fdsk: [u8; 16],
    ) -> Result<Self, FileIdentityError> {
        let path = path.as_ref();

        match path.try_exists() {
            Ok(true) => return Err(FileIdentityError::AlreadyExists(path.to_path_buf())),
            Ok(false) => {}
            Err(e) => return Err(FileIdentityError::Io(e)),
        }

        let identity_file = SecureIdentityFile { serial_number, fdsk };
        let json = serde_json::to_string_pretty(&identity_file)?;

        let tmp_path = path.with_extension("json.tmp");
        let mut file = File::create(&tmp_path)?;
        file.write_all(json.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&tmp_path, path)?;

        log::info!("Provisioned secure device identity at {:?}", path);
        Ok(Self { serial_number, fdsk })
    }

    /// Load the secure identity file if it exists, or provision it with the
    /// given defaults.
    ///
    /// Development convenience, mirroring
    /// [`FileIdentity::load_or_provision`]: production deployments provision
    /// during manufacturing and [`load`](Self::load) at runtime.
    pub fn load_or_provision(
        path: impl AsRef<Path>,
        default_serial_number: [u8; 6],
        default_fdsk: [u8; 16],
    ) -> Result<Self, FileIdentityError> {
        let path = path.as_ref();
        match Self::load(path) {
            Ok(identity) => Ok(identity),
            Err(FileIdentityError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
                Self::provision(path, default_serial_number, default_fdsk)
            }
            Err(e) => Err(e),
        }
    }

    /// The FDSK as an uppercase hex string — the form ETS expects when the key
    /// is typed in by hand. Printed at startup so the operator can commission
    /// the device without reading the JSON file.
    pub fn fdsk_hex(&self) -> String {
        self.fdsk.iter().map(|b| format!("{:02X}", b)).collect()
    }
}

impl DeviceIdentity for FileSecureIdentity {
    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }
}

impl SecureDeviceIdentity for FileSecureIdentity {
    fn fdsk(&self) -> &[u8; 16] {
        &self.fdsk
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

    // ------------------------------------------------------------------
    // FileSecureIdentity
    // ------------------------------------------------------------------

    const TEST_SERIAL: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x09];
    const TEST_FDSK: [u8; 16] =
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    #[test]
    fn secure_round_trip_provision_then_load() {
        let path = temp_identity_path();
        cleanup(&path);

        FileSecureIdentity::provision(&path, TEST_SERIAL, TEST_FDSK).expect("provision");

        let identity = FileSecureIdentity::load(&path).expect("load");
        assert_eq!(*identity.serial_number(), TEST_SERIAL);
        assert_eq!(*identity.fdsk(), TEST_FDSK, "the FDSK must survive the file round-trip");

        cleanup(&path);
    }

    /// The whole point of the file: editing the key changes what the device
    /// uses, with no rebuild and no re-provisioning.
    #[test]
    fn secure_load_honours_an_edited_fdsk() {
        let path = temp_identity_path();
        cleanup(&path);

        FileSecureIdentity::provision(&path, TEST_SERIAL, TEST_FDSK).expect("provision");

        let edited = "0123456789ABCDEF0123456789ABCDEF";
        fs::write(&path, format!("{{\"serial_number\": \"00FA00000009\", \"fdsk\": \"{edited}\"}}"))
            .expect("write edited identity");

        let identity = FileSecureIdentity::load(&path).expect("load edited");
        assert_eq!(identity.fdsk_hex(), edited);

        cleanup(&path);
    }

    #[test]
    fn secure_provision_refuses_overwrite() {
        let path = temp_identity_path();
        cleanup(&path);

        FileSecureIdentity::provision(&path, TEST_SERIAL, TEST_FDSK).expect("first provision");

        // A second provision must not clobber a commissioned key.
        let result = FileSecureIdentity::provision(&path, [0xFF; 6], [0xFF; 16]);
        assert!(matches!(result, Err(FileIdentityError::AlreadyExists(_))));

        // The original is intact.
        let identity = FileSecureIdentity::load(&path).expect("load");
        assert_eq!(*identity.fdsk(), TEST_FDSK);

        cleanup(&path);
    }

    #[test]
    fn secure_load_or_provision_creates_then_reuses() {
        let path = temp_identity_path();
        cleanup(&path);

        let created =
            FileSecureIdentity::load_or_provision(&path, TEST_SERIAL, TEST_FDSK).expect("load_or_provision creates");
        assert_eq!(*created.fdsk(), TEST_FDSK);

        // Second call loads the existing file, ignoring the new defaults.
        let loaded =
            FileSecureIdentity::load_or_provision(&path, [0xFF; 6], [0xFF; 16]).expect("load_or_provision loads");
        assert_eq!(*loaded.serial_number(), TEST_SERIAL);
        assert_eq!(*loaded.fdsk(), TEST_FDSK);

        cleanup(&path);
    }

    #[test]
    fn secure_file_content_is_readable_json() {
        let path = temp_identity_path();
        cleanup(&path);

        FileSecureIdentity::provision(&path, TEST_SERIAL, TEST_FDSK).expect("provision");

        let contents = fs::read_to_string(&path).expect("read");
        assert!(contents.contains("\"serial_number\": \"00FA00000009\""));
        assert!(contents.contains("\"fdsk\": \"00112233445566778899AABBCCDDEEFF\""));

        cleanup(&path);
    }

    #[test]
    fn secure_rejects_wrong_length_fdsk() {
        let path = temp_identity_path();
        cleanup(&path);

        // 30 hex chars = 15 bytes — one short of an FDSK.
        fs::write(&path, r#"{"serial_number": "00FA00000009", "fdsk": "00112233445566778899AABBCCDDEE"}"#)
            .expect("write short fdsk");

        assert!(matches!(FileSecureIdentity::load(&path), Err(FileIdentityError::Json(_))));

        cleanup(&path);
    }
}
