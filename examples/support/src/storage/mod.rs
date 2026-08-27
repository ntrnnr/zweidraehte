//! Device State Storage
//!
//! Provides storage backends for persisting device configuration and
//! device identity, plus a file-backed sequence-number/SIAT store
//! ([`open_siat_store`]) for host-target Data-Secure / IP-Secure devices.
//!
//! [`JsonStorage`] implements the framework's
//! [`ConfigStoreBackend`](zweidraehte_device::storage::ConfigStoreBackend), so
//! a host device wraps it in `ConfigStorage` (config only) or `SecureStorage`
//! (config + seq) and rides the shared `storage_task` for restart handling and
//! persistence, just like the embedded targets.
//!
//! # Example
//!
//! ```rust,ignore
//! use support::storage::JsonStorage;
//!
//! let identity = FileIdentity::load_or_provision("identity.json", serial).unwrap();
//! let mut storage = JsonStorage::<DemoState, _>::new("device_state.json", identity);
//! let persisted = storage.load_config().unwrap(); // returns Option<DemoDeviceConfig>
//! let config = DemoStateInit::new(storage.identity(), persisted);
//! ```

mod file_identity;
pub use file_identity::{FileIdentity, FileIdentityError, FileSecureIdentity};

mod secure_seq;
pub use secure_seq::{FileByteIo, LinuxSiatStore, SIAT_SLOTS, open_siat_store};

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;

use serde::{Serialize, de::DeserializeOwned};
use zweidraehte_device::storage::{ConfigStoreBackend, DeviceIdentity, HasDeviceConfig};

/// JSON file-based storage for device state.
///
/// Persists device configuration to a JSON file. Suitable for development
/// and testing on systems with a filesystem.
///
/// The type parameter `S` is the **runtime** state type (e.g.,
/// [`DemoState`](crate::devices::system_b_demo::DemoState)). The storage
/// internally converts to/from the serializable [`S::Config`] form.
///
/// `I` is the device identity type, stored in the backend so that callers
/// can access it when building the `StateInit`.
///
/// # Usage
///
/// ```rust,ignore
/// let identity = FileIdentity::load_or_provision("identity.json", serial).unwrap();
/// let mut storage = JsonStorage::<DemoState, _>::new("device_state.json", identity);
/// let persisted = storage.load_config().unwrap(); // returns Option<Persisted>
/// let config = DemoStateInit::new(storage.identity(), persisted);
/// // Pass config to zweidraehte_device::new() — the runner calls create_state()
/// storage.save(&state).unwrap();       // converts to persisted form internally
/// ```
pub struct JsonStorage<S, I> {
    /// Path to the JSON file.
    path: PathBuf,
    /// Device identity for restoring state on load.
    identity: I,
    /// Whether there are unsaved changes.
    dirty: bool,
    _phantom: core::marker::PhantomData<S>,
}

impl<S, I> JsonStorage<S, I> {
    /// Create a new JSON storage with the given file path and identity.
    pub fn new<P: Into<PathBuf>>(path: P, identity: I) -> Self {
        Self { path: path.into(), identity, dirty: false, _phantom: core::marker::PhantomData }
    }

    /// Get the path to the storage file.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Get the device identity used for restoring state.
    pub fn identity(&self) -> &I {
        &self.identity
    }
}

/// Error type for JSON storage operations.
#[derive(Debug)]
pub enum JsonStorageError {
    /// I/O error during file operations.
    Io(io::Error),
    /// JSON serialization/deserialization error.
    Json(serde_json::Error),
}

impl From<io::Error> for JsonStorageError {
    fn from(e: io::Error) -> Self {
        JsonStorageError::Io(e)
    }
}

impl From<serde_json::Error> for JsonStorageError {
    fn from(e: serde_json::Error) -> Self {
        JsonStorageError::Json(e)
    }
}

impl std::fmt::Display for JsonStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonStorageError::Io(e) => write!(f, "I/O error: {}", e),
            JsonStorageError::Json(e) => write!(f, "JSON error: {}", e),
        }
    }
}

impl std::error::Error for JsonStorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JsonStorageError::Io(e) => Some(e),
            JsonStorageError::Json(e) => Some(e),
        }
    }
}

impl<S, I> JsonStorage<S, I>
where
    S: HasDeviceConfig,
    S::Config: Serialize + DeserializeOwned,
    I: DeviceIdentity,
{
    /// Load the persisted snapshot from storage without constructing runtime state.
    ///
    /// Returns `Ok(None)` if no saved state exists (first boot / factory reset).
    /// The caller is responsible for passing the persisted data into the stack's
    /// `StateInit` so that `create_state` can reconstruct runtime state with
    /// access to the `LayerContext`.
    pub fn load_config(&mut self) -> Result<Option<S::Config>, JsonStorageError> {
        if !self.path.exists() {
            log::info!("No saved state at {:?}, using factory defaults", self.path);
            return Ok(None);
        }

        let mut file = File::open(&self.path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let persisted: S::Config = serde_json::from_str(&contents)?;
        log::info!("Loaded persisted state from {:?}", self.path);
        Ok(Some(persisted))
    }

    /// Save the current runtime state to storage.
    ///
    /// Converts to the persisted form via [`HasDeviceConfig::to_config`],
    /// then writes atomically (tmp file + rename).
    pub fn save(&mut self, state: &S) -> Result<(), JsonStorageError> {
        let persisted = state.to_config();

        let json = serde_json::to_string_pretty(&persisted)?;

        let tmp_path = self.path.with_extension("json.tmp");
        let mut file = File::create(&tmp_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;

        fs::rename(&tmp_path, &self.path)?;

        self.dirty = false;
        log::info!("Saved device state to {:?}", self.path);
        Ok(())
    }

    /// Mark the storage as having unsaved changes.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Returns whether there are unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}

/// Plug `JsonStorage` into the framework's storage vocabulary as the config
/// backend of a [`ConfigStorage`](zweidraehte_device::storage::ConfigStorage)
/// or [`SecureStorage`](zweidraehte_device::storage::SecureStorage). This lets
/// the host-target Linux devices ride the same generic
/// [`storage_task`](zweidraehte_device::storage) as the embedded devices —
/// restart handling, the ETS-download persist, and the periodic dirty poll —
/// instead of hand-rolling those in `main`.
///
/// The trait's error policy is "swallow with a warning", matching the flash
/// backends: a failed save/load must not panic the storage task, and a device
/// that can't read its config boots fresh. The framework composite wraps this
/// in a `RefCell`, supplying the `&mut self` these methods want from the
/// task's `&self` call sites.
impl<S, I> ConfigStoreBackend for JsonStorage<S, I>
where
    S: HasDeviceConfig,
    S::Config: Serialize + DeserializeOwned,
    I: DeviceIdentity,
{
    type State = S;
    type Config = S::Config;

    fn save(&mut self, state: &S) {
        if let Err(e) = JsonStorage::save(self, state) {
            log::warn!("config save failed: {e}");
        }
    }

    fn load(&mut self) -> Option<S::Config> {
        // A blank file (`Ok(None)`) and a read/decode failure (`Err`) both mean
        // "no usable config" — the device boots from factory defaults either
        // way; only the failure is worth a warning.
        match JsonStorage::load_config(self) {
            Ok(config) => config,
            Err(e) => {
                log::warn!("config load failed: {e}");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_device::storage::ConfigStorage;

    /// A unique temp path per test, avoiding a `tempfile` dependency. The
    /// process id keeps concurrent test binaries from colliding.
    fn temp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("zw-support-config-{}-{}.json", std::process::id(), tag));
        p
    }

    /// Minimal stand-in for a device state: one counter that round-trips
    /// through the persisted form.
    struct TestState {
        counter: u32,
    }

    #[derive(Serialize, serde::Deserialize, PartialEq, Debug)]
    struct TestConfig {
        counter: u32,
    }

    impl HasDeviceConfig for TestState {
        type Config = TestConfig;
        fn to_config(&self) -> TestConfig {
            TestConfig { counter: self.counter }
        }
    }

    /// A device's identity is irrelevant to the config blob, so the test uses
    /// the simplest `DeviceIdentity` the framework offers.
    fn identity() -> zweidraehte_device::storage::StaticIdentity {
        zweidraehte_device::storage::StaticIdentity::new([1, 2, 3, 4, 5, 6])
    }

    /// The path the storage task actually drives: `save_config`/`load_config`
    /// through `&self` on the `ConfigStorage` composite, backed by
    /// `JsonStorage`'s `ConfigStoreBackend` impl.
    #[test]
    fn config_storage_round_trips_through_json_backend() {
        let path = temp_path("roundtrip");
        let _ = std::fs::remove_file(&path);

        // A missing file is "boot fresh", not an error.
        let storage = ConfigStorage::new(JsonStorage::<TestState, _>::new(&path, identity()));
        assert_eq!(storage.load_config(), None, "absent file must load as None");

        // `save_config` takes `&self` — exactly how the storage task calls it.
        storage.save_config(&TestState { counter: 0x2A });

        // A fresh handle over the same file recovers the persisted blob.
        let reopened = ConfigStorage::new(JsonStorage::<TestState, _>::new(&path, identity()));
        assert_eq!(reopened.load_config(), Some(TestConfig { counter: 0x2A }));

        std::fs::remove_file(&path).ok();
    }

    /// An undecodable file must not panic the storage task — it boots fresh.
    #[test]
    fn corrupt_config_file_loads_as_none() {
        let path = temp_path("corrupt");
        std::fs::write(&path, b"this is not json").expect("write corrupt file");

        let storage = ConfigStorage::new(JsonStorage::<TestState, _>::new(&path, identity()));
        assert_eq!(storage.load_config(), None, "undecodable file must load as None");

        std::fs::remove_file(&path).ok();
    }
}
