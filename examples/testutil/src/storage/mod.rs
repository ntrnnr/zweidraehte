//! Device State Storage
//!
//! Provides storage backends for persisting device configuration and
//! device identity.
//!
//! # Example
//!
//! ```rust,ignore
//! use testutil::storage::JsonStorage;
//!
//! let identity = FileIdentity::load_or_provision("identity.json", serial).unwrap();
//! let mut storage = JsonStorage::<DemoState, _>::new("device_state.json", identity);
//! let persisted = storage.load_persisted().unwrap(); // returns Option<DemoPersistedState>
//! let config = DemoStateInit::new(storage.identity(), persisted);
//! ```

mod file_identity;
pub use file_identity::{FileIdentity, FileIdentityError};

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;

use serde::{Serialize, de::DeserializeOwned};
use zweidraehte_device::bcus::system_b::HasPersistedState;
use zweidraehte_device::storage::DeviceIdentity;

/// JSON file-based storage for device state.
///
/// Persists device configuration to a JSON file. Suitable for development
/// and testing on systems with a filesystem.
///
/// The type parameter `S` is the **runtime** state type (e.g.,
/// [`DemoState`](crate::devices::system_b_demo::DemoState)). The storage
/// internally converts to/from the serializable [`S::Persisted`] form.
///
/// `I` is the device identity type, stored in the backend so that callers
/// can access it when building the `StateInit`.
///
/// # Usage
///
/// ```rust,ignore
/// let identity = FileIdentity::load_or_provision("identity.json", serial).unwrap();
/// let mut storage = JsonStorage::<DemoState, _>::new("device_state.json", identity);
/// let persisted = storage.load_persisted().unwrap(); // returns Option<Persisted>
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
    S: HasPersistedState,
    S::Persisted: Serialize + DeserializeOwned,
    I: DeviceIdentity,
{
    /// Load the persisted snapshot from storage without constructing runtime state.
    ///
    /// Returns `Ok(None)` if no saved state exists (first boot / factory reset).
    /// The caller is responsible for passing the persisted data into the stack's
    /// `StateInit` so that `create_state` can reconstruct runtime state with
    /// access to the `LayerContext`.
    pub fn load_persisted(&mut self) -> Result<Option<S::Persisted>, JsonStorageError> {
        if !self.path.exists() {
            log::info!("No saved state at {:?}, using factory defaults", self.path);
            return Ok(None);
        }

        let mut file = File::open(&self.path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let persisted: S::Persisted = serde_json::from_str(&contents)?;
        log::info!("Loaded persisted state from {:?}", self.path);
        Ok(Some(persisted))
    }

    /// Save the current runtime state to storage.
    ///
    /// Converts to the persisted form via [`HasPersistedState::to_persisted`],
    /// then writes atomically (tmp file + rename).
    pub fn save(&mut self, state: &S) -> Result<(), JsonStorageError> {
        let persisted = state.to_persisted();

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
