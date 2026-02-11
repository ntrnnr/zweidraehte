//! Device State Storage
//!
//! Provides storage backends for persisting device configuration and
//! device identity.
//!
//! # Example
//!
//! ```rust,ignore
//! use testutil::storage::JsonStorage;
//! use zweidraehte::bcus::system_b::DeviceStorage;
//!
//! let mut storage = JsonStorage::<MyPersistedState>::new("device_state.json");
//! let state = storage.load().unwrap(); // no turbofish needed
//! ```

mod file_identity;
pub use file_identity::{FileIdentity, FileIdentityError};

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::path::PathBuf;

use serde::{Serialize, de::DeserializeOwned};
use zweidraehte::bcus::system_b::DeviceStorage;

/// JSON file-based storage for device state.
///
/// Persists device configuration to a JSON file. Suitable for development
/// and testing on systems with a filesystem.
///
/// The type parameter `S` is the persisted state type (typically a
/// [`PersistedState`](zweidraehte::bcus::system_b::PersistedState) with
/// concrete table sizes, parameter type, and link-layer config).
///
/// # Usage
///
/// ```rust,ignore
/// type MyState = PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, MyParams, PersistedIpConfig>;
/// let mut storage = JsonStorage::<MyState>::new("device_state.json");
/// let state = storage.load().unwrap(); // returns Option<MyState>
/// ```
pub struct JsonStorage<S> {
    /// Path to the JSON file.
    path: PathBuf,
    /// Whether there are unsaved changes.
    dirty: bool,
    _phantom: PhantomData<S>,
}

impl<S> JsonStorage<S> {
    /// Create a new JSON storage with the given file path.
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self { path: path.into(), dirty: false, _phantom: PhantomData }
    }

    /// Get the path to the storage file.
    pub fn path(&self) -> &PathBuf {
        &self.path
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

impl<S: Serialize + DeserializeOwned> DeviceStorage for JsonStorage<S> {
    type State = S;
    type Error = JsonStorageError;

    fn load(&mut self) -> Result<Option<S>, Self::Error> {
        // Check if the file exists
        if !self.path.exists() {
            log::info!("No saved state at {:?}, using factory defaults", self.path);
            return Ok(None);
        }

        // Read the file contents
        let mut file = File::open(&self.path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Parse the JSON
        let state: S = serde_json::from_str(&contents)?;

        log::info!("Loaded device state from {:?}", self.path);
        Ok(Some(state))
    }

    fn save(&mut self, state: &S) -> Result<(), Self::Error> {
        // Serialize to JSON with pretty printing for readability
        let json = serde_json::to_string_pretty(state)?;

        // Write to a temporary file first for atomic replacement
        let tmp_path = self.path.with_extension("json.tmp");
        let mut file = File::create(&tmp_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;

        // Atomically replace the old file
        fs::rename(&tmp_path, &self.path)?;

        self.dirty = false;
        log::info!("Saved device state to {:?}", self.path);
        Ok(())
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // Note: This just clears the dirty flag. The actual save must be done
        // by calling save() with the current state. The stack should call save()
        // when it detects changes, not flush().
        self.dirty = false;
        Ok(())
    }

    fn is_dirty(&self) -> bool {
        self.dirty
    }
}
