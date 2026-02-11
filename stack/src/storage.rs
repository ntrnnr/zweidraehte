//! Generic device storage traits.
//!
//! These traits define the interface for persisting device state to
//! various storage backends (flash, EEPROM, filesystem, etc.). They
//! are BCU-agnostic — the concrete persisted state type is determined
//! by the [`DeviceStorage::State`] associated type.
//!
//! BCU-specific types like [`PersistedState`](crate::bcus::system_b::PersistedState)
//! and [`PersistedIpConfig`](crate::bcus::system_b::PersistedIpConfig) remain
//! in their respective BCU modules.

use serde::{Deserialize, Serialize};

// ============================================================================
// Device storage trait
// ============================================================================

/// Trait for persisting device state to storage.
///
/// Each implementation is typed to a specific persisted state via the
/// `State` associated type. This eliminates the need for turbofish at
/// call sites — the storage instance already knows what state type it
/// handles.
///
/// # Persistence Strategy
///
/// The device calls [`mark_dirty`](Self::mark_dirty) whenever persistent
/// state changes. Implementations can choose to:
///
/// 1. **Immediate write**: Save on every change (simple but high wear)
/// 2. **Deferred write**: Batch changes and write periodically
/// 3. **Shutdown write**: Only save on graceful shutdown
///
/// Call [`flush`](Self::flush) to force pending writes to storage.
pub trait DeviceStorage: Sized {
    /// The persisted state type this storage handles.
    type State: Serialize + for<'de> Deserialize<'de>;

    /// Error type for storage operations.
    type Error;

    /// Load persistent state from storage.
    ///
    /// Returns:
    /// - `Ok(Some(state))` - Successfully loaded state
    /// - `Ok(None)` - No saved state exists (factory reset / first boot)
    /// - `Err(e)` - Storage error
    ///
    /// On first boot or after factory reset, this should return `Ok(None)`.
    /// The device will then use factory defaults.
    fn load(&mut self) -> Result<Option<Self::State>, Self::Error>;

    /// Save persistent state to storage.
    ///
    /// This should atomically replace the previous state to prevent
    /// corruption on power loss during write.
    fn save(&mut self, state: &Self::State) -> Result<(), Self::Error>;

    /// Mark state as dirty (needs save).
    ///
    /// Called whenever persistent state changes. Implementations can
    /// use this to track that a save is needed without immediately
    /// writing to storage.
    fn mark_dirty(&mut self);

    /// Flush any pending writes to storage.
    ///
    /// Called to ensure all changes are persisted. Should be called:
    /// - On graceful shutdown
    /// - Periodically (for wear leveling)
    /// - After critical configuration changes
    fn flush(&mut self) -> Result<(), Self::Error>;

    /// Check if there are unsaved changes.
    fn is_dirty(&self) -> bool {
        false // Default: not tracked
    }
}

// ============================================================================
// NoStorage - Null implementation
// ============================================================================

/// Storage implementation that doesn't persist anything.
///
/// Useful for:
/// - Testing
/// - Devices without persistent storage
/// - Devices with fixed configuration
///
/// All state will be lost on power cycle.
///
/// The type parameter `S` is the persisted state type. It is only used
/// to satisfy the [`DeviceStorage::State`] associated type — no actual
/// storage occurs.
pub struct NoStorage<S>(core::marker::PhantomData<S>);

impl<S> NoStorage<S> {
    /// Create a new no-op storage instance.
    pub fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<S> Default for NoStorage<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Clone for NoStorage<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for NoStorage<S> {}

impl<S> core::fmt::Debug for NoStorage<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NoStorage")
    }
}

impl<S: Serialize + for<'de> Deserialize<'de>> DeviceStorage for NoStorage<S> {
    type State = S;
    type Error = core::convert::Infallible;

    fn load(&mut self) -> Result<Option<S>, Self::Error> {
        Ok(None) // No saved state
    }

    fn save(&mut self, _state: &S) -> Result<(), Self::Error> {
        Ok(()) // Silently discard
    }

    fn mark_dirty(&mut self) {
        // Nothing to mark
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
