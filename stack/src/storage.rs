//! Device identity and generic storage traits.
//!
//! This module provides:
//!
//! - [`DeviceIdentity`] — read-only, factory-programmed data (serial number,
//!   future: FDSK, MAC address)
//! - [`StaticIdentity`] — compile-time constant identity for demos/testing
//! - [`DeviceStorage`] — trait for persisting device state to various backends
//!   (flash, EEPROM, filesystem, etc.)
//! - [`NoStorage`] — null implementation for devices without persistence
//!
//! BCU-specific types like [`PersistedState`](crate::bcus::system_b::PersistedState)
//! and [`PersistedIpConfig`](crate::bcus::system_b::PersistedIpConfig) remain
//! in their respective BCU modules.

use crate::bcus::system_b::HasPersistedState;

// ============================================================================
// Device identity
// ============================================================================

/// Read-only device identity data.
///
/// This data is programmed at the factory and is immutable from the
/// stack's perspective. It survives factory resets — unlike ETS-configured
/// state in [`DeviceStorage`].
///
/// # Required Data
///
/// - **Serial number**: 6 bytes (2 bytes manufacturer ID in network byte
///   order + 4 bytes device-specific). Unique per physical device.
///
/// # Future Expansion
///
/// - FDSK (Factory Default Setup Key) for KNX Secure
/// - Hardware MAC address for embedded devices without an OS-level query
pub trait DeviceIdentity {
    /// Get the factory-programmed serial number.
    fn serial_number(&self) -> &[u8; 6];
}

/// Compile-time constant identity for demos and testing.
///
/// The serial number is baked into the firmware binary. Suitable for
/// prototype devices or testing where every instance shares the same
/// serial. Not suitable for production where each physical device must
/// have a unique serial number.
///
/// # Example
///
/// ```rust,ignore
/// const SERIAL: [u8; 6] = [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF];
/// let identity = StaticIdentity::new(SERIAL);
/// let state = SystemBDeviceState::new(&identity);
/// ```
pub struct StaticIdentity {
    serial_number: [u8; 6],
}

impl StaticIdentity {
    /// Create a new static identity with the given serial number.
    pub const fn new(serial_number: [u8; 6]) -> Self {
        Self { serial_number }
    }
}

impl DeviceIdentity for StaticIdentity {
    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }
}

// ============================================================================
// Device storage trait
// ============================================================================

/// Trait for persisting device state to storage.
///
/// `State` is the **runtime** state type (e.g.,
/// [`SystemBDeviceState`](crate::bcus::system_b::SystemBDeviceState)).
/// The storage backend internalizes the conversion to/from the
/// serializable form via [`HasPersistedState`] and holds a
/// [`DeviceIdentity`] for restoring state on load.
///
/// This means callers work exclusively with the runtime state type —
/// no manual `to_persisted()` / `from_persisted()` calls needed.
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
    /// The runtime state type this storage handles.
    ///
    /// Must implement [`HasPersistedState`] so the storage can convert
    /// to/from the serializable form internally.
    type State: HasPersistedState;

    /// The device identity type held by this storage backend.
    type Identity: DeviceIdentity;

    /// Error type for storage operations.
    type Error;

    /// Get the device identity used for restoring state.
    fn identity(&self) -> &Self::Identity;

    /// Load persistent state from storage.
    ///
    /// Returns:
    /// - `Ok(Some(state))` - Successfully loaded and restored state
    /// - `Ok(None)` - No saved state exists (factory reset / first boot)
    /// - `Err(e)` - Storage error
    ///
    /// On first boot or after factory reset, this should return `Ok(None)`.
    /// The device will then use factory defaults.
    ///
    /// Implementations deserialize the persisted form and call
    /// [`HasPersistedState::from_persisted`] with [`identity()`](Self::identity)
    /// to produce the runtime state.
    fn load(&mut self) -> Result<Option<Self::State>, Self::Error>;

    /// Save persistent state to storage.
    ///
    /// Calls [`HasPersistedState::to_persisted`] internally to produce
    /// the serializable form, then writes it to the underlying store.
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
/// The type parameter `S` is the runtime state type. It must implement
/// [`HasPersistedState`] to satisfy the [`DeviceStorage::State`] bound,
/// but no actual storage occurs.
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

impl<S: HasPersistedState> DeviceStorage for NoStorage<S> {
    type State = S;
    type Identity = NoIdentity;
    type Error = core::convert::Infallible;

    fn identity(&self) -> &NoIdentity {
        // NoStorage never loads, so identity is never used.
        // Return a dummy static identity.
        &NoIdentity
    }

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

/// Dummy identity for [`NoStorage`] — never actually used since
/// `NoStorage::load()` always returns `None`.
pub struct NoIdentity;

impl DeviceIdentity for NoIdentity {
    fn serial_number(&self) -> &[u8; 6] {
        &[0; 6]
    }
}
