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
/// - Hardware MAC address for embedded devices without an OS-level query
pub trait DeviceIdentity {
    /// Get the factory-programmed serial number.
    fn serial_number(&self) -> &[u8; 6];

    /// Get the Factory Default Setup Key (FDSK) for KNX Data Secure.
    ///
    /// The FDSK is a 16-byte key programmed at the factory and printed
    /// on the device label. It is used as the initial tool key for the
    /// first ETS commissioning session. After ETS writes a new tool key
    /// (PID 56), the FDSK is no longer used for authentication.
    ///
    /// Returns `None` for devices without Data Secure support.
    fn fdsk(&self) -> Option<&[u8; 16]> {
        None
    }
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
    fdsk: Option<[u8; 16]>,
}

impl StaticIdentity {
    /// Create a new static identity with the given serial number.
    pub const fn new(serial_number: [u8; 6]) -> Self {
        Self { serial_number, fdsk: None }
    }

    /// Create a new static identity with serial number and FDSK.
    pub const fn with_fdsk(serial_number: [u8; 6], fdsk: [u8; 16]) -> Self {
        Self { serial_number, fdsk: Some(fdsk) }
    }
}

impl DeviceIdentity for StaticIdentity {
    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }

    fn fdsk(&self) -> Option<&[u8; 16]> {
        self.fdsk.as_ref()
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

// ============================================================================
// Sequence Number Storage — wear-resistant abstraction
// ============================================================================

/// Wear-resistant storage for security sequence numbers.
///
/// Sequence numbers increment on every outgoing secure message, so they
/// cannot live in regular flash/EEPROM without wear-leveling.
///
/// Implementations may use:
/// - FRAM (I2C/SPI) — unlimited write endurance, ideal
/// - Battery-backed SRAM
/// - A dedicated file (Linux userspace)
/// - RAM-only (accepting reset on power cycle)
///
/// Per KNX spec 03/03/07 section 5.3.1, there are exactly two sending
/// counters (regular + tool access) and per-peer receiving counters.
pub trait SequenceNumberStorage {
    /// Error type for storage operations.
    type Error;

    /// Load the two sending sequence numbers (regular + tool access).
    /// Each is 6 bytes big-endian. Returns `(regular, tool_access)`.
    fn load_sending_seqs(&self) -> Result<([u8; 6], [u8; 6]), Self::Error>;

    /// Save the two sending sequence numbers.
    /// Called after every outgoing secure message.
    fn save_sending_seqs(&mut self, regular: &[u8; 6], tool: &[u8; 6]) -> Result<(), Self::Error>;

    /// Load last-valid receiving sequence number for a peer.
    /// Returns `None` if no sequence is stored for this peer.
    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error>;

    /// Save last-valid receiving sequence number for a peer.
    /// Called after successful MAC verification of an incoming message.
    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error>;
}

/// RAM-only sequence number storage.
///
/// Keeps counters in memory only — they reset to initial values on power
/// cycle. Suitable for testing and devices that accept sequence reset on
/// reboot. The initial sending sequence number is 1 (per spec, must be
/// non-zero).
///
/// The peers array is kept sorted by individual address for O(log n)
/// lookup via binary search.
pub struct RamSequenceStorage<const MAX_PEERS: usize> {
    /// (regular, tool_access) sending sequence numbers.
    sending: ([u8; 6], [u8; 6]),
    /// Per-peer last-valid receiving sequence numbers, sorted by IA.
    peers: [(u16, [u8; 6]); MAX_PEERS],
    /// Number of peers currently tracked.
    peer_count: usize,
}

impl<const MAX_PEERS: usize> RamSequenceStorage<MAX_PEERS> {
    /// Create a new RAM-only storage with initial sequence number 1.
    pub const fn new() -> Self {
        Self {
            // Initial value must be non-zero (spec: 1–255 range).
            sending: ([0, 0, 0, 0, 0, 1], [0, 0, 0, 0, 0, 1]),
            peers: [(0u16, [0u8; 6]); MAX_PEERS],
            peer_count: 0,
        }
    }
}

impl<const MAX_PEERS: usize> Default for RamSequenceStorage<MAX_PEERS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_PEERS: usize> SequenceNumberStorage for RamSequenceStorage<MAX_PEERS> {
    type Error = core::convert::Infallible;

    fn load_sending_seqs(&self) -> Result<([u8; 6], [u8; 6]), Self::Error> {
        Ok(self.sending)
    }

    fn save_sending_seqs(&mut self, regular: &[u8; 6], tool: &[u8; 6]) -> Result<(), Self::Error> {
        self.sending = (*regular, *tool);
        Ok(())
    }

    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error> {
        let slice = &self.peers[..self.peer_count];
        match slice.binary_search_by_key(&peer_ia, |e| e.0) {
            Ok(idx) => Ok(Some(self.peers[idx].1)),
            Err(_) => Ok(None),
        }
    }

    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error> {
        let slice = &self.peers[..self.peer_count];
        match slice.binary_search_by_key(&peer_ia, |e| e.0) {
            Ok(idx) => {
                self.peers[idx].1 = *seq;
            }
            Err(idx) => {
                if self.peer_count < MAX_PEERS {
                    // Shift elements right to make room at the sorted position.
                    self.peers.copy_within(idx..self.peer_count, idx + 1);
                    self.peers[idx] = (peer_ia, *seq);
                    self.peer_count += 1;
                }
                // Silently drop if at capacity — bounded by const generic.
            }
        }
        Ok(())
    }
}
