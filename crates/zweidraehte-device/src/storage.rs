//! Device identity and generic storage traits.
//!
//! This module provides:
//!
//! - [`DeviceIdentity`] — read-only, factory-programmed data (serial number)
//! - [`SecureDeviceIdentity`] — extension trait for Data Secure devices,
//!   adding the Factory Default Setup Key (FDSK)
//! - [`StaticIdentity`] / [`StaticSecureIdentity`] — compile-time constant
//!   identities for demos/testing
//! - [`DeviceStorage`] — trait for persisting device state to various backends
//!   (flash, EEPROM, filesystem, etc.)
//! - [`NoStorage`] — null implementation for devices without persistence
//!
//! BCU-specific types like [`PersistedState`](crate::bcus::system_b::PersistedState)
//! and [`IpExtensionConfig`](crate::bcus::system_b::IpExtensionConfig) remain
//! in their respective BCU modules.

use core::cell::RefCell;

use serde::{Deserialize, Serialize};

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
}

/// Identity extension for KNX Data Secure devices.
///
/// Implemented only by identity types that carry a Factory Default Setup
/// Key (FDSK). The FDSK is a 16-byte key programmed at the factory and
/// printed on the device label. It acts as the initial tool key for the
/// first ETS commissioning session; after ETS writes a new tool key (PID
/// 56), the FDSK is no longer used for authentication but is re-applied
/// on factory reset (03/05/01 §6.1.4).
///
/// The trait is separate from [`DeviceIdentity`] so the type system can
/// distinguish secure from non-secure devices: a secure stack can bound
/// on `I: SecureDeviceIdentity` and be guaranteed an FDSK without any
/// runtime `Option`.
pub trait SecureDeviceIdentity: DeviceIdentity {
    /// Get the Factory Default Setup Key.
    fn fdsk(&self) -> &[u8; 16];
}

/// Compile-time constant identity for demos and testing.
///
/// The serial number is baked into the firmware binary. Suitable for
/// prototype devices or testing where every instance shares the same
/// serial. Not suitable for production where each physical device must
/// have a unique serial number.
///
/// For Data Secure devices, use [`StaticSecureIdentity`] instead.
///
/// # Example
///
/// ```rust,ignore
/// const SERIAL: [u8; 6] = [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF];
/// let identity = StaticIdentity::new(SERIAL);
/// let state = SystemBDeviceState::new(identity, /* ... */);
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

/// Compile-time constant identity for Data Secure demos and testing.
///
/// Bundles a serial number with an FDSK. Implements both
/// [`DeviceIdentity`] and [`SecureDeviceIdentity`] so it can be used
/// anywhere an `I: DeviceIdentity` is accepted *and* satisfies the
/// stronger `I: SecureDeviceIdentity` bound required by the secure
/// extension state.
pub struct StaticSecureIdentity {
    serial_number: [u8; 6],
    fdsk: [u8; 16],
}

impl StaticSecureIdentity {
    /// Create a new static secure identity with serial number and FDSK.
    pub const fn new(serial_number: [u8; 6], fdsk: [u8; 16]) -> Self {
        Self { serial_number, fdsk }
    }
}

impl DeviceIdentity for StaticSecureIdentity {
    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }
}

impl SecureDeviceIdentity for StaticSecureIdentity {
    fn fdsk(&self) -> &[u8; 16] {
        &self.fdsk
    }
}

// ============================================================================
// Runtime-state <-> config conversion
// ============================================================================

/// Trait for converting runtime state into its serializable config.
///
/// Implemented by a BCU's runtime state type (e.g.
/// [`SystemBDeviceState`](crate::bcus::system_b::SystemBDeviceState)) so
/// [`DeviceStorage`] backends can work with the runtime state directly,
/// internalizing the conversion to/from the persisted config form.
///
/// # Contract
///
/// - [`to_config`](Self::to_config) must capture all state that survives a
///   power cycle.
/// - The matching restore path (an inherent `from_config` on the state type)
///   must restore state such that the device behaves identically to before
///   the power cycle (modulo volatile state like programming mode and run
///   state).
pub trait HasDeviceConfig: Sized {
    /// The serializable config type (device-level persisted form).
    type Config: Serialize + for<'de> Deserialize<'de>;

    /// Export current runtime state to a serializable config.
    fn to_config(&self) -> Self::Config;
}

// ============================================================================
// Device storage trait
// ============================================================================

/// Trait for persisting device state to storage.
///
/// `State` is the **runtime** state type (e.g.,
/// [`SystemBDeviceState`](crate::bcus::system_b::SystemBDeviceState)).
/// The storage backend internalizes the conversion to/from the
/// serializable form via [`HasDeviceConfig`] and holds a
/// [`DeviceIdentity`] for restoring state on load.
///
/// This means callers work exclusively with the runtime state type —
/// no manual `to_config()` / `from_config()` calls needed.
///
/// # Dirty tracking lives on state, not here
///
/// The stack signals "state needs to be saved" via
/// [`HasPersistence::mark_dirty`](crate::HasPersistence::mark_dirty)
/// on the *state* (every property write / `A_Memory_Write` calls it).
/// User code is responsible for the save loop: observe the state's
/// dirty flag, then call [`save`](Self::save) (or [`flush`](Self::flush)
/// if the impl batches writes internally) and clear the flag.
///
/// # Persistence Strategy
///
/// Implementations can choose to:
///
/// 1. **Immediate write**: `save()` writes synchronously every call
///    (simple but high wear).
/// 2. **Deferred write**: `save()` queues / coalesces;
///    [`flush`](Self::flush) commits.
/// 3. **Shutdown write**: only [`flush`](Self::flush) writes.
pub trait DeviceStorage: Sized {
    /// The runtime state type this storage handles.
    ///
    /// Must implement [`HasDeviceConfig`] so the storage can convert
    /// to/from the serializable form internally.
    type State: HasDeviceConfig;

    /// The device identity type held by this storage backend.
    type Identity: DeviceIdentity;

    /// Error type for storage operations.
    type Error;

    /// Get the device identity used for restoring state.
    fn identity(&self) -> &Self::Identity;

    /// Load the persisted snapshot from storage.
    ///
    /// Returns:
    /// - `Ok(Some(persisted))` - Successfully loaded snapshot
    /// - `Ok(None)` - No saved state exists (factory reset / first boot)
    /// - `Err(e)` - Storage error
    ///
    /// The caller passes the snapshot into `D::StateInit` and lets
    /// [`StackDefinition::create_state`](crate::StackDefinition::create_state)
    /// reconstruct runtime state with access to the `LayerContext`.
    fn load_config(&mut self) -> Result<Option<<Self::State as HasDeviceConfig>::Config>, Self::Error>;

    /// Save persistent state to storage.
    ///
    /// Calls [`HasDeviceConfig::to_config`] internally to produce
    /// the serializable form, then writes it to the underlying store.
    ///
    /// This should atomically replace the previous state to prevent
    /// corruption on power loss during write.
    fn save(&mut self, state: &Self::State) -> Result<(), Self::Error>;

    /// Flush any pending writes to storage.
    ///
    /// Called to ensure all changes are persisted. Should be called:
    /// - On graceful shutdown
    /// - Periodically (for wear leveling)
    /// - After critical configuration changes
    fn flush(&mut self) -> Result<(), Self::Error>;
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
/// [`HasDeviceConfig`] to satisfy the [`DeviceStorage::State`] bound,
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

impl<S: HasDeviceConfig> DeviceStorage for NoStorage<S> {
    type State = S;
    type Identity = NoIdentity;
    type Error = core::convert::Infallible;

    fn identity(&self) -> &NoIdentity {
        // NoStorage never loads, so identity is never used.
        // Return a dummy static identity.
        &NoIdentity
    }

    fn load_config(&mut self) -> Result<Option<S::Config>, Self::Error> {
        Ok(None) // No saved state
    }

    fn save(&mut self, _state: &S) -> Result<(), Self::Error> {
        Ok(()) // Silently discard
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
/// # Sending sequence number
///
/// Per KNX 03/03/07 §5.x a device maintains **one single Sequence Number
/// Sending** for *all* its outgoing secure communication — group, broadcast,
/// P2P, and tool access alike — incremented on every secure frame it sends.
/// Receiving state is the separate, genuinely per-partner part: the SIAT (one
/// last-valid per sender IA) plus the tool-access receiving counter below.
pub trait SequenceNumberStorage {
    /// Error type for storage operations.
    type Error;

    /// Load the device's Sequence Number Sending (6 bytes big-endian).
    fn load_sending_seq(&self) -> Result<[u8; 6], Self::Error>;

    /// Save the device's Sequence Number Sending. Called after every outgoing
    /// secure message.
    fn save_sending_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error>;

    /// Load last-valid receiving sequence number for a peer, keyed by
    /// sender IA.
    ///
    /// Per 03/03/07 §5.3, this covers *every* non-tool secure sender —
    /// P2P partners and pure group-secure senders alike — not only
    /// P2P. "Peer" here means any remote IA from which this device has
    /// ever accepted a non-tool secure frame. Returns `None` if no
    /// sequence is stored for this peer.
    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error>;

    /// Save last-valid receiving sequence number for a sender IA.
    /// Called after successful MAC verification of an incoming message.
    /// Same keying as [`load_receiving_seq`](Self::load_receiving_seq).
    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error>;

    /// Load the last-valid receiving sequence number for tool access.
    ///
    /// Per spec §5.3.1 Note 27, the tool access receiving SeqNr is stored
    /// separately from the SIAT — there is no standardized resource for it.
    fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, Self::Error>;

    /// Save the last-valid receiving sequence number for tool access.
    fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error>;
}

/// Trait for stack definitions that provide sequence number storage.
///
/// Only implemented by secure device stacks (it names the concrete
/// `SeqStorage` type for the type system). Non-secure stacks don't need
/// it. The [`SecureDeviceBuilder`] requires this bound.
///
/// The storage *instance* is always constructed by the device's `main`
/// and threaded through [`StateInit`](crate::StackDefinition::StateInit)
/// → [`SecureResources`](crate::bcus::system_b::SecureResources) —
/// hardware-backed stores (an SPI FRAM, a flash sector handle) only
/// exist there. The trait deliberately has no factory method; an earlier
/// `create_seq_storage()` default existed and panicked on every device
/// except the conformance harness, which now builds its shared-memory
/// store through its own inherent function instead.
///
/// # Related
///
/// The runtime counterpart [`HasSeqStorage`]
/// lives on the `SecureExtensionState` and exposes that same storage
/// through `&self` so the S-AL layer and the PID 59 augment can borrow
/// it.
///
/// [`SecureDeviceBuilder`]: crate::composition::SecureDeviceBuilder
pub trait HasSequenceStorage {
    /// The concrete sequence number storage type.
    type SeqStorage: SequenceNumberStorage;
}

/// Runtime accessor for a secure device's sequence number storage.
///
/// Exposes the storage owned by the secure extension state through `&self`
/// so the Secure Application Layer and the PID 59 augment can borrow it.
///
/// # Related
///
/// This is the **extension-state-side** accessor. The corresponding
/// **stack-definition-side** trait is [`HasSequenceStorage`], which lets a
/// [`StackDefinition`](crate::StackDefinition) impl name the `SeqStorage`
/// concrete type during stack construction. The two cooperate:
/// `HasSequenceStorage` names the storage type, the storage instance lives
/// inside the secure extension state, and `HasSeqStorage` exposes it through
/// `&self` at runtime.
pub trait HasSeqStorage {
    /// The concrete sequence number storage type.
    type SeqStorage: SequenceNumberStorage;

    /// Borrow the sequence number storage RefCell.
    fn seq_storage(&self) -> &RefCell<Self::SeqStorage>;
}
