//! Core device state traits and error types.
//!
//! [`StackState`] is the fundamental runtime abstraction for any KNX device,
//! providing individual address, serial number, authorization, and
//! programming mode.

use crate::config::MAX_APDU_LENGTH_EXTENDED;
use crate::device_model::DeviceModelNotifier;
use crate::objects::{
    comm::{HasCommObjects, HasGoSecurityView},
    interface::HasRoutingCount,
    tables::{HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, LoadState},
};
use crate::storage::DeviceIdentity;
use serde::{Deserialize, Serialize};
use zweidraehte_proto::access::{AccessContext, HasConnectionAuth};
use zweidraehte_proto::address::IndividualAddress;

/// Error type for read object operations with timeout
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ReadObjectError {
    /// The read request timed out without receiving a response
    Timeout,
    /// The object is busy (already transmitting)
    Busy,
}

/// Error type for update/write object operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum UpdateObjectError {
    /// The object is busy (already transmitting)
    Busy,
}

/// Trait for stack state types.
///
/// Stack state holds runtime configuration that can be shared between
/// the stack, layers, and interface objects (e.g., programming mode, individual address).
/// This state can later be persisted to flash/storage.
///
/// # Example
///
/// ```rust,ignore
/// use core::cell::{Cell, RefCell};
/// use zweidraehte_device::{StackState, address::IndividualAddress};
///
/// pub struct MyDeviceState {
///     individual_address: RefCell<IndividualAddress>,
///     programming_mode: Cell<bool>,
///     max_apdu_length: Cell<u16>,
/// }
///
/// impl Default for MyDeviceState {
///     fn default() -> Self {
///         Self {
///             individual_address: RefCell::new(IndividualAddress::new(1, 0, 1)),
///             programming_mode: Cell::new(false),
///             max_apdu_length: Cell::new(254),
///         }
///     }
/// }
///
/// impl StackState for MyDeviceState {
///     fn individual_address(&self) -> IndividualAddress {
///         *self.individual_address.borrow()
///     }
///     fn set_individual_address(&self, addr: IndividualAddress) {
///         *self.individual_address.borrow_mut() = addr;
///     }
///     fn serial_number(&self) -> &[u8; 6] {
///         &[0x00, 0xFA, 0x00, 0x00, 0x00, 0x00]
///     }
///     fn max_apdu_length(&self) -> u16 { self.max_apdu_length.get() }
///     fn set_max_apdu_length(&self, length: u16) { self.max_apdu_length.set(length); }
///     fn is_programming_mode(&self) -> bool { self.programming_mode.get() }
///     fn set_programming_mode(&self, enabled: bool) { self.programming_mode.set(enabled); }
/// }
/// ```
pub trait StackState {
    /// Factory-programmed identity (serial number, optional FDSK).
    ///
    /// Bounded by [`DeviceIdentity`]; secure stacks additionally bound this on
    /// [`SecureDeviceIdentity`](crate::storage::SecureDeviceIdentity) at the
    /// call site to reach the FDSK without an `Option`.
    type Identity: DeviceIdentity;

    /// Get the device's individual address.
    ///
    /// This is the unique address assigned to this device on the KNX bus.
    /// It is used as the source address for outgoing messages.
    fn individual_address(&self) -> IndividualAddress;

    /// Set the device's individual address.
    ///
    /// This is typically set during device configuration or via
    /// `A_IndividualAddress_Write` when in programming mode.
    fn set_individual_address(&self, addr: IndividualAddress);

    /// Borrow the device identity.
    ///
    /// Identity is the authoritative source for serial number and (for
    /// Data Secure devices) the FDSK. The default
    /// [`serial_number`](Self::serial_number) implementation delegates here.
    fn identity(&self) -> &Self::Identity;

    /// Get the device serial number (6 bytes).
    ///
    /// Defaults to `self.identity().serial_number()`. Override only if
    /// the state holds a serial number outside its identity (rare).
    fn serial_number(&self) -> &[u8; 6] {
        self.identity().serial_number()
    }

    /// Get the runtime maximum APDU length.
    ///
    /// This value is reported via PID 56 (MAX_APDU_LENGTH) in the Device Object.
    /// It represents the actual limit based on detected hardware capabilities:
    ///
    /// - USB interface maximum frame size
    /// - TP1 MAC type (standard vs Extended Frame Format)
    /// - Other link layer constraints
    ///
    /// **Important**: This value must be ≤ [`StackDefinition::MAX_APDU_LENGTH`](crate::StackDefinition::MAX_APDU_LENGTH),
    /// which determines the compile-time buffer allocation.
    ///
    /// Common values:
    /// - 14: Standard TP1 without Extended Frame Format
    /// - 255: TP1 with EFF or KNX/IP
    ///
    /// Default implementation returns 254 (full EFF/KNX/IP support).
    /// Override this in your state implementation to return a value based on
    /// detected hardware capabilities.
    fn max_apdu_length(&self) -> u16 {
        MAX_APDU_LENGTH_EXTENDED
    }

    /// Set the runtime maximum APDU length.
    ///
    /// This is called by the link layer after detecting hardware capabilities.
    /// For example, a TP1 link layer may detect that the interface doesn't
    /// support Extended Frame Format and set this to 14 bytes.
    ///
    /// The value should not exceed [`StackDefinition::MAX_APDU_LENGTH`](crate::StackDefinition::MAX_APDU_LENGTH) which
    /// determines the compile-time buffer allocation.
    ///
    /// Implementations must persist the value into whatever backs
    /// [`max_apdu_length`](Self::max_apdu_length). State types that report a
    /// fixed compile-time `max_apdu_length` (e.g. test harnesses with no
    /// hardware-detection step) should provide an explicit empty body and
    /// document why the setter is intentionally inert.
    fn set_max_apdu_length(&self, length: u16);

    // =========================================================================
    // Programming Mode
    // =========================================================================

    /// Check if the device is in programming mode.
    ///
    /// Programming mode is a volatile runtime flag — it does not survive
    /// restarts and is not persisted. When set, the device responds to
    /// `A_IndividualAddress_Read` and accepts `A_IndividualAddress_Write`.
    ///
    /// Implementations must back this with a real flag (typically a
    /// `Cell<bool>` field). Defaulting to `false` would make the device
    /// silently un-addressable by ETS — every `A_IndividualAddress_Read`,
    /// `SystemNetworkParameterRead`, and PID 54 (PROGMODE) read would
    /// return the wrong answer.
    fn is_programming_mode(&self) -> bool;

    /// Set the programming mode flag.
    ///
    /// Paired with [`is_programming_mode`](Self::is_programming_mode); both
    /// must be backed by the same storage. A no-op setter would cause PID
    /// 54 writes and the programming button to silently fail.
    fn set_programming_mode(&self, enabled: bool);
}

// ============================================================================
// HasAuthorization — A_Authorize_Request / A_Key_Write
// ============================================================================

/// Authorization context for `A_Authorize_Request` and `A_Key_Write` services.
///
/// Provides key-based access level management. Devices that support
/// authorization implement this trait on their state type; the transport
/// layer uses [`default_access_level`](Self::default_access_level) when
/// opening connections, and the application layer uses
/// [`authorize`](Self::authorize) / [`key_write`](Self::key_write) to
/// process the corresponding APCIs.
///
/// All methods have defaults that grant minimum access (no key table).
pub trait HasAuthorization {
    /// The number of access levels this profile has: 4 (levels 0-3) or
    /// 16 (levels 0-15), per 06 Profiles v02.02.01 §4.2 row 12.
    ///
    /// A compile-time property of the profile, not a runtime one, so
    /// that a property descriptor can name an audience from 03/04/01
    /// Table 1 ([`AccessLevel`](zweidraehte_proto::access::AccessLevel))
    /// and have the number resolved when the descriptor table is built.
    const MAX_ACCESS_LEVELS: u8 = 4;

    /// Get the maximum number of access levels supported.
    ///
    /// The value form of [`MAX_ACCESS_LEVELS`](Self::MAX_ACCESS_LEVELS),
    /// for the runtime paths that hold a state rather than a type.
    fn max_access_levels(&self) -> u8 {
        Self::MAX_ACCESS_LEVELS
    }

    /// Get the default access level for new connections.
    ///
    /// This is the access level granted when a connection is opened without
    /// explicit authorization. It corresponds to the first level that has
    /// the default key (`0xFFFFFFFF`).
    ///
    /// For a device with `keys[0]`=0x00, `keys[1]`=0x12345678, `keys[2]`=0xFF..FF, `keys[3]`=0xFF..FF,
    /// this would return 2 (the first match for 0xFFFFFFFF when walking from level 0 upward).
    ///
    /// Default implementation: returns level 3 (minimum access, "access for everyone").
    /// Implementations with a key table should override this to call `authorize(&[0xFF, 0xFF, 0xFF, 0xFF])`.
    fn default_access_level(&self) -> u8 {
        self.max_access_levels() - 1 // Level 3 = minimum access = "access for everyone"
    }

    /// Authorize with a 4-byte key and return the associated access level.
    ///
    /// Returns the access level (0-3 or 0-15) associated with the key:
    /// - If key matches a configured key: return the associated level (first match wins, walking from level 0)
    /// - If key is not found in table: return max level (3 or 15, minimum access)
    ///
    /// Note: The key `0xFFFFFFFF` is NOT special - it must be found in the key table
    /// like any other key. This allows devices to configure which level(s) use the default key.
    ///
    /// Default implementation: returns minimum access for all keys (no key table).
    fn authorize(&self, _key: &[u8; 4]) -> u8 {
        self.max_access_levels() - 1 // No key table -> minimum access
    }

    /// Write a new key for a specific access level.
    ///
    /// Arguments:
    /// - `level`: The access level to set the key for
    /// - `key`: The new 4-byte key
    /// - `ctx`: The access context of the current connection
    ///
    /// Returns the level if successful, or 0xFF if:
    /// - The level is invalid (>= max_access_levels)
    /// - The caller's access level is higher (less privileged) than the target level
    ///
    /// If key is `0xFFFFFFFF`, the key for that level is deleted (set to invalid).
    ///
    /// Default implementation: always returns 0xFF (not supported).
    fn key_write(&self, _level: u8, _key: &[u8; 4], _ctx: AccessContext) -> u8 {
        0xFF // Not supported by default
    }
}

// ============================================================================
// HasPersistence — dirty tracking for state changes
// ============================================================================

/// Persistence notification for state changes.
///
/// Called by the stack whenever persistent state is modified through
/// property writes, memory writes, or other management operations.
/// Implementations that support persistence should set a dirty flag
/// so that state can be saved at the appropriate time (e.g., before
/// a restart or periodically).
pub trait HasPersistence {
    /// Mark the device state as dirty (needing persistence).
    ///
    /// Called from every successful property write and `A_Memory_Write`.
    /// Implementations must record the dirty state somewhere a save loop
    /// can observe (typically a `Cell<bool>` field). State types that
    /// genuinely don't persist (e.g. ephemeral test fixtures) should
    /// provide an explicit empty body and document why.
    fn mark_dirty(&self);

    /// Whether there are unsaved changes since the last successful save.
    ///
    /// The generic storage task reads this before saving the config blob.
    /// Deliberately has **no default**: a default `false` would let a state
    /// implement a real [`mark_dirty`](Self::mark_dirty) yet silently never
    /// save (the task would always see "clean"). A non-persisting state
    /// returns `false` explicitly, mirroring its empty `mark_dirty`.
    fn is_dirty(&self) -> bool;

    /// Clear the dirty flag after a successful save. Defaults to a no-op —
    /// harmless even for persisting states (the flag would merely stay set
    /// and force an extra save), unlike an `is_dirty` default, which would
    /// suppress saves entirely.
    fn clear_dirty(&self) {}

    /// Apply a restart erase code to the runtime state.
    ///
    /// This is the state-side half of a restart: wiping the individual
    /// address / tables / parameters / extension state per the code. The
    /// durable-storage half (clearing the mc_timer watermark, re-saving the
    /// config) is the storage task's `StorageHooks::erase`. Defaults
    /// to a no-op for states with nothing to erase; `SystemBDeviceState`
    /// forwards to its inherent `apply_erase_code`.
    fn apply_erase_code(&self, code: crate::restart::EraseCode) {
        let _ = code;
    }
}

// ============================================================================
// Generic capability traits — BCU implementations satisfy these
// ============================================================================
//
// These three traits describe capabilities that are required by generic stack
// layers but are not specific to any one BCU family. They live here, in the
// generic core, rather than inside `bcus::system_b` because:
//
// - `CoreDeviceState` bounds on them, and `CoreDeviceState` is generic.
// - The application layer, secure-application layer, and context-trait impls
//   all reach them through `D::State`, which is BCU-agnostic.
//
// Each trait carries only no-op defaults, so BCUs without the corresponding
// capability (e.g., a plain TP1 device without Data Secure) satisfy the bound
// for free with the blanket `impl HasSecurityMode for () {}`. BCUs that *do*
// implement the capability provide the real bodies.

/// Whether the device's Security Mode is currently enabled.
///
/// Extension state types that include security (e.g.,
/// `SecureExtensionState`) implement this to delegate to the Security
/// Interface Object's flag. Non-secure extensions use the default
/// (`false`).
///
/// Separated from [`ExtensionState`](crate::extension::ExtensionState)
/// because security mode is not a persistence concern — TP1 and IP
/// extensions should not need to know about it.
pub trait HasSecurityMode {
    fn security_mode_enabled(&self) -> bool {
        false
    }

    /// Log a security access denial. Called by the property dispatch layer
    /// when a property access is denied due to security policy.
    ///
    /// Default: no-op. Extensions with security state override this to
    /// record the failure in the security failures log.
    fn log_access_denied(&self, _source_addr: u16) {}

    /// Check whether a group key exists for the given TSAP index.
    ///
    /// Used by GO diagnostics to validate security flags on direct
    /// GroupValue_Write/Read commands. Default: `false` (no keys).
    fn has_group_key(&self, _tsap: u16) -> bool {
        false
    }
}

impl HasSecurityMode for () {}

/// Context trait for querying diagnostic mode state.
///
/// Implemented on `()` with no-op defaults so devices without diagnostics
/// support can use `()` as their diagnostics context.
pub trait DiagnosticsView {
    /// Whether the device is currently in diagnostic mode.
    fn is_diagnostic_mode(&self) -> bool {
        false
    }

    /// Current operation mode byte (0x00=normal, 0x01=diagnostic).
    fn operation_mode(&self) -> u8 {
        0x00
    }

    /// Remaining time in the current operation mode (0xFF = no timeout).
    fn time_left(&self) -> u8 {
        0xFF
    }

    /// Source address filter for incoming GO updates in diagnostic mode.
    /// `None` means no filter (all sources blocked in diagnostic mode).
    fn diagnostic_source_filter(&self) -> Option<u16> {
        None
    }

    /// Set the source address filter for diagnostic mode.
    fn set_diagnostic_source_filter(&self, _ia: Option<u16>) {}
}

impl DiagnosticsView for () {}

/// Trait for device states that provide a diagnostics context.
///
/// The application layer and stack handle use this to check diagnostic
/// mode state without coupling to the concrete state type.
pub trait HasDiagnosticsContext {
    /// The concrete diagnostics context type.
    type Diagnostics: DiagnosticsView;

    /// Get a reference to the diagnostics context.
    fn diagnostics(&self) -> &Self::Diagnostics;
}

/// Trait for accessing the extension state on a device state.
///
/// This enables context trait impls and other generic code to access
/// the extension state (e.g., `IpExtensionState`) through a trait bound
/// rather than knowing the concrete `SystemBDeviceState` type.
pub trait HasExtensionState {
    /// The extension state type.
    type ES;

    /// Get a reference to the extension state.
    fn extension_state(&self) -> &Self::ES;
}

// ============================================================================
// State Bundles
// ============================================================================

/// Core bundle of traits required for any KNX device state.
pub trait CoreDeviceState<CO>:
    StackState
    + HasAuthorization
    + HasPersistence
    + HasAddressTable
    + HasApplication
    + HasAssociationTable
    + HasCommunicationObjectTable
    + HasCommObjects<CO = CO>
    + HasGoSecurityView
    + HasSecurityMode
    + HasDiagnosticsContext
    + HasConnectionAuth
    + HasRoutingCount
    + DeviceModelNotifier
    + 'static
{
}

impl<T, CO> CoreDeviceState<CO> for T where
    T: StackState
        + HasAuthorization
        + HasPersistence
        + HasAddressTable
        + HasApplication
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasCommObjects<CO = CO>
        + HasGoSecurityView
        + HasSecurityMode
        + HasDiagnosticsContext
        + HasConnectionAuth
        + HasRoutingCount
        + DeviceModelNotifier
        + 'static
{
}

// ============================================================================
// KNX Data Secure — generic security-state surface
// ============================================================================
//
// These types are pure protocol/runtime vocabulary (failure categories per
// KNX 03/05/01 and the key/flag lookup surface the Secure Application Layer
// needs). They live here, alongside the other generic capability traits, so
// the generic S-AL and the composition builders depend on `crate::state`
// rather than reaching into the System B BCU. `bcus::system_b` re-exports
// them for backwards compatibility and implements `HasSecurityState` for its
// `SecureExtensionState`.

/// Security failure type indices per KNX spec.
///
/// The failures log maintains 4 × 16-bit counters. Types 0–2 each map
/// to their own counter; types 3 and 4 both increment counter 3 (the
/// "access & role" counter). The type value is also stored in the per-entry
/// ring buffer so that individual failures can be distinguished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// `#[non_exhaustive]`: every construction/match site is inside this crate,
/// where the attribute has no effect — so in-crate exhaustiveness checking
/// is preserved while downstream crates stay insulated from new variants.
#[non_exhaustive]
pub enum SecurityFailureType {
    /// Invalid SCF field (unsupported algorithm, reserved bits set).
    ScfError = 0,
    /// MAC verification failed (wrong key or tampered message).
    CryptoError = 1,
    /// Sequence number check failed (replay or out-of-order).
    SeqNrError = 2,
    /// Sender not found in Security Individual Address Table.
    RoleError = 3,
    /// Access denied by access policy after successful verification.
    AccessError = 4,
}

/// A single failure log entry recording a security event.
///
/// Each entry stores the source address of the offending device, the first
/// 9 bytes of the offending frame (for diagnostic purposes), and the
/// failure type code (see [`SecurityFailureType`]).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SecurityFailureEntry {
    /// Source individual address of the offending message.
    pub source_addr: u16,
    /// First 9 bytes of the offending frame (zero-padded if shorter).
    pub frame_fragment: [u8; 9],
    /// Failure type code (discriminant of [`SecurityFailureType`]).
    pub failure_type: u8,
}

impl Default for SecurityFailureEntry {
    fn default() -> Self {
        Self { source_addr: 0, frame_fragment: [0; 9], failure_type: 0 }
    }
}

/// Provides access to security keys and flags without exposing the
/// const-generic table sizes. The S-AL layer requires this trait on
/// `D::State` to look up keys for decryption/encryption.
///
/// Implemented automatically for `SystemBDeviceState` when the extension
/// state is `SecureExtensionState`.
///
/// [`HasSecurityMode`] is a supertrait rather than this trait redeclaring
/// `security_mode_enabled`: both spellings existed, with `HasSecurityMode`
/// defaulting to `false`, so which one a caller saw depended on which trait
/// happened to be in scope — and the default could silently answer `false`
/// for a device that does have security enabled.
pub trait HasSecurityState: HasSecurityMode {
    /// Current load state of the Security Interface Object.
    ///
    /// Per KNX spec 03/05/01 §6.3.4: security tables (P2P keys, group
    /// keys, SIAT) are only evaluated by the S-AL when this is `Loaded`.
    /// Tool Key and Security Mode are independent of load state.
    fn security_load_state(&self) -> LoadState;

    /// Get the 16-byte tool key.
    fn tool_key(&self) -> [u8; 16];

    /// Look up a group key by 1-based group address table index.
    fn group_key_for_index(&self, ga_index: u16) -> Option<[u8; 16]>;

    /// Look up GO security flags by 0-based group object index.
    fn go_security_flags_for(&self, go_index: u16) -> Option<u8>;

    /// Look up a P2P key and role bitmask by 1-based Security Individual
    /// Address Table index.
    ///
    /// The Point-to-point Key Table refers to a communication partner by its
    /// `IA_Index`, not by its address (03/05/01 §6.3.6.2); callers resolve the
    /// peer IA through `SiatAccess::siat_index_of` first. The security state
    /// cannot do that itself — the SIAT lives in the sequence-number store, so
    /// that the Last Valid SeqNr has a single source of truth.
    ///
    /// Returns `(key, roles)` where `roles` is a bitmask of R0-R15 from
    /// bytes 18-19 of the P2P key table entry.
    fn p2p_key_for_index(&self, ia_index: u16) -> Option<([u8; 16], u16)>;

    /// Record a security failure in the failures log and set bit 0 of
    /// PID_SECURITY_REPORT (57) per 03/05/01 §6.3.11.4.
    ///
    /// `frame_fragment` should be the first bytes of the offending frame
    /// (up to 9 bytes are stored per entry for diagnostic purposes).
    ///
    /// Deliberately returns nothing: whether to emit the spontaneous
    /// `A_NetworkParameter_InfoReport` does *not* depend on this call's
    /// effect on PID 57 — 03/05/01 §6.3.11.4 has every failure report
    /// while reporting is enabled, "even if a security failure is
    /// reported before or not", so a transition signal would only
    /// tempt callers into the gating the spec forbids.
    fn log_security_failure(&self, failure_type: SecurityFailureType, source_addr: u16, frame_fragment: &[u8]);

    /// Current value of PID_SECURITY_REPORT (57).
    fn security_report(&self) -> u8;

    /// Whether PID_SECURITY_REPORT_CONTROL (58) is Enabled.
    fn security_report_enabled(&self) -> bool;

    /// Get the 4 × 16-bit failure counters serialized as 8 big-endian bytes.
    fn failure_counters(&self) -> [u8; 8];

    /// Get a failure entry by reverse index (0 = most recent).
    fn failure_entry(&self, index: u8) -> Option<SecurityFailureEntry>;

    /// Clear all failure counters and entries.
    fn clear_failure_log(&self);
}
