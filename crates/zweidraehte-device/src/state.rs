//! Core device state traits and error types.
//!
//! [`StackState`] is the fundamental runtime abstraction for any KNX device,
//! providing individual address, serial number, authorization, and
//! providing individual address, serial number, authorization, and
//! programming mode. It has no dependency on KNX/IP.

use crate::bcus::system_b::HasDiagnosticsContext;
use crate::device_model::DeviceModelNotifier;
use crate::objects::{
    comm::{HasCommObjects, HasGoSecurityView},
    interface::HasRoutingCount,
    tables::{HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable},
};
use crate::storage::DeviceIdentity;
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
        crate::config::MAX_APDU_LENGTH_EXTENDED
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

    // =========================================================================
    // Persistence
    // =========================================================================

    // =========================================================================
    // KNX Data Secure
    // =========================================================================

    /// Whether the device's Security Mode is currently enabled.
    ///
    /// When `true`, the "Security Mode On" columns of the access policy
    /// matrix apply; when `false`, the "Security Mode Off" columns apply.
    ///
    /// Default: `false` (non-secure devices always use "Security Mode Off").
    /// Secure devices override this by delegating to the Security IO's
    /// `security_mode_enabled` flag.
    fn security_mode_enabled(&self) -> bool {
        false
    }

    /// Called by the property dispatch layer when a property access is
    /// denied due to security policy. Secure devices should log this as
    /// a security failure (AccessError).
    ///
    /// `source_addr` is the sender's individual address.
    ///
    /// Default: no-op (non-secure devices don't log security failures).
    fn log_access_denied(&self, _source_addr: u16) {}

    /// Check whether a group key exists for the given TSAP index.
    ///
    /// Used by GO diagnostics to validate security flags on direct
    /// GroupValue_Write/Read commands (ServiceIDs 0x01 and 0x03).
    ///
    /// Default: `false` (non-secure devices have no group keys).
    fn has_group_key(&self, _tsap: u16) -> bool {
        false
    }
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
    /// Get the maximum number of access levels supported.
    ///
    /// Returns 4 for levels 0-3, or 16 for levels 0-15.
    /// Default is 4 (levels 0-3).
    fn max_access_levels(&self) -> u8 {
        4
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
        + HasDiagnosticsContext
        + HasConnectionAuth
        + HasRoutingCount
        + DeviceModelNotifier
        + 'static
{
}
