//! Core device state traits and error types.
//!
//! [`StackState`] is the fundamental runtime abstraction for any KNX device,
//! providing individual address, serial number, authorization, and
//! programming mode. It has no dependency on KNX/IP.

use crate::access::AccessContext;
use crate::address::IndividualAddress;

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
/// use core::cell::RefCell;
/// use zweidraehte_device::{StackState, address::IndividualAddress};
///
/// pub struct MyDeviceState {
///     individual_address: RefCell<IndividualAddress>,
/// }
///
/// impl Default for MyDeviceState {
///     fn default() -> Self {
///         Self {
///             individual_address: RefCell::new(IndividualAddress::new(1, 0, 1)),
///         }
///     }
/// }
///
/// impl StackState for MyDeviceState {
///     fn individual_address(&self) -> IndividualAddress {
///         *self.individual_address.borrow()
///     }
///
///     fn set_individual_address(&self, addr: IndividualAddress) {
///         *self.individual_address.borrow_mut() = addr;
///     }
///
///     fn serial_number(&self) -> &[u8; 6] {
///         &[0x00, 0xFA, 0x00, 0x00, 0x00, 0x00]
///     }
/// }
/// ```
pub trait StackState {
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

    /// Get the device serial number (6 bytes).
    ///
    /// The serial number consists of 2 bytes manufacturer ID followed by
    /// 4 bytes device-specific identifier. Used for `A_IndividualAddressSerialNumber_Read/Write`.
    fn serial_number(&self) -> &[u8; 6];

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
    /// Default implementation does nothing (for state implementations that
    /// don't support runtime APDU length changes).
    fn set_max_apdu_length(&self, _length: u16) {
        // Default: no-op for implementations that don't support this
    }

    /// Receive link-layer-derived capabilities at boot time.
    ///
    /// Called once during stack initialisation with the value of
    /// [`LinkLayerCapabilities::KNXNETIP_DEVICE_CAPABILITIES`](crate::layers::LinkLayerCapabilities::KNXNETIP_DEVICE_CAPABILITIES).
    /// IP extensions store PID 68 here; non-IP devices ignore it.
    ///
    /// Default implementation does nothing.
    fn set_link_layer_capabilities(&self, _capabilities: u16) {
        // Default: no-op for implementations without IP extension state
    }

    // =========================================================================
    // Programming Mode
    // =========================================================================

    /// Check if the device is in programming mode.
    ///
    /// Programming mode is a volatile runtime flag — it does not survive
    /// restarts and is not persisted. When set, the device responds to
    /// `A_IndividualAddress_Read` and accepts `A_IndividualAddress_Write`.
    ///
    /// Default implementation returns `false`.
    fn is_programming_mode(&self) -> bool {
        false
    }

    /// Set the programming mode flag.
    ///
    /// Default implementation does nothing.
    fn set_programming_mode(&self, _enabled: bool) {}

    // =========================================================================
    // Persistence
    // =========================================================================

    /// Mark the device state as dirty (needing persistence).
    ///
    /// Called by the stack whenever persistent state is modified through
    /// property writes, memory writes, or other management operations.
    /// Implementations that support persistence should set a dirty flag
    /// so that state can be saved at the appropriate time (e.g., before
    /// a restart or periodically).
    ///
    /// Default implementation does nothing (for state implementations
    /// without persistence).
    fn mark_dirty(&self) {
        // Default: no-op for implementations without persistence
    }

    // =========================================================================
    // Authorization (A_Authorize_Request / A_Key_Write)
    // =========================================================================

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
