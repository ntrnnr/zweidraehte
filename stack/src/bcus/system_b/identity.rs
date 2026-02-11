//! Device identity — read-only, factory-programmed data.
//!
//! This module provides the [`DeviceIdentity`] trait for accessing
//! per-device identity data that is programmed at manufacturing time
//! and survives factory resets.
//!
//! Different platforms provide identity data from different sources:
//! - **Testing/demos**: [`StaticIdentity`] with a hardcoded serial number
//! - **Linux production**: `FileIdentity` (in the `testutil` crate) — reads
//!   from a JSON file at startup, with provisioning support
//! - **Embedded production**: Read from OTP (one-time programmable) memory
//!   or a dedicated flash sector

/// Read-only device identity data.
///
/// This data is programmed at the factory and is immutable from the
/// stack's perspective. It survives factory resets — unlike ETS-configured
/// state in [`DeviceStorage`](super::DeviceStorage).
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
/// let state = SystemBDeviceState::new(storage, &identity);
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
