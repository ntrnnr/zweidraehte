//! Read-only, factory-programmed device identity.
//!
//! Identity data (serial number, FDSK) is immutable from the stack's
//! perspective and survives factory resets — unlike ETS-configured state,
//! which lives in the persisted device config.

/// Read-only device identity data.
///
/// This data is programmed at the factory and is immutable from the
/// stack's perspective. It survives factory resets — unlike the
/// ETS-configured state in the persisted device config.
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
