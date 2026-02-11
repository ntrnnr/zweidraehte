//! Core traits for System B devices.

use crate::IpPlatform;

use super::DeviceStorage;

/// Core trait for System B devices.
///
/// This trait provides **only** System B-specific configuration. All device metadata
/// (mask version, manufacturer ID, application info, table capacities) comes from
/// [`StackDefinition::DEVICE`].
///
/// # What belongs here
///
/// - `PEI_TYPE`: Physical External Interface type (System B hardware concept)
/// - `Storage`: Persistence backend (System B state management)
///
/// # What does NOT belong here
///
/// - Serial number → Runtime state (factory-programmed, read from OTP/flash)
/// - Device descriptor → `StackDefinition::DEVICE`
/// - Mask version, hardware type, etc. → `StackDefinition::DEVICE`
/// - Application data size → Computed from `size_of::<StackDefinition::P>()`
///
/// # Example
///
/// ```rust,ignore
/// #[derive(Copy, Clone)]
/// pub struct MyDevice;
///
/// impl SystemBDevice for MyDevice {
///     type Storage = FileStorage;
/// }
/// ```
pub trait SystemBDevice: Sized + Copy {
    /// PEI type (0 = no PEI).
    ///
    /// Physical External Interface type, specific to System B devices.
    /// Most modern devices don't have a PEI, so default is 0.
    const PEI_TYPE: u8 = 0;

    /// Storage backend for persisting device state.
    ///
    /// Use [`NoStorage`](super::NoStorage) for testing or devices
    /// without persistent storage.
    type Storage: DeviceStorage;
}

/// Extension trait for KNX/IP devices (mask version 57B0).
///
/// This trait adds KNX/IP-specific configuration to a [`SystemBDevice`].
///
/// # Example
///
/// ```rust,ignore
/// impl KnxIpDevice for MyDevice {
///     const INTERFACE_NAME: &'static str = "eth0";
///     type Platform = LinuxPlatform;
/// }
/// ```
pub trait KnxIpDevice: SystemBDevice {
    /// Network interface name (e.g., "eth0", "wlan0", "enp0s3").
    const INTERFACE_NAME: &'static str;

    /// Platform for querying current network state.
    ///
    /// This provides runtime network information like current IP address,
    /// MAC address, etc. from the operating system or network stack.
    type Platform: IpPlatform + Default;
}

/// Extension trait for TP1 devices (mask version 07B0).
///
/// This trait adds TP1-specific configuration to a [`SystemBDevice`].
///
/// # Note
///
/// TP1 link layer is not yet implemented. This trait is a placeholder
/// for future development.
pub trait TpDevice: SystemBDevice {
    // TODO: Add TP1-specific configuration when TPUART link layer is implemented
    // - UART peripheral configuration
    // - Baud rate (9600 for TP1)
    // - etc.
}
