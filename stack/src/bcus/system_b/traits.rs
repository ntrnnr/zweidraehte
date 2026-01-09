//! Core traits for System B devices.

use const_default::ConstDefault;

use crate::{
    IpPlatform, StackState,
    objects::comm::ComObjects,
};

use super::DeviceStorage;

/// Core trait for System B devices.
///
/// This trait defines the compile-time constants that identify a device.
/// These values are burned into firmware and never change:
///
/// - **Identity**: Mask version, serial number, hardware type
/// - **Capabilities**: Program version, PEI type, device descriptor
/// - **Sizing**: Maximum table capacities
///
/// All ETS-configurable values (individual address, friendly name, etc.)
/// are stored in persistent storage and accessed via the device state,
/// NOT defined here.
///
/// # Example
///
/// ```rust,ignore
/// #[derive(Copy, Clone)]
/// pub struct MyDevice;
///
/// impl SystemBDevice for MyDevice {
///     const MASK_VERSION: [u8; 2] = [0x57, 0xB0];  // KNX/IP
///     const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78];
///     const HARDWARE_TYPE: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
///     const PROGRAM_VERSION: [u8; 5] = [0x00, 0xFA, 0x01, 0x00, 0x01];
///
///     const MAX_ADDRESSES: usize = 64;
///     const MAX_ASSOCIATIONS: usize = 64;
///     const MAX_COM_OBJECTS: usize = 32;
///
///     type ComObjects = MyComObjects;
///     type Storage = FileStorage;
/// }
/// ```
pub trait SystemBDevice: Sized + Copy {
    // ========================================================================
    // Device Identity (compile-time, immutable)
    // ========================================================================

    /// Mask version / Device Descriptor Type 0 (2 bytes).
    ///
    /// Common values:
    /// - `[0x57, 0xB0]` - KNX/IP System B
    /// - `[0x07, 0xB0]` - TP1 System B
    const MASK_VERSION: [u8; 2];

    /// Device serial number (6 bytes).
    ///
    /// Format: 2 bytes manufacturer ID + 4 bytes device-specific.
    /// This is factory-programmed and never changes.
    const SERIAL_NUMBER: [u8; 6];

    /// Hardware type identifier (6 bytes).
    ///
    /// Identifies the hardware revision/variant.
    const HARDWARE_TYPE: [u8; 6];

    /// Application program version (5 bytes).
    ///
    /// Format: 2 bytes manufacturer + 2 bytes app ID + 1 byte version.
    const PROGRAM_VERSION: [u8; 5];

    /// Device Descriptor Type 2 (14 bytes, optional).
    ///
    /// Extended device information. Set to `None` if not supported.
    const DEVICE_DESCRIPTOR_TYPE2: Option<[u8; 14]> = None;

    /// PEI type (0 = no PEI).
    const PEI_TYPE: u8 = 0;

    // ========================================================================
    // Table Sizing (determines memory allocation)
    // ========================================================================

    /// Maximum number of group addresses in the address table.
    const MAX_ADDRESSES: usize;

    /// Maximum number of associations in the association table.
    const MAX_ASSOCIATIONS: usize;

    /// Maximum number of communication objects.
    const MAX_COM_OBJECTS: usize;

    /// Maximum application data size in bytes.
    const MAX_APP_DATA: usize = 256;

    // ========================================================================
    // Associated Types
    // ========================================================================

    /// Communication objects container.
    ///
    /// Define using [`define_com_objects!`](crate::define_com_objects).
    type ComObjects: ComObjects;

    /// Application parameters type stored in the Application table.
    ///
    /// Use `()` if no application parameters are needed.
    type AppParams: ConstDefault = ();

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

    /// Number of UDP sockets needed.
    ///
    /// Default is 2 (one for discovery/unicast, one for routing multicast).
    const NUM_SOCKETS: usize = 2;

    /// Number of KNXnet/IP servers.
    ///
    /// Default is 2 (discovery server + routing server).
    const NUM_SERVERS: usize = 2;

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

// ============================================================================
// Helper trait for deriving manufacturer ID from serial number
// ============================================================================

/// Helper methods and computed constants derived from SystemBDevice.
pub trait SystemBDeviceExt: SystemBDevice {
    // ========================================================================
    // Computed table sizes (in bytes)
    // ========================================================================

    /// Address table size: 2-byte count + 2 bytes per entry.
    const ADT_SIZE: usize = 2 + Self::MAX_ADDRESSES * 2;

    /// Association table size: 2-byte count + 4 bytes per entry.
    const AST_SIZE: usize = 2 + Self::MAX_ASSOCIATIONS * 4;

    /// Group object table size: 2-byte count + 2 bytes per entry.
    const COT_SIZE: usize = 2 + Self::MAX_COM_OBJECTS * 2;

    /// Application data size.
    const APP_SIZE: usize = Self::MAX_APP_DATA;

    // ========================================================================
    // Helper methods
    // ========================================================================

    /// Get the manufacturer ID from the serial number.
    ///
    /// The manufacturer ID is the first 2 bytes of the serial number.
    fn manufacturer_id() -> u16 {
        u16::from_be_bytes([Self::SERIAL_NUMBER[0], Self::SERIAL_NUMBER[1]])
    }

    /// Check if this is a KNX/IP device (mask version 57B0).
    fn is_knxip() -> bool {
        Self::MASK_VERSION == [0x57, 0xB0]
    }

    /// Check if this is a TP1 device (mask version 07B0).
    fn is_tp1() -> bool {
        Self::MASK_VERSION == [0x07, 0xB0]
    }

    /// Get the memory layout for this device.
    ///
    /// Returns a `MemoryLayout` describing the virtual addresses for each table,
    /// calculated from the device's table size constants.
    fn memory_layout() -> super::memory_map::MemoryLayout {
        super::memory_map::MemoryLayout::calculate(
            super::memory_map::SystemBMemoryMap::DEFAULT_BASE_ADDRESS,
            Self::MAX_ADDRESSES,
            Self::MAX_ASSOCIATIONS,
            Self::MAX_COM_OBJECTS,
            Self::MAX_APP_DATA,
        )
    }
}

// Blanket implementation for all SystemBDevice types
impl<T: SystemBDevice> SystemBDeviceExt for T {}
