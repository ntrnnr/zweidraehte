//! IP Interface Device Definition
//!
//! A KNX IP Interface bridges KNX/IP tunneling connections to a TP1 bus.
//! Clients (ETS, visualization tools) connect via KNX/IP Tunneling; the
//! interface forwards cEMI frames bidirectionally to/from the bus.
//!
//! This is a pure infrastructure device — no application-level communication
//! objects or parameters. The device's sole purpose is tunneling.
//!
//! # Mask Version
//!
//! Real IP Interface devices (Weinzierl, MDT) use TP1-based masks because
//! the primary bus connection is TP1. KNX/IP is a secondary interface,
//! indicated by `IsIPEnabled="true"` on the Hardware element in MTXML.
//! We use `MaskVersion::SystemBTp1` (0x07B0).


use zweidraehte_device::ets::{DeviceDescriptor, MaskVersion};
use zweidraehte_device::NoParams;
use zweidraehte_device::objects::comm::{NoComObjectIndex, NoComObjects};

// ============================================================================
// Device Identity
// ============================================================================

/// IP Interface device metadata.
#[derive(Debug, Clone, Copy)]
pub struct IpInterfaceDevice;

impl IpInterfaceDevice {
    pub const MANUFACTURER_ID: u16 = 0x00FA;
    pub const HARDWARE_TYPE: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x10];
    pub const APPLICATION_ID: u16 = 0x1000;
    pub const APPLICATION_VERSION: u8 = 0x01;
    /// 1 device IA + 4 additional IAs for tunneling connections.
    pub const MAX_ADDRESS_TABLE_ENTRIES: u16 = 5;
    pub const MAX_ASSOCIATION_TABLE_ENTRIES: u16 = 1;
    /// No group communication objects — pure tunneling bridge.
    pub const MAX_COM_OBJECTS: u16 = 0;
    /// Number of simultaneous tunneling connections (additional IAs).
    pub const ADDITIONAL_IA_COUNT: u8 = 4;
    pub const PEI_TYPE: u8 = 0;

    pub const fn device_descriptor() -> DeviceDescriptor {
        DeviceDescriptor {
            mask_version: MaskVersion::SystemBTp1,
            manufacturer_id: Self::MANUFACTURER_ID,
            hardware_type: Self::HARDWARE_TYPE,
            application_id: Self::APPLICATION_ID,
            application_version: Self::APPLICATION_VERSION,
            max_address_table_entries: Self::MAX_ADDRESS_TABLE_ENTRIES,
            max_association_table_entries: Self::MAX_ASSOCIATION_TABLE_ENTRIES,
            max_com_objects: Self::MAX_COM_OBJECTS,
            pei_type: Self::PEI_TYPE,
        }
    }
}

/// Device descriptor for the IP Interface (mask version 07B0, TP1).
pub const DEVICE_DESCRIPTOR: DeviceDescriptor = IpInterfaceDevice::device_descriptor();

/// Serial number for the IP Interface hardware.
pub const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x10];

// ============================================================================
// Parameters (empty — no application settings)
// ============================================================================

/// Empty parameter block. The IP Interface has no application-level
/// parameters; all configuration is handled through interface object
/// properties (individual addresses, IP settings, etc.).
///
/// Aliases the stack's [`NoParams`], which supplies the `ConstDefault` +
/// zerocopy impls that `StackDefinition::P` requires.
pub type IpInterfaceParams = NoParams;

// ============================================================================
// Communication Objects (empty — pure bridge device)
// ============================================================================

/// Empty communication objects. The IP Interface has no group objects — it
/// only forwards frames between tunneling clients and the TP1 bus.
///
/// Aliases the stack's [`NoComObjects`] rather than restating the
/// uninhabited-index + three-impl boilerplate.
pub type IpInterfaceComObjects = NoComObjects;

/// Index type for the (empty) comm object set.
pub type IpInterfaceComObjectIndex = NoComObjectIndex;
