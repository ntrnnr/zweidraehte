//! 2-Button Light Switch Device Definition
//!
//! A wall switch with two momentary buttons, supporting 1-function
//! (rocker pair) and 2-function (independent buttons) operating modes.
//! Each button/pair is configurable for switching, dimming, blind
//! control, or scene selection.
//!
//! This module contains the transport-agnostic device definition:
//! parameters, communication objects, and ETS page layout. The
//! transport-specific wiring (`StackDefinition`, state types, link layer)
//! is provided by each binary crate.
//!
//! # Usage
//!
//! ```rust,ignore
//! use devices::light_switch::*;
//!
//! // Pick the right descriptor for your transport
//! let desc = &DEVICE_DESCRIPTOR_IP;   // for KNX/IP
//! let desc = &DEVICE_DESCRIPTOR_TP1;  // for TP-UART
//!
//! // In your StackDefinition impl:
//! impl StackDefinition for MyStack {
//!     const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR_IP;
//!     type P = LightSwitchParams;
//!     type CO = comm_objs::LightSwitchComObjects;
//!     // ... platform-specific types
//! }
//! ```

pub mod app;
pub mod params;
pub mod comm_objs;

#[cfg(feature = "knxprod")]
mod layout;
#[cfg(feature = "knxprod")]
pub mod translations;

pub use params::*;

use zweidraehte::ets::{DeviceDescriptor, MaskVersion};

// ============================================================================
// Device Identity
// ============================================================================

/// Device metadata container and descriptor factory.
///
/// Holds compile-time constants that identify the light switch firmware.
/// Use [`device_descriptor()`](Self::device_descriptor) to build a
/// [`DeviceDescriptor`] for the target transport medium.
#[derive(Debug, Clone, Copy)]
pub struct LightSwitchDevice;

impl LightSwitchDevice {
    pub const MANUFACTURER_ID: u16 = 0x00FA;
    pub const HARDWARE_TYPE: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
    pub const APPLICATION_ID: u16 = 0x0300;
    pub const APPLICATION_VERSION: u8 = 0x02;
    pub const MAX_ADDRESS_TABLE_ENTRIES: u16 = 10;
    pub const MAX_ASSOCIATION_TABLE_ENTRIES: u16 = 12;
    pub const MAX_COM_OBJECTS: u16 = 6;
    pub const PEI_TYPE: u8 = 0;

    /// Build a device descriptor for the given mask version.
    ///
    /// The mask version determines the transport medium:
    /// - `SystemBKnxIp` (0x57B0) for KNX/IP devices
    /// - `SystemBTp1` (0x07B0) for TP-UART devices
    pub const fn device_descriptor(mask: MaskVersion) -> DeviceDescriptor {
        DeviceDescriptor {
            mask_version: mask,
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

/// Device descriptor for KNX/IP (mask version 57B0).
pub const DEVICE_DESCRIPTOR_IP: DeviceDescriptor =
    LightSwitchDevice::device_descriptor(MaskVersion::SystemBKnxIp);

/// Device descriptor for TP-UART (mask version 07B0).
pub const DEVICE_DESCRIPTOR_TP1: DeviceDescriptor =
    LightSwitchDevice::device_descriptor(MaskVersion::SystemBTp1);
