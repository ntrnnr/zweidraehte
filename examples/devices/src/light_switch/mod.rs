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
pub mod comm_objs;
pub mod easter_egg;
pub mod params;

#[cfg(feature = "knxprod")]
mod layout;
#[cfg(feature = "knxprod")]
pub mod translations;

pub use params::*;

use zweidraehte_device::ets::{DeviceDescriptor, MaskVersion};

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
    /// Application ID for the KNX/IP variant.
    pub const APPLICATION_ID_IP: u16 = 0x0300;
    /// Application ID for the TP1 variant. Distinct from the IP variant so
    /// both can coexist in a single knxprod package.
    pub const APPLICATION_ID_TP1: u16 = 0x0301;
    /// Application ID for the KNX-RF variant (mask `SystemBRf` / 0x27B0).
    pub const APPLICATION_ID_RF: u16 = 0x0303;
    /// Application ID for the Data Secure TP1 variant. Same mask version
    /// as the plain TP1 variant (`SystemBTp1` / 0x07B0) — Data Secure is a
    /// System B feature, not a distinct mask — but a different
    /// application ID so both secure and insecure TP1 variants coexist in
    /// a single knxprod catalogue.
    pub const APPLICATION_ID_TP1_SECURE: u16 = 0x0302;
    /// Application ID for the Data Secure KNX-RF variant. Same mask
    /// version as the plain RF variant (`SystemBRf` / 0x27B0) — Data
    /// Secure is a System B feature, not a distinct mask — but a
    /// different application ID so both secure and insecure RF variants
    /// coexist in a single knxprod catalogue.
    pub const APPLICATION_ID_RF_SECURE: u16 = 0x0304;
    /// Application ID for the KNX/IP variant that supports **both** KNX IP
    /// Secure and KNX Data Secure. Same mask version as the plain IP
    /// variant (`SystemBKnxIp` / 0x57B0) — neither IP Secure nor Data
    /// Secure is a distinct mask, they are System B / KNXnet/IP features —
    /// but a different application ID so the secure and insecure IP
    /// variants coexist in a single knxprod catalogue.
    pub const APPLICATION_ID_IP_SECURE: u16 = 0x0305;
    pub const APPLICATION_VERSION: u8 = 0x02;
    pub const MAX_ADDRESS_TABLE_ENTRIES: u16 = 10;
    pub const MAX_ASSOCIATION_TABLE_ENTRIES: u16 = 12;
    pub const MAX_COM_OBJECTS: u16 = 6;
    pub const PEI_TYPE: u8 = 0;

    /// Build a descriptor from the only two fields that vary between this
    /// device's variants; the remaining seven are identical everywhere.
    const fn descriptor_for(mask: MaskVersion, application_id: u16) -> DeviceDescriptor {
        DeviceDescriptor {
            mask_version: mask,
            manufacturer_id: Self::MANUFACTURER_ID,
            hardware_type: Self::HARDWARE_TYPE,
            application_id,
            application_version: Self::APPLICATION_VERSION,
            max_address_table_entries: Self::MAX_ADDRESS_TABLE_ENTRIES,
            max_association_table_entries: Self::MAX_ASSOCIATION_TABLE_ENTRIES,
            max_com_objects: Self::MAX_COM_OBJECTS,
            pei_type: Self::PEI_TYPE,
        }
    }

    /// Build a device descriptor for the given mask version.
    ///
    /// The mask version determines the transport medium and selects the
    /// matching application ID:
    /// - `SystemBKnxIp` (0x57B0) → `APPLICATION_ID_IP` (0x0300)
    /// - `SystemBTp1` (0x07B0) → `APPLICATION_ID_TP1` (0x0301)
    /// - `SystemBRf` (0x27B0) → `APPLICATION_ID_RF` (0x0303)
    ///
    /// For the Data Secure TP1 variant see
    /// [`device_descriptor_secure_tp1`](Self::device_descriptor_secure_tp1).
    pub const fn device_descriptor(mask: MaskVersion) -> DeviceDescriptor {
        let application_id = match mask {
            MaskVersion::SystemBTp1 => Self::APPLICATION_ID_TP1,
            MaskVersion::SystemBRf => Self::APPLICATION_ID_RF,
            _ => Self::APPLICATION_ID_IP,
        };
        Self::descriptor_for(mask, application_id)
    }

    /// Build a device descriptor for the Data Secure TP1 variant.
    ///
    /// Same mask version (`SystemBTp1` / 0x07B0) as the plain TP1
    /// variant — the mask version does not distinguish secure from
    /// insecure System B — but uses
    /// [`APPLICATION_ID_TP1_SECURE`](Self::APPLICATION_ID_TP1_SECURE) so
    /// both variants coexist in the same knxprod catalogue.
    pub const fn device_descriptor_secure_tp1() -> DeviceDescriptor {
        Self::descriptor_for(MaskVersion::SystemBTp1, Self::APPLICATION_ID_TP1_SECURE)
    }

    /// Build a device descriptor for the Data Secure KNX-RF variant.
    ///
    /// Same mask version (`SystemBRf` / 0x27B0) as the plain RF variant —
    /// the mask version does not distinguish secure from insecure System
    /// B — but uses
    /// [`APPLICATION_ID_RF_SECURE`](Self::APPLICATION_ID_RF_SECURE) so
    /// both variants coexist in the same knxprod catalogue. This is the
    /// RF analogue of
    /// [`device_descriptor_secure_tp1`](Self::device_descriptor_secure_tp1);
    /// the matching firmware is not implemented yet.
    pub const fn device_descriptor_secure_rf() -> DeviceDescriptor {
        Self::descriptor_for(MaskVersion::SystemBRf, Self::APPLICATION_ID_RF_SECURE)
    }

    /// Build a device descriptor for the combined IP Secure + Data Secure
    /// KNX/IP variant.
    ///
    /// Same mask version (`SystemBKnxIp` / 0x57B0) as the plain IP variant
    /// — the mask version distinguishes neither IP Secure nor Data Secure
    /// from their insecure counterparts — but uses
    /// [`APPLICATION_ID_IP_SECURE`](Self::APPLICATION_ID_IP_SECURE) so both
    /// variants coexist in the same knxprod catalogue. Pairs with the
    /// `pico_eth_secure_light_switch` firmware.
    pub const fn device_descriptor_secure_ip() -> DeviceDescriptor {
        Self::descriptor_for(MaskVersion::SystemBKnxIp, Self::APPLICATION_ID_IP_SECURE)
    }
}

/// Device descriptor for KNX/IP (mask version 57B0).
pub const DEVICE_DESCRIPTOR_IP: DeviceDescriptor = LightSwitchDevice::device_descriptor(MaskVersion::SystemBKnxIp);

/// Device descriptor for TP-UART (mask version 07B0).
pub const DEVICE_DESCRIPTOR_TP1: DeviceDescriptor = LightSwitchDevice::device_descriptor(MaskVersion::SystemBTp1);

/// Device descriptor for KNX-RF (mask version 27B0).
pub const DEVICE_DESCRIPTOR_RF: DeviceDescriptor = LightSwitchDevice::device_descriptor(MaskVersion::SystemBRf);

/// Device descriptor for the Data Secure TP1 variant (mask version 07B0,
/// application ID 0x0302). Pairs with the `stm32g0_tp1_secure_light_switch`
/// firmware.
pub const DEVICE_DESCRIPTOR_TP1_SECURE: DeviceDescriptor = LightSwitchDevice::device_descriptor_secure_tp1();

/// Device descriptor for the Data Secure KNX-RF variant (mask version
/// 27B0, application ID 0x0304). The matching firmware does not exist
/// yet — this descriptor is the RF counterpart of
/// [`DEVICE_DESCRIPTOR_TP1_SECURE`] so the secure RF variant can already
/// be generated into the knxprod catalogue.
pub const DEVICE_DESCRIPTOR_RF_SECURE: DeviceDescriptor = LightSwitchDevice::device_descriptor_secure_rf();

/// Device descriptor for the combined IP Secure + Data Secure KNX/IP
/// variant (mask version 57B0, application ID 0x0305). Pairs with the
/// `pico_eth_secure_light_switch` firmware.
pub const DEVICE_DESCRIPTOR_IP_SECURE: DeviceDescriptor = LightSwitchDevice::device_descriptor_secure_ip();
