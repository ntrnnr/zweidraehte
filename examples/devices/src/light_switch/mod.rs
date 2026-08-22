//! 2-Button Light Switch Device Definition
//!
//! A wall switch with two momentary buttons, supporting 1-function
//! (rocker pair) and 2-function (independent buttons) operating modes.
//! Each button/pair is configurable for switching, dimming, blind
//! control, or scene selection.
//!
//! This module contains the transport-agnostic device definition:
//! parameters, communication objects, ETS page layout, and shared behavior.
//! `full` adapts those pieces to the composable stack while each firmware
//! owns its `StackDefinition`; `micro` supplies the baked family definitions
//! and polling adapter needed by BCU-era targets.
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

#[cfg(any(feature = "full", feature = "micro"))]
mod behavior;
pub mod comm_objs;
#[cfg(feature = "full")]
pub mod full;
pub mod params;

#[cfg(feature = "micro")]
pub mod micro;

#[cfg(feature = "knxprod")]
mod layout;
#[cfg(feature = "knxprod")]
pub mod translations;

pub use params::*;

use zweidraehte_proto::device::{DeviceDescriptor, MaskVersion};

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

    // Hardware types, one per hardware entry in the knxprod catalogue.
    //
    // The value in `PID_HARDWARE_TYPE` (PID 78) and the knxprod
    // Hardware's serial number are the same identifier: ETS's System 7
    // `ProductProcedure` opens with an `LdCtrlCompareProp` on PID 78
    // against the hardware serial and refuses the download on a
    // mismatch. The System B load procedures never check it, but the
    // property still identifies the hardware, so every variant reports
    // the serial its catalogue entry publishes. The generator
    // (`gen_light_switch_mtxml`) consumes these constants for its
    // `HardwareDef`s, keeping the two sides one value by construction.

    /// Hardware type / knxprod hardware serial for the KNX/IP variant.
    pub const HARDWARE_TYPE_IP: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x03];
    /// Hardware type / knxprod hardware serial for the TP1 variant.
    pub const HARDWARE_TYPE_TP1: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x04];
    /// Hardware type / knxprod hardware serial for the Data Secure TP1
    /// variant.
    pub const HARDWARE_TYPE_TP1_SECURE: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x05];
    /// Hardware type / knxprod hardware serial for the KNX-RF variant.
    pub const HARDWARE_TYPE_RF: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x06];
    /// Hardware type / knxprod hardware serial for the Data Secure
    /// KNX-RF handheld variant.
    pub const HARDWARE_TYPE_RF_SECURE: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x07];
    /// Hardware type / knxprod hardware serial for the Data Secure
    /// KNX-RF retransmitter — distinct hardware running the same
    /// RF-secure application as the handheld.
    pub const HARDWARE_TYPE_RF_SECURE_RETRANSMITTER: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x08];
    /// Hardware type / knxprod hardware serial for the IP Secure + Data
    /// Secure KNX/IP variant.
    pub const HARDWARE_TYPE_IP_SECURE: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x09];
    /// Hardware type / knxprod hardware serial for the System 7 TP1
    /// variant. This is the one the download actually verifies today.
    pub const HARDWARE_TYPE_TP1_SYSTEM7: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x0A];
    /// Hardware type / knxprod hardware serial for the Data Secure
    /// System 7 TP1 variant.
    pub const HARDWARE_TYPE_TP1_SYSTEM7_SECURE: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x0B];
    /// Hardware type / knxprod hardware serial for the BCU2 (mask
    /// 0020h) TP1 variant on the microdevice stack. The micro System 7
    /// variant needs no entry of its own: it presents itself as the
    /// [`HARDWARE_TYPE_TP1_SYSTEM7`](Self::HARDWARE_TYPE_TP1_SYSTEM7)
    /// product, one `.knxprod` driving either firmware.
    pub const HARDWARE_TYPE_TP1_BCU2: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x0C];
    /// Hardware type / knxprod hardware serial for the Data Secure BCU2
    /// (mask 0021h) variant on the microdevice stack.
    pub const HARDWARE_TYPE_TP1_BCU2_SECURE: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x0D];
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
    /// Application ID for the System 7 TP1 variant (mask `System7Tp1` /
    /// 0x0705). Unlike the secure variants this IS a distinct mask —
    /// the BCU family changes, not just a capability flag — so ETS
    /// programs it through the `ProductProcedure` load procedures with
    /// absolute memory segments instead of System B's relative model.
    pub const APPLICATION_ID_TP1_SYSTEM7: u16 = 0x0306;
    /// Application ID for the Data Secure System 7 TP1 variant. Same
    /// mask as the plain System 7 variant (`System7Tp1` / 0x0705) —
    /// KNX Data Security is a *profile module* (06 Profiles v02.02.01
    /// §9.1) composed onto a base profile, never a mask of its own —
    /// but a different application ID so both coexist in one catalogue,
    /// exactly as the System B pair does.
    pub const APPLICATION_ID_TP1_SYSTEM7_SECURE: u16 = 0x0307;
    /// Application ID for the BCU2 (mask 0020h) TP1 variant on the
    /// microdevice stack — a distinct mask, like the System 7 variant.
    /// The micro System 7 firmware reuses
    /// [`APPLICATION_ID_TP1_SYSTEM7`](Self::APPLICATION_ID_TP1_SYSTEM7):
    /// same mask, same product, alternative implementation.
    pub const APPLICATION_ID_TP1_BCU2: u16 = 0x0308;
    /// Application ID for the Data Secure BCU2 (mask 0021h) variant.
    pub const APPLICATION_ID_TP1_BCU2_SECURE: u16 = 0x0309;
    pub const APPLICATION_VERSION: u8 = 0x02;
    pub const MAX_ADDRESS_TABLE_ENTRIES: u16 = 10;
    pub const MAX_ASSOCIATION_TABLE_ENTRIES: u16 = 12;
    pub const MAX_COM_OBJECTS: u16 = 6;
    pub const PEI_TYPE: u8 = 0;

    /// Build a descriptor from the only three fields that vary between
    /// this device's variants; the remaining six are identical
    /// everywhere.
    const fn descriptor_for(mask: MaskVersion, application_id: u16, hardware_type: [u8; 6]) -> DeviceDescriptor {
        DeviceDescriptor {
            mask_version: mask,
            manufacturer_id: Self::MANUFACTURER_ID,
            hardware_type,
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
        let (application_id, hardware_type) = match mask {
            MaskVersion::SystemBTp1 => (Self::APPLICATION_ID_TP1, Self::HARDWARE_TYPE_TP1),
            MaskVersion::SystemBRf => (Self::APPLICATION_ID_RF, Self::HARDWARE_TYPE_RF),
            _ => (Self::APPLICATION_ID_IP, Self::HARDWARE_TYPE_IP),
        };
        Self::descriptor_for(mask, application_id, hardware_type)
    }

    /// Build a device descriptor for the Data Secure TP1 variant.
    ///
    /// Same mask version (`SystemBTp1` / 0x07B0) as the plain TP1
    /// variant — the mask version does not distinguish secure from
    /// insecure System B — but uses
    /// [`APPLICATION_ID_TP1_SECURE`](Self::APPLICATION_ID_TP1_SECURE) so
    /// both variants coexist in the same knxprod catalogue.
    pub const fn device_descriptor_secure_tp1() -> DeviceDescriptor {
        Self::descriptor_for(MaskVersion::SystemBTp1, Self::APPLICATION_ID_TP1_SECURE, Self::HARDWARE_TYPE_TP1_SECURE)
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
        Self::descriptor_for(MaskVersion::SystemBRf, Self::APPLICATION_ID_RF_SECURE, Self::HARDWARE_TYPE_RF_SECURE)
    }

    /// Build a device descriptor for the Data Secure KNX-RF
    /// retransmitter.
    ///
    /// Same mask and application as
    /// [`device_descriptor_secure_rf`](Self::device_descriptor_secure_rf)
    /// — the retransmitter runs the RF-secure application — but it is a
    /// different hardware entry in the catalogue, so it reports its own
    /// hardware type.
    pub const fn device_descriptor_secure_rf_retransmitter() -> DeviceDescriptor {
        Self::descriptor_for(
            MaskVersion::SystemBRf,
            Self::APPLICATION_ID_RF_SECURE,
            Self::HARDWARE_TYPE_RF_SECURE_RETRANSMITTER,
        )
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
        Self::descriptor_for(MaskVersion::SystemBKnxIp, Self::APPLICATION_ID_IP_SECURE, Self::HARDWARE_TYPE_IP_SECURE)
    }

    /// Build a device descriptor for the System 7 TP1 variant
    /// (mask `System7Tp1` / 0x0705).
    ///
    /// Same application logic and table capacities as the System B TP1
    /// variant; only the BCU family — and with it the download model
    /// (RT8 tables at absolute addresses, `ProductProcedure` load
    /// procedures, 16 access levels) — differs.
    pub const fn device_descriptor_system7_tp1() -> DeviceDescriptor {
        Self::descriptor_for(MaskVersion::System7Tp1, Self::APPLICATION_ID_TP1_SYSTEM7, Self::HARDWARE_TYPE_TP1_SYSTEM7)
    }

    /// Descriptor for the Data Secure System 7 TP1 variant.
    ///
    /// The System 7 download model of
    /// [`device_descriptor_system7_tp1`](Self::device_descriptor_system7_tp1)
    /// with KNX Data Security composed on: the mask is unchanged,
    /// because the security profile module adds interface objects and
    /// services rather than a BCU family.
    pub const fn device_descriptor_system7_secure_tp1() -> DeviceDescriptor {
        Self::descriptor_for(
            MaskVersion::System7Tp1,
            Self::APPLICATION_ID_TP1_SYSTEM7_SECURE,
            Self::HARDWARE_TYPE_TP1_SYSTEM7_SECURE,
        )
    }

    /// Build a device descriptor for the BCU2 TP1 variant (mask 0020h,
    /// the microdevice stack).
    ///
    /// Same application logic and table capacities again; the download
    /// model is the BCU-era one — RT2 tables behind one-byte pointer
    /// cells in the 0100h EEPROM page, the mask template's
    /// `DefaultProcedure`, memory-mapped everything.
    pub const fn device_descriptor_bcu2_tp1() -> DeviceDescriptor {
        Self::descriptor_for(MaskVersion::Other(0x0020), Self::APPLICATION_ID_TP1_BCU2, Self::HARDWARE_TYPE_TP1_BCU2)
    }

    /// Build a descriptor for the evidence-backed Data Secure BCU2 profile.
    ///
    /// Unlike System B, the BCU2 sibling mask is observable: secure firmware
    /// reports 0021h and the plain firmware reports 0020h.
    pub const fn device_descriptor_bcu2_secure_tp1() -> DeviceDescriptor {
        Self::descriptor_for(
            MaskVersion::Bcu2Tp1,
            Self::APPLICATION_ID_TP1_BCU2_SECURE,
            Self::HARDWARE_TYPE_TP1_BCU2_SECURE,
        )
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

/// Device descriptor for the Data Secure KNX-RF retransmitter — the
/// same RF-secure application on its own hardware entry. Pairs with the
/// `stm32g0_knxrf_secure_retransmitter` firmware.
pub const DEVICE_DESCRIPTOR_RF_SECURE_RETRANSMITTER: DeviceDescriptor =
    LightSwitchDevice::device_descriptor_secure_rf_retransmitter();

/// Device descriptor for the combined IP Secure + Data Secure KNX/IP
/// variant (mask version 57B0, application ID 0x0305). Pairs with the
/// `pico_eth_secure_light_switch` firmware.
pub const DEVICE_DESCRIPTOR_IP_SECURE: DeviceDescriptor = LightSwitchDevice::device_descriptor_secure_ip();

/// Device descriptor for the System 7 TP1 variant (mask version 0705,
/// application ID 0x0306). Pairs with the
/// `stm32g0_tp1_system7_light_switch` firmware; the same descriptor
/// also drives the family's `ProductProcedure` generator path in
/// `gen_light_switch_mtxml`.
pub const DEVICE_DESCRIPTOR_TP1_SYSTEM7: DeviceDescriptor = LightSwitchDevice::device_descriptor_system7_tp1();

/// Device descriptor for the Data Secure System 7 TP1 variant (mask
/// version 0705, application ID 0x0307). Pairs with the
/// `stm32g0_tp1_system7_secure_light_switch` firmware.
pub const DEVICE_DESCRIPTOR_TP1_SYSTEM7_SECURE: DeviceDescriptor =
    LightSwitchDevice::device_descriptor_system7_secure_tp1();

/// Device descriptor for the BCU2 TP1 variant (mask version 0020,
/// application ID 0x0308). Pairs with the
/// `stm32g0_tp1_bcu2_light_switch` firmware on the microdevice stack.
pub const DEVICE_DESCRIPTOR_TP1_BCU2: DeviceDescriptor = LightSwitchDevice::device_descriptor_bcu2_tp1();

/// Device descriptor for the Data Secure BCU2 TP1 variant (mask version
/// 0021, application ID 0x0309). Pairs with the polling
/// `stm32g0_tp1_bcu2_secure_light_switch` firmware.
pub const DEVICE_DESCRIPTOR_TP1_BCU2_SECURE: DeviceDescriptor = LightSwitchDevice::device_descriptor_bcu2_secure_tp1();
