//! ETS Export functionality for generating KNX product definitions.
//!
//! This module provides types and traits for exporting device configuration
//! to formats compatible with ETS (Engineering Tool Software) and the KNX
//! Manufacturing Tool.
//!
//! # Overview
//!
//! To create a product definition for ETS, you need:
//!
//! 1. **Device Descriptor** - Identifies the firmware/hardware platform (compile-time)
//! 2. **Parameters** - User-configurable application parameters
//! 3. **Communication Objects** - Group objects with DPT info
//! 4. **Memory Layout** - Where tables and parameters are located
//!
//! Note: Per-device instance data (serial number, individual address) is stored
//! in runtime state, not the device descriptor.
//!
//! # Usage
//!
//! The [`DeviceDescriptor`] struct consolidates all firmware-level metadata:
//!
//! ```rust,ignore
//! use zweidraehte::ets::DeviceDescriptor;
//!
//! const DEVICE: DeviceDescriptor = DeviceDescriptor {
//!     // Hardware/firmware identification
//!     mask_version: 0x07B0,
//!     manufacturer_id: 0x00FA,
//!     hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
//!
//!     // Application identification
//!     application_id: 0xF023,
//!     application_version: 0x01,
//!
//!     // Table capacities
//!     max_address_table_entries: 64,
//!     max_association_table_entries: 64,
//!     max_com_objects: 32,
//! };
//! ```
//!
//! # Derive Macro for Parameters
//!
//! Use the `#[derive(EtsParams)]` macro to automatically generate ETS parameter
//! definitions from a struct:
//!
//! ```rust,ignore
//! use zweidraehte::ets::EtsParams;
//!
//! #[derive(EtsParams)]
//! #[repr(C)]
//! pub struct MyParams {
//!     /// Operating mode
//!     #[ets(display = "Operating Mode")]
//!     pub mode: u8,
//!
//!     /// Temperature setpoint
//!     #[ets(display = "Setpoint")]
//!     pub setpoint: u16,
//!
//!     /// Enable feature
//!     #[ets(display = "Feature Enabled")]
//!     pub enabled: bool,
//! }
//!
//! // Access generated definitions:
//! let params = MyParams::ETS_PARAMS;
//! ```

// Re-export the derive macros
pub use ets_macros::EtsParams;
pub use ets_macros::EtsUnion;
pub use ets_macros::EtsEnum;
pub use ets_macros::EtsComObjects;

/// Device descriptor containing firmware/application-level metadata.
///
/// This struct consolidates the **compile-time** information that identifies
/// the firmware/application, NOT individual device instances. This is what
/// gets exported to ETS product definitions.
///
/// # What Goes Here vs. Runtime State
///
/// **DeviceDescriptor (compile-time, per-firmware):**
/// - Mask version, manufacturer ID, hardware type
/// - Application program ID and version
/// - Table capacities (max sizes)
///
/// **Runtime State (per-device instance):**
/// - Serial number (factory-programmed, unique per device)
/// - Individual address (ETS-configured)
/// - Device name/description (ETS-configured)
///
/// # Fields
///
/// ## Hardware/Firmware Identification
/// - `mask_version`: Device Descriptor Type 0 (e.g., 0x07B0 for System B TP1)
/// - `manufacturer_id`: KNX manufacturer ID (assigned by KNX Association)
/// - `hardware_type`: 6-byte hardware type identifier
///
/// ## Application Program
/// - `application_id`: Application program identifier (2 bytes)
/// - `application_version`: Application program version (1 byte)
///
/// ## Table Capacities
/// - `max_address_table_entries`: Maximum group addresses
/// - `max_association_table_entries`: Maximum associations
/// - `max_com_objects`: Maximum communication objects
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceDescriptor {
    // ========================================================================
    // Hardware/Firmware Identification
    // ========================================================================
    /// Device Descriptor Type 0 / Mask Version.
    ///
    /// Common values:
    /// - `0x07B0` - System B TP1 device
    /// - `0x27B0` - System B TP1 device with extended frames
    /// - `0x57B0` - System B KNX/IP device
    pub mask_version: u16,

    /// KNX Manufacturer ID.
    ///
    /// Assigned by the KNX Association. This identifies who made the firmware.
    /// Note: This is also used as the first 2 bytes of any device's serial number.
    pub manufacturer_id: u16,

    /// Hardware type identifier (6 bytes).
    ///
    /// Identifies the hardware platform/revision.
    pub hardware_type: [u8; 6],

    // ========================================================================
    // Application Program Identification
    // ========================================================================
    /// Application program identifier (2 bytes).
    ///
    /// Together with manufacturer_id and application_version, this uniquely
    /// identifies the application program in ETS.
    pub application_id: u16,

    /// Application program version (1 byte).
    ///
    /// Incremented when the application program changes.
    pub application_version: u8,

    // ========================================================================
    // Table Capacities
    // ========================================================================
    /// Maximum number of entries in the address table.
    ///
    /// This determines how many group addresses the device can handle.
    pub max_address_table_entries: u16,

    /// Maximum number of entries in the association table.
    ///
    /// This determines how many group address to communication object
    /// mappings the device supports.
    pub max_association_table_entries: u16,

    /// Maximum number of communication objects.
    ///
    /// This should match the number of objects defined in the application.
    pub max_com_objects: u16,
}

impl DeviceDescriptor {
    /// Create a new device descriptor with the given values.
    pub const fn new(
        mask_version: u16,
        manufacturer_id: u16,
        hardware_type: [u8; 6],
        application_id: u16,
        application_version: u8,
        max_address_table_entries: u16,
        max_association_table_entries: u16,
        max_com_objects: u16,
    ) -> Self {
        Self {
            mask_version,
            manufacturer_id,
            hardware_type,
            application_id,
            application_version,
            max_address_table_entries,
            max_association_table_entries,
            max_com_objects,
        }
    }

    /// Get the program version bytes (5 bytes).
    ///
    /// Format: 2 bytes manufacturer + 2 bytes app ID + 1 byte version.
    /// This matches the PID_PROGRAM_VERSION property format.
    pub const fn program_version(&self) -> [u8; 5] {
        [
            (self.manufacturer_id >> 8) as u8,
            self.manufacturer_id as u8,
            (self.application_id >> 8) as u8,
            self.application_id as u8,
            self.application_version,
        ]
    }

    /// Get the PEI program version bytes (5 bytes).
    ///
    /// For devices without a separate PEI application, this returns a default
    /// version [0x00, 0x00, 0x00, 0x00, 0x00].
    /// The PEI Program Object (Interface Object 5) reports this as PID_PROGRAM_VERSION.
    pub const fn pei_program_version(&self) -> [u8; 5] {
        [0x00, 0x00, 0x00, 0x00, 0x00]
    }

    /// Get the mask version as bytes (big-endian).
    pub const fn mask_version_bytes(&self) -> [u8; 2] {
        [(self.mask_version >> 8) as u8, self.mask_version as u8]
    }

    /// Check if this is a KNX/IP device (mask version 57B0).
    pub const fn is_knxip(&self) -> bool {
        self.mask_version == 0x57B0
    }

    /// Check if this is a TP1 device (mask version 07B0 or 27B0).
    pub const fn is_tp1(&self) -> bool {
        self.mask_version == 0x07B0 || self.mask_version == 0x27B0
    }

    /// Get the address table size in bytes.
    ///
    /// Format: 2-byte count + 2 bytes per entry.
    pub const fn address_table_size(&self) -> usize {
        2 + (self.max_address_table_entries as usize) * 2
    }

    /// Get the association table size in bytes.
    ///
    /// Format: 2-byte count + 4 bytes per entry (for System B).
    pub const fn association_table_size(&self) -> usize {
        2 + (self.max_association_table_entries as usize) * 4
    }

    /// Get the communication object table size in bytes.
    ///
    /// Format: 2-byte count + 2 bytes per entry.
    pub const fn comm_object_table_size(&self) -> usize {
        2 + (self.max_com_objects as usize) * 2
    }
}

// ============================================================================
// ETS Parameter Type
// ============================================================================

/// Parameter type for ETS export.
///
/// These correspond to the parameter type codes used in the ETS export:
/// - `UI` = Unsigned Integer
/// - `SI` = Signed Integer
/// - `EN` = Enumeration
/// - `ST` = String
/// - `NO` = None (raw bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EtsParamType {
    /// Unsigned integer (UI)
    UnsignedInt,
    /// Signed integer (SI)
    SignedInt,
    /// Enumeration (EN)
    Enum,
    /// String (ST)
    String,
    /// Raw bytes, no specific type (NO)
    None,
}

impl EtsParamType {
    /// Get the two-character code used in symbol names.
    pub const fn code(&self) -> &'static str {
        match self {
            EtsParamType::UnsignedInt => "UI",
            EtsParamType::SignedInt => "SI",
            EtsParamType::Enum => "EN",
            EtsParamType::String => "ST",
            EtsParamType::None => "NO",
        }
    }
}

// ============================================================================
// ETS Parameter Definition
// ============================================================================

/// Definition of a parameter for ETS export.
///
/// Contains all the metadata needed to export a parameter to ETS format.
#[derive(Debug, Clone, Copy)]
pub struct EtsParamDef {
    /// Parameter name (for symbol generation)
    pub name: &'static str,

    /// Human-readable display name
    pub display_name: &'static str,

    /// Offset in the parameter block (bytes)
    pub offset: u16,

    /// Size in bits
    pub size_bits: u8,

    /// Bit offset within the byte (0-7)
    pub bit_offset: u8,

    /// Parameter type
    pub param_type: EtsParamType,
}

// ============================================================================
// ETS Enum Variant Definition
// ============================================================================

/// Definition of an enum variant for ETS export.
///
/// Used for parameters that have a fixed set of named values.
#[derive(Debug, Clone, Copy)]
pub struct EtsEnumVariant {
    /// Display text for this variant
    pub text: &'static str,
    /// Numeric value for this variant
    pub value: i64,
}

// ============================================================================
// ETS Extended Parameter Definition
// ============================================================================

/// Extended parameter definition with enum variants.
///
/// This provides additional metadata beyond [`EtsParamDef`], specifically
/// enum variants for parameters of type [`EtsParamType::Enum`].
#[derive(Debug, Clone, Copy)]
pub struct EtsParamDefExt {
    /// Base parameter definition
    pub base: EtsParamDef,
    /// Enum variants (if this is an enum parameter)
    pub enum_variants: Option<&'static [EtsEnumVariant]>,
}

// ============================================================================
// ETS Union Definitions
// ============================================================================

/// Definition of a union parameter for ETS export.
///
/// A union parameter within an ETS union definition.
#[derive(Debug, Clone, Copy)]
pub struct EtsUnionParamDef {
    /// Parameter definition
    pub param: EtsParamDef,
    /// Enum variants (if this is an enum parameter)
    pub enum_variants: Option<&'static [EtsEnumVariant]>,
}

/// Definition of a union for ETS export (legacy/manual definition).
///
/// Unions allow multiple parameters to share the same memory location,
/// with a selector parameter determining which interpretation is active.
///
/// For derive-based unions, see [`EtsUnionInfo`] and [`EtsUnionType`].
#[derive(Debug, Clone, Copy)]
pub struct EtsUnionDef {
    /// Name of the union
    pub name: &'static str,
    /// Byte offset in parameter block where this union starts
    pub offset: u16,
    /// Size of the union in bytes
    pub size: u16,
    /// Name of the parameter that selects which union member is active
    pub selector_param: &'static str,
    /// The parameters that make up this union
    pub params: &'static [EtsUnionParamDef],
}

// ============================================================================
// ETS Union Types for Derive Macro
// ============================================================================

/// A parameter within a specific enum variant of a union.
///
/// Generated by `#[derive(EtsUnion)]` for each field in enum variants.
#[derive(Debug, Clone, Copy)]
pub struct EtsUnionVariantParam {
    /// Name of the variant this parameter belongs to
    pub variant_name: &'static str,
    /// Discriminant value for this variant
    pub variant_value: i64,
    /// The parameter definition (offset is relative to union data area)
    pub param: EtsParamDef,
    /// Optional enum variants for this parameter (for dropdown selection in ETS)
    pub enum_variants: Option<&'static [EtsEnumVariant]>,
}

/// Union information generated by `#[derive(EtsUnion)]`.
///
/// This captures the complete structure of a Rust `#[repr(C, u8)]` enum
/// for ETS export. The memory layout is:
/// - Byte 0: discriminant (selector)
/// - Bytes 1..data_offset-1: padding (for alignment)
/// - Bytes data_offset..N: variant data (largest variant size)
#[derive(Debug, Clone, Copy)]
pub struct EtsUnionInfo {
    /// Name of the enum type
    pub name: &'static str,
    /// Total size in bytes (1 byte discriminant + padding + max variant size)
    pub total_size: u16,
    /// Offset where variant data begins (after discriminant + alignment padding).
    /// In `#[repr(C, u8)]`, this is the alignment of the largest-aligned field
    /// across all variants (since the discriminant is 1 byte).
    pub data_offset: u16,
    /// Size of the data area in bytes (excluding discriminant and padding)
    pub data_size: u16,
    /// Number of variants
    pub variant_count: usize,
    /// Parameters for each variant's fields.
    /// Offsets are relative to the start of the variant data area (i.e., relative to data_offset).
    pub variant_params: &'static [EtsUnionVariantParam],
}

/// Marker trait for enums that can be exported as ETS unions.
///
/// Automatically implemented by `#[derive(EtsUnion)]`.
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte::ets::{EtsUnion, EtsUnionType};
///
/// #[derive(EtsUnion)]
/// #[repr(C, u8)]
/// pub enum MyUnion {
///     Off,
///     On { value: u16 },
/// }
///
/// // Now you can access:
/// let info = MyUnion::ets_union_info();
/// let variants = MyUnion::ets_selector_variants();
/// ```
pub trait EtsUnionType {
    /// Get the union information for this type.
    fn ets_union_info() -> &'static EtsUnionInfo;

    /// Get the selector variants (display names for discriminant values).
    fn ets_selector_variants() -> &'static [EtsEnumVariant];
}

/// Marker trait for simple enums (no data) that can be used as ETS parameters.
///
/// Automatically implemented by `#[derive(EtsEnum)]`. This is for simple `#[repr(u8)]`
/// enums without data fields - they become dropdown parameters in ETS.
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte::ets::{EtsEnum, EtsEnumType};
///
/// #[derive(EtsEnum)]
/// #[repr(u8)]
/// pub enum SensorType {
///     #[ets(display = "PT100")]
///     Pt100 = 0,
///     #[ets(display = "PT1000")]
///     Pt1000 = 1,
///     #[ets(display = "NTC 10K")]
///     Ntc10K = 2,
/// }
///
/// // Now you can use it in EtsUnion or EtsParams:
/// #[derive(EtsParams)]
/// struct Params {
///     sensor_type: SensorType,  // Automatically gets dropdown in ETS
/// }
/// ```
pub trait EtsEnumType {
    /// Get the enum variants for ETS dropdown display.
    fn ets_variants() -> &'static [EtsEnumVariant];

    /// Get the size in bytes of this enum (typically 1 for `#[repr(u8)]`).
    fn ets_size_bytes() -> usize;
}

/// Information about a union field within a parameter struct.
///
/// Generated by `#[derive(EtsParams)]` when a field is marked with `#[ets(union)]`.
/// This connects the union type to its position in the parameter block.
#[derive(Debug, Clone, Copy)]
pub struct EtsUnionFieldInfo {
    /// Name of the field in the parent struct
    pub field_name: &'static str,
    /// Byte offset in the parameter block where this union starts
    pub offset: u16,
    /// Reference to the union's metadata
    pub union_info: &'static EtsUnionInfo,
    /// Reference to the selector variants
    pub selector_variants: &'static [EtsEnumVariant],
}

// ============================================================================
// ETS Communication Object Definition
// ============================================================================

/// Definition of a communication object for ETS export.
///
/// Contains all the metadata needed to export a communication object to ETS format.
#[derive(Debug, Clone, Copy)]
pub struct EtsCommObjectDef {
    /// Object index (ASAP number)
    pub index: u16,

    /// Object name (for symbol generation)
    pub name: &'static str,

    /// Human-readable display name shown in ETS
    pub display_name: &'static str,

    /// Optional description/function text
    pub function_text: &'static str,

    /// DPT main type number (e.g., 1 for DPT 1.xxx)
    pub dpt_main: u16,

    /// DPT subtype number (e.g., 1 for DPT 1.001)
    pub dpt_sub: u16,

    /// Object size in bits (for KNX object size type calculation).
    ///
    /// Common values:
    /// - 1 = 1 bit (DPT 1.x)
    /// - 2 = 2 bits (DPT 2.x)
    /// - 4 = 4 bits (DPT 3.x)
    /// - 8 = 1 byte (DPT 4.x, 5.x, 6.x)
    /// - 16 = 2 bytes (DPT 7.x, 8.x, 9.x)
    /// - etc.
    pub size_bits: u8,

    /// Default flags (CE, WE, RE, TE, UE, ROI)
    pub default_flags: u8,
}

// ============================================================================
// ETS Communication Object Reference Definition
// ============================================================================

/// Definition of a communication object reference for ETS export.
///
/// A ComObjectRef references a base ComObject and can override certain properties
/// like display text, function text, datapoint type, size, and flags. This allows
/// a single physical group object to be presented in ETS with different
/// configurations depending on parameter settings.
///
/// In the ETS XML, ComObjectRefs only include attributes that differ from the
/// base ComObject - unchanged attributes are inherited.
#[derive(Debug, Clone, Copy)]
pub struct EtsCommObjectRefDef {
    /// Reference to the base ComObject index
    pub object_index: u16,

    /// Unique ref name (for code generation and XML ID)
    pub ref_name: &'static str,

    /// Display text override for ETS (can use `{{param:default}}` syntax).
    /// `None` = inherit from base ComObject
    pub text: Option<&'static str>,

    /// Function text for this ref
    pub function_text: &'static str,

    /// DPT main type number for this ref
    pub dpt_main: u16,

    /// DPT subtype number for this ref
    pub dpt_sub: u16,

    /// Size in bits for this ref
    pub size_bits: u8,

    /// Flag overrides - only flags that differ from base object.
    /// `None` = use all base flags
    pub flag_overrides: Option<FlagOverrides>,

    /// Selector value that activates this ref (for choose/when XML generation).
    /// `None` = no selector (always visible), `Some(value)` = show when selector equals value
    pub selector_value: Option<i64>,

    /// Name of the parameter that selects which ref is active.
    /// This is used to generate the ParamRefId in the choose/when XML structure.
    /// `None` = no selector parameter (unconditional visibility)
    pub selector_param: Option<&'static str>,
}

/// Individual flag overrides for a ComObjectRef.
///
/// Only flags that differ from the base ComObject need to be set.
/// `None` = inherit from base, `Some(value)` = override.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlagOverrides {
    /// Read flag (RE) override
    pub read: Option<bool>,
    /// Write flag (WE) override
    pub write: Option<bool>,
    /// Communication flag (CE) override
    pub communication: Option<bool>,
    /// Transmit flag (TE) override
    pub transmit: Option<bool>,
    /// Update flag (UE) override
    pub update: Option<bool>,
    /// Read-on-init flag (ROI) override
    pub read_on_init: Option<bool>,
}

impl FlagOverrides {
    /// Create a new FlagOverrides with all fields set to None (inherit all).
    pub const fn new() -> Self {
        Self {
            read: None,
            write: None,
            communication: None,
            transmit: None,
            update: None,
            read_on_init: None,
        }
    }

    /// Check if any flags are overridden.
    pub const fn has_overrides(&self) -> bool {
        self.read.is_some()
            || self.write.is_some()
            || self.communication.is_some()
            || self.transmit.is_some()
            || self.update.is_some()
            || self.read_on_init.is_some()
    }
}

// ============================================================================
// Traits for ETS Export
// ============================================================================

/// Trait for types that can provide ETS export metadata.
///
/// Implement this trait on your stack definition or device type to enable
/// ETS export functionality.
pub trait EtsExportable {
    /// Get the device descriptor containing hardware and application info.
    fn device_descriptor() -> &'static DeviceDescriptor;

    /// Get the list of parameter definitions.
    ///
    /// Returns an empty slice if no parameters are defined.
    fn parameters() -> &'static [EtsParamDef] {
        &[]
    }

    /// Get the list of communication object definitions.
    ///
    /// Returns an empty slice if no communication objects are defined.
    fn comm_objects() -> &'static [EtsCommObjectDef] {
        &[]
    }
}

// ============================================================================
// Helper trait for extracting DPT info from DatapointType
// ============================================================================

/// Trait for types that carry DPT information.
///
/// This is implemented for [`DatapointType`](crate::dpt::DatapointType) to allow
/// extracting DPT main/sub numbers at compile time.
pub trait HasDptInfo {
    /// DPT main type number
    const DPT_MAIN: u16;
    /// DPT subtype number
    const DPT_SUB: u16;
    /// Size in bits (for KNX object size calculation).
    ///
    /// This is the actual datapoint size, not the backing storage size.
    /// For example, DPT 1.x (Switch) is 1 bit, DPT 2.x is 2 bits, etc.
    const SIZE_BITS: usize;
}
