//! The ETS data model: the metadata vocabulary describing a device's
//! parameters, communication objects and translations for product
//! generation — and the single front door to the `zweidraehte-ets`
//! proc macros that emit it.
//!
//! This crate is deliberately light: it depends on `zweidraehte-proto`
//! only, so device definitions, the product generator
//! (`zweidraehte-knxprod`) and firmware can carry the metadata without
//! dragging the device stack (or its executor) into their dependency
//! graphs. The device *runtime* types the `EtsComObjects` derive also
//! wires up live in `zweidraehte-device` — a struct deriving it needs
//! that crate; everything else here stands alone.
//!
//! # Defining parameters
//!
//! ```rust,ignore
//! use zweidraehte_ets_model::{ets_params, ets_union, EtsEnum};
//!
//! #[ets_params]
//! pub struct MyParams {
//!     /// Operating mode
//!     #[ets(display = "Operating Mode")]
//!     pub mode: u8,
//!
//!     /// Temperature setpoint
//!     #[ets(display = "Setpoint")]
//!     pub setpoint: u16,
//! }
//!
//! // Access the generated definitions:
//! let params = MyParams::ETS_PARAMS_EXT;
//! ```
//!
//! Device identification (`DeviceDescriptor`, `MaskVersion`) is
//! protocol vocabulary and lives in `zweidraehte_proto::device`.

#![no_std]

// The proc macros, re-exported so a definition author depends on one
// crate: the macros emit paths into this crate's types.
pub use zweidraehte_ets::EtsEnum;
pub use zweidraehte_ets::ets_com_objects;
pub use zweidraehte_ets::ets_range_enum;
pub use zweidraehte_ets::{ets_params, ets_union};

// ============================================================================
// `#[ets(no_memory)]` — rejected combinations
// ============================================================================
//
// A tool-only parameter is one ETS displays and stores in the project but never
// downloads. Each of the four items below pins one combination that cannot
// mean anything, so the diagnostic lands on the attribute instead of on
// whatever the generator would have produced from it.

/// Compile-fail proof that `#[ets(no_memory)]` is rejected on a `union` field.
///
/// A union always occupies device memory — its discriminant selects which
/// variant's bytes are live — so there is no coherent reading of a union that
/// is never downloaded.
///
/// ```compile_fail
/// use serde::{Deserialize, Serialize};
/// use zweidraehte_ets_model::{ets_params, ets_union};
///
/// #[ets_union]
/// #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
/// pub enum Choice {
///     #[ets(display = "a")]
///     A { #[ets(display = "v")] v: u8 },
///     #[ets(display = "b")]
///     B { #[ets(display = "w")] w: u8 },
/// }
///
/// #[ets_params]
/// #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
/// pub struct Params {
///     // `union` + `no_memory` — must not compile.
///     #[ets(display = "Choice", union, no_memory)]
///     pub choice: Choice,
/// }
/// ```
#[allow(dead_code)]
struct NoMemoryOnUnionIsRejected;

/// Compile-fail proof that `#[ets(no_memory)]` is rejected alongside `skip`.
///
/// `skip` emits no ETS parameter at all while `no_memory` emits one without
/// device memory, so asking for both says nothing coherent.
///
/// ```compile_fail
/// use serde::{Deserialize, Serialize};
/// use zweidraehte_ets_model::ets_params;
///
/// #[ets_params]
/// #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
/// pub struct Params {
///     // `skip` + `no_memory` — must not compile.
///     #[ets(no_memory, skip)]
///     pub filler: u8,
/// }
/// ```
#[allow(dead_code)]
struct NoMemoryWithSkipIsRejected;

/// Compile-fail proof that `#[ets(no_memory)]` is rejected on a `module` field.
///
/// Module instances are stored per channel and occupy device memory, so they
/// cannot be tool-only.
///
/// ```compile_fail
/// use serde::{Deserialize, Serialize};
/// use zweidraehte_ets_model::ets_params;
///
/// #[ets_params]
/// #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
/// pub struct Params {
///     // `module` + `no_memory` — must not compile.
///     #[ets(no_memory, module = u8)]
///     pub channels: [u8; 2],
/// }
/// ```
#[allow(dead_code)]
struct NoMemoryOnModuleIsRejected;

/// Compile-fail proof that a tool-only parameter using inline `enum_variants`
/// must state its default explicitly.
///
/// A tool-only parameter contributes no bytes to the defaults blob and carries
/// offset 0, so without `#[ets(default = N)]` the generator would read the
/// first byte of an unrelated parameter. `ets_enum` fields are exempt — their
/// default comes from the type's `ConstDefault` — which is why this proof uses
/// inline variants.
///
/// ```compile_fail
/// use serde::{Deserialize, Serialize};
/// use zweidraehte_ets_model::ets_params;
///
/// #[ets_params]
/// #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
/// pub struct Params {
///     // Inline variants + `no_memory` and no `default` — must not compile.
///     #[ets(display = "Mode", no_memory, enum_variants("Off" => 0, "On" => 1))]
///     pub mode: u8,
/// }
/// ```
#[allow(dead_code)]
struct NoMemoryEnumVariantsNeedsDefault;

// ============================================================================
// ETS Parameter Type
// ============================================================================

/// Parameter type for ETS export.
///
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
    /// String/Text (ST) - can have a pattern for validation/special types
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

    /// Suffix text displayed after the parameter value (e.g., "s" for seconds)
    pub suffix: Option<&'static str>,

    /// Offset in device memory (bytes), which equals the offset in the
    /// Rust parameter struct — virtual (`no_memory`) parameters are not
    /// part of the struct and use 0.
    pub offset: u16,

    /// Size in bits.
    ///
    /// Wider than the byte a bit count would suggest because text parameters
    /// are sized in bits too: KNX master data ships `String_40Byte` (320 bits)
    /// and vendors use it — the MDT Push Button Lite gives its eight logic
    /// description fields that type — so a `u8` would cap parameters at 31
    /// characters and make those products inexpressible.
    pub size_bits: u16,

    /// Bit offset within the byte (0-7)
    pub bit_offset: u8,

    /// Parameter type
    pub param_type: EtsParamType,

    /// Whether this parameter is hidden (Access="None" in ETS)
    pub hidden: bool,

    /// Whether this parameter has no memory location (virtual/ETS-only parameter).
    /// Virtual parameters exist only in ETS for text substitution (e.g., `{{0}}` templates)
    /// and are not stored in device memory. They will not have a `<Memory>` element
    /// in the generated XML.
    pub no_memory: bool,

    /// Override for the ParameterType name in ETS export (optional)
    /// If None, a name is auto-generated based on param_type and size
    pub type_name: Option<&'static str>,

    /// Pattern for TypeText parameters (e.g., color patterns).
    /// Format: regex pattern with optional comment (e.g., "^#[0-9a-fA-F]{6}$(?# TypeColor:RGB)")
    pub text_pattern: Option<&'static str>,
}

// ============================================================================
// ETS Enum Variant Definition
// ============================================================================

/// Definition of an enum variant for ETS export.
///
/// Used for parameters that have a fixed set of named values.
#[derive(Debug, Clone, Copy)]
pub struct EtsEnumVariant {
    /// Display text for this variant (shown in ETS dropdown)
    pub text: &'static str,
    /// Rust variant name (e.g., `"TwoFunction"` for `ButtonsMode::TwoFunction`).
    /// Used by translation resolution to match `Type::Variant` ref_paths.
    pub variant_name: &'static str,
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
    /// Explicit default value (overrides byte-slice defaults when present)
    pub default_value: Option<i64>,
    /// Whether this parameter is the source for `{{0}}` text template substitution.
    /// In module definitions, the first parameter with this flag set is used
    /// as the `TextParameterRefId` for communication object text templates.
    pub is_text_source: bool,
}

impl EtsParamDefExt {
    /// Find the index of the first parameter marked as text source.
    ///
    /// Returns `Some(index)` if a parameter has `is_text_source = true`,
    /// otherwise `None`.
    pub fn find_text_source_index(params: &[EtsParamDefExt]) -> Option<usize> {
        params.iter().position(|p| p.is_text_source)
    }
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
/// Generated by `#[ets_union]` for each field in enum variants.
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
    /// Default value for this parameter (if None, uses 0)
    pub default_value: Option<i64>,
}

// ============================================================================
// Union layout arithmetic (used by the `#[ets_union]` macro)
// ============================================================================
//
// `#[ets_union]` sizes its generated `_pad` fields from these rather than from
// arithmetic done at macro-expansion time. That matters: the macro's own type
// table assumes every `#[ets(ets_enum)]` field is one byte, which is wrong for
// the `#[repr(u16)]` enums (`TimeForLongKeypress` and friends) — exactly the
// fields whose alignment creates the holes the padding exists to fill. Driving
// the lengths off real `size_of` / `align_of` keeps the generated layout
// correct however a field type is later defined.

/// Round `offset` up to the next multiple of `align`.
///
/// `align` is a power of two, as `align_of` always returns.
pub const fn union_align_up(offset: usize, align: usize) -> usize {
    offset.next_multiple_of(align)
}

/// `max` for `usize`, as a `const fn` so it can appear in an array length.
pub const fn union_max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// Union information generated by `#[ets_union]`.
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
/// Automatically implemented by `#[ets_union]`.
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte_ets_model::{EtsUnionType, ets_union};
///
/// #[ets_union]
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
/// use zweidraehte_ets_model::{EtsEnum, EtsEnumType};
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
/// #[ets_params]
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
/// Generated by `#[ets_params]` when a field is marked with `#[ets(union)]`.
/// This connects the union type to its position in the parameter block.
#[derive(Debug, Clone, Copy)]
pub struct EtsUnionFieldInfo {
    /// Name of the field in the parent struct
    pub field_name: &'static str,
    /// Human-readable display name for the selector (e.g., "Function Mode")
    pub display_name: &'static str,
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

    /// Object name (for symbol generation and XML Name attribute)
    pub name: &'static str,

    /// Human-readable display name shown in ETS (XML Text attribute)
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

    /// Object size override string (e.g., "4 Bytes") for ETS export.
    /// When `Some`, this overrides the size derived from `size_bits`.
    /// Useful when the same object supports multiple DPT sizes.
    pub object_size_override: Option<&'static str>,

    /// Text template for the ComObjectRef Text attribute.
    ///
    /// Supports placeholder syntax used in KNX module text templates:
    /// - `{{ArgName}}` - Substitutes the value of a module argument (e.g., `{{ChNo}}` → "1")
    /// - `{{0}}` - Substitutes the value of the parameter referenced by `TextParameterRefId`
    ///
    /// Example: `"F{{ChNo}} Switch: {{0}}"` renders as `"F1 Switch: Living Room"`
    ///
    /// When `None`, the `display_name` is used directly without any template substitution.
    pub text_template: Option<&'static str>,
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

    /// Short name of the selector variant (e.g., `"Switch"` for
    /// `ButtonConfigDiscriminant::Switch`). Used to resolve ref-level
    /// translations by `ref_name` + variant name.
    pub selector_value_name: Option<&'static str>,

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
        Self { read: None, write: None, communication: None, transmit: None, update: None, read_on_init: None }
    }
}

// ============================================================================
// Helper trait for extracting DPT info from DatapointType
// ============================================================================

/// Trait for types that carry DPT information.
///
/// This is implemented for [`DatapointType`] to allow
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

// Blanket impl of HasDptInfo for all DatapointType instances from proto.
use zweidraehte_proto::dpt::{DatapointType, PropertyDataDefinition};

impl<PDT: PropertyDataDefinition, const MAIN: u16, const SUB: u16> HasDptInfo for DatapointType<PDT, MAIN, SUB>
where
    PDT: Default,
{
    const DPT_MAIN: u16 = MAIN;
    const DPT_SUB: u16 = SUB;
    /// Size in bits based on DPT main type.
    ///
    /// KNX DPT sizes:
    /// - DPT 1.x = 1 bit (boolean)
    /// - DPT 2.x = 2 bits (control)
    /// - DPT 3.x = 4 bits (dimming/blinds)
    /// - DPT 4.x and higher = bytes (use PDT::SIZE * 8)
    const SIZE_BITS: usize = match MAIN {
        1 => 1,             // DPT 1.x - 1 bit (Switch, Bool, etc.)
        2 => 2,             // DPT 2.x - 2 bits (Bool Control)
        3 => 4,             // DPT 3.x - 4 bits (Dimming, Blinds Control)
        _ => PDT::SIZE * 8, // All other DPTs use full byte size
    };
}

// ============================================================================
// Module helper traits
// ============================================================================

/// Marker trait for parameter structs that provide ETS extended parameter definitions.
///
/// This trait is automatically implemented by `#[ets_params]` and provides
/// access to the `ETS_PARAMS_EXT` constant containing extended parameter metadata.
///
/// Used by `KnxModule` to automatically discover module parameters.
///
/// Also implemented for `()` to allow modules without parameters.
pub trait HasModuleParams {
    /// Extended parameter definitions for this type.
    const ETS_PARAMS_EXT: &'static [EtsParamDefExt];
}

/// Implementation for unit type allows modules to have no parameters.
impl HasModuleParams for () {
    const ETS_PARAMS_EXT: &'static [EtsParamDefExt] = &[];
}

/// Marker trait for communication object structs that provide ETS object definitions.
///
/// This trait is automatically implemented by `#[derive(EtsComObjects)]` and provides
/// access to the `ETS_COMM_OBJECTS` constant containing communication object metadata.
///
/// Used by `KnxModule` to automatically discover module communication objects.
///
/// Also implemented for `()` to allow modules without communication objects.
pub trait HasModuleCommObjects {
    /// Communication object definitions for this type.
    const ETS_COMM_OBJECTS: &'static [EtsCommObjectDef];
}

/// Implementation for unit type allows modules to have no communication objects.
impl HasModuleCommObjects for () {
    const ETS_COMM_OBJECTS: &'static [EtsCommObjectDef] = &[];
}

// ============================================================================
// Virtual Parameter Macro
// ============================================================================

/// Macro for defining virtual (no-memory) parameters.
///
/// Virtual parameters exist only in ETS for text substitution (e.g., `{{0}}` templates)
/// and are NOT stored in device memory. They have no `<Memory>` element in the XML.
///
/// # Syntax
///
/// ```rust,ignore
/// use zweidraehte_ets_model::ets_virtual_params;
///
/// ets_virtual_params! {
///     pub DIMMER_CHANNEL_VIRTUAL_PARAMS {
///         // String parameter (30 bytes) marked as text source for {{0}}
///         channel_name: String(30) => "Channel name" [text_source],
///     }
/// }
/// ```
///
/// # Supported Types
///
/// - `String(N)` - Text parameter with N bytes (N * 8 bits)
///
/// # Modifiers
///
/// - `[text_source]` - Marks this parameter as the text source for `{{0}}` substitution
/// Maps the optional `[text_source]` marker in [`ets_virtual_params`] onto a
/// `bool`. Not part of the public API.
#[doc(hidden)]
#[macro_export]
macro_rules! __ets_text_source_flag {
    () => {
        false
    };
    (text_source) => {
        true
    };
}

#[macro_export]
macro_rules! ets_virtual_params {
    // One repetition arm handles any number of params, each with or without
    // the `[text_source]` marker. An earlier version had one arm per shape and
    // accepted only a single parameter, which forced multi-param devices to
    // hand-expand the `EtsParamDefExt` literals.
    (
        $(#[$attr:meta])*
        $vis:vis $name:ident {
            $(
                $param_name:ident : String($size:expr) => $display:literal $([$text_source:ident])?
            ),* $(,)?
        }
    ) => {
        $(#[$attr])*
        $vis const $name: &[$crate::EtsParamDefExt] = &[
            $(
                $crate::EtsParamDefExt {
                    base: $crate::EtsParamDef {
                        name: stringify!($param_name),
                        display_name: $display,
                        suffix: None,
                        offset: 0,
                        size_bits: ($size * 8) as u16,
                        bit_offset: 0,
                        param_type: $crate::EtsParamType::String,
                        hidden: false,
                        no_memory: true,
                        type_name: None,
                        text_pattern: None,
                    },
                    enum_variants: None,
                    default_value: None,
                    is_text_source: $crate::__ets_text_source_flag!($($text_source)?),
                },
            )*
        ];
    };
}

// ============================================================================
// Translation Types
// ============================================================================

/// Attribute type being translated.
///
/// Maps to the `AttributeName` values in the XML `<Translation>` element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationAttribute {
    /// Display text for parameters, enum variants, comm objects
    Text,
    /// Suffix text for parameters (e.g., unit suffixes like "s", "ms")
    SuffixText,
    /// Name attribute (for application program)
    Name,
    /// Function text for communication objects
    FunctionText,
}

impl TranslationAttribute {
    /// Get the XML attribute name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            TranslationAttribute::Text => "Text",
            TranslationAttribute::SuffixText => "SuffixText",
            TranslationAttribute::Name => "Name",
            TranslationAttribute::FunctionText => "FunctionText",
        }
    }
}

/// A single translation entry.
///
/// Generated by the `ets_translations!` macro. Contains all the information
/// needed to generate a `<TranslationElement>` in the XML.
#[derive(Debug, Clone, Copy)]
pub struct EtsTranslation {
    /// Language identifier (BCP 47 format, e.g., "de-DE", "fr-FR")
    pub language: &'static str,

    /// Reference path identifying what is being translated.
    ///
    /// Format depends on the type:
    /// - Enum variants: `"EnumType::VariantName"` (e.g., `"EnableDisable::Active"`)
    /// - Parameters: `"param::field_name"` (e.g., `"param::startup_delay"`)
    /// - Comm objects: `"obj::object_name"` (e.g., `"obj::switch_output"`)
    /// - Comm object refs: `"obj_ref::name::Variant"` (e.g., `"obj_ref::btn1_primary::Switch"`)
    /// - Blocks: `"block::name"` (e.g., `"block::general"`)
    pub ref_path: &'static str,

    /// Which attribute is being translated
    pub attribute: TranslationAttribute,

    /// The translated text
    pub text: &'static str,
}

/// Macro for defining translations separately from struct/enum definitions.
///
/// This keeps translation definitions cleanly separated from the parameter and
/// object definitions, avoiding code clutter.
///
/// # Syntax
///
/// ```rust,ignore
/// use zweidraehte_ets_model::ets_translations;
///
/// ets_translations! {
///     pub DEVICE_TRANSLATIONS;
///
///     "de-DE" {
///         // Enum variant translations
///         EnableDisable::NotActive => "nicht aktiv",
///         EnableDisable::Active => "aktiv",
///     }
///
///     "fr-FR" {
///         EnableDisable::NotActive => "non actif",
///         EnableDisable::Active => "actif",
///     }
/// }
/// ```
///
/// ## Supported translation types:
///
/// - **Enum variants**: `EnumType::Variant => "translated text",`
/// - **Parameters**: `param field_name => "translated text",`
/// - **Suffixes**: `suffix field_name => "translated suffix",`
/// - **Comm objects**: `obj object_name { text: "translated text" },`
/// - **Comm objects with function**: `obj object_name { text: "text", function: "func" },`
/// - **Comm object refs**: `obj_ref name[Variant] { text: "text" },`
/// - **Comm object refs with function**: `obj_ref name[Variant] { text: "text", function: "func" },`
///
/// Note: Use commas (not semicolons) to separate items within a language block.
///
/// # Generated Output
///
/// This generates a constant:
/// ```rust,ignore
/// pub const DEVICE_TRANSLATIONS: &[EtsTranslation] = &[...];
/// ```
#[macro_export]
macro_rules! ets_translations {
    // Main entry point - start the accumulator pattern
    (
        $(#[$attr:meta])*
        $vis:vis $name:ident;

        $($lang:literal {
            $($item:tt)*
        })*
    ) => {
        $crate::__ets_translations_accumulate!(
            @acc []
            @langs [$(($lang, [$($item)*]))*]
            @attrs [$(#[$attr])*]
            @vis [$vis]
            @name [$name]
        );
    };
}

/// Internal: Accumulator-based translation expansion.
/// Uses TT munching to build up an array of translations.
#[macro_export]
#[doc(hidden)]
macro_rules! __ets_translations_accumulate {
    // Done processing all languages - emit the result
    (
        @acc [$($acc:tt)*]
        @langs []
        @attrs [$(#[$attr:meta])*]
        @vis [$vis:vis]
        @name [$name:ident]
    ) => {
        $(#[$attr])*
        $vis const $name: &[$crate::EtsTranslation] = &[
            $($acc)*
        ];
    };

    // Start processing a language block
    (
        @acc [$($acc:tt)*]
        @langs [($lang:literal, [$($items:tt)*]) $($rest_langs:tt)*]
        @attrs $attrs:tt
        @vis $vis:tt
        @name $name:tt
    ) => {
        $crate::__ets_translations_items!(
            @acc [$($acc)*]
            @lang $lang
            @items [$($items)*]
            @rest_langs [$($rest_langs)*]
            @attrs $attrs
            @vis $vis
            @name $name
        );
    };
}

/// Internal: Process items within a language block.
#[macro_export]
#[doc(hidden)]
macro_rules! __ets_translations_items {
    // No more items in this language - continue with next language
    (
        @acc [$($acc:tt)*]
        @lang $lang:literal
        @items []
        @rest_langs [$($rest_langs:tt)*]
        @attrs $attrs:tt
        @vis $vis:tt
        @name $name:tt
    ) => {
        $crate::__ets_translations_accumulate!(
            @acc [$($acc)*]
            @langs [$($rest_langs)*]
            @attrs $attrs
            @vis $vis
            @name $name
        );
    };

    // Enum variant: Type::Variant => "text",
    (
        @acc [$($acc:tt)*]
        @lang $lang:literal
        @items [$enum_type:ident :: $variant:ident => $text:literal, $($rest:tt)*]
        @rest_langs $rest_langs:tt
        @attrs $attrs:tt
        @vis $vis:tt
        @name $name:tt
    ) => {
        $crate::__ets_translations_items!(
            @acc [
                $($acc)*
                $crate::EtsTranslation {
                    language: $lang,
                    ref_path: concat!(stringify!($enum_type), "::", stringify!($variant)),
                    attribute: $crate::TranslationAttribute::Text,
                    text: $text,
                },
            ]
            @lang $lang
            @items [$($rest)*]
            @rest_langs $rest_langs
            @attrs $attrs
            @vis $vis
            @name $name
        );
    };

    // Comm object with text only: obj name { text: "..." },
    (
        @acc [$($acc:tt)*]
        @lang $lang:literal
        @items [obj $obj_name:ident { text: $text:literal }, $($rest:tt)*]
        @rest_langs $rest_langs:tt
        @attrs $attrs:tt
        @vis $vis:tt
        @name $name:tt
    ) => {
        $crate::__ets_translations_items!(
            @acc [
                $($acc)*
                $crate::EtsTranslation {
                    language: $lang,
                    ref_path: concat!("obj::", stringify!($obj_name)),
                    attribute: $crate::TranslationAttribute::Text,
                    text: $text,
                },
            ]
            @lang $lang
            @items [$($rest)*]
            @rest_langs $rest_langs
            @attrs $attrs
            @vis $vis
            @name $name
        );
    };

    // Comm object with text and function: obj name { text: "...", function: "..." },
    (
        @acc [$($acc:tt)*]
        @lang $lang:literal
        @items [obj $obj_name:ident { text: $text:literal, function: $func:literal }, $($rest:tt)*]
        @rest_langs $rest_langs:tt
        @attrs $attrs:tt
        @vis $vis:tt
        @name $name:tt
    ) => {
        $crate::__ets_translations_items!(
            @acc [
                $($acc)*
                $crate::EtsTranslation {
                    language: $lang,
                    ref_path: concat!("obj::", stringify!($obj_name)),
                    attribute: $crate::TranslationAttribute::Text,
                    text: $text,
                },
                $crate::EtsTranslation {
                    language: $lang,
                    ref_path: concat!("obj::", stringify!($obj_name)),
                    attribute: $crate::TranslationAttribute::FunctionText,
                    text: $func,
                },
            ]
            @lang $lang
            @items [$($rest)*]
            @rest_langs $rest_langs
            @attrs $attrs
            @vis $vis
            @name $name
        );
    };

    // Parameter display name: param name => "text",
    (
        @acc [$($acc:tt)*]
        @lang $lang:literal
        @items [param $param_name:ident => $text:literal, $($rest:tt)*]
        @rest_langs $rest_langs:tt
        @attrs $attrs:tt
        @vis $vis:tt
        @name $name:tt
    ) => {
        $crate::__ets_translations_items!(
            @acc [
                $($acc)*
                $crate::EtsTranslation {
                    language: $lang,
                    ref_path: concat!("param::", stringify!($param_name)),
                    attribute: $crate::TranslationAttribute::Text,
                    text: $text,
                },
            ]
            @lang $lang
            @items [$($rest)*]
            @rest_langs $rest_langs
            @attrs $attrs
            @vis $vis
            @name $name
        );
    };

    // Parameter suffix: suffix name => "text",
    (
        @acc [$($acc:tt)*]
        @lang $lang:literal
        @items [suffix $param_name:ident => $text:literal, $($rest:tt)*]
        @rest_langs $rest_langs:tt
        @attrs $attrs:tt
        @vis $vis:tt
        @name $name:tt
    ) => {
        $crate::__ets_translations_items!(
            @acc [
                $($acc)*
                $crate::EtsTranslation {
                    language: $lang,
                    ref_path: concat!("param::", stringify!($param_name)),
                    attribute: $crate::TranslationAttribute::SuffixText,
                    text: $text,
                },
            ]
            @lang $lang
            @items [$($rest)*]
            @rest_langs $rest_langs
            @attrs $attrs
            @vis $vis
            @name $name
        );
    };

    // ComObjectRef with text only: obj_ref name[Variant] { text: "..." },
    //
    // Targets a specific ComObjectRef identified by the base object field name
    // and the selector variant. The variant name is the last segment of the
    // `when` path (e.g., `Switch` from `ButtonConfigDiscriminant::Switch`).
    (
        @acc [$($acc:tt)*]
        @lang $lang:literal
        @items [obj_ref $obj_name:ident [ $variant:ident ] { text: $text:literal }, $($rest:tt)*]
        @rest_langs $rest_langs:tt
        @attrs $attrs:tt
        @vis $vis:tt
        @name $name:tt
    ) => {
        $crate::__ets_translations_items!(
            @acc [
                $($acc)*
                $crate::EtsTranslation {
                    language: $lang,
                    ref_path: concat!("obj_ref::", stringify!($obj_name), "::", stringify!($variant)),
                    attribute: $crate::TranslationAttribute::Text,
                    text: $text,
                },
            ]
            @lang $lang
            @items [$($rest)*]
            @rest_langs $rest_langs
            @attrs $attrs
            @vis $vis
            @name $name
        );
    };

    // ComObjectRef with text and function: obj_ref name[Variant] { text: "...", function: "..." },
    (
        @acc [$($acc:tt)*]
        @lang $lang:literal
        @items [obj_ref $obj_name:ident [ $variant:ident ] { text: $text:literal, function: $func:literal }, $($rest:tt)*]
        @rest_langs $rest_langs:tt
        @attrs $attrs:tt
        @vis $vis:tt
        @name $name:tt
    ) => {
        $crate::__ets_translations_items!(
            @acc [
                $($acc)*
                $crate::EtsTranslation {
                    language: $lang,
                    ref_path: concat!("obj_ref::", stringify!($obj_name), "::", stringify!($variant)),
                    attribute: $crate::TranslationAttribute::Text,
                    text: $text,
                },
                $crate::EtsTranslation {
                    language: $lang,
                    ref_path: concat!("obj_ref::", stringify!($obj_name), "::", stringify!($variant)),
                    attribute: $crate::TranslationAttribute::FunctionText,
                    text: $func,
                },
            ]
            @lang $lang
            @items [$($rest)*]
            @rest_langs $rest_langs
            @attrs $attrs
            @vis $vis
            @name $name
        );
    };

    // Parameter block display text: block "name" => "text",
    (
        @acc [$($acc:tt)*]
        @lang $lang:literal
        @items [block $block_name:literal => $text:literal, $($rest:tt)*]
        @rest_langs $rest_langs:tt
        @attrs $attrs:tt
        @vis $vis:tt
        @name $name:tt
    ) => {
        $crate::__ets_translations_items!(
            @acc [
                $($acc)*
                $crate::EtsTranslation {
                    language: $lang,
                    ref_path: concat!("block::", $block_name),
                    attribute: $crate::TranslationAttribute::Text,
                    text: $text,
                },
            ]
            @lang $lang
            @items [$($rest)*]
            @rest_langs $rest_langs
            @attrs $attrs
            @vis $vis
            @name $name
        );
    };
}
