//! Proc-macros for KNX ETS parameter export.
//!
//! This crate provides derive macros for generating ETS parameter definitions:
//! - `#[derive(EtsParams)]` - For structs containing parameters
//! - `#[ets_union]` - For enums representing union parameters (with data)
//! - `#[derive(EtsEnum)]` - For simple enums (no data) used as dropdown parameters
//!
//! # EtsParams Usage
//!
//! ```rust,ignore
//! use zweidraehte_ets::EtsParams;
//!
//! #[derive(EtsParams)]
//! #[repr(C)]
//! pub struct MyParams {
//!     /// Operating mode with enum variants for ETS
//!     #[ets(display = "Operating Mode", enum_variants("Off" => 0, "Normal" => 1))]
//!     pub mode: u8,
//!
//!     /// Temperature setpoint
//!     #[ets(display = "Setpoint")]
//!     pub setpoint: u16,
//! }
//!
//! // Generated:
//! // impl MyParams {
//! //     pub const ETS_PARAMS: &'static [EtsParamDef] = &[...];
//! //     pub const ETS_PARAMS_EXT: &'static [EtsParamDefExt] = &[...];
//! //     pub const MODE_VARIANTS: &[EtsEnumVariant] = &[...];
//! // }
//! ```
//!
//! # ets_union Usage
//!
//! Use `#[ets_union]` on enums to create union parameters
//! where the discriminant acts as the selector:
//!
//! ```rust,ignore
//! use zweidraehte_ets::ets_union;
//!
//! #[ets_union]
//! #[repr(C, u8)]
//! pub enum ConfigUnion {
//!     #[ets(display = "Off")]
//!     Off,
//!
//!     #[ets(display = "Normal Mode")]
//!     Normal {
//!         #[ets(display = "Normal Config")]
//!         config: u32,
//!     },
//!
//!     #[ets(display = "Eco Mode")]
//!     Eco {
//!         #[ets(display = "Eco Temperature")]
//!         temp: u16,
//!         #[ets(display = "Eco Timeout")]
//!         timeout: u16,
//!     },
//! }
//!
//! // Generated:
//! // impl ConfigUnion {
//! //     pub const ETS_UNION_INFO: EtsUnionInfo = ...;
//! //     pub const ETS_SELECTOR_VARIANTS: &[EtsEnumVariant] = &[...];
//! // }
//! ```
//!
//! # Supported Field Types
//!
//! - `u8`, `u16`, `u32` - Unsigned integers
//! - `i8`, `i16`, `i32` - Signed integers
//! - `bool` - Boolean (1 byte)
//! - `[u8; N]` - Raw byte arrays
//!
//! # EtsParams Attributes
//!
//! - `#[ets(display = "...")]` - Human-readable name for ETS UI
//! - `#[ets(skip)]` - Skip this field (don't generate ETS parameter)
//! - `#[ets(bits = N)]` - Override size in bits (for bitfields)
//! - `#[ets(bit_offset = N)]` - Bit offset within byte (for bitfields)
//! - `#[ets(enum_variants("Name" => 0, "Other" => 1))]` - Define enum variants for ETS
//!
//! # ets_union Attributes
//!
//! On the enum:
//! - `#[repr(C, u8)]` - Required, ensures predictable memory layout
//!
//! On variants:
//! - `#[ets(display = "...")]` - Human-readable name for ETS selector dropdown
//!
//! On variant fields:
//! - `#[ets(display = "...")]` - Human-readable name for the parameter
//! - `#[ets(enum_variants("Name" => 0, "Other" => 1))]` - Define enum variants for ETS dropdown
//! - `#[ets(ets_enum)]` - Mark field as an EtsEnum type (uses type's ETS_VARIANTS)
//!
//! # EtsEnum Attributes
//!
//! On the enum:
//! - `#[repr(u8)]` - Required, ensures predictable memory layout
//!
//! On variants:
//! - `#[ets(display = "...")]` - Human-readable name for ETS dropdown

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

mod ets_com_objects;
mod ets_enum;
mod ets_params;
mod ets_params_attr;
mod ets_range_enum;
mod ets_union;
mod ets_union_attr;
mod parse;

/// Derive macro for generating ETS parameter definitions.
///
/// Generates an `ETS_PARAMS` constant containing metadata for each field
/// that can be used for ETS export.

/// Derive macro for generating ETS union definitions from Rust enums.
///
/// Requires `#[repr(C, u8)]` on the enum for predictable memory layout.
/// The discriminant becomes the ETS selector parameter.
///
/// # Generated Items
///
/// - `ETS_UNION_INFO: EtsUnionInfo` - Union metadata including size and variant params
/// - `ETS_SELECTOR_VARIANTS: &[EtsEnumVariant]` - Enum variants for the selector param
///
/// # Example
///
/// ```rust,ignore
/// #[derive(EtsUnion)]
/// #[repr(C, u8)]
/// pub enum ConfigUnion {
///     #[ets(display = "Off")]
///     Off,
///
///     #[ets(display = "Normal")]
///     Normal { config: u32 },
/// }
/// ```
/// Define an ETS union parameter (a tagged union of parameter variants).
///
/// Rewrites the enum so its byte image is fully initialised — inserting the
/// alignment and tail padding a `#[repr(u8)]` tagged union needs — then applies
/// `#[derive(zerocopy::IntoBytes)]`, which is what actually proves the result
/// has no uninitialized bytes. That matters because a union's bytes are read
/// wholesale: as the `<Data>` defaults blob ETS reads back, and as the live
/// parameter memory served to `A_Memory_Read`.
///
/// Write only the real parameters; do **not** add a `repr` (the macro emits
/// `#[repr(u8)]`) and never hand-write `unsafe impl IntoBytes`.
///
/// ```rust,ignore
/// #[ets_union]
/// #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
/// pub enum ButtonConfig {
///     #[ets(default_variant, display = "Switch")]
///     Switch {
///         #[ets(display = "Switch action", ets_enum)]
///         action: SwitchAction,
///     } = 0,
///
///     #[ets(display = "Dimmer")]
///     Dimmer = 1,
/// }
/// ```
///
/// Generated padding is named `_pad_tail` / `_pad_before_<field>` and carries
/// `#[ets(skip)]`, so it produces no ETS parameter and shifts no real
/// parameter's offset. One consequence worth knowing: a unit variant gains a
/// body, so `ButtonConfig::Dimmer` is constructed and matched as
/// `ButtonConfig::Dimmer { .. }`.
/// Define an ETS parameter struct.
///
/// Rewrites the struct so its byte image is fully initialised — inserting the
/// alignment and trailing padding `#[repr(C)]` would otherwise leave unnamed —
/// then applies `#[derive(zerocopy::IntoBytes)]`, which proves there is none
/// left. That matters because the struct is read wholesale: as the `<Data>`
/// defaults blob ETS reads back, and as the live parameter memory served to
/// `A_Memory_Read`.
///
/// Write only the real parameters; do **not** add a `repr` (the macro emits
/// `#[repr(C)]`) and never hand-write `unsafe impl IntoBytes`.
///
/// ```rust,ignore
/// #[ets_params]
/// #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
/// pub struct MyParams {
///     #[ets(display = "Startup time", suffix = "s")]
///     pub startup_timeout: u16,
///
///     #[ets(display = "Reaction time", ets_enum)]
///     pub debounce_time: ReactionTime,
/// }
/// ```
///
/// Generated padding is named `_pad_before_<field>` / `_pad_tail` and carries
/// `#[ets(skip)]`, so it emits no ETS parameter. Real parameters keep their
/// offsets because the metadata reads them from `core::mem::offset_of!`.
#[proc_macro_attribute]
pub fn ets_params(_args: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);

    match ets_params_attr::ets_params_impl(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

#[proc_macro_attribute]
pub fn ets_union(_args: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);

    match ets_union_attr::ets_union_impl(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Derive macro for generating ETS enum definitions from simple Rust enums.
///
/// Use this for `#[repr(u8)]` enums without data fields. These become dropdown
/// parameters in ETS and can be used as field types in `EtsParams` structs
/// or `EtsUnion` variants.
///
/// # Requirements
///
/// - Enum must have `#[repr(u8)]` (or `#[repr(u16)]` for larger enums)
/// - All variants must be unit variants (no data)
/// - Explicit discriminant values are recommended for stability
///
/// # Generated Items
///
/// - `ETS_VARIANTS: &[EtsEnumVariant]` - Enum variants for ETS dropdown
/// - `ETS_SIZE_BITS: u16` - Size in bits (8 for repr(u8), 16 for repr(u16))
/// - `EtsEnumType` trait implementation
/// - `Display` trait implementation (uses `#[ets(display = "...")]` values)
///
/// # Example
///
/// ```rust,ignore
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
/// // Use in EtsUnion variants:
/// #[derive(EtsUnion)]
/// #[repr(C, u8)]
/// pub enum InputSource {
///     Temperature {
///         sensor_type: SensorType,  // Gets dropdown in ETS
///         offset: i8,
///     },
/// }
/// ```
#[proc_macro_derive(EtsEnum, attributes(ets))]
pub fn derive_ets_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match ets_enum::derive_ets_enum_impl(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Derive macro for generating KNX communication objects with ETS metadata.
///
/// This macro replaces the `define_com_objects!` declarative macro with a more
/// powerful proc macro that supports:
/// - ComObjectRef definitions (same object with different DPT/size interpretations)
/// - Selector-based typed access (match on selector to get correctly typed refs)
/// - Auto-derived storage size for multi-ref objects
/// - Zero-overhead type-safe accessors
///
/// # Basic Usage
///
/// ```rust,ignore
/// use zweidraehte_ets::EtsComObjects;
/// use zweidraehte_proto::dpt::*;
///
/// #[derive(EtsComObjects)]
/// pub struct MyComObjects {
///     /// Simple switch input
///     #[ets(index = 0, display = "Switch Input", function = "On/Off")]
///     pub switch_in: DPT_Switch,
///
///     /// Temperature value
///     #[ets(index = 1, display = "Temperature")]
///     pub temperature: DPT_Value_Temp,
/// }
/// ```
///
/// # Multi-Ref Objects (ComObjectRefs)
///
/// For objects that can have different DPT interpretations based on ETS parameters:
///
/// ```rust,ignore
/// #[derive(EtsComObjects)]
/// #[ets(selector_enum = ButtonMode)]
/// pub struct MyComObjects {
///     /// Multi-type output controlled by button_mode parameter
///     #[ets(index = 0, display = "Output", flags = 0x5F)]
///     #[ets_ref(dpt = DPT_Switch, when = ButtonMode::Switch)]
///     #[ets_ref(dpt = DPT_Scaling, when = ButtonMode::Dimmer)]
///     pub output: (),  // Placeholder - replaced with ComObjectStorage<N>
/// }
///
/// // Generated: ButtonModeObjs enum for typed access
/// match params.button_mode.comm_objects(&mut objs) {
///     ButtonModeObjs::Switch { output, .. } => {
///         // output is TypedComObj<DPT_Switch, 0>
///     }
///     ButtonModeObjs::Dimmer { output, .. } => {
///         // output is TypedComObj<DPT_Scaling, 0>
///     }
/// }
/// ```
///
/// # Attributes
///
/// ## On struct:
/// - `#[ets(manual_impl)]` - Don't generate `ComObjects` trait impl
/// - `#[ets(selector_enum = EnumType)]` - Generate selector-based typed access
///
/// ## On fields (base object):
/// - `#[ets(index = N)]` - **Required**. 0-based logical index for this comm object
///   (the ETS object number is `N` plus the mask family's start index: 0 for
///   System 7, 1 for System B)
/// - `#[ets(display = "...")]` - Human-readable name for ETS
/// - `#[ets(function = "...")]` - Function text (for simple objects)
/// - `#[ets(flags = 0xNN)]` - Default flags byte (default: 0xDF)
///
/// ## On multi-ref fields:
/// - `#[ets_ref(dpt = TYPE, when = Selector::Variant)]` - Define a ref for a variant
/// - `#[ets_ref(..., function = "...")]` - Function text for this ref
/// - `#[ets_ref(..., read = true/false)]` - Override read flag
/// - `#[ets_ref(..., write = true/false)]` - Override write flag
/// - etc. for other flags
#[proc_macro_derive(EtsComObjects, attributes(ets, ets_ref))]
pub fn derive_ets_com_objects(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match ets_com_objects::derive_ets_com_objects_impl(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Generate an enum with sequential or formula-based numeric variants.
///
/// This macro generates enums for numeric ranges like scene numbers (1-64)
/// or percentages (0-100%), complete with all required ETS traits.
///
/// # Usage
///
/// ```rust,ignore
/// // Simple sequential: values 0..64, display = value + 1
/// ets_range_enum! {
///     /// Scene number selection
///     #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
///     #[ets(type_name = "SceneValue")]
///     pub enum SceneValue {
///         // Generates Scene1 = 0 with display "1", through Scene64 = 63 with display "64"
///         range 0..64 => |i| (format!("Scene{}", i + 1), format!("{}", i + 1));
///         default = 0;
///     }
/// }
///
/// // Percentage with formula: percent * 2.55 rounded
/// ets_range_enum! {
///     /// Percentage selection 0-100%
///     #[derive(Debug, Clone, Copy, PartialEq, Eq)]
///     #[ets(type_name = "select0to100percent")]
///     pub enum Select0to100Percent {
///         range 0..=100 => percent_to_byte |i| (format!("P{}", i), format!("{}%", i));
///         default = 0;
///     }
/// }
/// ```
///
/// # Generated Code
///
/// For each enum, generates:
/// - The enum definition with variants
/// - `ETS_VARIANTS: &'static [EtsEnumVariant]`
/// - `ETS_SIZE_BITS: u16`
/// - `impl Default`
/// - `impl ConstDefault`
#[proc_macro]
pub fn ets_range_enum(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as ets_range_enum::EtsRangeEnumInput);

    match ets_range_enum::generate_range_enum(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}
