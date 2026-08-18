//! Parameter types and definitions.

use serde::{Deserialize, Serialize};

// ============================================================================
// Parameter Types
// ============================================================================

/// Container for parameter type definitions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParameterTypes {
    #[serde(rename = "ParameterType", alias = "PT", default)]
    pub types: Vec<ParameterType>,
}

/// A parameter type definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterType {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,

    #[serde(rename = "$value")]
    pub type_def: ParameterTypeDef,
}

/// The actual type definition (choice)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ParameterTypeDef {
    #[serde(alias = "TNr")]
    TypeNumber(TypeNumber),
    TypeFloat(TypeFloat),
    #[serde(alias = "TR")]
    TypeRestriction(TypeRestriction),
    TypeText(TypeText),
    TypeNone(TypeNone),
    TypePicture(TypePicture),
    #[serde(rename = "TypeIPAddress")]
    TypeIpAddress(TypeIpAddress),
}

impl ParameterTypeDef {
    /// The storage width in bits, or 0 when the type does not declare
    /// one (`TypeFloat` carries a DPT encoding instead of a width;
    /// `TypeNone`/`TypePicture`/`TypeIPAddress` occupy no parameter
    /// memory a download patches). Callers treat 0 as "byte-aligned,
    /// size known only from the value itself".
    pub fn size_bits(&self) -> u16 {
        match self {
            Self::TypeNumber(n) => u16::from(n.size_in_bit),
            Self::TypeRestriction(r) => r.size_in_bit as u16,
            Self::TypeText(t) => t.size_in_bit as u16,
            Self::TypeFloat(_) | Self::TypeNone(_) | Self::TypePicture(_) | Self::TypeIpAddress(_) => 0,
        }
    }
}

/// Numeric parameter type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeNumber {
    #[serde(rename = "@SizeInBit")]
    pub size_in_bit: u8,
    #[serde(rename = "@Type")]
    pub num_type: String, // "signedInt" or "unsignedInt"
    #[serde(rename = "@minInclusive")]
    pub min_inclusive: i64,
    #[serde(rename = "@maxInclusive")]
    pub max_inclusive: i64,
}

/// Float parameter type (for DPT 9, DPT 14, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeFloat {
    #[serde(rename = "@Encoding")]
    pub encoding: String, // e.g., "DPT 9", "DPT 14"
    #[serde(rename = "@minInclusive")]
    pub min_inclusive: f64,
    #[serde(rename = "@maxInclusive")]
    pub max_inclusive: f64,
}

/// Enumeration/restriction parameter type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeRestriction {
    #[serde(rename = "@Base")]
    pub base: String, // "Value" or "BinaryValue"
    #[serde(rename = "@SizeInBit")]
    pub size_in_bit: u32,

    #[serde(rename = "Enumeration", default)]
    pub enumerations: Vec<Enumeration>,
}

/// An enumeration value within TypeRestriction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enumeration {
    #[serde(rename = "@Text")]
    pub text: String,
    #[serde(rename = "@Value")]
    pub value: u32,
    #[serde(rename = "@Id")]
    pub id: String,
    // Note: DisplayOrder is ETS3-only, removed for ETS5+ compatibility
}

/// Text parameter type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeText {
    #[serde(rename = "@SizeInBit")]
    pub size_in_bit: u32,
    #[serde(rename = "@Pattern", skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

/// No type (raw bytes)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeNone {}

/// Picture/image parameter type (references a baggaged image file)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypePicture {
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    /// How ETS places the picture inside the value column:
    /// "Left" (the schema default) | "Middle" | "Right" | "Stretch" |
    /// "Repeat"
    #[serde(rename = "@HorizontalAlignment", skip_serializing_if = "Option::is_none")]
    pub horizontal_alignment: Option<String>,
}

/// IP address parameter type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeIpAddress {
    #[serde(rename = "@AddressType")]
    pub address_type: String,
}

// ============================================================================
// Parameters
// ============================================================================

/// Container for parameters
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Parameters {
    #[serde(rename = "$value", default)]
    pub items: Vec<ParameterItem>,
}

/// A parameter or union in the Parameters section
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ParameterItem {
    #[serde(alias = "P")]
    Parameter(Parameter),
    #[serde(alias = "U")]
    Union(Union),
}

/// A single parameter definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@ParameterType")]
    pub parameter_type: String,
    #[serde(rename = "@Text")]
    pub text: String,
    #[serde(rename = "@SuffixText", skip_serializing_if = "Option::is_none")]
    pub suffix_text: Option<String>,
    /// Access mode: "None" means hidden from user
    #[serde(rename = "@Access", skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    #[serde(rename = "@Value")]
    pub value: String,
    /// Reference to a module argument for relative value calculation.
    /// When set, the final value = argument_value + Value.
    /// Used in modules to add a base value to parameter defaults.
    #[serde(rename = "@BaseValue", skip_serializing_if = "Option::is_none")]
    pub base_value: Option<String>,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
    /// ETS writes this parameter on every download, even when its value
    /// equals the product default. Vendor programs use it for values the
    /// firmware treats as tool-written rather than image defaults, so a
    /// diff-from-defaults download must not skip them.
    #[serde(rename = "@LegacyPatchAlways", default, skip_serializing_if = "std::ops::Not::not")]
    pub legacy_patch_always: bool,

    #[serde(rename = "Memory", alias = "M", skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryLocation>,
}

/// Memory location for a parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLocation {
    #[serde(rename = "@CodeSegment")]
    pub code_segment: String,
    #[serde(rename = "@Offset")]
    pub offset: u32,
    #[serde(rename = "@BitOffset")]
    pub bit_offset: u8,
    /// Reference to a module argument for relative offset calculation.
    /// When set, the final offset = argument_value + offset.
    #[serde(rename = "@BaseOffset", skip_serializing_if = "Option::is_none")]
    pub base_offset: Option<String>,
}

/// A union containing multiple parameters sharing memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Union {
    #[serde(rename = "@SizeInBit")]
    pub size_in_bit: u32,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,

    #[serde(rename = "Memory", alias = "M")]
    pub memory: UnionMemory,
    #[serde(rename = "Parameter", alias = "P", default)]
    pub parameters: Vec<UnionParameter>,
}

/// Memory location for a union
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionMemory {
    #[serde(rename = "@CodeSegment")]
    pub code_segment: String,
    #[serde(rename = "@Offset")]
    pub offset: u32,
    #[serde(rename = "@BitOffset")]
    pub bit_offset: u8,
    /// Reference to a module argument for relative offset calculation.
    /// When set, the final offset = argument_value + offset.
    #[serde(rename = "@BaseOffset", skip_serializing_if = "Option::is_none")]
    pub base_offset: Option<String>,
}

/// A parameter within a union
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionParameter {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@ParameterType")]
    pub parameter_type: String,
    #[serde(rename = "@Text")]
    pub text: String,
    #[serde(rename = "@SuffixText", skip_serializing_if = "Option::is_none")]
    pub suffix_text: Option<String>,
    /// Access mode, same semantics as on [`Parameter`]: "None" means hidden
    /// from user, "Read" means visible but not user-writable
    #[serde(rename = "@Access", skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    #[serde(rename = "@Value")]
    pub value: String,
    #[serde(rename = "@Offset")]
    pub offset: u16,
    #[serde(rename = "@BitOffset")]
    pub bit_offset: u8,
    #[serde(rename = "@DefaultUnionParameter", skip_serializing_if = "Option::is_none")]
    pub default_union_parameter: Option<bool>,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
}
