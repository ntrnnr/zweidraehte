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
    TypeColor(TypeColor),
    TypeTime(TypeTime),
}

impl ParameterTypeDef {
    /// The storage width in bits, or 0 when the type does not declare
    /// one. `TypeFloat` carries its width indirectly in the DPT encoding;
    /// the encodings supported by the runtime are resolved here so image
    /// construction can retain their product defaults as well as patching
    /// explicitly configured values. `TypeNone`/`TypePicture`/`TypeIPAddress`
    /// occupy no parameter memory a download patches. Callers treat 0 as
    /// "byte-aligned, size known only from the value itself".
    pub fn size_bits(&self) -> u16 {
        match self {
            Self::TypeNumber(n) => u16::from(n.size_in_bit),
            Self::TypeRestriction(r) => r.size_in_bit as u16,
            Self::TypeText(t) => t.size_in_bit as u16,
            Self::TypeColor(color) => color.space.size_bits(),
            Self::TypeTime(time) => u16::from(time.size_in_bit),
            Self::TypeFloat(f) if f.encoding.starts_with("DPT 9") => 16,
            Self::TypeFloat(f) if f.encoding.starts_with("DPT 14") => 32,
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

/// ETS colour picker parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeColor {
    #[serde(rename = "@Space")]
    pub space: ColorSpace,
}

/// Time or duration parameter. `Unit` controls both display and, for the
/// packed variants, its wire representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeTime {
    #[serde(rename = "@SizeInBit")]
    pub size_in_bit: u8,
    #[serde(rename = "@Unit")]
    pub unit: String,
    #[serde(rename = "@minInclusive")]
    pub min_inclusive: i64,
    #[serde(rename = "@maxInclusive")]
    pub max_inclusive: i64,
    #[serde(rename = "@UIHint", skip_serializing_if = "Option::is_none")]
    pub ui_hint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ColorSpace {
    #[serde(rename = "RGB")]
    Rgb,
    #[serde(rename = "HSV")]
    Hsv,
    #[serde(rename = "RGBW")]
    Rgbw,
}

impl ColorSpace {
    pub const fn size_bits(self) -> u16 {
        match self {
            Self::Rgb | Self::Hsv => 24,
            Self::Rgbw => 32,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Rgb => "RGB",
            Self::Hsv => "HSV",
            Self::Rgbw => "RGBW",
        }
    }

    /// Decode the canonical ETS `#RRGGBB`-style spelling into its stored
    /// channel octets. HSV uses the same three-pair spelling; RGBW has four.
    pub fn decode_value(self, value: &str) -> Option<Vec<u8>> {
        let digits = value.strip_prefix('#')?;
        if digits.len() != usize::from(self.size_bits() / 4) || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        (0..digits.len()).step_by(2).map(|index| u8::from_str_radix(&digits[index..index + 2], 16).ok()).collect()
    }
}

#[cfg(test)]
mod color_tests {
    use super::*;

    #[test]
    fn type_color_deserializes_and_decodes_ets_values() {
        let parameter: ParameterType = quick_xml::de::from_str(
            r#"<ParameterType Id="M-00C5_A-1_PT-RGB" Name="RGB"><TypeColor Space="RGB" /></ParameterType>"#,
        )
        .expect("TypeColor parses");
        let ParameterTypeDef::TypeColor(color) = parameter.type_def else { panic!("expected TypeColor") };
        assert_eq!(color.space, ColorSpace::Rgb);
        assert_eq!(color.space.size_bits(), 24);
        assert_eq!(color.space.decode_value("#12aBef"), Some(vec![0x12, 0xAB, 0xEF]));
        assert_eq!(color.space.decode_value("12ABEF"), None);
        assert_eq!(ColorSpace::Rgbw.decode_value("#01020304"), Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn type_time_deserializes_with_its_storage_width() {
        let parameter: ParameterType = quick_xml::de::from_str(
            r#"<ParameterType Id="M-00C5_A-1_PT-TIME" Name="Time"><TypeTime SizeInBit="24" Unit="PackedDaysHoursMinutesAndSeconds" minInclusive="0" maxInclusive="86400" UIHint="Time_hhmmss" /></ParameterType>"#,
        )
        .expect("TypeTime parses");
        let ParameterTypeDef::TypeTime(time) = parameter.type_def else { panic!("expected TypeTime") };
        assert_eq!(time.size_in_bit, 24);
        assert_eq!(time.unit, "PackedDaysHoursMinutesAndSeconds");
        assert_eq!(time.ui_hint.as_deref(), Some("Time_hhmmss"));
    }

    #[test]
    fn type_float_derives_its_storage_width_from_the_dpt() {
        let float16 = ParameterTypeDef::TypeFloat(TypeFloat {
            encoding: "DPT 9.001".to_string(),
            min_inclusive: -273.0,
            max_inclusive: 670_760.0,
        });
        let float32 = ParameterTypeDef::TypeFloat(TypeFloat {
            encoding: "DPT 14".to_string(),
            min_inclusive: f64::MIN,
            max_inclusive: f64::MAX,
        });

        assert_eq!(float16.size_bits(), 16);
        assert_eq!(float32.size_bits(), 32);
    }

    #[test]
    fn property_backed_parameter_deserializes() {
        let parameters: Parameters = quick_xml::de::from_str(
            r#"<Parameters><Parameter Id="P-1" Name="Rate" ParameterType="PT-1" Text="Rate" Value="0"><Property ObjectIndex="0" PropertyId="86" Offset="0" BitOffset="0" /></Parameter></Parameters>"#,
        )
        .expect("property parameter parses");
        let ParameterItem::Parameter(parameter) = &parameters.items[0] else {
            panic!("expected parameter");
        };
        let property = parameter.property.as_ref().expect("property location is retained");
        assert_eq!(property.object_index, Some(0));
        assert_eq!(property.property_id, 86);
        assert!(parameter.memory.is_none());
    }
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
    #[serde(rename = "Property", skip_serializing_if = "Option::is_none")]
    pub property: Option<PropertyLocation>,
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

/// Interface-object property location for a parameter. Exactly one of
/// `object_index` and `object_type` is present in a valid product.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyLocation {
    #[serde(rename = "@ObjectIndex", skip_serializing_if = "Option::is_none")]
    pub object_index: Option<u8>,
    #[serde(rename = "@ObjectType", skip_serializing_if = "Option::is_none")]
    pub object_type: Option<u16>,
    #[serde(rename = "@Occurrence", default, skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<u16>,
    #[serde(rename = "@PropertyId")]
    pub property_id: u16,
    #[serde(rename = "@Offset")]
    pub offset: u32,
    #[serde(rename = "@BitOffset")]
    pub bit_offset: u8,
}

/// A union containing multiple parameters sharing memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Union {
    #[serde(rename = "@SizeInBit")]
    pub size_in_bit: u32,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,

    #[serde(rename = "Memory", alias = "M", skip_serializing_if = "Option::is_none")]
    pub memory: Option<UnionMemory>,
    #[serde(rename = "Property", skip_serializing_if = "Option::is_none")]
    pub property: Option<PropertyLocation>,
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
