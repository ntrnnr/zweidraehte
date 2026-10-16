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
    /// Opaque binary data of at most `MaxSize` bytes (schema 20+).
    TypeRawData(TypeRawData),
}

impl ParameterTypeDef {
    /// Whether the product's `ParameterByteOrder` reorders this type's bytes.
    ///
    /// Only numeric encodings have a byte order: numbers, restrictions,
    /// floats and times are reversed for a little-endian product, while
    /// text, IP addresses, colours and raw data keep their byte sequence,
    /// as the reference encoder does.
    pub fn byte_ordered(&self) -> bool {
        matches!(self, Self::TypeNumber(_) | Self::TypeRestriction(_) | Self::TypeFloat(_) | Self::TypeTime(_))
    }

    /// The storage width in bits, or 0 when the type does not declare
    /// one. `TypeFloat` carries its width indirectly in the DPT encoding;
    /// the encodings supported by the runtime are resolved here so image
    /// construction can retain their product defaults as well as patching
    /// explicitly configured values. `TypeNone`/`TypePicture`
    /// occupy no parameter memory a download patches. Callers treat 0 as
    /// "byte-aligned, size known only from the value itself".
    pub fn size_bits(&self) -> u16 {
        match self {
            Self::TypeNumber(n) => u16::from(n.size_in_bit),
            Self::TypeRestriction(r) => r.size_in_bit as u16,
            Self::TypeText(t) => t.size_in_bit as u16,
            Self::TypeColor(color) => color.space.size_bits(),
            Self::TypeIpAddress(address) => address.version.size_bits(),
            Self::TypeTime(time) => u16::from(time.size_in_bit),
            Self::TypeFloat(f) if f.encoding.starts_with("DPT 9") => 16,
            Self::TypeFloat(f) if f.encoding.starts_with("DPT 14") => 32,
            Self::TypeFloat(f) if f.encoding == "IEEE-754 Single" => 32,
            Self::TypeFloat(f) if f.encoding == "IEEE-754 Double" => 64,
            // TODO: decide whether ETS pads raw data shorter than `MaxSize`
            // in parameter memory; until then its size comes from the value.
            Self::TypeFloat(_) | Self::TypeNone(_) | Self::TypePicture(_) | Self::TypeRawData(_) => 0,
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
    // `Text` is optional in the KNX project schema. Icon-only choices and
    // registration-only sentinel values in vendor products legitimately omit
    // it; a selected language may still supply the visible text later.
    #[serde(rename = "@Text", default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    #[serde(rename = "@Value")]
    pub value: u32,
    /// Encoded payload selected by `Value` when the restriction uses
    /// `Base="BinaryValue"`. Manufacturer Tool uses this for opaque
    /// firmware/version records which are wider than an integer.
    #[serde(rename = "@BinaryValue", skip_serializing_if = "Option::is_none")]
    pub binary_value: Option<String>,
    #[serde(rename = "@Id")]
    pub id: String,
    // Note: DisplayOrder is ETS3-only, removed for ETS5+ compatibility
}

// ============================================================================
// Derived parameter values
// ============================================================================

/// Registration-relevant transformations between editable (`L`) and stored
/// (`R`) parameter references.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParameterCalculations {
    #[serde(rename = "ParameterCalculation", default)]
    pub calculations: Vec<ParameterCalculation>,
}

/// One bidirectional Manufacturer Tool parameter transformation.
///
/// Commissioning evaluates `LRTransformation`: it derives the right-hand
/// storage values from the left-hand values edited in ETS. `RLTransformation`
/// is retained because an editor needs it when reconstructing controls from
/// stored values, but it does not contribute to a download image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterCalculation {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Language")]
    pub language: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
    #[serde(rename = "RLTransformation", skip_serializing_if = "Option::is_none")]
    pub rl_transformation: Option<String>,
    #[serde(rename = "LRTransformation", skip_serializing_if = "Option::is_none")]
    pub lr_transformation: Option<String>,
    #[serde(rename = "LParameters")]
    pub left_parameters: CalculationParameters,
    #[serde(rename = "RParameters")]
    pub right_parameters: CalculationParameters,
    #[serde(rename = "@RLTransformationFunc", skip_serializing_if = "Option::is_none")]
    pub rl_transformation_func: Option<String>,
    #[serde(rename = "@RLTransformationParameters", skip_serializing_if = "Option::is_none")]
    pub rl_transformation_parameters: Option<String>,
    #[serde(rename = "@LRTransformationFunc", skip_serializing_if = "Option::is_none")]
    pub lr_transformation_func: Option<String>,
    #[serde(rename = "@LRTransformationParameters", skip_serializing_if = "Option::is_none")]
    pub lr_transformation_parameters: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CalculationParameters {
    #[serde(rename = "ParameterRefRef", default)]
    pub parameters: Vec<CalculationParameterRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalculationParameterRef {
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    #[serde(rename = "@AliasName", skip_serializing_if = "Option::is_none")]
    pub alias_name: Option<String>,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
}

/// Product-defined validation hooks. Their function implementation lives in
/// Manufacturer Tool/ETS rather than in the application XML, so consumers
/// must reject them unless they explicitly provide the named function.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParameterValidations {
    #[serde(rename = "ParameterValidation", default)]
    pub validations: Vec<ParameterValidation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterValidation {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
    #[serde(rename = "@ValidationFunc")]
    pub validation_func: String,
    #[serde(rename = "@ValidationParameters", skip_serializing_if = "Option::is_none")]
    pub validation_parameters: Option<String>,
    #[serde(rename = "Parameters")]
    pub parameters: CalculationParameters,
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

/// Raw binary parameter type; values are hex-encoded bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeRawData {
    #[serde(rename = "@MaxSize")]
    pub max_size: u32,
}

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
    #[serde(rename = "@Version", default)]
    pub version: IpAddressVersion,
}

/// Address family declared by an ETS IP-address parameter; omission means IPv4.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpAddressVersion {
    #[default]
    #[serde(rename = "IPv4")]
    Ipv4,
    #[serde(rename = "IPv6")]
    Ipv6,
}

impl IpAddressVersion {
    pub const fn size_bits(self) -> u16 {
        match self {
            Self::Ipv4 => 32,
            Self::Ipv6 => 128,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        }
    }
}

impl TypeIpAddress {
    /// Decode the parameter's textual address into network-order octets.
    /// Family mismatches and abbreviated/non-address spellings fail closed.
    pub fn decode_value(&self, value: &str) -> Option<Vec<u8>> {
        match self.version {
            IpAddressVersion::Ipv4 => {
                value.parse::<core::net::Ipv4Addr>().ok().map(|address| address.octets().to_vec())
            }
            IpAddressVersion::Ipv6 => {
                value.parse::<core::net::Ipv6Addr>().ok().map(|address| address.octets().to_vec())
            }
        }
    }
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
    pub unit: TimeUnit,
    #[serde(rename = "@minInclusive")]
    pub min_inclusive: i64,
    #[serde(rename = "@maxInclusive")]
    pub max_inclusive: i64,
    #[serde(rename = "@UIHint", skip_serializing_if = "Option::is_none")]
    pub ui_hint: Option<String>,
}

/// Unit and display grouping of an ETS time parameter.
///
/// ETS stores the parameter value as an integer count in the basis returned by
/// [`Self::value_unit`]. The `Packed*` variants select a composite editor
/// presentation; they do not introduce BCD or a second bit-field encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TimeUnit {
    /// Whole hours.
    Hours,
    /// Whole minutes.
    Minutes,
    /// Whole seconds.
    Seconds,
    /// Units of 100 milliseconds.
    HundredMilliseconds,
    /// Units of 10 milliseconds.
    TenMilliseconds,
    /// Whole milliseconds.
    Milliseconds,
    /// Milliseconds displayed as seconds plus milliseconds.
    PackedSecondsAndMilliseconds,
    /// Seconds displayed as days, hours, minutes, and seconds.
    PackedDaysHoursMinutesAndSeconds,
    /// Milliseconds displayed as minutes, seconds, and milliseconds.
    PackedMinutesSecondsAndMilliseconds,
}

impl TimeUnit {
    /// Short unit for the integer stored in the product and project files.
    pub const fn value_unit(self) -> &'static str {
        match self {
            Self::Hours => "h",
            Self::Minutes => "min",
            Self::Seconds | Self::PackedDaysHoursMinutesAndSeconds => "s",
            Self::HundredMilliseconds => "100 ms",
            Self::TenMilliseconds => "10 ms",
            Self::Milliseconds | Self::PackedSecondsAndMilliseconds | Self::PackedMinutesSecondsAndMilliseconds => "ms",
        }
    }

    /// Exact spelling used by the KNX XML schema.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hours => "Hours",
            Self::Minutes => "Minutes",
            Self::Seconds => "Seconds",
            Self::HundredMilliseconds => "HundredMilliseconds",
            Self::TenMilliseconds => "TenMilliseconds",
            Self::Milliseconds => "Milliseconds",
            Self::PackedSecondsAndMilliseconds => "PackedSecondsAndMilliseconds",
            Self::PackedDaysHoursMinutesAndSeconds => "PackedDaysHoursMinutesAndSeconds",
            Self::PackedMinutesSecondsAndMilliseconds => "PackedMinutesSecondsAndMilliseconds",
        }
    }
}

impl std::fmt::Display for TimeUnit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TypeTime {
    /// Whether an integer is both in the product's range and representable by
    /// its declared storage width.
    pub fn accepts_value(&self, value: i64) -> bool {
        if value < self.min_inclusive || value > self.max_inclusive {
            return false;
        }

        let Ok(raw) = u64::try_from(value) else { return false };
        let size_bits = u32::from(self.size_in_bit);

        size_bits > 0 && size_bits <= 64 && (size_bits == 64 || raw < (1u64 << size_bits))
    }

    /// Encode the canonical ETS integer into its big-endian parameter-memory
    /// representation.
    pub fn encode_value(&self, value: i64) -> Option<Vec<u8>> {
        if !self.accepts_value(value) {
            return None;
        }

        let raw = u64::try_from(value).ok()?;
        let width = usize::from(self.size_in_bit.div_ceil(8));

        Some(raw.to_be_bytes()[8 - width..].to_vec())
    }
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
    fn ip_address_version_selects_the_width_and_network_octets() {
        for (version, value, width, bytes) in [
            ("", "192.168.1.135", 32, vec![192, 168, 1, 135]),
            (" Version=\"IPv4\"", "255.255.255.0", 32, vec![255, 255, 255, 0]),
            (" Version=\"IPv6\"", "2001:db8:abcd::1234", 128, vec![
                0x20, 1, 0x0d, 0xb8, 0xab, 0xcd, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34,
            ]),
        ] {
            let xml = format!(
                r#"<ParameterType Id="PT-IP" Name="Address"><TypeIPAddress AddressType="HostAddress"{version}/></ParameterType>"#
            );
            let parameter: ParameterType = quick_xml::de::from_str(&xml).expect("IP type parses");
            assert_eq!(parameter.type_def.size_bits(), width);
            let ParameterTypeDef::TypeIpAddress(address) = parameter.type_def else { panic!("IP address type") };
            assert_eq!(address.decode_value(value), Some(bytes));
            assert_eq!(address.decode_value("invalid-address"), None);
            assert_eq!(address.decode_value(if width == 32 { "::1" } else { "127.0.0.1" }), None);
        }

        assert!(quick_xml::de::from_str::<ParameterType>(
            r#"<ParameterType Id="PT-IP" Name="Address"><TypeIPAddress AddressType="HostAddress" Version="Future"/></ParameterType>"#
        ).is_err());
    }

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
        assert_eq!(time.unit, TimeUnit::PackedDaysHoursMinutesAndSeconds);
        assert_eq!(time.ui_hint.as_deref(), Some("Time_hhmmss"));
    }

    #[test]
    fn type_time_encodes_the_ets_integer_in_its_declared_width() {
        let scalar = TypeTime {
            size_in_bit: 16,
            unit: TimeUnit::Minutes,
            min_inclusive: 0,
            max_inclusive: 65_535,
            ui_hint: None,
        };
        let packed = TypeTime {
            size_in_bit: 24,
            unit: TimeUnit::PackedDaysHoursMinutesAndSeconds,
            min_inclusive: 0,
            max_inclusive: 691_199,
            ui_hint: Some("Time_dhhmmss".to_string()),
        };

        assert_eq!(scalar.encode_value(0x1234), Some(vec![0x12, 0x34]));
        assert_eq!(packed.encode_value(86_400), Some(vec![0x01, 0x51, 0x80]));
        assert_eq!(packed.unit.value_unit(), "s");

        assert_eq!(scalar.encode_value(-1), None);
        assert_eq!(scalar.encode_value(65_536), None);
        assert_eq!(packed.encode_value(691_200), None);
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
        assert_eq!(
            ParameterTypeDef::TypeFloat(TypeFloat {
                encoding: "IEEE-754 Double".to_string(),
                min_inclusive: f64::MIN,
                max_inclusive: f64::MAX,
            })
            .size_bits(),
            64
        );
    }

    #[test]
    fn restriction_enumeration_may_omit_text() {
        let parameter: ParameterType = quick_xml::de::from_str(
            r#"<ParameterType Id="M-0083_A-1_PT-MODE" Name="Mode"><TypeRestriction Base="Value" SizeInBit="2"><Enumeration Icon="Position" Value="2" Id="M-0083_A-1_PT-MODE_EN-2" /></TypeRestriction></ParameterType>"#,
        )
        .expect("icon-only enumeration parses");
        let ParameterTypeDef::TypeRestriction(restriction) = parameter.type_def else {
            panic!("expected TypeRestriction");
        };

        assert_eq!(restriction.enumerations[0].text, "");
        let serialized = quick_xml::se::to_string(&restriction.enumerations[0]).expect("enumeration serializes");
        assert!(!serialized.contains("Text="));
    }

    #[test]
    fn binary_restriction_preserves_the_enumeration_payload() {
        let parameter: ParameterType = quick_xml::de::from_str(
            r#"<ParameterType Id="PT-HWT" Name="Hardware"><TypeRestriction Base="BinaryValue" SizeInBit="48"><Enumeration Text="HWT" Value="0" Id="PT-HWT_EN-0" BinaryValue="AIMAAAMo" /></TypeRestriction></ParameterType>"#,
        )
        .expect("binary restriction parses");
        let ParameterTypeDef::TypeRestriction(restriction) = parameter.type_def else {
            panic!("expected TypeRestriction")
        };

        assert_eq!(restriction.enumerations[0].binary_value.as_deref(), Some("AIMAAAMo"));
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
    /// Module argument added to `offset`, as for [`MemoryLocation`]; each
    /// module instance then owns its own slice of the property.
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
