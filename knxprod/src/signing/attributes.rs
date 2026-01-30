//! Registration-relevant attribute definitions.
//!
//! These definitions match the .NET Information.cs class from Knx.Ets.Xml.RegistrationRelevanceInformation.
//! Each element type has a set of attributes that are relevant for computing hashes.

use std::io::{self, Write};

use super::binary_writer::{
    parse_bool, write_dotnet_bool, write_dotnet_byte_str, write_dotnet_int32_str,
    write_dotnet_string, write_dotnet_uint16_str, write_dotnet_uint32_str,
};

/// Type of an attribute value for serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrType {
    /// String value (length-prefixed UTF-8)
    String,
    /// Boolean value (single byte)
    Bool,
    /// Unsigned 32-bit integer (4 bytes little-endian)
    UInt32,
    /// Signed 32-bit integer (4 bytes little-endian)
    Int32,
    /// Unsigned 16-bit integer (2 bytes little-endian)
    UInt16,
    /// Unsigned 8-bit integer (1 byte)
    Byte,
    /// Application Program ID with normalization (removes 5 chars at position 16)
    ApplProgId,
}

/// Definition of a registration-relevant attribute.
#[derive(Debug, Clone)]
pub struct AttrDef {
    /// XML attribute name (e.g., "Id", "SerialNumber")
    pub xml_name: &'static str,
    /// Short name used in serialization (e.g., "I", "SN")
    pub short_name: &'static str,
    /// Type of the attribute value
    pub attr_type: AttrType,
    /// Default value if attribute is not present (None means null)
    pub default: Option<&'static str>,
}

impl AttrDef {
    const fn new(
        xml_name: &'static str,
        short_name: &'static str,
        attr_type: AttrType,
        default: Option<&'static str>,
    ) -> Self {
        Self {
            xml_name,
            short_name,
            attr_type,
            default,
        }
    }
}

/// Hardware element attributes (sorted alphabetically by xml_name).
pub const HARDWARE_ATTRS: &[AttrDef] = &[
    AttrDef::new("HasApplicationProgram", "HAP", AttrType::Bool, None),
    AttrDef::new("HasApplicationProgram2", "HAP2", AttrType::Bool, Some("0")),
    AttrDef::new("HasIndividualAddress", "HIA", AttrType::Bool, None),
    AttrDef::new("Id", "I", AttrType::String, None),
    AttrDef::new("IsAccessory", "A", AttrType::Bool, Some("0")),
    AttrDef::new("IsCable", "CA", AttrType::Bool, Some("0")),
    AttrDef::new("IsChoke", "CH", AttrType::Bool, Some("0")),
    AttrDef::new("IsCoupler", "CO", AttrType::Bool, Some("0")),
    AttrDef::new("IsIPEnabled", "IP", AttrType::Bool, Some("0")),
    AttrDef::new("IsPowerLineRepeater", "PR", AttrType::Bool, Some("0")),
    AttrDef::new("IsPowerLineSignalFilter", "PF", AttrType::Bool, Some("0")),
    AttrDef::new("IsPowerSupply", "PS", AttrType::Bool, Some("0")),
    AttrDef::new("IsRFRetransmitter", "RFR", AttrType::Bool, Some("0")),
    AttrDef::new("OriginalManufacturer", "OM", AttrType::String, None),
    AttrDef::new("RFRxCapabilities", "Rx", AttrType::String, None),
    AttrDef::new("RFTxCapabilities", "Tx", AttrType::String, None),
    AttrDef::new("SerialNumber", "SN", AttrType::String, None),
    AttrDef::new("VersionNumber", "VN", AttrType::UInt32, None),
];

/// Product element attributes (sorted alphabetically by xml_name).
pub const PRODUCT_ATTRS: &[AttrDef] = &[
    AttrDef::new("Id", "I", AttrType::String, None),
    AttrDef::new("OrderNumber", "O", AttrType::String, None),
];

/// RegistrationInfo element attributes (sorted alphabetically by xml_name).
pub const REGISTRATION_INFO_ATTRS: &[AttrDef] = &[
    AttrDef::new("OriginalRegistrationNumber", "O", AttrType::String, None),
    AttrDef::new("RegistrationDate", "D", AttrType::String, None),
    AttrDef::new("RegistrationNumber", "N", AttrType::String, None),
    AttrDef::new("RegistrationStatus", "ST", AttrType::String, None),
];

/// Hardware2Program element attributes (sorted alphabetically by xml_name).
pub const HARDWARE2PROGRAM_ATTRS: &[AttrDef] = &[
    AttrDef::new("CheckSums", "C", AttrType::String, None),
    AttrDef::new("CouplerCapabilities", "CC", AttrType::String, None),
    AttrDef::new("LoadedImage", "L", AttrType::String, None),
];

/// ApplicationProgram element attributes (sorted alphabetically by xml_name).
pub const APPLICATION_PROGRAM_ATTRS: &[AttrDef] = &[
    AttrDef::new("AdditionalAddressesCount", "AAC", AttrType::Int32, Some("0")),
    AttrDef::new("ApplicationNumber", "AN", AttrType::UInt16, None),
    AttrDef::new("ApplicationVersion", "AV", AttrType::Byte, None),
    AttrDef::new("ConvertedFromPreEts4Data", "CVETS", AttrType::Bool, Some("0")),
    AttrDef::new("DynamicTableManagement", "DTM", AttrType::Bool, None),
    AttrDef::new("IPConfig", "IP", AttrType::String, Some("Tool")),
    AttrDef::new("Id", "I", AttrType::ApplProgId, None),
    AttrDef::new("IsSecureEnabled", "ISE", AttrType::Bool, None),
    AttrDef::new("Linkable", "L", AttrType::Bool, None),
    AttrDef::new("LoadProcedureStyle", "LPS", AttrType::String, None),
    AttrDef::new("MaskVersion", "MV", AttrType::String, None),
    AttrDef::new(
        "MaxSecurityGroupKeyTableEntries",
        "MSGK",
        AttrType::UInt16,
        Some("0"),
    ),
    AttrDef::new(
        "MaxSecurityIndividualAddressEntries",
        "MSIAE",
        AttrType::UInt16,
        Some("0"),
    ),
    AttrDef::new(
        "MaxSecurityP2PKeyTableEntries",
        "MSP2",
        AttrType::UInt16,
        Some("0"),
    ),
    AttrDef::new(
        "MaxSecurityProxyGroupKeyTableEntries",
        "MSPGK",
        AttrType::UInt16,
        Some("0"),
    ),
    AttrDef::new(
        "MaxSecurityProxyIndividualAddressTableEntries",
        "MSPIA",
        AttrType::UInt16,
        Some("0"),
    ),
    AttrDef::new("MaxTunnelingUserEntries", "MTUE", AttrType::UInt16, Some("0")),
    AttrDef::new("MaxUserEntries", "MUE", AttrType::UInt16, Some("0")),
    AttrDef::new("OriginalManufacturer", "OEM", AttrType::String, None),
    AttrDef::new("PeiType", "PT", AttrType::Byte, None),
    AttrDef::new("PreEts4Style", "PES", AttrType::Bool, Some("0")),
    AttrDef::new("ProgramType", "PrT", AttrType::String, None),
    AttrDef::new("ReplacesVersions", "RV", AttrType::String, None),
    AttrDef::new("TunnelingAddressIndices", "TAI", AttrType::String, None),
];

/// Normalize an ApplicationProgram ID by removing 5 characters at position 16.
///
/// Example: "M-00FA_A-1000-01-7957" becomes "M-00FA_A-1000-01"
///
/// This matches .NET ApplProgIdAttributeInfo.NormalizeId().
pub fn normalize_appl_prog_id(id: &str) -> String {
    if id.len() >= 21 {
        format!("{}{}", &id[..16], &id[21..])
    } else {
        id.to_string()
    }
}

/// Write a single attribute in .NET BinaryWriter format.
///
/// Format: short_name + value (type-dependent encoding)
pub fn write_attribute<W: Write>(
    writer: &mut W,
    attr: &AttrDef,
    value: Option<&str>,
) -> io::Result<()> {
    // Write short name
    write_dotnet_string(writer, Some(attr.short_name))?;

    // Get effective value (attribute value or default)
    let effective_value = value.or(attr.default);

    match attr.attr_type {
        AttrType::String => {
            write_dotnet_string(writer, effective_value)?;
        }
        AttrType::ApplProgId => {
            if let Some(v) = effective_value {
                let normalized = normalize_appl_prog_id(v);
                write_dotnet_string(writer, Some(&normalized))?;
            } else {
                write_dotnet_string(writer, None)?;
            }
        }
        AttrType::Bool => {
            if let Some(v) = effective_value {
                write_dotnet_bool(writer, parse_bool(v))?;
            } else {
                // Null bool is encoded as the null string marker
                write_dotnet_string(writer, None)?;
            }
        }
        AttrType::UInt32 => {
            if let Some(v) = effective_value {
                write_dotnet_uint32_str(writer, v)?;
            } else {
                write_dotnet_string(writer, None)?;
            }
        }
        AttrType::Int32 => {
            if let Some(v) = effective_value {
                write_dotnet_int32_str(writer, v)?;
            } else {
                write_dotnet_string(writer, None)?;
            }
        }
        AttrType::UInt16 => {
            if let Some(v) = effective_value {
                write_dotnet_uint16_str(writer, v)?;
            } else {
                write_dotnet_string(writer, None)?;
            }
        }
        AttrType::Byte => {
            if let Some(v) = effective_value {
                write_dotnet_byte_str(writer, v)?;
            } else {
                write_dotnet_string(writer, None)?;
            }
        }
    }

    Ok(())
}

/// Trait for getting attribute values from an element.
pub trait AttributeProvider {
    /// Get the value of an attribute by XML name.
    fn get_attribute(&self, name: &str) -> Option<&str>;
}

/// Serialize an element's registration-relevant attributes to bytes.
pub fn serialize_element<W: Write, E: AttributeProvider>(
    writer: &mut W,
    element: &E,
    attr_defs: &[AttrDef],
) -> io::Result<()> {
    for attr in attr_defs {
        let value = element.get_attribute(attr.xml_name);
        write_attribute(writer, attr, value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_appl_prog_id() {
        assert_eq!(
            normalize_appl_prog_id("M-00FA_A-1000-01-7957"),
            "M-00FA_A-1000-01"
        );
        assert_eq!(
            normalize_appl_prog_id("M-0083_A-009B-14-E59D"),
            "M-0083_A-009B-14"
        );
        // Short IDs are returned as-is
        assert_eq!(normalize_appl_prog_id("M-00FA_A-1000-01"), "M-00FA_A-1000-01");
        assert_eq!(normalize_appl_prog_id("short"), "short");
    }

    #[test]
    fn test_hardware_attrs_sorted() {
        // Verify attributes are sorted alphabetically
        let mut prev = "";
        for attr in HARDWARE_ATTRS {
            assert!(
                attr.xml_name > prev,
                "HARDWARE_ATTRS not sorted: {} should come before {}",
                prev,
                attr.xml_name
            );
            prev = attr.xml_name;
        }
    }

    #[test]
    fn test_product_attrs_sorted() {
        let mut prev = "";
        for attr in PRODUCT_ATTRS {
            assert!(
                attr.xml_name > prev,
                "PRODUCT_ATTRS not sorted: {} should come before {}",
                prev,
                attr.xml_name
            );
            prev = attr.xml_name;
        }
    }

    #[test]
    fn test_application_program_attrs_sorted() {
        let mut prev = "";
        for attr in APPLICATION_PROGRAM_ATTRS {
            assert!(
                attr.xml_name > prev,
                "APPLICATION_PROGRAM_ATTRS not sorted: {} should come before {}",
                prev,
                attr.xml_name
            );
            prev = attr.xml_name;
        }
    }
}
