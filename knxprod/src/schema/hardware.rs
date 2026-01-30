//! Hardware MTXML schema types.

use serde::{Deserialize, Serialize};

// ============================================================================
// Hardware MTXML Schema Types
// ============================================================================

/// Root element for Hardware MTXML files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "KNX")]
pub struct HardwareKnx {
    #[serde(rename = "@xmlns:xsi")]
    pub xmlns_xsi: String,
    #[serde(rename = "@xmlns:xsd")]
    pub xmlns_xsd: String,
    #[serde(rename = "@CreatedBy")]
    pub created_by: String,
    #[serde(rename = "@ToolVersion")]
    pub tool_version: String,
    #[serde(rename = "@xmlns")]
    pub xmlns: String,
    #[serde(rename = "ManufacturerData")]
    pub manufacturer_data: HardwareManufacturerData,
}

impl Default for HardwareKnx {
    fn default() -> Self {
        Self {
            xmlns_xsi: "http://www.w3.org/2001/XMLSchema-instance".to_string(),
            xmlns_xsd: "http://www.w3.org/2001/XMLSchema".to_string(),
            created_by: "zweidraehte".to_string(),
            tool_version: "0.1.0".to_string(),
            xmlns: "http://knx.org/xml/project/23".to_string(),
            manufacturer_data: HardwareManufacturerData::default(),
        }
    }
}

/// ManufacturerData wrapper for Hardware files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardwareManufacturerData {
    #[serde(rename = "Manufacturer")]
    pub manufacturer: HardwareManufacturer,
}

/// Manufacturer element containing Hardware definitions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardwareManufacturer {
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    #[serde(rename = "Hardware")]
    pub hardware: HardwareContainer,
}

/// Container for Hardware elements.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardwareContainer {
    #[serde(rename = "Hardware")]
    pub hardware: Hardware,
}

/// Hardware definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hardware {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@SerialNumber")]
    pub serial_number: String,
    #[serde(rename = "@VersionNumber")]
    pub version_number: u8,
    #[serde(rename = "@HasIndividualAddress")]
    pub has_individual_address: bool,
    #[serde(rename = "@HasApplicationProgram")]
    pub has_application_program: bool,
    #[serde(rename = "Products")]
    pub products: Products,
    #[serde(rename = "Hardware2Programs")]
    pub hardware2programs: Hardware2Programs,
}

impl Default for Hardware {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            serial_number: String::new(),
            version_number: 1,
            has_individual_address: true,
            has_application_program: true,
            products: Products::default(),
            hardware2programs: Hardware2Programs::default(),
        }
    }
}

/// Container for Product elements.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Products {
    #[serde(rename = "Product")]
    pub product: Product,
}

/// Product definition within Hardware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Product {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Text")]
    pub text: String,
    #[serde(rename = "@OrderNumber")]
    pub order_number: String,
    #[serde(rename = "@IsRailMounted")]
    pub is_rail_mounted: bool,
    #[serde(rename = "@DefaultLanguage")]
    pub default_language: String,
}

impl Default for Product {
    fn default() -> Self {
        Self {
            id: String::new(),
            text: String::new(),
            order_number: String::new(),
            is_rail_mounted: false,
            default_language: "en-US".to_string(),
        }
    }
}

/// Container for Hardware2Program elements.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hardware2Programs {
    #[serde(rename = "Hardware2Program")]
    pub hardware2program: Hardware2Program,
}

/// Links Hardware to ApplicationProgram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hardware2Program {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@MediumTypes")]
    pub medium_types: String,
    #[serde(rename = "ApplicationProgramRef")]
    pub application_program_ref: ApplicationProgramRef,
}

impl Default for Hardware2Program {
    fn default() -> Self {
        Self {
            id: String::new(),
            medium_types: "MT-0".to_string(),
            application_program_ref: ApplicationProgramRef::default(),
        }
    }
}

/// Reference to an ApplicationProgram.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplicationProgramRef {
    #[serde(rename = "@RefId")]
    pub ref_id: String,
}
