//! Catalog MTXML schema types.

use serde::{Deserialize, Serialize};

// ============================================================================
// Catalog MTXML Schema Types
// ============================================================================

/// Root element for Catalog MTXML files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "KNX")]
pub struct CatalogKnx {
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
    pub manufacturer_data: CatalogManufacturerData,
}

impl Default for CatalogKnx {
    fn default() -> Self {
        Self {
            xmlns_xsi: "http://www.w3.org/2001/XMLSchema-instance".to_string(),
            xmlns_xsd: "http://www.w3.org/2001/XMLSchema".to_string(),
            created_by: "zweidraehte".to_string(),
            tool_version: "0.1.0".to_string(),
            xmlns: "http://knx.org/xml/project/23".to_string(),
            manufacturer_data: CatalogManufacturerData::default(),
        }
    }
}

/// ManufacturerData wrapper for Catalog files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CatalogManufacturerData {
    #[serde(rename = "Manufacturer")]
    pub manufacturer: CatalogManufacturer,
}

/// Manufacturer element containing Catalog definitions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CatalogManufacturer {
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    #[serde(rename = "Catalog")]
    pub catalog: Catalog,
}

/// Catalog container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(rename = "CatalogSection", default)]
    pub catalog_sections: Vec<CatalogSection>,
}

/// Catalog section (category) containing items and nested subsections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogSection {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Number")]
    pub number: String,
    #[serde(rename = "@DefaultLanguage")]
    pub default_language: String,
    #[serde(rename = "CatalogItem", default, skip_serializing_if = "Vec::is_empty")]
    pub catalog_items: Vec<CatalogItem>,
    #[serde(rename = "CatalogSection", default, skip_serializing_if = "Vec::is_empty")]
    pub subsections: Vec<CatalogSection>,
}

impl Default for CatalogSection {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            number: "1".to_string(),
            default_language: "en-US".to_string(),
            catalog_items: vec![],
            subsections: vec![],
        }
    }
}

/// Catalog item linking product to hardware/application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogItem {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Number")]
    pub number: String,
    #[serde(rename = "@ProductRefId")]
    pub product_ref_id: String,
    #[serde(rename = "@Hardware2ProgramRefId")]
    pub hardware2program_ref_id: String,
    #[serde(rename = "@DefaultLanguage")]
    pub default_language: String,
}

impl Default for CatalogItem {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            number: "1".to_string(),
            product_ref_id: String::new(),
            hardware2program_ref_id: String::new(),
            default_language: "en-US".to_string(),
        }
    }
}
