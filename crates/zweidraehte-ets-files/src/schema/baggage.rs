//! `Baggages.xml` document model shared by generators and readers.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename = "KNX")]
pub struct BaggagesKnx {
    #[serde(rename = "@xmlns:xsi", default, skip_serializing_if = "String::is_empty")]
    pub xmlns_xsi: String,
    #[serde(rename = "@xmlns:xsd", default, skip_serializing_if = "String::is_empty")]
    pub xmlns_xsd: String,
    #[serde(rename = "@CreatedBy", default, skip_serializing_if = "String::is_empty")]
    pub created_by: String,
    #[serde(rename = "@ToolVersion", default, skip_serializing_if = "String::is_empty")]
    pub tool_version: String,
    #[serde(rename = "@xmlns", default, skip_serializing_if = "String::is_empty")]
    pub xmlns: String,
    #[serde(rename = "ManufacturerData")]
    pub manufacturer_data: BaggagesManufacturerData,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaggagesManufacturerData {
    #[serde(rename = "Manufacturer")]
    pub manufacturer: BaggagesManufacturer,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaggagesManufacturer {
    #[serde(rename = "@RefId", default, skip_serializing_if = "String::is_empty")]
    pub ref_id: String,
    #[serde(rename = "Baggages", default, skip_serializing_if = "Option::is_none")]
    pub baggages: Option<BaggagesList>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaggagesList {
    #[serde(rename = "Baggage", default)]
    pub items: Vec<BaggageXmlEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaggageXmlEntry {
    #[serde(rename = "@TargetPath", default)]
    pub target_path: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "FileInfo", default, skip_serializing_if = "Option::is_none")]
    pub file_info: Option<BaggageFileInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaggageFileInfo {
    #[serde(rename = "@TimeInfo")]
    pub time_info: String,
}
