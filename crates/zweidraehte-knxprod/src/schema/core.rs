//! Core KNX schema types: root elements, ApplicationProgram, MTXML generation helpers.

use serde::{Deserialize, Serialize};

use super::dynamic::DynamicSection;
use super::languages::Languages;
use super::modules::ModuleDefs;
use super::static_section::StaticSection;

// Re-export MaskFamily from the stack crate. The enum and
// `from_mask_version()` live in `zweidraehte_device::messages::knx`;
// generation-specific behaviour is added via `MaskFamilyExt` below.
pub use zweidraehte_device::ets::MaskFamily;

// ============================================================================
// Mask Family — MTXML Generation Extensions
// ============================================================================

/// MTXML-generation-specific behaviour for [`MaskFamily`].
///
/// These methods encode knowledge about load procedures, memory segment
/// types, and table generation that is only relevant when producing
/// knxprod / MTXML output.
pub trait MaskFamilyExt {
    /// Get the load procedure style for this mask family.
    fn load_procedure_style(&self) -> &'static str;
    /// Get the data segment type for this mask family.
    fn data_segment_type(&self) -> DataSegmentType;
    /// Get the starting index for communication objects.
    fn com_object_start_index(&self) -> u16;
    /// Whether this mask family uses a ComObject table.
    fn has_com_object_table(&self) -> bool;
    /// Whether this mask family generates address/association tables.
    fn generates_address_tables(&self) -> bool;
}

impl MaskFamilyExt for MaskFamily {
    fn load_procedure_style(&self) -> &'static str {
        match self {
            MaskFamily::System7 => "ProductProcedure",
            MaskFamily::SystemB => "MergedProcedure",
            MaskFamily::Bim => "DefaultProcedure",
            MaskFamily::BimM => "MergedProcedure",
        }
    }

    fn data_segment_type(&self) -> DataSegmentType {
        match self {
            MaskFamily::System7 | MaskFamily::Bim | MaskFamily::BimM => DataSegmentType::Absolute,
            MaskFamily::SystemB => DataSegmentType::Relative,
        }
    }

    fn com_object_start_index(&self) -> u16 {
        0
    }

    fn has_com_object_table(&self) -> bool {
        match self {
            MaskFamily::System7 | MaskFamily::SystemB => true,
            MaskFamily::Bim | MaskFamily::BimM => false,
        }
    }

    fn generates_address_tables(&self) -> bool {
        matches!(self, MaskFamily::SystemB | MaskFamily::System7)
    }
}

/// Type of data segment used by the mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSegmentType {
    /// Absolute memory addresses (System 7, BIM)
    Absolute,
    /// Relative segments with load state machines (System B)
    Relative,
}

// ============================================================================
// Root Elements
// ============================================================================

/// The root KNX element
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "KNX")]
pub struct Knx {
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
    pub manufacturer_data: ManufacturerData,
}

impl Default for Knx {
    fn default() -> Self {
        Self {
            xmlns_xsi: "http://www.w3.org/2001/XMLSchema-instance".to_string(),
            xmlns_xsd: "http://www.w3.org/2001/XMLSchema".to_string(),
            created_by: "zweidraehte".to_string(),
            tool_version: "0.1.0".to_string(),
            xmlns: "http://knx.org/xml/project/23".to_string(),
            manufacturer_data: ManufacturerData::default(),
        }
    }
}

/// ManufacturerData container
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManufacturerData {
    #[serde(rename = "Manufacturer")]
    pub manufacturer: Manufacturer,
}

/// Manufacturer element containing application programs and language translations.
///
/// Per the XSD schema (`ManufacturerData_t`), the child element ordering is:
/// Catalog, ApplicationPrograms, Baggages, Hardware, Languages.
/// Since each MTXML file only contains one of these sections, only
/// `ApplicationPrograms` and `Languages` appear here (in the ApplicationProgram
/// MTXML file).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manufacturer {
    #[serde(rename = "@RefId")]
    pub ref_id: String,

    #[serde(rename = "ApplicationPrograms")]
    pub application_programs: ApplicationPrograms,

    /// Language translations for multi-language support.
    /// Must appear after ApplicationPrograms at the Manufacturer level per XSD.
    #[serde(rename = "Languages", skip_serializing_if = "Option::is_none")]
    pub languages: Option<Languages>,
}

/// Container for ApplicationProgram elements
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplicationPrograms {
    #[serde(rename = "ApplicationProgram")]
    pub programs: Vec<ApplicationProgram>,
}

/// The main ApplicationProgram element
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationProgram {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@ApplicationNumber")]
    pub application_number: u16,
    #[serde(rename = "@ApplicationVersion")]
    pub application_version: u8,
    #[serde(rename = "@ProgramType")]
    pub program_type: String,
    #[serde(rename = "@MaskVersion")]
    pub mask_version: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@LoadProcedureStyle")]
    pub load_procedure_style: String,
    #[serde(rename = "@PeiType")]
    pub pei_type: u8,
    #[serde(rename = "@DefaultLanguage")]
    pub default_language: String,
    #[serde(rename = "@DynamicTableManagement")]
    pub dynamic_table_management: bool,
    #[serde(rename = "@Linkable")]
    pub linkable: bool,
    #[serde(rename = "@MinEtsVersion", skip_serializing_if = "Option::is_none")]
    pub min_ets_version: Option<String>,
    #[serde(rename = "@NonRegRelevantDataVersion", skip_serializing_if = "Option::is_none")]
    pub non_reg_relevant_data_version: Option<u32>,
    #[serde(rename = "@ReplacesVersions", skip_serializing_if = "Option::is_none")]
    pub replaces_versions: Option<String>,
    #[serde(rename = "@Hash", skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(rename = "@AdditionalAddressesCount", skip_serializing_if = "Option::is_none")]
    pub additional_addresses_count: Option<u32>,
    #[serde(rename = "@IPConfig", skip_serializing_if = "Option::is_none")]
    pub ip_config: Option<String>,

    #[serde(rename = "Static")]
    pub static_section: StaticSection,
    /// Module definitions - reusable templates for parameters and communication objects.
    /// Note: This is placed at ApplicationProgram level, between Static and Dynamic.
    #[serde(rename = "ModuleDefs", skip_serializing_if = "Option::is_none")]
    pub module_defs: Option<ModuleDefs>,
    #[serde(rename = "Dynamic", skip_serializing_if = "Option::is_none")]
    pub dynamic: Option<DynamicSection>,
}

impl Default for ApplicationProgram {
    fn default() -> Self {
        Self {
            id: String::new(),
            application_number: 0,
            application_version: 1,
            program_type: "ApplicationProgram".to_string(),
            mask_version: "MV-07B0".to_string(),
            name: "Application".to_string(),
            load_procedure_style: "MergedProcedure".to_string(),
            pei_type: 0,
            default_language: "en-US".to_string(),
            dynamic_table_management: false,
            linkable: false,
            min_ets_version: Some("5.0".to_string()),
            non_reg_relevant_data_version: None,
            replaces_versions: None,
            hash: None,
            additional_addresses_count: None,
            ip_config: None,
            static_section: StaticSection::default(),
            module_defs: None,
            dynamic: None,
        }
    }
}
