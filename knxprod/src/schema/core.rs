//! Core KNX schema types: MaskFamily, root elements, ApplicationProgram.

use serde::{Deserialize, Serialize};

use super::dynamic::DynamicSection;
use super::languages::Languages;
use super::modules::ModuleDefs;
use super::static_section::StaticSection;

// ============================================================================
// Mask Version Configuration
// ============================================================================

/// Configuration for different KNX mask versions.
///
/// Different masks have different memory models, load procedures, and features.
/// This enum captures the mask-specific behavior needed for MTXML generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskFamily {
    /// System 7 masks (0701, 0705, 2705, 5705)
    /// - Absolute memory segments
    /// - ProductProcedure load style
    /// - ComObject indices start at 0
    System7,
    /// System B masks (07B0, 27B0, 57B0)
    /// - Relative memory segments with load state machines
    /// - MergedProcedure load style
    /// - ComObject indices start at 1
    /// - Generates address/association tables
    SystemB,
    /// BIM masks (0912, 091A)
    /// - Absolute memory segments
    /// - DefaultProcedure load style
    /// - No ComObject table
    Bim,
    /// BIM M masks (0920, 2920)
    /// - Absolute memory segments
    /// - MergedProcedure load style
    /// - No ComObject table
    BimM,
}

impl MaskFamily {
    /// Determine mask family from mask version ID
    pub fn from_mask_version(mask: u16) -> Self {
        match mask {
            0x0701 | 0x0705 | 0x2705 | 0x5705 | 0x0700 => MaskFamily::System7,
            0x07B0 | 0x17B0 | 0x27B0 | 0x57B0 => MaskFamily::SystemB,
            0x0912 | 0x091A => MaskFamily::Bim,
            0x0920 | 0x2920 => MaskFamily::BimM,
            // Default to SystemB for unknown masks with 'B0' suffix
            m if (m & 0x00FF) == 0x00B0 => MaskFamily::SystemB,
            // Default to System7 for other unknown masks
            _ => MaskFamily::System7,
        }
    }

    /// Get the load procedure style for this mask family
    pub fn load_procedure_style(&self) -> &'static str {
        match self {
            MaskFamily::System7 => "ProductProcedure",
            MaskFamily::SystemB => "MergedProcedure",
            MaskFamily::Bim => "DefaultProcedure",
            MaskFamily::BimM => "MergedProcedure",
        }
    }

    /// Get the data segment type for this mask family
    pub fn data_segment_type(&self) -> DataSegmentType {
        match self {
            MaskFamily::System7 | MaskFamily::Bim | MaskFamily::BimM => DataSegmentType::Absolute,
            MaskFamily::SystemB => DataSegmentType::Relative,
        }
    }

    /// Get the starting index for communication objects.
    /// Always 0 - the index in the struct is the index in the XML.
    pub fn com_object_start_index(&self) -> u16 {
        0
    }

    /// Whether this mask family uses a ComObject table
    pub fn has_com_object_table(&self) -> bool {
        match self {
            MaskFamily::System7 | MaskFamily::SystemB => true,
            MaskFamily::Bim | MaskFamily::BimM => false,
        }
    }

    /// Whether this mask family generates address/association tables
    pub fn generates_address_tables(&self) -> bool {
        matches!(self, MaskFamily::SystemB | MaskFamily::System7)
    }
}

/// Type of data segment used by the mask
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

/// Manufacturer element containing application programs
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manufacturer {
    #[serde(rename = "@RefId")]
    pub ref_id: String,

    #[serde(rename = "ApplicationPrograms")]
    pub application_programs: ApplicationPrograms,
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

    #[serde(rename = "Static")]
    pub static_section: StaticSection,
    /// Module definitions - reusable templates for parameters and communication objects.
    /// Note: This is placed at ApplicationProgram level, between Static and Dynamic.
    #[serde(rename = "ModuleDefs", skip_serializing_if = "Option::is_none")]
    pub module_defs: Option<ModuleDefs>,
    #[serde(rename = "Dynamic", skip_serializing_if = "Option::is_none")]
    pub dynamic: Option<DynamicSection>,
    /// Language translations for multi-language support.
    /// Contains translations for parameter names, enum values, and comm object texts.
    #[serde(rename = "Languages", skip_serializing_if = "Option::is_none")]
    pub languages: Option<Languages>,
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
            static_section: StaticSection::default(),
            module_defs: None,
            dynamic: None,
            languages: None,
        }
    }
}
