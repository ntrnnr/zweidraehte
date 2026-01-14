//! KNX Project XML Schema Types
//!
//! Typed Rust structs matching the KNX project XSD schema for MTXML files.
//! These types are used with serde and quick-xml for proper XML serialization.

use serde::{Serialize, Deserialize};

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

    /// Get the starting index for communication objects
    pub fn com_object_start_index(&self) -> u16 {
        match self {
            MaskFamily::SystemB => 1,
            _ => 0,
        }
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
        matches!(self, MaskFamily::SystemB)
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
            xmlns: "http://knx.org/xml/project/20".to_string(),
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

    #[serde(rename = "Static")]
    pub static_section: StaticSection,
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
            static_section: StaticSection::default(),
            dynamic: None,
        }
    }
}

// ============================================================================
// Static Section
// ============================================================================

/// The Static section containing Code, Parameters, ComObjects, etc.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StaticSection {
    #[serde(rename = "Code", skip_serializing_if = "Option::is_none")]
    pub code: Option<Code>,
    #[serde(rename = "ParameterTypes", skip_serializing_if = "Option::is_none")]
    pub parameter_types: Option<ParameterTypes>,
    #[serde(rename = "Parameters", skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Parameters>,
    #[serde(rename = "ParameterRefs", skip_serializing_if = "Option::is_none")]
    pub parameter_refs: Option<ParameterRefs>,
    #[serde(rename = "ComObjectTable", skip_serializing_if = "Option::is_none")]
    pub com_object_table: Option<ComObjectTable>,
    #[serde(rename = "ComObjectRefs", skip_serializing_if = "Option::is_none")]
    pub com_object_refs: Option<ComObjectRefs>,
    #[serde(rename = "AddressTable", skip_serializing_if = "Option::is_none")]
    pub address_table: Option<AddressTable>,
    #[serde(rename = "AssociationTable", skip_serializing_if = "Option::is_none")]
    pub association_table: Option<AssociationTable>,
    #[serde(rename = "LoadProcedures", skip_serializing_if = "Option::is_none")]
    pub load_procedures: Option<LoadProcedures>,
    #[serde(rename = "Options", skip_serializing_if = "Option::is_none")]
    pub options: Option<Options>,
}

/// Code section containing memory segments
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Code {
    #[serde(rename = "AbsoluteSegment", default, skip_serializing_if = "Vec::is_empty")]
    pub absolute_segments: Vec<AbsoluteSegment>,
    #[serde(rename = "RelativeSegment", default, skip_serializing_if = "Vec::is_empty")]
    pub relative_segments: Vec<RelativeSegment>,
}

/// Absolute memory segment (System 7)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbsoluteSegment {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Size")]
    pub size: u32,
    #[serde(rename = "@Address")]
    pub address: u32,
    #[serde(rename = "@MemoryType", skip_serializing_if = "Option::is_none")]
    pub memory_type: Option<String>,

    #[serde(rename = "Data", skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// Relative memory segment (System B)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelativeSegment {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Size")]
    pub size: u32,
    #[serde(rename = "@LoadStateMachine")]
    pub load_state_machine: u8,
    #[serde(rename = "@Offset")]
    pub offset: u32,

    #[serde(rename = "Data", skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

// ============================================================================
// Parameter Types
// ============================================================================

/// Container for parameter type definitions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParameterTypes {
    #[serde(rename = "ParameterType", default)]
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
    TypeNumber(TypeNumber),
    TypeRestriction(TypeRestriction),
    TypeText(TypeText),
    TypeNone(TypeNone),
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
    Parameter(Parameter),
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
    #[serde(rename = "@Value")]
    pub value: String,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,

    #[serde(rename = "Memory", skip_serializing_if = "Option::is_none")]
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
}

/// A union containing multiple parameters sharing memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Union {
    #[serde(rename = "@SizeInBit")]
    pub size_in_bit: u32,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,

    #[serde(rename = "Memory")]
    pub memory: UnionMemory,
    #[serde(rename = "Parameter", default)]
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

// ============================================================================
// Parameter References
// ============================================================================

/// Container for parameter references
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParameterRefs {
    #[serde(rename = "ParameterRef", default)]
    pub refs: Vec<ParameterRef>,
}

/// Reference to a parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterRef {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
}

// ============================================================================
// Communication Objects
// ============================================================================

/// Container for communication objects
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComObjectTable {
    #[serde(rename = "@Offset", skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    #[serde(rename = "@MaxEntries", skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<u16>,

    #[serde(rename = "ComObject", default)]
    pub objects: Vec<ComObject>,
}

/// A communication object definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComObject {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Text")]
    pub text: String,
    #[serde(rename = "@Number")]
    pub number: u16,
    #[serde(rename = "@FunctionText")]
    pub function_text: String,
    #[serde(rename = "@ObjectSize")]
    pub object_size: String,
    #[serde(rename = "@DatapointType", skip_serializing_if = "Option::is_none")]
    pub datapoint_type: Option<String>,
    #[serde(rename = "@ReadFlag")]
    pub read_flag: EnableFlag,
    #[serde(rename = "@WriteFlag")]
    pub write_flag: EnableFlag,
    #[serde(rename = "@CommunicationFlag")]
    pub communication_flag: EnableFlag,
    #[serde(rename = "@TransmitFlag")]
    pub transmit_flag: EnableFlag,
    #[serde(rename = "@UpdateFlag")]
    pub update_flag: EnableFlag,
    #[serde(rename = "@ReadOnInitFlag")]
    pub read_on_init_flag: EnableFlag,
    #[serde(rename = "@Priority", skip_serializing_if = "Option::is_none")]
    pub priority: Option<ComObjectPriority>,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
}

/// Enable/Disable flag for ComObject flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnableFlag {
    Enabled,
    Disabled,
}

impl From<bool> for EnableFlag {
    fn from(b: bool) -> Self {
        if b { EnableFlag::Enabled } else { EnableFlag::Disabled }
    }
}

/// Communication object priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComObjectPriority {
    Low,
    High,
    Alert,
    System,
}

impl Default for ComObjectPriority {
    fn default() -> Self {
        ComObjectPriority::Low
    }
}

/// Container for communication object references
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComObjectRefs {
    #[serde(rename = "ComObjectRef", default)]
    pub refs: Vec<ComObjectRef>,
}

/// Reference to a communication object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComObjectRef {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    #[serde(rename = "@Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
}

// ============================================================================
// Address and Association Tables
// ============================================================================

/// Address table configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressTable {
    #[serde(rename = "@Offset")]
    pub offset: u32,
    #[serde(rename = "@MaxEntries")]
    pub max_entries: u16,
}

/// Association table configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssociationTable {
    #[serde(rename = "@Offset")]
    pub offset: u32,
    #[serde(rename = "@MaxEntries")]
    pub max_entries: u16,
}

// ============================================================================
// Load Procedures
// ============================================================================

/// Container for load procedures
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoadProcedures {
    #[serde(rename = "LoadProcedure", default)]
    pub procedures: Vec<LoadProcedure>,
}

/// A load procedure containing load control elements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadProcedure {
    #[serde(rename = "@MergeId")]
    pub merge_id: u8,

    #[serde(rename = "$value", default)]
    pub controls: Vec<LoadControl>,
}

/// Load control elements (choice)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum LoadControl {
    LdCtrlRelSegment(LdCtrlRelSegment),
    LdCtrlWriteRelMem(LdCtrlWriteRelMem),
    LdCtrlLoadImageProp(LdCtrlLoadImageProp),
}

/// Relative segment load control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdCtrlRelSegment {
    #[serde(rename = "@AppliesTo")]
    pub applies_to: String,
    #[serde(rename = "@LsmIdx")]
    pub lsm_idx: u8,
    #[serde(rename = "@Size")]
    pub size: u32,
    #[serde(rename = "@Mode")]
    pub mode: u8,
    #[serde(rename = "@Fill")]
    pub fill: u8,
}

/// Write relative memory load control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdCtrlWriteRelMem {
    #[serde(rename = "@AppliesTo")]
    pub applies_to: String,
    #[serde(rename = "@ObjIdx")]
    pub obj_idx: u8,
    #[serde(rename = "@Offset")]
    pub offset: u32,
    #[serde(rename = "@Size")]
    pub size: u32,
    #[serde(rename = "@Verify")]
    pub verify: bool,
}

/// Load image property control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdCtrlLoadImageProp {
    #[serde(rename = "@ObjIdx")]
    pub obj_idx: u8,
    #[serde(rename = "@PropId")]
    pub prop_id: u8,
}

/// Empty options element
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Options {}

// ============================================================================
// Dynamic Section
// ============================================================================

/// The Dynamic section for UI organization
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicSection {
    #[serde(rename = "Channel", default)]
    pub channels: Vec<Channel>,
}

/// A channel in the Dynamic section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Number", skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,

    #[serde(rename = "ParameterBlock", default, skip_serializing_if = "Vec::is_empty")]
    pub parameter_blocks: Vec<ParameterBlock>,
}

/// A parameter block in a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterBlock {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,

    #[serde(rename = "$value", default)]
    pub items: Vec<ParameterBlockItem>,
}

/// Items in a parameter block
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParameterBlockItem {
    #[serde(rename = "ParameterRefRef")]
    ParameterRefRef(ParameterRefRef),
    #[serde(rename = "ComObjectRefRef")]
    ComObjectRefRef(ComObjectRefRef),
    #[serde(rename = "choose")]
    Choose(Choose),
}

/// A choose element for conditional parameter visibility based on a selector value
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "choose")]
pub struct Choose {
    /// Reference to the selector parameter that controls visibility
    #[serde(rename = "@ParamRefId")]
    pub param_ref_id: String,

    #[serde(rename = "when", default)]
    pub whens: Vec<When>,
}

/// A when clause within a choose - shows contained items when test matches
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "when")]
pub struct When {
    /// Test condition - typically a numeric value to match against the selector
    /// Can be: "0", "1", "=1", "!=0", ">5", "0 1 2" (multiple values), etc.
    #[serde(rename = "@test", skip_serializing_if = "Option::is_none")]
    pub test: Option<String>,

    /// Whether this is the default case (when no other test matches)
    #[serde(rename = "@default", skip_serializing_if = "Option::is_none")]
    pub default: Option<bool>,

    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,

    #[serde(rename = "$value", default)]
    pub items: Vec<WhenItem>,
}

/// Items that can appear inside a when clause
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WhenItem {
    #[serde(rename = "ParameterRefRef")]
    ParameterRefRef(ParameterRefRef),
    #[serde(rename = "ComObjectRefRef")]
    ComObjectRefRef(ComObjectRefRef),
    #[serde(rename = "ParameterBlock")]
    ParameterBlock(ParameterBlock),
    #[serde(rename = "choose")]
    Choose(Choose),
}

/// Reference to a parameter reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterRefRef {
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
}

/// Reference to a communication object reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComObjectRefRef {
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert object size in bits to ETS string format
pub fn object_size_to_string(size_bits: u8) -> &'static str {
    match size_bits {
        1 => "1 Bit",
        2 => "2 Bit",
        3 => "3 Bit",
        4 => "4 Bit",
        5 => "5 Bit",
        6 => "6 Bit",
        7 => "7 Bit",
        8 => "1 Byte",
        16 => "2 Bytes",
        24 => "3 Bytes",
        32 => "4 Bytes",
        40 => "5 Bytes",
        48 => "6 Bytes",
        56 => "7 Bytes",
        64 => "8 Bytes",
        72 => "9 Bytes",
        80 => "10 Bytes",
        88 => "11 Bytes",
        96 => "12 Bytes",
        104 => "13 Bytes",
        112 => "14 Bytes",
        _ => {
            // Default to bytes calculation
            let bytes = (size_bits + 7) / 8;
            match bytes {
                1 => "1 Byte",
                2 => "2 Bytes",
                3 => "3 Bytes",
                4 => "4 Bytes",
                5 => "5 Bytes",
                6 => "6 Bytes",
                7 => "7 Bytes",
                8 => "8 Bytes",
                _ => "14 Bytes",
            }
        }
    }
}

/// Convert DPT main/sub to ETS string format
pub fn dpt_to_string(dpt_main: u16, dpt_sub: u16) -> String {
    if dpt_sub == 0 {
        format!("DPT-{}", dpt_main)
    } else {
        format!("DPST-{}-{}", dpt_main, dpt_sub)
    }
}

/// Convert priority flags to ComObjectPriority
pub fn priority_from_flags(flags: u8) -> ComObjectPriority {
    match flags & 0x03 {
        0 => ComObjectPriority::System,
        1 => ComObjectPriority::High,
        2 => ComObjectPriority::Alert,
        _ => ComObjectPriority::Low,
    }
}
