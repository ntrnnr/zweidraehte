//! Communication object types.

use serde::{Deserialize, Serialize};

// ============================================================================
// Communication Objects
// ============================================================================

/// Container for communication objects
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComObjectTable {
    #[serde(rename = "@CodeSegment", skip_serializing_if = "Option::is_none")]
    pub code_segment: Option<String>,
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
    /// Reference to a module argument for relative object numbering.
    /// When set, the final object number = argument_value + number.
    #[serde(rename = "@BaseNumber", skip_serializing_if = "Option::is_none")]
    pub base_number: Option<String>,
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
///
/// Note: KNX has 4 priority levels (System=0, High=1, Alert=2, Low=3),
/// but the ETS/MTXML schema only supports Low, High, and Alert.
/// System priority is mapped to Low when generating XML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ComObjectPriority {
    #[default]
    Low,
    High,
    Alert,
}

/// Container for communication object references
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComObjectRefs {
    #[serde(rename = "ComObjectRef", default)]
    pub refs: Vec<ComObjectRef>,
}

/// Reference to a communication object with optional overrides
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComObjectRef {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    #[serde(rename = "@Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "@Text", skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "@FunctionText", skip_serializing_if = "Option::is_none")]
    pub function_text: Option<String>,
    #[serde(rename = "@Priority", skip_serializing_if = "Option::is_none")]
    pub priority: Option<ComObjectPriority>,
    #[serde(rename = "@ObjectSize", skip_serializing_if = "Option::is_none")]
    pub object_size: Option<String>,
    #[serde(rename = "@ReadFlag", skip_serializing_if = "Option::is_none")]
    pub read_flag: Option<EnableFlag>,
    #[serde(rename = "@WriteFlag", skip_serializing_if = "Option::is_none")]
    pub write_flag: Option<EnableFlag>,
    #[serde(rename = "@CommunicationFlag", skip_serializing_if = "Option::is_none")]
    pub communication_flag: Option<EnableFlag>,
    #[serde(rename = "@TransmitFlag", skip_serializing_if = "Option::is_none")]
    pub transmit_flag: Option<EnableFlag>,
    #[serde(rename = "@UpdateFlag", skip_serializing_if = "Option::is_none")]
    pub update_flag: Option<EnableFlag>,
    #[serde(rename = "@ReadOnInitFlag", skip_serializing_if = "Option::is_none")]
    pub read_on_init_flag: Option<EnableFlag>,
    #[serde(rename = "@DatapointType", skip_serializing_if = "Option::is_none")]
    pub datapoint_type: Option<String>,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
    /// Reference to a parameter for text template substitution.
    /// Used with text templates like "F{{ChNo}} Switch: {{0}}" where {{0}}
    /// is replaced by the value of this referenced parameter.
    #[serde(rename = "@TextParameterRefId", skip_serializing_if = "Option::is_none")]
    pub text_parameter_ref_id: Option<String>,
}
