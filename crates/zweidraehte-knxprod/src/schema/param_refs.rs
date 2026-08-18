//! Parameter references.

use serde::{Deserialize, Serialize};

// ============================================================================
// Parameter References
// ============================================================================

/// Container for parameter references
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParameterRefs {
    #[serde(rename = "ParameterRef", alias = "PR", default)]
    pub refs: Vec<ParameterRef>,
}

/// Reference to a parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterRef {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    /// Optional text override for the parameter display (MDT uses this to show context-specific labels)
    #[serde(rename = "@Text", skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
    /// Access mode: "None" means hidden from user (overrides the base Parameter's access)
    #[serde(rename = "@Access", skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    /// Optional value override for the parameter
    #[serde(rename = "@Value", skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Reference to a module argument for relative value calculation.
    /// When set, the final value = argument_value + Value.
    /// Used in modules to add a base value to parameter values on the reference.
    #[serde(rename = "@BaseValue", skip_serializing_if = "Option::is_none")]
    pub base_value: Option<String>,
}
