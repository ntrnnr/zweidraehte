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
    /// The reference's own name. Product scripts address a calculation or
    /// validation parameter by it when the product gives no alias.
    #[serde(rename = "@Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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
    /// The value a new parameter instance starts with, ahead of `Value`.
    /// The reference resets an untouched instance to it, so it is the
    /// instance's default. Translations may replace it, as MDT does for
    /// labels such as "Bus failure" ("Busausfall" in de-DE).
    #[serde(rename = "@InitialValue", skip_serializing_if = "Option::is_none")]
    pub initial_value: Option<String>,
    /// Reference to a module argument for relative value calculation.
    /// When set, the final value = argument_value + Value.
    /// Used in modules to add a base value to parameter values on the reference.
    #[serde(rename = "@BaseValue", skip_serializing_if = "Option::is_none")]
    pub base_value: Option<String>,
    /// Authored download order. When several visible references share one
    /// stored parameter, a numeric tag places the reference after untagged
    /// ones (see `ReferenceWriteOrder`).
    #[serde(rename = "@Tag", skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}
