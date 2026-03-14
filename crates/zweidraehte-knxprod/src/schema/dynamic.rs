//! Dynamic section types for UI organization and conditional visibility.

use serde::{Deserialize, Serialize};

use super::modules::Module;

// ============================================================================
// Dynamic Section
// ============================================================================

/// The Dynamic section for UI organization
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicSection {
    #[serde(rename = "ChannelIndependentBlock", skip_serializing_if = "Option::is_none")]
    pub channel_independent_block: Option<ChannelIndependentBlock>,
    #[serde(rename = "Channel", default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<Channel>,
}

/// ChannelIndependentBlock - contains device-wide settings that appear outside of any channel tab
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelIndependentBlock {
    #[serde(rename = "$value", default)]
    pub items: Vec<ChannelIndependentItem>,
}

/// Items that can appear in a ChannelIndependentBlock
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelIndependentItem {
    #[serde(rename = "ParameterBlock")]
    ParameterBlock(ParameterBlock),
    #[serde(rename = "choose")]
    Choose(Choose),
}

/// A channel in the Dynamic section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Text", skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "@Number", skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
    #[serde(rename = "@TextParameterRefId", skip_serializing_if = "Option::is_none")]
    pub text_parameter_ref_id: Option<String>,

    #[serde(rename = "$value", default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<ChannelItem>,
}

/// Items that can appear in a Channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelItem {
    #[serde(rename = "ParameterBlock")]
    ParameterBlock(ParameterBlock),
    #[serde(rename = "choose")]
    Choose(Choose),
    /// A module instance directly in a channel.
    #[serde(rename = "Module")]
    Module(Module),
}

/// A parameter block in a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterBlock {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "@Text", skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "@TextParameterRefId", skip_serializing_if = "Option::is_none")]
    pub text_parameter_ref_id: Option<String>,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
    #[serde(rename = "@Inline", skip_serializing_if = "Option::is_none")]
    pub inline: Option<bool>,
    #[serde(rename = "@ShowInComObjectTree", skip_serializing_if = "Option::is_none")]
    pub show_in_com_object_tree: Option<bool>,
    #[serde(rename = "@Layout", skip_serializing_if = "Option::is_none")]
    pub layout: Option<String>,

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
    #[serde(rename = "ParameterSeparator")]
    ParameterSeparator(ParameterSeparator),
    #[serde(rename = "choose")]
    Choose(Choose),
    /// A module instance (can appear in parameter blocks, converted to WhenItem::Module in choose/when).
    #[serde(rename = "Module")]
    Module(Module),
    /// A button that triggers an event handler
    #[serde(rename = "Button")]
    Button(Button),
    /// Rows for table layout in parameter blocks
    #[serde(rename = "Rows")]
    Rows(TableRows),
    /// Columns for table layout in parameter blocks
    #[serde(rename = "Columns")]
    Columns(TableColumns),
}

/// Container for table rows
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TableRows {
    #[serde(rename = "Row", default, skip_serializing_if = "Vec::is_empty")]
    pub rows: Vec<TableRow>,
}

/// A single table row definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableRow {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Text", skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// Container for table columns
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TableColumns {
    #[serde(rename = "Column", default, skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<TableColumn>,
}

/// A single table column definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableColumn {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Text", skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "@Width", skip_serializing_if = "Option::is_none")]
    pub width: Option<String>,
}

/// A button element in a parameter block (triggers event handlers in ETS)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Button {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Text")]
    pub text: String,
    #[serde(rename = "@EventHandler")]
    pub event_handler: String,
    #[serde(rename = "@EventHandlerParameters", skip_serializing_if = "Option::is_none")]
    pub event_handler_parameters: Option<String>,
}

/// A visual separator element in a parameter block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterSeparator {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Text", skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
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
    #[serde(rename = "ParameterSeparator")]
    ParameterSeparator(ParameterSeparator),
    #[serde(rename = "ParameterBlock")]
    ParameterBlock(ParameterBlock),
    #[serde(rename = "choose")]
    Choose(Choose),
    #[serde(rename = "Assign")]
    Assign(Assign),
    /// A module instance within a when clause.
    #[serde(rename = "Module")]
    Module(Module),
}

/// Assignment element that copies one parameter value to another (or assigns a constant)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assign {
    #[serde(rename = "@TargetParamRefRef")]
    pub target_param_ref_ref: String,
    /// Reference to source parameter (mutually exclusive with Value)
    #[serde(rename = "@SourceParamRefRef", skip_serializing_if = "Option::is_none")]
    pub source_param_ref_ref: Option<String>,
    /// Constant value to assign (mutually exclusive with SourceParamRefRef)
    #[serde(rename = "@Value", skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Reference to a parameter reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterRefRef {
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    /// Optional text override for the parameter display (MDT uses this to show context-specific labels)
    #[serde(rename = "@Text", skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
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
