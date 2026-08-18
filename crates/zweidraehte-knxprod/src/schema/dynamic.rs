//! Dynamic section types for UI organization and conditional visibility.

use serde::{Deserialize, Serialize};

use super::modules::Module;

// ============================================================================
// Dynamic Section
// ============================================================================

/// The Dynamic section for UI organization.
///
/// Kept as a document-order item list because the MTXML content model
/// is one: ETS6-era programs put `choose` elements directly under
/// `Dynamic`, with whole `Channel`s inside the `when` branches (the
/// L&J E032 programs gate every button channel this way).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicSection {
    #[serde(rename = "$value", default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<DynamicItem>,
}

/// Items that can appear directly under `Dynamic`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DynamicItem {
    #[serde(rename = "ChannelIndependentBlock")]
    ChannelIndependentBlock(ChannelIndependentBlock),
    #[serde(rename = "Channel")]
    Channel(Channel),
    #[serde(rename = "choose")]
    Choose(Choose),
}

impl DynamicSection {
    /// The (first) top-level `ChannelIndependentBlock`, if any.
    pub fn channel_independent_block(&self) -> Option<&ChannelIndependentBlock> {
        self.items.iter().find_map(|item| match item {
            DynamicItem::ChannelIndependentBlock(cib) => Some(cib),
            _ => None,
        })
    }

    /// Every channel in document order, regardless of `choose` gating —
    /// for consumers that need the full roster (translations, module
    /// discovery, lookup by id), not the currently visible one.
    pub fn all_channels(&self) -> Vec<&Channel> {
        fn from_choose<'a>(choose: &'a Choose, out: &mut Vec<&'a Channel>) {
            for when in &choose.whens {
                for item in &when.items {
                    match item {
                        WhenItem::Channel(channel) => out.push(channel),
                        WhenItem::Choose(nested) => from_choose(nested, out),
                        _ => {}
                    }
                }
            }
        }

        let mut channels = Vec::new();
        for item in &self.items {
            match item {
                DynamicItem::Channel(channel) => channels.push(channel),
                DynamicItem::Choose(choose) => from_choose(choose, &mut channels),
                DynamicItem::ChannelIndependentBlock(_) => {}
            }
        }
        channels
    }

    /// Look up a channel by its `Id`, wherever it is nested.
    pub fn find_channel(&self, id: &str) -> Option<&Channel> {
        self.all_channels().into_iter().find(|c| c.id == id)
    }
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
    #[serde(rename = "ParameterBlockRename")]
    ParameterBlockRename(ParameterBlockRename),
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
    #[serde(rename = "ParameterBlockRename")]
    ParameterBlockRename(ParameterBlockRename),
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
    /// Pre-ETS4-style block header: a parameter ref whose text is the block's
    /// title. Converted legacy programs (`PreEts4Style`) key each block's
    /// content `choose` on this very ref, so its presence makes the ref part
    /// of the visible tree.
    #[serde(rename = "@ParamRefId", skip_serializing_if = "Option::is_none")]
    pub param_ref_id: Option<String>,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
    /// `None` access hides the whole block from the ETS parameter
    /// dialog; its parameters stay part of the configuration.
    #[serde(rename = "@Access", skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
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
    #[serde(rename = "ParameterBlockRename")]
    ParameterBlockRename(ParameterBlockRename),
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
    /// Presentation hint: "HorizontalRuler" draws a divider line,
    /// "Information" marks the text as an informational note. Absent means a
    /// plain separator — ETS shows its text as a heading/paragraph, or just
    /// vertical spacing when the text is empty.
    #[serde(rename = "@UIHint", skip_serializing_if = "Option::is_none")]
    pub ui_hint: Option<String>,
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
    #[serde(rename = "ParameterBlockRename")]
    ParameterBlockRename(ParameterBlockRename),
    /// A whole channel — only meaningful in the `when` branches of a
    /// Dynamic-level `choose`, where ETS6 programs gate entire channel
    /// pages on an enable parameter.
    #[serde(rename = "Channel")]
    Channel(Channel),
}

/// Renames a referenced [`ParameterBlock`]'s display text while the
/// containing branch is active (newer ETS schema versions; the MDT
/// V14+/V15 programs carry it). Pure UI — it affects neither
/// visibility nor memory, so the runtime walkers skip it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterBlockRename {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    #[serde(rename = "@Text", skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,
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
