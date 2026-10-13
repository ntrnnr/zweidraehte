//! Shared parameter-form projection for terminal and web frontends.
//!
//! The runtime owns values and visibility. This module describes the evaluated
//! pages and controls without terminal sizes, cursor state, HTML, or Master Data.
//! Borrow a new projection after an edit; never treat an old page as validation.
//!
//! This preserves the current TUI's supported controls. TODO: editable floats,
//! IP addresses and product button actions need shared runtime support.

use std::{fmt, mem};

use serde::{Deserialize, Serialize};

use crate::Device;
use crate::runtime::configuration::{
    EffectiveFlagSources, ParameterDescription, ProductConfiguration, effective_com_objects,
};
use crate::runtime::model::{
    Condition, DynamicVisitor, ExpandedModule, ModuleArgValue, ParameterValue, VisitorModuleContext, walk_dynamic,
};
use crate::schema::{
    Channel, ChannelIndependentBlock, ChannelIndependentItem, ChannelItem, Choose, DynamicSection, Module, ModuleDef,
    ModuleDefDynamicItem, ParameterBlock, ParameterBlockItem, ParameterRefRef, ParameterSeparator, ParameterTypeDef,
    WhenItem,
};

/// One visible navigation entry, including children regardless of UI expansion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormNode {
    pub id: String,
    pub name: String,
    pub node_type: NodeType,
    pub children: Vec<FormNode>,
}

impl FormNode {
    /// Groups label collections of pages and do not have their own controls.
    pub fn is_group(&self) -> bool {
        matches!(self.node_type, NodeType::DeviceSettings | NodeType::Channel(_))
    }
}

/// A versioned, serializable view of one temporary product configuration.
///
/// The complete tree lets each frontend own its navigation. Page controls are
/// loaded on demand rather than serializing every page after every edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormSnapshot {
    pub version: u32,
    pub program_id: String,
    pub tree: Vec<FormNode>,
    pub page_id: Option<String>,
    pub content: Vec<ContentItem>,
    pub objects: Vec<FormObject>,
    /// A failed derivation means this is diagnostic output, not a valid preview.
    pub derivation_error: Option<String>,
}

/// A visible communication object with resolved product/reference flags.
/// Group-address assignment and project overrides belong to the project editor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormObject {
    pub number: u16,
    pub name: String,
    pub function: String,
    pub size: String,
    pub datapoint_type: Option<String>,
    pub priority: String,
    pub communication: bool,
    pub read: bool,
    pub write: bool,
    pub transmit: bool,
    pub update: bool,
    pub read_on_init: bool,
    pub flag_sources: EffectiveFlagSources,
}

/// A short-lived projection of an already evaluated device.
///
/// Constructing this does not load Master Data, contact the network, or perform
/// programming validation. Unsupported derivation is available on
/// `Device::derivation_error` and must be reported by the caller.
///
/// ```
/// use zweidraehte_ets_files::Device;
/// use zweidraehte_ets_files::runtime::presentation::{FormPresentation, FormSnapshot};
///
/// fn current_page(device: &Device, page_id: Option<&str>) -> FormSnapshot {
///     FormPresentation::new(device).snapshot(page_id)
/// }
/// ```
pub struct FormPresentation<'a> {
    device: &'a Device,
    content_items: Vec<ContentItem>,
}

impl fmt::Debug for FormPresentation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FormPresentation").field("program", &self.device.program().id).finish_non_exhaustive()
    }
}

/// Widget type for rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum WidgetType {
    /// Dropdown/enum selector
    Dropdown { options: Vec<(i64, String)>, current_idx: usize },
    /// Numeric spinner/input
    Number {
        /// Decimal strings in JSON preserve values beyond JavaScript's exact
        /// integer range. Rust and terminal consumers retain native integers.
        #[serde(with = "decimal_integer")]
        value: i64,
        #[serde(with = "optional_decimal_integer")]
        min: Option<i64>,
        #[serde(with = "optional_decimal_integer")]
        max: Option<i64>,
    },
    /// Text input field
    Text { value: String },
    /// Read-only display
    ReadOnly { value: String },
}

/// Type of sidebar tree node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum NodeType {
    /// Device-wide settings (ChannelIndependentBlock)
    DeviceSettings,
    /// A channel, identified by its `Id` (channels can be nested in
    /// Dynamic-level chooses, so there is no stable index to hold).
    Channel(String),
    /// A parameter block within device settings or channel
    ParameterBlock {
        /// Parent: None = device settings, Some(id) = channel
        parent: Option<String>,
        /// Exact block identity; display names are not necessarily unique.
        block_id: String,
    },
    /// A module instance
    ModuleInstance {
        /// Module instance ID
        instance_id: String,
        /// Parent context: None = device level, Some(id) = channel
        parent: Option<String>,
    },
}

// ============================================================================
// Tree Builder Visitor
// ============================================================================

/// Intermediate tree node for building the sidebar tree.
///
/// This is collected by TreeBuilderVisitor and then flattened to TreeNode
/// based on expansion state.
#[derive(Debug, Clone)]
pub struct VisibleTreeNode {
    /// Unique identifier
    pub id: String,
    /// Display name (may need interpolation)
    pub raw_name: String,
    /// Node type
    pub node_type: VisibleNodeType,
    /// Children (parameter blocks and modules)
    pub children: Vec<VisibleTreeNode>,
}

/// Type of node in the visible tree.
#[derive(Debug, Clone)]
pub enum VisibleNodeType {
    /// Channel-independent block (device settings)
    DeviceSettings,
    /// A channel, by its `Id`
    Channel { id: String },
    /// A parameter block, with the id of the channel it sits in (None
    /// for device settings)
    ParameterBlock { block_id: String, parent_channel: Option<String> },
    /// A module instance, with the id of the channel it sits in
    Module { instance_id: String, parent_channel: Option<String> },
}

/// Visitor that builds a tree of visible elements.
///
/// This visitor walks the dynamic section and builds an intermediate tree
/// structure representing only the visible blocks and modules. The tree
/// can then be flattened to `TreeNode` list based on expansion state.
pub struct TreeBuilderVisitor<'a> {
    /// Reference to device for visibility checks and text interpolation
    device: &'a Device,
    /// Root nodes (CIB and channels)
    root_nodes: Vec<VisibleTreeNode>,
    /// Current channel id (None when in CIB)
    current_channel_id: Option<String>,
    /// Stack of parent nodes we're building into
    node_stack: Vec<VisibleTreeNode>,
    /// Whether each entered application-level block contributed a tree node.
    /// This pairs enter/leave callbacks while allowing empty blocks to remain
    /// absent without flattening their visible siblings.
    parameter_block_nodes: Vec<bool>,
    /// Module nesting depth (internal blocks belong to the module placement,
    /// not directly to the application's navigation tree).
    module_depth: usize,

    /// Nesting depth below a block hidden from the ETS parameter dialog.
    hidden_parameter_block_depth: usize,
}

impl<'a> TreeBuilderVisitor<'a> {
    /// Create a new visitor for building the tree.
    pub fn new(device: &'a Device) -> Self {
        Self {
            device,
            root_nodes: Vec::new(),
            current_channel_id: None,
            node_stack: Vec::new(),
            parameter_block_nodes: Vec::new(),
            module_depth: 0,
            hidden_parameter_block_depth: 0,
        }
    }

    /// Consume the visitor and return the collected tree nodes.
    pub fn into_tree(self) -> Vec<VisibleTreeNode> {
        self.root_nodes
    }

    /// Pre-ETS4-style blocks title themselves via `ParamRefId`: ETS shows the
    /// referenced parameter's text (with the ref's own override winning).
    fn block_has_visible_items(&self, block: &ParameterBlock) -> bool {
        for item in &block.items {
            match item {
                ParameterBlockItem::ParameterBlock(nested) => {
                    if self.block_has_visible_items(nested) {
                        return true;
                    }
                }
                ParameterBlockItem::ParameterBlockRename(_) => {}
                ParameterBlockItem::ParameterRefRef(prr) => {
                    if self.device.is_param_ref_visible(&prr.ref_id) {
                        return true;
                    }
                }
                ParameterBlockItem::ComObjectRefRef(corr) => {
                    if self.device.is_com_object_ref_visible(&corr.ref_id) {
                        return true;
                    }
                }
                ParameterBlockItem::Choose(_) => {
                    // Choose blocks may contain visible items
                    return true;
                }
                ParameterBlockItem::ParameterSeparator(_)
                | ParameterBlockItem::Button(_)
                | ParameterBlockItem::Rows(_)
                | ParameterBlockItem::Columns(_) => {}
                // Like their `when` counterparts, the editor neither renders
                // nested channels inside blocks nor applies assignments.
                ParameterBlockItem::Assign(_) | ParameterBlockItem::Channel(_) => {}
                ParameterBlockItem::Module(_) | ParameterBlockItem::Repeat(_) => {
                    // Materialized modules are pages of their own. Their
                    // containing block must therefore remain in the tree even
                    // when it has no direct scalar parameters.
                    return true;
                }
            }
        }
        false
    }

    fn block_header_text(&self, block: &ParameterBlock) -> Option<String> {
        let ref_id = block.param_ref_id.as_ref()?;
        let param_ref = self.device.get_parameter_ref(ref_id)?;
        let text = match &param_ref.text {
            Some(text) => text.clone(),
            None => self.device.get_parameter_info(&param_ref.ref_id)?.text.clone(),
        };
        (!text.is_empty()).then_some(text)
    }
}

impl<'a> DynamicVisitor for TreeBuilderVisitor<'a> {
    fn enter_channel_independent_block(&mut self, _block: &ChannelIndependentBlock) {
        self.current_channel_id = None;
        // Create device settings node that will collect children
        self.node_stack.push(VisibleTreeNode {
            id: "device".to_string(),
            raw_name: "Device Settings".to_string(),
            node_type: VisibleNodeType::DeviceSettings,
            children: Vec::new(),
        });
    }

    fn leave_channel_independent_block(&mut self, _block: &ChannelIndependentBlock) {
        if let Some(node) = self.node_stack.pop() {
            // Only add if it has children (visible blocks)
            if !node.children.is_empty() {
                self.root_nodes.push(node);
            }
        }
    }

    fn enter_channel(&mut self, channel: &Channel) {
        if self.hidden_parameter_block_depth > 0 {
            return;
        }

        self.current_channel_id = Some(channel.id.clone());

        let raw_name = channel.text.clone().unwrap_or_else(|| channel.name.clone());

        self.node_stack.push(VisibleTreeNode {
            id: format!("channel_{}", channel.id),
            raw_name,
            node_type: VisibleNodeType::Channel { id: channel.id.clone() },
            children: Vec::new(),
        });
    }

    fn leave_channel(&mut self, _channel: &Channel) {
        if self.hidden_parameter_block_depth > 0 {
            return;
        }

        if let Some(node) = self.node_stack.pop() {
            self.root_nodes.push(node);
        }
        self.current_channel_id = None;
    }

    fn enter_parameter_block(&mut self, block: &ParameterBlock) {
        // An invisible block's selector parameters can still drive dynamic
        // communication objects, but neither it nor nested pages belong in
        // the parameter tree.
        if self.hidden_parameter_block_depth > 0 || block.access.as_deref() == Some("None") {
            self.hidden_parameter_block_depth += 1;
            return;
        }

        // Skip module-internal ParameterBlocks from tree (modules show their own content)
        if self.module_depth > 0 {
            return;
        }

        // Inline blocks are layout containers inside their owning page, not
        // navigation pages. Their nested content still gets traversed and is
        // rendered when the parent page is selected.
        let visible = block.inline != Some(true) && self.block_has_visible_items(block);
        self.parameter_block_nodes.push(visible);
        if !visible {
            return;
        }

        let block_name = block.name.clone().unwrap_or_else(|| block.id.clone());
        // An active ParameterBlockRename replaces the block's title.
        let raw_text = self
            .device
            .active_block_rename(&block.id)
            .map(str::to_string)
            .or_else(|| block.text.clone())
            .or_else(|| self.block_header_text(block))
            .unwrap_or_else(|| block_name.clone());

        let id = format!("block_{}", block.id);

        let child_node = VisibleTreeNode {
            id,
            raw_name: raw_text,
            node_type: VisibleNodeType::ParameterBlock {
                block_id: block.id.clone(),
                parent_channel: self.current_channel_id.clone(),
            },
            children: Vec::new(),
        };

        // Keep the block on the stack until its complete nested subtree has
        // been visited. The former append-only approach made every page a
        // direct child of its channel.
        self.node_stack.push(child_node);
    }

    fn leave_parameter_block(&mut self, _block: &ParameterBlock) {
        if self.hidden_parameter_block_depth > 0 {
            self.hidden_parameter_block_depth -= 1;
            return;
        }

        if self.module_depth > 0 {
            return;
        }

        let Some(visible) = self.parameter_block_nodes.pop() else { return };
        if !visible {
            return;
        }
        let Some(node) = self.node_stack.pop() else { return };
        if let Some(parent) = self.node_stack.last_mut() {
            parent.children.push(node);
        } else {
            self.root_nodes.push(node);
        }
    }

    fn visit_module(&mut self, module: &Module) {
        if self.hidden_parameter_block_depth > 0 {
            return;
        }

        // A module whose complete presentation is inline contributes its
        // fields to the enclosing page. Giving it a tree node would turn the
        // inline block's conventional `#` table label into a fake sub-page.
        if self.device.get_module_def(&module.ref_id).is_some_and(module_definition_is_inline) {
            return;
        }

        // Only add visible modules
        if !self.device.is_module_visible(&module.id) {
            return;
        }

        let id = if let Some(ch_id) = &self.current_channel_id {
            format!("channel_{}_module_{}", ch_id, module.id)
        } else {
            format!("device_module_{}", module.id)
        };

        // Get raw name - will be interpolated later
        let raw_name = module.name.clone().unwrap_or_else(|| module.id.clone());

        let child_node = VisibleTreeNode {
            id,
            raw_name,
            node_type: VisibleNodeType::Module {
                instance_id: module.id.clone(),
                parent_channel: self.current_channel_id.clone(),
            },
            children: Vec::new(),
        };

        // Add to current parent
        if let Some(parent) = self.node_stack.last_mut() {
            parent.children.push(child_node);
        }
    }

    fn enter_module(&mut self, _module: &Module, _ctx: &VisitorModuleContext) {
        if self.hidden_parameter_block_depth > 0 {
            return;
        }

        // Mark that we're inside a module - skip internal ParameterBlocks from tree
        self.module_depth += 1;
    }

    fn leave_module(&mut self, _module: &Module, _ctx: &VisitorModuleContext) {
        if self.hidden_parameter_block_depth > 0 {
            return;
        }

        self.module_depth = self.module_depth.saturating_sub(1);
    }
}

/// Inline-only module definitions are presentation fragments. They do not
/// establish navigation pages of their own; the containing parameter block
/// owns their content just like it owns an inline `ParameterBlock`.
fn module_definition_is_inline(module_def: &ModuleDef) -> bool {
    let Some(dynamic) = &module_def.dynamic else { return false };
    let mut found_content = false;

    for item in &dynamic.items {
        match item {
            ModuleDefDynamicItem::ParameterBlock(block) if block.inline == Some(true) => {
                found_content = true;
            }
            _ => return false,
        }
    }

    found_content
}

/// Item in the parameter content area.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ContentItem {
    /// A parameter with its widget
    Parameter {
        /// Parameter ID used to commit edits.
        param_id: String,
        /// Interpolated label shown beside the widget.
        text: String,
        /// Product-authored unit or suffix.
        suffix: Option<String>,
        /// Editor appropriate for the parameter type and access.
        widget: WidgetType,
        /// Whether the current value differs from its effective product default.
        is_non_default: bool,
    },
    /// A separator: a ruler, an information note, or — with no `ui_hint` —
    /// a heading (single-line text), paragraph (multi-line text), or spacer
    /// (empty text)
    Separator { text: Option<String>, ui_hint: Option<String> },
    /// A communication object (displayed inline in module content)
    CommObject { name: String, function: String, dpt: String },
    /// A picture/image reference. ETS shows the picture parameter's
    /// `Text` in the label column, the image in the value column.
    Picture {
        /// Baggage reference ID
        ref_id: String,
        /// Interpolated label text shown left of the image
        text: Option<String>,
        /// The `TypePicture` `HorizontalAlignment` value (XSD default Left)
        alignment: Option<String>,
    },
    /// An ETS `ParameterBlock` with `Layout="Table"`. Cell placement is
    /// authored explicitly as one-based row/column coordinates, so retaining
    /// it is necessary for products where an empty parameter label only makes
    /// sense in combination with the table headers.
    Table(ParameterTable),
}

/// An editable ETS parameter table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterTable {
    /// Heading for the row-label column (often `#`).
    pub corner_label: String,
    pub columns: Vec<ParameterTableColumn>,
    pub rows: Vec<ParameterTableRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterTableColumn {
    pub text: String,
    /// Relative width parsed from the product's optional percentage.
    pub weight: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterTableRow {
    pub text: String,
    pub cells: Vec<Option<ParameterTableCell>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ParameterTableCell {
    Parameter {
        param_id: String,
        suffix: Option<String>,
        widget: WidgetType,
        is_non_default: bool,
    },
    /// Non-interactive authored cell content, normally `-` in a branch where
    /// an editable value does not apply.
    Text(String),
}

#[derive(Clone, Copy)]
enum TablePlacement<'a> {
    Parameter(&'a ParameterRefRef),
    Text(&'a ParameterSeparator),
}

impl<'a> TablePlacement<'a> {
    fn cell(self) -> Option<&'a str> {
        match self {
            TablePlacement::Parameter(reference) => reference.cell.as_deref(),
            TablePlacement::Text(separator) => separator.cell.as_deref(),
        }
    }
}

impl ParameterTableCell {
    /// Whether a frontend can focus this cell as a parameter control.
    pub fn is_parameter(&self) -> bool {
        matches!(self, ParameterTableCell::Parameter { .. })
    }
}

impl<'device> FormPresentation<'device> {
    pub fn new(device: &'device Device) -> Self {
        Self { device, content_items: Vec::new() }
    }

    /// Render the requested page, falling back to the first page if an edit
    /// removed it. The returned `page_id` is always the actual selected page.
    pub fn snapshot(&mut self, page_id: Option<&str>) -> FormSnapshot {
        fn find_page<'a>(nodes: &'a [FormNode], id: Option<&str>) -> Option<&'a FormNode> {
            for node in nodes {
                if !node.is_group() && id.is_none_or(|id| id == node.id) {
                    return Some(node);
                }
                if let Some(found) = find_page(&node.children, id) {
                    return Some(found);
                }
            }
            None
        }

        let tree = self.tree();
        let selected = find_page(&tree, page_id).or_else(|| find_page(&tree, None));
        let content = selected.map(|node| self.page(&node.node_type)).unwrap_or_default();
        let page_id = selected.map(|node| node.id.clone());
        let objects = effective_com_objects(self.device, &ProductConfiguration::default())
            .into_iter()
            .map(|object| FormObject {
                number: object.number,
                name: self.device.interpolate_text(&object.text),
                function: self.device.interpolate_text(&object.function_text),
                size: object.object_size,
                datapoint_type: object.datapoint_type,
                priority: object.priority.to_string(),
                communication: object.communication,
                read: object.read,
                write: object.write,
                transmit: object.transmit,
                update: object.update,
                read_on_init: object.read_on_init,
                flag_sources: object.flag_sources,
            })
            .collect();
        FormSnapshot {
            version: 1,
            program_id: self.device.program().id.clone(),
            tree,
            page_id,
            content,
            objects,
            derivation_error: self.device.derivation_error().map(str::to_owned),
        }
    }

    /// All currently visible groups and pages, in authored order.
    pub fn tree(&self) -> Vec<FormNode> {
        let Some(dynamic) = self.device.dynamic_section() else { return Vec::new() };
        let mut visitor = TreeBuilderVisitor::new(self.device);
        walk_dynamic(dynamic, &mut visitor, self.device, self.device.module_defs());
        visitor.into_tree().into_iter().map(|node| self.resolve_node(node, dynamic)).collect()
    }

    fn resolve_node(&self, node: VisibleTreeNode, dynamic: &DynamicSection) -> FormNode {
        let (name, node_type) = match node.node_type {
            VisibleNodeType::DeviceSettings => (node.raw_name, NodeType::DeviceSettings),
            VisibleNodeType::Channel { id } => {
                let name = if let Some(channel) = dynamic.find_channel(&id) {
                    self.device.interpolate_channel_text(&node.raw_name, channel.text_parameter_ref_id.as_deref())
                } else {
                    self.device.interpolate_text(&node.raw_name)
                };
                (name, NodeType::Channel(id))
            }
            VisibleNodeType::ParameterBlock { block_id, parent_channel } => {
                (self.device.interpolate_text(&node.raw_name), NodeType::ParameterBlock {
                    parent: parent_channel,
                    block_id,
                })
            }
            VisibleNodeType::Module { instance_id, parent_channel } => {
                (self.interpolate_module_name(&instance_id, &node.raw_name), NodeType::ModuleInstance {
                    instance_id,
                    parent: parent_channel,
                })
            }
        };
        FormNode {
            id: node.id,
            name,
            node_type,
            children: node.children.into_iter().map(|child| self.resolve_node(child, dynamic)).collect(),
        }
    }

    /// Controls for a node from the current tree; group headers yield no controls.
    ///
    /// Callers resolving browser-supplied IDs should look them up in `tree()`
    /// first. A previously visible node may disappear following a parameter edit.
    pub fn page(&mut self, target: &NodeType) -> Vec<ContentItem> {
        self.content_items.clear();
        match target {
            NodeType::DeviceSettings | NodeType::Channel(_) => {}
            NodeType::ParameterBlock { parent, block_id } => self.build_block_content(parent.as_deref(), block_id),
            NodeType::ModuleInstance { instance_id, .. } => self.build_module_content(instance_id),
        }
        mem::take(&mut self.content_items)
    }

    /// Interpolate module display name using expanded module args.
    fn interpolate_module_name(&self, instance_id: &str, raw_name: &str) -> String {
        if let Some(expanded) = self.device.get_expanded_module(instance_id) {
            // Try to get a better display name from the module def
            if let Some(module_def) = self.device.get_module_def(&expanded.module_def_id) {
                // Get the first ParameterBlock's text and text_parameter_ref_id
                let (block_text, text_param_ref_id) = module_def
                    .dynamic
                    .as_ref()
                    .and_then(|dyn_sec| {
                        dyn_sec.items.iter().find_map(|item| {
                            if let ModuleDefDynamicItem::ParameterBlock(pb) = item
                                && pb.inline != Some(true)
                            {
                                Some((pb.text.clone(), pb.text_parameter_ref_id.clone()))
                            } else {
                                None
                            }
                        })
                    })
                    .unwrap_or((None, None));

                // Look up the text parameter value for {{0}} substitution
                let text_param_value = text_param_ref_id.and_then(|ref_id| {
                    let param_ref = module_def
                        .static_section
                        .parameter_refs
                        .as_ref()
                        .and_then(|refs| refs.refs.iter().find(|pr| pr.id == ref_id));

                    param_ref.and_then(|pr| {
                        let composite_id = format!("{}::{}", expanded.instance_id, pr.id);
                        self.device.get_module_parameter_value_by_composite_id(&composite_id).and_then(|v| match v {
                            // Only return actual text values for {{0}} substitution
                            // Integer 0 should NOT be converted to "0" - that's not meaningful text
                            ParameterValue::Text(s) if !s.is_empty() => Some(s.clone()),
                            _ => None,
                        })
                    })
                });

                if let Some(text) = block_text {
                    return self.device.interpolate_module_text_with_param(
                        &text,
                        expanded,
                        text_param_value.as_deref(),
                    );
                } else if let Some(instance_name) = &expanded.name {
                    return self.device.interpolate_module_text(instance_name, expanded);
                } else {
                    // Fallback: use module name with channel number
                    if let Some(ModuleArgValue::Numeric(ch)) = expanded.args.get("ChNo") {
                        return format!("{} {}", module_def.name, ch);
                    }
                    return module_def.name.clone();
                }
            } else if let Some(instance_name) = &expanded.name {
                return self.device.interpolate_module_text(instance_name, expanded);
            }
        } else {
            log::warn!("  expanded module NOT found for instance_id='{}'", instance_id);
        }
        raw_name.to_string()
    }

    /// Get the integer value of a selector parameter ref.
    fn get_selector_value(&self, param_ref_id: &str) -> Option<i64> {
        let param_value = self.device.get_parameter_value(param_ref_id)?;

        match param_value {
            ParameterValue::Integer(v) => Some(*v),
            ParameterValue::Float(v) => Some(*v as i64),
            _ => None,
        }
    }

    /// Check if a selector value matches a condition test string —
    /// the library's condition grammar, adapted for the optional
    /// selector value the tree-building paths carry.
    fn matches_condition(&self, value: Option<i64>, test: &str) -> bool {
        value.is_some_and(|v| Condition::parse(test).is_some_and(|c| c.matches(v)))
    }

    fn build_block_content(&mut self, parent: Option<&str>, block_id: &str) {
        let dynamic = self.device.dynamic_section().cloned();

        if let Some(dynamic) = dynamic {
            match parent {
                None => {
                    // Device settings block
                    if let Some(cib) = dynamic.channel_independent_block()
                        && let Some(pb) = self.find_block_in_cib(cib, block_id)
                    {
                        self.add_parameter_block(&pb.clone());
                    }
                }
                Some(channel_id) => {
                    if let Some(channel) = dynamic.find_channel(channel_id)
                        && let Some(pb) = self.find_block_in_channel(channel, block_id)
                    {
                        self.add_parameter_block(&pb.clone());
                    }
                }
            }
        }
    }

    /// Build content for a module instance.
    fn build_module_content(&mut self, instance_id: &str) {
        // Get the expanded module and its definition
        let expanded = self.device.get_expanded_module(instance_id).cloned();
        let expanded = match expanded {
            Some(e) => e,
            None => {
                log::warn!("build_module_content: expanded module NOT found for '{}'", instance_id);
                return;
            }
        };

        let module_def = self.device.get_module_def(&expanded.module_def_id).cloned();
        let module_def = match module_def {
            Some(def) => def,
            None => {
                log::warn!("build_module_content: module def NOT found for '{}'", expanded.module_def_id);
                return;
            }
        };

        // If the module has a Dynamic section, render its contents
        if let Some(dynamic) = &module_def.dynamic {
            for item in &dynamic.items {
                match item {
                    ModuleDefDynamicItem::ParameterBlock(pb) => {
                        self.add_module_parameter_block(pb, &expanded);
                    }
                    ModuleDefDynamicItem::Choose(choose) => {
                        self.add_module_choose_items(choose, &expanded);
                    }
                    ModuleDefDynamicItem::ChannelIndependentBlock(_)
                    | ModuleDefDynamicItem::Channel(_)
                    | ModuleDefDynamicItem::Module(_)
                    | ModuleDefDynamicItem::Repeat(_) => {
                        // Nested module structures are traversed by the runtime;
                        // this content renderer currently flattens block items.
                    }
                }
            }
        } else {
            // Fall back to rendering params from Static section
            // For now, just show a placeholder message
            self.content_items.push(ContentItem::Separator {
                text: Some(format!("Module: {}", expanded.name.as_deref().unwrap_or(&expanded.instance_id))),
                ui_hint: None,
            });
        }
    }

    fn add_inline_module(&mut self, instance_id: &str, module_def_id: &str) {
        if self.device.get_module_def(module_def_id).is_some_and(module_definition_is_inline) {
            self.build_module_content(instance_id);
        }
    }

    fn add_inline_repeat_modules(&mut self, repeat_id: &str) {
        // Cloning the stable identities releases the immutable device borrow
        // before content construction mutates the view.
        let mut instances = self
            .device
            .all_expanded_modules()
            .filter(|expanded| expanded.repeat_id.as_deref() == Some(repeat_id))
            .filter(|expanded| {
                self.device.get_module_def(&expanded.module_def_id).is_some_and(module_definition_is_inline)
            })
            .map(|expanded| (expanded.instance_id.clone(), expanded.module_def_id.clone()))
            .collect::<Vec<_>>();
        instances.sort();

        for (instance_id, module_def_id) in instances {
            self.add_inline_module(&instance_id, &module_def_id);
        }
    }

    /// Preserve the layout contract of a parameter block. List blocks are
    /// recursively lowered to the existing linear content stream; table
    /// blocks remain one structured, editable item.
    fn add_parameter_block(&mut self, block: &ParameterBlock) {
        if block.layout.as_deref() == Some("Table") {
            if let Some(table) = self.build_parameter_table(block) {
                self.content_items.push(ContentItem::Table(table));
            }
        } else {
            self.add_block_items(&block.items);
        }
    }

    fn add_module_parameter_block(&mut self, block: &ParameterBlock, expanded: &ExpandedModule) {
        if block.layout.as_deref() == Some("Table") {
            if let Some(table) = self.build_module_parameter_table(block, expanded) {
                self.content_items.push(ContentItem::Table(table));
            }
        } else {
            self.add_module_block_items(&block.items, expanded);
        }
    }

    /// Add parameter block items for a module, applying text interpolation.
    fn add_module_block_items(&mut self, items: &[ParameterBlockItem], expanded: &ExpandedModule) {
        for item in items {
            match item {
                ParameterBlockItem::ParameterBlock(block) => {
                    self.add_module_parameter_block(block, expanded);
                }
                ParameterBlockItem::ParameterBlockRename(_) => {}
                ParameterBlockItem::ParameterRefRef(prr) => {
                    self.add_module_param_ref(&prr.ref_id, expanded);
                }
                ParameterBlockItem::ComObjectRefRef(corr) => {
                    self.add_module_com_obj_ref(&corr.ref_id, expanded);
                }
                ParameterBlockItem::Choose(choose) => {
                    self.add_module_choose_items(choose, expanded);
                }
                ParameterBlockItem::ParameterSeparator(sep) => {
                    let raw_text = sep.text.clone();
                    let text = raw_text.map(|t| self.device.interpolate_module_text(&t, expanded));
                    self.content_items.push(ContentItem::Separator { text, ui_hint: sep.ui_hint.clone() });
                }
                ParameterBlockItem::Module(module) => {
                    self.add_inline_module(&module.id, &module.ref_id);
                }
                ParameterBlockItem::Repeat(repeat) => {
                    self.add_inline_repeat_modules(&repeat.id);
                }
                ParameterBlockItem::Button(_) => {
                    // Buttons are ETS UI elements, not displayed in TUI
                }
                ParameterBlockItem::Assign(_) | ParameterBlockItem::Channel(_) => {}
                ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => {
                    // Table layout elements, not displayed in TUI
                }
            }
        }
    }

    /// Add choose items for a module.
    fn add_module_choose_items(&mut self, choose: &Choose, expanded: &ExpandedModule) {
        // Try module-internal lookup first, fall back to device-level
        let module_val = self.get_module_selector_value(&choose.param_ref_id, expanded);
        let device_val = self.get_selector_value(&choose.param_ref_id);
        let selector_value = module_val.or(device_val);

        let mut any_matched = false;
        for when in &choose.whens {
            if when.default.unwrap_or(false) {
                continue;
            }
            if let Some(test) = &when.test {
                let matches = self.matches_condition(selector_value, test);
                if matches {
                    any_matched = true;
                    self.add_module_when_items(&when.items, expanded);
                }
            }
        }

        if !any_matched {
            for when in &choose.whens {
                if when.default.unwrap_or(false) {
                    self.add_module_when_items(&when.items, expanded);
                    break;
                }
            }
        }
    }

    /// Get the selector value for a module-internal parameter ref.
    pub fn get_module_selector_value(&self, param_ref_id: &str, expanded: &ExpandedModule) -> Option<i64> {
        // Get the module definition
        let module_def = self.device.get_module_def(&expanded.module_def_id)?;

        // Find the ParameterRef in the module's static section
        let param_ref = module_def.static_section.parameter_refs.as_ref()?.refs.iter().find(|pr| pr.id == param_ref_id);

        let param_ref = match param_ref {
            Some(pr) => pr,
            None => {
                return None;
            }
        };

        // Build the composite ID for module parameter lookup
        let composite_id = format!("{}::{}", expanded.instance_id, param_ref.id);

        // Get the value from module params
        let param_value = self.device.get_module_parameter_value_by_composite_id(&composite_id);

        match param_value {
            Some(ParameterValue::Integer(v)) => Some(*v),
            Some(ParameterValue::Float(v)) => Some(*v as i64),
            _ => None,
        }
    }

    /// Add when items for a module.
    fn add_module_when_items(&mut self, items: &[WhenItem], expanded: &ExpandedModule) {
        for item in items {
            match item {
                WhenItem::ParameterBlockRename(_) => {}
                WhenItem::ParameterRefRef(prr) => {
                    self.add_module_param_ref(&prr.ref_id, expanded);
                }
                WhenItem::ComObjectRefRef(corr) => {
                    self.add_module_com_obj_ref(&corr.ref_id, expanded);
                }
                WhenItem::ParameterBlock(pb) => {
                    self.add_module_parameter_block(pb, expanded);
                }
                WhenItem::Choose(nested_choose) => {
                    self.add_module_choose_items(nested_choose, expanded);
                }
                WhenItem::ParameterSeparator(sep) => {
                    let raw_text = sep.text.clone();
                    let text = raw_text.map(|t| self.device.interpolate_module_text(&t, expanded));
                    self.content_items.push(ContentItem::Separator { text, ui_hint: sep.ui_hint.clone() });
                }
                WhenItem::Button(_) => {}
                WhenItem::Assign(_) => {}
                // Modules cannot nest channels.
                WhenItem::Channel(_) => {}
                WhenItem::Module(module) => self.add_inline_module(&module.id, &module.ref_id),
                WhenItem::Repeat(repeat) => self.add_inline_repeat_modules(&repeat.id),
            }
        }
    }

    fn add_module_param_ref(&mut self, ref_id: &str, expanded: &ExpandedModule) {
        let param_id = format!("{}::{ref_id}", expanded.instance_id);
        if let Some(item) = self.parameter_content(&param_id, None) {
            self.content_items.push(item);
        }
    }

    /// Root and module rows differ only in text interpolation; their effective
    /// value, access, defaults and type all come from the runtime description.
    fn parameter_content(&self, param_id: &str, text_override: Option<&str>) -> Option<ContentItem> {
        let description = self.device.parameter_description(param_id)?;
        if description.hidden {
            return None;
        }
        let text = text_override.unwrap_or(description.text);
        let text = match description.module {
            Some(module) => self.device.interpolate_module_text(text, module),
            None => self.device.interpolate_text(text),
        };
        if let Some(ParameterTypeDef::TypePicture(picture)) = description.parameter_type {
            return Some(ContentItem::Picture {
                ref_id: picture.ref_id.clone(),
                text: (!text.is_empty()).then_some(text),
                alignment: picture.horizontal_alignment.clone(),
            });
        }
        if text.is_empty() {
            return None;
        }
        Some(ContentItem::Parameter {
            param_id: param_id.to_owned(),
            text,
            widget: Self::parameter_widget(&description),
            suffix: description.suffix.map(str::to_owned),
            is_non_default: description.modified,
        })
    }

    /// Add a module comm object ref to content items.
    fn add_module_com_obj_ref(&mut self, ref_id: &str, expanded: &ExpandedModule) {
        if !self.device.is_module_com_object_ref_visible(&expanded.instance_id, ref_id) {
            return;
        }

        // Look up the ModuleDef to access its static section
        let module_def = match self.device.get_module_def(&expanded.module_def_id) {
            Some(def) => def.clone(),
            None => return,
        };

        // Find the ComObjectRef in the module's static section
        let com_obj_ref = module_def
            .static_section
            .com_object_refs
            .as_ref()
            .and_then(|refs| refs.refs.iter().find(|cor| cor.id == ref_id));

        let com_obj_ref = match com_obj_ref {
            Some(cor) => cor.clone(),
            None => return,
        };

        // Find the ComObject using the RefId
        let com_object = module_def
            .static_section
            .com_objects
            .as_ref()
            .and_then(|objs| objs.objects.iter().find(|o| o.id == com_obj_ref.ref_id));

        let com_object = match com_object {
            Some(o) => o.clone(),
            None => return,
        };

        // Build display text with interpolation
        let raw_text = com_obj_ref.text.clone().unwrap_or_else(|| com_object.text.clone());

        let text = self.device.interpolate_module_text(&raw_text, expanded);

        // Add as a comm object display item
        self.content_items.push(ContentItem::CommObject {
            name: text,
            function: com_obj_ref.function_text.clone().unwrap_or_else(|| com_object.function_text.clone()),
            dpt: com_obj_ref.datapoint_type.clone().or_else(|| com_object.datapoint_type.clone()).unwrap_or_default(),
        });
    }

    fn build_parameter_table(&self, block: &ParameterBlock) -> Option<ParameterTable> {
        let rows = block.items.iter().find_map(|item| match item {
            ParameterBlockItem::Rows(rows) => Some(&rows.rows),
            _ => None,
        })?;
        let columns = block.items.iter().find_map(|item| match item {
            ParameterBlockItem::Columns(columns) => Some(&columns.columns),
            _ => None,
        })?;

        let mut table_rows: Vec<_> = rows
            .iter()
            .map(|row| ParameterTableRow {
                text: row.text.as_deref().map(|text| self.device.interpolate_text(text)).unwrap_or_default(),
                cells: vec![None; columns.len()],
            })
            .collect();
        let mut placements = Vec::new();
        self.collect_parameter_table_refs(&block.items, &mut placements);
        for placement in placements {
            let Some((row, column)) = table_cell_indices(placement.cell(), rows.len(), columns.len()) else {
                continue;
            };
            table_rows[row].cells[column] = match placement {
                TablePlacement::Parameter(parameter_ref) => self.parameter_table_cell(&parameter_ref.ref_id),
                TablePlacement::Text(separator) if separator.access.as_deref() != Some("None") => {
                    Some(ParameterTableCell::Text(
                        separator.text.as_deref().map(|text| self.device.interpolate_text(text)).unwrap_or_default(),
                    ))
                }
                TablePlacement::Text(_) => None,
            };
        }

        // ETS permits sparse conditional rows and explicitly marks the rows
        // that disappear when none of their cells are active.
        table_rows = table_rows
            .into_iter()
            .zip(rows)
            .filter_map(|(row, definition)| {
                (!definition.collapse_if_empty || row.cells.iter().any(Option::is_some)).then_some(row)
            })
            .collect();

        Some(ParameterTable {
            corner_label: block.text.as_deref().map(|text| self.device.interpolate_text(text)).unwrap_or_default(),
            columns: columns
                .iter()
                .map(|column| ParameterTableColumn {
                    text: column.text.as_deref().map(|text| self.device.interpolate_text(text)).unwrap_or_default(),
                    weight: table_column_weight(column.width.as_deref()),
                })
                .collect(),
            rows: table_rows,
        })
    }

    fn parameter_table_cell(&self, id: &str) -> Option<ParameterTableCell> {
        let description = self.device.parameter_description(id)?;
        if description.hidden || matches!(description.parameter_type, Some(ParameterTypeDef::TypePicture(_))) {
            return None;
        }
        Some(ParameterTableCell::Parameter {
            param_id: id.to_owned(),
            suffix: description.suffix.map(str::to_owned),
            widget: Self::parameter_widget(&description),
            is_non_default: description.modified,
        })
    }

    fn collect_parameter_table_refs<'a>(&self, items: &'a [ParameterBlockItem], output: &mut Vec<TablePlacement<'a>>) {
        for item in items {
            match item {
                ParameterBlockItem::ParameterRefRef(parameter_ref) if parameter_ref.cell.is_some() => {
                    output.push(TablePlacement::Parameter(parameter_ref));
                }
                ParameterBlockItem::ParameterSeparator(separator) if separator.cell.is_some() => {
                    output.push(TablePlacement::Text(separator));
                }
                ParameterBlockItem::ParameterBlock(block) => {
                    self.collect_parameter_table_refs(&block.items, output);
                }
                ParameterBlockItem::Choose(choose) => self.collect_parameter_table_choose_refs(choose, output),
                _ => {}
            }
        }
    }

    fn collect_parameter_table_choose_refs<'a>(&self, choose: &'a Choose, output: &mut Vec<TablePlacement<'a>>) {
        let selector_value = self.get_selector_value(&choose.param_ref_id);
        let mut matched = false;
        for when in &choose.whens {
            if !when.default.unwrap_or(false)
                && when.test.as_deref().is_some_and(|test| self.matches_condition(selector_value, test))
            {
                matched = true;
                self.collect_parameter_table_when_refs(&when.items, output);
            }
        }
        if !matched {
            for when in &choose.whens {
                if when.default.unwrap_or(false) {
                    self.collect_parameter_table_when_refs(&when.items, output);
                    break;
                }
            }
        }
    }

    fn collect_parameter_table_when_refs<'a>(&self, items: &'a [WhenItem], output: &mut Vec<TablePlacement<'a>>) {
        for item in items {
            match item {
                WhenItem::ParameterRefRef(parameter_ref) if parameter_ref.cell.is_some() => {
                    output.push(TablePlacement::Parameter(parameter_ref));
                }
                WhenItem::ParameterSeparator(separator) if separator.cell.is_some() => {
                    output.push(TablePlacement::Text(separator));
                }
                WhenItem::ParameterBlock(block) => self.collect_parameter_table_refs(&block.items, output),
                WhenItem::Choose(choose) => self.collect_parameter_table_choose_refs(choose, output),
                _ => {}
            }
        }
    }

    fn build_module_parameter_table(
        &self,
        block: &ParameterBlock,
        expanded: &ExpandedModule,
    ) -> Option<ParameterTable> {
        let rows = block.items.iter().find_map(|item| match item {
            ParameterBlockItem::Rows(rows) => Some(&rows.rows),
            _ => None,
        })?;
        let columns = block.items.iter().find_map(|item| match item {
            ParameterBlockItem::Columns(columns) => Some(&columns.columns),
            _ => None,
        })?;

        let mut table_rows: Vec<_> = rows
            .iter()
            .map(|row| ParameterTableRow {
                text: row
                    .text
                    .as_deref()
                    .map(|text| self.device.interpolate_module_text(text, expanded))
                    .unwrap_or_default(),
                cells: vec![None; columns.len()],
            })
            .collect();
        let mut placements = Vec::new();
        self.collect_module_table_refs(&block.items, expanded, &mut placements);
        for placement in placements {
            let Some((row, column)) = table_cell_indices(placement.cell(), rows.len(), columns.len()) else {
                continue;
            };
            table_rows[row].cells[column] = match placement {
                TablePlacement::Parameter(parameter_ref) => {
                    self.module_parameter_table_cell(&parameter_ref.ref_id, expanded)
                }
                TablePlacement::Text(separator) if separator.access.as_deref() != Some("None") => {
                    Some(ParameterTableCell::Text(
                        separator
                            .text
                            .as_deref()
                            .map(|text| self.device.interpolate_module_text(text, expanded))
                            .unwrap_or_default(),
                    ))
                }
                TablePlacement::Text(_) => None,
            };
        }

        table_rows = table_rows
            .into_iter()
            .zip(rows)
            .filter_map(|(row, definition)| {
                (!definition.collapse_if_empty || row.cells.iter().any(Option::is_some)).then_some(row)
            })
            .collect();

        Some(ParameterTable {
            corner_label: block
                .text
                .as_deref()
                .map(|text| self.device.interpolate_module_text(text, expanded))
                .unwrap_or_default(),
            columns: columns
                .iter()
                .map(|column| ParameterTableColumn {
                    text: column
                        .text
                        .as_deref()
                        .map(|text| self.device.interpolate_module_text(text, expanded))
                        .unwrap_or_default(),
                    weight: table_column_weight(column.width.as_deref()),
                })
                .collect(),
            rows: table_rows,
        })
    }

    fn module_parameter_table_cell(&self, ref_id: &str, expanded: &ExpandedModule) -> Option<ParameterTableCell> {
        self.parameter_table_cell(&format!("{}::{ref_id}", expanded.instance_id))
    }

    fn collect_module_table_refs<'a>(
        &self,
        items: &'a [ParameterBlockItem],
        expanded: &ExpandedModule,
        output: &mut Vec<TablePlacement<'a>>,
    ) {
        for item in items {
            match item {
                ParameterBlockItem::ParameterRefRef(parameter_ref) if parameter_ref.cell.is_some() => {
                    output.push(TablePlacement::Parameter(parameter_ref));
                }
                ParameterBlockItem::ParameterSeparator(separator) if separator.cell.is_some() => {
                    output.push(TablePlacement::Text(separator));
                }
                ParameterBlockItem::ParameterBlock(block) => {
                    self.collect_module_table_refs(&block.items, expanded, output);
                }
                ParameterBlockItem::Choose(choose) => self.collect_module_table_choose_refs(choose, expanded, output),
                _ => {}
            }
        }
    }

    fn collect_module_table_choose_refs<'a>(
        &self,
        choose: &'a Choose,
        expanded: &ExpandedModule,
        output: &mut Vec<TablePlacement<'a>>,
    ) {
        let selector_value = self
            .get_module_selector_value(&choose.param_ref_id, expanded)
            .or_else(|| self.get_selector_value(&choose.param_ref_id));
        let mut matched = false;
        for when in &choose.whens {
            if !when.default.unwrap_or(false)
                && when.test.as_deref().is_some_and(|test| self.matches_condition(selector_value, test))
            {
                matched = true;
                self.collect_module_table_when_refs(&when.items, expanded, output);
            }
        }
        if !matched {
            for when in &choose.whens {
                if when.default.unwrap_or(false) {
                    self.collect_module_table_when_refs(&when.items, expanded, output);
                    break;
                }
            }
        }
    }

    fn collect_module_table_when_refs<'a>(
        &self,
        items: &'a [WhenItem],
        expanded: &ExpandedModule,
        output: &mut Vec<TablePlacement<'a>>,
    ) {
        for item in items {
            match item {
                WhenItem::ParameterRefRef(parameter_ref) if parameter_ref.cell.is_some() => {
                    output.push(TablePlacement::Parameter(parameter_ref));
                }
                WhenItem::ParameterSeparator(separator) if separator.cell.is_some() => {
                    output.push(TablePlacement::Text(separator));
                }
                WhenItem::ParameterBlock(block) => {
                    self.collect_module_table_refs(&block.items, expanded, output);
                }
                WhenItem::Choose(choose) => self.collect_module_table_choose_refs(choose, expanded, output),
                _ => {}
            }
        }
    }

    /// Find a parameter block by exact identity in a CIB, including inside Choose blocks.
    fn find_block_in_cib<'a>(&self, cib: &'a ChannelIndependentBlock, block_id: &str) -> Option<&'a ParameterBlock> {
        for item in &cib.items {
            match item {
                ChannelIndependentItem::ParameterBlockRename(_) => {}
                ChannelIndependentItem::ParameterBlock(pb) => {
                    if let Some(found) = self.find_block_in_parameter_block(pb, block_id) {
                        return Some(found);
                    }
                }
                ChannelIndependentItem::Choose(choose) => {
                    if let Some(pb) = self.find_block_in_choose(choose, block_id) {
                        return Some(pb);
                    }
                }
                ChannelIndependentItem::Module(_)
                | ChannelIndependentItem::Repeat(_)
                | ChannelIndependentItem::ComObjectRefRef(_) => {}
            }
        }
        None
    }

    /// Find a parameter block by exact identity in a channel, including inside Choose blocks.
    fn find_block_in_channel<'a>(&self, channel: &'a Channel, block_id: &str) -> Option<&'a ParameterBlock> {
        for item in &channel.items {
            match item {
                ChannelItem::ParameterBlockRename(_) => {}
                ChannelItem::ComObjectRefRef(_) => {
                    // Direct object placements have no nested blocks.
                }
                ChannelItem::ParameterBlock(pb) => {
                    if let Some(found) = self.find_block_in_parameter_block(pb, block_id) {
                        return Some(found);
                    }
                }
                ChannelItem::Choose(choose) => {
                    if let Some(pb) = self.find_block_in_choose(choose, block_id) {
                        return Some(pb);
                    }
                }
                ChannelItem::Module(_) => {
                    // Module instances have their own blocks - skip for now
                }
                ChannelItem::Repeat(_) => {
                    // Materialized repeat modules have their own pages.
                }
            }
        }
        None
    }

    /// Find a parameter block by name inside a Choose structure.
    /// Note: Multiple when clauses can match the same value in KNX choose blocks.
    fn find_block_in_choose<'a>(&self, choose: &'a Choose, block_id: &str) -> Option<&'a ParameterBlock> {
        let selector_value = self.get_selector_value(&choose.param_ref_id);

        // First pass: search in all matching non-default whens
        let mut any_matched = false;
        for when in &choose.whens {
            if when.default.unwrap_or(false) {
                continue;
            }
            if let Some(test) = &when.test
                && self.matches_condition(selector_value, test)
            {
                any_matched = true;
                if let Some(pb) = self.find_block_in_when_items(&when.items, block_id) {
                    return Some(pb);
                }
            }
        }

        // Second pass: if no explicit when matched, search in default
        if !any_matched {
            for when in &choose.whens {
                if when.default.unwrap_or(false) {
                    return self.find_block_in_when_items(&when.items, block_id);
                }
            }
        }

        None
    }

    fn find_block_in_parameter_block<'a>(
        &self,
        block: &'a ParameterBlock,
        block_id: &str,
    ) -> Option<&'a ParameterBlock> {
        if block.id == block_id {
            return Some(block);
        }
        for item in &block.items {
            match item {
                ParameterBlockItem::ParameterBlock(nested) => {
                    if let Some(found) = self.find_block_in_parameter_block(nested, block_id) {
                        return Some(found);
                    }
                }
                ParameterBlockItem::Choose(choose) => {
                    if let Some(found) = self.find_block_in_choose(choose, block_id) {
                        return Some(found);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Helper to find a block in when items.
    fn find_block_in_when_items<'a>(&self, items: &'a [WhenItem], block_id: &str) -> Option<&'a ParameterBlock> {
        for item in items {
            match item {
                WhenItem::ParameterBlock(pb) => {
                    if let Some(found) = self.find_block_in_parameter_block(pb, block_id) {
                        return Some(found);
                    }
                }
                WhenItem::Choose(nested_choose) => {
                    if let Some(pb) = self.find_block_in_choose(nested_choose, block_id) {
                        return Some(pb);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn add_block_items(&mut self, items: &[ParameterBlockItem]) {
        for item in items {
            match item {
                ParameterBlockItem::ParameterBlock(block) => {
                    // A nested ordinary block is a separate navigation page.
                    // Inline blocks are transparent layout containers whose
                    // contents belong to this page.
                    if block.inline == Some(true) {
                        self.add_parameter_block(block);
                    }
                }
                ParameterBlockItem::ParameterBlockRename(_) => {}
                ParameterBlockItem::ParameterRefRef(prr) => {
                    if self.device.is_param_ref_visible(&prr.ref_id)
                        && let Some(item) = self.parameter_content(&prr.ref_id, prr.text.as_deref())
                    {
                        self.content_items.push(item);
                    }
                }
                ParameterBlockItem::ParameterSeparator(sep) => {
                    let text = sep.text.as_ref().map(|t| self.device.interpolate_text(t));
                    self.content_items.push(ContentItem::Separator { text, ui_hint: sep.ui_hint.clone() });
                }
                ParameterBlockItem::Choose(choose) => {
                    // Process nested choose blocks within parameter blocks
                    self.add_choose_items(choose);
                }
                ParameterBlockItem::ComObjectRefRef(_) => {
                    // Skip comm objects in parameters view
                }
                ParameterBlockItem::Module(module) => {
                    self.add_inline_module(&module.id, &module.ref_id);
                }
                ParameterBlockItem::Repeat(repeat) => {
                    self.add_inline_repeat_modules(&repeat.id);
                }
                ParameterBlockItem::Button(_) => {
                    // Buttons are ETS UI elements, not displayed in TUI
                }
                ParameterBlockItem::Assign(_) | ParameterBlockItem::Channel(_) => {}
                ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => {
                    // Table layout elements, not displayed in TUI
                }
            }
        }
    }

    /// Process a Choose block and add visible items to content.
    /// Note: Multiple when clauses can match the same value in KNX choose blocks.
    fn add_choose_items(&mut self, choose: &Choose) {
        let selector_value = self.get_selector_value(&choose.param_ref_id);

        // First pass: process all matching non-default whens
        let mut any_matched = false;
        for when in &choose.whens {
            if when.default.unwrap_or(false) {
                continue; // Handle defaults in second pass
            }
            if let Some(test) = &when.test
                && self.matches_condition(selector_value, test)
            {
                any_matched = true;
                self.add_when_items(&when.items);
            }
        }

        // Second pass: if no explicit when matched, process default
        if !any_matched {
            for when in &choose.whens {
                if when.default.unwrap_or(false) {
                    self.add_when_items(&when.items);
                    break;
                }
            }
        }
    }

    /// Add items from a when clause to the content.
    fn add_when_items(&mut self, items: &[WhenItem]) {
        for item in items {
            match item {
                WhenItem::ParameterBlockRename(_) => {}
                WhenItem::ParameterRefRef(prr) => {
                    if self.device.is_param_ref_visible(&prr.ref_id)
                        && let Some(item) = self.parameter_content(&prr.ref_id, prr.text.as_deref())
                    {
                        self.content_items.push(item);
                    }
                }
                WhenItem::ParameterSeparator(sep) => {
                    let text = sep.text.as_ref().map(|t| self.device.interpolate_text(t));
                    self.content_items.push(ContentItem::Separator { text, ui_hint: sep.ui_hint.clone() });
                }
                // Manufacturer event handlers execute inside ETS and cannot be
                // meaningfully invoked by the standalone product editor.
                WhenItem::Button(_) => {}
                WhenItem::ParameterBlock(pb) => {
                    if pb.inline == Some(true) {
                        self.add_parameter_block(pb);
                    }
                }
                WhenItem::Choose(nested_choose) => {
                    self.add_choose_items(nested_choose);
                }
                // Channels inside whens exist only at Dynamic level;
                // page content is built per block, never through them.
                WhenItem::Channel(_) => {}
                WhenItem::Module(module) => self.add_inline_module(&module.id, &module.ref_id),
                WhenItem::Repeat(repeat) => self.add_inline_repeat_modules(&repeat.id),
                WhenItem::ComObjectRefRef(_) | WhenItem::Assign(_) => {
                    // Skip comm objects and assignments in parameters view.
                }
            }
        }
    }

    /// Select the shared control from an effective parameter description.
    /// Unsupported editors remain read-only, matching terminal behavior.
    pub fn parameter_widget(description: &ParameterDescription<'_>) -> WidgetType {
        let read_only = !description.writable;
        let value = description.value.as_deref();
        match description.parameter_type {
            Some(ParameterTypeDef::TypeRestriction(tr)) => {
                let current_val = match value {
                    Some(ParameterValue::Integer(v)) => *v,
                    _ => 0,
                };

                if read_only {
                    // Show the current value's enum text as static display.
                    let text = tr
                        .enumerations
                        .iter()
                        .find(|e| e.value as i64 == current_val)
                        .map(|e| e.text.clone())
                        .unwrap_or_else(|| current_val.to_string());
                    return WidgetType::ReadOnly { value: text };
                }

                let options: Vec<(i64, String)> =
                    tr.enumerations.iter().map(|e| (e.value as i64, e.text.clone())).collect();
                let current_idx = options.iter().position(|(v, _)| *v == current_val).unwrap_or(0);

                WidgetType::Dropdown { options, current_idx }
            }
            Some(ParameterTypeDef::TypeNumber(tn)) => {
                let val = match value {
                    Some(ParameterValue::Integer(v)) => *v,
                    _ => 0,
                };
                if read_only {
                    WidgetType::ReadOnly { value: val.to_string() }
                } else {
                    WidgetType::Number { value: val, min: Some(tn.min_inclusive), max: Some(tn.max_inclusive) }
                }
            }
            Some(ParameterTypeDef::TypeTime(time)) => {
                let value = match value {
                    Some(ParameterValue::Integer(value)) => *value,
                    _ => 0,
                };

                if read_only {
                    WidgetType::ReadOnly { value: value.to_string() }
                } else {
                    WidgetType::Number { value, min: Some(time.min_inclusive), max: Some(time.max_inclusive) }
                }
            }
            Some(ParameterTypeDef::TypeFloat(_)) => {
                let val = match value {
                    Some(ParameterValue::Float(v)) => v.to_string(),
                    Some(ParameterValue::Integer(v)) => v.to_string(),
                    _ => "0".to_string(),
                };
                WidgetType::ReadOnly { value: val }
            }
            Some(ParameterTypeDef::TypeText(_) | ParameterTypeDef::TypeColor(_)) => {
                let val = match value {
                    Some(ParameterValue::Text(s)) => s.clone(),
                    _ => String::new(),
                };
                if read_only { WidgetType::ReadOnly { value: val } } else { WidgetType::Text { value: val } }
            }
            Some(ParameterTypeDef::TypeRawData(_)) => WidgetType::ReadOnly {
                value: match value {
                    Some(ParameterValue::Bytes(bytes)) => bytes.iter().map(|byte| format!("{byte:02X}")).collect(),
                    _ => "—".to_string(),
                },
            },
            Some(ParameterTypeDef::TypeNone(_)) | Some(ParameterTypeDef::TypeIpAddress(_)) | None => {
                WidgetType::ReadOnly { value: "—".to_string() }
            }
            // TypePicture should be handled separately - shouldn't reach here
            Some(ParameterTypeDef::TypePicture(_)) => WidgetType::ReadOnly { value: "[picture]".to_string() },
        }
    }
}

fn table_cell_indices(cell: Option<&str>, row_count: usize, column_count: usize) -> Option<(usize, usize)> {
    let (row, column) = cell?.split_once(',')?;
    let row = row.trim().parse::<usize>().ok()?.checked_sub(1)?;
    let column = column.trim().parse::<usize>().ok()?.checked_sub(1)?;
    (row < row_count && column < column_count).then_some((row, column))
}

fn table_column_weight(width: Option<&str>) -> u16 {
    width
        .and_then(|width| width.trim().strip_suffix('%'))
        .and_then(|width| width.parse::<u16>().ok())
        .filter(|weight| *weight > 0)
        .unwrap_or(1)
}

mod decimal_integer {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &i64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
        String::deserialize(deserializer)?.parse().map_err(Error::custom)
    }
}

mod optional_decimal_integer {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(value: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error> {
        value.map(|value| value.to_string()).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<i64>, D::Error> {
        Option::<String>::deserialize(deserializer)?.map(|value| value.parse().map_err(Error::custom)).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::WidgetType;

    #[test]
    fn numeric_controls_cross_json_without_javascript_integer_rounding() {
        let control = WidgetType::Number { value: i64::MAX, min: Some(i64::MIN), max: None };
        let json = serde_json::to_value(&control).expect("numeric control");
        assert_eq!(json["data"]["value"], i64::MAX.to_string());
        assert_eq!(json["data"]["min"], i64::MIN.to_string());
        assert!(json["data"]["max"].is_null());
        assert_eq!(serde_json::from_value::<WidgetType>(json).expect("exact integer round trip"), control);
    }
}
