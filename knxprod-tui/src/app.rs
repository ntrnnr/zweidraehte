//! Application state and logic for the KNX TUI viewer.

use knxprod::model::{DeviceModel, ParameterValue};
use knxprod::{
    Channel, ChannelIndependentBlock, ChannelIndependentItem, ChannelItem, Choose,
    ComObjectPriority, EnableFlag, ParameterBlock, ParameterBlockItem, ParameterTypeDef, WhenItem,
};

/// Interpolate text containing `{{ref:default}}` or `{{ref}}` patterns.
///
/// For patterns like `{{48:Push button 1}}`:
/// - First tries to look up the parameter value via ParameterRef with suffix `_R-48`
/// - If the parameter has a non-empty string value, uses that
/// - Otherwise falls back to the default text after the colon
///
/// For patterns like `{{3059}}` without default:
/// - Looks up the parameter value via ParameterRef with suffix `_R-3059`
/// - If found and non-empty, uses the parameter's string value
/// - Otherwise shows empty string (the parameter is meant to be user-filled)
fn interpolate_text(text: &str, model: &DeviceModel) -> String {
    if !text.contains("{{") {
        return text.to_string();
    }

    let mut result = String::with_capacity(text.len());
    let mut remaining = text;

    while let Some(start) = remaining.find("{{") {
        // Add text before the pattern
        result.push_str(&remaining[..start]);

        // Find the end of the pattern
        if let Some(end) = remaining[start..].find("}}") {
            let pattern = &remaining[start + 2..start + end];

            // Check if there's a default text (format: ref:default)
            let (ref_num, default_text) = if let Some(colon_pos) = pattern.find(':') {
                (&pattern[..colon_pos], Some(&pattern[colon_pos + 1..]))
            } else {
                (pattern, None)
            };

            // Try to look up the parameter value
            let resolved = resolve_param_ref_value(ref_num, model);

            if let Some(value) = resolved {
                if !value.is_empty() {
                    result.push_str(&value);
                } else if let Some(default) = default_text {
                    result.push_str(default);
                }
                // If no value and no default, leave empty
            } else if let Some(default) = default_text {
                // Couldn't find parameter, use default
                result.push_str(default);
            }
            // If no value and no default, leave empty (don't show [ref] placeholder)

            remaining = &remaining[start + end + 2..];
        } else {
            // Malformed pattern, just add the rest
            result.push_str(&remaining[start..]);
            break;
        }
    }

    // Add any remaining text
    result.push_str(remaining);

    result
}

/// Resolve a parameter reference number to its current string value.
///
/// The ref_num is the numeric suffix of a ParameterRef ID (e.g., "3059" for "*_R-3059").
/// Returns the parameter's string value if found, or None.
fn resolve_param_ref_value(ref_num: &str, model: &DeviceModel) -> Option<String> {
    // Find a ParameterRef whose ID ends with _R-{ref_num}
    let suffix = format!("_R-{}", ref_num);

    // Search through all parameter refs to find one matching this suffix
    if let Some(param_refs) = model.program.static_section.parameter_refs.as_ref() {
        for pref in &param_refs.refs {
            if pref.id.ends_with(&suffix) {
                // Found the ParameterRef, now get the parameter value
                if let Some(value) = model.get_parameter_value(&pref.ref_id) {
                    return match value {
                        ParameterValue::Text(s) => Some(s.clone()),
                        ParameterValue::Integer(i) => Some(i.to_string()),
                        ParameterValue::Float(f) => Some(f.to_string()),
                        ParameterValue::Bytes(b) => {
                            // Try to interpret as UTF-8 string
                            String::from_utf8(b.clone()).ok()
                        }
                    };
                }
            }
        }
    }

    None
}

/// Interpolate module text templates like "{{ChNo}}" and "{{0}}".
///
/// Module text templates use argument names:
/// - `{{ChNo}}` - Replaced with the channel number argument value
/// - `{{0}}` - Replaced with the text_param_value if provided, or first text arg
fn interpolate_module_text(text: &str, expanded: &knxprod::model::ExpandedModule) -> String {
    interpolate_module_text_with_param(text, expanded, None)
}

/// Interpolate module text templates with an optional text parameter value.
///
/// The `text_param_value` is used for `{{0}}` substitution when provided.
/// This is typically the value of the parameter referenced by TextParameterRefId.
fn interpolate_module_text_with_param(
    text: &str,
    expanded: &knxprod::model::ExpandedModule,
    text_param_value: Option<&str>,
) -> String {
    use knxprod::model::ModuleArgValue;

    if !text.contains("{{") {
        return text.to_string();
    }

    let mut result = String::with_capacity(text.len());
    let mut remaining = text;

    while let Some(start) = remaining.find("{{") {
        // Add text before the pattern
        result.push_str(&remaining[..start]);

        // Find the end of the pattern
        if let Some(end) = remaining[start..].find("}}") {
            let pattern = &remaining[start + 2..start + end];

            // Look up the argument value
            let resolved = match expanded.args.get(pattern) {
                Some(ModuleArgValue::Numeric(n)) => Some(n.to_string()),
                Some(ModuleArgValue::Text(s)) => Some(s.clone()),
                None => {
                    // Try to interpret as a number index for text args ({{0}}, {{1}}, etc.)
                    if let Ok(idx) = pattern.parse::<usize>() {
                        if idx == 0 {
                            // {{0}} is typically the text parameter value
                            text_param_value.map(|s| s.to_string()).or_else(|| {
                                // Fall back to first text argument if available
                                expanded
                                    .args
                                    .values()
                                    .filter_map(|v| match v {
                                        ModuleArgValue::Text(s) => Some(s.clone()),
                                        _ => None,
                                    })
                                    .next()
                            })
                        } else {
                            // Find the idx-th text argument
                            let text_args: Vec<_> = expanded
                                .args
                                .iter()
                                .filter_map(|(_, v)| match v {
                                    ModuleArgValue::Text(s) => Some(s.clone()),
                                    _ => None,
                                })
                                .collect();
                            text_args.get(idx).cloned()
                        }
                    } else {
                        None
                    }
                }
            };

            if let Some(value) = resolved {
                result.push_str(&value);
            }
            // If not resolved, leave empty

            remaining = &remaining[start + end + 2..];
        } else {
            // Malformed pattern, just add the rest
            result.push_str(&remaining[start..]);
            break;
        }
    }

    // Add any remaining text
    result.push_str(remaining);

    result
}

/// Main tab in the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainTab {
    /// Parameters view with sidebar
    Parameters,
    /// Communication objects table
    CommObjects,
}

/// A node in the sidebar tree (for Parameters tab).
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Unique ID for selection
    pub id: String,
    /// Display name
    pub name: String,
    /// Nesting depth (0 = root)
    pub depth: usize,
    /// Whether this node is expanded
    pub expanded: bool,
    /// Whether this node has children
    pub has_children: bool,
    /// Node type for content loading
    pub node_type: NodeType,
}

/// Type of sidebar tree node.
#[derive(Debug, Clone)]
pub enum NodeType {
    /// Device-wide settings (ChannelIndependentBlock)
    DeviceSettings,
    /// A channel
    Channel(usize),
    /// A parameter block within device settings or channel
    ParameterBlock {
        /// Parent: None = device settings, Some(idx) = channel
        parent: Option<usize>,
        /// Block name/ID
        block_name: String,
    },
    /// A module instance
    ModuleInstance {
        /// Module instance ID
        instance_id: String,
        /// Parent context: None = device level, Some(idx) = channel
        parent: Option<usize>,
    },
}

/// Focus state within the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    /// Tab bar has focus
    Tabs,
    /// Sidebar tree has focus (Parameters tab)
    Sidebar,
    /// Content area has focus
    Content,
}

/// Edit mode state.
#[derive(Debug, Clone)]
pub enum EditMode {
    /// Not editing
    None,
    /// Editing an enum parameter with dropdown
    EnumDropdown {
        param_id: String,
        options: Vec<(i64, String)>,
        selected_idx: usize,
        /// Scroll offset for long dropdown lists
        scroll_offset: usize,
    },
    /// Editing a number parameter
    NumberInput {
        param_id: String,
        buffer: String,
    },
    /// Editing a text parameter
    TextInput {
        param_id: String,
        buffer: String,
        cursor: usize,
    },
}

/// Widget type for rendering.
#[derive(Debug, Clone)]
pub enum WidgetType {
    /// Dropdown/enum selector
    Dropdown {
        options: Vec<(i64, String)>,
        current_idx: usize,
    },
    /// Numeric spinner/input
    Number {
        value: i64,
        min: Option<i64>,
        max: Option<i64>,
    },
    /// Text input field
    Text { value: String },
    /// Read-only display
    ReadOnly { value: String },
}

/// Item in the parameter content area.
#[derive(Debug, Clone)]
pub enum ContentItem {
    /// A parameter with its widget
    Parameter {
        param_id: String,
        text: String,
        suffix: Option<String>,
        widget: WidgetType,
    },
    /// A separator
    Separator { text: Option<String> },
    /// A communication object (displayed inline in module content)
    CommObject {
        name: String,
        function: String,
        dpt: String,
    },
}

/// A row in the communication objects table.
#[derive(Debug, Clone)]
pub struct ComObjectRow {
    /// Object number
    pub number: u16,
    /// Object name/text
    pub name: String,
    /// Function text
    pub function: String,
    /// Group address (empty for now)
    pub group_address: String,
    /// Object size (e.g., "1 Bit", "1 Byte")
    pub size: String,
    /// Datapoint type (e.g., "DPST-1-1")
    pub dpt: String,
    /// Priority
    pub priority: String,
    /// Communication flag
    pub flag_c: bool,
    /// Read flag
    pub flag_r: bool,
    /// Write flag
    pub flag_w: bool,
    /// Transmit flag
    pub flag_t: bool,
    /// Update flag
    pub flag_u: bool,
}

/// Application state.
pub struct App {
    /// The device model
    pub model: DeviceModel,
    /// Current main tab
    pub current_tab: MainTab,
    /// Sidebar tree nodes (for Parameters tab)
    pub tree_nodes: Vec<TreeNode>,
    /// Selected tree node index
    pub selected_tree_idx: usize,
    /// Currently displayed parameter content
    pub content_items: Vec<ContentItem>,
    /// Selected content item index
    pub selected_content_idx: usize,
    /// Communication objects table rows
    pub com_object_rows: Vec<ComObjectRow>,
    /// Selected comm object row index
    pub selected_obj_idx: usize,
    /// Current focus
    pub focus: Focus,
    /// Current edit mode
    pub edit_mode: EditMode,
    /// Set of expanded tree node IDs
    pub expanded_nodes: std::collections::HashSet<String>,
    /// Whether the app should quit
    pub should_quit: bool,
}

impl App {
    /// Create a new application with the given device model.
    pub fn new(model: DeviceModel) -> Self {
        let mut app = Self {
            model,
            current_tab: MainTab::Parameters,
            tree_nodes: Vec::new(),
            selected_tree_idx: 0,
            content_items: Vec::new(),
            selected_content_idx: 0,
            com_object_rows: Vec::new(),
            selected_obj_idx: 0,
            focus: Focus::Tabs,
            edit_mode: EditMode::None,
            expanded_nodes: std::collections::HashSet::new(),
            should_quit: false,
        };

        // Build initial data
        app.rebuild_tree();
        app.rebuild_content();
        app.rebuild_com_objects();

        app
    }

    /// Switch to next main tab.
    pub fn next_tab(&mut self) {
        self.current_tab = match self.current_tab {
            MainTab::Parameters => MainTab::CommObjects,
            MainTab::CommObjects => MainTab::Parameters,
        };
        // Reset focus when switching tabs
        self.focus = Focus::Tabs;
    }

    /// Switch to previous main tab.
    pub fn prev_tab(&mut self) {
        self.next_tab(); // Only 2 tabs, so prev == next
    }

    /// Rebuild the sidebar tree based on the model structure.
    pub fn rebuild_tree(&mut self) {
        self.tree_nodes.clear();

        // Clone to avoid borrow issues
        let dynamic = self.model.dynamic_section().cloned();

        if let Some(dynamic) = dynamic {
            // Device settings node (if there's a channel-independent block)
            if let Some(cib) = &dynamic.channel_independent_block {
                let device_id = "device".to_string();
                let device_expanded = self.expanded_nodes.contains(&device_id);

                self.tree_nodes.push(TreeNode {
                    id: device_id.clone(),
                    name: "Device Settings".to_string(),
                    depth: 0,
                    expanded: device_expanded,
                    has_children: self.count_visible_blocks_in_cib(cib) > 0,
                    node_type: NodeType::DeviceSettings,
                });

                // Add child blocks if expanded
                if device_expanded {
                    self.add_cib_blocks_to_tree(cib, 1);
                }
            }

            // Channel nodes
            for (i, channel) in dynamic.channels.iter().enumerate() {
                let channel_id = format!("channel_{}", i);
                let channel_expanded = self.expanded_nodes.contains(&channel_id);
                let channel_name = channel
                    .text
                    .clone()
                    .unwrap_or_else(|| channel.name.clone());

                self.tree_nodes.push(TreeNode {
                    id: channel_id.clone(),
                    name: channel_name,
                    depth: 0,
                    expanded: channel_expanded,
                    has_children: self.count_visible_blocks_in_channel(channel) > 0,
                    node_type: NodeType::Channel(i),
                });

                // Add child blocks if expanded
                if channel_expanded {
                    self.add_channel_blocks_to_tree(channel, i, 1);
                }
            }
        }
    }

    fn count_visible_blocks_in_cib(&self, cib: &ChannelIndependentBlock) -> usize {
        let mut blocks = Vec::new();
        self.collect_visible_cib_blocks(cib, &mut blocks);
        blocks.len()
    }

    fn count_visible_blocks_in_channel(&self, channel: &Channel) -> usize {
        let mut blocks = Vec::new();
        self.collect_visible_channel_blocks(channel, &mut blocks);

        let mut modules = Vec::new();
        self.collect_visible_channel_modules(channel, &mut modules);

        blocks.len() + modules.len()
    }

    /// Collect all visible parameter blocks from a channel, including those nested in Choose blocks.
    fn collect_visible_channel_blocks<'a>(
        &self,
        channel: &'a Channel,
        blocks: &mut Vec<&'a ParameterBlock>,
    ) {
        for item in &channel.items {
            match item {
                ChannelItem::ParameterBlock(pb) => {
                    if self.block_has_visible_items(&pb.items) {
                        blocks.push(pb);
                    }
                }
                ChannelItem::Choose(choose) => {
                    self.collect_blocks_from_choose(choose, blocks);
                }
                ChannelItem::Module(_) => {
                    // Modules are collected separately via collect_visible_modules
                }
            }
        }
    }

    /// Collect all visible module instances from a channel.
    fn collect_visible_channel_modules<'a>(
        &self,
        channel: &'a Channel,
        modules: &mut Vec<&'a knxprod::Module>,
    ) {
        for item in &channel.items {
            match item {
                ChannelItem::Module(module) => {
                    if self.model.is_module_visible(&module.id) {
                        modules.push(module);
                    }
                }
                ChannelItem::Choose(choose) => {
                    self.collect_modules_from_choose(choose, modules);
                }
                ChannelItem::ParameterBlock(pb) => {
                    // Modules can be inside parameter blocks
                    self.collect_modules_from_pb(&pb.items, modules);
                }
            }
        }
    }

    /// Collect modules from parameter block items.
    fn collect_modules_from_pb<'a>(
        &self,
        items: &'a [ParameterBlockItem],
        modules: &mut Vec<&'a knxprod::Module>,
    ) {
        for item in items {
            match item {
                ParameterBlockItem::Module(module) => {
                    if self.model.is_module_visible(&module.id) {
                        modules.push(module);
                    }
                }
                ParameterBlockItem::Choose(choose) => {
                    self.collect_modules_from_choose(choose, modules);
                }
                _ => {}
            }
        }
    }

    /// Collect modules from Choose blocks.
    fn collect_modules_from_choose<'a>(
        &self,
        choose: &'a Choose,
        modules: &mut Vec<&'a knxprod::Module>,
    ) {
        let selector_value = self.get_selector_value(&choose.param_ref_id);

        let mut any_matched = false;
        for when in &choose.whens {
            if when.default.unwrap_or(false) {
                continue;
            }
            if let Some(test) = &when.test {
                if self.matches_condition(selector_value, test) {
                    any_matched = true;
                    self.collect_modules_from_when(&when.items, modules);
                }
            }
        }

        if !any_matched {
            for when in &choose.whens {
                if when.default.unwrap_or(false) {
                    self.collect_modules_from_when(&when.items, modules);
                    break;
                }
            }
        }
    }

    /// Collect modules from when items.
    fn collect_modules_from_when<'a>(
        &self,
        items: &'a [WhenItem],
        modules: &mut Vec<&'a knxprod::Module>,
    ) {
        for item in items {
            match item {
                WhenItem::Module(module) => {
                    if self.model.is_module_visible(&module.id) {
                        modules.push(module);
                    }
                }
                WhenItem::Choose(nested_choose) => {
                    self.collect_modules_from_choose(nested_choose, modules);
                }
                _ => {}
            }
        }
    }

    /// Collect parameter blocks from a Choose structure based on current parameter values.
    /// Note: Multiple when clauses can match the same value in KNX choose blocks.
    fn collect_blocks_from_choose<'a>(
        &self,
        choose: &'a Choose,
        blocks: &mut Vec<&'a ParameterBlock>,
    ) {
        // Get the selector parameter value
        let selector_value = self.get_selector_value(&choose.param_ref_id);

        // First pass: collect all matching non-default whens
        let mut any_matched = false;
        for when in &choose.whens {
            if when.default.unwrap_or(false) {
                continue; // Handle defaults in second pass
            }
            if let Some(test) = &when.test {
                if self.matches_condition(selector_value, test) {
                    any_matched = true;
                    self.collect_when_blocks(&when.items, blocks);
                }
            }
        }

        // Second pass: if no explicit when matched, process default
        if !any_matched {
            for when in &choose.whens {
                if when.default.unwrap_or(false) {
                    self.collect_when_blocks(&when.items, blocks);
                    break;
                }
            }
        }
    }

    /// Helper to collect blocks from when items.
    fn collect_when_blocks<'a>(&self, items: &'a [WhenItem], blocks: &mut Vec<&'a ParameterBlock>) {
        for item in items {
            match item {
                WhenItem::ParameterBlock(pb) => {
                    if self.block_has_visible_items(&pb.items) {
                        blocks.push(pb);
                    }
                }
                WhenItem::Choose(nested_choose) => {
                    self.collect_blocks_from_choose(nested_choose, blocks);
                }
                _ => {}
            }
        }
    }

    /// Get the integer value of a selector parameter ref.
    fn get_selector_value(&self, param_ref_id: &str) -> Option<i64> {
        let param_ref = self.model.get_parameter_ref(param_ref_id)?;
        let param_value = self.model.get_parameter_value(&param_ref.ref_id)?;

        match param_value {
            ParameterValue::Integer(v) => Some(*v),
            ParameterValue::Float(v) => Some(*v as i64),
            _ => None,
        }
    }

    /// Check if a selector value matches a condition test string.
    fn matches_condition(&self, value: Option<i64>, test: &str) -> bool {
        let value = match value {
            Some(v) => v,
            None => return false,
        };

        let test = test.trim();

        // Handle comparison operators
        if let Some(rest) = test.strip_prefix("!=") {
            if let Ok(test_val) = rest.trim().parse::<i64>() {
                return value != test_val;
            }
        } else if let Some(rest) = test.strip_prefix(">=") {
            if let Ok(test_val) = rest.trim().parse::<i64>() {
                return value >= test_val;
            }
        } else if let Some(rest) = test.strip_prefix("<=") {
            if let Ok(test_val) = rest.trim().parse::<i64>() {
                return value <= test_val;
            }
        } else if let Some(rest) = test.strip_prefix('>') {
            if let Ok(test_val) = rest.trim().parse::<i64>() {
                return value > test_val;
            }
        } else if let Some(rest) = test.strip_prefix('<') {
            if let Ok(test_val) = rest.trim().parse::<i64>() {
                return value < test_val;
            }
        } else if let Some(rest) = test.strip_prefix('=') {
            if let Ok(test_val) = rest.trim().parse::<i64>() {
                return value == test_val;
            }
        }

        // Handle space-separated list of values (OR)
        for part in test.split_whitespace() {
            if let Ok(test_val) = part.parse::<i64>() {
                if value == test_val {
                    return true;
                }
            }
        }

        false
    }

    fn add_cib_blocks_to_tree(&mut self, cib: &ChannelIndependentBlock, depth: usize) {
        let mut blocks = Vec::new();
        self.collect_visible_cib_blocks(cib, &mut blocks);

        for pb in blocks {
            let block_id = format!("device_block_{}", pb.name);
            let raw_text = pb.text.clone().unwrap_or_else(|| pb.name.clone());
            let text = interpolate_text(&raw_text, &self.model);

            self.tree_nodes.push(TreeNode {
                id: block_id,
                name: text,
                depth,
                expanded: false,
                has_children: false,
                node_type: NodeType::ParameterBlock {
                    parent: None,
                    block_name: pb.name.clone(),
                },
            });
        }
    }

    /// Collect all visible parameter blocks from CIB, including those nested in Choose blocks.
    fn collect_visible_cib_blocks<'a>(
        &self,
        cib: &'a ChannelIndependentBlock,
        blocks: &mut Vec<&'a ParameterBlock>,
    ) {
        for item in &cib.items {
            match item {
                ChannelIndependentItem::ParameterBlock(pb) => {
                    if self.block_has_visible_items(&pb.items) {
                        blocks.push(pb);
                    }
                }
                ChannelIndependentItem::Choose(choose) => {
                    self.collect_blocks_from_choose(choose, blocks);
                }
            }
        }
    }

    fn add_channel_blocks_to_tree(&mut self, channel: &Channel, channel_idx: usize, depth: usize) {
        // Add parameter blocks
        let mut blocks = Vec::new();
        self.collect_visible_channel_blocks(channel, &mut blocks);

        for pb in blocks {
            let block_id = format!("channel_{}_block_{}", channel_idx, pb.name);
            let raw_text = pb.text.clone().unwrap_or_else(|| pb.name.clone());
            let text = interpolate_text(&raw_text, &self.model);

            self.tree_nodes.push(TreeNode {
                id: block_id,
                name: text,
                depth,
                expanded: false,
                has_children: false,
                node_type: NodeType::ParameterBlock {
                    parent: Some(channel_idx),
                    block_name: pb.name.clone(),
                },
            });
        }

        // Add visible module instances
        let mut modules = Vec::new();
        self.collect_visible_channel_modules(channel, &mut modules);

        for module in modules {
            // Get module name from expanded module data
            let expanded = self.model.get_expanded_module(&module.id);
            let name = if let Some(exp) = expanded {
                // Try to build a friendly display name from the module's Dynamic section
                if let Some(module_def) = self.model.get_module_def(&exp.module_def_id) {
                    // Get the first ParameterBlock's text and text_parameter_ref_id
                    let (block_text, text_param_ref_id) = module_def
                        .dynamic
                        .as_ref()
                        .and_then(|dyn_sec| {
                            dyn_sec.items.iter().find_map(|item| {
                                if let knxprod::ModuleDefDynamicItem::ParameterBlock(pb) = item {
                                    Some((pb.text.clone(), pb.text_parameter_ref_id.clone()))
                                } else {
                                    None
                                }
                            })
                        })
                        .unwrap_or((None, None));

                    // Look up the text parameter value for {{0}} substitution
                    let text_param_value = text_param_ref_id.and_then(|ref_id| {
                        // Find the ParameterRef to get the parameter ID
                        let param_ref = module_def
                            .static_section
                            .parameter_refs
                            .as_ref()
                            .and_then(|refs| refs.refs.iter().find(|pr| pr.id == ref_id));

                        param_ref.and_then(|pr| {
                            // Build composite ID and look up value
                            let composite_id = format!("{}::{}", exp.instance_id, pr.ref_id);
                            self.model
                                .get_module_parameter_value(&composite_id)
                                .and_then(|v| match v {
                                    ParameterValue::Text(s) if !s.is_empty() => Some(s.clone()),
                                    ParameterValue::Integer(i) => Some(i.to_string()),
                                    _ => None,
                                })
                        })
                    });

                    if let Some(text) = block_text {
                        // Interpolate {{ChNo}} and {{0}} in the text
                        interpolate_module_text_with_param(
                            &text,
                            exp,
                            text_param_value.as_deref(),
                        )
                    } else if let Some(instance_name) = &exp.name {
                        interpolate_module_text(instance_name, exp)
                    } else {
                        // Fallback: use module name with channel number
                        if let Some(knxprod::model::ModuleArgValue::Numeric(ch)) =
                            exp.args.get("ChNo")
                        {
                            format!("{} {}", module_def.name, ch)
                        } else {
                            module_def.name.clone()
                        }
                    }
                } else if let Some(instance_name) = &exp.name {
                    interpolate_module_text(instance_name, exp)
                } else {
                    module.id.clone()
                }
            } else {
                module.name.clone().unwrap_or_else(|| module.id.clone())
            };

            let node_id = format!("channel_{}_module_{}", channel_idx, module.id);

            self.tree_nodes.push(TreeNode {
                id: node_id,
                name,
                depth,
                expanded: false,
                has_children: false,
                node_type: NodeType::ModuleInstance {
                    instance_id: module.id.clone(),
                    parent: Some(channel_idx),
                },
            });
        }
    }

    fn block_has_visible_items(&self, items: &[ParameterBlockItem]) -> bool {
        for item in items {
            match item {
                ParameterBlockItem::ParameterRefRef(prr) => {
                    if self.model.is_param_ref_visible(&prr.ref_id) {
                        return true;
                    }
                }
                ParameterBlockItem::ComObjectRefRef(corr) => {
                    if self.model.is_com_object_ref_visible(&corr.ref_id) {
                        return true;
                    }
                }
                ParameterBlockItem::Choose(_) => {
                    return true;
                }
                ParameterBlockItem::ParameterSeparator(_) => {}
                ParameterBlockItem::Module(_) => {
                    // Module instances are shown separately
                }
            }
        }
        false
    }

    /// Set a parameter value, handling both regular and module parameters.
    fn set_any_parameter_value(&mut self, param_id: &str, value: ParameterValue) {
        if self.model.is_module_parameter(param_id) {
            self.model.set_module_parameter_value(param_id, value);
        } else {
            self.model.set_parameter_value(param_id, value);
        }
    }

    /// Rebuild parameter content based on selected tree node.
    pub fn rebuild_content(&mut self) {
        self.content_items.clear();

        // Clone node_type to avoid borrow conflict
        let node_type = self
            .tree_nodes
            .get(self.selected_tree_idx)
            .map(|n| n.node_type.clone());

        if let Some(node_type) = node_type {
            match &node_type {
                NodeType::DeviceSettings => {
                    self.build_device_settings_content();
                }
                NodeType::Channel(idx) => {
                    self.build_channel_content(*idx);
                }
                NodeType::ParameterBlock { parent, block_name } => {
                    self.build_block_content(*parent, block_name);
                }
                NodeType::ModuleInstance { instance_id, .. } => {
                    self.build_module_content(instance_id);
                }
            }
        }
    }

    fn build_device_settings_content(&mut self) {
        let cib = self
            .model
            .dynamic_section()
            .and_then(|d| d.channel_independent_block.clone());

        if let Some(cib) = cib {
            for item in &cib.items {
                match item {
                    ChannelIndependentItem::ParameterBlock(pb) => {
                        self.add_block_items(&pb.items);
                    }
                    ChannelIndependentItem::Choose(choose) => {
                        // Process Choose blocks to include their visible content
                        self.add_choose_items(choose);
                    }
                }
            }
        }
    }

    fn build_channel_content(&mut self, channel_idx: usize) {
        let channel = self
            .model
            .dynamic_section()
            .and_then(|d| d.channels.get(channel_idx).cloned());

        if let Some(channel) = channel {
            for item in &channel.items {
                match item {
                    ChannelItem::ParameterBlock(pb) => {
                        self.add_block_items(&pb.items);
                    }
                    ChannelItem::Choose(choose) => {
                        // Process Choose blocks to include their visible content
                        self.add_choose_items(choose);
                    }
                    ChannelItem::Module(_) => {
                        // Module instances have their own dynamic content - skip for now
                    }
                }
            }
        }
    }

    fn build_block_content(&mut self, parent: Option<usize>, block_name: &str) {
        let dynamic = self.model.dynamic_section().cloned();

        if let Some(dynamic) = dynamic {
            match parent {
                None => {
                    // Device settings block
                    if let Some(cib) = &dynamic.channel_independent_block {
                        if let Some(pb) = self.find_block_in_cib(&cib, block_name) {
                            self.add_block_items(&pb.items.clone());
                        }
                    }
                }
                Some(channel_idx) => {
                    if let Some(channel) = dynamic.channels.get(channel_idx) {
                        if let Some(pb) = self.find_block_in_channel(channel, block_name) {
                            self.add_block_items(&pb.items.clone());
                        }
                    }
                }
            }
        }
    }

    /// Build content for a module instance.
    fn build_module_content(&mut self, instance_id: &str) {
        // Get the expanded module and its definition
        let expanded = self.model.get_expanded_module(instance_id).cloned();
        let expanded = match expanded {
            Some(e) => e,
            None => return,
        };

        let module_def = self.model.get_module_def(&expanded.module_def_id).cloned();
        let module_def = match module_def {
            Some(def) => def,
            None => return,
        };

        // If the module has a Dynamic section, render its contents
        if let Some(dynamic) = &module_def.dynamic {
            for item in &dynamic.items {
                match item {
                    knxprod::ModuleDefDynamicItem::ParameterBlock(pb) => {
                        self.add_module_block_items(&pb.items, &expanded);
                    }
                    knxprod::ModuleDefDynamicItem::Choose(choose) => {
                        self.add_module_choose_items(choose, &expanded);
                    }
                }
            }
        } else {
            // Fall back to rendering params from Static section
            // For now, just show a placeholder message
            self.content_items.push(ContentItem::Separator {
                text: Some(format!(
                    "Module: {}",
                    expanded.name.as_deref().unwrap_or(&expanded.instance_id)
                )),
            });
        }
    }

    /// Add parameter block items for a module, applying text interpolation.
    fn add_module_block_items(
        &mut self,
        items: &[ParameterBlockItem],
        expanded: &knxprod::model::ExpandedModule,
    ) {
        for item in items {
            match item {
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
                    let text = raw_text.map(|t| interpolate_module_text(&t, expanded));
                    self.content_items.push(ContentItem::Separator { text });
                }
                ParameterBlockItem::Module(_) => {
                    // Nested modules not supported yet
                }
            }
        }
    }

    /// Add choose items for a module.
    fn add_module_choose_items(
        &mut self,
        choose: &Choose,
        expanded: &knxprod::model::ExpandedModule,
    ) {
        let selector_value = self.get_selector_value(&choose.param_ref_id);

        let mut any_matched = false;
        for when in &choose.whens {
            if when.default.unwrap_or(false) {
                continue;
            }
            if let Some(test) = &when.test {
                if self.matches_condition(selector_value, test) {
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

    /// Add when items for a module.
    fn add_module_when_items(
        &mut self,
        items: &[WhenItem],
        expanded: &knxprod::model::ExpandedModule,
    ) {
        for item in items {
            match item {
                WhenItem::ParameterRefRef(prr) => {
                    self.add_module_param_ref(&prr.ref_id, expanded);
                }
                WhenItem::ComObjectRefRef(corr) => {
                    self.add_module_com_obj_ref(&corr.ref_id, expanded);
                }
                WhenItem::ParameterBlock(pb) => {
                    self.add_module_block_items(&pb.items, expanded);
                }
                WhenItem::Choose(nested_choose) => {
                    self.add_module_choose_items(nested_choose, expanded);
                }
                WhenItem::ParameterSeparator(sep) => {
                    let raw_text = sep.text.clone();
                    let text = raw_text.map(|t| interpolate_module_text(&t, expanded));
                    self.content_items.push(ContentItem::Separator { text });
                }
                WhenItem::Assign(_) => {}
                WhenItem::Module(_) => {}
            }
        }
    }

    /// Add a module parameter ref to content items.
    fn add_module_param_ref(
        &mut self,
        ref_id: &str,
        expanded: &knxprod::model::ExpandedModule,
    ) {
        // Look up the ModuleDef to access its static section
        let module_def = match self.model.get_module_def(&expanded.module_def_id) {
            Some(def) => def.clone(),
            None => return,
        };

        // Find the ParameterRef in the module's static section
        let param_ref = module_def
            .static_section
            .parameter_refs
            .as_ref()
            .and_then(|refs| refs.refs.iter().find(|pr| pr.id == ref_id));

        let param_ref = match param_ref {
            Some(pr) => pr.clone(),
            None => return,
        };

        // Find the Parameter using the RefId
        let parameter = module_def
            .static_section
            .parameters
            .as_ref()
            .and_then(|params| {
                params.items.iter().find_map(|item| match item {
                    knxprod::ParameterItem::Parameter(p) if p.id == param_ref.ref_id => Some(p),
                    _ => None,
                })
            });

        let parameter = match parameter {
            Some(p) => p.clone(),
            None => return,
        };

        // Skip hidden parameters
        if parameter.access.as_deref() == Some("None") {
            return;
        }

        // Build display text with interpolation
        let raw_text = param_ref
            .text
            .clone()
            .unwrap_or_else(|| parameter.text.clone());

        if raw_text.is_empty() {
            return;
        }

        let text = interpolate_module_text(&raw_text, expanded);

        // Use a unique ID that includes the module instance
        let param_id = format!("{}::{}", expanded.instance_id, parameter.id);

        // Build widget based on parameter type
        let widget = self.build_widget_for_module_param(&parameter, &module_def, &param_id);

        self.content_items.push(ContentItem::Parameter {
            param_id,
            text,
            suffix: parameter.suffix_text.clone(),
            widget,
        });
    }

    /// Build a widget for a module parameter.
    fn build_widget_for_module_param(
        &self,
        parameter: &knxprod::Parameter,
        _module_def: &knxprod::ModuleDef,
        composite_param_id: &str,
    ) -> WidgetType {
        use knxprod::ParameterTypeDef;

        // Get the current value from module parameter storage
        let current_value = self.model.get_module_parameter_value(composite_param_id);

        // Look up the parameter type
        let param_type = self.model.get_parameter_type(&parameter.parameter_type);

        match param_type.map(|pt| &pt.type_def) {
            Some(ParameterTypeDef::TypeRestriction(tr)) => {
                // Build dropdown options from enumerations
                let options: Vec<(i64, String)> = tr
                    .enumerations
                    .iter()
                    .map(|e| (e.value as i64, e.text.clone()))
                    .collect();

                let current_val = match current_value {
                    Some(ParameterValue::Integer(v)) => *v,
                    _ => parameter.value.parse().unwrap_or(0),
                };

                let current_idx = options
                    .iter()
                    .position(|(v, _)| *v == current_val)
                    .unwrap_or(0);

                WidgetType::Dropdown {
                    options,
                    current_idx,
                }
            }
            Some(ParameterTypeDef::TypeNumber(tn)) => {
                let current_val = match current_value {
                    Some(ParameterValue::Integer(v)) => *v,
                    _ => parameter.value.parse().unwrap_or(0),
                };

                WidgetType::Number {
                    value: current_val,
                    min: Some(tn.min_inclusive),
                    max: Some(tn.max_inclusive),
                }
            }
            Some(ParameterTypeDef::TypeText(_)) => {
                let val = match current_value {
                    Some(ParameterValue::Text(s)) => s.clone(),
                    _ => parameter.value.clone(),
                };
                WidgetType::Text { value: val }
            }
            Some(ParameterTypeDef::TypeFloat(tf)) => {
                let current_val = match current_value {
                    Some(ParameterValue::Integer(v)) => *v,
                    Some(ParameterValue::Float(v)) => *v as i64,
                    _ => parameter.value.parse().unwrap_or(0),
                };

                WidgetType::Number {
                    value: current_val,
                    min: Some(tf.min_inclusive as i64),
                    max: Some(tf.max_inclusive as i64),
                }
            }
            Some(ParameterTypeDef::TypeNone(_)) | None => {
                // For unknown types, show as read-only
                let val = match current_value {
                    Some(ParameterValue::Integer(v)) => v.to_string(),
                    Some(ParameterValue::Text(s)) => s.clone(),
                    _ => parameter.value.clone(),
                };
                WidgetType::ReadOnly { value: val }
            }
        }
    }

    /// Add a module comm object ref to content items.
    fn add_module_com_obj_ref(
        &mut self,
        ref_id: &str,
        expanded: &knxprod::model::ExpandedModule,
    ) {
        // Look up the ModuleDef to access its static section
        let module_def = match self.model.get_module_def(&expanded.module_def_id) {
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
        let raw_text = com_obj_ref
            .text
            .clone()
            .unwrap_or_else(|| com_object.text.clone());

        let text = interpolate_module_text(&raw_text, expanded);

        // Add as a comm object display item
        self.content_items.push(ContentItem::CommObject {
            name: text,
            function: com_obj_ref
                .function_text
                .clone()
                .unwrap_or_else(|| com_object.function_text.clone()),
            dpt: com_obj_ref
                .datapoint_type
                .clone()
                .or_else(|| com_object.datapoint_type.clone())
                .unwrap_or_default(),
        });
    }

    /// Find a parameter block by name in a CIB, including inside Choose blocks.
    fn find_block_in_cib<'a>(
        &self,
        cib: &'a ChannelIndependentBlock,
        block_name: &str,
    ) -> Option<&'a ParameterBlock> {
        for item in &cib.items {
            match item {
                ChannelIndependentItem::ParameterBlock(pb) => {
                    if pb.name == block_name {
                        return Some(pb);
                    }
                }
                ChannelIndependentItem::Choose(choose) => {
                    if let Some(pb) = self.find_block_in_choose(choose, block_name) {
                        return Some(pb);
                    }
                }
            }
        }
        None
    }

    /// Find a parameter block by name in a channel, including inside Choose blocks.
    fn find_block_in_channel<'a>(
        &self,
        channel: &'a Channel,
        block_name: &str,
    ) -> Option<&'a ParameterBlock> {
        for item in &channel.items {
            match item {
                ChannelItem::ParameterBlock(pb) => {
                    if pb.name == block_name {
                        return Some(pb);
                    }
                }
                ChannelItem::Choose(choose) => {
                    if let Some(pb) = self.find_block_in_choose(choose, block_name) {
                        return Some(pb);
                    }
                }
                ChannelItem::Module(_) => {
                    // Module instances have their own blocks - skip for now
                }
            }
        }
        None
    }

    /// Find a parameter block by name inside a Choose structure.
    /// Note: Multiple when clauses can match the same value in KNX choose blocks.
    fn find_block_in_choose<'a>(
        &self,
        choose: &'a Choose,
        block_name: &str,
    ) -> Option<&'a ParameterBlock> {
        let selector_value = self.get_selector_value(&choose.param_ref_id);

        // First pass: search in all matching non-default whens
        let mut any_matched = false;
        for when in &choose.whens {
            if when.default.unwrap_or(false) {
                continue;
            }
            if let Some(test) = &when.test {
                if self.matches_condition(selector_value, test) {
                    any_matched = true;
                    if let Some(pb) = self.find_block_in_when_items(&when.items, block_name) {
                        return Some(pb);
                    }
                }
            }
        }

        // Second pass: if no explicit when matched, search in default
        if !any_matched {
            for when in &choose.whens {
                if when.default.unwrap_or(false) {
                    return self.find_block_in_when_items(&when.items, block_name);
                }
            }
        }

        None
    }

    /// Helper to find a block in when items.
    fn find_block_in_when_items<'a>(
        &self,
        items: &'a [WhenItem],
        block_name: &str,
    ) -> Option<&'a ParameterBlock> {
        for item in items {
            match item {
                WhenItem::ParameterBlock(pb) => {
                    if pb.name == block_name {
                        return Some(pb);
                    }
                }
                WhenItem::Choose(nested_choose) => {
                    if let Some(pb) = self.find_block_in_choose(nested_choose, block_name) {
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
                ParameterBlockItem::ParameterRefRef(prr) => {
                    if self.model.is_param_ref_visible(&prr.ref_id) {
                        if let Some(pref) = self.model.get_parameter_ref(&prr.ref_id) {
                            // Skip if the ParameterRef itself has Access="None"
                            if pref.access.as_deref() == Some("None") {
                                continue;
                            }

                            let param_id = pref.ref_id.clone();

                            // Skip hidden parameters (Access="None") or those with empty text
                            if let Some(info) = self.model.get_parameter_info(&param_id) {
                                if info.hidden || info.text.is_empty() {
                                    continue;
                                }
                            }

                            let raw_text = prr
                                .text
                                .clone()
                                .or_else(|| pref.text.clone())
                                .unwrap_or_else(|| {
                                    self.model
                                        .get_parameter_info(&param_id)
                                        .map(|p| p.text.clone())
                                        .unwrap_or_else(|| param_id.clone())
                                });

                            // Skip if the final text is empty
                            if raw_text.is_empty() {
                                continue;
                            }

                            let text = interpolate_text(&raw_text, &self.model);

                            let suffix = self
                                .model
                                .get_parameter_info(&param_id)
                                .and_then(|p| p.suffix.clone());

                            let widget = self.build_widget_for_param(&param_id);

                            self.content_items.push(ContentItem::Parameter {
                                param_id,
                                text,
                                suffix,
                                widget,
                            });
                        }
                    }
                }
                ParameterBlockItem::ParameterSeparator(sep) => {
                    let text = sep.text.as_ref().map(|t| interpolate_text(t, &self.model));
                    self.content_items.push(ContentItem::Separator { text });
                }
                ParameterBlockItem::Choose(choose) => {
                    // Process nested choose blocks within parameter blocks
                    self.add_choose_items(choose);
                }
                ParameterBlockItem::ComObjectRefRef(_) => {
                    // Skip comm objects in parameters view
                }
                ParameterBlockItem::Module(_) => {
                    // Module instances are shown separately
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
            if let Some(test) = &when.test {
                if self.matches_condition(selector_value, test) {
                    any_matched = true;
                    self.add_when_items(&when.items);
                }
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
                WhenItem::ParameterRefRef(prr) => {
                    if self.model.is_param_ref_visible(&prr.ref_id) {
                        if let Some(pref) = self.model.get_parameter_ref(&prr.ref_id) {
                            // Skip if the ParameterRef itself has Access="None"
                            if pref.access.as_deref() == Some("None") {
                                continue;
                            }

                            let param_id = pref.ref_id.clone();

                            // Skip hidden parameters (Access="None") or those with empty text
                            if let Some(info) = self.model.get_parameter_info(&param_id) {
                                if info.hidden || info.text.is_empty() {
                                    continue;
                                }
                            }

                            let raw_text = prr
                                .text
                                .clone()
                                .or_else(|| pref.text.clone())
                                .unwrap_or_else(|| {
                                    self.model
                                        .get_parameter_info(&param_id)
                                        .map(|p| p.text.clone())
                                        .unwrap_or_else(|| param_id.clone())
                                });

                            // Skip if the final text is empty
                            if raw_text.is_empty() {
                                continue;
                            }

                            let text = interpolate_text(&raw_text, &self.model);

                            let suffix = self
                                .model
                                .get_parameter_info(&param_id)
                                .and_then(|p| p.suffix.clone());

                            let widget = self.build_widget_for_param(&param_id);

                            self.content_items.push(ContentItem::Parameter {
                                param_id,
                                text,
                                suffix,
                                widget,
                            });
                        }
                    }
                }
                WhenItem::ParameterSeparator(sep) => {
                    let text = sep.text.as_ref().map(|t| interpolate_text(t, &self.model));
                    self.content_items.push(ContentItem::Separator { text });
                }
                WhenItem::ParameterBlock(pb) => {
                    self.add_block_items(&pb.items);
                }
                WhenItem::Choose(nested_choose) => {
                    self.add_choose_items(nested_choose);
                }
                WhenItem::ComObjectRefRef(_) | WhenItem::Assign(_) | WhenItem::Module(_) => {
                    // Skip comm objects, assignments, and modules in parameters view
                }
            }
        }
    }

    fn build_widget_for_param(&self, param_id: &str) -> WidgetType {
        let info = match self.model.get_parameter_info(param_id) {
            Some(i) => i,
            None => {
                return WidgetType::ReadOnly {
                    value: "?".to_string(),
                }
            }
        };

        let ptype = self.model.get_parameter_type(&info.type_id);
        let value = self.model.get_parameter_value(param_id);

        match ptype.map(|pt| &pt.type_def) {
            Some(ParameterTypeDef::TypeRestriction(tr)) => {
                let current_val = match value {
                    Some(ParameterValue::Integer(v)) => *v,
                    _ => 0,
                };
                let options: Vec<(i64, String)> = tr
                    .enumerations
                    .iter()
                    .map(|e| (e.value as i64, e.text.clone()))
                    .collect();
                let current_idx = options
                    .iter()
                    .position(|(v, _)| *v == current_val)
                    .unwrap_or(0);

                WidgetType::Dropdown {
                    options,
                    current_idx,
                }
            }
            Some(ParameterTypeDef::TypeNumber(tn)) => {
                let val = match value {
                    Some(ParameterValue::Integer(v)) => *v,
                    _ => 0,
                };
                WidgetType::Number {
                    value: val,
                    min: Some(tn.min_inclusive),
                    max: Some(tn.max_inclusive),
                }
            }
            Some(ParameterTypeDef::TypeFloat(_)) => {
                let val = match value {
                    Some(ParameterValue::Float(v)) => format!("{:.2}", v),
                    Some(ParameterValue::Integer(v)) => v.to_string(),
                    _ => "0".to_string(),
                };
                WidgetType::ReadOnly { value: val }
            }
            Some(ParameterTypeDef::TypeText(_)) => {
                let val = match value {
                    Some(ParameterValue::Text(s)) => s.clone(),
                    _ => String::new(),
                };
                WidgetType::Text { value: val }
            }
            Some(ParameterTypeDef::TypeNone(_)) | None => WidgetType::ReadOnly {
                value: "—".to_string(),
            },
        }
    }

    /// Rebuild the communication objects table.
    pub fn rebuild_com_objects(&mut self) {
        self.com_object_rows.clear();

        // Add comm objects from main device
        let visible_refs: Vec<_> = self.model.visible_com_object_refs().cloned().collect();

        for oref in visible_refs {
            if let Some(obj) = self.model.get_com_object(&oref.ref_id) {
                let raw_name = oref.text.clone().unwrap_or_else(|| obj.text.clone());
                let name = interpolate_text(&raw_name, &self.model);
                let raw_function = oref
                    .function_text
                    .clone()
                    .unwrap_or_else(|| obj.function_text.clone());
                let function = interpolate_text(&raw_function, &self.model);

                // Get effective values (ref overrides base object)
                let size = oref
                    .object_size
                    .clone()
                    .unwrap_or_else(|| obj.object_size.clone());
                let dpt = oref
                    .datapoint_type
                    .clone()
                    .or_else(|| obj.datapoint_type.clone())
                    .unwrap_or_default();
                let priority = oref.priority.unwrap_or(
                    obj.priority.unwrap_or(ComObjectPriority::Low),
                );
                let priority_str = match priority {
                    ComObjectPriority::Low => "Low",
                    ComObjectPriority::High => "High",
                    ComObjectPriority::Alert => "Alert",
                };

                // Flags (ref overrides base)
                let flag_c = oref
                    .communication_flag
                    .unwrap_or(obj.communication_flag)
                    == EnableFlag::Enabled;
                let flag_r =
                    oref.read_flag.unwrap_or(obj.read_flag) == EnableFlag::Enabled;
                let flag_w =
                    oref.write_flag.unwrap_or(obj.write_flag) == EnableFlag::Enabled;
                let flag_t = oref
                    .transmit_flag
                    .unwrap_or(obj.transmit_flag)
                    == EnableFlag::Enabled;
                let flag_u =
                    oref.update_flag.unwrap_or(obj.update_flag) == EnableFlag::Enabled;

                self.com_object_rows.push(ComObjectRow {
                    number: obj.number,
                    name,
                    function,
                    group_address: String::new(), // Empty for now
                    size,
                    dpt,
                    priority: priority_str.to_string(),
                    flag_c,
                    flag_r,
                    flag_w,
                    flag_t,
                    flag_u,
                });
            }
        }

        // Add comm objects from visible modules
        self.add_module_com_objects_to_list();

        // Sort by object number
        self.com_object_rows.sort_by_key(|r| r.number);
    }

    /// Add comm objects from visible modules to the com_object_rows list.
    fn add_module_com_objects_to_list(&mut self) {
        // Collect visible modules first to avoid borrow issues
        let visible_modules: Vec<_> = self.model.visible_modules().cloned().collect();

        for expanded in visible_modules {
            // Get the ModuleDef
            let module_def = match self.model.get_module_def(&expanded.module_def_id) {
                Some(def) => def.clone(),
                None => continue,
            };

            // Get comm object refs from the module's static section
            let com_obj_refs = match &module_def.static_section.com_object_refs {
                Some(refs) => refs.refs.clone(),
                None => continue,
            };

            // Get comm objects from the module's static section
            let com_objects = match &module_def.static_section.com_objects {
                Some(objs) => &objs.objects,
                None => continue,
            };

            for oref in &com_obj_refs {
                // Find the comm object
                let obj = match com_objects.iter().find(|o| o.id == oref.ref_id) {
                    Some(o) => o,
                    None => continue,
                };

                // Look up the text parameter value for {{0}} substitution
                let text_param_value = oref.text_parameter_ref_id.as_ref().and_then(|ref_id| {
                    // Find the ParameterRef to get the parameter ID
                    let param_ref = module_def
                        .static_section
                        .parameter_refs
                        .as_ref()
                        .and_then(|refs| refs.refs.iter().find(|pr| pr.id == *ref_id));

                    param_ref.and_then(|pr| {
                        // Build composite ID and look up value
                        let composite_id = format!("{}::{}", expanded.instance_id, pr.ref_id);
                        self.model
                            .get_module_parameter_value(&composite_id)
                            .and_then(|v| match v {
                                ParameterValue::Text(s) if !s.is_empty() => Some(s.clone()),
                                ParameterValue::Integer(i) => Some(i.to_string()),
                                _ => None,
                            })
                    })
                });

                let raw_name = oref.text.clone().unwrap_or_else(|| obj.text.clone());
                let name =
                    interpolate_module_text_with_param(&raw_name, &expanded, text_param_value.as_deref());
                let raw_function = oref
                    .function_text
                    .clone()
                    .unwrap_or_else(|| obj.function_text.clone());
                let function = interpolate_module_text(&raw_function, &expanded);

                // Get effective values (ref overrides base object)
                let size = oref
                    .object_size
                    .clone()
                    .unwrap_or_else(|| obj.object_size.clone());
                let dpt = oref
                    .datapoint_type
                    .clone()
                    .or_else(|| obj.datapoint_type.clone())
                    .unwrap_or_default();
                let priority = oref.priority.unwrap_or(
                    obj.priority.unwrap_or(ComObjectPriority::Low),
                );
                let priority_str = match priority {
                    ComObjectPriority::Low => "Low",
                    ComObjectPriority::High => "High",
                    ComObjectPriority::Alert => "Alert",
                };

                // Flags (ref overrides base)
                let flag_c = oref
                    .communication_flag
                    .unwrap_or(obj.communication_flag)
                    == EnableFlag::Enabled;
                let flag_r =
                    oref.read_flag.unwrap_or(obj.read_flag) == EnableFlag::Enabled;
                let flag_w =
                    oref.write_flag.unwrap_or(obj.write_flag) == EnableFlag::Enabled;
                let flag_t = oref
                    .transmit_flag
                    .unwrap_or(obj.transmit_flag)
                    == EnableFlag::Enabled;
                let flag_u =
                    oref.update_flag.unwrap_or(obj.update_flag) == EnableFlag::Enabled;

                self.com_object_rows.push(ComObjectRow {
                    number: obj.number,
                    name,
                    function,
                    group_address: String::new(), // Empty for now
                    size,
                    dpt,
                    priority: priority_str.to_string(),
                    flag_c,
                    flag_r,
                    flag_w,
                    flag_t,
                    flag_u,
                });
            }
        }
    }

    /// Toggle focus between tabs, sidebar, and content.
    pub fn toggle_focus(&mut self) {
        if !matches!(self.edit_mode, EditMode::None) {
            return;
        }

        self.focus = match (self.current_tab, self.focus) {
            (MainTab::Parameters, Focus::Tabs) => Focus::Sidebar,
            (MainTab::Parameters, Focus::Sidebar) => Focus::Content,
            (MainTab::Parameters, Focus::Content) => Focus::Tabs,
            (MainTab::CommObjects, Focus::Tabs) => Focus::Content,
            (MainTab::CommObjects, Focus::Content) => Focus::Tabs,
            (MainTab::CommObjects, Focus::Sidebar) => Focus::Content, // Shouldn't happen
        };
    }

    /// Move selection up.
    pub fn move_up(&mut self) {
        match &mut self.edit_mode {
            EditMode::EnumDropdown {
                selected_idx,
                scroll_offset,
                ..
            } => {
                if *selected_idx > 0 {
                    *selected_idx -= 1;
                    // Adjust scroll if selection went above visible area
                    if *selected_idx < *scroll_offset {
                        *scroll_offset = *selected_idx;
                    }
                }
            }
            EditMode::None => match (self.current_tab, self.focus) {
                (_, Focus::Tabs) => {
                    // No vertical movement in tabs
                }
                (MainTab::Parameters, Focus::Sidebar) => {
                    if self.selected_tree_idx > 0 {
                        self.selected_tree_idx -= 1;
                        self.rebuild_content();
                        self.selected_content_idx = 0;
                    }
                }
                (MainTab::Parameters, Focus::Content) => {
                    if self.selected_content_idx > 0 {
                        self.selected_content_idx -= 1;
                    }
                }
                (MainTab::CommObjects, Focus::Content) => {
                    if self.selected_obj_idx > 0 {
                        self.selected_obj_idx -= 1;
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// Maximum visible items in dropdown popup
    const DROPDOWN_VISIBLE_ITEMS: usize = 12;

    /// Move selection down.
    pub fn move_down(&mut self) {
        match &mut self.edit_mode {
            EditMode::EnumDropdown {
                selected_idx,
                options,
                scroll_offset,
                ..
            } => {
                if *selected_idx < options.len().saturating_sub(1) {
                    *selected_idx += 1;
                    // Adjust scroll if selection went below visible area
                    let visible_items = Self::DROPDOWN_VISIBLE_ITEMS;
                    if *selected_idx >= *scroll_offset + visible_items {
                        *scroll_offset = selected_idx.saturating_sub(visible_items - 1);
                    }
                }
            }
            EditMode::None => match (self.current_tab, self.focus) {
                (_, Focus::Tabs) => {
                    // No vertical movement in tabs
                }
                (MainTab::Parameters, Focus::Sidebar) => {
                    if self.selected_tree_idx < self.tree_nodes.len().saturating_sub(1) {
                        self.selected_tree_idx += 1;
                        self.rebuild_content();
                        self.selected_content_idx = 0;
                    }
                }
                (MainTab::Parameters, Focus::Content) => {
                    if self.selected_content_idx < self.content_items.len().saturating_sub(1) {
                        self.selected_content_idx += 1;
                    }
                }
                (MainTab::CommObjects, Focus::Content) => {
                    if self.selected_obj_idx < self.com_object_rows.len().saturating_sub(1) {
                        self.selected_obj_idx += 1;
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// Move selection left (for tabs).
    pub fn move_left(&mut self) {
        if !matches!(self.edit_mode, EditMode::None) {
            return;
        }
        match self.focus {
            Focus::Tabs => self.prev_tab(),
            Focus::Sidebar => {
                // Collapse the selected tree node
                if let Some(node) = self.tree_nodes.get(self.selected_tree_idx) {
                    if node.has_children && self.expanded_nodes.contains(&node.id) {
                        self.expanded_nodes.remove(&node.id);
                        self.rebuild_tree();
                    }
                }
            }
            Focus::Content => {}
        }
    }

    /// Move selection right (for tabs) or expand tree node (for sidebar).
    pub fn move_right(&mut self) {
        if !matches!(self.edit_mode, EditMode::None) {
            return;
        }
        match self.focus {
            Focus::Tabs => self.next_tab(),
            Focus::Sidebar => {
                // Expand the selected tree node
                if let Some(node) = self.tree_nodes.get(self.selected_tree_idx) {
                    if node.has_children && !self.expanded_nodes.contains(&node.id) {
                        self.expanded_nodes.insert(node.id.clone());
                        self.rebuild_tree();
                    }
                }
            }
            Focus::Content => {}
        }
    }

    /// Toggle expand/collapse on sidebar or enter edit mode on content.
    pub fn activate(&mut self) {
        match &self.edit_mode {
            EditMode::EnumDropdown {
                param_id,
                options,
                selected_idx,
                ..
            } => {
                // Commit the selection
                let param_id = param_id.clone();
                let new_value = options[*selected_idx].0;
                self.set_any_parameter_value(&param_id, ParameterValue::Integer(new_value));
                self.edit_mode = EditMode::None;
                // Rebuild everything since visibility may have changed
                self.rebuild_tree();
                self.rebuild_content();
                self.rebuild_com_objects();
            }
            EditMode::NumberInput { param_id, buffer } => {
                // Commit the number
                let param_id = param_id.clone();
                if let Ok(v) = buffer.parse::<i64>() {
                    self.set_any_parameter_value(&param_id, ParameterValue::Integer(v));
                }
                self.edit_mode = EditMode::None;
                self.rebuild_tree();
                self.rebuild_content();
                self.rebuild_com_objects();
            }
            EditMode::TextInput { param_id, buffer, .. } => {
                // Commit the text
                let param_id = param_id.clone();
                let text = buffer.clone();
                self.set_any_parameter_value(&param_id, ParameterValue::Text(text));
                self.edit_mode = EditMode::None;
                self.rebuild_tree();
                self.rebuild_content();
                self.rebuild_com_objects();
            }
            EditMode::None => match (self.current_tab, self.focus) {
                (_, Focus::Tabs) => {
                    // Enter into the content area
                    self.toggle_focus();
                }
                (MainTab::Parameters, Focus::Sidebar) => {
                    // Toggle expand/collapse
                    if let Some(node) = self.tree_nodes.get(self.selected_tree_idx) {
                        if node.has_children {
                            let id = node.id.clone();
                            if self.expanded_nodes.contains(&id) {
                                self.expanded_nodes.remove(&id);
                            } else {
                                self.expanded_nodes.insert(id);
                            }
                            self.rebuild_tree();
                        }
                    }
                }
                (MainTab::Parameters, Focus::Content) => {
                    // Enter edit mode for the selected parameter
                    self.enter_edit_mode();
                }
                (MainTab::CommObjects, Focus::Content) => {
                    // No editing for comm objects (read-only for now)
                }
                _ => {}
            },
        }
    }

    /// Cancel editing.
    pub fn cancel_edit(&mut self) {
        self.edit_mode = EditMode::None;
    }

    fn enter_edit_mode(&mut self) {
        if let Some(ContentItem::Parameter { param_id, widget, .. }) =
            self.content_items.get(self.selected_content_idx)
        {
            let param_id = param_id.clone();
            match widget {
                WidgetType::Dropdown {
                    options,
                    current_idx,
                } => {
                    // Calculate initial scroll offset to center the selected item if possible
                    let visible = Self::DROPDOWN_VISIBLE_ITEMS;
                    let scroll_offset = if options.len() <= visible {
                        0
                    } else if *current_idx < visible / 2 {
                        0
                    } else if *current_idx > options.len() - visible / 2 {
                        options.len().saturating_sub(visible)
                    } else {
                        current_idx.saturating_sub(visible / 2)
                    };
                    self.edit_mode = EditMode::EnumDropdown {
                        param_id,
                        options: options.clone(),
                        selected_idx: *current_idx,
                        scroll_offset,
                    };
                }
                WidgetType::Number { value, .. } => {
                    self.edit_mode = EditMode::NumberInput {
                        param_id,
                        buffer: value.to_string(),
                    };
                }
                WidgetType::Text { value } => {
                    let len = value.len();
                    self.edit_mode = EditMode::TextInput {
                        param_id,
                        buffer: value.clone(),
                        cursor: len,
                    };
                }
                WidgetType::ReadOnly { .. } => {
                    // Can't edit read-only
                }
            }
        }
    }

    /// Handle character input for editing.
    pub fn handle_char(&mut self, c: char) {
        match &mut self.edit_mode {
            EditMode::NumberInput { buffer, .. } => {
                if c.is_ascii_digit() || (c == '-' && buffer.is_empty()) {
                    buffer.push(c);
                }
            }
            EditMode::TextInput { buffer, cursor, .. } => {
                buffer.insert(*cursor, c);
                *cursor += 1;
            }
            _ => {}
        }
    }

    /// Handle backspace for editing.
    pub fn handle_backspace(&mut self) {
        match &mut self.edit_mode {
            EditMode::NumberInput { buffer, .. } => {
                buffer.pop();
            }
            EditMode::TextInput { buffer, cursor, .. } => {
                if *cursor > 0 {
                    *cursor -= 1;
                    buffer.remove(*cursor);
                }
            }
            _ => {}
        }
    }

    /// Get the current tree node name for the title.
    pub fn current_node_name(&self) -> String {
        self.tree_nodes
            .get(self.selected_tree_idx)
            .map(|n| n.name.clone())
            .unwrap_or_else(|| "No Selection".to_string())
    }
}
