//! Application state and logic for the KNX TUI viewer.

use knxprod::device_info::DeviceInfo;
use knxprod::master_data::{MasterData, MaskVersion, TableFlavour};
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
    /// Memory segments hex view
    Memory,
}

/// Type of memory segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentType {
    /// Absolute segment (System 7.x devices - MV-0705, etc.)
    Absolute,
    /// Relative segment (System B devices - MV-07B0, MV-57B0, etc.)
    Relative,
}

/// A parsed memory segment for display in the hex view.
#[derive(Debug, Clone)]
pub struct MemorySegment {
    /// Segment ID from XML
    pub id: String,
    /// Segment type
    pub segment_type: SegmentType,
    /// Start address (for absolute) or offset (for relative)
    pub address: u32,
    /// Size in bytes (declared size)
    pub size: u32,
    /// Memory type (RAM, EEPROM, etc.) - optional for absolute segments
    pub memory_type: Option<String>,
    /// Load state machine number (for relative segments)
    pub load_state_machine: Option<u8>,
    /// Raw byte data decoded from base64
    pub data: Vec<u8>,
    /// Parameter annotations: regions occupied by parameters
    pub annotations: Vec<MemoryAnnotation>,
}

/// Annotation for a memory region occupied by a parameter.
#[derive(Debug, Clone)]
pub struct MemoryAnnotation {
    /// Byte offset within the segment
    pub offset: u32,
    /// Bit offset (0-7)
    pub bit_offset: u8,
    /// Parameter name for display
    pub name: String,
    /// Size in bits
    pub size_bits: u16,
    /// Parameter ID for linking
    pub param_id: String,
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
    /// KNX master data (optional - used for mask version info)
    pub master_data: Option<MasterData>,
    /// Device programming information (extracted from model and master data)
    pub device_info: DeviceInfo,
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
    /// Parsed memory segments for Memory tab
    pub memory_segments: Vec<MemorySegment>,
    /// Currently selected segment index
    pub selected_segment_idx: usize,
    /// Scroll offset in hex view (line number, 16 bytes per line)
    pub memory_scroll_offset: usize,
    /// Currently highlighted byte offset within segment (for navigation)
    pub selected_byte_offset: usize,
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
        Self::with_master_data(model, None)
    }

    /// Create a new application with device model and optional master data.
    ///
    /// When master data is provided, the app can use mask version information
    /// to correctly generate table layouts based on the device's mask version.
    pub fn with_master_data(model: DeviceModel, master_data: Option<MasterData>) -> Self {
        // Extract device info for future programming use
        let device_info = DeviceInfo::from_program(&model.program, master_data.as_ref());

        let mut app = Self {
            model,
            master_data,
            device_info,
            current_tab: MainTab::Parameters,
            tree_nodes: Vec::new(),
            selected_tree_idx: 0,
            content_items: Vec::new(),
            selected_content_idx: 0,
            com_object_rows: Vec::new(),
            selected_obj_idx: 0,
            memory_segments: Vec::new(),
            selected_segment_idx: 0,
            memory_scroll_offset: 0,
            selected_byte_offset: 0,
            focus: Focus::Tabs,
            edit_mode: EditMode::None,
            expanded_nodes: std::collections::HashSet::new(),
            should_quit: false,
        };

        // Build initial data
        app.rebuild_tree();
        app.rebuild_content();
        app.rebuild_com_objects();
        app.rebuild_memory_segments();

        app
    }

    /// Switch to next main tab.
    pub fn next_tab(&mut self) {
        self.current_tab = match self.current_tab {
            MainTab::Parameters => MainTab::CommObjects,
            MainTab::CommObjects => MainTab::Memory,
            MainTab::Memory => MainTab::Parameters,
        };
        // Reset focus when switching tabs
        self.focus = Focus::Tabs;
    }

    /// Switch to previous main tab.
    pub fn prev_tab(&mut self) {
        self.current_tab = match self.current_tab {
            MainTab::Parameters => MainTab::Memory,
            MainTab::CommObjects => MainTab::Parameters,
            MainTab::Memory => MainTab::CommObjects,
        };
        self.focus = Focus::Tabs;
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
            let block_name = pb.name.clone().unwrap_or_else(|| pb.id.clone());
            let block_id = format!("device_block_{}", block_name);
            let raw_text = pb.text.clone().unwrap_or_else(|| block_name.clone());
            let text = interpolate_text(&raw_text, &self.model);

            self.tree_nodes.push(TreeNode {
                id: block_id,
                name: text,
                depth,
                expanded: false,
                has_children: false,
                node_type: NodeType::ParameterBlock {
                    parent: None,
                    block_name,
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
            let block_name = pb.name.clone().unwrap_or_else(|| pb.id.clone());
            let block_id = format!("channel_{}_block_{}", channel_idx, block_name);
            let raw_text = pb.text.clone().unwrap_or_else(|| block_name.clone());
            let text = interpolate_text(&raw_text, &self.model);

            self.tree_nodes.push(TreeNode {
                id: block_id,
                name: text,
                depth,
                expanded: false,
                has_children: false,
                node_type: NodeType::ParameterBlock {
                    parent: Some(channel_idx),
                    block_name,
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
                ParameterBlockItem::Button(_) => {
                    // Buttons are UI elements, no parameters to show
                }
                ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => {
                    // Table layout elements, no parameters to show
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
                ParameterBlockItem::Button(_) => {
                    // Buttons are ETS UI elements, not displayed in TUI
                }
                ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => {
                    // Table layout elements, not displayed in TUI
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
            Some(ParameterTypeDef::TypeNone(_))
            | Some(ParameterTypeDef::TypePicture(_))
            | Some(ParameterTypeDef::TypeIpAddress(_))
            | None => {
                // For unknown/picture/IP types, show as read-only
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
                    if pb.name.as_deref() == Some(block_name) {
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
                    if pb.name.as_deref() == Some(block_name) {
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
                    if pb.name.as_deref() == Some(block_name) {
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
                ParameterBlockItem::Button(_) => {
                    // Buttons are ETS UI elements, not displayed in TUI
                }
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
            Some(ParameterTypeDef::TypeNone(_))
            | Some(ParameterTypeDef::TypePicture(_))
            | Some(ParameterTypeDef::TypeIpAddress(_))
            | None => WidgetType::ReadOnly {
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

    /// Get the MaskVersion info for this device, if master data is available.
    pub fn get_mask_version(&self) -> Option<&MaskVersion> {
        self.master_data
            .as_ref()
            .and_then(|md| md.get_mask_version(self.model.mask_version()))
    }

    /// Get a human-readable mask version display string.
    /// Returns something like "System B (MV-07B0)" or just "MV-07B0" if no master data.
    pub fn mask_version_display(&self) -> String {
        let mv_id = self.model.mask_version();
        if let Some(mv) = self.get_mask_version() {
            format!("{} ({})", mv.name, mv_id)
        } else {
            mv_id.to_string()
        }
    }

    /// Get the management model string (e.g., "SystemB", "BimM112").
    pub fn management_model(&self) -> Option<&str> {
        self.get_mask_version().map(|mv| mv.management_model.as_str())
    }

    /// Get the first application object index from mask version.
    pub fn first_app_object_idx(&self) -> u8 {
        self.get_mask_version()
            .map(|mv| mv.first_app_object_idx())
            .unwrap_or(5) // Default BCU1-style
    }

    /// Get max APDU length from master data resources.
    #[allow(dead_code)]
    pub fn max_apdu_length(&self) -> Option<u32> {
        self.get_mask_version()
            .and_then(|mv| mv.hawk_config())
            .and_then(|hc| hc.resources.as_ref())
            .and_then(|r| r.resources.iter().find(|res| res.name == "MaxApduLength"))
            .and_then(|r| r.location.as_ref())
            .and_then(|l| l.start_address)
    }

    /// Get the table flavour for address table from mask version.
    fn get_address_table_flavour(&self) -> TableFlavour {
        self.get_mask_version()
            .and_then(|mv| mv.address_table())
            .and_then(|r| r.resource_type.as_ref())
            .and_then(|rt| rt.flavour.as_ref())
            .map(|f| TableFlavour::from_str(f))
            .unwrap_or(TableFlavour::AddressTableSystemB)
    }

    /// Get the table flavour for association table from mask version.
    fn get_association_table_flavour(&self) -> TableFlavour {
        self.get_mask_version()
            .and_then(|mv| mv.association_table())
            .and_then(|r| r.resource_type.as_ref())
            .and_then(|rt| rt.flavour.as_ref())
            .map(|f| TableFlavour::from_str(f))
            .unwrap_or(TableFlavour::AssociationTableSystemB)
    }

    /// Rebuild memory segments from the Code section in the ApplicationProgram.
    pub fn rebuild_memory_segments(&mut self) {
        use base64::Engine;
        self.memory_segments.clear();

        // Get Code section from static section
        let code = match &self.model.program.static_section.code {
            Some(c) => c,
            None => return,
        };

        // Collect parameter-to-segment mappings for annotations
        let param_mappings = self.collect_parameter_memory_mappings();

        // Process AbsoluteSegments (System 7.x)
        for seg in &code.absolute_segments {
            let mut data = seg
                .data
                .as_ref()
                .and_then(|d| base64::engine::general_purpose::STANDARD.decode(d).ok())
                .unwrap_or_default();

            // Apply current parameter values to the memory data
            self.apply_parameter_values_to_segment(&seg.id, &mut data);

            let annotations = self.build_annotations_for_segment(&seg.id, &param_mappings);

            self.memory_segments.push(MemorySegment {
                id: seg.id.clone(),
                segment_type: SegmentType::Absolute,
                address: seg.address,
                size: seg.size,
                memory_type: seg.memory_type.clone(),
                load_state_machine: None,
                data,
                annotations,
            });
        }

        // Process RelativeSegments (System B)
        for seg in &code.relative_segments {
            let mut data = seg
                .data
                .as_ref()
                .and_then(|d| base64::engine::general_purpose::STANDARD.decode(d).ok())
                .unwrap_or_default();

            // Apply current parameter values to the memory data
            self.apply_parameter_values_to_segment(&seg.id, &mut data);

            let annotations = self.build_annotations_for_segment(&seg.id, &param_mappings);

            self.memory_segments.push(MemorySegment {
                id: seg.id.clone(),
                segment_type: SegmentType::Relative,
                address: seg.offset,
                size: seg.size,
                memory_type: None,
                load_state_machine: Some(seg.load_state_machine),
                data,
                annotations,
            });
        }

        // Generate synthetic tables for Address Table (ADT), Association Table (AST), and ComObject Table (COT)
        self.generate_address_table();
        self.generate_association_table();
        self.generate_com_object_table();

        // Sort by address
        self.memory_segments.sort_by_key(|s| s.address);
    }

    /// Generate the Address Table (ADT) as a synthetic memory segment.
    ///
    /// The Address Table stores group addresses for each communication object.
    /// Format depends on mask version:
    /// - BCU1 (MV-0705): 1-byte count + N x 2-byte group addresses
    /// - System B (MV-07B0): 2-byte count + N x 2-byte group addresses
    ///
    /// Since we don't have actual group addresses assigned (that's done in ETS),
    /// we generate placeholder entries (0x0000) for each visible ComObject.
    ///
    /// For System 7.x devices, the table is placed within an AbsoluteSegment.
    /// For System B devices, it's loaded via a separate Load State Machine.
    fn generate_address_table(&mut self) {
        let static_section = &self.model.program.static_section;

        // Get AddressTable config if present
        let at = match &static_section.address_table {
            Some(at) => at,
            None => return, // No address table configured
        };

        let offset = at.offset.unwrap_or(0);
        let max_entries = at.max_entries;

        // Get table flavour from mask version
        let flavour = self.get_address_table_flavour();
        let count_size = flavour.count_size();
        let entry_size = flavour.entry_size();

        // Check if this table references an existing code segment
        // If so, add annotations to that segment instead of creating a new one
        if let Some(code_segment) = &at.code_segment {
            if let Some(seg_idx) = self
                .memory_segments
                .iter()
                .position(|s| s.id == *code_segment)
            {
                // Add annotations to existing segment
                let annotations = self.build_address_table_annotations(offset, &flavour);
                self.memory_segments[seg_idx].annotations.extend(annotations);
                return;
            }
        }

        // Create a standalone synthetic segment (for System B or if segment not found)
        let visible_count = self.model.visible_com_object_refs().count() as u16;

        // Build table data based on flavour
        let mut data = Vec::with_capacity(count_size + (visible_count as usize) * entry_size);

        // Count field (size depends on flavour)
        if count_size == 1 {
            data.push(visible_count as u8);
        } else {
            data.push((visible_count >> 8) as u8);
            data.push((visible_count & 0xFF) as u8);
        }

        // Placeholder group addresses (0x0000 since not assigned in viewer)
        for _ in 0..visible_count {
            for _ in 0..entry_size {
                data.push(0x00);
            }
        }

        let annotations = self.build_address_table_annotations(0, &flavour);

        self.memory_segments.push(MemorySegment {
            id: "ADT".to_string(),
            segment_type: SegmentType::Relative,
            address: offset,
            size: count_size as u32 + (max_entries as u32) * entry_size as u32,
            memory_type: Some("Address Table".to_string()),
            load_state_machine: Some(1), // LSM 1 is typically for ADT
            data,
            annotations,
        });
    }

    /// Build annotations for Address Table entries.
    fn build_address_table_annotations(
        &self,
        base_offset: u32,
        flavour: &TableFlavour,
    ) -> Vec<MemoryAnnotation> {
        let mut annotations = Vec::new();
        let count_size = flavour.count_size() as u32;
        let entry_size = flavour.entry_size() as u32;

        annotations.push(MemoryAnnotation {
            offset: base_offset,
            bit_offset: 0,
            name: "ADT: Entry Count".to_string(),
            size_bits: (count_size * 8) as u16,
            param_id: String::new(),
        });

        let mut idx: u32 = 0;
        for com_obj_ref in self.model.visible_com_object_refs() {
            let name = com_obj_ref
                .text
                .clone()
                .unwrap_or_else(|| com_obj_ref.name.clone().unwrap_or_default());
            annotations.push(MemoryAnnotation {
                offset: base_offset + count_size + (idx * entry_size),
                bit_offset: 0,
                name: format!("ADT[{}] {}", idx, name),
                size_bits: (entry_size * 8) as u16,
                param_id: com_obj_ref.id.clone(),
            });
            idx += 1;
        }

        annotations
    }

    /// Generate the Association Table (AST) as a synthetic memory segment.
    ///
    /// The Association Table maps group addresses (TSAP) to communication objects (ASAP).
    /// Format depends on mask version:
    /// - BCU1 (MV-0705): 1-byte count + N x 2-byte entries (1-byte TSAP + 1-byte ASAP)
    /// - System B (MV-07B0): 2-byte count + N x 4-byte entries (2-byte TSAP + 2-byte ASAP)
    ///
    /// Since actual associations are configured in ETS, we generate 1:1 mappings for display.
    ///
    /// For System 7.x devices, the table is placed within an AbsoluteSegment.
    /// For System B devices, it's loaded via a separate Load State Machine.
    fn generate_association_table(&mut self) {
        let static_section = &self.model.program.static_section;

        // Get AssociationTable config if present
        let at = match &static_section.association_table {
            Some(at) => at,
            None => return, // No association table configured
        };

        let offset = at.offset.unwrap_or(0);
        let max_entries = at.max_entries;

        // Get table flavour from mask version
        let flavour = self.get_association_table_flavour();
        let count_size = flavour.count_size();
        let entry_size = flavour.entry_size();

        // Check if this table references an existing code segment
        if let Some(code_segment) = &at.code_segment {
            if let Some(seg_idx) = self
                .memory_segments
                .iter()
                .position(|s| s.id == *code_segment)
            {
                // Add annotations to existing segment
                let annotations = self.build_association_table_annotations(offset, &flavour);
                self.memory_segments[seg_idx].annotations.extend(annotations);
                return;
            }
        }

        // Create a standalone synthetic segment
        let visible_objs: Vec<_> = self.model.visible_com_object_refs().collect();
        let visible_count = visible_objs.len() as u16;

        // Build table data based on flavour
        let mut data = Vec::with_capacity(count_size + (visible_count as usize) * entry_size);

        // Count field (size depends on flavour)
        if count_size == 1 {
            data.push(visible_count as u8);
        } else {
            data.push((visible_count >> 8) as u8);
            data.push((visible_count & 0xFF) as u8);
        }

        // Association entries: TSAP -> ASAP (1:1 mapping for display)
        for (idx, _) in visible_objs.iter().enumerate() {
            let tsap = idx as u16;
            let asap = idx as u16;

            if entry_size == 2 {
                // BCU1: 1-byte TSAP + 1-byte ASAP
                data.push(tsap as u8);
                data.push(asap as u8);
            } else {
                // System B: 2-byte TSAP + 2-byte ASAP
                data.push((tsap >> 8) as u8);
                data.push((tsap & 0xFF) as u8);
                data.push((asap >> 8) as u8);
                data.push((asap & 0xFF) as u8);
            }
        }

        let annotations = self.build_association_table_annotations(0, &flavour);

        self.memory_segments.push(MemorySegment {
            id: "AST".to_string(),
            segment_type: SegmentType::Relative,
            address: offset,
            size: count_size as u32 + (max_entries as u32) * entry_size as u32,
            memory_type: Some("Association Table".to_string()),
            load_state_machine: Some(2), // LSM 2 is typically for AST
            data,
            annotations,
        });
    }

    /// Build annotations for Association Table entries.
    fn build_association_table_annotations(
        &self,
        base_offset: u32,
        flavour: &TableFlavour,
    ) -> Vec<MemoryAnnotation> {
        let mut annotations = Vec::new();
        let count_size = flavour.count_size() as u32;
        let entry_size = flavour.entry_size() as u32;

        annotations.push(MemoryAnnotation {
            offset: base_offset,
            bit_offset: 0,
            name: "AST: Entry Count".to_string(),
            size_bits: (count_size * 8) as u16,
            param_id: String::new(),
        });

        let mut idx: u32 = 0;
        for com_obj_ref in self.model.visible_com_object_refs() {
            let name = com_obj_ref
                .text
                .clone()
                .unwrap_or_else(|| com_obj_ref.name.clone().unwrap_or_default());
            annotations.push(MemoryAnnotation {
                offset: base_offset + count_size + (idx * entry_size),
                bit_offset: 0,
                name: format!("AST[{}] {}", idx, name),
                size_bits: (entry_size * 8) as u16,
                param_id: com_obj_ref.id.clone(),
            });
            idx += 1;
        }

        annotations
    }

    /// Generate the Communication Object Table (COT) as a synthetic memory segment.
    ///
    /// The COT stores type and flags for each communication object.
    /// Format: 2-byte count + N x 2-byte entries (type/size byte + flags byte)
    ///
    /// For System 7.x devices, the table is placed within an AbsoluteSegment.
    /// For System B devices, it's loaded via a separate Load State Machine.
    fn generate_com_object_table(&mut self) {
        let static_section = &self.model.program.static_section;

        // Get ComObjectTable config if present
        let cot = match &static_section.com_object_table {
            Some(cot) => cot,
            None => return, // No COM object table configured
        };

        let offset = cot.offset.unwrap_or(0);
        let max_entries = cot.max_entries.unwrap_or(255);

        // Check if this table references an existing code segment
        if let Some(code_segment) = &cot.code_segment {
            if let Some(seg_idx) = self
                .memory_segments
                .iter()
                .position(|s| s.id == *code_segment)
            {
                // Add annotations to existing segment
                let annotations = self.build_com_object_table_annotations(offset);
                self.memory_segments[seg_idx].annotations.extend(annotations);
                return;
            }
        }

        // Create a standalone synthetic segment
        let visible_objs: Vec<_> = self.model.visible_com_object_refs().collect();
        let visible_count = visible_objs.len() as u16;

        // Build table data: 2-byte count + N x 2-byte entries
        let mut data = Vec::with_capacity(2 + (visible_count as usize) * 2);

        // Count field (2 bytes, big-endian)
        data.push((visible_count >> 8) as u8);
        data.push((visible_count & 0xFF) as u8);

        // Look up ComObject definitions to get type/flags
        let com_objects = static_section
            .com_object_table
            .as_ref()
            .map(|t| &t.objects)
            .cloned()
            .unwrap_or_default();

        for com_obj_ref in &visible_objs {
            let base_obj = com_objects.iter().find(|o| o.id == com_obj_ref.ref_id);

            let size_str = com_obj_ref
                .object_size
                .clone()
                .or_else(|| base_obj.map(|o| o.object_size.clone()))
                .unwrap_or_else(|| "1 Byte".to_string());

            let type_byte = self.object_size_to_type_byte(&size_str);
            let flags = self.build_com_object_flags(com_obj_ref, base_obj);

            data.push(type_byte);
            data.push(flags);
        }

        let annotations = self.build_com_object_table_annotations(0);

        self.memory_segments.push(MemorySegment {
            id: "COT".to_string(),
            segment_type: SegmentType::Relative,
            address: offset,
            size: 2 + (max_entries as u32) * 2,
            memory_type: Some("ComObject Table".to_string()),
            load_state_machine: Some(3), // LSM 3 is typically for COT
            data,
            annotations,
        });
    }

    /// Build annotations for ComObject Table entries.
    fn build_com_object_table_annotations(&self, base_offset: u32) -> Vec<MemoryAnnotation> {
        let mut annotations = Vec::new();

        annotations.push(MemoryAnnotation {
            offset: base_offset,
            bit_offset: 0,
            name: "COT: Entry Count".to_string(),
            size_bits: 16,
            param_id: String::new(),
        });

        let mut idx: u32 = 0;
        for com_obj_ref in self.model.visible_com_object_refs() {
            let name = com_obj_ref
                .text
                .clone()
                .unwrap_or_else(|| com_obj_ref.name.clone().unwrap_or_default());
            annotations.push(MemoryAnnotation {
                offset: base_offset + 2 + (idx * 2),
                bit_offset: 0,
                name: format!("COT[{}] {}", idx, name),
                size_bits: 16,
                param_id: com_obj_ref.id.clone(),
            });
            idx += 1;
        }

        annotations
    }

    /// Convert object size string to type byte for COT.
    fn object_size_to_type_byte(&self, size_str: &str) -> u8 {
        match size_str {
            "1 Bit" => 0x00,
            "2 Bit" => 0x01,
            "3 Bit" => 0x02,
            "4 Bit" => 0x03,
            "5 Bit" => 0x04,
            "6 Bit" => 0x05,
            "7 Bit" => 0x06,
            "1 Byte" => 0x07,
            "2 Bytes" => 0x08,
            "3 Bytes" => 0x09,
            "4 Bytes" => 0x0A,
            "6 Bytes" => 0x0B,
            "8 Bytes" => 0x0C,
            "10 Bytes" => 0x0D,
            "14 Bytes" => 0x0E,
            _ => 0x07, // Default to 1 Byte
        }
    }

    /// Build flags byte from ComObjectRef and base ComObject.
    fn build_com_object_flags(
        &self,
        obj_ref: &knxprod::ComObjectRef,
        base_obj: Option<&knxprod::ComObject>,
    ) -> u8 {
        use knxprod::EnableFlag;

        let mut flags: u8 = 0;

        // Communication flag (bit 2)
        let comm = obj_ref
            .communication_flag
            .or(base_obj.map(|o| o.communication_flag))
            .unwrap_or(EnableFlag::Disabled);
        if comm == EnableFlag::Enabled {
            flags |= 0x04;
        }

        // Read flag (bit 3)
        let read = obj_ref
            .read_flag
            .or(base_obj.map(|o| o.read_flag))
            .unwrap_or(EnableFlag::Disabled);
        if read == EnableFlag::Enabled {
            flags |= 0x08;
        }

        // Write flag (bit 4)
        let write = obj_ref
            .write_flag
            .or(base_obj.map(|o| o.write_flag))
            .unwrap_or(EnableFlag::Disabled);
        if write == EnableFlag::Enabled {
            flags |= 0x10;
        }

        // Transmit flag (bit 5)
        let transmit = obj_ref
            .transmit_flag
            .or(base_obj.map(|o| o.transmit_flag))
            .unwrap_or(EnableFlag::Disabled);
        if transmit == EnableFlag::Enabled {
            flags |= 0x20;
        }

        // Update flag (bit 6)
        let update = obj_ref
            .update_flag
            .or(base_obj.map(|o| o.update_flag))
            .unwrap_or(EnableFlag::Disabled);
        if update == EnableFlag::Enabled {
            flags |= 0x40;
        }

        // Read on init flag (bit 7)
        let read_init = obj_ref
            .read_on_init_flag
            .or(base_obj.map(|o| o.read_on_init_flag))
            .unwrap_or(EnableFlag::Disabled);
        if read_init == EnableFlag::Enabled {
            flags |= 0x80;
        }

        flags
    }

    /// Apply current parameter values to a memory segment's data buffer.
    fn apply_parameter_values_to_segment(&self, segment_id: &str, data: &mut [u8]) {
        // Apply main static section parameters
        if let Some(params) = &self.model.program.static_section.parameters {
            self.apply_params_to_segment(&params.items, segment_id, data, None);
        }

        // Apply module parameter values
        for expanded in self.model.all_expanded_modules() {
            if let Some(module_def) = self.model.get_module_def(&expanded.module_def_id) {
                let base_offset_value = self.get_module_param_offset_base(expanded, module_def);

                if let Some(params) = &module_def.static_section.parameters {
                    let instance_id: &str = &expanded.instance_id;
                    self.apply_params_to_segment(
                        &params.items,
                        segment_id,
                        data,
                        base_offset_value.map(|v| (v, instance_id)),
                    );
                }
            }
        }
    }

    /// Apply parameters from a Parameters items list to a memory segment.
    fn apply_params_to_segment(
        &self,
        items: &[knxprod::ParameterItem],
        segment_id: &str,
        data: &mut [u8],
        base_offset_info: Option<(u32, &str)>,
    ) {
        for item in items {
            if let knxprod::ParameterItem::Parameter(param) = item {
                if let Some(memory) = &param.memory {
                    if memory.code_segment != segment_id {
                        continue;
                    }

                    // Calculate actual offset
                    let actual_offset = if memory.base_offset.is_some() {
                        if let Some((base_val, _)) = base_offset_info {
                            base_val + memory.offset
                        } else {
                            continue;
                        }
                    } else {
                        memory.offset
                    };

                    // Get value - use module value for module params, regular value for main params
                    let value = if let Some((_, instance_id)) = base_offset_info {
                        let composite_id = format!("{}::{}", instance_id, param.id);
                        self.model.get_module_parameter_value(&composite_id)
                    } else {
                        self.model.get_parameter_value(&param.id)
                    };

                    if let Some(value) = value {
                        let size_bits = self.get_parameter_size_bits(&param.parameter_type);
                        self.write_value_to_memory(
                            data,
                            actual_offset as usize,
                            memory.bit_offset,
                            size_bits,
                            value,
                        );
                    }
                }
            } else if let knxprod::ParameterItem::Union(union) = item {
                let memory = &union.memory;
                if memory.code_segment != segment_id {
                    continue;
                }

                // Calculate actual base offset for union
                let union_base_offset = if memory.base_offset.is_some() {
                    if let Some((base_val, _)) = base_offset_info {
                        base_val + memory.offset
                    } else {
                        continue;
                    }
                } else {
                    memory.offset
                };

                for param in &union.parameters {
                    let value = if let Some((_, instance_id)) = base_offset_info {
                        let composite_id = format!("{}::{}", instance_id, param.id);
                        self.model.get_module_parameter_value(&composite_id)
                    } else {
                        self.model.get_parameter_value(&param.id)
                    };

                    if let Some(value) = value {
                        let size_bits = self.get_parameter_size_bits(&param.parameter_type);
                        let offset = union_base_offset + param.offset as u32;
                        let bit_offset = memory.bit_offset + param.bit_offset;
                        self.write_value_to_memory(
                            data,
                            offset as usize,
                            bit_offset,
                            size_bits,
                            value,
                        );
                    }
                }
            }
        }
    }

    /// Write a parameter value to a memory buffer at the specified offset/bit position.
    fn write_value_to_memory(
        &self,
        data: &mut [u8],
        byte_offset: usize,
        bit_offset: u8,
        size_bits: u16,
        value: &knxprod::model::ParameterValue,
    ) {
        // Convert value to integer (most parameters are integer-based)
        let int_value: u64 = match value {
            knxprod::model::ParameterValue::Integer(v) => *v as u64,
            knxprod::model::ParameterValue::Float(v) => {
                // For float, assume DPT9 encoding (2 bytes)
                // Simplified: just cast to u64 for now
                (*v as i64) as u64
            }
            knxprod::model::ParameterValue::Text(s) => {
                // For text, write raw bytes
                let bytes = s.as_bytes();
                let max_bytes = (size_bits as usize + 7) / 8;
                for (i, &b) in bytes.iter().take(max_bytes).enumerate() {
                    if byte_offset + i < data.len() {
                        data[byte_offset + i] = b;
                    }
                }
                return;
            }
            knxprod::model::ParameterValue::Bytes(bytes) => {
                // For raw bytes, write directly
                for (i, &b) in bytes.iter().enumerate() {
                    if byte_offset + i < data.len() {
                        data[byte_offset + i] = b;
                    }
                }
                return;
            }
        };

        // Handle bit-level writing for integer values
        if bit_offset == 0 && size_bits % 8 == 0 {
            // Simple byte-aligned write
            let num_bytes = (size_bits / 8) as usize;
            for i in 0..num_bytes {
                if byte_offset + i < data.len() {
                    // Big-endian: most significant byte first
                    let shift = (num_bytes - 1 - i) * 8;
                    data[byte_offset + i] = ((int_value >> shift) & 0xFF) as u8;
                }
            }
        } else {
            // Bit-level write (handles non-byte-aligned parameters)
            // This is more complex - need to preserve surrounding bits
            let total_bits = size_bits as usize;
            let start_bit = byte_offset * 8 + bit_offset as usize;

            for bit_idx in 0..total_bits {
                let target_bit = start_bit + bit_idx;
                let target_byte = target_bit / 8;
                let target_bit_in_byte = 7 - (target_bit % 8); // MSB first within byte

                if target_byte < data.len() {
                    // Get the bit value from int_value (MSB first)
                    let source_bit_idx = total_bits - 1 - bit_idx;
                    let bit_val = ((int_value >> source_bit_idx) & 1) as u8;

                    // Set or clear the bit
                    if bit_val == 1 {
                        data[target_byte] |= 1 << target_bit_in_byte;
                    } else {
                        data[target_byte] &= !(1 << target_bit_in_byte);
                    }
                }
            }
        }
    }

    /// Collect parameter memory mappings: (segment_id, offset, bit_offset, name, size_bits, param_id)
    fn collect_parameter_memory_mappings(
        &self,
    ) -> Vec<(String, u32, u8, String, u16, String)> {
        let mut mappings = Vec::new();

        // Get parameters from main static section
        if let Some(params) = &self.model.program.static_section.parameters {
            self.collect_params_from_items(&params.items, &mut mappings, None);
        }

        // Collect parameters from expanded module instances
        for expanded in self.model.all_expanded_modules() {
            if let Some(module_def) = self.model.get_module_def(&expanded.module_def_id) {
                // Get the base offset value from the module's ParamOffsBase argument
                let base_offset_value = self.get_module_param_offset_base(expanded, module_def);

                if let Some(params) = &module_def.static_section.parameters {
                    let instance_id: &str = &expanded.instance_id;
                    // Build a display label for this module instance
                    // Try to use channel number or similar argument for identification
                    let instance_label = self.build_module_instance_label(expanded, module_def);
                    self.collect_params_from_items(
                        &params.items,
                        &mut mappings,
                        base_offset_value.map(|v| (v, instance_id, instance_label.as_str())),
                    );
                }
            }
        }

        mappings
    }

    /// Get the base offset value for a module instance's parameter memory.
    /// Returns the resolved parameter base offset argument value.
    ///
    /// Modules typically define an argument that allocates parameter memory space,
    /// commonly named "ParamBase", "ParamOffsBase", or similar. This function
    /// searches for such an argument and returns its resolved value.
    fn get_module_param_offset_base(
        &self,
        expanded: &knxprod::model::ExpandedModule,
        module_def: &knxprod::ModuleDef,
    ) -> Option<u32> {
        // Find the parameter base offset argument definition
        // Common names: ParamBase, ParamOffsBase, ParameterBase, etc.
        let arg_def = module_def.arguments.as_ref()?.arguments.iter().find(|a| {
            let name_lower = a.name.to_lowercase();
            // Match various naming conventions for parameter base offset
            name_lower.contains("param") && (name_lower.contains("base") || name_lower.contains("offs"))
        })?;

        // Get the resolved value from the expanded module
        if let Some(knxprod::model::ModuleArgValue::Numeric(val)) = expanded.args.get(&arg_def.name)
        {
            Some(*val as u32)
        } else {
            None
        }
    }

    /// Build a display label for a module instance.
    /// Tries to find a channel number or similar identifier from the module arguments.
    /// Falls back to the module definition name if no identifier is found.
    fn build_module_instance_label(
        &self,
        expanded: &knxprod::model::ExpandedModule,
        module_def: &knxprod::ModuleDef,
    ) -> String {
        // Try to find a channel/instance number argument (commonly named ChNo, Channel, ChannelNo, etc.)
        let channel_arg = module_def
            .arguments
            .as_ref()
            .and_then(|args| {
                args.arguments.iter().find(|a| {
                    let name_lower = a.name.to_lowercase();
                    name_lower.contains("ch") || name_lower.contains("channel") || name_lower.contains("instance")
                })
            });

        if let Some(arg_def) = channel_arg {
            if let Some(knxprod::model::ModuleArgValue::Numeric(val)) = expanded.args.get(&arg_def.name) {
                // Use module name with channel number, e.g., "Ch1" or "DimmerChannel 1"
                return format!("Ch{}", val);
            }
        }

        // Fallback: use interpolated module name if available
        if let Some(name) = &expanded.name {
            // The name might contain templates like "{{ChNo}}" - try to interpolate
            let interpolated = interpolate_module_text(name, expanded);
            if !interpolated.is_empty() && interpolated != *name {
                return interpolated;
            }
        }

        // Final fallback: use module definition name
        module_def.name.clone()
    }

    /// Collect parameters from a Parameters items list.
    /// If base_offset_info is provided (base_value, instance_id, instance_label), apply it to parameters with BaseOffset.
    fn collect_params_from_items(
        &self,
        items: &[knxprod::ParameterItem],
        mappings: &mut Vec<(String, u32, u8, String, u16, String)>,
        base_offset_info: Option<(u32, &str, &str)>,
    ) {
        for item in items {
            if let knxprod::ParameterItem::Parameter(param) = item {
                if let Some(memory) = &param.memory {
                    let size_bits = self.get_parameter_size_bits(&param.parameter_type);

                    // Calculate actual offset, applying base_offset if present
                    let actual_offset = if memory.base_offset.is_some() {
                        if let Some((base_val, _, _)) = base_offset_info {
                            base_val + memory.offset
                        } else {
                            // No base offset value available, skip this parameter
                            continue;
                        }
                    } else {
                        memory.offset
                    };

                    // Compose parameter ID with instance prefix for module parameters
                    let param_id = if let Some((_, instance_id, _)) = base_offset_info {
                        format!("{}::{}", instance_id, param.id)
                    } else {
                        param.id.clone()
                    };

                    // Add instance label to name for module parameters
                    let display_name = if let Some((_, _, instance_label)) = base_offset_info {
                        format!("[{}] {}", instance_label, param.text)
                    } else {
                        param.text.clone()
                    };

                    mappings.push((
                        memory.code_segment.clone(),
                        actual_offset,
                        memory.bit_offset,
                        display_name,
                        size_bits,
                        param_id,
                    ));
                }
            } else if let knxprod::ParameterItem::Union(union) = item {
                let memory = &union.memory;

                // Calculate actual base offset for union
                let union_base_offset = if memory.base_offset.is_some() {
                    if let Some((base_val, _, _)) = base_offset_info {
                        base_val + memory.offset
                    } else {
                        continue;
                    }
                } else {
                    memory.offset
                };

                for param in &union.parameters {
                    let size_bits = self.get_parameter_size_bits(&param.parameter_type);

                    let param_id = if let Some((_, instance_id, _)) = base_offset_info {
                        format!("{}::{}", instance_id, param.id)
                    } else {
                        param.id.clone()
                    };

                    let display_name = if let Some((_, _, instance_label)) = base_offset_info {
                        format!("[{}] {}", instance_label, param.text)
                    } else {
                        param.text.clone()
                    };

                    mappings.push((
                        memory.code_segment.clone(),
                        union_base_offset + param.offset as u32,
                        memory.bit_offset + param.bit_offset,
                        display_name,
                        size_bits,
                        param_id,
                    ));
                }
            }
        }
    }

    /// Get the size in bits for a parameter type.
    fn get_parameter_size_bits(&self, type_id: &str) -> u16 {
        if let Some(pt) = self.model.get_parameter_type(type_id) {
            match &pt.type_def {
                knxprod::ParameterTypeDef::TypeNumber(tn) => tn.size_in_bit as u16,
                knxprod::ParameterTypeDef::TypeRestriction(tr) => tr.size_in_bit as u16,
                knxprod::ParameterTypeDef::TypeText(tt) => (tt.size_in_bit) as u16,
                knxprod::ParameterTypeDef::TypeFloat(_) => 16, // DPT9 is typically 16 bits
                knxprod::ParameterTypeDef::TypeNone(_) => 8,
                knxprod::ParameterTypeDef::TypePicture(_) => 0, // Picture types don't occupy memory
                knxprod::ParameterTypeDef::TypeIpAddress(_) => 32, // IPv4 address is 4 bytes
            }
        } else {
            8 // Default to 1 byte
        }
    }

    /// Build annotations for a specific segment from the parameter mappings.
    fn build_annotations_for_segment(
        &self,
        segment_id: &str,
        mappings: &[(String, u32, u8, String, u16, String)],
    ) -> Vec<MemoryAnnotation> {
        let mut annotations: Vec<MemoryAnnotation> = mappings
            .iter()
            .filter(|(seg_id, _, _, _, _, _)| seg_id == segment_id)
            .map(|(_, offset, bit_offset, name, size_bits, param_id)| MemoryAnnotation {
                offset: *offset,
                bit_offset: *bit_offset,
                name: name.clone(),
                size_bits: *size_bits,
                param_id: param_id.clone(),
            })
            .collect();

        // Sort by offset
        annotations.sort_by_key(|a| (a.offset, a.bit_offset));
        annotations
    }

    /// Get the annotation at a specific byte offset within the currently selected segment.
    pub fn get_annotation_at_offset(&self, byte_offset: usize) -> Option<&MemoryAnnotation> {
        let segment = self.memory_segments.get(self.selected_segment_idx)?;

        for ann in &segment.annotations {
            let start_byte = ann.offset as usize;
            let end_byte = start_byte + ((ann.size_bits as usize + 7) / 8);
            if byte_offset >= start_byte && byte_offset < end_byte {
                return Some(ann);
            }
        }
        None
    }

    /// Navigate memory view up (by 16 bytes).
    pub fn memory_move_up(&mut self) {
        if self.selected_byte_offset >= 16 {
            self.selected_byte_offset -= 16;
            self.adjust_memory_scroll();
        }
    }

    /// Navigate memory view down (by 16 bytes).
    pub fn memory_move_down(&mut self, visible_lines: usize) {
        if let Some(seg) = self.memory_segments.get(self.selected_segment_idx) {
            let max_offset = seg.data.len().saturating_sub(1);
            if self.selected_byte_offset + 16 <= max_offset {
                self.selected_byte_offset += 16;
                self.adjust_memory_scroll_with_visible(visible_lines);
            }
        }
    }

    /// Navigate memory view left (by 1 byte).
    pub fn memory_move_left(&mut self) {
        if self.selected_byte_offset > 0 {
            self.selected_byte_offset -= 1;
            self.adjust_memory_scroll();
        }
    }

    /// Navigate memory view right (by 1 byte).
    pub fn memory_move_right(&mut self, visible_lines: usize) {
        if let Some(seg) = self.memory_segments.get(self.selected_segment_idx) {
            if self.selected_byte_offset + 1 < seg.data.len() {
                self.selected_byte_offset += 1;
                self.adjust_memory_scroll_with_visible(visible_lines);
            }
        }
    }

    /// Select a specific memory segment.
    pub fn select_segment(&mut self, idx: usize) {
        if idx < self.memory_segments.len() {
            self.selected_segment_idx = idx;
            self.selected_byte_offset = 0;
            self.memory_scroll_offset = 0;
        }
    }

    /// Adjust memory scroll to keep selected byte visible.
    fn adjust_memory_scroll(&mut self) {
        self.adjust_memory_scroll_with_visible(20); // Default visible lines
    }

    /// Adjust memory scroll with specific visible line count.
    fn adjust_memory_scroll_with_visible(&mut self, visible_lines: usize) {
        let current_line = self.selected_byte_offset / 16;

        // Scroll up if above visible area
        if current_line < self.memory_scroll_offset {
            self.memory_scroll_offset = current_line;
        }

        // Scroll down if below visible area
        if current_line >= self.memory_scroll_offset + visible_lines {
            self.memory_scroll_offset = current_line.saturating_sub(visible_lines - 1);
        }
    }

    /// Move segment selection up.
    pub fn segment_move_up(&mut self) {
        if self.selected_segment_idx > 0 {
            self.selected_segment_idx -= 1;
            self.selected_byte_offset = 0;
            self.memory_scroll_offset = 0;
        }
    }

    /// Move segment selection down.
    pub fn segment_move_down(&mut self) {
        if self.selected_segment_idx < self.memory_segments.len().saturating_sub(1) {
            self.selected_segment_idx += 1;
            self.selected_byte_offset = 0;
            self.memory_scroll_offset = 0;
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
            // Memory tab: Tabs -> Sidebar (segment list) -> Content (hex view) -> Tabs
            (MainTab::Memory, Focus::Tabs) => Focus::Sidebar,
            (MainTab::Memory, Focus::Sidebar) => Focus::Content,
            (MainTab::Memory, Focus::Content) => Focus::Tabs,
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
                (MainTab::Memory, Focus::Sidebar) => {
                    self.segment_move_up();
                }
                (MainTab::Memory, Focus::Content) => {
                    self.memory_move_up();
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
                (MainTab::Memory, Focus::Sidebar) => {
                    self.segment_move_down();
                }
                (MainTab::Memory, Focus::Content) => {
                    // Use default visible lines for now (20)
                    self.memory_move_down(20);
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
        match (self.current_tab, self.focus) {
            (_, Focus::Tabs) => self.prev_tab(),
            (MainTab::Parameters, Focus::Sidebar) => {
                // Collapse the selected tree node
                if let Some(node) = self.tree_nodes.get(self.selected_tree_idx) {
                    if node.has_children && self.expanded_nodes.contains(&node.id) {
                        self.expanded_nodes.remove(&node.id);
                        self.rebuild_tree();
                    }
                }
            }
            (MainTab::Memory, Focus::Content) => {
                self.memory_move_left();
            }
            _ => {}
        }
    }

    /// Move selection right (for tabs) or expand tree node (for sidebar).
    pub fn move_right(&mut self) {
        if !matches!(self.edit_mode, EditMode::None) {
            return;
        }
        match (self.current_tab, self.focus) {
            (_, Focus::Tabs) => self.next_tab(),
            (MainTab::Parameters, Focus::Sidebar) => {
                // Expand the selected tree node
                if let Some(node) = self.tree_nodes.get(self.selected_tree_idx) {
                    if node.has_children && !self.expanded_nodes.contains(&node.id) {
                        self.expanded_nodes.insert(node.id.clone());
                        self.rebuild_tree();
                    }
                }
            }
            (MainTab::Memory, Focus::Content) => {
                // Use default visible lines for now (20)
                self.memory_move_right(20);
            }
            _ => {}
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
                self.rebuild_memory_segments();
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
                self.rebuild_memory_segments();
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
                self.rebuild_memory_segments();
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
