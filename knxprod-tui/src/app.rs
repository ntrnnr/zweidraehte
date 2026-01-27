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
        blocks.len()
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
                    // Module instances have their own dynamic content - skip for now
                }
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
            }
        }
        false
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

        // Sort by object number
        self.com_object_rows.sort_by_key(|r| r.number);
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
        if self.focus == Focus::Tabs && matches!(self.edit_mode, EditMode::None) {
            self.prev_tab();
        }
    }

    /// Move selection right (for tabs).
    pub fn move_right(&mut self) {
        if self.focus == Focus::Tabs && matches!(self.edit_mode, EditMode::None) {
            self.next_tab();
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
                self.model
                    .set_parameter_value(&param_id, ParameterValue::Integer(new_value));
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
                    self.model
                        .set_parameter_value(&param_id, ParameterValue::Integer(v));
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
                self.model
                    .set_parameter_value(&param_id, ParameterValue::Text(text));
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
