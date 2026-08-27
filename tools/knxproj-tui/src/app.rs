//! Application state and logic for the KNX TUI viewer.

use crate::project_view::{EditableKey, ProjectKeyEditor, ProjectNavigation, ProjectNavigationTarget, ProjectOverview};
use zweidraehte_client::download::{
    ConfigurationPreviewBuilder, DeviceConfiguration, DeviceIdentity, MaskData, MembershipRole as ClientMembershipRole,
    ObjectMembership as ClientObjectMembership, PreviewPlacement, resolve_product_configuration,
};
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_ets_files::runtime::configuration::{
    EffectiveValueSource, ObjectFlagOverrides as ProductFlagOverrides, ObjectSetting, ProductConfiguration,
    ProductDptReferences, apply_configuration, configuration_from_device, effective_com_objects, effective_default,
};
use zweidraehte_ets_files::runtime::model::{DynamicVisitor, ParameterValue, walk_dynamic};
use zweidraehte_ets_files::schema::master_data::MaskVersion;
use zweidraehte_ets_files::schema::{
    Channel, ChannelIndependentBlock, ChannelIndependentItem, ChannelItem, Choose, ComObject, ComObjectPriority,
    DynamicSection, EnableFlag, Module, ModuleDef, ModuleDefDynamicItem, Parameter, ParameterBlock, ParameterBlockItem,
    ParameterItem, ParameterTypeDef, UnionParameter, WhenItem,
};
use zweidraehte_ets_files::{Device, MasterData};
use zweidraehte_project::{
    AuthoredProject, DataSecureMode, NetId, NetSecurityPolicy, ObjectFlagOverrides, ProjectDeviceId,
};

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

#[cfg(feature = "images")]
use ratatui_image::picker::Picker;
#[cfg(feature = "images")]
use ratatui_image::protocol::StatefulProtocol;
#[cfg(feature = "images")]
use std::collections::HashMap;

#[cfg(feature = "images")]
fn terminal_multiplexer_active() -> bool {
    std::env::var_os("TMUX").is_some() || std::env::var_os("STY").is_some()
}

/// Compute the actual object number for a module comm object.
///
/// Module comm objects have a local `number` (0, 1, 2, ...) and may have a `base_number`
/// argument reference. The actual object number is `base_number_value + local_number`.
/// If no BaseNumber is specified, the local number is used as-is.
fn compute_module_object_number(
    obj: &ComObject,
    expanded: &zweidraehte_ets_files::runtime::model::ExpandedModule,
    module_def: &ModuleDef,
) -> u16 {
    use zweidraehte_ets_files::runtime::model::ModuleArgValue;

    let local_number = obj.number;

    // Check if object has a BaseNumber argument reference
    if let Some(base_number_ref) = &obj.base_number {
        // The base_number_ref is an argument ID - we need to find the argument name first
        if let Some(arguments) = &module_def.arguments
            && let Some(arg_def) = arguments.arguments.iter().find(|a| a.id == *base_number_ref)
        {
            // Now look up the argument value by name in the expanded module
            if let Some(ModuleArgValue::Numeric(base)) = expanded.args.get(&arg_def.name) {
                return (*base as u16).saturating_add(local_number);
            }
        }
    }

    // No BaseNumber or couldn't resolve - use local number as-is
    local_number
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
    /// Byte offset → index into `annotations` (`u32::MAX` = none), one
    /// entry per byte of `data`. The hex view queries an annotation for
    /// every visible cell every frame; with tens of thousands of
    /// annotations in one segment a linear scan per cell dominates the
    /// frame time, so the lookup is precomputed here at rebuild time.
    pub annotation_index: Vec<u32>,
}

/// Annotation for a memory region occupied by a parameter.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields reserved for future use (click-to-navigate)
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

impl TreeNode {
    /// Group headers — the ETS-style main groups (channels, the
    /// device-settings block): never selectable, never a page of
    /// their own; only the sub-pages below them carry settings.
    pub fn is_group(&self) -> bool {
        matches!(self.node_type, NodeType::DeviceSettings | NodeType::Channel(_))
    }
}

/// Type of sidebar tree node.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields reserved for future use
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
        /// Block name/ID
        block_name: String,
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
    ParameterBlock { block_name: String, parent_channel: Option<String> },
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
    /// Whether we're inside a parameter block that has visible items
    in_visible_block: bool,
    /// Whether we're inside a module (skip internal ParameterBlocks from tree)
    in_module: bool,

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
            in_visible_block: false,
            in_module: false,
            hidden_parameter_block_depth: 0,
        }
    }

    /// Consume the visitor and return the collected tree nodes.
    pub fn into_tree(self) -> Vec<VisibleTreeNode> {
        self.root_nodes
    }

    /// Check if parameter block has any visible content.
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
                | ParameterBlockItem::Module(_)
                | ParameterBlockItem::Button(_)
                | ParameterBlockItem::Rows(_)
                | ParameterBlockItem::Columns(_) => {}
            }
        }
        false
    }

    /// Pre-ETS4-style blocks title themselves via `ParamRefId`: ETS shows the
    /// referenced parameter's text (with the ref's own override winning).
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
        if self.in_module {
            return;
        }

        // Only track visible blocks
        self.in_visible_block = self.block_has_visible_items(block);
        if !self.in_visible_block {
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

        let id = if let Some(ch_id) = &self.current_channel_id {
            format!("channel_{}_block_{}", ch_id, block_name)
        } else {
            format!("device_block_{}", block_name)
        };

        let child_node = VisibleTreeNode {
            id,
            raw_name: raw_text,
            node_type: VisibleNodeType::ParameterBlock {
                block_name: block_name.clone(),
                parent_channel: self.current_channel_id.clone(),
            },
            children: Vec::new(),
        };

        // Add to current parent
        if let Some(parent) = self.node_stack.last_mut() {
            parent.children.push(child_node);
        }
    }

    fn leave_parameter_block(&mut self, _block: &ParameterBlock) {
        if self.hidden_parameter_block_depth > 0 {
            self.hidden_parameter_block_depth -= 1;
            return;
        }

        self.in_visible_block = false;
    }

    fn visit_module(&mut self, module: &Module) {
        if self.hidden_parameter_block_depth > 0 {
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

    fn enter_module(&mut self, _module: &Module, _ctx: &zweidraehte_ets_files::runtime::model::VisitorModuleContext) {
        if self.hidden_parameter_block_depth > 0 {
            return;
        }

        // Mark that we're inside a module - skip internal ParameterBlocks from tree
        self.in_module = true;
    }

    fn leave_module(&mut self, _module: &Module, _ctx: &zweidraehte_ets_files::runtime::model::VisitorModuleContext) {
        if self.hidden_parameter_block_depth > 0 {
            return;
        }

        self.in_module = false;
    }
}

/// Focus state within the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    /// Project topology and group-address navigator.
    Project,
    /// Tab bar has focus
    Tabs,
    /// Sidebar tree has focus (Parameters tab)
    Sidebar,
    /// Content area has focus
    Content,
}

/// User-adjustable pane dimensions.
///
/// They are project-local editor state rather than authored KNX configuration:
/// storing them below `.zweidraehte/` avoids changing `project.knx` whenever a
/// user with a differently sized terminal opens the project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaneLayout {
    pub project_width: u16,
    pub topology_percent: u16,
    pub parameter_sidebar_width: u16,
    pub memory_sidebar_width: u16,
}

impl Default for PaneLayout {
    fn default() -> Self {
        Self { project_width: 34, topology_percent: 58, parameter_sidebar_width: 30, memory_sidebar_width: 35 }
    }
}

impl PaneLayout {
    const STATE_FILE: &'static str = "tui.toml";

    fn resize_horizontal(&mut self, tab: MainTab, focus: Focus, delta: i16) {
        let (target, minimum) = match (tab, focus) {
            (_, Focus::Project) => (&mut self.project_width, 24),
            (MainTab::Parameters, Focus::Sidebar | Focus::Content) => (&mut self.parameter_sidebar_width, 18),
            (MainTab::Memory, Focus::Sidebar | Focus::Content) => (&mut self.memory_sidebar_width, 20),
            _ => return,
        };
        *target = resize_dimension(*target, delta, minimum, 60);
    }

    fn resize_vertical(&mut self, focus: Focus, delta: i16) {
        if focus == Focus::Project {
            self.topology_percent = resize_dimension(self.topology_percent, delta, 25, 75);
        }
    }

    fn load(project_path: &Path) -> Result<Option<Self>, String> {
        let path = Self::state_path(project_path);
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("reading {}: {error}", path.display())),
        };
        let document =
            source.parse::<toml_edit::DocumentMut>().map_err(|error| format!("parsing {}: {error}", path.display()))?;
        let version = document
            .get("version")
            .and_then(toml_edit::Item::as_integer)
            .ok_or_else(|| format!("{} has no integer `version`", path.display()))?;
        if version != 1 {
            return Err(format!("{} uses unsupported version {version}", path.display()));
        }

        let defaults = Self::default();
        Ok(Some(Self {
            project_width: pane_dimension(&document, "project_width", defaults.project_width, 24, 60, &path)?,
            topology_percent: pane_dimension(&document, "topology_percent", defaults.topology_percent, 25, 75, &path)?,
            parameter_sidebar_width: pane_dimension(
                &document,
                "parameter_sidebar_width",
                defaults.parameter_sidebar_width,
                18,
                60,
                &path,
            )?,
            memory_sidebar_width: pane_dimension(
                &document,
                "memory_sidebar_width",
                defaults.memory_sidebar_width,
                20,
                60,
                &path,
            )?,
        }))
    }

    fn persist(self, project_path: &Path) -> Result<(), String> {
        let path = Self::state_path(project_path);
        let directory = path.parent().expect("TUI state path has a parent");
        fs::create_dir_all(directory).map_err(|error| format!("creating {}: {error}", directory.display()))?;

        // Preserve future editor settings and comments instead of replacing
        // the whole document just because the pane split changed.
        let mut document = match fs::read_to_string(&path) {
            Ok(source) => source
                .parse::<toml_edit::DocumentMut>()
                .map_err(|error| format!("parsing {}: {error}", path.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => toml_edit::DocumentMut::new(),
            Err(error) => return Err(format!("reading {}: {error}", path.display())),
        };
        document["version"] = toml_edit::value(1);
        if !document.get("panes").is_some_and(toml_edit::Item::is_table_like) {
            document["panes"] = toml_edit::table();
        }
        document["panes"]["project_width"] = toml_edit::value(i64::from(self.project_width));
        document["panes"]["topology_percent"] = toml_edit::value(i64::from(self.topology_percent));
        document["panes"]["parameter_sidebar_width"] = toml_edit::value(i64::from(self.parameter_sidebar_width));
        document["panes"]["memory_sidebar_width"] = toml_edit::value(i64::from(self.memory_sidebar_width));

        let temporary = directory.join(format!(
            ".tui.{}.{}.tmp",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("creating {}: {error}", temporary.display()))?;
        file.write_all(document.to_string().as_bytes())
            .map_err(|error| format!("writing {}: {error}", temporary.display()))?;
        file.sync_all().map_err(|error| format!("syncing {}: {error}", temporary.display()))?;
        fs::rename(&temporary, &path)
            .inspect_err(|_| {
                let _ = fs::remove_file(&temporary);
            })
            .map_err(|error| format!("replacing {}: {error}", path.display()))?;
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("syncing {}: {error}", directory.display()))?;
        Ok(())
    }

    fn state_path(project_path: &Path) -> PathBuf {
        project_path.parent().unwrap_or_else(|| Path::new(".")).join(".zweidraehte").join(Self::STATE_FILE)
    }
}

fn pane_dimension(
    document: &toml_edit::DocumentMut,
    name: &str,
    default: u16,
    minimum: u16,
    maximum: u16,
    path: &Path,
) -> Result<u16, String> {
    let Some(item) = document.get("panes").and_then(toml_edit::Item::as_table_like).and_then(|panes| panes.get(name))
    else {
        return Ok(default);
    };
    let value = item.as_integer().ok_or_else(|| format!("{} has a non-integer `panes.{name}`", path.display()))?;
    let value = u16::try_from(value).map_err(|_| format!("{} has an invalid `panes.{name}`", path.display()))?;
    Ok(value.clamp(minimum, maximum))
}

fn resize_dimension(current: u16, delta: i16, minimum: u16, maximum: u16) -> u16 {
    let next = i32::from(current) + i32::from(delta);
    next.clamp(i32::from(minimum), i32::from(maximum)) as u16
}

pub(crate) fn keep_selection_visible(offset: &mut usize, selected: usize, visible_rows: usize) {
    if selected < *offset {
        *offset = selected;
    } else if selected >= *offset + visible_rows {
        *offset = selected + 1 - visible_rows;
    }
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
    NumberInput { param_id: String, buffer: String, select_all: bool, min: Option<i64>, max: Option<i64> },
    /// Editing a text parameter
    TextInput { param_id: String, buffer: String, cursor: usize },
    /// Selecting the display language from a popup list.
    LanguageSelect {
        /// `(language, label)` per row; `None` is the default language.
        options: Vec<(Option<String>, String)>,
        selected_idx: usize,
        scroll_offset: usize,
    },
    /// Editing a group address for a communication object
    GroupAddressInput {
        /// The communication object number (ASAP)
        object_number: u16,
        /// The input buffer (e.g., "1/2/3")
        buffer: String,
    },
    /// Editing all per-object flag overrides in one compact form.
    ObjectFlagsInput { object_number: u16, buffer: String },
    /// Editing the selected net's human-readable group-address name. The
    /// stable net identifier—and therefore its key/state identity—does not
    /// change.
    NetNameInput { net: NetId, buffer: String, cursor: usize },
}

fn edit_number_input(buffer: &mut String, select_all: &mut bool, character: char) {
    let can_insert = character.is_ascii_digit() || (character == '-' && (*select_all || buffer.is_empty()));
    if !can_insert {
        return;
    }

    if core::mem::take(select_all) {
        buffer.clear();
    }

    buffer.push(character);
}

fn backspace_number_input(buffer: &mut String, select_all: &mut bool) {
    if core::mem::take(select_all) {
        buffer.clear();
    } else {
        buffer.pop();
    }
}

/// Widget type for rendering.
#[derive(Debug, Clone)]
pub enum WidgetType {
    /// Dropdown/enum selector
    Dropdown { options: Vec<(i64, String)>, current_idx: usize },
    /// Numeric spinner/input
    Number { value: i64, min: Option<i64>, max: Option<i64> },
    /// Text input field
    Text { value: String },
    /// Read-only display
    ReadOnly { value: String },
}

impl WidgetType {
    /// Collapse an editable widget into its read-only display form
    /// (Access = "Read": the value is shown but not user-editable).
    fn into_read_only(self) -> WidgetType {
        match self {
            WidgetType::Dropdown { options, current_idx } => WidgetType::ReadOnly {
                value: options.get(current_idx).map(|(_, text)| text.clone()).unwrap_or_default(),
            },
            WidgetType::Number { value, .. } => WidgetType::ReadOnly { value: value.to_string() },
            WidgetType::Text { value } => WidgetType::ReadOnly { value },
            read_only @ WidgetType::ReadOnly { .. } => read_only,
        }
    }
}

/// Item in the parameter content area.
#[derive(Debug, Clone)]
pub enum ContentItem {
    /// A parameter with its widget
    Parameter { param_id: String, text: String, suffix: Option<String>, widget: WidgetType },
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
    /// Read-on-init flag.
    pub flag_i: bool,
    /// Compact provenance summary (`P` product, `R` visible ref, `J`
    /// project) in C/R/W/T/U/I/priority order.
    pub provenance: String,
}

/// Everything a language switch needs to rebuild the device.
pub struct LanguageContext {
    /// The document's `<Languages>` translations.
    pub translations: zweidraehte_ets_files::runtime::Translations,
    /// The program as parsed, in its `DefaultLanguage` — every switch
    /// starts from this copy, because applying a translation rewrites
    /// texts in place.
    pub pristine: zweidraehte_ets_files::schema::ApplicationProgram,
    /// The baggage the device was originally built with.
    pub baggage: Option<zweidraehte_ets_files::runtime::BaggageIndex>,
}

/// The live download popup's state, fed by the worker thread.
pub struct DownloadUi {
    /// Finished task labels, oldest first.
    pub past: Vec<String>,
    /// The task currently running.
    pub current: Option<String>,
    /// `(index, total)` of the current procedure step; total 0 while
    /// still in the preparation stages.
    pub step: (usize, usize),
    /// Byte progress within the current step, when it has one.
    pub data: Option<(usize, usize)>,
    /// The outcome, once the worker is done.
    pub result: Option<Result<String, String>>,
    /// Spinner phase, advanced every UI tick.
    pub spinner: usize,
    receiver: std::sync::mpsc::Receiver<crate::download::DownloadMsg>,
}

/// What the App needs to start a download; provided from the CLI.
pub struct DownloadContext {
    pub target: Option<zweidraehte_client::cli::BusTarget>,
    pub master_data: Option<std::path::PathBuf>,
    pub security: zweidraehte_client::cli::SecurityArgs,
}

/// Persistent context behind the product editor. Product-only mode starts
/// without `authored`; its first save creates this project and its key/state
/// files before programming can start.
#[derive(Clone)]
pub struct ProjectContext {
    pub path: std::path::PathBuf,
    pub device: ProjectDeviceId,
    pub product_path: std::path::PathBuf,
    pub catalog_product: Option<String>,
    pub application_program: Option<String>,
    pub authored: Option<AuthoredProject>,
    pub original_source: Option<String>,
}

/// Product state prepared by the binary when the project navigator opens a
/// different device. Keeping XML/archive loading outside [`App`] lets the
/// editor remain reusable without teaching its UI state about file formats.
pub struct LoadedProjectDevice {
    pub device: Device,
    pub context: ProjectContext,
    pub flags: BTreeMap<u16, ObjectFlagOverrides>,
    pub language_context: Option<LanguageContext>,
    pub current_language: Option<String>,
}

/// Product data plus every view derived from it.
///
/// Rendering borrows this state through narrow [`App`] view accessors;
/// changes go through coordinator commands.
#[allow(dead_code)]
pub struct ProductWorkspace {
    device: Device,
    master_data: Option<MasterData>,
    /// Image picker for terminal protocol detection
    #[cfg(feature = "images")]
    image_picker: Option<Picker>,
    /// Cache of loaded images by baggage RefId, with their pixel
    /// dimensions (the protocol consumes the decoded image, so the size
    /// must be recorded at load time)
    #[cfg(feature = "images")]
    image_cache: HashMap<String, (StatefulProtocol, (u32, u32))>,
    tree_nodes: Vec<TreeNode>,
    content_items: Vec<ContentItem>,
    /// Visible parameter-ref count shown in the status bar. Cached
    /// because counting means hashing every visible ref id (~100k on
    /// large products), far too much to redo every frame; refreshed by
    /// `rebuild_com_objects`, which runs on every visibility change.
    visible_param_count: usize,
    /// Visible com-object-ref count for the status bar; same caching.
    visible_obj_count: usize,
    /// `content_items` no longer matches the selected tree node.
    /// Sidebar navigation only marks this and lets the rebuild happen
    /// once per rendered frame — holding an arrow key down repeats
    /// faster than large pages rebuild, and paying per keypress starves
    /// the draw loop.
    content_dirty: bool,
    /// `com_object_rows` no longer matches the device (an edit changed
    /// visibility or group links); rebuilt lazily by `ensure_tab_data`
    /// when the Communication Objects tab is next rendered, so edits on
    /// the Parameters tab don't pay for a table they aren't looking at.
    com_objects_dirty: bool,
    /// Same deferral for `memory_segments`.
    memory_dirty: bool,
    com_object_rows: Vec<ComObjectRow>,
    memory_segments: Vec<MemorySegment>,
    language_context: Option<LanguageContext>,
    current_language: Option<String>,
}

/// Project identity, navigation, authored overrides, and key editing.
#[allow(dead_code)]
pub struct ProjectWorkspace {
    product: ProductWorkspace,
    project_context: Option<ProjectContext>,
    /// Permanent project topology/net navigation. Product-only mode has none.
    project_navigation: Option<ProjectNavigation>,
    /// A device selected in the project navigator and awaiting product load.
    pending_project_device: Option<ProjectDeviceId>,
    /// Authored overrides remain separate from product/ref effective flags.
    object_flag_overrides: BTreeMap<u16, ObjectFlagOverrides>,
    /// Net-policy edits remain separate until the project source is saved.
    net_policy_overrides: BTreeMap<NetId, NetSecurityPolicy>,
    /// Project-selected Data Secure state. Product support remains an
    /// immutable MTXML capability and is checked before this can be enabled.
    data_secure: DataSecureMode,
    /// Read-only project/key/state dashboard. Key values never enter it.
    project_overview: Option<ProjectOverview>,
    /// Masked key-slot editor. Its input is transient and is cleared after
    /// each atomic key-store write.
    key_editor: Option<ProjectKeyEditor>,
}

impl Deref for ProjectWorkspace {
    type Target = ProductWorkspace;

    fn deref(&self) -> &Self::Target {
        &self.product
    }
}

impl DerefMut for ProjectWorkspace {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.product
    }
}

/// Transient navigation, focus, selection, scrolling, and popup state.
#[allow(dead_code)]
pub struct ViewState {
    project: ProjectWorkspace,
    current_tab: MainTab,
    selected_tree_idx: usize,
    selected_content_idx: usize,
    content_scroll_offset: usize,
    selected_obj_idx: usize,
    comm_obj_scroll_offset: usize,
    selected_segment_idx: usize,
    memory_scroll_offset: usize,
    selected_byte_offset: usize,
    focus: Focus,
    edit_mode: EditMode,
    expanded_nodes: std::collections::HashSet<String>,
    should_quit: bool,
    status_message: Option<String>,
    status_message_timer: Option<(String, std::time::Instant)>,
    pane_layout: PaneLayout,
    pane_layout_dirty: bool,
}

impl Deref for ViewState {
    type Target = ProjectWorkspace;

    fn deref(&self) -> &Self::Target {
        &self.project
    }
}

impl DerefMut for ViewState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.project
    }
}

/// Concrete coordinator for editor commands, rendering state, and downloads.
pub struct App {
    view: ViewState,
    /// Bus access for programming the device, from the CLI.
    download_context: Option<DownloadContext>,
    /// The download popup, while one is running or awaiting dismissal.
    download: Option<DownloadUi>,
}

impl Deref for App {
    type Target = ViewState;

    fn deref(&self) -> &Self::Target {
        &self.view
    }
}

impl DerefMut for App {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.view
    }
}

#[allow(dead_code)] // Convenience constructors for library use
impl App {
    const STATUS_MESSAGE_DURATION: std::time::Duration = std::time::Duration::from_secs(4);

    /// Create a new application with the given device.
    pub fn new(device: Device) -> Self {
        Self::with_master_data(device, None)
    }

    /// Create a new application with device and optional master data.
    ///
    /// When master data is provided, the app can use mask version information
    /// to correctly generate table layouts based on the device's mask version.
    pub fn with_master_data(device: Device, master_data: Option<MasterData>) -> Self {
        let mut app = Self {
            view: ViewState {
                project: ProjectWorkspace {
                    product: ProductWorkspace {
                        device,
                        master_data,
                        #[cfg(feature = "images")]
                        image_picker: Some(Picker::halfblocks()),
                        #[cfg(feature = "images")]
                        image_cache: HashMap::new(),
                        tree_nodes: Vec::new(),
                        content_items: Vec::new(),
                        visible_param_count: 0,
                        visible_obj_count: 0,
                        content_dirty: false,
                        com_objects_dirty: false,
                        memory_dirty: false,
                        com_object_rows: Vec::new(),
                        memory_segments: Vec::new(),
                        language_context: None,
                        current_language: None,
                    },
                    project_context: None,
                    project_navigation: None,
                    pending_project_device: None,
                    object_flag_overrides: BTreeMap::new(),
                    net_policy_overrides: BTreeMap::new(),
                    data_secure: DataSecureMode::Disabled,
                    project_overview: None,
                    key_editor: None,
                },
                current_tab: MainTab::Parameters,
                selected_tree_idx: 0,
                selected_content_idx: 0,
                content_scroll_offset: 0,
                selected_obj_idx: 0,
                comm_obj_scroll_offset: 0,
                selected_segment_idx: 0,
                memory_scroll_offset: 0,
                selected_byte_offset: 0,
                focus: Focus::Tabs,
                edit_mode: EditMode::None,
                expanded_nodes: std::collections::HashSet::new(),
                should_quit: false,
                status_message: None,
                status_message_timer: None,
                pane_layout: PaneLayout::default(),
                pane_layout_dirty: false,
            },
            download_context: None,
            download: None,
        };

        // Build initial data
        app.rebuild_tree();
        app.rebuild_content();
        app.rebuild_com_objects();
        app.rebuild_memory_segments();

        app
    }

    pub fn set_download_context(&mut self, context: DownloadContext) {
        self.download_context = Some(context);
    }

    pub fn master_data(&self) -> Option<&MasterData> {
        self.master_data.as_ref()
    }

    pub fn current_tab(&self) -> MainTab {
        self.current_tab
    }

    pub fn focus(&self) -> Focus {
        self.focus
    }

    pub fn pane_layout(&self) -> PaneLayout {
        self.pane_layout
    }

    pub fn edit_mode(&self) -> &EditMode {
        &self.edit_mode
    }

    pub fn project_navigation(&self) -> Option<&ProjectNavigation> {
        self.project_navigation.as_ref()
    }

    pub fn project_overview(&self) -> Option<&ProjectOverview> {
        self.project_overview.as_ref()
    }

    pub fn key_editor(&self) -> Option<&ProjectKeyEditor> {
        self.key_editor.as_ref()
    }

    pub fn download(&self) -> Option<&DownloadUi> {
        self.download.as_ref()
    }

    pub fn tree_nodes(&self) -> &[TreeNode] {
        &self.tree_nodes
    }

    pub fn content_items(&self) -> &[ContentItem] {
        &self.content_items
    }

    pub fn com_object_rows(&self) -> &[ComObjectRow] {
        &self.com_object_rows
    }

    pub fn memory_segments(&self) -> &[MemorySegment] {
        &self.memory_segments
    }

    pub fn selected_tree_idx(&self) -> usize {
        self.selected_tree_idx
    }

    pub fn selected_content_idx(&self) -> usize {
        self.selected_content_idx
    }

    pub fn selected_obj_idx(&self) -> usize {
        self.selected_obj_idx
    }

    pub fn selected_segment_idx(&self) -> usize {
        self.selected_segment_idx
    }

    pub fn selected_byte_offset(&self) -> usize {
        self.selected_byte_offset
    }

    pub fn content_scroll_offset_for(&mut self, viewport_rows: usize) -> usize {
        let selected = self.selected_content_idx;
        keep_selection_visible(&mut self.content_scroll_offset, selected, viewport_rows.max(1));
        self.content_scroll_offset
    }

    pub fn comm_object_scroll_offset_for(&mut self, viewport_rows: usize) -> usize {
        let selected = self.selected_obj_idx;
        keep_selection_visible(&mut self.comm_obj_scroll_offset, selected, viewport_rows.max(1));
        self.comm_obj_scroll_offset
    }

    pub fn memory_scroll_offset_for(&mut self, viewport_rows: usize) -> usize {
        let selected_line = self.selected_byte_offset / 16;
        keep_selection_visible(&mut self.memory_scroll_offset, selected_line, viewport_rows.max(1));
        self.memory_scroll_offset
    }

    pub fn visible_param_count(&self) -> usize {
        self.visible_param_count
    }

    pub fn visible_obj_count(&self) -> usize {
        self.visible_obj_count
    }

    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }

    pub fn product_supports_data_secure(&self) -> bool {
        self.device.program().is_secure_enabled.unwrap_or(false)
    }

    pub fn product_name(&self) -> &str {
        &self.device.program().name
    }

    pub fn data_secure_enabled(&self) -> bool {
        self.data_secure.is_enabled()
    }

    pub fn is_editing(&self) -> bool {
        !matches!(self.edit_mode, EditMode::None)
    }

    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub fn request_quit(&mut self) {
        self.should_quit = true;
    }

    pub fn set_status_message(&mut self, message: impl Into<String>) {
        self.status_message = Some(message.into());
    }

    pub fn download_active(&self) -> bool {
        self.download.is_some()
    }

    pub fn download_finished(&self) -> bool {
        self.download.as_ref().is_some_and(|download| download.result.is_some())
    }

    pub fn project_overview_active(&self) -> bool {
        self.project_overview.is_some()
    }

    pub fn key_editor_active(&self) -> bool {
        self.key_editor.is_some()
    }

    pub fn key_editor_accepts_close(&self) -> bool {
        self.key_editor.as_ref().is_some_and(|editor| editor.input.is_none())
    }

    /// Start or advance the transient status-message timer. Returning `true`
    /// asks the event loop for one final redraw after the legend is revealed.
    pub fn poll_status_message(&mut self) -> bool {
        let Some(message) = self.status_message.as_ref() else {
            self.status_message_timer = None;
            return false;
        };
        let now = std::time::Instant::now();
        match &self.status_message_timer {
            Some((tracked, started)) if tracked == message => {
                if now.duration_since(*started) >= Self::STATUS_MESSAGE_DURATION {
                    self.status_message = None;
                    self.status_message_timer = None;
                    return true;
                }
            }
            _ => self.status_message_timer = Some((message.clone(), now)),
        }
        false
    }

    /// Move the splitter nearest the focused pane. Horizontal arrows move
    /// by two columns; vertical arrows move the project navigator's divider
    /// in five-percent steps.
    pub fn resize_focused_pane(&mut self, horizontal: i16, vertical: i16) {
        let previous = self.pane_layout;
        let current_tab = self.current_tab;
        let focus = self.focus;
        if horizontal != 0 {
            self.pane_layout.resize_horizontal(current_tab, focus, horizontal.saturating_mul(2));
        }
        if vertical != 0 {
            self.pane_layout.resize_vertical(focus, vertical.saturating_mul(5));
        }
        self.pane_layout_dirty |= self.pane_layout != previous;
    }

    /// Detect the terminal's image protocol after terminal setup and before
    /// crossterm starts reading events.
    #[cfg(feature = "images")]
    pub fn initialize_image_picker(&mut self) {
        // A timed-out ratatui-image query leaves its stdin worker blocked.
        // tmux and screen can swallow the response, after which that worker
        // consumes the application's key events.
        // See https://github.com/ratatui/ratatui-image/issues/87.
        self.image_picker = Some(if terminal_multiplexer_active() {
            Picker::halfblocks()
        } else {
            Picker::from_query_stdio().unwrap_or_else(|_| Picker::halfblocks())
        });
        self.image_cache.clear();
    }

    /// Load an image from the baggage index and cache it.
    ///
    /// Returns a reference to the cached StatefulProtocol if the image
    /// was loaded successfully.
    #[cfg(feature = "images")]
    pub fn load_image(&mut self, ref_id: &str) -> Option<&mut StatefulProtocol> {
        self.load_image_entry(ref_id).map(|(protocol, _)| protocol)
    }

    #[cfg(feature = "images")]
    fn load_image_entry(&mut self, ref_id: &str) -> Option<&mut (StatefulProtocol, (u32, u32))> {
        // Check if already cached
        if self.image_cache.contains_key(ref_id) {
            return self.image_cache.get_mut(ref_id);
        }

        // Try to load from baggage (baggage_index is now in device)
        let baggage_path = self.device.baggage_index()?.get(ref_id)?.file_path().to_owned();
        let picker = self.image_picker.as_mut()?;
        if !baggage_path.exists() {
            return None;
        }

        // Load the image
        let dyn_img = image::open(baggage_path).ok()?;
        let dims = (dyn_img.width(), dyn_img.height());

        // Create the protocol for rendering
        let protocol = picker.new_resize_protocol(dyn_img);

        // Cache it
        self.image_cache.insert(ref_id.to_string(), (protocol, dims));
        self.image_cache.get_mut(ref_id)
    }

    /// The image's display extent in terminal cells, downscaled to fit
    /// `max_cols` columns (aspect preserved).
    ///
    /// The extent is computed against a fixed logical cell of 8×16 px —
    /// the classic 96-dpi terminal cell — rather than the terminal's
    /// actual font size. ETS sizes pictures in logical pixels, so their
    /// size tracks the text around them; using device pixels instead
    /// made images shrink to half on a HiDPI terminal. The renderer
    /// pairs this with `Resize::Scale`, which fills the resulting area
    /// on any backend.
    #[cfg(feature = "images")]
    pub fn picture_cell_size(&mut self, ref_id: &str, max_cols: u16) -> Option<(u16, u16)> {
        const CELL_W: f64 = 8.0;
        const CELL_H: f64 = 16.0;

        let (_, (img_w, img_h)) = *self.load_image_entry(ref_id)?;
        if img_w == 0 || img_h == 0 || max_cols == 0 {
            return None;
        }

        let max_px = f64::from(max_cols) * CELL_W;
        let scale = (max_px / f64::from(img_w)).min(1.0);
        let cols = (f64::from(img_w) * scale / CELL_W).ceil().max(1.0) as u16;
        let rows = (f64::from(img_h) * scale / CELL_H).ceil().max(1.0) as u16;
        Some((cols, rows))
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

    /// Rebuild the sidebar tree based on the model structure using the visitor pattern.
    pub fn rebuild_tree(&mut self) {
        self.tree_nodes.clear();

        // Clone to avoid borrow issues
        let dynamic = self.device.dynamic_section().cloned();
        let module_defs = self.device.module_defs().clone();

        if let Some(dynamic) = dynamic {
            // Use the visitor to walk the dynamic section and collect visible tree
            let mut visitor = TreeBuilderVisitor::new(&self.device);
            walk_dynamic(&dynamic, &mut visitor, &self.device, &module_defs);

            let visible_tree = visitor.into_tree();

            // Flatten the visible tree to TreeNode list based on expansion state
            self.flatten_visible_tree(&visible_tree, &dynamic);
        }

        // The cursor must rest on a page, never a group header.
        self.snap_selection_to_page();
    }

    /// Move `selected_tree_idx` onto the nearest selectable page —
    /// forward first, then backward; a tree of nothing but headers
    /// leaves it at 0 with no content.
    fn snap_selection_to_page(&mut self) {
        if self.tree_nodes.get(self.selected_tree_idx).is_some_and(|n| !n.is_group()) {
            return;
        }
        let forward = self.tree_nodes.iter().skip(self.selected_tree_idx).position(|n| !n.is_group());
        let index = match forward {
            Some(offset) => Some(self.selected_tree_idx + offset),
            None => self.tree_nodes.iter().rposition(|n| !n.is_group()),
        };
        self.selected_tree_idx = index.unwrap_or(0);
    }

    /// Flatten a VisibleTreeNode tree to the flat TreeNode list.
    ///
    /// This traverses the collected visible tree and creates TreeNode entries,
    /// respecting expansion state to determine which children to include.
    fn flatten_visible_tree(&mut self, visible_tree: &[VisibleTreeNode], dynamic: &DynamicSection) {
        for node in visible_tree {
            let is_expanded = self.expanded_nodes.contains(&node.id);

            // Interpolate the display name
            let name = match &node.node_type {
                VisibleNodeType::DeviceSettings => node.raw_name.clone(),
                VisibleNodeType::Channel { id } => {
                    // For channels, interpolate {{0}} with TextParameterRefId
                    if let Some(channel) = dynamic.find_channel(id) {
                        self.device.interpolate_channel_text(&node.raw_name, channel.text_parameter_ref_id.as_deref())
                    } else {
                        self.device.interpolate_text(&node.raw_name)
                    }
                }
                VisibleNodeType::ParameterBlock { .. } => self.device.interpolate_text(&node.raw_name),
                VisibleNodeType::Module { instance_id, .. } => {
                    // For modules, get the expanded module and interpolate with its args
                    self.interpolate_module_name(instance_id, &node.raw_name)
                }
            };

            // Convert to NodeType
            let node_type = match &node.node_type {
                VisibleNodeType::DeviceSettings => NodeType::DeviceSettings,
                VisibleNodeType::Channel { id } => NodeType::Channel(id.clone()),
                VisibleNodeType::ParameterBlock { block_name, parent_channel } => {
                    NodeType::ParameterBlock { parent: parent_channel.clone(), block_name: block_name.clone() }
                }
                VisibleNodeType::Module { instance_id, parent_channel } => {
                    NodeType::ModuleInstance { instance_id: instance_id.clone(), parent: parent_channel.clone() }
                }
            };

            // Main groups are permanent headers: always expanded (a
            // header you cannot select cannot be re-opened), their
            // sub-pages always listed — the way ETS presents them.
            let _ = is_expanded;
            self.tree_nodes.push(TreeNode {
                id: node.id.clone(),
                name,
                depth: 0, // Root nodes
                expanded: true,
                has_children: !node.children.is_empty(),
                node_type,
            });
            self.flatten_children(&node.children, 1, dynamic);
        }
    }

    /// Flatten children of a visible tree node at a given depth.
    fn flatten_children(&mut self, children: &[VisibleTreeNode], depth: usize, _dynamic: &DynamicSection) {
        for child in children {
            let is_expanded = self.expanded_nodes.contains(&child.id);

            let name = match &child.node_type {
                VisibleNodeType::ParameterBlock { .. } => self.device.interpolate_text(&child.raw_name),
                VisibleNodeType::Module { instance_id, .. } => {
                    self.interpolate_module_name(instance_id, &child.raw_name)
                }
                _ => child.raw_name.clone(),
            };

            let node_type = match &child.node_type {
                VisibleNodeType::ParameterBlock { block_name, parent_channel } => {
                    NodeType::ParameterBlock { parent: parent_channel.clone(), block_name: block_name.clone() }
                }
                VisibleNodeType::Module { instance_id, parent_channel } => {
                    NodeType::ModuleInstance { instance_id: instance_id.clone(), parent: parent_channel.clone() }
                }
                _ => continue, // Skip unexpected types at child level
            };

            self.tree_nodes.push(TreeNode {
                id: child.id.clone(),
                name,
                depth,
                expanded: is_expanded,
                has_children: !child.children.is_empty(),
                node_type,
            });

            // If expanded, recursively add grandchildren
            if is_expanded {
                self.flatten_children(&child.children, depth + 1, _dynamic);
            }
        }
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
                            if let ModuleDefDynamicItem::ParameterBlock(pb) = item {
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
                        let composite_id = format!("{}::{}", expanded.instance_id, pr.ref_id);
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
                    if let Some(zweidraehte_ets_files::runtime::model::ModuleArgValue::Numeric(ch)) =
                        expanded.args.get("ChNo")
                    {
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
    fn collect_visible_channel_blocks<'a>(&self, channel: &'a Channel, blocks: &mut Vec<&'a ParameterBlock>) {
        for item in &channel.items {
            match item {
                ChannelItem::ParameterBlockRename(_) => {}
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
    fn collect_visible_channel_modules<'a>(&self, channel: &'a Channel, modules: &mut Vec<&'a Module>) {
        for item in &channel.items {
            match item {
                ChannelItem::ParameterBlockRename(_) => {}
                ChannelItem::Module(module) => {
                    if self.device.is_module_visible(&module.id) {
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
    fn collect_modules_from_pb<'a>(&self, items: &'a [ParameterBlockItem], modules: &mut Vec<&'a Module>) {
        for item in items {
            match item {
                ParameterBlockItem::ParameterBlock(block) => {
                    self.collect_modules_from_pb(&block.items, modules);
                }
                ParameterBlockItem::Module(module) if self.device.is_module_visible(&module.id) => {
                    modules.push(module);
                }
                ParameterBlockItem::Choose(choose) => {
                    self.collect_modules_from_choose(choose, modules);
                }
                _ => {}
            }
        }
    }

    /// Collect modules from Choose blocks.
    fn collect_modules_from_choose<'a>(&self, choose: &'a Choose, modules: &mut Vec<&'a Module>) {
        let selector_value = self.get_selector_value(&choose.param_ref_id);

        let mut any_matched = false;
        for when in &choose.whens {
            if when.default.unwrap_or(false) {
                continue;
            }
            if let Some(test) = &when.test
                && self.matches_condition(selector_value, test)
            {
                any_matched = true;
                self.collect_modules_from_when(&when.items, modules);
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
    fn collect_modules_from_when<'a>(&self, items: &'a [WhenItem], modules: &mut Vec<&'a Module>) {
        for item in items {
            match item {
                WhenItem::Module(module) if self.device.is_module_visible(&module.id) => {
                    modules.push(module);
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
    fn collect_blocks_from_choose<'a>(&self, choose: &'a Choose, blocks: &mut Vec<&'a ParameterBlock>) {
        // Get the selector parameter value
        let selector_value = self.get_selector_value(&choose.param_ref_id);

        // First pass: collect all matching non-default whens
        let mut any_matched = false;
        for when in &choose.whens {
            if when.default.unwrap_or(false) {
                continue; // Handle defaults in second pass
            }
            if let Some(test) = &when.test
                && self.matches_condition(selector_value, test)
            {
                any_matched = true;
                self.collect_when_blocks(&when.items, blocks);
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
                WhenItem::ParameterBlock(pb) if self.block_has_visible_items(&pb.items) => {
                    blocks.push(pb);
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
        let param_ref = self.device.get_parameter_ref(param_ref_id)?;
        let param_value = self.device.get_parameter_value(&param_ref.ref_id)?;

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
        use zweidraehte_ets_files::runtime::model::Condition;
        value.is_some_and(|v| Condition::parse(test).is_some_and(|c| c.matches(v)))
    }

    /// Collect all visible parameter blocks from CIB, including those nested in Choose blocks.
    fn collect_visible_cib_blocks<'a>(&self, cib: &'a ChannelIndependentBlock, blocks: &mut Vec<&'a ParameterBlock>) {
        for item in &cib.items {
            match item {
                ChannelIndependentItem::ParameterBlockRename(_) => {}
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

    fn block_has_visible_items(&self, items: &[ParameterBlockItem]) -> bool {
        for item in items {
            match item {
                ParameterBlockItem::ParameterBlock(block) => {
                    if self.block_has_visible_items(&block.items) {
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
        if self.device.is_module_parameter(param_id) {
            self.device.set_module_parameter_value_by_composite_id(param_id, value);
        } else {
            self.device.set_parameter_value(param_id, value);
        }
    }

    /// Rebuild `content_items` if sidebar navigation left it stale.
    /// A no-op otherwise, so it is safe to call from any place about to
    /// read `content_items`.
    pub fn ensure_content(&mut self) {
        if self.content_dirty {
            self.rebuild_content();
        }
    }

    /// Rebuild parameter content based on selected tree node.
    pub fn rebuild_content(&mut self) {
        self.content_dirty = false;
        self.content_items.clear();

        // Clone node_type to avoid borrow conflict
        let node_type = self.tree_nodes.get(self.selected_tree_idx).map(|n| n.node_type.clone());

        if let Some(node_type) = node_type {
            match &node_type {
                // Group headers are not pages: no settings of their
                // own, ETS-style. (Unreachable through navigation —
                // the cursor snaps to pages — but a tree of nothing
                // but headers still lands here.)
                NodeType::DeviceSettings | NodeType::Channel(_) => {}
                NodeType::ParameterBlock { parent, block_name } => {
                    self.build_block_content(parent.as_deref(), block_name);
                }
                NodeType::ModuleInstance { instance_id, .. } => {
                    self.build_module_content(instance_id);
                }
            }
        }
    }

    fn build_block_content(&mut self, parent: Option<&str>, block_name: &str) {
        let dynamic = self.device.dynamic_section().cloned();

        if let Some(dynamic) = dynamic {
            match parent {
                None => {
                    // Device settings block
                    if let Some(cib) = dynamic.channel_independent_block()
                        && let Some(pb) = self.find_block_in_cib(cib, block_name)
                    {
                        self.add_block_items(&pb.items.clone());
                    }
                }
                Some(channel_id) => {
                    if let Some(channel) = dynamic.find_channel(channel_id)
                        && let Some(pb) = self.find_block_in_channel(channel, block_name)
                    {
                        self.add_block_items(&pb.items.clone());
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
                        self.add_module_block_items(&pb.items, &expanded);
                    }
                    ModuleDefDynamicItem::Choose(choose) => {
                        self.add_module_choose_items(choose, &expanded);
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

    /// Add parameter block items for a module, applying text interpolation.
    fn add_module_block_items(
        &mut self,
        items: &[ParameterBlockItem],
        expanded: &zweidraehte_ets_files::runtime::model::ExpandedModule,
    ) {
        for item in items {
            match item {
                ParameterBlockItem::ParameterBlock(block) => {
                    self.add_module_block_items(&block.items, expanded);
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
        expanded: &zweidraehte_ets_files::runtime::model::ExpandedModule,
    ) {
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
    fn get_module_selector_value(
        &self,
        param_ref_id: &str,
        expanded: &zweidraehte_ets_files::runtime::model::ExpandedModule,
    ) -> Option<i64> {
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
        let composite_id = format!("{}::{}", expanded.instance_id, param_ref.ref_id);

        // Get the value from module params
        let param_value = self.device.get_module_parameter_value_by_composite_id(&composite_id);

        match param_value {
            Some(ParameterValue::Integer(v)) => Some(*v),
            Some(ParameterValue::Float(v)) => Some(*v as i64),
            _ => None,
        }
    }

    /// Add when items for a module.
    fn add_module_when_items(
        &mut self,
        items: &[WhenItem],
        expanded: &zweidraehte_ets_files::runtime::model::ExpandedModule,
    ) {
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
                    self.add_module_block_items(&pb.items, expanded);
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
                WhenItem::Module(_) => {}
            }
        }
    }

    /// Add a module parameter ref to content items.
    fn add_module_param_ref(&mut self, ref_id: &str, expanded: &zweidraehte_ets_files::runtime::model::ExpandedModule) {
        // Look up the ModuleDef to access its static section
        let module_def = match self.device.get_module_def(&expanded.module_def_id) {
            Some(def) => def.clone(),
            None => {
                return;
            }
        };

        // Find the ParameterRef in the module's static section
        let param_ref = module_def
            .static_section
            .parameter_refs
            .as_ref()
            .and_then(|refs| refs.refs.iter().find(|pr| pr.id == ref_id));

        let param_ref = match param_ref {
            Some(pr) => pr.clone(),
            None => {
                return;
            }
        };

        // Find the Parameter using the RefId - check both regular parameters and union parameters
        enum FoundParameter {
            Regular(Parameter),
            Union(UnionParameter),
        }

        let found_param: Option<FoundParameter> = module_def.static_section.parameters.as_ref().and_then(|params| {
            for item in &params.items {
                match item {
                    ParameterItem::Parameter(p) if p.id == param_ref.ref_id => {
                        return Some(FoundParameter::Regular(p.clone()));
                    }
                    ParameterItem::Union(u) => {
                        // Search inside union parameters
                        if let Some(up) = u.parameters.iter().find(|up| up.id == param_ref.ref_id) {
                            return Some(FoundParameter::Union(up.clone()));
                        }
                    }
                    _ => {}
                }
            }
            None
        });

        // Extract common fields based on parameter type
        let (param_id_str, param_text, param_suffix, param_type, param_access) = match &found_param {
            Some(FoundParameter::Regular(p)) => {
                (p.id.clone(), p.text.clone(), p.suffix_text.clone(), p.parameter_type.clone(), p.access.clone())
            }
            Some(FoundParameter::Union(up)) => {
                (up.id.clone(), up.text.clone(), up.suffix_text.clone(), up.parameter_type.clone(), up.access.clone())
            }
            None => {
                return;
            }
        };

        // Effective access: the ParameterRef's override, else the base
        // Parameter's.
        let effective_access = param_ref.access.clone().or(param_access);

        // Skip hidden parameters
        if effective_access.as_deref() == Some("None") {
            return;
        }

        // Build display text with interpolation
        let raw_text = param_ref.text.clone().unwrap_or(param_text);
        let text = self.device.interpolate_module_text(&raw_text, expanded);

        // Use a unique ID that includes the module instance
        let param_id = format!("{}::{}", expanded.instance_id, param_id_str);

        // Check if this is a picture type (only for regular parameters).
        // A picture renders even without a label text, so this comes
        // before the empty-text skip.
        if let Some(FoundParameter::Regular(ref p)) = found_param
            && let Some((ref_id, alignment)) = self.get_module_picture_ref_id(p)
        {
            let text = (!text.is_empty()).then_some(text);
            self.content_items.push(ContentItem::Picture { ref_id, text, alignment });
            return;
        }

        if text.is_empty() {
            return;
        }

        // Build widget based on parameter type
        let mut widget = self.build_widget_for_module_param_by_type(&param_type, &param_id);
        if effective_access.as_deref() == Some("Read") {
            widget = widget.into_read_only();
        }

        let suffix = param_suffix.or_else(|| self.parameter_type_suffix(&param_type));

        self.content_items.push(ContentItem::Parameter { param_id, text, suffix, widget });
    }

    /// Build a widget for a module parameter.
    fn build_widget_for_module_param(
        &self,
        parameter: &Parameter,
        _module_def: &ModuleDef,
        composite_param_id: &str,
    ) -> WidgetType {
        use ParameterTypeDef;

        // Get the current value from module parameter storage
        let current_value = self.device.get_module_parameter_value_by_composite_id(composite_param_id);

        // Look up the parameter type
        let param_type = self.device.get_parameter_type(&parameter.parameter_type);

        match param_type.map(|pt| &pt.type_def) {
            Some(ParameterTypeDef::TypeRestriction(tr)) => {
                // Build dropdown options from enumerations
                let options: Vec<(i64, String)> =
                    tr.enumerations.iter().map(|e| (e.value as i64, e.text.clone())).collect();

                let current_val = match current_value {
                    Some(&ParameterValue::Integer(v)) => v,
                    _ => parameter.value.parse().unwrap_or(0),
                };

                let current_idx = options.iter().position(|(v, _)| *v == current_val).unwrap_or(0);

                WidgetType::Dropdown { options, current_idx }
            }
            Some(ParameterTypeDef::TypeNumber(tn)) => {
                let current_val = match current_value {
                    Some(&ParameterValue::Integer(v)) => v,
                    _ => parameter.value.parse().unwrap_or(0),
                };

                WidgetType::Number { value: current_val, min: Some(tn.min_inclusive), max: Some(tn.max_inclusive) }
            }
            Some(ParameterTypeDef::TypeTime(time)) => {
                let current_val = match current_value {
                    Some(&ParameterValue::Integer(value)) => value,
                    _ => parameter.value.parse().unwrap_or(0),
                };

                WidgetType::Number { value: current_val, min: Some(time.min_inclusive), max: Some(time.max_inclusive) }
            }
            Some(ParameterTypeDef::TypeText(_) | ParameterTypeDef::TypeColor(_)) => {
                let val = match current_value {
                    Some(ParameterValue::Text(s)) => s.clone(),
                    _ => parameter.value.clone(),
                };
                WidgetType::Text { value: val }
            }
            Some(ParameterTypeDef::TypeFloat(tf)) => {
                let current_val = match current_value {
                    Some(&ParameterValue::Integer(v)) => v,
                    Some(&ParameterValue::Float(v)) => v as i64,
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
                // For unknown, picture, and IP types, show as read-only.
                let val = match current_value {
                    Some(ParameterValue::Integer(v)) => v.to_string(),
                    Some(ParameterValue::Text(s)) => s.clone(),
                    _ => parameter.value.clone(),
                };
                WidgetType::ReadOnly { value: val }
            }
        }
    }

    /// Build a widget for a module parameter using only the type ID.
    /// Used when we have extracted parameter info (e.g., from union parameters).
    fn build_widget_for_module_param_by_type(&self, type_id: &str, composite_param_id: &str) -> WidgetType {
        use ParameterTypeDef;

        // Get the current value from module parameter storage
        let current_value = self.device.get_module_parameter_value_by_composite_id(composite_param_id);

        // Look up the parameter type
        let param_type = self.device.get_parameter_type(type_id);

        match param_type.map(|pt| &pt.type_def) {
            Some(ParameterTypeDef::TypeRestriction(tr)) => {
                // Build dropdown options from enumerations
                let options: Vec<(i64, String)> =
                    tr.enumerations.iter().map(|e| (e.value as i64, e.text.clone())).collect();

                let current_val = match current_value {
                    Some(&ParameterValue::Integer(v)) => v,
                    _ => 0,
                };

                let current_idx = options.iter().position(|(v, _)| *v == current_val).unwrap_or(0);

                WidgetType::Dropdown { options, current_idx }
            }
            Some(ParameterTypeDef::TypeNumber(tn)) => {
                let current_val = match current_value {
                    Some(&ParameterValue::Integer(v)) => v,
                    _ => 0,
                };

                WidgetType::Number { value: current_val, min: Some(tn.min_inclusive), max: Some(tn.max_inclusive) }
            }
            Some(ParameterTypeDef::TypeTime(time)) => {
                let current_val = match current_value {
                    Some(&ParameterValue::Integer(value)) => value,
                    _ => 0,
                };

                WidgetType::Number { value: current_val, min: Some(time.min_inclusive), max: Some(time.max_inclusive) }
            }
            Some(ParameterTypeDef::TypeText(_) | ParameterTypeDef::TypeColor(_)) => {
                let val = match current_value {
                    Some(ParameterValue::Text(s)) => s.clone(),
                    _ => String::new(),
                };
                WidgetType::Text { value: val }
            }
            Some(ParameterTypeDef::TypeFloat(tf)) => {
                let current_val = match current_value {
                    Some(&ParameterValue::Integer(v)) => v,
                    Some(&ParameterValue::Float(v)) => v as i64,
                    _ => 0,
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
                // For unknown, picture, and IP types, show as read-only.
                let val = match current_value {
                    Some(ParameterValue::Integer(v)) => v.to_string(),
                    Some(ParameterValue::Text(s)) => s.clone(),
                    _ => String::new(),
                };
                WidgetType::ReadOnly { value: val }
            }
        }
    }

    /// Add a module comm object ref to content items.
    fn add_module_com_obj_ref(
        &mut self,
        ref_id: &str,
        expanded: &zweidraehte_ets_files::runtime::model::ExpandedModule,
    ) {
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

    /// Find a parameter block by name in a CIB, including inside Choose blocks.
    fn find_block_in_cib<'a>(&self, cib: &'a ChannelIndependentBlock, block_name: &str) -> Option<&'a ParameterBlock> {
        for item in &cib.items {
            match item {
                ChannelIndependentItem::ParameterBlockRename(_) => {}
                ChannelIndependentItem::ParameterBlock(pb) => {
                    if let Some(found) = self.find_block_in_parameter_block(pb, block_name) {
                        return Some(found);
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
    fn find_block_in_channel<'a>(&self, channel: &'a Channel, block_name: &str) -> Option<&'a ParameterBlock> {
        for item in &channel.items {
            match item {
                ChannelItem::ParameterBlockRename(_) => {}
                ChannelItem::ParameterBlock(pb) => {
                    if let Some(found) = self.find_block_in_parameter_block(pb, block_name) {
                        return Some(found);
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
    fn find_block_in_choose<'a>(&self, choose: &'a Choose, block_name: &str) -> Option<&'a ParameterBlock> {
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
                if let Some(pb) = self.find_block_in_when_items(&when.items, block_name) {
                    return Some(pb);
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

    fn find_block_in_parameter_block<'a>(
        &self,
        block: &'a ParameterBlock,
        block_name: &str,
    ) -> Option<&'a ParameterBlock> {
        if block.name.as_deref() == Some(block_name) {
            return Some(block);
        }
        for item in &block.items {
            match item {
                ParameterBlockItem::ParameterBlock(nested) => {
                    if let Some(found) = self.find_block_in_parameter_block(nested, block_name) {
                        return Some(found);
                    }
                }
                ParameterBlockItem::Choose(choose) => {
                    if let Some(found) = self.find_block_in_choose(choose, block_name) {
                        return Some(found);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Helper to find a block in when items.
    fn find_block_in_when_items<'a>(&self, items: &'a [WhenItem], block_name: &str) -> Option<&'a ParameterBlock> {
        for item in items {
            match item {
                WhenItem::ParameterBlock(pb) => {
                    if let Some(found) = self.find_block_in_parameter_block(pb, block_name) {
                        return Some(found);
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
                ParameterBlockItem::ParameterBlock(block) => {
                    self.add_block_items(&block.items);
                }
                ParameterBlockItem::ParameterBlockRename(_) => {}
                ParameterBlockItem::ParameterRefRef(prr) => {
                    if self.device.is_param_ref_visible(&prr.ref_id)
                        && let Some(pref) = self.device.get_parameter_ref(&prr.ref_id)
                    {
                        // Skip if the ParameterRef itself has Access="None"
                        if pref.access.as_deref() == Some("None") {
                            continue;
                        }

                        let param_id = pref.ref_id.clone();

                        // Check if this is a picture type first — a picture
                        // renders even without a label text, but takes the
                        // usual label chain when one is present.
                        if let Some((ref_id, alignment)) = self.get_picture_ref_id(&param_id) {
                            let raw_text = prr
                                .text
                                .clone()
                                .or_else(|| pref.text.clone())
                                .or_else(|| self.device.get_parameter_info(&param_id).map(|p| p.text.clone()))
                                .unwrap_or_default();
                            let text = (!raw_text.is_empty()).then(|| self.device.interpolate_text(&raw_text));
                            self.content_items.push(ContentItem::Picture { ref_id, text, alignment });
                            continue;
                        }

                        // Skip hidden parameters (Access="None") or those with empty text
                        if let Some(info) = self.device.get_parameter_info(&param_id)
                            && (info.hidden || info.text.is_empty())
                        {
                            continue;
                        }

                        let raw_text = prr.text.clone().or_else(|| pref.text.clone()).unwrap_or_else(|| {
                            self.device
                                .get_parameter_info(&param_id)
                                .map(|p| p.text.clone())
                                .unwrap_or_else(|| param_id.clone())
                        });

                        // Skip if the final text is empty
                        if raw_text.is_empty() {
                            continue;
                        }

                        let text = self.device.interpolate_text(&raw_text);

                        let suffix = self.parameter_suffix(&param_id);

                        let widget = self.build_widget_for_param(&param_id, pref.access.as_deref());

                        self.content_items.push(ContentItem::Parameter { param_id, text, suffix, widget });
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
                        && let Some(pref) = self.device.get_parameter_ref(&prr.ref_id)
                    {
                        // Skip if the ParameterRef itself has Access="None"
                        if pref.access.as_deref() == Some("None") {
                            continue;
                        }

                        let param_id = pref.ref_id.clone();

                        // Check if this is a picture type first — a picture
                        // renders even without a label text, but takes the
                        // usual label chain when one is present.
                        if let Some((ref_id, alignment)) = self.get_picture_ref_id(&param_id) {
                            let raw_text = prr
                                .text
                                .clone()
                                .or_else(|| pref.text.clone())
                                .or_else(|| self.device.get_parameter_info(&param_id).map(|p| p.text.clone()))
                                .unwrap_or_default();
                            let text = (!raw_text.is_empty()).then(|| self.device.interpolate_text(&raw_text));
                            self.content_items.push(ContentItem::Picture { ref_id, text, alignment });
                            continue;
                        }

                        // Skip hidden parameters (Access="None") or those with empty text
                        if let Some(info) = self.device.get_parameter_info(&param_id)
                            && (info.hidden || info.text.is_empty())
                        {
                            continue;
                        }

                        let raw_text = prr.text.clone().or_else(|| pref.text.clone()).unwrap_or_else(|| {
                            self.device
                                .get_parameter_info(&param_id)
                                .map(|p| p.text.clone())
                                .unwrap_or_else(|| param_id.clone())
                        });

                        // Skip if the final text is empty
                        if raw_text.is_empty() {
                            continue;
                        }

                        let text = self.device.interpolate_text(&raw_text);

                        let suffix = self.parameter_suffix(&param_id);

                        let widget = self.build_widget_for_param(&param_id, pref.access.as_deref());

                        self.content_items.push(ContentItem::Parameter { param_id, text, suffix, widget });
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
                    self.add_block_items(&pb.items);
                }
                WhenItem::Choose(nested_choose) => {
                    self.add_choose_items(nested_choose);
                }
                // Channels inside whens exist only at Dynamic level;
                // page content is built per block, never through them.
                WhenItem::Channel(_) => {}
                WhenItem::ComObjectRefRef(_) | WhenItem::Assign(_) | WhenItem::Module(_) => {
                    // Skip comm objects, assignments, and modules in parameters view
                }
            }
        }
    }

    fn build_widget_for_param(&self, param_id: &str, ref_access: Option<&str>) -> WidgetType {
        let info = match self.device.get_parameter_info(param_id) {
            Some(i) => i,
            None => return WidgetType::ReadOnly { value: "?".to_string() },
        };

        // Effective access: the ParameterRef's override, else the base
        // Parameter's. "Read" placements display the current value but
        // are not editable (ETS greys them out).
        let read_only = match ref_access {
            Some(access) => access == "Read",
            None => info.read_only,
        };

        let ptype = self.device.get_parameter_type(&info.type_id);
        let default_value = if self.device.is_parameter_touched(param_id) {
            None
        } else {
            // Keep untouched widgets aligned with what product lowering
            // writes: the active ref's default wins over the base parameter.
            effective_default(&self.device, param_id)
        };

        let value = default_value.as_ref().or_else(|| self.device.get_parameter_value(param_id));

        match ptype.map(|pt| &pt.type_def) {
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
                    Some(ParameterValue::Float(v)) => format!("{:.2}", v),
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
            Some(ParameterTypeDef::TypeNone(_)) | Some(ParameterTypeDef::TypeIpAddress(_)) | None => {
                WidgetType::ReadOnly { value: "—".to_string() }
            }
            // TypePicture should be handled separately - shouldn't reach here
            Some(ParameterTypeDef::TypePicture(_)) => WidgetType::ReadOnly { value: "[picture]".to_string() },
        }
    }

    /// Prefer the product's authored suffix. Time parameters without one still
    /// need their integer basis visible so `60` cannot be mistaken for a
    /// formatted duration.
    fn parameter_suffix(&self, param_id: &str) -> Option<String> {
        let info = self.device.get_parameter_info(param_id)?;

        info.suffix.clone().or_else(|| self.parameter_type_suffix(&info.type_id))
    }

    fn parameter_type_suffix(&self, type_id: &str) -> Option<String> {
        let parameter_type = self.device.get_parameter_type(type_id)?;
        let ParameterTypeDef::TypeTime(time) = &parameter_type.type_def else { return None };

        Some(time.unit.value_unit().to_string())
    }

    /// Check if a parameter is a TypePicture and return its ref_id and
    /// horizontal alignment if so.
    fn get_picture_ref_id(&self, param_id: &str) -> Option<(String, Option<String>)> {
        let info = self.device.get_parameter_info(param_id)?;
        let ptype = self.device.get_parameter_type(&info.type_id)?;
        if let ParameterTypeDef::TypePicture(tp) = &ptype.type_def {
            Some((tp.ref_id.clone(), tp.horizontal_alignment.clone()))
        } else {
            None
        }
    }

    /// Check if a module parameter is a TypePicture and return its ref_id
    /// and horizontal alignment if so.
    fn get_module_picture_ref_id(&self, parameter: &Parameter) -> Option<(String, Option<String>)> {
        let ptype = self.device.get_parameter_type(&parameter.parameter_type)?;
        if let ParameterTypeDef::TypePicture(tp) = &ptype.type_def {
            Some((tp.ref_id.clone(), tp.horizontal_alignment.clone()))
        } else {
            None
        }
    }

    /// Rebuild the communication objects table.
    /// Mark the derived views (com-object table, memory segments) as
    /// stale after a device edit. The views are rebuilt lazily when
    /// their tab is next rendered; only the cheap status-bar counts are
    /// refreshed eagerly, since they show on every tab.
    fn mark_derived_views_dirty(&mut self) {
        self.visible_param_count = self.device.visible_param_refs().count();
        self.visible_obj_count = self.device.visible_com_object_refs().count();
        self.com_objects_dirty = true;
        self.memory_dirty = true;
    }

    /// Rebuild whatever stale view the current tab is about to render.
    /// Called at the top of every frame; selections are re-clamped
    /// because a rebuild can shrink the data they point into.
    pub fn ensure_tab_data(&mut self) {
        match self.current_tab {
            MainTab::Parameters => {
                self.ensure_content();
            }
            MainTab::CommObjects if self.com_objects_dirty => {
                self.rebuild_com_objects();
                self.selected_obj_idx = self.selected_obj_idx.min(self.com_object_rows.len().saturating_sub(1));
                self.adjust_comm_obj_scroll();
            }
            MainTab::Memory if self.memory_dirty => {
                self.rebuild_memory_segments();
                self.selected_segment_idx = self.selected_segment_idx.min(self.memory_segments.len().saturating_sub(1));
                let data_len = self.memory_segments.get(self.selected_segment_idx).map_or(0, |s| s.data.len());
                self.selected_byte_offset = self.selected_byte_offset.min(data_len.saturating_sub(1));
                self.adjust_memory_scroll();
            }
            _ => {}
        }
    }

    pub fn rebuild_com_objects(&mut self) {
        self.com_objects_dirty = false;
        self.com_object_rows.clear();
        self.visible_param_count = self.device.visible_param_refs().count();
        self.visible_obj_count = self.device.visible_com_object_refs().count();

        // Resolve all three flag layers in the same helper used by the
        // compiler. The provenance string keeps project overrides visible
        // instead of making the effective booleans look like product facts.
        let configuration = ProductConfiguration {
            parameters: Vec::new(),
            objects: self
                .object_flag_overrides
                .iter()
                .map(|(&com_object, &flags)| ObjectSetting { com_object, flags: product_flags(flags) })
                .collect(),
        };
        for object in effective_com_objects(&self.device, &configuration) {
            let sources = object.flag_sources;
            let row = ComObjectRow {
                number: object.number,
                name: self.device.interpolate_text(&object.text),
                function: self.device.interpolate_text(&object.function_text),
                group_address: self.format_group_address(object.number),
                size: object.object_size,
                dpt: object.datapoint_type.unwrap_or_default(),
                priority: format!("{:?}", object.priority),
                flag_c: object.communication,
                flag_r: object.read,
                flag_w: object.write,
                flag_t: object.transmit,
                flag_u: object.update,
                flag_i: object.read_on_init,
                provenance: [
                    sources.communication,
                    sources.read,
                    sources.write,
                    sources.transmit,
                    sources.update,
                    sources.read_on_init,
                    sources.priority,
                ]
                .map(source_letter)
                .into_iter()
                .collect(),
            };
            self.com_object_rows.push(row);
        }

        // Add comm objects from visible modules
        self.add_module_com_objects_to_list();

        // Sort by object number
        self.com_object_rows.sort_by_key(|r| r.number);
    }

    /// Add comm objects from visible modules to the com_object_rows list.
    fn add_module_com_objects_to_list(&mut self) {
        // Collect visible modules first to avoid borrow issues
        let visible_modules: Vec<_> = self.device.visible_modules().cloned().collect();

        for expanded in visible_modules {
            // Get the ModuleDef
            let module_def = match self.device.get_module_def(&expanded.module_def_id) {
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
                // Check if this comm object ref is visible (selected by dynamic section conditions)
                if !self.device.is_com_object_ref_visible(&oref.id) {
                    continue;
                }

                // Find the comm object
                let obj = match com_objects.iter().find(|o| o.id == oref.ref_id) {
                    Some(o) => o,
                    None => continue,
                };

                // Compute actual object number using BaseNumber argument if present
                let actual_number = compute_module_object_number(obj, &expanded, &module_def);

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
                        self.device.get_module_parameter_value_by_composite_id(&composite_id).and_then(|v| match v {
                            ParameterValue::Text(s) if !s.is_empty() => Some(s.clone()),
                            ParameterValue::Integer(i) => Some(i.to_string()),
                            _ => None,
                        })
                    })
                });

                let raw_name = oref.text.clone().unwrap_or_else(|| obj.text.clone());
                let name =
                    self.device.interpolate_module_text_with_param(&raw_name, &expanded, text_param_value.as_deref());
                let raw_function = oref.function_text.clone().unwrap_or_else(|| obj.function_text.clone());
                let function = self.device.interpolate_module_text(&raw_function, &expanded);

                // Get effective values (ref overrides base object)
                let size = oref.object_size.clone().unwrap_or_else(|| obj.object_size.clone());
                let dpt = oref.datapoint_type.clone().or_else(|| obj.datapoint_type.clone()).unwrap_or_default();
                let priority = oref.priority.unwrap_or(obj.priority.unwrap_or(ComObjectPriority::Low));
                let priority_str = match priority {
                    ComObjectPriority::Low => "Low",
                    ComObjectPriority::High => "High",
                    ComObjectPriority::Alert => "Alert",
                };

                // Flags (ref overrides base)
                let flag_c = oref.communication_flag.unwrap_or(obj.communication_flag) == EnableFlag::Enabled;
                let flag_r = oref.read_flag.unwrap_or(obj.read_flag) == EnableFlag::Enabled;
                let flag_w = oref.write_flag.unwrap_or(obj.write_flag) == EnableFlag::Enabled;
                let flag_t = oref.transmit_flag.unwrap_or(obj.transmit_flag) == EnableFlag::Enabled;
                let flag_u = oref.update_flag.unwrap_or(obj.update_flag) == EnableFlag::Enabled;

                // Get group address binding if any - use actual computed number
                let group_address = self.format_group_address(actual_number);

                self.com_object_rows.push(ComObjectRow {
                    number: actual_number,
                    name,
                    function,
                    group_address,
                    size,
                    dpt,
                    priority: priority_str.to_string(),
                    flag_c,
                    flag_r,
                    flag_w,
                    flag_t,
                    flag_u,
                    flag_i: oref.read_on_init_flag.unwrap_or(obj.read_on_init_flag) == EnableFlag::Enabled,
                    provenance: "RRRRRRR".to_string(),
                });
            }
        }
    }

    /// Format the group address(es) bound to a communication object for display.
    ///
    /// Returns the primary sending address, or multiple addresses separated by ", ".
    /// If no address is assigned, returns an empty string.
    fn format_group_address(&self, object_number: u16) -> String {
        let bindings = self.device.get_group_addresses(object_number);
        if bindings.is_empty() {
            return String::new();
        }

        // Format all bindings, sending address first
        let mut addresses: Vec<String> = bindings.iter().map(|b| b.group_address.to_string()).collect();

        if addresses.len() == 1 { addresses.pop().unwrap() } else { addresses.join(", ") }
    }

    /// Get the MaskVersion info for this device, if master data is available.
    pub fn get_mask_version(&self) -> Option<&MaskVersion> {
        self.master_data.as_ref().and_then(|md| md.get_mask_version(self.device.mask_version()))
    }

    /// Get a human-readable mask version display string.
    /// Returns something like "System B (MV-07B0)" or just "MV-07B0" if no master data.
    pub fn mask_version_display(&self) -> String {
        let mv_id = self.device.mask_version();
        if let Some(mv) = self.get_mask_version() { format!("{} ({})", mv.name, mv_id) } else { mv_id.to_string() }
    }

    /// Get the management model string (e.g., "SystemB", "BimM112").
    pub fn management_model(&self) -> Option<&str> {
        self.get_mask_version().map(|mv| mv.management_model.as_str())
    }

    /// Get the first application object index from mask version.
    pub fn first_app_object_idx(&self) -> u8 {
        self.get_mask_version().map(|mv| mv.first_app_object_idx()).unwrap_or(5)
        // Default BCU1-style
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

    /// Rebuild memory segments from the Code section in the ApplicationProgram.
    pub fn rebuild_memory_segments(&mut self) {
        self.memory_dirty = false;
        self.memory_segments.clear();
        let preview = match self.configuration_preview() {
            Ok(preview) => preview,
            Err(error) => {
                self.status_message = Some(format!("Cannot build configuration preview: {error}"));
                return;
            }
        };
        let param_mappings = self.collect_parameter_memory_mappings();
        for segment in preview.segments {
            let (segment_type, address, load_state_machine) = match segment.placement {
                PreviewPlacement::Absolute { address } => (SegmentType::Absolute, u32::from(address), None),
                PreviewPlacement::Relative { object_index } => (SegmentType::Relative, 0, Some(object_index)),
                PreviewPlacement::InterfaceProperty { .. } => continue,
            };
            let annotations = self.build_annotations_for_segment(&segment.id, &param_mappings);
            self.memory_segments.push(MemorySegment {
                id: segment.id,
                segment_type,
                address,
                size: segment.size,
                memory_type: segment.memory_type,
                load_state_machine,
                data: segment.bytes,
                annotations,
                annotation_index: Vec::new(),
            });
        }

        for table in preview.tables.into_iter().filter(|table| !table.redacted) {
            let target = self.memory_segments.iter_mut().find(|segment| match table.placement {
                PreviewPlacement::Absolute { address } => {
                    let start = segment.address;
                    let end = start + segment.data.len() as u32;
                    segment.segment_type == SegmentType::Absolute
                        && u32::from(address) >= start
                        && u32::from(address) < end
                }
                PreviewPlacement::Relative { object_index } => segment.load_state_machine == Some(object_index),
                PreviewPlacement::InterfaceProperty { .. } => false,
            });
            let Some(segment) = target else { continue };
            let offset = match table.placement {
                PreviewPlacement::Absolute { address } => u32::from(address).saturating_sub(segment.address),
                _ => table.offset,
            };
            segment.annotations.push(MemoryAnnotation {
                offset,
                bit_offset: 0,
                name: format!("{:?} table", table.kind),
                size_bits: u16::try_from(table.len.saturating_mul(8)).unwrap_or(u16::MAX),
                param_id: String::new(),
            });
        }

        // Sort by address
        self.memory_segments.sort_by_key(|s| s.address);

        // Build the per-byte annotation lookup last: the synthetic table
        // generators above may still extend a code segment's annotation
        // list after the segment was pushed. First annotation in list
        // order wins, matching the scan this index replaces (bit fields
        // sharing a byte resolve to the lowest (offset, bit_offset)).
        for seg in &mut self.memory_segments {
            seg.annotation_index = vec![u32::MAX; seg.data.len()];
            for (ann_idx, ann) in seg.annotations.iter().enumerate() {
                let start = ann.offset as usize;
                let end = (start + (ann.size_bits as usize).div_ceil(8)).min(seg.data.len());
                for slot in seg.annotation_index.get_mut(start..end).unwrap_or_default() {
                    if *slot == u32::MAX {
                        *slot = ann_idx as u32;
                    }
                }
            }
        }
    }

    fn configuration_preview(&self) -> Result<zweidraehte_client::download::ConfigurationPreview, String> {
        let mut settings = configuration_from_device(&self.device);
        settings.objects = self
            .object_flag_overrides
            .iter()
            .map(|(&com_object, &flags)| ObjectSetting { com_object, flags: product_flags(flags) })
            .collect();

        let authored_device = self
            .project_context
            .as_ref()
            .and_then(|context| context.authored.as_ref().and_then(|project| project.devices.get(&context.device)));
        let identity = DeviceIdentity {
            desired_address: authored_device
                .map_or_else(|| zweidraehte_proto::address::IndividualAddress::new(1, 1, 1), |device| device.address),
            serial_number: authored_device.and_then(|device| device.serial),
        };
        let object_memberships = self
            .device
            .all_bindings()
            .flat_map(|(com_object, bindings)| {
                bindings.iter().map(move |binding| ClientObjectMembership {
                    group_address: zweidraehte_proto::address::GroupAddress(
                        binding.group_address.to_u16().to_be_bytes(),
                    ),
                    com_object,
                    role: if binding.is_sending {
                        ClientMembershipRole::Primary
                    } else {
                        ClientMembershipRole::Additional
                    },
                })
            })
            .collect();
        let base = DeviceConfiguration {
            identity,
            // Project keys are intentionally absent from UI memory. The
            // preview redacts Security IO key spans when a caller supplies
            // them; this product view compiles the ordinary application image.
            data_secure_enabled: false,
            parameters: Vec::new(),
            object_memberships,
            objects: Vec::new(),
            net_security: BTreeMap::new(),
            max_apdu: authored_device.and_then(|device| device.max_apdu),
        };
        let product = ProductData::from_program(self.device.program()).map_err(|error| error.to_string())?;
        let resolved = resolve_product_configuration(&self.device, &settings, base, &product)
            .map_err(|error| error.to_string())?;
        let builder = ConfigurationPreviewBuilder::new(&product, &resolved.configuration);
        if let (Some(master), Some(mask_version)) = (self.master_data.as_ref(), product.mask_version()) {
            let mask = MaskData::from_master_data(master, mask_version)
                .ok_or_else(|| format!("master data does not describe {mask_version:?}"))?;
            builder.with_mask(mask).build().map_err(|error| error.to_string())
        } else {
            builder.build().map_err(|error| error.to_string())
        }
    }

    /// Collect parameter memory mappings: (segment_id, offset, bit_offset, name, size_bits, param_id)
    fn collect_parameter_memory_mappings(&self) -> Vec<(String, u32, u8, String, u16, String)> {
        let mut mappings = Vec::new();

        // Get parameters from main static section
        if let Some(params) = &self.device.static_section().parameters {
            self.collect_params_from_items(&params.items, &mut mappings, None);
        }

        // Collect parameters from expanded module instances
        for expanded in self.device.all_expanded_modules() {
            if let Some(module_def) = self.device.get_module_def(&expanded.module_def_id) {
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
        expanded: &zweidraehte_ets_files::runtime::model::ExpandedModule,
        module_def: &ModuleDef,
    ) -> Option<u32> {
        // Find the parameter base offset argument definition
        // Common names: ParamBase, ParamOffsBase, ParameterBase, etc.
        let arg_def = module_def.arguments.as_ref()?.arguments.iter().find(|a| {
            let name_lower = a.name.to_lowercase();
            // Match various naming conventions for parameter base offset
            name_lower.contains("param") && (name_lower.contains("base") || name_lower.contains("offs"))
        })?;

        // Get the resolved value from the expanded module
        if let Some(zweidraehte_ets_files::runtime::model::ModuleArgValue::Numeric(val)) =
            expanded.args.get(&arg_def.name)
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
        expanded: &zweidraehte_ets_files::runtime::model::ExpandedModule,
        module_def: &ModuleDef,
    ) -> String {
        // Try to find a channel/instance number argument (commonly named ChNo, Channel, ChannelNo, etc.)
        let channel_arg = module_def.arguments.as_ref().and_then(|args| {
            args.arguments.iter().find(|a| {
                let name_lower = a.name.to_lowercase();
                name_lower.contains("ch") || name_lower.contains("channel") || name_lower.contains("instance")
            })
        });

        if let Some(arg_def) = channel_arg
            && let Some(zweidraehte_ets_files::runtime::model::ModuleArgValue::Numeric(val)) =
                expanded.args.get(&arg_def.name)
        {
            // Use module name with channel number, e.g., "Ch1" or "DimmerChannel 1"
            return format!("Ch{}", val);
        }

        // Fallback: use interpolated module name if available
        if let Some(name) = &expanded.name {
            // The name might contain templates like "{{ChNo}}" - try to interpolate
            let interpolated = self.device.interpolate_module_text(name, expanded);
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
        items: &[ParameterItem],
        mappings: &mut Vec<(String, u32, u8, String, u16, String)>,
        base_offset_info: Option<(u32, &str, &str)>,
    ) {
        for item in items {
            if let ParameterItem::Parameter(param) = item {
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
            } else if let ParameterItem::Union(union) = item {
                let Some(memory) = &union.memory else {
                    continue;
                };

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
        if let Some(pt) = self.device.get_parameter_type(type_id) {
            match &pt.type_def {
                ParameterTypeDef::TypeNumber(tn) => tn.size_in_bit as u16,
                ParameterTypeDef::TypeRestriction(tr) => tr.size_in_bit as u16,
                ParameterTypeDef::TypeText(tt) => (tt.size_in_bit) as u16,
                ParameterTypeDef::TypeColor(color) => color.space.size_bits(),
                ParameterTypeDef::TypeTime(time) => u16::from(time.size_in_bit),
                ParameterTypeDef::TypeFloat(_) => 16, // DPT9 is typically 16 bits
                ParameterTypeDef::TypeNone(_) => 8,
                ParameterTypeDef::TypePicture(_) => 0, // Picture types don't occupy memory
                ParameterTypeDef::TypeIpAddress(_) => 32, // IPv4 address is 4 bytes
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
        let ann_idx = *segment.annotation_index.get(byte_offset)?;
        segment.annotations.get(ann_idx as usize)
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
        if let Some(seg) = self.memory_segments.get(self.selected_segment_idx)
            && self.selected_byte_offset + 1 < seg.data.len()
        {
            self.selected_byte_offset += 1;
            self.adjust_memory_scroll_with_visible(visible_lines);
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

    /// Maximum visible rows in comm objects table
    const COMM_OBJ_VISIBLE_ROWS: usize = 20;

    /// Adjust comm object scroll to keep selected item visible.
    fn adjust_comm_obj_scroll(&mut self) {
        // Scroll up if above visible area
        if self.selected_obj_idx < self.comm_obj_scroll_offset {
            self.comm_obj_scroll_offset = self.selected_obj_idx;
        }

        // Scroll down if below visible area
        if self.selected_obj_idx >= self.comm_obj_scroll_offset + Self::COMM_OBJ_VISIBLE_ROWS {
            self.comm_obj_scroll_offset = self.selected_obj_idx.saturating_sub(Self::COMM_OBJ_VISIBLE_ROWS - 1);
        }
    }

    /// Adjust content scroll to keep selected item visible.
    fn adjust_content_scroll(&mut self) {
        // Scroll up if above visible area
        if self.selected_content_idx < self.content_scroll_offset {
            self.content_scroll_offset = self.selected_content_idx;
        }

        // Scroll down if below visible area
        if self.selected_content_idx >= self.content_scroll_offset + Self::CONTENT_VISIBLE_ROWS {
            self.content_scroll_offset = self.selected_content_idx.saturating_sub(Self::CONTENT_VISIBLE_ROWS - 1);
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

        // Entering the content pane must see the page the sidebar
        // selection points at, even mid-batch before the next frame's
        // `ensure_tab_data` runs — the very next key may navigate or
        // edit `content_items`.
        if self.current_tab == MainTab::Parameters && self.focus == Focus::Sidebar {
            self.ensure_content();
        }

        self.focus = match (self.current_tab, self.focus) {
            (_, Focus::Project) => Focus::Tabs,
            (MainTab::Parameters, Focus::Tabs) => Focus::Sidebar,
            (MainTab::Parameters, Focus::Sidebar) => Focus::Content,
            (MainTab::Parameters, Focus::Content) => {
                if self.project_navigation.is_some() {
                    Focus::Project
                } else {
                    Focus::Tabs
                }
            }
            (MainTab::CommObjects, Focus::Tabs) => Focus::Content,
            (MainTab::CommObjects, Focus::Content) => {
                if self.project_navigation.is_some() {
                    Focus::Project
                } else {
                    Focus::Tabs
                }
            }
            (MainTab::CommObjects, Focus::Sidebar) => Focus::Content, // Shouldn't happen
            // Memory tab: Tabs -> Sidebar (segment list) -> Content (hex view) -> Tabs
            (MainTab::Memory, Focus::Tabs) => Focus::Sidebar,
            (MainTab::Memory, Focus::Sidebar) => Focus::Content,
            (MainTab::Memory, Focus::Content) => {
                if self.project_navigation.is_some() {
                    Focus::Project
                } else {
                    Focus::Tabs
                }
            }
        };
    }

    /// Move selection up.
    pub fn move_up(&mut self) {
        match &mut self.edit_mode {
            EditMode::EnumDropdown { selected_idx, scroll_offset, .. }
            | EditMode::LanguageSelect { selected_idx, scroll_offset, .. }
                if *selected_idx > 0 =>
            {
                *selected_idx -= 1;
                // Adjust scroll if selection went above visible area
                if *selected_idx < *scroll_offset {
                    *scroll_offset = *selected_idx;
                }
            }
            EditMode::None => match (self.current_tab, self.focus) {
                (_, Focus::Project) => {
                    if let Some(navigation) = &mut self.project_navigation {
                        navigation.move_up();
                    }
                }
                (_, Focus::Tabs) => {
                    // No vertical movement in tabs
                }
                (MainTab::Parameters, Focus::Sidebar) => {
                    // Hop over group headers — they are not pages.
                    if let Some(index) = self.tree_nodes[..self.selected_tree_idx].iter().rposition(|n| !n.is_group()) {
                        self.selected_tree_idx = index;
                        self.content_dirty = true;
                        self.selected_content_idx = 0;
                        self.content_scroll_offset = 0;
                    }
                }
                (MainTab::Parameters, Focus::Content) if self.selected_content_idx > 0 => {
                    self.selected_content_idx -= 1;
                    self.adjust_content_scroll();
                }
                (MainTab::CommObjects, Focus::Content) if self.selected_obj_idx > 0 => {
                    self.selected_obj_idx -= 1;
                    self.adjust_comm_obj_scroll();
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

    /// Maximum visible rows in content area
    const CONTENT_VISIBLE_ROWS: usize = 20;

    /// Move selection down.
    pub fn move_down(&mut self) {
        match &mut self.edit_mode {
            EditMode::EnumDropdown { selected_idx, options, scroll_offset, .. }
                if *selected_idx < options.len().saturating_sub(1) =>
            {
                *selected_idx += 1;
                // Adjust scroll if selection went below visible area
                let visible_items = Self::DROPDOWN_VISIBLE_ITEMS;
                if *selected_idx >= *scroll_offset + visible_items {
                    *scroll_offset = selected_idx.saturating_sub(visible_items - 1);
                }
            }
            EditMode::LanguageSelect { selected_idx, options, scroll_offset }
                if *selected_idx < options.len().saturating_sub(1) =>
            {
                *selected_idx += 1;
                let visible_items = Self::DROPDOWN_VISIBLE_ITEMS;
                if *selected_idx >= *scroll_offset + visible_items {
                    *scroll_offset = selected_idx.saturating_sub(visible_items - 1);
                }
            }
            EditMode::None => match (self.current_tab, self.focus) {
                (_, Focus::Project) => {
                    if let Some(navigation) = &mut self.project_navigation {
                        navigation.move_down();
                    }
                }
                (_, Focus::Tabs) => {
                    // No vertical movement in tabs
                }
                (MainTab::Parameters, Focus::Sidebar) => {
                    // Hop over group headers — they are not pages.
                    if let Some(offset) =
                        self.tree_nodes.iter().skip(self.selected_tree_idx + 1).position(|n| !n.is_group())
                    {
                        self.selected_tree_idx += 1 + offset;
                        self.content_dirty = true;
                        self.selected_content_idx = 0;
                        self.content_scroll_offset = 0;
                    }
                }
                (MainTab::Parameters, Focus::Content)
                    if self.selected_content_idx < self.content_items.len().saturating_sub(1) =>
                {
                    self.selected_content_idx += 1;
                    self.adjust_content_scroll();
                }
                (MainTab::CommObjects, Focus::Content)
                    if self.selected_obj_idx < self.com_object_rows.len().saturating_sub(1) =>
                {
                    self.selected_obj_idx += 1;
                    self.adjust_comm_obj_scroll();
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

    /// Page size for page up/down navigation
    const PAGE_SIZE: usize = 10;

    /// Move selection up by a page.
    pub fn page_up(&mut self) {
        match (self.current_tab, self.focus) {
            (_, Focus::Project) => {
                for _ in 0..Self::PAGE_SIZE {
                    if let Some(navigation) = &mut self.project_navigation {
                        navigation.move_up();
                    }
                }
            }
            (_, Focus::Tabs) => {
                // No vertical movement in tabs
            }
            (MainTab::Parameters, Focus::Sidebar) if self.selected_tree_idx > 0 => {
                self.selected_tree_idx = self.selected_tree_idx.saturating_sub(Self::PAGE_SIZE);
                self.content_dirty = true;
                self.selected_content_idx = 0;
                self.content_scroll_offset = 0;
            }
            (MainTab::Parameters, Focus::Content) if self.selected_content_idx > 0 => {
                self.selected_content_idx = self.selected_content_idx.saturating_sub(Self::PAGE_SIZE);
                self.adjust_content_scroll();
            }
            (MainTab::CommObjects, Focus::Content) if self.selected_obj_idx > 0 => {
                self.selected_obj_idx = self.selected_obj_idx.saturating_sub(Self::PAGE_SIZE);
                self.adjust_comm_obj_scroll();
            }
            (MainTab::Memory, Focus::Sidebar) => {
                for _ in 0..Self::PAGE_SIZE {
                    self.segment_move_up();
                }
            }
            (MainTab::Memory, Focus::Content) => {
                for _ in 0..Self::PAGE_SIZE {
                    self.memory_move_up();
                }
            }
            _ => {}
        }
    }

    /// Move selection down by a page.
    pub fn page_down(&mut self) {
        match (self.current_tab, self.focus) {
            (_, Focus::Project) => {
                for _ in 0..Self::PAGE_SIZE {
                    if let Some(navigation) = &mut self.project_navigation {
                        navigation.move_down();
                    }
                }
            }
            (_, Focus::Tabs) => {
                // No vertical movement in tabs
            }
            (MainTab::Parameters, Focus::Sidebar) => {
                let max_idx = self.tree_nodes.len().saturating_sub(1);
                if self.selected_tree_idx < max_idx {
                    self.selected_tree_idx = (self.selected_tree_idx + Self::PAGE_SIZE).min(max_idx);
                    self.content_dirty = true;
                    self.selected_content_idx = 0;
                    self.content_scroll_offset = 0;
                }
            }
            (MainTab::Parameters, Focus::Content) => {
                let max_idx = self.content_items.len().saturating_sub(1);
                if self.selected_content_idx < max_idx {
                    self.selected_content_idx = (self.selected_content_idx + Self::PAGE_SIZE).min(max_idx);
                    self.adjust_content_scroll();
                }
            }
            (MainTab::CommObjects, Focus::Content) => {
                let max_idx = self.com_object_rows.len().saturating_sub(1);
                if self.selected_obj_idx < max_idx {
                    self.selected_obj_idx = (self.selected_obj_idx + Self::PAGE_SIZE).min(max_idx);
                    self.adjust_comm_obj_scroll();
                }
            }
            (MainTab::Memory, Focus::Sidebar) => {
                for _ in 0..Self::PAGE_SIZE {
                    self.segment_move_down();
                }
            }
            (MainTab::Memory, Focus::Content) => {
                for _ in 0..Self::PAGE_SIZE {
                    self.memory_move_down(20);
                }
            }
            _ => {}
        }
    }

    /// Move selection left (for tabs).
    pub fn move_left(&mut self) {
        if !matches!(self.edit_mode, EditMode::None) {
            return;
        }
        match (self.current_tab, self.focus) {
            (_, Focus::Project) => {}
            (_, Focus::Tabs) => self.prev_tab(),
            (MainTab::Parameters, Focus::Sidebar) => {
                // Collapse the selected tree node
                let node = self
                    .tree_nodes
                    .get(self.selected_tree_idx)
                    .filter(|node| node.has_children)
                    .map(|node| node.id.clone());
                if let Some(node) = node
                    && self.expanded_nodes.contains(&node)
                {
                    self.expanded_nodes.remove(&node);
                    self.rebuild_tree();
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
            (_, Focus::Project) => {}
            (_, Focus::Tabs) => self.next_tab(),
            (MainTab::Parameters, Focus::Sidebar) => {
                // Expand the selected tree node
                let node = self
                    .tree_nodes
                    .get(self.selected_tree_idx)
                    .filter(|node| node.has_children)
                    .map(|node| node.id.clone());
                if let Some(node) = node
                    && !self.expanded_nodes.contains(&node)
                {
                    self.expanded_nodes.insert(node);
                    self.rebuild_tree();
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
            EditMode::LanguageSelect { options, selected_idx, .. } => {
                let next = options[*selected_idx].0.clone();
                self.edit_mode = EditMode::None;
                self.switch_language(next);
            }
            EditMode::EnumDropdown { param_id, options, selected_idx, .. } => {
                // Commit the selection
                let param_id = param_id.clone();
                let new_value = options[*selected_idx].0;
                self.set_any_parameter_value(&param_id, ParameterValue::Integer(new_value));
                self.edit_mode = EditMode::None;
                // Visibility may have changed: rebuild what this tab
                // shows now, defer the other tabs' views.
                self.rebuild_tree();
                self.rebuild_content();
                self.mark_derived_views_dirty();
            }
            EditMode::NumberInput { param_id, buffer, min, max, .. } => {
                // Commit the number, clamped to the type's bounds the way
                // ETS does it (entering 0 on a 1..5 field commits 1,
                // entering 6 commits 5). An unparseable buffer keeps the
                // old value.
                let param_id = param_id.clone();
                let (min, max) = (*min, *max);
                if let Ok(mut v) = buffer.parse::<i64>() {
                    if let Some(min) = min {
                        v = v.max(min);
                    }
                    if let Some(max) = max {
                        v = v.min(max);
                    }
                    self.set_any_parameter_value(&param_id, ParameterValue::Integer(v));
                }
                self.edit_mode = EditMode::None;
                self.rebuild_tree();
                self.rebuild_content();
                self.mark_derived_views_dirty();
            }
            EditMode::TextInput { param_id, buffer, .. } => {
                // Commit the text
                let param_id = param_id.clone();
                let text = buffer.clone();
                self.set_any_parameter_value(&param_id, ParameterValue::Text(text));
                self.edit_mode = EditMode::None;
                self.rebuild_tree();
                self.rebuild_content();
                self.mark_derived_views_dirty();
            }
            EditMode::NetNameInput { net, buffer, .. } => {
                let net = net.clone();
                let name = buffer.clone();
                let result = self.rename_net_label(&net, &name);
                if let Err(error) = result {
                    self.status_message = Some(format!("Cannot rename group address: {error}"));
                } else {
                    self.edit_mode = EditMode::None;
                    self.status_message = Some(format!("Renamed {net}; press e to save"));
                }
            }
            EditMode::GroupAddressInput { object_number, buffer } => {
                // Parse and assign the group addresses: several may be
                // given, separated by commas or spaces; the first one
                // becomes the sending address, the rest listen.
                let object_number = *object_number;
                let buffer = buffer.clone();

                // Clear existing addresses for this object first
                self.device.clear_group_addresses(object_number);

                for part in buffer.split([',', ' ']).filter(|p| !p.is_empty()) {
                    if let Some(addr) = zweidraehte_ets_files::runtime::model::GroupAddress::parse(part) {
                        self.device.assign_group_address(object_number, addr);
                    } else {
                        self.status_message = Some(format!("'{part}' is not a group address (main/middle/sub)"));
                    }
                }

                self.edit_mode = EditMode::None;
                // Group links only touch the com-object table's address
                // column and the synthetic ADT/AST segments; both are
                // rebuilt by `ensure_tab_data` before the next frame of
                // whichever tab shows them.
                self.mark_derived_views_dirty();
                if let Err(error) = self.refresh_project_navigation() {
                    self.status_message = Some(format!("Cannot refresh project navigation: {error}"));
                }
            }
            EditMode::ObjectFlagsInput { object_number, buffer } => {
                let object_number = *object_number;
                match parse_object_flags(buffer) {
                    Ok(flags) => {
                        if flags == ObjectFlagOverrides::default() {
                            self.object_flag_overrides.remove(&object_number);
                        } else {
                            self.object_flag_overrides.insert(object_number, flags);
                        }
                        self.edit_mode = EditMode::None;
                        self.mark_derived_views_dirty();
                    }
                    Err(error) => self.status_message = Some(error),
                }
            }
            EditMode::None => match (self.current_tab, self.focus) {
                (_, Focus::Project) => {
                    let selected =
                        self.project_navigation.as_ref().and_then(ProjectNavigation::selected_target).cloned();
                    match selected {
                        Some(ProjectNavigationTarget::Device(device)) => {
                            let current = self.project_context.as_ref().map(|context| &context.device);
                            if current != Some(&device) {
                                self.pending_project_device = Some(device);
                            }
                        }
                        Some(ProjectNavigationTarget::Net(net)) => {
                            if let Some(project) =
                                self.project_context.as_ref().and_then(|context| context.authored.as_ref())
                                && let Some(entry) = project.nets.get(&net)
                            {
                                self.status_message = Some(format!(
                                    "Net {}{}: {}, DPT {}, {:?}",
                                    entry.id,
                                    entry.name.as_ref().map_or_else(String::new, |name| format!(" ({name})")),
                                    entry.address,
                                    entry.dpt,
                                    entry.security
                                ));
                            }
                        }
                        None => {}
                    }
                }
                (_, Focus::Tabs) => {
                    // Enter into the content area
                    self.toggle_focus();
                }
                (MainTab::Parameters, Focus::Sidebar) => {
                    // Toggle expand/collapse
                    if let Some(node) = self.tree_nodes.get(self.selected_tree_idx)
                        && node.has_children
                    {
                        let id = node.id.clone();
                        if self.expanded_nodes.contains(&id) {
                            self.expanded_nodes.remove(&id);
                        } else {
                            self.expanded_nodes.insert(id);
                        }
                        self.rebuild_tree();
                    }
                }
                (MainTab::Parameters, Focus::Content) => {
                    // Enter edit mode for the selected parameter
                    self.enter_edit_mode();
                }
                (MainTab::CommObjects, Focus::Content) => {
                    // Enter group address edit mode for the selected comm object
                    self.enter_group_address_edit_mode();
                }
                _ => {}
            },
        }
    }

    /// Cancel editing.
    pub fn cancel_edit(&mut self) {
        self.edit_mode = EditMode::None;
    }

    /// Start editing the selected group address's display name.
    pub fn enter_selected_net_name_edit_mode(&mut self) {
        if self.focus != Focus::Project || !matches!(self.edit_mode, EditMode::None) {
            return;
        }
        if let Err(error) = self.stage_current_project_device() {
            self.status_message = Some(format!("Cannot stage project edits: {error}"));
            return;
        }
        let Some(ProjectNavigationTarget::Net(net)) =
            self.project_navigation.as_ref().and_then(ProjectNavigation::selected_target).cloned()
        else {
            self.status_message = Some("Select a group address before renaming it".into());
            return;
        };
        let name = self
            .project_context
            .as_ref()
            .and_then(|context| context.authored.as_ref())
            .and_then(|project| project.nets.get(&net))
            .and_then(|entry| entry.name.clone())
            .unwrap_or_else(|| net.0.clone());
        let cursor = name.len();
        self.edit_mode = EditMode::NetNameInput { net, buffer: name, cursor };
    }

    fn rename_net_label(&mut self, net: &NetId, name: &str) -> Result<(), String> {
        let context = self.project_context.as_mut().ok_or_else(|| "no project context is configured".to_string())?;
        let project =
            context.authored.as_ref().ok_or_else(|| "save the product draft before renaming nets".to_string())?;
        let source = project.render_net_name_update(net, name).map_err(|error| error.to_string())?;
        let authored = AuthoredProject::parse(source).map_err(|error| error.to_string())?;
        context.authored = Some(authored);
        self.project_navigation =
            context.authored.as_ref().map(|project| ProjectNavigation::from_project(project, context.device.clone()));
        if let Some(navigation) = &mut self.project_navigation {
            navigation.select(&ProjectNavigationTarget::Net(net.clone()));
        }
        Ok(())
    }

    /// Provide the language-switching context (see
    /// [`LanguageContext`]); `initial` names the language the program
    /// was already rewritten into before construction.
    pub fn set_language_context(&mut self, context: LanguageContext, initial: Option<String>) {
        self.language_context = Some(context);
        self.current_language = initial;
    }

    /// Open the language-selection popup: the program's default
    /// language first, then every translation the document carries,
    /// with the active one preselected.
    pub fn open_language_select(&mut self) {
        let Some(context) = &self.language_context else {
            self.status_message = Some("This product carries no translations".to_string());
            return;
        };
        let mut options: Vec<(Option<String>, String)> =
            vec![(None, format!("default ({})", self.device.program().default_language))];
        options.extend(
            context.translations.languages().iter().map(|language| (Some(language.to_string()), language.to_string())),
        );
        if options.len() == 1 {
            self.status_message = Some("This product carries no translations".to_string());
            return;
        }

        let selected_idx = self
            .current_language
            .as_ref()
            .and_then(|current| options.iter().position(|(value, _)| value.as_ref() == Some(current)))
            .unwrap_or(0);
        let visible = Self::DROPDOWN_VISIBLE_ITEMS;
        let scroll_offset =
            if options.len() <= visible || selected_idx < visible { 0 } else { selected_idx + 1 - visible };
        self.edit_mode = EditMode::LanguageSelect { options, selected_idx, scroll_offset };
    }

    /// Switch the display language.
    ///
    /// A switch rebuilds the device from the pristine program with the
    /// new language applied, then restores the format-neutral product
    /// configuration. Group bindings and project flag overrides are copied
    /// separately because neither belongs to the product value model.
    pub fn switch_language(&mut self, next: Option<String>) {
        let Some(context) = &self.language_context else {
            return;
        };
        if next == self.current_language {
            return;
        }

        // Snapshot the session's edits, rebuild in the new language,
        // and replay them.
        let mut edits = configuration_from_device(&self.device);
        edits.objects = self
            .object_flag_overrides
            .iter()
            .map(|(&com_object, &flags)| ObjectSetting { com_object, flags: product_flags(flags) })
            .collect();
        let bindings: Vec<_> = self
            .device
            .all_bindings()
            .map(|(object, bindings)| {
                (object, bindings.iter().map(|binding| binding.group_address).collect::<Vec<_>>())
            })
            .collect();
        let mut program = context.pristine.clone();
        if let Some(language) = &next {
            context.translations.apply(&mut program, language);
        }
        let mut device = Device::new(program, context.baggage.clone());
        if let Err(e) = apply_configuration(&mut device, &edits) {
            // Values that applied to the old device apply to the new
            // one — same program, different texts. Failing here would
            // be a bug worth seeing, not hiding.
            self.status_message = Some(format!("Language switch failed replaying edits: {e}"));
            return;
        }
        for (object, addresses) in bindings {
            for address in addresses {
                device.assign_group_address(object, address);
            }
        }
        self.device = device;
        self.current_language = next;

        self.rebuild_tree();
        self.rebuild_content();
        self.rebuild_com_objects();
        self.rebuild_memory_segments();
        self.selected_tree_idx = self.selected_tree_idx.min(self.tree_nodes.len().saturating_sub(1));
        self.selected_content_idx = self.selected_content_idx.min(self.content_items.len().saturating_sub(1));
        self.selected_obj_idx = self.selected_obj_idx.min(self.com_object_rows.len().saturating_sub(1));

        // Keep the authored in-memory project in lockstep with the editor.
        // The normal save command remains the point that writes project.knx.
        if let Err(error) = self.refresh_project_navigation() {
            self.status_message = Some(format!("Cannot update language preference: {error}"));
            return;
        }

        self.status_message = Some(match &self.current_language {
            Some(language) => format!("Language: {language}"),
            None => format!("Language: default ({})", self.device.program().default_language),
        });
    }

    pub fn set_project_context(&mut self, context: ProjectContext, flags: BTreeMap<u16, ObjectFlagOverrides>) {
        let load_pane_layout = self.project_context.is_none() && context.authored.is_some();
        self.data_secure = context
            .authored
            .as_ref()
            .and_then(|project| project.devices.get(&context.device))
            .map_or(DataSecureMode::Disabled, |device| device.data_secure);
        let had_navigation = self.project_navigation.is_some();
        self.project_navigation =
            context.authored.as_ref().map(|project| ProjectNavigation::from_project(project, context.device.clone()));
        if !had_navigation && self.project_navigation.is_some() {
            self.focus = Focus::Project;
        }
        self.project_context = Some(context);
        if load_pane_layout {
            let project_path = &self.project_context.as_ref().expect("project context was just set").path;
            match PaneLayout::load(project_path) {
                Ok(Some(layout)) => self.pane_layout = layout,
                Ok(None) => {}
                Err(error) => self.status_message = Some(format!("Cannot load pane layout: {error}")),
            }
            self.pane_layout_dirty = false;
        }
        self.object_flag_overrides = flags;
        self.net_policy_overrides.clear();
        self.project_overview = None;
        self.key_editor = None;
        self.mark_derived_views_dirty();
    }

    /// Stage edits to the selected device in the lossless in-memory project
    /// source before another product is opened. No file is written: `e`
    /// remains the explicit persistence action, while navigation cannot lose
    /// edits made to a previously visited device.
    pub fn stage_current_project_device(&mut self) -> Result<ProjectContext, String> {
        let mut context = self.project_context.clone().ok_or_else(|| "no project context is configured".to_string())?;
        let Some(project) = &context.authored else {
            return Ok(context);
        };
        let draft = self.project_draft(&context)?;
        let source = project.render_device_update(&draft).map_err(|error| error.to_string())?;
        let authored = AuthoredProject::parse(source).map_err(|error| error.to_string())?;
        self.project_navigation = Some(ProjectNavigation::from_project(&authored, context.device.clone()));
        context.authored = Some(authored);
        self.net_policy_overrides.clear();
        self.project_context = Some(context.clone());
        Ok(context)
    }

    fn refresh_project_navigation(&mut self) -> Result<(), String> {
        if self.project_navigation.is_none() {
            return Ok(());
        }
        self.stage_current_project_device().map(|_| ())
    }

    pub fn take_pending_project_device(&mut self) -> Option<ProjectDeviceId> {
        self.pending_project_device.take()
    }

    /// Replace only the product-editor portion of the application. Project
    /// commands, bus settings, and the surrounding TUI remain intact.
    pub fn open_project_device(&mut self, loaded: LoadedProjectDevice) {
        self.device = loaded.device;
        self.language_context = loaded.language_context;
        self.current_language = loaded.current_language;
        self.expanded_nodes.clear();
        self.selected_tree_idx = 0;
        self.selected_content_idx = 0;
        self.content_scroll_offset = 0;
        self.selected_obj_idx = 0;
        self.comm_obj_scroll_offset = 0;
        self.selected_segment_idx = 0;
        self.memory_scroll_offset = 0;
        self.selected_byte_offset = 0;
        #[cfg(feature = "images")]
        self.image_cache.clear();
        let id = loaded.context.device.clone();
        self.set_project_context(loaded.context, loaded.flags);
        self.rebuild_tree();
        self.rebuild_content();
        self.rebuild_com_objects();
        self.rebuild_memory_segments();
        self.status_message = Some(format!("Opened project device {id}"));
    }

    pub fn toggle_project_overview(&mut self) {
        if self.project_overview.take().is_some() {
            return;
        }
        let Some(context) = &self.project_context else { return };
        match zweidraehte_project::ProjectStore::open(&context.path)
            .map_err(|error| error.to_string())
            .and_then(|store| ProjectOverview::load(&store))
        {
            Ok(overview) => self.project_overview = Some(overview),
            Err(error) => self.status_message = Some(format!("Project overview: {error}")),
        }
    }

    pub fn toggle_key_editor(&mut self) {
        if self.key_editor.take().is_some() {
            return;
        }
        if let Err(error) = self.save_project() {
            self.status_message = Some(format!("Project save failed: {error}"));
            return;
        }
        let context = self.project_context.as_ref().expect("save establishes project context");
        match zweidraehte_project::ProjectStore::open(&context.path)
            .map_err(|error| error.to_string())
            .and_then(|store| ProjectKeyEditor::load(&store))
        {
            Ok(editor) => self.key_editor = Some(editor),
            Err(error) => self.status_message = Some(format!("Key editor: {error}")),
        }
    }

    pub fn key_editor_move_up(&mut self) {
        if let Some(editor) = &mut self.key_editor
            && editor.input.is_none()
        {
            editor.move_up();
        }
    }

    pub fn key_editor_move_down(&mut self) {
        if let Some(editor) = &mut self.key_editor
            && editor.input.is_none()
        {
            editor.move_down();
        }
    }

    pub fn key_editor_activate(&mut self) {
        let Some(editor) = &mut self.key_editor else { return };
        if editor.input.is_none() {
            editor.input = Some(String::new());
            return;
        }
        let target = editor.selected_target().cloned();
        let input = editor.input.take().unwrap_or_default();
        let result = target.map_or_else(
            || Err("the project has no editable key slots".to_string()),
            |target| self.persist_key_input(target, &input),
        );
        match result {
            Ok(()) => {
                let context = self.project_context.as_ref().expect("key editor has project context");
                match zweidraehte_project::ProjectStore::open(&context.path)
                    .map_err(|error| error.to_string())
                    .and_then(|store| ProjectKeyEditor::load(&store))
                {
                    Ok(editor) => {
                        self.key_editor = Some(editor);
                        self.status_message = Some("Key persisted".into());
                    }
                    Err(error) => self.status_message = Some(format!("Key editor refresh failed: {error}")),
                }
            }
            Err(error) => {
                if let Some(editor) = &mut self.key_editor {
                    editor.input = Some(input);
                }
                self.status_message = Some(format!("Key rejected: {error}"));
            }
        }
    }

    pub fn key_editor_cancel(&mut self) {
        let Some(editor) = &mut self.key_editor else { return };
        if editor.input.take().is_none() {
            self.key_editor = None;
        }
    }

    pub fn key_editor_char(&mut self, character: char) {
        if let Some(input) = self.key_editor.as_mut().and_then(|editor| editor.input.as_mut())
            && !character.is_control()
        {
            input.push(character);
        }
    }

    pub fn key_editor_backspace(&mut self) {
        if let Some(input) = self.key_editor.as_mut().and_then(|editor| editor.input.as_mut()) {
            input.pop();
        }
    }

    fn persist_key_input(&self, target: EditableKey, input: &str) -> Result<(), String> {
        use zweidraehte_project::{KeyOrigin, ProjectStore, parse_fdsk};

        let context = self.project_context.as_ref().ok_or_else(|| "no project context".to_string())?;
        let mut store = ProjectStore::open(&context.path).map_err(|error| error.to_string())?;
        let authored = store.authored().clone();
        let keys = store.keys_mut().ok_or_else(|| "project keys are not initialized".to_string())?;
        match target {
            EditableKey::DeviceFdsk(device) => {
                let decoded = parse_fdsk(input).map_err(|error| error.to_string())?;
                let configured = authored.devices.get(&device).and_then(|device| device.serial);
                if let (Some(configured), Some(embedded)) = (configured, decoded.serial)
                    && configured != embedded
                {
                    return Err(format!(
                        "FDSK serial {} disagrees with project serial {}",
                        zweidraehte_project::format_serial(&embedded),
                        zweidraehte_project::format_serial(&configured)
                    ));
                }
                let origin = if decoded.serial.is_some() { KeyOrigin::DeviceLabel } else { KeyOrigin::Manual };
                keys.put_device_fdsk(&device.0, input, origin).map_err(|error| error.to_string())
            }
            EditableKey::DeviceToolKey(device) => {
                keys.put_device_tool_key(&device.0, input, KeyOrigin::Manual).map_err(|error| error.to_string())
            }
            EditableKey::GroupKey { net, epoch } => {
                keys.put_group_key(&net.0, epoch, input, KeyOrigin::Manual, true).map_err(|error| error.to_string())
            }
        }
    }

    /// Cycle the selected object's primary net policy. This is deliberately
    /// object-centric: GA membership editing and net security remain separate
    /// operations in the UI and in the project model.
    pub fn cycle_selected_net_security(&mut self) {
        let Some(row) = self.com_object_rows.get(self.selected_obj_idx) else { return };
        let Some(project) = self.project_context.as_ref().and_then(|context| context.authored.as_ref()) else {
            self.status_message = Some("Save the product draft before editing net security".into());
            return;
        };
        let Some(object) = project
            .devices
            .get(&self.project_context.as_ref().expect("project context checked").device)
            .and_then(|device| device.objects.get(&row.number))
        else {
            self.status_message = Some("The selected object has no authored project membership".into());
            return;
        };
        let Some(primary) = object
            .memberships
            .iter()
            .find(|membership| membership.role == zweidraehte_project::MembershipRole::Primary)
        else {
            self.status_message = Some("The selected object has no primary net".into());
            return;
        };
        let primary_net = primary.net.clone();
        let current =
            self.net_policy_overrides.get(&primary_net).copied().unwrap_or(project.nets[&primary_net].security);
        let next = match current {
            NetSecurityPolicy::Plain => NetSecurityPolicy::Automatic,
            NetSecurityPolicy::Automatic => NetSecurityPolicy::Authentication,
            NetSecurityPolicy::Authentication => NetSecurityPolicy::AuthenticationConfidentiality,
            NetSecurityPolicy::AuthenticationConfidentiality => NetSecurityPolicy::Plain,
        };
        self.net_policy_overrides.insert(primary_net.clone(), next);
        if let Err(error) = self.refresh_project_navigation() {
            self.status_message = Some(format!("Cannot refresh project navigation: {error}"));
            return;
        }
        self.status_message = Some(format!("Net {primary_net} security: {next:?}"));
    }

    pub fn toggle_data_secure(&mut self) {
        if !self.device.program().is_secure_enabled.unwrap_or(false) {
            self.status_message = Some("This product does not support Data Secure".into());
            return;
        }
        self.data_secure = match self.data_secure {
            DataSecureMode::Disabled => DataSecureMode::Enabled,
            DataSecureMode::Enabled => DataSecureMode::Disabled,
        };
        if let Err(error) = self.refresh_project_navigation() {
            self.status_message = Some(format!("Cannot refresh project navigation: {error}"));
            return;
        }
        self.status_message =
            Some(format!("Data Secure {}", if self.data_secure.is_enabled() { "enabled" } else { "disabled" }));
    }

    /// Commission and load the selected device in one operation.
    pub fn start_download(&mut self) {
        self.start_download_selection(false, false, zweidraehte_client::ProgrammingScope::AddressAndApplication);
    }

    /// Commission and load with the complete mask procedure even when the
    /// project state permits a differential update.
    pub fn start_full_download(&mut self) {
        self.start_download_selection(false, true, zweidraehte_client::ProgrammingScope::AddressAndApplication);
    }

    /// Assign the IA and secure-management state without touching the app.
    pub fn start_address_commissioning(&mut self) {
        self.start_download_selection(false, false, zweidraehte_client::ProgrammingScope::Address);
    }

    /// Reload the application at its configured IA without commissioning it.
    pub fn start_application_download(&mut self) {
        self.start_download_selection(false, false, zweidraehte_client::ProgrammingScope::Application);
    }

    pub fn start_affected_download(&mut self) {
        self.start_download_selection(true, false, zweidraehte_client::ProgrammingScope::AddressAndApplication);
    }

    fn start_download_selection(
        &mut self,
        affected_only: bool,
        force_full: bool,
        scope: zweidraehte_client::ProgrammingScope,
    ) {
        if self.download.as_ref().is_some_and(|d| d.result.is_none()) {
            return; // already running
        }
        let Some(target) = self.download_context.as_ref().and_then(|c| c.target.clone()) else {
            self.status_message = Some("Start the TUI with --server or --usb to program the device".to_string());
            return;
        };
        if let Err(error) = self.save_project() {
            self.status_message = Some(format!("Project save failed: {error}"));
            return;
        };
        let project = self.project_context.as_ref().expect("save establishes project context");

        let (tx, rx) = std::sync::mpsc::channel();
        crate::download::spawn(
            crate::download::DownloadJob {
                target,
                project_path: project.path.clone(),
                device: (!affected_only).then(|| project.device.clone()),
                affected_only,
                master_data: self.download_context.as_ref().and_then(|c| c.master_data.clone()),
                security: self
                    .download_context
                    .as_ref()
                    .expect("download target came from the context")
                    .security
                    .clone(),
                include_affected: true,
                program_ia: false,
                scope,
                force_full,
            },
            tx,
        );
        self.download = Some(DownloadUi {
            past: Vec::new(),
            current: None,
            step: (0, 0),
            data: None,
            result: None,
            spinner: 0,
            receiver: rx,
        });
    }

    /// Drain the worker's progress; called every UI tick.
    pub fn poll_download(&mut self) {
        let Some(download) = &mut self.download else { return };
        download.spinner = download.spinner.wrapping_add(1);
        while let Ok(message) = download.receiver.try_recv() {
            match message {
                crate::download::DownloadMsg::Task(label, index, total) => {
                    if let Some(previous) = download.current.take() {
                        download.past.push(previous);
                    }
                    download.current = Some(label);
                    download.step = (index, total);
                    download.data = None;
                }
                crate::download::DownloadMsg::Data(done, total) => {
                    download.data = Some((done, total));
                }
                crate::download::DownloadMsg::Done(result) => {
                    if let Some(previous) = download.current.take() {
                        download.past.push(previous);
                    }
                    download.result = Some(result);
                }
            }
        }
    }

    /// Close the popup once the worker finished.
    pub fn dismiss_download(&mut self) {
        if self.download.as_ref().is_some_and(|d| d.result.is_some()) {
            self.download = None;
        }
    }

    /// Overall progress of the running download, 0..=100.
    pub fn download_ratio(&self) -> u16 {
        let Some(download) = &self.download else { return 0 };
        if download.result.is_some() {
            return 100;
        }
        let (index, total) = download.step;
        if total == 0 {
            return 0;
        }
        let intra = download.data.map_or(0.0, |(done, all)| if all == 0 { 0.0 } else { done as f64 / all as f64 });
        (((index as f64 + intra) / total as f64) * 100.0).clamp(0.0, 100.0) as u16
    }

    /// Persist product edits into the selected project. In product-only mode
    /// this is the transition that creates the one-device project, keys.toml,
    /// and matching mutable state identity.
    pub fn export_project(&mut self) {
        self.status_message = Some(match self.save_project() {
            Ok(()) => format!(
                "Saved project {}",
                self.project_context.as_ref().expect("save establishes context").path.display()
            ),
            Err(error) => format!("Project save failed: {error}"),
        });
    }

    /// Persist changed editor geometry without touching `project.knx` or the
    /// secure commissioning journal. The event loop calls this on clean exit;
    /// an explicit project save calls it as well.
    pub fn persist_pane_layout(&mut self) -> Result<(), String> {
        if !self.pane_layout_dirty {
            return Ok(());
        }
        let Some(context) = &self.project_context else {
            return Ok(());
        };
        // Opening a product must remain side-effect free until the first save
        // turns it into a real project.
        if context.authored.is_none() {
            return Ok(());
        }
        self.pane_layout.persist(&context.path)?;
        self.pane_layout_dirty = false;
        Ok(())
    }

    fn save_project(&mut self) -> Result<(), String> {
        let context = self.project_context.clone().ok_or_else(|| "no project context is configured".to_string())?;
        let draft = self.project_draft(&context)?;
        let source = match &context.authored {
            Some(project) => project.render_device_update(&draft).map_err(|error| error.to_string())?,
            None => zweidraehte_project::render_single_device_project(&draft).map_err(|error| error.to_string())?,
        };
        let checked = AuthoredProject::parse(source.clone()).map_err(|error| error.to_string())?;
        checked.validate_download().map_err(|error| {
            error.diagnostics().iter().map(|diagnostic| diagnostic.message.as_str()).collect::<Vec<_>>().join("; ")
        })?;
        zweidraehte_project::ProjectStore::write_authored(&context.path, context.original_source.as_deref(), &source)
            .map_err(|error| error.to_string())?;
        let mut store = zweidraehte_project::ProjectStore::open(&context.path).map_err(|error| error.to_string())?;
        if store.keys().is_none() && store.state().is_none() {
            store.initialize().map_err(|error| error.to_string())?;
        }
        let authored = store.authored().clone();
        let refreshed = ProjectContext {
            path: context.path,
            device: context.device,
            product_path: context.product_path,
            catalog_product: context.catalog_product,
            application_program: context.application_program,
            authored: Some(authored),
            original_source: Some(source),
        };
        self.project_navigation = refreshed
            .authored
            .as_ref()
            .map(|project| ProjectNavigation::from_project(project, refreshed.device.clone()));
        self.project_context = Some(refreshed);
        self.persist_pane_layout()
    }

    fn project_draft(&self, context: &ProjectContext) -> Result<zweidraehte_project::ProjectDeviceDraft, String> {
        use zweidraehte_project::{
            DraftNet, MembershipRole, NetId, NetSecurityPolicy, ObjectMembership, ParamValue as ProjectValue,
            ParameterAssignment, ProjectObjectConfiguration, SourceSpan,
        };
        let zero = SourceSpan { start: 0, end: 0 };
        let existing = context.authored.as_ref().and_then(|project| project.devices.get(&context.device));
        let mut nets = BTreeMap::new();
        let mut address_to_id = BTreeMap::new();
        if let Some(project) = &context.authored {
            for net in project.nets.values() {
                address_to_id.insert(u16::from_be_bytes(net.address.0), net.id.clone());
                nets.insert(net.id.clone(), DraftNet {
                    id: net.id.clone(),
                    address: net.address,
                    dpt: net.dpt.clone(),
                    security: net.security,
                });
            }
        }
        for (net, policy) in &self.net_policy_overrides {
            if let Some(draft) = nets.get_mut(net) {
                draft.security = *policy;
            }
        }
        let rows: BTreeMap<_, _> = self.com_object_rows.iter().map(|row| (row.number, row)).collect();
        let mut objects = BTreeMap::new();
        for (number, bindings) in self.device.all_bindings() {
            let mut memberships = Vec::new();
            for binding in bindings {
                let raw = binding.group_address.to_u16();
                let id = address_to_id.get(&raw).cloned().unwrap_or_else(|| {
                    NetId(format!(
                        "ga_{}_{}_{}",
                        binding.group_address.main, binding.group_address.middle, binding.group_address.sub
                    ))
                });
                address_to_id.insert(raw, id.clone());
                nets.entry(id.clone()).or_insert_with(|| DraftNet {
                    id: id.clone(),
                    address: zweidraehte_proto::address::GroupAddress::from_three_level(
                        binding.group_address.main,
                        binding.group_address.middle,
                        binding.group_address.sub,
                    ),
                    dpt: rows.get(&number).map_or_else(|| "1.001".into(), project_dpt),
                    security: NetSecurityPolicy::Automatic,
                });
                memberships.push(ObjectMembership {
                    net: id,
                    role: if binding.is_sending { MembershipRole::Primary } else { MembershipRole::Additional },
                    span: zero,
                });
            }
            objects.insert(number, ProjectObjectConfiguration {
                com_object: number,
                memberships,
                flags: self.object_flag_overrides.get(&number).copied().unwrap_or_default(),
                span: zero,
            });
        }
        // Preserve flag-only objects even when they currently have no links.
        for (&number, &flags) in &self.object_flag_overrides {
            objects.entry(number).or_insert(ProjectObjectConfiguration {
                com_object: number,
                memberships: Vec::new(),
                flags,
                span: zero,
            });
        }
        let parameters = configuration_from_device(&self.device)
            .parameters
            .into_iter()
            .map(|parameter| -> Result<ParameterAssignment, String> {
                let value = match parameter.value {
                    ParameterValue::Integer(value) => ProjectValue::Integer(value),
                    ParameterValue::Float(value) => ProjectValue::Float(value),
                    ParameterValue::Text(value) => ProjectValue::Text(value),
                    ParameterValue::Bytes(_) => {
                        return Err("raw-byte parameters cannot be stored in project.knx".into());
                    }
                };
                Ok(ParameterAssignment { id: parameter.id, value, span: zero })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(zweidraehte_project::ProjectDeviceDraft {
            id: context.device.clone(),
            product: context.product_path.clone(),
            catalog_product: existing
                .and_then(|device| device.catalog_product.clone())
                .or_else(|| context.catalog_product.clone()),
            application_program: existing
                .and_then(|device| device.application_program.clone())
                .or_else(|| context.application_program.clone()),
            language: self.current_language.clone(),
            address: existing
                .map_or_else(|| zweidraehte_proto::address::IndividualAddress::new(1, 1, 1), |device| device.address),
            medium: existing.map_or(zweidraehte_project::Medium::Tp1, |device| device.medium),
            serial: existing.and_then(|device| device.serial),
            max_apdu: existing.and_then(|device| device.max_apdu),
            data_secure: self.data_secure,
            parameters,
            objects,
            nets,
        })
    }

    fn enter_edit_mode(&mut self) {
        if let Some(ContentItem::Parameter { param_id, widget, .. }) = self.content_items.get(self.selected_content_idx)
        {
            let param_id = param_id.clone();
            match widget {
                WidgetType::Dropdown { options, current_idx } => {
                    // Calculate initial scroll offset to center the selected item if possible
                    let visible = Self::DROPDOWN_VISIBLE_ITEMS;
                    let scroll_offset = if options.len() <= visible || *current_idx < visible / 2 {
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
                WidgetType::Number { value, min, max } => {
                    self.edit_mode = EditMode::NumberInput {
                        param_id,
                        buffer: value.to_string(),
                        select_all: true,
                        min: *min,
                        max: *max,
                    };
                }
                WidgetType::Text { value } => {
                    let len = value.len();
                    self.edit_mode = EditMode::TextInput { param_id, buffer: value.clone(), cursor: len };
                }
                WidgetType::ReadOnly { .. } => {
                    // Can't edit read-only
                }
            }
        }
    }

    /// Enter group address edit mode for the currently selected communication object.
    fn enter_group_address_edit_mode(&mut self) {
        if let Some(row) = self.com_object_rows.get(self.selected_obj_idx) {
            // Get existing group address as initial buffer value
            let existing = self.format_group_address(row.number);
            self.edit_mode = EditMode::GroupAddressInput { object_number: row.number, buffer: existing };
        }
    }

    pub fn enter_object_flags_edit_mode(&mut self) {
        let Some(row) = self.com_object_rows.get(self.selected_obj_idx) else { return };
        let flags = self.object_flag_overrides.get(&row.number).copied().unwrap_or_default();
        self.edit_mode = EditMode::ObjectFlagsInput { object_number: row.number, buffer: format_object_flags(flags) };
    }

    /// Handle character input for editing.
    pub fn handle_char(&mut self, c: char) {
        match &mut self.edit_mode {
            EditMode::NumberInput { buffer, select_all, .. } => {
                edit_number_input(buffer, select_all, c);
            }
            EditMode::TextInput { buffer, cursor, .. } => {
                buffer.insert(*cursor, c);
                *cursor += c.len_utf8();
            }
            EditMode::NetNameInput { buffer, cursor, .. } if !c.is_control() => {
                buffer.insert(*cursor, c);
                *cursor += c.len_utf8();
            }
            EditMode::GroupAddressInput { buffer, .. }
                // Digits and slashes for the addresses themselves,
                // commas/spaces to separate several of them
                if (c.is_ascii_digit() || c == '/' || c == ',' || c == ' ') => {
                    buffer.push(c);
                }
            EditMode::ObjectFlagsInput { buffer, .. }
                if c.is_ascii_alphanumeric() || matches!(c, '=' | '-' | '_' | ' ') =>
            {
                buffer.push(c);
            }
            _ => {}
        }
    }

    /// Handle backspace for editing.
    pub fn handle_backspace(&mut self) {
        match &mut self.edit_mode {
            EditMode::NumberInput { buffer, select_all, .. } => {
                backspace_number_input(buffer, select_all);
            }
            EditMode::GroupAddressInput { buffer, .. } | EditMode::ObjectFlagsInput { buffer, .. } => {
                buffer.pop();
            }
            EditMode::TextInput { buffer, cursor, .. } if *cursor > 0 => {
                let previous = buffer[..*cursor].char_indices().next_back().map_or(0, |(index, _)| index);
                buffer.drain(previous..*cursor);
                *cursor = previous;
            }
            EditMode::NetNameInput { buffer, cursor, .. } if *cursor > 0 => {
                let previous = buffer[..*cursor].char_indices().next_back().map_or(0, |(index, _)| index);
                buffer.drain(previous..*cursor);
                *cursor = previous;
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

fn product_flags(flags: ObjectFlagOverrides) -> ProductFlagOverrides {
    ProductFlagOverrides {
        communication: flags.communication,
        read: flags.read,
        write: flags.write,
        transmit: flags.transmit,
        update: flags.update,
        read_on_init: flags.read_on_init,
        priority: flags.priority.map(|priority| match priority {
            zweidraehte_project::ObjectPriority::System => zweidraehte_proto::messages::knx::Priority::System,
            zweidraehte_project::ObjectPriority::High => zweidraehte_proto::messages::knx::Priority::High,
            zweidraehte_project::ObjectPriority::Alarm => zweidraehte_proto::messages::knx::Priority::Alarm,
            zweidraehte_project::ObjectPriority::Low => zweidraehte_proto::messages::knx::Priority::Low,
        }),
    }
}

fn source_letter(source: EffectiveValueSource) -> char {
    match source {
        EffectiveValueSource::Product => 'P',
        EffectiveValueSource::VisibleReference => 'R',
        EffectiveValueSource::Project => 'J',
    }
}

fn project_dpt(row: &&ComObjectRow) -> String {
    if let Some(references) = ProductDptReferences::parse(&row.dpt) {
        let preferred = references.preferred();
        return format!("{}.{:03}", preferred.main, preferred.subtype.unwrap_or(1));
    }
    match row.size.as_str() {
        "1 Bit" => "1.001",
        "2 Bit" => "2.001",
        "4 Bit" => "3.007",
        "1 Byte" => "5.001",
        "2 Bytes" => "7.001",
        "3 Bytes" => "10.001",
        "4 Bytes" => "12.001",
        "6 Bytes" => "234.001",
        "8 Bytes" => "29.001",
        "14 Bytes" => "16.001",
        _ => "1.001",
    }
    .to_string()
}

fn format_object_flags(flags: ObjectFlagOverrides) -> String {
    let value = |value: Option<bool>| match value {
        Some(true) => "1",
        Some(false) => "0",
        None => "-",
    };
    let priority = match flags.priority {
        Some(zweidraehte_project::ObjectPriority::System) => "system",
        Some(zweidraehte_project::ObjectPriority::High) => "high",
        Some(zweidraehte_project::ObjectPriority::Alarm) => "alarm",
        Some(zweidraehte_project::ObjectPriority::Low) => "low",
        None => "-",
    };
    format!(
        "C={} R={} W={} T={} U={} I={} P={priority}",
        value(flags.communication),
        value(flags.read),
        value(flags.write),
        value(flags.transmit),
        value(flags.update),
        value(flags.read_on_init)
    )
}

fn parse_object_flags(input: &str) -> Result<ObjectFlagOverrides, String> {
    let mut flags = ObjectFlagOverrides::default();
    for entry in input.split_whitespace() {
        let (name, value) = entry.split_once('=').ok_or_else(|| format!("flag `{entry}` needs NAME=value"))?;
        let boolean = || match value {
            "1" | "true" => Ok(Some(true)),
            "0" | "false" => Ok(Some(false)),
            "-" => Ok(None),
            _ => Err(format!("{name} wants 1, 0, or -")),
        };
        match name.to_ascii_uppercase().as_str() {
            "C" => flags.communication = boolean()?,
            "R" => flags.read = boolean()?,
            "W" => flags.write = boolean()?,
            "T" => flags.transmit = boolean()?,
            "U" => flags.update = boolean()?,
            "I" => flags.read_on_init = boolean()?,
            "P" => {
                flags.priority = match value {
                    "-" => None,
                    "system" => Some(zweidraehte_project::ObjectPriority::System),
                    "high" => Some(zweidraehte_project::ObjectPriority::High),
                    "alarm" | "alert" => Some(zweidraehte_project::ObjectPriority::Alarm),
                    "low" => Some(zweidraehte_project::ObjectPriority::Low),
                    _ => return Err("P wants system, high, alarm, low, or -".into()),
                };
            }
            _ => return Err(format!("unknown flag `{name}`")),
        }
    }
    Ok(flags)
}

#[cfg(test)]
mod project_editor_tests {
    use super::*;
    use zweidraehte_ets_files::runtime::parser::parse_application_program;

    const PARAMETER_REF_DEFAULT_FIXTURE: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-1" ApplicationNumber="1" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="Fixture" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="false" Linkable="false">
      <Static>
        <ParameterTypes>
          <ParameterType Id="M-00FA_A-1_PT-N8" Name="N8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="100" /></ParameterType>
        </ParameterTypes>
        <Parameters>
          <Parameter Id="M-00FA_A-1_P-1" Name="Level" ParameterType="M-00FA_A-1_PT-N8" Text="Level" Value="50" />
        </Parameters>
        <ParameterRefs>
          <ParameterRef Id="M-00FA_A-1_P-1_R-1" RefId="M-00FA_A-1_P-1" Value="60" />
        </ParameterRefs>
      </Static>
      <Dynamic>
        <Channel Id="M-00FA_A-1_CH-1" Name="Main">
          <ParameterBlock Id="M-00FA_A-1_PB-1" Text="Main">
            <ParameterRefRef RefId="M-00FA_A-1_P-1_R-1" />
          </ParameterBlock>
        </Channel>
      </Dynamic>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    fn parameter_ref_default_app() -> App {
        let knx = parse_application_program(PARAMETER_REF_DEFAULT_FIXTURE).expect("the fixture parses");
        let program =
            knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next().expect("one program");

        App::new(Device::new(program, None))
    }

    #[test]
    fn number_input_replaces_the_initial_selection() {
        let mut buffer = "1".to_string();
        let mut select_all = true;

        edit_number_input(&mut buffer, &mut select_all, '2');

        assert_eq!(buffer, "2");
        assert!(!select_all);

        edit_number_input(&mut buffer, &mut select_all, '3');

        assert_eq!(buffer, "23");
    }

    #[test]
    fn number_input_backspace_clears_the_initial_selection() {
        let mut buffer = "123".to_string();
        let mut select_all = true;

        backspace_number_input(&mut buffer, &mut select_all);

        assert!(buffer.is_empty());
        assert!(!select_all);
    }

    #[test]
    fn parameter_widget_uses_the_visible_reference_default_until_edited() {
        let mut app = parameter_ref_default_app();
        let parameter_id = "M-00FA_A-1_P-1";

        let WidgetType::Number { value, .. } = app.build_widget_for_param(parameter_id, None) else {
            panic!("number parameter has a numeric widget");
        };

        assert_eq!(value, 60);

        app.device.set_parameter_value(parameter_id, ParameterValue::Integer(50));

        let WidgetType::Number { value, .. } = app.build_widget_for_param(parameter_id, None) else {
            panic!("number parameter has a numeric widget");
        };

        assert_eq!(value, 50);
    }

    #[test]
    fn pane_preferences_resize_and_stay_inside_useful_bounds() {
        let mut panes = PaneLayout::default();
        panes.resize_horizontal(MainTab::Parameters, Focus::Sidebar, 4);
        panes.resize_horizontal(MainTab::Memory, Focus::Content, -4);
        panes.resize_horizontal(MainTab::Parameters, Focus::Project, 4);
        panes.resize_vertical(Focus::Project, -5);
        assert_eq!(panes.parameter_sidebar_width, 34);
        assert_eq!(panes.memory_sidebar_width, 31);
        assert_eq!(panes.project_width, 38);
        assert_eq!(panes.topology_percent, 53);

        panes.resize_horizontal(MainTab::Parameters, Focus::Project, -100);
        panes.resize_vertical(Focus::Project, 100);
        assert_eq!(panes.project_width, 24);
        assert_eq!(panes.topology_percent, 75);
    }

    #[test]
    fn pane_preferences_round_trip_as_project_local_editor_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project = directory.path().join("project.knx");
        let state_directory = directory.path().join(".zweidraehte");
        fs::create_dir(&state_directory).expect("state directory is created");
        fs::write(
            state_directory.join(PaneLayout::STATE_FILE),
            "# retained editor setting\nversion = 1\nfuture_setting = true\n",
        )
        .expect("initial preferences write");

        let panes = PaneLayout {
            project_width: 42,
            topology_percent: 65,
            parameter_sidebar_width: 36,
            memory_sidebar_width: 40,
        };
        panes.persist(&project).expect("pane preferences persist");

        assert_eq!(PaneLayout::load(&project).expect("pane preferences load"), Some(panes));
        let source = fs::read_to_string(state_directory.join(PaneLayout::STATE_FILE)).expect("preferences read");
        assert!(source.contains("# retained editor setting"));
        assert!(source.contains("future_setting = true"));
    }

    #[test]
    fn object_flag_editor_round_trips_optional_overrides() {
        let flags = ObjectFlagOverrides {
            communication: Some(true),
            transmit: Some(false),
            priority: Some(zweidraehte_project::ObjectPriority::High),
            ..Default::default()
        };
        assert_eq!(parse_object_flags(&format_object_flags(flags)).expect("flags parse"), flags);
    }

    #[test]
    fn project_net_uses_the_specific_dpt_from_mtxml_idrefs() {
        let row = ComObjectRow {
            number: 10,
            name: String::new(),
            function: String::new(),
            group_address: String::new(),
            size: "1 Bit".into(),
            dpt: "DPT-1 DPST-1-1".into(),
            priority: String::new(),
            flag_c: true,
            flag_r: false,
            flag_w: false,
            flag_t: true,
            flag_u: false,
            flag_i: false,
            provenance: String::new(),
        };
        assert_eq!(project_dpt(&&row), "1.001");
    }
}
