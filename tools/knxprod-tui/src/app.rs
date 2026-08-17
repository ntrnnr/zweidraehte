//! Application state and logic for the KNX TUI viewer.

use zweidraehte_knxprod::runtime::master_data::{MaskVersion, TableFlavour};
use zweidraehte_knxprod::runtime::model::{DynamicVisitor, ParameterValue, walk_dynamic};
use zweidraehte_knxprod::schema::{
    Channel, ChannelIndependentBlock, ChannelIndependentItem, ChannelItem, Choose, ComObject, ComObjectPriority,
    ComObjectRef, DynamicSection, EnableFlag, Module, ModuleDef, ModuleDefDynamicItem, Parameter, ParameterBlock,
    ParameterBlockItem, ParameterItem, ParameterTypeDef, UnionParameter, WhenItem,
};
use zweidraehte_knxprod::{Device, MasterData};

#[cfg(feature = "images")]
use ratatui_image::picker::Picker;
#[cfg(feature = "images")]
use ratatui_image::protocol::StatefulProtocol;
#[cfg(feature = "images")]
use std::collections::HashMap;

/// Compute the actual object number for a module comm object.
///
/// Module comm objects have a local `number` (0, 1, 2, ...) and may have a `base_number`
/// argument reference. The actual object number is `base_number_value + local_number`.
/// If no BaseNumber is specified, the local number is used as-is.
fn compute_module_object_number(
    obj: &ComObject,
    expanded: &zweidraehte_knxprod::runtime::model::ExpandedModule,
    module_def: &ModuleDef,
) -> u16 {
    use zweidraehte_knxprod::runtime::model::ModuleArgValue;

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
    /// A channel with its index
    Channel { index: usize },
    /// A parameter block
    ParameterBlock { block_name: String },
    /// A module instance
    Module { instance_id: String },
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
    /// Current channel index (None when in CIB)
    current_channel_idx: Option<usize>,
    /// Stack of parent nodes we're building into
    node_stack: Vec<VisibleTreeNode>,
    /// Whether we're inside a parameter block that has visible items
    in_visible_block: bool,
    /// Whether we're inside a module (skip internal ParameterBlocks from tree)
    in_module: bool,
}

impl<'a> TreeBuilderVisitor<'a> {
    /// Create a new visitor for building the tree.
    pub fn new(device: &'a Device) -> Self {
        Self {
            device,
            root_nodes: Vec::new(),
            current_channel_idx: None,
            node_stack: Vec::new(),
            in_visible_block: false,
            in_module: false,
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
}

impl<'a> DynamicVisitor for TreeBuilderVisitor<'a> {
    fn enter_channel_independent_block(&mut self, _block: &ChannelIndependentBlock) {
        self.current_channel_idx = None;
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
        // Determine channel index by counting existing channel nodes
        let channel_idx =
            self.root_nodes.iter().filter(|n| matches!(n.node_type, VisibleNodeType::Channel { .. })).count();

        // Also count the CIB node that may have been added
        let _has_cib = self.root_nodes.iter().any(|n| matches!(n.node_type, VisibleNodeType::DeviceSettings));

        // The actual channel index in the dynamic section
        // TODO: Adjust index when CIB node is present (currently a no-op).
        let actual_idx = channel_idx;
        self.current_channel_idx = Some(actual_idx);

        let raw_name = channel.text.clone().unwrap_or_else(|| channel.name.clone());

        self.node_stack.push(VisibleTreeNode {
            id: format!("channel_{}", actual_idx),
            raw_name,
            node_type: VisibleNodeType::Channel { index: actual_idx },
            children: Vec::new(),
        });
    }

    fn leave_channel(&mut self, _channel: &Channel) {
        if let Some(node) = self.node_stack.pop() {
            self.root_nodes.push(node);
        }
        self.current_channel_idx = None;
    }

    fn enter_parameter_block(&mut self, block: &ParameterBlock) {
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
            .unwrap_or_else(|| block_name.clone());

        let id = if let Some(ch_idx) = self.current_channel_idx {
            format!("channel_{}_block_{}", ch_idx, block_name)
        } else {
            format!("device_block_{}", block_name)
        };

        let child_node = VisibleTreeNode {
            id,
            raw_name: raw_text,
            node_type: VisibleNodeType::ParameterBlock { block_name: block_name.clone() },
            children: Vec::new(),
        };

        // Add to current parent
        if let Some(parent) = self.node_stack.last_mut() {
            parent.children.push(child_node);
        }
    }

    fn leave_parameter_block(&mut self, _block: &ParameterBlock) {
        self.in_visible_block = false;
    }

    fn visit_module(&mut self, module: &Module) {
        // Only add visible modules
        if !self.device.is_module_visible(&module.id) {
            return;
        }

        let id = if let Some(ch_idx) = self.current_channel_idx {
            format!("channel_{}_module_{}", ch_idx, module.id)
        } else {
            format!("device_module_{}", module.id)
        };

        // Get raw name - will be interpolated later
        let raw_name = module.name.clone().unwrap_or_else(|| module.id.clone());

        let child_node = VisibleTreeNode {
            id,
            raw_name,
            node_type: VisibleNodeType::Module { instance_id: module.id.clone() },
            children: Vec::new(),
        };

        // Add to current parent
        if let Some(parent) = self.node_stack.last_mut() {
            parent.children.push(child_node);
        }
    }

    fn enter_module(&mut self, _module: &Module, _ctx: &zweidraehte_knxprod::runtime::model::VisitorModuleContext) {
        // Mark that we're inside a module - skip internal ParameterBlocks from tree
        self.in_module = true;
    }

    fn leave_module(&mut self, _module: &Module, _ctx: &zweidraehte_knxprod::runtime::model::VisitorModuleContext) {
        self.in_module = false;
    }
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
    NumberInput { param_id: String, buffer: String, min: Option<i64>, max: Option<i64> },
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
}

/// Everything a language switch needs to rebuild the device.
pub struct LanguageContext {
    /// The document's `<Languages>` translations.
    pub translations: zweidraehte_knxprod::runtime::Translations,
    /// The program as parsed, in its `DefaultLanguage` — every switch
    /// starts from this copy, because applying a translation rewrites
    /// texts in place.
    pub pristine: zweidraehte_knxprod::schema::ApplicationProgram,
    /// The baggage the device was originally built with.
    pub baggage: Option<zweidraehte_knxprod::runtime::BaggageIndex>,
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
}

/// Application state.
#[allow(dead_code)] // Some fields reserved for future use
pub struct App {
    /// The unified device (model + info + baggage)
    pub device: Device,
    /// KNX master data (optional - used for mask version info, shared across devices)
    pub master_data: Option<MasterData>,
    /// Image picker for terminal protocol detection
    #[cfg(feature = "images")]
    pub image_picker: Option<Picker>,
    /// Cache of loaded images by baggage RefId, with their pixel
    /// dimensions (the protocol consumes the decoded image, so the size
    /// must be recorded at load time)
    #[cfg(feature = "images")]
    pub image_cache: HashMap<String, (StatefulProtocol, (u32, u32))>,
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
    /// Scroll offset for content items
    pub content_scroll_offset: usize,
    /// Visible parameter-ref count shown in the status bar. Cached
    /// because counting means hashing every visible ref id (~100k on
    /// large products), far too much to redo every frame; refreshed by
    /// `rebuild_com_objects`, which runs on every visibility change.
    pub visible_param_count: usize,
    /// Visible com-object-ref count for the status bar; same caching.
    pub visible_obj_count: usize,
    /// `content_items` no longer matches the selected tree node.
    /// Sidebar navigation only marks this and lets the rebuild happen
    /// once per rendered frame — holding an arrow key down repeats
    /// faster than large pages rebuild, and paying per keypress starves
    /// the draw loop.
    pub content_dirty: bool,
    /// `com_object_rows` no longer matches the device (an edit changed
    /// visibility or group links); rebuilt lazily by `ensure_tab_data`
    /// when the Communication Objects tab is next rendered, so edits on
    /// the Parameters tab don't pay for a table they aren't looking at.
    pub com_objects_dirty: bool,
    /// Same deferral for `memory_segments`.
    pub memory_dirty: bool,
    /// Communication objects table rows
    pub com_object_rows: Vec<ComObjectRow>,
    /// Selected comm object row index
    pub selected_obj_idx: usize,
    /// Scroll offset for comm objects table
    pub comm_obj_scroll_offset: usize,
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
    /// One-line feedback shown in the status bar (export results,
    /// input errors); replaced by the next message.
    pub status_message: Option<String>,
    /// Where `e` exports the mods to: the file loaded via `--mods`,
    /// or a name derived from the program id.
    pub mods_export_path: Option<std::path::PathBuf>,
    /// Everything a language switch needs to rebuild the device from
    /// scratch: the document's translations, the untranslated program,
    /// and the baggage the device was built with.
    pub language_context: Option<LanguageContext>,
    /// The currently applied language; `None` shows the program's
    /// `DefaultLanguage` base texts.
    pub current_language: Option<String>,
    /// Bus access for programming the device, from the CLI.
    pub download_context: Option<DownloadContext>,
    /// The download popup, while one is running or awaiting dismissal.
    pub download: Option<DownloadUi>,
    /// The loaded mods file's `[device]` section, carried through the
    /// export so the individual address survives a TUI round trip.
    pub mods_device_section: Option<zweidraehte_knxprod::runtime::mods::DeviceSection>,
}

#[allow(dead_code)] // Convenience constructors for library use
impl App {
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
            device,
            master_data,
            #[cfg(feature = "images")]
            image_picker: Some(Picker::from_query_stdio().unwrap_or_else(|_| Picker::halfblocks())),
            #[cfg(feature = "images")]
            image_cache: HashMap::new(),
            current_tab: MainTab::Parameters,
            tree_nodes: Vec::new(),
            selected_tree_idx: 0,
            content_items: Vec::new(),
            selected_content_idx: 0,
            content_scroll_offset: 0,
            visible_param_count: 0,
            visible_obj_count: 0,
            content_dirty: false,
            com_objects_dirty: false,
            memory_dirty: false,
            com_object_rows: Vec::new(),
            selected_obj_idx: 0,
            comm_obj_scroll_offset: 0,
            memory_segments: Vec::new(),
            selected_segment_idx: 0,
            memory_scroll_offset: 0,
            selected_byte_offset: 0,
            focus: Focus::Tabs,
            edit_mode: EditMode::None,
            expanded_nodes: std::collections::HashSet::new(),
            should_quit: false,
            status_message: None,
            mods_export_path: None,
            mods_device_section: None,
            language_context: None,
            current_language: None,
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
        let baggage_index = self.device.baggage_index()?;
        let picker = self.image_picker.as_mut()?;
        let baggage = baggage_index.get(ref_id)?;

        if !baggage.exists() {
            return None;
        }

        // Load the image
        let dyn_img = image::open(baggage.file_path()).ok()?;
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
                VisibleNodeType::Channel { index } => {
                    // For channels, interpolate {{0}} with TextParameterRefId
                    if let Some(channel) = dynamic.channels.get(*index) {
                        self.device.interpolate_channel_text(&node.raw_name, channel.text_parameter_ref_id.as_deref())
                    } else {
                        self.device.interpolate_text(&node.raw_name)
                    }
                }
                VisibleNodeType::ParameterBlock { .. } => self.device.interpolate_text(&node.raw_name),
                VisibleNodeType::Module { instance_id } => {
                    // For modules, get the expanded module and interpolate with its args
                    self.interpolate_module_name(instance_id, &node.raw_name)
                }
            };

            // Convert to NodeType
            let node_type = match &node.node_type {
                VisibleNodeType::DeviceSettings => NodeType::DeviceSettings,
                VisibleNodeType::Channel { index } => NodeType::Channel(*index),
                VisibleNodeType::ParameterBlock { block_name } => {
                    // Determine parent from node id
                    let parent = if node.id.starts_with("channel_") {
                        // Extract channel index from id like "channel_0_block_foo"
                        node.id.strip_prefix("channel_").and_then(|s| s.split('_').next()).and_then(|s| s.parse().ok())
                    } else {
                        None
                    };
                    NodeType::ParameterBlock { parent, block_name: block_name.clone() }
                }
                VisibleNodeType::Module { instance_id } => {
                    // Determine parent from node id
                    let parent = if node.id.starts_with("channel_") {
                        node.id.strip_prefix("channel_").and_then(|s| s.split('_').next()).and_then(|s| s.parse().ok())
                    } else {
                        None
                    };
                    NodeType::ModuleInstance { instance_id: instance_id.clone(), parent }
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
                VisibleNodeType::Module { instance_id } => self.interpolate_module_name(instance_id, &child.raw_name),
                _ => child.raw_name.clone(),
            };

            let node_type = match &child.node_type {
                VisibleNodeType::ParameterBlock { block_name } => {
                    let parent = if child.id.starts_with("channel_") {
                        child.id.strip_prefix("channel_").and_then(|s| s.split('_').next()).and_then(|s| s.parse().ok())
                    } else {
                        None
                    };
                    NodeType::ParameterBlock { parent, block_name: block_name.clone() }
                }
                VisibleNodeType::Module { instance_id } => {
                    let parent = if child.id.starts_with("channel_") {
                        child.id.strip_prefix("channel_").and_then(|s| s.split('_').next()).and_then(|s| s.parse().ok())
                    } else {
                        None
                    };
                    NodeType::ModuleInstance { instance_id: instance_id.clone(), parent }
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
                    if let Some(zweidraehte_knxprod::runtime::model::ModuleArgValue::Numeric(ch)) =
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
        use zweidraehte_knxprod::runtime::model::Condition;
        value.is_some_and(|v| Condition::parse(test).is_some_and(|c| c.matches(v)))
    }

    fn add_cib_blocks_to_tree(&mut self, cib: &ChannelIndependentBlock, depth: usize) {
        let mut blocks = Vec::new();
        self.collect_visible_cib_blocks(cib, &mut blocks);

        for pb in blocks {
            let block_name = pb.name.clone().unwrap_or_else(|| pb.id.clone());
            let block_id = format!("device_block_{}", block_name);
            let raw_text = self
                .device
                .active_block_rename(&pb.id)
                .map(str::to_string)
                .or_else(|| pb.text.clone())
                .unwrap_or_else(|| block_name.clone());
            let text = self.device.interpolate_text(&raw_text);

            self.tree_nodes.push(TreeNode {
                id: block_id,
                name: text,
                depth,
                expanded: false,
                has_children: false,
                node_type: NodeType::ParameterBlock { parent: None, block_name },
            });
        }
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

    fn add_channel_blocks_to_tree(&mut self, channel: &Channel, channel_idx: usize, depth: usize) {
        // Add parameter blocks
        let mut blocks = Vec::new();
        self.collect_visible_channel_blocks(channel, &mut blocks);

        for pb in blocks {
            let block_name = pb.name.clone().unwrap_or_else(|| pb.id.clone());
            let block_id = format!("channel_{}_block_{}", channel_idx, block_name);
            let raw_text = self
                .device
                .active_block_rename(&pb.id)
                .map(str::to_string)
                .or_else(|| pb.text.clone())
                .unwrap_or_else(|| block_name.clone());
            let text = self.device.interpolate_text(&raw_text);

            self.tree_nodes.push(TreeNode {
                id: block_id,
                name: text,
                depth,
                expanded: false,
                has_children: false,
                node_type: NodeType::ParameterBlock { parent: Some(channel_idx), block_name },
            });
        }

        // Add visible module instances
        let mut modules = Vec::new();
        self.collect_visible_channel_modules(channel, &mut modules);

        for module in modules {
            // Get module name from expanded module data
            let expanded = self.device.get_expanded_module(&module.id);
            let name = if let Some(exp) = expanded {
                // Try to build a friendly display name from the module's Dynamic section
                if let Some(module_def) = self.device.get_module_def(&exp.module_def_id) {
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
                        // Find the ParameterRef to get the parameter ID
                        let param_ref = module_def
                            .static_section
                            .parameter_refs
                            .as_ref()
                            .and_then(|refs| refs.refs.iter().find(|pr| pr.id == ref_id));

                        param_ref.and_then(|pr| {
                            // Build composite ID and look up value
                            let composite_id = format!("{}::{}", exp.instance_id, pr.ref_id);
                            self.device.get_module_parameter_value_by_composite_id(&composite_id).and_then(
                                |v| match v {
                                    ParameterValue::Text(s) if !s.is_empty() => Some(s.clone()),
                                    ParameterValue::Integer(i) => Some(i.to_string()),
                                    _ => None,
                                },
                            )
                        })
                    });

                    if let Some(text) = block_text {
                        // Interpolate {{ChNo}} and {{0}} in the text
                        self.device.interpolate_module_text_with_param(&text, exp, text_param_value.as_deref())
                    } else if let Some(instance_name) = &exp.name {
                        self.device.interpolate_module_text(instance_name, exp)
                    } else {
                        // Fallback: use module name with channel number
                        if let Some(zweidraehte_knxprod::runtime::model::ModuleArgValue::Numeric(ch)) =
                            exp.args.get("ChNo")
                        {
                            format!("{} {}", module_def.name, ch)
                        } else {
                            module_def.name.clone()
                        }
                    }
                } else if let Some(instance_name) = &exp.name {
                    self.device.interpolate_module_text(instance_name, exp)
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
                node_type: NodeType::ModuleInstance { instance_id: module.id.clone(), parent: Some(channel_idx) },
            });
        }
    }

    fn block_has_visible_items(&self, items: &[ParameterBlockItem]) -> bool {
        for item in items {
            match item {
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
                    self.build_block_content(*parent, block_name);
                }
                NodeType::ModuleInstance { instance_id, .. } => {
                    self.build_module_content(instance_id);
                }
            }
        }
    }

    fn build_device_settings_content(&mut self) {
        let cib = self.device.dynamic_section().and_then(|d| d.channel_independent_block.clone());

        if let Some(cib) = cib {
            for item in &cib.items {
                match item {
                    ChannelIndependentItem::ParameterBlockRename(_) => {}
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
        let channel = self.device.dynamic_section().and_then(|d| d.channels.get(channel_idx).cloned());

        if let Some(channel) = channel {
            for item in &channel.items {
                match item {
                    ChannelItem::ParameterBlockRename(_) => {}
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
        let dynamic = self.device.dynamic_section().cloned();

        if let Some(dynamic) = dynamic {
            match parent {
                None => {
                    // Device settings block
                    if let Some(cib) = &dynamic.channel_independent_block
                        && let Some(pb) = self.find_block_in_cib(cib, block_name)
                    {
                        self.add_block_items(&pb.items.clone());
                    }
                }
                Some(channel_idx) => {
                    if let Some(channel) = dynamic.channels.get(channel_idx)
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
        expanded: &zweidraehte_knxprod::runtime::model::ExpandedModule,
    ) {
        for item in items {
            match item {
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
        expanded: &zweidraehte_knxprod::runtime::model::ExpandedModule,
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
        expanded: &zweidraehte_knxprod::runtime::model::ExpandedModule,
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
        expanded: &zweidraehte_knxprod::runtime::model::ExpandedModule,
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
                WhenItem::Assign(_) => {}
                WhenItem::Module(_) => {}
            }
        }
    }

    /// Add a module parameter ref to content items.
    fn add_module_param_ref(&mut self, ref_id: &str, expanded: &zweidraehte_knxprod::runtime::model::ExpandedModule) {
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

        self.content_items.push(ContentItem::Parameter { param_id, text, suffix: param_suffix, widget });
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
            Some(ParameterTypeDef::TypeText(_)) => {
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
            Some(ParameterTypeDef::TypeText(_)) => {
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
                // For unknown/picture/IP types, show as read-only
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
    fn add_module_com_obj_ref(&mut self, ref_id: &str, expanded: &zweidraehte_knxprod::runtime::model::ExpandedModule) {
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
    fn find_block_in_channel<'a>(&self, channel: &'a Channel, block_name: &str) -> Option<&'a ParameterBlock> {
        for item in &channel.items {
            match item {
                ChannelItem::ParameterBlockRename(_) => {}
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

    /// Helper to find a block in when items.
    fn find_block_in_when_items<'a>(&self, items: &'a [WhenItem], block_name: &str) -> Option<&'a ParameterBlock> {
        for item in items {
            match item {
                WhenItem::ParameterBlock(pb) if pb.name.as_deref() == Some(block_name) => {
                    return Some(pb);
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

                        let suffix = self.device.get_parameter_info(&param_id).and_then(|p| p.suffix.clone());

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

                        let suffix = self.device.get_parameter_info(&param_id).and_then(|p| p.suffix.clone());

                        let widget = self.build_widget_for_param(&param_id, pref.access.as_deref());

                        self.content_items.push(ContentItem::Parameter { param_id, text, suffix, widget });
                    }
                }
                WhenItem::ParameterSeparator(sep) => {
                    let text = sep.text.as_ref().map(|t| self.device.interpolate_text(t));
                    self.content_items.push(ContentItem::Separator { text, ui_hint: sep.ui_hint.clone() });
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
        let value = self.device.get_parameter_value(param_id);

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
                if read_only { WidgetType::ReadOnly { value: val } } else { WidgetType::Text { value: val } }
            }
            Some(ParameterTypeDef::TypeNone(_)) | Some(ParameterTypeDef::TypeIpAddress(_)) | None => {
                WidgetType::ReadOnly { value: "—".to_string() }
            }
            // TypePicture should be handled separately - shouldn't reach here
            Some(ParameterTypeDef::TypePicture(_)) => WidgetType::ReadOnly { value: "[picture]".to_string() },
        }
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

        // Add comm objects from main device
        let visible_refs: Vec<_> = self.device.visible_com_object_refs().cloned().collect();

        for oref in visible_refs {
            if let Some(obj) = self.device.get_com_object(&oref.ref_id) {
                let raw_name = oref.text.clone().unwrap_or_else(|| obj.text.clone());
                let name = self.device.interpolate_text(&raw_name);
                let raw_function = oref.function_text.clone().unwrap_or_else(|| obj.function_text.clone());
                let function = self.device.interpolate_text(&raw_function);

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

                // Get group address binding if any
                let group_address = self.format_group_address(obj.number);

                self.com_object_rows.push(ComObjectRow {
                    number: obj.number,
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

    /// Get the table flavour for address table from mask version.
    fn get_address_table_flavour(&self) -> TableFlavour {
        self.get_mask_version()
            .and_then(|mv| mv.address_table())
            .and_then(|r| r.resource_type.as_ref())
            .and_then(|rt| rt.flavour.as_ref())
            .map(|f| TableFlavour::parse_flavour(f))
            .unwrap_or(TableFlavour::AddressTableSystemB)
    }

    /// Get the table flavour for association table from mask version.
    fn get_association_table_flavour(&self) -> TableFlavour {
        self.get_mask_version()
            .and_then(|mv| mv.association_table())
            .and_then(|r| r.resource_type.as_ref())
            .and_then(|rt| rt.flavour.as_ref())
            .map(|f| TableFlavour::parse_flavour(f))
            .unwrap_or(TableFlavour::AssociationTableSystemB)
    }

    /// Rebuild memory segments from the Code section in the ApplicationProgram.
    pub fn rebuild_memory_segments(&mut self) {
        use base64::Engine;
        self.memory_dirty = false;
        self.memory_segments.clear();

        // Get Code section from static section
        let code = match &self.device.static_section().code {
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
                annotation_index: Vec::new(),
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
                annotation_index: Vec::new(),
            });
        }

        // Generate synthetic tables for Address Table (ADT), Association Table (AST), and ComObject Table (COT)
        self.generate_address_table();
        self.generate_association_table();
        self.generate_com_object_table();

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
        let static_section = &self.device.static_section();

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
        if let Some(code_segment) = &at.code_segment
            && let Some(seg_idx) = self.memory_segments.iter().position(|s| s.id == *code_segment)
        {
            // Add annotations to existing segment
            let annotations = self.build_address_table_annotations(offset, &flavour);
            self.memory_segments[seg_idx].annotations.extend(annotations);
            return;
        }

        // Create a standalone synthetic segment (for System B or if segment not found)
        // Use real assigned group addresses instead of placeholders
        let group_addresses = self.device.all_group_addresses();
        let addr_count = group_addresses.len() as u16;

        // Build table data based on flavour
        let mut data = Vec::with_capacity(count_size + (addr_count as usize) * entry_size);

        // Count field (size depends on flavour)
        if count_size == 1 {
            data.push(addr_count as u8);
        } else {
            data.push((addr_count >> 8) as u8);
            data.push((addr_count & 0xFF) as u8);
        }

        // Write actual group addresses (or 0x0000 if none assigned)
        for addr in &group_addresses {
            let bytes = addr.to_bytes();
            data.push(bytes[0]);
            data.push(bytes[1]);
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
            annotation_index: Vec::new(),
        });
    }

    /// Build annotations for Address Table entries.
    fn build_address_table_annotations(&self, base_offset: u32, flavour: &TableFlavour) -> Vec<MemoryAnnotation> {
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

        // Use real group addresses for annotations
        let group_addresses = self.device.all_group_addresses();
        for (idx, addr) in group_addresses.iter().enumerate() {
            annotations.push(MemoryAnnotation {
                offset: base_offset + count_size + (idx as u32 * entry_size),
                bit_offset: 0,
                name: format!("ADT[{}] {}", idx + 1, addr), // 1-based TSAP
                size_bits: (entry_size * 8) as u16,
                param_id: String::new(),
            });
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
        let static_section = &self.device.static_section();

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
        if let Some(code_segment) = &at.code_segment
            && let Some(seg_idx) = self.memory_segments.iter().position(|s| s.id == *code_segment)
        {
            // Add annotations to existing segment
            let annotations = self.build_association_table_annotations(offset, &flavour);
            self.memory_segments[seg_idx].annotations.extend(annotations);
            return;
        }

        // Create a standalone synthetic segment using real association entries
        let association_entries = self.device.build_association_entries();
        let entry_count = association_entries.len() as u16;

        // Build table data based on flavour
        let mut data = Vec::with_capacity(count_size + (entry_count as usize) * entry_size);

        // Count field (size depends on flavour)
        if count_size == 1 {
            data.push(entry_count as u8);
        } else {
            data.push((entry_count >> 8) as u8);
            data.push((entry_count & 0xFF) as u8);
        }

        // Write association entries: TSAP -> ASAP mappings
        for entry in &association_entries {
            if flavour.uses_u8_entries() {
                // Small format: u8 TSAP + u8 ASAP (BCU1/BCU2/M112/SystemBSmall)
                data.push(entry.tsap as u8);
                data.push(entry.asap as u8);
            } else {
                // Big format: u16 TSAP + u16 ASAP (SystemB/SystemBBig)
                data.push((entry.tsap >> 8) as u8);
                data.push((entry.tsap & 0xFF) as u8);
                data.push((entry.asap >> 8) as u8);
                data.push((entry.asap & 0xFF) as u8);
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
            annotation_index: Vec::new(),
        });
    }

    /// Build annotations for Association Table entries.
    fn build_association_table_annotations(&self, base_offset: u32, flavour: &TableFlavour) -> Vec<MemoryAnnotation> {
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

        // Use real association entries for annotations
        let association_entries = self.device.build_association_entries();
        let address_table = self.device.all_group_addresses();

        for (idx, entry) in association_entries.iter().enumerate() {
            // Get the group address from TSAP (1-based index)
            let ga_str = if entry.tsap > 0 && (entry.tsap as usize) <= address_table.len() {
                address_table[(entry.tsap - 1) as usize].to_string()
            } else {
                format!("TSAP:{}", entry.tsap)
            };

            annotations.push(MemoryAnnotation {
                offset: base_offset + count_size + (idx as u32 * entry_size),
                bit_offset: 0,
                name: format!("AST[{}] {} -> CO{}", idx, ga_str, entry.asap),
                size_bits: (entry_size * 8) as u16,
                param_id: String::new(),
            });
        }

        annotations
    }

    /// Generate the Communication Object Table (COT) as a synthetic memory segment.
    ///
    /// The COT stores type and flags for each communication object.
    /// Format: 2-byte count + N x 2-byte entries (type/size byte + flags byte)
    ///
    /// The COT is indexed by object number - object N is at position N+1 in the table
    /// (since COT uses 1-based indexing). This means if we have objects 0,1,2 and 9,10,11,
    /// we need a table with count=12, with entries at positions 1-3 and 10-12.
    ///
    /// For System 7.x devices, the table is placed within an AbsoluteSegment.
    /// For System B devices, it's loaded via a separate Load State Machine.
    fn generate_com_object_table(&mut self) {
        let static_section = &self.device.static_section();

        // Collect all comm objects with their actual numbers and type/flag data
        let cot_entries = self.collect_all_cot_entries();

        if cot_entries.is_empty() {
            return; // No communication objects to display
        }

        // Find the highest object number to determine table size
        let max_obj_num = cot_entries.iter().map(|(num, _, _)| *num).max().unwrap_or(0);
        let entry_count = max_obj_num + 1; // Object numbers are 0-indexed

        // Get ComObjectTable config if present (may be None for some devices)
        let cot_config = &static_section.com_object_table;
        let offset = cot_config.as_ref().and_then(|c| c.offset).unwrap_or(0);
        let max_entries = cot_config.as_ref().and_then(|c| c.max_entries).unwrap_or(255);

        // Check if this table references an existing code segment
        if let Some(cot) = cot_config
            && let Some(code_segment) = &cot.code_segment
            && let Some(seg_idx) = self.memory_segments.iter().position(|s| s.id == *code_segment)
        {
            // Add annotations to existing segment
            let annotations = self.build_com_object_table_annotations(offset);
            self.memory_segments[seg_idx].annotations.extend(annotations);
            return;
        }

        // Create a standalone synthetic segment
        // Build table data: 2-byte count + entry_count x 2-byte entries
        let table_size = 2 + (entry_count as usize) * 2;
        let mut data = vec![0u8; table_size];

        // Count field (2 bytes, big-endian)
        data[0] = (entry_count >> 8) as u8;
        data[1] = (entry_count & 0xFF) as u8;

        // Place each entry at its correct position
        // Object number N goes at offset 2 + N*2 (since count is at offset 0-1)
        for (obj_num, type_byte, flags) in &cot_entries {
            let entry_offset = 2 + (*obj_num as usize) * 2;
            if entry_offset + 1 < data.len() {
                data[entry_offset] = *type_byte;
                data[entry_offset + 1] = *flags;
            }
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
            annotation_index: Vec::new(),
        });
    }

    /// Collect all visible comm objects with their actual numbers and COT entry data.
    /// Returns Vec of (object_number, type_byte, flags_byte).
    fn collect_all_cot_entries(&self) -> Vec<(u16, u8, u8)> {
        let mut entries = Vec::new();
        let static_section = &self.device.static_section();

        // Get ComObjectTable config for looking up base objects
        let com_objects = static_section.com_object_table.as_ref().map(|t| &t.objects).cloned().unwrap_or_default();

        // Add main device comm objects
        for com_obj_ref in self.device.visible_com_object_refs() {
            let base_obj = com_objects.iter().find(|o| o.id == com_obj_ref.ref_id);

            // For main device objects, the number comes from the base object
            let obj_num = base_obj.map(|o| o.number).unwrap_or(0);

            let size_str = com_obj_ref
                .object_size
                .clone()
                .or_else(|| base_obj.map(|o| o.object_size.clone()))
                .unwrap_or_else(|| "1 Byte".to_string());

            let type_byte = self.object_size_to_type_byte(&size_str);
            let flags = self.build_com_object_flags(com_obj_ref, base_obj);

            entries.push((obj_num, type_byte, flags));
        }

        // Add module comm objects
        let visible_modules: Vec<_> = self.device.visible_modules().cloned().collect();

        for expanded in &visible_modules {
            let module_def = match self.device.get_module_def(&expanded.module_def_id) {
                Some(def) => def.clone(),
                None => continue,
            };

            let com_obj_refs = match &module_def.static_section.com_object_refs {
                Some(refs) => &refs.refs,
                None => continue,
            };

            let module_com_objects = match &module_def.static_section.com_objects {
                Some(objs) => &objs.objects,
                None => continue,
            };

            for oref in com_obj_refs {
                let obj = match module_com_objects.iter().find(|o| o.id == oref.ref_id) {
                    Some(o) => o,
                    None => continue,
                };

                // Compute actual object number using BaseNumber argument
                let actual_number = compute_module_object_number(obj, expanded, &module_def);

                let size_str = oref.object_size.clone().unwrap_or_else(|| obj.object_size.clone());

                let type_byte = self.object_size_to_type_byte(&size_str);
                let flags = self.build_module_com_object_flags(oref, obj);

                entries.push((actual_number, type_byte, flags));
            }
        }

        entries
    }

    /// Build flags byte for a module comm object.
    fn build_module_com_object_flags(&self, oref: &ComObjectRef, obj: &ComObject) -> u8 {
        let mut flags: u8 = 0;

        // Communication flag (bit 2)
        if oref.communication_flag.unwrap_or(obj.communication_flag) == EnableFlag::Enabled {
            flags |= 0x04;
        }

        // Read flag (bit 3)
        if oref.read_flag.unwrap_or(obj.read_flag) == EnableFlag::Enabled {
            flags |= 0x08;
        }

        // Write flag (bit 4)
        if oref.write_flag.unwrap_or(obj.write_flag) == EnableFlag::Enabled {
            flags |= 0x10;
        }

        // Transmit flag (bit 5)
        if oref.transmit_flag.unwrap_or(obj.transmit_flag) == EnableFlag::Enabled {
            flags |= 0x20;
        }

        // Update flag (bit 6)
        if oref.update_flag.unwrap_or(obj.update_flag) == EnableFlag::Enabled {
            flags |= 0x40;
        }

        // Read on init flag (bit 7)
        if oref.read_on_init_flag.unwrap_or(obj.read_on_init_flag) == EnableFlag::Enabled {
            flags |= 0x80;
        }

        flags
    }

    /// Build annotations for ComObject Table entries.
    ///
    /// The COT format depends on the mask version:
    /// - System 7.x (MV-0705, etc.): 4 bytes per entry (no count header)
    ///   Format: [RAM_ptr_lo, RAM_ptr_hi, flags, type]
    /// - System B (MV-07B0): 2-byte count + 2 bytes per entry
    ///   Format: [count_lo, count_hi] + N × [type, flags]
    fn build_com_object_table_annotations(&self, base_offset: u32) -> Vec<MemoryAnnotation> {
        let mut annotations = Vec::new();

        // Determine format based on mask version
        let mask_version = &self.device.mask_version().to_string();
        let is_system_7x = mask_version.starts_with("MV-07") && !mask_version.ends_with("B0");

        if is_system_7x {
            // System 7.x: 4 bytes per entry, no count header
            // Format: [RAM_ptr_lo, RAM_ptr_hi, flags, type] per entry
            // The RAM pointer indicates where the object's value is stored at runtime
            for (idx, com_obj_ref) in (0_u32..).zip(self.device.visible_com_object_refs()) {
                let name = com_obj_ref.text.clone().unwrap_or_else(|| com_obj_ref.name.clone().unwrap_or_default());

                // Include assigned group address in annotation if present
                let ga_info = self.format_group_address(idx as u16);

                // Get object size for display
                let size_str = com_obj_ref.object_size.as_deref().unwrap_or("?");

                let full_name = if ga_info.is_empty() {
                    format!("CO[{}] {} ({})", idx, name, size_str)
                } else {
                    format!("CO[{}] {} ({}) GA:{}", idx, name, size_str, ga_info)
                };

                annotations.push(MemoryAnnotation {
                    offset: base_offset + (idx * 4),
                    bit_offset: 0,
                    name: full_name,
                    size_bits: 32, // 4 bytes: RAM_ptr(2) + flags(1) + type(1)
                    param_id: com_obj_ref.id.clone(),
                });
            }
        } else {
            // System B: 2-byte count header + 2 bytes per entry
            // Format: [count_lo, count_hi] + N × [type, flags]
            annotations.push(MemoryAnnotation {
                offset: base_offset,
                bit_offset: 0,
                name: "COT: Entry Count".to_string(),
                size_bits: 16,
                param_id: String::new(),
            });

            for (idx, com_obj_ref) in (0_u32..).zip(self.device.visible_com_object_refs()) {
                let name = com_obj_ref.text.clone().unwrap_or_else(|| com_obj_ref.name.clone().unwrap_or_default());

                // Include assigned group address in annotation if present
                let ga_info = self.format_group_address(idx as u16);

                // Get object size for display
                let size_str = com_obj_ref.object_size.as_deref().unwrap_or("?");

                let full_name = if ga_info.is_empty() {
                    format!("CO[{}] {} ({})", idx, name, size_str)
                } else {
                    format!("CO[{}] {} ({}) GA:{}", idx, name, size_str, ga_info)
                };

                annotations.push(MemoryAnnotation {
                    offset: base_offset + 2 + (idx * 2),
                    bit_offset: 0,
                    name: full_name,
                    size_bits: 16, // 2 bytes: type(1) + flags(1)
                    param_id: com_obj_ref.id.clone(),
                });
            }
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
    fn build_com_object_flags(&self, obj_ref: &ComObjectRef, base_obj: Option<&ComObject>) -> u8 {
        let mut flags: u8 = 0;

        // Communication flag (bit 2)
        let comm =
            obj_ref.communication_flag.or(base_obj.map(|o| o.communication_flag)).unwrap_or(EnableFlag::Disabled);
        if comm == EnableFlag::Enabled {
            flags |= 0x04;
        }

        // Read flag (bit 3)
        let read = obj_ref.read_flag.or(base_obj.map(|o| o.read_flag)).unwrap_or(EnableFlag::Disabled);
        if read == EnableFlag::Enabled {
            flags |= 0x08;
        }

        // Write flag (bit 4)
        let write = obj_ref.write_flag.or(base_obj.map(|o| o.write_flag)).unwrap_or(EnableFlag::Disabled);
        if write == EnableFlag::Enabled {
            flags |= 0x10;
        }

        // Transmit flag (bit 5)
        let transmit = obj_ref.transmit_flag.or(base_obj.map(|o| o.transmit_flag)).unwrap_or(EnableFlag::Disabled);
        if transmit == EnableFlag::Enabled {
            flags |= 0x20;
        }

        // Update flag (bit 6)
        let update = obj_ref.update_flag.or(base_obj.map(|o| o.update_flag)).unwrap_or(EnableFlag::Disabled);
        if update == EnableFlag::Enabled {
            flags |= 0x40;
        }

        // Read on init flag (bit 7)
        let read_init =
            obj_ref.read_on_init_flag.or(base_obj.map(|o| o.read_on_init_flag)).unwrap_or(EnableFlag::Disabled);
        if read_init == EnableFlag::Enabled {
            flags |= 0x80;
        }

        flags
    }

    /// Apply current parameter values to a memory segment's data buffer.
    fn apply_parameter_values_to_segment(&self, segment_id: &str, data: &mut [u8]) {
        // Apply main static section parameters
        if let Some(params) = &self.device.static_section().parameters {
            self.apply_params_to_segment(&params.items, segment_id, data, None);
        }

        // Apply module parameter values
        for expanded in self.device.all_expanded_modules() {
            if let Some(module_def) = self.device.get_module_def(&expanded.module_def_id) {
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
        items: &[ParameterItem],
        segment_id: &str,
        data: &mut [u8],
        base_offset_info: Option<(u32, &str)>,
    ) {
        for item in items {
            if let ParameterItem::Parameter(param) = item {
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
                        self.device.get_module_parameter_value_by_composite_id(&composite_id)
                    } else {
                        self.device.get_parameter_value(&param.id)
                    };

                    if let Some(value) = value {
                        let size_bits = self.get_parameter_size_bits(&param.parameter_type);
                        self.write_value_to_memory(data, actual_offset as usize, memory.bit_offset, size_bits, value);
                    }
                }
            } else if let ParameterItem::Union(union) = item {
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
                        self.device.get_module_parameter_value_by_composite_id(&composite_id)
                    } else {
                        self.device.get_parameter_value(&param.id)
                    };

                    if let Some(value) = value {
                        let size_bits = self.get_parameter_size_bits(&param.parameter_type);
                        let offset = union_base_offset + param.offset as u32;
                        let bit_offset = memory.bit_offset + param.bit_offset;
                        self.write_value_to_memory(data, offset as usize, bit_offset, size_bits, value);
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
        value: &zweidraehte_knxprod::runtime::model::ParameterValue,
    ) {
        // Skip if no bits to write (e.g., picture types)
        if size_bits == 0 {
            return;
        }

        // Convert value to integer (most parameters are integer-based)
        let int_value: u64 = match value {
            zweidraehte_knxprod::runtime::model::ParameterValue::Integer(v) => *v as u64,
            zweidraehte_knxprod::runtime::model::ParameterValue::Float(v) => {
                // For float, assume DPT9 encoding (2 bytes)
                // Simplified: just cast to u64 for now
                (*v as i64) as u64
            }
            zweidraehte_knxprod::runtime::model::ParameterValue::Text(s) => {
                // For text, write raw bytes
                let bytes = s.as_bytes();
                let max_bytes = (size_bits as usize).div_ceil(8);
                for (i, &b) in bytes.iter().take(max_bytes).enumerate() {
                    if byte_offset + i < data.len() {
                        data[byte_offset + i] = b;
                    }
                }
                return;
            }
            zweidraehte_knxprod::runtime::model::ParameterValue::Bytes(bytes) => {
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
        if bit_offset == 0 && size_bits.is_multiple_of(8) {
            // Simple byte-aligned write
            let num_bytes = (size_bits / 8) as usize;
            // Clamp to max 8 bytes (64 bits) since we use u64
            let num_bytes = num_bytes.min(8);
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
            let total_bits = (size_bits as usize).min(64); // Clamp to 64 bits
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
        expanded: &zweidraehte_knxprod::runtime::model::ExpandedModule,
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
        if let Some(zweidraehte_knxprod::runtime::model::ModuleArgValue::Numeric(val)) =
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
        expanded: &zweidraehte_knxprod::runtime::model::ExpandedModule,
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
            && let Some(zweidraehte_knxprod::runtime::model::ModuleArgValue::Numeric(val)) =
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
        if let Some(pt) = self.device.get_parameter_type(type_id) {
            match &pt.type_def {
                ParameterTypeDef::TypeNumber(tn) => tn.size_in_bit as u16,
                ParameterTypeDef::TypeRestriction(tr) => tr.size_in_bit as u16,
                ParameterTypeDef::TypeText(tt) => (tt.size_in_bit) as u16,
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
            (_, Focus::Tabs) => self.prev_tab(),
            (MainTab::Parameters, Focus::Sidebar) => {
                // Collapse the selected tree node
                if let Some(node) = self.tree_nodes.get(self.selected_tree_idx)
                    && node.has_children
                    && self.expanded_nodes.contains(&node.id)
                {
                    self.expanded_nodes.remove(&node.id);
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
            (_, Focus::Tabs) => self.next_tab(),
            (MainTab::Parameters, Focus::Sidebar) => {
                // Expand the selected tree node
                if let Some(node) = self.tree_nodes.get(self.selected_tree_idx)
                    && node.has_children
                    && !self.expanded_nodes.contains(&node.id)
                {
                    self.expanded_nodes.insert(node.id.clone());
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
            EditMode::NumberInput { param_id, buffer, min, max } => {
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
            EditMode::GroupAddressInput { object_number, buffer } => {
                // Parse and assign the group addresses: several may be
                // given, separated by commas or spaces; the first one
                // becomes the sending address, the rest listen.
                let object_number = *object_number;
                let buffer = buffer.clone();

                // Clear existing addresses for this object first
                self.device.clear_group_addresses(object_number);

                for part in buffer.split([',', ' ']).filter(|p| !p.is_empty()) {
                    if let Some(addr) = zweidraehte_knxprod::runtime::model::GroupAddress::parse(part) {
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
            }
            EditMode::None => match (self.current_tab, self.focus) {
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
    /// new language applied, then restores the session's edits through
    /// the mods machinery — parameter values, group links and the
    /// touched-tracking all survive.
    pub fn switch_language(&mut self, next: Option<String>) {
        let Some(context) = &self.language_context else {
            return;
        };
        if next == self.current_language {
            return;
        }

        // Snapshot the session's edits, rebuild in the new language,
        // and replay them.
        let edits = zweidraehte_knxprod::runtime::mods::mods_from_device(&self.device);
        let mut program = context.pristine.clone();
        if let Some(language) = &next {
            context.translations.apply(&mut program, language);
        }
        let mut device = Device::new(program, self.master_data.as_ref(), context.baggage.clone());
        if let Err(e) = zweidraehte_knxprod::runtime::mods::apply_mods(&mut device, &edits) {
            // Values that applied to the old device apply to the new
            // one — same program, different texts. Failing here would
            // be a bug worth seeing, not hiding.
            self.status_message = Some(format!("Language switch failed replaying edits: {e}"));
            return;
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

        self.status_message = Some(match &self.current_language {
            Some(language) => format!("Language: {language}"),
            None => format!("Language: default ({})", self.device.program().default_language),
        });
    }

    /// Remember the mods file the session started from: `e` exports
    /// back to it, and its `[device]` section (the individual
    /// address) survives the round trip.
    pub fn set_mods_context(
        &mut self,
        path: std::path::PathBuf,
        device_section: zweidraehte_knxprod::runtime::mods::DeviceSection,
    ) {
        self.mods_export_path = Some(path);
        self.mods_device_section = Some(device_section);
    }

    /// Start programming the device: snapshot the session's
    /// configuration, spawn the worker, open the popup.
    pub fn start_download(&mut self) {
        if self.download.as_ref().is_some_and(|d| d.result.is_none()) {
            return; // already running
        }
        let Some(target) = self.download_context.as_ref().and_then(|c| c.target.clone()) else {
            self.status_message = Some("Start the TUI with --server or --usb to program the device".to_string());
            return;
        };
        let Some(section) = self.mods_device_section.clone() else {
            self.status_message =
                Some("Load a mods file (--mods) carrying the device's individual_address first".to_string());
            return;
        };
        let ia = match zweidraehte_client::cli::parse_ia(&section.individual_address) {
            Ok(ia) => ia,
            Err(e) => {
                self.status_message = Some(format!("The mods file's individual_address is unusable: {e}"));
                return;
            }
        };

        // The session's configuration, exactly as `e` would export it.
        let mut mods = zweidraehte_knxprod::runtime::mods::mods_from_device(&self.device);
        mods.device = section;
        // The worker rebuilds its own device; texts are irrelevant, so
        // the pristine program (when a language is active) serves.
        let program = self
            .language_context
            .as_ref()
            .map(|ctx| ctx.pristine.clone())
            .unwrap_or_else(|| self.device.program().clone());

        let (tx, rx) = std::sync::mpsc::channel();
        crate::download::spawn(
            crate::download::DownloadJob {
                target,
                ia,
                mods,
                program,
                master_data: self.download_context.as_ref().and_then(|c| c.master_data.clone()),
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

    /// Export the diff-from-defaults as a mods file — back to the
    /// `--mods` file this session loaded, else to
    /// `<program id>-mods.toml`; the same format `knx-dump` emits and
    /// `knx-loader` consumes.
    pub fn export_mods(&mut self) {
        let mut mods = zweidraehte_knxprod::runtime::mods::mods_from_device(&self.device);
        mods.device = self.mods_device_section.clone().unwrap_or_else(|| {
            // The product knows nothing about the installation's
            // addressing; leave a placeholder to edit before loading.
            zweidraehte_knxprod::runtime::mods::DeviceSection {
                individual_address: "1.1.1".to_string(),
                max_apdu: None,
            }
        });

        let path = self
            .mods_export_path
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from(format!("{}-mods.toml", self.device.program().id)));
        let result = toml::to_string_pretty(&mods)
            .map_err(|e| e.to_string())
            .and_then(|text| std::fs::write(&path, text).map_err(|e| e.to_string()));
        // Only a placeholder address needs the reminder; a section
        // carried in from --mods is already the installation's.
        let hint = if self.mods_device_section.is_some() { "" } else { " — set individual_address before loading" };
        self.status_message = Some(match result {
            Ok(()) => format!(
                "Exported {} parameter(s), {} link(s) to {}{hint}",
                mods.params.len(),
                mods.links.len(),
                path.display()
            ),
            Err(e) => format!("Export failed: {e}"),
        });
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
                    self.edit_mode =
                        EditMode::NumberInput { param_id, buffer: value.to_string(), min: *min, max: *max };
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

    /// Handle character input for editing.
    pub fn handle_char(&mut self, c: char) {
        match &mut self.edit_mode {
            EditMode::NumberInput { buffer, .. }
                if (c.is_ascii_digit() || (c == '-' && buffer.is_empty())) => {
                    buffer.push(c);
                }
            EditMode::TextInput { buffer, cursor, .. } => {
                buffer.insert(*cursor, c);
                *cursor += 1;
            }
            EditMode::GroupAddressInput { buffer, .. }
                // Digits and slashes for the addresses themselves,
                // commas/spaces to separate several of them
                if (c.is_ascii_digit() || c == '/' || c == ',' || c == ' ') => {
                    buffer.push(c);
                }
            _ => {}
        }
    }

    /// Handle backspace for editing.
    pub fn handle_backspace(&mut self) {
        match &mut self.edit_mode {
            EditMode::NumberInput { buffer, .. } | EditMode::GroupAddressInput { buffer, .. } => {
                buffer.pop();
            }
            EditMode::TextInput { buffer, cursor, .. } if *cursor > 0 => {
                *cursor -= 1;
                buffer.remove(*cursor);
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
