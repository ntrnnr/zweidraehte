//! Application coordinator: explicit product, project, navigation and operation owners.

use crate::catalog_view::{CatalogAddRequest, CatalogProjectDefaults, PackageCatalogView, ProjectCatalogDialog};
use crate::project_view::{ProjectKeyEditor, ProjectNavigation, ProjectNavigationTarget, ProjectOverview};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use zweidraehte_client::commissioning::ImageRequirement;
use zweidraehte_client::project::Error as ProjectError;
#[cfg(test)]
use zweidraehte_client::project::{ProgrammingSnapshot, ProjectStatusCache};
use zweidraehte_ets_files::archive::{PackageCatalogIndex, PackageCatalogSelector};
#[cfg(test)]
use zweidraehte_ets_files::product::SelectedProduct;
#[cfg(test)]
use zweidraehte_ets_files::runtime::configuration::ProductConfiguration;
use zweidraehte_ets_files::runtime::model::ParameterValue;
use zweidraehte_project::{
    AuthoredProject, DataSecureMode, DeviceProgrammingStatus, NetId, ObjectFlagOverrides, ProjectDeviceId,
};
use zweidraehte_proto::address::GroupAddress;

mod editor;
mod operations;
pub use operations::{
    AssignmentPrompt, DeviceOperation, DownloadContext, DownloadUi, OperationUi, ProgrammingDialog, ProgrammingTarget,
};
mod project;
use project::{ProjectEditor, StartupStatusUi};
#[cfg(test)]
use project::{group_keys_to_materialize, project_dpt};
mod product;
pub use editor::{EditorDocument, PreparedEditorProduct};
use product::ProductEditor;
pub use product::{
    ComObjectRow, ContentItem, LanguageContext, MemoryAnnotation, MemorySegment, NodeType, ParameterTable,
    ParameterTableCell, ParameterTableColumn, ParameterTableRow, ProductView, TreeBuilderVisitor, TreeNode,
    VisibleNodeType, VisibleTreeNode, WidgetType, image_requirements_label,
};

#[cfg(feature = "images")]
use ratatui_image::protocol::StatefulProtocol;

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
}

/// Project-local editor state that is not part of the authored KNX project.
///
/// Storing this below `.zweidraehte/` avoids changing `project.knx` whenever
/// someone opens the project with different display preferences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TuiPreferences {
    panes: PaneLayout,
    highlight_non_default_parameters: bool,
}

impl Default for TuiPreferences {
    fn default() -> Self {
        Self { panes: PaneLayout::default(), highlight_non_default_parameters: true }
    }
}

impl TuiPreferences {
    const STATE_FILE: &'static str = "tui.toml";

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
            panes: PaneLayout {
                project_width: pane_dimension(&document, "project_width", defaults.panes.project_width, 24, 60, &path)?,
                topology_percent: pane_dimension(
                    &document,
                    "topology_percent",
                    defaults.panes.topology_percent,
                    25,
                    75,
                    &path,
                )?,
                parameter_sidebar_width: pane_dimension(
                    &document,
                    "parameter_sidebar_width",
                    defaults.panes.parameter_sidebar_width,
                    18,
                    60,
                    &path,
                )?,
                memory_sidebar_width: pane_dimension(
                    &document,
                    "memory_sidebar_width",
                    defaults.panes.memory_sidebar_width,
                    20,
                    60,
                    &path,
                )?,
            },
            highlight_non_default_parameters: boolean_preference(
                &document,
                "parameters",
                "highlight_non_default",
                defaults.highlight_non_default_parameters,
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
        document["panes"]["project_width"] = toml_edit::value(i64::from(self.panes.project_width));
        document["panes"]["topology_percent"] = toml_edit::value(i64::from(self.panes.topology_percent));
        document["panes"]["parameter_sidebar_width"] = toml_edit::value(i64::from(self.panes.parameter_sidebar_width));
        document["panes"]["memory_sidebar_width"] = toml_edit::value(i64::from(self.panes.memory_sidebar_width));
        if !document.get("parameters").is_some_and(toml_edit::Item::is_table_like) {
            document["parameters"] = toml_edit::table();
        }
        document["parameters"]["highlight_non_default"] = toml_edit::value(self.highlight_non_default_parameters);

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

fn boolean_preference(
    document: &toml_edit::DocumentMut,
    table: &str,
    name: &str,
    default: bool,
    path: &Path,
) -> Result<bool, String> {
    let Some(item) = document.get(table).and_then(toml_edit::Item::as_table_like).and_then(|table| table.get(name))
    else {
        return Ok(default);
    };

    item.as_bool().ok_or_else(|| format!("{} has a non-boolean `{table}.{name}`", path.display()))
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

fn nearest_parameter_cell(row: &ParameterTableRow, preferred_column: usize) -> Option<usize> {
    row.cells
        .get(preferred_column)
        .and_then(Option::as_ref)
        .filter(|cell| cell.is_parameter())
        .map(|_| preferred_column)
        .or_else(|| {
            row.cells
                .iter()
                .enumerate()
                .filter(|(_, cell)| cell.as_ref().is_some_and(ParameterTableCell::is_parameter))
                .min_by_key(|(column, _)| column.abs_diff(preferred_column))
                .map(|(column, _)| column)
        })
}

/// Persistent context behind the product editor.
///
/// Standalone MTXML and `.knxprod` inputs intentionally have no `authored`
/// project: they are inspectable/editable previews, but project commissioning
/// is rooted exclusively in an immutable package selector from `project.knx`.
#[derive(Clone)]
pub struct ProjectContext {
    pub path: std::path::PathBuf,
    pub device: ProjectDeviceId,
    pub authored: Option<AuthoredProject>,
    pub original_source: Option<String>,
}

/// Product state prepared by the binary when the project navigator opens a
/// different device. Keeping XML/archive loading outside [`App`] lets the
/// editor remain reusable without teaching its UI state about file formats.
pub struct LoadedProjectDevice {
    pub product: PreparedEditorProduct,
    pub context: ProjectContext,
    pub flags: BTreeMap<u16, ObjectFlagOverrides>,
}

/// Transient navigation, focus, selection, scrolling, and popup state.
pub struct NavigationState {
    pending_project_device: Option<ProjectDeviceId>,
    package_catalog: Option<PackageCatalogView<PackageCatalogSelector>>,
    project_overview: Option<ProjectOverview>,
    key_editor: Option<ProjectKeyEditor>,
    pub current_tab: MainTab,
    pub selected_tree_idx: usize,
    pub selected_content_idx: usize,
    /// Active `(row, column)` when the selected content item is a table.
    pub selected_table_cell: Option<(usize, usize)>,
    content_scroll_offset: usize,
    pub selected_obj_idx: usize,
    comm_obj_scroll_offset: usize,
    pub selected_segment_idx: usize,
    memory_scroll_offset: usize,
    pub selected_byte_offset: usize,
    pub focus: Focus,
    pub edit_mode: EditMode,
    expanded_nodes: std::collections::HashSet<String>,
    pub should_quit: bool,
    pub status_message: Option<String>,
    status_message_timer: Option<(String, std::time::Instant)>,
    tui_preferences: TuiPreferences,
    tui_preferences_dirty: bool,
}

/// Concrete coordinator for editor commands, rendering state, and downloads.
pub struct App {
    product: ProductEditor,
    project: ProjectEditor,
    navigation: NavigationState,
    operations: OperationUi,
    /// Package-catalog browser or add-device form.
    catalog_dialog: Option<ProjectCatalogDialog<PackageCatalogSelector>>,
    /// Validated form result awaiting source-preserving project insertion by
    /// the binary coordinator.
    pending_catalog_add: Option<CatalogAddRequest<PackageCatalogSelector>>,
}

impl App {
    const STATUS_MESSAGE_DURATION: std::time::Duration = std::time::Duration::from_secs(4);

    /// Create an editor from a fully prepared product and its metadata.
    pub fn new(product: PreparedEditorProduct) -> Self {
        let mut app = Self {
            product: ProductEditor::new(product),
            project: ProjectEditor::default(),
            navigation: NavigationState {
                pending_project_device: None,
                package_catalog: None,
                project_overview: None,
                key_editor: None,
                current_tab: MainTab::Parameters,
                selected_tree_idx: 0,
                selected_content_idx: 0,
                selected_table_cell: None,
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
                tui_preferences: TuiPreferences::default(),
                tui_preferences_dirty: false,
            },
            operations: OperationUi::default(),
            catalog_dialog: None,
            pending_catalog_add: None,
        };

        // Build initial data
        app.rebuild_tree();
        app.rebuild_content();
        app.rebuild_com_objects();

        app
    }

    fn start_startup_status_refresh(&mut self) {
        self.project.refresh(self.operations.download_context.as_ref());
    }
    fn clear_programming_statuses(&mut self) {
        self.project.invalidate();
    }
    pub fn stage_current_project_device(&mut self) -> Result<ProjectContext, String> {
        self.project.stage(self.product.view())
    }
    fn rename_net_label(&mut self, net: &NetId, name: &str) -> Result<(), String> {
        self.project.rename_net_label(net, name)
    }
    fn apply_persisted_serial_updates(
        &mut self,
        updates: &BTreeMap<ProjectDeviceId, Option<[u8; 6]>>,
    ) -> Result<(), String> {
        self.project.apply_persisted_serial_updates(updates)
    }
    fn save_project(&mut self) -> Result<(), String> {
        self.project
            .save(self.product.view(), self.operations.download_context.as_ref().map(|context| &context.security))?;
        self.start_startup_status_refresh();
        self.persist_tui_preferences()
    }
    pub fn poll_startup_status(&mut self) -> bool {
        let (changed, message) = self.project.poll_status();
        if let Some(message) = message {
            self.navigation.status_message = Some(message);
        }
        changed
    }
    pub fn set_download_context(&mut self, context: DownloadContext) {
        self.operations.download_context = Some(context);
        self.start_startup_status_refresh();
    }

    fn start_programming_status_refresh(&mut self, scope: BTreeSet<ProjectDeviceId>) {
        // Durable changes may affect any dependency. Until cross-revision reuse
        // has a proof, refresh the entire authored draft after an operation.
        if !scope.is_empty() {
            self.start_startup_status_refresh();
        }
    }

    #[cfg(feature = "images")]
    pub fn initialize_image_picker(&mut self) {
        self.product.initialize_image_picker();
    }
    #[cfg(feature = "images")]
    pub fn load_image(&mut self, id: &str) -> Option<&mut StatefulProtocol> {
        self.product.load_image(id)
    }
    #[cfg(feature = "images")]
    pub fn picture_cell_size(&mut self, id: &str, width: u16) -> Option<(u16, u16)> {
        self.product.picture_cell_size(id, width)
    }

    /// Borrow the product and its derived presentation together.
    ///
    /// Editing through this view would bypass invalidation, so even a mutable
    /// `App` only lends shared product access:
    /// ```compile_fail,E0596
    /// use knxproj_tui::app::App;
    /// use zweidraehte_ets_files::runtime::model::ParameterValue;
    /// fn edit_without_invalidation(app: &mut App) {
    ///     app.product_view().device.set_parameter_value("P-1", ParameterValue::Integer(1));
    /// }
    /// ```
    pub fn product_view(&self) -> &ProductView {
        self.product.view()
    }

    /// Navigation can be inspected by renderers; commands own cursor changes.
    pub fn navigation(&self) -> &NavigationState {
        &self.navigation
    }

    pub fn operations(&self) -> &OperationUi {
        &self.operations
    }

    pub fn operations_mut(&mut self) -> &mut OperationUi {
        &mut self.operations
    }

    pub fn master_data_override(&self) -> Option<&Path> {
        self.operations.download_context.as_ref().and_then(|context| context.master_data.as_deref())
    }

    pub fn pane_layout(&self) -> PaneLayout {
        self.navigation.tui_preferences.panes
    }

    pub fn highlight_non_default_parameters(&self) -> bool {
        self.navigation.tui_preferences.highlight_non_default_parameters
    }

    pub fn project_navigation(&self) -> Option<&ProjectNavigation> {
        self.project.navigation()
    }

    pub fn project_programming_status(&self, device: &ProjectDeviceId) -> Option<DeviceProgrammingStatus> {
        self.project.snapshot()?.view().statuses.get(device).copied()
    }

    pub fn project_programming_requirements(&self, device: &ProjectDeviceId) -> &[ImageRequirement] {
        self.project.snapshot().and_then(|snapshot| snapshot.view().requirements.get(device)).map_or(&[], Vec::as_slice)
    }

    pub fn project_overview(&self) -> Option<&ProjectOverview> {
        self.navigation.project_overview.as_ref()
    }

    pub fn key_editor(&self) -> Option<&ProjectKeyEditor> {
        self.navigation.key_editor.as_ref()
    }

    pub fn catalog_dialog(&self) -> Option<&ProjectCatalogDialog<PackageCatalogSelector>> {
        self.catalog_dialog.as_ref()
    }

    pub fn catalog_dialog_mut(&mut self) -> Option<&mut ProjectCatalogDialog<PackageCatalogSelector>> {
        self.catalog_dialog.as_mut()
    }

    pub(crate) fn startup_status(&self) -> Option<&StartupStatusUi> {
        self.project.status()
    }

    /// Keep the selected logical item visible when items occupy different
    /// numbers of terminal rows. Pictures, tables and wrapped notes make a
    /// simple item-count window incorrect.
    pub fn content_scroll_offset_for_layout(&mut self, item_heights: &[usize], viewport_rows: usize) -> usize {
        if item_heights.is_empty() {
            self.navigation.content_scroll_offset = 0;
            return 0;
        }

        let viewport_rows = viewport_rows.max(1);
        let selected = self.navigation.selected_content_idx.min(item_heights.len() - 1);
        let mut prefix = Vec::with_capacity(item_heights.len() + 1);
        prefix.push(0usize);
        for height in item_heights {
            prefix.push(prefix.last().copied().unwrap_or(0).saturating_add((*height).max(1)));
        }
        let occupied = |start: usize, end: usize| prefix[end + 1].saturating_sub(prefix[start]);

        let mut offset = self.navigation.content_scroll_offset.min(selected);
        while offset < selected && occupied(offset, selected) > viewport_rows {
            offset += 1;
        }
        while offset > 0 && occupied(offset - 1, selected) <= viewport_rows {
            offset -= 1;
        }

        self.navigation.content_scroll_offset = offset;
        offset
    }

    pub fn comm_object_scroll_offset_for(&mut self, viewport_rows: usize) -> usize {
        let selected = self.navigation.selected_obj_idx;
        keep_selection_visible(&mut self.navigation.comm_obj_scroll_offset, selected, viewport_rows.max(1));
        self.navigation.comm_obj_scroll_offset
    }

    pub fn memory_scroll_offset_for(&mut self, viewport_rows: usize) -> usize {
        let selected_line = self.navigation.selected_byte_offset / 16;
        keep_selection_visible(&mut self.navigation.memory_scroll_offset, selected_line, viewport_rows.max(1));
        self.navigation.memory_scroll_offset
    }

    pub fn is_editing(&self) -> bool {
        !matches!(self.navigation.edit_mode, EditMode::None)
    }

    pub fn request_quit(&mut self) {
        self.navigation.should_quit = true;
    }

    pub fn set_status_message(&mut self, message: impl Into<String>) {
        self.navigation.status_message = Some(message.into());
    }

    pub fn startup_status_active(&self) -> bool {
        self.project.status().is_some()
    }

    pub fn startup_status_failed(&self) -> bool {
        self.project.status().is_some_and(|status| status.error.is_some())
    }

    pub fn dismiss_startup_status(&mut self) {
        self.project.dismiss_status();
    }

    pub fn project_overview_active(&self) -> bool {
        self.navigation.project_overview.is_some()
    }

    pub fn key_editor_active(&self) -> bool {
        self.navigation.key_editor.is_some()
    }

    pub fn catalog_dialog_active(&self) -> bool {
        self.catalog_dialog.is_some()
    }

    pub fn key_editor_accepts_close(&self) -> bool {
        self.navigation.key_editor.as_ref().is_some_and(|editor| editor.input.is_none())
    }

    /// Start or advance the transient status-message timer. Returning `true`
    /// asks the event loop for one final redraw after the legend is revealed.
    pub fn poll_status_message(&mut self) -> bool {
        let Some(message) = self.navigation.status_message.as_ref() else {
            self.navigation.status_message_timer = None;
            return false;
        };
        let now = std::time::Instant::now();
        match &self.navigation.status_message_timer {
            Some((tracked, started)) if tracked == message => {
                if now.duration_since(*started) >= Self::STATUS_MESSAGE_DURATION {
                    self.navigation.status_message = None;
                    self.navigation.status_message_timer = None;
                    return true;
                }
            }
            _ => self.navigation.status_message_timer = Some((message.clone(), now)),
        }
        false
    }

    /// Move the splitter nearest the focused pane. Horizontal arrows move
    /// by two columns; vertical arrows move the project navigator's divider
    /// in five-percent steps.
    pub fn resize_focused_pane(&mut self, horizontal: i16, vertical: i16) {
        let previous = self.navigation.tui_preferences.panes;
        let current_tab = self.navigation.current_tab;
        let focus = self.navigation.focus;
        if horizontal != 0 {
            self.navigation.tui_preferences.panes.resize_horizontal(current_tab, focus, horizontal.saturating_mul(2));
        }
        if vertical != 0 {
            self.navigation.tui_preferences.panes.resize_vertical(focus, vertical.saturating_mul(5));
        }
        self.navigation.tui_preferences_dirty |= self.navigation.tui_preferences.panes != previous;
    }

    /// Toggle the visual distinction between default and configured parameter
    /// values. This is editor state only; it never changes the product data.
    pub fn toggle_non_default_highlight(&mut self) {
        let enabled = !self.navigation.tui_preferences.highlight_non_default_parameters;
        self.navigation.tui_preferences.highlight_non_default_parameters = enabled;
        self.navigation.tui_preferences_dirty = true;
        self.navigation.status_message = Some(if enabled {
            "Non-default parameter highlighting enabled".to_string()
        } else {
            "Non-default parameter highlighting disabled".to_string()
        });
    }

    /// Switch to next main tab.
    pub fn next_tab(&mut self) {
        self.navigation.current_tab = match self.navigation.current_tab {
            MainTab::Parameters => MainTab::CommObjects,
            MainTab::CommObjects => MainTab::Memory,
            MainTab::Memory => MainTab::Parameters,
        };
        // Reset focus when switching tabs
        self.navigation.focus = Focus::Tabs;
    }

    /// Switch to previous main tab.
    pub fn prev_tab(&mut self) {
        self.navigation.current_tab = match self.navigation.current_tab {
            MainTab::Parameters => MainTab::Memory,
            MainTab::CommObjects => MainTab::Parameters,
            MainTab::Memory => MainTab::CommObjects,
        };
        self.navigation.focus = Focus::Tabs;
    }

    /// Rebuild whatever stale view the current tab is about to render.
    /// Called at the top of every frame; selections are re-clamped
    /// because a rebuild can shrink the data they point into.
    pub fn rebuild_tree(&mut self) {
        self.product.rebuild_tree(&mut self.navigation);
    }
    pub fn rebuild_content(&mut self) {
        self.product.rebuild_content(self.navigation.selected_tree_idx);
        self.normalize_selected_table_cell();
    }
    pub fn rebuild_com_objects(&mut self) {
        self.product.rebuild_com_objects();
    }
    pub fn rebuild_memory_segments(&mut self) {
        if let Some(message) = self.product.rebuild_memory_segments(self.project.context()) {
            self.navigation.status_message = Some(message);
        }
    }
    pub fn ensure_content(&mut self) {
        self.product.ensure_content(self.navigation.selected_tree_idx);
        self.normalize_selected_table_cell();
    }
    pub fn ensure_tab_data(&mut self) {
        match self.navigation.current_tab {
            MainTab::Parameters => {
                self.ensure_content();
            }
            MainTab::CommObjects => {
                self.product.ensure_com_objects();
                self.navigation.selected_obj_idx =
                    self.navigation.selected_obj_idx.min(self.product.view().com_object_rows.len().saturating_sub(1));
                self.adjust_comm_obj_scroll();
            }
            MainTab::Memory => {
                if let Some(message) = self.product.ensure_memory(self.project.context()) {
                    self.navigation.status_message = Some(message);
                }
                self.navigation.selected_segment_idx = self
                    .navigation
                    .selected_segment_idx
                    .min(self.product.view().memory_segments.len().saturating_sub(1));
                let data_len = self
                    .product
                    .view()
                    .memory_segments
                    .get(self.navigation.selected_segment_idx)
                    .map_or(0, |s| s.data.len());
                self.navigation.selected_byte_offset =
                    self.navigation.selected_byte_offset.min(data_len.saturating_sub(1));
                self.adjust_memory_scroll();
            }
        }
    }

    /// Get the annotation at a specific byte offset within the currently selected segment.
    pub fn get_annotation_at_offset(&self, byte_offset: usize) -> Option<&MemoryAnnotation> {
        let segment = self.product.view().memory_segments.get(self.navigation.selected_segment_idx)?;
        let ann_idx = *segment.annotation_index.get(byte_offset)?;
        segment.annotations.get(ann_idx as usize)
    }

    /// Navigate memory view up (by 16 bytes).
    pub fn memory_move_up(&mut self) {
        if self.navigation.selected_byte_offset >= 16 {
            self.navigation.selected_byte_offset -= 16;
            self.adjust_memory_scroll();
        }
    }

    /// Navigate memory view down (by 16 bytes).
    pub fn memory_move_down(&mut self, visible_lines: usize) {
        if let Some(seg) = self.product.view().memory_segments.get(self.navigation.selected_segment_idx) {
            let max_offset = seg.data.len().saturating_sub(1);
            if self.navigation.selected_byte_offset + 16 <= max_offset {
                self.navigation.selected_byte_offset += 16;
                self.adjust_memory_scroll_with_visible(visible_lines);
            }
        }
    }

    /// Navigate memory view left (by 1 byte).
    pub fn memory_move_left(&mut self) {
        if self.navigation.selected_byte_offset > 0 {
            self.navigation.selected_byte_offset -= 1;
            self.adjust_memory_scroll();
        }
    }

    /// Navigate memory view right (by 1 byte).
    pub fn memory_move_right(&mut self, visible_lines: usize) {
        if let Some(seg) = self.product.view().memory_segments.get(self.navigation.selected_segment_idx)
            && self.navigation.selected_byte_offset + 1 < seg.data.len()
        {
            self.navigation.selected_byte_offset += 1;
            self.adjust_memory_scroll_with_visible(visible_lines);
        }
    }

    /// Select a specific memory segment.
    pub fn select_segment(&mut self, idx: usize) {
        if idx < self.product.view().memory_segments.len() {
            self.navigation.selected_segment_idx = idx;
            self.navigation.selected_byte_offset = 0;
            self.navigation.memory_scroll_offset = 0;
        }
    }

    /// Adjust memory scroll to keep selected byte visible.
    fn adjust_memory_scroll(&mut self) {
        self.adjust_memory_scroll_with_visible(20); // Default visible lines
    }

    /// Adjust memory scroll with specific visible line count.
    fn adjust_memory_scroll_with_visible(&mut self, visible_lines: usize) {
        let current_line = self.navigation.selected_byte_offset / 16;

        // Scroll up if above visible area
        if current_line < self.navigation.memory_scroll_offset {
            self.navigation.memory_scroll_offset = current_line;
        }

        // Scroll down if below visible area
        if current_line >= self.navigation.memory_scroll_offset + visible_lines {
            self.navigation.memory_scroll_offset = current_line.saturating_sub(visible_lines - 1);
        }
    }

    /// Maximum visible rows in comm objects table
    const COMM_OBJ_VISIBLE_ROWS: usize = 20;

    /// Adjust comm object scroll to keep selected item visible.
    fn adjust_comm_obj_scroll(&mut self) {
        // Scroll up if above visible area
        if self.navigation.selected_obj_idx < self.navigation.comm_obj_scroll_offset {
            self.navigation.comm_obj_scroll_offset = self.navigation.selected_obj_idx;
        }

        // Scroll down if below visible area
        if self.navigation.selected_obj_idx >= self.navigation.comm_obj_scroll_offset + Self::COMM_OBJ_VISIBLE_ROWS {
            self.navigation.comm_obj_scroll_offset =
                self.navigation.selected_obj_idx.saturating_sub(Self::COMM_OBJ_VISIBLE_ROWS - 1);
        }
    }

    /// Adjust content scroll to keep selected item visible.
    fn adjust_content_scroll(&mut self) {
        // Scroll up if above visible area
        if self.navigation.selected_content_idx < self.navigation.content_scroll_offset {
            self.navigation.content_scroll_offset = self.navigation.selected_content_idx;
        }

        // Scroll down if below visible area
        if self.navigation.selected_content_idx >= self.navigation.content_scroll_offset + Self::CONTENT_VISIBLE_ROWS {
            self.navigation.content_scroll_offset =
                self.navigation.selected_content_idx.saturating_sub(Self::CONTENT_VISIBLE_ROWS - 1);
        }
    }

    fn normalize_selected_table_cell(&mut self) {
        let Some(ContentItem::Table(table)) =
            self.product.view().content_items.get(self.navigation.selected_content_idx)
        else {
            self.navigation.selected_table_cell = None;
            return;
        };
        if self
            .navigation
            .selected_table_cell
            .and_then(|(row, column)| table.rows.get(row).and_then(|row| row.cells.get(column)))
            .is_some_and(|cell| cell.as_ref().is_some_and(ParameterTableCell::is_parameter))
        {
            return;
        }
        self.navigation.selected_table_cell = table.rows.iter().enumerate().find_map(|(row_index, row)| {
            row.cells
                .iter()
                .position(|cell| cell.as_ref().is_some_and(ParameterTableCell::is_parameter))
                .map(|column_index| (row_index, column_index))
        });
    }

    /// Move within the selected table. `None` means the current content item
    /// is not a table; `Some(false)` means the cursor hit the table boundary.
    fn move_table_row(&mut self, down: bool) -> Option<bool> {
        self.normalize_selected_table_cell();
        let table = match self.product.view().content_items.get(self.navigation.selected_content_idx) {
            Some(ContentItem::Table(table)) => table,
            _ => return None,
        };
        let (current_row, current_column) = self.navigation.selected_table_cell?;
        let next = if down {
            (current_row.saturating_add(1)..table.rows.len()).find_map(|row_index| {
                nearest_parameter_cell(&table.rows[row_index], current_column)
                    .map(|column_index| (row_index, column_index))
            })
        } else {
            (0..current_row).rev().find_map(|row_index| {
                nearest_parameter_cell(&table.rows[row_index], current_column)
                    .map(|column_index| (row_index, column_index))
            })
        };
        if let Some(cell) = next {
            self.navigation.selected_table_cell = Some(cell);
            return Some(true);
        }
        Some(false)
    }

    fn move_table_column(&mut self, right: bool) -> bool {
        self.normalize_selected_table_cell();
        let Some(ContentItem::Table(table)) =
            self.product.view().content_items.get(self.navigation.selected_content_idx)
        else {
            return false;
        };
        let Some((row_index, current_column)) = self.navigation.selected_table_cell else { return true };
        let Some(row) = table.rows.get(row_index) else { return true };
        let next = if right {
            row.cells
                .iter()
                .enumerate()
                .skip(current_column.saturating_add(1))
                .find(|(_, cell)| cell.as_ref().is_some_and(ParameterTableCell::is_parameter))
                .map(|(column, _)| column)
        } else {
            row.cells[..current_column]
                .iter()
                .rposition(|cell| cell.as_ref().is_some_and(ParameterTableCell::is_parameter))
        };
        if let Some(column) = next {
            self.navigation.selected_table_cell = Some((row_index, column));
        }
        true
    }

    /// Move segment selection up.
    pub fn segment_move_up(&mut self) {
        if self.navigation.selected_segment_idx > 0 {
            self.navigation.selected_segment_idx -= 1;
            self.navigation.selected_byte_offset = 0;
            self.navigation.memory_scroll_offset = 0;
        }
    }

    /// Move segment selection down.
    pub fn segment_move_down(&mut self) {
        if self.navigation.selected_segment_idx < self.product.view().memory_segments.len().saturating_sub(1) {
            self.navigation.selected_segment_idx += 1;
            self.navigation.selected_byte_offset = 0;
            self.navigation.memory_scroll_offset = 0;
        }
    }

    /// Move focus forward through the panes available on the current tab.
    pub fn toggle_focus(&mut self) {
        if !matches!(self.navigation.edit_mode, EditMode::None) {
            return;
        }

        // Entering the content pane must see the page the sidebar
        // selection points at, even mid-batch before the next frame's
        // `ensure_tab_data` runs — the very next key may navigate or
        // edit `content_items`.
        if self.navigation.current_tab == MainTab::Parameters && self.navigation.focus == Focus::Sidebar {
            self.ensure_content();
        }

        self.navigation.focus = match (self.navigation.current_tab, self.navigation.focus) {
            (_, Focus::Project) => Focus::Tabs,
            (MainTab::Parameters, Focus::Tabs) => Focus::Sidebar,
            (MainTab::Parameters, Focus::Sidebar) => Focus::Content,
            (MainTab::Parameters, Focus::Content) => {
                if self.project.navigation().is_some() {
                    Focus::Project
                } else {
                    Focus::Tabs
                }
            }
            (MainTab::CommObjects, Focus::Tabs) => Focus::Content,
            (MainTab::CommObjects, Focus::Content) => {
                if self.project.navigation().is_some() {
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
                if self.project.navigation().is_some() {
                    Focus::Project
                } else {
                    Focus::Tabs
                }
            }
        };
    }

    /// Move focus backward through the panes available on the current tab.
    pub fn focus_previous(&mut self) {
        if !matches!(self.navigation.edit_mode, EditMode::None) {
            return;
        }

        let project_visible = self.project.navigation().is_some();
        let next_focus = match (self.navigation.current_tab, self.navigation.focus, project_visible) {
            (_, Focus::Project, true) => Focus::Content,
            (_, Focus::Project, false) => Focus::Tabs,
            (_, Focus::Tabs, true) => Focus::Project,
            (_, Focus::Tabs, false) => Focus::Content,
            (_, Focus::Sidebar, _) => Focus::Tabs,
            (MainTab::Parameters | MainTab::Memory, Focus::Content, _) => Focus::Sidebar,
            (MainTab::CommObjects, Focus::Content, _) => Focus::Tabs,
        };

        // Shift+Tab can enter parameter content from either the tabs or the
        // project pane. Materialize the selected page before the next key can
        // navigate or edit it, just as forward focus does from the sidebar.
        if self.navigation.current_tab == MainTab::Parameters && next_focus == Focus::Content {
            self.ensure_content();
        }

        self.navigation.focus = next_focus;
    }

    /// Move selection up.
    pub fn move_up(&mut self) {
        match &mut self.navigation.edit_mode {
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
            EditMode::None => match (self.navigation.current_tab, self.navigation.focus) {
                (_, Focus::Project) => {
                    if let Some(navigation) = self.project.navigation_mut() {
                        navigation.move_up();
                    }
                }
                (_, Focus::Tabs) => {
                    // No vertical movement in tabs
                }
                (MainTab::Parameters, Focus::Sidebar) => {
                    // Hop over group headers — they are not pages.
                    if let Some(index) = self.product.view().tree_nodes[..self.navigation.selected_tree_idx]
                        .iter()
                        .rposition(|n| !n.is_group())
                    {
                        self.navigation.selected_tree_idx = index;

                        self.navigation.selected_content_idx = 0;
                        self.navigation.selected_table_cell = None;
                        self.navigation.content_scroll_offset = 0;
                    }
                }
                (MainTab::Parameters, Focus::Content) => {
                    if self.move_table_row(false) != Some(true) && self.navigation.selected_content_idx > 0 {
                        self.navigation.selected_content_idx -= 1;
                        self.normalize_selected_table_cell();
                        self.adjust_content_scroll();
                    }
                }
                (MainTab::CommObjects, Focus::Content) if self.navigation.selected_obj_idx > 0 => {
                    self.navigation.selected_obj_idx -= 1;
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
        match &mut self.navigation.edit_mode {
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
            EditMode::None => match (self.navigation.current_tab, self.navigation.focus) {
                (_, Focus::Project) => {
                    if let Some(navigation) = self.project.navigation_mut() {
                        navigation.move_down();
                    }
                }
                (_, Focus::Tabs) => {
                    // No vertical movement in tabs
                }
                (MainTab::Parameters, Focus::Sidebar) => {
                    // Hop over group headers — they are not pages.
                    if let Some(offset) = self
                        .product
                        .view()
                        .tree_nodes
                        .iter()
                        .skip(self.navigation.selected_tree_idx + 1)
                        .position(|n| !n.is_group())
                    {
                        self.navigation.selected_tree_idx += 1 + offset;

                        self.navigation.selected_content_idx = 0;
                        self.navigation.selected_table_cell = None;
                        self.navigation.content_scroll_offset = 0;
                    }
                }
                (MainTab::Parameters, Focus::Content) => {
                    if self.move_table_row(true) != Some(true)
                        && self.navigation.selected_content_idx
                            < self.product.view().content_items.len().saturating_sub(1)
                    {
                        self.navigation.selected_content_idx += 1;
                        self.normalize_selected_table_cell();
                        self.adjust_content_scroll();
                    }
                }
                (MainTab::CommObjects, Focus::Content)
                    if self.navigation.selected_obj_idx
                        < self.product.view().com_object_rows.len().saturating_sub(1) =>
                {
                    self.navigation.selected_obj_idx += 1;
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
        match (self.navigation.current_tab, self.navigation.focus) {
            (_, Focus::Project) => {
                for _ in 0..Self::PAGE_SIZE {
                    if let Some(navigation) = self.project.navigation_mut() {
                        navigation.move_up();
                    }
                }
            }
            (_, Focus::Tabs) => {
                // No vertical movement in tabs
            }
            (MainTab::Parameters, Focus::Sidebar) if self.navigation.selected_tree_idx > 0 => {
                self.navigation.selected_tree_idx = self.navigation.selected_tree_idx.saturating_sub(Self::PAGE_SIZE);

                self.navigation.selected_content_idx = 0;
                self.navigation.selected_table_cell = None;
                self.navigation.content_scroll_offset = 0;
            }
            (MainTab::Parameters, Focus::Content) => {
                if matches!(
                    self.product.view().content_items.get(self.navigation.selected_content_idx),
                    Some(ContentItem::Table(_))
                ) {
                    for _ in 0..Self::PAGE_SIZE {
                        if self.move_table_row(false) != Some(true) {
                            break;
                        }
                    }
                } else {
                    self.navigation.selected_content_idx =
                        self.navigation.selected_content_idx.saturating_sub(Self::PAGE_SIZE);
                    self.normalize_selected_table_cell();
                }
                self.adjust_content_scroll();
            }
            (MainTab::CommObjects, Focus::Content) if self.navigation.selected_obj_idx > 0 => {
                self.navigation.selected_obj_idx = self.navigation.selected_obj_idx.saturating_sub(Self::PAGE_SIZE);
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
        match (self.navigation.current_tab, self.navigation.focus) {
            (_, Focus::Project) => {
                for _ in 0..Self::PAGE_SIZE {
                    if let Some(navigation) = self.project.navigation_mut() {
                        navigation.move_down();
                    }
                }
            }
            (_, Focus::Tabs) => {
                // No vertical movement in tabs
            }
            (MainTab::Parameters, Focus::Sidebar) => {
                let max_idx = self.product.view().tree_nodes.len().saturating_sub(1);
                if self.navigation.selected_tree_idx < max_idx {
                    self.navigation.selected_tree_idx =
                        (self.navigation.selected_tree_idx + Self::PAGE_SIZE).min(max_idx);

                    self.navigation.selected_content_idx = 0;
                    self.navigation.selected_table_cell = None;
                    self.navigation.content_scroll_offset = 0;
                }
            }
            (MainTab::Parameters, Focus::Content) => {
                if matches!(
                    self.product.view().content_items.get(self.navigation.selected_content_idx),
                    Some(ContentItem::Table(_))
                ) {
                    for _ in 0..Self::PAGE_SIZE {
                        if self.move_table_row(true) != Some(true) {
                            break;
                        }
                    }
                } else {
                    let max_idx = self.product.view().content_items.len().saturating_sub(1);
                    if self.navigation.selected_content_idx < max_idx {
                        self.navigation.selected_content_idx =
                            (self.navigation.selected_content_idx + Self::PAGE_SIZE).min(max_idx);
                        self.normalize_selected_table_cell();
                    }
                }
                self.adjust_content_scroll();
            }
            (MainTab::CommObjects, Focus::Content) => {
                let max_idx = self.product.view().com_object_rows.len().saturating_sub(1);
                if self.navigation.selected_obj_idx < max_idx {
                    self.navigation.selected_obj_idx =
                        (self.navigation.selected_obj_idx + Self::PAGE_SIZE).min(max_idx);
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
        if !matches!(self.navigation.edit_mode, EditMode::None) {
            return;
        }
        match (self.navigation.current_tab, self.navigation.focus) {
            (_, Focus::Project) => {}
            (_, Focus::Tabs) => self.prev_tab(),
            (MainTab::Parameters, Focus::Sidebar) => {
                // Collapse the selected tree node
                let node = self
                    .product
                    .view()
                    .tree_nodes
                    .get(self.navigation.selected_tree_idx)
                    .filter(|node| node.has_children)
                    .map(|node| node.id.clone());
                if let Some(node) = node
                    && self.navigation.expanded_nodes.contains(&node)
                {
                    self.navigation.expanded_nodes.remove(&node);
                    self.rebuild_tree();
                }
            }
            (MainTab::Parameters, Focus::Content) => {
                self.move_table_column(false);
            }
            (MainTab::Memory, Focus::Content) => {
                self.memory_move_left();
            }
            _ => {}
        }
    }

    /// Move selection right (for tabs) or expand tree node (for sidebar).
    pub fn move_right(&mut self) {
        if !matches!(self.navigation.edit_mode, EditMode::None) {
            return;
        }
        match (self.navigation.current_tab, self.navigation.focus) {
            (_, Focus::Project) => {}
            (_, Focus::Tabs) => self.next_tab(),
            (MainTab::Parameters, Focus::Sidebar) => {
                // Expand the selected tree node
                let node = self
                    .product
                    .view()
                    .tree_nodes
                    .get(self.navigation.selected_tree_idx)
                    .filter(|node| node.has_children)
                    .map(|node| node.id.clone());
                if let Some(node) = node
                    && !self.navigation.expanded_nodes.contains(&node)
                {
                    self.navigation.expanded_nodes.insert(node);
                    self.rebuild_tree();
                }
            }
            (MainTab::Parameters, Focus::Content) => {
                self.move_table_column(true);
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
        match &self.navigation.edit_mode {
            EditMode::LanguageSelect { options, selected_idx, .. } => {
                let next = options[*selected_idx].0.clone();
                self.navigation.edit_mode = EditMode::None;
                self.switch_language(next);
            }
            EditMode::EnumDropdown { param_id, options, selected_idx, .. } => {
                // Commit the selection
                let param_id = param_id.clone();
                let new_value = options[*selected_idx].0;
                let changed =
                    self.product.set_parameter(&mut self.navigation, &param_id, ParameterValue::Integer(new_value));
                self.navigation.edit_mode = EditMode::None;
                // Visibility may have changed: rebuild what this tab
                // shows now, defer the other tabs' views.
                if changed && let Err(error) = self.refresh_programming_statuses_after_edit() {
                    self.navigation.status_message = Some(format!("Cannot recalculate programming status: {error}"));
                }
            }
            EditMode::NumberInput { param_id, buffer, min, max, .. } => {
                // Commit the number, clamped to the type's bounds the way
                // ETS does it (entering 0 on a 1..5 field commits 1,
                // entering 6 commits 5). An unparseable buffer keeps the
                // old value.
                let param_id = param_id.clone();
                let (min, max) = (*min, *max);
                let mut changed = false;
                if let Ok(mut v) = buffer.parse::<i64>() {
                    if let Some(min) = min {
                        v = v.max(min);
                    }
                    if let Some(max) = max {
                        v = v.min(max);
                    }
                    changed = self.product.set_parameter(&mut self.navigation, &param_id, ParameterValue::Integer(v));
                }
                self.navigation.edit_mode = EditMode::None;
                if changed && let Err(error) = self.refresh_programming_statuses_after_edit() {
                    self.navigation.status_message = Some(format!("Cannot recalculate programming status: {error}"));
                }
            }
            EditMode::TextInput { param_id, buffer, .. } => {
                // Commit the text
                let param_id = param_id.clone();
                let text = buffer.clone();
                let changed = self.product.set_parameter(&mut self.navigation, &param_id, ParameterValue::Text(text));
                self.navigation.edit_mode = EditMode::None;
                if changed && let Err(error) = self.refresh_programming_statuses_after_edit() {
                    self.navigation.status_message = Some(format!("Cannot recalculate programming status: {error}"));
                }
            }
            EditMode::NetNameInput { net, buffer, .. } => {
                let net = net.clone();
                let name = buffer.clone();
                let result = self.rename_net_label(&net, &name);
                if let Err(error) = result {
                    self.navigation.status_message = Some(format!("Cannot rename group address: {error}"));
                } else {
                    self.navigation.edit_mode = EditMode::None;
                    self.navigation.status_message = Some(format!("Renamed {net}; press e to save"));
                }
            }
            EditMode::GroupAddressInput { object_number, buffer } => {
                // Parse and assign the group addresses: several may be
                // given, separated by commas or spaces; the first one
                // becomes the sending address, the rest listen.
                let object_number = *object_number;
                let buffer = buffer.clone();

                // Validate the whole edit before replacing any links so a
                // typo leaves the current configuration and editor intact.
                let mut addresses = Vec::new();
                for part in buffer.split([',', ' ']).filter(|p| !p.is_empty()) {
                    if let Some(addr) = parse_group_address(part) {
                        addresses.push(addr);
                    } else {
                        self.navigation.status_message =
                            Some(format!("'{part}' is not a group address (main/middle/sub)"));
                        return;
                    }
                }

                self.navigation.status_message = None;
                self.navigation.edit_mode = EditMode::None;
                // Group links only touch the com-object table's address
                // column and the synthetic ADT/AST segments; both are
                // rebuilt by `ensure_tab_data` before the next frame of
                // whichever tab shows them.
                self.product.set_group_addresses(object_number, addresses);
                if let Err(error) = self.refresh_programming_statuses_after_edit() {
                    self.navigation.status_message = Some(format!("Cannot recalculate programming status: {error}"));
                }
            }
            EditMode::ObjectFlagsInput { object_number, buffer } => {
                let object_number = *object_number;
                match parse_object_flags(buffer) {
                    Ok(flags) => {
                        let changed = self.product.set_object_flags(object_number, flags);
                        self.navigation.edit_mode = EditMode::None;
                        if changed && let Err(error) = self.refresh_programming_statuses_after_edit() {
                            self.navigation.status_message =
                                Some(format!("Cannot recalculate programming status: {error}"));
                        }
                    }
                    Err(error) => self.navigation.status_message = Some(error),
                }
            }
            EditMode::None => match (self.navigation.current_tab, self.navigation.focus) {
                (_, Focus::Project) => {
                    let selected = self.project.navigation().and_then(ProjectNavigation::selected_target).cloned();
                    match selected {
                        Some(ProjectNavigationTarget::Device(device)) => {
                            let current = self.project.context().map(|context| &context.device);
                            if current != Some(&device) {
                                self.navigation.pending_project_device = Some(device);
                            }
                        }
                        Some(ProjectNavigationTarget::Net(net)) => {
                            if let Some(project) = self.project.context().and_then(|context| context.authored.as_ref())
                                && let Some(entry) = project.nets.get(&net)
                            {
                                self.navigation.status_message = Some(format!(
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
                    if let Some(node) = self.product.view().tree_nodes.get(self.navigation.selected_tree_idx)
                        && node.has_children
                    {
                        let id = node.id.clone();
                        if self.navigation.expanded_nodes.contains(&id) {
                            self.navigation.expanded_nodes.remove(&id);
                        } else {
                            self.navigation.expanded_nodes.insert(id);
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
        self.navigation.edit_mode = EditMode::None;
    }

    /// Start editing the selected group address's display name.
    pub fn enter_selected_net_name_edit_mode(&mut self) {
        if self.navigation.focus != Focus::Project || !matches!(self.navigation.edit_mode, EditMode::None) {
            return;
        }
        let Some(ProjectNavigationTarget::Net(net)) =
            self.project.navigation().and_then(ProjectNavigation::selected_target).cloned()
        else {
            self.navigation.status_message = Some("Select a group address before renaming it".into());
            return;
        };

        // Staging rebuilds the navigator from the lossless source. Preserve
        // the command's target across that rebuild instead of accidentally
        // testing the reset selection, which is always the active device.
        if let Err(error) = self.stage_current_project_device() {
            self.navigation.status_message = Some(format!("Cannot stage project edits: {error}"));
            return;
        }
        if let Some(navigation) = self.project.navigation_mut() {
            navigation.select(&ProjectNavigationTarget::Net(net.clone()));
        }
        let name = self
            .project
            .context()
            .and_then(|context| context.authored.as_ref())
            .and_then(|project| project.nets.get(&net))
            .and_then(|entry| entry.name.clone())
            .unwrap_or_else(|| net.0.clone());
        let cursor = name.len();
        self.navigation.edit_mode = EditMode::NetNameInput { net, buffer: name, cursor };
    }

    /// Open the language-selection popup: the program's default
    /// language first, then every translation the document carries,
    /// with the active one preselected.
    pub fn open_language_select(&mut self) {
        let Some(context) = &self.product.view().language_context else {
            self.navigation.status_message = Some("This product carries no translations".to_string());
            return;
        };
        let mut options: Vec<(Option<String>, String)> =
            vec![(None, format!("default ({})", self.product.view().device.program().default_language))];
        options.extend(
            context.translations.languages().iter().map(|language| (Some(language.to_string()), language.to_string())),
        );
        if options.len() == 1 {
            self.navigation.status_message = Some("This product carries no translations".to_string());
            return;
        }

        let selected_idx = self
            .product
            .view()
            .current_language
            .as_ref()
            .and_then(|current| options.iter().position(|(value, _)| value.as_ref() == Some(current)))
            .unwrap_or(0);
        let visible = Self::DROPDOWN_VISIBLE_ITEMS;
        let scroll_offset =
            if options.len() <= visible || selected_idx < visible { 0 } else { selected_idx + 1 - visible };
        self.navigation.edit_mode = EditMode::LanguageSelect { options, selected_idx, scroll_offset };
    }

    /// Switch the display language.
    ///
    /// A switch rebuilds the device from the pristine program with the
    /// new language applied, then restores the format-neutral product
    /// configuration. Group bindings and project flag overrides are copied
    /// separately because neither belongs to the product value model.
    pub fn switch_language(&mut self, next: Option<String>) {
        match self.product.switch_language(next) {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                self.navigation.status_message = Some(error);
                return;
            }
        }
        // Language is project presentation state, not part of the device
        // draft. Stage the one root declaration independently so switching
        // products cannot create conflicting per-device preferences.
        let preferred_language = self.product.view().current_language.clone();
        if let Err(error) = self.project.set_language(preferred_language.as_deref()) {
            self.navigation.status_message = Some(format!("Cannot update language preference: {error}"));
            return;
        }

        self.rebuild_tree();
        self.rebuild_content();
        self.rebuild_com_objects();
        self.rebuild_memory_segments();
        self.navigation.selected_tree_idx =
            self.navigation.selected_tree_idx.min(self.product.view().tree_nodes.len().saturating_sub(1));
        self.navigation.selected_content_idx =
            self.navigation.selected_content_idx.min(self.product.view().content_items.len().saturating_sub(1));
        self.navigation.selected_obj_idx =
            self.navigation.selected_obj_idx.min(self.product.view().com_object_rows.len().saturating_sub(1));

        // Keep the authored in-memory project in lockstep with the editor.
        // The normal save command remains the point that writes project.knx.
        if let Err(error) = self.refresh_project_navigation() {
            self.navigation.status_message = Some(format!("Cannot update language preference: {error}"));
            return;
        }

        self.navigation.status_message = Some(match &self.product.view().current_language {
            Some(language) => format!("Language: {language}"),
            None => format!("Language: default ({})", self.product.view().device.program().default_language),
        });
    }

    pub fn set_project_context(&mut self, context: ProjectContext, flags: BTreeMap<u16, ObjectFlagOverrides>) {
        let load_tui_preferences = self.project.context().is_none() && context.authored.is_some();
        let project_changed = self.project.context().is_none_or(|previous| previous.path != context.path);
        if project_changed {
            self.navigation.package_catalog = None;
        }
        self.catalog_dialog = None;
        self.pending_catalog_add = None;

        let data_secure = context
            .authored
            .as_ref()
            .and_then(|project| project.devices.get(&context.device))
            .map_or(DataSecureMode::Disabled, |device| device.data_secure);
        let had_navigation = self.project.navigation().is_some();
        self.project.replace_context(context);
        if !had_navigation && self.project.navigation().is_some() {
            self.navigation.focus = Focus::Project;
        }
        if load_tui_preferences {
            let project_path = &self.project.context().expect("project context was just set").path;
            match TuiPreferences::load(project_path) {
                Ok(Some(preferences)) => self.navigation.tui_preferences = preferences,
                Ok(None) => {}
                Err(error) => self.navigation.status_message = Some(format!("Cannot load TUI preferences: {error}")),
            }
            self.navigation.tui_preferences_dirty = false;
        }
        self.product.set_project_configuration(flags, data_secure);
        self.navigation.project_overview = None;
        self.navigation.key_editor = None;

        // Status generation starts once the download/keyring context is
        // present. Keeping it separate from project navigation prevents this
        // setter from blocking the UI thread on product parsing.
    }

    /// Stage edits to the selected device in the lossless in-memory project
    /// source before another product is opened. No file is written merely by
    /// navigating: `e` persists explicitly, while programming and unloading
    /// run the same save before touching the bus.
    fn refresh_project_navigation(&mut self) -> Result<(), String> {
        if self.project.navigation().is_none() {
            return Ok(());
        }

        self.stage_current_project_device()?;
        Ok(())
    }

    /// Invalidate before staging: even a failed edit cannot leave an older
    /// worker free to publish statuses against the previous intent.
    fn refresh_programming_statuses_after_edit(&mut self) -> Result<(), String> {
        self.clear_programming_statuses();
        self.refresh_project_navigation()?;
        self.start_startup_status_refresh();
        Ok(())
    }

    pub fn take_pending_project_device(&mut self) -> Option<ProjectDeviceId> {
        self.navigation.pending_project_device.take()
    }

    /// Replace the virtual package tree after the project package index has
    /// been loaded. The index is presentation-only; its opaque selectors
    /// continue to point at content-addressed package bytes.
    pub fn set_package_catalog(&mut self, index: PackageCatalogIndex) {
        self.navigation.package_catalog = Some(index.into());
        self.catalog_dialog = None;
        self.pending_catalog_add = None;
    }

    pub fn open_package_catalog(&mut self) {
        let Some(context) = self.project.context() else {
            self.navigation.status_message = Some("Open a project before adding a package catalogue device".into());
            return;
        };
        let Some(project) = context.authored.as_ref() else {
            self.navigation.status_message = Some(
                "Loose MTXML and standalone product files are editor-only; add devices from a project package catalog"
                    .into(),
            );
            return;
        };
        let Some(catalog) = self.navigation.package_catalog.clone() else {
            self.navigation.status_message = Some("The project package catalog is unavailable".into());
            return;
        };
        let Some(current) = project.devices.get(&context.device) else {
            self.navigation.status_message = Some(format!("Project has no current device `{}`", context.device));
            return;
        };

        let defaults = CatalogProjectDefaults {
            existing_device_ids: project.devices.keys().map(|id| id.0.clone()).collect(),
            existing_addresses: project.devices.values().map(|device| device.address).collect(),
            area: current.address.area(),
            line: current.address.line(),
        };
        self.catalog_dialog = Some(ProjectCatalogDialog::new(catalog, defaults));
        self.pending_catalog_add = None;
        self.navigation.status_message = None;
    }

    pub fn catalog_move_up(&mut self) {
        if let Some(dialog) = &mut self.catalog_dialog {
            dialog.move_up();
        }
    }

    pub fn catalog_move_down(&mut self) {
        if let Some(dialog) = &mut self.catalog_dialog {
            dialog.move_down();
        }
    }

    pub fn catalog_move_left(&mut self) {
        if let Some(dialog) = &mut self.catalog_dialog {
            dialog.move_left();
        }
    }

    pub fn catalog_move_right(&mut self) {
        if let Some(dialog) = &mut self.catalog_dialog {
            dialog.move_right();
        }
    }

    pub fn catalog_move_home(&mut self) {
        if let Some(dialog) = &mut self.catalog_dialog {
            dialog.move_home();
        }
    }

    pub fn catalog_move_end(&mut self) {
        if let Some(dialog) = &mut self.catalog_dialog {
            dialog.move_end();
        }
    }

    pub fn catalog_toggle_add_field(&mut self) {
        if let Some(dialog) = &mut self.catalog_dialog {
            dialog.toggle_add_field();
        }
    }

    pub fn catalog_insert(&mut self, character: char) {
        if let Some(dialog) = &mut self.catalog_dialog {
            dialog.insert(character);
        }
    }

    pub fn catalog_backspace(&mut self) {
        if let Some(dialog) = &mut self.catalog_dialog {
            dialog.backspace();
        }
    }

    pub fn catalog_activate(&mut self) {
        if self.pending_catalog_add.is_some() {
            return;
        }
        if let Some(request) = self.catalog_dialog.as_mut().and_then(ProjectCatalogDialog::activate) {
            self.pending_catalog_add = Some(request);
        }
    }

    pub fn catalog_cancel(&mut self) {
        let close = self.catalog_dialog.as_mut().is_some_and(ProjectCatalogDialog::cancel);
        if close {
            self.catalog_dialog = None;
            self.pending_catalog_add = None;
        }
    }

    pub fn take_pending_catalog_add(&mut self) -> Option<CatalogAddRequest<PackageCatalogSelector>> {
        self.pending_catalog_add.take()
    }

    pub fn reject_catalog_add(&mut self, error: impl Into<String>) {
        if let Some(dialog) = &mut self.catalog_dialog {
            dialog.set_add_error(error);
        }
    }

    pub fn finish_catalog_add(&mut self) {
        self.catalog_dialog = None;
        self.pending_catalog_add = None;
    }

    /// Replace only the product-editor portion of the application. Project
    /// commands, bus settings, and the surrounding TUI remain intact.
    pub fn open_project_device(&mut self, loaded: LoadedProjectDevice) {
        // Device, provenance, catalogue and language resources change together.
        // Terminal capabilities belong to the session, so retain its picker.
        self.product.replace(loaded.product);
        self.navigation.expanded_nodes.clear();
        self.navigation.selected_tree_idx = 0;
        self.navigation.selected_content_idx = 0;
        self.navigation.selected_table_cell = None;
        self.navigation.content_scroll_offset = 0;
        self.navigation.selected_obj_idx = 0;
        self.navigation.comm_obj_scroll_offset = 0;
        self.navigation.selected_segment_idx = 0;
        self.navigation.memory_scroll_offset = 0;
        self.navigation.selected_byte_offset = 0;
        let id = loaded.context.device.clone();
        self.set_project_context(loaded.context, loaded.flags);
        self.rebuild_tree();
        self.rebuild_content();
        self.rebuild_com_objects();
        self.rebuild_memory_segments();
        self.start_startup_status_refresh();
        self.navigation.status_message = Some(format!("Opened project device {id}"));
    }

    pub fn toggle_project_overview(&mut self) {
        if self.navigation.project_overview.take().is_some() {
            return;
        }
        let Some(context) = self.project.context() else { return };
        match zweidraehte_project::ProjectStore::open(&context.path)
            .map_err(|error| error.to_string())
            .and_then(|store| ProjectOverview::load(&store))
        {
            Ok(overview) => self.navigation.project_overview = Some(overview),
            Err(error) => self.navigation.status_message = Some(format!("Project overview: {error}")),
        }
    }

    pub fn toggle_key_editor(&mut self) {
        if self.navigation.key_editor.take().is_some() {
            return;
        }
        if let Err(error) = self.save_project() {
            self.navigation.status_message = Some(format!("Project save failed: {error}"));
            return;
        }
        let context = self.project.context().expect("save establishes project context");
        match zweidraehte_project::ProjectStore::open(&context.path)
            .map_err(|error| error.to_string())
            .and_then(|store| ProjectKeyEditor::load(&store))
        {
            Ok(editor) => self.navigation.key_editor = Some(editor),
            Err(error) => self.navigation.status_message = Some(format!("Key editor: {error}")),
        }
    }

    pub fn key_editor_move_up(&mut self) {
        if let Some(editor) = &mut self.navigation.key_editor
            && editor.input.is_none()
        {
            editor.move_up();
        }
    }

    pub fn key_editor_move_down(&mut self) {
        if let Some(editor) = &mut self.navigation.key_editor
            && editor.input.is_none()
        {
            editor.move_down();
        }
    }

    pub fn key_editor_activate(&mut self) {
        let Some(editor) = &mut self.navigation.key_editor else { return };
        if editor.input.is_none() {
            editor.input = Some(String::new());
            return;
        }
        let target = editor.selected_target().cloned();
        let input = editor.input.take().unwrap_or_default();
        let result = target.map_or_else(
            || Err("the project has no editable key slots".to_string()),
            |target| self.project.persist_key_input(target, &input),
        );
        match result {
            Ok(()) => {
                let context = self.project.context().expect("key editor has project context");
                match zweidraehte_project::ProjectStore::open(&context.path)
                    .map_err(|error| error.to_string())
                    .and_then(|store| ProjectKeyEditor::load(&store))
                {
                    Ok(editor) => {
                        self.navigation.key_editor = Some(editor);
                        self.start_startup_status_refresh();
                        self.navigation.status_message = Some("Key persisted".into());
                    }
                    Err(error) => self.navigation.status_message = Some(format!("Key editor refresh failed: {error}")),
                }
            }
            Err(error) => {
                if let Some(editor) = &mut self.navigation.key_editor {
                    editor.input = Some(input);
                }
                self.navigation.status_message = Some(format!("Key rejected: {error}"));
            }
        }
    }

    pub fn key_editor_cancel(&mut self) {
        let Some(editor) = &mut self.navigation.key_editor else { return };
        if editor.input.take().is_none() {
            self.navigation.key_editor = None;
        }
    }

    pub fn key_editor_char(&mut self, character: char) {
        if let Some(input) = self.navigation.key_editor.as_mut().and_then(|editor| editor.input.as_mut())
            && !character.is_control()
        {
            input.push(character);
        }
    }

    pub fn key_editor_backspace(&mut self) {
        if let Some(input) = self.navigation.key_editor.as_mut().and_then(|editor| editor.input.as_mut()) {
            input.pop();
        }
    }

    /// Cycle the selected object's primary net policy. This is deliberately
    /// object-centric: GA membership editing and net security remain separate
    /// operations in the UI and in the project model.
    pub fn cycle_selected_net_security(&mut self) {
        let Some(row) = self.product.view().com_object_rows.get(self.navigation.selected_obj_idx) else { return };
        let Some(project) = self.project.context().and_then(|context| context.authored.as_ref()) else {
            self.navigation.status_message = Some("Save the product draft before editing net security".into());
            return;
        };
        let Some(object) = project
            .devices
            .get(&self.project.context().expect("project context checked").device)
            .and_then(|device| device.objects.get(&row.number))
        else {
            self.navigation.status_message = Some("The selected object has no authored project membership".into());
            return;
        };
        let Some(primary) = object
            .memberships
            .iter()
            .find(|membership| membership.role == zweidraehte_project::MembershipRole::Primary)
        else {
            self.navigation.status_message = Some("The selected object has no primary net".into());
            return;
        };
        let primary_net = primary.net.clone();
        let next = self.project.cycle_net_security(primary_net.clone(), project.nets[&primary_net].security);
        if let Err(error) = self.refresh_programming_statuses_after_edit() {
            self.navigation.status_message = Some(format!("Cannot recalculate programming status: {error}"));
            return;
        }
        self.navigation.status_message = Some(format!("Net {primary_net} security: {next:?}"));
    }

    pub fn toggle_data_secure(&mut self) {
        if !self.product.view().device.program().is_secure_enabled.unwrap_or(false) {
            self.navigation.status_message = Some("This product does not support Data Secure".into());
            return;
        }
        self.product.toggle_data_secure();
        if let Err(error) = self.refresh_programming_statuses_after_edit() {
            self.navigation.status_message = Some(format!("Cannot recalculate programming status: {error}"));
            return;
        }
        self.navigation.status_message = Some(format!(
            "Data Secure {}",
            if self.product.view().data_secure.is_enabled() { "enabled" } else { "disabled" }
        ));
    }

    /// Open the ETS-style programming selector without touching the bus.
    pub fn open_programming_dialog(&mut self) {
        if self.operations.download().is_some_and(|download| download.result.is_none()) {
            return;
        }

        if self.operations.download_context.as_ref().and_then(|context| context.target.as_ref()).is_none() {
            self.navigation.status_message = Some("Start the TUI with --server or --usb to program the device".into());
            return;
        }

        // Recompile after staging current editor values. Startup status belongs
        // to the opened source revision and must not be reused after edits.
        // Keep the selector usable on failure while exposing the exact error.
        let status_error = self.refresh_programming_statuses_after_edit().err();

        let desired_address = self
            .project
            .context()
            .and_then(|context| context.authored.as_ref()?.devices.get(&context.device))
            .map(|device| device.address.to_string())
            .unwrap_or_else(|| "not saved".into());

        self.operations.programming_dialog = Some(ProgrammingDialog {
            operation: crate::download::ProgrammingOperation::Partial,
            target: ProgrammingTarget::Selected,
            desired_address,
            overwrite_address_input: None,
            overwrite_address_error: None,
        });
        if let Some(error) = status_error {
            self.navigation.status_message = Some(format!("Cannot calculate exact device programming status: {error}"));
        }
    }

    /// Repair every active device whose project programming state is stale.
    /// This remains an explicit project-wide action: programming one selected
    /// device may mark secure consumers stale, but never silently programs
    /// those other physical devices.
    pub fn program_all_affected(&mut self) {
        self.start_download_selection(true, crate::download::ProgrammingOperation::Partial, None);
    }

    pub fn move_programming_selection(&mut self, delta: isize) {
        let Some(dialog) = &mut self.operations.programming_dialog else { return };
        let operations = crate::download::ProgrammingOperation::ALL;
        let current = operations
            .iter()
            .position(|operation| *operation == dialog.operation)
            .expect("the selected programming operation is listed");
        let selected = current.saturating_add_signed(delta).min(operations.len() - 1);

        dialog.operation = operations[selected];
        dialog.overwrite_address_input = None;
        dialog.overwrite_address_error = None;

        if !dialog.operation.supports_affected_target() {
            dialog.target = ProgrammingTarget::Selected;
        }
    }

    pub fn select_programming_operation(&mut self, index: usize) {
        let Some(operation) = crate::download::ProgrammingOperation::ALL.get(index).copied() else { return };
        let Some(dialog) = &mut self.operations.programming_dialog else { return };

        dialog.operation = operation;
        dialog.overwrite_address_input = None;
        dialog.overwrite_address_error = None;

        if !operation.supports_affected_target() {
            dialog.target = ProgrammingTarget::Selected;
        }
    }

    pub fn toggle_programming_target(&mut self) {
        let Some(dialog) = &mut self.operations.programming_dialog else { return };
        if !dialog.operation.supports_affected_target() {
            return;
        }

        dialog.target = match dialog.target {
            ProgrammingTarget::Selected => ProgrammingTarget::Affected,
            ProgrammingTarget::Affected => ProgrammingTarget::Selected,
        };
    }

    pub fn cancel_programming_dialog(&mut self) {
        self.operations.programming_dialog = None;
    }

    pub fn programming_address_input_active(&self) -> bool {
        self.operations.programming_dialog.as_ref().is_some_and(|dialog| dialog.overwrite_address_input.is_some())
    }

    pub fn push_programming_address_character(&mut self, character: char) {
        if !character.is_ascii_digit() && character != '.' {
            return;
        }

        let Some(dialog) = &mut self.operations.programming_dialog else { return };
        let Some(input) = &mut dialog.overwrite_address_input else { return };
        if input.len() >= 10 {
            return;
        }

        input.push(character);
        dialog.overwrite_address_error = None;
    }

    pub fn pop_programming_address_character(&mut self) {
        let Some(dialog) = &mut self.operations.programming_dialog else { return };
        let Some(input) = &mut dialog.overwrite_address_input else { return };

        input.pop();
        dialog.overwrite_address_error = None;
    }

    pub fn cancel_programming_address_input(&mut self) {
        let Some(dialog) = &mut self.operations.programming_dialog else { return };

        dialog.overwrite_address_input = None;
        dialog.overwrite_address_error = None;
    }

    pub fn confirm_programming_dialog(&mut self) {
        let Some(dialog) = &mut self.operations.programming_dialog else { return };
        if dialog.operation == crate::download::ProgrammingOperation::OverwriteIndividualAddress {
            let Some(input) = dialog.overwrite_address_input.as_deref() else {
                dialog.overwrite_address_input = Some(String::new());
                dialog.overwrite_address_error = None;
                return;
            };
            let Some(current_address) = crate::download::parse_individual_address(input) else {
                dialog.overwrite_address_error = Some("Enter a KNX address as area.line.device".into());
                return;
            };
            if current_address.to_string() == dialog.desired_address {
                dialog.overwrite_address_error = Some("Current IA already equals the configured IA".into());
                return;
            }

            let operation = dialog.operation;
            self.operations.programming_dialog = None;
            self.start_download_selection(false, operation, Some(current_address));
            return;
        }

        let dialog = self.operations.programming_dialog.take().expect("dialog checked above");
        self.start_download_selection(dialog.target == ProgrammingTarget::Affected, dialog.operation, None);
    }

    pub fn programming_effect_summary(&self) -> Option<String> {
        let dialog = self.operations.programming_dialog.as_ref()?;
        let fixed = match dialog.operation {
            crate::download::ProgrammingOperation::All => Some("Adr Prg Par Grp Cfg"),
            crate::download::ProgrammingOperation::IndividualAddress => Some("Adr"),
            crate::download::ProgrammingOperation::OverwriteIndividualAddress => {
                return Some("Will update: Adr; secure consumers become Grp-stale".into());
            }
            crate::download::ProgrammingOperation::Application => Some("Prg Par Grp Cfg"),
            crate::download::ProgrammingOperation::Partial => None,
        };
        if let Some(fixed) = fixed {
            return Some(format!("Will update: {fixed}"));
        }

        let unknown = "Programming status is not available yet";
        let statuses: Vec<_> = match dialog.target {
            ProgrammingTarget::Selected => {
                let Some(status) =
                    self.project.context().and_then(|context| self.project_programming_status(&context.device))
                else {
                    return Some(unknown.into());
                };
                vec![status]
            }
            ProgrammingTarget::Affected => {
                let Some(project) = self.project.context().and_then(|context| context.authored.as_ref()) else {
                    return Some(unknown.into());
                };
                let Some(statuses) = project
                    .devices
                    .values()
                    .filter(|device| device.active)
                    .map(|device| self.project_programming_status(&device.id))
                    .collect::<Option<Vec<_>>>()
                else {
                    return Some(unknown.into());
                };
                statuses.into_iter().filter(|status| !status.is_complete()).collect()
            }
        };
        if statuses.is_empty() {
            return Some("No stale project data is currently known".into());
        }

        let stale = [
            ("Adr", statuses.iter().any(|status| !status.individual_address)),
            ("Prg", statuses.iter().any(|status| !status.application_program)),
            ("Par", statuses.iter().any(|status| !status.parameters)),
            ("Grp", statuses.iter().any(|status| !status.group_communication)),
            ("Cfg", statuses.iter().any(|status| !status.medium_configuration)),
        ]
        .into_iter()
        .filter_map(|(label, is_stale)| is_stale.then_some(label))
        .collect::<Vec<_>>();

        Some(format!("Will update stale: {}", stale.join(" ")))
    }

    /// Open the destructive unload selector without changing the device.
    pub fn open_unload_confirmation(&mut self) {
        if self.operations.download().is_some_and(|download| download.result.is_none()) {
            return;
        }

        if self.operations.download_context.as_ref().and_then(|context| context.target.as_ref()).is_none() {
            self.navigation.status_message = Some("Start the TUI with --server or --usb to unload the device".into());
            return;
        }

        self.operations.unload_confirmation = Some(crate::download::UnloadScope::Application);
    }

    pub fn confirm_unload(&mut self) {
        let Some(scope) = self.operations.unload_confirmation.take() else { return };
        self.start_unload(scope);
    }

    fn start_unload(&mut self, scope: crate::download::UnloadScope) {
        let Some(target) = self.operations.download_context.as_ref().and_then(|context| context.target.clone()) else {
            self.navigation.status_message = Some("Start the TUI with --server or --usb to unload the device".into());
            return;
        };

        if let Err(error) = self.save_project() {
            self.navigation.status_message = Some(format!("Project save failed: {error}"));
            return;
        }

        let project = self.project.context().expect("save establishes project context");
        let (tx, rx) = std::sync::mpsc::channel();
        let (control, _) = tokio::sync::mpsc::unbounded_channel();
        crate::download::spawn_unload(
            crate::download::UnloadJob {
                target,
                project_path: project.path.clone(),
                device: project.device.clone(),
                master_data: self.operations.download_context.as_ref().and_then(|context| context.master_data.clone()),
                security: self
                    .operations
                    .download_context
                    .as_ref()
                    .expect("unload target came from the context")
                    .security
                    .clone(),
                scope,
            },
            tx,
        );

        self.operations.start(DeviceOperation::Unloading, rx, control);
    }

    fn start_download_selection(
        &mut self,
        affected_only: bool,
        operation: crate::download::ProgrammingOperation,
        overwrite_current_address: Option<zweidraehte_client::IndividualAddress>,
    ) {
        if self.operations.download().is_some_and(|d| d.result.is_none()) {
            return; // already running
        }
        let Some(target) = self.operations.download_context.as_ref().and_then(|c| c.target.clone()) else {
            self.navigation.status_message =
                Some("Start the TUI with --server or --usb to program the device".to_string());
            return;
        };
        if let Err(error) = self.save_project() {
            self.navigation.status_message = Some(format!("Project save failed: {error}"));
            return;
        };
        let project = self.project.context().expect("save establishes project context");

        let (tx, rx) = std::sync::mpsc::channel();
        let (control, control_receiver) = tokio::sync::mpsc::unbounded_channel();
        crate::download::spawn(
            crate::download::DownloadJob {
                target,
                project_path: project.path.clone(),
                device: (!affected_only).then(|| project.device.clone()),
                affected_only,
                master_data: self.operations.download_context.as_ref().and_then(|c| c.master_data.clone()),
                security: self
                    .operations
                    .download_context
                    .as_ref()
                    .expect("download target came from the context")
                    .security
                    .clone(),
                operation,
                overwrite_current_address,
                control: control_receiver,
            },
            tx,
        );
        self.operations.start(DeviceOperation::Programming, rx, control);
    }

    /// Drain the worker's progress; called every UI tick.
    pub fn poll_download(&mut self) {
        let Some(completion) = self.operations.poll() else { return };
        let (result, status_scope, execution) = match completion {
            Ok(outcome) => {
                let same_project = self.project.context().is_some_and(|context| context.path == outcome.project_path);
                let report = match &outcome.execution {
                    Ok(report) => Some(report),
                    Err(ProjectError::ProjectBatch(failure)) => Some(&failure.report),
                    Err(_) => None,
                };
                let merge = if same_project && let Some(report) = report {
                    self.apply_persisted_serial_updates(&report.serial_updates)
                } else {
                    Ok(())
                };
                let result = match &outcome.execution {
                    Ok(_) => Ok(outcome.summary),
                    Err(error) => Err(error.to_string()),
                };
                let result = match merge {
                    Ok(()) => result,
                    Err(error) => Err(format!(
                        "{}; reflecting persisted serials in the editor: {error}",
                        result.unwrap_or_else(|error| error)
                    )),
                };
                (result, if same_project { outcome.status_scope } else { BTreeSet::new() }, Some(outcome.execution))
            }
            Err(error) => (Err(error), BTreeSet::new(), None),
        };
        self.operations.complete(result, execution);
        self.start_programming_status_refresh(status_scope);
    }

    pub(crate) fn startup_status_ratio(&self) -> u16 {
        let Some(status) = self.project.status() else { return 0 };
        if status.total == 0 {
            return 0;
        }
        ((status.completed as f64 / status.total as f64) * 100.0).clamp(0.0, 100.0) as u16
    }

    /// Persist product edits into the selected project. Standalone MTXML and
    /// `.knxprod` files are editor-only: a project device must already carry
    /// an exact package digest and CatalogItem selector.
    pub fn export_project(&mut self) {
        self.navigation.status_message = Some(match self.save_project() {
            Ok(()) => {
                format!("Saved project {}", self.project.context().expect("save establishes context").path.display())
            }
            Err(error) => format!("Project save failed: {error}"),
        });
    }

    /// Persist changed editor preferences without touching `project.knx` or
    /// the secure commissioning journal. The event loop calls this on clean
    /// exit; an explicit project save calls it as well.
    pub fn persist_tui_preferences(&mut self) -> Result<(), String> {
        if !self.navigation.tui_preferences_dirty {
            return Ok(());
        }
        let Some(context) = self.project.context() else {
            return Ok(());
        };
        // Opening a product must remain side-effect free until the first save
        // turns it into a real project.
        if context.authored.is_none() {
            return Ok(());
        }
        self.navigation.tui_preferences.persist(&context.path)?;
        self.navigation.tui_preferences_dirty = false;
        Ok(())
    }

    fn enter_edit_mode(&mut self) {
        self.normalize_selected_table_cell();
        let target = match self.product.view().content_items.get(self.navigation.selected_content_idx) {
            Some(ContentItem::Parameter { param_id, widget, .. }) => Some((param_id.clone(), widget.clone())),
            Some(ContentItem::Table(table)) => self
                .navigation
                .selected_table_cell
                .and_then(|(row, column)| table.rows.get(row)?.cells.get(column)?.as_ref())
                .and_then(|cell| match cell {
                    ParameterTableCell::Parameter { param_id, widget, .. } => Some((param_id.clone(), widget.clone())),
                    ParameterTableCell::Text(_) => None,
                }),
            _ => None,
        };
        let Some((param_id, widget)) = target else { return };

        match widget {
            WidgetType::Dropdown { options, current_idx } => {
                // Calculate initial scroll offset to center the selected item if possible
                let visible = Self::DROPDOWN_VISIBLE_ITEMS;
                let scroll_offset = if options.len() <= visible || current_idx < visible / 2 {
                    0
                } else if current_idx > options.len() - visible / 2 {
                    options.len().saturating_sub(visible)
                } else {
                    current_idx.saturating_sub(visible / 2)
                };
                self.navigation.edit_mode =
                    EditMode::EnumDropdown { param_id, options, selected_idx: current_idx, scroll_offset };
            }
            WidgetType::Number { value, min, max } => {
                self.navigation.edit_mode =
                    EditMode::NumberInput { param_id, buffer: value.to_string(), select_all: true, min, max };
            }
            WidgetType::Text { value } => {
                let len = value.len();
                self.navigation.edit_mode = EditMode::TextInput { param_id, buffer: value, cursor: len };
            }
            WidgetType::ReadOnly { .. } => {
                // Can't edit read-only
            }
        }
    }

    /// Enter group address edit mode for the currently selected communication object.
    fn enter_group_address_edit_mode(&mut self) {
        if let Some(row) = self.product.view().com_object_rows.get(self.navigation.selected_obj_idx) {
            // Get existing group address as initial buffer value
            let existing = self.product.format_group_address(row.number);
            self.navigation.edit_mode = EditMode::GroupAddressInput { object_number: row.number, buffer: existing };
        }
    }

    pub fn enter_object_flags_edit_mode(&mut self) {
        let Some(row) = self.product.view().com_object_rows.get(self.navigation.selected_obj_idx) else { return };
        let flags = self.product.view().object_flag_overrides.get(&row.number).copied().unwrap_or_default();
        self.navigation.edit_mode =
            EditMode::ObjectFlagsInput { object_number: row.number, buffer: format_object_flags(flags) };
    }

    /// Handle character input for editing.
    pub fn handle_char(&mut self, c: char) {
        match &mut self.navigation.edit_mode {
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
        match &mut self.navigation.edit_mode {
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
        self.product
            .view()
            .tree_nodes
            .get(self.navigation.selected_tree_idx)
            .map(|n| n.name.clone())
            .unwrap_or_else(|| "No Selection".to_string())
    }
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

// The editor accepts three levels, although the protocol parser also supports
// two-level and raw notation. Zero remains representable; project validation
// determines whether a binding may be commissioned.
fn parse_group_address(value: &str) -> Option<GroupAddress> {
    if value.bytes().filter(|byte| *byte == b'/').count() != 2 {
        return None;
    }
    value.parse().ok()
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
    use zweidraehte_ets_files::runtime::presentation::FormPresentation;

    #[test]
    fn save_materializes_effectively_secure_nets_without_imported_keys() {
        let project = AuthoredProject::parse(
            "ga plain = 1/0/1\n\
             ga automatic_secure = 1/0/2\n\
             ga auth = 1/0/3\n\
             ga confidential = 1/0/4\n\
             ga automatic_mixed = 1/0/5\n\
             ga automatic_external = 1/0/6\n\
             net plain : 1.001 { security plain }\n\
             net automatic_secure : 1.001 { security automatic }\n\
             net auth : 1.001 { security authentication }\n\
             net confidential : 1.001 { security authentication_confidentiality }\n\
             net automatic_mixed : 1.001 { security automatic }\n\
             net automatic_external : 1.001 { security automatic }\n\
             external_sender legacy { address 1.1.250 data_secure disabled on automatic_external }\n\
             area 1 bench { line 1 main { medium tp1\n\
               device secure { product package:\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" catalog_item \"secure\" address 1.1.1 data_secure enabled object 0 { on automatic_secure } object 1 { on automatic_mixed } object 2 { on automatic_external } }\n\
               device legacy { product package:\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\" catalog_item \"legacy\" address 1.1.2 object 0 { on automatic_mixed } }\n\
               device parked { active false product package:\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\" catalog_item \"parked\" address 1.1.3 object 0 { on automatic_secure } }\n\
             } }\n",
        )
        .expect("project parses");
        let imported = BTreeSet::from([u16::from_be_bytes(
            project.nets.get(&NetId("confidential".into())).expect("confidential net exists").address.0,
        )]);

        assert_eq!(group_keys_to_materialize(&project, &imported), ["auth", "automatic_secure"]);
    }

    const PROJECT_STATUS_FIXTURE: &str = "ga lights = 1/0/1\n\
         net lights : 1.001 { security automatic }\n\
         area 1 bench { line 1 main { medium tp1\n\
           device button { product package:\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" catalog_item \"button\" address 1.1.10 object 0 { on lights } }\n\
           device relay { product package:\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\" catalog_item \"relay\" address 1.1.20 object 0 { on lights } }\n\
         } }\n";

    const PARAMETER_REF_DEFAULT_FIXTURE: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-1" ApplicationNumber="1" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="Fixture" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="false" Linkable="false" IsSecureEnabled="true">
      <Static>
        <ParameterTypes>
          <ParameterType Id="M-00FA_A-1_PT-N8" Name="N8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="100" /></ParameterType>
        </ParameterTypes>
        <Parameters>
          <Parameter Id="M-00FA_A-1_P-1" Name="Level" ParameterType="M-00FA_A-1_PT-N8" Text="Level" Value="50" />
          <Union SizeInBit="8">
            <Parameter Id="M-00FA_A-1_UP-570" Name="LedReaction" ParameterType="M-00FA_A-1_PT-N8" Text="LED reacts to" Value="1" Offset="0" BitOffset="0" />
          </Union>
        </Parameters>
        <ParameterRefs>
          <ParameterRef Id="M-00FA_A-1_P-1_R-1" RefId="M-00FA_A-1_P-1" Value="60" />
          <ParameterRef Id="M-00FA_A-1_UP-570_R-2" RefId="M-00FA_A-1_UP-570" />
        </ParameterRefs>
      </Static>
      <Dynamic>
        <Channel Id="M-00FA_A-1_CH-1" Name="Main">
          <ParameterBlock Id="M-00FA_A-1_PB-1" Text="Main">
            <ParameterRefRef RefId="M-00FA_A-1_P-1_R-1" />
            <ParameterRefRef RefId="M-00FA_A-1_UP-570_R-2" />
          </ParameterBlock>
        </Channel>
      </Dynamic>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    const TABLE_FIXTURE: &str = r##"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-2" ApplicationNumber="2" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="Table fixture" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="en-US" DynamicTableManagement="false" Linkable="false">
      <Static>
        <ParameterTypes>
          <ParameterType Id="M-00FA_A-2_PT-FUNCTION" Name="Function"><TypeRestriction Base="Value" SizeInBit="8"><Enumeration Text="Inactive" Value="0" Id="M-00FA_A-2_PT-FUNCTION_EN-0"/><Enumeration Text="Switch" Value="1" Id="M-00FA_A-2_PT-FUNCTION_EN-1"/></TypeRestriction></ParameterType>
        </ParameterTypes>
        <Parameters>
          <Parameter Id="M-00FA_A-2_P-INLINE" Name="Inline" ParameterType="M-00FA_A-2_PT-FUNCTION" Text="Inline" Value="0"/>
        </Parameters>
        <ParameterRefs>
          <ParameterRef Id="M-00FA_A-2_P-INLINE_R-1" RefId="M-00FA_A-2_P-INLINE"/>
        </ParameterRefs>
      </Static>
      <ModuleDefs>
        <ModuleDef Id="M-00FA_A-2_MD-PAGE" Name="Page">
          <Static>
            <Parameters>
              <Parameter Id="M-00FA_A-2_MD-PAGE_P-STYLE" Name="Style" ParameterType="M-00FA_A-2_PT-FUNCTION" Text="Style" Value="0"/>
              <Parameter Id="M-00FA_A-2_MD-PAGE_P-1" Name="Function 1" ParameterType="M-00FA_A-2_PT-FUNCTION" Text="" Value="0"/>
              <Parameter Id="M-00FA_A-2_MD-PAGE_P-2" Name="Function 2" ParameterType="M-00FA_A-2_PT-FUNCTION" Text="" Value="0"/>
              <Parameter Id="M-00FA_A-2_MD-PAGE_P-READ" Name="Preview" ParameterType="M-00FA_A-2_PT-FUNCTION" Text="" Access="Read" Value="1"/>
              <Parameter Id="M-00FA_A-2_MD-PAGE_P-4" Name="Fourth" ParameterType="M-00FA_A-2_PT-FUNCTION" Text="" Value="0"/>
              <Parameter Id="M-00FA_A-2_MD-PAGE_P-5" Name="Fifth" ParameterType="M-00FA_A-2_PT-FUNCTION" Text="" Value="0"/>
              <Parameter Id="M-00FA_A-2_MD-PAGE_P-6" Name="Sixth" ParameterType="M-00FA_A-2_PT-FUNCTION" Text="" Value="0"/>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-2_MD-PAGE_P-STYLE_R-1" RefId="M-00FA_A-2_MD-PAGE_P-STYLE"/>
              <ParameterRef Id="M-00FA_A-2_MD-PAGE_P-1_R-1" RefId="M-00FA_A-2_MD-PAGE_P-1"/>
              <ParameterRef Id="M-00FA_A-2_MD-PAGE_P-2_R-1" RefId="M-00FA_A-2_MD-PAGE_P-2"/>
              <ParameterRef Id="M-00FA_A-2_MD-PAGE_P-READ_R-1" RefId="M-00FA_A-2_MD-PAGE_P-READ"/>
              <ParameterRef Id="M-00FA_A-2_MD-PAGE_P-4_R-1" RefId="M-00FA_A-2_MD-PAGE_P-4"/>
              <ParameterRef Id="M-00FA_A-2_MD-PAGE_P-5_R-1" RefId="M-00FA_A-2_MD-PAGE_P-5"/>
              <ParameterRef Id="M-00FA_A-2_MD-PAGE_P-6_R-1" RefId="M-00FA_A-2_MD-PAGE_P-6"/>
            </ParameterRefs>
          </Static>
          <Dynamic>
            <ParameterBlock Id="M-00FA_A-2_MD-PAGE_PB-1" Name="Page" Text="Page 1">
              <ParameterRefRef RefId="M-00FA_A-2_MD-PAGE_P-STYLE_R-1"/>
              <ParameterBlock Id="M-00FA_A-2_MD-PAGE_PB-TABLE" Name="Page table" Text="#" Inline="true" Layout="Table">
                <Rows><Row Id="M-00FA_A-2_MD-PAGE_ROW-1" Text="1"/><Row Id="M-00FA_A-2_MD-PAGE_ROW-2" Text="2" CollapseIfEmpty="true"/></Rows>
                <Columns>
                  <Column Id="M-00FA_A-2_MD-PAGE_COL-1" Text="Function" Width="20%"/>
                  <Column Id="M-00FA_A-2_MD-PAGE_COL-2" Text="Preview" Width="15%"/>
                  <Column Id="M-00FA_A-2_MD-PAGE_COL-3" Text="Literal" Width="15%"/>
                  <Column Id="M-00FA_A-2_MD-PAGE_COL-4" Text="Fourth" Width="15%"/>
                  <Column Id="M-00FA_A-2_MD-PAGE_COL-5" Text="Fifth" Width="15%"/>
                  <Column Id="M-00FA_A-2_MD-PAGE_COL-6" Text="Sixth" Width="20%"/>
                </Columns>
                <ParameterRefRef RefId="M-00FA_A-2_MD-PAGE_P-1_R-1" Cell="1,1"/>
                <ParameterRefRef RefId="M-00FA_A-2_MD-PAGE_P-READ_R-1" Cell="1,2"/>
                <ParameterSeparator Id="M-00FA_A-2_MD-PAGE_PS-1" Text="computed" Cell="1,3"/>
                <ParameterRefRef RefId="M-00FA_A-2_MD-PAGE_P-4_R-1" Cell="1,4"/>
                <ParameterRefRef RefId="M-00FA_A-2_MD-PAGE_P-5_R-1" Cell="1,5"/>
                <ParameterRefRef RefId="M-00FA_A-2_MD-PAGE_P-6_R-1" Cell="1,6"/>
                <choose ParamRefId="M-00FA_A-2_MD-PAGE_P-STYLE_R-1"><when test="1"><ParameterRefRef RefId="M-00FA_A-2_MD-PAGE_P-2_R-1" Cell="2,1"/></when></choose>
              </ParameterBlock>
            </ParameterBlock>
          </Dynamic>
        </ModuleDef>
        <ModuleDef Id="M-00FA_A-2_MD-INLINE" Name="Inline fragment">
          <Static/>
          <Dynamic>
            <ParameterBlock Id="M-00FA_A-2_MD-INLINE_PB-1" Name="Inline fragment" Text="#" Inline="true">
              <ParameterSeparator Id="M-00FA_A-2_MD-INLINE_PS-1" Text="inline module content"/>
            </ParameterBlock>
          </Dynamic>
        </ModuleDef>
      </ModuleDefs>
      <Dynamic>
        <Channel Id="M-00FA_A-2_CH-1" Name="Pages" Text="Page layout / Functions">
          <ParameterBlock Id="M-00FA_A-2_PB-OUTER" Name="Outer" Text="Page layout / Functions">
            <ParameterBlock Id="M-00FA_A-2_PB-CONFIG" Name="Configuration" Text="Page configuration">
              <ParameterBlock Id="M-00FA_A-2_PB-INLINE" Name="Inline table" Text="#" Inline="true" Layout="Table">
                <Rows><Row Id="M-00FA_A-2_PB-INLINE_ROW-1" Text="1"/></Rows>
                <Columns><Column Id="M-00FA_A-2_PB-INLINE_COL-1" Text="Inline value" Width="100%"/></Columns>
                <ParameterRefRef RefId="M-00FA_A-2_P-INLINE_R-1" Cell="1,1"/>
              </ParameterBlock>
              <Module Id="M-00FA_A-2_MD-INLINE_M-1" RefId="M-00FA_A-2_MD-INLINE" Name="Fragment"/>
              <Module Id="M-00FA_A-2_MD-PAGE_M-1" RefId="M-00FA_A-2_MD-PAGE" Name="Page 1"/>
            </ParameterBlock>
          </ParameterBlock>
        </Channel>
      </Dynamic>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"##;

    fn parameter_ref_default_app() -> App {
        App::new(prepared_fixture(PARAMETER_REF_DEFAULT_FIXTURE, EMPTY_MASTER))
    }

    #[test]
    fn preview_reports_invalid_authoring_before_missing_live_or_catalogue_facts() {
        let mut app = parameter_ref_default_app();
        app.product.set_parameter(&mut app.navigation, "M-00FA_A-1_P-1_R-1", ParameterValue::Integer(999));
        let error =
            app.product.configuration_preview(app.project.context()).expect_err("invalid edit cannot publish an image");
        assert!(error.contains("outside the allowed range"), "{error}");

        app.product.set_parameter(&mut app.navigation, "M-00FA_A-1_P-1_R-1", ParameterValue::Integer(42));
        app.product.view().device.evaluate(&[]).expect("repaired draft is valid again");
    }

    fn table_app() -> App {
        App::new(prepared_fixture(TABLE_FIXTURE, EMPTY_MASTER))
    }

    const EMPTY_MASTER: &str = r#"<KNX xmlns="http://knx.org/xml/project/20"><MasterData Version="1"/></KNX>"#;

    fn prepared_fixture(xml: &str, master: &str) -> PreparedEditorProduct {
        editor_fixture(xml, master).prepare(&ProductConfiguration::default(), [], None, None).expect("prepared fixture")
    }

    fn editor_fixture(xml: &str, master: &str) -> EditorDocument {
        let knx = parse_application_program(xml).expect("fixture document");
        let selected =
            SelectedProduct::from_document(knx, None, Some(master)).expect("fixture selection with Master Data");
        EditorDocument::new(selected, None)
    }

    fn open_fixture(app: &mut App, product: PreparedEditorProduct) {
        app.open_project_device(LoadedProjectDevice {
            product,
            context: ProjectContext {
                path: PathBuf::from("fixture.knx"),
                device: ProjectDeviceId("fixture".into()),
                authored: None,
                original_source: None,
            },
            flags: BTreeMap::new(),
        });
    }

    #[test]
    fn group_address_editor_keeps_three_level_input_and_zero() {
        for (text, normalized) in
            [("0/0/0", "0/0/0"), ("31/7/255", "31/7/255"), ("01/02/003", "1/2/3"), ("+1/+2/+3", "1/2/3")]
        {
            assert_eq!(parse_group_address(text).expect("accepted editor notation").to_string(), normalized);
        }
        for text in [
            "", "1/2", "2049", "1/2/3/4", "32/0/0", "1/8/0", "1/2/256", "1//2", "1/2/-3", "1/2/é", "1.2.3", " 1/2/3",
            "1/2/3 ", "1/2/\t3",
        ] {
            assert!(parse_group_address(text).is_none(), "{text}");
        }

        // An invalid token rejects the whole edit: the links stay as they
        // were and the input stays open for correction.
        let mut app = parameter_ref_default_app();
        app.navigation.edit_mode =
            EditMode::GroupAddressInput { object_number: 0, buffer: "1/0/2, invalid 1/0/1 1/0/2,0/0/0".into() };
        app.activate();
        assert!(app.product_view().device.get_group_addresses(0).is_empty());
        assert!(app.navigation().status_message.as_deref().expect("invalid token reported").contains("invalid"));
        assert!(matches!(app.navigation.edit_mode, EditMode::GroupAddressInput { .. }));

        app.navigation.edit_mode =
            EditMode::GroupAddressInput { object_number: 0, buffer: "1/0/2, 1/0/1 1/0/2,0/0/0".into() };
        app.activate();
        let bindings = app.product_view().device.get_group_addresses(0);
        assert_eq!(
            bindings.iter().map(|binding| (binding.group_address.to_string(), binding.is_sending)).collect::<Vec<_>>(),
            [("1/0/2".into(), true), ("1/0/1".into(), false), ("0/0/0".into(), false),]
        );

        app.navigation.edit_mode = EditMode::GroupAddressInput { object_number: 0, buffer: String::new() };
        app.activate();
        assert!(app.product_view().device.get_group_addresses(0).is_empty());
    }

    #[test]
    fn prepared_editor_replays_values_bindings_and_language_together() {
        use zweidraehte_ets_files::runtime::configuration::ParameterSetting;

        let xml = PARAMETER_REF_DEFAULT_FIXTURE.replace("</Static>", r#"
          <ComObjectTable><ComObject Id="M-00FA_A-1_O-0" Name="Light" Text="Light" Number="0" FunctionText="Switch"
          ObjectSize="1 Bit" ReadFlag="Enabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Enabled"
          UpdateFlag="Enabled" ReadOnInitFlag="Disabled"/></ComObjectTable></Static>"#)
            .replace("</Manufacturer>", r#"<Languages><Language Identifier="en-US"><TranslationUnit RefId="M-00FA_A-1">
            <TranslationElement RefId="M-00FA_A-1_P-1"><Translation AttributeName="Text" Text="Brightness"/></TranslationElement>
            </TranslationUnit></Language></Languages></Manufacturer>"#);
        let settings = ProductConfiguration {
            parameters: vec![ParameterSetting { id: "M-00FA_A-1_P-1_R-1".into(), value: ParameterValue::Integer(77) }],
            objects: Vec::new(),
        };
        let primary = GroupAddress::from_three_level(1, 0, 2);
        let additional = GroupAddress::from_three_level(1, 0, 1);
        let prepared = editor_fixture(&xml, EMPTY_MASTER)
            .prepare(&settings, [(0, vec![primary, additional])], Some("en-US"), Some(Path::new("missing-master.xml")))
            .expect("bundled catalogue wins; overrides and translation apply");
        let mut app = App::new(prepared);
        assert_eq!(app.product.view().current_language.as_deref(), Some("en-US"));
        assert_eq!(
            app.product.view().device.get_parameter_info("M-00FA_A-1_P-1").expect("level parameter").text,
            "Brightness"
        );

        app.switch_language(None);
        assert_eq!(
            app.product.view().device.get_parameter_info("M-00FA_A-1_P-1").expect("level parameter").text,
            "Level"
        );
        assert_eq!(
            app.product.view().device.get_parameter_value("M-00FA_A-1_P-1_R-1"),
            Some(&ParameterValue::Integer(77))
        );
        let bindings = app.product.view().device.get_bindings(0).expect("light bindings survive language switch");
        assert_eq!(bindings.iter().map(|binding| (binding.group_address, binding.is_sending)).collect::<Vec<_>>(), [
            (primary, true),
            (additional, false)
        ]);
    }

    #[test]
    fn preparation_retains_language_fallback_and_requires_explicit_catalogue() {
        let prepared = editor_fixture(TABLE_FIXTURE, EMPTY_MASTER)
            .prepare(&ProductConfiguration::default(), [], Some("unavailable"), None)
            .expect("unknown language retains product defaults");
        assert_eq!(prepared.current_language(), None);
        assert_eq!(prepared.default_language(), "en-US");

        let directory = tempfile::tempdir().expect("empty directory");
        let missing = directory.path().join("master.xml");
        let knx = parse_application_program(TABLE_FIXTURE).expect("fixture document");
        let selected = SelectedProduct::from_document(knx, None, None).expect("unbound selection");
        let error = EditorDocument::new(selected, None)
            .prepare(&ProductConfiguration::default(), [], None, Some(&missing))
            .expect_err("explicit missing file cannot fall back to a download");
        assert!(error.to_string().contains("master.xml"));
    }

    #[test]
    fn mask_views_follow_catalog_installation_and_replacement() {
        let mut app = table_app();
        assert_eq!(app.product_view().mask_version_display(), "MV-0705");

        // Opening another product replaces its catalogue along with the device;
        // every mask view must follow the newly selected document.
        for name in ["Bundled System 7", "Replacement System 7"] {
            let xml = format!(
                r#"<KNX xmlns="http://knx.org/xml/project/20"><MasterData Version="1">
                <MaskVersions><MaskVersion Id="MV-0705" MaskVersion="1797" Name="{name}" ManagementModel="System7"/></MaskVersions>
                </MasterData></KNX>"#
            );
            open_fixture(&mut app, prepared_fixture(TABLE_FIXTURE, &xml));
            assert_eq!(app.product_view().mask_version_display(), format!("{name} (MV-0705)"));
            assert_eq!(app.product_view().management_model(), Some("System7"));
        }

        open_fixture(&mut app, prepared_fixture(PARAMETER_REF_DEFAULT_FIXTURE, EMPTY_MASTER));
        assert_eq!(app.product.view().device.program().id, "M-00FA_A-1");
        assert_eq!(app.product.view().device.program().id, "M-00FA_A-1");
        assert_eq!(app.product_view().mask_version_display(), "MV-0705");
        assert!(app.product_view().management_model().is_none());
    }

    #[test]
    fn nested_module_pages_retain_hierarchy_and_edit_table_cells() {
        let mut app = table_app();
        app.navigation.expanded_nodes.insert("block_M-00FA_A-2_PB-OUTER".into());
        app.navigation.expanded_nodes.insert("block_M-00FA_A-2_PB-CONFIG".into());
        app.rebuild_tree();

        let page_index = app.product.view().tree_nodes
            .iter()
            .position(|node| matches!(&node.node_type, NodeType::ModuleInstance { instance_id, .. } if instance_id == "M-00FA_A-2_MD-PAGE_M-1"))
            .expect("module page is visible");
        assert_eq!(app.product.view().tree_nodes[page_index].depth, 3);
        assert_eq!(app.product.view().tree_nodes[page_index - 1].name, "Page configuration");
        assert_eq!(app.product.view().tree_nodes[page_index - 1].depth, 2);
        assert!(
            !app.product.view().tree_nodes.iter().any(|node| node.name == "#"),
            "inline blocks are not navigation pages: {:?}",
            app.product
                .view()
                .tree_nodes
                .iter()
                .map(|node| (&node.name, node.depth, &node.node_type))
                .collect::<Vec<_>>()
        );
        assert!(!app.product.view().tree_nodes.iter().any(
            |node| matches!(&node.node_type, NodeType::ModuleInstance { instance_id, .. } if instance_id == "M-00FA_A-2_MD-INLINE_M-1")
        ));

        app.navigation.selected_tree_idx = page_index - 1;
        app.rebuild_content();
        assert!(
            app.product
                .view()
                .content_items
                .iter()
                .any(|item| matches!(item, ContentItem::Table(table) if table.columns[0].text == "Inline value")),
            "the inline block's content is rendered on its owning page"
        );
        assert!(app.product.view().content_items.iter().any(
            |item| matches!(item, ContentItem::Separator { text: Some(text), .. } if text == "inline module content")
        ));

        app.navigation.selected_tree_idx = page_index;
        app.rebuild_content();
        let table_index = app
            .product
            .view()
            .content_items
            .iter()
            .position(|item| matches!(item, ContentItem::Table(_)))
            .expect("module content retains its table");
        app.navigation.selected_content_idx = table_index;
        app.normalize_selected_table_cell();
        let ContentItem::Table(table) = &app.product.view().content_items[table_index] else { unreachable!() };
        assert_eq!(table.corner_label, "#");
        assert_eq!(table.columns[0].text, "Function");
        assert_eq!(table.columns.len(), 6);
        assert_eq!(table.rows.len(), 1, "an authored empty conditional row collapses");
        assert!(table.rows[0].cells.iter().all(Option::is_some));
        assert!(matches!(
            &table.rows[0].cells[1],
            Some(ParameterTableCell::Parameter { widget: WidgetType::ReadOnly { .. }, .. })
        ));
        assert!(matches!(&table.rows[0].cells[2], Some(ParameterTableCell::Text(text)) if text == "computed"));
        assert_eq!(app.navigation.selected_table_cell, Some((0, 0)));

        app.product.set_parameter(
            &mut app.navigation,
            "M-00FA_A-2_MD-PAGE_M-1::M-00FA_A-2_MD-PAGE_P-STYLE_R-1",
            ParameterValue::Integer(1),
        );
        assert_eq!(
            FormPresentation::new(&app.product.view().device).get_module_selector_value(
                "M-00FA_A-2_MD-PAGE_P-STYLE_R-1",
                app.product.view().device.get_expanded_module("M-00FA_A-2_MD-PAGE_M-1").expect("page remains expanded")
            ),
            Some(1)
        );
        assert!(
            app.product
                .view()
                .device
                .is_module_param_ref_visible("M-00FA_A-2_MD-PAGE_M-1", "M-00FA_A-2_MD-PAGE_P-2_R-1"),
            "the selected page-style branch exposes row two"
        );
        app.rebuild_content();
        let ContentItem::Table(table) = &app.product.view().content_items[table_index] else {
            panic!("table remains visible")
        };
        assert_eq!(table.rows.len(), 2, "the active page style controls conditional rows");

        app.navigation.focus = Focus::Content;
        app.activate();
        assert!(matches!(app.navigation.edit_mode, EditMode::EnumDropdown { .. }));
        app.move_down();
        app.activate();
        assert_eq!(
            app.product
                .view()
                .device
                .get_module_parameter_value_by_composite_id("M-00FA_A-2_MD-PAGE_M-1::M-00FA_A-2_MD-PAGE_P-1_R-1"),
            Some(&ParameterValue::Integer(1))
        );
    }

    #[test]
    fn content_scrolling_counts_the_rows_consumed_by_large_items() {
        let mut app = table_app();
        app.navigation.selected_content_idx = 1;

        assert_eq!(app.content_scroll_offset_for_layout(&[12, 1, 1], 10), 1);

        app.navigation.selected_content_idx = 2;
        assert_eq!(app.content_scroll_offset_for_layout(&[5, 1, 1], 10), 0);
    }

    fn app_with_project() -> (tempfile::TempDir, App, ProjectDeviceId) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, PROJECT_STATUS_FIXTURE).expect("project fixture is written");

        let button = ProjectDeviceId("button".into());
        {
            let store = zweidraehte_project::ProjectStore::open(&project_path).expect("project store opens");
            store.initialize().expect("project state initializes");
        }

        let store = zweidraehte_project::ProjectStore::open(&project_path).expect("project store reopens");
        let source = store.authored().source().to_string();
        let authored = store.authored().clone();
        let mut app = parameter_ref_default_app();
        app.set_project_context(
            ProjectContext {
                path: project_path,
                device: button.clone(),
                authored: Some(authored),
                original_source: Some(source),
            },
            BTreeMap::new(),
        );
        (directory, app, button)
    }

    #[test]
    fn project_context_keeps_status_unknown_until_products_are_compared() {
        let (_directory, app, button) = app_with_project();

        assert_eq!(app.project_programming_status(&button), None);
        assert_eq!(app.project_programming_status(&ProjectDeviceId("relay".into())), None);
    }

    #[test]
    fn project_edits_reject_an_active_writer_or_stale_source_before_changing_keys() {
        use crate::project_view::EditableKey;
        use zweidraehte_project::ProjectStore;

        for stale in [false, true] {
            let (_directory, mut app, button) = app_with_project();
            let path = app.project.context().expect("context").path.clone();
            let keys_path = path.with_file_name("keys.toml");
            let before = fs::read(&keys_path).expect("saved keys");
            let owner = if stale {
                fs::write(&path, format!("{PROJECT_STATUS_FIXTURE}# external edit\n")).expect("external edit");
                None
            } else {
                Some(ProjectStore::open(&path).expect("reader").into_writer().expect("active writer"))
            };
            let expected = if stale { "changed after it was opened" } else { "already locked" };
            let key_error = app
                .project
                .persist_key_input(EditableKey::DeviceToolKey(button), "00112233445566778899AABBCCDDEEFF")
                .expect_err("key edit rejected");
            assert!(key_error.contains(expected), "{key_error}");
            let save_error = app.save_project().expect_err("save rejected");
            assert!(save_error.contains(expected), "{save_error}");
            assert_eq!(fs::read(&keys_path).expect("unchanged keys"), before);
            drop(owner);
        }
    }

    #[test]
    fn stale_editor_does_not_initialize_an_unsaved_project() {
        let (directory, mut app, _) = app_with_project();
        let path = app.project.context().expect("context").path.clone();
        fs::remove_file(path.with_file_name("keys.toml")).expect("remove fixture keys");
        fs::remove_dir_all(directory.path().join(".zweidraehte")).expect("remove fixture state");
        fs::write(&path, format!("{PROJECT_STATUS_FIXTURE}# external edit\n")).expect("external edit");
        let error = app.save_project().expect_err("stale editor");
        assert!(error.contains("changed after it was opened"), "{error}");
        assert!(!path.with_file_name("keys.toml").exists());
        assert!(!directory.path().join(".zweidraehte/snapshot.json").exists());
    }

    #[test]
    fn persisted_serials_merge_by_id_without_saving_or_discarding_drafts() {
        let (_directory, mut app, button) = app_with_project();
        let relay = ProjectDeviceId("relay".into());
        app.project.navigation_mut().expect("navigation").select(&ProjectNavigationTarget::Device(relay.clone()));
        let mut context = app.project.context().cloned().expect("project context");
        let authored = context.authored.as_ref().expect("authored project");
        context.authored = Some(
            authored
                .reparse(authored.source().replace("address 1.1.20", "address 1.1.21"))
                .expect("unsaved address edit"),
        );
        app.project.replace_context(context);
        app.project.navigation_mut().expect("navigation").select(&ProjectNavigationTarget::Device(relay.clone()));
        let serial = [0, 0xFA, 0, 0, 0, 1];
        app.apply_persisted_serial_updates(&BTreeMap::from([(button.clone(), Some(serial))])).expect("merge serial");

        let context = app.project.context().expect("project context");
        let draft = context.authored.as_ref().expect("draft");
        let original =
            draft.reparse(context.original_source.clone().expect("original source")).expect("original parses");
        assert_eq!(draft.devices[&button].serial, Some(serial));
        assert_eq!(original.devices[&button].serial, Some(serial));
        assert_eq!(draft.devices[&relay].serial, None);
        assert_eq!(draft.devices[&relay].address, zweidraehte_client::IndividualAddress::new(1, 1, 21));
        assert_eq!(original.devices[&relay].address, zweidraehte_client::IndividualAddress::new(1, 1, 20));
        assert_eq!(
            fs::read_to_string(&context.path).expect("disk source"),
            PROJECT_STATUS_FIXTURE,
            "the operation alone owns the write"
        );
        assert_eq!(
            app.project.navigation().and_then(ProjectNavigation::selected_target),
            Some(&ProjectNavigationTarget::Device(relay))
        );
    }

    #[test]
    fn download_completion_retains_typed_failure_and_ignores_another_projects_serials() {
        use zweidraehte_client::project::{ProjectBatchFailure, ProjectBatchFailureStage, ProjectBatchReport};

        let (_directory, mut app, button) = app_with_project();
        let (tx, receiver) = std::sync::mpsc::channel();
        let (control, _) = tokio::sync::mpsc::unbounded_channel();
        app.operations.start(DeviceOperation::Unloading, receiver, control);
        let failure = ProjectBatchFailure {
            device: Some(button.clone()),
            stage: ProjectBatchFailureStage::Finalization,
            report: ProjectBatchReport {
                serial_updates: BTreeMap::from([(button.clone(), Some([0, 0xFA, 0, 0, 0, 1]))]),
                affected_devices: BTreeSet::from([button.clone()]),
                ..Default::default()
            },
            source: None,
            state_errors: vec![],
            finalization: vec![],
        };
        tx.send(crate::download::DownloadMsg::Done(Ok(crate::download::DownloadOutcome {
            project_path: PathBuf::from("another/project.knx"),
            summary: String::new(),
            execution: Err(ProjectError::ProjectBatch(Box::new(failure))),
            status_scope: BTreeSet::from([button.clone()]),
        })))
        .expect("send worker outcome");
        app.poll_download();
        assert!(
            matches!(&app.operations.download().expect("download").execution, Some(Err(ProjectError::ProjectBatch(failure))) if failure.report.affected_devices.contains(&button))
        );
        assert_eq!(
            app.project.context().expect("context").authored.as_ref().expect("authored").devices[&button].serial,
            None
        );
        assert!(app.project.status().is_none());

        // A failure in this project can still have changed durable evidence.
        // Refresh from its original scope even if selection has moved elsewhere.
        let relay = ProjectDeviceId("relay".into());
        let mut context = app.project.context().cloned().expect("context");
        context.device = relay.clone();
        let project_path = context.path.clone();
        app.project.replace_context(context);
        let snapshot = status_snapshot(&app, BTreeSet::from([button.clone(), relay.clone()]));
        install_snapshot(&mut app, snapshot);
        let generation = app.project.generation();
        tx.send(crate::download::DownloadMsg::Done(Ok(crate::download::DownloadOutcome {
            project_path,
            summary: String::new(),
            execution: Err(ProjectError::ProjectBatch(Box::new(ProjectBatchFailure {
                device: Some(button.clone()),
                stage: ProjectBatchFailureStage::Commissioning,
                report: ProjectBatchReport { affected_devices: BTreeSet::from([button.clone()]), ..Default::default() },
                source: None,
                state_errors: vec![],
                finalization: vec![],
            }))),
            status_scope: BTreeSet::from([button.clone()]),
        })))
        .expect("partial failure");
        app.poll_download();
        assert!(app.project.generation() > generation);
        assert!(app.project.status().is_some());
        assert_eq!(app.project_programming_status(&button), None);
        assert_eq!(app.project_programming_status(&relay), None);
    }

    #[test]
    fn selected_group_address_survives_staging_before_rename() {
        let (_directory, mut app, _button) = app_with_project();
        let net = NetId("lights".into());
        app.navigation.focus = Focus::Project;
        app.project
            .navigation_mut()
            .expect("project navigation exists")
            .select(&ProjectNavigationTarget::Net(net.clone()));

        app.enter_selected_net_name_edit_mode();

        let EditMode::NetNameInput { net: edited, buffer, cursor } = &mut app.navigation.edit_mode else {
            panic!("selected group address enters name editing");
        };
        assert_eq!(edited, &net);
        *buffer = "Ceiling lights".into();
        *cursor = buffer.len();
        app.activate();

        assert!(matches!(app.navigation.edit_mode, EditMode::None));
        assert_eq!(
            app.project.navigation().and_then(ProjectNavigation::selected_target),
            Some(&ProjectNavigationTarget::Net(net.clone()))
        );
        assert_eq!(
            app.project
                .context()
                .and_then(|context| context.authored.as_ref())
                .and_then(|project| project.nets.get(&net))
                .and_then(|entry| entry.name.as_deref()),
            Some("Ceiling lights")
        );
    }

    // Use real planner output: tests must not manufacture revision/view pairs
    // that production callers cannot construct.
    fn status_snapshot(app: &App, scope: BTreeSet<ProjectDeviceId>) -> ProgrammingSnapshot {
        use zweidraehte_client::project::{ProjectPlanner, ProjectProduct};
        let mut project = app.project.context().expect("context").authored.clone().expect("project");
        // These tests exercise delivery and invalidation, independently of the
        // parameter editor's richer fixture and its absent package archive.
        for device in project.devices.values_mut() {
            device.objects.clear();
        }
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20"><ManufacturerData><Manufacturer RefId="M-00FA">
          <ApplicationPrograms><ApplicationProgram Id="M-00FA_A-1" ApplicationNumber="1" ApplicationVersion="1"
          ProgramType="ApplicationProgram" MaskVersion="MV-0012" Name="Button" LoadProcedureStyle="DefaultProcedure"
          PeiType="0" DefaultLanguage="en-US" DynamicTableManagement="false" Linkable="false"><Static/>
          </ApplicationProgram></ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#;
        let master = r#"<KNX xmlns="http://knx.org/xml/project/20"><MasterData Version="1"><MaskVersions>
          <MaskVersion Id="MV-0012" MaskVersion="18" Name="BCU1" ManagementModel="Bcu1" MediumTypeRefId="MT-0">
          <HawkConfigurationData><Procedures><Procedure ProcedureType="Load" ProcedureSubType="all">
          <LdCtrlConnect/><LdCtrlDisconnect/></Procedure></Procedures></HawkConfigurationData></MaskVersion>
          </MaskVersions></MasterData></KNX>"#;
        let selected =
            SelectedProduct::from_document(parse_application_program(xml).expect("document"), None, Some(master))
                .expect("selected fixture");
        let product = ProjectProduct::new(selected);
        let products = project.devices.keys().map(|id| (id.clone(), product.clone())).collect();
        ProjectPlanner::new(&project, None, &products, None, None).programming_snapshot_for(&scope).expect("status")
    }

    fn install_snapshot(app: &mut App, snapshot: ProgrammingSnapshot) {
        let tx = status_worker(app);
        tx.send(crate::status::StatusRefreshMsg::Done {
            generation: app.project.generation(),
            result: Ok(Box::new(crate::status::StatusRefreshOutcome {
                snapshot,
                cache: ProjectStatusCache::default(),
            })),
        })
        .expect("snapshot delivered");
        app.poll_startup_status();
    }

    fn status_worker(app: &mut App) -> std::sync::mpsc::Sender<crate::status::StatusRefreshMsg> {
        let (tx, receiver) = std::sync::mpsc::channel();
        app.project.begin_status(receiver, 3);
        tx
    }

    #[test]
    fn startup_status_installs_one_complete_project_view() {
        let (_directory, mut app, button) = app_with_project();
        let relay = ProjectDeviceId("relay".into());
        let tx = status_worker(&mut app);
        tx.send(crate::status::StatusRefreshMsg::Progress {
            generation: app.project.generation(),
            label: "Loading product for button".into(),
            completed: 1,
            total: 3,
        })
        .expect("progress is delivered");
        assert!(app.poll_startup_status());
        assert_eq!(app.startup_status().expect("refresh remains active").completed, 1);
        assert_eq!(app.startup_status_ratio(), 33);
        assert_eq!(app.project_programming_status(&button), None);

        let snapshot = status_snapshot(&app, BTreeSet::from([button.clone(), relay.clone()]));
        tx.send(crate::status::StatusRefreshMsg::Done {
            generation: app.project.generation(),
            result: Ok(Box::new(crate::status::StatusRefreshOutcome {
                snapshot,
                cache: ProjectStatusCache::default(),
            })),
        })
        .expect("result is delivered");
        assert!(app.poll_startup_status());
        assert!(!app.startup_status_active());
        assert_eq!(app.project_programming_status(&button), Some(DeviceProgrammingStatus::NONE));
        assert_eq!(app.project_programming_status(&relay), Some(DeviceProgrammingStatus::NONE));
    }

    #[test]
    fn refresh_does_not_preserve_rows_outside_the_new_snapshot() {
        let (_directory, mut app, button) = app_with_project();
        let relay = ProjectDeviceId("relay".into());
        let snapshot = status_snapshot(&app, BTreeSet::from([button.clone(), relay.clone()]));
        install_snapshot(&mut app, snapshot);
        let tx = status_worker(&mut app);
        let snapshot = status_snapshot(&app, BTreeSet::from([button.clone()]));
        tx.send(crate::status::StatusRefreshMsg::Done {
            generation: app.project.generation(),
            result: Ok(Box::new(crate::status::StatusRefreshOutcome {
                snapshot,
                cache: ProjectStatusCache::default(),
            })),
        })
        .expect("result is delivered");
        assert!(app.poll_startup_status());
        assert_eq!(app.project_programming_status(&button), Some(DeviceProgrammingStatus::NONE));
        assert_eq!(app.project_programming_status(&relay), None);
    }

    #[test]
    fn parameter_edits_refresh_object_rows_and_drafts_without_visiting_the_tab() {
        let xml = PARAMETER_REF_DEFAULT_FIXTURE
            .replace("</Static>", r#"
              <ComObjectTable><ComObject Id="M-00FA_A-1_O-0" Name="Output" Text="Output" Number="0"
                FunctionText="Value" ObjectSize="1 Byte" CommunicationFlag="Enabled" TransmitFlag="Enabled"
                ReadFlag="Disabled" WriteFlag="Enabled" UpdateFlag="Enabled" ReadOnInitFlag="Disabled"/></ComObjectTable>
              <ComObjectRefs>
                <ComObjectRef Id="M-00FA_A-1_O-0_R-1" RefId="M-00FA_A-1_O-0" DatapointType="DPST-5-1"/>
                <ComObjectRef Id="M-00FA_A-1_O-0_R-2" RefId="M-00FA_A-1_O-0" DatapointType="DPST-5-10"/>
              </ComObjectRefs></Static>"#)
            .replace("</ParameterBlock>", r#"
              <choose ParamRefId="M-00FA_A-1_P-1_R-1">
                <when test="60"><ComObjectRefRef RefId="M-00FA_A-1_O-0_R-1"/></when>
                <when test="42"><ComObjectRefRef RefId="M-00FA_A-1_O-0_R-2"/></when>
              </choose></ParameterBlock>"#);
        let (_directory, mut app, _) = app_with_project();
        app.product.replace(prepared_fixture(&xml, EMPTY_MASTER));
        app.product.set_group_addresses(0, vec![GroupAddress::from_three_level(7, 1, 1)]);
        app.product.ensure_com_objects();
        assert_eq!(app.product_view().com_object_rows[0].dpt, "DPST-5-1");

        app.product.set_parameter(&mut app.navigation, "M-00FA_A-1_P-1_R-1", ParameterValue::Integer(42));
        let draft = app.project.draft(app.product_view()).expect("draft uses evaluated product");
        assert_eq!(draft.nets[&NetId("ga_7_1_1".into())].dpt, "5.010");

        app.navigation.current_tab = MainTab::CommObjects;
        app.ensure_tab_data();
        assert_eq!(app.product_view().com_object_rows[0].dpt, "DPST-5-10");
        assert_eq!(app.product_view().com_object_rows[0].group_address, "7/1/1");
        app.product.set_object_flags(0, ObjectFlagOverrides { read: Some(true), ..Default::default() });
        app.ensure_tab_data();
        assert!(app.product_view().com_object_rows[0].flag_r);
    }

    #[test]
    fn language_change_rejects_already_queued_status() {
        let (_directory, mut app, button) = app_with_project();
        let worker = status_worker(&mut app);
        worker
            .send(crate::status::StatusRefreshMsg::Done {
                generation: app.project.generation(),
                result: Ok(Box::new(crate::status::StatusRefreshOutcome {
                    snapshot: status_snapshot(&app, BTreeSet::from([button.clone()])),
                    cache: ProjectStatusCache::default(),
                })),
            })
            .expect("queue result before language changes");

        app.project.set_language(Some("de-DE")).expect("language changes draft");
        assert!(!app.poll_startup_status());
        assert_eq!(app.project_programming_status(&button), None);
        assert_eq!(
            app.project.context().expect("context").authored.as_ref().expect("draft").language.as_deref(),
            Some("de-DE")
        );
    }

    #[test]
    fn late_worker_messages_cannot_restore_status_after_an_edit() {
        let (_directory, mut app, button) = app_with_project();
        let snapshot = status_snapshot(&app, BTreeSet::from([button.clone()]));
        let old_worker = status_worker(&mut app);
        let old_generation = app.project.generation();
        old_worker
            .send(crate::status::StatusRefreshMsg::Done {
                generation: old_generation,
                result: Ok(Box::new(crate::status::StatusRefreshOutcome {
                    snapshot: snapshot.clone(),
                    cache: ProjectStatusCache::default(),
                })),
            })
            .expect("queued result");
        let mut context = app.project.context().cloned().expect("context");
        let authored = context.authored.as_ref().expect("authored draft");
        context.authored = Some(
            authored
                .reparse(authored.source().replace("address 1.1.10", "address 1.1.12"))
                .expect("new draft for the same products"),
        );
        app.set_project_context(context, BTreeMap::new());
        assert!(!app.poll_startup_status());
        assert_eq!(app.project_programming_status(&button), None);

        let current_worker = status_worker(&mut app);
        current_worker
            .send(crate::status::StatusRefreshMsg::Done {
                generation: old_generation,
                result: Ok(Box::new(crate::status::StatusRefreshOutcome {
                    snapshot: snapshot.clone(),
                    cache: ProjectStatusCache::default(),
                })),
            })
            .expect("obsolete generation");
        assert!(!app.poll_startup_status());
        assert_eq!(app.project_programming_status(&button), None);
        current_worker
            .send(crate::status::StatusRefreshMsg::Done {
                generation: app.project.generation(),
                result: Ok(Box::new(crate::status::StatusRefreshOutcome {
                    snapshot,
                    cache: ProjectStatusCache::default(),
                })),
            })
            .expect("current generation");
        assert!(app.poll_startup_status());
        assert!(app.project_programming_status(&button).is_some());
    }

    #[test]
    fn queued_status_rejects_external_file_changes_before_display() {
        use zweidraehte_client::project::{ProjectStatusInputs, ProjectStatusRequest};
        let (_directory, mut app, button) = app_with_project();
        let path = app.project.context().expect("context").path.clone();
        fs::write(&path, "# empty saved project\n").expect("source");
        let snapshot = ProjectStatusInputs::load(
            ProjectStatusRequest {
                project_path: &path,
                draft: None,
                scope: None,
                master_data: None,
                keyring_path: None,
            },
            &mut ProjectStatusCache::default(),
            || Ok(None),
            |_, _, _| {},
        )
        .expect("coherent inputs")
        .snapshot()
        .expect("status");
        let tx = status_worker(&mut app);
        tx.send(crate::status::StatusRefreshMsg::Done {
            generation: app.project.generation(),
            result: Ok(Box::new(crate::status::StatusRefreshOutcome {
                snapshot,
                cache: ProjectStatusCache::default(),
            })),
        })
        .expect("queued result");
        fs::write(&path, "# external modification\n").expect("external edit");

        assert!(app.poll_startup_status());
        assert!(app.startup_status_failed());
        assert_eq!(app.project_programming_status(&button), None);
    }

    #[test]
    fn automatic_programming_summary_keeps_uncomputed_status_unknown() {
        let (_directory, mut app, _button) = app_with_project();
        app.operations.programming_dialog = Some(ProgrammingDialog {
            operation: crate::download::ProgrammingOperation::Partial,
            target: ProgrammingTarget::Selected,
            desired_address: "1.1.10".into(),
            overwrite_address_input: None,
            overwrite_address_error: None,
        });
        assert_eq!(app.programming_effect_summary().as_deref(), Some("Programming status is not available yet"));
        app.operations.programming_dialog.as_mut().expect("dialog").target = ProgrammingTarget::Affected;
        assert_eq!(app.programming_effect_summary().as_deref(), Some("Programming status is not available yet"));
    }

    #[test]
    fn startup_status_failure_remains_readable_until_dismissed() {
        let (_directory, mut app, _button) = app_with_project();
        let tx = status_worker(&mut app);
        tx.send(crate::status::StatusRefreshMsg::Done {
            generation: app.project.generation(),
            result: Err("exact status failure".into()),
        })
        .expect("failure is delivered");
        drop(tx);
        assert!(app.poll_startup_status());
        assert!(app.startup_status_failed());
        assert_eq!(app.startup_status().and_then(|status| status.error.as_deref()), Some("exact status failure"));
        assert!(!app.poll_startup_status(), "acknowledged worker result is not replaced by channel closure");
        assert_eq!(app.startup_status().and_then(|status| status.error.as_deref()), Some("exact status failure"));
        app.dismiss_startup_status();
        assert!(!app.startup_status_active());
    }

    #[test]
    fn parameter_edit_invalidates_the_previous_revision() {
        let (_directory, mut app, button) = app_with_project();
        let relay = ProjectDeviceId("relay".into());
        let snapshot = status_snapshot(&app, BTreeSet::from([button.clone(), relay.clone()]));
        install_snapshot(&mut app, snapshot);
        assert!(app.project_programming_status(&relay).is_some());
        app.navigation.edit_mode = EditMode::NumberInput {
            param_id: "M-00FA_A-1_P-1".into(),
            buffer: "42".into(),
            select_all: false,
            min: Some(0),
            max: Some(100),
        };

        app.activate();

        assert_eq!(app.project_programming_status(&button), None);
        assert_eq!(app.project_programming_status(&relay), None);
    }

    #[test]
    fn parameter_ref_edits_render_as_valid_project_overrides() {
        let (_directory, mut app, _button) = app_with_project();
        let parameter_id = "M-00FA_A-1_UP-570_R-2";
        let _ = app.product.set_parameter(&mut app.navigation, parameter_id, ParameterValue::Integer(4));
        let context = app.project.context().expect("project context exists");

        let draft = app.project.draft(app.product.view()).expect("project draft renders");
        assert!(draft.parameters.iter().any(|parameter| parameter.id == parameter_id));
        let project = context.authored.as_ref().expect("authored project exists");
        let source = project.render_device_update(&draft).expect("device update renders");

        project
            .reparse(source)
            .expect("rendered project parses")
            .validate_download()
            .expect("union parameter override validates");
    }

    #[test]
    fn object_flag_edit_invalidates_the_previous_revision() {
        let (_directory, mut app, button) = app_with_project();
        let relay = ProjectDeviceId("relay".into());
        let snapshot = status_snapshot(&app, BTreeSet::from([button.clone(), relay.clone()]));
        install_snapshot(&mut app, snapshot);
        assert!(app.project_programming_status(&relay).is_some());
        app.navigation.edit_mode = EditMode::ObjectFlagsInput { object_number: 0, buffer: "C=0".into() };

        app.activate();

        assert_eq!(app.project_programming_status(&button), None);
        assert_eq!(app.project_programming_status(&relay), None);
    }

    #[test]
    fn group_link_edit_invalidates_the_previous_revision() {
        let (_directory, mut app, button) = app_with_project();
        let relay = ProjectDeviceId("relay".into());
        let snapshot = status_snapshot(&app, BTreeSet::from([button.clone(), relay.clone()]));
        install_snapshot(&mut app, snapshot);
        assert!(app.project_programming_status(&relay).is_some());
        app.navigation.edit_mode = EditMode::GroupAddressInput { object_number: 0, buffer: "1/0/1".into() };

        app.activate();

        assert_eq!(app.project_programming_status(&button), None);
        assert_eq!(app.project_programming_status(&relay), None);
    }

    #[test]
    fn data_secure_edit_invalidates_the_previous_revision() {
        let (_directory, mut app, button) = app_with_project();
        let relay = ProjectDeviceId("relay".into());
        let snapshot = status_snapshot(&app, BTreeSet::from([button.clone(), relay.clone()]));
        install_snapshot(&mut app, snapshot);
        assert!(app.project_programming_status(&relay).is_some());

        app.toggle_data_secure();

        assert_eq!(app.project_programming_status(&button), None);
        assert_eq!(app.project_programming_status(&relay), None);
    }

    #[test]
    fn group_address_edit_rejects_invalid_input_without_changing_links() {
        use zweidraehte_proto::address::GroupAddress;

        for input in ["bad, 2/1/3", "2/1/3, bad, worse"] {
            let mut app = parameter_ref_default_app();
            let original = [GroupAddress::from_three_level(1, 2, 3), GroupAddress::from_three_level(1, 2, 4)];
            app.product.set_group_addresses(0, original.to_vec());
            app.navigation.edit_mode = EditMode::GroupAddressInput { object_number: 0, buffer: input.into() };

            app.activate();

            let links = app.product.view().device.get_group_addresses(0);
            assert_eq!(links.iter().map(|link| link.group_address).collect::<Vec<_>>(), original);
            assert!(links[0].is_sending);
            assert!(!links[1].is_sending);
            assert!(matches!(
                &app.navigation.edit_mode,
                EditMode::GroupAddressInput { object_number: 0, buffer } if buffer == input
            ));
            assert_eq!(
                app.navigation.status_message.as_deref(),
                Some("'bad' is not a group address (main/middle/sub)")
            );
        }
    }

    #[test]
    fn group_address_edit_replaces_links_in_order_and_allows_clearing() {
        use zweidraehte_proto::address::GroupAddress;

        let mut app = parameter_ref_default_app();
        app.product.set_group_addresses(0, vec![GroupAddress::from_three_level(1, 2, 3)]);
        app.navigation.status_message = Some("previous validation error".into());
        app.navigation.edit_mode =
            EditMode::GroupAddressInput { object_number: 0, buffer: "2/1/3, 1/1/1 2/1/3".into() };

        app.activate();

        let links = app.product.view().device.get_group_addresses(0);
        assert_eq!(links.iter().map(|link| (link.group_address, link.is_sending)).collect::<Vec<_>>(), [
            (GroupAddress::from_three_level(2, 1, 3), true),
            (GroupAddress::from_three_level(1, 1, 1), false)
        ]);
        assert!(matches!(app.navigation.edit_mode, EditMode::None));
        assert_eq!(app.navigation.status_message, None);

        app.navigation.edit_mode = EditMode::GroupAddressInput { object_number: 0, buffer: String::new() };
        app.activate();

        assert!(app.product.view().device.get_group_addresses(0).is_empty());
        assert!(matches!(app.navigation.edit_mode, EditMode::None));
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

    /// Separator headings on the current content page.
    fn page_headings(app: &App) -> Vec<&str> {
        app.product
            .view()
            .content_items
            .iter()
            .filter_map(|item| match item {
                ContentItem::Separator { text, .. } => text.as_deref(),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn parameter_pages_resolve_by_id_with_missing_or_duplicate_names() {
        for name in ["", " Name=\"Shared\""] {
            let xml = PARAMETER_REF_DEFAULT_FIXTURE
                .replace("<ParameterBlock Id=", &format!("<ParameterBlock{name} Id="))
                .replace("</ParameterBlock>", r#"<ParameterSeparator Id="first" Text="First page" /></ParameterBlock>"#)
                .replace(
                    "</Channel>",
                    &format!(
                        r#"<ParameterBlock Id="M-00FA_A-1_PB-2"{name} Text="Second">
                          <ParameterRefRef RefId="M-00FA_A-1_P-1_R-1" />
                          <ParameterSeparator Id="second" Text="Second page" />
                        </ParameterBlock></Channel>"#
                    ),
                );
            let cib_xml = xml
                .replace(r#"<Channel Id="M-00FA_A-1_CH-1" Name="Main">"#, "<ChannelIndependentBlock>")
                .replace("</Channel>", "</ChannelIndependentBlock>");

            for xml in [&xml, &cib_xml] {
                let mut app = App::new(prepared_fixture(xml, EMPTY_MASTER));
                let pages: Vec<_> = app
                    .product
                    .view()
                    .tree_nodes
                    .iter()
                    .enumerate()
                    .filter(|(_, node)| matches!(node.node_type, NodeType::ParameterBlock { .. }))
                    .map(|(index, node)| (index, node.id.clone()))
                    .collect();
                assert_eq!(pages.len(), 2);
                assert_ne!(pages[0].1, pages[1].1);

                for ((index, _), heading) in pages.into_iter().zip(["First page", "Second page"]) {
                    app.navigation.selected_tree_idx = index;
                    app.rebuild_content();

                    assert_eq!(page_headings(&app), [heading]);
                    assert!(
                        app.product
                            .view()
                            .content_items
                            .iter()
                            .any(|item| matches!(item, ContentItem::Parameter { .. }))
                    );
                }
            }
        }
    }

    #[test]
    fn choose_uses_reference_default_until_selector_is_edited() {
        let xml = PARAMETER_REF_DEFAULT_FIXTURE
            .replace(
                "</ParameterRefs>",
                r#"<ParameterRef Id="M-00FA_A-1_P-1_R-2" RefId="M-00FA_A-1_P-1" /></ParameterRefs>"#,
            )
            .replace(
                "</ParameterBlock>",
                r#"<choose ParamRefId="M-00FA_A-1_P-1_R-1">
                  <when default="true"><ParameterSeparator Id="fallback" Text="Fallback" /></when>
                  <when test="60">
                    <ParameterRefRef RefId="M-00FA_A-1_P-1_R-2" />
                    <ParameterSeparator Id="matched" Text="Matched" />
                  </when>
                </choose></ParameterBlock>"#,
            );
        let mut app = App::new(prepared_fixture(&xml, EMPTY_MASTER));
        app.navigation.selected_tree_idx = app
            .product
            .view()
            .tree_nodes
            .iter()
            .position(|node| matches!(node.node_type, NodeType::ParameterBlock { .. }))
            .expect("fixture has a parameter page");

        // The untouched selector, runtime visibility and the TUI branch must
        // all use the reference default 60. Editing the base parameter to its
        // own default (50) must still override the reference. The widget half
        // is `parameter_widget_uses_the_visible_reference_default_until_edited`.
        for (edit, expected, branch) in [(None, 60, "Matched"), (Some(50), 50, "Fallback"), (Some(60), 60, "Matched")] {
            if let Some(value) = edit {
                app.product.set_parameter(&mut app.navigation, "M-00FA_A-1_P-1", ParameterValue::Integer(value));
            }
            app.rebuild_content();

            assert_eq!(app.product.view().device.is_param_ref_visible("M-00FA_A-1_P-1_R-2"), expected == 60);
            assert_eq!(page_headings(&app), [branch]);
        }
    }

    #[test]
    fn parameter_widget_uses_the_visible_reference_default_until_edited() {
        let mut app = parameter_ref_default_app();
        let parameter_id = "M-00FA_A-1_P-1";

        let WidgetType::Number { value, .. } = FormPresentation::parameter_widget(
            &app.product.view().device.parameter_description(parameter_id).expect("parameter"),
        ) else {
            panic!("number parameter has a numeric widget");
        };

        assert_eq!(value, 60);

        app.product.set_parameter(&mut app.navigation, parameter_id, ParameterValue::Integer(50));

        let WidgetType::Number { value, .. } = FormPresentation::parameter_widget(
            &app.product.view().device.parameter_description(parameter_id).expect("parameter"),
        ) else {
            panic!("number parameter has a numeric widget");
        };

        assert_eq!(value, 50);
    }

    #[test]
    fn root_and_module_float_widgets_preserve_fractional_reference_defaults() {
        for encoding in ["DPT 9", "IEEE-754 Single", "IEEE-754 Double"] {
            let start = TABLE_FIXTURE.find("<TypeRestriction").expect("fixture restriction");
            let end =
                TABLE_FIXTURE.find("</TypeRestriction>").expect("fixture restriction end") + "</TypeRestriction>".len();
            let mut xml = TABLE_FIXTURE.to_owned();
            xml.replace_range(
                start..end,
                &format!("<TypeFloat Encoding=\"{encoding}\" minInclusive=\"0\" maxInclusive=\"100\"/>"),
            );
            for id in ["M-00FA_A-2_P-INLINE", "M-00FA_A-2_MD-PAGE_P-1"] {
                xml = xml.replace(&format!("RefId=\"{id}\"/>"), &format!("RefId=\"{id}\" Value=\"2.75\"/>"));
            }
            let app = App::new(prepared_fixture(&xml, EMPTY_MASTER));
            for id in ["M-00FA_A-2_P-INLINE_R-1", "M-00FA_A-2_MD-PAGE_M-1::M-00FA_A-2_MD-PAGE_P-1_R-1"] {
                let WidgetType::ReadOnly { value } = FormPresentation::parameter_widget(
                    &app.product.view().device.parameter_description(id).expect("parameter"),
                ) else {
                    panic!("float editing is intentionally unsupported: {encoding} {id}");
                };
                assert_eq!(value, "2.75", "{encoding} {id}");
            }
        }
    }

    #[test]
    fn root_and_module_widgets_use_reference_access_defaults_and_labels() {
        let mut xml = TABLE_FIXTURE.to_owned();
        for id in ["M-00FA_A-2_P-INLINE", "M-00FA_A-2_MD-PAGE_P-1"] {
            xml = xml.replace(
                &format!("RefId=\"{id}\"/>"),
                &format!("RefId=\"{id}\" Value=\"1\" Access=\"Read\" Text=\"Function\"/>"),
            );
        }
        xml = xml.replace("</ApplicationPrograms>", r#"</ApplicationPrograms>
          <Languages><Language Identifier="de-DE"><TranslationUnit RefId="M-00FA_A-2">
            <TranslationElement RefId="M-00FA_A-2_P-INLINE_R-1"><Translation AttributeName="Text" Text="Funktion"/></TranslationElement>
            <TranslationElement RefId="M-00FA_A-2_MD-PAGE_P-1_R-1"><Translation AttributeName="Text" Text="Funktion"/></TranslationElement>
          </TranslationUnit></Language></Languages>"#);
        let mut app = App::new(prepared_fixture(&xml, EMPTY_MASTER));
        app.switch_language(Some("de-DE".into()));
        for id in ["M-00FA_A-2_P-INLINE_R-1", "M-00FA_A-2_MD-PAGE_M-1::M-00FA_A-2_MD-PAGE_P-1_R-1"] {
            let description = app.product.view().device.parameter_description(id).expect("known reference");
            assert_eq!(description.text, "Funktion");
            assert_eq!(description.default, Some(ParameterValue::Integer(1)));
            assert!(!description.writable);
            assert!(!description.modified);
            let WidgetType::ReadOnly { value } = FormPresentation::parameter_widget(&description) else {
                panic!("read-only reference");
            };
            assert_eq!(value, "Switch");
        }
    }

    #[test]
    fn parameter_non_default_status_tracks_the_effective_default() {
        let mut app = parameter_ref_default_app();
        let parameter_id = "M-00FA_A-1_P-1";

        assert!(!app.product.view().device.parameter_description(parameter_id).expect("parameter").modified);

        app.product.set_parameter(&mut app.navigation, parameter_id, ParameterValue::Integer(50));

        assert!(app.product.view().device.parameter_description(parameter_id).expect("parameter").modified);

        app.product.set_parameter(&mut app.navigation, parameter_id, ParameterValue::Integer(60));

        assert!(!app.product.view().device.parameter_description(parameter_id).expect("parameter").modified);
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
    fn backward_focus_navigation_reverses_each_tab_cycle() {
        let mut app = parameter_ref_default_app();

        for tab in [MainTab::Parameters, MainTab::Memory] {
            app.navigation.current_tab = tab;
            app.navigation.focus = Focus::Tabs;

            for expected in [Focus::Content, Focus::Sidebar, Focus::Tabs] {
                app.focus_previous();
                assert_eq!(app.navigation.focus, expected);
            }
        }

        app.navigation.current_tab = MainTab::CommObjects;
        app.navigation.focus = Focus::Tabs;

        app.focus_previous();
        assert_eq!(app.navigation.focus, Focus::Content);

        app.focus_previous();
        assert_eq!(app.navigation.focus, Focus::Tabs);
    }

    #[test]
    fn backward_focus_navigation_includes_the_project_pane() {
        let project = AuthoredProject::parse(
            "ga lights = 1/0/1\n\
             net lights : 1.001 { security plain }\n\
             area 1 bench { line 1 main { medium tp1\n\
               device button { product package:\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" catalog_item \"button\" address 1.1.10 object 0 { on lights } }\n\
             } }\n",
        )
        .expect("project parses");
        let active_device = ProjectDeviceId("button".into());
        let mut app = parameter_ref_default_app();
        app.project.replace_context(ProjectContext {
            path: PathBuf::from("project.knx"),
            device: active_device,
            original_source: Some(project.source().into()),
            authored: Some(project),
        });

        for tab in [MainTab::Parameters, MainTab::Memory] {
            app.navigation.current_tab = tab;
            app.navigation.focus = Focus::Tabs;

            for expected in [Focus::Project, Focus::Content, Focus::Sidebar, Focus::Tabs] {
                app.focus_previous();
                assert_eq!(app.navigation.focus, expected);
            }
        }

        app.navigation.current_tab = MainTab::CommObjects;
        app.navigation.focus = Focus::Tabs;

        for expected in [Focus::Project, Focus::Content, Focus::Tabs] {
            app.focus_previous();
            assert_eq!(app.navigation.focus, expected);
        }
    }

    #[test]
    fn tui_preferences_round_trip_as_project_local_editor_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project = directory.path().join("project.knx");
        let state_directory = directory.path().join(".zweidraehte");
        fs::create_dir(&state_directory).expect("state directory is created");
        fs::write(
            state_directory.join(TuiPreferences::STATE_FILE),
            "# retained editor setting\nversion = 1\nfuture_setting = true\n",
        )
        .expect("initial preferences write");

        let previous =
            TuiPreferences::load(&project).expect("existing TUI preferences load").expect("preferences file exists");
        assert!(previous.highlight_non_default_parameters);

        let preferences = TuiPreferences {
            panes: PaneLayout {
                project_width: 42,
                topology_percent: 65,
                parameter_sidebar_width: 36,
                memory_sidebar_width: 40,
            },
            highlight_non_default_parameters: false,
        };
        preferences.persist(&project).expect("TUI preferences persist");

        assert_eq!(TuiPreferences::load(&project).expect("TUI preferences load"), Some(preferences));
        let source = fs::read_to_string(state_directory.join(TuiPreferences::STATE_FILE)).expect("preferences read");
        assert!(source.contains("# retained editor setting"));
        assert!(source.contains("future_setting = true"));
        assert!(source.contains("highlight_non_default = false"));
    }

    #[test]
    fn non_default_highlight_toggle_updates_the_persisted_preference() {
        let mut app = parameter_ref_default_app();

        assert!(app.highlight_non_default_parameters());
        assert!(!app.navigation.tui_preferences_dirty);

        app.toggle_non_default_highlight();

        assert!(!app.highlight_non_default_parameters());
        assert!(app.navigation.tui_preferences_dirty);
        assert_eq!(app.navigation().status_message.as_deref(), Some("Non-default parameter highlighting disabled"));
    }

    #[test]
    fn unload_selection_moves_between_application_and_all() {
        let mut app = parameter_ref_default_app();
        app.operations.unload_confirmation = Some(crate::download::UnloadScope::Application);

        app.operations.move_unload_selection(1);
        assert_eq!(app.operations.unload_confirmation(), Some(crate::download::UnloadScope::All));

        app.operations.move_unload_selection(1);
        assert_eq!(app.operations.unload_confirmation(), Some(crate::download::UnloadScope::All));

        app.operations.move_unload_selection(-10);
        assert_eq!(app.operations.unload_confirmation(), Some(crate::download::UnloadScope::Application));

        app.operations.cancel_unload_confirmation();
        assert!(!app.operations.unload_confirmation_active());
    }

    #[test]
    fn programming_selector_separates_operation_from_target() {
        let mut app = parameter_ref_default_app();
        app.operations.programming_dialog = Some(ProgrammingDialog {
            operation: crate::download::ProgrammingOperation::Partial,
            target: ProgrammingTarget::Selected,
            desired_address: "1.1.2".into(),
            overwrite_address_input: None,
            overwrite_address_error: None,
        });

        app.toggle_programming_target();
        assert_eq!(
            app.operations.programming_dialog().expect("dialog remains open").target,
            ProgrammingTarget::Affected
        );

        app.select_programming_operation(2);
        let dialog = app.operations.programming_dialog().expect("dialog remains open");
        assert_eq!(dialog.operation, crate::download::ProgrammingOperation::IndividualAddress);
        assert_eq!(dialog.target, ProgrammingTarget::Selected);

        app.move_programming_selection(1);
        assert_eq!(
            app.operations.programming_dialog().expect("dialog remains open").operation,
            crate::download::ProgrammingOperation::OverwriteIndividualAddress
        );
        assert_eq!(
            app.programming_effect_summary().as_deref(),
            Some("Will update: Adr; secure consumers become Grp-stale")
        );

        app.cancel_programming_dialog();
        assert!(!app.operations.programming_dialog_active());
    }

    #[test]
    fn programming_selector_describes_the_parts_it_will_update() {
        let (_directory, mut app, button) = app_with_project();
        let snapshot = status_snapshot(&app, BTreeSet::from([button]));
        install_snapshot(&mut app, snapshot);
        app.operations.programming_dialog = Some(ProgrammingDialog {
            operation: crate::download::ProgrammingOperation::Partial,
            target: ProgrammingTarget::Selected,
            desired_address: "1.1.1".into(),
            overwrite_address_input: None,
            overwrite_address_error: None,
        });

        assert_eq!(app.programming_effect_summary().as_deref(), Some("Will update stale: Adr Prg Par Grp Cfg"));

        app.select_programming_operation(4);
        assert_eq!(app.programming_effect_summary().as_deref(), Some("Will update: Prg Par Grp Cfg"));
    }

    #[test]
    fn overwrite_address_is_entered_explicitly() {
        let mut app = parameter_ref_default_app();
        app.operations.programming_dialog = Some(ProgrammingDialog {
            operation: crate::download::ProgrammingOperation::OverwriteIndividualAddress,
            target: ProgrammingTarget::Selected,
            desired_address: "1.1.2".into(),
            overwrite_address_input: None,
            overwrite_address_error: None,
        });

        app.confirm_programming_dialog();
        assert!(app.programming_address_input_active());

        for character in "1.1.2".chars() {
            app.push_programming_address_character(character);
        }
        app.confirm_programming_dialog();

        assert_eq!(
            app.operations.programming_dialog().and_then(|dialog| dialog.overwrite_address_error.as_deref()),
            Some("Current IA already equals the configured IA")
        );

        app.pop_programming_address_character();
        app.push_programming_address_character('1');
        assert_eq!(
            app.operations.programming_dialog().and_then(|dialog| dialog.overwrite_address_input.as_deref()),
            Some("1.1.1")
        );
        assert_eq!(
            app.operations.programming_dialog().and_then(|dialog| dialog.overwrite_address_error.as_deref()),
            None
        );
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
        assert_eq!(project_dpt("DPT-1 DPST-1-1", "1 Bit"), "1.001");
    }
}
