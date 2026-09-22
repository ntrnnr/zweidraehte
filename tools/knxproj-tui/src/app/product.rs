//! Product edits own invalidation of every derived presentation.

use super::{NavigationState, PreparedEditorProduct, ProjectContext};
#[cfg(feature = "images")]
use ratatui_image::{picker::Picker, protocol::StatefulProtocol};
use std::collections::BTreeMap;
#[cfg(feature = "images")]
use std::collections::HashMap;
use zweidraehte_client::commissioning::{ImageRequirement, ProgrammingCatalog};
use zweidraehte_client::project::product_object_flags;
use zweidraehte_ets_files::product::SelectedProduct;
use zweidraehte_ets_files::runtime::configuration::{
    EffectiveValueSource, ObjectSetting, ProductConfiguration, apply_configuration, configuration_from_device,
    effective_com_objects,
};
use zweidraehte_ets_files::runtime::model::ParameterValue;
use zweidraehte_ets_files::schema::master_data::MaskVersion;
use zweidraehte_ets_files::{Device, MasterData};
use zweidraehte_project::{DataSecureMode, ObjectFlagOverrides};
use zweidraehte_proto::address::GroupAddress;
mod memory;
mod presentation;
pub use memory::{MemoryAnnotation, MemorySegment, image_requirements_label};
pub use presentation::*;

/// Runtime product and derived rows borrowed together from the editor.
/// Only editor commands can mutate the instance held by `App`.
pub struct ProductView {
    pub device: Device,
    /// Selected Master Data shared by display views and image compilation.
    pub programming_catalog: ProgrammingCatalog,
    pub tree_nodes: Vec<TreeNode>,
    pub content_items: Vec<ContentItem>,
    /// Natural terminal-cell width of the widest label on the current page.
    pub content_label_width: usize,
    /// Natural terminal-cell width of the widest value on the current page.
    pub content_value_width: usize,
    /// Visible parameter-ref count shown in the status bar. Cached
    /// because counting means hashing every visible ref id (~100k on
    /// large products), far too much to redo every frame. Product commands
    /// refresh these counts when visibility can change.
    pub visible_param_count: usize,
    /// Visible com-object-ref count for the status bar; same caching.
    pub visible_obj_count: usize,
    pub com_object_rows: Vec<ComObjectRow>,
    pub memory_segments: Vec<MemorySegment>,
    pub memory_requirements: Vec<ImageRequirement>,
    pub language_context: Option<LanguageContext>,
    pub current_language: Option<String>,
    pub object_flag_overrides: BTreeMap<u16, ObjectFlagOverrides>,
    pub data_secure: DataSecureMode,
}

impl std::fmt::Debug for ProductView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProductView")
            .field("product", &self.device.program().id)
            .field("language", &self.current_language)
            .finish_non_exhaustive()
    }
}

pub(super) struct ProductEditor {
    view: ProductView,
    content_page: Option<usize>,
    com_objects_dirty: bool,
    memory_dirty: bool,
    #[cfg(feature = "images")]
    image_picker: Option<Picker>,
    #[cfg(feature = "images")]
    image_cache: HashMap<String, (StatefulProtocol, (u32, u32))>,
}

impl ProductEditor {
    pub(super) fn new(product: PreparedEditorProduct) -> Self {
        let PreparedEditorProduct { device, programming_catalog, language_context, current_language } = product;
        Self {
            view: ProductView {
                device,
                programming_catalog,
                language_context,
                current_language,
                tree_nodes: Vec::new(),
                content_items: Vec::new(),
                content_label_width: 0,
                content_value_width: 0,
                visible_param_count: 0,
                visible_obj_count: 0,
                com_object_rows: Vec::new(),
                memory_segments: Vec::new(),
                memory_requirements: Vec::new(),
                object_flag_overrides: BTreeMap::new(),
                data_secure: DataSecureMode::Disabled,
            },
            content_page: None,
            com_objects_dirty: true,
            memory_dirty: true,
            #[cfg(feature = "images")]
            image_picker: Some(Picker::halfblocks()),
            #[cfg(feature = "images")]
            image_cache: HashMap::new(),
        }
    }

    pub(super) fn switch_language(&mut self, next: Option<String>) -> Result<bool, String> {
        let Some(context) = &self.view.language_context else {
            return Ok(false);
        };
        if next == self.view.current_language {
            return Ok(false);
        }

        // Snapshot the session's edits, rebuild in the new language,
        // and replay them.
        let mut edits = configuration_from_device(&self.view.device);
        edits.objects = self
            .view
            .object_flag_overrides
            .iter()
            .map(|(&com_object, &flags)| ObjectSetting { com_object, flags: product_object_flags(flags) })
            .collect();
        let bindings: Vec<_> = self
            .view
            .device
            .all_bindings()
            .map(|(object, bindings)| {
                (object, bindings.iter().map(|binding| binding.group_address).collect::<Vec<_>>())
            })
            .collect();
        let mut device = Device::from_product(context.selected.clone(), context.baggage.clone(), next.as_deref());
        if let Err(e) = apply_configuration(&mut device, &edits) {
            // Values that applied to the old device apply to the new
            // one — same program, different texts. Failing here would
            // be a bug worth seeing, not hiding.
            return Err(format!("Language switch failed replaying edits: {e}"));
        }
        for (object, addresses) in bindings {
            for address in addresses {
                device.assign_group_address(object, address);
            }
        }
        self.view.device = device;
        self.view.current_language = next;

        self.content_page = None;
        self.mark_derived_views_dirty();
        Ok(true)
    }

    pub(super) fn set_project_configuration(
        &mut self,
        flags: BTreeMap<u16, ObjectFlagOverrides>,
        secure: DataSecureMode,
    ) {
        self.view.object_flag_overrides = flags;
        self.view.data_secure = secure;
        self.mark_derived_views_dirty();
    }

    pub(super) fn set_object_flags(&mut self, number: u16, flags: ObjectFlagOverrides) -> bool {
        let changed = self.view.object_flag_overrides.get(&number).copied().unwrap_or_default() != flags;
        if flags == ObjectFlagOverrides::default() {
            self.view.object_flag_overrides.remove(&number);
        } else {
            self.view.object_flag_overrides.insert(number, flags);
        }
        if changed {
            self.mark_derived_views_dirty();
        }
        changed
    }

    pub(super) fn set_group_addresses(&mut self, number: u16, addresses: Vec<GroupAddress>) {
        self.view.device.clear_group_addresses(number);
        for address in addresses {
            self.view.device.assign_group_address(number, address);
        }
        self.mark_derived_views_dirty();
    }

    pub(super) fn toggle_data_secure(&mut self) -> bool {
        if !self.view.device.program().is_secure_enabled.unwrap_or(false) {
            return false;
        }
        self.view.data_secure = match self.view.data_secure {
            DataSecureMode::Disabled => DataSecureMode::Enabled,
            DataSecureMode::Enabled => DataSecureMode::Disabled,
        };
        self.mark_derived_views_dirty();
        true
    }

    pub(super) fn ensure_com_objects(&mut self) -> bool {
        if !self.com_objects_dirty {
            return false;
        }
        self.rebuild_com_objects();
        true
    }

    pub(super) fn ensure_memory(&mut self, context: Option<&ProjectContext>) -> Option<String> {
        if !self.memory_dirty {
            return None;
        }
        self.rebuild_memory_segments(context)
    }

    pub(super) fn replace(&mut self, product: PreparedEditorProduct) {
        let mut replacement = Self::new(product);
        #[cfg(feature = "images")]
        {
            replacement.image_picker = self.image_picker.take();
        }
        std::mem::swap(self, &mut replacement);
    }

    pub(super) fn view(&self) -> &ProductView {
        &self.view
    }

    /// Set a parameter value, handling both regular and module parameters.
    pub(super) fn set_parameter(
        &mut self,
        navigation: &mut NavigationState,
        param_id: &str,
        value: ParameterValue,
    ) -> bool {
        let is_module = self.view.device.is_module_parameter(param_id);
        let changed = if is_module {
            self.view.device.get_module_parameter_value_by_composite_id(param_id) != Some(&value)
        } else {
            self.view.device.get_parameter_value(param_id) != Some(&value)
        };
        if is_module {
            self.view.device.set_module_parameter_value_by_composite_id(param_id, value);
        } else {
            self.view.device.set_parameter_value(param_id, value);
        }

        if changed {
            self.rebuild_tree(navigation);
            self.rebuild_content(navigation.selected_tree_idx);
            self.mark_derived_views_dirty();
        }
        changed
    }
    /// Keep expensive projections lazy while status-bar counts stay current.
    fn mark_derived_views_dirty(&mut self) {
        self.view.visible_param_count = self.view.device.visible_param_refs().count();
        self.view.visible_obj_count = effective_com_objects(&self.view.device, &ProductConfiguration::default()).len();
        self.com_objects_dirty = true;
        self.memory_dirty = true;
    }

    pub(super) fn rebuild_com_objects(&mut self) {
        self.com_objects_dirty = false;
        self.view.com_object_rows.clear();
        self.view.visible_param_count = self.view.device.visible_param_refs().count();

        // Resolve all three flag layers in the same helper used by the
        // compiler. The provenance string keeps project overrides visible
        // instead of making the effective booleans look like product facts.
        let configuration = ProductConfiguration {
            parameters: Vec::new(),
            objects: self
                .view
                .object_flag_overrides
                .iter()
                .map(|(&com_object, &flags)| ObjectSetting { com_object, flags: product_object_flags(flags) })
                .collect(),
        };
        for object in effective_com_objects(&self.view.device, &configuration) {
            let sources = object.flag_sources;
            let row = ComObjectRow {
                number: object.number,
                name: self.view.device.interpolate_text(&object.text),
                function: self.view.device.interpolate_text(&object.function_text),
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
            self.view.com_object_rows.push(row);
        }

        self.view.visible_obj_count = self.view.com_object_rows.len();

        // Sort by object number
        self.view.com_object_rows.sort_by_key(|r| r.number);
    }

    /// Format the group address(es) bound to a communication object for display.
    ///
    /// Returns the primary sending address, or multiple addresses separated by ", ".
    /// If no address is assigned, returns an empty string.
    pub(super) fn format_group_address(&self, object_number: u16) -> String {
        self.view
            .device
            .get_group_addresses(object_number)
            .iter()
            .map(|binding| binding.group_address.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Detect the terminal's image protocol after terminal setup and before
    /// crossterm starts reading events.
    #[cfg(feature = "images")]
    pub(super) fn initialize_image_picker(&mut self) {
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
    pub(super) fn load_image(&mut self, ref_id: &str) -> Option<&mut StatefulProtocol> {
        self.load_image_entry(ref_id).map(|(protocol, _)| protocol)
    }

    #[cfg(feature = "images")]
    pub(super) fn load_image_entry(&mut self, ref_id: &str) -> Option<&mut (StatefulProtocol, (u32, u32))> {
        // Check if already cached
        if self.image_cache.contains_key(ref_id) {
            return self.image_cache.get_mut(ref_id);
        }

        // Try to load from baggage (baggage_index is now in device)
        let baggage_path = self.view.device.baggage_index()?.get(ref_id)?.file_path().to_owned();
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
    pub(super) fn picture_cell_size(&mut self, ref_id: &str, max_cols: u16) -> Option<(u16, u16)> {
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
}

impl ProductView {
    pub fn master_data(&self) -> &MasterData {
        self.programming_catalog.as_ref()
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

    /// Get the device's mask metadata, if the selected catalogue declares it.
    pub fn get_mask_version(&self) -> Option<&MaskVersion> {
        self.master_data().get_mask_version(self.device.mask_version())
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
    pub fn first_app_object_idx(&self) -> Option<u8> {
        self.get_mask_version().and_then(|mask| mask.first_app_object_idx())
    }

    /// Get max APDU length from master data resources.
    pub fn max_apdu_length(&self) -> Option<u32> {
        self.get_mask_version()
            .and_then(|mv| mv.hawk_config())
            .and_then(|hc| hc.resources.as_ref())
            .and_then(|r| r.resources.iter().find(|res| res.name == "MaxApduLength"))
            .and_then(|r| r.location.as_ref())
            .and_then(|l| l.start_address)
    }
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
    /// Each language starts from the same immutable product document.
    pub selected: std::sync::Arc<SelectedProduct>,
    /// The baggage the device was originally built with.
    pub baggage: Option<zweidraehte_ets_files::runtime::BaggageIndex>,
}

fn source_letter(source: EffectiveValueSource) -> char {
    match source {
        EffectiveValueSource::Product => 'P',
        EffectiveValueSource::VisibleReference => 'R',
        EffectiveValueSource::Project => 'J',
    }
}

#[cfg(feature = "images")]
fn terminal_multiplexer_active() -> bool {
    std::env::var_os("TMUX").is_some() || std::env::var_os("STY").is_some()
}
