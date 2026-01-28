//! MTXML Generator - Builds ApplicationProgram XML from device definitions.

use std::collections::HashMap;

use base64::Engine;

use zweidraehte::ets::{
    DeviceDescriptor, EtsCommObjectDef, EtsCommObjectRefDef, EtsParamDefExt, EtsParamType,
    EtsUnionFieldInfo,
};

use super::page_layout::{
    ConditionalElement, ConditionalItem, PageBlock, PageElement, PageItem, PageStructure,
};
use super::module::{ModuleArgRole, ModuleArgType, ModuleCollection, StoredModuleDef};
use super::schema::*;

/// Tracks active conditions when generating nested XML structures.
/// This allows us to avoid redundant choose/when nesting when an object's
/// selector_param matches an already-active condition.
#[derive(Clone, Debug, Default)]
struct ActiveConditions {
    /// Active conditions as (selector_param_name, values) pairs.
    /// When processing items inside a `when` block, this tracks which selector
    /// is active and what values are being tested.
    conditions: Vec<(String, Vec<i64>)>,
}

/// Tracks usage of selector params for creating separate ParameterRefs.
/// MDT creates separate ParameterRefs for the same parameter when used in
/// different ObjWithValue/GroupedObjChoose contexts.
/// This allows for more choose blocks with fewer when clauses each.
#[derive(Default)]
struct SelectorRefCounters {
    /// Counter per selector param name, incremented each time a new ref is used.
    counters: HashMap<String, usize>,
}

impl SelectorRefCounters {
    fn new() -> Self {
        Self { counters: HashMap::new() }
    }

    /// Get the next ref index for a selector param and increment counter.
    fn next_index(&mut self, param_name: &str) -> usize {
        let counter = self.counters.entry(param_name.to_string()).or_insert(0);
        let index = *counter;
        *counter += 1;
        index
    }
}

/// Maps parameter names to multiple ParameterRef IDs.
/// For params that are used multiple times as selectors, stores all their ref IDs.
struct MultiParamRefMap {
    /// Primary ref map (first/only ref for each param)
    primary: HashMap<String, String>,
    /// Multi-ref map: param name -> Vec<ref_id> for params with multiple refs
    multi: HashMap<String, Vec<String>>,
    /// Text-based ref map: (param_name, text_override) -> ref_id
    /// For union variant params that have different text overrides in different contexts
    by_text: HashMap<(String, Option<String>), String>,
    /// Map from param name to primary ref number (for text interpolation)
    param_ref_nums: HashMap<String, u32>,
}

impl MultiParamRefMap {
    /// Get the ref ID for a param. If it has multiple refs and an index is provided,
    /// returns the ref at that index. Otherwise returns the primary ref.
    fn get(&self, param_name: &str, index: Option<usize>) -> Option<&String> {
        if let Some(idx) = index {
            // Try to get the indexed ref from multi map
            if let Some(refs) = self.multi.get(param_name) {
                if idx < refs.len() {
                    return Some(&refs[idx]);
                }
            }
        }
        // Fall back to primary
        self.primary.get(param_name)
    }

    /// Get the primary ref (for params that aren't selectors or when index doesn't matter)
    fn get_primary(&self, param_name: &str) -> Option<&String> {
        self.primary.get(param_name)
    }

    /// Get the ref ID for a param with a specific text override.
    /// Used for union variant params that have context-specific text.
    fn get_by_text(&self, param_name: &str, text: Option<&str>) -> Option<&String> {
        let key = (param_name.to_string(), text.map(|s| s.to_string()));
        self.by_text.get(&key)
    }
}

impl ActiveConditions {
    /// Create an empty set of active conditions.
    fn new() -> Self {
        Self { conditions: Vec::new() }
    }

    /// Add a condition to the active set.
    fn with_condition(&self, selector: &str, values: Vec<i64>) -> Self {
        let mut new = self.clone();
        new.conditions.push((selector.to_string(), values));
        new
    }

    /// Check if the given selector matches any active condition.
    /// Returns Some(values) if the selector matches an active condition.
    fn get_active_values(&self, selector: &str) -> Option<&Vec<i64>> {
        self.conditions
            .iter()
            .find(|(sel, _)| sel == selector)
            .map(|(_, vals)| vals)
    }
}

/// Collects union variant text overrides from the page layout.
/// Returns a map of (union_field, variant_name) -> Vec<text_override>
/// where each text_override is a unique text used for that variant.
fn collect_union_variant_texts(layout: &PageStructure) -> HashMap<(String, String), Vec<Option<String>>> {
    let mut texts: HashMap<(String, String), Vec<Option<String>>> = HashMap::new();

    // Process device settings
    for element in &layout.device_settings {
        collect_texts_in_element(element, &mut texts);
    }

    // Process channels
    for channel in &layout.channels {
        for element in &channel.elements {
            collect_texts_in_element(element, &mut texts);
        }
    }

    texts
}

fn collect_texts_in_element(
    element: &PageElement,
    texts: &mut HashMap<(String, String), Vec<Option<String>>>,
) {
    match element {
        PageElement::Block(block) => {
            collect_texts_in_block(block, texts);
        }
        PageElement::When(cond) => {
            for case in &cond.cases {
                for elem in &case.elements {
                    collect_texts_in_element(elem, texts);
                }
            }
        }
    }
}

fn collect_texts_in_block(
    block: &PageBlock,
    texts: &mut HashMap<(String, String), Vec<Option<String>>>,
) {
    for item in &block.items {
        collect_texts_in_item(item, texts);
    }
}

fn collect_texts_in_item(
    item: &PageItem,
    texts: &mut HashMap<(String, String), Vec<Option<String>>>,
) {
    match item {
        PageItem::When(cond) => {
            for case in &cond.cases {
                for nested_item in &case.items {
                    collect_texts_in_item(nested_item, texts);
                }
            }
        }
        PageItem::UnionVariantDirect { union_field, variant_name, text_override } => {
            let key = (union_field.to_string(), variant_name.to_string());
            let text = text_override.map(|s| s.to_string());
            let entry = texts.entry(key).or_insert_with(Vec::new);
            if !entry.contains(&text) {
                entry.push(text);
            }
        }
        PageItem::UnionVariantWithChoose { union_field, variant_name, text_override, cases } => {
            let key = (union_field.to_string(), variant_name.to_string());
            let text = text_override.map(|s| s.to_string());
            let entry = texts.entry(key).or_insert_with(Vec::new);
            if !entry.contains(&text) {
                entry.push(text);
            }
            // Also process nested cases
            for case in cases {
                for nested_item in &case.items {
                    collect_texts_in_item(nested_item, texts);
                }
            }
        }
        PageItem::ChooseOnUnionVariant { cases, .. } => {
            // This doesn't output the param itself, but process nested items
            for case in cases {
                for nested_item in &case.items {
                    collect_texts_in_item(nested_item, texts);
                }
            }
            // Don't add - this is just a choose block, not a param output
        }
        PageItem::ObjWithValue { value_union, sub_selectors, .. } => {
            // ObjWithValue outputs union variant params without text override
            // We need to track all variants that could be used
            // The variants are determined by the selector_param values, but we don't know those here
            // For now, just add a None text for all variants we might use
            // This is handled in the generator when it iterates over union_info.selector_variants
            let key = (value_union.to_string(), "".to_string()); // We'll handle this specially
            let entry = texts.entry(key).or_insert_with(Vec::new);
            if !entry.contains(&None) {
                entry.push(None);
            }
            // Also handle sub_selectors which have their own variant params
            for (_, _, sub_variants) in sub_selectors.iter() {
                for (_, _, variant_name) in sub_variants.iter() {
                    let key = (value_union.to_string(), variant_name.to_string());
                    let entry = texts.entry(key).or_insert_with(Vec::new);
                    if !entry.contains(&None) {
                        entry.push(None);
                    }
                }
            }
        }
        _ => {}
    }
}

/// Counts how many times each parameter is used as a selector in ObjWithValue,
/// GroupedObjChoose, or Obj items. Used to generate multiple ParameterRefs
/// for the same parameter (matching MDT's fine-grained structure).
///
/// Takes comm_obj_ref_map to look up which objects have selector_params for PageItem::Obj counting.
fn count_selector_usages_with_objects(
    layout: &PageStructure,
    comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();

    // Process device settings
    for element in &layout.device_settings {
        count_selector_in_element_with_objects(element, &mut counts, comm_obj_ref_map);
    }

    // Process channels
    for channel in &layout.channels {
        for element in &channel.elements {
            count_selector_in_element_with_objects(element, &mut counts, comm_obj_ref_map);
        }
    }

    counts
}

fn count_selector_in_element_with_objects(
    element: &PageElement,
    counts: &mut HashMap<String, usize>,
    comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
) {
    match element {
        PageElement::Block(block) => {
            count_selector_in_block_with_objects(block, counts, comm_obj_ref_map);
        }
        PageElement::When(cond) => {
            for case in &cond.cases {
                for elem in &case.elements {
                    count_selector_in_element_with_objects(elem, counts, comm_obj_ref_map);
                }
            }
        }
    }
}

fn count_selector_in_block_with_objects(
    block: &PageBlock,
    counts: &mut HashMap<String, usize>,
    comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
) {
    for item in &block.items {
        count_selector_in_item_with_objects(item, counts, comm_obj_ref_map);
    }
}

fn count_selector_in_item_with_objects(
    item: &PageItem,
    counts: &mut HashMap<String, usize>,
    comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
) {
    match item {
        PageItem::When(cond) => {
            for case in &cond.cases {
                for nested_item in &case.items {
                    count_selector_in_item_with_objects(nested_item, counts, comm_obj_ref_map);
                }
            }
        }
        // These items create choose blocks on their selector_param
        PageItem::ObjWithValue { selector_param, .. } => {
            *counts.entry(selector_param.to_string()).or_insert(0) += 1;
        }
        PageItem::GroupedObjChoose { selector_param, .. } => {
            *counts.entry(selector_param.to_string()).or_insert(0) += 1;
        }
        // Obj items also create choose blocks - count selectors from the object refs
        PageItem::Obj(name) => {
            if let Some(refs) = comm_obj_ref_map.get(*name) {
                // Collect unique selector params from this object's refs
                let mut seen_selectors: std::collections::HashSet<&str> = std::collections::HashSet::new();
                for (_, sel_param, sel_val) in refs {
                    if let (Some(param), Some(_)) = (sel_param.as_ref(), sel_val) {
                        // Only count each selector once per Obj item (it creates one choose per selector)
                        if seen_selectors.insert(param.as_str()) {
                            *counts.entry(param.clone()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
        _ => {}
    }
}


/// Memory segment definition for System 7 devices.
#[derive(Debug, Clone)]
pub struct System7Segment {
    /// Segment name suffix (e.g., "4000" for address table)
    pub name: &'static str,
    /// Memory address
    pub address: u32,
    /// Segment size in bytes
    pub size: u32,
    /// Memory type ("EEPROM" or "RAM", None for default)
    pub memory_type: Option<&'static str>,
    /// Data bytes (base64 encoded). If None, segment is uninitialized (RAM).
    pub data: Option<&'static [u8]>,
    /// Mask bytes (base64 encoded). If None, no mask.
    pub mask: Option<&'static [u8]>,
}

/// System 7 memory layout configuration.
#[derive(Debug, Clone)]
pub struct System7MemoryLayout {
    /// Memory segments for the Code section
    pub segments: Vec<System7Segment>,
    /// Address table segment name (reference to segment in segments)
    pub address_table_segment: &'static str,
    /// Association table segment name
    pub association_table_segment: &'static str,
    /// Address table offset within segment
    pub address_table_offset: u32,
    /// Association table offset within segment
    pub association_table_offset: u32,
    /// Address table max entries
    pub address_table_max_entries: u16,
    /// Association table max entries
    pub association_table_max_entries: u16,
}

/// Configuration for generating MTXML files (ApplicationProgram, Hardware, Catalog).
pub struct ApplicationProgramConfig<'a> {
    /// Human-readable application name
    pub name: &'a str,
    /// Device descriptor with mask version, manufacturer ID, etc.
    pub device: &'a DeviceDescriptor,
    /// Extended parameter definitions with enum variants
    pub params: &'a [EtsParamDefExt],
    /// Virtual parameter definitions that exist only in ETS (not stored in device memory).
    /// These are useful for things like device name, channel names, or other text parameters
    /// that are displayed in ETS but don't consume device memory.
    ///
    /// Virtual params appear first in the parameter list, followed by regular params.
    pub virtual_params: Option<&'a [EtsParamDefExt]>,
    /// Default parameter values as raw bytes
    pub param_defaults: &'a [u8],
    /// Communication object definitions
    pub comm_objects: &'a [EtsCommObjectDef],
    /// Communication object reference definitions (for multi-ref objects)
    pub comm_object_refs: &'a [EtsCommObjectRefDef],
    /// Union fields from derive macro (optional)
    pub union_fields: Option<&'a [EtsUnionFieldInfo]>,
    /// Channel name for the UI grouping
    pub channel_name: &'a str,
    /// Base address for absolute segments (System 7 only, deprecated - use system7_layout)
    /// For System 7, this is the memory address where parameters start
    pub absolute_segment_address: Option<u32>,
    /// System 7 memory layout configuration (if None, uses simple single-segment layout)
    pub system7_layout: Option<System7MemoryLayout>,
    /// Application hash/suffix for the ApplicationProgram ID (4 hex chars).
    /// If None, defaults to "0000". Example: "E59D" for MDT devices.
    pub application_hash: Option<&'a str>,

    // ========================================================================
    // ApplicationProgram optional version attributes
    // ========================================================================
    /// Non-registration relevant data version (optional).
    /// Used for version management in ETS.
    pub non_reg_relevant_data_version: Option<u32>,
    /// Previous versions this program replaces (space-separated list).
    /// Example: "18 19" means this version replaces versions 18 and 19.
    pub replaces_versions: Option<&'a str>,
    /// Hash of the application data (base64 encoded).
    /// Used by ETS for integrity checking.
    pub application_data_hash: Option<&'a str>,

    // ========================================================================
    // Hardware/Catalog fields (for Hardware.mtxml and Catalog.mtxml generation)
    // ========================================================================
    /// Device serial number (6 bytes, unique per device).
    /// First 2 bytes should match manufacturer_id.
    pub serial_number: [u8; 6],
    /// Hardware version number (displayed in ETS)
    pub hardware_version: u8,
    /// Hardware name (displayed in ETS hardware list)
    pub hardware_name: &'a str,
    /// Product display text (shown in ETS catalog)
    pub product_name: &'a str,
    /// Product order number (for ordering/identification)
    pub order_number: &'a str,
    /// Whether the device is rail-mounted (DIN rail)
    pub is_rail_mounted: bool,
    /// Catalog section name (category in ETS catalog)
    pub catalog_section: &'a str,
    /// Optional page layout definition. If provided, the Dynamic section will be
    /// generated according to this layout. If None, auto-generation is used.
    pub page_layout: Option<PageStructure>,
    /// Optional module collection. If provided, ModuleDefs and Module instances
    /// will be generated in the output XML.
    pub modules: Option<ModuleCollection>,
}

impl<'a> ApplicationProgramConfig<'a> {
    /// Get the mask family for this configuration
    pub fn mask_family(&self) -> MaskFamily {
        MaskFamily::from_mask_version(self.device.mask_version)
    }

    /// Get the number of virtual params at the device level.
    pub fn virtual_params_count(&self) -> usize {
        self.virtual_params.map_or(0, |vp| vp.len())
    }

    /// Iterate over all device-level params (virtual params first, then regular params).
    /// This matches the XML generation order.
    pub fn all_params(&self) -> impl Iterator<Item = &EtsParamDefExt> {
        let virtual_params = self.virtual_params.unwrap_or(&[]);
        virtual_params.iter().chain(self.params.iter())
    }

    /// Find a device-level parameter by name (searches virtual params first, then regular).
    /// Returns the 1-based parameter number.
    pub fn find_param_num_by_name(&self, name: &str) -> Option<u32> {
        let virtual_params = self.virtual_params.unwrap_or(&[]);

        // First search virtual params (index 0 -> param_num 1)
        if let Some(idx) = virtual_params.iter().position(|p| p.base.name == name) {
            return Some((idx + 1) as u32);
        }

        // Then search regular params (offset by virtual_params.len())
        if let Some(idx) = self.params.iter().position(|p| p.base.name == name) {
            return Some((virtual_params.len() + idx + 1) as u32);
        }

        None
    }
}

/// Strip bytes belonging to `no_memory` (virtual) parameters from the raw defaults.
///
/// Virtual parameters exist in the Rust struct for metadata purposes but should not
/// occupy device memory. This function creates a new byte vector with the `no_memory`
/// fields' bytes removed.
///
/// The function works by:
/// 1. Identifying ranges of bytes that belong to `no_memory` parameters
/// 2. Copying only the non-virtual bytes to the output
///
/// # Arguments
/// * `raw_defaults` - The original parameter bytes (from the Rust struct)
/// * `params` - Parameter definitions including offset and size info
///
/// # Returns
/// A new `Vec<u8>` with virtual parameter bytes removed
fn strip_no_memory_bytes(raw_defaults: &[u8], params: &[EtsParamDefExt]) -> Vec<u8> {
    // Collect ranges of bytes to exclude (offset, size_bytes) for no_memory params
    let mut exclude_ranges: Vec<(usize, usize)> = params
        .iter()
        .filter(|p| p.base.no_memory)
        .map(|p| {
            let offset = p.base.offset as usize;
            let size_bytes = ((p.base.size_bits as usize) + 7) / 8;
            (offset, size_bytes)
        })
        .collect();

    // If no no_memory params, return as-is
    if exclude_ranges.is_empty() {
        return raw_defaults.to_vec();
    }

    // Sort by offset and merge overlapping ranges
    exclude_ranges.sort_by_key(|(offset, _)| *offset);

    // Build output by copying non-excluded ranges
    let mut result = Vec::with_capacity(raw_defaults.len());
    let mut current_pos = 0;

    for (exclude_start, exclude_size) in &exclude_ranges {
        // Copy bytes before this exclusion
        if current_pos < *exclude_start {
            result.extend_from_slice(&raw_defaults[current_pos..*exclude_start]);
        }
        // Skip past the excluded bytes
        current_pos = (*exclude_start + *exclude_size).max(current_pos);
    }

    // Copy any remaining bytes after the last exclusion
    if current_pos < raw_defaults.len() {
        result.extend_from_slice(&raw_defaults[current_pos..]);
    }

    result
}

/// Generator for creating ApplicationProgram MTXML files.
pub struct MtxmlGenerator;

impl MtxmlGenerator {
    /// Generate a complete KNX MTXML document from the configuration.
    ///
    /// This method builds the KNX document, validates all references, and then
    /// serializes to XML. If any references are invalid (e.g., a ParameterRefRef
    /// refers to a non-existent ParameterRef), an error is returned.
    pub fn generate(config: &ApplicationProgramConfig) -> Result<String, GeneratorError> {
        let knx = Self::build_knx(config)?;

        // Validate all references before serialization
        Self::validate(&knx)?;

        Self::serialize(&knx)
    }

    /// Build the complete KNX document structure.
    fn build_knx(config: &ApplicationProgramConfig) -> Result<Knx, GeneratorError> {
        let app_id = Self::format_app_id(config);

        let mut knx = Knx::default();
        knx.manufacturer_data.manufacturer.ref_id =
            format!("M-{:04X}", config.device.manufacturer_id);
        knx.manufacturer_data
            .manufacturer
            .application_programs
            .programs
            .push(Self::build_application_program(config, &app_id)?);

        Ok(knx)
    }

    /// Format the application ID string.
    fn format_app_id(config: &ApplicationProgramConfig) -> String {
        let hash = config.application_hash.unwrap_or("0000");
        format!(
            "M-{:04X}_A-{:04X}-{:02X}-{}",
            config.device.manufacturer_id, config.device.application_id, config.device.application_version,
            hash
        )
    }

    /// Build the ApplicationProgram element.
    fn build_application_program(
        config: &ApplicationProgramConfig,
        app_id: &str,
    ) -> Result<ApplicationProgram, GeneratorError> {
        let mask_family = config.mask_family();

        let mut app = ApplicationProgram {
            id: app_id.to_string(),
            application_number: config.device.application_id,
            application_version: config.device.application_version,
            mask_version: format!("MV-{:04X}", config.device.mask_version),
            name: config.name.to_string(),
            load_procedure_style: mask_family.load_procedure_style().to_string(),
            non_reg_relevant_data_version: config.non_reg_relevant_data_version,
            replaces_versions: config.replaces_versions.map(|s| s.to_string()),
            hash: config.application_data_hash.map(|s| s.to_string()),
            ..Default::default()
        };

        // Build Static section
        app.static_section = Self::build_static_section(config, app_id, mask_family)?;

        // Build ModuleDefs (placed between Static and Dynamic per XSD schema)
        app.module_defs = Self::build_module_defs(config, app_id);

        // Build Dynamic section - use page layout if provided, otherwise auto-generate
        let dynamic = if let Some(ref layout) = config.page_layout {
            Self::build_dynamic_section_from_layout(config, app_id, mask_family, layout)?
        } else {
            Self::build_dynamic_section(config, app_id, mask_family)?
        };
        app.dynamic = Some(dynamic);

        Ok(app)
    }

    /// Build the Static section with all components.
    fn build_static_section(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
    ) -> Result<StaticSection, GeneratorError> {
        // Calculate the stripped param size (excluding no_memory virtual parameters)
        let stripped_defaults = strip_no_memory_bytes(config.param_defaults, config.params);
        let param_size = stripped_defaults.len() as u32;

        // Build code segment ID based on mask family (for parameter references)
        let code_segment_id = match mask_family.data_segment_type() {
            DataSegmentType::Relative => format!("{}_RS-04-00000", app_id),
            DataSegmentType::Absolute => {
                // For System 7 with full layout, use the first EEPROM segment
                if let Some(ref layout) = config.system7_layout {
                    // Find the EEPROM segment (usually the parameter segment)
                    let eeprom_seg = layout.segments.iter()
                        .find(|s| s.memory_type == Some("EEPROM") && s.data.is_some())
                        .or_else(|| layout.segments.first());
                    if let Some(seg) = eeprom_seg {
                        format!("{}_AS-{}", app_id, seg.name)
                    } else {
                        format!("{}_AS-{:04X}", app_id, config.absolute_segment_address.unwrap_or(0))
                    }
                } else {
                    format!("{}_AS-{:04X}", app_id, config.absolute_segment_address.unwrap_or(0))
                }
            }
        };

        // Build address/association tables only for masks that support them
        let (address_table, association_table) = if mask_family.generates_address_tables() {
            // For System 7, use code segments from the layout if available
            let (addr_seg, assoc_seg) = if let Some(ref layout) = config.system7_layout {
                (
                    Some(format!("{}_AS-{}", app_id, layout.address_table_segment)),
                    Some(format!("{}_AS-{}", app_id, layout.association_table_segment)),
                )
            } else {
                (None, None)
            };
            (
                Some(AddressTable {
                    code_segment: addr_seg,
                    offset: Some(0),
                    max_entries: config.device.max_address_table_entries,
                }),
                Some(AssociationTable {
                    code_segment: assoc_seg,
                    offset: Some(0),
                    max_entries: config.device.max_association_table_entries,
                }),
            )
        } else {
            (None, None)
        };

        // Count selector usages from page layout for creating multiple ParameterRefs
        // We need the comm_obj_ref_map to count PageItem::Obj usages
        let (selector_usage_counts, union_variant_texts) = if let Some(layout) = config.page_layout.as_ref() {
            let comm_obj_ref_map = Self::build_comm_object_ref_map(config, app_id, mask_family);
            let counts = count_selector_usages_with_objects(layout, &comm_obj_ref_map);
            let texts = collect_union_variant_texts(layout);
            (Some(counts), Some(texts))
        } else {
            (None, None)
        };

        // Build ParameterRefs first to get the param_name -> ref_num mapping for text param refs
        let (parameter_refs, param_ref_nums) = Self::build_parameter_refs(
            config,
            app_id,
            selector_usage_counts.as_ref(),
            union_variant_texts.as_ref(),
        );

        // Build ComObject table only for masks that support it
        let (com_object_table, com_object_refs) = if mask_family.has_com_object_table() {
            let table = Self::build_com_object_table(config, app_id, mask_family);
            let refs = Self::build_com_object_refs(config, app_id, mask_family, &param_ref_nums);
            // XSD requires ComObjectRefs to have at least one child if present
            let refs_opt = if refs.refs.is_empty() { None } else { Some(refs) };
            (Some(table), refs_opt)
        } else {
            (None, None)
        };

        Ok(StaticSection {
            code: Some(Self::build_code(config, app_id, param_size, mask_family)),
            parameter_types: Some(Self::build_parameter_types(config, app_id)),
            parameters: Some(Self::build_parameters(config, app_id, &code_segment_id)),
            parameter_refs: Some(parameter_refs),
            com_object_table,
            com_object_refs,
            address_table,
            association_table,
            load_procedures: {
                let procs = Self::build_load_procedures(config, param_size, mask_family);
                if procs.procedures.is_empty() {
                    None
                } else {
                    Some(procs)
                }
            },
            extension: Some(Extension { baggages: Vec::new() }),
            messages: None,
            options: Some(Options {
                comparable: Some(true),
                reconstructable: Some(true),
            }),
        })
    }

    /// Build ModuleDefs from the module collection if present.
    fn build_module_defs(
        config: &ApplicationProgramConfig,
        app_id: &str,
    ) -> Option<ModuleDefs> {
        let modules = config.modules.as_ref()?;
        if modules.is_empty() {
            return None;
        }

        let mut module_defs = Vec::new();

        for (def_idx, def) in modules.definitions().iter().enumerate() {
            let module_id = format!("{}_MD-{}", app_id, def_idx + 1);

            // Compute allocates values from params/objects for role-based arguments
            let param_size: u32 = def.params
                .map(|p| p.iter()
                    // Exclude no_memory (virtual) parameters - they don't occupy device memory
                    .filter(|param| !param.base.no_memory)
                    .map(|param| (param.base.size_bits as u32 + 7) / 8)
                    .sum())
                .unwrap_or(0);
            let object_count: u32 = def.comm_objects.map(|o| o.len() as u32).unwrap_or(0);

            // Build argument definitions
            let arguments = if def.arguments.is_empty() {
                None
            } else {
                let args: Vec<ModuleDefArgument> = def
                    .arguments
                    .iter()
                    .enumerate()
                    .map(|(arg_idx, arg)| {
                        // Compute allocates based on role
                        let allocates = match arg.role {
                            ModuleArgRole::ParamOffset => param_size,
                            ModuleArgRole::ObjectNumber => object_count,
                            _ => arg.allocates,
                        };
                        ModuleDefArgument {
                            id: format!("{}_A-{}", module_id, arg_idx + 1),
                            name: arg.name.to_string(),
                            allocates,
                            alignment: arg.alignment,
                            arg_type: match arg.arg_type {
                                ModuleArgType::Numeric => None, // Default, no need to specify
                                ModuleArgType::Text => Some("Text".to_string()),
                            },
                        }
                    })
                    .collect();
                Some(ModuleDefArguments { arguments: args })
            };

            // Build the BaseOffset argument ID using role-based lookup
            let base_offset_arg_id = def.arg_index_by_role(ModuleArgRole::ParamOffset).map(|idx| {
                format!("{}_A-{}", module_id, idx + 1)
            });

            // Build the BaseNumber argument ID using role-based lookup
            let base_number_arg_id = def.arg_index_by_role(ModuleArgRole::ObjectNumber).map(|idx| {
                format!("{}_A-{}", module_id, idx + 1)
            });

            // Build the BaseValue argument ID using role-based lookup
            let base_value_arg_id = def.arg_index_by_role(ModuleArgRole::ValueBase).map(|idx| {
                format!("{}_A-{}", module_id, idx + 1)
            });

            // Build module-internal parameters if provided
            let (module_params, module_param_refs) = Self::build_module_parameters(
                config,
                app_id,
                &module_id,
                def,
                base_offset_arg_id.as_deref(),
                base_value_arg_id.as_deref(),
            );

            // Build the TextParameterRefId for {{0}} text template substitution
            // This references the parameter ref of the text parameter within this module
            // Auto-detect text source parameter via #[ets(text_source)] attribute
            // Must search both virtual_params (first) and regular params, matching XML generation order
            let virtual_params = def.virtual_params.unwrap_or(&[]);
            let regular_params = def.params.unwrap_or(&[]);

            // First check virtual params for text_source
            let text_param_num = zweidraehte::ets::EtsParamDefExt::find_text_source_index(virtual_params)
                .map(|idx| idx + 1)  // 1-based param number
                .or_else(|| {
                    // Then check regular params (offset by virtual_params length)
                    zweidraehte::ets::EtsParamDefExt::find_text_source_index(regular_params)
                        .map(|idx| virtual_params.len() + idx + 1)
                });

            let text_param_ref_id = text_param_num.map(|param_num| {
                // Reference the ParameterRef ID within this module
                format!("{}_P-{}_R-{}", module_id, param_num, param_num)
            });

            // Build module-internal communication objects if provided
            let (module_com_objects, module_com_object_refs) = Self::build_module_com_objects(
                app_id,
                &module_id,
                def,
                base_number_arg_id.as_deref(),
                text_param_ref_id.as_deref(),
            );

            // Build module Dynamic section with a ParameterBlock containing all parameter refs
            let module_dynamic = Self::build_module_dynamic(&module_id, def, text_param_ref_id.as_deref());

            module_defs.push(ModuleDef {
                id: module_id,
                name: def.name.clone(),
                internal_description: def.internal_description.clone(),
                arguments,
                static_section: ModuleDefStatic {
                    parameters: module_params,
                    parameter_refs: module_param_refs,
                    com_objects: module_com_objects,
                    com_object_refs: module_com_object_refs,
                },
                dynamic: module_dynamic,
            });
        }

        Some(ModuleDefs { module_defs })
    }

    /// Build parameters for a module definition.
    ///
    /// Creates the Parameters and ParameterRefs elements for the module's Static section.
    /// Parameters use `BaseOffset` to reference the module's parameter base argument,
    /// and `BaseValue` to reference the module's value base argument for relative values.
    #[allow(unused_variables)]
    fn build_module_parameters(
        config: &ApplicationProgramConfig,
        app_id: &str,
        module_id: &str,
        def: &StoredModuleDef,
        base_offset_arg_id: Option<&str>,
        base_value_arg_id: Option<&str>,
    ) -> (Option<Parameters>, Option<ParameterRefs>) {
        // Combine virtual params (first) and regular params
        // Virtual params come first so that text_source param gets the right index for {{0}}
        let virtual_params = def.virtual_params.unwrap_or(&[]);
        let regular_params = def.params.unwrap_or(&[]);

        if virtual_params.is_empty() && regular_params.is_empty() {
            return (None, None);
        }

        let code_segment_id = format!("{}_RS-04-00000", app_id);
        let mut parameters = Parameters::default();
        let mut parameter_refs = ParameterRefs::default();

        // Process all parameters (virtual + regular)
        let all_params: Vec<_> = virtual_params.iter().chain(regular_params.iter()).collect();

        for (idx, param_ext) in all_params.iter().enumerate() {
            let param = &param_ext.base;
            let param_num = idx + 1;

            // Generate parameter ID within the module
            let param_id = format!("{}_P-{}", module_id, param_num);

            // Get the parameter type ID (reuse the app-level type if available)
            let type_name = Self::param_type_name(param);
            let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));

            // Get default value - use empty string for text parameters
            let default_value: String = if let Some(val) = param_ext.default_value {
                val.to_string()
            } else if param.param_type == zweidraehte::ets::EtsParamType::String {
                String::new() // Empty string for text parameters
            } else {
                "0".to_string()
            };

            // Build memory location with BaseOffset if argument is specified
            // Virtual (no_memory) parameters don't have a Memory element
            let memory = if param.no_memory {
                None
            } else {
                Some(MemoryLocation {
                    code_segment: code_segment_id.clone(),
                    offset: param.offset as u32,
                    bit_offset: param.bit_offset,
                    base_offset: base_offset_arg_id.map(|s| s.to_string()),
                })
            };

            parameters.items.push(ParameterItem::Parameter(Parameter {
                id: param_id.clone(),
                name: param.name.to_string(),
                parameter_type: type_id,
                text: param.display_name.to_string(),
                value: default_value,
                suffix_text: param.suffix.map(|s| s.to_string()),
                access: None,
                base_value: base_value_arg_id.map(|s| s.to_string()),
                memory,
                internal_description: None,
            }));

            // Generate parameter reference
            let ref_id = format!("{}_R-{}", param_id, param_num);
            parameter_refs.refs.push(ParameterRef {
                id: ref_id,
                ref_id: param_id,
                text: None,
                internal_description: None,
                access: None,
                value: None,
                base_value: None,
            });
        }

        (
            Some(parameters),
            if parameter_refs.refs.is_empty() { None } else { Some(parameter_refs) },
        )
    }

    /// Build communication objects for a module definition.
    ///
    /// Creates the ComObjects and ComObjectRefs elements for the module's Static section.
    /// Note: Module static sections use `<ComObjects>` (not `<ComObjectTable>`).
    /// ComObjects use `BaseNumber` to reference the module's object base argument.
    /// ComObjectRefs use `TextParameterRefId` for `{{0}}` text template substitution.
    #[allow(unused_variables)]
    fn build_module_com_objects(
        app_id: &str,
        module_id: &str,
        def: &StoredModuleDef,
        base_number_arg_id: Option<&str>,
        text_param_ref_id: Option<&str>,
    ) -> (Option<ModuleComObjects>, Option<ComObjectRefs>) {
        let objects: &[EtsCommObjectDef] = match def.comm_objects {
            Some(objects) if !objects.is_empty() => objects,
            _ => return (None, None),
        };

        let mut module_com_objects = ModuleComObjects {
            objects: Vec::new(),
        };
        let mut com_object_refs = ComObjectRefs::default();

        for obj_def in objects.iter() {
            // Module ComObject IDs use a different format: {module_id}_O-{table}-{number}
            let obj_id = format!("{}_O-2-{}", module_id, obj_def.index);

            // Parse flags from bitmask (same as in build_com_object_table)
            let flags = obj_def.default_flags;
            let communication_flag = if flags & 0x04 != 0 { EnableFlag::Enabled } else { EnableFlag::Disabled };
            let read_flag = if flags & 0x08 != 0 { EnableFlag::Enabled } else { EnableFlag::Disabled };
            let write_flag = if flags & 0x10 != 0 { EnableFlag::Enabled } else { EnableFlag::Disabled };
            let transmit_flag = if flags & 0x20 != 0 { EnableFlag::Enabled } else { EnableFlag::Disabled };
            let update_flag = if flags & 0x80 != 0 { EnableFlag::Enabled } else { EnableFlag::Disabled };
            let read_on_init_flag = EnableFlag::Disabled; // Not in bitmask

            module_com_objects.objects.push(ComObject {
                id: obj_id.clone(),
                name: obj_def.name.to_string(),
                text: obj_def.display_name.to_string(),
                number: obj_def.index,
                function_text: obj_def.function_text.to_string(),
                object_size: object_size_to_string(obj_def.size_bits).to_string(),
                datapoint_type: Some(dpt_to_string(obj_def.dpt_main, obj_def.dpt_sub)),
                read_flag,
                write_flag,
                communication_flag,
                transmit_flag,
                update_flag,
                read_on_init_flag,
                priority: None,
                internal_description: None,
                base_number: base_number_arg_id.map(|s| s.to_string()),
            });

            // Generate ComObjectRef with text template support
            let ref_id = format!("{}_R-{}", obj_id, obj_def.index + 1);

            // Use text_template if provided, otherwise use display_name
            let text = obj_def.text_template
                .map(|t| t.to_string())
                .unwrap_or_else(|| obj_def.display_name.to_string());

            // Only set TextParameterRefId if we have a text template containing {{0}}
            let text_parameter_ref_id = if obj_def.text_template.map(|t| t.contains("{{0}}")).unwrap_or(false) {
                text_param_ref_id.map(|s| s.to_string())
            } else {
                None
            };

            com_object_refs.refs.push(ComObjectRef {
                id: ref_id,
                ref_id: obj_id,
                name: None,
                text: Some(text),
                function_text: Some(obj_def.function_text.to_string()),
                datapoint_type: Some(dpt_to_string(obj_def.dpt_main, obj_def.dpt_sub)),
                object_size: Some(object_size_to_string(obj_def.size_bits).to_string()),
                text_parameter_ref_id,
                ..Default::default()
            });
        }

        (
            Some(module_com_objects),
            if com_object_refs.refs.is_empty() { None } else { Some(com_object_refs) },
        )
    }

    /// Build the Dynamic section for a module definition.
    ///
    /// Creates a ParameterBlock containing ParameterRefRef elements for all
    /// parameters in the module. This defines the UI layout that ETS displays
    /// when the module is active/visible.
    fn build_module_dynamic(
        module_id: &str,
        def: &StoredModuleDef,
        text_param_ref_id: Option<&str>,
    ) -> Option<ModuleDefDynamic> {
        // If a custom page_layout is provided, use it
        if let Some(ref layout) = def.page_layout {
            return Self::build_module_dynamic_from_layout(module_id, def, layout, text_param_ref_id);
        }

        // Otherwise, auto-generate a simple layout
        Self::build_default_module_dynamic(module_id, def, text_param_ref_id)
    }

    /// Build module dynamic layout from the new ModulePageLayout structure.
    fn build_module_dynamic_from_layout(
        module_id: &str,
        def: &StoredModuleDef,
        layout: &crate::page_layout::ModulePageLayout,
        text_param_ref_id: Option<&str>,
    ) -> Option<ModuleDefDynamic> {
        use crate::page_layout::ModuleLayoutElement;

        let obj_base_arg_idx = def.arg_index_by_role(crate::module::ModuleArgRole::ObjectNumber)
            .unwrap_or(1);

        let mut block_counter = 0u32;
        let mut sep_counter = 0u32;
        let mut dynamic_items = Vec::new();

        for element in &layout.elements {
            match element {
                ModuleLayoutElement::Block(block) => {
                    block_counter += 1;
                    let block_id = format!("{}_PB-{}", module_id, block_counter);
                    let block_items = Self::convert_module_layout_items(
                        module_id, def, obj_base_arg_idx, &block.items, &mut sep_counter
                    );
                    // Only set text_parameter_ref_id if the text contains {{0}}
                    let block_text_ref = if block.text.contains("{{0}}") {
                        text_param_ref_id.map(|s| s.to_string())
                    } else {
                        None
                    };
                    dynamic_items.push(ModuleDefDynamicItem::ParameterBlock(ParameterBlock {
                        id: block_id,
                        name: Some(block.name.to_string()),
                        text: Some(block.text.to_string()),
                        text_parameter_ref_id: block_text_ref,
                        internal_description: None,
                        inline: None,
                        show_in_com_object_tree: None,
                        layout: None,
                        items: block_items,
                    }));
                }
                ModuleLayoutElement::When(when_elem) => {
                    if let Some(choose) = Self::convert_module_layout_when_to_choose(
                        module_id, def, obj_base_arg_idx, when_elem, &mut sep_counter
                    ) {
                        dynamic_items.push(ModuleDefDynamicItem::Choose(choose));
                    }
                }
            }
        }

        if dynamic_items.is_empty() {
            None
        } else {
            Some(ModuleDefDynamic { items: dynamic_items })
        }
    }

    /// Convert ModuleLayoutItem list to ParameterBlockItem list.
    fn convert_module_layout_items(
        module_id: &str,
        def: &StoredModuleDef,
        obj_base_arg_idx: usize,
        items: &[crate::page_layout::ModuleLayoutItem],
        sep_counter: &mut u32,
    ) -> Vec<ParameterBlockItem> {
        use crate::page_layout::ModuleLayoutItem;

        let mut result = Vec::new();
        for item in items {
            match item {
                ModuleLayoutItem::Param(name) => {
                    // Look up param number by name (searches both virtual_params and params)
                    if let Some(param_num) = def.find_param_num_by_name(name) {
                        let ref_id = format!("{}_P-{}_R-{}", module_id, param_num, param_num);
                        result.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                            ref_id,
                            text: None,
                            internal_description: None,
                        }));
                    }
                }
                ModuleLayoutItem::Obj(name) => {
                    // Look up comm object index by name
                    if let Some(objs) = def.comm_objects {
                        if let Some(idx) = objs.iter().position(|o| o.name == *name) {
                            let ref_num = idx + 1;
                            let ref_id = format!("{}_O-{}-{}_R-{}", module_id, obj_base_arg_idx + 1, idx, ref_num);
                            result.push(ParameterBlockItem::ComObjectRefRef(ComObjectRefRef {
                                ref_id,
                                internal_description: None,
                            }));
                        }
                    }
                }
                ModuleLayoutItem::Separator(text) => {
                    *sep_counter += 1;
                    result.push(ParameterBlockItem::ParameterSeparator(ParameterSeparator {
                        id: format!("{}_PS-{}", module_id, sep_counter),
                        text: text.map(|s| s.to_string()),
                    }));
                }
                ModuleLayoutItem::When(when_item) => {
                    if let Some(choose) = Self::convert_module_layout_when_to_choose(
                        module_id, def, obj_base_arg_idx, when_item, sep_counter
                    ) {
                        result.push(ParameterBlockItem::Choose(choose));
                    }
                }
            }
        }
        result
    }

    /// Convert ModuleLayoutItem list to WhenItem list (for inside choose/when clauses).
    fn convert_module_layout_items_to_when(
        module_id: &str,
        def: &StoredModuleDef,
        obj_base_arg_idx: usize,
        items: &[crate::page_layout::ModuleLayoutItem],
        sep_counter: &mut u32,
    ) -> Vec<WhenItem> {
        use crate::page_layout::ModuleLayoutItem;

        let mut result = Vec::new();
        for item in items {
            match item {
                ModuleLayoutItem::Param(name) => {
                    // Look up param number by name (searches both virtual_params and params)
                    if let Some(param_num) = def.find_param_num_by_name(name) {
                        let ref_id = format!("{}_P-{}_R-{}", module_id, param_num, param_num);
                        result.push(WhenItem::ParameterRefRef(ParameterRefRef {
                            ref_id,
                            text: None,
                            internal_description: None,
                        }));
                    }
                }
                ModuleLayoutItem::Obj(name) => {
                    // Look up comm object index by name
                    if let Some(objs) = def.comm_objects {
                        if let Some(idx) = objs.iter().position(|o| o.name == *name) {
                            let ref_num = idx + 1;
                            let ref_id = format!("{}_O-{}-{}_R-{}", module_id, obj_base_arg_idx + 1, idx, ref_num);
                            result.push(WhenItem::ComObjectRefRef(ComObjectRefRef {
                                ref_id,
                                internal_description: None,
                            }));
                        }
                    }
                }
                ModuleLayoutItem::Separator(text) => {
                    *sep_counter += 1;
                    result.push(WhenItem::ParameterSeparator(ParameterSeparator {
                        id: format!("{}_PS-{}", module_id, sep_counter),
                        text: text.map(|s| s.to_string()),
                    }));
                }
                ModuleLayoutItem::When(when_item) => {
                    if let Some(choose) = Self::convert_module_layout_when_to_choose(
                        module_id, def, obj_base_arg_idx, when_item, sep_counter
                    ) {
                        result.push(WhenItem::Choose(choose));
                    }
                }
            }
        }
        result
    }

    /// Convert a ModuleLayoutWhen to a Choose element.
    fn convert_module_layout_when_to_choose(
        module_id: &str,
        def: &StoredModuleDef,
        obj_base_arg_idx: usize,
        when_elem: &crate::page_layout::ModuleLayoutWhen,
        sep_counter: &mut u32,
    ) -> Option<Choose> {
        // Look up selector param number by name (searches both virtual_params and params)
        let param_num = def.find_param_num_by_name(&when_elem.selector)?;
        let param_ref_id = format!("{}_P-{}_R-{}", module_id, param_num, param_num);

        let mut when_items = Vec::new();
        for case in &when_elem.cases {
            let test_str = case.condition.to_test_string();
            let is_default = case.condition.is_default();
            let converted = Self::convert_module_layout_items_to_when(
                module_id, def, obj_base_arg_idx, &case.items, sep_counter
            );
            when_items.push(When {
                test: test_str,
                default: if is_default { Some(true) } else { None },
                internal_description: None,
                items: converted,
            });
        }

        Some(Choose {
            param_ref_id,
            whens: when_items,
        })
    }

    /// Build default module dynamic layout (all params and comm objects in one block).
    fn build_default_module_dynamic(
        module_id: &str,
        def: &StoredModuleDef,
        text_param_ref_id: Option<&str>,
    ) -> Option<ModuleDefDynamic> {
        // Check if we have either params or comm objects
        let has_params = def.params.map_or(false, |p| !p.is_empty());
        let has_comm_objs = def.comm_objects.map_or(false, |c| !c.is_empty());

        if !has_params && !has_comm_objs {
            return None;
        }

        let mut items: Vec<ParameterBlockItem> = Vec::new();

        // Build ParameterRefRef items for each parameter
        if let Some(params) = def.params {
            for (idx, _param) in params.iter().enumerate() {
                let param_num = idx + 1;
                let ref_id = format!("{}_P-{}_R-{}", module_id, param_num, param_num);
                items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                    ref_id,
                    text: None,
                    internal_description: None,
                }));
            }
        }

        // Build ComObjectRefRef items for each communication object
        // This makes the comm objects visible in ETS when the module is instantiated
        if let Some(comm_objs) = def.comm_objects {
            // Find the ObjBase argument index (argument with ObjectNumber role)
            let obj_base_arg_idx = def.arg_index_by_role(crate::module::ModuleArgRole::ObjectNumber);
            let obj_base_arg_idx = obj_base_arg_idx.unwrap_or(1); // Default to second argument

            for (idx, _obj) in comm_objs.iter().enumerate() {
                let ref_num = idx + 1;
                // ComObjectRef ID format: {module_id}_O-{arg_idx+1}-{obj_index}_R-{ref_num}
                let ref_id = format!("{}_O-{}-{}_R-{}", module_id, obj_base_arg_idx + 1, idx, ref_num);
                items.push(ParameterBlockItem::ComObjectRefRef(ComObjectRefRef {
                    ref_id,
                    internal_description: None,
                }));
            }
        }

        // Create a ParameterBlock with a name based on module name
        // The text uses {{ChNo}} for channel number and {{0}} for the text param value
        // TextParameterRefId must be set when using {{0}} template
        let block = ParameterBlock {
            id: format!("{}_PB-1", module_id),
            name: Some(def.name.clone()),
            text: Some("{{ChNo}}: {{0}}".to_string()), // Use module argument for channel and text param for name
            text_parameter_ref_id: text_param_ref_id.map(|s| s.to_string()),
            internal_description: None,
            inline: None,
            show_in_com_object_tree: None,
            layout: None,
            items,
        };

        Some(ModuleDefDynamic {
            items: vec![ModuleDefDynamicItem::ParameterBlock(block)],
        })
    }

    /// Build the Code section with appropriate segment type for the mask.
    fn build_code(
        config: &ApplicationProgramConfig,
        app_id: &str,
        size: u32,
        mask_family: MaskFamily,
    ) -> Code {
        // Strip no_memory (virtual) parameters' bytes from the raw defaults
        let stripped_defaults = strip_no_memory_bytes(config.param_defaults, config.params);
        let data = base64::engine::general_purpose::STANDARD.encode(&stripped_defaults);

        match mask_family.data_segment_type() {
            DataSegmentType::Relative => {
                let code_segment_id = format!("{}_RS-04-00000", app_id);
                Code {
                    absolute_segments: vec![],
                    relative_segments: vec![RelativeSegment {
                        id: code_segment_id,
                        size,
                        load_state_machine: 4,
                        offset: 0,
                        data: Some(data),
                    }],
                }
            }
            DataSegmentType::Absolute => {
                // Check if we have a full System 7 layout
                if let Some(ref layout) = config.system7_layout {
                    Self::build_system7_code(app_id, layout)
                } else {
                    // Simple single-segment layout
                    let code_segment_id = format!("{}_AS-{:04X}", app_id, config.absolute_segment_address.unwrap_or(0));
                    Code {
                        absolute_segments: vec![AbsoluteSegment {
                            id: code_segment_id,
                            address: config.absolute_segment_address.unwrap_or(0),
                            size,
                            memory_type: Some("RAM".to_string()),
                            data: Some(data),
                            mask: None,
                        }],
                        relative_segments: vec![],
                    }
                }
            }
        }
    }

    /// Build Code section for System 7 with full memory layout.
    fn build_system7_code(app_id: &str, layout: &System7MemoryLayout) -> Code {
        let mut segments = Vec::new();

        for seg in &layout.segments {
            let segment_id = format!("{}_AS-{}", app_id, seg.name);
            let data = seg.data.map(|d| base64::engine::general_purpose::STANDARD.encode(d));
            let mask = seg.mask.map(|m| base64::engine::general_purpose::STANDARD.encode(m));

            segments.push(AbsoluteSegment {
                id: segment_id,
                address: seg.address,
                size: seg.size,
                memory_type: seg.memory_type.map(|s| s.to_string()),
                data,
                mask,
            });
        }

        Code {
            absolute_segments: segments,
            relative_segments: vec![],
        }
    }

    /// Build parameter type definitions.
    fn build_parameter_types(config: &ApplicationProgramConfig, app_id: &str) -> ParameterTypes {
        let mut types = ParameterTypes::default();
        let mut seen_types = std::collections::HashSet::new();

        // Process all device params (virtual first, then regular)
        for param in config.all_params() {
            let type_name = Self::param_type_name(&param.base);
            if seen_types.contains(&type_name) {
                continue;
            }
            seen_types.insert(type_name.clone());

            // URL-encode the type name for the ID
            let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));
            let type_def = Self::build_type_def(&param.base, param.enum_variants, &type_id);

            types.types.push(ParameterType {
                id: type_id,
                name: type_name,
                internal_description: None,
                type_def,
            });
        }

        // Add types for union parameters if any
        if let Some(union_fields) = config.union_fields {
            for field in union_fields {
                // Selector type
                let selector_type_name = format!("tENUM_{}_selector_8", field.field_name);
                if !seen_types.contains(&selector_type_name) {
                    seen_types.insert(selector_type_name.clone());
                    let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&selector_type_name));
                    types.types.push(ParameterType {
                        id: type_id.clone(),
                        name: selector_type_name,
                        internal_description: None,
                        type_def: ParameterTypeDef::TypeRestriction(TypeRestriction {
                            base: "Value".to_string(),
                            size_in_bit: 8,
                            enumerations: field
                                .selector_variants
                                .iter()
                                .map(|v| Enumeration {
                                    text: v.text.to_string(),
                                    value: v.value as u32,
                                    // Enum ID includes full prefix and the value (not index)
                                    id: format!("{}_EN-{}", type_id, v.value),
                                })
                                .collect(),
                        }),
                    });
                }

                // Types for variant parameters
                for param in field.union_info.variant_params {
                    // For union variant params with enum types and custom enum_variants,
                    // include the variant name in the type name to make it unique.
                    // This ensures ForcibleControl's value gets a different type than Switch's value.
                    let type_name = Self::union_variant_param_type_name(&param.param, param.variant_name, param.enum_variants);
                    if !seen_types.contains(&type_name) {
                        seen_types.insert(type_name.clone());
                        let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));
                        let type_def = Self::build_type_def(&param.param, param.enum_variants, &type_id);
                        types.types.push(ParameterType {
                            id: type_id,
                            name: type_name,
                            internal_description: None,
                            type_def,
                        });
                    }
                }
            }
        }

        // Add types for module parameters (both virtual and regular)
        if let Some(modules) = &config.modules {
            for def in modules.definitions() {
                // Process virtual params first (they come first in the combined param list)
                let virtual_params = def.virtual_params.unwrap_or(&[]);
                let regular_params = def.params.unwrap_or(&[]);
                let all_params = virtual_params.iter().chain(regular_params.iter());

                for param_ext in all_params {
                    let type_name = Self::param_type_name(&param_ext.base);
                    if seen_types.contains(&type_name) {
                        continue;
                    }
                    seen_types.insert(type_name.clone());

                    let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));
                    let type_def = Self::build_type_def(&param_ext.base, param_ext.enum_variants, &type_id);

                    types.types.push(ParameterType {
                        id: type_id,
                        name: type_name,
                        internal_description: None,
                        type_def,
                    });
                }
            }
        }

        types
    }

    /// Generate a type name from a parameter definition.
    fn param_type_name(param: &zweidraehte::ets::EtsParamDef) -> String {
        // Use explicit type_name if provided
        if let Some(type_name) = param.type_name {
            return type_name.to_string();
        }
        // Otherwise auto-generate based on type
        match param.param_type {
            EtsParamType::UnsignedInt => format!("tUINT{}", param.size_bits),
            EtsParamType::SignedInt => format!("tSINT{}", param.size_bits),
            EtsParamType::Enum => format!("tENUM_{}_{}", param.name, param.size_bits),
            EtsParamType::String => {
                // For text with patterns, generate a unique type name
                if let Some(pattern) = param.text_pattern {
                    // Extract type hint from pattern comment if present (e.g., "(?# TypeColor:RGB)")
                    if pattern.contains("TypeColor:RGB") {
                        "RGBColor".to_string()
                    } else if pattern.contains("TypeColor:HSV") {
                        "HSV-Werte".to_string()  // MDT uses hyphen in display name
                    } else {
                        format!("tTEXT{}", param.size_bits)
                    }
                } else {
                    format!("tTEXT{}", param.size_bits)
                }
            }
            EtsParamType::None => format!("tNONE{}", param.size_bits),
        }
    }

    /// Generate a type name for a union variant parameter.
    ///
    /// For enum types with custom enum_variants, includes the variant name
    /// in the type name to ensure each variant's params get unique types.
    /// This is necessary because different variants (e.g., ForcibleControl vs Switch)
    /// may have the same param name (e.g., "value") but different enum options.
    fn union_variant_param_type_name(
        param: &zweidraehte::ets::EtsParamDef,
        variant_name: &str,
        enum_variants: Option<&[zweidraehte::ets::EtsEnumVariant]>,
    ) -> String {
        // Use explicit type_name if provided
        if let Some(type_name) = param.type_name {
            return type_name.to_string();
        }
        // For enum types with custom enum_variants, include variant name for uniqueness
        if param.param_type == EtsParamType::Enum && enum_variants.is_some() {
            return format!("tENUM_{}_{}", variant_name, param.size_bits);
        }
        // Otherwise use the standard type name generation
        Self::param_type_name(param)
    }

    /// URL-encode a name for use in IDs
    /// - Underscores become .5F
    /// - Hyphens become .2D
    /// - Slashes become .2F
    /// This applies to all user-defined names that appear in IDs
    fn encode_id(name: &str) -> String {
        name.replace('_', ".5F")
            .replace('-', ".2D")
            .replace('/', ".2F")
    }

    /// Build a type definition for a parameter.
    fn build_type_def(
        param: &zweidraehte::ets::EtsParamDef,
        enum_variants: Option<&[zweidraehte::ets::EtsEnumVariant]>,
        type_id: &str,
    ) -> ParameterTypeDef {
        match param.param_type {
            EtsParamType::UnsignedInt => {
                let max = (1i64 << param.size_bits) - 1;
                ParameterTypeDef::TypeNumber(TypeNumber {
                    size_in_bit: param.size_bits,
                    num_type: "unsignedInt".to_string(),
                    min_inclusive: 0,
                    max_inclusive: max,
                })
            }
            EtsParamType::SignedInt => {
                let half = 1i64 << (param.size_bits - 1);
                ParameterTypeDef::TypeNumber(TypeNumber {
                    size_in_bit: param.size_bits,
                    num_type: "signedInt".to_string(),
                    min_inclusive: -half,
                    max_inclusive: half - 1,
                })
            }
            EtsParamType::Enum => {
                let enumerations = if let Some(variants) = enum_variants {
                    variants
                        .iter()
                        .map(|v| Enumeration {
                            text: v.text.to_string(),
                            value: v.value as u32,
                            // Enum ID includes full type prefix and the value
                            id: format!("{}_EN-{}", type_id, v.value),
                        })
                        .collect()
                } else {
                    vec![]
                };
                ParameterTypeDef::TypeRestriction(TypeRestriction {
                    base: "Value".to_string(),
                    size_in_bit: param.size_bits as u32,
                    enumerations,
                })
            }
            EtsParamType::String => {
                // Use pattern if provided, with fixed size for color types
                let (size, pattern) = if let Some(pat) = param.text_pattern {
                    // Color patterns use 56 bits (7 bytes for "#RRGGBB" text representation)
                    if pat.contains("TypeColor:") {
                        (56, Some(pat.to_string()))
                    } else {
                        (param.size_bits as u32, Some(pat.to_string()))
                    }
                } else {
                    (param.size_bits as u32, None)
                };
                ParameterTypeDef::TypeText(TypeText {
                    size_in_bit: size,
                    pattern,
                })
            }
            EtsParamType::None => ParameterTypeDef::TypeNone(TypeNone {}),
        }
    }

    /// Build parameters section.
    fn build_parameters(
        config: &ApplicationProgramConfig,
        app_id: &str,
        code_segment_id: &str,
    ) -> Parameters {
        let mut params = Parameters::default();
        let mut param_counter = 1u32;

        // Build a set of union selector names to skip them in regular params
        // (they are generated inside the Union element, not as separate Parameters)
        let union_selector_names: std::collections::HashSet<String> = config
            .union_fields
            .map(|fields| {
                fields
                    .iter()
                    .map(|f| format!("{}_selector", f.field_name))
                    .collect()
            })
            .unwrap_or_default();

        // Process all parameters (virtual first, then regular)
        // Virtual params have no_memory=true and don't use param_defaults
        for param_ext in config.all_params() {
            let param = &param_ext.base;

            // Skip union selector parameters - they go inside the Union, not as separate params
            if union_selector_names.contains(param.name) {
                continue;
            }

            let param_id = format!("{}_P-{}", app_id, param_counter);
            let type_name = Self::param_type_name(param);
            // Use encoded type ID
            let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));

            // Get default value: prefer explicit default_value, then fall back to param_defaults byte slice
            let param_offset = param.offset as usize;
            let size_bytes = (param.size_bits as usize + 7) / 8;
            let default_value = if let Some(val) = param_ext.default_value {
                val.to_string()
            } else if param.param_type == EtsParamType::String {
                // String parameters default to empty string
                String::new()
            } else if param_offset + size_bytes <= config.param_defaults.len() {
                match size_bytes {
                    1 => config.param_defaults[param_offset].to_string(),
                    2 => {
                        let val = u16::from_le_bytes([
                            config.param_defaults[param_offset],
                            config.param_defaults[param_offset + 1],
                        ]);
                        val.to_string()
                    }
                    4 => {
                        let val = u32::from_le_bytes([
                            config.param_defaults[param_offset],
                            config.param_defaults[param_offset + 1],
                            config.param_defaults[param_offset + 2],
                            config.param_defaults[param_offset + 3],
                        ]);
                        val.to_string()
                    }
                    _ => config.param_defaults[param_offset].to_string(),
                }
            } else {
                "0".to_string()
            };

            // Virtual (no_memory) parameters don't have a Memory element
            let memory = if param.no_memory {
                None
            } else {
                Some(MemoryLocation {
                    code_segment: code_segment_id.to_string(),
                    offset: param.offset as u32,
                    bit_offset: param.bit_offset,
                    base_offset: None,
                })
            };

            params.items.push(ParameterItem::Parameter(Parameter {
                id: param_id,
                name: param.name.to_string(),
                parameter_type: type_id,
                text: param.display_name.to_string(),
                suffix_text: param.suffix.map(|s| s.to_string()),
                access: if param.hidden { Some("None".to_string()) } else { None },
                value: default_value,
                base_value: None,
                internal_description: None,
                memory,
            }));

            param_counter += 1;
        }

        // Union parameters - start counting from 1
        if let Some(union_fields) = config.union_fields {
            let mut up_counter = 1u32;
            for field in union_fields {
                // Look up the selector's explicit default from EtsParamDefExt
                let selector_name = format!("{}_selector", field.field_name);
                let selector_default = config.all_params()
                    .find(|p| p.base.name == selector_name)
                    .and_then(|p| p.default_value);

                let (union_elem, next_counter) = Self::build_union(
                    field,
                    app_id,
                    code_segment_id,
                    up_counter,
                    selector_default,
                );
                params.items.push(ParameterItem::Union(union_elem));
                up_counter = next_counter;
            }
        }

        params
    }

    /// Build a union element from a union field info.
    /// Returns (Union, next_up_counter) to track union parameter numbering.
    fn build_union(
        field: &EtsUnionFieldInfo,
        app_id: &str,
        code_segment_id: &str,
        up_counter: u32,
        selector_default: Option<i64>,
    ) -> (Union, u32) {
        let union_info = field.union_info;
        let total_size_bits = union_info.total_size as u32 * 8;

        let mut parameters = vec![];
        let mut counter = up_counter;

        // Selector parameter (discriminant) - uses sequential UP- numbering
        let selector_type_name = format!("tENUM_{}_selector_8", field.field_name);
        let selector_type = format!("{}_PT-{}", app_id, Self::encode_id(&selector_type_name));
        let selector_value = selector_default.unwrap_or(0).to_string();
        parameters.push(UnionParameter {
            id: format!("{}_UP-{}", app_id, counter),
            name: format!("{}_selector", field.field_name),
            parameter_type: selector_type,
            text: format!("{} Mode", field.field_name),
            suffix_text: None,
            value: selector_value,
            offset: 0,
            bit_offset: 0,
            default_union_parameter: Some(true),
            internal_description: None,
        });
        counter += 1;

        // Variant field parameters - in the order they appear in variant_params
        for param in union_info.variant_params {
            // Use union_variant_param_type_name to match the type generation in build_parameter_types
            let type_name = Self::union_variant_param_type_name(&param.param, param.variant_name, param.enum_variants);
            // Use encoded type ID
            let type_id = format!("{}_PT-{}", app_id, Self::encode_id(&type_name));

            // Use default_value if specified, otherwise:
            // - For color fields (TypeColor pattern), use "#000000"
            // - Otherwise use 0
            let default_value = if let Some(val) = param.default_value {
                val.to_string()
            } else if param.param.text_pattern.map_or(false, |p| p.contains("TypeColor")) {
                "#000000".to_string()
            } else {
                "0".to_string()
            };

            parameters.push(UnionParameter {
                id: format!("{}_UP-{}", app_id, counter),
                name: format!("{}_{}", param.variant_name, param.param.name),
                parameter_type: type_id,
                text: param.param.display_name.to_string(),
                suffix_text: param.param.suffix.map(|s| s.to_string()),
                value: default_value,
                offset: union_info.data_offset + param.param.offset, // data_offset accounts for discriminant + alignment padding
                bit_offset: param.param.bit_offset,
                default_union_parameter: None,
                internal_description: None,
            });
            counter += 1;
        }

        (Union {
            size_in_bit: total_size_bits,
            internal_description: None,
            memory: UnionMemory {
                code_segment: code_segment_id.to_string(),
                offset: field.offset as u32,
                bit_offset: 0,
                base_offset: None,
            },
            parameters,
        }, counter)
    }

    /// Build parameter references.
    /// If `selector_usage_counts` is provided, creates multiple refs for parameters that are
    /// used multiple times as selectors in ObjWithValue/GroupedObjChoose.
    /// If `union_variant_texts` is provided, creates multiple refs for union variant params with
    /// different text overrides (matching MDT's approach where each use context has its own ref).
    /// This must use the same numbering scheme as `build_multi_param_ref_map` so the refs match.
    /// Returns both the ParameterRefs and a mapping of param_name -> first_ref_num for text param refs.
    fn build_parameter_refs(
        config: &ApplicationProgramConfig,
        app_id: &str,
        selector_usage_counts: Option<&HashMap<String, usize>>,
        union_variant_texts: Option<&HashMap<(String, String), Vec<Option<String>>>>,
    ) -> (ParameterRefs, HashMap<String, u32>) {
        let mut refs = ParameterRefs::default();
        let mut param_ref_nums: HashMap<String, u32> = HashMap::new();

        // Build a set of union selector names to skip them in regular params
        let union_selector_names: std::collections::HashSet<String> = config
            .union_fields
            .map(|fields| {
                fields
                    .iter()
                    .map(|f| format!("{}_selector", f.field_name))
                    .collect()
            })
            .unwrap_or_default();

        // Use a single sequential counter for all ref numbers (matching build_multi_param_ref_map)
        let mut next_ref_num = 1u32;
        let mut param_counter = 1u32;

        // Process all params (virtual first, then regular)
        for param in config.all_params() {
            // Skip union selector parameters - they are referenced via union param refs
            if union_selector_names.contains(param.base.name) {
                continue;
            }

            let param_id = format!("{}_P-{}", app_id, param_counter);

            // Determine how many refs to create for this parameter
            let num_refs = selector_usage_counts
                .and_then(|counts| counts.get(param.base.name))
                .copied()
                .unwrap_or(0)
                .max(1); // At least 1 ref

            // Track the first ref number for this param (for text param ref resolution)
            param_ref_nums.insert(param.base.name.to_string(), next_ref_num);

            // Create refs with sequential numbering
            for _ in 0..num_refs {
                let ref_id = format!("{}_R-{}", param_id, next_ref_num);
                refs.refs.push(ParameterRef {
                    id: ref_id,
                    ref_id: param_id.clone(),
                    text: None,
                    internal_description: None,
                    access: None,
                    value: None,
                    base_value: None,
                });
                next_ref_num += 1;
            }

            param_counter += 1;
        }

        // Union parameter refs
        if let Some(union_fields) = config.union_fields {
            let mut up_counter = 1u32;

            for field in union_fields {
                // Selector ref - must match ID in build_union (UP-1, UP-2, etc.)
                let selector_id = format!("{}_UP-{}", app_id, up_counter);
                let selector_name = format!("{}_selector", field.field_name);

                // How many refs for the selector?
                let num_refs = selector_usage_counts
                    .and_then(|counts| counts.get(&selector_name))
                    .copied()
                    .unwrap_or(0)
                    .max(1);

                for _ in 0..num_refs {
                    refs.refs.push(ParameterRef {
                        id: format!("{}_R-{}", selector_id, next_ref_num),
                        ref_id: selector_id.clone(),
                        text: None,
                        internal_description: None,
                        access: None,
                        value: None,
                        base_value: None,
                    });
                    next_ref_num += 1;
                }
                up_counter += 1;

                // Variant parameter refs - in the same order as build_union
                // Create multiple refs for each unique text override
                for param in field.union_info.variant_params {
                    let param_id = format!("{}_UP-{}", app_id, up_counter);

                    // Look up text overrides for this variant
                    let key = (field.field_name.to_string(), param.variant_name.to_string());
                    let text_overrides = union_variant_texts
                        .and_then(|texts| texts.get(&key))
                        .cloned()
                        .unwrap_or_else(|| vec![None]); // At least one ref with no text

                    // Create a ref for each unique text override
                    for text in text_overrides {
                        refs.refs.push(ParameterRef {
                            id: format!("{}_R-{}", param_id, next_ref_num),
                            ref_id: param_id.clone(),
                            text,
                            internal_description: None,
                            access: None,
                            value: None,
                            base_value: None,
                        });
                        next_ref_num += 1;
                    }
                    up_counter += 1;
                }
            }
        }

        (refs, param_ref_nums)
    }

    /// Resolve text parameter references in a string.
    /// Replaces `{{param_name:default}}` with `{{N:default}}` where N is the ref number.
    fn resolve_text_param_refs(text: &str, param_ref_nums: &HashMap<String, u32>) -> String {
        // Quick check if there are any references to resolve
        if !text.contains("{{") {
            return text.to_string();
        }

        let mut result = text.to_string();

        // Find all {{param_name:default}} patterns and replace with {{N:default}}
        // Pattern: {{ followed by param_name, then :, then anything until }}
        let re = regex::Regex::new(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*):([^}]*)\}\}").unwrap();

        for cap in re.captures_iter(text) {
            let full_match = cap.get(0).unwrap().as_str();
            let param_name = cap.get(1).unwrap().as_str();
            let default_text = cap.get(2).unwrap().as_str();

            if let Some(&ref_num) = param_ref_nums.get(param_name) {
                // Use {{N}} format when default is empty, {{N:default}} otherwise (matches MDT)
                let replacement = if default_text.is_empty() {
                    format!("{{{{{}}}}}", ref_num)
                } else {
                    format!("{{{{{}:{}}}}}", ref_num, default_text)
                };
                result = result.replace(full_match, &replacement);
            }
            // If param not found, leave the original text (will show as static text)
        }

        result
    }

    /// Build communication object table.
    fn build_com_object_table(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
    ) -> ComObjectTable {
        // For System 7, use the third segment (typically 4400) for ComObjectTable
        let code_segment = if let Some(ref layout) = config.system7_layout {
            // Find the com object table segment (usually after address and association tables)
            if let Some(seg) = layout.segments.get(2) {
                Some(format!("{}_AS-{}", app_id, seg.name))
            } else {
                None
            }
        } else {
            None
        };
        let mut table = ComObjectTable {
            code_segment,
            offset: Some(0),
            ..ComObjectTable::default()
        };
        let start_index = mask_family.com_object_start_index();

        // Build a map of object_index -> (ref_count, max_size_bits)
        let mut ref_info: std::collections::HashMap<u16, (usize, u8)> = std::collections::HashMap::new();
        for ref_def in config.comm_object_refs {
            let entry = ref_info.entry(ref_def.object_index).or_insert((0, 0));
            entry.0 += 1; // increment ref count
            entry.1 = entry.1.max(ref_def.size_bits); // track max size
        }

        for co in config.comm_objects {
            // Adjust index based on mask family
            let adjusted_index = co.index + start_index;
            let obj_id = format!("{}_O-{}", app_id, adjusted_index);
            let flags = co.default_flags;

            // Check if this object has multiple refs
            let (ref_count, max_size) = ref_info.get(&co.index).copied().unwrap_or((1, co.size_bits));
            let is_multi_ref = ref_count > 1;

            // For multi-ref objects: no DPT on base object, use max size from refs
            // For single-ref objects: include DPT and use object's size
            // object_size_override takes precedence if specified
            let (datapoint_type, object_size) = if is_multi_ref {
                let size = co.object_size_override
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| object_size_to_string(max_size).to_string());
                (None, size)
            } else {
                let size = co.object_size_override
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| object_size_to_string(co.size_bits).to_string());
                (Some(dpt_to_string(co.dpt_main, co.dpt_sub)), size)
            };

            table.objects.push(ComObject {
                id: obj_id,
                name: co.name.to_string(),
                text: co.display_name.to_string(),
                number: adjusted_index,
                function_text: co.function_text.to_string(),
                object_size,
                datapoint_type,
                // KNX ComObjectFlags bit layout (from tables/mod.rs):
                // Bit 7 (0x80): Update Enable (UE)
                // Bit 6 (0x40): Transmit Enable (TE)
                // Bit 5 (0x20): Read On Init (ROI)
                // Bit 4 (0x10): Write Enable (WE)
                // Bit 3 (0x08): Read Enable (RE)
                // Bit 2 (0x04): Communication Enable (CE)
                // Bits 0-1: Priority
                read_flag: (flags & 0x08 != 0).into(),
                write_flag: (flags & 0x10 != 0).into(),
                communication_flag: (flags & 0x04 != 0).into(),
                transmit_flag: (flags & 0x40 != 0).into(),
                update_flag: (flags & 0x80 != 0).into(),
                read_on_init_flag: (flags & 0x20 != 0).into(),
                priority: None, // MDT doesn't include Priority in ComObjects
                internal_description: None,
                base_number: None,
            });
        }

        table
    }

    /// Build communication object references.
    ///
    /// Uses the comm_object_refs array which contains one entry per ref.
    /// For multi-ref objects, there will be multiple refs pointing to the same ComObject.
    /// The param_ref_nums map is used to resolve text parameter references in Text attributes.
    fn build_com_object_refs(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_nums: &HashMap<String, u32>,
    ) -> ComObjectRefs {
        let mut refs = ComObjectRefs::default();
        let start_index = mask_family.com_object_start_index();

        for (i, ref_def) in config.comm_object_refs.iter().enumerate() {
            let adjusted_index = ref_def.object_index + start_index;
            let co_id = format!("{}_O-{}", app_id, adjusted_index);
            let ref_id = format!("{}_R-{}", co_id, i + 1);

            // Resolve text parameter references in the text attribute
            let text = ref_def.text.map(|s| Self::resolve_text_param_refs(s, param_ref_nums));

            // Build the ComObjectRef with potential overrides from the ref definition
            // Note: MDT doesn't include Name attribute on ComObjectRefs, only on ComObjects
            let mut com_ref = ComObjectRef {
                id: ref_id,
                ref_id: co_id,
                name: None,
                text,
                function_text: Some(ref_def.function_text.to_string()),
                datapoint_type: Some(dpt_to_string(ref_def.dpt_main, ref_def.dpt_sub)),
                object_size: Some(object_size_to_string(ref_def.size_bits).to_string()),
                internal_description: None,
                ..Default::default()
            };

            // Apply flag overrides if present
            if let Some(flags) = &ref_def.flag_overrides {
                com_ref.read_flag = flags.read.map(|b| b.into());
                com_ref.write_flag = flags.write.map(|b| b.into());
                com_ref.communication_flag = flags.communication.map(|b| b.into());
                com_ref.transmit_flag = flags.transmit.map(|b| b.into());
                com_ref.update_flag = flags.update.map(|b| b.into());
                com_ref.read_on_init_flag = flags.read_on_init.map(|b| b.into());
            }

            refs.refs.push(com_ref);
        }

        refs
    }

    /// Build load procedures based on mask family.
    fn build_load_procedures(
        config: &ApplicationProgramConfig,
        param_size: u32,
        mask_family: MaskFamily,
    ) -> LoadProcedures {
        match mask_family {
            MaskFamily::SystemB => Self::build_system_b_load_procedures(param_size),
            MaskFamily::System7 => Self::build_system_7_load_procedures(config),
            MaskFamily::Bim | MaskFamily::BimM => Self::build_bim_load_procedures(),
        }
    }

    /// Build load procedures for System B (MergedProcedure with relative segments).
    fn build_system_b_load_procedures(param_size: u32) -> LoadProcedures {
        LoadProcedures {
            procedures: vec![
                LoadProcedure {
                    merge_id: Some(2),
                    controls: vec![
                        LoadControl::LdCtrlRelSegment(LdCtrlRelSegment {
                            applies_to: "full".to_string(),
                            lsm_idx: 4,
                            size: param_size,
                            mode: 1,
                            fill: 0,
                        }),
                        LoadControl::LdCtrlRelSegment(LdCtrlRelSegment {
                            applies_to: "par".to_string(),
                            lsm_idx: 4,
                            size: param_size,
                            mode: 0,
                            fill: 0,
                        }),
                    ],
                },
                LoadProcedure {
                    merge_id: Some(4),
                    controls: vec![LoadControl::LdCtrlWriteRelMem(LdCtrlWriteRelMem {
                        applies_to: "full,par".to_string(),
                        obj_idx: 4,
                        offset: 0,
                        size: param_size,
                        verify: true,
                    })],
                },
                LoadProcedure {
                    merge_id: Some(7),
                    controls: vec![
                        LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                            obj_idx: 1,
                            prop_id: 27,
                        }),
                        LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                            obj_idx: 2,
                            prop_id: 27,
                        }),
                        LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                            obj_idx: 3,
                            prop_id: 27,
                        }),
                        LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                            obj_idx: 4,
                            prop_id: 27,
                        }),
                    ],
                },
            ],
        }
    }

    /// Build load procedures for System 7 (ProductProcedure with absolute segments).
    ///
    /// System 7 LoadProcedure format (based on MDT M-0083_A-009B-14-E59D.xml):
    /// 1. LdCtrlConnect - Establish connection
    /// 2. LdCtrlCompareProp - Verify device identity (ObjIdx=0, PropId=78 is PID_SERIAL_NUMBER)
    /// 3. LdCtrlUnload LSM 1,2,3 - Unload existing load state machines
    /// 4. For each LSM:
    ///    - LdCtrlLoad
    ///    - LdCtrlAbsSegment(s) for the segments belonging to this LSM
    ///    - LdCtrlTaskSegment
    ///    - LdCtrlLoadCompleted
    /// 5. LdCtrlRestart
    /// 6. LdCtrlDisconnect
    fn build_system_7_load_procedures(config: &ApplicationProgramConfig) -> LoadProcedures {
        // If no System 7 layout is provided, return empty
        let Some(ref layout) = config.system7_layout else {
            return LoadProcedures { procedures: vec![] };
        };

        let mut controls = Vec::new();

        // 1. Connect
        controls.push(LoadControl::LdCtrlConnect(LdCtrlConnect {}));

        // 2. Compare device serial number (PID_SERIAL_NUMBER = 78, ObjIdx = 0 for Device Object)
        // The InlineData is the expected serial number as hex
        let serial_hex = config.serial_number.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();
        // Pad to 10 bytes (20 hex chars) like MDT does
        let serial_padded = format!("{:0<20}", serial_hex);
        controls.push(LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
            obj_idx: 0,
            prop_id: 78, // PID_SERIAL_NUMBER
            inline_data: Some(serial_padded),
            range: None,
            on_error: None,
        }));

        // 3. Unload existing LSMs (1, 2, 3)
        controls.push(LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: 1 }));
        controls.push(LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: 2 }));
        controls.push(LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: 3 }));

        // 4. Load LSM 1 - Address Table
        controls.push(LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: 1 }));
        if let Some(seg) = layout.segments.iter().find(|s| s.name == layout.address_table_segment) {
            controls.push(LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                lsm_idx: 1,
                seg_type: 0,
                address: seg.address as u16,
                size: seg.size as u16,
                access: 255,       // Full access
                mem_type: 3,       // EEPROM
                seg_flags: 128,    // Standard flags
            }));
            controls.push(LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment {
                lsm_idx: 1,
                address: seg.address as u16,
            }));
        }
        controls.push(LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: 1 }));

        // 5. Load LSM 2 - Association Table
        controls.push(LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: 2 }));
        if let Some(seg) = layout.segments.iter().find(|s| s.name == layout.association_table_segment) {
            controls.push(LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                lsm_idx: 2,
                seg_type: 0,
                address: seg.address as u16,
                size: seg.size as u16,
                access: 255,
                mem_type: 3,
                seg_flags: 128,
            }));
            controls.push(LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment {
                lsm_idx: 2,
                address: seg.address as u16,
            }));
        }
        controls.push(LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: 2 }));

        // 6. Load LSM 3 - Application (RAM segments, COT, Parameters)
        controls.push(LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: 3 }));

        // Add RAM segments first
        for seg in &layout.segments {
            if seg.memory_type == Some("RAM") {
                let seg_type = if seg.size == 1 { 1 } else { 0 }; // Type 1 for 1-byte segments
                controls.push(LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                    lsm_idx: 3,
                    seg_type,
                    address: seg.address as u16,
                    size: seg.size as u16,
                    access: 0,     // No external access for RAM
                    mem_type: 2,   // RAM
                    seg_flags: 0,
                }));
            }
        }

        // Add EEPROM segments (COT and Parameters) - skip address/assoc tables
        for seg in &layout.segments {
            if seg.name != layout.address_table_segment
                && seg.name != layout.association_table_segment
                && seg.memory_type != Some("RAM")
            {
                controls.push(LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                    lsm_idx: 3,
                    seg_type: 0,
                    address: seg.address as u16,
                    size: seg.size as u16,
                    access: 255,
                    mem_type: 3,   // EEPROM
                    seg_flags: 128,
                }));
            }
        }

        // Task segment points to COT (17408 = 0x4400)
        // Find the COT segment (typically the one that's not address table, assoc table, RAM, or param EEPROM)
        // For simplicity, use address 17408 (0x4400) which is standard for COT
        let cot_address = layout.segments.iter()
            .find(|s| s.name != layout.address_table_segment
                && s.name != layout.association_table_segment
                && s.memory_type != Some("RAM")
                && s.memory_type != Some("EEPROM"))
            .map(|s| s.address as u16)
            .unwrap_or(17408);
        controls.push(LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment {
            lsm_idx: 3,
            address: cot_address,
        }));
        controls.push(LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: 3 }));

        // 7. Restart and disconnect
        controls.push(LoadControl::LdCtrlRestart(LdCtrlRestart {}));
        controls.push(LoadControl::LdCtrlDisconnect(LdCtrlDisconnect {}));

        LoadProcedures {
            procedures: vec![LoadProcedure {
                merge_id: None, // ProductProcedure doesn't use MergeId
                controls,
            }],
        }
    }

    /// Build load procedures for BIM devices.
    fn build_bim_load_procedures() -> LoadProcedures {
        // BIM devices have their own load mechanism
        LoadProcedures { procedures: vec![] }
    }

    /// Build the Dynamic section with channel and parameter blocks.
    fn build_dynamic_section(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
    ) -> Result<DynamicSection, GeneratorError> {
        let co_start_index = mask_family.com_object_start_index();
        let mut items = vec![];

        // Build a set of union selector names to skip them in regular params
        let union_selector_names: std::collections::HashSet<String> = config
            .union_fields
            .map(|fields| {
                fields
                    .iter()
                    .map(|f| format!("{}_selector", f.field_name))
                    .collect()
            })
            .unwrap_or_default();

        // Add ParameterRefRefs for all parameters (virtual first, then regular)
        let mut param_counter = 1usize;
        for param in config.all_params() {
            // Skip union selector parameters
            if union_selector_names.contains(param.base.name) {
                continue;
            }

            let param_id = format!("{}_P-{}", app_id, param_counter);
            // The ref_id must match what we generate in build_parameter_refs
            let ref_id = format!("{}_R-{}", param_id, param_counter);

            items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                ref_id,
                text: None,
                internal_description: None,
            }));
            param_counter += 1;
        }

        // Add union fields with choose/when for conditional visibility
        if let Some(union_fields) = config.union_fields {
            // Count non-selector params for ref_counter
            let non_selector_param_count = config
                .all_params()
                .filter(|p| !union_selector_names.contains(p.base.name))
                .count();
            let mut ref_counter = non_selector_param_count + 1;
            let mut up_counter = 1u32; // Sequential UP- counter matching build_union and build_parameter_refs

            for field in union_fields {
                // First, add the selector parameter (always visible)
                // Uses sequential UP-N ID matching build_union and build_parameter_refs
                let selector_id = format!("{}_UP-{}", app_id, up_counter);
                let selector_ref_id = format!("{}_R-{}", selector_id, ref_counter);

                items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                    ref_id: selector_ref_id.clone(),
                    text: None,
                    internal_description: None,
                }));
                ref_counter += 1;
                up_counter += 1;

                // Build a map of discriminant_value -> (display_name, param_ref_ids)
                let mut variant_refs: std::collections::HashMap<i64, (&str, Vec<String>)> =
                    std::collections::HashMap::new();

                // Get display names from selector_variants (keyed by discriminant value)
                for variant in field.selector_variants {
                    variant_refs.insert(variant.value, (variant.text, vec![]));
                }

                // Assign parameter refs to their variants (matching by discriminant value)
                // Uses sequential UP-N IDs matching build_union
                for param in field.union_info.variant_params {
                    let param_id = format!("{}_UP-{}", app_id, up_counter);
                    let param_ref_id = format!("{}_R-{}", param_id, ref_counter);

                    // Match by variant_value (discriminant), not by name
                    if let Some((_, refs)) = variant_refs.get_mut(&param.variant_value) {
                        refs.push(param_ref_id);
                    }
                    ref_counter += 1;
                    up_counter += 1;
                }

                // Build the choose/when structure
                let mut whens = vec![];

                // Sort variants by discriminant value for consistent output
                let mut sorted_variants: Vec<_> = variant_refs.into_iter().collect();
                sorted_variants.sort_by_key(|(disc, _)| *disc);

                for (discriminant, (_display_name, param_ref_ids)) in sorted_variants {
                    // Create when clause for this variant
                    let when_items: Vec<WhenItem> = param_ref_ids
                        .into_iter()
                        .map(|ref_id| {
                            WhenItem::ParameterRefRef(ParameterRefRef {
                                ref_id,
                                text: None,
                                internal_description: None,
                            })
                        })
                        .collect();

                    whens.push(When {
                        test: Some(discriminant.to_string()),
                        default: None,
                        internal_description: None,
                        items: when_items,
                    });
                }

                items.push(ParameterBlockItem::Choose(Choose {
                    param_ref_id: selector_ref_id,
                    whens,
                }));
            }
        }

        // Add ComObjectRefRefs - reference each ref from comm_object_refs
        // The ref IDs must match those generated in build_com_object_refs
        //
        // For refs with selector_param, we need to group them and create choose/when structures.
        // For refs without selector_param (simple objects), add them directly.

        // First, build a map: selector_param -> (object_index -> [(ref_index, selector_value)])
        let mut selector_groups: std::collections::HashMap<
            &str, // selector_param name
            std::collections::HashMap<u16, Vec<(usize, i64)>> // object_index -> [(ref_index, selector_value)]
        > = std::collections::HashMap::new();

        // Also track which refs need choose/when (have selector_param)
        let mut refs_in_choose: std::collections::HashSet<usize> = std::collections::HashSet::new();

        for (i, ref_def) in config.comm_object_refs.iter().enumerate() {
            if let (Some(param), Some(value)) = (ref_def.selector_param, ref_def.selector_value) {
                selector_groups
                    .entry(param)
                    .or_default()
                    .entry(ref_def.object_index)
                    .or_default()
                    .push((i, value));
                refs_in_choose.insert(i);
            }
        }

        // Add simple refs (those without selector) directly
        for (i, ref_def) in config.comm_object_refs.iter().enumerate() {
            if refs_in_choose.contains(&i) {
                continue; // Skip - will be added in choose/when
            }

            let adjusted_index = ref_def.object_index + co_start_index;
            let co_id = format!("{}_O-{}", app_id, adjusted_index);
            let ref_id = format!("{}_R-{}", co_id, i + 1);

            items.push(ParameterBlockItem::ComObjectRefRef(ComObjectRefRef {
                ref_id,
                internal_description: None,
            }));
        }

        // Now build choose/when for each selector_param
        // Need to find the parameter ref ID for each selector_param
        for (selector_param, objects) in &selector_groups {
            // Find the parameter ref ID for this selector
            // The selector_param is the parameter name, we need to find its ref ID
            let param_ref_id = Self::find_param_ref_id(config, app_id, selector_param);

            // Build when clauses - group by selector_value across all objects
            let mut value_to_refs: std::collections::HashMap<i64, Vec<String>> =
                std::collections::HashMap::new();

            for (object_index, ref_list) in objects {
                for (ref_index, selector_value) in ref_list {
                    let adjusted_index = object_index + co_start_index;
                    let co_id = format!("{}_O-{}", app_id, adjusted_index);
                    let ref_id = format!("{}_R-{}", co_id, ref_index + 1);
                    value_to_refs.entry(*selector_value).or_default().push(ref_id);
                }
            }

            // Sort by selector value for consistent output
            let mut sorted_values: Vec<_> = value_to_refs.into_iter().collect();
            sorted_values.sort_by_key(|(v, _)| *v);

            let whens: Vec<When> = sorted_values
                .into_iter()
                .map(|(selector_value, ref_ids)| {
                    let when_items: Vec<WhenItem> = ref_ids
                        .into_iter()
                        .map(|ref_id| {
                            WhenItem::ComObjectRefRef(ComObjectRefRef {
                                ref_id,
                                internal_description: None,
                            })
                        })
                        .collect();

                    When {
                        test: Some(selector_value.to_string()),
                        default: None,
                        internal_description: None,
                        items: when_items,
                    }
                })
                .collect();

            items.push(ParameterBlockItem::Choose(Choose {
                param_ref_id,
                whens,
            }));
        }

        Ok(DynamicSection {
            channel_independent_block: None,
            channels: vec![Channel {
                id: format!("{}_CH-1", app_id),
                name: config.channel_name.to_string(),
                text: None,
                number: Some("1".to_string()),
                internal_description: None,
                items: vec![ChannelItem::ParameterBlock(ParameterBlock {
                    id: format!("{}_PB-1", app_id),
                    name: Some(config.name.to_string()),
                    text: None,
                    text_parameter_ref_id: None,
                    internal_description: None,
                    inline: None,
                    show_in_com_object_tree: None,
                    layout: None,
                    items,
                })],
            }],
        })
    }

    /// Find the parameter ref ID for a given parameter name.
    ///
    /// This looks through the params to find the parameter by name, then
    /// constructs the corresponding ParameterRef ID.
    fn find_param_ref_id(config: &ApplicationProgramConfig, app_id: &str, param_name: &str) -> String {
        // Build a set of union selector names that are handled specially
        let union_selector_names: std::collections::HashSet<String> = config
            .union_fields
            .map(|fields| {
                fields
                    .iter()
                    .map(|f| format!("{}_selector", f.field_name))
                    .collect()
            })
            .unwrap_or_default();

        // Search through all params (virtual first, then regular)
        let mut param_counter = 1usize;
        for param_ext in config.all_params() {
            // Skip union selector params - they are numbered differently
            if union_selector_names.contains(param_ext.base.name) {
                continue;
            }

            if param_ext.base.name == param_name {
                let param_id = format!("{}_P-{}", app_id, param_counter);
                let ref_id = format!("{}_R-{}", param_id, param_counter);
                return ref_id;
            }
            param_counter += 1;
        }

        // Search through union selectors
        if let Some(union_fields) = config.union_fields {
            // Count non-selector params for ref_counter
            let non_selector_param_count = config
                .all_params()
                .filter(|p| !union_selector_names.contains(p.base.name))
                .count();
            let mut ref_counter = non_selector_param_count + 1;
            let mut up_counter = 1u32;

            for field in union_fields {
                let selector_name = format!("{}_selector", field.field_name);
                if selector_name == param_name {
                    let selector_id = format!("{}_UP-{}", app_id, up_counter);
                    let selector_ref_id = format!("{}_R-{}", selector_id, ref_counter);
                    return selector_ref_id;
                }
                ref_counter += 1;
                up_counter += 1;

                // Skip variant params
                for _param in field.union_info.variant_params {
                    ref_counter += 1;
                    up_counter += 1;
                }
            }
        }

        // Fallback: just construct a reasonable ref ID
        format!("{}_P-{}_R-1", app_id, param_name)
    }

    /// Build the Dynamic section from a page layout definition.
    ///
    /// This generates the Dynamic section based on user-defined page structure,
    /// allowing precise control over how parameters are organized in the ETS UI.
    fn build_dynamic_section_from_layout(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        layout: &PageStructure,
    ) -> Result<DynamicSection, GeneratorError> {
        // Build name-to-RefId mapping for all comm objects (needed for counting)
        let comm_obj_ref_map = Self::build_comm_object_ref_map(config, app_id, mask_family);

        // Count selector usages (including PageItem::Obj which needs comm_obj_ref_map)
        let selector_usage_counts = count_selector_usages_with_objects(layout, &comm_obj_ref_map);

        // Collect union variant text overrides for creating multiple ParameterRefs with different Text
        let union_variant_texts = collect_union_variant_texts(layout);

        // Build multi-ref parameter map (supports multiple refs per selector param)
        let param_ref_map = Self::build_multi_param_ref_map(config, app_id, &selector_usage_counts, Some(&union_variant_texts));

        // Generate block and separator counters
        let mut block_counter = 1u32;
        let mut sep_counter = 1u32;

        // Track selector ref usage for allocating unique refs to each choose block
        let mut selector_counters = SelectorRefCounters::new();

        // Build ChannelIndependentBlock if device_settings is non-empty
        let channel_independent_block = if layout.device_settings.is_empty() {
            None
        } else {
            let items = Self::build_channel_independent_items(
                &layout.device_settings,
                config,
                app_id,
                mask_family,
                &param_ref_map,
                &comm_obj_ref_map,
                &mut block_counter,
                &mut sep_counter,
                &mut selector_counters,
            )?;
            Some(ChannelIndependentBlock { items })
        };

        // Build Channel elements
        let channels: Vec<Channel> = layout
            .channels
            .iter()
            .enumerate()
            .map(|(i, ch_def)| {
                let items = Self::build_channel_items(
                    &ch_def.elements,
                    config,
                    app_id,
                    mask_family,
                    &param_ref_map,
                    &comm_obj_ref_map,
                    &mut block_counter,
                    &mut sep_counter,
                    &mut selector_counters,
                )?;
                // Use channel number in ID if specified, otherwise use sequential index
                let ch_num = ch_def.number.unwrap_or(i as u32 + 1);
                Ok(Channel {
                    id: format!("{}_CH-{}", app_id, ch_num),
                    // Use display text for Name attribute (matches MDT convention)
                    name: ch_def.text.to_string(),
                    text: Some(ch_def.text.to_string()),
                    // XSD requires Number attribute (use index + 1 as default)
                    number: Some(ch_num.to_string()),
                    internal_description: None,
                    items,
                })
            })
            .collect::<Result<Vec<_>, GeneratorError>>()?;

        Ok(DynamicSection {
            channel_independent_block,
            channels,
        })
    }
    /// Build a multi-ref parameter map that supports multiple refs per parameter.
    /// Parameters that are used as selectors in ObjWithValue/GroupedObjChoose
    /// get multiple refs (matching MDT's fine-grained structure).
    fn build_multi_param_ref_map(
        config: &ApplicationProgramConfig,
        app_id: &str,
        selector_usage_counts: &HashMap<String, usize>,
        union_variant_texts: Option<&HashMap<(String, String), Vec<Option<String>>>>,
    ) -> MultiParamRefMap {
        let mut primary = HashMap::new();
        let mut multi: HashMap<String, Vec<String>> = HashMap::new();
        let mut by_text: HashMap<(String, Option<String>), String> = HashMap::new();
        let mut param_ref_nums: HashMap<String, u32> = HashMap::new();

        // Build a set of union selector names
        let union_selector_names: std::collections::HashSet<String> = config
            .union_fields
            .map(|fields| {
                fields
                    .iter()
                    .map(|f| format!("{}_selector", f.field_name))
                    .collect()
            })
            .unwrap_or_default();

        // Track ref numbering - we need unique numbers for all refs
        // MDT uses high numbers for additional refs (e.g., R-90, R-174, R-216 for same P-35)
        let mut next_ref_num = 1u32;

        // Map all params (virtual first, then regular, non-selector)
        let mut param_counter = 1usize;
        for param_ext in config.all_params() {
            if union_selector_names.contains(param_ext.base.name) {
                continue;
            }
            let param_name = param_ext.base.name.to_string();
            let param_id = format!("{}_P-{}", app_id, param_counter);

            // How many refs do we need for this param?
            let num_refs = selector_usage_counts.get(&param_name).copied().unwrap_or(0).max(1);

            // Create refs
            let mut refs = Vec::with_capacity(num_refs);
            let first_ref_num = next_ref_num; // Track for param_ref_nums
            for i in 0..num_refs {
                let ref_id = format!("{}_R-{}", param_id, next_ref_num);
                if i == 0 {
                    primary.insert(param_name.clone(), ref_id.clone());
                }
                refs.push(ref_id);
                next_ref_num += 1;
            }

            // Store the primary ref number for text interpolation
            param_ref_nums.insert(param_name.clone(), first_ref_num);

            if num_refs > 1 {
                multi.insert(param_name, refs);
            }

            param_counter += 1;
        }

        // Map union fields (selector and variant params)
        if let Some(union_fields) = config.union_fields {
            let mut up_counter = 1u32;

            for field in union_fields {
                // Selector param
                let selector_name = format!("{}_selector", field.field_name);
                let selector_id = format!("{}_UP-{}", app_id, up_counter);

                // How many refs for the selector?
                let num_refs = selector_usage_counts.get(&selector_name).copied().unwrap_or(0).max(1);

                let mut refs = Vec::with_capacity(num_refs);
                let first_ref_num = next_ref_num; // Track for param_ref_nums
                for i in 0..num_refs {
                    let ref_id = format!("{}_R-{}", selector_id, next_ref_num);
                    if i == 0 {
                        primary.insert(selector_name.clone(), ref_id.clone());
                    }
                    refs.push(ref_id);
                    next_ref_num += 1;
                }

                // Store the primary ref number for text interpolation
                param_ref_nums.insert(selector_name.clone(), first_ref_num);

                if num_refs > 1 {
                    multi.insert(selector_name, refs);
                }

                up_counter += 1;

                // Variant params - create refs for each unique text override
                for variant_param in field.union_info.variant_params {
                    let param_id = format!("{}_UP-{}", app_id, up_counter);
                    let full_param_name = format!("{}_{}_{}", field.field_name, variant_param.variant_name, variant_param.param.name);

                    // Look up text overrides for this variant
                    let key = (field.field_name.to_string(), variant_param.variant_name.to_string());
                    let text_overrides = union_variant_texts
                        .and_then(|texts| texts.get(&key))
                        .cloned()
                        .unwrap_or_else(|| vec![None]); // At least one ref with no text

                    // Create a ref for each unique text override
                    for (i, text) in text_overrides.iter().enumerate() {
                        let ref_id = format!("{}_R-{}", param_id, next_ref_num);
                        if i == 0 {
                            primary.insert(full_param_name.clone(), ref_id.clone());
                        }
                        // Also add to by_text for text-based lookup
                        by_text.insert((full_param_name.clone(), text.clone()), ref_id.clone());
                        next_ref_num += 1;
                    }
                    up_counter += 1;
                }
            }
        }

        MultiParamRefMap { primary, multi, by_text, param_ref_nums }
    }

    /// Build a mapping from comm object field names to their ComObjectRefRef info.
    ///
    /// Returns a map where the key is the field name (e.g., "channel_a_in") and the
    /// value is a tuple of (ref_id, selector_param, selector_value).
    ///
    /// For objects without selectors, selector_param and selector_value are None.
    /// For objects with selectors, multiple refs exist with different selector_values.
    fn build_comm_object_ref_map(
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
    ) -> HashMap<String, Vec<(String, Option<String>, Option<i64>)>> {
        let mut map: HashMap<String, Vec<(String, Option<String>, Option<i64>)>> = HashMap::new();
        let co_start_index = mask_family.com_object_start_index();

        // Build ref info map
        for (i, ref_def) in config.comm_object_refs.iter().enumerate() {
            let adjusted_index = ref_def.object_index + co_start_index;
            let co_id = format!("{}_O-{}", app_id, adjusted_index);
            let ref_id = format!("{}_R-{}", co_id, i + 1);

            // Use the ref_name as the key (this is the field name from the struct)
            map.entry(ref_def.ref_name.to_string())
                .or_default()
                .push((
                    ref_id,
                    ref_def.selector_param.map(|s| s.to_string()),
                    ref_def.selector_value,
                ));
        }

        map
    }

    /// Build items for a ChannelIndependentBlock.
    fn build_channel_independent_items(
        elements: &[PageElement],
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_map: &MultiParamRefMap,
        comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
        block_counter: &mut u32,
        sep_counter: &mut u32,
        selector_counters: &mut SelectorRefCounters,
    ) -> Result<Vec<ChannelIndependentItem>, GeneratorError> {
        let mut items = Vec::new();

        // Start with empty active conditions at the top level
        let active_conditions = ActiveConditions::new();

        for element in elements {
            match element {
                PageElement::Block(block) => {
                    let pb = Self::build_parameter_block(
                        block,
                        config,
                        app_id,
                        mask_family,
                        param_ref_map,
                        comm_obj_ref_map,
                        block_counter,
                        sep_counter,
                        selector_counters,
                        &active_conditions,
                    )?;
                    items.push(ChannelIndependentItem::ParameterBlock(pb));
                }
                PageElement::When(cond) => {
                    let choose = Self::build_element_choose(
                        cond,
                        config,
                        app_id,
                        mask_family,
                        param_ref_map,
                        comm_obj_ref_map,
                        block_counter,
                        sep_counter,
                        selector_counters,
                        &active_conditions,
                    )?;
                    items.push(ChannelIndependentItem::Choose(choose));
                }
            }
        }

        Ok(items)
    }

    /// Build items for a Channel.
    fn build_channel_items(
        elements: &[PageElement],
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_map: &MultiParamRefMap,
        comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
        block_counter: &mut u32,
        sep_counter: &mut u32,
        selector_counters: &mut SelectorRefCounters,
    ) -> Result<Vec<ChannelItem>, GeneratorError> {
        let mut items = Vec::new();

        // Start with empty active conditions at the top level
        let active_conditions = ActiveConditions::new();

        for element in elements {
            match element {
                PageElement::Block(block) => {
                    let pb = Self::build_parameter_block(
                        block,
                        config,
                        app_id,
                        mask_family,
                        param_ref_map,
                        comm_obj_ref_map,
                        block_counter,
                        sep_counter,
                        selector_counters,
                        &active_conditions,
                    )?;
                    items.push(ChannelItem::ParameterBlock(pb));
                }
                PageElement::When(cond) => {
                    let choose = Self::build_element_choose(
                        cond,
                        config,
                        app_id,
                        mask_family,
                        param_ref_map,
                        comm_obj_ref_map,
                        block_counter,
                        sep_counter,
                        selector_counters,
                        &active_conditions,
                    )?;
                    items.push(ChannelItem::Choose(choose));
                }
            }
        }

        Ok(items)
    }

    /// Build a ParameterBlock from a PageBlock definition.
    fn build_parameter_block(
        block: &PageBlock,
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_map: &MultiParamRefMap,
        comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
        block_counter: &mut u32,
        sep_counter: &mut u32,
        selector_counters: &mut SelectorRefCounters,
        active_conditions: &ActiveConditions,
    ) -> Result<ParameterBlock, GeneratorError> {
        let block_id = *block_counter;
        *block_counter += 1;

        let items = Self::build_block_items(
            &block.items,
            config,
            app_id,
            mask_family,
            param_ref_map,
            comm_obj_ref_map,
            sep_counter,
            selector_counters,
            active_conditions,
        )?;

        // Resolve text parameter references in block text
        let resolved_text = Self::resolve_text_param_refs(block.text, &param_ref_map.param_ref_nums);

        Ok(ParameterBlock {
            id: format!("{}_PB-{}", app_id, block_id),
            name: Some(block.name.to_string()),
            text: Some(resolved_text),
            text_parameter_ref_id: None,
            internal_description: None,
            inline: None,
            show_in_com_object_tree: None,
            layout: None,
            items,
        })
    }

    /// Build items for a ParameterBlock.
    fn build_block_items(
        page_items: &[PageItem],
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_map: &MultiParamRefMap,
        comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
        sep_counter: &mut u32,
        selector_counters: &mut SelectorRefCounters,
        active_conditions: &ActiveConditions,
    ) -> Result<Vec<ParameterBlockItem>, GeneratorError> {
        let mut items = Vec::new();

        for page_item in page_items {
            match page_item {
                PageItem::Param(name) => {
                    if let Some(ref_id) = param_ref_map.get_primary(*name) {
                        items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                            ref_id: ref_id.clone(),
                            text: None,
                            internal_description: None,
                        }));
                    } else {
                        // Try to find it using the existing method as fallback
                        let ref_id = Self::find_param_ref_id(config, app_id, name);
                        items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                            ref_id,
                            text: None,
                            internal_description: None,
                        }));
                    }
                }
                PageItem::Obj(name) => {
                    // Look up comm object refs by field name
                    if let Some(refs) = comm_obj_ref_map.get(*name) {
                        // Group refs by selector_param
                        let refs_with_selector: Vec<&(String, Option<String>, Option<i64>)> = refs.iter()
                            .filter(|(_, sel_param, sel_val)| sel_param.is_some() && sel_val.is_some())
                            .collect();
                        let refs_without_selector: Vec<&(String, Option<String>, Option<i64>)> = refs.iter()
                            .filter(|(_, sel_param, _)| sel_param.is_none())
                            .collect();

                        // If there are no selector-based refs, just emit the unconditional ref
                        if refs_with_selector.is_empty() {
                            if let Some((ref_id, _, _)) = refs_without_selector.first() {
                                items.push(ParameterBlockItem::ComObjectRefRef(ComObjectRefRef {
                                    ref_id: ref_id.clone(),
                                    internal_description: None,
                                }));
                            }
                        } else {
                            // Group refs by selector_param name
                            let mut by_selector: std::collections::HashMap<&str, Vec<(&String, i64)>> =
                                std::collections::HashMap::new();
                            for (ref_id, sel_param, sel_val) in &refs_with_selector {
                                if let (Some(param), Some(val)) = (sel_param.as_ref(), sel_val) {
                                    by_selector.entry(param.as_str()).or_default().push((ref_id, *val));
                                }
                            }

                            // For each selector_param, check if there's an active condition
                            // If so, emit only the matching ref(s) directly without a choose block
                            for (selector_param, ref_vals) in by_selector {
                                // Check if this selector_param has an active condition
                                if let Some(active_vals) = active_conditions.get_active_values(selector_param) {
                                    // We're inside a when block for this selector - emit only matching refs
                                    // Group refs by selector value
                                    let mut value_to_ref: std::collections::HashMap<i64, &String> =
                                        std::collections::HashMap::new();
                                    for (ref_id, val) in &ref_vals {
                                        value_to_ref.entry(*val).or_insert(ref_id);
                                    }

                                    // Emit refs that match the active values
                                    for active_val in active_vals {
                                        if let Some(ref_id) = value_to_ref.get(active_val) {
                                            items.push(ParameterBlockItem::ComObjectRefRef(ComObjectRefRef {
                                                ref_id: (*ref_id).clone(),
                                                internal_description: None,
                                            }));
                                        }
                                    }
                                } else {
                                    // No active condition - create a choose/when block as before
                                    // Get unique ref index for this choose block
                                    let ref_index = selector_counters.next_index(selector_param);
                                    let selector_ref_id = param_ref_map
                                        .get(selector_param, Some(ref_index))
                                        .cloned()
                                        .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, selector_param));

                                    // Group refs by selector value - each value gets ONE when clause
                                    // with ONE ComObjectRefRef (use the first one for that value)
                                    let mut value_to_ref: std::collections::HashMap<i64, &String> =
                                        std::collections::HashMap::new();
                                    for (ref_id, val) in &ref_vals {
                                        // Only keep the first ref for each selector value
                                        value_to_ref.entry(*val).or_insert(ref_id);
                                    }

                                    // Build when clauses - one per unique selector value
                                    let mut whens: Vec<When> = value_to_ref.iter()
                                        .map(|(val, ref_id)| When {
                                            default: None,
                                            test: Some(val.to_string()),
                                            internal_description: None,
                                            items: vec![WhenItem::ComObjectRefRef(ComObjectRefRef {
                                                ref_id: (*ref_id).clone(),
                                                internal_description: None,
                                            })],
                                        })
                                        .collect();

                                    // Sort by selector value for consistent output
                                    whens.sort_by(|a, b| {
                                        let a_val: i64 = a.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                                        let b_val: i64 = b.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                                        a_val.cmp(&b_val)
                                    });

                                    items.push(ParameterBlockItem::Choose(Choose {
                                        param_ref_id: selector_ref_id,
                                        whens,
                                    }));
                                }
                            }
                        }
                    }
                }
                PageItem::Separator(text) => {
                    let sep_id = *sep_counter;
                    *sep_counter += 1;
                    items.push(ParameterBlockItem::ParameterSeparator(ParameterSeparator {
                        id: format!("{}_PS-{}", app_id, sep_id),
                        text: text.map(|t| t.to_string()),
                    }));
                }
                PageItem::When(cond_item) => {
                    let choose = Self::build_item_choose(
                        cond_item,
                        config,
                        app_id,
                        mask_family,
                        param_ref_map,
                        comm_obj_ref_map,
                        sep_counter,
                        selector_counters,
                        active_conditions,
                    )?;
                    items.push(ParameterBlockItem::Choose(choose));
                }
                PageItem::UnionSelector(union_name) => {
                    // UnionSelector emits:
                    // 1. The selector parameter reference
                    // 2. A choose/when block for each variant's parameters

                    // Get the selector param name
                    let selector_name = format!("{}_selector", union_name);

                    // Emit selector parameter ref
                    if let Some(ref_id) = param_ref_map.get_primary(&selector_name) {
                        items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                            ref_id: ref_id.clone(),
                            text: None,
                            internal_description: None,
                        }));
                    }

                    // Find the union field info to get variant info
                    if let Some(union_fields) = config.union_fields {
                        if let Some(union_info) = union_fields.iter().find(|u| u.field_name == *union_name) {
                            // Get selector ref ID for the choose
                            let selector_ref_id = param_ref_map
                                .get_primary(&selector_name)
                                .cloned()
                                .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, &selector_name));

                            // Build when clauses for each variant
                            let mut whens: Vec<When> = Vec::new();
                            for variant in union_info.selector_variants {
                                // For each variant, find all the variant parameters
                                // Variant params are named like: union_name_VariantName_field
                                let variant_prefix = format!("{}_{}_", union_name, variant.text);

                                // Collect param refs for this variant
                                let variant_param_refs: Vec<_> = param_ref_map
                                    .primary
                                    .iter()
                                    .filter(|(name, _)| name.starts_with(&variant_prefix))
                                    .map(|(_, ref_id)| WhenItem::ParameterRefRef(ParameterRefRef {
                                        ref_id: ref_id.clone(),
                                        text: None,
                                        internal_description: None,
                                    }))
                                    .collect();

                                // Only add when clause if there are params for this variant
                                if !variant_param_refs.is_empty() {
                                    whens.push(When {
                                        default: None,
                                        test: Some(variant.value.to_string()),
                                        internal_description: None,
                                        items: variant_param_refs,
                                    });
                                }
                            }

                            // Sort by selector value for consistent output
                            whens.sort_by(|a, b| {
                                let a_val: i64 = a.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                                let b_val: i64 = b.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                                a_val.cmp(&b_val)
                            });

                            // Only add choose if we have when clauses
                            if !whens.is_empty() {
                                items.push(ParameterBlockItem::Choose(Choose {
                                    param_ref_id: selector_ref_id,
                                    whens,
                                }));
                            }
                        }
                    }
                }
                PageItem::ObjWithValue { obj_name, selector_param, value_union, extra_params, sub_selectors } => {
                    // ObjWithValue combines object ref, optional extra params, and value param in same when blocks
                    // This matches MDT's structure where each when contains:
                    // - ComObjectRefRef
                    // - Extra param refs (optional, e.g., P-27, P-15, etc.)
                    // - Value param ref (UP-xxx)
                    //
                    // For variants with sub_selectors, the structure is different:
                    // - Extra param refs
                    // - Sub-selector param ref
                    // - Nested choose on sub-selector with:
                    //   - ComObjectRefRef (from ref_name)
                    //   - Value param ref (from variant_name)

                    // Get unique selector ref ID for this choose block
                    let ref_index = selector_counters.next_index(selector_param);
                    let selector_ref_id = param_ref_map
                        .get(*selector_param, Some(ref_index))
                        .cloned()
                        .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, selector_param));

                    // Get object refs grouped by selector value
                    let obj_refs = comm_obj_ref_map.get(*obj_name);

                    // Get union field info for value params
                    let union_info = config.union_fields.and_then(|fields| {
                        fields.iter().find(|u| u.field_name == *value_union)
                    });

                    // Build a map of variant_value -> sub_selector info for quick lookup
                    let sub_selector_map: std::collections::HashMap<i64, _> = sub_selectors.iter()
                        .map(|(val, param, variants)| (*val, (*param, *variants)))
                        .collect();

                    if let (Some(refs), Some(union_info)) = (obj_refs, union_info) {
                        // Group object refs by selector value
                        let mut obj_by_value: std::collections::HashMap<i64, &String> =
                            std::collections::HashMap::new();
                        for (ref_id, sel_param, sel_val) in refs {
                            if sel_param.as_ref().map(|s| s.as_str()) == Some(*selector_param) {
                                if let Some(val) = sel_val {
                                    obj_by_value.entry(*val).or_insert(ref_id);
                                }
                            }
                        }

                        // Build when clauses combining object ref, extra params, and value params
                        let mut whens: Vec<When> = Vec::new();

                        for variant in union_info.selector_variants {
                            let selector_value = variant.value;
                            let mut when_items: Vec<WhenItem> = Vec::new();

                            // Check if this variant has a sub-selector
                            if let Some((sub_selector_param, sub_variants)) = sub_selector_map.get(&selector_value) {
                                // Variant with sub-selector: extra params + sub-selector + nested choose

                                // Add extra param refs first
                                for extra_param in *extra_params {
                                    if let Some(ref_id) = param_ref_map.get_primary(*extra_param) {
                                        when_items.push(WhenItem::ParameterRefRef(ParameterRefRef {
                                            ref_id: ref_id.clone(),
                                            text: None,
                                            internal_description: None,
                                        }));
                                    }
                                }

                                // Add sub-selector param ref
                                if let Some(ref_id) = param_ref_map.get_primary(*sub_selector_param) {
                                    when_items.push(WhenItem::ParameterRefRef(ParameterRefRef {
                                        ref_id: ref_id.clone(),
                                        text: None,
                                        internal_description: None,
                                    }));
                                }

                                // Build nested choose on sub-selector
                                let sub_selector_ref_id = param_ref_map
                                    .get_primary(*sub_selector_param)
                                    .cloned()
                                    .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, sub_selector_param));

                                let mut nested_whens: Vec<When> = Vec::new();

                                for (sub_value, ref_name, variant_name) in *sub_variants {
                                    let mut nested_when_items: Vec<WhenItem> = Vec::new();

                                    // Look up object ref by ref_name
                                    if let Some(named_refs) = comm_obj_ref_map.get(*ref_name) {
                                        if let Some((ref_id, _, _)) = named_refs.first() {
                                            nested_when_items.push(WhenItem::ComObjectRefRef(ComObjectRefRef {
                                                ref_id: ref_id.clone(),
                                                internal_description: None,
                                            }));
                                        }
                                    }

                                    // Add value param refs for this sub-variant
                                    let variant_prefix = format!("{}_{}_", value_union, variant_name);
                                    for (param_name, ref_id) in param_ref_map.primary.iter() {
                                        if param_name.starts_with(&variant_prefix) {
                                            nested_when_items.push(WhenItem::ParameterRefRef(ParameterRefRef {
                                                ref_id: ref_id.clone(),
                                                text: None,
                                                internal_description: None,
                                            }));
                                        }
                                    }

                                    if !nested_when_items.is_empty() {
                                        nested_whens.push(When {
                                            default: None,
                                            test: Some(sub_value.to_string()),
                                            internal_description: None,
                                            items: nested_when_items,
                                        });
                                    }
                                }

                                if !nested_whens.is_empty() {
                                    when_items.push(WhenItem::Choose(Choose {
                                        param_ref_id: sub_selector_ref_id,
                                        whens: nested_whens,
                                    }));
                                }
                            } else {
                                // Standard variant: object ref + extra params + value param

                                // Add object ref for this selector value
                                if let Some(obj_ref_id) = obj_by_value.get(&selector_value) {
                                    when_items.push(WhenItem::ComObjectRefRef(ComObjectRefRef {
                                        ref_id: (*obj_ref_id).clone(),
                                        internal_description: None,
                                    }));
                                }

                                // Add extra param refs
                                for extra_param in *extra_params {
                                    if let Some(ref_id) = param_ref_map.get_primary(*extra_param) {
                                        when_items.push(WhenItem::ParameterRefRef(ParameterRefRef {
                                            ref_id: ref_id.clone(),
                                            text: None,
                                            internal_description: None,
                                        }));
                                    }
                                }

                                // Add value param refs for this variant
                                // We need the variant NAME (like "ForcibleControl"), not display text (like "Forcible control")
                                // Look it up from variant_params using the selector value
                                let variant_name = union_info.union_info.variant_params.iter()
                                    .find(|vp| vp.variant_value == selector_value)
                                    .map(|vp| vp.variant_name)
                                    .unwrap_or("");
                                let variant_prefix = format!("{}_{}_{}", value_union, variant_name, "");
                                for (param_name, ref_id) in param_ref_map.primary.iter() {
                                    if !variant_name.is_empty() && param_name.starts_with(&variant_prefix.trim_end_matches('_')) && param_name.len() > variant_prefix.len() - 1 {
                                        when_items.push(WhenItem::ParameterRefRef(ParameterRefRef {
                                            ref_id: ref_id.clone(),
                                            text: None,
                                            internal_description: None,
                                        }));
                                    }
                                }
                            }

                            // Only add when clause if there's content
                            if !when_items.is_empty() {
                                whens.push(When {
                                    default: None,
                                    test: Some(selector_value.to_string()),
                                    internal_description: None,
                                    items: when_items,
                                });
                            }
                        }

                        // Sort by selector value
                        whens.sort_by(|a, b| {
                            let a_val: i64 = a.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                            let b_val: i64 = b.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                            a_val.cmp(&b_val)
                        });

                        if !whens.is_empty() {
                            items.push(ParameterBlockItem::Choose(Choose {
                                param_ref_id: selector_ref_id,
                                whens,
                            }));
                        }
                    }
                }
                PageItem::GroupedObjChoose { selector_param, hidden_params, objects } => {
                    // GroupedObjChoose creates ONE choose block containing ALL specified objects.
                    // Each when clause contains all objects' ComObjectRefRefs and value params for that type variant.
                    // This matches MDT's pattern where a single choose on P-35 (object_type) contains
                    // multiple objects like button1_main, button1_status_toggle, etc.

                    // Get unique selector ref ID for this choose block
                    let ref_index = selector_counters.next_index(selector_param);
                    let selector_ref_id = param_ref_map
                        .get(*selector_param, Some(ref_index))
                        .cloned()
                        .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, selector_param));

                    // We need to find union info from one of the value_union fields
                    // All objects in the group should use the same selector (object_type param)
                    // so we can use any value_union to get the variant list
                    let union_info = if let Some((_, first_value_union)) = objects.first() {
                        config.union_fields.and_then(|fields| {
                            fields.iter().find(|u| u.field_name == *first_value_union)
                        })
                    } else {
                        None
                    };

                    if let Some(union_info) = union_info {
                        // Pre-collect object refs for all objects in the group
                        let mut all_obj_refs: Vec<(&str, &str, std::collections::HashMap<i64, &String>)> = Vec::new();

                        for (obj_name, value_union) in *objects {
                            let mut obj_by_value: std::collections::HashMap<i64, &String> =
                                std::collections::HashMap::new();

                            if let Some(refs) = comm_obj_ref_map.get(*obj_name) {
                                for (ref_id, sel_param, sel_val) in refs {
                                    if sel_param.as_ref().map(|s| s.as_str()) == Some(*selector_param) {
                                        if let Some(val) = sel_val {
                                            obj_by_value.entry(*val).or_insert(ref_id);
                                        }
                                    }
                                }
                            }
                            all_obj_refs.push((*obj_name, *value_union, obj_by_value));
                        }

                        // Build when clauses - one for each variant
                        let mut whens: Vec<When> = Vec::new();

                        for variant in union_info.selector_variants {
                            let selector_value = variant.value;
                            let mut when_items: Vec<WhenItem> = Vec::new();

                            // For each object in the group, add its ComObjectRefRef and value params
                            for (_obj_name, _value_union, obj_by_value) in &all_obj_refs {
                                // Add object ref for this selector value
                                if let Some(obj_ref_id) = obj_by_value.get(&selector_value) {
                                    when_items.push(WhenItem::ComObjectRefRef(ComObjectRefRef {
                                        ref_id: (*obj_ref_id).clone(),
                                        internal_description: None,
                                    }));
                                }

                                // Add hidden param refs (same for all objects in the group)
                                // Only add once per when clause, not per object
                                // We'll add these after all objects are processed
                            }

                            // Add hidden param refs (once per when clause)
                            for hidden_param in *hidden_params {
                                if let Some(ref_id) = param_ref_map.get_primary(*hidden_param) {
                                    when_items.push(WhenItem::ParameterRefRef(ParameterRefRef {
                                        ref_id: ref_id.clone(),
                                        text: None,
                                        internal_description: None,
                                    }));
                                }
                            }

                            // Add value param refs for each object's union
                            for (_obj_name, value_union, _) in &all_obj_refs {
                                let variant_prefix = format!("{}_{}_", value_union, variant.text);
                                for (param_name, ref_id) in param_ref_map.primary.iter() {
                                    if param_name.starts_with(&variant_prefix) {
                                        when_items.push(WhenItem::ParameterRefRef(ParameterRefRef {
                                            ref_id: ref_id.clone(),
                                            text: None,
                                            internal_description: None,
                                        }));
                                    }
                                }
                            }

                            // Only add when clause if there's content
                            if !when_items.is_empty() {
                                whens.push(When {
                                    default: None,
                                    test: Some(selector_value.to_string()),
                                    internal_description: None,
                                    items: when_items,
                                });
                            }
                        }

                        // Sort by selector value
                        whens.sort_by(|a, b| {
                            let a_val: i64 = a.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                            let b_val: i64 = b.test.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                            a_val.cmp(&b_val)
                        });

                        if !whens.is_empty() {
                            items.push(ParameterBlockItem::Choose(Choose {
                                param_ref_id: selector_ref_id,
                                whens,
                            }));
                        }
                    }
                }
                PageItem::ObjDirect { obj_name, params } => {
                    // ObjDirect outputs object and params directly without a choose block
                    // Used in switch mode where object type is fixed to 1Bit Switch

                    // Get object refs for this object - use the unconditional ref or first ref
                    if let Some(refs) = comm_obj_ref_map.get(*obj_name) {
                        // Prefer the unconditional ref (no selector), otherwise use first available
                        let ref_to_use = refs.iter()
                            .find(|(_, sel_param, _)| sel_param.is_none())
                            .or_else(|| refs.first());

                        if let Some((ref_id, _, _)) = ref_to_use {
                            items.push(ParameterBlockItem::ComObjectRefRef(ComObjectRefRef {
                                ref_id: ref_id.clone(),
                                internal_description: None,
                            }));
                        }
                    }

                    // Add param refs directly
                    for param_name in *params {
                        if let Some(ref_id) = param_ref_map.get_primary(*param_name) {
                            items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                                ref_id: ref_id.clone(),
                                text: None,
                                internal_description: None,
                            }));
                        }
                    }
                }
                PageItem::ObjsDirectWithParams { obj_names, params } => {
                    // ObjsDirectWithParams outputs multiple objects followed by params directly
                    // Used in toggle mode where O-0 and O-1 appear together

                    // Add each object ref
                    for obj_name in *obj_names {
                        if let Some(refs) = comm_obj_ref_map.get(*obj_name) {
                            // Prefer the unconditional ref (no selector), otherwise use first available
                            let ref_to_use = refs.iter()
                                .find(|(_, sel_param, _)| sel_param.is_none())
                                .or_else(|| refs.first());

                            if let Some((ref_id, _, _)) = ref_to_use {
                                items.push(ParameterBlockItem::ComObjectRefRef(ComObjectRefRef {
                                    ref_id: ref_id.clone(),
                                    internal_description: None,
                                }));
                            }
                        }
                    }

                    // Add param refs directly
                    for param_name in *params {
                        if let Some(ref_id) = param_ref_map.get_primary(*param_name) {
                            items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                                ref_id: ref_id.clone(),
                                text: None,
                                internal_description: None,
                            }));
                        }
                    }
                }
                PageItem::ObjsByRefName { ref_names, params } => {
                    // ObjsByRefName outputs objects by looking up specific ref_names
                    // Used when objects have named refs for different modes (e.g., dimming, blinds)

                    // Add each object ref by its ref_name
                    for ref_name in *ref_names {
                        if let Some(refs) = comm_obj_ref_map.get(*ref_name) {
                            // Get the first ref with this name (should be unique)
                            if let Some((ref_id, _, _)) = refs.first() {
                                items.push(ParameterBlockItem::ComObjectRefRef(ComObjectRefRef {
                                    ref_id: ref_id.clone(),
                                    internal_description: None,
                                }));
                            }
                        }
                    }

                    // Add param refs directly
                    for param_name in *params {
                        if let Some(ref_id) = param_ref_map.get_primary(*param_name) {
                            items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                                ref_id: ref_id.clone(),
                                text: None,
                                internal_description: None,
                            }));
                        }
                    }
                }
                PageItem::ObjWithFixedVariant { obj_name, hidden_params, union_field, variant_name, selector_value, text_override } => {
                    // ObjWithFixedVariant outputs object + hidden params + specific union variant
                    // Used in switch mode where object type is fixed (always Switch/1Bit)
                    // No choose block - outputs directly
                    // selector_value specifies which object ref to use (matching the selector's value)

                    // Get object ref matching the specified selector_value
                    if let Some(refs) = comm_obj_ref_map.get(*obj_name) {
                        let ref_to_use = refs.iter()
                            .find(|(_, _, sel_val)| sel_val.as_ref() == Some(selector_value))
                            .or_else(|| refs.first());

                        if let Some((ref_id, _, _)) = ref_to_use {
                            items.push(ParameterBlockItem::ComObjectRefRef(ComObjectRefRef {
                                ref_id: ref_id.clone(),
                                internal_description: None,
                            }));
                        }
                    }

                    // Add hidden param refs
                    for param_name in *hidden_params {
                        if let Some(ref_id) = param_ref_map.get_primary(*param_name) {
                            items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                                ref_id: ref_id.clone(),
                                text: None,
                                internal_description: None,
                            }));
                        }
                    }

                    // Add the specific union variant param
                    // Variant params are named like: union_field_VariantName_field
                    // Use get_by_text to find the ref with the matching text override (Text is on ParameterRef)
                    let variant_prefix = format!("{}_{}_", union_field, variant_name);
                    for (param_name, _) in param_ref_map.primary.iter() {
                        if param_name.starts_with(&variant_prefix) {
                            // Look up ref by text - the ParameterRef already has the Text attribute
                            let ref_id = param_ref_map.get_by_text(param_name, *text_override)
                                .or_else(|| param_ref_map.get_primary(param_name));
                            if let Some(ref_id) = ref_id {
                                items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                                    ref_id: ref_id.clone(),
                                    text: None, // Text is on ParameterRef, not ParameterRefRef
                                    internal_description: None,
                                }));
                            }
                        }
                    }
                }
                PageItem::UnionVariantDirect { union_field, variant_name, text_override } => {
                    // UnionVariantDirect outputs specific variant's params directly (no choose block)
                    // Used when variant is already determined by outer context (e.g., inside switch mode)
                    // This matches MDT's pattern where UP-xxx params appear directly without choose

                    // Add the specific union variant param(s)
                    // Variant params are named like: union_field_VariantName_field
                    // Use get_by_text to find the ref with the matching text override
                    let variant_prefix = format!("{}_{}_", union_field, variant_name);
                    for (param_name, _) in param_ref_map.primary.iter() {
                        if param_name.starts_with(&variant_prefix) {
                            // Look up ref by text - the ParameterRef already has the Text attribute
                            let ref_id = param_ref_map.get_by_text(param_name, *text_override)
                                .or_else(|| param_ref_map.get_primary(param_name));
                            if let Some(ref_id) = ref_id {
                                items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                                    ref_id: ref_id.clone(),
                                    text: None, // Text is on ParameterRef, not ParameterRefRef
                                    internal_description: None,
                                }));
                            }
                        }
                    }
                }
                PageItem::UnionVariantWithChoose { union_field, variant_name, text_override, cases } => {
                    // UnionVariantWithChoose outputs the union variant param FIRST,
                    // then creates a choose block that references that same param.
                    // This matches MDT's pattern:
                    //   <ParameterRefRef RefId="...UP-143_R-172" />
                    //   <choose ParamRefId="...UP-143_R-172">
                    //     <when test="2">...</when>
                    //   </choose>

                    // First, find and output the union variant param ref
                    // Use get_by_text to find the ref with the matching text override
                    let variant_prefix = format!("{}_{}_", union_field, variant_name);
                    let mut param_ref_id: Option<String> = None;
                    for (param_name, _) in param_ref_map.primary.iter() {
                        if param_name.starts_with(&variant_prefix) {
                            // Look up ref by text - the ParameterRef already has the Text attribute
                            let ref_id = param_ref_map.get_by_text(param_name, *text_override)
                                .or_else(|| param_ref_map.get_primary(param_name));
                            if let Some(ref_id) = ref_id {
                                items.push(ParameterBlockItem::ParameterRefRef(ParameterRefRef {
                                    ref_id: ref_id.clone(),
                                    text: None, // Text is on ParameterRef, not ParameterRefRef
                                    internal_description: None,
                                }));
                                param_ref_id = Some(ref_id.clone());
                            }
                            break; // Only output one param for the union variant
                        }
                    }

                    // Now create the choose block referencing that same param
                    if let Some(ref_id) = param_ref_id {
                        let mut whens = Vec::new();
                        for case in cases {
                            // Recursively build the items for this case
                            let case_block_items = Self::build_block_items(
                                &case.items,
                                config,
                                app_id,
                                mask_family,
                                param_ref_map,
                                comm_obj_ref_map,
                                sep_counter,
                                selector_counters,
                                active_conditions,
                            )?;
                            // Convert ParameterBlockItem to WhenItem
                            let when_items: Vec<WhenItem> = case_block_items.into_iter().filter_map(|item| {
                                match item {
                                    ParameterBlockItem::ParameterRefRef(r) => Some(WhenItem::ParameterRefRef(r)),
                                    ParameterBlockItem::ComObjectRefRef(r) => Some(WhenItem::ComObjectRefRef(r)),
                                    ParameterBlockItem::ParameterSeparator(s) => Some(WhenItem::ParameterSeparator(s)),
                                    ParameterBlockItem::Choose(c) => Some(WhenItem::Choose(c)),
                                    ParameterBlockItem::Module(m) => Some(WhenItem::Module(m)),
                                    ParameterBlockItem::Button(_) => None, // Buttons not in WhenItem
                                    ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => None, // Table layout elements not in WhenItem
                                }
                            }).collect();
                            whens.push(When {
                                test: case.condition.to_test_string(),
                                default: if case.condition.is_default() { Some(true) } else { None },
                                internal_description: None,
                                items: when_items,
                            });
                        }
                        if !whens.is_empty() {
                            items.push(ParameterBlockItem::Choose(Choose {
                                param_ref_id: ref_id,
                                whens,
                            }));
                        }
                    }
                }
                PageItem::ChooseOnUnionVariant { union_field, variant_name, cases } => {
                    // ChooseOnUnionVariant creates ONLY a choose block referencing an already-output
                    // union variant parameter. Use this after union_variant to create additional
                    // choose blocks that reference the same param without re-outputting it.
                    // This matches MDT's pattern where UP-xxx is output once, then referenced
                    // by multiple choose blocks in nested contexts.

                    // Find the union variant param ref (should have been output earlier)
                    let variant_prefix = format!("{}_{}_", union_field, variant_name);
                    let mut param_ref_id: Option<String> = None;
                    for (param_name, ref_id) in param_ref_map.primary.iter() {
                        if param_name.starts_with(&variant_prefix) {
                            param_ref_id = Some(ref_id.clone());
                            break;
                        }
                    }

                    // Create the choose block (without outputting the param ref)
                    if let Some(ref_id) = param_ref_id {
                        let mut whens = Vec::new();
                        for case in cases {
                            // Recursively build the items for this case
                            let case_block_items = Self::build_block_items(
                                &case.items,
                                config,
                                app_id,
                                mask_family,
                                param_ref_map,
                                comm_obj_ref_map,
                                sep_counter,
                                selector_counters,
                                active_conditions,
                            )?;
                            // Convert ParameterBlockItem to WhenItem
                            let when_items: Vec<WhenItem> = case_block_items.into_iter().filter_map(|item| {
                                match item {
                                    ParameterBlockItem::ParameterRefRef(r) => Some(WhenItem::ParameterRefRef(r)),
                                    ParameterBlockItem::ComObjectRefRef(r) => Some(WhenItem::ComObjectRefRef(r)),
                                    ParameterBlockItem::ParameterSeparator(s) => Some(WhenItem::ParameterSeparator(s)),
                                    ParameterBlockItem::Choose(c) => Some(WhenItem::Choose(c)),
                                    ParameterBlockItem::Module(m) => Some(WhenItem::Module(m)),
                                    ParameterBlockItem::Button(_) => None, // Buttons not in WhenItem
                                    ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => None, // Table layout elements not in WhenItem
                                }
                            }).collect();
                            whens.push(When {
                                test: case.condition.to_test_string(),
                                default: if case.condition.is_default() { Some(true) } else { None },
                                internal_description: None,
                                items: when_items,
                            });
                        }
                        if !whens.is_empty() {
                            items.push(ParameterBlockItem::Choose(Choose {
                                param_ref_id: ref_id,
                                whens,
                            }));
                        }
                    }
                }
                PageItem::Module { module_name, instance_index } => {
                    // Module instances are generated as Module XML elements.
                    // They need the module collection to look up the definition and instance data.
                    if let Some(modules) = config.modules.as_ref() {
                        // Find the module definition by name
                        let def = modules.definitions().iter().enumerate().find(|(_, d)| d.name == *module_name);
                        if let Some((def_idx, def)) = def {
                            // Find the specific instance
                            let instances_for_def: Vec<_> = modules.raw_instances()
                                .iter()
                                .enumerate()
                                .filter(|(_, inst)| inst.def_index == def_idx)
                                .collect();

                            if let Some((global_idx, instance)) = instances_for_def.get(*instance_index) {
                                // Build the Module schema element
                                let module_def_id = format!("{}_MD-{}", app_id, def_idx + 1);
                                let module_instance_id = format!("{}_M-{}", module_def_id, global_idx + 1);

                                let mut args = Vec::new();
                                for (arg_idx, (_arg_def, arg_val)) in def.arguments.iter().zip(instance.args.iter()).enumerate() {
                                    let arg_ref_id = format!("{}_A-{}", module_def_id, arg_idx + 1);
                                    match arg_val {
                                        crate::module::ModuleArgValue::Numeric(v) => {
                                            args.push(ModuleArg::NumericArg {
                                                ref_id: arg_ref_id,
                                                value: *v,
                                            });
                                        }
                                        crate::module::ModuleArgValue::Text(v) => {
                                            args.push(ModuleArg::TextArg {
                                                ref_id: arg_ref_id,
                                                id: format!("{}_TA-{}", module_instance_id, arg_idx + 1),
                                                value: v.clone(),
                                            });
                                        }
                                    }
                                }

                                items.push(ParameterBlockItem::Module(Module {
                                    id: module_instance_id,
                                    ref_id: module_def_id,
                                    name: None,
                                    internal_description: None,
                                    args,
                                }));
                            }
                        }
                    }
                }
                PageItem::ModuleInline { module_name, args: inline_args } => {
                    // Module instances with inline arguments - create instance on the fly.
                    // This allows defining module instances directly in the page layout.
                    if let Some(modules) = config.modules.as_ref() {
                        // Find the module definition by name
                        let def = modules.definitions().iter().enumerate().find(|(_, d)| d.name == *module_name);
                        if let Some((def_idx, def)) = def {
                            // Count how many inline instances we've seen for this module
                            // to generate unique instance IDs
                            // We use a simple approach: hash the inline args to create a unique suffix
                            let args_hash: i64 = inline_args.iter()
                                .map(|(name, val)| name.len() as i64 * 31 + val)
                                .sum();
                            let instance_suffix = (args_hash.abs() % 10000) + 1;

                            let module_def_id = format!("{}_MD-{}", app_id, def_idx + 1);
                            let module_instance_id = format!("{}_M-{}", module_def_id, instance_suffix);

                            // Build argument values from inline args, matching by name
                            let mut schema_args = Vec::new();
                            for (arg_idx, arg_def) in def.arguments.iter().enumerate() {
                                let arg_ref_id = format!("{}_A-{}", module_def_id, arg_idx + 1);
                                // Find the inline arg value by name
                                if let Some((_, value)) = inline_args.iter().find(|(name, _)| *name == arg_def.name) {
                                    schema_args.push(ModuleArg::NumericArg {
                                        ref_id: arg_ref_id,
                                        value: *value,
                                    });
                                } else {
                                    // Argument not found in inline args - use 0 as default
                                    schema_args.push(ModuleArg::NumericArg {
                                        ref_id: arg_ref_id,
                                        value: 0,
                                    });
                                }
                            }

                            items.push(ParameterBlockItem::Module(Module {
                                id: module_instance_id,
                                ref_id: module_def_id,
                                name: None,
                                internal_description: None,
                                args: schema_args,
                            }));
                        }
                    }
                }
                PageItem::ModuleInstances { module_name, instances } => {
                    // Multiple module instances with visibility conditions.
                    // Generates a choose/when block for each instance.
                    if let Some(modules) = config.modules.as_ref() {
                        // Find the module definition by name
                        let def = modules.definitions().iter().enumerate().find(|(_, d)| d.name == *module_name);
                        if let Some((def_idx, def)) = def {
                            let module_def_id = format!("{}_MD-{}", app_id, def_idx + 1);

                            for (idx, (selector, inline_args)) in instances.iter().enumerate() {
                                // Get the param ref for the selector
                                if let Some(selector_ref_id) = param_ref_map.get_primary(selector) {
                                    // Create module instance
                                    let instance_suffix = idx + 1;
                                    let module_instance_id = format!("{}_M-{}", module_def_id, instance_suffix);

                                    // Build argument values from inline args
                                    let mut schema_args = Vec::new();
                                    for (arg_idx, arg_def) in def.arguments.iter().enumerate() {
                                        let arg_ref_id = format!("{}_A-{}", module_def_id, arg_idx + 1);
                                        if let Some((_, value)) = inline_args.iter().find(|(name, _)| *name == arg_def.name) {
                                            schema_args.push(ModuleArg::NumericArg {
                                                ref_id: arg_ref_id,
                                                value: *value,
                                            });
                                        } else {
                                            schema_args.push(ModuleArg::NumericArg {
                                                ref_id: arg_ref_id,
                                                value: 0,
                                            });
                                        }
                                    }

                                    // Create a choose/when wrapper for visibility
                                    let module_item = WhenItem::Module(Module {
                                        id: module_instance_id,
                                        ref_id: module_def_id.clone(),
                                        name: None,
                                        internal_description: None,
                                        args: schema_args,
                                    });

                                    // Wrap in choose/when for conditional visibility
                                    items.push(ParameterBlockItem::Choose(Choose {
                                        param_ref_id: selector_ref_id.clone(),
                                        whens: vec![When {
                                            test: Some("1".to_string()),
                                            default: None,
                                            internal_description: None,
                                            items: vec![module_item],
                                        }],
                                    }));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(items)
    }

    /// Build a Choose element for block-level conditionals (wrapping ParameterBlocks).
    fn build_element_choose(
        cond: &ConditionalElement,
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_map: &MultiParamRefMap,
        comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
        block_counter: &mut u32,
        sep_counter: &mut u32,
        selector_counters: &mut SelectorRefCounters,
        active_conditions: &ActiveConditions,
    ) -> Result<Choose, GeneratorError> {
        let selector_ref_id = param_ref_map
            .get_primary(cond.selector)
            .cloned()
            .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, cond.selector));

        let mut whens = Vec::new();
        for case in &cond.cases {
            // Create new active conditions with this case's selector and values
            let case_active_conditions = active_conditions
                .with_condition(cond.selector, case.condition.to_values());

            let mut when_items: Vec<WhenItem> = Vec::new();
            for elem in &case.elements {
                match elem {
                    PageElement::Block(block) => {
                        if let Ok(pb) = Self::build_parameter_block(
                            block,
                            config,
                            app_id,
                            mask_family,
                            param_ref_map,
                            comm_obj_ref_map,
                            block_counter,
                            sep_counter,
                            selector_counters,
                            &case_active_conditions,
                        ) {
                            when_items.push(WhenItem::ParameterBlock(pb));
                        }
                    }
                    PageElement::When(nested_cond) => {
                        if let Ok(choose) = Self::build_element_choose(
                            nested_cond,
                            config,
                            app_id,
                            mask_family,
                            param_ref_map,
                            comm_obj_ref_map,
                            block_counter,
                            sep_counter,
                            selector_counters,
                            &case_active_conditions,
                        ) {
                            when_items.push(WhenItem::Choose(choose));
                        }
                    }
                }
            }

            whens.push(When {
                test: case.condition.to_test_string(),
                default: if case.condition.is_default() { Some(true) } else { None },
                internal_description: None,
                items: when_items,
            });
        }

        Ok(Choose {
            param_ref_id: selector_ref_id,
            whens,
        })
    }

    /// Build a Choose element for item-level conditionals (within a ParameterBlock).
    fn build_item_choose(
        cond: &ConditionalItem,
        config: &ApplicationProgramConfig,
        app_id: &str,
        mask_family: MaskFamily,
        param_ref_map: &MultiParamRefMap,
        comm_obj_ref_map: &HashMap<String, Vec<(String, Option<String>, Option<i64>)>>,
        sep_counter: &mut u32,
        selector_counters: &mut SelectorRefCounters,
        active_conditions: &ActiveConditions,
    ) -> Result<Choose, GeneratorError> {
        let selector_ref_id = param_ref_map
            .get_primary(cond.selector)
            .cloned()
            .unwrap_or_else(|| Self::find_param_ref_id(config, app_id, cond.selector));

        let mut whens = Vec::new();
        for case in &cond.cases {
            // Create new active conditions with this case's selector and values
            let case_active_conditions = active_conditions
                .with_condition(cond.selector, case.condition.to_values());
            let items = Self::build_block_items(
                &case.items,
                config,
                app_id,
                mask_family,
                param_ref_map,
                comm_obj_ref_map,
                sep_counter,
                selector_counters,
                &case_active_conditions,
            )?;

            // Convert ParameterBlockItem to WhenItem (filter out Buttons/Rows/Columns which aren't in WhenItem)
            let when_items: Vec<WhenItem> = items
                .into_iter()
                .filter_map(|item| match item {
                    ParameterBlockItem::ParameterRefRef(prr) => Some(WhenItem::ParameterRefRef(prr)),
                    ParameterBlockItem::ComObjectRefRef(corr) => Some(WhenItem::ComObjectRefRef(corr)),
                    ParameterBlockItem::ParameterSeparator(ps) => Some(WhenItem::ParameterSeparator(ps)),
                    ParameterBlockItem::Choose(c) => Some(WhenItem::Choose(c)),
                    ParameterBlockItem::Module(m) => Some(WhenItem::Module(m)),
                    ParameterBlockItem::Button(_) => None,
                    ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => None,
                })
                .collect();

            whens.push(When {
                test: case.condition.to_test_string(),
                default: if case.condition.is_default() { Some(true) } else { None },
                internal_description: None,
                items: when_items,
            });
        }

        Ok(Choose {
            param_ref_id: selector_ref_id,
            whens,
        })
    }

    /// Serialize the KNX document to XML string.
    fn serialize(knx: &Knx) -> Result<String, GeneratorError> {
        let mut buffer = String::new();
        buffer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        let mut serializer = quick_xml::se::Serializer::new(&mut buffer);
        serializer.indent(' ', 2);

        serde::Serialize::serialize(knx, serializer)
            .map_err(|e| GeneratorError::Serialization(e.to_string()))?;

        Ok(buffer)
    }

    /// Validate all references in the generated document.
    ///
    /// This checks that:
    /// 1. All ParameterRefRef RefIds have matching ParameterRef Ids
    /// 2. All ComObjectRefRef RefIds have matching ComObjectRef Ids
    /// 3. All Choose ParamRefId values have matching ParameterRef Ids
    /// 4. All Parameter ParameterType references have matching ParameterType Ids
    pub fn validate(knx: &Knx) -> Result<(), GeneratorError> {
        let app = &knx.manufacturer_data.manufacturer.application_programs.programs[0];

        // Collect all defined IDs
        let param_ref_ids: std::collections::HashSet<&str> = app
            .static_section
            .parameter_refs
            .as_ref()
            .map(|refs| refs.refs.iter().map(|r| r.id.as_str()).collect())
            .unwrap_or_default();

        let com_obj_ref_ids: std::collections::HashSet<&str> = app
            .static_section
            .com_object_refs
            .as_ref()
            .map(|refs| refs.refs.iter().map(|r| r.id.as_str()).collect())
            .unwrap_or_default();

        let param_type_ids: std::collections::HashSet<&str> = app
            .static_section
            .parameter_types
            .as_ref()
            .map(|types| types.types.iter().map(|t| t.id.as_str()).collect())
            .unwrap_or_default();

        // Check Parameter -> ParameterType references
        if let Some(params) = &app.static_section.parameters {
            for item in &params.items {
                if let ParameterItem::Parameter(param) = item {
                    if !param_type_ids.contains(param.parameter_type.as_str()) {
                        return Err(GeneratorError::MissingReference {
                            ref_type: "ParameterType".to_string(),
                            ref_id: param.parameter_type.clone(),
                            context: format!("Parameter '{}'", param.name),
                        });
                    }
                }
            }
        }

        // Check references in Dynamic section
        if let Some(dynamic) = &app.dynamic {
            // Check ChannelIndependentBlock
            if let Some(cib) = &dynamic.channel_independent_block {
                Self::validate_channel_independent_items(&cib.items, &param_ref_ids, &com_obj_ref_ids)?;
            }

            // Check Channels
            for channel in &dynamic.channels {
                Self::validate_channel_items(&channel.items, &param_ref_ids, &com_obj_ref_ids)?;
            }
        }

        Ok(())
    }

    fn validate_channel_independent_items(
        items: &[ChannelIndependentItem],
        param_ref_ids: &std::collections::HashSet<&str>,
        com_obj_ref_ids: &std::collections::HashSet<&str>,
    ) -> Result<(), GeneratorError> {
        for item in items {
            match item {
                ChannelIndependentItem::ParameterBlock(pb) => {
                    Self::validate_parameter_block_items(&pb.items, param_ref_ids, com_obj_ref_ids)?;
                }
                ChannelIndependentItem::Choose(choose) => {
                    Self::validate_choose(choose, param_ref_ids, com_obj_ref_ids)?;
                }
            }
        }
        Ok(())
    }

    fn validate_channel_items(
        items: &[ChannelItem],
        param_ref_ids: &std::collections::HashSet<&str>,
        com_obj_ref_ids: &std::collections::HashSet<&str>,
    ) -> Result<(), GeneratorError> {
        for item in items {
            match item {
                ChannelItem::ParameterBlock(pb) => {
                    Self::validate_parameter_block_items(&pb.items, param_ref_ids, com_obj_ref_ids)?;
                }
                ChannelItem::Choose(choose) => {
                    Self::validate_choose(choose, param_ref_ids, com_obj_ref_ids)?;
                }
                ChannelItem::Module(_) => {
                    // Module instances are validated separately - skip for now
                }
            }
        }
        Ok(())
    }

    fn validate_parameter_block_items(
        items: &[ParameterBlockItem],
        param_ref_ids: &std::collections::HashSet<&str>,
        com_obj_ref_ids: &std::collections::HashSet<&str>,
    ) -> Result<(), GeneratorError> {
        for item in items {
            match item {
                ParameterBlockItem::ParameterRefRef(prr) => {
                    if !param_ref_ids.contains(prr.ref_id.as_str()) {
                        return Err(GeneratorError::MissingReference {
                            ref_type: "ParameterRef".to_string(),
                            ref_id: prr.ref_id.clone(),
                            context: "ParameterRefRef in ParameterBlock".to_string(),
                        });
                    }
                }
                ParameterBlockItem::ComObjectRefRef(corr) => {
                    if !com_obj_ref_ids.contains(corr.ref_id.as_str()) {
                        return Err(GeneratorError::MissingReference {
                            ref_type: "ComObjectRef".to_string(),
                            ref_id: corr.ref_id.clone(),
                            context: "ComObjectRefRef in ParameterBlock".to_string(),
                        });
                    }
                }
                ParameterBlockItem::Choose(choose) => {
                    Self::validate_choose(choose, param_ref_ids, com_obj_ref_ids)?;
                }
                ParameterBlockItem::ParameterSeparator(_) => {}
                ParameterBlockItem::Module(_) => {
                    // Module instances are validated separately - skip for now
                }
                ParameterBlockItem::Button(_) => {
                    // Buttons are UI elements, no validation needed
                }
                ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => {
                    // Table layout elements, no validation needed
                }
            }
        }
        Ok(())
    }

    fn validate_choose(
        choose: &Choose,
        param_ref_ids: &std::collections::HashSet<&str>,
        com_obj_ref_ids: &std::collections::HashSet<&str>,
    ) -> Result<(), GeneratorError> {
        // Validate the Choose's ParamRefId
        if !param_ref_ids.contains(choose.param_ref_id.as_str()) {
            return Err(GeneratorError::MissingReference {
                ref_type: "ParameterRef".to_string(),
                ref_id: choose.param_ref_id.clone(),
                context: "Choose ParamRefId".to_string(),
            });
        }

        // Validate items in each when clause
        for when in &choose.whens {
            Self::validate_when_items(&when.items, param_ref_ids, com_obj_ref_ids)?;
        }

        Ok(())
    }

    fn validate_when_items(
        items: &[WhenItem],
        param_ref_ids: &std::collections::HashSet<&str>,
        com_obj_ref_ids: &std::collections::HashSet<&str>,
    ) -> Result<(), GeneratorError> {
        for item in items {
            match item {
                WhenItem::ParameterRefRef(prr) => {
                    if !param_ref_ids.contains(prr.ref_id.as_str()) {
                        return Err(GeneratorError::MissingReference {
                            ref_type: "ParameterRef".to_string(),
                            ref_id: prr.ref_id.clone(),
                            context: "ParameterRefRef in When".to_string(),
                        });
                    }
                }
                WhenItem::ComObjectRefRef(corr) => {
                    if !com_obj_ref_ids.contains(corr.ref_id.as_str()) {
                        return Err(GeneratorError::MissingReference {
                            ref_type: "ComObjectRef".to_string(),
                            ref_id: corr.ref_id.clone(),
                            context: "ComObjectRefRef in When".to_string(),
                        });
                    }
                }
                WhenItem::Choose(nested_choose) => {
                    Self::validate_choose(nested_choose, param_ref_ids, com_obj_ref_ids)?;
                }
                WhenItem::ParameterBlock(pb) => {
                    Self::validate_parameter_block_items(&pb.items, param_ref_ids, com_obj_ref_ids)?;
                }
                WhenItem::ParameterSeparator(_) => {}
                WhenItem::Assign(_) => {
                    // Assign elements copy parameter values; validation would check refs exist
                }
                WhenItem::Module(_) => {
                    // Module instances are validated separately - skip for now
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// Hardware MTXML Generator
// ============================================================================

/// Generator for creating Hardware MTXML files.
pub struct HardwareGenerator;

impl HardwareGenerator {
    /// Generate a complete Hardware MTXML document from the configuration.
    pub fn generate(config: &ApplicationProgramConfig) -> Result<String, GeneratorError> {
        let knx = Self::build_hardware_knx(config);
        Self::serialize(&knx)
    }

    /// Build the complete Hardware KNX document structure.
    fn build_hardware_knx(config: &ApplicationProgramConfig) -> HardwareKnx {
        let manufacturer_id = format!("M-{:04X}", config.device.manufacturer_id);
        let serial_hex = config
            .serial_number
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();

        // Hardware ID: M-XXXX_H-<serial>-<version>
        let hardware_id = format!("{}_H-{}-{}", manufacturer_id, serial_hex, config.hardware_version);

        // Application hash suffix (defaults to 0000)
        let app_hash = config.application_hash.unwrap_or("0000");

        // Application ID for reference - must match ApplicationProgram ID
        let app_id = format!(
            "{}_A-{:04X}-{:02X}-{}",
            manufacturer_id, config.device.application_id, config.device.application_version, app_hash
        );

        // Hardware2Program ID: <hardware_id>_HP-<app_number>-<app_version>-<hash>
        let h2p_id = format!(
            "{}_HP-{:04X}-{:02X}-{}",
            hardware_id, config.device.application_id, config.device.application_version, app_hash
        );

        // Product ID: <hardware_id>_P-<order_number>
        // Order number must be URL-encoded for ID convention compliance
        let product_id = format!("{}_P-{}", hardware_id, MtxmlGenerator::encode_id(config.order_number));

        let mut knx = HardwareKnx::default();
        knx.manufacturer_data.manufacturer.ref_id = manufacturer_id;
        knx.manufacturer_data.manufacturer.hardware.hardware = Hardware {
            id: hardware_id,
            name: config.hardware_name.to_string(),
            serial_number: serial_hex,
            version_number: config.hardware_version,
            has_individual_address: true,
            has_application_program: true,
            products: Products {
                product: Product {
                    id: product_id,
                    text: config.product_name.to_string(),
                    order_number: config.order_number.to_string(),
                    is_rail_mounted: config.is_rail_mounted,
                    default_language: "en-US".to_string(),
                },
            },
            hardware2programs: Hardware2Programs {
                hardware2program: Hardware2Program {
                    id: h2p_id,
                    medium_types: medium_type_from_mask(config.device.mask_version).to_string(),
                    application_program_ref: ApplicationProgramRef { ref_id: app_id },
                },
            },
        };

        knx
    }

    /// Serialize the Hardware KNX document to XML string.
    fn serialize(knx: &HardwareKnx) -> Result<String, GeneratorError> {
        let mut buffer = String::new();
        buffer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        let mut serializer = quick_xml::se::Serializer::new(&mut buffer);
        serializer.indent(' ', 2);

        serde::Serialize::serialize(knx, serializer)
            .map_err(|e| GeneratorError::Serialization(e.to_string()))?;

        Ok(buffer)
    }
}

// ============================================================================
// Catalog MTXML Generator
// ============================================================================

/// Generator for creating Catalog MTXML files.
pub struct CatalogGenerator;

impl CatalogGenerator {
    /// Generate a complete Catalog MTXML document from the configuration.
    pub fn generate(config: &ApplicationProgramConfig) -> Result<String, GeneratorError> {
        let knx = Self::build_catalog_knx(config);
        Self::serialize(&knx)
    }

    /// Build the complete Catalog KNX document structure.
    fn build_catalog_knx(config: &ApplicationProgramConfig) -> CatalogKnx {
        let manufacturer_id = format!("M-{:04X}", config.device.manufacturer_id);
        let serial_hex = config
            .serial_number
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();

        // Hardware ID: M-XXXX_H-<serial>-<version>
        let hardware_id = format!("{}_H-{}-{}", manufacturer_id, serial_hex, config.hardware_version);

        // Application hash suffix (defaults to 0000)
        let app_hash = config.application_hash.unwrap_or("0000");

        // Hardware2Program ID - must match Hardware2Program ID in Hardware.xml
        let h2p_id = format!(
            "{}_HP-{:04X}-{:02X}-{}",
            hardware_id, config.device.application_id, config.device.application_version, app_hash
        );

        // Product ID - must be URL-encoded for ID convention compliance
        let product_id = format!("{}_P-{}", hardware_id, MtxmlGenerator::encode_id(config.order_number));

        // Catalog Section ID
        let section_id = format!("{}_CS-1", manufacturer_id);

        // Catalog Item ID: <h2p_id>_CI-<order_number>-1
        // Order number must be URL-encoded for ID convention compliance
        let catalog_item_id = format!("{}_CI-{}-1", h2p_id, MtxmlGenerator::encode_id(config.order_number));

        let mut knx = CatalogKnx::default();
        knx.manufacturer_data.manufacturer.ref_id = manufacturer_id;
        knx.manufacturer_data.manufacturer.catalog.catalog_section = CatalogSection {
            id: section_id,
            name: config.catalog_section.to_string(),
            number: "1".to_string(),
            default_language: "en-US".to_string(),
            catalog_item: CatalogItem {
                id: catalog_item_id,
                name: config.product_name.to_string(),
                number: "1".to_string(),
                product_ref_id: product_id,
                hardware2program_ref_id: h2p_id,
                default_language: "en-US".to_string(),
            },
        };

        knx
    }

    /// Serialize the Catalog KNX document to XML string.
    fn serialize(knx: &CatalogKnx) -> Result<String, GeneratorError> {
        let mut buffer = String::new();
        buffer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        let mut serializer = quick_xml::se::Serializer::new(&mut buffer);
        serializer.indent(' ', 2);

        serde::Serialize::serialize(knx, serializer)
            .map_err(|e| GeneratorError::Serialization(e.to_string()))?;

        Ok(buffer)
    }
}

/// Errors that can occur during MTXML generation.
#[derive(Debug)]
pub enum GeneratorError {
    /// Error during XML serialization
    Serialization(String),
    /// Missing reference error - a RefId was used but no matching definition exists
    MissingReference {
        /// Type of reference (ParameterRef, ComObjectRef, ParameterType, etc.)
        ref_type: String,
        /// The RefId that was used but not found
        ref_id: String,
        /// Where the reference was used (e.g., "Dynamic/Choose" or "ParameterRefRef")
        context: String,
    },
}

impl std::fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeneratorError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            GeneratorError::MissingReference { ref_type, ref_id, context } => {
                write!(f, "Missing {ref_type} reference: '{ref_id}' referenced in {context}")
            }
        }
    }
}

impl std::error::Error for GeneratorError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_app_id() {
        let device = DeviceDescriptor {
            mask_version: 0x57B0,
            manufacturer_id: 0x00FA,
            hardware_type: [0; 6],
            application_id: 0x0200,
            application_version: 0x01,
            max_address_table_entries: 16,
            max_association_table_entries: 16,
            max_com_objects: 8,
        };
        let config = ApplicationProgramConfig {
            name: "TestDevice",
            device: &device,
            params: &[],
            virtual_params: None,
            param_defaults: &[],
            comm_objects: &[],
            comm_object_refs: &[],
            union_fields: None,
            channel_name: "General",
            absolute_segment_address: None,
            system7_layout: None,
            application_hash: None,
            non_reg_relevant_data_version: None,
            replaces_versions: None,
            application_data_hash: None,
            serial_number: [0x00, 0xFA, 0x00, 0x00, 0x00, 0x01],
            hardware_version: 1,
            hardware_name: "Test Hardware",
            product_name: "Test Product",
            order_number: "TEST-001",
            is_rail_mounted: false,
            catalog_section: "Test Section",
            page_layout: None,
            modules: None,
        };

        let app_id = MtxmlGenerator::format_app_id(&config);
        assert_eq!(app_id, "M-00FA_A-0200-01-0000");
    }

    #[test]
    fn test_generate_empty_system_b() {
        let config = ApplicationProgramConfig {
            name: "TestDevice",
            device: &DeviceDescriptor {
                mask_version: 0x57B0,
                manufacturer_id: 0x00FA,
                hardware_type: [0; 6],
                application_id: 0x0200,
                application_version: 0x01,
                max_address_table_entries: 16,
                max_association_table_entries: 16,
                max_com_objects: 8,
            },
            params: &[],
            virtual_params: None,
            param_defaults: &[],
            comm_objects: &[],
            comm_object_refs: &[],
            union_fields: None,
            channel_name: "General",
            absolute_segment_address: None,
            system7_layout: None,
            application_hash: None,
            non_reg_relevant_data_version: None,
            replaces_versions: None,
            application_data_hash: None,
            serial_number: [0x00, 0xFA, 0x00, 0x00, 0x00, 0x01],
            hardware_version: 1,
            hardware_name: "Test Hardware",
            product_name: "Test Product",
            order_number: "TEST-001",
            is_rail_mounted: false,
            catalog_section: "Test Section",
            page_layout: None,
            modules: None,
        };

        let xml = MtxmlGenerator::generate(&config).unwrap();
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("TestDevice"));
        assert!(xml.contains("MV-57B0"));
        assert!(xml.contains("M-00FA_A-0200-01-0000"));
        assert!(xml.contains("MergedProcedure")); // System B uses MergedProcedure
        assert!(xml.contains("RelativeSegment")); // System B uses relative segments
    }

    #[test]
    fn test_generate_empty_system_7() {
        let config = ApplicationProgramConfig {
            name: "System7Device",
            device: &DeviceDescriptor {
                mask_version: 0x0705,
                manufacturer_id: 0x00FA,
                hardware_type: [0; 6],
                application_id: 0x0100,
                application_version: 0x01,
                max_address_table_entries: 16,
                max_association_table_entries: 16,
                max_com_objects: 8,
            },
            params: &[],
            virtual_params: None,
            param_defaults: &[],
            comm_objects: &[],
            comm_object_refs: &[],
            union_fields: None,
            channel_name: "General",
            absolute_segment_address: Some(0x4000),
            system7_layout: None,
            application_hash: None,
            non_reg_relevant_data_version: None,
            replaces_versions: None,
            application_data_hash: None,
            serial_number: [0x00, 0xFA, 0x00, 0x00, 0x00, 0x02],
            hardware_version: 1,
            hardware_name: "System 7 Hardware",
            product_name: "System 7 Product",
            order_number: "SYS7-001",
            is_rail_mounted: true,
            catalog_section: "Test Section",
            page_layout: None,
            modules: None,
        };

        let xml = MtxmlGenerator::generate(&config).unwrap();
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("System7Device"));
        assert!(xml.contains("MV-0705"));
        assert!(xml.contains("ProductProcedure")); // System 7 uses ProductProcedure
        assert!(xml.contains("AbsoluteSegment")); // System 7 uses absolute segments
    }

    #[test]
    fn test_mask_family_detection() {
        assert_eq!(MaskFamily::from_mask_version(0x57B0), MaskFamily::SystemB);
        assert_eq!(MaskFamily::from_mask_version(0x07B0), MaskFamily::SystemB);
        assert_eq!(MaskFamily::from_mask_version(0x0705), MaskFamily::System7);
        assert_eq!(MaskFamily::from_mask_version(0x0701), MaskFamily::System7);
        assert_eq!(MaskFamily::from_mask_version(0x0912), MaskFamily::Bim);
        assert_eq!(MaskFamily::from_mask_version(0x0920), MaskFamily::BimM);
    }

    #[test]
    fn test_generate_with_modules() {
        use crate::module::{KnxModule, ModuleArgDef, ModuleArgValue, ModuleCollection, ModuleInstanceBuilder};

        // Define a simple test module
        struct TestDimmerModule;

        impl KnxModule for TestDimmerModule {
            const NAME: &'static str = "DimmerChannel";
            const ARGUMENTS: &'static [ModuleArgDef] = &[
                ModuleArgDef::param_offset("ParamBase"),
                ModuleArgDef::object_number("ObjBase"),
                ModuleArgDef::display("ChNo", 1),
            ];
            type Params = ();
            type Objects = ();
        }

        // Create module instances
        let mut modules = ModuleCollection::new();
        let instances = ModuleInstanceBuilder::<TestDimmerModule>::new()
            .for_range(1..=4, |ch| {
                vec![
                    ModuleArgValue::numeric(100 + (ch - 1) * 8),
                    ModuleArgValue::numeric(10 + (ch - 1) * 3),
                    ModuleArgValue::numeric(ch),
                ]
            })
            .build();
        modules.add_instances(instances);

        let config = ApplicationProgramConfig {
            name: "ModuleTestDevice",
            device: &DeviceDescriptor {
                mask_version: 0x57B0,
                manufacturer_id: 0x00FA,
                hardware_type: [0; 6],
                application_id: 0x0300,
                application_version: 0x01,
                max_address_table_entries: 16,
                max_association_table_entries: 16,
                max_com_objects: 16,
            },
            params: &[],
            virtual_params: None,
            param_defaults: &[],
            comm_objects: &[],
            comm_object_refs: &[],
            union_fields: None,
            channel_name: "General",
            absolute_segment_address: None,
            system7_layout: None,
            application_hash: None,
            non_reg_relevant_data_version: None,
            replaces_versions: None,
            application_data_hash: None,
            serial_number: [0x00, 0xFA, 0x00, 0x00, 0x00, 0x03],
            hardware_version: 1,
            hardware_name: "Test Hardware",
            product_name: "Test Product",
            order_number: "TEST-MOD",
            is_rail_mounted: false,
            catalog_section: "Test Section",
            page_layout: None,
            modules: Some(modules),
        };

        let xml = MtxmlGenerator::generate(&config).unwrap();

        // Verify ModuleDefs was generated
        assert!(xml.contains("ModuleDefs"), "XML should contain ModuleDefs section");
        assert!(xml.contains("ModuleDef"), "XML should contain ModuleDef elements");
        assert!(xml.contains("DimmerChannel"), "XML should contain module name");
        assert!(xml.contains("Arguments"), "XML should contain Arguments section");
        assert!(xml.contains("Argument"), "XML should contain Argument elements");
        assert!(xml.contains("ParamBase"), "XML should contain ParamBase argument");
        assert!(xml.contains("ObjBase"), "XML should contain ObjBase argument");
        assert!(xml.contains("ChNo"), "XML should contain ChNo argument");
        // Allocates is computed from actual Params/Objects types, which are () here (size 0)
        // Only ChNo has a fixed allocates value from display() constructor
        assert!(xml.contains("Allocates=\"0\""), "XML should have allocates 0 for empty params/objects");
        assert!(xml.contains("Allocates=\"1\""), "XML should have correct ChNo allocates");
    }

    #[test]
    fn test_generate_module_instances_in_dynamic() {
        use crate::module::{KnxModule, ModuleArgDef, ModuleArgValue, ModuleCollection, ModuleInstanceBuilder};
        use crate::page_layout::{PageStructure, PageElement, PageBlock, PageItem};

        // Define a simple test module
        struct TestChannelModule;

        impl KnxModule for TestChannelModule {
            const NAME: &'static str = "ChannelModule";
            const ARGUMENTS: &'static [ModuleArgDef] = &[
                ModuleArgDef::param_offset("ParamBase"),
                ModuleArgDef::object_number("ObjBase"),
                ModuleArgDef::display("ChNo", 1),
            ];
            type Params = ();
            type Objects = ();
        }

        // Create module instances
        let mut modules = ModuleCollection::new();
        let instances = ModuleInstanceBuilder::<TestChannelModule>::new()
            .for_range(1..=2, |ch| {
                vec![
                    ModuleArgValue::numeric(100 + (ch - 1) * 4),  // ParamBase
                    ModuleArgValue::numeric(10 + (ch - 1) * 2),   // ObjBase
                    ModuleArgValue::numeric(ch),                   // ChNo
                ]
            })
            .build();
        modules.add_instances(instances);

        // Create a page layout that includes module instances directly in a block
        // This tests that PageItem::Module generates the proper XML in ParameterBlock
        let page_layout = PageStructure {
            device_settings: vec![
                PageElement::Block(PageBlock {
                    name: "modules",
                    text: "Channel Modules",
                    items: vec![
                        // Module instances directly in the block (simpler test case)
                        PageItem::Module {
                            module_name: "ChannelModule",
                            instance_index: 0,
                        },
                        PageItem::Module {
                            module_name: "ChannelModule",
                            instance_index: 1,
                        },
                    ],
                }),
            ],
            channels: vec![],
        };

        let config = ApplicationProgramConfig {
            name: "ModuleInstanceDevice",
            device: &DeviceDescriptor {
                mask_version: 0x57B0,
                manufacturer_id: 0x00FA,
                hardware_type: [0; 6],
                application_id: 0x0400,
                application_version: 0x01,
                max_address_table_entries: 16,
                max_association_table_entries: 16,
                max_com_objects: 16,
            },
            params: &[],
            virtual_params: None,
            param_defaults: &[],
            comm_objects: &[],
            comm_object_refs: &[],
            union_fields: None,
            channel_name: "General",
            absolute_segment_address: None,
            system7_layout: None,
            application_hash: None,
            non_reg_relevant_data_version: None,
            replaces_versions: None,
            application_data_hash: None,
            serial_number: [0x00, 0xFA, 0x00, 0x00, 0x00, 0x04],
            hardware_version: 1,
            hardware_name: "Test Hardware",
            product_name: "Module Instance Test",
            order_number: "TEST-MOD-INST",
            is_rail_mounted: false,
            catalog_section: "Test Section",
            page_layout: Some(page_layout),
            modules: Some(modules),
        };

        let xml = MtxmlGenerator::generate(&config).unwrap();

        // Verify ModuleDefs was generated
        assert!(xml.contains("ModuleDefs"), "XML should contain ModuleDefs section");
        assert!(xml.contains("ChannelModule"), "XML should contain module name");

        // Verify Module instances appear in Dynamic section
        assert!(xml.contains("<Dynamic>"), "XML should have Dynamic section");

        // The Module instances should appear inside choose/when blocks
        // Check for Module element with proper attributes
        assert!(xml.contains("<Module "), "XML should contain Module elements");
        assert!(xml.contains("RefId="), "Module should have RefId referencing the ModuleDef");

        // Check for NumericArg elements with values
        assert!(xml.contains("<NumericArg "), "XML should contain NumericArg elements");
        assert!(xml.contains("Value=\"100\""), "First instance ParamBase should be 100");
        assert!(xml.contains("Value=\"104\""), "Second instance ParamBase should be 104");
        assert!(xml.contains("Value=\"10\""), "First instance ObjBase should be 10");
        assert!(xml.contains("Value=\"12\""), "Second instance ObjBase should be 12");
        assert!(xml.contains("Value=\"1\""), "First instance ChNo should be 1");
        assert!(xml.contains("Value=\"2\""), "Second instance ChNo should be 2");
    }
}
