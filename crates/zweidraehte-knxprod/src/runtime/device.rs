//! Unified Device struct for KNX device configuration.
//!
//! This module provides a `Device` struct that encapsulates all state needed
//! for a KNX device configuration, including:
//! - Parsed ApplicationProgram (XML structure)
//! - Device identification and programming info (DeviceInfo)
//! - Runtime parameter values and visibility state
//! - Module expansion and parameter values
//! - Group address bindings
//! - Baggage resources (images, icons)
//!
//! # Example
//!
//! ```rust,ignore
//! use zweidraehte_knxprod::{Device, parse_application_program_from_file};
//!
//! let knx = parse_application_program_from_file("device.mtxml")?;
//! let program = knx.manufacturer_data.manufacturer.application_programs.programs.remove(0);
//!
//! let device = Device::new(program, None, None);
//!
//! // Get parameter value
//! if let Some(value) = device.get_parameter_value("Param_1") {
//!     println!("Param_1 = {:?}", value);
//! }
//!
//! // Interpolate text with parameter substitution
//! let text = device.interpolate_text("Value is {{1:unknown}}");
//! ```

use std::collections::{HashMap, HashSet};

use crate::runtime::baggage::BaggageIndex;
use crate::runtime::device_info::DeviceInfo;
use crate::runtime::master_data::MasterData;
use crate::runtime::model::{
    AssociationEntry, Condition, ExpandedModule, GroupAddress, GroupAddressBinding, ModuleArgValue, ParameterInfo,
    ParameterValue,
};
use crate::schema::{
    ApplicationProgram, Channel, ChannelIndependentBlock, ChannelIndependentItem, ChannelItem, Choose, ComObject,
    ComObjectRef, DynamicSection, Module, ModuleArg, ModuleDef, ModuleDefDynamicItem, ParameterBlock,
    ParameterBlockItem, ParameterRef, ParameterType, WhenItem,
};

/// A complete KNX device instance with all state needed for configuration and programming.
///
/// This struct combines:
/// - **ApplicationProgram**: The parsed XML structure (immutable)
/// - **DeviceInfo**: Device identification and programming metadata
/// - **Runtime State**: Parameter values, visibility, module expansion, bindings
/// - **Resources**: Baggage index for images and icons
pub struct Device {
    // === Immutable Core ===
    /// The parsed application program
    program: ApplicationProgram,

    /// Device identification and programming info
    pub info: DeviceInfo,

    /// Device-specific baggage/resources (images, icons)
    baggage_index: Option<BaggageIndex>,

    // === Mutable Configuration State ===
    /// Current parameter values indexed by parameter ID
    param_values: HashMap<String, ParameterValue>,

    /// Module instance parameter values indexed by composite ID (instance_id::param_id)
    module_param_values: HashMap<String, ParameterValue>,

    /// Group address bindings indexed by communication object number
    group_address_bindings: HashMap<u16, Vec<GroupAddressBinding>>,

    /// Parameters whose value was explicitly set after construction.
    ///
    /// Distinguishes "the user chose this value" from "still at its
    /// construction-time default" — needed because a visible
    /// `ParameterRef` may carry a `Value` override, making the
    /// *effective* default differ from the stored initial value.
    touched_params: HashSet<String>,

    // === Computed State ===
    /// Set of visible parameter ref IDs
    visible_param_refs: HashSet<String>,

    /// Set of visible communication object ref IDs
    visible_com_object_refs: HashSet<String>,

    /// Set of visible module instance IDs
    visible_modules: HashSet<String>,

    /// Active `ParameterBlockRename`s under the current configuration:
    /// renamed block id -> display text. A rename inside an active
    /// choose branch replaces the referenced block's title.
    active_block_renames: HashMap<String, String>,

    /// Expanded module instances indexed by instance ID
    expanded_modules: HashMap<String, ExpandedModule>,

    // === Internal Lookup Caches ===
    /// Parameter types indexed by type ID
    param_types: HashMap<String, ParameterType>,

    /// Parameters indexed by ID
    parameters: HashMap<String, ParameterInfo>,

    /// Parameter refs indexed by ID
    param_refs: HashMap<String, ParameterRef>,

    /// Parameter ref ids indexed by their numeric tail — inline text
    /// templates name refs that way (`{{48:…}}` means `…_P-23_R-48`),
    /// full ids appear only in attributes.
    param_ref_tails: HashMap<String, String>,

    /// Communication objects indexed by ID
    com_objects: HashMap<String, ComObject>,

    /// Communication object refs indexed by ID
    com_object_refs: HashMap<String, ComObjectRef>,

    /// Module definitions indexed by ID
    module_defs: HashMap<String, ModuleDef>,
}

/// Context for processing a module's dynamic section.
#[derive(Clone)]
pub struct ModuleContext {
    /// The module instance ID
    pub instance_id: String,
    /// The module definition
    pub module_def: ModuleDef,
}

impl Device {
    /// Create a new device from a parsed ApplicationProgram.
    ///
    /// # Arguments
    /// * `program` - The parsed ApplicationProgram
    /// * `master_data` - Optional master data for enriching device info
    /// * `baggage_index` - Optional baggage index for images/resources
    pub fn new(
        program: ApplicationProgram,
        master_data: Option<&MasterData>,
        baggage_index: Option<BaggageIndex>,
    ) -> Self {
        // Extract DeviceInfo
        let info = DeviceInfo::from_program(&program, master_data);

        // Build lookup caches
        let param_types = build_param_type_lookup(&program.static_section);
        let (parameters, param_values) = build_parameter_lookup(&program.static_section, &param_types);
        let param_refs = build_param_ref_lookup(&program.static_section);
        let param_ref_tails = build_param_ref_tail_lookup(&param_refs);
        let com_objects = build_com_object_lookup(&program.static_section);
        let com_object_refs = build_com_object_ref_lookup(&program.static_section);
        let module_defs = build_module_def_lookup(&program);

        // Expand module instances from dynamic section
        let expanded_modules = expand_all_modules(&program, &module_defs);

        // Initialize module parameter values from defaults
        let module_param_values = build_module_param_values(&expanded_modules, &module_defs);

        let mut device = Self {
            program,
            info,
            baggage_index,
            param_values,
            module_param_values,
            group_address_bindings: HashMap::new(),
            touched_params: HashSet::new(),
            visible_param_refs: HashSet::new(),
            visible_com_object_refs: HashSet::new(),
            visible_modules: HashSet::new(),
            active_block_renames: HashMap::new(),
            expanded_modules,
            param_types,
            parameters,
            param_refs,
            param_ref_tails,
            com_objects,
            com_object_refs,
            module_defs,
        };

        // Compute initial visibility
        device.recompute_visibility();

        device
    }

    // ========================================================================
    // Program Access
    // ========================================================================

    /// Get a reference to the parsed ApplicationProgram.
    pub fn program(&self) -> &ApplicationProgram {
        &self.program
    }

    // ========================================================================
    // Parameter Access
    // ========================================================================

    /// Get the current value of a parameter by ID.
    pub fn get_parameter_value(&self, param_id: &str) -> Option<&ParameterValue> {
        self.param_values.get(param_id)
    }

    /// Set a parameter value and recompute visibility.
    pub fn set_parameter_value(&mut self, param_id: &str, value: ParameterValue) {
        self.param_values.insert(param_id.to_string(), value);
        self.touched_params.insert(param_id.to_string());
        self.recompute_visibility();
    }

    /// Whether a parameter's value was explicitly set since
    /// construction (as opposed to still holding its initial default).
    pub fn is_parameter_touched(&self, param_id: &str) -> bool {
        self.touched_params.contains(param_id)
    }

    /// The display text an active `ParameterBlockRename` gives a
    /// block under the current configuration, if any. Renders (and
    /// re-renders on every visibility recomputation) what ETS shows:
    /// a rename in an active choose branch replaces the referenced
    /// block's title.
    pub fn active_block_rename(&self, block_id: &str) -> Option<&str> {
        self.active_block_renames.get(block_id).map(String::as_str)
    }

    /// Get parameter info by ID.
    pub fn get_parameter_info(&self, param_id: &str) -> Option<&ParameterInfo> {
        self.parameters.get(param_id)
    }

    /// Get a parameter type by ID.
    pub fn get_parameter_type(&self, type_id: &str) -> Option<&ParameterType> {
        self.param_types.get(type_id)
    }

    /// Get a parameter ref by ID.
    pub fn get_parameter_ref(&self, ref_id: &str) -> Option<&ParameterRef> {
        self.param_refs.get(ref_id)
    }

    // ========================================================================
    // Communication Object Access
    // ========================================================================

    /// Get a communication object by ID.
    pub fn get_com_object(&self, obj_id: &str) -> Option<&ComObject> {
        self.com_objects.get(obj_id)
    }

    /// Get a communication object ref by ID.
    pub fn get_com_object_ref(&self, ref_id: &str) -> Option<&ComObjectRef> {
        self.com_object_refs.get(ref_id)
    }

    // ========================================================================
    // Visibility Queries
    // ========================================================================

    /// Check if a parameter ref is currently visible.
    pub fn is_param_ref_visible(&self, ref_id: &str) -> bool {
        self.visible_param_refs.contains(ref_id)
    }

    /// Check if a communication object ref is currently visible.
    pub fn is_com_object_ref_visible(&self, ref_id: &str) -> bool {
        self.visible_com_object_refs.contains(ref_id)
    }

    /// Check if a module instance is currently visible.
    pub fn is_module_visible(&self, instance_id: &str) -> bool {
        self.visible_modules.contains(instance_id)
    }

    /// Iterate over visible parameter refs.
    pub fn visible_param_refs(&self) -> impl Iterator<Item = &ParameterRef> {
        self.visible_param_refs.iter().filter_map(|id| self.param_refs.get(id))
    }

    /// Iterate over visible communication object refs.
    pub fn visible_com_object_refs(&self) -> impl Iterator<Item = &ComObjectRef> {
        self.visible_com_object_refs.iter().filter_map(|id| self.com_object_refs.get(id))
    }

    /// Iterate over visible module instances.
    pub fn visible_modules(&self) -> impl Iterator<Item = &ExpandedModule> {
        self.visible_modules.iter().filter_map(|id| self.expanded_modules.get(id))
    }

    // ========================================================================
    // Module Access
    // ========================================================================

    /// Get an expanded module instance by ID.
    pub fn get_expanded_module(&self, instance_id: &str) -> Option<&ExpandedModule> {
        self.expanded_modules.get(instance_id)
    }

    /// Get a module definition by ID.
    pub fn get_module_def(&self, def_id: &str) -> Option<&ModuleDef> {
        self.module_defs.get(def_id)
    }

    /// Get all module definitions (for visitor pattern traversal).
    pub fn module_defs(&self) -> &HashMap<String, ModuleDef> {
        &self.module_defs
    }

    /// Get a module parameter value.
    pub fn get_module_parameter_value(&self, instance_id: &str, param_id: &str) -> Option<&ParameterValue> {
        let composite_id = format!("{}::{}", instance_id, param_id);
        self.module_param_values.get(&composite_id)
    }

    /// Set a module parameter value and recompute visibility.
    pub fn set_module_parameter_value(&mut self, instance_id: &str, param_id: &str, value: ParameterValue) {
        let composite_id = format!("{}::{}", instance_id, param_id);
        self.module_param_values.insert(composite_id, value);
        self.recompute_visibility();
    }

    // ========================================================================
    // Group Address Bindings
    // ========================================================================

    /// Assign a group address to a communication object.
    pub fn assign_group_address(&mut self, obj_number: u16, address: GroupAddress) {
        let bindings = self.group_address_bindings.entry(obj_number).or_default();

        // Check if already bound
        if bindings.iter().any(|b| b.group_address == address) {
            return;
        }

        // First binding is the sending address
        let is_sending = bindings.is_empty();
        bindings.push(GroupAddressBinding { group_address: address, is_sending });
    }

    /// Remove a group address binding from a communication object.
    pub fn remove_group_address(&mut self, obj_number: u16, address: &GroupAddress) {
        if let Some(bindings) = self.group_address_bindings.get_mut(&obj_number) {
            bindings.retain(|b| &b.group_address != address);

            // Update sending flag if first was removed
            if !bindings.is_empty() && !bindings.iter().any(|b| b.is_sending) {
                bindings[0].is_sending = true;
            }

            if bindings.is_empty() {
                self.group_address_bindings.remove(&obj_number);
            }
        }
    }

    /// Clear all group address bindings for a communication object.
    pub fn clear_group_addresses(&mut self, obj_number: u16) {
        self.group_address_bindings.remove(&obj_number);
    }

    /// Get all group address bindings for a communication object.
    pub fn get_bindings(&self, obj_number: u16) -> Option<&[GroupAddressBinding]> {
        self.group_address_bindings.get(&obj_number).map(|v| v.as_slice())
    }

    /// All group address bindings, per communication object number.
    pub fn all_bindings(&self) -> impl Iterator<Item = (u16, &[GroupAddressBinding])> {
        self.group_address_bindings.iter().map(|(number, bindings)| (*number, bindings.as_slice()))
    }

    /// Build association table entries for all bindings.
    pub fn build_association_entries(&self) -> Vec<AssociationEntry> {
        // Collect all unique group addresses and sort them
        let mut all_addresses: Vec<GroupAddress> =
            self.group_address_bindings.values().flatten().map(|b| b.group_address).collect();
        all_addresses.sort_by_key(|ga| ga.to_u16());
        all_addresses.dedup();

        // Build address table index (1-based)
        let address_to_tsap: HashMap<GroupAddress, u16> =
            all_addresses.iter().enumerate().map(|(i, ga)| (*ga, (i + 1) as u16)).collect();

        // Build association entries
        let mut entries = Vec::new();
        for (obj_number, bindings) in &self.group_address_bindings {
            for binding in bindings {
                if let Some(&tsap) = address_to_tsap.get(&binding.group_address) {
                    entries.push(AssociationEntry { tsap, asap: *obj_number });
                }
            }
        }

        // Sort by TSAP then ASAP
        entries.sort_by(|a, b| a.tsap.cmp(&b.tsap).then(a.asap.cmp(&b.asap)));

        entries
    }

    /// Get all group address bindings for a communication object (empty slice if none).
    ///
    /// This is a convenience method that returns an empty slice instead of None
    /// when there are no bindings.
    pub fn get_group_addresses(&self, obj_number: u16) -> &[GroupAddressBinding] {
        self.group_address_bindings.get(&obj_number).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get all unique group addresses from all bindings, sorted.
    pub fn all_group_addresses(&self) -> Vec<GroupAddress> {
        let mut addresses: Vec<GroupAddress> =
            self.group_address_bindings.values().flatten().map(|b| b.group_address).collect();
        addresses.sort_by_key(|ga| ga.to_u16());
        addresses.dedup();
        addresses
    }

    /// Check if any group addresses are bound.
    pub fn has_group_addresses(&self) -> bool {
        !self.group_address_bindings.is_empty()
    }

    // ========================================================================
    // Static/Dynamic Section Access
    // ========================================================================

    /// Get a reference to the static section.
    pub fn static_section(&self) -> &crate::schema::StaticSection {
        &self.program.static_section
    }

    /// Get the dynamic section if present.
    pub fn dynamic_section(&self) -> Option<&crate::schema::DynamicSection> {
        self.program.dynamic.as_ref()
    }

    /// Get the mask version string.
    pub fn mask_version(&self) -> &str {
        &self.program.mask_version
    }

    // ========================================================================
    // Module Utilities
    // ========================================================================

    /// Check if a parameter ID refers to a module parameter (contains "::").
    pub fn is_module_parameter(&self, param_id: &str) -> bool {
        param_id.contains("::")
    }

    /// Iterate over all expanded module instances.
    pub fn all_expanded_modules(&self) -> impl Iterator<Item = &ExpandedModule> {
        self.expanded_modules.values()
    }

    /// Get a module parameter value by composite ID (instance_id::param_id).
    ///
    /// This is a convenience method for when the composite ID is already formed.
    pub fn get_module_parameter_value_by_composite_id(&self, composite_id: &str) -> Option<&ParameterValue> {
        self.module_param_values.get(composite_id)
    }

    /// Set a module parameter value by composite ID (instance_id::param_id).
    ///
    /// This is a convenience method for when the composite ID is already formed.
    pub fn set_module_parameter_value_by_composite_id(&mut self, composite_id: &str, value: ParameterValue) {
        self.module_param_values.insert(composite_id.to_string(), value);
        self.recompute_visibility();
    }

    // ========================================================================
    // Baggage Access
    // ========================================================================

    /// Get the baggage index if available.
    pub fn baggage_index(&self) -> Option<&BaggageIndex> {
        self.baggage_index.as_ref()
    }

    // ========================================================================
    // Text Interpolation
    // ========================================================================

    /// Interpolate `{{ref}}` or `{{ref:default}}` patterns in text.
    ///
    /// Looks up parameter ref values and substitutes them into the text.
    /// If the ref is not found or empty, uses the default value (if provided).
    pub fn interpolate_text(&self, text: &str) -> String {
        interpolate_patterns(text, |pattern| {
            let (ref_num, default_text) = parse_pattern(pattern);
            match self.resolve_param_ref_value(ref_num) {
                Some(value) if !value.is_empty() => Some(value),
                _ => default_text.map(|s| s.to_string()),
            }
        })
    }

    /// Interpolate text with module context for `{{ArgName}}` patterns.
    ///
    /// First tries to resolve as a module argument, then falls back to
    /// device-level parameter ref lookup.
    pub fn interpolate_module_text(&self, text: &str, module: &ExpandedModule) -> String {
        self.interpolate_module_text_with_param(text, module, None)
    }

    /// Interpolate text with module context and optional text parameter value.
    ///
    /// The `text_param_value` is used for `{{0}}` substitution when provided.
    /// This is typically the value of the parameter referenced by TextParameterRefId.
    pub fn interpolate_module_text_with_param(
        &self,
        text: &str,
        module: &ExpandedModule,
        text_param_value: Option<&str>,
    ) -> String {
        interpolate_patterns(text, |pattern| {
            // First, try direct argument lookup
            if let Some(value) = module.args.get(pattern) {
                return Some(format_arg_value(value));
            }

            // Try to interpret as a number index for text args ({{0}}, {{1}}, etc.)
            if let Ok(idx) = pattern.parse::<usize>() {
                if idx == 0 {
                    // {{0}} is typically the text parameter value
                    return text_param_value.map(|s| s.to_string()).or_else(|| {
                        // Fall back to first text argument if available
                        module
                            .args
                            .values()
                            .filter_map(|v| match v {
                                ModuleArgValue::Text(s) => Some(s.clone()),
                                _ => None,
                            })
                            .next()
                    });
                } else {
                    // Find the idx-th text argument
                    let text_args: Vec<_> = module
                        .args
                        .values()
                        .filter_map(|v| match v {
                            ModuleArgValue::Text(s) => Some(s.clone()),
                            _ => None,
                        })
                        .collect();
                    return text_args.get(idx).cloned();
                }
            }

            // Fall back to device-level param ref
            let (ref_num, default_text) = parse_pattern(pattern);
            match self.resolve_param_ref_value(ref_num) {
                Some(value) if !value.is_empty() => Some(value),
                _ => default_text.map(|s| s.to_string()),
            }
        })
    }

    /// Interpolate `{{0}}` pattern using TextParameterRefId.
    ///
    /// Used for channel names where `{{0}}` is replaced with the value
    /// of the parameter referenced by TextParameterRefId.
    pub fn interpolate_channel_text(&self, text: &str, text_param_ref_id: Option<&str>) -> String {
        if !text.contains("{{0}}") {
            return text.to_string();
        }
        let value = text_param_ref_id.and_then(|id| self.resolve_text_param_ref(id)).unwrap_or_default();
        text.replace("{{0}}", &value)
    }

    /// Resolve a parameter ref value to a string.
    ///
    /// `ref_id` is either a full ref id (from an attribute) or the
    /// bare numeric tail an inline `{{N[:default]}}` template uses.
    fn resolve_param_ref_value(&self, ref_id: &str) -> Option<String> {
        let param_ref = self.lookup_param_ref(ref_id)?;
        let value = self.param_values.get(&param_ref.ref_id)?;

        Some(match value {
            ParameterValue::Integer(i) => i.to_string(),
            ParameterValue::Float(f) => f.to_string(),
            ParameterValue::Text(s) => s.clone(),
            ParameterValue::Bytes(b) => format!("{:02X?}", b),
        })
    }

    /// Parse a raw attribute value with the parameter's declared type
    /// — the same rules construction uses, so effective defaults and
    /// initial values can never disagree about a text parameter.
    pub(crate) fn parse_value_typed(&self, param_id: &str, raw: &str) -> ParameterValue {
        let type_def =
            self.parameters.get(param_id).and_then(|info| self.param_types.get(&info.type_id)).map(|t| &t.type_def);
        match type_def {
            Some(crate::schema::ParameterTypeDef::TypeText(_)) => ParameterValue::Text(raw.to_string()),
            Some(crate::schema::ParameterTypeDef::TypeFloat(_)) => ParameterValue::Float(raw.parse().unwrap_or(0.0)),
            Some(
                crate::schema::ParameterTypeDef::TypeNumber(_) | crate::schema::ParameterTypeDef::TypeRestriction(_),
            ) => ParameterValue::Integer(raw.parse().unwrap_or(0)),
            _ => parse_default_value(raw),
        }
    }

    /// A ref by full id first, by numeric tail second.
    fn lookup_param_ref(&self, ref_id: &str) -> Option<&ParameterRef> {
        self.param_refs
            .get(ref_id)
            .or_else(|| self.param_ref_tails.get(ref_id).and_then(|full| self.param_refs.get(full)))
    }

    /// Resolve a text parameter ref (used for {{0}} substitution).
    ///
    /// Only returns text values - integers are not converted to strings here
    /// because {{0}} substitution is meant for actual text content (like channel names),
    /// not numeric values.
    fn resolve_text_param_ref(&self, ref_id: &str) -> Option<String> {
        let param_ref = self.lookup_param_ref(ref_id)?;
        let value = self.param_values.get(&param_ref.ref_id)?;

        match value {
            ParameterValue::Text(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    }

    // ========================================================================
    // Visibility Computation
    // ========================================================================

    /// Recompute visibility based on current parameter values.
    fn recompute_visibility(&mut self) {
        self.visible_param_refs.clear();
        self.visible_com_object_refs.clear();
        self.visible_modules.clear();
        self.active_block_renames.clear();

        // Build the read-only lookup context from self's maps, then call the
        // free traversal function so the borrow checker sees distinct borrows:
        // `self.program.dynamic` (read) vs. `self.visible_*` (write).
        //
        // Iterated to a fixpoint because choose gating is
        // self-referential: a choose counts only when its selector's
        // ref is visible, and that ref may itself sit inside another
        // choose. Visibility only ever grows across iterations
        // (opening a choose can hide nothing), so the loop converges;
        // the bound is the deepest selector chain, with a hard cap as
        // a backstop against product-data cycles.
        if let Some(dynamic) = &self.program.dynamic {
            let ctx = VisibilityReadCtx {
                param_refs: &self.param_refs,
                param_values: &self.param_values,
                module_param_values: &self.module_param_values,
                module_defs: &self.module_defs,
            };
            let mut previous: HashSet<String> = HashSet::new();
            for _ in 0..8 {
                let mut params = HashSet::new();
                let mut objects = HashSet::new();
                let mut modules = HashSet::new();
                let mut renames = HashMap::new();
                traverse_dynamic_section(
                    dynamic,
                    &ctx,
                    &mut params,
                    &mut objects,
                    &mut modules,
                    &mut renames,
                    &previous,
                );
                let stable = params == previous;
                previous = params.clone();
                self.visible_param_refs = params;
                self.visible_com_object_refs = objects;
                self.visible_modules = modules;
                self.active_block_renames = renames;
                if stable {
                    break;
                }
            }
        }
    }

    fn get_selector_value(&self, param_ref_id: &str) -> Option<i64> {
        let param_ref = self.param_refs.get(param_ref_id)?;
        let param_value = self.param_values.get(&param_ref.ref_id)?;

        match param_value {
            ParameterValue::Integer(v) => Some(*v),
            ParameterValue::Float(v) => Some(*v as i64),
            _ => None,
        }
    }
}

// ============================================================================
// ConditionEvaluator Implementation
// ============================================================================

impl crate::runtime::model::ConditionEvaluator for Device {
    fn get_selector_value(&self, param_ref_id: &str) -> Option<i64> {
        // Delegate to Device's internal method
        Device::get_selector_value(self, param_ref_id)
    }

    fn get_selector_value_with_module(
        &self,
        param_ref_id: &str,
        module_ctx: Option<&crate::runtime::model::VisitorModuleContext>,
    ) -> Option<i64> {
        // If module context is provided, first try module parameter lookup
        if let Some(ctx) = module_ctx
            && let Some(param_refs) = &ctx.module_def.static_section.parameter_refs
            && let Some(param_ref) = param_refs.refs.iter().find(|pr| pr.id == param_ref_id)
        {
            let composite_id = format!("{}::{}", ctx.instance_id, param_ref.ref_id);
            if let Some(value) = self.module_param_values.get(&composite_id) {
                return match value {
                    ParameterValue::Integer(v) => Some(*v),
                    ParameterValue::Float(v) => Some(*v as i64),
                    _ => None,
                };
            }
        }

        // Fall back to main device parameter lookup
        Device::get_selector_value(self, param_ref_id)
    }
}

// ============================================================================
// Visibility Traversal — Free Functions
// ============================================================================

/// Read-only lookup tables needed during a visibility traversal.
///
/// Separating these into their own struct lets the borrow checker see that
/// `program.dynamic` (read) and the `visible_*` sets (write) are independent
/// fields, removing the need to clone the entire `DynamicSection`.
struct VisibilityReadCtx<'a> {
    param_refs: &'a HashMap<String, ParameterRef>,
    param_values: &'a HashMap<String, ParameterValue>,
    module_param_values: &'a HashMap<String, ParameterValue>,
    module_defs: &'a HashMap<String, ModuleDef>,
}

impl VisibilityReadCtx<'_> {
    fn selector_value(&self, param_ref_id: &str, module_ctx: Option<&ModuleContext>) -> Option<i64> {
        if let Some(ctx) = module_ctx
            && let Some(param_refs) = &ctx.module_def.static_section.parameter_refs
            && let Some(param_ref) = param_refs.refs.iter().find(|pr| pr.id == param_ref_id)
        {
            let composite_id = format!("{}::{}", ctx.instance_id, param_ref.ref_id);
            if let Some(value) = self.module_param_values.get(&composite_id) {
                return match value {
                    ParameterValue::Integer(v) => Some(*v),
                    ParameterValue::Float(v) => Some(*v as i64),
                    _ => None,
                };
            }
        }
        let param_ref = self.param_refs.get(param_ref_id)?;
        match self.param_values.get(&param_ref.ref_id)? {
            ParameterValue::Integer(v) => Some(*v),
            ParameterValue::Float(v) => Some(*v as i64),
            _ => None,
        }
    }
}

fn traverse_dynamic_section(
    dynamic: &DynamicSection,
    ctx: &VisibilityReadCtx<'_>,
    visible_params: &mut HashSet<String>,
    visible_objects: &mut HashSet<String>,
    visible_modules: &mut HashSet<String>,
    renames: &mut HashMap<String, String>,
    previously_visible: &HashSet<String>,
) {
    if let Some(cib) = &dynamic.channel_independent_block {
        for item in &cib.items {
            match item {
                ChannelIndependentItem::ParameterBlock(pb) => {
                    traverse_parameter_block(
                        pb,
                        None,
                        ctx,
                        visible_params,
                        visible_objects,
                        visible_modules,
                        renames,
                        previously_visible,
                    );
                }
                ChannelIndependentItem::Choose(choose) => {
                    traverse_choose(
                        choose,
                        None,
                        ctx,
                        visible_params,
                        visible_objects,
                        visible_modules,
                        renames,
                        previously_visible,
                    );
                }
                ChannelIndependentItem::ParameterBlockRename(rename) => {
                    renames.insert(rename.ref_id.clone(), rename.text.clone().unwrap_or_default());
                }
            }
        }
    }

    for channel in &dynamic.channels {
        for item in &channel.items {
            match item {
                ChannelItem::ParameterBlock(pb) => {
                    traverse_parameter_block(
                        pb,
                        None,
                        ctx,
                        visible_params,
                        visible_objects,
                        visible_modules,
                        renames,
                        previously_visible,
                    );
                }
                ChannelItem::Choose(choose) => {
                    traverse_choose(
                        choose,
                        None,
                        ctx,
                        visible_params,
                        visible_objects,
                        visible_modules,
                        renames,
                        previously_visible,
                    );
                }
                ChannelItem::Module(module) => {
                    traverse_module(
                        module,
                        ctx,
                        visible_params,
                        visible_objects,
                        visible_modules,
                        renames,
                        previously_visible,
                    );
                }
                ChannelItem::ParameterBlockRename(rename) => {
                    renames.insert(rename.ref_id.clone(), rename.text.clone().unwrap_or_default());
                }
            }
        }
    }
}

fn traverse_parameter_block(
    pb: &ParameterBlock,
    module_ctx: Option<&ModuleContext>,
    ctx: &VisibilityReadCtx<'_>,
    visible_params: &mut HashSet<String>,
    visible_objects: &mut HashSet<String>,
    visible_modules: &mut HashSet<String>,
    renames: &mut HashMap<String, String>,
    previously_visible: &HashSet<String>,
) {
    for item in &pb.items {
        match item {
            ParameterBlockItem::ParameterRefRef(prr) => {
                visible_params.insert(prr.ref_id.clone());
            }
            ParameterBlockItem::ComObjectRefRef(corr) => {
                visible_objects.insert(corr.ref_id.clone());
            }
            ParameterBlockItem::Choose(choose) => {
                traverse_choose(
                    choose,
                    module_ctx,
                    ctx,
                    visible_params,
                    visible_objects,
                    visible_modules,
                    renames,
                    previously_visible,
                );
            }
            ParameterBlockItem::Module(module) => {
                traverse_module(
                    module,
                    ctx,
                    visible_params,
                    visible_objects,
                    visible_modules,
                    renames,
                    previously_visible,
                );
            }
            ParameterBlockItem::ParameterBlockRename(rename) => {
                renames.insert(rename.ref_id.clone(), rename.text.clone().unwrap_or_default());
            }
            ParameterBlockItem::ParameterSeparator(_)
            | ParameterBlockItem::Button(_)
            | ParameterBlockItem::Rows(_)
            | ParameterBlockItem::Columns(_) => {}
        }
    }
}

fn traverse_choose(
    choose: &Choose,
    module_ctx: Option<&ModuleContext>,
    ctx: &VisibilityReadCtx<'_>,
    visible_params: &mut HashSet<String>,
    visible_objects: &mut HashSet<String>,
    visible_modules: &mut HashSet<String>,
    renames: &mut HashMap<String, String>,
    previously_visible: &HashSet<String>,
) {
    // ETS scopes a choose to its selector's *visible* ref: a choose
    // whose ParamRefId is not part of the current tree contributes
    // nothing, whatever the parameter's value. The MDT LED pages rely
    // on this — the dynamic-brightness thresholds hang off a choose
    // on "Datapoint type", whose own ref only appears when day or
    // night brightness selects "dynamic". Evaluated against the
    // previous fixpoint iteration's set.
    if !previously_visible.contains(&choose.param_ref_id) {
        return;
    }

    let selector_value = ctx.selector_value(&choose.param_ref_id, module_ctx);

    let mut any_matched = false;
    let mut default_items: Option<&[WhenItem]> = None;

    for when in &choose.whens {
        if when.default.unwrap_or(false) {
            default_items = Some(&when.items);
            continue;
        }
        if let Some(test) = &when.test
            && matches!(
                (selector_value, Condition::parse(test)),
                (Some(v), Some(cond)) if cond.matches(v)
            )
        {
            traverse_when_items(
                &when.items,
                module_ctx,
                ctx,
                visible_params,
                visible_objects,
                visible_modules,
                renames,
                previously_visible,
            );
            any_matched = true;
        }
    }

    if !any_matched {
        if let Some(items) = default_items {
            traverse_when_items(
                items,
                module_ctx,
                ctx,
                visible_params,
                visible_objects,
                visible_modules,
                renames,
                previously_visible,
            );
        }
    }
}

fn traverse_when_items(
    items: &[WhenItem],
    module_ctx: Option<&ModuleContext>,
    ctx: &VisibilityReadCtx<'_>,
    visible_params: &mut HashSet<String>,
    visible_objects: &mut HashSet<String>,
    visible_modules: &mut HashSet<String>,
    renames: &mut HashMap<String, String>,
    previously_visible: &HashSet<String>,
) {
    for item in items {
        match item {
            WhenItem::ParameterRefRef(prr) => {
                visible_params.insert(prr.ref_id.clone());
            }
            WhenItem::ComObjectRefRef(corr) => {
                visible_objects.insert(corr.ref_id.clone());
            }
            WhenItem::ParameterBlock(pb) => {
                traverse_parameter_block(
                    pb,
                    module_ctx,
                    ctx,
                    visible_params,
                    visible_objects,
                    visible_modules,
                    renames,
                    previously_visible,
                );
            }
            WhenItem::Choose(nested_choose) => {
                traverse_choose(
                    nested_choose,
                    module_ctx,
                    ctx,
                    visible_params,
                    visible_objects,
                    visible_modules,
                    renames,
                    previously_visible,
                );
            }
            WhenItem::Module(module) => {
                traverse_module(
                    module,
                    ctx,
                    visible_params,
                    visible_objects,
                    visible_modules,
                    renames,
                    previously_visible,
                );
            }
            WhenItem::ParameterBlockRename(rename) => {
                renames.insert(rename.ref_id.clone(), rename.text.clone().unwrap_or_default());
            }
            WhenItem::ParameterSeparator(_) | WhenItem::Assign(_) => {}
        }
    }
}

fn traverse_module(
    module: &Module,
    ctx: &VisibilityReadCtx<'_>,
    visible_params: &mut HashSet<String>,
    visible_objects: &mut HashSet<String>,
    visible_modules: &mut HashSet<String>,
    renames: &mut HashMap<String, String>,
    previously_visible: &HashSet<String>,
) {
    visible_modules.insert(module.id.clone());

    if let Some(module_def) = ctx.module_defs.get(&module.ref_id)
        && let Some(dynamic) = &module_def.dynamic
    {
        let module_ctx = ModuleContext { instance_id: module.id.clone(), module_def: module_def.clone() };

        for item in &dynamic.items {
            match item {
                ModuleDefDynamicItem::ParameterBlock(pb) => {
                    traverse_parameter_block(
                        pb,
                        Some(&module_ctx),
                        ctx,
                        visible_params,
                        visible_objects,
                        visible_modules,
                        renames,
                        previously_visible,
                    );
                }
                ModuleDefDynamicItem::Choose(choose) => {
                    traverse_choose(
                        choose,
                        Some(&module_ctx),
                        ctx,
                        visible_params,
                        visible_objects,
                        visible_modules,
                        renames,
                        previously_visible,
                    );
                }
            }
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Core interpolation loop for `{{pattern}}` substitution.
fn interpolate_patterns(text: &str, mut resolver: impl FnMut(&str) -> Option<String>) -> String {
    if !text.contains("{{") {
        return text.to_string();
    }

    let mut result = String::with_capacity(text.len());
    let mut remaining = text;

    while let Some(start) = remaining.find("{{") {
        result.push_str(&remaining[..start]);
        if let Some(end) = remaining[start..].find("}}") {
            let pattern = &remaining[start + 2..start + end];
            if let Some(replacement) = resolver(pattern) {
                result.push_str(&replacement);
            }
            remaining = &remaining[start + end + 2..];
        } else {
            result.push_str(&remaining[start..]);
            break;
        }
    }
    result.push_str(remaining);
    result
}

/// Parse a pattern like "ref" or "ref:default" into (ref, Option<default>).
fn parse_pattern(pattern: &str) -> (&str, Option<&str>) {
    if let Some(colon_pos) = pattern.find(':') {
        (&pattern[..colon_pos], Some(&pattern[colon_pos + 1..]))
    } else {
        (pattern, None)
    }
}

/// Format a module argument value as a string.
fn format_arg_value(value: &ModuleArgValue) -> String {
    match value {
        ModuleArgValue::Numeric(n) => n.to_string(),
        ModuleArgValue::Text(s) => s.clone(),
    }
}

// ============================================================================
// Lookup Builders (copied from model.rs)
// ============================================================================

use crate::schema::{ParameterItem, StaticSection};

fn build_lookup<T, K, V, I>(
    items: Option<I>,
    mut key_fn: impl FnMut(&T) -> K,
    mut val_fn: impl FnMut(&T) -> V,
) -> HashMap<K, V>
where
    K: std::hash::Hash + Eq,
    I: IntoIterator<Item = T>,
{
    items.into_iter().flatten().map(|item| (key_fn(&item), val_fn(&item))).collect()
}

fn build_param_type_lookup(static_section: &StaticSection) -> HashMap<String, ParameterType> {
    build_lookup(static_section.parameter_types.as_ref().map(|pt| pt.types.iter()), |t| t.id.clone(), |t| (*t).clone())
}

fn build_parameter_lookup(
    static_section: &StaticSection,
    param_types: &HashMap<String, ParameterType>,
) -> (HashMap<String, ParameterInfo>, HashMap<String, ParameterValue>) {
    let mut parameters = HashMap::new();
    let mut param_values = HashMap::new();

    // Type-aware default parsing: a text parameter's `Value=""` (or
    // "12"!) must become `Text`, never the numeric-first guess —
    // guessing turned every empty description into `Integer(0)`,
    // which then rendered as a literal "0" in interpolated labels.
    let parse = |type_id: &str, value: &str| -> ParameterValue {
        match param_types.get(type_id).map(|t| &t.type_def) {
            Some(crate::schema::ParameterTypeDef::TypeText(_)) => ParameterValue::Text(value.to_string()),
            Some(crate::schema::ParameterTypeDef::TypeFloat(_)) => ParameterValue::Float(value.parse().unwrap_or(0.0)),
            Some(
                crate::schema::ParameterTypeDef::TypeNumber(_) | crate::schema::ParameterTypeDef::TypeRestriction(_),
            ) => ParameterValue::Integer(value.parse().unwrap_or(0)),
            _ => parse_default_value(value),
        }
    };

    if let Some(params) = &static_section.parameters {
        for item in &params.items {
            match item {
                ParameterItem::Parameter(p) => {
                    let info = ParameterInfo {
                        id: p.id.clone(),
                        name: p.name.clone(),
                        text: p.text.clone(),
                        type_id: p.parameter_type.clone(),
                        default_value: p.value.clone(),
                        suffix: p.suffix_text.clone(),
                        hidden: p.access.as_deref() == Some("None"),
                        read_only: p.access.as_deref() == Some("Read"),
                    };
                    let default = parse(&p.parameter_type, &info.default_value);
                    param_values.insert(p.id.clone(), default);
                    parameters.insert(p.id.clone(), info);
                }
                ParameterItem::Union(u) => {
                    for p in &u.parameters {
                        let info = ParameterInfo {
                            id: p.id.clone(),
                            name: p.name.clone(),
                            text: p.text.clone(),
                            type_id: p.parameter_type.clone(),
                            default_value: p.value.clone(),
                            suffix: p.suffix_text.clone(),
                            hidden: p.access.as_deref() == Some("None"),
                            read_only: p.access.as_deref() == Some("Read"),
                        };
                        let default = parse(&p.parameter_type, &info.default_value);
                        param_values.insert(p.id.clone(), default);
                        parameters.insert(p.id.clone(), info);
                    }
                }
            }
        }
    }

    (parameters, param_values)
}

/// Parse an MTXML `Value` attribute the way the device model does at
/// construction: integer first, then float, then verbatim text. Also
/// used by the mods layer to interpret `ParameterRef` value overrides.
pub(crate) fn parse_default_value(value: &str) -> ParameterValue {
    if value.is_empty() {
        return ParameterValue::Integer(0);
    }

    if let Ok(i) = value.parse::<i64>() {
        return ParameterValue::Integer(i);
    }

    if let Ok(f) = value.parse::<f64>() {
        return ParameterValue::Float(f);
    }

    ParameterValue::Text(value.to_string())
}

fn build_param_ref_lookup(static_section: &StaticSection) -> HashMap<String, ParameterRef> {
    build_lookup(static_section.parameter_refs.as_ref().map(|pr| pr.refs.iter()), |r| r.id.clone(), |r| (*r).clone())
}

/// Inline text templates address refs by the digits after `_R-`
/// (`{{48:Push button 1}}` → `…_P-23_R-48`); index those tails once.
fn build_param_ref_tail_lookup(param_refs: &HashMap<String, ParameterRef>) -> HashMap<String, String> {
    param_refs.keys().filter_map(|id| id.rsplit_once("_R-").map(|(_, tail)| (tail.to_string(), id.clone()))).collect()
}

fn build_com_object_lookup(static_section: &StaticSection) -> HashMap<String, ComObject> {
    build_lookup(
        static_section.com_object_table.as_ref().map(|cot| cot.objects.iter()),
        |o| o.id.clone(),
        |o| (*o).clone(),
    )
}

fn build_com_object_ref_lookup(static_section: &StaticSection) -> HashMap<String, ComObjectRef> {
    build_lookup(static_section.com_object_refs.as_ref().map(|cor| cor.refs.iter()), |r| r.id.clone(), |r| (*r).clone())
}

fn build_module_def_lookup(program: &ApplicationProgram) -> HashMap<String, ModuleDef> {
    build_lookup(program.module_defs.as_ref().map(|md| md.module_defs.iter()), |m| m.id.clone(), |m| (*m).clone())
}

fn build_module_param_values(
    expanded_modules: &HashMap<String, ExpandedModule>,
    module_defs: &HashMap<String, ModuleDef>,
) -> HashMap<String, ParameterValue> {
    let mut values = HashMap::new();

    for (instance_id, expanded) in expanded_modules {
        if let Some(module_def) = module_defs.get(&expanded.module_def_id)
            && let Some(params) = &module_def.static_section.parameters
        {
            for item in &params.items {
                match item {
                    ParameterItem::Parameter(p) => {
                        let composite_id = format!("{}::{}", instance_id, p.id);
                        let default = parse_default_value(&p.value);
                        values.insert(composite_id, default);
                    }
                    ParameterItem::Union(u) => {
                        // Also initialize union parameters
                        for up in &u.parameters {
                            let composite_id = format!("{}::{}", instance_id, up.id);
                            let default = parse_default_value(&up.value);
                            values.insert(composite_id, default);
                        }
                    }
                }
            }
        }
    }

    values
}

fn expand_all_modules(
    program: &ApplicationProgram,
    module_defs: &HashMap<String, ModuleDef>,
) -> HashMap<String, ExpandedModule> {
    let mut expanded = HashMap::new();

    if let Some(dynamic) = &program.dynamic {
        // From channel-independent block
        if let Some(cib) = &dynamic.channel_independent_block {
            collect_modules_from_cib(cib, module_defs, &mut expanded);
        }

        // From channels
        for channel in &dynamic.channels {
            collect_modules_from_channel(channel, module_defs, &mut expanded);
        }
    }

    expanded
}

fn collect_modules_from_cib(
    cib: &ChannelIndependentBlock,
    module_defs: &HashMap<String, ModuleDef>,
    expanded: &mut HashMap<String, ExpandedModule>,
) {
    for item in &cib.items {
        match item {
            ChannelIndependentItem::ParameterBlock(pb) => {
                collect_modules_from_pb(pb, module_defs, expanded);
            }
            ChannelIndependentItem::Choose(choose) => {
                collect_modules_from_choose(choose, module_defs, expanded);
            }
            // Renames carry no module instances.
            ChannelIndependentItem::ParameterBlockRename(_) => {}
        }
    }
}

fn collect_modules_from_channel(
    channel: &Channel,
    module_defs: &HashMap<String, ModuleDef>,
    expanded: &mut HashMap<String, ExpandedModule>,
) {
    for item in &channel.items {
        match item {
            ChannelItem::ParameterBlock(pb) => {
                collect_modules_from_pb(pb, module_defs, expanded);
            }
            ChannelItem::Choose(choose) => {
                collect_modules_from_choose(choose, module_defs, expanded);
            }
            ChannelItem::ParameterBlockRename(_) => {}
            ChannelItem::Module(module) => {
                if let Some(exp) = expand_module(module, module_defs) {
                    expanded.insert(exp.instance_id.clone(), exp);
                }
            }
        }
    }
}

fn collect_modules_from_pb(
    pb: &ParameterBlock,
    module_defs: &HashMap<String, ModuleDef>,
    expanded: &mut HashMap<String, ExpandedModule>,
) {
    for item in &pb.items {
        match item {
            ParameterBlockItem::Module(module) => {
                if let Some(exp) = expand_module(module, module_defs) {
                    expanded.insert(exp.instance_id.clone(), exp);
                }
            }
            ParameterBlockItem::Choose(choose) => {
                collect_modules_from_choose(choose, module_defs, expanded);
            }
            _ => {}
        }
    }
}

fn collect_modules_from_choose(
    choose: &Choose,
    module_defs: &HashMap<String, ModuleDef>,
    expanded: &mut HashMap<String, ExpandedModule>,
) {
    for when in &choose.whens {
        for item in &when.items {
            match item {
                WhenItem::Module(module) => {
                    if let Some(exp) = expand_module(module, module_defs) {
                        expanded.insert(exp.instance_id.clone(), exp);
                    }
                }
                WhenItem::ParameterBlock(pb) => {
                    collect_modules_from_pb(pb, module_defs, expanded);
                }
                WhenItem::Choose(nested) => {
                    collect_modules_from_choose(nested, module_defs, expanded);
                }
                _ => {}
            }
        }
    }
}

fn expand_module(module: &Module, module_defs: &HashMap<String, ModuleDef>) -> Option<ExpandedModule> {
    let module_def = module_defs.get(&module.ref_id)?;

    let mut args = HashMap::new();

    // Resolve argument values from module instance args
    if let Some(def_args) = &module_def.arguments {
        for def_arg in &def_args.arguments {
            // Find corresponding instance argument in the module's args Vec
            let mut found = false;
            for inst_arg in &module.args {
                match inst_arg {
                    ModuleArg::NumericArg { ref_id, value } if ref_id == &def_arg.id => {
                        args.insert(def_arg.name.clone(), ModuleArgValue::Numeric(*value));
                        found = true;
                    }
                    ModuleArg::TextArg { ref_id, value, .. } if ref_id == &def_arg.id => {
                        args.insert(def_arg.name.clone(), ModuleArgValue::Text(value.clone()));
                        found = true;
                    }
                    _ => {}
                }
            }
            if !found {
                log::warn!(
                    "Module {} missing arg '{}' (def_id={}), available args: {:?}",
                    module.id,
                    def_arg.name,
                    def_arg.id,
                    module
                        .args
                        .iter()
                        .map(|a| match a {
                            ModuleArg::NumericArg { ref_id, value } => format!("Num({}: {})", ref_id, value),
                            ModuleArg::TextArg { ref_id, value, .. } => format!("Text({}: {})", ref_id, value),
                        })
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    Some(ExpandedModule {
        instance_id: module.id.clone(),
        module_def_id: module.ref_id.clone(),
        name: module.name.clone(),
        args,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::parser::parse_application_program_from_file;
    use std::path::Path;

    #[test]
    fn test_mdt_module_expansion() {
        let path = Path::new("../manuf_tool_data/VC-EASY-03_MDT_KP_V35/M-0083/M-0083_A-0070-35-1740.xml");
        if !path.exists() {
            eprintln!("Skipping test - MDT file not found");
            return;
        }

        let knx = parse_application_program_from_file(path).expect("Failed to parse");
        let program = knx
            .manufacturer_data
            .manufacturer
            .application_programs
            .programs
            .into_iter()
            .next()
            .expect("No application program found");

        let device = Device::new(program, None, None);

        // Check that we have expanded modules
        let modules: Vec<_> = device.all_expanded_modules().collect();
        assert!(!modules.is_empty(), "Should have expanded modules");

        // Check that first module has ChNo arg
        let first = &modules[0];
        eprintln!("First module: {} -> {:?}", first.instance_id, first.args);

        // Find a module with ChNo=1
        let m1 = modules.iter().find(|m| matches!(m.args.get("ChNo"), Some(ModuleArgValue::Numeric(1))));
        assert!(m1.is_some(), "Should find module with ChNo=1");
        let m1 = m1.unwrap();
        eprintln!("Module with ChNo=1: {} -> {:?}", m1.instance_id, m1.args);

        // Test interpolation
        let result = device.interpolate_module_text("F{{ChNo}}: {{0}}", m1);
        eprintln!("Interpolation result: '{}'", result);
        assert!(result.starts_with("F1:"), "Should interpolate ChNo=1, got: {}", result);
    }

    #[test]
    fn test_interpolate_patterns() {
        // Simple pattern
        let result =
            interpolate_patterns("Hello {{name}}", |p| if p == "name" { Some("World".to_string()) } else { None });
        assert_eq!(result, "Hello World");

        // Pattern with default
        let result = interpolate_patterns("Value: {{ref:default}}", |_| None);
        assert_eq!(result, "Value: ");

        // No patterns
        let result = interpolate_patterns("No patterns here", |_| panic!("shouldn't be called"));
        assert_eq!(result, "No patterns here");

        // Multiple patterns
        let result = interpolate_patterns("{{a}} and {{b}}", |p| Some(p.to_uppercase()));
        assert_eq!(result, "A and B");
    }

    #[test]
    fn test_parse_pattern() {
        assert_eq!(parse_pattern("ref"), ("ref", None));
        assert_eq!(parse_pattern("ref:default"), ("ref", Some("default")));
        assert_eq!(parse_pattern("ref:a:b"), ("ref", Some("a:b")));
    }
}
