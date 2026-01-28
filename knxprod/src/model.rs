//! Device Model for KNX ApplicationProgram Runtime
//!
//! This module provides a runtime model for KNX device configurations,
//! including parameter value management, condition evaluation for choose/when
//! blocks, and visibility computation.

use std::collections::{HashMap, HashSet};

use crate::schema::{
    ApplicationProgram, Channel, ChannelIndependentBlock, ChannelIndependentItem, ChannelItem,
    Choose, ComObject, ComObjectRef, DynamicSection, Module, ModuleArg, ModuleDef,
    ModuleDefDynamicItem, ParameterBlock, ParameterBlockItem, ParameterItem, ParameterRef,
    ParameterType, StaticSection, WhenItem,
};

/// Represents a parameter value that can be stored in the device model.
#[derive(Debug, Clone, PartialEq)]
pub enum ParameterValue {
    /// Integer value (for TypeNumber and TypeRestriction)
    Integer(i64),
    /// Float value (for TypeFloat)
    Float(f64),
    /// Text value (for TypeText)
    Text(String),
    /// Raw bytes (for TypeNone or unknown types)
    Bytes(Vec<u8>),
}

impl Default for ParameterValue {
    fn default() -> Self {
        ParameterValue::Integer(0)
    }
}

/// A KNX group address in 3-level notation (main/middle/sub).
///
/// This is a simplified representation for the TUI. The raw 16-bit value
/// can be obtained via `to_u16()` for table generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct GroupAddress {
    /// Main group (0-31)
    pub main: u8,
    /// Middle group (0-7)
    pub middle: u8,
    /// Sub group (0-255)
    pub sub: u8,
}

impl GroupAddress {
    /// Create a new group address from 3-level notation.
    pub const fn new(main: u8, middle: u8, sub: u8) -> Self {
        Self { main, middle, sub }
    }

    /// Parse a group address from string (e.g., "1/2/3").
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 3 {
            return None;
        }
        let main = parts[0].parse().ok()?;
        let middle = parts[1].parse().ok()?;
        let sub = parts[2].parse().ok()?;
        if main > 31 || middle > 7 {
            return None;
        }
        Some(Self { main, middle, sub })
    }

    /// Convert to raw 16-bit value (big-endian format for KNX tables).
    pub const fn to_u16(&self) -> u16 {
        (((self.main as u16) & 0x1f) << 11) | (((self.middle as u16) & 0x07) << 8) | (self.sub as u16)
    }

    /// Convert to bytes (big-endian) for table storage.
    pub const fn to_bytes(&self) -> [u8; 2] {
        let val = self.to_u16();
        [(val >> 8) as u8, (val & 0xff) as u8]
    }

    /// Create from raw 16-bit value.
    pub const fn from_u16(val: u16) -> Self {
        Self {
            main: ((val >> 11) & 0x1f) as u8,
            middle: ((val >> 8) & 0x07) as u8,
            sub: (val & 0xff) as u8,
        }
    }

    /// Check if this is a valid (non-zero) group address.
    pub const fn is_valid(&self) -> bool {
        self.main != 0 || self.middle != 0 || self.sub != 0
    }
}

impl std::fmt::Display for GroupAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.main, self.middle, self.sub)
    }
}

/// A binding between a communication object and a group address.
#[derive(Debug, Clone)]
pub struct GroupAddressBinding {
    /// The group address
    pub group_address: GroupAddress,
    /// Whether this is the sending address (first/primary binding)
    pub is_sending: bool,
}

/// Association entry for table generation (TSAP -> ASAP mapping).
#[derive(Debug, Clone, Copy)]
pub struct AssociationEntry {
    /// Transport Service Access Point (index into address table, 1-based)
    pub tsap: u16,
    /// Application Service Access Point (communication object number)
    pub asap: u16,
}

/// Runtime model for a KNX device configuration.
///
/// This holds the parsed application program and tracks:
/// - Current parameter values
/// - Computed visibility states for parameters and objects
/// - Parameter type lookups
/// - Module definitions and expanded instances
/// - Group address bindings for communication objects
pub struct DeviceModel {
    /// The parsed application program
    pub program: ApplicationProgram,
    /// Current parameter values indexed by parameter ID
    param_values: HashMap<String, ParameterValue>,
    /// Parameter types indexed by type ID
    param_types: HashMap<String, ParameterType>,
    /// Parameters indexed by ID
    parameters: HashMap<String, ParameterInfo>,
    /// Parameter refs indexed by ID
    param_refs: HashMap<String, ParameterRef>,
    /// Communication objects indexed by ID
    com_objects: HashMap<String, ComObject>,
    /// Communication object refs indexed by ID
    com_object_refs: HashMap<String, ComObjectRef>,
    /// Set of visible parameter ref IDs
    visible_param_refs: HashSet<String>,
    /// Set of visible communication object ref IDs
    visible_com_object_refs: HashSet<String>,
    /// Module definitions indexed by ID
    module_defs: HashMap<String, ModuleDef>,
    /// Expanded module instances indexed by instance ID
    expanded_modules: HashMap<String, ExpandedModule>,
    /// Set of visible module instance IDs
    visible_modules: HashSet<String>,
    /// Module parameter values indexed by composite ID (instance_id::param_id)
    module_param_values: HashMap<String, ParameterValue>,
    /// Group address bindings indexed by communication object number
    /// Each object can have multiple bindings (one sending + multiple listening)
    group_address_bindings: HashMap<u16, Vec<GroupAddressBinding>>,
}

/// Information about a parameter including its default value.
#[derive(Debug, Clone)]
pub struct ParameterInfo {
    /// Parameter ID
    pub id: String,
    /// Parameter name
    pub name: String,
    /// Display text
    pub text: String,
    /// Parameter type ID
    pub type_id: String,
    /// Default value as string
    pub default_value: String,
    /// Suffix text (e.g., "s" for seconds)
    pub suffix: Option<String>,
    /// Whether hidden from user (Access = "None")
    pub hidden: bool,
}

/// A module argument value (numeric or text).
#[derive(Debug, Clone)]
pub enum ModuleArgValue {
    /// Numeric argument (used for BaseOffset, BaseNumber, channel numbers)
    Numeric(i64),
    /// Text argument (used for text substitution like {{0}})
    Text(String),
}

/// An expanded module instance with resolved argument values.
#[derive(Debug, Clone)]
pub struct ExpandedModule {
    /// The module instance ID
    pub instance_id: String,
    /// Reference to the ModuleDef being instantiated
    pub module_def_id: String,
    /// Module instance name (may contain templates)
    pub name: Option<String>,
    /// Resolved argument values by argument name
    pub args: HashMap<String, ModuleArgValue>,
}

impl DeviceModel {
    /// Create a new device model from an application program.
    ///
    /// This initializes all parameters to their default values and computes
    /// initial visibility.
    pub fn new(program: ApplicationProgram) -> Self {
        let static_section = &program.static_section;

        // Build parameter type lookup
        let param_types = build_param_type_lookup(static_section);

        // Build parameter lookup and extract default values
        let (parameters, param_values) = build_parameter_lookup(static_section);

        // Build parameter ref lookup
        let param_refs = build_param_ref_lookup(static_section);

        // Build communication object lookups
        let com_objects = build_com_object_lookup(static_section);
        let com_object_refs = build_com_object_ref_lookup(static_section);

        // Build module definition lookup
        let module_defs = build_module_def_lookup(&program);

        // Expand module instances from dynamic section
        let expanded_modules = expand_all_modules(&program, &module_defs);

        // Initialize module parameter values from defaults
        let module_param_values =
            build_module_param_values(&expanded_modules, &module_defs);

        let mut model = Self {
            program,
            param_values,
            param_types,
            parameters,
            param_refs,
            com_objects,
            com_object_refs,
            visible_param_refs: HashSet::new(),
            visible_com_object_refs: HashSet::new(),
            module_defs,
            expanded_modules,
            visible_modules: HashSet::new(),
            module_param_values,
            group_address_bindings: HashMap::new(),
        };

        // Compute initial visibility
        model.recompute_visibility();

        model
    }

    /// Get the current value of a parameter by ID.
    pub fn get_parameter_value(&self, param_id: &str) -> Option<&ParameterValue> {
        self.param_values.get(param_id)
    }

    /// Set a parameter value by ID.
    ///
    /// This will trigger a visibility recomputation if the parameter is used
    /// as a selector in any choose blocks.
    pub fn set_parameter_value(&mut self, param_id: &str, value: ParameterValue) {
        if self.param_values.contains_key(param_id) {
            self.param_values.insert(param_id.to_string(), value);
            // Recompute visibility since this parameter might be a selector
            self.recompute_visibility();
        }
    }

    /// Get a module parameter value by composite ID (instance_id::param_id).
    pub fn get_module_parameter_value(&self, composite_id: &str) -> Option<&ParameterValue> {
        self.module_param_values.get(composite_id)
    }

    /// Set a module parameter value by composite ID (instance_id::param_id).
    pub fn set_module_parameter_value(&mut self, composite_id: &str, value: ParameterValue) {
        if self.module_param_values.contains_key(composite_id) {
            self.module_param_values.insert(composite_id.to_string(), value);
            // Note: Module parameters don't typically affect visibility conditions,
            // but we could recompute if needed in the future
        }
    }

    /// Check if a parameter ID is a module parameter (contains "::").
    pub fn is_module_parameter(&self, param_id: &str) -> bool {
        param_id.contains("::")
    }

    /// Get parameter info by ID.
    pub fn get_parameter_info(&self, param_id: &str) -> Option<&ParameterInfo> {
        self.parameters.get(param_id)
    }

    /// Get parameter type by ID.
    pub fn get_parameter_type(&self, type_id: &str) -> Option<&ParameterType> {
        self.param_types.get(type_id)
    }

    /// Get parameter ref by ID.
    pub fn get_parameter_ref(&self, ref_id: &str) -> Option<&ParameterRef> {
        self.param_refs.get(ref_id)
    }

    /// Get communication object by ID.
    pub fn get_com_object(&self, obj_id: &str) -> Option<&ComObject> {
        self.com_objects.get(obj_id)
    }

    /// Get communication object ref by ID.
    pub fn get_com_object_ref(&self, ref_id: &str) -> Option<&ComObjectRef> {
        self.com_object_refs.get(ref_id)
    }

    /// Check if a parameter ref is currently visible.
    pub fn is_param_ref_visible(&self, ref_id: &str) -> bool {
        self.visible_param_refs.contains(ref_id)
    }

    /// Check if a communication object ref is currently visible.
    pub fn is_com_object_ref_visible(&self, ref_id: &str) -> bool {
        self.visible_com_object_refs.contains(ref_id)
    }

    /// Get all visible parameter refs.
    pub fn visible_parameter_refs(&self) -> impl Iterator<Item = &ParameterRef> {
        self.visible_param_refs
            .iter()
            .filter_map(|id| self.param_refs.get(id))
    }

    /// Get all visible communication object refs.
    pub fn visible_com_object_refs(&self) -> impl Iterator<Item = &ComObjectRef> {
        self.visible_com_object_refs
            .iter()
            .filter_map(|id| self.com_object_refs.get(id))
    }

    /// Get all parameters.
    pub fn all_parameters(&self) -> impl Iterator<Item = &ParameterInfo> {
        self.parameters.values()
    }

    /// Get all communication objects.
    pub fn all_com_objects(&self) -> impl Iterator<Item = &ComObject> {
        self.com_objects.values()
    }

    /// Get the dynamic section of the program.
    pub fn dynamic_section(&self) -> Option<&DynamicSection> {
        self.program.dynamic.as_ref()
    }

    /// Get a module definition by ID.
    pub fn get_module_def(&self, def_id: &str) -> Option<&ModuleDef> {
        self.module_defs.get(def_id)
    }

    /// Get an expanded module instance by ID.
    pub fn get_expanded_module(&self, instance_id: &str) -> Option<&ExpandedModule> {
        self.expanded_modules.get(instance_id)
    }

    /// Check if a module instance is currently visible.
    pub fn is_module_visible(&self, instance_id: &str) -> bool {
        self.visible_modules.contains(instance_id)
    }

    /// Get all visible module instances.
    pub fn visible_modules(&self) -> impl Iterator<Item = &ExpandedModule> {
        self.visible_modules
            .iter()
            .filter_map(|id| self.expanded_modules.get(id))
    }

    /// Get all expanded module instances.
    pub fn all_expanded_modules(&self) -> impl Iterator<Item = &ExpandedModule> {
        self.expanded_modules.values()
    }

    /// Get the mask version ID (e.g., "MV-07B0").
    pub fn mask_version(&self) -> &str {
        &self.program.mask_version
    }

    // ========================================================================
    // Group Address Binding Management
    // ========================================================================

    /// Assign a group address to a communication object.
    ///
    /// The first assignment becomes the "sending" address. Multiple addresses
    /// can be assigned to a single object (one sending, others listening).
    pub fn assign_group_address(&mut self, object_number: u16, group_address: GroupAddress) {
        let bindings = self.group_address_bindings.entry(object_number).or_default();

        // Check if this address is already assigned
        if bindings.iter().any(|b| b.group_address == group_address) {
            return;
        }

        // First binding is the sending address
        let is_sending = bindings.is_empty();
        bindings.push(GroupAddressBinding {
            group_address,
            is_sending,
        });
    }

    /// Remove a group address binding from a communication object.
    pub fn remove_group_address(&mut self, object_number: u16, group_address: &GroupAddress) {
        if let Some(bindings) = self.group_address_bindings.get_mut(&object_number) {
            let was_sending = bindings.first().map(|b| b.group_address == *group_address).unwrap_or(false);
            bindings.retain(|b| b.group_address != *group_address);

            // If we removed the sending address and there are others, promote the first
            if was_sending && !bindings.is_empty() {
                bindings[0].is_sending = true;
            }
        }
    }

    /// Clear all group addresses from a communication object.
    pub fn clear_group_addresses(&mut self, object_number: u16) {
        self.group_address_bindings.remove(&object_number);
    }

    /// Get all group addresses bound to a communication object.
    pub fn get_group_addresses(&self, object_number: u16) -> &[GroupAddressBinding] {
        self.group_address_bindings
            .get(&object_number)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get the primary (sending) group address for a communication object.
    pub fn get_sending_group_address(&self, object_number: u16) -> Option<GroupAddress> {
        self.group_address_bindings
            .get(&object_number)
            .and_then(|bindings| bindings.iter().find(|b| b.is_sending))
            .map(|b| b.group_address)
    }

    /// Get all unique group addresses assigned across all objects (for address table).
    ///
    /// Returns addresses sorted and deduplicated.
    pub fn all_group_addresses(&self) -> Vec<GroupAddress> {
        let mut addresses: Vec<GroupAddress> = self
            .group_address_bindings
            .values()
            .flatten()
            .map(|b| b.group_address)
            .collect();
        addresses.sort_by_key(|a| a.to_u16());
        addresses.dedup();
        addresses
    }

    /// Build the association table entries (TSAP -> ASAP mappings).
    ///
    /// Returns entries sorted by TSAP (address table index).
    /// TSAP is 1-based index into the address table.
    /// ASAP is the communication object number.
    pub fn build_association_entries(&self) -> Vec<AssociationEntry> {
        // First, build the address table to get TSAP indices
        let address_table = self.all_group_addresses();

        let mut entries = Vec::new();

        for (&object_number, bindings) in &self.group_address_bindings {
            for binding in bindings {
                // Find the TSAP (1-based index into address table)
                if let Some(idx) = address_table.iter().position(|a| *a == binding.group_address) {
                    entries.push(AssociationEntry {
                        tsap: (idx + 1) as u16, // 1-based
                        asap: object_number,
                    });
                }
            }
        }

        // Sort by TSAP, then by ASAP
        entries.sort_by_key(|e| (e.tsap, e.asap));
        entries
    }

    /// Check if any group addresses are assigned.
    pub fn has_group_addresses(&self) -> bool {
        !self.group_address_bindings.is_empty()
    }

    // ========================================================================
    // Visibility Computation
    // ========================================================================

    /// Recompute visibility of all parameter refs and communication object refs
    /// based on current parameter values and choose/when conditions.
    pub fn recompute_visibility(&mut self) {
        self.visible_param_refs.clear();
        self.visible_com_object_refs.clear();
        self.visible_modules.clear();

        // Clone the dynamic section to avoid borrow conflicts
        let dynamic = self.program.dynamic.clone();

        if let Some(dynamic) = dynamic {
            // Process channel-independent block
            if let Some(cib) = &dynamic.channel_independent_block {
                self.process_channel_independent_block(cib);
            }

            // Process channels
            for channel in &dynamic.channels {
                self.process_channel(channel);
            }
        }
    }

    fn process_channel_independent_block(&mut self, cib: &ChannelIndependentBlock) {
        for item in &cib.items {
            match item {
                ChannelIndependentItem::ParameterBlock(pb) => {
                    self.process_parameter_block(pb);
                }
                ChannelIndependentItem::Choose(choose) => {
                    self.process_choose(choose);
                }
            }
        }
    }

    fn process_channel(&mut self, channel: &Channel) {
        for item in &channel.items {
            match item {
                ChannelItem::ParameterBlock(pb) => {
                    self.process_parameter_block(pb);
                }
                ChannelItem::Choose(choose) => {
                    self.process_choose(choose);
                }
                ChannelItem::Module(module) => {
                    self.process_module(module);
                }
            }
        }
    }

    fn process_parameter_block(&mut self, pb: &ParameterBlock) {
        for item in &pb.items {
            self.process_parameter_block_item(item);
        }
    }

    fn process_parameter_block_item(&mut self, item: &ParameterBlockItem) {
        match item {
            ParameterBlockItem::ParameterRefRef(prr) => {
                self.visible_param_refs.insert(prr.ref_id.clone());
            }
            ParameterBlockItem::ComObjectRefRef(corr) => {
                self.visible_com_object_refs.insert(corr.ref_id.clone());
            }
            ParameterBlockItem::Choose(choose) => {
                self.process_choose(choose);
            }
            ParameterBlockItem::ParameterSeparator(_) => {}
            ParameterBlockItem::Module(module) => {
                self.process_module(module);
            }
            ParameterBlockItem::Button(_) => {}
            ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => {}
        }
    }

    fn process_choose(&mut self, choose: &Choose) {
        // Get the selector parameter value
        let selector_value = self.get_selector_value(&choose.param_ref_id);

        // Collect items to process to avoid borrow issues
        // Note: Multiple when clauses can match the same value in KNX choose blocks,
        // so we process ALL matching when clauses, not just the first one.
        let mut items_to_process: Vec<Vec<WhenItem>> = Vec::new();
        let mut any_matched = false;

        for when in &choose.whens {
            if when.default.unwrap_or(false) {
                // Default is processed only if no other when matched at all
                continue; // We'll handle defaults after checking all whens
            } else if let Some(test) = &when.test {
                if self.matches_condition(selector_value, test) {
                    items_to_process.push(when.items.clone());
                    any_matched = true;
                }
            }
        }

        // If no explicit when matched, process the default (if any)
        if !any_matched {
            for when in &choose.whens {
                if when.default.unwrap_or(false) {
                    items_to_process.push(when.items.clone());
                    break; // Only one default
                }
            }
        }

        // Process collected items
        for items in items_to_process {
            self.process_when_items(&items);
        }
    }

    fn process_when_items(&mut self, items: &[WhenItem]) {
        for item in items {
            match item {
                WhenItem::ParameterRefRef(prr) => {
                    self.visible_param_refs.insert(prr.ref_id.clone());
                }
                WhenItem::ComObjectRefRef(corr) => {
                    self.visible_com_object_refs.insert(corr.ref_id.clone());
                }
                WhenItem::ParameterBlock(pb) => {
                    self.process_parameter_block(pb);
                }
                WhenItem::Choose(nested_choose) => {
                    self.process_choose(nested_choose);
                }
                WhenItem::ParameterSeparator(_) => {}
                WhenItem::Assign(_) => {
                    // Assign operations don't affect visibility
                }
                WhenItem::Module(module) => {
                    self.process_module(module);
                }
            }
        }
    }

    /// Process a module instance - mark it as visible.
    fn process_module(&mut self, module: &Module) {
        // Mark this module instance as visible
        self.visible_modules.insert(module.id.clone());

        // Process the module's dynamic section if it has one
        if let Some(module_def) = self.module_defs.get(&module.ref_id).cloned() {
            if let Some(dynamic) = &module_def.dynamic {
                for item in &dynamic.items {
                    match item {
                        ModuleDefDynamicItem::ParameterBlock(pb) => {
                            self.process_parameter_block(pb);
                        }
                        ModuleDefDynamicItem::Choose(choose) => {
                            self.process_choose(choose);
                        }
                    }
                }
            }
        }
    }

    /// Get the integer value of a selector parameter ref.
    fn get_selector_value(&self, param_ref_id: &str) -> Option<i64> {
        // Parameter ref ID points to a ParameterRef which has a RefId pointing to the Parameter
        let param_ref = self.param_refs.get(param_ref_id)?;
        let param_value = self.param_values.get(&param_ref.ref_id)?;

        match param_value {
            ParameterValue::Integer(v) => Some(*v),
            ParameterValue::Float(v) => Some(*v as i64),
            _ => None,
        }
    }

    /// Check if a selector value matches a condition test string.
    ///
    /// Test formats:
    /// - "1" - equals 1
    /// - "1 2 3" - equals 1 OR 2 OR 3
    /// - "=1" - equals 1
    /// - "!=0" - not equals 0
    /// - ">5" - greater than 5
    /// - "<10" - less than 10
    /// - ">=5" - greater than or equal to 5
    /// - "<=10" - less than or equal to 10
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
}

/// Build a lookup map of parameter types by ID.
fn build_param_type_lookup(static_section: &StaticSection) -> HashMap<String, ParameterType> {
    let mut map = HashMap::new();
    if let Some(pt) = &static_section.parameter_types {
        for param_type in &pt.types {
            map.insert(param_type.id.clone(), param_type.clone());
        }
    }
    map
}

/// Build a lookup map of parameters and their default values.
fn build_parameter_lookup(
    static_section: &StaticSection,
) -> (HashMap<String, ParameterInfo>, HashMap<String, ParameterValue>) {
    let mut info_map = HashMap::new();
    let mut value_map = HashMap::new();

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
                    };
                    info_map.insert(p.id.clone(), info);
                    value_map.insert(p.id.clone(), parse_default_value(&p.value));
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
                            hidden: false,
                        };
                        info_map.insert(p.id.clone(), info);
                        value_map.insert(p.id.clone(), parse_default_value(&p.value));
                    }
                }
            }
        }
    }

    (info_map, value_map)
}

/// Parse a default value string into a ParameterValue.
fn parse_default_value(value: &str) -> ParameterValue {
    // Try to parse as integer first
    if let Ok(v) = value.parse::<i64>() {
        return ParameterValue::Integer(v);
    }
    // Try to parse as float
    if let Ok(v) = value.parse::<f64>() {
        return ParameterValue::Float(v);
    }
    // Otherwise treat as text
    ParameterValue::Text(value.to_string())
}

/// Build a lookup map of parameter refs by ID.
fn build_param_ref_lookup(static_section: &StaticSection) -> HashMap<String, ParameterRef> {
    let mut map = HashMap::new();
    if let Some(pr) = &static_section.parameter_refs {
        for param_ref in &pr.refs {
            map.insert(param_ref.id.clone(), param_ref.clone());
        }
    }
    map
}

/// Build a lookup map of communication objects by ID.
fn build_com_object_lookup(static_section: &StaticSection) -> HashMap<String, ComObject> {
    let mut map = HashMap::new();
    if let Some(cot) = &static_section.com_object_table {
        for obj in &cot.objects {
            map.insert(obj.id.clone(), obj.clone());
        }
    }
    map
}

/// Build a lookup map of communication object refs by ID.
fn build_com_object_ref_lookup(static_section: &StaticSection) -> HashMap<String, ComObjectRef> {
    let mut map = HashMap::new();
    if let Some(cor) = &static_section.com_object_refs {
        for obj_ref in &cor.refs {
            map.insert(obj_ref.id.clone(), obj_ref.clone());
        }
    }
    map
}

/// Build a lookup map of module definitions by ID.
fn build_module_def_lookup(program: &ApplicationProgram) -> HashMap<String, ModuleDef> {
    let mut map = HashMap::new();
    if let Some(module_defs) = &program.module_defs {
        for module_def in &module_defs.module_defs {
            map.insert(module_def.id.clone(), module_def.clone());
        }
    }
    map
}

/// Build module parameter values with defaults from module definitions.
///
/// Returns a map of composite IDs (instance_id::param_id) to parameter values.
fn build_module_param_values(
    expanded_modules: &HashMap<String, ExpandedModule>,
    module_defs: &HashMap<String, ModuleDef>,
) -> HashMap<String, ParameterValue> {
    let mut values = HashMap::new();

    for (instance_id, expanded) in expanded_modules {
        if let Some(module_def) = module_defs.get(&expanded.module_def_id) {
            // Get parameters from the module's static section
            if let Some(params) = &module_def.static_section.parameters {
                for item in &params.items {
                    if let ParameterItem::Parameter(p) = item {
                        let composite_id = format!("{}::{}", instance_id, p.id);
                        values.insert(composite_id, parse_default_value(&p.value));
                    }
                }
            }
        }
    }

    values
}

/// Expand all module instances found in the dynamic section.
fn expand_all_modules(
    program: &ApplicationProgram,
    module_defs: &HashMap<String, ModuleDef>,
) -> HashMap<String, ExpandedModule> {
    let mut expanded = HashMap::new();

    if let Some(dynamic) = &program.dynamic {
        // Collect modules from channel-independent block
        if let Some(cib) = &dynamic.channel_independent_block {
            collect_modules_from_cib(&cib.items, module_defs, &mut expanded);
        }

        // Collect modules from channels
        for channel in &dynamic.channels {
            collect_modules_from_channel(&channel.items, module_defs, &mut expanded);
        }
    }

    expanded
}

/// Collect modules from channel-independent block items.
fn collect_modules_from_cib(
    items: &[ChannelIndependentItem],
    module_defs: &HashMap<String, ModuleDef>,
    expanded: &mut HashMap<String, ExpandedModule>,
) {
    for item in items {
        match item {
            ChannelIndependentItem::ParameterBlock(pb) => {
                collect_modules_from_pb(&pb.items, module_defs, expanded);
            }
            ChannelIndependentItem::Choose(choose) => {
                collect_modules_from_choose(choose, module_defs, expanded);
            }
        }
    }
}

/// Collect modules from channel items.
fn collect_modules_from_channel(
    items: &[ChannelItem],
    module_defs: &HashMap<String, ModuleDef>,
    expanded: &mut HashMap<String, ExpandedModule>,
) {
    for item in items {
        match item {
            ChannelItem::ParameterBlock(pb) => {
                collect_modules_from_pb(&pb.items, module_defs, expanded);
            }
            ChannelItem::Choose(choose) => {
                collect_modules_from_choose(choose, module_defs, expanded);
            }
            ChannelItem::Module(module) => {
                expand_module(module, module_defs, expanded);
            }
        }
    }
}

/// Collect modules from parameter block items.
fn collect_modules_from_pb(
    items: &[ParameterBlockItem],
    module_defs: &HashMap<String, ModuleDef>,
    expanded: &mut HashMap<String, ExpandedModule>,
) {
    for item in items {
        match item {
            ParameterBlockItem::Choose(choose) => {
                collect_modules_from_choose(choose, module_defs, expanded);
            }
            ParameterBlockItem::Module(module) => {
                expand_module(module, module_defs, expanded);
            }
            _ => {}
        }
    }
}

/// Collect modules from choose/when blocks.
fn collect_modules_from_choose(
    choose: &Choose,
    module_defs: &HashMap<String, ModuleDef>,
    expanded: &mut HashMap<String, ExpandedModule>,
) {
    for when in &choose.whens {
        for item in &when.items {
            match item {
                WhenItem::ParameterBlock(pb) => {
                    collect_modules_from_pb(&pb.items, module_defs, expanded);
                }
                WhenItem::Choose(nested_choose) => {
                    collect_modules_from_choose(nested_choose, module_defs, expanded);
                }
                WhenItem::Module(module) => {
                    expand_module(module, module_defs, expanded);
                }
                _ => {}
            }
        }
    }
}

/// Expand a single module instance.
fn expand_module(
    module: &Module,
    module_defs: &HashMap<String, ModuleDef>,
    expanded: &mut HashMap<String, ExpandedModule>,
) {
    // Look up the module definition
    let module_def = match module_defs.get(&module.ref_id) {
        Some(def) => def,
        None => return, // Module def not found, skip
    };

    // Build argument values map
    let mut args = HashMap::new();
    for arg in &module.args {
        match arg {
            ModuleArg::NumericArg { ref_id, value } => {
                // Find the argument name from the module def
                if let Some(arg_defs) = &module_def.arguments {
                    for arg_def in &arg_defs.arguments {
                        if arg_def.id == *ref_id {
                            args.insert(arg_def.name.clone(), ModuleArgValue::Numeric(*value));
                            break;
                        }
                    }
                }
            }
            ModuleArg::TextArg { ref_id, value, .. } => {
                // Find the argument name from the module def
                if let Some(arg_defs) = &module_def.arguments {
                    for arg_def in &arg_defs.arguments {
                        if arg_def.id == *ref_id {
                            args.insert(arg_def.name.clone(), ModuleArgValue::Text(value.clone()));
                            break;
                        }
                    }
                }
            }
        }
    }

    // Create expanded module
    let expanded_module = ExpandedModule {
        instance_id: module.id.clone(),
        module_def_id: module.ref_id.clone(),
        name: module.name.clone(),
        args,
    };

    expanded.insert(module.id.clone(), expanded_module);
}

/// Helper struct for iterating over the dynamic structure with visibility context.
pub struct DynamicIterator<'a> {
    model: &'a DeviceModel,
}

impl<'a> DynamicIterator<'a> {
    pub fn new(model: &'a DeviceModel) -> Self {
        Self { model }
    }

    /// Get the channel-independent block if present.
    pub fn channel_independent_block(&self) -> Option<&'a ChannelIndependentBlock> {
        self.model
            .program
            .dynamic
            .as_ref()
            .and_then(|d| d.channel_independent_block.as_ref())
    }

    /// Get all channels.
    pub fn channels(&self) -> impl Iterator<Item = &'a Channel> {
        self.model
            .program
            .dynamic
            .as_ref()
            .map(|d| d.channels.iter())
            .into_iter()
            .flatten()
    }

    /// Check if a parameter ref is visible.
    pub fn is_param_ref_visible(&self, ref_id: &str) -> bool {
        self.model.is_param_ref_visible(ref_id)
    }

    /// Check if a com object ref is visible.
    pub fn is_com_object_ref_visible(&self, ref_id: &str) -> bool {
        self.model.is_com_object_ref_visible(ref_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_matching() {
        let model = create_test_model();

        // Test simple equality
        assert!(model.matches_condition(Some(1), "1"));
        assert!(!model.matches_condition(Some(2), "1"));

        // Test space-separated values (OR)
        assert!(model.matches_condition(Some(1), "1 2 3"));
        assert!(model.matches_condition(Some(2), "1 2 3"));
        assert!(model.matches_condition(Some(3), "1 2 3"));
        assert!(!model.matches_condition(Some(4), "1 2 3"));

        // Test comparison operators
        assert!(model.matches_condition(Some(5), "=5"));
        assert!(!model.matches_condition(Some(4), "=5"));

        assert!(model.matches_condition(Some(4), "!=5"));
        assert!(!model.matches_condition(Some(5), "!=5"));

        assert!(model.matches_condition(Some(6), ">5"));
        assert!(!model.matches_condition(Some(5), ">5"));

        assert!(model.matches_condition(Some(4), "<5"));
        assert!(!model.matches_condition(Some(5), "<5"));

        assert!(model.matches_condition(Some(5), ">=5"));
        assert!(model.matches_condition(Some(6), ">=5"));
        assert!(!model.matches_condition(Some(4), ">=5"));

        assert!(model.matches_condition(Some(5), "<=5"));
        assert!(model.matches_condition(Some(4), "<=5"));
        assert!(!model.matches_condition(Some(6), "<=5"));

        // Test None value
        assert!(!model.matches_condition(None, "1"));
    }

    fn create_test_model() -> DeviceModel {
        // Create a minimal application program for testing
        let program = ApplicationProgram {
            id: "test".to_string(),
            application_number: 1,
            application_version: 1,
            program_type: "ApplicationProgram".to_string(),
            mask_version: "MV-07B0".to_string(),
            name: "Test".to_string(),
            load_procedure_style: "MergedProcedure".to_string(),
            pei_type: 0,
            default_language: "en-US".to_string(),
            dynamic_table_management: false,
            linkable: false,
            min_ets_version: None,
            non_reg_relevant_data_version: None,
            replaces_versions: None,
            hash: None,
            static_section: StaticSection::default(),
            module_defs: None,
            dynamic: None,
        };
        DeviceModel::new(program)
    }
}
