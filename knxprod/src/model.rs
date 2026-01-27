//! Device Model for KNX ApplicationProgram Runtime
//!
//! This module provides a runtime model for KNX device configurations,
//! including parameter value management, condition evaluation for choose/when
//! blocks, and visibility computation.

use std::collections::{HashMap, HashSet};

use crate::schema::{
    ApplicationProgram, Channel, ChannelIndependentBlock, ChannelIndependentItem, ChannelItem,
    Choose, ComObject, ComObjectRef, DynamicSection, ParameterBlock, ParameterBlockItem,
    ParameterItem, ParameterRef, ParameterType, StaticSection, WhenItem,
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

/// Runtime model for a KNX device configuration.
///
/// This holds the parsed application program and tracks:
/// - Current parameter values
/// - Computed visibility states for parameters and objects
/// - Parameter type lookups
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

    /// Recompute visibility of all parameter refs and communication object refs
    /// based on current parameter values and choose/when conditions.
    pub fn recompute_visibility(&mut self) {
        self.visible_param_refs.clear();
        self.visible_com_object_refs.clear();

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
                ChannelItem::Module(_module) => {
                    // Module instances contain their own parameters/objects
                    // TODO: Expand module content when processing
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
            ParameterBlockItem::Module(_) => {
                // Module instances have their own visibility logic
            }
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
                WhenItem::Module(_module) => {
                    // Module instances contain their own parameters/objects
                    // TODO: Expand module content when processing
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
