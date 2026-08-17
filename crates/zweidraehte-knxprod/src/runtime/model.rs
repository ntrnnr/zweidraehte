//! Device Model for KNX ApplicationProgram Runtime
//!
//! This module provides a runtime model for KNX device configurations,
//! including parameter value management, condition evaluation for choose/when
//! blocks, and visibility computation.

use std::collections::{HashMap, HashSet};

use crate::schema::{
    Channel, ChannelIndependentBlock, ChannelIndependentItem, ChannelItem, Choose, DynamicSection, Module, ModuleDef,
    ModuleDefDynamicItem, ParameterBlock, ParameterBlockItem, ParameterBlockRename, WhenItem,
};

/// Represents a KNX choose/when condition test.
///
/// Test formats supported:
/// - `Eq(values)` - equals any of the values (from "1" or "1 2 3")
/// - `NotEq(value)` - not equals (from "!=0")
/// - `GreaterThan(value)` - from ">5"
/// - `LessThan(value)` - from "<10"
/// - `GreaterOrEq(value)` - from ">=5"
/// - `LessOrEq(value)` - from "<=10"
#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    /// Value equals any of the specified values
    Eq(Vec<i64>),
    /// Value does not equal the specified value
    NotEq(i64),
    /// Value is greater than the specified value
    GreaterThan(i64),
    /// Value is less than the specified value
    LessThan(i64),
    /// Value is greater than or equal to the specified value
    GreaterOrEq(i64),
    /// Value is less than or equal to the specified value
    LessOrEq(i64),
}

impl Condition {
    /// Parse a condition from a KNX test string.
    ///
    /// Returns `None` if the string cannot be parsed as a valid condition.
    pub fn parse(test: &str) -> Option<Self> {
        let test = test.trim();

        // Handle comparison operators (check multi-char operators first)
        if let Some(rest) = test.strip_prefix("!=") {
            return rest.trim().parse().ok().map(Condition::NotEq);
        }
        if let Some(rest) = test.strip_prefix(">=") {
            return rest.trim().parse().ok().map(Condition::GreaterOrEq);
        }
        if let Some(rest) = test.strip_prefix("<=") {
            return rest.trim().parse().ok().map(Condition::LessOrEq);
        }
        if let Some(rest) = test.strip_prefix('>') {
            return rest.trim().parse().ok().map(Condition::GreaterThan);
        }
        if let Some(rest) = test.strip_prefix('<') {
            return rest.trim().parse().ok().map(Condition::LessThan);
        }
        if let Some(rest) = test.strip_prefix('=') {
            return rest.trim().parse().ok().map(|v| Condition::Eq(vec![v]));
        }

        // Handle space-separated list of values (OR)
        let values: Vec<i64> = test.split_whitespace().filter_map(|s| s.parse().ok()).collect();

        if values.is_empty() { None } else { Some(Condition::Eq(values)) }
    }

    /// Check if a value matches this condition.
    pub fn matches(&self, value: i64) -> bool {
        match self {
            Condition::Eq(values) => values.contains(&value),
            Condition::NotEq(v) => value != *v,
            Condition::GreaterThan(v) => value > *v,
            Condition::LessThan(v) => value < *v,
            Condition::GreaterOrEq(v) => value >= *v,
            Condition::LessOrEq(v) => value <= *v,
        }
    }
}

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
        Self { main: ((val >> 11) & 0x1f) as u8, middle: ((val >> 8) & 0x07) as u8, sub: (val & 0xff) as u8 }
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
    /// Whether visible but not user-writable (Access = "Read"). A
    /// `ParameterRef` may override this per placement in either direction.
    pub read_only: bool,
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

// ============================================================================
// Dynamic Section Visitor Pattern
// ============================================================================

/// Visitor for traversing dynamic section elements.
///
/// The traversal walks through channels, parameter blocks, choose/when conditions,
/// and module instances. Implement only the methods you need - all have default
/// no-op implementations.
///
/// # Example
///
/// ```rust,ignore
/// struct VisibilityCollector {
///     visible_params: HashSet<String>,
/// }
///
/// impl DynamicVisitor for VisibilityCollector {
///     fn visit_param_ref(&mut self, ref_id: &str, _module_ctx: Option<&VisitorModuleContext>) {
///         self.visible_params.insert(ref_id.to_string());
///     }
/// }
/// ```
pub trait DynamicVisitor {
    /// Called when visiting a parameter ref reference.
    fn visit_param_ref(&mut self, _ref_id: &str, _module_ctx: Option<&VisitorModuleContext>) {}

    /// Called when visiting a communication object ref reference.
    fn visit_com_object_ref(&mut self, _ref_id: &str, _module_ctx: Option<&VisitorModuleContext>) {}

    /// Called when visiting a block rename. The walker only reaches
    /// it inside an *active* branch, so a visited rename is in force:
    /// the referenced `ParameterBlock` displays the rename's text.
    fn visit_block_rename(&mut self, _rename: &ParameterBlockRename, _module_ctx: Option<&VisitorModuleContext>) {}

    /// Called when visiting a module instance (before entering its content).
    fn visit_module(&mut self, _module: &Module) {}

    /// Called when entering a module's internal content.
    ///
    /// This is called after `visit_module` when the walker is about to traverse
    /// the module definition's dynamic section. Tree builders can use this to
    /// push the module onto their stack.
    fn enter_module(&mut self, _module: &Module, _ctx: &VisitorModuleContext) {}

    /// Called when leaving a module's internal content.
    ///
    /// This is called after the module's dynamic section has been fully traversed.
    fn leave_module(&mut self, _module: &Module, _ctx: &VisitorModuleContext) {}

    /// Called when entering a parameter block.
    fn enter_parameter_block(&mut self, _block: &ParameterBlock) {}

    /// Called when leaving a parameter block.
    fn leave_parameter_block(&mut self, _block: &ParameterBlock) {}

    /// Called when entering a choose block (before condition evaluation).
    fn enter_choose(&mut self, _choose: &Choose) {}

    /// Called when leaving a choose block.
    fn leave_choose(&mut self, _choose: &Choose) {}

    /// Called when entering a channel.
    fn enter_channel(&mut self, _channel: &Channel) {}

    /// Called when leaving a channel.
    fn leave_channel(&mut self, _channel: &Channel) {}

    /// Called when entering a channel-independent block.
    fn enter_channel_independent_block(&mut self, _block: &ChannelIndependentBlock) {}

    /// Called when leaving a channel-independent block.
    fn leave_channel_independent_block(&mut self, _block: &ChannelIndependentBlock) {}

    /// Called for parameter separators.
    fn visit_separator(&mut self, _id: Option<&str>, _text: Option<&str>) {}
}

/// Context for condition evaluation during traversal.
///
/// Implement this trait to provide parameter values for choose/when condition
/// evaluation during the walk.
pub trait ConditionEvaluator {
    /// Get selector value for a parameter ref (for choose/when evaluation).
    ///
    /// Returns `None` if the parameter doesn't exist or has no value.
    fn get_selector_value(&self, param_ref_id: &str) -> Option<i64>;

    /// Get selector value with module context.
    ///
    /// For module-internal parameter refs, the module context provides
    /// the instance ID for proper value lookup.
    fn get_selector_value_with_module(
        &self,
        param_ref_id: &str,
        module_ctx: Option<&VisitorModuleContext>,
    ) -> Option<i64>;
}

/// Module context passed to visitors during module traversal.
#[derive(Debug, Clone)]
pub struct VisitorModuleContext<'a> {
    /// The module instance ID
    pub instance_id: &'a str,
    /// The module definition
    pub module_def: &'a ModuleDef,
    /// The module instance
    pub module_instance: &'a Module,
}

/// Walk the dynamic section with a visitor.
///
/// This function traverses the entire dynamic section structure, calling
/// visitor methods at appropriate points. Condition evaluation is performed
/// using the provided `ConditionEvaluator` to determine which `when` branches
/// are active.
pub fn walk_dynamic<V, E>(
    dynamic: &DynamicSection,
    visitor: &mut V,
    evaluator: &E,
    module_defs: &HashMap<String, ModuleDef>,
) where
    V: DynamicVisitor,
    E: ConditionEvaluator,
{
    // Walk channel-independent block
    if let Some(cib) = &dynamic.channel_independent_block {
        visitor.enter_channel_independent_block(cib);
        walk_channel_independent_block(cib, visitor, evaluator, module_defs, None);
        visitor.leave_channel_independent_block(cib);
    }

    // Walk channels
    for channel in &dynamic.channels {
        visitor.enter_channel(channel);
        walk_channel(channel, visitor, evaluator, module_defs);
        visitor.leave_channel(channel);
    }
}

fn walk_channel_independent_block<V, E>(
    cib: &ChannelIndependentBlock,
    visitor: &mut V,
    evaluator: &E,
    module_defs: &HashMap<String, ModuleDef>,
    module_ctx: Option<&VisitorModuleContext>,
) where
    V: DynamicVisitor,
    E: ConditionEvaluator,
{
    for item in &cib.items {
        match item {
            ChannelIndependentItem::ParameterBlockRename(rename) => {
                visitor.visit_block_rename(rename, module_ctx);
            }
            ChannelIndependentItem::ParameterBlock(pb) => {
                walk_parameter_block(pb, visitor, evaluator, module_defs, module_ctx);
            }
            ChannelIndependentItem::Choose(choose) => {
                walk_choose(choose, visitor, evaluator, module_defs, module_ctx);
            }
        }
    }
}

fn walk_channel<V, E>(channel: &Channel, visitor: &mut V, evaluator: &E, module_defs: &HashMap<String, ModuleDef>)
where
    V: DynamicVisitor,
    E: ConditionEvaluator,
{
    for item in &channel.items {
        match item {
            ChannelItem::ParameterBlockRename(rename) => {
                visitor.visit_block_rename(rename, None);
            }
            ChannelItem::ParameterBlock(pb) => {
                walk_parameter_block(pb, visitor, evaluator, module_defs, None);
            }
            ChannelItem::Choose(choose) => {
                walk_choose(choose, visitor, evaluator, module_defs, None);
            }
            ChannelItem::Module(module) => {
                walk_module(module, visitor, evaluator, module_defs);
            }
        }
    }
}

fn walk_parameter_block<V, E>(
    block: &ParameterBlock,
    visitor: &mut V,
    evaluator: &E,
    module_defs: &HashMap<String, ModuleDef>,
    module_ctx: Option<&VisitorModuleContext>,
) where
    V: DynamicVisitor,
    E: ConditionEvaluator,
{
    visitor.enter_parameter_block(block);

    for item in &block.items {
        match item {
            ParameterBlockItem::ParameterBlockRename(rename) => {
                visitor.visit_block_rename(rename, module_ctx);
            }
            ParameterBlockItem::ParameterRefRef(prr) => {
                visitor.visit_param_ref(&prr.ref_id, module_ctx);
            }
            ParameterBlockItem::ComObjectRefRef(corr) => {
                visitor.visit_com_object_ref(&corr.ref_id, module_ctx);
            }
            ParameterBlockItem::Choose(choose) => {
                walk_choose(choose, visitor, evaluator, module_defs, module_ctx);
            }
            ParameterBlockItem::Module(module) => {
                walk_module(module, visitor, evaluator, module_defs);
            }
            ParameterBlockItem::ParameterSeparator(sep) => {
                visitor.visit_separator(Some(&sep.id), sep.text.as_deref());
            }
            // Button, Rows, Columns are UI elements that don't affect visibility
            ParameterBlockItem::Button(_) | ParameterBlockItem::Rows(_) | ParameterBlockItem::Columns(_) => {}
        }
    }

    visitor.leave_parameter_block(block);
}

fn walk_choose<V, E>(
    choose: &Choose,
    visitor: &mut V,
    evaluator: &E,
    module_defs: &HashMap<String, ModuleDef>,
    module_ctx: Option<&VisitorModuleContext>,
) where
    V: DynamicVisitor,
    E: ConditionEvaluator,
{
    visitor.enter_choose(choose);

    let selector_value = evaluator.get_selector_value_with_module(&choose.param_ref_id, module_ctx);

    // Find matching when clauses (multiple can match!)
    let mut any_matched = false;
    for when in &choose.whens {
        if when.default.unwrap_or(false) {
            continue;
        }
        if let Some(test) = &when.test
            && let Some(condition) = Condition::parse(test)
            && selector_value.is_some_and(|v| condition.matches(v))
        {
            walk_when_items(&when.items, visitor, evaluator, module_defs, module_ctx);
            any_matched = true;
        }
    }

    // Process default if nothing matched
    if !any_matched {
        for when in &choose.whens {
            if when.default.unwrap_or(false) {
                walk_when_items(&when.items, visitor, evaluator, module_defs, module_ctx);
                break;
            }
        }
    }

    visitor.leave_choose(choose);
}

fn walk_when_items<V, E>(
    items: &[WhenItem],
    visitor: &mut V,
    evaluator: &E,
    module_defs: &HashMap<String, ModuleDef>,
    module_ctx: Option<&VisitorModuleContext>,
) where
    V: DynamicVisitor,
    E: ConditionEvaluator,
{
    for item in items {
        match item {
            WhenItem::ParameterBlockRename(rename) => {
                visitor.visit_block_rename(rename, module_ctx);
            }
            WhenItem::ParameterRefRef(prr) => {
                visitor.visit_param_ref(&prr.ref_id, module_ctx);
            }
            WhenItem::ComObjectRefRef(corr) => {
                visitor.visit_com_object_ref(&corr.ref_id, module_ctx);
            }
            WhenItem::ParameterBlock(pb) => {
                walk_parameter_block(pb, visitor, evaluator, module_defs, module_ctx);
            }
            WhenItem::Choose(nested) => {
                walk_choose(nested, visitor, evaluator, module_defs, module_ctx);
            }
            WhenItem::Module(module) => {
                walk_module(module, visitor, evaluator, module_defs);
            }
            WhenItem::ParameterSeparator(sep) => {
                visitor.visit_separator(Some(&sep.id), sep.text.as_deref());
            }
            // Assign elements are runtime operations, not structural
            WhenItem::Assign(_) => {}
        }
    }
}

fn walk_module<V, E>(module: &Module, visitor: &mut V, evaluator: &E, module_defs: &HashMap<String, ModuleDef>)
where
    V: DynamicVisitor,
    E: ConditionEvaluator,
{
    visitor.visit_module(module);

    // If we have the module definition, walk its dynamic section too
    if let Some(module_def) = module_defs.get(&module.ref_id) {
        let ctx = VisitorModuleContext { instance_id: &module.id, module_def, module_instance: module };

        if let Some(dynamic) = &module_def.dynamic {
            visitor.enter_module(module, &ctx);
            walk_module_dynamic(dynamic, visitor, evaluator, module_defs, &ctx);
            visitor.leave_module(module, &ctx);
        }
    }
}

fn walk_module_dynamic<V, E>(
    dynamic: &crate::schema::ModuleDefDynamic,
    visitor: &mut V,
    evaluator: &E,
    module_defs: &HashMap<String, ModuleDef>,
    module_ctx: &VisitorModuleContext,
) where
    V: DynamicVisitor,
    E: ConditionEvaluator,
{
    for item in &dynamic.items {
        match item {
            ModuleDefDynamicItem::ParameterBlock(pb) => {
                walk_parameter_block(pb, visitor, evaluator, module_defs, Some(module_ctx));
            }
            ModuleDefDynamicItem::Choose(choose) => {
                walk_choose(choose, visitor, evaluator, module_defs, Some(module_ctx));
            }
        }
    }
}

// ============================================================================
// Visibility Visitor Implementation
// ============================================================================

/// A visitor that collects visible parameter refs, com object refs, and modules.
///
/// Use this with `walk_dynamic` to compute visibility based on current parameter values.
///
/// # Example
///
/// ```rust,ignore
/// let mut visitor = VisibilityVisitor::new();
/// walk_dynamic(&program.dynamic.unwrap(), &mut visitor, &evaluator, &module_defs);
///
/// // Now visitor contains all visible refs
/// for param_ref_id in visitor.visible_param_refs() {
///     println!("Visible: {}", param_ref_id);
/// }
/// ```
#[derive(Debug, Default)]
pub struct VisibilityVisitor {
    visible_param_refs: HashSet<String>,
    visible_com_object_refs: HashSet<String>,
    visible_modules: HashSet<String>,
    /// Module-scoped param refs (keyed as "instance_id::param_ref_id")
    visible_module_param_refs: HashSet<String>,
    /// Module-scoped com object refs (keyed as "instance_id::com_obj_ref_id")
    visible_module_com_object_refs: HashSet<String>,
}

impl VisibilityVisitor {
    /// Create a new empty visibility visitor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the set of visible parameter refs (device-level).
    pub fn visible_param_refs(&self) -> &HashSet<String> {
        &self.visible_param_refs
    }

    /// Get the set of visible com object refs (device-level).
    pub fn visible_com_object_refs(&self) -> &HashSet<String> {
        &self.visible_com_object_refs
    }

    /// Get the set of visible module instance IDs.
    pub fn visible_modules(&self) -> &HashSet<String> {
        &self.visible_modules
    }

    /// Get the set of visible module-scoped param refs.
    ///
    /// Keys are in the format "instance_id::param_ref_id".
    pub fn visible_module_param_refs(&self) -> &HashSet<String> {
        &self.visible_module_param_refs
    }

    /// Get the set of visible module-scoped com object refs.
    ///
    /// Keys are in the format "instance_id::com_obj_ref_id".
    pub fn visible_module_com_object_refs(&self) -> &HashSet<String> {
        &self.visible_module_com_object_refs
    }

    /// Check if a device-level parameter ref is visible.
    pub fn is_param_ref_visible(&self, ref_id: &str) -> bool {
        self.visible_param_refs.contains(ref_id)
    }

    /// Check if a device-level com object ref is visible.
    pub fn is_com_object_ref_visible(&self, ref_id: &str) -> bool {
        self.visible_com_object_refs.contains(ref_id)
    }

    /// Check if a module instance is visible.
    pub fn is_module_visible(&self, instance_id: &str) -> bool {
        self.visible_modules.contains(instance_id)
    }

    /// Check if a module-scoped parameter ref is visible.
    pub fn is_module_param_ref_visible(&self, instance_id: &str, param_ref_id: &str) -> bool {
        self.visible_module_param_refs.contains(&format!("{}::{}", instance_id, param_ref_id))
    }

    /// Check if a module-scoped com object ref is visible.
    pub fn is_module_com_object_ref_visible(&self, instance_id: &str, com_obj_ref_id: &str) -> bool {
        self.visible_module_com_object_refs.contains(&format!("{}::{}", instance_id, com_obj_ref_id))
    }

    /// Take ownership of collected visibility sets, consuming the visitor.
    pub fn into_parts(self) -> (HashSet<String>, HashSet<String>, HashSet<String>, HashSet<String>, HashSet<String>) {
        (
            self.visible_param_refs,
            self.visible_com_object_refs,
            self.visible_modules,
            self.visible_module_param_refs,
            self.visible_module_com_object_refs,
        )
    }
}

impl DynamicVisitor for VisibilityVisitor {
    fn visit_param_ref(&mut self, ref_id: &str, module_ctx: Option<&VisitorModuleContext>) {
        if let Some(ctx) = module_ctx {
            self.visible_module_param_refs.insert(format!("{}::{}", ctx.instance_id, ref_id));
        } else {
            self.visible_param_refs.insert(ref_id.to_string());
        }
    }

    fn visit_com_object_ref(&mut self, ref_id: &str, module_ctx: Option<&VisitorModuleContext>) {
        if let Some(ctx) = module_ctx {
            self.visible_module_com_object_refs.insert(format!("{}::{}", ctx.instance_id, ref_id));
        } else {
            self.visible_com_object_refs.insert(ref_id.to_string());
        }
    }

    fn visit_module(&mut self, module: &Module) {
        self.visible_modules.insert(module.id.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to test condition matching.
    fn matches(value: Option<i64>, test: &str) -> bool {
        match (value, Condition::parse(test)) {
            (Some(v), Some(cond)) => cond.matches(v),
            _ => false,
        }
    }

    #[test]
    fn test_condition_matching() {
        // Test simple equality
        assert!(matches(Some(1), "1"));
        assert!(!matches(Some(2), "1"));

        // Test space-separated values (OR)
        assert!(matches(Some(1), "1 2 3"));
        assert!(matches(Some(2), "1 2 3"));
        assert!(matches(Some(3), "1 2 3"));
        assert!(!matches(Some(4), "1 2 3"));

        // Test comparison operators
        assert!(matches(Some(5), "=5"));
        assert!(!matches(Some(4), "=5"));

        assert!(matches(Some(4), "!=5"));
        assert!(!matches(Some(5), "!=5"));

        assert!(matches(Some(6), ">5"));
        assert!(!matches(Some(5), ">5"));

        assert!(matches(Some(4), "<5"));
        assert!(!matches(Some(5), "<5"));

        assert!(matches(Some(5), ">=5"));
        assert!(matches(Some(6), ">=5"));
        assert!(!matches(Some(4), ">=5"));

        assert!(matches(Some(5), "<=5"));
        assert!(matches(Some(4), "<=5"));
        assert!(!matches(Some(6), "<=5"));

        // Test None value
        assert!(!matches(None, "1"));
    }
}
