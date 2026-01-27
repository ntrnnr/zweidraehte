//! KNX Module Definition DSL
//!
//! This module provides traits and types for defining reusable KNX modules.
//! Modules are templates that can be instantiated multiple times with different
//! argument values, allowing for efficient definition of repeating device structures
//! (e.g., multiple identical channels).
//!
//! # Overview
//!
//! A module in KNX is a reusable template containing:
//! - **Arguments**: Placeholders that get filled with concrete values on instantiation
//!   - `ParamOffsBase`: Base memory offset for parameters
//!   - `ObjNumberBase`: Base number for communication objects
//!   - `ChNo`: Channel number for display text substitution
//! - **Parameters**: User-configurable values (with offsets relative to ParamOffsBase)
//! - **Communication Objects**: Group objects (with numbers relative to ObjNumberBase)
//! - **UI Layout**: ETS page structure for the module's parameters
//!
//! # Example
//!
//! ```rust,ignore
//! use knxprod::module::{KnxModule, ModuleArgDef, ModuleInstance};
//! use zweidraehte::ets::{EtsParams, EtsComObjects};
//!
//! // Define parameters for a dimmer channel module
//! #[derive(EtsParams)]
//! #[repr(C)]
//! pub struct DimmerChannelParams {
//!     #[ets(display = "Enable channel")]
//!     pub enabled: u8,
//!     #[ets(display = "Dimming speed")]
//!     pub dim_speed: u8,
//! }
//!
//! // Define communication objects for the module
//! #[derive(EtsComObjects)]
//! pub struct DimmerChannelObjects {
//!     #[ets(index = 0, display = "Switch", function = "Switching")]
//!     pub switch: ComObj<Dpt1>,
//!     #[ets(index = 1, display = "Dimming", function = "Relative dimming")]
//!     pub dimming: ComObj<Dpt3>,
//!     #[ets(index = 2, display = "Value", function = "Absolute dimming")]
//!     pub value: ComObj<Dpt5>,
//! }
//!
//! // Define the module
//! pub struct DimmerChannelModule;
//!
//! impl KnxModule for DimmerChannelModule {
//!     const NAME: &'static str = "DimmerChannel";
//!
//!     const ARGUMENTS: &'static [ModuleArgDef] = &[
//!         ModuleArgDef::param_offset("ParamBase", 8),  // 8 bytes per channel
//!         ModuleArgDef::object_number("ObjBase", 3),   // 3 objects per channel
//!         ModuleArgDef::channel_number("ChNo"),        // Channel number for display
//!     ];
//!
//!     type Params = DimmerChannelParams;
//!     type Objects = DimmerChannelObjects;
//! }
//!
//! // Instantiate the module for 4 channels
//! let instances: Vec<ModuleInstance<DimmerChannelModule>> = (1..=4)
//!     .map(|ch| DimmerChannelModule::instance(ch, 100 + (ch - 1) * 8, 10 + (ch - 1) * 3))
//!     .collect();
//! ```
//!
//! # Text Templates
//!
//! Module text fields can use template placeholders:
//! - `{{ArgName}}` - Substitutes the value of an argument (e.g., `{{ChNo}}` → "1")
//! - `{{0}}` - Substitutes the value of a TextParameterRef parameter
//!
//! Example: `"F{{ChNo}} Switch: {{0}}"` might render as `"F1 Switch: Living Room"`

use std::marker::PhantomData;

// ============================================================================
// Module Argument Definitions
// ============================================================================

/// Definition of a module argument.
///
/// Arguments are placeholders that get substituted with actual values when
/// the module is instantiated. Common argument types include:
/// - Parameter offset base (for relative memory addressing)
/// - Object number base (for relative communication object numbering)
/// - Channel number (for display text substitution)
#[derive(Debug, Clone, Copy)]
pub struct ModuleArgDef {
    /// Name of the argument (e.g., "ParamOffsBase", "ObjNumberBase", "ChNo")
    pub name: &'static str,
    /// The amount of resources this argument allocates.
    /// For parameter offsets, this is the number of bytes per instance.
    /// For object numbers, this is the number of objects per instance.
    /// For display arguments like ChNo, this is typically 1.
    pub allocates: u32,
    /// Optional memory alignment (1, 2, 4, or 8 bytes).
    pub alignment: Option<u8>,
    /// Argument type: Numeric (default) or Text
    pub arg_type: ModuleArgType,
}

/// Type of module argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModuleArgType {
    /// Numeric argument (offsets, counts, channel numbers)
    #[default]
    Numeric,
    /// Text argument (for string substitution)
    Text,
}

impl ModuleArgDef {
    /// Create a parameter offset argument.
    ///
    /// This argument type is used for memory addressing - parameters within
    /// the module have their offset calculated as: `base_value + local_offset`.
    ///
    /// # Arguments
    /// * `name` - Argument name (e.g., "ParamOffsBase")
    /// * `bytes_per_instance` - Number of bytes this module's parameters occupy
    pub const fn param_offset(name: &'static str, bytes_per_instance: u32) -> Self {
        Self {
            name,
            allocates: bytes_per_instance,
            alignment: None,
            arg_type: ModuleArgType::Numeric,
        }
    }

    /// Create an object number argument.
    ///
    /// This argument type is used for communication object numbering - objects
    /// within the module have their number calculated as: `base_value + local_number`.
    ///
    /// # Arguments
    /// * `name` - Argument name (e.g., "ObjNumberBase")
    /// * `objects_per_instance` - Number of communication objects in this module
    pub const fn object_number(name: &'static str, objects_per_instance: u32) -> Self {
        Self {
            name,
            allocates: objects_per_instance,
            alignment: None,
            arg_type: ModuleArgType::Numeric,
        }
    }

    /// Create a channel number argument for display purposes.
    ///
    /// This argument is typically used in text templates like `"F{{ChNo}} Switch"`
    /// to show which channel an object belongs to.
    ///
    /// # Arguments
    /// * `name` - Argument name (e.g., "ChNo")
    pub const fn channel_number(name: &'static str) -> Self {
        Self {
            name,
            allocates: 1,
            alignment: None,
            arg_type: ModuleArgType::Numeric,
        }
    }

    /// Create a text argument for string substitution.
    ///
    /// # Arguments
    /// * `name` - Argument name
    /// * `max_length` - Maximum text length
    pub const fn text(name: &'static str, max_length: u32) -> Self {
        Self {
            name,
            allocates: max_length,
            alignment: None,
            arg_type: ModuleArgType::Text,
        }
    }

    /// Create a custom argument with explicit settings.
    pub const fn custom(
        name: &'static str,
        allocates: u32,
        alignment: Option<u8>,
        arg_type: ModuleArgType,
    ) -> Self {
        Self {
            name,
            allocates,
            alignment,
            arg_type,
        }
    }
}

// ============================================================================
// Module Trait
// ============================================================================

/// Trait for defining a KNX module template.
///
/// Implement this trait to define a reusable module that can be instantiated
/// multiple times with different argument values. The module contains parameter
/// definitions, communication object definitions, and optionally a page layout.
///
/// # Type Parameters
///
/// The associated types define what parameters and objects the module contains:
/// - `Params`: A struct deriving `EtsParams` with the module's parameters
/// - `Objects`: A struct deriving `EtsComObjects` with the module's communication objects
///
/// # Example
///
/// ```rust,ignore
/// impl KnxModule for DimmerChannelModule {
///     const NAME: &'static str = "DimmerChannel";
///     const ARGUMENTS: &'static [ModuleArgDef] = &[
///         ModuleArgDef::param_offset("ParamBase", 8),
///         ModuleArgDef::object_number("ObjBase", 3),
///         ModuleArgDef::channel_number("ChNo"),
///     ];
///     type Params = DimmerChannelParams;
///     type Objects = DimmerChannelObjects;
/// }
/// ```
pub trait KnxModule {
    /// Name of the module (used in XML ModuleDef/@Name)
    const NAME: &'static str;

    /// Argument definitions for this module
    const ARGUMENTS: &'static [ModuleArgDef];

    /// Parameter type - must implement the EtsParams derive traits.
    /// Access parameter definitions via `Params::ETS_PARAMS_EXT`.
    type Params;

    /// Communication objects type - must implement the EtsComObjects derive traits.
    /// Access object definitions via `Objects::ETS_COMM_OBJECTS`.
    type Objects;

    /// Optional internal description for the module
    const INTERNAL_DESCRIPTION: Option<&'static str> = None;

    /// Create a module instance with the given argument values.
    ///
    /// # Arguments
    /// * `args` - Argument values in the same order as `ARGUMENTS`
    ///
    /// # Panics
    /// Panics if the number of arguments doesn't match `ARGUMENTS.len()`
    fn instance(args: &[ModuleArgValue]) -> ModuleInstance<Self>
    where
        Self: Sized,
    {
        assert_eq!(
            args.len(),
            Self::ARGUMENTS.len(),
            "Expected {} arguments for module {}, got {}",
            Self::ARGUMENTS.len(),
            Self::NAME,
            args.len()
        );
        ModuleInstance {
            args: args.to_vec(),
            _phantom: PhantomData,
        }
    }

    /// Get the index of an argument by name.
    fn arg_index(name: &str) -> Option<usize> {
        Self::ARGUMENTS.iter().position(|a| a.name == name)
    }
}

// ============================================================================
// Module Argument Values
// ============================================================================

/// A concrete value for a module argument.
#[derive(Debug, Clone)]
pub enum ModuleArgValue {
    /// Numeric value (for offsets, counts, channel numbers)
    Numeric(i64),
    /// Text value (for string substitution)
    Text(String),
}

impl ModuleArgValue {
    /// Create a numeric argument value.
    pub const fn numeric(value: i64) -> Self {
        Self::Numeric(value)
    }

    /// Create a text argument value.
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// Get the numeric value, panicking if this is a text value.
    pub fn as_numeric(&self) -> i64 {
        match self {
            Self::Numeric(v) => *v,
            Self::Text(_) => panic!("Expected numeric argument, got text"),
        }
    }

    /// Get the text value, panicking if this is a numeric value.
    pub fn as_text(&self) -> &str {
        match self {
            Self::Text(v) => v,
            Self::Numeric(_) => panic!("Expected text argument, got numeric"),
        }
    }
}

impl From<i64> for ModuleArgValue {
    fn from(value: i64) -> Self {
        Self::Numeric(value)
    }
}

impl From<i32> for ModuleArgValue {
    fn from(value: i32) -> Self {
        Self::Numeric(value as i64)
    }
}

impl From<u32> for ModuleArgValue {
    fn from(value: u32) -> Self {
        Self::Numeric(value as i64)
    }
}

impl From<usize> for ModuleArgValue {
    fn from(value: usize) -> Self {
        Self::Numeric(value as i64)
    }
}

impl From<String> for ModuleArgValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for ModuleArgValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_string())
    }
}

// ============================================================================
// Module Instance
// ============================================================================

/// An instance of a module with concrete argument values.
///
/// Created by calling `KnxModule::instance()` with the argument values for
/// this specific instance. Multiple instances of the same module can exist
/// with different argument values.
///
/// # Example
///
/// ```rust,ignore
/// // Create instances for a 4-channel dimmer
/// let instances: Vec<ModuleInstance<DimmerChannelModule>> = (1..=4)
///     .map(|ch| {
///         DimmerChannelModule::instance(&[
///             ModuleArgValue::numeric(100 + (ch - 1) * 8),  // ParamBase
///             ModuleArgValue::numeric(10 + (ch - 1) * 3),   // ObjBase
///             ModuleArgValue::numeric(ch),                  // ChNo
///         ])
///     })
///     .collect();
/// ```
#[derive(Debug, Clone)]
pub struct ModuleInstance<M: KnxModule> {
    /// Argument values for this instance
    pub args: Vec<ModuleArgValue>,
    _phantom: PhantomData<M>,
}

impl<M: KnxModule> ModuleInstance<M> {
    /// Get the argument value by index.
    pub fn arg(&self, index: usize) -> &ModuleArgValue {
        &self.args[index]
    }

    /// Get a numeric argument value by index.
    pub fn numeric_arg(&self, index: usize) -> i64 {
        self.args[index].as_numeric()
    }

    /// Get a text argument value by index.
    pub fn text_arg(&self, index: usize) -> &str {
        self.args[index].as_text()
    }

    /// Get the argument value by name.
    pub fn arg_by_name(&self, name: &str) -> Option<&ModuleArgValue> {
        M::arg_index(name).map(|i| &self.args[i])
    }

    /// Get a numeric argument value by name.
    pub fn numeric_arg_by_name(&self, name: &str) -> Option<i64> {
        self.arg_by_name(name).map(|v| v.as_numeric())
    }

    /// Get a text argument value by name.
    pub fn text_arg_by_name(&self, name: &str) -> Option<&str> {
        self.arg_by_name(name).map(|v| v.as_text())
    }
}

// ============================================================================
// Module Instance Builder
// ============================================================================

/// Builder for creating multiple module instances with a pattern.
///
/// This provides a convenient way to create multiple instances of a module
/// where argument values follow a predictable pattern (e.g., sequential
/// channel numbers with calculated offsets).
///
/// # Example
///
/// ```rust,ignore
/// let instances = ModuleInstanceBuilder::<DimmerChannelModule>::new()
///     .for_range(1..=8, |ch| vec![
///         ModuleArgValue::numeric(100 + (ch - 1) * 8),  // ParamBase
///         ModuleArgValue::numeric(10 + (ch - 1) * 3),   // ObjBase
///         ModuleArgValue::numeric(ch),                  // ChNo
///     ])
///     .build();
/// ```
#[derive(Debug)]
pub struct ModuleInstanceBuilder<M: KnxModule> {
    instances: Vec<ModuleInstance<M>>,
}

impl<M: KnxModule> ModuleInstanceBuilder<M> {
    /// Create a new builder.
    pub fn new() -> Self {
        Self { instances: Vec::new() }
    }

    /// Add a single instance with the given arguments.
    pub fn add(mut self, args: Vec<ModuleArgValue>) -> Self {
        self.instances.push(M::instance(&args));
        self
    }

    /// Add instances for a range, using a function to compute arguments.
    ///
    /// # Arguments
    /// * `range` - Range of values to iterate over
    /// * `args_fn` - Function that takes the current value and returns argument values
    pub fn for_range<R, F>(mut self, range: R, args_fn: F) -> Self
    where
        R: IntoIterator<Item = i64>,
        F: Fn(i64) -> Vec<ModuleArgValue>,
    {
        for i in range {
            let args = args_fn(i);
            self.instances.push(M::instance(&args));
        }
        self
    }

    /// Build and return the list of instances.
    pub fn build(self) -> Vec<ModuleInstance<M>> {
        self.instances
    }
}

impl<M: KnxModule> Default for ModuleInstanceBuilder<M> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Conditional Module Instance
// ============================================================================

/// A module instance with an associated visibility condition.
///
/// Used when a module instance should only be shown in ETS when certain
/// parameter conditions are met.
#[derive(Debug, Clone)]
pub struct ConditionalModuleInstance<M: KnxModule> {
    /// The module instance
    pub instance: ModuleInstance<M>,
    /// Parameter name that controls visibility
    pub selector_param: String,
    /// Value(s) of the selector that make this instance visible
    pub selector_values: Vec<i64>,
}

impl<M: KnxModule> ConditionalModuleInstance<M> {
    /// Create a new conditional module instance.
    pub fn new(
        instance: ModuleInstance<M>,
        selector_param: impl Into<String>,
        selector_value: i64,
    ) -> Self {
        Self {
            instance,
            selector_param: selector_param.into(),
            selector_values: vec![selector_value],
        }
    }

    /// Create a conditional instance that's visible for multiple selector values.
    pub fn with_values(
        instance: ModuleInstance<M>,
        selector_param: impl Into<String>,
        selector_values: Vec<i64>,
    ) -> Self {
        Self {
            instance,
            selector_param: selector_param.into(),
            selector_values,
        }
    }
}

// ============================================================================
// Module Collection
// ============================================================================

/// Collection of module definitions and instances for a device.
///
/// This is the main structure used by the generator to produce the ModuleDefs
/// and Module elements in the XML output.
#[derive(Debug, Default)]
pub struct ModuleCollection {
    /// All module definitions used by this device
    definitions: Vec<StoredModuleDef>,
    /// All module instances
    instances: Vec<StoredModuleInstance>,
}

/// Stored module definition entry (internal representation).
#[derive(Debug, Clone)]
pub struct StoredModuleDef {
    /// Name of the module
    pub name: String,
    /// Argument definitions
    pub arguments: Vec<ModuleArgDef>,
    /// Optional internal description
    pub internal_description: Option<String>,
}

/// Stored module instance entry (internal representation).
#[derive(Debug, Clone)]
pub struct StoredModuleInstance {
    /// Index into definitions
    pub def_index: usize,
    /// Argument values
    pub args: Vec<ModuleArgValue>,
    /// Optional visibility condition (selector_param, selector_values)
    pub condition: Option<(String, Vec<i64>)>,
}

impl ModuleCollection {
    /// Create a new empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a module type and add instances.
    ///
    /// The module definition is automatically registered if not already present.
    pub fn add_instances<M: KnxModule>(&mut self, instances: Vec<ModuleInstance<M>>) {
        let def_index = self.ensure_definition::<M>();
        for instance in instances {
            self.instances.push(StoredModuleInstance {
                def_index,
                args: instance.args,
                condition: None,
            });
        }
    }

    /// Add conditional module instances.
    pub fn add_conditional_instances<M: KnxModule>(
        &mut self,
        instances: Vec<ConditionalModuleInstance<M>>,
    ) {
        let def_index = self.ensure_definition::<M>();
        for cond_instance in instances {
            self.instances.push(StoredModuleInstance {
                def_index,
                args: cond_instance.instance.args,
                condition: Some((cond_instance.selector_param, cond_instance.selector_values)),
            });
        }
    }

    /// Ensure a module definition is registered, returning its index.
    fn ensure_definition<M: KnxModule>(&mut self) -> usize {
        // Check if already registered
        if let Some(idx) = self.definitions.iter().position(|d| d.name == M::NAME) {
            return idx;
        }

        // Register new definition
        let idx = self.definitions.len();
        self.definitions.push(StoredModuleDef {
            name: M::NAME.to_string(),
            arguments: M::ARGUMENTS.to_vec(),
            internal_description: M::INTERNAL_DESCRIPTION.map(|s| s.to_string()),
        });
        idx
    }

    /// Get all module definitions.
    pub fn definitions(&self) -> &[StoredModuleDef] {
        &self.definitions
    }

    /// Get all module instances with their definitions.
    pub fn instances(&self) -> impl Iterator<Item = (&StoredModuleDef, &StoredModuleInstance)> {
        self.instances
            .iter()
            .map(|inst| (&self.definitions[inst.def_index], inst))
    }

    /// Get all module instances (raw).
    pub fn raw_instances(&self) -> &[StoredModuleInstance] {
        &self.instances
    }

    /// Check if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }

    /// Get the number of module definitions.
    pub fn definition_count(&self) -> usize {
        self.definitions.len()
    }

    /// Get the number of module instances.
    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Test module definition
    struct TestDimmerModule;

    impl KnxModule for TestDimmerModule {
        const NAME: &'static str = "TestDimmer";
        const ARGUMENTS: &'static [ModuleArgDef] = &[
            ModuleArgDef::param_offset("ParamBase", 8),
            ModuleArgDef::object_number("ObjBase", 3),
            ModuleArgDef::channel_number("ChNo"),
        ];
        type Params = ();
        type Objects = ();
    }

    #[test]
    fn test_module_arg_def_constructors() {
        let param_arg = ModuleArgDef::param_offset("ParamBase", 52);
        assert_eq!(param_arg.name, "ParamBase");
        assert_eq!(param_arg.allocates, 52);
        assert_eq!(param_arg.arg_type, ModuleArgType::Numeric);

        let obj_arg = ModuleArgDef::object_number("ObjBase", 6);
        assert_eq!(obj_arg.name, "ObjBase");
        assert_eq!(obj_arg.allocates, 6);

        let ch_arg = ModuleArgDef::channel_number("ChNo");
        assert_eq!(ch_arg.name, "ChNo");
        assert_eq!(ch_arg.allocates, 1);
    }

    #[test]
    fn test_module_instance_creation() {
        let instance = TestDimmerModule::instance(&[
            ModuleArgValue::numeric(100),
            ModuleArgValue::numeric(10),
            ModuleArgValue::numeric(1),
        ]);

        assert_eq!(instance.numeric_arg(0), 100);
        assert_eq!(instance.numeric_arg(1), 10);
        assert_eq!(instance.numeric_arg(2), 1);
    }

    #[test]
    fn test_module_instance_arg_by_name() {
        let instance = TestDimmerModule::instance(&[
            ModuleArgValue::numeric(100),
            ModuleArgValue::numeric(10),
            ModuleArgValue::numeric(1),
        ]);

        assert_eq!(instance.numeric_arg_by_name("ParamBase"), Some(100));
        assert_eq!(instance.numeric_arg_by_name("ObjBase"), Some(10));
        assert_eq!(instance.numeric_arg_by_name("ChNo"), Some(1));
        assert!(instance.arg_by_name("NonExistent").is_none());
    }

    #[test]
    fn test_module_instance_builder() {
        let instances = ModuleInstanceBuilder::<TestDimmerModule>::new()
            .for_range(1..=4, |ch| {
                vec![
                    ModuleArgValue::numeric(100 + (ch - 1) * 8),
                    ModuleArgValue::numeric(10 + (ch - 1) * 3),
                    ModuleArgValue::numeric(ch),
                ]
            })
            .build();

        assert_eq!(instances.len(), 4);

        // Check first instance
        assert_eq!(instances[0].numeric_arg(0), 100);
        assert_eq!(instances[0].numeric_arg(1), 10);
        assert_eq!(instances[0].numeric_arg(2), 1);

        // Check last instance
        assert_eq!(instances[3].numeric_arg(0), 124); // 100 + 3*8
        assert_eq!(instances[3].numeric_arg(1), 19);  // 10 + 3*3
        assert_eq!(instances[3].numeric_arg(2), 4);
    }

    #[test]
    fn test_module_collection() {
        let mut collection = ModuleCollection::new();

        let instances = ModuleInstanceBuilder::<TestDimmerModule>::new()
            .for_range(1..=2, |ch| {
                vec![
                    ModuleArgValue::numeric(100 + (ch - 1) * 8),
                    ModuleArgValue::numeric(10 + (ch - 1) * 3),
                    ModuleArgValue::numeric(ch),
                ]
            })
            .build();

        collection.add_instances(instances);

        assert_eq!(collection.definition_count(), 1);
        assert_eq!(collection.instance_count(), 2);
    }

    #[test]
    fn test_conditional_module_instance() {
        let instance = TestDimmerModule::instance(&[
            ModuleArgValue::numeric(100),
            ModuleArgValue::numeric(10),
            ModuleArgValue::numeric(1),
        ]);

        let cond = ConditionalModuleInstance::new(instance, "EnableChannel", 1);
        assert_eq!(cond.selector_param, "EnableChannel");
        assert_eq!(cond.selector_values, vec![1]);
    }
}
