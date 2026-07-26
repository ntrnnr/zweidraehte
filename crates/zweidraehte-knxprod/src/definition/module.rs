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
//! use zweidraehte_knxprod::definition::module::{KnxModule, ModuleArgDef, ModuleInstance};
//! use zweidraehte_device::ets::{EtsParams, EtsComObjects};
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
//!         ModuleArgDef::param_offset("ParamBase"),
//!         ModuleArgDef::object_number("ObjBase"),
//!         ModuleArgDef::display("ChNo", 1),  // For {{ChNo}} in text templates
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
    /// Role of this argument - determines how it's used in XML generation.
    /// Set automatically by constructor methods.
    pub role: ModuleArgRole,
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

/// Role of a module argument - determines how it's used in XML generation.
///
/// The role is automatically set by the constructor methods:
/// - `param_offset()` → `ParamOffset`
/// - `object_number()` → `ObjectNumber`
/// - `value_base()` → `ValueBase`
/// - `custom()` / `text()` / `display()` → `Custom`
///
/// The generator uses roles to:
/// - Compute `Allocates` from MODULE_PARAMS/MODULE_COMM_OBJECTS
/// - Generate `BaseOffset` attributes on Memory elements
/// - Generate `BaseNumber` attributes on ComObject elements
/// - Generate `BaseValue` attributes on Parameter elements
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModuleArgRole {
    /// Used for Memory/@BaseOffset - parameter memory addressing.
    /// Allocates is computed from MODULE_PARAMS total size.
    ParamOffset,
    /// Used for ComObject/@BaseNumber - object numbering.
    /// Allocates is computed from MODULE_COMM_OBJECTS length.
    ObjectNumber,
    /// Used for Parameter/@BaseValue - relative parameter values
    ValueBase,
    /// Generic argument without special handling
    #[default]
    Custom,
}

impl ModuleArgDef {
    /// Create a parameter offset argument.
    ///
    /// This argument type is used for memory addressing - parameters within
    /// the module have their offset calculated as: `base_value + local_offset`.
    ///
    /// The `Allocates` value in the generated XML is automatically computed from
    /// the total size of `MODULE_PARAMS`. You don't need to specify it manually.
    ///
    /// # Arguments
    /// * `name` - Argument name (e.g., "ParamOffsBase")
    pub const fn param_offset(name: &'static str) -> Self {
        Self {
            name,
            allocates: 0, // Computed from MODULE_PARAMS by generator
            alignment: None,
            arg_type: ModuleArgType::Numeric,
            role: ModuleArgRole::ParamOffset,
        }
    }

    /// Create an object number argument.
    ///
    /// This argument type is used for communication object numbering - objects
    /// within the module have their number calculated as: `base_value + local_number`.
    ///
    /// The `Allocates` value in the generated XML is automatically computed from
    /// the length of `MODULE_COMM_OBJECTS`. You don't need to specify it manually.
    ///
    /// # Arguments
    /// * `name` - Argument name (e.g., "ObjNumberBase")
    pub const fn object_number(name: &'static str) -> Self {
        Self {
            name,
            allocates: 0, // Computed from MODULE_COMM_OBJECTS by generator
            alignment: None,
            arg_type: ModuleArgType::Numeric,
            role: ModuleArgRole::ObjectNumber,
        }
    }

    /// Create a display argument for text template substitution.
    ///
    /// This argument is used in text templates like `"F{{ChNo}} Switch"`.
    /// ETS substitutes `{{ArgName}}` with the argument's value.
    /// The name must match what you use in text templates.
    ///
    /// # Arguments
    /// * `name` - Argument name (e.g., "ChNo" for `{{ChNo}}`)
    /// * `allocates` - Number of values this argument consumes per instance
    pub const fn display(name: &'static str, allocates: u32) -> Self {
        Self { name, allocates, alignment: None, arg_type: ModuleArgType::Numeric, role: ModuleArgRole::Custom }
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
            role: ModuleArgRole::Custom,
        }
    }

    /// Create a custom argument with explicit settings.
    pub const fn custom(name: &'static str, allocates: u32, alignment: Option<u8>, arg_type: ModuleArgType) -> Self {
        Self { name, allocates, alignment, arg_type, role: ModuleArgRole::Custom }
    }

    /// Create a value base argument for relative parameter values.
    ///
    /// This argument type is used when parameter values need to be offset based on
    /// instance number. For example, when parameters reference sequential indices
    /// or object numbers that vary per instance.
    ///
    /// # Arguments
    /// * `name` - Argument name (e.g., "ValueBase")
    /// * `values_per_instance` - Number of sequential values this instance consumes
    pub const fn value_base(name: &'static str, values_per_instance: u32) -> Self {
        Self {
            name,
            allocates: values_per_instance,
            alignment: None,
            arg_type: ModuleArgType::Numeric,
            role: ModuleArgRole::ValueBase,
        }
    }

    /// Find the index of an argument with the given role in an argument slice.
    ///
    /// Returns the first argument matching the role, or `None` if no match.
    pub fn find_by_role(args: &[ModuleArgDef], role: ModuleArgRole) -> Option<usize> {
        args.iter().position(|a| a.role == role)
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
///         ModuleArgDef::param_offset("ParamBase"),
///         ModuleArgDef::object_number("ObjBase"),
///         ModuleArgDef::display("ChNo", 1),
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

    /// Parameter type - must derive `EtsParams`.
    ///
    /// This type provides module parameter definitions via the `HasModuleParams` trait
    /// which is automatically implemented by `#[derive(EtsParams)]`.
    type Params: zweidraehte_device::ets::HasModuleParams;

    /// Communication objects type - must derive `EtsComObjects`.
    ///
    /// This type provides communication object definitions via the `HasModuleCommObjects`
    /// trait which is automatically implemented by `#[derive(EtsComObjects)]`.
    type Objects: zweidraehte_device::ets::HasModuleCommObjects;

    /// Optional internal description for the module
    const INTERNAL_DESCRIPTION: Option<&'static str> = None;

    /// Parameter definitions for the module.
    ///
    /// **Default implementation**: Automatically uses `<Self::Params as HasModuleParams>::ETS_PARAMS_EXT`.
    ///
    /// Override only if you need different behavior (e.g., to return `None` for no params).
    const MODULE_PARAMS: Option<&'static [zweidraehte_device::ets::EtsParamDefExt]> =
        Some(<Self::Params as zweidraehte_device::ets::HasModuleParams>::ETS_PARAMS_EXT);

    /// Virtual parameter definitions for the module.
    ///
    /// Virtual parameters exist only in ETS for text substitution (e.g., `{{0}}` templates)
    /// and are NOT stored in device memory. They have `no_memory: true` in their definition.
    ///
    /// **Default implementation**: Returns `None` (no virtual params).
    ///
    /// Override this to provide virtual parameters like channel names that appear in ETS
    /// UI but don't consume device memory.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// const VIRTUAL_PARAMS: Option<&'static [EtsParamDefExt]> = Some(&[
    ///     EtsParamDefExt {
    ///         base: EtsParamDef {
    ///             name: "channel_name",
    ///             display_name: "Channel name",
    ///             no_memory: true,  // Virtual - no device memory
    ///             // ... other fields
    ///         },
    ///         is_text_source: true,  // Used for {{0}} substitution
    ///         // ...
    ///     },
    /// ]);
    /// ```
    const VIRTUAL_PARAMS: Option<&'static [zweidraehte_device::ets::EtsParamDefExt]> = None;

    /// Communication object definitions for the module.
    ///
    /// **Default implementation**: Automatically uses `<Self::Objects as HasModuleCommObjects>::ETS_COMM_OBJECTS`.
    ///
    /// Override only if you need different behavior (e.g., to return `None` for no objects).
    const MODULE_COMM_OBJECTS: Option<&'static [zweidraehte_device::ets::EtsCommObjectDef]> =
        Some(<Self::Objects as zweidraehte_device::ets::HasModuleCommObjects>::ETS_COMM_OBJECTS);

    /// Custom page layout for the module's `<Dynamic>` section.
    ///
    /// **Default implementation**: Returns `None`, which causes the generator to create
    /// a simple layout with all parameters and comm objects in a single ParameterBlock.
    ///
    /// Override this method to define custom conditional visibility using `choose/when`
    /// blocks, multiple parameter blocks, separators, etc.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// fn module_layout() -> Option<ModulePageLayout> {
    ///     Some(ets_module_pages! {
    ///         block "basic" => "{{ChNo}}: Basic Settings" {
    ///             param channel_name
    ///             param min_brightness
    ///             sep "Communication Objects"
    ///             obj switch_obj
    ///         }
    ///         when @dim_mode {
    ///             [1] => {
    ///                 param fade_time
    ///             }
    ///         }
    ///     })
    /// }
    /// ```
    fn module_layout() -> Option<crate::definition::page_layout::ModulePageLayout> {
        None
    }

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
        ModuleInstance { args: args.to_vec(), _phantom: PhantomData }
    }

    /// Get the index of an argument by name.
    fn arg_index(name: &str) -> Option<usize> {
        Self::ARGUMENTS.iter().position(|a| a.name == name)
    }

    /// Get the index of an argument by role.
    ///
    /// Looks up arguments by their `ModuleArgRole`, which is automatically
    /// set by constructor methods like `param_offset()`, `object_number()`, etc.
    fn arg_index_by_role(role: ModuleArgRole) -> Option<usize> {
        ModuleArgDef::find_by_role(Self::ARGUMENTS, role)
    }
}

/// Validate that provided argument names match the module's expected arguments.
///
/// This is a const function that can be used at compile time to validate
/// module arguments in the `ets_pages!` macro.
///
/// # Arguments
/// * `module_args` - The module's ARGUMENTS constant
/// * `provided_names` - The argument names provided in the macro invocation
///
/// # Panics
/// Panics with a descriptive message if:
/// - The number of arguments doesn't match
/// - Any argument name doesn't match the expected name at that position
pub const fn validate_module_args(module_args: &[ModuleArgDef], provided_names: &[&str]) {
    // First check count
    if provided_names.len() != module_args.len() {
        panic!("Wrong number of arguments for module");
    }

    // Check each argument name matches the expected name at that position
    let mut i = 0;
    while i < provided_names.len() {
        let provided_name = provided_names[i];
        let expected_name = module_args[i].name;

        // Compare strings byte by byte (const-compatible)
        let provided_bytes = provided_name.as_bytes();
        let expected_bytes = expected_name.as_bytes();

        if provided_bytes.len() != expected_bytes.len() {
            panic!("Module argument name mismatch - check argument names and order");
        }

        let mut j = 0;
        while j < provided_bytes.len() {
            if provided_bytes[j] != expected_bytes[j] {
                panic!("Module argument name mismatch - check argument names and order");
            }
            j += 1;
        }

        i += 1;
    }
}

/// Trait for device parameter types that have module channel helpers.
///
/// This trait is automatically used when you have a `#[ets(module = ...)]` field
/// in your params struct. It provides the interface needed by `module_instances()`
/// to generate module instance page items.
pub trait HasChannelHelpers<M: KnxModule> {
    /// Number of channel/module instances
    const COUNT: usize;

    /// Compute parameter offset for instance N (1-indexed)
    fn param_offset(instance: usize) -> usize;

    /// Compute first object index for instance N (1-indexed)
    fn object_base(instance: usize) -> usize;
}

/// Create a `PageItem::ModuleInstances` for multi-channel modules.
///
/// This helper generates all module instances with proper argument values
/// computed from the device params helpers, along with visibility selectors.
///
/// # Type Parameters
/// - `M`: The module type (implements `KnxModule`)
/// - `P`: The device params type (implements `HasChannelHelpers<M>`)
///
/// # Arguments
/// - `enable_prefix`: Prefix for enable params (e.g., "enable_ch" generates "enable_ch1", "enable_ch2", etc.)
///
/// # Example
/// ```ignore
/// use zweidraehte_knxprod::definition::module::module_instances;
///
/// // In your page layout:
/// block "channels" => "Channel Configuration" {
///     // Generates 4 module instances with visibility conditions
///     items: module_instances::<DimmerChannelModule, DeviceParams>("enable_ch")
/// }
/// ```
pub fn module_instances<M, P>(enable_prefix: &str) -> crate::definition::page_layout::PageItem
where
    M: KnxModule,
    P: HasChannelHelpers<M>,
{
    let mut instances = Vec::with_capacity(P::COUNT);

    for ch in 1..=P::COUNT {
        let selector = format!("{}{}", enable_prefix, ch);
        let args = vec![
            ("ParamBase", P::param_offset(ch) as i64),
            ("ObjBase", P::object_base(ch) as i64),
            ("ChNo", ch as i64),
        ];
        instances.push((selector, args));
    }

    crate::definition::page_layout::PageItem::ModuleInstances { module_name: M::NAME, instances }
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
    #[allow(clippy::should_implement_trait)]
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
    pub fn new(instance: ModuleInstance<M>, selector_param: impl Into<String>, selector_value: i64) -> Self {
        Self { instance, selector_param: selector_param.into(), selector_values: vec![selector_value] }
    }

    /// Create a conditional instance that's visible for multiple selector values.
    pub fn with_values(
        instance: ModuleInstance<M>,
        selector_param: impl Into<String>,
        selector_values: Vec<i64>,
    ) -> Self {
        Self { instance, selector_param: selector_param.into(), selector_values }
    }
}

// ============================================================================
// Module Collection
// ============================================================================

/// Collection of module definitions and instances for a device.
///
/// This is the main structure used by the generator to produce the ModuleDefs
/// and Module elements in the XML output.
#[derive(Debug, Default, Clone)]
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
    /// Parameter definitions for the module (from ETS_PARAMS_EXT).
    /// Used to generate the ModuleDef/Static/Parameters section.
    pub params: Option<&'static [zweidraehte_device::ets::EtsParamDefExt]>,
    /// Virtual parameter definitions for the module (from VIRTUAL_PARAMS).
    /// These exist only in ETS for text substitution and are NOT stored in device memory.
    pub virtual_params: Option<&'static [zweidraehte_device::ets::EtsParamDefExt]>,
    /// Communication object definitions for the module (from ETS_COMM_OBJECTS).
    /// Used to generate the ModuleDef/Static/ComObjectTable section.
    pub comm_objects: Option<&'static [zweidraehte_device::ets::EtsCommObjectDef]>,
    /// Module page layout (using ets_module_pages! macro).
    /// If None, a simple layout with all params and comm objects is auto-generated.
    pub page_layout: Option<crate::definition::page_layout::ModulePageLayout>,
}

impl StoredModuleDef {
    /// Find the index of an argument with the given role.
    ///
    /// Looks up arguments by their `ModuleArgRole`, which is automatically
    /// set by constructor methods like `param_offset()`, `object_number()`, etc.
    pub fn arg_index_by_role(&self, role: ModuleArgRole) -> Option<usize> {
        ModuleArgDef::find_by_role(&self.arguments, role)
    }

    /// Find a parameter by name across both virtual_params and params.
    ///
    /// Returns the 1-based parameter number (matching the XML ID scheme).
    /// Virtual params come first, then regular params, matching the order
    /// used when generating the XML.
    pub fn find_param_num_by_name(&self, name: &str) -> Option<u32> {
        let virtual_params = self.virtual_params.unwrap_or(&[]);
        let regular_params = self.params.unwrap_or(&[]);

        // First search virtual params (index 0 -> param_num 1)
        if let Some(idx) = virtual_params.iter().position(|p| p.base.name == name) {
            return Some((idx + 1) as u32);
        }

        // Then search regular params (offset by virtual_params.len())
        if let Some(idx) = regular_params.iter().position(|p| p.base.name == name) {
            return Some((virtual_params.len() + idx + 1) as u32);
        }

        None
    }
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
            self.instances.push(StoredModuleInstance { def_index, args: instance.args, condition: None });
        }
    }

    /// Add conditional module instances.
    pub fn add_conditional_instances<M: KnxModule>(&mut self, instances: Vec<ConditionalModuleInstance<M>>) {
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
            params: M::MODULE_PARAMS,
            virtual_params: M::VIRTUAL_PARAMS,
            comm_objects: M::MODULE_COMM_OBJECTS,
            page_layout: M::module_layout(),
        });
        idx
    }

    /// Get all module definitions.
    pub fn definitions(&self) -> &[StoredModuleDef] {
        &self.definitions
    }

    /// Get all module instances with their definitions.
    pub fn instances(&self) -> impl Iterator<Item = (&StoredModuleDef, &StoredModuleInstance)> {
        self.instances.iter().map(|inst| (&self.definitions[inst.def_index], inst))
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

    /// Create a collection with a single module definition (no instances).
    ///
    /// This is useful when using `module_instances()` in the page layout,
    /// which generates instances at XML generation time. The collection
    /// only needs to know about the module definition.
    ///
    /// # Example
    /// ```ignore
    /// let modules = ModuleCollection::with_definition::<DimmerChannelModule>();
    /// ```
    pub fn with_definition<M: KnxModule>() -> Self {
        let mut collection = Self::new();
        collection.ensure_definition::<M>();
        collection
    }
}

// ============================================================================
// define_module! Macro
// ============================================================================

/// Macro for defining KNX modules with an ergonomic DSL.
///
/// This macro generates:
/// - A params struct with `#[derive(EtsParams)]`
/// - Virtual params constant (optional)
/// - The module struct implementing `KnxModule`
///
/// # Syntax
///
/// The syntax uses `=` for module-level assignments to be consistent with
/// `#[ets(...)]` attribute style used in derive macros.
///
/// ```rust,ignore
/// define_module! {
///     /// Module documentation
///     pub module DimmerChannelModule {
///         name = "DimmerChannel",
///         description = "Dimmer channel module",  // optional
///
///         // Module arguments (required)
///         args {
///             ParamBase: param_offset,
///             ObjBase: object_number,
///             ChNo: display(1),
///         }
///
///         // Virtual parameters - ETS-only, not in device memory (optional)
///         // Syntax: name: Type(size) = "display",
///         //     or: name: Type(size) = "display" [text_source],
///         virtual_params {
///             channel_name: String(30) = "Channel name" [text_source],
///         }
///
///         // Regular parameters (optional)
///         params {
///             #[ets(display = "Minimum brightness", suffix = "%")]
///             min_brightness: u8,
///
///             #[ets(display = "Maximum brightness", suffix = "%")]
///             max_brightness: u8 = 100,  // with default
///         }
///
///         // Communication objects - reference an existing type with #[derive(EtsComObjects)]
///         // This type provides BOTH ETS metadata AND runtime storage
///         objects: DimmerChannelObjects,
///
///         // Page layout (optional) - uses ets_module_pages! syntax
///         layout {
///             block "DimmerChannel" => "{{ChNo}}: {{0}}" {
///                 param channel_name
///                 sep "Dimming Settings"
///                 param min_brightness
///                 obj switch
///             }
///         }
///     }
/// }
/// ```
///
/// # Virtual Parameters
///
/// Virtual parameters use a compact inline syntax (no attributes):
/// - `name: Type(size) = "display",` - Basic virtual param
/// - `name: Type(size) = "display" [text_source],` - With text_source modifier
///
/// The `=` is used for the display name to be consistent with other assignment patterns.
///
/// # Communication Objects
///
/// Define your communication objects separately using `#[derive(EtsComObjects)]`:
///
/// ```rust,ignore
/// #[derive(EtsComObjects)]
/// pub struct DimmerChannelObjects {
///     #[ets(index = 0, display = "Switch", function = "Switch on/off",
///           flags = C | R | W | T, text_template = "Ch{{ChNo}} Switch: {{0}}")]
///     pub switch: ComObject<DPT_Switch>,
///
///     #[ets(index = 1, display = "Dimming", function = "Dimming value %")]
///     pub dim_value: ComObject<DPT_Scaling>,
/// }
/// ```
///
/// Then reference this type in the module definition with `objects: DimmerChannelObjects`.
/// This single type provides both ETS metadata generation AND runtime storage.
///
/// # Generated Items
///
/// For a module named `FooModule`, the macro generates:
/// - `FooModuleParams` - params struct (if params defined)
/// - `FOO_MODULE_VIRTUAL_PARAMS` - virtual params constant (if virtual_params defined)
/// - `FooModule` - the module type implementing `KnxModule`
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte_knxprod::define_module;
/// use zweidraehte_proto::dpt::DPT_Switch;
/// use zweidraehte_device::ets::EtsComObjects;
/// use zweidraehte_device::objects::comm::ComObject;
///
/// // Define objects once - used for both ETS metadata and runtime storage
/// #[derive(EtsComObjects)]
/// pub struct SwitchObjects {
///     #[ets(index = 0, display = "Switch", function = "Switching", flags = C | R | W | T)]
///     pub switch: ComObject<DPT_Switch>,
/// }
///
/// define_module! {
///     pub module SwitchModule {
///         name = "Switch",
///
///         args {
///             ParamBase: param_offset,
///             ObjBase: object_number,
///             ChNo: display(1),
///         }
///
///         params {
///             #[ets(display = "Enable")]
///             enabled: u8,
///         }
///
///         objects: SwitchObjects,
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_module {
    // Main entry point
    // Uses `=` for module-level assignments
    // Virtual params use inline syntax: `name: Type(size) = "display" [modifier],`
    // Objects: reference an existing type with `objects: TypeName,`
    (
        $(#[$module_attr:meta])*
        $vis:vis module $module_name:ident {
            name = $name_str:literal,
            $(description = $desc:literal,)?

            args {
                $($arg_name:ident : $arg_type:tt $(($arg_alloc:expr))?),* $(,)?
            }

            $(
                virtual_params {
                    $(
                        $vp_name:ident : $vp_type:tt ($vp_size:expr) = $vp_display:literal $([$vp_mod:ident])?
                    ),* $(,)?
                }
            )?

            $(
                params {
                    $(
                        $(#[$p_attr:meta])*
                        $p_name:ident : $p_type:ty $(= $p_default:expr)? $(,)?
                    )*
                }
            )?

            $(objects: $objects_type:ty,)?

            $(
                layout $layout_body:tt
            )?
        }
    ) => {
        $crate::__define_module_impl! {
            @module
            attrs: [$(#[$module_attr])*]
            vis: [$vis]
            module_name: [$module_name]
            name_str: [$name_str]
            desc: [$($desc)?]
            args: [$($arg_name : $arg_type $(($arg_alloc))?),*]
            virtual_params: [$($(
                name: [$vp_name]
                type: [$vp_type]
                size: [$vp_size]
                display: [$vp_display]
                modifier: [$($vp_mod)?]
            )*)?]
            params: [$($(
                attrs: [$(#[$p_attr])*]
                name: [$p_name]
                type: [$p_type]
                default: [$($p_default)?]
            )*)?]
            objects: [$($objects_type)?]
            layout: [$($layout_body)?]
        }
    };
}

/// Internal implementation macro for define_module - generates the params struct.
#[macro_export]
#[doc(hidden)]
macro_rules! __define_module_impl {
    // Generate everything
    (
        @module
        attrs: [$(#[$module_attr:meta])*]
        vis: [$vis:vis]
        module_name: [$module_name:ident]
        name_str: [$name_str:literal]
        desc: [$($desc:literal)?]
        args: [$($arg_name:ident : $arg_type:tt $(($arg_alloc:expr))?),*]
        virtual_params: [$(
            name: [$vp_name:ident]
            type: [$vp_type:tt]
            size: [$vp_size:expr]
            display: [$vp_display:literal]
            modifier: [$($vp_mod:ident)?]
        )*]
        params: [$(
            attrs: [$(#[$p_attr:meta])*]
            name: [$p_name:ident]
            type: [$p_type:ty]
            default: [$($p_default:expr)?]
        )*]
        objects: [$($objects_type:ty)?]
        layout: [$($layout_body:tt)?]
    ) => {
        // Generate params struct name (ModuleNameParams)
        $crate::__define_module_params_struct! {
            vis: [$vis]
            module_name: [$module_name]
            params: [$(
                attrs: [$(#[$p_attr])*]
                name: [$p_name]
                type: [$p_type]
            )*]
        }

        // Generate virtual params constant (MODULE_NAME_VIRTUAL_PARAMS)
        $crate::__define_module_virtual_params! {
            vis: [$vis]
            module_name: [$module_name]
            virtual_params: [$(
                name: [$vp_name]
                type: [$vp_type]
                size: [$vp_size]
                display: [$vp_display]
                modifier: [$($vp_mod)?]
            )*]
        }

        // Generate the module struct and KnxModule impl
        $crate::__define_module_struct! {
            attrs: [$(#[$module_attr])*]
            vis: [$vis]
            module_name: [$module_name]
            name_str: [$name_str]
            desc: [$($desc)?]
            args: [$($arg_name : $arg_type $(($arg_alloc))?),*]
            has_virtual_params: [$($vp_name)*]
            has_params: [$($p_name)*]
            objects_type: [$($objects_type)?]
            layout: [$($layout_body)?]
        }
    };
}

/// Generate the params struct with #[derive(EtsParams)]
#[macro_export]
#[doc(hidden)]
macro_rules! __define_module_params_struct {
    // No params - generate unit type placeholder
    (
        vis: [$vis:vis]
        module_name: [$module_name:ident]
        params: []
    ) => {
        // No params struct needed - will use () as Params type
    };

    // Has params - generate the struct
    (
        vis: [$vis:vis]
        module_name: [$module_name:ident]
        params: [$(
            attrs: [$(#[$p_attr:meta])*]
            name: [$p_name:ident]
            type: [$p_type:ty]
        )+]
    ) => {
        $crate::paste::paste! {
            // `IntoBytes` is derived (not hand-written) because the generator
            // reinterprets these params as the `<Data>` defaults blob ETS reads
            // back byte-for-byte. zerocopy rejects any struct with padding, so a
            // module whose fields would leave an alignment hole fails to compile
            // rather than emitting uninitialized bytes at real parameter offsets.
            #[derive(
                Debug, Clone, Copy, ::zweidraehte_device::ets::EtsParams, ::serde::Serialize, ::serde::Deserialize,
                $crate::zerocopy::KnownLayout, $crate::zerocopy::Immutable, $crate::zerocopy::IntoBytes,
            )]
            #[repr(C)]
            $vis struct [<$module_name Params>] {
                $(
                    $(#[$p_attr])*
                    pub $p_name: $p_type,
                )+
            }
        }
    };
}

/// Generate the virtual params constant
///
/// Virtual params use inline syntax: `name: Type(size) = "display" [modifier],`
/// Supported modifiers:
/// - `text_source` - Mark as the text source for `{{0}}` template substitution
#[macro_export]
#[doc(hidden)]
macro_rules! __define_module_virtual_params {
    // No virtual params - don't generate anything
    (
        vis: [$vis:vis]
        module_name: [$module_name:ident]
        virtual_params: []
    ) => {
        // No virtual params constant needed
    };

    // Has virtual params with inline syntax
    (
        vis: [$vis:vis]
        module_name: [$module_name:ident]
        virtual_params: [$(
            name: [$vp_name:ident]
            type: [$vp_type:tt]
            size: [$vp_size:expr]
            display: [$vp_display:literal]
            modifier: [$($vp_mod:ident)?]
        )+]
    ) => {
        $crate::paste::paste! {
            $vis const [<$module_name:snake:upper _VIRTUAL_PARAMS>]: &[::zweidraehte_device::ets::EtsParamDefExt] = &[
                $(
                    $crate::__vp_def!(
                        name: $vp_name,
                        type: $vp_type,
                        size: $vp_size,
                        display: $vp_display,
                        modifier: [$($vp_mod)?]
                    ),
                )+
            ];
        }
    };
}

/// Generate EtsParamDefExt for a virtual param
#[macro_export]
#[doc(hidden)]
macro_rules! __vp_def {
    // With text_source modifier
    (
        name: $name:ident,
        type: $vp_type:tt,
        size: $size:expr,
        display: $display:literal,
        modifier: [text_source]
    ) => {
        ::zweidraehte_device::ets::EtsParamDefExt {
            base: ::zweidraehte_device::ets::EtsParamDef {
                name: stringify!($name),
                display_name: $display,
                suffix: None,
                offset: 0,
                size_bits: ($size * 8) as u8,
                bit_offset: 0,
                param_type: $crate::__vp_param_type!($vp_type),
                hidden: false,
                no_memory: true,
                type_name: None,
                text_pattern: None,
            },
            enum_variants: None,
            default_value: None,
            is_text_source: true,
        }
    };

    // Without modifier (no text_source)
    (
        name: $name:ident,
        type: $vp_type:tt,
        size: $size:expr,
        display: $display:literal,
        modifier: []
    ) => {
        ::zweidraehte_device::ets::EtsParamDefExt {
            base: ::zweidraehte_device::ets::EtsParamDef {
                name: stringify!($name),
                display_name: $display,
                suffix: None,
                offset: 0,
                size_bits: ($size * 8) as u8,
                bit_offset: 0,
                param_type: $crate::__vp_param_type!($vp_type),
                hidden: false,
                no_memory: true,
                type_name: None,
                text_pattern: None,
            },
            enum_variants: None,
            default_value: None,
            is_text_source: false,
        }
    };
}

/// Helper to determine parameter type for virtual params
#[macro_export]
#[doc(hidden)]
macro_rules! __vp_param_type {
    (String) => {
        ::zweidraehte_device::ets::EtsParamType::String
    };
    (u8) => {
        ::zweidraehte_device::ets::EtsParamType::UnsignedInt
    };
    (u16) => {
        ::zweidraehte_device::ets::EtsParamType::UnsignedInt
    };
    (u32) => {
        ::zweidraehte_device::ets::EtsParamType::UnsignedInt
    };
    (i8) => {
        ::zweidraehte_device::ets::EtsParamType::SignedInt
    };
    (i16) => {
        ::zweidraehte_device::ets::EtsParamType::SignedInt
    };
    (i32) => {
        ::zweidraehte_device::ets::EtsParamType::SignedInt
    };
}

/// Generate the module struct and KnxModule impl
#[macro_export]
#[doc(hidden)]
macro_rules! __define_module_struct {
    // With objects type
    (
        attrs: [$(#[$module_attr:meta])*]
        vis: [$vis:vis]
        module_name: [$module_name:ident]
        name_str: [$name_str:literal]
        desc: [$($desc:literal)?]
        args: [$($arg_name:ident : $arg_type:tt $(($arg_alloc:expr))?),*]
        has_virtual_params: [$($vp_name:ident)*]
        has_params: [$($p_name:ident)*]
        objects_type: [$objects_type:ty]
        layout: [$($layout_body:tt)?]
    ) => {
        $crate::paste::paste! {
            $(#[$module_attr])*
            $vis struct $module_name;

            impl $crate::definition::module::KnxModule for $module_name {
                const NAME: &'static str = $name_str;

                const ARGUMENTS: &'static [$crate::definition::module::ModuleArgDef] = &[
                    $($crate::__module_arg_def!($arg_name : $arg_type $(($arg_alloc))?)),*
                ];

                $crate::__module_params_type!($module_name [$($p_name)*]);

                type Objects = $objects_type;

                $crate::__module_description!([$($desc)?]);

                $crate::__module_virtual_params!($module_name [$($vp_name)*]);

                $crate::__module_layout!([$($layout_body)?]);
            }
        }
    };

    // Without objects type
    (
        attrs: [$(#[$module_attr:meta])*]
        vis: [$vis:vis]
        module_name: [$module_name:ident]
        name_str: [$name_str:literal]
        desc: [$($desc:literal)?]
        args: [$($arg_name:ident : $arg_type:tt $(($arg_alloc:expr))?),*]
        has_virtual_params: [$($vp_name:ident)*]
        has_params: [$($p_name:ident)*]
        objects_type: []
        layout: [$($layout_body:tt)?]
    ) => {
        $crate::paste::paste! {
            $(#[$module_attr])*
            $vis struct $module_name;

            impl $crate::definition::module::KnxModule for $module_name {
                const NAME: &'static str = $name_str;

                const ARGUMENTS: &'static [$crate::definition::module::ModuleArgDef] = &[
                    $($crate::__module_arg_def!($arg_name : $arg_type $(($arg_alloc))?)),*
                ];

                $crate::__module_params_type!($module_name [$($p_name)*]);

                type Objects = ();

                $crate::__module_description!([$($desc)?]);

                $crate::__module_virtual_params!($module_name [$($vp_name)*]);

                $crate::__module_layout!([$($layout_body)?]);
            }
        }
    };
}

/// Generate ModuleArgDef from argument specification
#[macro_export]
#[doc(hidden)]
macro_rules! __module_arg_def {
    ($name:ident : param_offset) => {
        $crate::definition::module::ModuleArgDef::param_offset(stringify!($name))
    };
    ($name:ident : object_number) => {
        $crate::definition::module::ModuleArgDef::object_number(stringify!($name))
    };
    ($name:ident : display ($alloc:expr)) => {
        $crate::definition::module::ModuleArgDef::display(stringify!($name), $alloc)
    };
    ($name:ident : value_base ($alloc:expr)) => {
        $crate::definition::module::ModuleArgDef::value_base(stringify!($name), $alloc)
    };
    ($name:ident : text ($max_len:expr)) => {
        $crate::definition::module::ModuleArgDef::text(stringify!($name), $max_len)
    };
}

/// Generate type Params = ...
#[macro_export]
#[doc(hidden)]
macro_rules! __module_params_type {
    ($module_name:ident []) => {
        type Params = ();
    };
    ($module_name:ident [$($p_name:ident)+]) => {
        $crate::paste::paste! {
            type Params = [<$module_name Params>];
        }
    };
}

/// Generate INTERNAL_DESCRIPTION
#[macro_export]
#[doc(hidden)]
macro_rules! __module_description {
    ([]) => {};
    ([$desc:literal]) => {
        const INTERNAL_DESCRIPTION: Option<&'static str> = Some($desc);
    };
}

/// Generate VIRTUAL_PARAMS
#[macro_export]
#[doc(hidden)]
macro_rules! __module_virtual_params {
    ($module_name:ident []) => {};
    ($module_name:ident [$($vp_name:ident)+]) => {
        $crate::paste::paste! {
            const VIRTUAL_PARAMS: Option<&'static [::zweidraehte_device::ets::EtsParamDefExt]> =
                Some([<$module_name:snake:upper _VIRTUAL_PARAMS>]);
        }
    };
}

/// Generate module_layout()
#[macro_export]
#[doc(hidden)]
macro_rules! __module_layout {
    ([]) => {};
    ([$layout_body:tt]) => {
        fn module_layout() -> Option<$crate::definition::page_layout::ModulePageLayout> {
            Some($crate::ets_module_pages! $layout_body)
        }
    };
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
            ModuleArgDef::param_offset("ParamBase"),
            ModuleArgDef::object_number("ObjBase"),
            ModuleArgDef::display("ChNo", 1),
        ];
        type Params = ();
        type Objects = ();
    }

    #[test]
    fn test_module_arg_def_constructors() {
        let param_arg = ModuleArgDef::param_offset("ParamBase");
        assert_eq!(param_arg.name, "ParamBase");
        assert_eq!(param_arg.role, ModuleArgRole::ParamOffset);
        assert_eq!(param_arg.arg_type, ModuleArgType::Numeric);

        let obj_arg = ModuleArgDef::object_number("ObjBase");
        assert_eq!(obj_arg.name, "ObjBase");
        assert_eq!(obj_arg.role, ModuleArgRole::ObjectNumber);

        let ch_arg = ModuleArgDef::display("ChNo", 1);
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
        assert_eq!(instances[3].numeric_arg(1), 19); // 10 + 3*3
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

    // ========================================================================
    // define_module! macro tests
    // ========================================================================

    // Test minimal module definition (args only)
    crate::define_module! {
        /// A minimal module for testing
        pub module MinimalModule {
            name = "Minimal",

            args {
                ParamBase: param_offset,
                ObjBase: object_number,
                ChNo: display(1),
            }
        }
    }

    #[test]
    fn test_define_module_minimal() {
        assert_eq!(MinimalModule::NAME, "Minimal");
        assert_eq!(MinimalModule::ARGUMENTS.len(), 3);
        assert_eq!(MinimalModule::ARGUMENTS[0].name, "ParamBase");
        assert_eq!(MinimalModule::ARGUMENTS[0].role, ModuleArgRole::ParamOffset);
        assert_eq!(MinimalModule::ARGUMENTS[1].name, "ObjBase");
        assert_eq!(MinimalModule::ARGUMENTS[1].role, ModuleArgRole::ObjectNumber);
        assert_eq!(MinimalModule::ARGUMENTS[2].name, "ChNo");
        assert_eq!(MinimalModule::ARGUMENTS[2].allocates, 1);
    }

    // Test module with params
    crate::define_module! {
        /// A module with params for testing
        pub module ParamsTestModule {
            name = "ParamsTest",
            description = "Test module with params",

            args {
                ParamBase: param_offset,
                ObjBase: object_number,
                ChNo: display(1),
            }

            params {
                #[ets(display = "Brightness", suffix = "%")]
                brightness: u8,

                #[ets(display = "Speed")]
                speed: u8,
            }
        }
    }

    #[test]
    fn test_define_module_with_params() {
        assert_eq!(ParamsTestModule::NAME, "ParamsTest");
        assert_eq!(ParamsTestModule::INTERNAL_DESCRIPTION, Some("Test module with params"));

        // Check MODULE_PARAMS
        let params = ParamsTestModule::MODULE_PARAMS.expect("Should have params");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].base.name, "brightness");
        assert_eq!(params[0].base.display_name, "Brightness");
        assert_eq!(params[0].base.suffix, Some("%"));
        assert_eq!(params[1].base.name, "speed");
        assert_eq!(params[1].base.display_name, "Speed");

        // Check generated params struct size
        assert_eq!(std::mem::size_of::<ParamsTestModuleParams>(), 2);
    }
}
