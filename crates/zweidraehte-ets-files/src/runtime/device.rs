//! Unified Device struct for KNX device configuration.
//!
//! This module provides a `Device` struct that encapsulates all state needed
//! for a KNX device configuration, including:
//! - Parsed ApplicationProgram (XML structure)
//! - Runtime parameter values and visibility state
//! - Module expansion and parameter values
//! - Group address bindings
//! - Baggage resources (images, icons)
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use std::sync::Arc;
//! use zweidraehte_ets_files::product::SelectedProduct;
//! use zweidraehte_ets_files::{Device, parse_application_program_from_file};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let document = parse_application_program_from_file(Path::new("light-switch.mtxml"))?;
//! let selected = Arc::new(SelectedProduct::from_document(document, None, None)?);
//!
//! let device = Device::from_product(selected, None, None);
//!
//! // Get parameter value
//! if let Some(value) = device.get_parameter_value("Param_1") {
//!     println!("Param_1 = {:?}", value);
//! }
//!
//! // Interpolate text with parameter substitution
//! let text = device.interpolate_text("Value is {{1:unknown}}");
//! let evaluated = device.evaluate(&[])?;
//! # Ok(())
//! # }
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::Translations;
use super::configuration::{
    ConfigurationError, ObjectSetting, ParameterDescription, effective_default, validate_setting,
};
use super::evaluation::EvaluatedProduct;
use super::scripting::{
    CalculationEdges, Direction, ScriptBinding, ScriptHost, ValidationOutcome, execute_calculation, execute_validation,
    plan_for_change, script_name,
};
use crate::product::SelectedProduct;
use zweidraehte_proto::address::GroupAddress;

use crate::runtime::baggage::BaggageIndex;
use crate::runtime::model::{
    Condition, ExpandedModule, GroupAddressBinding, ModuleArgValue, ParameterInfo, ParameterValue,
};
use crate::schema::{
    Allocator, ApplicationProgram, Assign, CalculationParameterRef, Channel, ChannelIndependentBlock,
    ChannelIndependentItem, ChannelItem, Choose, ComObject, ComObjectRef, DynamicItem, DynamicSection, Module,
    ModuleArg, ModuleDef, ModuleDefDynamicItem, ParameterBlock, ParameterBlockItem, ParameterCalculation, ParameterRef,
    ParameterType, ParameterTypeDef, ParameterValidation, Repeat, RepeatItem, WhenItem,
};

/// A complete KNX device instance with all state needed for configuration and programming.
///
/// This struct combines:
/// - **ApplicationProgram**: The parsed XML structure (immutable)
/// - **Runtime State**: Parameter values, visibility, module expansion, bindings
/// - **Resources**: Baggage index for images and icons
pub struct Device {
    /// Only construction from a checked selection can publish evaluated input.
    /// Raw `ApplicationProgram` editors remain useful for schema inspection.
    selected_product: Option<Arc<SelectedProduct>>,
    // === Immutable Core ===
    /// Shared program, lookup tables and initial values; never edited in place.
    definition: Arc<DeviceDefinition>,

    /// Device-specific baggage/resources (images, icons)
    baggage_index: Option<BaggageIndex>,

    // === Mutable Configuration State ===
    /// Current base-parameter values indexed by parameter ID.
    param_values: HashMap<String, ParameterValue>,

    /// Current root ParameterRef values indexed by reference ID. A reusable
    /// UI-only parameter can have several independent refs (and therefore
    /// several independent values) even though they share one base record.
    param_ref_values: HashMap<String, ParameterValue>,

    /// Module instance parameter values indexed by composite ID (instance_id::param_id)
    module_param_values: HashMap<String, ParameterValue>,

    /// Values produced by active dynamic `Assign` nodes. They are recomputed,
    /// never persisted as authored input. Parameter calculations are not
    /// derived: their results are stored values written during an edit.
    derived_param_ref_values: HashMap<String, ParameterValue>,
    derived_module_param_values: HashMap<String, ParameterValue>,

    /// Derivation failures are retained because the public edit API predates
    /// fallible calculations. Configuration/image construction checks this
    /// field and refuses to silently compile defaults instead.
    derivation_error: Option<String>,

    /// Group address bindings indexed by communication object number
    group_address_bindings: HashMap<u16, Vec<GroupAddressBinding>>,

    /// Parameters whose value was explicitly set after construction.
    ///
    /// Distinguishes "the user chose this value" from "still at its
    /// construction-time default" — needed because a visible
    /// `ParameterRef` may carry a `Value` override, making the
    /// *effective* default differ from the stored initial value.
    touched_params: HashSet<String>,

    /// Root ParameterRefs explicitly edited by the project or user.
    touched_param_refs: HashSet<String>,

    /// Module parameters explicitly edited by the project or user. This is
    /// separate from initialized defaults so `ParameterRef/@Value` overrides
    /// remain effective until a concrete instance value is authored. The bool
    /// records whether that ID resolved when edited: a misspelled ID must fail
    /// evaluation, while a valid instance hidden by a later repeat count keeps
    /// its draft without becoming part of the current configuration.
    touched_module_params: HashMap<String, bool>,

    // === Computed State ===
    /// Parameter references which participate in the current dynamic tree.
    ///
    /// This is deliberately broader than visibility: controls below an
    /// `Access="None"` block remain active and may select a load-procedure
    /// branch even though an editor must not display them.
    active_param_refs: HashSet<String>,

    /// Set of visible parameter ref IDs
    visible_param_refs: HashSet<String>,

    /// Visible module parameter refs, qualified as `instance_id::ref_id`.
    visible_module_param_refs: HashSet<String>,

    /// Set of visible communication object ref IDs
    visible_com_object_refs: HashSet<String>,

    /// Visible module communication-object refs, qualified as
    /// `instance_id::ref_id`. Module definitions are reused by every
    /// instance, so the unqualified ref ID cannot describe which concrete
    /// object number is active.
    visible_module_com_object_refs: HashSet<String>,

    /// Set of visible module instance IDs
    visible_modules: HashSet<String>,

    /// Active `ParameterBlockRename`s under the current configuration:
    /// renamed block id -> display text. A rename inside an active
    /// choose branch replaces the referenced block's title.
    active_block_renames: HashMap<String, String>,

    /// Expanded module instances indexed by instance ID
    expanded_modules: HashMap<String, ExpandedModule>,
}

/// Immutable data built once for every retained, untranslated selection.
/// Defaults are templates: each editor owns and mutates its own value maps.
#[derive(Debug)]
pub(crate) struct DeviceDefinition {
    program: ApplicationProgram,
    param_values: HashMap<String, ParameterValue>,
    param_ref_values: HashMap<String, ParameterValue>,
    // === Internal Lookup Caches ===
    /// Parameter types indexed by type ID
    param_types: HashMap<String, ParameterType>,

    /// Parameters indexed by ID
    parameters: HashMap<String, ParameterInfo>,

    /// Parameter refs indexed by ID
    param_refs: HashMap<String, ParameterRef>,

    /// Parameter ref IDs in their authored order.
    ///
    /// The MTXML schema makes this list order significant so products
    /// behave deterministically when several active refs target the same
    /// parameter. Keep the map for lookup and the list for precedence.
    param_ref_order: Vec<String>,

    /// Parameter ref ids indexed by their numeric tail — inline text
    /// templates name refs that way (`{{48:…}}` means `…_P-23_R-48`),
    /// full ids appear only in attributes.
    param_ref_tails: HashMap<String, String>,

    /// Communication objects indexed by ID
    com_objects: HashMap<String, ComObject>,

    /// Communication object refs indexed by ID
    com_object_refs: HashMap<String, ComObjectRef>,
    /// Communication-object ref IDs in their authored order. When several
    /// visible refs target one object number, the first authored one
    /// supplies its overrides; iterating the visibility set instead made
    /// that choice depend on hash order.
    com_object_ref_order: Vec<String>,

    /// Module definitions indexed by ID
    module_defs: HashMap<String, ModuleDef>,

    /// Module parameters indexed by `ModuleDefId::ParameterId`.
    module_parameters: HashMap<String, ParameterInfo>,
}

impl DeviceDefinition {
    pub(crate) fn new(program: ApplicationProgram) -> Self {
        // Build lookup caches
        let param_types = build_param_type_lookup(&program.static_section);
        let (parameters, param_values) = build_parameter_lookup(&program.static_section, &param_types);
        let param_refs = build_param_ref_lookup(&program.static_section);
        let param_ref_order = build_param_ref_order(&program.static_section);
        let param_ref_tails = build_param_ref_tail_lookup(&param_refs);
        let param_ref_values = build_param_ref_value_lookup(&param_refs, &parameters, &param_values, &param_types);
        let com_objects = build_com_object_lookup(&program.static_section);
        let com_object_refs = build_com_object_ref_lookup(&program.static_section);
        let com_object_ref_order = program
            .static_section
            .com_object_refs
            .iter()
            .flat_map(|refs| refs.refs.iter().map(|reference| reference.id.clone()))
            .collect();
        let module_defs = build_module_def_lookup(&program);
        let module_parameters = build_module_parameter_lookup(&module_defs);

        Self {
            program,
            param_values,
            param_ref_values,
            param_types,
            parameters,
            param_refs,
            param_ref_order,
            param_ref_tails,
            com_objects,
            com_object_refs,
            com_object_ref_order,
            module_defs,
            module_parameters,
        }
    }
}

/// Context for processing a module's dynamic section.
#[derive(Clone)]
pub struct ModuleContext {
    /// The module instance ID
    pub instance_id: String,
    /// The module definition
    pub module_def: ModuleDef,
}

/// One visible communication object from a concrete module instance.
#[derive(Debug, Clone, Copy)]
pub struct VisibleModuleComObject<'a> {
    pub module: &'a ExpandedModule,
    pub object: &'a ComObject,
    pub reference: &'a ComObjectRef,
    pub number: u16,
}

/// One visible parameter reference from a concrete module instance.
#[derive(Debug, Clone, Copy)]
pub struct VisibleModuleParameterRef<'a> {
    pub module: &'a ExpandedModule,
    pub reference: &'a ParameterRef,
}

fn module_numeric_argument(module: &ExpandedModule, module_def: &ModuleDef, argument_id: &str) -> Option<i64> {
    let argument = module_def.arguments.as_ref()?.arguments.iter().find(|argument| argument.id == argument_id)?;
    match module.args.get(&argument.name)? {
        ModuleArgValue::Numeric(value) => Some(*value),
        ModuleArgValue::Text(_) => None,
    }
}

fn module_object_number(module: &ExpandedModule, module_def: &ModuleDef, object: &ComObject) -> Option<u16> {
    let base = match &object.base_number {
        Some(argument_id) => module_numeric_argument(module, module_def, argument_id)?,
        None => 0,
    };
    let number = base.checked_add(i64::from(object.number))?;
    u16::try_from(number).ok()
}

impl Device {
    /// Open a checked product for editing, optionally translating its presentation.
    /// Every language starts from the retained original document. Raw edits may
    /// be temporarily invalid; [`Self::evaluate`] checks them before publication.
    /// An unavailable language leaves the original product text in place.
    /// Instances without a translation share the selection's immutable program
    /// and lookup tables; values, visibility and module expansion remain local.
    pub fn from_product(selected: Arc<SelectedProduct>, baggage: Option<BaggageIndex>, language: Option<&str>) -> Self {
        // The ordinary project path reuses one immutable definition. A
        // translated editor gets its own presentation, always derived from
        // the original document rather than another editor's translated text.
        let definition = match language {
            None => selected.runtime_definition().clone(),
            Some(language) => {
                let mut program = selected.program().clone();
                Translations::from_knx(selected.document()).apply(&mut program, language);
                Arc::new(DeviceDefinition::new(program))
            }
        };
        let mut device = Self::from_definition(definition, baggage);
        device.selected_product = Some(selected);
        device
    }

    /// Publish a checked, immutable view of the current product configuration.
    /// A raw program has no checked product identity and cannot be evaluated.
    ///
    /// # Errors
    /// Rejects an unbound program, failed derivation, invalid edits or object
    /// overrides, and unresolved product geometry. The draft remains editable.
    pub fn evaluate(&self, objects: &[ObjectSetting]) -> Result<EvaluatedProduct<'_>, ConfigurationError> {
        let selected = self.selected_product.as_ref().ok_or(ConfigurationError::UnboundProduct)?;
        EvaluatedProduct::new(self, selected, objects)
    }

    pub(crate) fn edited_parameter_values(&self) -> impl Iterator<Item = (&str, &ParameterValue)> {
        self.touched_params
            .iter()
            .map(|id| (id.as_str(), &self.param_values[id]))
            .chain(self.touched_param_refs.iter().map(|id| (id.as_str(), &self.param_ref_values[id])))
            .chain(self.touched_module_params.iter().filter_map(|(id, known)| {
                let active =
                    id.split_once("::").is_some_and(|(instance, _)| self.expanded_modules.contains_key(instance));
                (!known || active).then(|| (id.as_str(), &self.module_param_values[id]))
            }))
    }

    /// Create a new device from a parsed ApplicationProgram.
    /// For editing followed by compilation, use [`Self::from_product`]; this
    /// schema-only constructor cannot establish a checked product identity.
    ///
    /// # Arguments
    /// * `program` - The parsed ApplicationProgram
    /// * `baggage_index` - Optional baggage index for images/resources
    pub fn new(program: ApplicationProgram, baggage_index: Option<BaggageIndex>) -> Self {
        Self::from_definition(Arc::new(DeviceDefinition::new(program)), baggage_index)
    }

    fn from_definition(definition: Arc<DeviceDefinition>, baggage_index: Option<BaggageIndex>) -> Self {
        let param_values = definition.param_values.clone();
        let param_ref_values = definition.param_ref_values.clone();

        let mut device = Self {
            selected_product: None,
            definition,
            baggage_index,
            param_values,
            param_ref_values,
            module_param_values: HashMap::new(),
            derived_param_ref_values: HashMap::new(),
            derived_module_param_values: HashMap::new(),
            derivation_error: None,
            group_address_bindings: HashMap::new(),
            touched_params: HashSet::new(),
            touched_param_refs: HashSet::new(),
            touched_module_params: HashMap::new(),
            active_param_refs: HashSet::new(),
            visible_param_refs: HashSet::new(),
            visible_module_param_refs: HashSet::new(),
            visible_com_object_refs: HashSet::new(),
            visible_module_com_object_refs: HashSet::new(),
            visible_modules: HashSet::new(),
            active_block_renames: HashMap::new(),
            expanded_modules: HashMap::new(),
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
        &self.definition.program
    }

    // ========================================================================
    // Parameter Access
    // ========================================================================

    /// Get the current value of a base parameter or root ParameterRef by ID.
    ///
    /// A ref-specific edit wins. A base edit is otherwise reflected by every
    /// ref targeting that base. Untouched refs retain their own `@Value`
    /// override, if present.
    pub fn get_parameter_value(&self, param_id: &str) -> Option<&ParameterValue> {
        let Some(parameter_ref) = self.definition.param_refs.get(param_id) else {
            return self.param_values.get(param_id);
        };
        if let Some(value) = self.derived_param_ref_values.get(param_id) {
            return Some(value);
        }
        if self.touched_param_refs.contains(param_id) || !self.touched_params.contains(&parameter_ref.ref_id) {
            self.param_ref_values.get(param_id)
        } else {
            self.param_values.get(&parameter_ref.ref_id)
        }
    }

    /// Set a base parameter or root ParameterRef value and recompute visibility.
    ///
    /// This stores a value as a project records it; it runs neither
    /// validations nor calculations. Use [`Self::try_set_parameter_value`]
    /// for an edit with the product's script semantics.
    pub fn set_parameter_value(&mut self, param_id: &str, value: ParameterValue) {
        if self.definition.param_refs.contains_key(param_id) {
            self.param_ref_values.insert(param_id.to_string(), value);
            self.touched_param_refs.insert(param_id.to_string());
        } else {
            self.param_values.insert(param_id.to_string(), value);
            self.touched_params.insert(param_id.to_string());
        }
        self.recompute_visibility();
    }

    /// Whether a parameter's value was explicitly set since
    /// construction (as opposed to still holding its initial default).
    pub fn is_parameter_touched(&self, param_id: &str) -> bool {
        if self.definition.param_refs.contains_key(param_id) {
            self.touched_param_refs.contains(param_id)
        } else {
            self.touched_params.contains(param_id)
        }
    }

    /// Edit one currently visible parameter, retaining inactive draft values.
    ///
    /// Unlike applying a programming configuration, hiding a previously edited
    /// field does not reject the edit or discard its value. Both root references
    /// and concrete `instance::reference` IDs use this boundary.
    ///
    /// This is the only place product scripts run, as in the reference: the
    /// product's validations may reject the value first, then the
    /// calculations reachable from the edited parameter store their results.
    /// Defaults, loaded projects and downloads never run a script.
    ///
    /// # Errors
    /// Rejects unknown, hidden, read-only, ill-typed and out-of-range values,
    /// and values a product validation rejects. Failed module expansion or
    /// calculation restores the previous draft.
    pub fn try_set_parameter_value(&mut self, id: &str, value: ParameterValue) -> Result<(), ConfigurationError> {
        if let Some(error) = self.derivation_error() {
            return Err(ConfigurationError::Derivation(error.to_owned()));
        }
        validate_setting(self, id, &value)?;
        if !self.configuration_parameter_is_visible(id) {
            return Err(ConfigurationError::NotVisible(id.to_owned()));
        }

        // The product's validations see the proposed value before anything
        // is stored, so a rejected edit leaves no trace.
        self.validate_edit(id, &value)?;

        // A selector can create module defaults as well as change its own
        // value. Roll back all authored maps, then derive visibility again;
        // cloning the much larger immutable XML definition is unnecessary.
        let previous = (
            self.param_values.clone(),
            self.param_ref_values.clone(),
            self.module_param_values.clone(),
            self.touched_params.clone(),
            self.touched_param_refs.clone(),
            self.touched_module_params.clone(),
        );
        if self.is_module_parameter(id) {
            self.set_module_parameter_value_by_composite_id(id, value);
        } else {
            self.set_parameter_value(id, value);
        }

        // Then the calculations reachable from the edited parameter run once,
        // in dependency order, and their results are stored like the edit.
        // TODO: the reference keeps the edit when a calculation throws; this
        // restores the whole draft so a failed script cannot leave its
        // outputs half-written.
        if self.derivation_error.is_none() {
            match self.run_calculations(id) {
                Ok(true) => self.recompute_visibility(),
                Ok(false) => {}
                Err(error) => self.derivation_error = Some(error),
            }
        }
        if let Some(error) = self.derivation_error().map(str::to_owned) {
            (
                self.param_values,
                self.param_ref_values,
                self.module_param_values,
                self.touched_params,
                self.touched_param_refs,
                self.touched_module_params,
            ) = previous;
            self.recompute_visibility();
            return Err(ConfigurationError::Derivation(error));
        }
        Ok(())
    }

    /// Rebuild presentation in another language without losing hidden edits.
    ///
    /// Only touched values cross the language boundary; untouched defaults come
    /// from the newly translated definition. Values of inactive repeat instances
    /// remain draft state, distinct from an active programming configuration.
    ///
    /// # Errors
    /// Requires a checked product selection and successful final derivation.
    /// The original device is never mutated, including on failure.
    pub fn with_language(&self, language: Option<&str>) -> Result<Self, ConfigurationError> {
        let selected = self.selected_product.as_ref().ok_or(ConfigurationError::UnboundProduct)?;
        let mut next = Self::from_product(selected.clone(), self.baggage_index.clone(), language);
        for id in &self.touched_params {
            if let Some(value) = self.param_values.get(id) {
                next.param_values.insert(id.clone(), value.clone());
            }
        }
        for id in &self.touched_param_refs {
            if let Some(value) = self.param_ref_values.get(id) {
                next.param_ref_values.insert(id.clone(), value.clone());
            }
        }
        for id in self.touched_module_params.keys() {
            if let Some(value) = self.module_param_values.get(id) {
                next.module_param_values.insert(id.clone(), value.clone());
            }
        }
        next.touched_params = self.touched_params.clone();
        next.touched_param_refs = self.touched_param_refs.clone();
        next.touched_module_params = self.touched_module_params.clone();
        next.group_address_bindings = self.group_address_bindings.clone();
        next.recompute_visibility();
        if let Some(error) = next.derivation_error() {
            return Err(ConfigurationError::Derivation(error.to_owned()));
        }
        Ok(next)
    }

    /// The display text an active `ParameterBlockRename` gives a
    /// block under the current configuration, if any. Renders (and
    /// re-renders on every visibility recomputation) what ETS shows:
    /// a rename in an active choose branch replaces the referenced
    /// block's title.
    pub fn active_block_rename(&self, block_id: &str) -> Option<&str> {
        self.active_block_renames.get(block_id).map(String::as_str)
    }

    /// Get parameter info by base ID or root ParameterRef ID.
    pub fn get_parameter_info(&self, param_id: &str) -> Option<&ParameterInfo> {
        self.definition.parameters.get(param_id).or_else(|| {
            self.definition
                .param_refs
                .get(param_id)
                .and_then(|parameter_ref| self.definition.parameters.get(&parameter_ref.ref_id))
        })
    }

    /// Resolve metadata for a root or concrete module configuration ID.
    pub fn get_configuration_parameter_info(&self, id: &str) -> Option<&ParameterInfo> {
        if let Some(info) = self.get_parameter_info(id) {
            return Some(info);
        }
        let (instance_id, parameter_id) = id.split_once("::")?;
        let expanded = self.expanded_modules.get(instance_id)?;
        let base_id = self.module_parameter_base_id(expanded, parameter_id)?;
        self.definition.module_parameters.get(&format!("{}::{base_id}", expanded.module_def_id))
    }

    /// Describe a parameter using its exact root reference or module instance
    /// identity. Base IDs retain the visible-reference default used by editors.
    pub fn parameter_description(&self, id: &str) -> Option<ParameterDescription<'_>> {
        use std::borrow::Cow;

        let info = self.get_configuration_parameter_info(id)?;
        let module = id.split_once("::").and_then(|(instance, _)| self.expanded_modules.get(instance));
        let reference = self.configuration_parameter_ref(id).or_else(|| {
            module.is_none().then(|| self.visible_param_refs().find(|reference| reference.ref_id == id)).flatten()
        });
        let default = effective_default(self, id);
        let (touched, value) = if let Some(module) = module {
            let touched = self.touched_module_params.contains_key(id)
                || reference.is_some_and(|reference| {
                    self.touched_module_params.contains_key(&format!("{}::{}", module.instance_id, reference.ref_id))
                });
            (touched, self.get_module_parameter_value_by_composite_id(id).map(Cow::Borrowed))
        } else {
            let touched = self.is_parameter_touched(id)
                || self.root_parameter_id(id).is_some_and(|base| self.is_parameter_touched(base));
            let derived = reference.and_then(|reference| self.derived_param_ref_values.get(&reference.id));
            let value = derived.map(Cow::Borrowed).or_else(|| {
                if touched {
                    self.get_parameter_value(id).map(Cow::Borrowed)
                } else {
                    default.clone().map(Cow::Owned).or_else(|| self.get_parameter_value(id).map(Cow::Borrowed))
                }
            });
            (touched, value)
        };
        let parameter_type = self.get_parameter_type(&info.type_id).map(|parameter_type| &parameter_type.type_def);
        let suffix = info.suffix.as_deref().or_else(|| match parameter_type {
            Some(ParameterTypeDef::TypeTime(time)) => Some(time.unit.value_unit()),
            _ => None,
        });
        let access = reference.and_then(|reference| reference.access.as_deref());
        let hidden = info.hidden || access == Some("None");
        let writable = !hidden && !info.read_only && access != Some("Read");
        let modified = touched && value.as_deref() != default.as_ref();
        Some(ParameterDescription {
            info,
            parameter_type,
            text: reference.and_then(|reference| reference.text.as_deref()).unwrap_or(&info.text),
            suffix,
            module,
            value,
            default,
            hidden,
            writable,
            modified,
        })
    }

    fn module_parameter_base_id(&self, expanded: &ExpandedModule, parameter_id: &str) -> Option<String> {
        let module_def = self.definition.module_defs.get(&expanded.module_def_id)?;
        if self.definition.module_parameters.contains_key(&format!("{}::{parameter_id}", expanded.module_def_id)) {
            return Some(parameter_id.to_string());
        }
        module_def
            .static_section
            .parameter_refs
            .as_ref()?
            .refs
            .iter()
            .find(|parameter_ref| parameter_ref.id == parameter_id)
            .map(|parameter_ref| parameter_ref.ref_id.clone())
    }

    pub(crate) fn configuration_parameter_is_visible(&self, id: &str) -> bool {
        if let Some(parameter_ref) = self.definition.param_refs.get(id) {
            return self.visible_param_refs.contains(&parameter_ref.id);
        }
        if self.definition.parameters.contains_key(id) {
            return self.definition.param_refs.is_empty()
                || self.visible_param_refs.iter().any(|ref_id| {
                    self.definition.param_refs.get(ref_id).is_some_and(|parameter_ref| parameter_ref.ref_id == id)
                });
        }

        let Some((instance_id, parameter_id)) = id.split_once("::") else { return false };
        let Some(expanded) = self.expanded_modules.get(instance_id) else { return false };
        let Some(module_def) = self.definition.module_defs.get(&expanded.module_def_id) else { return false };
        if module_def
            .static_section
            .parameter_refs
            .as_ref()
            .and_then(|refs| refs.refs.iter().find(|parameter_ref| parameter_ref.id == parameter_id))
            .is_some()
        {
            return self.visible_module_param_refs.contains(id);
        }
        module_def.static_section.parameter_refs.as_ref().is_none_or(|refs| refs.refs.is_empty())
            || module_def.static_section.parameter_refs.as_ref().is_some_and(|refs| {
                refs.refs.iter().any(|parameter_ref| {
                    parameter_ref.ref_id == parameter_id
                        && self.visible_module_param_refs.contains(&format!("{instance_id}::{}", parameter_ref.id))
                })
            })
    }

    pub(crate) fn configuration_parameter_is_writable(&self, id: &str) -> bool {
        let Some(info) = self.get_configuration_parameter_info(id) else { return false };
        let access = self.configuration_parameter_ref(id).and_then(|reference| reference.access.as_deref());
        match access {
            Some("None" | "Read") => false,
            Some(_) => true,
            None => !info.hidden && !info.read_only,
        }
    }

    fn configuration_parameter_ref(&self, id: &str) -> Option<&ParameterRef> {
        if let Some(reference) = self.definition.param_refs.get(id) {
            return Some(reference);
        }
        let (instance, parameter) = id.split_once("::")?;
        let module = self.expanded_modules.get(instance)?;
        self.definition
            .module_defs
            .get(&module.module_def_id)?
            .static_section
            .parameter_refs
            .as_ref()?
            .refs
            .iter()
            .find(|reference| reference.id == parameter)
    }

    /// Iterate over every base parameter declared by the application program.
    ///
    /// Most modern products expose their configurable surface through
    /// `ParameterRef`s. Compact BCU-era products can omit that layer and expose
    /// the base parameter table directly, so format-neutral configuration code
    /// needs access to both shapes.
    pub fn parameter_infos(&self) -> impl Iterator<Item = &ParameterInfo> {
        self.definition.parameters.values()
    }

    /// Get a parameter type by ID.
    pub fn get_parameter_type(&self, type_id: &str) -> Option<&ParameterType> {
        self.definition.param_types.get(type_id)
    }

    /// Get a parameter ref by ID.
    pub fn get_parameter_ref(&self, ref_id: &str) -> Option<&ParameterRef> {
        self.definition.param_refs.get(ref_id)
    }

    /// The base parameter targeted by a root ParameterRef, or the supplied
    /// base ID itself when it is already a parameter.
    pub fn root_parameter_id<'a>(&'a self, id: &'a str) -> Option<&'a str> {
        if self.definition.parameters.contains_key(id) {
            Some(id)
        } else {
            self.definition.param_refs.get(id).map(|parameter_ref| parameter_ref.ref_id.as_str())
        }
    }

    // ========================================================================
    // Communication Object Access
    // ========================================================================

    /// Get a communication object by ID.
    pub fn get_com_object(&self, obj_id: &str) -> Option<&ComObject> {
        self.definition.com_objects.get(obj_id)
    }

    /// Get a communication object ref by ID.
    pub fn get_com_object_ref(&self, ref_id: &str) -> Option<&ComObjectRef> {
        self.definition.com_object_refs.get(ref_id)
    }

    // ========================================================================
    // Visibility Queries
    // ========================================================================

    /// Check whether a root parameter reference participates in the current
    /// dynamic configuration, including controls hidden from the editor.
    pub fn is_param_ref_active(&self, ref_id: &str) -> bool {
        self.active_param_refs.contains(ref_id)
    }

    /// Check whether one concrete module parameter reference participates in
    /// the current dynamic configuration, including hidden controls.
    pub fn is_module_param_ref_active(&self, instance_id: &str, param_ref_id: &str) -> bool {
        self.active_param_refs.contains(&format!("{instance_id}::{param_ref_id}"))
    }

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

    /// Check whether one concrete module instance currently exposes a
    /// parameter reference through its active dynamic branches.
    pub fn is_module_param_ref_visible(&self, instance_id: &str, param_ref_id: &str) -> bool {
        self.visible_module_param_refs.contains(&format!("{instance_id}::{param_ref_id}"))
    }

    /// Iterate over visible parameter refs.
    pub fn visible_param_refs(&self) -> impl Iterator<Item = &ParameterRef> {
        self.definition
            .param_ref_order
            .iter()
            .filter(|id| self.visible_param_refs.contains(*id))
            .filter_map(|id| self.definition.param_refs.get(id))
    }

    /// Resolve every visible module parameter ref to its concrete instance.
    pub fn visible_module_parameter_refs(&self) -> Vec<VisibleModuleParameterRef<'_>> {
        let mut parameters = self
            .visible_module_param_refs
            .iter()
            .filter_map(|id| {
                let (instance_id, ref_id) = id.split_once("::")?;
                let module = self.expanded_modules.get(instance_id)?;
                let module_def = self.definition.module_defs.get(&module.module_def_id)?;
                let reference = module_def
                    .static_section
                    .parameter_refs
                    .as_ref()?
                    .refs
                    .iter()
                    .find(|reference| reference.id == ref_id)?;
                Some(VisibleModuleParameterRef { module, reference })
            })
            .collect::<Vec<_>>();
        parameters.sort_by(|left, right| {
            left.module
                .instance_id
                .cmp(&right.module.instance_id)
                .then_with(|| left.reference.id.cmp(&right.reference.id))
        });
        parameters
    }

    /// Iterate over visible communication object refs.
    pub fn visible_com_object_refs(&self) -> impl Iterator<Item = &ComObjectRef> {
        self.definition
            .com_object_ref_order
            .iter()
            .filter(|id| self.visible_com_object_refs.contains(*id))
            .filter_map(|id| self.definition.com_object_refs.get(id))
    }

    /// Whether a communication-object ref is visible in one concrete module
    /// instance.
    pub fn is_module_com_object_ref_visible(&self, instance_id: &str, ref_id: &str) -> bool {
        self.visible_module_com_object_refs.contains(&format!("{instance_id}::{ref_id}"))
    }

    /// Resolve every visible module communication object to its concrete
    /// object number.
    ///
    /// Manufacturer Tool module objects carry a local number and name a
    /// `BaseNumber` argument. The argument is resolved independently for each
    /// expanded module instance, so consumers must not treat the module's
    /// static object table as a global roster.
    pub fn visible_module_com_objects(&self) -> Vec<VisibleModuleComObject<'_>> {
        let mut objects = self
            .visible_module_com_object_refs
            .iter()
            .filter_map(|id| {
                let (instance_id, ref_id) = id.split_once("::")?;
                let module = self.expanded_modules.get(instance_id)?;
                let module_def = self.definition.module_defs.get(&module.module_def_id)?;
                let reference = module_def
                    .static_section
                    .com_object_refs
                    .as_ref()?
                    .refs
                    .iter()
                    .find(|reference| reference.id == ref_id)?;
                let object = module_def
                    .static_section
                    .com_objects
                    .as_ref()?
                    .objects
                    .iter()
                    .find(|object| object.id == reference.ref_id)?;
                let number = module_object_number(module, module_def, object)?;
                Some(VisibleModuleComObject { module, object, reference, number })
            })
            .collect::<Vec<_>>();
        objects.sort_by(|left, right| {
            left.number
                .cmp(&right.number)
                .then_with(|| left.module.instance_id.cmp(&right.module.instance_id))
                .then_with(|| left.reference.id.cmp(&right.reference.id))
        });
        objects
    }

    /// Whether any currently instantiated module declares this concrete
    /// object number, irrespective of dynamic visibility.
    pub(crate) fn module_com_object_exists(&self, number: u16) -> bool {
        self.expanded_modules.values().any(|module| {
            self.definition
                .module_defs
                .get(&module.module_def_id)
                .and_then(|module_def| {
                    module_def.static_section.com_objects.as_ref().map(|objects| {
                        objects.objects.iter().any(|object| {
                            module_object_number(module, module_def, object)
                                .is_some_and(|candidate| candidate == number)
                        })
                    })
                })
                .unwrap_or(false)
        })
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
        self.definition.module_defs.get(def_id)
    }

    /// Resolve one numeric module argument by the argument definition's ID.
    pub fn module_numeric_argument(&self, module: &ExpandedModule, argument_id: &str) -> Option<i64> {
        let module_def = self.definition.module_defs.get(&module.module_def_id)?;
        module_numeric_argument(module, module_def, argument_id)
    }

    /// Get all module definitions (for visitor pattern traversal).
    pub fn module_defs(&self) -> &HashMap<String, ModuleDef> {
        &self.definition.module_defs
    }

    /// Get a module parameter value.
    pub fn get_module_parameter_value(&self, instance_id: &str, param_id: &str) -> Option<&ParameterValue> {
        let composite_id = format!("{}::{}", instance_id, param_id);
        self.get_module_parameter_value_by_composite_id(&composite_id)
    }

    /// Set a module parameter value and recompute visibility.
    pub fn set_module_parameter_value(&mut self, instance_id: &str, param_id: &str, value: ParameterValue) {
        let composite_id = format!("{}::{}", instance_id, param_id);
        self.set_module_parameter_value_by_composite_id(&composite_id, value);
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
        addresses.sort_unstable();
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
        &self.definition.program.static_section
    }

    /// Get the dynamic section if present.
    pub fn dynamic_section(&self) -> Option<&crate::schema::DynamicSection> {
        self.definition.program.dynamic.as_ref()
    }

    /// Get the mask version string.
    pub fn mask_version(&self) -> &str {
        &self.definition.program.mask_version
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
        let (instance_id, parameter_id) = composite_id.split_once("::")?;
        let expanded = self.expanded_modules.get(instance_id)?;
        let module_def = self.definition.module_defs.get(&expanded.module_def_id)?;
        let parameter_ref = module_def
            .static_section
            .parameter_refs
            .as_ref()
            .and_then(|refs| refs.refs.iter().find(|parameter_ref| parameter_ref.id == parameter_id));

        if let Some(parameter_ref) = parameter_ref {
            if let Some(value) = self.derived_module_param_values.get(composite_id) {
                return Some(value);
            }
            if self.touched_module_params.contains_key(composite_id) {
                return self.module_param_values.get(composite_id);
            }
            let base_composite = format!("{}::{}", instance_id, parameter_ref.ref_id);
            if self.touched_module_params.contains_key(&base_composite) {
                return self.module_param_values.get(&base_composite);
            }
            return self
                .module_param_values
                .get(composite_id)
                .or_else(|| self.module_param_values.get(&base_composite));
        }

        // A storage-oriented caller may ask for the base parameter. Reflect
        // an edited ref which targets it so previews encode what the UI shows.
        if !self.touched_module_params.contains_key(composite_id)
            && let Some(refs) = &module_def.static_section.parameter_refs
            && let Some(value) = refs.refs.iter().find_map(|parameter_ref| {
                (parameter_ref.ref_id == parameter_id)
                    .then(|| format!("{}::{}", instance_id, parameter_ref.id))
                    .filter(|id| self.touched_module_params.contains_key(id))
                    .and_then(|id| self.module_param_values.get(&id))
            })
        {
            return Some(value);
        }
        self.module_param_values.get(composite_id)
    }

    /// A failed product derivation makes any generated process image unsafe.
    pub fn derivation_error(&self) -> Option<&str> {
        self.derivation_error.as_deref()
    }

    /// Derived ref values together with the concrete parameter storage they
    /// patch. They are deliberately separate from authored project settings.
    pub fn derived_parameter_values(&self) -> Vec<(String, &ParameterValue)> {
        let mut values = self
            .derived_param_ref_values
            .iter()
            .filter_map(|(ref_id, value)| {
                self.definition.param_refs.get(ref_id).map(|reference| (reference.ref_id.clone(), value))
            })
            .chain(self.derived_module_param_values.iter().filter_map(|(composite_id, value)| {
                let (instance_id, ref_id) = composite_id.split_once("::")?;
                let expanded = self.expanded_modules.get(instance_id)?;
                let module_def = self.definition.module_defs.get(&expanded.module_def_id)?;
                let reference = module_def
                    .static_section
                    .parameter_refs
                    .as_ref()?
                    .refs
                    .iter()
                    .find(|reference| reference.id == ref_id)?;
                Some((format!("{instance_id}::{}", reference.ref_id), value))
            }))
            .collect::<Vec<_>>();
        values.sort_by(|left, right| left.0.cmp(&right.0));
        values
    }

    /// Set a module parameter value by composite ID (instance_id::param_id).
    ///
    /// This is a convenience method for when the composite ID is already formed.
    pub fn set_module_parameter_value_by_composite_id(&mut self, composite_id: &str, value: ParameterValue) {
        let known = self.get_configuration_parameter_info(composite_id).is_some();
        self.module_param_values.insert(composite_id.to_string(), value);
        self.touched_module_params.insert(composite_id.to_string(), known);
        self.recompute_visibility();
    }

    /// Active module values explicitly authored in this session.
    pub fn touched_module_parameter_values(&self) -> impl Iterator<Item = (&str, &ParameterValue)> {
        self.touched_module_params.keys().filter_map(|id| {
            let (instance_id, _) = id.split_once("::")?;
            self.expanded_modules
                .contains_key(instance_id)
                .then(|| (id.as_str(), self.module_param_values.get(id).expect("touched module parameter has a value")))
        })
    }

    /// Effective product default for a concrete module parameter or ref ID.
    pub(crate) fn module_parameter_default(&self, composite_id: &str) -> Option<ParameterValue> {
        let (instance_id, parameter_id) = composite_id.split_once("::")?;
        let expanded = self.expanded_modules.get(instance_id)?;
        let module_def = self.definition.module_defs.get(&expanded.module_def_id)?;
        let parameter_ref = module_def
            .static_section
            .parameter_refs
            .as_ref()
            .and_then(|refs| refs.refs.iter().find(|parameter_ref| parameter_ref.id == parameter_id));
        let base_id = parameter_ref.map_or(parameter_id, |parameter_ref| parameter_ref.ref_id.as_str());
        let info = self.definition.module_parameters.get(&format!("{}::{base_id}", expanded.module_def_id))?;
        let raw = parameter_ref.and_then(|parameter_ref| parameter_ref.value.as_deref()).unwrap_or(&info.default_value);
        Some(parse_value_for_type(self.definition.param_types.get(&info.type_id), raw))
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
        let value = self.get_parameter_value(&param_ref.id)?;

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
        let parameter_type =
            self.get_parameter_info(param_id).and_then(|info| self.definition.param_types.get(&info.type_id));
        parse_value_for_type(parameter_type, raw)
    }

    /// A ref by full id first, by numeric tail second.
    fn lookup_param_ref(&self, ref_id: &str) -> Option<&ParameterRef> {
        self.definition.param_refs.get(ref_id).or_else(|| {
            self.definition.param_ref_tails.get(ref_id).and_then(|full| self.definition.param_refs.get(full))
        })
    }

    /// Resolve a text parameter ref (used for {{0}} substitution).
    ///
    /// Only returns text values - integers are not converted to strings here
    /// because {{0}} substitution is meant for actual text content (like channel names),
    /// not numeric values.
    fn resolve_text_param_ref(&self, ref_id: &str) -> Option<String> {
        let param_ref = self.lookup_param_ref(ref_id)?;
        let value = self.get_parameter_value(&param_ref.id)?;

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
        // Repeats instantiate and dispose modules as their count parameter or
        // enclosing choices change. Rebuild the active instance roster first,
        // but retain values of temporarily inactive instances so reducing and
        // restoring a count does not discard the user's edits.
        let (expanded_modules, expansion_error) = expand_active_modules(
            &self.definition.program,
            &self.definition.module_defs,
            &self.definition.param_refs,
            &self.param_values,
            &self.param_ref_values,
            &self.touched_params,
            &self.touched_param_refs,
        );
        self.expanded_modules = expanded_modules;
        initialize_module_param_values(
            &mut self.module_param_values,
            &self.expanded_modules,
            &self.definition.module_defs,
            &self.definition.module_parameters,
            &self.definition.param_types,
        );

        self.visible_param_refs.clear();
        self.active_param_refs.clear();
        self.visible_module_param_refs.clear();
        self.visible_com_object_refs.clear();
        self.visible_module_com_object_refs.clear();
        self.visible_modules.clear();
        self.active_block_renames.clear();
        self.derived_param_ref_values.clear();
        self.derived_module_param_values.clear();
        // Failed active modules must not disappear into an apparently valid
        // configuration. The same public error channel covers calculations
        // and expansion, so callers discard either kind of partial state.
        self.derivation_error = expansion_error;
        if self.derivation_error.is_some() {
            return;
        }

        // Build the read-only lookup context from self's maps, then call the
        // free traversal function so the borrow checker sees distinct borrows:
        // `self.definition.program.dynamic` (read) vs. `self.visible_*` (write).
        //
        // Iterated to a fixpoint because choose gating is
        // self-referential: a choose counts only when its selector's
        // ref is active, and that ref may itself sit inside another
        // choose. The active set only ever grows across iterations
        // (opening a choose can hide nothing), so the loop converges;
        // the bound is the deepest selector chain, with a hard cap as
        // a backstop against product-data cycles.
        // Active refs include controls under `Access="None"` blocks: their
        // defaults still drive chooses even though project editors must not
        // expose them. Keep that fixpoint state separate from the public,
        // user-visible set. Derived values participate in the same fixpoint:
        // an `Assign` can feed a later choose or parameter calculation.
        let mut active_param_refs = HashSet::new();

        // The cap must cover the deepest selector chain: converted BCU2
        // programs alternate block-header refs and nested selectors up to
        // ~8 levels, and each level opens one iteration after its selector
        // became active.
        for _ in 0..16 {
            let (
                next_active_param_refs,
                visible_param_refs,
                visible_module_param_refs,
                objects,
                module_objects,
                modules,
                renames,
                assignments,
            ) = {
                let mut next_active_param_refs = HashSet::new();
                let mut visible_param_refs = HashSet::new();
                let mut visible_module_param_refs = HashSet::new();
                let mut objects = HashSet::new();
                let mut module_objects = HashSet::new();
                let mut modules = HashSet::new();
                let mut renames = HashMap::new();
                let mut assignments = Vec::new();
                let ctx = VisibilityReadCtx {
                    param_refs: &self.definition.param_refs,
                    param_values: &self.param_values,
                    param_ref_values: &self.param_ref_values,
                    module_param_values: &self.module_param_values,
                    derived_param_ref_values: &self.derived_param_ref_values,
                    derived_module_param_values: &self.derived_module_param_values,
                    touched_params: &self.touched_params,
                    touched_param_refs: &self.touched_param_refs,
                    touched_module_params: &self.touched_module_params,
                    module_defs: &self.definition.module_defs,
                    expanded_modules: &self.expanded_modules,
                };
                let mut output = VisibilityOutput {
                    active_params: &mut next_active_param_refs,
                    visible_params: &mut visible_param_refs,
                    module_params: &mut visible_module_param_refs,
                    objects: &mut objects,
                    module_objects: &mut module_objects,
                    modules: &mut modules,
                    renames: &mut renames,
                    assignments: &mut assignments,
                };
                if let Some(dynamic) = &self.definition.program.dynamic {
                    traverse_dynamic_section(dynamic, &ctx, &mut output, &active_param_refs);
                }

                (
                    next_active_param_refs,
                    visible_param_refs,
                    visible_module_param_refs,
                    objects,
                    module_objects,
                    modules,
                    renames,
                    assignments,
                )
            };

            let derived = self.derive_parameter_values(&assignments);
            let (next_derived_refs, next_derived_module_refs) = match derived {
                Ok(values) => values,
                Err(error) => {
                    self.derivation_error = Some(error);
                    break;
                }
            };
            let stable = next_active_param_refs == active_param_refs
                && next_derived_refs == self.derived_param_ref_values
                && next_derived_module_refs == self.derived_module_param_values;
            active_param_refs = next_active_param_refs;
            self.active_param_refs = active_param_refs.clone();
            self.derived_param_ref_values = next_derived_refs;
            self.derived_module_param_values = next_derived_module_refs;
            self.visible_param_refs = visible_param_refs;
            self.visible_module_param_refs = visible_module_param_refs;
            self.visible_com_object_refs = objects;
            self.visible_module_com_object_refs = module_objects;
            self.visible_modules = modules;
            self.active_block_renames = renames;

            if stable {
                break;
            }
        }
    }

    /// Rebuild the values which active dynamic `Assign` nodes impose. Starting
    /// from empty maps is important: when a `when` branch closes, assignments
    /// from that branch must disappear instead of surviving as a cache.
    ///
    /// Parameter calculations are deliberately absent. They run only while a
    /// parameter is edited, and their results are stored values; see
    /// [`Self::try_set_parameter_value`].
    fn derive_parameter_values(
        &self,
        assignments: &[ActiveAssignment],
    ) -> Result<(HashMap<String, ParameterValue>, HashMap<String, ParameterValue>), String> {
        let mut root = HashMap::new();
        let mut modules = HashMap::new();

        for active in assignments {
            let target =
                self.qualify_parameter_ref(active.module_instance.as_deref(), &active.assignment.target_param_ref_ref);
            let value = match (&active.assignment.source_param_ref_ref, &active.assignment.value) {
                (Some(source), None) => {
                    let source = self.qualify_parameter_ref(active.module_instance.as_deref(), source);
                    self.derivation_value(&source, &root, &modules)
                        .cloned()
                        .ok_or_else(|| format!("assignment target `{target}` references unknown source `{source}`"))?
                }
                (None, Some(raw)) => {
                    let info = self
                        .get_configuration_parameter_info(&target)
                        .ok_or_else(|| format!("assignment references unknown target `{target}`"))?;
                    parse_value_for_type(self.definition.param_types.get(&info.type_id), raw)
                }
                (Some(_), Some(_)) => {
                    return Err(format!("assignment target `{target}` supplies both SourceParamRefRef and Value"));
                }
                (None, None) => {
                    return Err(format!("assignment target `{target}` supplies neither SourceParamRefRef nor Value"));
                }
            };
            insert_derived_value(target, value, &mut root, &mut modules);
        }

        Ok((root, modules))
    }

    fn parameter_type_for_configuration_id(&self, id: &str) -> Option<&ParameterTypeDef> {
        self.get_configuration_parameter_info(id)
            .and_then(|info| self.definition.param_types.get(&info.type_id))
            .map(|parameter_type| &parameter_type.type_def)
    }

    // ========================================================================
    // Product Scripts
    // ========================================================================

    /// Every concrete calculation: the application's own, then each module
    /// definition's once per expanded instance of it, ordered by instance ID.
    fn calculation_scopes(&self) -> Vec<(&ParameterCalculation, Option<&str>)> {
        let mut scopes: Vec<(&ParameterCalculation, Option<&str>)> = Vec::new();
        if let Some(calculations) = &self.definition.program.static_section.parameter_calculations {
            scopes.extend(calculations.calculations.iter().map(|calculation| (calculation, None)));
        }
        let mut modules = self.expanded_modules.values().collect::<Vec<_>>();
        modules.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
        for module in modules {
            let Some(module_def) = self.definition.module_defs.get(&module.module_def_id) else { continue };
            if let Some(calculations) = &module_def.static_section.parameter_calculations {
                scopes.extend(
                    calculations
                        .calculations
                        .iter()
                        .map(|calculation| (calculation, Some(module.instance_id.as_str()))),
                );
            }
        }
        scopes
    }

    /// Every concrete validation, scoped like [`Self::calculation_scopes`].
    fn validation_scopes(&self) -> Vec<(&ParameterValidation, Option<&str>)> {
        let mut scopes: Vec<(&ParameterValidation, Option<&str>)> = Vec::new();
        if let Some(validations) = &self.definition.program.static_section.parameter_validations {
            scopes.extend(validations.validations.iter().map(|validation| (validation, None)));
        }
        let mut modules = self.expanded_modules.values().collect::<Vec<_>>();
        modules.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
        for module in modules {
            let Some(module_def) = self.definition.module_defs.get(&module.module_def_id) else { continue };
            if let Some(validations) = &module_def.static_section.parameter_validations {
                scopes.extend(
                    validations.validations.iter().map(|validation| (validation, Some(module.instance_id.as_str()))),
                );
            }
        }
        scopes
    }

    /// Whether a configuration ID is written by a product calculation. Such
    /// values are stored like authored ones, but the product owns them: they
    /// may sit behind `Access="None"` and are accepted from saved projects
    /// even where a user could not edit them.
    pub fn is_calculation_parameter(&self, id: &str) -> bool {
        let mentions = |calculations: Option<&crate::schema::ParameterCalculations>, ref_id: &str| {
            calculations.is_some_and(|calculations| {
                calculations.calculations.iter().any(|calculation| {
                    calculation
                        .left_parameters
                        .parameters
                        .iter()
                        .chain(&calculation.right_parameters.parameters)
                        .any(|reference| reference.ref_id == ref_id)
                })
            })
        };

        // Module IDs differ from root IDs, so a module definition's own
        // references can only match through an instance; a root reference
        // can be named by any calculation, including a module's.
        if let Some((instance, ref_id)) = id.split_once("::") {
            return self
                .expanded_modules
                .get(instance)
                .and_then(|module| self.definition.module_defs.get(&module.module_def_id))
                .is_some_and(|module_def| mentions(module_def.static_section.parameter_calculations.as_ref(), ref_id));
        }
        mentions(self.definition.program.static_section.parameter_calculations.as_ref(), id)
            || self
                .definition
                .module_defs
                .values()
                .any(|module_def| mentions(module_def.static_section.parameter_calculations.as_ref(), id))
    }

    /// Edited values of references which are active but not shown, as
    /// `(storage ID, reference ID)`. Only product calculations can store
    /// these; they reach the download like any active value.
    pub(crate) fn hidden_active_edits(&self) -> Vec<(String, String)> {
        // Without a dynamic section nothing selects references, so every one
        // of them is active.
        let unconditional = self.definition.program.dynamic.is_none();
        let mut edits = Vec::new();
        for ref_id in &self.touched_param_refs {
            if (unconditional || self.active_param_refs.contains(ref_id))
                && !self.visible_param_refs.contains(ref_id)
                && let Some(reference) = self.definition.param_refs.get(ref_id)
            {
                edits.push((reference.ref_id.clone(), ref_id.clone()));
            }
        }
        for id in self.touched_module_params.keys() {
            let Some((instance, ref_id)) = id.split_once("::") else { continue };
            if !self.active_param_refs.contains(id) || self.visible_module_param_refs.contains(id) {
                continue;
            }
            let Some(reference) = self.scoped_parameter_ref(Some(instance), ref_id) else { continue };
            edits.push((format!("{instance}::{}", reference.ref_id), id.clone()));
        }
        edits.sort();
        edits
    }

    /// The current value of a root or module configuration ID as a script
    /// reads it, including values imposed by active assignments.
    fn script_parameter_value(&self, id: &str) -> Option<ParameterValue> {
        if id.contains("::") {
            self.get_module_parameter_value_by_composite_id(id).cloned()
        } else {
            self.get_parameter_value(id).cloned()
        }
    }

    /// The `ParameterRef` behind a scoped calculation or validation reference.
    fn scoped_parameter_ref(&self, scope: Option<&str>, ref_id: &str) -> Option<&ParameterRef> {
        if let Some(module) = scope.and_then(|instance| self.expanded_modules.get(instance))
            && let Some(reference) = self
                .definition
                .module_defs
                .get(&module.module_def_id)
                .and_then(|module_def| module_def.static_section.parameter_refs.as_ref())
                .and_then(|references| references.refs.iter().find(|reference| reference.id == ref_id))
        {
            return Some(reference);
        }
        self.definition.param_refs.get(ref_id)
    }

    fn script_binding(
        &self,
        scope: Option<&str>,
        reference: &CalculationParameterRef,
    ) -> Result<(String, ScriptBinding<'_>), String> {
        let id = self.qualify_parameter_ref(scope, &reference.ref_id);
        let value = self.script_parameter_value(&id).ok_or_else(|| format!("script parameter `{id}` has no value"))?;
        let parameter_name = self.get_configuration_parameter_info(&id).map_or("", |info| info.name.as_str());
        let reference_name =
            self.scoped_parameter_ref(scope, &reference.ref_id).and_then(|reference| reference.name.as_deref());
        let name = script_name(reference.alias_name.as_deref(), reference_name, parameter_name);
        let type_def = self.parameter_type_for_configuration_id(&id);
        Ok((id, ScriptBinding { name, value, type_def }))
    }

    /// `(number, name, text)` of the application's messages; a message's
    /// number is the tail of its `_M-<n>` ID.
    fn script_messages(&self) -> Vec<(Option<i32>, &str, &str)> {
        self.definition
            .program
            .static_section
            .messages
            .iter()
            .flat_map(|messages| &messages.messages)
            .map(|message| {
                let number = message.id.rsplit_once("_M-").and_then(|(_, number)| number.parse().ok());
                (number, message.name.as_str(), message.text.as_str())
            })
            .collect()
    }

    /// The textual value of an argument of the executing module instance.
    fn module_argument_text(&self, scope: Option<&str>, name: &str) -> Option<String> {
        let module = self.expanded_modules.get(scope?)?;
        module.args.get(name).map(format_arg_value)
    }

    /// Run the product's validations for an edit of `id` to `value`, before
    /// anything is stored. The first rejection wins.
    fn validate_edit(&self, id: &str, value: &ParameterValue) -> Result<(), ConfigurationError> {
        let messages = self.script_messages();
        let host = ScriptHost { script: self.definition.program.static_section.script.as_deref(), messages: &messages };
        for (validation, scope) in self.validation_scopes() {
            let Some(changed_reference) = validation
                .parameters
                .parameters
                .iter()
                .find(|reference| self.qualify_parameter_ref(scope, &reference.ref_id) == id)
            else {
                continue;
            };

            // Every input reads its current value except the edited one,
            // which the script sees with the proposed value.
            let derivation =
                |error: String| ConfigurationError::Derivation(format!("validation `{}`: {error}", validation.id));
            let (_, mut changed) = self.script_binding(scope, changed_reference).map_err(derivation)?;
            changed.value = value.clone();
            let mut inputs = Vec::new();
            for reference in &validation.parameters.parameters {
                let (input_id, mut binding) = self.script_binding(scope, reference).map_err(derivation)?;
                if input_id == id {
                    binding.value = value.clone();
                }
                inputs.push(binding);
            }

            let argument = |name: &str| self.module_argument_text(scope, name);
            match execute_validation(&host, validation, &inputs, &changed, &argument).map_err(derivation)? {
                ValidationOutcome::Valid => {}
                ValidationOutcome::Invalid(message) => {
                    return Err(ConfigurationError::Rejected { param: id.to_owned(), message });
                }
            }
        }
        Ok(())
    }

    /// Run the calculations an edit of `id` triggers and store their results.
    /// Returns whether any calculation ran.
    fn run_calculations(&mut self, id: &str) -> Result<bool, String> {
        let scopes = self.calculation_scopes();
        let edges = scopes
            .iter()
            .map(|(calculation, scope)| CalculationEdges {
                left: calculation
                    .left_parameters
                    .parameters
                    .iter()
                    .map(|reference| self.qualify_parameter_ref(*scope, &reference.ref_id))
                    .collect(),
                right: calculation
                    .right_parameters
                    .parameters
                    .iter()
                    .map(|reference| self.qualify_parameter_ref(*scope, &reference.ref_id))
                    .collect(),
            })
            .collect::<Vec<_>>();
        let plan = plan_for_change(&edges, id)?;
        if plan.is_empty() {
            return Ok(false);
        }

        let messages = self.script_messages();
        let host = ScriptHost { script: self.definition.program.static_section.script.as_deref(), messages: &messages };
        let mut results: Vec<(String, ParameterValue)> = Vec::new();
        for (index, direction) in plan {
            let (calculation, scope) = scopes[index];
            let (input_refs, output_refs) = match direction {
                Direction::LeftToRight => (&calculation.left_parameters, &calculation.right_parameters),
                Direction::RightToLeft => (&calculation.right_parameters, &calculation.left_parameters),
            };

            // A later calculation must see what an earlier one in the same
            // plan stored, before any of it reaches the device state.
            let bind = |reference: &CalculationParameterRef| -> Result<(String, ScriptBinding<'_>), String> {
                let (bound_id, mut binding) = self.script_binding(scope, reference)?;
                if let Some((_, value)) = results.iter().rev().find(|(stored, _)| *stored == bound_id) {
                    binding.value = value.clone();
                }
                Ok((bound_id, binding))
            };
            let inputs = input_refs.parameters.iter().map(bind).collect::<Result<Vec<_>, _>>()?;
            let outputs = output_refs.parameters.iter().map(bind).collect::<Result<Vec<_>, _>>()?;
            let input_bindings = inputs.into_iter().map(|(_, binding)| binding).collect::<Vec<_>>();
            let (output_ids, output_bindings): (Vec<_>, Vec<_>) = outputs.into_iter().unzip();

            let argument = |name: &str| self.module_argument_text(scope, name);
            let values =
                execute_calculation(&host, calculation, direction, &input_bindings, &output_bindings, &argument)
                    .map_err(|error| format!("calculation `{}`: {error}", calculation.id))?;
            for (output_id, value) in output_ids.into_iter().zip(values) {
                if let Some(value) = value {
                    results.push((output_id, value));
                }
            }
        }

        for (output_id, value) in results {
            self.store_value(&output_id, value);
        }
        Ok(true)
    }

    /// Store a value without recomputing visibility, as an edit would.
    fn store_value(&mut self, id: &str, value: ParameterValue) {
        if id.contains("::") {
            let known = self.get_configuration_parameter_info(id).is_some();
            self.module_param_values.insert(id.to_owned(), value);
            self.touched_module_params.insert(id.to_owned(), known);
        } else if self.definition.param_refs.contains_key(id) {
            self.param_ref_values.insert(id.to_owned(), value);
            self.touched_param_refs.insert(id.to_owned());
        } else {
            self.param_values.insert(id.to_owned(), value);
            self.touched_params.insert(id.to_owned());
        }
    }

    /// A module's dynamic program may refer both to parameters declared by
    /// that module and to application-wide parameters. Qualify only references
    /// actually owned by the module definition; otherwise the invented
    /// `instance::root-ref` ID can neither be read nor persisted.
    fn qualify_parameter_ref(&self, module_instance: Option<&str>, ref_id: &str) -> String {
        let Some(instance_id) = module_instance else { return ref_id.to_string() };
        let Some(expanded) = self.expanded_modules.get(instance_id) else { return ref_id.to_string() };
        let Some(module_def) = self.definition.module_defs.get(&expanded.module_def_id) else {
            return ref_id.to_string();
        };
        let owns_reference = module_def
            .static_section
            .parameter_refs
            .as_ref()
            .is_some_and(|references| references.refs.iter().any(|reference| reference.id == ref_id));

        if owns_reference { format!("{instance_id}::{ref_id}") } else { ref_id.to_string() }
    }

    fn derivation_value<'a>(
        &'a self,
        id: &str,
        root: &'a HashMap<String, ParameterValue>,
        modules: &'a HashMap<String, ParameterValue>,
    ) -> Option<&'a ParameterValue> {
        if let Some((instance_id, parameter_id)) = id.split_once("::") {
            if let Some(value) = modules.get(id) {
                return Some(value);
            }
            let expanded = self.expanded_modules.get(instance_id)?;
            let module_def = self.definition.module_defs.get(&expanded.module_def_id)?;
            let reference = module_def
                .static_section
                .parameter_refs
                .as_ref()?
                .refs
                .iter()
                .find(|reference| reference.id == parameter_id);
            if let Some(reference) = reference {
                if self.touched_module_params.contains_key(id) {
                    return self.module_param_values.get(id);
                }
                let base = format!("{instance_id}::{}", reference.ref_id);
                if self.touched_module_params.contains_key(&base) {
                    return self.module_param_values.get(&base);
                }
                return self.module_param_values.get(id).or_else(|| self.module_param_values.get(&base));
            }
            return self.module_param_values.get(id);
        }

        if let Some(value) = root.get(id) {
            return Some(value);
        }
        let Some(reference) = self.definition.param_refs.get(id) else {
            return self.param_values.get(id);
        };
        if self.touched_param_refs.contains(id) || !self.touched_params.contains(&reference.ref_id) {
            self.param_ref_values.get(id)
        } else {
            self.param_values.get(&reference.ref_id)
        }
    }

    fn get_selector_value(&self, param_ref_id: &str) -> Option<i64> {
        let param_ref = self.definition.param_refs.get(param_ref_id)?;
        let param_value =
            if self.touched_param_refs.contains(param_ref_id) || !self.touched_params.contains(&param_ref.ref_id) {
                self.param_ref_values.get(param_ref_id)?
            } else {
                self.param_values.get(&param_ref.ref_id)?
            };

        // `param_ref_values` already holds the reference's own default,
        // parsed with the parameter's type, until the parameter is edited.
        match param_value {
            ParameterValue::Integer(v) => Some(*v),
            ParameterValue::Float(v) => Some(*v as i64),
            _ => None,
        }
    }
}

fn insert_derived_value(
    id: String,
    value: ParameterValue,
    root: &mut HashMap<String, ParameterValue>,
    modules: &mut HashMap<String, ParameterValue>,
) {
    if id.contains("::") {
        modules.insert(id, value);
    } else {
        root.insert(id, value);
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
            let composite_id = format!("{}::{}", ctx.instance_id, param_ref.id);
            if let Some(value) = self.get_module_parameter_value_by_composite_id(&composite_id) {
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

    fn repeat_modules(&self, repeat_id: &str, prototype_id: &str) -> Vec<Module> {
        let mut modules = self
            .expanded_modules
            .values()
            .filter(|expanded| {
                expanded.repeat_id.as_deref() == Some(repeat_id) && expanded.prototype_id == prototype_id
            })
            .map(|expanded| expanded.module.clone())
            .collect::<Vec<_>>();
        modules.sort_by(|left, right| left.id.cmp(&right.id));
        modules
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
    param_ref_values: &'a HashMap<String, ParameterValue>,
    module_param_values: &'a HashMap<String, ParameterValue>,
    derived_param_ref_values: &'a HashMap<String, ParameterValue>,
    derived_module_param_values: &'a HashMap<String, ParameterValue>,
    touched_params: &'a HashSet<String>,
    touched_param_refs: &'a HashSet<String>,
    touched_module_params: &'a HashMap<String, bool>,
    module_defs: &'a HashMap<String, ModuleDef>,
    expanded_modules: &'a HashMap<String, ExpandedModule>,
}

/// Mutable products of one visibility fixpoint iteration.
///
/// These sets change together at every traversal step. Bundling their borrows
/// keeps the recursive visitor signatures focused on the XML node and its
/// evaluation context instead of repeating five accumulator parameters.
struct VisibilityOutput<'a> {
    active_params: &'a mut HashSet<String>,
    visible_params: &'a mut HashSet<String>,
    module_params: &'a mut HashSet<String>,
    objects: &'a mut HashSet<String>,
    module_objects: &'a mut HashSet<String>,
    modules: &'a mut HashSet<String>,
    renames: &'a mut HashMap<String, String>,
    assignments: &'a mut Vec<ActiveAssignment>,
}

#[derive(Debug, Clone)]
struct ActiveAssignment {
    module_instance: Option<String>,
    assignment: Assign,
}

fn scoped_parameter_ref(ref_id: &str, module_ctx: Option<&ModuleContext>) -> String {
    module_ctx
        .filter(|module_ctx| module_owns_parameter_ref(module_ctx, ref_id))
        .map_or_else(|| ref_id.to_string(), |module_ctx| format!("{}::{ref_id}", module_ctx.instance_id))
}

fn module_owns_parameter_ref(module_ctx: &ModuleContext, ref_id: &str) -> bool {
    module_ctx
        .module_def
        .static_section
        .parameter_refs
        .as_ref()
        .is_some_and(|references| references.refs.iter().any(|reference| reference.id == ref_id))
}

fn mark_parameter_ref(
    ref_id: &str,
    module_ctx: Option<&ModuleContext>,
    parameters_visible: bool,
    output: &mut VisibilityOutput<'_>,
) {
    output.active_params.insert(scoped_parameter_ref(ref_id, module_ctx));
    if !parameters_visible {
        return;
    }
    if let Some(module_ctx) = module_ctx.filter(|module_ctx| module_owns_parameter_ref(module_ctx, ref_id)) {
        output.module_params.insert(format!("{}::{ref_id}", module_ctx.instance_id));
    } else {
        output.visible_params.insert(ref_id.to_string());
    }
}

fn mark_com_object_ref(ref_id: &str, module_ctx: Option<&ModuleContext>, output: &mut VisibilityOutput<'_>) {
    if let Some(module_ctx) = module_ctx {
        output.module_objects.insert(format!("{}::{ref_id}", module_ctx.instance_id));
    } else {
        output.objects.insert(ref_id.to_string());
    }
}

impl VisibilityReadCtx<'_> {
    fn selector_value(&self, param_ref_id: &str, module_ctx: Option<&ModuleContext>) -> Option<i64> {
        if let Some(ctx) = module_ctx
            && let Some(param_refs) = &ctx.module_def.static_section.parameter_refs
            && let Some(param_ref) = param_refs.refs.iter().find(|pr| pr.id == param_ref_id)
        {
            let ref_composite_id = format!("{}::{}", ctx.instance_id, param_ref.id);
            let base_composite_id = format!("{}::{}", ctx.instance_id, param_ref.ref_id);
            let value = if let Some(value) = self.derived_module_param_values.get(&ref_composite_id) {
                Some(value)
            } else if self.touched_module_params.contains_key(&ref_composite_id) {
                self.module_param_values.get(&ref_composite_id)
            } else if self.touched_module_params.contains_key(&base_composite_id) {
                self.module_param_values.get(&base_composite_id)
            } else {
                self.module_param_values
                    .get(&ref_composite_id)
                    .or_else(|| self.module_param_values.get(&base_composite_id))
            };
            if let Some(value) = value {
                return match value {
                    ParameterValue::Integer(v) => Some(*v),
                    ParameterValue::Float(v) => Some(*v as i64),
                    _ => None,
                };
            }
        }
        let param_ref = self.param_refs.get(param_ref_id)?;
        let value = if let Some(value) = self.derived_param_ref_values.get(param_ref_id) {
            value
        } else if self.touched_param_refs.contains(param_ref_id) || !self.touched_params.contains(&param_ref.ref_id) {
            self.param_ref_values.get(param_ref_id)?
        } else {
            self.param_values.get(&param_ref.ref_id)?
        };
        match value {
            ParameterValue::Integer(v) => Some(*v),
            ParameterValue::Float(v) => Some(*v as i64),
            _ => None,
        }
    }
}

fn traverse_dynamic_section(
    dynamic: &DynamicSection,
    ctx: &VisibilityReadCtx<'_>,
    output: &mut VisibilityOutput<'_>,
    previously_active: &HashSet<String>,
) {
    for item in &dynamic.items {
        match item {
            DynamicItem::ChannelIndependentBlock(cib) => {
                for item in &cib.items {
                    match item {
                        ChannelIndependentItem::ParameterBlock(pb) => {
                            traverse_parameter_block(pb, None, true, ctx, output, previously_active);
                        }
                        ChannelIndependentItem::ComObjectRefRef(reference) => {
                            mark_com_object_ref(&reference.ref_id, None, output);
                        }
                        ChannelIndependentItem::Choose(choose) => {
                            traverse_choose(choose, None, true, ctx, output, previously_active);
                        }
                        ChannelIndependentItem::ParameterBlockRename(rename) => {
                            output.renames.insert(rename.ref_id.clone(), rename.text.clone().unwrap_or_default());
                        }
                        ChannelIndependentItem::Module(module) => {
                            traverse_module(module, true, ctx, output, previously_active);
                        }
                        ChannelIndependentItem::Repeat(repeat) => {
                            traverse_repeat(repeat, true, ctx, output, previously_active);
                        }
                    }
                }
            }
            DynamicItem::Channel(channel) => {
                traverse_channel(channel, None, true, ctx, output, previously_active);
            }
            // ETS6 programs gate whole channels on an enable parameter
            // via a Dynamic-level choose; the gate works exactly like
            // any other choose, and the channels sit in its when
            // branches (WhenItem::Channel).
            DynamicItem::Choose(choose) => {
                traverse_choose(choose, None, true, ctx, output, previously_active);
            }
            DynamicItem::Module(module) => traverse_module(module, true, ctx, output, previously_active),
            DynamicItem::Repeat(repeat) => traverse_repeat(repeat, true, ctx, output, previously_active),
        }
    }
}

fn traverse_channel(
    channel: &Channel,
    module_ctx: Option<&ModuleContext>,
    parameters_visible: bool,
    ctx: &VisibilityReadCtx<'_>,
    output: &mut VisibilityOutput<'_>,
    previously_active: &HashSet<String>,
) {
    for item in &channel.items {
        match item {
            ChannelItem::ParameterBlock(pb) => {
                traverse_parameter_block(pb, module_ctx, parameters_visible, ctx, output, previously_active);
            }
            ChannelItem::ComObjectRefRef(reference) => {
                mark_com_object_ref(&reference.ref_id, module_ctx, output);
            }
            ChannelItem::Choose(choose) => {
                traverse_choose(choose, module_ctx, parameters_visible, ctx, output, previously_active);
            }
            ChannelItem::Module(module) => {
                traverse_module(module, parameters_visible, ctx, output, previously_active);
            }
            ChannelItem::Repeat(repeat) => {
                traverse_repeat(repeat, parameters_visible, ctx, output, previously_active);
            }
            ChannelItem::ParameterBlockRename(rename) => {
                output.renames.insert(rename.ref_id.clone(), rename.text.clone().unwrap_or_default());
            }
        }
    }
}

fn traverse_parameter_block(
    pb: &ParameterBlock,
    module_ctx: Option<&ModuleContext>,
    parameters_visible: bool,
    ctx: &VisibilityReadCtx<'_>,
    output: &mut VisibilityOutput<'_>,
    previously_active: &HashSet<String>,
) {
    // `Access="None"` removes the parameter controls, not the block's
    // dynamic logic. In particular, real products put communication-object
    // refs behind invisible selector parameters. Keep those refs active so
    // their chooses still evaluate, but do not expose them to project editors.
    let parameters_visible = parameters_visible && pb.access.as_deref() != Some("None");

    // A block's `ParamRefId` header ref is a placement like any other: ETS
    // shows its parameter's text as the block title. Pre-ETS4 converted
    // programs (e.g. BCU2 products) rely on this by gating each block's
    // content `choose` on this very ref — without seeding it here, no choose
    // in such a program ever opens.
    if let Some(header_ref) = &pb.param_ref_id {
        mark_parameter_ref(header_ref, module_ctx, parameters_visible, output);
    }

    for item in &pb.items {
        match item {
            ParameterBlockItem::ParameterBlock(block) => {
                traverse_parameter_block(block, module_ctx, parameters_visible, ctx, output, previously_active);
            }
            ParameterBlockItem::ParameterRefRef(prr) => {
                mark_parameter_ref(&prr.ref_id, module_ctx, parameters_visible, output);
            }
            ParameterBlockItem::ComObjectRefRef(corr) => {
                mark_com_object_ref(&corr.ref_id, module_ctx, output);
            }
            ParameterBlockItem::Choose(choose) => {
                traverse_choose(choose, module_ctx, parameters_visible, ctx, output, previously_active);
            }
            ParameterBlockItem::Module(module) => {
                traverse_module(module, parameters_visible, ctx, output, previously_active);
            }
            ParameterBlockItem::Repeat(repeat) => {
                traverse_repeat(repeat, parameters_visible, ctx, output, previously_active);
            }
            ParameterBlockItem::ParameterBlockRename(rename) => {
                output.renames.insert(rename.ref_id.clone(), rename.text.clone().unwrap_or_default());
            }
            // Both are active exactly while the enclosing block is reached,
            // which is the same rule that applies inside a `when` branch.
            ParameterBlockItem::Assign(assignment) => output.assignments.push(ActiveAssignment {
                module_instance: module_ctx.map(|module_ctx| module_ctx.instance_id.clone()),
                assignment: assignment.clone(),
            }),
            ParameterBlockItem::Channel(channel) => {
                traverse_channel(channel, module_ctx, parameters_visible, ctx, output, previously_active);
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
    parameters_visible: bool,
    ctx: &VisibilityReadCtx<'_>,
    output: &mut VisibilityOutput<'_>,
    previously_active: &HashSet<String>,
) {
    // ETS scopes a choose to an active placement of its selector ref. A ref
    // in an `Access="None"` block is active for this purpose, although it is
    // absent from the user-visible parameter set. The MDT LED pages rely on
    // the other side of this distinction: their dynamic-brightness selector
    // is inactive until another choose places it in the tree. Evaluate that
    // activity against the previous fixpoint iteration's set.
    if !previously_active.contains(&scoped_parameter_ref(&choose.param_ref_id, module_ctx)) {
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
            traverse_when_items(&when.items, module_ctx, parameters_visible, ctx, output, previously_active);
            any_matched = true;
        }
    }

    if !any_matched && let Some(items) = default_items {
        traverse_when_items(items, module_ctx, parameters_visible, ctx, output, previously_active);
    }
}

fn traverse_when_items(
    items: &[WhenItem],
    module_ctx: Option<&ModuleContext>,
    parameters_visible: bool,
    ctx: &VisibilityReadCtx<'_>,
    output: &mut VisibilityOutput<'_>,
    previously_active: &HashSet<String>,
) {
    for item in items {
        match item {
            WhenItem::ParameterRefRef(prr) => {
                mark_parameter_ref(&prr.ref_id, module_ctx, parameters_visible, output);
            }
            WhenItem::ComObjectRefRef(corr) => {
                mark_com_object_ref(&corr.ref_id, module_ctx, output);
            }
            WhenItem::ParameterBlock(pb) => {
                traverse_parameter_block(pb, module_ctx, parameters_visible, ctx, output, previously_active);
            }
            WhenItem::Choose(nested_choose) => {
                traverse_choose(nested_choose, module_ctx, parameters_visible, ctx, output, previously_active);
            }
            WhenItem::Module(module) => {
                traverse_module(module, parameters_visible, ctx, output, previously_active);
            }
            WhenItem::Repeat(repeat) => {
                traverse_repeat(repeat, parameters_visible, ctx, output, previously_active);
            }
            WhenItem::ParameterBlockRename(rename) => {
                output.renames.insert(rename.ref_id.clone(), rename.text.clone().unwrap_or_default());
            }
            WhenItem::Channel(channel) => {
                traverse_channel(channel, module_ctx, parameters_visible, ctx, output, previously_active);
            }
            WhenItem::Assign(assignment) => output.assignments.push(ActiveAssignment {
                module_instance: module_ctx.map(|module_ctx| module_ctx.instance_id.clone()),
                assignment: assignment.clone(),
            }),
            WhenItem::ParameterSeparator(_) | WhenItem::Button(_) => {}
        }
    }
}

fn traverse_repeat(
    repeat: &Repeat,
    parameters_visible: bool,
    ctx: &VisibilityReadCtx<'_>,
    output: &mut VisibilityOutput<'_>,
    previously_active: &HashSet<String>,
) {
    for item in &repeat.items {
        match item {
            RepeatItem::Module(prototype) => {
                let mut modules = ctx
                    .expanded_modules
                    .values()
                    .filter(|expanded| {
                        expanded.repeat_id.as_deref() == Some(&repeat.id) && expanded.prototype_id == prototype.id
                    })
                    .collect::<Vec<_>>();
                modules.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
                for expanded in modules {
                    traverse_module(&expanded.module, parameters_visible, ctx, output, previously_active);
                }
            }
            RepeatItem::Choose(choose) => {
                traverse_choose(choose, None, parameters_visible, ctx, output, previously_active);
            }
            RepeatItem::Repeat(nested) => {
                traverse_repeat(nested, parameters_visible, ctx, output, previously_active);
            }
        }
    }
}

fn traverse_module(
    module: &Module,
    parameters_visible: bool,
    ctx: &VisibilityReadCtx<'_>,
    output: &mut VisibilityOutput<'_>,
    previously_active: &HashSet<String>,
) {
    if parameters_visible {
        output.modules.insert(module.id.clone());
    }

    if let Some(module_def) = ctx.module_defs.get(&module.ref_id)
        && let Some(dynamic) = &module_def.dynamic
    {
        let module_ctx = ModuleContext { instance_id: module.id.clone(), module_def: module_def.clone() };

        for item in &dynamic.items {
            match item {
                ModuleDefDynamicItem::ParameterBlock(pb) => {
                    traverse_parameter_block(pb, Some(&module_ctx), parameters_visible, ctx, output, previously_active);
                }
                ModuleDefDynamicItem::Choose(choose) => {
                    traverse_choose(choose, Some(&module_ctx), parameters_visible, ctx, output, previously_active);
                }
                ModuleDefDynamicItem::ChannelIndependentBlock(cib) => {
                    for item in &cib.items {
                        match item {
                            ChannelIndependentItem::ParameterBlock(pb) => traverse_parameter_block(
                                pb,
                                Some(&module_ctx),
                                parameters_visible,
                                ctx,
                                output,
                                previously_active,
                            ),
                            ChannelIndependentItem::Choose(choose) => traverse_choose(
                                choose,
                                Some(&module_ctx),
                                parameters_visible,
                                ctx,
                                output,
                                previously_active,
                            ),
                            ChannelIndependentItem::Module(module) => {
                                traverse_module(module, parameters_visible, ctx, output, previously_active);
                            }
                            ChannelIndependentItem::Repeat(repeat) => {
                                traverse_repeat(repeat, parameters_visible, ctx, output, previously_active);
                            }
                            ChannelIndependentItem::ComObjectRefRef(reference) => {
                                mark_com_object_ref(&reference.ref_id, Some(&module_ctx), output);
                            }
                            ChannelIndependentItem::ParameterBlockRename(rename) => {
                                output.renames.insert(rename.ref_id.clone(), rename.text.clone().unwrap_or_default());
                            }
                        }
                    }
                }
                ModuleDefDynamicItem::Channel(channel) => {
                    traverse_channel(channel, Some(&module_ctx), parameters_visible, ctx, output, previously_active);
                }
                ModuleDefDynamicItem::Module(module) => {
                    traverse_module(module, parameters_visible, ctx, output, previously_active);
                }
                ModuleDefDynamicItem::Repeat(repeat) => {
                    traverse_repeat(repeat, parameters_visible, ctx, output, previously_active);
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
            Some(
                crate::schema::ParameterTypeDef::TypeText(_)
                | crate::schema::ParameterTypeDef::TypeColor(_)
                | crate::schema::ParameterTypeDef::TypeIpAddress(_),
            ) => ParameterValue::Text(value.to_string()),
            Some(crate::schema::ParameterTypeDef::TypeRawData(_)) => parse_raw_data_value(value),
            Some(crate::schema::ParameterTypeDef::TypeTime(_)) => ParameterValue::Integer(value.parse().unwrap_or(0)),
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
/// used by product/project configuration to interpret `ParameterRef` value overrides.
/// `TypeRawData` values are base64 (`xs:base64Binary`): the reference
/// decodes them with a plain base64 conversion and neither pads nor
/// truncates them. Every non-empty catalogue default is base64, for example
/// 688 characters for a 516-byte `MaxSize`. The numeric-first default guess
/// would turn `1234` into an integer, so decode them explicitly; malformed
/// base64 stays text rather than inventing bytes.
fn parse_raw_data_value(value: &str) -> ParameterValue {
    use base64::Engine;

    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_or_else(|_| ParameterValue::Text(value.to_string()), ParameterValue::Bytes)
}

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

fn build_param_ref_order(static_section: &StaticSection) -> Vec<String> {
    static_section
        .parameter_refs
        .iter()
        .flat_map(|parameter_refs| parameter_refs.refs.iter().map(|parameter_ref| parameter_ref.id.clone()))
        .collect()
}

fn build_param_ref_value_lookup(
    param_refs: &HashMap<String, ParameterRef>,
    parameters: &HashMap<String, ParameterInfo>,
    param_values: &HashMap<String, ParameterValue>,
    param_types: &HashMap<String, ParameterType>,
) -> HashMap<String, ParameterValue> {
    param_refs
        .iter()
        .filter_map(|(id, parameter_ref)| {
            let base = parameters.get(&parameter_ref.ref_id)?;
            let value = parameter_ref.value.as_deref().map_or_else(
                || param_values.get(&parameter_ref.ref_id).cloned(),
                |raw| Some(parse_value_for_type(param_types.get(&base.type_id), raw)),
            )?;
            Some((id.clone(), value))
        })
        .collect()
}

fn parse_value_for_type(parameter_type: Option<&ParameterType>, raw: &str) -> ParameterValue {
    match parameter_type.map(|parameter_type| &parameter_type.type_def) {
        Some(
            crate::schema::ParameterTypeDef::TypeText(_)
            | crate::schema::ParameterTypeDef::TypeColor(_)
            | crate::schema::ParameterTypeDef::TypeIpAddress(_),
        ) => ParameterValue::Text(raw.to_string()),
        Some(crate::schema::ParameterTypeDef::TypeRawData(_)) => parse_raw_data_value(raw),
        Some(crate::schema::ParameterTypeDef::TypeTime(_)) => ParameterValue::Integer(raw.parse().unwrap_or(0)),
        Some(crate::schema::ParameterTypeDef::TypeFloat(_)) => ParameterValue::Float(raw.parse().unwrap_or(0.0)),
        Some(crate::schema::ParameterTypeDef::TypeNumber(_) | crate::schema::ParameterTypeDef::TypeRestriction(_)) => {
            ParameterValue::Integer(raw.parse().unwrap_or(0))
        }
        _ => parse_default_value(raw),
    }
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

fn build_module_parameter_lookup(module_defs: &HashMap<String, ModuleDef>) -> HashMap<String, ParameterInfo> {
    let mut parameters = HashMap::new();
    for module_def in module_defs.values() {
        let Some(items) = module_def.static_section.parameters.as_ref().map(|parameters| &parameters.items) else {
            continue;
        };
        for item in items {
            match item {
                ParameterItem::Parameter(parameter) => {
                    parameters.insert(format!("{}::{}", module_def.id, parameter.id), ParameterInfo {
                        id: parameter.id.clone(),
                        name: parameter.name.clone(),
                        text: parameter.text.clone(),
                        type_id: parameter.parameter_type.clone(),
                        default_value: parameter.value.clone(),
                        suffix: parameter.suffix_text.clone(),
                        hidden: parameter.access.as_deref() == Some("None"),
                        read_only: parameter.access.as_deref() == Some("Read"),
                    });
                }
                ParameterItem::Union(union) => {
                    for parameter in &union.parameters {
                        parameters.insert(format!("{}::{}", module_def.id, parameter.id), ParameterInfo {
                            id: parameter.id.clone(),
                            name: parameter.name.clone(),
                            text: parameter.text.clone(),
                            type_id: parameter.parameter_type.clone(),
                            default_value: parameter.value.clone(),
                            suffix: parameter.suffix_text.clone(),
                            hidden: parameter.access.as_deref() == Some("None"),
                            read_only: parameter.access.as_deref() == Some("Read"),
                        });
                    }
                }
            }
        }
    }
    parameters
}

fn initialize_module_param_values(
    values: &mut HashMap<String, ParameterValue>,
    expanded_modules: &HashMap<String, ExpandedModule>,
    module_defs: &HashMap<String, ModuleDef>,
    module_parameters: &HashMap<String, ParameterInfo>,
    param_types: &HashMap<String, ParameterType>,
) {
    for (instance_id, expanded) in expanded_modules {
        if let Some(module_def) = module_defs.get(&expanded.module_def_id)
            && let Some(params) = &module_def.static_section.parameters
        {
            for item in &params.items {
                match item {
                    ParameterItem::Parameter(p) => {
                        let composite_id = format!("{}::{}", instance_id, p.id);
                        let default = parse_value_for_type(param_types.get(&p.parameter_type), &p.value);
                        values.entry(composite_id).or_insert(default);
                    }
                    ParameterItem::Union(u) => {
                        // Also initialize union parameters
                        for up in &u.parameters {
                            let composite_id = format!("{}::{}", instance_id, up.id);
                            let default = parse_value_for_type(param_types.get(&up.parameter_type), &up.value);
                            values.entry(composite_id).or_insert(default);
                        }
                    }
                }
            }

            if let Some(parameter_refs) = &module_def.static_section.parameter_refs {
                for parameter_ref in &parameter_refs.refs {
                    let composite_id = format!("{}::{}", instance_id, parameter_ref.id);
                    let base_composite_id = format!("{}::{}", instance_id, parameter_ref.ref_id);
                    if values.contains_key(&composite_id) {
                        continue;
                    }
                    let Some(base_value) = values.get(&base_composite_id).cloned() else { continue };
                    let parameter_type = module_parameters
                        .get(&format!("{}::{}", expanded.module_def_id, parameter_ref.ref_id))
                        .and_then(|parameter| param_types.get(&parameter.type_id));
                    let value = parameter_ref
                        .value
                        .as_deref()
                        .map_or(base_value, |raw| parse_value_for_type(parameter_type, raw));
                    values.insert(composite_id, value);
                }
            }
        }
    }
}

/// Materialize the modules present under the current parameter choices.
///
/// Allocators are shared across the application and consumed in dynamic XML
/// order. Their `maxInclusive` value is the first value after the allocated
/// range in real Manufacturer Tool products (for example 12 arguments of
/// size 78 span `2442..3378`), so the post-allocation cursor may equal it.
fn expand_active_modules(
    program: &ApplicationProgram,
    module_defs: &HashMap<String, ModuleDef>,
    param_refs: &HashMap<String, ParameterRef>,
    param_values: &HashMap<String, ParameterValue>,
    param_ref_values: &HashMap<String, ParameterValue>,
    touched_params: &HashSet<String>,
    touched_param_refs: &HashSet<String>,
) -> (HashMap<String, ExpandedModule>, Option<String>) {
    let allocators = program
        .static_section
        .allocators
        .iter()
        .flat_map(|allocators| allocators.allocators.iter())
        .map(|allocator| (allocator.id.clone(), allocator.clone()))
        .collect();
    let mut expander = ModuleExpander {
        module_defs,
        param_refs,
        param_values,
        param_ref_values,
        touched_params,
        touched_param_refs,
        allocators,
        allocator_cursors: HashMap::new(),
        repeat_path: Vec::new(),
        expanded: HashMap::new(),
        error: None,
    };
    if let Some(dynamic) = &program.dynamic {
        expander.dynamic(dynamic, None);
    }
    (expander.expanded, expander.error)
}

struct ModuleExpander<'a> {
    module_defs: &'a HashMap<String, ModuleDef>,
    param_refs: &'a HashMap<String, ParameterRef>,
    param_values: &'a HashMap<String, ParameterValue>,
    param_ref_values: &'a HashMap<String, ParameterValue>,
    touched_params: &'a HashSet<String>,
    touched_param_refs: &'a HashSet<String>,
    allocators: HashMap<String, Allocator>,
    allocator_cursors: HashMap<String, i64>,
    repeat_path: Vec<(String, u32)>,
    expanded: HashMap<String, ExpandedModule>,
    error: Option<String>,
}

impl ModuleExpander<'_> {
    fn dynamic(&mut self, dynamic: &DynamicSection, repeat_id: Option<&str>) {
        for item in &dynamic.items {
            match item {
                DynamicItem::ChannelIndependentBlock(cib) => self.cib(cib, repeat_id),
                DynamicItem::Channel(channel) => self.channel(channel, repeat_id),
                DynamicItem::Choose(choose) => self.choose(choose, repeat_id),
                DynamicItem::Module(module) => self.module(module, repeat_id),
                DynamicItem::Repeat(repeat) => self.repeat(repeat),
            }
        }
    }

    fn cib(&mut self, cib: &ChannelIndependentBlock, repeat_id: Option<&str>) {
        for item in &cib.items {
            match item {
                ChannelIndependentItem::ParameterBlock(block) => self.parameter_block(block, repeat_id),
                ChannelIndependentItem::Choose(choose) => self.choose(choose, repeat_id),
                ChannelIndependentItem::Module(module) => self.module(module, repeat_id),
                ChannelIndependentItem::Repeat(repeat) => self.repeat(repeat),
                ChannelIndependentItem::ComObjectRefRef(_) | ChannelIndependentItem::ParameterBlockRename(_) => {}
            }
        }
    }

    fn channel(&mut self, channel: &Channel, repeat_id: Option<&str>) {
        for item in &channel.items {
            match item {
                ChannelItem::ParameterBlock(block) => self.parameter_block(block, repeat_id),
                ChannelItem::Choose(choose) => self.choose(choose, repeat_id),
                ChannelItem::Module(module) => self.module(module, repeat_id),
                ChannelItem::Repeat(repeat) => self.repeat(repeat),
                ChannelItem::ComObjectRefRef(_) | ChannelItem::ParameterBlockRename(_) => {}
            }
        }
    }

    fn parameter_block(&mut self, block: &ParameterBlock, repeat_id: Option<&str>) {
        for item in &block.items {
            match item {
                ParameterBlockItem::ParameterBlock(nested) => self.parameter_block(nested, repeat_id),
                ParameterBlockItem::Choose(choose) => self.choose(choose, repeat_id),
                ParameterBlockItem::Module(module) => self.module(module, repeat_id),
                ParameterBlockItem::Repeat(repeat) => self.repeat(repeat),
                // A nested channel can instantiate modules like any other.
                ParameterBlockItem::Channel(channel) => self.channel(channel, repeat_id),
                ParameterBlockItem::Assign(_)
                | ParameterBlockItem::ParameterRefRef(_)
                | ParameterBlockItem::ComObjectRefRef(_)
                | ParameterBlockItem::ParameterSeparator(_)
                | ParameterBlockItem::Button(_)
                | ParameterBlockItem::Rows(_)
                | ParameterBlockItem::Columns(_)
                | ParameterBlockItem::ParameterBlockRename(_) => {}
            }
        }
    }

    fn choose(&mut self, choose: &Choose, repeat_id: Option<&str>) {
        let selector = self.ref_integer(&choose.param_ref_id);
        let mut matched = false;
        let mut default = None;
        for when in &choose.whens {
            if when.default.unwrap_or(false) {
                default = Some(when.items.as_slice());
            } else if when
                .test
                .as_deref()
                .and_then(Condition::parse)
                .is_some_and(|condition| selector.is_some_and(|value| condition.matches(value)))
            {
                self.when_items(&when.items, repeat_id);
                matched = true;
            }
        }
        if !matched && let Some(items) = default {
            self.when_items(items, repeat_id);
        }
    }

    fn when_items(&mut self, items: &[WhenItem], repeat_id: Option<&str>) {
        for item in items {
            match item {
                WhenItem::ParameterBlock(block) => self.parameter_block(block, repeat_id),
                WhenItem::Choose(choose) => self.choose(choose, repeat_id),
                WhenItem::Channel(channel) => self.channel(channel, repeat_id),
                WhenItem::Module(module) => self.module(module, repeat_id),
                WhenItem::Repeat(repeat) => self.repeat(repeat),
                WhenItem::ParameterRefRef(_)
                | WhenItem::ComObjectRefRef(_)
                | WhenItem::ParameterSeparator(_)
                | WhenItem::Assign(_)
                | WhenItem::Button(_)
                | WhenItem::ParameterBlockRename(_) => {}
            }
        }
    }

    fn repeat(&mut self, repeat: &Repeat) {
        let count = repeat
            .parameter_ref_id
            .as_deref()
            .and_then(|id| self.ref_integer(id))
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(repeat.count);
        for index in 0..count {
            self.repeat_path.push((repeat.id.clone(), index));
            for item in &repeat.items {
                match item {
                    RepeatItem::Choose(choose) => self.choose(choose, Some(&repeat.id)),
                    RepeatItem::Module(module) => self.module(module, Some(&repeat.id)),
                    RepeatItem::Repeat(nested) => self.repeat(nested),
                }
            }
            self.repeat_path.pop();
        }
    }

    fn ref_integer(&self, ref_id: &str) -> Option<i64> {
        let parameter_ref = self.param_refs.get(ref_id)?;
        let value = if self.touched_param_refs.contains(ref_id) || !self.touched_params.contains(&parameter_ref.ref_id)
        {
            self.param_ref_values.get(ref_id)?
        } else {
            self.param_values.get(&parameter_ref.ref_id)?
        };
        match value {
            ParameterValue::Integer(value) => Some(*value),
            ParameterValue::Float(value) => Some(*value as i64),
            ParameterValue::Text(_) | ParameterValue::Bytes(_) => None,
        }
    }

    fn module(&mut self, prototype: &Module, repeat_id: Option<&str>) {
        if self.error.is_some() {
            return;
        }
        let Some(module_def) = self.module_defs.get(&prototype.ref_id) else {
            self.error = Some(format!("module {} references missing definition {}", prototype.id, prototype.ref_id));
            return;
        };
        let mut module = prototype.clone();
        if !self.repeat_path.is_empty() {
            // Fixed-width indices keep instance IDs in dynamic XML order when
            // maps need to sort them for presentation or traversal.
            let suffix = self
                .repeat_path
                .iter()
                .map(|(id, index)| format!("{id}[{:010}]", index + 1))
                .collect::<Vec<_>>()
                .join("/");
            module.id = format!("{}@{}", prototype.id, suffix);
        }

        let mut numeric = HashMap::new();
        for argument in &mut module.args {
            let ModuleArg::NumericArg { ref_id, value, allocator_ref_id, .. } = argument else { continue };
            let resolved = if let Some(value) = *value {
                Some(value)
            } else if let Some(allocator_id) = allocator_ref_id.as_deref() {
                self.allocate(allocator_id, module_def, ref_id)
            } else {
                None
            };
            let Some(resolved) = resolved else {
                self.error.get_or_insert_with(|| {
                    format!("module {} has no value for numeric argument {}", module.id, ref_id)
                });
                return;
            };
            *value = Some(resolved);
            numeric.insert(ref_id.clone(), resolved);
        }
        for argument in &mut module.args {
            let ModuleArg::NumericArg { value, base_value: Some(base), .. } = argument else { continue };
            let Some(base) = numeric.get(base) else {
                self.error = Some(format!("module {} references unresolved base argument {}", module.id, base));
                return;
            };
            *value = value.and_then(|value| value.checked_add(*base));
            if value.is_none() {
                self.error = Some(format!("module {} base argument addition overflows", module.id));
                return;
            }
        }

        if let Some(expanded) = expand_module(&module, self.module_defs, repeat_id, &prototype.id) {
            self.expanded.insert(expanded.instance_id.clone(), expanded);
        } else {
            self.error = Some(format!("module {} cannot expand its declared arguments", module.id));
        }
    }

    fn allocate(&mut self, allocator_id: &str, module_def: &ModuleDef, argument_id: &str) -> Option<i64> {
        let allocator = self.allocators.get(allocator_id)?;
        let definition = module_def.arguments.as_ref()?.arguments.iter().find(|arg| arg.id == argument_id)?;
        let Some(width) = definition.allocates else {
            self.error =
                Some(format!("module argument {argument_id} needs Allocates when using allocator {allocator_id}"));
            return None;
        };
        let Ok(width) = i64::try_from(width) else {
            self.error =
                Some(format!("module argument {argument_id} allocation width exceeds the signed runtime range"));
            return None;
        };
        let alignment = i64::from(definition.alignment.unwrap_or(1)).max(1);
        let cursor = self.allocator_cursors.entry(allocator_id.to_string()).or_insert(allocator.start);
        let remainder = cursor.rem_euclid(alignment);
        if remainder != 0 {
            *cursor = cursor.checked_add(alignment - remainder)?;
        }
        let value = *cursor;
        let next = cursor.checked_add(width)?;
        if next > allocator.max_inclusive {
            log::warn!(
                "Allocator {} overflows while instantiating argument {}: {} + {} > {}",
                allocator.id,
                argument_id,
                value,
                width,
                allocator.max_inclusive
            );
            return None;
        }
        *cursor = next;
        Some(value)
    }
}

fn expand_module(
    module: &Module,
    module_defs: &HashMap<String, ModuleDef>,
    repeat_id: Option<&str>,
    prototype_id: &str,
) -> Option<ExpandedModule> {
    let module_def = module_defs.get(&module.ref_id)?;
    let mut args = HashMap::new();

    if let Some(def_args) = &module_def.arguments {
        for def_arg in &def_args.arguments {
            let argument = module.args.iter().find(|argument| match argument {
                ModuleArg::NumericArg { ref_id, .. } | ModuleArg::TextArg { ref_id, .. } => ref_id == &def_arg.id,
            });
            match argument {
                Some(ModuleArg::NumericArg { value: Some(value), .. }) => {
                    args.insert(def_arg.name.clone(), ModuleArgValue::Numeric(*value));
                }
                Some(ModuleArg::TextArg { value, .. }) => {
                    args.insert(def_arg.name.clone(), ModuleArgValue::Text(value.clone()));
                }
                _ => {
                    log::warn!("Module {} is missing argument {}", module.id, def_arg.id);
                }
            }
        }
    }

    Some(ExpandedModule {
        instance_id: module.id.clone(),
        module_def_id: module.ref_id.clone(),
        name: module.name.clone(),
        args,
        module: module.clone(),
        repeat_id: repeat_id.map(str::to_string),
        prototype_id: prototype_id.to_string(),
    })
}

#[cfg(test)]
mod raw_data_tests {
    use super::{ParameterValue, parse_raw_data_value};

    #[test]
    fn raw_data_defaults_decode_as_base64_bytes_not_numbers() {
        // A decimal-looking value is still base64, not an integer or hex.
        assert_eq!(parse_raw_data_value("1234"), ParameterValue::Bytes(vec![0xD7, 0x6D, 0xF8]));
        assert_eq!(parse_raw_data_value("AAAAEAAg"), ParameterValue::Bytes(vec![0, 0, 0, 0x10, 0, 0x20]));
        assert_eq!(parse_raw_data_value("EjQ="), ParameterValue::Bytes(vec![0x12, 0x34]));
        assert_eq!(parse_raw_data_value(""), ParameterValue::Bytes(Vec::new()));
        assert_eq!(parse_raw_data_value("ABC"), ParameterValue::Text("ABC".into()));
        assert_eq!(parse_raw_data_value("Z!"), ParameterValue::Text("Z!".into()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::configuration::{ProductConfiguration, effective_com_objects};
    use crate::runtime::parser::{parse_application_program, parse_application_program_from_file};
    use std::path::Path;

    #[test]
    fn shared_definition_preserves_instance_values_bindings_and_geometry() {
        let selected = Arc::new(
            SelectedProduct::from_document(
                parse_application_program(ALLOCATOR_REPEAT_FIXTURE).expect("repeat fixture"),
                None,
                None,
            )
            .expect("selected product"),
        );
        let mut edited = Device::from_product(selected.clone(), None, None);
        let untouched = Device::from_product(selected.clone(), None, None);
        assert!(Arc::ptr_eq(&edited.definition, &untouched.definition));
        let original_geometry = untouched.evaluate(&[]).expect("default evaluation").into_product();

        let count = "M-00FA_A-5_P-COUNT_R-1";
        let instance = edited.visible_module_com_objects()[0].module.instance_id.clone();
        let level = format!("{instance}::M-00FA_A-5_MD-1_P-1_R-1");
        edited.set_parameter_value(count, ParameterValue::Integer(1));
        edited.set_module_parameter_value_by_composite_id(&level, ParameterValue::Integer(9));
        edited.assign_group_address(220, GroupAddress::from_three_level(1, 2, 3));

        assert_eq!(untouched.get_parameter_value(count), Some(&ParameterValue::Integer(2)));
        assert_eq!(untouched.get_module_parameter_value_by_composite_id(&level), Some(&ParameterValue::Integer(7)));
        assert!(untouched.get_group_addresses(220).is_empty());
        assert_eq!(untouched.all_expanded_modules().count(), 2);
        assert_eq!(edited.all_expanded_modules().count(), 1);
        assert_ne!(
            edited.evaluate(&[]).expect("edited evaluation").product().parameters(),
            original_geometry.parameters()
        );
        assert_eq!(
            untouched.evaluate(&[]).expect("unchanged evaluation").product().parameters(),
            original_geometry.parameters()
        );

        // The cache outlives the first editor, but never retains its edits.
        drop(edited);
        let fresh = Device::from_product(selected, None, None);
        assert!(Arc::ptr_eq(&fresh.definition, &untouched.definition));
        assert_eq!(fresh.get_parameter_value(count), untouched.get_parameter_value(count));
        assert_eq!(
            fresh.get_module_parameter_value_by_composite_id(&level),
            untouched.get_module_parameter_value_by_composite_id(&level)
        );
    }

    #[test]
    fn translations_cannot_mutate_shared_definitions_or_geometry() {
        let xml = ALLOCATOR_REPEAT_FIXTURE.replace("</Manufacturer>", r#"<Languages>
          <Language Identifier="de-DE"><TranslationUnit RefId="M-00FA_A-5">
            <TranslationElement RefId="M-00FA_A-5_P-COUNT"><Translation AttributeName="Text" Text="Anzahl"/></TranslationElement>
          </TranslationUnit></Language></Languages></Manufacturer>"#);
        let selected = Arc::new(
            SelectedProduct::from_document(parse_application_program(&xml).expect("translated fixture"), None, None)
                .expect("selected product"),
        );
        let translated = Device::from_product(selected.clone(), None, Some("de-DE"));
        let original = Device::from_product(selected.clone(), None, None);
        let missing = Device::from_product(selected.clone(), None, Some("xx-XX"));
        let count = "M-00FA_A-5_P-COUNT_R-1";
        assert_eq!(translated.parameter_description(count).expect("translated parameter").text, "Anzahl");
        for device in [&original, &missing] {
            assert_eq!(device.parameter_description(count).expect("original parameter").text, "Count");
            assert_eq!(
                device.evaluate(&[]).expect("original geometry").product().parameters(),
                translated.evaluate(&[]).expect("translated geometry").product().parameters()
            );
        }
        assert!(Arc::ptr_eq(&original.definition, &Device::from_product(selected, None, None).definition));
    }

    #[test]
    fn root_and_module_bindings_preserve_protocol_addresses_and_primary_order() {
        let primary = GroupAddress::from_three_level(31, 7, 255);
        let additional = GroupAddress::from_three_level(0, 0, 1);
        for (xml, expected_objects) in [(PRE_ETS4_FIXTURE, 1), (ALLOCATOR_REPEAT_FIXTURE, 2)] {
            let selected = SelectedProduct::from_document(parse_application_program(xml).expect("fixture"), None, None)
                .expect("selected fixture");
            let mut device = Device::from_product(Arc::new(selected), None, None);
            let objects = effective_com_objects(&device, &ProductConfiguration::default());
            assert_eq!(objects.len(), expected_objects);

            for object in &objects {
                device.assign_group_address(object.number, primary);
                device.assign_group_address(object.number, additional);
                device.assign_group_address(object.number, primary);
                let bindings = device.get_group_addresses(object.number);
                assert_eq!(
                    bindings.iter().map(|binding| (binding.group_address, binding.is_sending)).collect::<Vec<_>>(),
                    [(primary, true), (additional, false),]
                );
                assert_eq!(bindings[0].group_address.0, [0xFF, 0xFF]);
                assert_eq!(bindings[1].group_address.0, [0, 1]);
            }
            assert_eq!(device.all_group_addresses(), [additional, primary]);
            assert_eq!(device.all_bindings().count(), expected_objects);

            let number = objects[0].number;
            device.remove_group_address(number, &primary);
            device.assign_group_address(number, primary);
            assert_eq!(
                device
                    .get_group_addresses(number)
                    .iter()
                    .map(|binding| (binding.group_address, binding.is_sending))
                    .collect::<Vec<_>>(),
                [(additional, true), (primary, false),]
            );
            device.clear_group_addresses(number);
            assert!(device.get_group_addresses(number).is_empty());
            assert_eq!(device.all_bindings().count(), expected_objects - 1);
        }
    }

    /// The pre-ETS4 converter idiom (BCU2 and other converted legacy
    /// programs): each block titles itself via `ParamRefId` and gates its
    /// entire content on a `choose` keyed on that very ref. The header ref
    /// is placed nowhere else, so it must count as visible by virtue of the
    /// block referencing it — otherwise no choose in the program ever opens.
    /// A second, modern-style block without `ParamRefId` proves the seeding
    /// changes nothing for ordinary programs.
    const PRE_ETS4_FIXTURE: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-2" ApplicationNumber="2" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0021" Name="Legacy fixture" LoadProcedureStyle="ProductProcedure" PeiType="17" DefaultLanguage="de-DE" DynamicTableManagement="true" Linkable="true" PreEts4Style="true">
      <Static>
        <Code><AbsoluteSegment Id="M-00FA_A-2_AS-0274" Address="628" Size="8" /></Code>
        <ParameterTypes>
          <ParameterType Id="M-00FA_A-2_PT-PAGE" Name="Page"><TypeNone /></ParameterType>
          <ParameterType Id="M-00FA_A-2_PT-MODE" Name="Mode"><TypeRestriction Base="Value" SizeInBit="8"><Enumeration Text="Off" Value="0" Id="M-00FA_A-2_PT-MODE_EN-0" /><Enumeration Text="On" Value="1" Id="M-00FA_A-2_PT-MODE_EN-1" /></TypeRestriction></ParameterType>
          <ParameterType Id="M-00FA_A-2_PT-N8" Name="N8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="100" /></ParameterType>
        </ParameterTypes>
        <Parameters>
          <Parameter Id="M-00FA_A-2_P-100" Name="PageGeneral" ParameterType="M-00FA_A-2_PT-PAGE" Text="general" Value="" />
          <Parameter Id="M-00FA_A-2_P-1" Name="Mode" ParameterType="M-00FA_A-2_PT-MODE" Text="Mode" Value="1"><Memory CodeSegment="M-00FA_A-2_AS-0274" Offset="0" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-2_P-2" Name="Level" ParameterType="M-00FA_A-2_PT-N8" Text="Level" Value="10"><Memory CodeSegment="M-00FA_A-2_AS-0274" Offset="1" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-2_P-3" Name="Other" ParameterType="M-00FA_A-2_PT-N8" Text="Other" Value="20"><Memory CodeSegment="M-00FA_A-2_AS-0274" Offset="2" BitOffset="0" /></Parameter>
        </Parameters>
        <ParameterRefs>
          <ParameterRef Id="M-00FA_A-2_P-100_R-100" RefId="M-00FA_A-2_P-100" />
          <ParameterRef Id="M-00FA_A-2_P-1_R-1" RefId="M-00FA_A-2_P-1" />
          <ParameterRef Id="M-00FA_A-2_P-2_R-2" RefId="M-00FA_A-2_P-2" />
          <ParameterRef Id="M-00FA_A-2_P-3_R-3" RefId="M-00FA_A-2_P-3" />
        </ParameterRefs>
        <ComObjectTable>
          <ComObject Id="M-00FA_A-2_O-1" Name="Switch" Text="Switch" Number="1" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
        </ComObjectTable>
        <ComObjectRefs>
          <ComObjectRef Id="M-00FA_A-2_O-1_R-1" RefId="M-00FA_A-2_O-1" />
        </ComObjectRefs>
      </Static>
      <Dynamic>
        <Channel Id="M-00FA_A-2_CH-0" Name="Generic" Text="" Number="0">
          <ParameterBlock Id="M-00FA_A-2_PB-100" Name="General" ParamRefId="M-00FA_A-2_P-100_R-100">
            <choose ParamRefId="M-00FA_A-2_P-100_R-100">
              <when default="true">
                <ParameterRefRef RefId="M-00FA_A-2_P-1_R-1" />
                <choose ParamRefId="M-00FA_A-2_P-1_R-1">
                  <when test="1">
                    <ParameterRefRef RefId="M-00FA_A-2_P-2_R-2" />
                    <ComObjectRefRef RefId="M-00FA_A-2_O-1_R-1" />
                    <Assign TargetParamRefRef="M-00FA_A-2_P-3_R-3" SourceParamRefRef="M-00FA_A-2_P-2_R-2" />
                  </when>
                </choose>
              </when>
            </choose>
          </ParameterBlock>
          <ParameterBlock Id="M-00FA_A-2_PB-2" Text="Plain">
            <ParameterRefRef RefId="M-00FA_A-2_P-3_R-3" />
          </ParameterBlock>
        </Channel>
      </Dynamic>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    #[test]
    fn block_param_ref_id_opens_gated_chooses() {
        let knx = parse_application_program(PRE_ETS4_FIXTURE).expect("the fixture parses");
        let program =
            knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next().expect("one program");
        let mut device = Device::new(program, None);

        // The header ref itself is part of the tree...
        assert!(device.is_param_ref_visible("M-00FA_A-2_P-100_R-100"));
        // ...which opens the content choose (default branch) on the next
        // fixpoint iteration, and the nested selector one iteration later.
        assert!(device.is_param_ref_visible("M-00FA_A-2_P-1_R-1"));
        assert!(device.is_param_ref_visible("M-00FA_A-2_P-2_R-2"));
        assert!(device.is_param_ref_active("M-00FA_A-2_P-1_R-1"));
        assert!(device.is_param_ref_active("M-00FA_A-2_P-2_R-2"));
        assert!(device.is_com_object_ref_visible("M-00FA_A-2_O-1_R-1"));
        // The modern-style block is unaffected.
        assert!(device.is_param_ref_visible("M-00FA_A-2_P-3_R-3"));
        assert_eq!(device.get_parameter_value("M-00FA_A-2_P-3_R-3"), Some(&ParameterValue::Integer(10)));

        // Closing the branch removes its derived assignment instead of
        // leaving a cached value behind.
        device.set_parameter_value("M-00FA_A-2_P-1_R-1", ParameterValue::Integer(0));
        assert!(!device.is_param_ref_active("M-00FA_A-2_P-2_R-2"));
        assert_eq!(device.get_parameter_value("M-00FA_A-2_P-3_R-3"), Some(&ParameterValue::Integer(20)));
    }

    /// `ChannelIndependentBlock_t` and `ComObjectParameterBlock_t` allow a
    /// `ComObjectRefRef`, an `Assign` and a nested `Channel` respectively,
    /// outside the `when` placements the walkers already handled. Catalogue
    /// products use all three; each must parse and take effect.
    #[test]
    fn block_level_assignments_nested_channels_and_independent_objects_take_effect() {
        let xml = PRE_ETS4_FIXTURE
            .replace(
                r#"<ComObjectRef Id="M-00FA_A-2_O-1_R-1" RefId="M-00FA_A-2_O-1" />"#,
                r#"<ComObjectRef Id="M-00FA_A-2_O-1_R-1" RefId="M-00FA_A-2_O-1" /><ComObjectRef Id="M-00FA_A-2_O-1_R-2" RefId="M-00FA_A-2_O-1" Text="Always" />"#,
            )
            .replace(
                "<Dynamic>",
                r#"<Dynamic><ChannelIndependentBlock><ComObjectRefRef RefId="M-00FA_A-2_O-1_R-2" /></ChannelIndependentBlock>"#,
            )
            .replace(
                r#"<ParameterBlock Id="M-00FA_A-2_PB-2" Text="Plain">
            <ParameterRefRef RefId="M-00FA_A-2_P-3_R-3" />
          </ParameterBlock>"#,
                r#"<ParameterBlock Id="M-00FA_A-2_PB-2" Text="Plain">
            <Assign TargetParamRefRef="M-00FA_A-2_P-3_R-3" Value="42" />
            <Channel Id="M-00FA_A-2_CH-1" Name="Nested">
              <ParameterBlock Id="M-00FA_A-2_PB-3" Text="Nested block"><ParameterRefRef RefId="M-00FA_A-2_P-3_R-3" /></ParameterBlock>
            </Channel>
          </ParameterBlock>"#,
            );
        let knx = parse_application_program(&xml).expect("schema-allowed placements parse");
        let program =
            knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next().expect("one program");
        let device = Device::new(program, None);

        assert!(device.is_com_object_ref_visible("M-00FA_A-2_O-1_R-2"), "independent object is placed");
        assert!(device.is_param_ref_visible("M-00FA_A-2_P-3_R-3"), "nested channel is walked");
        assert_eq!(
            device.get_parameter_value("M-00FA_A-2_P-3_R-3"),
            Some(&ParameterValue::Integer(42)),
            "block-level assignment applies while the block is reached"
        );
    }

    /// `ApplicationProgramChannel_t` permits communication-object placements
    /// directly under a channel. Converted products use this for their
    /// unconditional objects, before any parameter blocks.
    const DIRECT_CHANNEL_OBJECT_FIXTURE: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="converter" ToolVersion="6.4" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-4" ApplicationNumber="4" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0011" Name="Direct channel object" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="true" Linkable="true">
      <Static>
        <Code />
        <ComObjectTable>
          <ComObject Id="M-00FA_A-4_O-0" Name="Input" Text="Input" Number="0" FunctionText="Value" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
        </ComObjectTable>
        <ComObjectRefs>
          <ComObjectRef Id="M-00FA_A-4_O-0_R-0" RefId="M-00FA_A-4_O-0" />
        </ComObjectRefs>
      </Static>
      <Dynamic>
        <Channel Name="Generic" Text="" Number="0" Id="M-00FA_A-4_CH-0">
          <ComObjectRefRef RefId="M-00FA_A-4_O-0_R-0" />
          <ParameterBlock Id="M-00FA_A-4_PB-1" Name="Settings" />
        </Channel>
      </Dynamic>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    #[test]
    fn direct_channel_object_references_remain_unconditionally_visible() {
        let knx = parse_application_program(DIRECT_CHANNEL_OBJECT_FIXTURE).expect("the converted fixture parses");
        let program =
            knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next().expect("one program");

        let device = Device::new(program, None);

        assert!(device.is_com_object_ref_visible("M-00FA_A-4_O-0_R-0"));
        assert_eq!(device.visible_com_object_refs().map(|reference| reference.id.as_str()).collect::<Vec<_>>(), [
            "M-00FA_A-4_O-0_R-0"
        ]);
    }

    /// The ETS6 idiom (L&J E032): whole channels sit inside `when`
    /// branches of a `choose` directly under `Dynamic`, gated by an
    /// enable parameter placed in the ChannelIndependentBlock. The
    /// channel roster must be complete regardless of gating, while
    /// visibility follows the selector chain.
    const GATED_CHANNEL_FIXTURE: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/23">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-3" ApplicationNumber="3" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0021" Name="Gated channels" LoadProcedureStyle="ProductProcedure" PeiType="17" DefaultLanguage="de-DE" DynamicTableManagement="true" Linkable="true">
      <Static>
        <Code><AbsoluteSegment Id="M-00FA_A-3_AS-0274" Address="628" Size="8" /></Code>
        <ParameterTypes>
          <ParameterType Id="M-00FA_A-3_PT-USAGE" Name="Usage"><TypeRestriction Base="Value" SizeInBit="8"><Enumeration Text="disabled" Value="0" Id="M-00FA_A-3_PT-USAGE_EN-0" /><Enumeration Text="enabled" Value="3" Id="M-00FA_A-3_PT-USAGE_EN-3" /></TypeRestriction></ParameterType>
          <ParameterType Id="M-00FA_A-3_PT-N8" Name="N8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="100" /></ParameterType>
        </ParameterTypes>
        <Parameters>
          <Parameter Id="M-00FA_A-3_P-10" Name="Usage" ParameterType="M-00FA_A-3_PT-USAGE" Text="usage" Value="0"><Memory CodeSegment="M-00FA_A-3_AS-0274" Offset="0" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-3_P-11" Name="Subtype" ParameterType="M-00FA_A-3_PT-N8" Text="subtype" Value="0"><Memory CodeSegment="M-00FA_A-3_AS-0274" Offset="1" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-3_P-12" Name="Level" ParameterType="M-00FA_A-3_PT-N8" Text="level" Value="5"><Memory CodeSegment="M-00FA_A-3_AS-0274" Offset="2" BitOffset="0" /></Parameter>
        </Parameters>
        <ParameterRefs>
          <ParameterRef Id="M-00FA_A-3_P-10_R-10" RefId="M-00FA_A-3_P-10" />
          <ParameterRef Id="M-00FA_A-3_P-11_R-11" RefId="M-00FA_A-3_P-11" />
          <ParameterRef Id="M-00FA_A-3_P-12_R-12" RefId="M-00FA_A-3_P-12" />
        </ParameterRefs>
        <ComObjectTable>
          <ComObject Id="M-00FA_A-3_O-1" Name="Switch" Text="Switch" Number="1" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
        </ComObjectTable>
        <ComObjectRefs>
          <ComObjectRef Id="M-00FA_A-3_O-1_R-1" RefId="M-00FA_A-3_O-1" />
        </ComObjectRefs>
      </Static>
      <Dynamic>
        <ChannelIndependentBlock>
          <ParameterBlock Id="M-00FA_A-3_PB-1" Text="input setup">
            <ParameterRefRef RefId="M-00FA_A-3_P-10_R-10" />
            <choose ParamRefId="M-00FA_A-3_P-10_R-10">
              <when test="3">
                <ParameterRefRef RefId="M-00FA_A-3_P-11_R-11" />
              </when>
            </choose>
          </ParameterBlock>
        </ChannelIndependentBlock>
        <choose ParamRefId="M-00FA_A-3_P-10_R-10">
          <when test="3">
            <choose ParamRefId="M-00FA_A-3_P-11_R-11">
              <when test="0">
                <Channel Id="M-00FA_A-3_CH-1" Name="Button A" Text="input A" Number="1">
                  <ParameterBlock Id="M-00FA_A-3_PB-2" Text="button A">
                    <ParameterRefRef RefId="M-00FA_A-3_P-12_R-12" />
                    <ComObjectRefRef RefId="M-00FA_A-3_O-1_R-1" />
                  </ParameterBlock>
                </Channel>
              </when>
            </choose>
          </when>
        </choose>
      </Dynamic>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    #[test]
    fn dynamic_level_choose_gates_whole_channels() {
        let knx = parse_application_program(GATED_CHANNEL_FIXTURE).expect("the fixture parses");
        let program =
            knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next().expect("one program");
        let mut device = Device::new(program, None);

        // The roster sees the gated channel regardless of visibility.
        let dynamic = device.program().dynamic.as_ref().expect("dynamic");
        assert_eq!(dynamic.all_channels().len(), 1);
        assert!(dynamic.find_channel("M-00FA_A-3_CH-1").is_some());

        // Disabled (default): the channel's contents are hidden.
        assert!(!device.is_param_ref_visible("M-00FA_A-3_P-12_R-12"));
        assert!(!device.is_com_object_ref_visible("M-00FA_A-3_O-1_R-1"));

        // Enable: the subtype ref appears (CIB choose) and its default
        // value 0 routes the Dynamic-level choose to the channel.
        device.set_parameter_value("M-00FA_A-3_P-10", ParameterValue::Integer(3));
        assert!(device.is_param_ref_visible("M-00FA_A-3_P-11_R-11"));
        assert!(device.is_param_ref_visible("M-00FA_A-3_P-12_R-12"));
        assert!(device.is_com_object_ref_visible("M-00FA_A-3_O-1_R-1"));

        // Disable again: everything behind the gate goes away.
        device.set_parameter_value("M-00FA_A-3_P-10", ParameterValue::Integer(0));
        assert!(!device.is_param_ref_visible("M-00FA_A-3_P-12_R-12"));
        assert!(!device.is_com_object_ref_visible("M-00FA_A-3_O-1_R-1"));
    }

    /// The real ETS6 MV-0021 product the fixture above distills
    /// (licensed vendor data; skipped when absent). Before Dynamic-level
    /// chooses were modeled, all 36 channels were silently dropped at
    /// parse time and no com object could ever become visible.
    #[test]
    fn lj_e032_channels_appear_when_buttons_are_enabled() {
        let path = Path::new("../../manuf_tool_data/M-00E1_A-E032-40-9322.xml");
        if !path.exists() {
            eprintln!("Skipping test - L&J E032 file not found");
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
        let mut device = Device::new(program, None);

        assert_eq!(device.program().dynamic.as_ref().expect("dynamic").all_channels().len(), 36);

        // Factory default: input A disabled, no button channel content.
        let objects_before = device.visible_com_object_refs().count();

        // Enable input A as a switching button: usage on, standard
        // connection, button mode — the selector chain of the first
        // Dynamic-level choose (P-19 -> P-21 -> UP-83).
        device.set_parameter_value("M-00E1_A-E032-40-9322_P-19", ParameterValue::Integer(3));
        device.set_parameter_value("M-00E1_A-E032-40-9322_P-21", ParameterValue::Integer(0));
        device.set_parameter_value("M-00E1_A-E032-40-9322_UP-83", ParameterValue::Integer(0));

        let objects_after = device.visible_com_object_refs().count();
        assert!(
            objects_after > objects_before,
            "enabling input A must surface its com objects ({objects_before} -> {objects_after})"
        );
        // The button A channel's page contents are now visible.
        assert!(device.is_param_ref_visible("M-00E1_A-E032-40-9322_P-22_R-22"));
    }

    /// The real MV-0021 product the fixture distills (licensed vendor data;
    /// skipped when absent). Before the `ParamRefId` seeding, this program
    /// rendered completely empty: zero visible refs of either kind.
    #[test]
    fn lj_bcu2_program_has_visible_surface() {
        let path = Path::new("../../manuf_tool_data/L&J-ta8fxct-sec-en-de-30/M-00E1/M-00E1_A-E024-30-0403.xml");
        if !path.exists() {
            eprintln!("Skipping test - L&J file not found");
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
        let device = Device::new(program, None);

        // Loose lower bounds: the factory-default configuration shows a few
        // hundred of the 1604 parameter refs but keeps most of the 683
        // object refs behind per-button mode selections (16 visible today).
        let visible_params = device.visible_param_refs().count();
        let visible_objects = device.visible_com_object_refs().count();
        assert!(visible_params > 100, "only {visible_params} visible parameter refs");
        assert!(visible_objects >= 10, "only {visible_objects} visible com-object refs");
    }

    /// Manufacturer Tool repeats do not clone literal argument values. Each
    /// active iteration consumes the next value from the referenced allocator,
    /// and changing the count recreates the active module-instance set.
    const ALLOCATOR_REPEAT_FIXTURE: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="Manufacturer Tool" ToolVersion="5.7" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-5" ApplicationNumber="5" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-07B0" Name="Allocator repeat" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="true" Linkable="true">
      <Static>
        <Code><AbsoluteSegment Id="M-00FA_A-5_AS-1" Address="4096" Size="64" /></Code>
        <ParameterTypes>
          <ParameterType Id="M-00FA_A-5_PT-N8" Name="N8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="10" /></ParameterType>
        </ParameterTypes>
        <Parameters>
          <Parameter Id="M-00FA_A-5_P-COUNT" Name="Count" ParameterType="M-00FA_A-5_PT-N8" Text="Count" Value="1"><Memory CodeSegment="M-00FA_A-5_AS-1" Offset="0" BitOffset="0" /></Parameter>
        </Parameters>
        <ParameterRefs>
          <ParameterRef Id="M-00FA_A-5_P-COUNT_R-1" RefId="M-00FA_A-5_P-COUNT" Value="2" />
          <ParameterRef Id="M-00FA_A-5_P-COUNT_R-2" RefId="M-00FA_A-5_P-COUNT" />
        </ParameterRefs>
        <Allocators>
          <Allocator Id="M-00FA_A-5_L-CH" Name="Channels" Start="1" maxInclusive="4" />
          <Allocator Id="M-00FA_A-5_L-OFF" Name="Offsets" Start="10" maxInclusive="22" />
          <Allocator Id="M-00FA_A-5_L-OBJ" Name="Objects" Start="220" maxInclusive="250" />
        </Allocators>
      </Static>
      <ModuleDefs>
        <ModuleDef Id="M-00FA_A-5_MD-1" Name="Channel">
          <Arguments>
            <Argument Id="M-00FA_A-5_MD-1_A-CH" Name="ChNo" Allocates="1" />
            <Argument Id="M-00FA_A-5_MD-1_A-OFF" Name="ParamOffset" Allocates="4" />
            <Argument Id="M-00FA_A-5_MD-1_A-OBJ" Name="ObjectBase" Allocates="10" />
          </Arguments>
          <Static>
            <Parameters>
              <Parameter Id="M-00FA_A-5_MD-1_P-1" Name="Level" ParameterType="M-00FA_A-5_PT-N8" Text="Level" Value="7"><Memory CodeSegment="M-00FA_A-5_AS-1" Offset="0" BitOffset="0" BaseOffset="M-00FA_A-5_MD-1_A-OFF" /></Parameter>
              <Parameter Id="M-00FA_A-5_MD-1_P-2" Name="RootMode" ParameterType="M-00FA_A-5_PT-N8" Text="" Access="None" Value="0"><Memory CodeSegment="M-00FA_A-5_AS-1" Offset="1" BitOffset="0" BaseOffset="M-00FA_A-5_MD-1_A-OFF" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-5_MD-1_P-1_R-1" RefId="M-00FA_A-5_MD-1_P-1" />
              <ParameterRef Id="M-00FA_A-5_MD-1_P-2_R-2" RefId="M-00FA_A-5_MD-1_P-2" Access="None" />
            </ParameterRefs>
            <ComObjects>
              <ComObject Id="M-00FA_A-5_MD-1_O-1" Name="Switch" Text="Channel {{ChNo}}" Number="0" FunctionText="Switch" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" BaseNumber="M-00FA_A-5_MD-1_A-OBJ" />
            </ComObjects>
            <ComObjectRefs>
              <ComObjectRef Id="M-00FA_A-5_MD-1_O-1_R-1" RefId="M-00FA_A-5_MD-1_O-1" />
            </ComObjectRefs>
          </Static>
          <Dynamic>
            <ParameterBlock Id="M-00FA_A-5_MD-1_PB-1" Text="Channel {{ChNo}}">
              <choose ParamRefId="M-00FA_A-5_P-COUNT_R-1">
                <when test=">=1">
                  <ParameterRefRef RefId="M-00FA_A-5_MD-1_P-1_R-1" />
                  <Assign TargetParamRefRef="M-00FA_A-5_MD-1_P-2_R-2" SourceParamRefRef="M-00FA_A-5_P-COUNT_R-1" />
                </when>
              </choose>
              <ComObjectRefRef RefId="M-00FA_A-5_MD-1_O-1_R-1" />
            </ParameterBlock>
          </Dynamic>
        </ModuleDef>
      </ModuleDefs>
      <Dynamic>
        <ChannelIndependentBlock>
          <ParameterBlock Id="M-00FA_A-5_PB-1" Text="Channels">
            <ParameterRefRef RefId="M-00FA_A-5_P-COUNT_R-1" />
            <Repeat Id="M-00FA_A-5_X-1" Name="" ParameterRefId="M-00FA_A-5_P-COUNT_R-1">
              <Module Id="M-00FA_A-5_MD-1_M-1" RefId="M-00FA_A-5_MD-1">
                <NumericArg RefId="M-00FA_A-5_MD-1_A-CH" AllocatorRefId="M-00FA_A-5_L-CH" />
                <NumericArg RefId="M-00FA_A-5_MD-1_A-OFF" AllocatorRefId="M-00FA_A-5_L-OFF" />
                <NumericArg RefId="M-00FA_A-5_MD-1_A-OBJ" AllocatorRefId="M-00FA_A-5_L-OBJ" />
              </Module>
            </Repeat>
          </ParameterBlock>
        </ChannelIndependentBlock>
      </Dynamic>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    #[test]
    fn checked_form_edits_restore_failed_expansion_and_keep_inactive_module_drafts() {
        use crate::runtime::presentation::FormPresentation;
        let selected = SelectedProduct::from_document(
            parse_application_program(ALLOCATOR_REPEAT_FIXTURE).expect("repeat fixture"),
            None,
            None,
        )
        .expect("selected repeat product");
        let mut device = Device::from_product(Arc::new(selected), None, None);
        let count = "M-00FA_A-5_P-COUNT_R-1";
        let instance = device.all_expanded_modules().map(|m| m.instance_id.clone()).max().expect("second instance");
        let parameter = format!("{instance}::M-00FA_A-5_MD-1_P-1_R-1");
        device.try_set_parameter_value(&parameter, ParameterValue::Integer(9)).expect("module edit");
        let before = FormPresentation::new(&device).snapshot(None);

        // The scalar range permits ten, but the allocators cannot instantiate
        // ten modules. Failure must restore derived state as well as the value.
        assert!(matches!(
            device.try_set_parameter_value(count, ParameterValue::Integer(10)),
            Err(ConfigurationError::Derivation(_)),
        ));
        assert_eq!(FormPresentation::new(&device).snapshot(None), before);
        assert_eq!(device.get_module_parameter_value_by_composite_id(&parameter), Some(&ParameterValue::Integer(9)));

        device.try_set_parameter_value(count, ParameterValue::Integer(1)).expect("shrink");
        assert!(device.get_expanded_module(&instance).is_none());
        device = device.with_language(Some("de-DE")).expect("translate hidden module draft");
        device.try_set_parameter_value(count, ParameterValue::Integer(2)).expect("grow");
        assert_eq!(FormPresentation::new(&device).snapshot(None), before);
        assert_eq!(device.get_module_parameter_value_by_composite_id(&parameter), Some(&ParameterValue::Integer(9)));
    }

    #[test]
    fn evaluated_modules_follow_repeat_counts_and_keep_their_allocated_geometry() {
        use crate::product::MaterializedModuleArgument;

        let selected = SelectedProduct::from_document(
            parse_application_program(ALLOCATOR_REPEAT_FIXTURE).expect("repeat fixture"),
            None,
            None,
        )
        .expect("selected product");
        let mut device = Device::from_product(Arc::new(selected), None, None);

        // Removing and restoring instances must replace both the roster and
        // geometry; allocator values must not be recomputed while lowering.
        for count in [2, 0, 3, 1, 2] {
            device.set_parameter_value("M-00FA_A-5_P-COUNT_R-1", ParameterValue::Integer(count));
            let evaluated = device.evaluate(&[]).expect("valid repeat count");
            let modules = evaluated.modules();
            assert_eq!(modules.len(), count as usize);
            assert!(modules.windows(2).all(|pair| pair[0].instance_id < pair[1].instance_id));
            assert_eq!(evaluated.product().parameters().len(), 1 + 2 * modules.len());

            for (index, module) in modules.iter().enumerate() {
                let offset = 10 + 4 * index as u32;
                assert_eq!(module.definition_id, "M-00FA_A-5_MD-1");
                assert_eq!(
                    module.arguments.get("ParamOffset"),
                    Some(&MaterializedModuleArgument::Numeric(i64::from(offset)))
                );
                assert_eq!(module.arguments.get("ChNo"), Some(&MaterializedModuleArgument::Numeric(index as i64 + 1)));
                let id = format!("{}::M-00FA_A-5_MD-1_P-1", module.instance_id);
                let location = evaluated.product().parameters().iter().find(|p| p.id == id).expect("module storage");
                assert_eq!(location.offset, offset);
            }
        }
    }

    #[test]
    fn evaluated_selectors_keep_exact_values_and_activity_in_each_scope() {
        // The hidden ref is placed in the active tree, unlike an Assign target
        // alone, so it participates in procedure choices without a UI control.
        let xml = ALLOCATOR_REPEAT_FIXTURE.replace(
            r#"<ParameterRefRef RefId="M-00FA_A-5_MD-1_P-1_R-1" />"#,
            r#"<ParameterRefRef RefId="M-00FA_A-5_MD-1_P-1_R-1" />
               <ParameterBlock Id="internal" Text="Internal" Access="None">
                 <ParameterRefRef RefId="M-00FA_A-5_MD-1_P-2_R-2" />
               </ParameterBlock>"#,
        );
        let selected =
            SelectedProduct::from_document(parse_application_program(&xml).expect("repeat fixture"), None, None)
                .expect("selected product");
        let mut device = Device::from_product(Arc::new(selected), None, None);
        let evaluated = device.evaluate(&[]).expect("default evaluation");

        let count = evaluated.procedure_selector("M-00FA_A-5_P-COUNT_R-1").expect("visible selector");
        assert_eq!(count.value, &ParameterValue::Integer(2));
        assert!(count.active);
        let other = evaluated.procedure_selector("M-00FA_A-5_P-COUNT_R-2").expect("inactive selector");
        assert_eq!(other.value, &ParameterValue::Integer(1));
        assert!(!other.active);
        assert!(evaluated.procedure_selector("unknown").is_none());

        let instance = &evaluated.modules()[0].instance_id;
        let level = format!("{instance}::M-00FA_A-5_MD-1_P-1_R-1");
        let hidden = format!("{instance}::M-00FA_A-5_MD-1_P-2_R-2");
        let selector = evaluated.procedure_selector(&level).expect("module selector");
        assert_eq!(selector.value, &ParameterValue::Integer(7));
        assert!(selector.active);
        let selector = evaluated.procedure_selector(&hidden).expect("hidden derived selector");
        assert_eq!(selector.value, &ParameterValue::Integer(2));
        assert!(selector.active);
        assert!(!device.is_module_param_ref_visible(instance, "M-00FA_A-5_MD-1_P-2_R-2"));

        device.set_parameter_value("M-00FA_A-5_P-COUNT_R-1", ParameterValue::Integer(0));
        let evaluated = device.evaluate(&[]).expect("no active modules");
        assert!(evaluated.procedure_selector(&level).is_none());
        assert!(evaluated.procedure_selector(&hidden).is_none());
        assert!(evaluated.parameter_overlays().all(|parameter| !parameter.id.contains("::")));
    }

    #[test]
    fn evaluated_overlays_borrow_values_and_keep_programming_separate_from_edits() {
        use crate::runtime::evaluation::ParameterSource;
        use std::borrow::Cow;

        let selected = SelectedProduct::from_document(
            parse_application_program(ALLOCATOR_REPEAT_FIXTURE).expect("repeat fixture"),
            None,
            None,
        )
        .expect("selected product");
        let device = Device::from_product(Arc::new(selected), None, None);
        let evaluated = device.evaluate(&[]).expect("default evaluation");
        assert!(evaluated.settings().parameters.is_empty());
        let overlays = evaluated.parameter_overlays().collect::<Vec<_>>();
        let count = overlays.iter().filter(|p| p.id == "M-00FA_A-5_P-COUNT").collect::<Vec<_>>();
        assert_eq!(count.len(), 2);
        assert_eq!(count[0].source, ParameterSource::Default);
        assert_eq!(*count[0].value, ParameterValue::Integer(1));
        assert_eq!(count[1].source, ParameterSource::Reference(Cow::Borrowed("M-00FA_A-5_P-COUNT_R-1")));
        assert_eq!(*count[1].value, ParameterValue::Integer(2));
        assert_eq!(count[1].size_bits, 8);
        assert!(matches!(count[1].parameter_type, Some(ParameterTypeDef::TypeNumber(_))));
        assert!(matches!(count[1].id, Cow::Borrowed(_)));
        assert!(overlays.iter().all(|p| matches!(p.value, Cow::Borrowed(_))));

        // Each instance contributes one visible ref and a hidden Assign output.
        // The outputs follow every seed/ref and are not authored project edits.
        let derived = overlays.iter().rev().take_while(|p| p.source == ParameterSource::Derived).collect::<Vec<_>>();
        assert_eq!(derived.len(), 2);
        for module in evaluated.modules() {
            let id = format!("{}::M-00FA_A-5_MD-1_P-1", module.instance_id);
            let reference = format!("{}::M-00FA_A-5_MD-1_P-1_R-1", module.instance_id);
            assert!(overlays.iter().any(|p| {
                p.id == id
                    && p.source == ParameterSource::Reference(Cow::Borrowed(&reference))
                    && *p.value == ParameterValue::Integer(7)
            }));
            let id = format!("{}::M-00FA_A-5_MD-1_P-2", module.instance_id);
            assert!(derived.iter().any(|p| p.id == id && *p.value == ParameterValue::Integer(2)));
        }
    }

    #[test]
    fn evaluated_geometry_uses_argument_identity_and_preserves_union_float_widths() {
        let xml = ALLOCATOR_REPEAT_FIXTURE
            .replace("Name=\"ParamOffset\"", "Name=\"StorageStart\"")
            .replace("</ParameterTypes>", r#"
              <ParameterType Id="F16" Name="F16"><TypeFloat Encoding="DPT 9" minInclusive="0" maxInclusive="100"/></ParameterType>
              <ParameterType Id="F32" Name="F32"><TypeFloat Encoding="IEEE-754 Single" minInclusive="0" maxInclusive="100"/></ParameterType>
              <ParameterType Id="F64" Name="F64"><TypeFloat Encoding="IEEE-754 Double" minInclusive="0" maxInclusive="100"/></ParameterType>
            </ParameterTypes>"#)
            .replacen("</Parameters>", r#"
              <Union SizeInBit="64">
                <Memory CodeSegment="M-00FA_A-5_AS-1" Offset="40" BitOffset="0"/>
                <Parameter Id="float16" Name="F16" ParameterType="F16" Text="Float 16" Value="2.75" Offset="0" BitOffset="0" DefaultUnionParameter="true"/>
                <Parameter Id="float32" Name="F32" ParameterType="F32" Text="Float 32" Value="2.75" Offset="0" BitOffset="0"/>
                <Parameter Id="float64" Name="F64" ParameterType="F64" Text="Float 64" Value="2.75" Offset="0" BitOffset="0"/>
              </Union>
            </Parameters>"#, 1);
        let module_union = r#"<Union SizeInBit="16">
            <Memory CodeSegment="M-00FA_A-5_AS-1" Offset="2" BitOffset="0" BaseOffset="M-00FA_A-5_MD-1_A-OFF"/>
            <Parameter Id="packed" Name="Packed" ParameterType="M-00FA_A-5_PT-N8" Text="Packed" Value="1" Offset="0" BitOffset="6" DefaultUnionParameter="true"/>
          </Union>"#;
        let module_start = xml.find("<ModuleDefs>").expect("module fixture");
        let parameters_end = module_start + xml[module_start..].find("</Parameters>").expect("module parameters");
        let mut xml = xml;
        xml.insert_str(parameters_end, module_union);
        let selected =
            SelectedProduct::from_document(parse_application_program(&xml).expect("geometry fixture"), None, None)
                .expect("selected product");
        let device = Device::from_product(Arc::new(selected), None, None);
        let evaluated = device.evaluate(&[]).expect("valid repeated geometry");
        let locations = evaluated.product().parameters();
        for (id, width) in [("float16", 16), ("float32", 32), ("float64", 64)] {
            let location = locations.iter().find(|location| location.id == id).expect("root union member");
            assert_eq!((location.offset, location.bit_offset, location.size_bits), (40, 0, width));
        }
        let mut packed: Vec<_> = locations
            .iter()
            .filter(|location| location.id.ends_with("::packed"))
            .map(|location| (location.offset, location.bit_offset, location.size_bits))
            .collect();
        packed.sort_unstable();
        assert_eq!(packed, [(12, 6, 8), (16, 6, 8)]);
        assert_eq!(
            device.parameter_description("M-00FA_A-5_P-COUNT_R-1").expect("root reference").default,
            Some(ParameterValue::Integer(2))
        );
    }

    #[test]
    fn module_object_inheritance_preserves_numbering_text_and_provenance() {
        use crate::runtime::configuration::{
            EffectiveFlagSources, EffectiveValueSource, ObjectFlagOverrides, ObjectSetting,
        };
        use zweidraehte_proto::messages::knx::Priority;

        let xml = ALLOCATOR_REPEAT_FIXTURE.replace(
            r#"<ComObjectRef Id="M-00FA_A-5_MD-1_O-1_R-1" RefId="M-00FA_A-5_MD-1_O-1" />"#,
            r#"<ComObjectRef Id="M-00FA_A-5_MD-1_O-1_R-1" RefId="M-00FA_A-5_MD-1_O-1"
                Text="Channel {{ChNo}} {{0}}" TextParameterRefId="M-00FA_A-5_MD-1_P-1_R-1"
                FunctionText="Switch {{ChNo}}" Priority="Alert" ReadFlag="Enabled" WriteFlag="Disabled"
                UpdateFlag="Enabled" ReadOnInitFlag="Enabled" ObjectSize="1 Byte" DatapointType="DPST-5-1" />"#,
        );
        let selected =
            SelectedProduct::from_document(parse_application_program(&xml).expect("module overrides"), None, None)
                .expect("selected product");
        let device = Device::from_product(Arc::new(selected), None, None);
        let configuration = ProductConfiguration {
            parameters: vec![],
            objects: vec![ObjectSetting {
                com_object: 220,
                flags: ObjectFlagOverrides {
                    priority: Some(Priority::System),
                    read: Some(false),
                    write: Some(true),
                    communication: Some(false),
                    transmit: Some(true),
                    update: Some(false),
                    ..Default::default()
                },
            }],
        };
        let objects = effective_com_objects(&device, &configuration);
        assert_eq!(objects.iter().map(|object| object.number).collect::<Vec<_>>(), [220, 230]);
        let first = &objects[0];
        assert_eq!((first.text.as_str(), first.function_text.as_str()), ("Channel 1 7", "Switch 1"));
        assert_eq!((first.object_size.as_str(), first.datapoint_type.as_deref()), ("1 Byte", Some("DPST-5-1")));
        assert_eq!(first.priority, Priority::System);
        assert!(
            !first.read && first.write && !first.communication && first.transmit && !first.update && first.read_on_init
        );
        assert_eq!(first.flag_sources, EffectiveFlagSources {
            priority: EffectiveValueSource::Project,
            read: EffectiveValueSource::Project,
            write: EffectiveValueSource::Project,
            communication: EffectiveValueSource::Project,
            transmit: EffectiveValueSource::Project,
            update: EffectiveValueSource::Project,
            read_on_init: EffectiveValueSource::VisibleReference,
        });
        let second = &objects[1];
        assert_eq!((second.text.as_str(), second.function_text.as_str()), ("Channel 2 7", "Switch 2"));
        assert_eq!(second.priority, Priority::Alarm);
        assert!(
            second.read
                && !second.write
                && second.communication
                && !second.transmit
                && second.update
                && second.read_on_init
        );
        assert_eq!(second.flag_sources.communication, EffectiveValueSource::Product);
    }

    #[test]
    fn allocator_backed_repeat_tracks_its_count_and_preserves_instance_values() {
        let knx = parse_application_program(ALLOCATOR_REPEAT_FIXTURE).expect("the repeat fixture parses");
        let program =
            knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next().expect("one program");
        let product = crate::product::ProductData::from_program(&program).expect("the repeat product extracts");
        let mut device = Device::new(program, None);

        // The ParameterRef override (2) is the effective initial count,
        // rather than the base parameter's default (1).
        let mut modules = device.all_expanded_modules().collect::<Vec<_>>();
        modules.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
        assert_eq!(modules.len(), 2);
        assert!(matches!(modules[0].args.get("ChNo"), Some(ModuleArgValue::Numeric(1))));
        assert!(matches!(modules[0].args.get("ParamOffset"), Some(ModuleArgValue::Numeric(10))));
        assert!(matches!(modules[1].args.get("ChNo"), Some(ModuleArgValue::Numeric(2))));
        assert!(matches!(modules[1].args.get("ParamOffset"), Some(ModuleArgValue::Numeric(14))));
        assert_eq!(device.visible_module_com_objects().iter().map(|object| object.number).collect::<Vec<_>>(), [
            220, 230
        ]);
        let first_id = modules[0].instance_id.clone();
        drop(modules);
        let first_root_mode = format!("{first_id}::M-00FA_A-5_MD-1_P-2_R-2");
        assert_eq!(
            device.get_module_parameter_value_by_composite_id(&first_root_mode),
            Some(&ParameterValue::Integer(2)),
            "a module assignment can read an application-wide parameter ref"
        );

        let object_settings = crate::runtime::configuration::ProductConfiguration {
            parameters: Vec::new(),
            objects: vec![crate::runtime::configuration::ObjectSetting { com_object: 220, flags: Default::default() }],
        };
        crate::runtime::configuration::apply_configuration(&mut device, &object_settings)
            .expect("the concrete module object is a valid project object");
        let effective = crate::runtime::configuration::effective_com_objects(&device, &object_settings);
        assert!(effective.iter().any(|object| object.number == 220 && object.text == "Channel 1"));
        let resolved_product = product.resolve_device_geometry(&device).expect("module offsets resolve");
        let mut module_offsets = resolved_product
            .parameters()
            .iter()
            .filter(|location| location.id.contains("::"))
            .map(|location| location.offset)
            .collect::<Vec<_>>();
        module_offsets.sort_unstable();
        assert_eq!(module_offsets, [10, 11, 14, 15]);

        // The two refs reuse one base Parameter but remain distinct values.
        assert_eq!(device.get_parameter_value("M-00FA_A-5_P-COUNT_R-1"), Some(&ParameterValue::Integer(2)));
        assert_eq!(device.get_parameter_value("M-00FA_A-5_P-COUNT_R-2"), Some(&ParameterValue::Integer(1)));
        device.set_parameter_value("M-00FA_A-5_P-COUNT_R-1", ParameterValue::Integer(3));
        assert_eq!(device.get_parameter_value("M-00FA_A-5_P-COUNT_R-2"), Some(&ParameterValue::Integer(1)));

        let first_parameter_ref = format!("{first_id}::M-00FA_A-5_MD-1_P-1_R-1");
        device.set_module_parameter_value_by_composite_id(&first_parameter_ref, ParameterValue::Integer(9));
        device.set_parameter_value("M-00FA_A-5_P-COUNT_R-1", ParameterValue::Integer(1));
        assert_eq!(device.all_expanded_modules().count(), 1);

        device.set_parameter_value("M-00FA_A-5_P-COUNT_R-1", ParameterValue::Integer(3));
        assert_eq!(
            device.get_module_parameter_value_by_composite_id(&first_root_mode),
            Some(&ParameterValue::Integer(3)),
            "the application-wide assignment source remains live"
        );
        let mut modules = device.all_expanded_modules().collect::<Vec<_>>();
        modules.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
        assert_eq!(modules.len(), 3);
        assert!(matches!(modules[2].args.get("ChNo"), Some(ModuleArgValue::Numeric(3))));
        assert!(matches!(modules[2].args.get("ParamOffset"), Some(ModuleArgValue::Numeric(18))));
        assert_eq!(device.visible_module_com_objects().iter().map(|object| object.number).collect::<Vec<_>>(), [
            220, 230, 240
        ]);
        assert_eq!(
            device.get_module_parameter_value(&first_id, "M-00FA_A-5_MD-1_P-1"),
            Some(&ParameterValue::Integer(9))
        );

        let settings = crate::runtime::configuration::configuration_from_device(&device);
        assert!(
            settings.parameters.iter().any(|setting| {
                setting.id == "M-00FA_A-5_P-COUNT_R-1" && setting.value == ParameterValue::Integer(3)
            })
        );
        assert!(
            settings
                .parameters
                .iter()
                .any(|setting| setting.id == first_parameter_ref && setting.value == ParameterValue::Integer(9))
        );

        let knx = parse_application_program(ALLOCATOR_REPEAT_FIXTURE).expect("the repeat fixture reparses");
        let program =
            knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next().expect("one program");
        let mut restored = Device::new(program, None);
        crate::runtime::configuration::apply_configuration(&mut restored, &settings)
            .expect("ref and module settings restore");
        assert_eq!(restored.all_expanded_modules().count(), 3);
        assert_eq!(
            restored.get_module_parameter_value_by_composite_id(&first_parameter_ref),
            Some(&ParameterValue::Integer(9))
        );
    }

    #[test]
    fn explicit_module_arguments_do_not_require_allocation_widths() {
        let xml = ALLOCATOR_REPEAT_FIXTURE
            .replace(" Allocates=\"1\"", "")
            .replace(" Allocates=\"4\"", "")
            .replace(" Allocates=\"10\"", "")
            .replace("AllocatorRefId=\"M-00FA_A-5_L-CH\"", "Value=\"1\"")
            .replace("AllocatorRefId=\"M-00FA_A-5_L-OFF\"", "Value=\"10\"")
            .replace("AllocatorRefId=\"M-00FA_A-5_L-OBJ\"", "Value=\"220\"")
            .replace("Value=\"2\"", "Value=\"1\"");
        let knx = parse_application_program(&xml).expect("explicit arguments parse without Allocates");
        let program =
            knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next().expect("one program");
        let device = Device::new(program, None);
        assert_eq!(device.derivation_error(), None);
        assert_eq!(device.all_expanded_modules().count(), 1);
        let module = device.all_expanded_modules().next().expect("one expanded module");
        assert!(matches!(module.args.get("ObjectBase"), Some(ModuleArgValue::Numeric(220))));
    }

    #[test]
    fn invalid_active_allocations_are_configuration_errors_not_missing_modules() {
        use crate::runtime::configuration::{ProductConfiguration, apply_configuration};

        for (replacement, reason) in
            [("", "needs Allocates"), (" Allocates=\"18446744073709551615\"", "exceeds the signed runtime range")]
        {
            let xml = ALLOCATOR_REPEAT_FIXTURE.replace(" Allocates=\"1\"", replacement);
            let knx = parse_application_program(&xml).expect("optional unsigned-long width parses");
            let selected = SelectedProduct::from_document(knx, None, None).expect("product selection");
            let mut device = Device::from_product(Arc::new(selected), None, None);
            assert!(device.derivation_error().expect("active allocation fails").contains(reason));
            let error = device.evaluate(&[]).expect_err("failed derivation cannot publish a preview");
            assert!(matches!(error, ConfigurationError::Derivation(ref message) if message.contains(reason)));
            let error = apply_configuration(&mut device, &ProductConfiguration::default())
                .expect_err("partial module state is not a valid configuration");
            assert!(error.to_string().contains(reason), "{error}");
        }
    }

    #[test]
    fn test_mdt_module_expansion() {
        let path = Path::new("../../manuf_tool_data/VC-EASY-03_MDT_KP_V35/M-0083/M-0083_A-0070-35-1740.xml");
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

        let mut device = Device::new(program, None);

        // The MDT product creates module instances only for enabled function
        // blocks. Select the first one through the same exact reference the
        // editor exposes.
        device.set_parameter_value("M-0083_A-0070-35-1740_P-9155_R-1201", ParameterValue::Integer(1));

        // Check that we have expanded modules
        let modules: Vec<_> = device.all_expanded_modules().collect();
        assert!(!modules.is_empty(), "Should have expanded modules");

        // Check that first module has ChNo arg
        let first = &modules[0];
        eprintln!("First module: {} -> {:?}", first.instance_id, first.args);

        // Find a module with ChNo=1
        let m1 = modules.iter().find(|m| matches!(m.args.get("ChNo"), Some(ModuleArgValue::Numeric(1))));
        assert!(m1.is_some(), "Should find module with ChNo=1");
        let m1 = m1.expect("module ChNo=1 exists");
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

    // ========================================================================
    // Product scripts
    // ========================================================================

    /// A product whose scripts disagree with its defaults: the calculation
    /// would turn `Source=4` into `Target=12`, but the product declares
    /// `Target=0`. `Celsius`/`Kelvin` pair both directions inline, `Vb` uses
    /// VBScript, and `Guard` carries a validation.
    const SCRIPTED_FIXTURE: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="Manufacturer Tool" ToolVersion="5.7" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-6" ApplicationNumber="6" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-07B0" Name="Scripted" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="true" Linkable="true">
      <Static>
        <Code><AbsoluteSegment Id="M-00FA_A-6_AS-1" Address="4096" Size="16" /></Code>
        <ParameterTypes>
          <ParameterType Id="M-00FA_A-6_PT-N8" Name="N8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
        </ParameterTypes>
        <Parameters>
          <Parameter Id="M-00FA_A-6_P-1" Name="Source" ParameterType="M-00FA_A-6_PT-N8" Text="Source" Value="4"><Memory CodeSegment="M-00FA_A-6_AS-1" Offset="0" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-6_P-2" Name="Target" ParameterType="M-00FA_A-6_PT-N8" Text="Target" Value="0"><Memory CodeSegment="M-00FA_A-6_AS-1" Offset="1" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-6_P-3" Name="Guard" ParameterType="M-00FA_A-6_PT-N8" Text="Guard" Value="1"><Memory CodeSegment="M-00FA_A-6_AS-1" Offset="2" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-6_P-4" Name="Celsius" ParameterType="M-00FA_A-6_PT-N8" Text="Celsius" Value="20"><Memory CodeSegment="M-00FA_A-6_AS-1" Offset="3" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-6_P-5" Name="Kelvin" ParameterType="M-00FA_A-6_PT-N8" Text="Kelvin" Value="30"><Memory CodeSegment="M-00FA_A-6_AS-1" Offset="4" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-6_P-6" Name="Vb" ParameterType="M-00FA_A-6_PT-N8" Text="Vb" Value="1"><Memory CodeSegment="M-00FA_A-6_AS-1" Offset="5" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-6_P-7" Name="VbOut" ParameterType="M-00FA_A-6_PT-N8" Text="VbOut" Value="0"><Memory CodeSegment="M-00FA_A-6_AS-1" Offset="6" BitOffset="0" /></Parameter>
        </Parameters>
        <ParameterRefs>
          <ParameterRef Id="M-00FA_A-6_P-1_R-1" RefId="M-00FA_A-6_P-1" />
          <ParameterRef Id="M-00FA_A-6_P-2_R-2" RefId="M-00FA_A-6_P-2" Name="dst" />
          <ParameterRef Id="M-00FA_A-6_P-3_R-3" RefId="M-00FA_A-6_P-3" />
          <ParameterRef Id="M-00FA_A-6_P-4_R-4" RefId="M-00FA_A-6_P-4" />
          <ParameterRef Id="M-00FA_A-6_P-5_R-5" RefId="M-00FA_A-6_P-5" />
          <ParameterRef Id="M-00FA_A-6_P-6_R-6" RefId="M-00FA_A-6_P-6" />
          <ParameterRef Id="M-00FA_A-6_P-7_R-7" RefId="M-00FA_A-6_P-7" />
        </ParameterRefs>
        <Messages>
          <Message Id="M-00FA_A-6_M-1" Name="GuardTooLarge" Text="Guard exceeds source" />
        </Messages>
        <Script>
          function Scale(input, output, context) { output.dst = input.src * context.factor; }
          function Unscale(input, output, context) { output.src = input.dst / context.factor; }
          function CheckGuard(input, changed, newValue, context) {
            return input.guard &lt;= input.src ? true : getMessage(1);
          }
        </Script>
        <ParameterCalculations>
          <ParameterCalculation Id="M-00FA_A-6_PC-1" Language="JavaScript" Name="Scale" LRTransformationFunc="Scale" LRTransformationParameters="{ factor: 3 }" RLTransformationFunc="Unscale" RLTransformationParameters="{ factor: 3 }">
            <LParameters><ParameterRefRef RefId="M-00FA_A-6_P-1_R-1" AliasName="src" /></LParameters>
            <RParameters><ParameterRefRef RefId="M-00FA_A-6_P-2_R-2" /></RParameters>
          </ParameterCalculation>
          <ParameterCalculation Id="M-00FA_A-6_PC-2" Language="JavaScript" Name="Temperature">
            <LRTransformation>kelvin = celsius + 10;</LRTransformation>
            <RLTransformation>celsius = kelvin - 10;</RLTransformation>
            <LParameters><ParameterRefRef RefId="M-00FA_A-6_P-4_R-4" AliasName="celsius" /></LParameters>
            <RParameters><ParameterRefRef RefId="M-00FA_A-6_P-5_R-5" AliasName="kelvin" /></RParameters>
          </ParameterCalculation>
          <ParameterCalculation Id="M-00FA_A-6_PC-3" Language="VBScript" Name="Basic">
            <LRTransformation>VbOut = Vb * 2</LRTransformation>
            <LParameters><ParameterRefRef RefId="M-00FA_A-6_P-6_R-6" AliasName="Vb" /></LParameters>
            <RParameters><ParameterRefRef RefId="M-00FA_A-6_P-7_R-7" AliasName="VbOut" /></RParameters>
          </ParameterCalculation>
        </ParameterCalculations>
        <ParameterValidations>
          <ParameterValidation Id="M-00FA_A-6_PV-1" Name="Guard" ValidationFunc="CheckGuard">
            <Parameters>
              <ParameterRefRef RefId="M-00FA_A-6_P-1_R-1" AliasName="src" />
              <ParameterRefRef RefId="M-00FA_A-6_P-3_R-3" AliasName="guard" />
            </Parameters>
          </ParameterValidation>
        </ParameterValidations>
      </Static>
      <Dynamic>
        <ChannelIndependentBlock>
          <ParameterBlock Id="M-00FA_A-6_PB-1" Text="Settings">
            <ParameterRefRef RefId="M-00FA_A-6_P-1_R-1" />
            <ParameterRefRef RefId="M-00FA_A-6_P-3_R-3" />
            <ParameterRefRef RefId="M-00FA_A-6_P-4_R-4" />
            <ParameterRefRef RefId="M-00FA_A-6_P-5_R-5" />
            <ParameterRefRef RefId="M-00FA_A-6_P-6_R-6" />
          </ParameterBlock>
          <ParameterBlock Id="M-00FA_A-6_PB-2" Text="Internal" Access="None">
            <ParameterRefRef RefId="M-00FA_A-6_P-2_R-2" />
            <ParameterRefRef RefId="M-00FA_A-6_P-7_R-7" />
          </ParameterBlock>
        </ChannelIndependentBlock>
      </Dynamic>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    fn scripted_device() -> Device {
        let selected = SelectedProduct::from_document(
            parse_application_program(SCRIPTED_FIXTURE).expect("fixture parses"),
            None,
            None,
        )
        .expect("selected scripted product");
        Device::from_product(Arc::new(selected), None, None)
    }

    #[test]
    fn defaults_and_stored_values_never_run_scripts() {
        // Neither the VBScript calculation nor the validation is needed to
        // compile defaults, and the calculated target keeps its own default.
        let mut device = scripted_device();
        assert_eq!(device.derivation_error(), None);
        assert_eq!(device.get_parameter_value("M-00FA_A-6_P-2_R-2"), Some(&ParameterValue::Integer(0)));
        assert!(device.evaluate(&[]).is_ok());

        // A project's stored values are taken as they are, including a
        // calculation result behind `Access="None"` that disagrees with
        // what the script would compute now.
        let configuration = ProductConfiguration {
            parameters: vec![
                crate::runtime::configuration::ParameterSetting {
                    id: "M-00FA_A-6_P-1_R-1".into(),
                    value: ParameterValue::Integer(9),
                },
                crate::runtime::configuration::ParameterSetting {
                    id: "M-00FA_A-6_P-2_R-2".into(),
                    value: ParameterValue::Integer(5),
                },
            ],
            objects: Vec::new(),
        };
        crate::runtime::configuration::apply_configuration(&mut device, &configuration).expect("stored values apply");
        assert_eq!(device.get_parameter_value("M-00FA_A-6_P-2_R-2"), Some(&ParameterValue::Integer(5)));
        let exported = crate::runtime::configuration::configuration_from_device(&device);
        assert!(exported.parameters.iter().any(|setting| setting.id == "M-00FA_A-6_P-2_R-2"));
    }

    #[cfg(feature = "javascript")]
    #[test]
    fn numeric_script_outputs_respect_bounds_and_restore_failed_edits() {
        let fixture = SCRIPTED_FIXTURE.replace("maxInclusive=\"255\"", "maxInclusive=\"100\"");
        let selected = SelectedProduct::from_document(
            parse_application_program(&fixture).expect("bounded fixture parses"),
            None,
            None,
        )
        .expect("selected bounded product");
        let mut device = Device::from_product(Arc::new(selected), None, None);

        // Each proposed edit is legal itself. Its calculation crosses a
        // declared output bound, including a hidden function output and
        // inline calculations in both directions. Nothing may be committed.
        for (edited, output, value) in [
            ("M-00FA_A-6_P-1_R-1", "M-00FA_A-6_P-2_R-2", 85),
            ("M-00FA_A-6_P-4_R-4", "M-00FA_A-6_P-5_R-5", 95),
            ("M-00FA_A-6_P-5_R-5", "M-00FA_A-6_P-4_R-4", 5),
        ] {
            let before_edit = device.get_parameter_value(edited).cloned();
            let before_output = device.get_parameter_value(output).cloned();
            let result = device.try_set_parameter_value(edited, ParameterValue::Integer(value));
            assert!(
                matches!(&result, Err(ConfigurationError::Derivation(message)) if message.contains("0..=100")),
                "{edited}: {result:?}"
            );
            assert_eq!(device.get_parameter_value(edited), before_edit.as_ref());
            assert_eq!(device.get_parameter_value(output), before_output.as_ref());
            assert!(!device.is_parameter_touched(edited));
            assert!(!device.is_parameter_touched(output));
            assert_eq!(device.derivation_error(), None);
        }

        // Bounds are inclusive; hidden outputs do not require editor access.
        device.try_set_parameter_value("M-00FA_A-6_P-3_R-3", ParameterValue::Integer(0)).expect("lower guard");
        device.try_set_parameter_value("M-00FA_A-6_P-1_R-1", ParameterValue::Integer(0)).expect("minimum output");
        assert_eq!(device.get_parameter_value("M-00FA_A-6_P-2_R-2"), Some(&ParameterValue::Integer(0)));
        device.try_set_parameter_value("M-00FA_A-6_P-4_R-4", ParameterValue::Integer(90)).expect("maximum output");
        assert_eq!(device.get_parameter_value("M-00FA_A-6_P-5_R-5"), Some(&ParameterValue::Integer(100)));
    }

    #[cfg(feature = "javascript")]
    #[test]
    fn edits_run_reachable_calculations_and_store_their_results() {
        let mut device = scripted_device();

        // Left to right through a named function and its `context`; the
        // output has no alias and is addressed by its reference's name.
        device.try_set_parameter_value("M-00FA_A-6_P-1_R-1", ParameterValue::Integer(5)).expect("edit source");
        assert_eq!(device.get_parameter_value("M-00FA_A-6_P-2_R-2"), Some(&ParameterValue::Integer(15)));
        assert!(device.is_parameter_touched("M-00FA_A-6_P-2_R-2"));

        // The hidden but active result reaches the programming overlays.
        let evaluated = device.evaluate(&[]).expect("evaluates");
        let overlay = evaluated
            .parameter_overlays()
            .filter(|overlay| overlay.id == "M-00FA_A-6_P-2")
            .last()
            .expect("target overlay");
        assert_eq!(overlay.value.as_ref(), &ParameterValue::Integer(15));
        drop(evaluated);

        // Inline transformations run in both directions; editing the right
        // side does not bounce back through the left-to-right body.
        device.try_set_parameter_value("M-00FA_A-6_P-4_R-4", ParameterValue::Integer(25)).expect("edit celsius");
        assert_eq!(device.get_parameter_value("M-00FA_A-6_P-5_R-5"), Some(&ParameterValue::Integer(35)));
        device.try_set_parameter_value("M-00FA_A-6_P-5_R-5", ParameterValue::Integer(50)).expect("edit kelvin");
        assert_eq!(device.get_parameter_value("M-00FA_A-6_P-4_R-4"), Some(&ParameterValue::Integer(40)));
    }

    #[cfg(feature = "javascript")]
    #[test]
    fn validations_reject_edits_before_anything_is_stored() {
        let mut device = scripted_device();
        let rejected = device.try_set_parameter_value("M-00FA_A-6_P-3_R-3", ParameterValue::Integer(7));
        assert!(
            matches!(&rejected, Err(ConfigurationError::Rejected { message: Some(message), .. }) if message == "Guard exceeds source"),
            "{rejected:?}"
        );
        assert_eq!(device.get_parameter_value("M-00FA_A-6_P-3_R-3"), Some(&ParameterValue::Integer(1)));
        device.try_set_parameter_value("M-00FA_A-6_P-3_R-3", ParameterValue::Integer(3)).expect("guard within source");
    }

    #[test]
    fn a_failed_calculation_restores_the_whole_edit() {
        // TODO: replace with a VBScript result once the interpreter exists.
        let mut device = scripted_device();
        let failed = device.try_set_parameter_value("M-00FA_A-6_P-6_R-6", ParameterValue::Integer(4));
        assert!(matches!(failed, Err(ConfigurationError::Derivation(_))), "{failed:?}");
        assert_eq!(device.get_parameter_value("M-00FA_A-6_P-6_R-6"), Some(&ParameterValue::Integer(1)));
        assert!(!device.is_parameter_touched("M-00FA_A-6_P-6_R-6"));
        assert_eq!(device.derivation_error(), None);
    }

    #[cfg(feature = "javascript")]
    #[test]
    fn module_calculations_see_their_instance_arguments_in_context() {
        let fixture = ALLOCATOR_REPEAT_FIXTURE
            // The scaled outputs exceed the allocator fixture's 0..=10
            // input domain, so give this calculation fixture its own bounds.
            .replace("maxInclusive=\"10\"", "maxInclusive=\"100\"")
            .replace(
                r#"<Parameter Id="M-00FA_A-5_MD-1_P-2""#,
                r#"<Parameter Id="M-00FA_A-5_MD-1_P-3" Name="Scaled" ParameterType="M-00FA_A-5_PT-N8" Text="" Value="0"><Memory CodeSegment="M-00FA_A-5_AS-1" Offset="2" BitOffset="0" BaseOffset="M-00FA_A-5_MD-1_A-OFF" /></Parameter>
              <Parameter Id="M-00FA_A-5_MD-1_P-2""#,
            )
            .replace(
                r#"<ParameterRef Id="M-00FA_A-5_MD-1_P-2_R-2""#,
                r#"<ParameterRef Id="M-00FA_A-5_MD-1_P-3_R-3" RefId="M-00FA_A-5_MD-1_P-3" />
              <ParameterRef Id="M-00FA_A-5_MD-1_P-2_R-2""#,
            )
            .replace(
                "          </Static>\n          <Dynamic>",
                r#"            <ParameterCalculations>
              <ParameterCalculation Id="M-00FA_A-5_MD-1_PC-1" Language="JavaScript" Name="Channel" LRTransformationFunc="Channel" LRTransformationParameters="{ channel: {{ChNo}}, missing: '{{Nothing}}' }">
                <LParameters><ParameterRefRef RefId="M-00FA_A-5_MD-1_P-1_R-1" AliasName="level" /></LParameters>
                <RParameters><ParameterRefRef RefId="M-00FA_A-5_MD-1_P-3_R-3" AliasName="scaled" /></RParameters>
              </ParameterCalculation>
            </ParameterCalculations>
          </Static>
          <Dynamic>
            <ParameterBlock Id="M-00FA_A-5_MD-1_PB-2" Text="" Access="None"><ParameterRefRef RefId="M-00FA_A-5_MD-1_P-3_R-3" /></ParameterBlock>"#,
            )
            .replace(
                "      </Static>\n      <ModuleDefs>",
                "        <Script>function Channel(input, output, context) { output.scaled = input.level * 10 + context.channel + context.missing.length; }</Script>\n      </Static>\n      <ModuleDefs>",
            );
        let selected =
            SelectedProduct::from_document(parse_application_program(&fixture).expect("fixture parses"), None, None)
                .expect("selected");
        let mut device = Device::from_product(Arc::new(selected), None, None);
        let mut instances = device.all_expanded_modules().map(|module| module.instance_id.clone()).collect::<Vec<_>>();
        instances.sort();

        // Each instance's calculation sees its own channel number. An unknown
        // argument expands to the two characters `""`, so inside quotes it
        // becomes a two-character string rather than an empty one.
        for (index, instance) in instances.iter().enumerate() {
            let level = format!("{instance}::M-00FA_A-5_MD-1_P-1_R-1");
            device.try_set_parameter_value(&level, ParameterValue::Integer(2)).expect("module edit");
            let channel =
                device.get_expanded_module(instance).and_then(|module| module.args.get("ChNo")).map(format_arg_value);
            let expected = 20 + channel.expect("allocated channel").parse::<i64>().expect("numeric channel") + 2;
            assert_eq!(
                device.get_module_parameter_value_by_composite_id(&format!("{instance}::M-00FA_A-5_MD-1_P-3_R-3")),
                Some(&ParameterValue::Integer(expected)),
                "instance {index}"
            );
            let rejected = device.try_set_parameter_value(&level, ParameterValue::Integer(10));
            assert!(
                matches!(&rejected, Err(ConfigurationError::Derivation(message)) if message.contains("0..=100")),
                "instance {index}: {rejected:?}"
            );
            assert_eq!(device.get_module_parameter_value_by_composite_id(&level), Some(&ParameterValue::Integer(2)));
            assert_eq!(
                device.get_module_parameter_value_by_composite_id(&format!("{instance}::M-00FA_A-5_MD-1_P-3_R-3")),
                Some(&ParameterValue::Integer(expected))
            );
        }
    }
}
