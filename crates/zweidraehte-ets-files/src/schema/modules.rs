//! Module definition types for reusable parameter/object templates.

use serde::{Deserialize, Serialize};

use super::com_objects::ComObject;
use super::dynamic::{Choose, ParameterBlock};
use super::param_refs::ParameterRefs;
use super::parameters::Parameters;

// ============================================================================
// Module Definitions
// ============================================================================

/// Container for module definitions.
/// Modules are reusable templates that can be instantiated multiple times
/// with different argument values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleDefs {
    #[serde(rename = "ModuleDef", default)]
    pub module_defs: Vec<ModuleDef>,
}

/// A module definition - a reusable template for parameters and communication objects.
///
/// Modules allow defining a set of parameters and communication objects once,
/// then instantiating them multiple times with different argument values.
/// This is useful for devices with repeating channel structures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleDef {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,

    /// Arguments that can be passed when instantiating this module.
    #[serde(rename = "Arguments", skip_serializing_if = "Option::is_none")]
    pub arguments: Option<ModuleDefArguments>,

    /// Static section containing parameters and communication objects.
    #[serde(rename = "Static")]
    pub static_section: ModuleDefStatic,

    /// Optional dynamic section for UI layout within the module.
    #[serde(rename = "Dynamic", skip_serializing_if = "Option::is_none")]
    pub dynamic: Option<ModuleDefDynamic>,
}

/// Container for module argument definitions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleDefArguments {
    #[serde(rename = "Argument", default)]
    pub arguments: Vec<ModuleDefArgument>,
}

/// A module argument definition.
///
/// Arguments are placeholders that get substituted with actual values when
/// the module is instantiated. They can be used for:
/// - Memory offset calculation (ParamOffsBase)
/// - Communication object numbering (ObjNumberBase)
/// - Display text substitution (ChNo)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleDefArgument {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    /// The amount of resources this argument allocates.
    /// For parameter offsets, this is the number of bytes.
    /// For object numbers, this is the number of objects.
    #[serde(rename = "@Allocates")]
    pub allocates: u32,
    /// Optional memory alignment (1, 2, 4, or 8 bytes).
    #[serde(rename = "@Alignment", skip_serializing_if = "Option::is_none")]
    pub alignment: Option<u8>,
    /// Argument type: "Numeric" (default) or "Text".
    #[serde(rename = "@Type", skip_serializing_if = "Option::is_none")]
    pub arg_type: Option<String>,
}

/// Static section within a module definition.
/// Contains the same elements as the main Static section but scoped to the module.
/// Note: For modules, comm objects use `ComObjects` element (not `ComObjectTable`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleDefStatic {
    #[serde(rename = "Parameters", skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Parameters>,
    #[serde(rename = "ParameterRefs", skip_serializing_if = "Option::is_none")]
    pub parameter_refs: Option<ParameterRefs>,
    /// Communication objects for the module. Note: This uses `ComObjects` (not `ComObjectTable`)
    /// as required by the KNX schema for ModuleDefStatic_t.
    #[serde(rename = "ComObjects", skip_serializing_if = "Option::is_none")]
    pub com_objects: Option<ModuleComObjects>,
    #[serde(rename = "ComObjectRefs", skip_serializing_if = "Option::is_none")]
    pub com_object_refs: Option<super::com_objects::ComObjectRefs>,
}

/// Communication objects container for module definitions.
/// This is the module-specific equivalent of ComObjectTable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleComObjects {
    #[serde(rename = "ComObject", default)]
    pub objects: Vec<ComObject>,
}

/// Dynamic section within a module definition.
/// Contains UI layout elements specific to the module.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleDefDynamic {
    #[serde(rename = "$value", default)]
    pub items: Vec<ModuleDefDynamicItem>,
}

/// Items that can appear in a module's dynamic section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleDefDynamicItem {
    #[serde(rename = "ParameterBlock")]
    ParameterBlock(ParameterBlock),
    #[serde(rename = "choose")]
    Choose(Choose),
}

/// A module instance - instantiates a ModuleDef with specific argument values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    #[serde(rename = "@Id")]
    pub id: String,
    /// Reference to the ModuleDef being instantiated.
    #[serde(rename = "@RefId")]
    pub ref_id: String,
    #[serde(rename = "@Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,

    /// Argument values for this instance.
    #[serde(rename = "$value", default)]
    pub args: Vec<ModuleArg>,
}

/// An argument value passed to a module instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleArg {
    /// Numeric argument value.
    #[serde(rename = "NumericArg")]
    NumericArg {
        /// Reference to the argument definition in the ModuleDef.
        #[serde(rename = "@RefId")]
        ref_id: String,
        /// The numeric value to pass.
        #[serde(rename = "@Value")]
        value: i64,
    },
    /// Text argument value.
    #[serde(rename = "TextArg")]
    TextArg {
        /// Reference to the argument definition in the ModuleDef.
        #[serde(rename = "@RefId")]
        ref_id: String,
        /// Unique ID for this text argument instance.
        #[serde(rename = "@Id")]
        id: String,
        /// The text value to pass.
        #[serde(rename = "@Value")]
        value: String,
    },
}
