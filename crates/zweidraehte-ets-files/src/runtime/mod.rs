//! Runtime Support for Parsed KNX Devices
//!
//! This module provides types for parsing and working with existing KNX MTXML files.
//! It contains:
//!
//! - [`parser`] - XML parsing for ApplicationProgram files
//! - [`baggage`] - Loading baggage files (images, icons)
//! - [`device`] - Editable product-configuration state (without master data)
//! - [`model`] - Runtime model with condition evaluation and visitor pattern
//! - [`configuration`] - Product-aware configuration validation and flag resolution
//! - [`translations`] - Applying `<Languages>` translations to a parsed program
//!
//! These types are used by the TUI viewer and for working with parsed MTXML files.

pub mod baggage;
pub mod configuration;
pub mod device;
pub mod model;
pub mod parser;
pub mod translations;

// Re-export key types for convenience
pub use baggage::BaggageIndex;
pub use configuration::{
    ConfigurationError, EffectiveComObject, EffectiveFlagSources, EffectiveValueSource, ObjectFlagOverrides,
    ObjectSetting, ParameterSetting, ProductConfiguration, ProductDptReference, ProductDptReferences,
    apply_configuration, configuration_from_device, effective_com_objects, effective_default,
};
pub use device::Device;
pub use model::{ConditionEvaluator, DynamicVisitor, VisibilityVisitor, VisitorModuleContext, walk_dynamic};
pub use parser::{ParseError, parse_application_program, parse_application_program_from_file};
pub use translations::Translations;
