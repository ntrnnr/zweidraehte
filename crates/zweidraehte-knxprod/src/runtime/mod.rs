//! Runtime Support for Parsed KNX Devices
//!
//! This module provides types for parsing and working with existing KNX MTXML files.
//! It contains:
//!
//! - [`parser`] - XML parsing for ApplicationProgram files
//! - [`baggage`] - Loading baggage files (images, icons)
//! - [`master_data`] - Parsing knx_master.xml for mask version definitions
//! - [`device_info`] - Device programming information extraction
//! - [`device`] - Unified Device struct with runtime state
//! - [`model`] - Runtime model with condition evaluation and visitor pattern
//! - [`mods`] - Declarative single-device configuration overrides ("mods" files)
//! - [`translations`] - Applying `<Languages>` translations to a parsed program
//!
//! These types are used by the TUI viewer and for working with parsed MTXML files.

pub mod baggage;
pub mod device;
pub mod device_info;
pub mod master_data;
pub mod model;
pub mod mods;
pub mod parser;
pub mod translations;

/// Reading `.knxprod` archives (needs the `zip` dependency).
#[cfg(feature = "product-files")]
pub mod knxprod;

// Re-export key types for convenience
pub use baggage::BaggageIndex;
pub use device::Device;
pub use device_info::DeviceInfo;
#[cfg(feature = "product-files")]
pub use knxprod::KnxprodArchive;
pub use master_data::MasterData;
pub use model::{ConditionEvaluator, DynamicVisitor, VisibilityVisitor, VisitorModuleContext, walk_dynamic};
pub use mods::{DeviceMods, ModsError, apply_mods, effective_com_objects, mods_from_device};
pub use parser::{ParseError, parse_application_program, parse_application_program_from_file};
pub use translations::Translations;
