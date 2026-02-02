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
//!
//! These types are used by the TUI viewer and for working with parsed MTXML files.

pub mod baggage;
pub mod device;
pub mod device_info;
pub mod master_data;
pub mod model;
pub mod parser;

// Re-export key types for convenience
pub use baggage::BaggageIndex;
pub use device::Device;
pub use device_info::DeviceInfo;
pub use master_data::MasterData;
pub use model::{walk_dynamic, ConditionEvaluator, DynamicVisitor, VisibilityVisitor, VisitorModuleContext};
pub use parser::{parse_application_program, parse_application_program_from_file, ParseError};
