//! KNX Project XML Schema Types
//!
//! Typed Rust structs matching the KNX project XSD schema for MTXML files.
//! These types are used with serde and quick-xml for proper XML serialization.
//!
//! # Module Organization
//!
//! - [`core`] - Root types: MaskFamily, Knx, ManufacturerData, ApplicationProgram
//! - [`static_section`] - Static section types: Code, segments, Extension, BaggageDef
//! - [`parameters`] - Parameter types and definitions
//! - [`param_refs`] - Parameter references
//! - [`com_objects`] - Communication object types
//! - [`load_procedures`] - Load control and procedure types
//! - [`modules`] - Module definitions and instances
//! - [`dynamic`] - Dynamic section: channels, blocks, choose/when
//! - [`hardware`] - Hardware MTXML types
//! - [`catalog`] - Catalog MTXML types
//! - [`languages`] - Language translations for multi-language support
//! - [`helpers`] - Helper functions for conversions

mod catalog;
mod com_objects;
mod core;
mod dynamic;
mod hardware;
mod helpers;
mod languages;
mod load_procedures;
mod modules;
mod param_refs;
mod parameters;
mod project;
mod static_section;

// Re-export all public types for backwards compatibility
pub use self::core::*;
pub use catalog::*;
pub use com_objects::*;
pub use dynamic::*;
pub use hardware::*;
pub use helpers::*;
pub use languages::*;
pub use load_procedures::*;
pub use modules::*;
pub use param_refs::*;
pub use parameters::*;
pub use project::*;
pub use static_section::*;
