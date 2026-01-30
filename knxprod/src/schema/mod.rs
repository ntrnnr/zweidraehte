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
//! - [`helpers`] - Helper functions for conversions

mod core;
mod static_section;
mod parameters;
mod param_refs;
mod com_objects;
mod load_procedures;
mod modules;
mod dynamic;
mod hardware;
mod catalog;
mod helpers;

// Re-export all public types for backwards compatibility
pub use self::core::*;
pub use static_section::*;
pub use parameters::*;
pub use param_refs::*;
pub use com_objects::*;
pub use load_procedures::*;
pub use modules::*;
pub use dynamic::*;
pub use hardware::*;
pub use catalog::*;
pub use helpers::*;
