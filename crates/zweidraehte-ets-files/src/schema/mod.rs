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

mod baggage;
mod catalog;
mod com_objects;
mod core;
mod dynamic;
mod hardware;
mod helpers;
mod languages;
mod load_procedures;
pub mod master_data;
mod modules;
mod param_refs;
mod parameters;
mod project;
mod static_section;

// One schema namespace is easier to use than format-specific module paths;
// the modules remain private except where a document is large enough to merit
// its own namespace (`master_data`).
pub use self::core::*;
pub use baggage::*;
pub use catalog::*;
pub use com_objects::*;
pub use dynamic::*;
pub use hardware::*;
pub use helpers::*;
pub use languages::*;
pub use load_procedures::*;
pub use master_data::{MasterData, MasterDataError};
pub use modules::*;
pub use param_refs::*;
pub use parameters::*;
pub use project::*;
pub use static_section::*;
