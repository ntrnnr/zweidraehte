//! KNX Product Definition Generator
//!
//! This crate provides the core functionality for generating KNX product definition files
//! (MTXML format) from Rust device definitions. It includes:
//!
//! - **Schema types** - Typed Rust structs matching the KNX project XSD schema
//! - **Generator** - Builds ApplicationProgram, Hardware, and Catalog XML from device definitions
//! - **Page layout DSL** - Declarative macro for defining ETS parameter page structure
//!
//! # Overview
//!
//! This crate is designed to be used alongside the `zweidraehte` stack crate and `ets-macros`
//! proc-macro crate. The typical workflow is:
//!
//! 1. Define device parameters using `#[derive(EtsParams)]` and `#[derive(EtsUnion)]`
//! 2. Define communication objects using `#[derive(EtsComObjects)]`
//! 3. Implement `EtsPageLayout` using the `ets_pages!` macro
//! 4. Use `MtxmlGenerator`, `HardwareGenerator`, and `CatalogGenerator` to produce XML
//!
//! # Example
//!
//! ```rust,ignore
//! use knxprod::{MtxmlGenerator, HardwareGenerator, CatalogGenerator, ApplicationProgramConfig};
//! use knxprod::page_layout::EtsPageLayout;
//!
//! let config = ApplicationProgramConfig {
//!     name: "MyDevice",
//!     device: &DEVICE_DESCRIPTOR,
//!     params: MyParams::ETS_PARAMS_EXT,
//!     param_defaults: &param_bytes,
//!     comm_objects: &comm_objs::ETS_COMM_OBJECTS,
//!     comm_object_refs: &comm_objs::ETS_COMM_OBJECT_REFS,
//!     union_fields: Some(MyParams::ETS_UNIONS),
//!     // ... other config
//!     page_layout: Some(MyDevice::page_layout()),
//! };
//!
//! let app_xml = MtxmlGenerator::generate(&config)?;
//! let hw_xml = HardwareGenerator::generate(&config)?;
//! let cat_xml = CatalogGenerator::generate(&config)?;
//! ```
//!
//! # Modules
//!
//! - [`schema`] - XML schema types for serialization
//! - [`generator`] - MTXML generation engine
//! - [`definition`] - Device definition DSL (modules, page layouts)
//! - [`runtime`] - Parsing and runtime support for MTXML files

// Core modules
mod generator;
mod schema;
pub mod signing;

// Definition DSL (for creating devices in Rust)
pub mod definition;

// Runtime support (for parsing and working with MTXML)
pub mod runtime;

// Re-export definition types at crate root for convenience
pub use definition::module::{
    ConditionalModuleInstance, KnxModule, ModuleArgDef, ModuleArgRole, ModuleArgType,
    ModuleArgValue, ModuleCollection, ModuleInstance, ModuleInstanceBuilder, StoredModuleDef,
    StoredModuleInstance,
};
pub use definition::page_layout::{
    ChannelDef, Condition, ConditionalElement, ConditionalItem, ElementCase, EtsPageLayout,
    ItemCase, PageBlock, PageElement, PageItem, PageStructure,
};

// Re-export runtime types at crate root for convenience
pub use runtime::device::Device;
pub use runtime::model::{
    ConditionEvaluator, DynamicVisitor, VisibilityVisitor, VisitorModuleContext, walk_dynamic,
};

// Re-export generator types
pub use generator::*;

// Re-export schema types
pub use schema::*;

// Legacy module aliases for backwards compatibility
pub mod baggage {
    //! Baggage file loading utilities (re-exported from [`crate::runtime::baggage`])
    pub use crate::runtime::baggage::*;
}
pub mod device {
    //! Device runtime state (re-exported from [`crate::runtime::device`])
    pub use crate::runtime::device::*;
}
pub mod device_info {
    //! Device programming information (re-exported from [`crate::runtime::device_info`])
    pub use crate::runtime::device_info::*;
}
pub mod master_data {
    //! KNX master data parsing (re-exported from [`crate::runtime::master_data`])
    pub use crate::runtime::master_data::*;
}
pub mod model {
    //! Runtime model and visitor pattern (re-exported from [`crate::runtime::model`])
    pub use crate::runtime::model::*;
}
pub mod module {
    //! Module definition DSL (re-exported from [`crate::definition::module`])
    pub use crate::definition::module::*;
}
pub mod page_layout {
    //! Page layout DSL (re-exported from [`crate::definition::page_layout`])
    pub use crate::definition::page_layout::*;
}
pub mod parser {
    //! XML parsing (re-exported from [`crate::runtime::parser`])
    pub use crate::runtime::parser::*;
}

// Re-export baggage generation utilities
pub use generator::baggage::{
    baggages_to_refs, encode_baggage_filename, generate_baggages_xml,
    get_baggage_files_for_signing, make_baggage_id, make_baggage_id_with_path,
    write_baggage_files,
};

// Re-export paste for use by macros
#[doc(hidden)]
pub use paste;
