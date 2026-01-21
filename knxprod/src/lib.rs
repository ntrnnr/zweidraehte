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
//! - [`page_layout`] - ETS page layout definition DSL

mod schema;
mod generator;
pub mod page_layout;
pub mod parser;
pub mod model;

pub use schema::*;
pub use generator::*;
pub use page_layout::{
    EtsPageLayout, PageStructure, ChannelDef, PageElement, PageBlock, PageItem,
    ConditionalElement, ElementCase, ConditionalItem, ItemCase, Condition,
};
