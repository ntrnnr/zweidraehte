//! MTXML Generator - Generate KNX Manufacturing Tool XML files from Rust device definitions.
//!
//! This module generates complete ApplicationProgram MTXML files from scratch,
//! using typed Rust structs derived from the KNX Project XSD schema.
//!
//! Unlike the `mtxml` modifier which patches existing files, this generator
//! creates valid MTXML from device definitions alone.
//!
//! # Usage
//!
//! ```rust,ignore
//! use testutil::mtxml_gen::{MtxmlGenerator, ApplicationProgramConfig};
//!
//! let config = ApplicationProgramConfig {
//!     name: "MyDevice",
//!     device: &DEVICE_DESCRIPTOR,
//!     params: DemoParams::ETS_PARAMS_EXT,
//!     params_defaults: &DemoParams::DEFAULT.to_bytes(),
//!     comm_objects: &comm_objs::ETS_COMM_OBJECTS,
//!     union_fields: Some(DemoParams::ETS_UNIONS),
//! };
//!
//! let xml = MtxmlGenerator::generate(&config)?;
//! std::fs::write("ApplicationProgram1.mtxml", xml)?;
//! ```

mod schema;
mod generator;
pub mod page_layout;

pub use schema::*;
pub use generator::*;
pub use page_layout::{
    EtsPageLayout, PageStructure, ChannelDef, PageElement, PageBlock, PageItem,
    ConditionalElement, ElementCase, ConditionalItem, ItemCase, Condition,
};
