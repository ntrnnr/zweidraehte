//! MTXML Generator - Generate KNX Manufacturing Tool XML files from Rust device definitions.
//!
//! This module re-exports the `knxprod` crate which provides the core MTXML generation
//! functionality. For documentation and usage, see the `knxprod` crate.
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

// Re-export everything from knxprod
pub use knxprod::*;
pub use knxprod::page_layout;

// Re-export the ets_pages macro
pub use knxprod::ets_pages;
