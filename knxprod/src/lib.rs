//! KNX Product Definition Generator
//!
//! This crate provides the core functionality for generating KNX product definition files
//! (MTXML format) from Rust device definitions. It includes:
//!
//! - **Schema types** - Typed Rust structs matching the KNX project XSD schema
//! - **Generator** - Builds ApplicationProgram, Hardware, and Catalog XML from device definitions
//! - **Builder** - Unified workflow for generating MTXML and .knxprod packages
//! - **Definition DSL** - Declarative macros for defining device structure and ETS pages
//! - **Runtime** - Parsing and working with existing MTXML files
//!
//! # Overview
//!
//! This crate is designed to be used alongside the `zweidraehte` stack crate and `ets-macros`
//! proc-macro crate. The typical workflow is:
//!
//! 1. Define device parameters using `#[derive(EtsParams)]` and `#[derive(EtsUnion)]`
//! 2. Define communication objects using `#[derive(EtsComObjects)]`
//! 3. Implement `EtsPageLayout` using the `ets_pages!` macro
//! 4. Use `KnxprodBuilder` to generate all files and optionally create .knxprod packages
//!
//! # Quick Start with KnxprodBuilder
//!
//! ```rust,ignore
//! use knxprod::{KnxprodBuilder, ApplicationProgramDef, SingleDeviceDef};
//! use knxprod::signing::{KnxSchemaVersion, MasterDataSource};
//!
//! let app = ApplicationProgramDef { /* ... */ };
//!
//! // Generate all MTXML files
//! let output = KnxprodBuilder::single_device(SingleDeviceDef {
//!     app: &app,
//!     serial_number: [0x00, 0xFA, 0x00, 0x00, 0x00, 0x01],
//!     hardware_version: 1,
//!     hardware_name: "My Device",
//!     product_name: "My Device v1",
//!     order_number: "DEV-001",
//!     is_rail_mounted: false,
//!     catalog_section: "My Devices",
//! })
//! .schema_version(KnxSchemaVersion::V20)
//! .generate_all()?;
//!
//! // Or write to disk and create a signed .knxprod package
//! let (output, knxprod_path) = KnxprodBuilder::single_device(SingleDeviceDef {
//!     app: &app,
//!     /* ... same fields ... */
//! })
//! .output_dir("out/MyDevice")
//! .schema_version(KnxSchemaVersion::V20)
//! .master_data(MasterDataSource::Download)
//! .build_all()?;
//! ```
//!
//! # Modules
//!
//! - [`schema`] - XML schema types for serialization (ApplicationProgram, Channel, etc.)
//! - [`definition`] - Device definition DSL (modules, page layouts)
//! - [`runtime`] - Parsing and runtime support for MTXML files
//! - [`signing`] - Package signing utilities

// ============================================================================
// Submodules
// ============================================================================

mod generator;

/// XML schema types matching the KNX project XSD.
///
/// Contains all the types needed for serialization/deserialization of MTXML files:
/// - Root types: `Knx`, `ManufacturerData`, `ApplicationProgram`
/// - Dynamic section: `Channel`, `Choose`, `When`, `ParameterBlock`
/// - Static section: `Code`, `Extension`, `BaggageDef`
/// - Parameters: `Parameter`, `ParameterType`, `ParameterRef`
/// - Communication objects: `ComObject`, `ComObjectRef`
/// - Hardware/Catalog: `Hardware2Programs`, `CatalogSection`
pub mod schema;

/// Package signing utilities for creating .knxprod files.
pub mod signing;

/// Device definition DSL for creating KNX devices in Rust.
///
/// Contains:
/// - [`definition::module`] - Reusable module definitions (`KnxModule`, `ModuleCollection`)
/// - [`definition::page_layout`] - ETS page structure (`EtsPageLayout`, `ets_pages!` macro)
pub mod definition;

/// Runtime support for parsing and working with MTXML files.
///
/// Contains:
/// - [`runtime::parser`] - XML parsing functions
/// - [`runtime::device`] - Unified `Device` struct with runtime state
/// - [`runtime::model`] - Visitor pattern and condition evaluation
/// - [`runtime::baggage`] - Baggage file loading
/// - [`runtime::master_data`] - knx_master.xml parsing
/// - [`runtime::device_info`] - Device programming info extraction
pub mod runtime;

// ============================================================================
// Primary API - Re-exports at crate root
// ============================================================================

// Generators - main API for creating MTXML
pub use generator::{
    AppProgramRef, ApplicationProgramDef, BaggageGenerator, BuilderError,
    CatalogEntryDef, CatalogGenerator, CatalogSectionDef, GeneratorError, HardwareDef, HardwareGenerator,
    HardwareRef, KnxprodBuilder, KnxprodOutput, MtxmlGenerator, ProductDef, SingleDeviceDef,
    System7MemoryLayout, System7Segment,
};

// Parsing - main entry points
pub use runtime::parser::{parse_application_program, parse_application_program_from_file, ParseError};

// Key runtime types
pub use runtime::device::Device;
pub use runtime::master_data::MasterData;

// Baggage helper utilities (commonly used directly)
pub use generator::baggage::{baggages_to_refs, encode_baggage_filename, make_baggage_id, make_baggage_id_with_path};

// ============================================================================
// Macro support
// ============================================================================

/// Re-export paste for use by macros (internal use only)
#[doc(hidden)]
pub use paste;
