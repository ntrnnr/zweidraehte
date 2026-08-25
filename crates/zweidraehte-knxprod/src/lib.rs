//! KNX Product Definition Generator
//!
//! This crate provides the core functionality for generating KNX product definition files
//! (MTXML format) from Rust device definitions. It includes:
//!
//! - **Generator** - Builds ApplicationProgram, Hardware, and Catalog XML from device definitions
//! - **Builder** - Unified workflow for generating MTXML and .knxprod packages
//! - **Definition DSL** - Declarative macros for defining device structure and ETS pages
//!
//! ETS schema, parsing, archive, project, keyring, and signing APIs live in
//! `zweidraehte-ets-files`.
//!
//! # Overview
//!
//! This crate is designed to be used alongside the `zweidraehte` stack crate and `ets-macros`
//! proc-macro crate. The typical workflow is:
//!
//! 1. Define device parameters using `#[ets_params]` and `#[ets_union]`
//! 2. Define communication objects using `#[derive(EtsComObjects)]`
//! 3. Implement `EtsPageLayout` using the `ets_pages!` macro
//! 4. Use `KnxprodBuilder` to generate all files and optionally create .knxprod packages
//!
//! # Quick Start with KnxprodBuilder
//!
//! ```rust,ignore
//! use zweidraehte_knxprod::{KnxprodBuilder, ApplicationProgramDef, SingleDeviceDef};
//! use zweidraehte_ets_files::signing::{KnxSchemaVersion, MasterDataSource};
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
//! .converter_key_file("converter_key.xml")
//! .build_all()?;
//! ```
//!
//! # Modules
//!
//! - [`definition`] - Device definition DSL (modules, page layouts)

// ============================================================================
// Submodules
// ============================================================================

mod generator;

/// Device definition DSL for creating KNX devices in Rust.
///
/// Contains:
/// - [`definition::module`] - Reusable module definitions (`KnxModule`, `ModuleCollection`)
/// - [`definition::page_layout`] - ETS page structure (`EtsPageLayout`, `ets_pages!` macro)
pub mod definition;

// ============================================================================
// Primary API - Re-exports at crate root
// ============================================================================

// Generators - main API for creating MTXML
pub use generator::{
    AppProgramRef, ApplicationProgramDef, BaggageGenerator, Bcu2MemoryLayout, BuilderError, BusInterfaceDef,
    CatalogEntryDef, CatalogGenerator, CatalogSectionDef, GeneratorError, HardwareDef, HardwareGenerator, HardwareRef,
    KnxprodBuilder, KnxprodOutput, MtxmlGenerator, ProductDef, RfRxCapabilities, RfTxCapabilities, SingleDeviceDef,
    System7MemoryLayout, System7Segment,
};
pub use zweidraehte_ets_files::schema::BusAccessType;

// Baggage helper utilities (commonly used directly)
pub use generator::baggage::{baggages_to_refs, encode_baggage_filename, make_baggage_id, make_baggage_id_with_path};

// ============================================================================
// Macro support
// ============================================================================

/// Re-export paste for use by macros (internal use only)
#[doc(hidden)]
pub use paste;

/// Re-export zerocopy for use by macros (internal use only).
///
/// `define_module!` derives [`zerocopy::IntoBytes`] on the params struct it
/// generates, so downstream crates get the no-padding guarantee without having
/// to depend on zerocopy themselves.
#[doc(hidden)]
pub use zerocopy;
