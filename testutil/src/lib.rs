//! Test Utilities for the KNX Stack
//!
//! This crate provides test utilities, device definitions, and helper modules
//! for testing and debugging KNX stack implementations.
//!
//! # Modules
//!
//! - [`devices`] - Device definitions (parameters, comm objects, descriptors)
//! - [`storage`] - Device state persistence backends
//! - [`util`] - Shared utilities (keyboard input, etc.)
//! - [`mtxml_gen`] - MTXML generation from Rust device definitions
//! - [`equivalence`] - Application program equivalence testing
//!
//! # Binaries
//!
//! This crate also provides several useful binaries:
//!
//! - `stack_system_b` - Run a System B device demo
//! - `stack_knxip` - Run a full KNX/IP stack
//! - `gen_mtxml` - Generate MTXML files from device definitions
//! - `compare_programs` - Compare two application programs for equivalence
//! - `busmon` - TPUART bus monitor
//! - And more...
//!
//! Run `cargo run --bin <name> -- --help` for usage information.

#![feature(adt_const_params)]

// Core modules
pub mod devices;
pub mod storage;
pub mod util;
pub mod mtxml_gen;
pub mod equivalence;

// Re-export commonly used items for convenience
pub use devices::{DEVICE_DESCRIPTOR, DemoParams, comm_objs};
pub use storage::JsonStorage;
pub use util::poll_key;
