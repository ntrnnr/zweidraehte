//! Test Utilities for the KNX Stack
//!
//! This crate provides test utilities, device definitions, and helper modules
//! for testing and debugging KNX stack implementations.
//!
//! # Modules
//!
//! - [`devices`] - Device definitions (parameters, comm objects, descriptors)
//! - [`mock_platform`] - Shared mock [`IpPlatform`] for KNX/IP demos and tests
//! - [`storage`] - Device state persistence backends
//! - [`util`] - Shared utilities (keyboard input, etc.)
//! - [`equivalence`] - Application program equivalence testing
//!
//! # Binaries
//!
//! This crate also provides several useful binaries:
//!
//! - `stack_system_b` - Run a System B device demo
//! - `gen_mtxml` - Generate MTXML files from device definitions
//! - `compare_programs` - Compare two application programs for equivalence
//! - `busmon` - TPUART bus monitor
//! - And more...
//!
//! Run `cargo run --bin <name> -- --help` for usage information.

#![feature(adt_const_params)]

// Core modules
pub mod devices;
pub mod equivalence;
pub mod mock_platform;
pub mod storage;
pub mod util;

// Re-export commonly used items for convenience
pub use mock_platform::MockIpPlatform;
pub use storage::{FileIdentity, JsonStorage};
pub use util::poll_key;
