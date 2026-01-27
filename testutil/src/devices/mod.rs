//! Device definitions for test utilities.
//!
//! This module contains complete device definitions that can be used by
//! various tools like:
//! - `stack_system_b` binary (running the device)
//! - `mtxml_modifier` (updating ETS XML files)
//! - Future `knxprod` generator tools

pub mod mdt_push_button_lite;
pub mod module_test_device;
pub mod system_b_demo;

// Re-export the demo device for convenience
pub use system_b_demo::*;
