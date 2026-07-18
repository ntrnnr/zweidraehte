//! Shared Support Code for Demos and Host-Side Tools
//!
//! This crate provides host-side (std, Linux) support code shared by the
//! example device demos and the hardware utility tools:
//!
//! - [`storage`] - Device state persistence backends (JSON files)
//! - [`util`] - Shared utilities (keyboard input polling, mock stack context)

pub mod storage;
pub mod util;

// Re-export commonly used items for convenience
pub use storage::{FileIdentity, JsonStorage};
pub use util::poll_key;
