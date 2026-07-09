//! Shared Support Code for Demos and Host-Side Tools
//!
//! This crate provides host-side (std, Linux) support code shared by the
//! example device demos and the hardware utility tools:
//!
//! - [`mock_platform`] - Shared mock [`IpPlatform`](zweidraehte_device::prelude::IpPlatform)
//!   for KNX/IP demos and tests
//! - [`storage`] - Device state persistence backends (JSON files)
//! - [`util`] - Shared utilities (keyboard input polling, mock stack context)

pub mod mock_platform;
pub mod storage;
pub mod util;

// Re-export commonly used items for convenience
pub use mock_platform::MockIpPlatform;
pub use storage::{FileIdentity, JsonStorage};
pub use util::poll_key;
