//! Shared Utilities
//!
//! Common helper modules used across the testutil crate.

pub mod keyboard;

// Re-export commonly used items
pub use keyboard::poll_key;
