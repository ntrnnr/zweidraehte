//! Shared Utilities
//!
//! Common helper modules used across the example demos and tools.

pub mod keyboard;
pub mod mock_context;

// Re-export commonly used items
pub use keyboard::poll_key;
pub use mock_context::MockContext;
