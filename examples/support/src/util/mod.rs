//! Shared Utilities
//!
//! Common helper modules used across the example demos and tools.

pub mod evdev_button;
pub mod keyboard;
pub mod mock_context;
pub mod rng;

// Re-export commonly used items
pub use evdev_button::{
    EvdevButton, EvdevButtonId, EvdevChannels, open_keyboard, spawn_evdev_reader, terminal_key_to_button,
};
pub use keyboard::poll_key;
pub use mock_context::MockContext;
pub use rng::GetrandomRng;
