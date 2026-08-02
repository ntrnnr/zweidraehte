//! Medium extensions available to System 7 devices.
//!
//! The TP1 medium extension is shared with System B — the retry-count
//! surface (`PID_MAX_RETRY_COUNT`) is a property of the medium, not of
//! the BCU family — so this module re-exports it rather than defining a
//! twin. IP, RF and security extensions are System B-only until a
//! System 7 profile needs them.

pub use crate::bcus::system_b::{Tp1Augment, Tp1ExtensionConfig, Tp1ExtensionState};
