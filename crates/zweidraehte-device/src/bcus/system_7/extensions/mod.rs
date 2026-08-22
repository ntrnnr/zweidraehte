//! Extensions available to System 7 devices.
//!
//! The TP1 medium extension is shared with System B — the retry-count
//! surface (`PID_MAX_RETRY_COUNT`) is a property of the medium, not of
//! the BCU family — so this module re-exports it rather than defining a
//! twin. The same holds for KNX Data Security, which 06 Profiles
//! v02.02.01 §9.1 defines as a *profile module* composed onto a base
//! profile: the machinery lives in [`crate::security`] and both families
//! name it. IP and RF extensions are System B-only until a System 7
//! device needs them.

pub use crate::bcus::system_b::{Tp1Augment, Tp1ExtensionConfig, Tp1ExtensionState};
pub use crate::security::{
    SecureAugmentBundle, SecureExtensionConfig, SecureExtensionState, SecureResources, SecurityAugment, SecurityConfig,
    SecurityFailuresLog, SecurityState, SecurityTable,
};
