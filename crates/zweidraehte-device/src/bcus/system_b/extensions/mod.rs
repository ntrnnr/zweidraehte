//! Extension state modules for System B devices.
//!
//! Each extension type bundles its persistent config, runtime state,
//! `ExtensionState` impl, and `Augment<D>` impl in one module.
//!
//! - [`tp1`] — TP1 retry count (PID 52) extension + augment
//! - [`ip`] — KNX/IP configuration + IP Parameter Object augment
//! - [`rf`] — KNX-RF Domain Address + RF Medium Object (Type 19) augment

mod tp1;
pub use tp1::*;

mod rf;
pub use rf::*;

#[cfg(feature = "knxip")]
mod ip;
#[cfg(feature = "knxip")]
pub use ip::*;

// GO Diagnostics is a profile module of its own (06 Profiles
// v02.02.01 §9.2, "functionality with can be added to any KNX Profile
// that supports Group Objects"), so it lives at the crate root. Kept
// re-exported here because every existing device names it through
// `bcus::system_b`.
pub use crate::diagnostics::{
    DiagnosticsAugment, GroupObjectTableAugment, NoSecureGoSend, OperationModeState, SecureGoSender, SecureSendOutcome,
    WithSecureGoSend,
};

pub mod security;
pub use security::{
    SecureAugmentBundle, SecureExtensionConfig, SecureExtensionState, SecureResources, SecureRfExtensionState,
    SecureRfRetransmitterExtensionState, SecureTp1DeviceState, SecureTp1ExtensionState, SecurityAugment,
    SecurityConfig, SecurityFailuresLog, SecurityState, SecurityTable,
};
