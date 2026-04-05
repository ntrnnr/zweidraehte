//! Extension state modules for System B devices.
//!
//! Each extension type bundles its persistent config, runtime state,
//! `ExtensionState` impl, and `InterfaceObjectAugment` impl in one module.
//!
//! - [`tp1`] — TP1 retry count (PID 52) extension + augment
//! - [`ip`] — KNX/IP configuration + IP Parameter Object augment

mod tp1;
pub use tp1::*;

#[cfg(feature = "knxip")]
mod ip;
#[cfg(feature = "knxip")]
pub use ip::*;

pub mod security;
pub use security::{
    HasSecurityState, HasSeqStorage, SecureExtensionConfig, SecureExtensionState, SecureTp1DeviceState,
    SecureTp1ExtensionState, SecurityAugment, SecurityExtensionConfig, SecurityFailureType, SecurityFailuresLog,
    SecurityState, SecurityTable,
};
#[cfg(feature = "knxip")]
pub use security::{SecureIpDeviceState, SecureIpExtensionState};
