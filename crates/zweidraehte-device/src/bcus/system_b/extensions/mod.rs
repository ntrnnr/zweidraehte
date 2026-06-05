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

pub mod operation_mode;
pub use operation_mode::{DiagnosticsAugment, DiagnosticsContext, HasDiagnosticsContext, OperationModeState};

pub mod security;
pub use security::{
    HasSecurityState, HasSeqStorage, SecureExtensionConfig, SecureExtensionState, SecureResources, SecureRfDeviceState,
    SecureRfExtensionState, SecureTp1DeviceState, SecureTp1ExtensionState, SecurityAugment, SecurityExtensionConfig,
    SecurityFailureType, SecurityFailuresLog, SecurityState, SecurityTable,
};
#[cfg(feature = "knxip")]
pub use security::{SecureIpDeviceState, SecureIpExtensionState};
