#![cfg_attr(not(test), no_std)]
#![feature(const_trait_impl)]
#![feature(const_convert)]
#![feature(generic_const_exprs)]
#![feature(never_type)]
#![feature(associated_type_defaults)]
// generic_const_exprs is deliberate and load-bearing (const-generic buffer
// sizing); the nightly toolchain is pinned with it in mind, so the blanket
// "incomplete feature" lint is pure noise here.
#![allow(incomplete_features)]

// Re-export paste for use in macros
#[doc(hidden)]
pub use paste;

// Make `::zweidraehte_device::…` resolvable from within this crate so that
// proc-macros (e.g. `#[interface_object(...)]`) can emit absolute paths
// without caring whether they're invoked inside or outside the crate.
extern crate self as zweidraehte_device;

#[macro_use]
extern crate zweidraehte_util;
extern crate zweidraehte_proto;

// `forward_to_field!` is used by both device-state families and by the
// family-neutral wrapper extensions, so it is declared here — textual
// macro scoping makes it visible to every module declared after this one.
#[macro_use]
mod forward;

mod state;
pub use state::{
    DiagnosticsView, HasAuthorization, HasDiagnosticsContext, HasExtensionState, HasPersistence, HasSecurityMode,
    ReadObjectError, StackState, UpdateObjectError,
};

pub mod actor;

mod definition;
pub use definition::{NoParams, StackDefinition};

pub mod rng;
pub use rng::{NoRng, Rng, SecureRng};

#[cfg(feature = "knxip")]
mod ip;
#[cfg(feature = "knxip")]
pub use ip::{
    DEFAULT_MULTICAST_ADDR, HasAdditionalIas, HasIpExtensionState, HasIpSecureView, HasRoutingMulticastRebind,
    IpConfig, IpPlatform, IpPlatformConfig, IpSecureStateView, IpStateView, KNX_PORT, SYSTEM_SETUP_MULTICAST_ADDRESS,
};

mod composition;
#[cfg(feature = "knxip")]
pub use composition::{
    IpDeviceLayers, IpLayerStack, PlainIpDeviceBuilder, SecureIpDeviceBuilder, SecureIpDeviceLayers,
};
pub use composition::{
    LayerStackBuilder, PlainDeviceBuilder, SecureDeviceBuilder, StandardDeviceLayers, StandardLayerStack,
    StandardSecureDeviceLayers,
};

pub(crate) mod stack_core;

mod resources;
pub use resources::StackResources;

mod runner;
pub use runner::{Runner, new};

mod stack_handle;
pub use stack_handle::{Stack, SyncError, SyncOptions};

#[doc(hidden)]
pub mod logging;

/// Macro-support re-exports for `#[derive(...)]` users.
///
/// Proc macros emitted by this crate's sibling
/// `zweidraehte-device-macros` need to reach types from
/// `zweidraehte-proto` (e.g. `KnxMessageBuffer`, `InterfaceObjectType`).
/// Downstream binaries don't always have `zweidraehte-proto` as a
/// direct dependency, so the macros route through this module
/// instead.
///
/// Don't depend on the contents directly — they are not part of the
/// public API and may change without notice.
#[doc(hidden)]
pub mod __macro_support {
    pub use ::embassy_futures;
    pub use ::zweidraehte_proto::{access, dpt, messages, properties};
}

// Device-specific modules
pub mod access_policy;
pub mod bcus;
pub mod config;
pub mod context;
pub mod device_model;
pub mod ets;
pub mod extension;
pub mod layers;
pub mod lifecycle;
pub mod memory;
pub mod objects;
pub mod persist;
pub mod prelude;
pub mod provisioning;
pub mod restart;
pub mod router;
pub mod security;
pub mod service;
pub mod storage;
