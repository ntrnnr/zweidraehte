#![cfg_attr(not(test), no_std)]
#![feature(const_trait_impl)]
#![feature(const_convert)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![feature(never_type)]
#![feature(associated_type_defaults)]

// Re-export paste for use in macros
#[doc(hidden)]
pub use paste;

// Make `::zweidraehte_device::…` resolvable from within this crate so that
// proc-macros (e.g. `#[interface_object(...)]`) can emit absolute paths
// without caring whether they're invoked inside or outside the crate.
extern crate self as zweidraehte_device;

#[macro_use]
extern crate zweidraehte_util;
#[macro_use]
extern crate zweidraehte_proto;

mod state;
pub use state::{HasAuthorization, HasPersistence, ReadObjectError, StackState, UpdateObjectError};

pub mod actor;

mod definition;
pub use definition::StackDefinition;

pub mod rng;
pub use rng::{NoRng, Rng, SecureRng};

#[cfg(feature = "knxip")]
mod ip;
#[cfg(feature = "knxip")]
pub use ip::{
    DEFAULT_MULTICAST_ADDR, HasRoutingMulticastRebind, IpConfig, IpPlatform, IpPlatformConfig, IpPlatformState,
    IpStackState, KNX_PORT, SYSTEM_SETUP_MULTICAST_ADDRESS,
};

mod composition;
pub use composition::{
    InsecureDeviceBuilder, LayerStackBuilder, SecureDeviceBuilder, StandardDeviceLayers, StandardLayerStack,
    StandardSecureDeviceLayers,
};
#[cfg(feature = "knxip")]
pub use composition::{InsecureIpDeviceBuilder, IpDeviceLayers, IpLayerStack};

pub(crate) mod inner;

mod resources;
pub use resources::StackResources;

mod runner;
pub use runner::{Runner, new};

mod stack_handle;
pub use stack_handle::Stack;

pub(crate) mod logging;

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
pub mod layers;
pub mod lifecycle;
pub mod memory;
pub mod objects;
pub mod prelude;
pub mod restart;
pub mod router;
pub mod service;
pub mod storage;
