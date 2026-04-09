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

#[macro_use]
extern crate zweidraehte_util;
#[macro_use]
extern crate zweidraehte_proto;

// Re-export protocol types from proto so downstream can use zweidraehte_device::address etc.
pub use zweidraehte_proto::access;
pub use zweidraehte_proto::address;
pub use zweidraehte_proto::crypto;
pub use zweidraehte_proto::device;
pub use zweidraehte_proto::dpt;
pub use zweidraehte_proto::encoding;
pub use zweidraehte_proto::messages;
pub use zweidraehte_proto::properties;
pub use zweidraehte_proto::util;
pub use zweidraehte_proto::{
    AccessContext, AccessSource, ConnectionAuthLevels, HasConnectionAuth, MAX_ACCESS_LEVELS, NUM_AUTH_KEYS,
};

mod state;
pub use state::{HasAuthorization, HasPersistence, HasSecureIdentity, ReadObjectError, StackState, UpdateObjectError};

pub mod actor;

mod definition;
pub use definition::StackDefinition;

#[cfg(feature = "knxip")]
mod ip;
#[cfg(feature = "knxip")]
pub use ip::{DEFAULT_MULTICAST_ADDR, IpConfig, IpPlatform, IpPlatformConfig, IpPlatformState, IpStackState, KNX_PORT};

mod composition;
pub use composition::{
    InsecureDeviceBuilder, InsecureDeviceLayers, LayerContext, LayerStackBuilder, SecureDeviceBuilder,
    SecureDeviceLayers, StandardDeviceLayers, StandardSecureDeviceLayers,
};
#[cfg(feature = "knxip")]
pub use composition::{InsecureIpDeviceBuilder, IpDeviceLayers};

pub(crate) mod inner;
pub use inner::StackContext;

mod resources;
pub use resources::StackResources;

mod runner;
pub use runner::{Runner, new};

mod stack_handle;
pub use stack_handle::Stack;

pub use zweidraehte_proto::error;

pub(crate) mod logging;

// Device-specific modules
pub mod access_policy;
pub mod bcus;
pub mod config;
pub mod context;
pub mod device_model;
pub mod layer_context;
pub mod ets;
pub mod layers;
pub mod memory;
pub mod objects;
pub mod prelude;
pub mod restart;
pub mod router;
pub mod storage;
