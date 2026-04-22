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

mod state;
pub use state::{HasAuthorization, HasPersistence, HasSecureIdentity, ReadObjectError, StackState, UpdateObjectError};

pub mod actor;

mod definition;
pub use definition::StackDefinition;

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

// Device-specific modules
pub mod access_policy;
pub mod bcus;
pub mod config;
pub mod context;
pub mod device_model;
pub mod ets;
pub mod layers;
pub mod memory;
pub mod objects;
pub mod prelude;
pub mod restart;
pub mod router;
pub mod storage;
