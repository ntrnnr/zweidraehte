#![cfg_attr(not(test), no_std)]
#![feature(const_trait_impl)]
#![feature(const_convert)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![feature(type_alias_impl_trait)]
#![feature(never_type)]
#![feature(associated_type_defaults)]

// Re-export paste for use in macros
#[doc(hidden)]
pub use paste;

mod fmt;

#[macro_use]
mod macros;

mod access;
pub use access::{
    AccessContext, AccessSource, ConnectionAuthLevels, HasConnectionAuth,
    MAX_ACCESS_LEVELS, NUM_AUTH_KEYS,
};

mod state;
pub use state::{ReadObjectError, StackState, UpdateObjectError};

pub mod actor;

mod definition;
pub use definition::StackDefinition;

#[cfg(feature = "knxip")]
mod ip;
#[cfg(feature = "knxip")]
pub use ip::{
    DEFAULT_MULTICAST_ADDR, IpConfig, IpDevice, IpPlatform, IpPlatformConfig, IpStackState,
    KNX_PORT,
};

mod composition;
pub use composition::{
    InsecureDeviceBuilder, InsecureDeviceLayers, LayerContext, LayerStackBuilder,
    StandardDeviceLayers,
};
#[cfg(feature = "knxip")]
pub use composition::{InsecureIpDeviceBuilder, IpDeviceLayers};

pub(crate) mod inner;
pub use inner::StackContext;

mod resources;
pub use resources::StackResources;

mod runner;
pub use runner::{new, Runner};

mod stack_handle;
pub use stack_handle::Stack;

// Existing public modules
pub mod access_policy;
pub mod address;
pub mod bcus;
pub mod config;
pub mod context;
pub mod dpt;
pub mod encoding;
pub mod error;
pub mod ets;
pub mod layers;
pub mod memory;
pub mod messages;
pub mod objects;
pub mod prelude;
pub mod restart;
pub mod router;
pub mod storage;
pub mod util;
