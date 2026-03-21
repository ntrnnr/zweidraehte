#![cfg_attr(not(test), no_std)]
#![feature(const_trait_impl)]
#![feature(const_convert)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![feature(type_alias_impl_trait)]
#![feature(never_type)]
#![feature(associated_type_defaults)]

#[cfg(feature = "alloc")]
extern crate alloc;

// Re-export paste for use in macros
#[doc(hidden)]
pub use paste;

mod fmt;

#[macro_use]
mod macros;

pub mod access;
pub use access::{
    AccessContext, AccessSource, ConnectionAuthLevels, HasConnectionAuth,
    MAX_ACCESS_LEVELS, NUM_AUTH_KEYS,
};

pub mod address;
pub mod config;
pub mod device;
pub mod dpt;
pub mod encoding;
pub mod messages;
pub mod error;
pub mod properties;
pub mod util;
