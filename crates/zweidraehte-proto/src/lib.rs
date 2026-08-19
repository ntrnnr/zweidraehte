#![cfg_attr(not(test), no_std)]
#![feature(const_trait_impl)]
#![feature(const_convert)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
// generic_const_exprs is deliberate and load-bearing (const-generic buffer
// sizing); the nightly toolchain is pinned with it in mind, so the blanket
// "incomplete feature" lint is pure noise here.
#![allow(incomplete_features)]

#[cfg(feature = "alloc")]
extern crate alloc;

// Re-export paste for use in macros
#[doc(hidden)]
pub use paste;

#[macro_use]
extern crate zweidraehte_util;

#[macro_use]
mod macros;

pub mod access;
pub use access::{
    AccessContext, AccessSource, ConnectionAuthLevels, HasConnectionAuth, MAX_ACCESS_LEVELS, NUM_AUTH_KEYS,
};

pub mod address;
pub mod com_object;
pub mod config;
pub mod crypto;
pub mod device;
pub mod dpt;
pub mod encoding;
pub mod error;
pub mod memory;
pub mod messages;
pub mod pid;
pub mod properties;
pub mod tables;
pub mod transport;
#[cfg(feature = "usb-hid")]
pub mod usb_hid;
pub mod util;
