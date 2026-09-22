//! Utilities shared by KNX crates.
//!
//! The optional `secrets` feature adds zeroizing owned bytes using `alloc`.
//! Default builds require neither allocation nor cryptographic dependencies.

#![cfg_attr(not(test), no_std)]

#[cfg(feature = "secrets")]
extern crate alloc;

pub mod fmt;
pub mod input;
#[cfg(feature = "secrets")]
pub mod secret;
