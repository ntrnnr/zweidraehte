#![no_std]

//! Small raw-register helpers for secure polling STM32G0 targets.
//!
//! This deliberately does not depend on embassy. Plain micro firmware does
//! not depend on this crate at all; secure firmware gets one shared ADC
//! entropy source and the FM25L16B medium under the shared
//! `zweidraehte_nv::PackedSeqStore` sequence layout.

mod entropy;
mod fram_store;

pub use entropy::seed_csprng;
pub use fram_store::FramStore;
