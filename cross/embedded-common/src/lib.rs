#![no_std]
#![feature(never_type)]

//! HAL-agnostic helpers shared across all embedded KNX targets.
//!
//! Anything that doesn't depend on a specific embassy HAL (embassy-rp,
//! embassy-stm32, ...) lives here so new embedded targets can reuse
//! it without duplication.

pub mod button;
pub mod system;

pub use button::DebouncedButton;
pub use system::{CortexMSystem, SystemError};
