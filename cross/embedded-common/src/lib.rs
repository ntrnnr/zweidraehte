#![no_std]
#![feature(never_type)]

//! HAL-agnostic helpers shared across all embedded KNX targets.
//!
//! Anything that doesn't depend on a specific embassy HAL (embassy-rp,
//! embassy-stm32, ...) lives here so new embedded targets can reuse
//! it without duplication.

#[cfg(feature = "tp1")]
pub mod busy_guard;
pub mod button;
pub mod persist;
pub mod system;

#[cfg(feature = "tp1")]
pub use busy_guard::{BusyGate, BusyGuard};
pub use button::DebouncedButton;
pub use system::{CortexMSystem, SystemError};
