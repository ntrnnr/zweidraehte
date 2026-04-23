#![no_std]

//! STM32-specific shared code for KNX devices.
//!
//! - `uart` — direct-register USART driver that decouples TPUART byte
//!   arrival from task-level latency, critical for meeting the
//!   NCN5120/TPUART ACK window.
//! - `storage` — persistent device state and identity in internal
//!   flash, with the KNX serial number derived from the STM32's
//!   factory-programmed UID.
//!
//! HAL-agnostic helpers (`DebouncedButton`, `CortexMSystem`) live in
//! `embedded-common` and are imported from there directly at every
//! call site.

pub mod storage;
pub mod uart;

pub use storage::{FlashError, FlashIdentityData, StmFlashStorage, read_or_provision_identity};
