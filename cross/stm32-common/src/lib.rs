#![no_std]

//! STM32-specific shared code for KNX devices.
//!
//! - `uart` — direct-register USART driver that decouples TPUART byte
//!   arrival from task-level latency, critical for meeting the
//!   NCN5120/TPUART ACK window.
//! - `storage` — persistent device state and identity in internal
//!   flash, with the KNX serial number derived from the STM32's
//!   factory-programmed UID. Plain and Data Secure identity record
//!   shapes are both supported.
//! - `ram_seq` — `RamSeqStorage`, a RAM-only implementation of the
//!   KNX Data Secure `SequenceNumberStorage` trait. Loses state on
//!   reboot — bring-up only.
//! - `fram` — `Fm25l16b` blocking driver for the Infineon FM25L16B
//!   2 KiB SPI FRAM.
//! - `fram_seq` — `FramKv`, a persistent
//!   `SequenceNumberStorage` backed by the FRAM driver. Suitable for
//!   production: write-through on every update, unlimited endurance.
//! - `rng` — `Stm32CommonRng`, a *non-cryptographic* PRNG seeded
//!   from the STM32 factory UID plus boot-time ticks. Plugs into
//!   [`StackDefinition::Rng`][sd] on secure firmware.
//!
//! HAL-agnostic helpers (`DebouncedButton`, `CortexMSystem`) live in
//! `embedded-common` and are imported from there directly at every
//! call site.
//!
//! [sd]: zweidraehte_device::StackDefinition::Rng

pub mod fram;
pub mod fram_seq;
pub mod prov_storage;
pub mod ram_seq;
pub mod rng;
pub mod storage;
#[cfg(feature = "rf")]
pub mod sx1211_adapter;
pub mod uart;

pub use fram::{CAPACITY as FRAM_CAPACITY, Fm25l16b, FramError};
pub use fram_seq::FramKv;
#[cfg(feature = "provision-on-boot")]
pub use prov_storage::synthesize_and_write;
pub use prov_storage::{identity_from_record, read_provisioning, secure_identity_from_record, write_provisioning};
pub use ram_seq::RamSeqStorage;
pub use rng::Stm32CommonRng;
pub use storage::{FlashError, FlashIdentityData, FlashSecureIdentityData, StmFlashStorage};
