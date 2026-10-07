#![no_std]

//! STM32-specific shared code for KNX devices.
//!
//! - `uart` — direct-register USART driver that decouples TPUART byte
//!   arrival from task-level latency, critical for meeting the
//!   NCN5120/TPUART ACK window.
//! - `storage` — the write-through config log and device identity in
//!   internal flash, with the KNX serial number derived from the STM32's
//!   factory-programmed UID. Plain and Data Secure identity record
//!   shapes are both supported.
//! - `ecc` — the NMI handler (installed by `storage_platform!`) that survives
//!   flash ECC errors in a log torn by power loss.
//! - `fram_seq` — the `Fram` chip descriptor and `FramChip` `ByteIo`
//!   handle over the shared `fm25l16b` driver's FRAM regions. Suitable
//!   for production: write-through on every update, unlimited endurance.
//! - `rng` — `Stm32CommonRng`, a *non-cryptographic* PRNG seeded
//!   from the STM32 factory UID plus boot-time ticks. Plugs into
//!   [`StackDefinition::Rng`][sd] on secure firmware.
//!
//! HAL-agnostic helpers (`DebouncedButton`, `CortexMSystem`) live in
//! `embedded-common` and are imported from there directly at every
//! call site.
//!
//! [sd]: zweidraehte_device::StackDefinition::Rng

pub mod ecc;
pub mod flash_io;
pub mod fram_seq;
pub mod prov_storage;
pub mod rng;
pub mod storage;
#[cfg(feature = "rf")]
pub mod sx1211_adapter;
pub mod uart;

pub use flash_io::StmFlashIo;
pub use fm25l16b::{CAPACITY as FRAM_CAPACITY, Fm25l16b, FramError};
pub use fram_seq::{FramChip, StmFramCs, StmFramSpi};
pub use prov_storage::{identity_from_record, load_plain_identity, load_secure_identity, secure_identity_from_record};
pub use rng::Stm32CommonRng;
pub use storage::{
    BANK2_OFFSET, ConfigLog, FLASH_SIZE, FlashIdentityData, FlashSecureIdentityData, Fram, FramSeqStore, InternalFlash,
    PAGE_SIZE, PROVISIONING_PAGE, log_config_flash_diagnostics,
};
