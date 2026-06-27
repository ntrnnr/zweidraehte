//! Flash-backed [`KeyValueStore`] implementation and the `FlashIo` seam.
//!
//! The [`KeyValueStore`] trait itself lives in the core crate
//! (`zweidraehte_device::kvstore`) so the HAL-agnostic typed views (`SiatStore`)
//! can use it without depending on this crate. Here we provide the flash backend
//! over the [`FlashIo`] seam:
//!
//! - [`WearLeveledKv`] — circular append-log; cheap per-record writes; for hot
//!   data like the SIAT and the sequence counters.
//!
//! The ETS-programmed device configuration is a separate concern, persisted as a
//! single blob by [`ConfigStore`] over the same `FlashIo` seam (it is not a
//! `KeyValueStore`).
//!
//! Key/value widths are bounded so the wear-levelled slot stays a fixed 12 bytes
//! (no_alloc). The current bounds cover the SIAT (key = IA, 2 bytes; value =
//! SeqNr, 6 bytes) and the singleton counters (1-byte key).

pub use zweidraehte_device::kvstore::KeyValueStore;

/// Maximum key width across all namespaces (IA = 2 bytes).
pub const MAX_KEY: usize = 2;
/// Maximum value width across all namespaces (SeqNr = 6 bytes).
pub const MAX_VAL: usize = 6;

mod config_store;
mod flash_io;
mod mirror;
mod wear_leveled;

#[cfg(test)]
mod tests;

pub use config_store::{ConfigStore, ConfigStoreError};
pub use flash_io::FlashIo;
pub use wear_leveled::WearLeveledKv;
