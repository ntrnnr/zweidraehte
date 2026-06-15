//! Flash-backed [`KeyValueStore`] implementations and the `FlashIo` seam.
//!
//! The [`KeyValueStore`] trait itself lives in the core crate
//! (`zweidraehte_device::kvstore`) so the HAL-agnostic typed views (`SiatStore`)
//! can use it without depending on this crate. Here we provide two backends over
//! the [`FlashIo`] seam, both implementing that same trait so a typed view is
//! agnostic to which it gets:
//!
//! - [`WearLeveledKv`] — circular append-log; cheap per-record writes; for hot
//!   data like the SIAT and the sequence counters.
//! - [`VerbatimKv`] — single erase-rewrite region; whole-region rewrite per
//!   write; for rarely-written tables/objects. Implements the *same*
//!   `KeyValueStore` interface, so wear-levelling is an orthogonal,
//!   construction-time choice.
//!
//! Key/value widths are bounded so the wear-levelled slot stays a fixed 12 bytes
//! (no_alloc). The current bounds cover the SIAT (key = IA, 2 bytes; value =
//! SeqNr, 6 bytes) and the singleton counters (1-byte key).

pub use zweidraehte_device::kvstore::KeyValueStore;

/// Maximum key width across all namespaces (IA = 2 bytes).
pub const MAX_KEY: usize = 2;
/// Maximum value width across all namespaces (SeqNr = 6 bytes).
pub const MAX_VAL: usize = 6;

mod flash_io;
mod ram;
mod verbatim;
mod wear_leveled;

#[cfg(test)]
mod tests;

pub use flash_io::FlashIo;
pub use ram::RamKv;
pub use verbatim::VerbatimKv;
pub use wear_leveled::WearLeveledKv;
