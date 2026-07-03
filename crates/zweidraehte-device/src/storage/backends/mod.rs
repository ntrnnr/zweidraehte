//! Medium-agnostic persistent-storage backends over the medium seams.
//!
//! These backends are HAL-free: they speak only the [`SectorIo`] / [`ByteIo`]
//! seams and integer arithmetic, so the HAL adapters that drive real media
//! (`RpFlashIo`, `StmFlashIo`, `FramRegion` in the `cross/` workspace) plug in
//! from outside. Four backends sit here:
//!
//! - [`WearLeveledKv`] — circular append-log over [`SectorIo`]; cheap
//!   per-record writes; for hot data like the SIAT and sequence counters.
//! - [`ConfigStore`] — a single postcard blob (magic + length + payload) over
//!   [`SectorIo`] for the ETS-programmed device configuration. Erase+rewrite,
//!   not a [`KeyValueStore`](crate::storage::kv::KeyValueStore) — config
//!   writes are rare.
//! - [`PackedSeqStore`] — the fixed packed sequence-state layout over
//!   [`ByteIo`] (FRAM, shared memory); write-in-place, no erase.
//! - [`PackedWatermark`] — the byte-medium mc_timer watermark record; the
//!   write-in-place sibling of the wear-levelled mc_timer log.
//!
//! All take their region placement as runtime constructor args — the storage
//! layer's auto-packing derives each offset from the declared region sizes.
//!
//! Key/value widths are bounded so the wear-levelled slot stays a fixed 12 bytes
//! (no_alloc). The current bounds cover the SIAT (key = IA, 2 bytes; value =
//! SeqNr, 6 bytes) and the singleton counters (1-byte key).

use crate::storage::kv::KeyValueStore;

/// Maximum key width across all namespaces (IA = 2 bytes).
pub const MAX_KEY: usize = 2;
/// Maximum value width across all namespaces (SeqNr = 6 bytes).
pub const MAX_VAL: usize = 6;

mod byte_io;
mod config_store;
mod mirror;
mod packed_watermark;
mod sector_io;
mod wear_leveled;

pub mod packed_seq;

#[cfg(test)]
mod tests;

pub use byte_io::ByteIo;
pub use config_store::{ConfigStore, ConfigStoreError};
pub use packed_seq::{PackedSeqStore, region_len};
pub use packed_watermark::PackedWatermark;
pub use sector_io::SectorIo;
pub use wear_leveled::WearLeveledKv;
