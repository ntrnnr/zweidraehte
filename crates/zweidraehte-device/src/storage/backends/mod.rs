//! Medium-agnostic persistent-storage backends over the medium seams.
//!
//! These backends are HAL-free: they speak only the [`SectorIo`] / [`ByteIo`]
//! seams and integer arithmetic, so the HAL adapters that drive real media
//! (`RpFlashIo`, `StmFlashIo`, `FramRegion` in the `firmware/` workspace) plug in
//! from outside. The seams, the append log and the wear-levelled key/value
//! store live in `zweidraehte-nv` (shared with the micro stack) and are
//! re-exported here; the backends below are the ones tied to this crate's
//! region vocabulary:
//!
//! - [`WearLeveledKv`] — key/value view over the `zweidraehte-nv` append log;
//!   cheap per-record writes; for hot data like the SIAT and sequence
//!   counters. Its region binding lives in [`layout`](crate::storage::layout).
//! - [`ConfigStore`] — a single postcard blob (magic + length + payload) over
//!   [`SectorIo`] for the ETS-programmed device configuration. Erase+rewrite,
//!   not a [`KeyValueStore`](crate::storage::KeyValueStore) — config
//!   writes are rare.
//! - [`PackedSeqStore`] — the fixed packed sequence-state layout over
//!   [`ByteIo`] (FRAM, shared memory, a file), from `zweidraehte-nv`;
//!   write-in-place, no erase, no RAM mirror.
//! - [`PackedWatermark`] — the byte-medium mc_timer watermark record; the
//!   write-in-place sibling of the wear-levelled mc_timer log.
//! - [`NvConfig`] — write-through configuration storage: the device state's
//!   persistent sections in an [`NvStore`](zweidraehte_nv::NvStore), flushed
//!   by the router. Replaces [`ConfigStore`] as each target moves over.
//!
//! All take their region placement as runtime constructor args — the storage
//! layer's auto-packing derives each offset from the declared region sizes.

mod config_store;
mod nv_config;
mod packed_watermark;

#[cfg(test)]
mod tests;

pub use config_store::{ConfigStore, ConfigStoreError};
pub use nv_config::{FlushFailed, NvConfig};
pub use packed_watermark::PackedWatermark;
pub use zweidraehte_nv::{ByteIo, MAX_KEY, MAX_VAL, PackedSeqStore, SectorIo, WearLeveledKv, region_len};
pub use zweidraehte_nv::{Loaded, NvError, NvStore};
