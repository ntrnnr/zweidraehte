//! Medium-agnostic persistent-storage backends over the medium seams.
//!
//! These backends are HAL-free: they speak only the [`SectorIo`] / [`ByteIo`]
//! seams and integer arithmetic, so the HAL adapters that drive real media
//! (`RpFlashIo`, `StmFlashIo`, `FramRegion` in the `firmware/` workspace) plug in
//! from outside. The seams, the append log and the wear-levelled key/value
//! store live in `zweidraehte-nv` (shared with the micro stack) and are
//! re-exported here:
//!
//! - [`WearLeveledKv`] — key/value view over the `zweidraehte-nv` append log;
//!   cheap per-record writes; for hot data like the SIAT and sequence
//!   counters.
//! - [`PackedSeqStore`] — the fixed packed sequence-state layout over
//!   [`ByteIo`] (FRAM, shared memory, a file), from `zweidraehte-nv`;
//!   write-in-place, no erase, no RAM mirror.
//! - [`NvConfig`] — write-through configuration storage: the device state's
//!   persistent sections in an [`NvStore`], flushed
//!   by the router; [`ConfigLog`] is its flash shape.
//!
//! All take where they live as constructor arguments: an offset, or a
//! [`LogGeometry`] built from an [`Area`]. Devices open them through the
//! `open_*` functions of [`placement`](super::placement), which compute
//! both from the device's placements at compile time.

mod nv_config;

#[cfg(test)]
mod tests;

pub use nv_config::{CONFIG_LOG_REC, ConfigLog, NvConfig};
pub use zweidraehte_nv::{
    Area, ByteIo, FlashLog, LogGeometry, MAX_KEY, MAX_VAL, PackedSeqStore, SEQUENCE_MAGIC, SectorIo, WearLeveledKv,
    region_len,
};
pub use zweidraehte_nv::{Loaded, NvError, NvStore};
