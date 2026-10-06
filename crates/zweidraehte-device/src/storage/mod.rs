//! Device identity, the storage framework, and the stores a device opens.
//!
//! This module provides:
//!
//! - [`identity`] — read-only, factory-programmed data ([`DeviceIdentity`],
//!   [`SecureDeviceIdentity`], and the compile-time-constant demo variants)
//! - [`definition`] — [`DeviceStorage`], the one capability the router and
//!   the storage task drive, and [`Storage`], the stores struct behind it
//! - [`NvConfig`] — the write-through configuration slot over any
//!   [`NvStore`], and [`ConfigLog`], its flash shape
//! - [`placement`] — [`Medium`] and [`Placement`]: where a device puts each
//!   store, checked at compile time, and the `open_*` functions that open a
//!   store at its placement
//! - [`seq`] — the [`SequenceNumberStorage`] seam and the [`HasSeqStore`]
//!   capability the secure layers pull the store through
//! - [`task`] — the generic [`storage_task`] every device spawns
//!
//! The HAL-free parts come from `zweidraehte-nv`, shared with the micro
//! stack, and are re-exported here: the [`SectorIo`] / [`ByteIo`] medium
//! seams the `firmware/` HAL adapters implement, [`Area`] and
//! [`LogGeometry`], the config stores, and the Data Secure sequence stores
//! ([`SiatStore`] over a [`WearLeveledKv`] on flash, [`PackedSeqStore`] on
//! byte media); IP Secure routing selects an independent [`McTimerStore`].

pub mod definition;
pub mod identity;
mod nv_config;
pub mod placement;
pub mod seq;
pub mod task;

pub use definition::{
    ConfigStorage, DeviceStorage, FlushError, NoMcTimer, NoSeq, SecureRoutingStorage, SecureStorage, SeqSlot, Storage,
};
pub use identity::{DeviceIdentity, SecureDeviceIdentity, StaticIdentity, StaticSecureIdentity};
pub use nv_config::{CONFIG_LOG_REC, ConfigLog, NvConfig};
pub use placement::{
    Medium, Placement, assert_disjoint, checked_area, open_config_image, open_config_log, open_mc_timer_bytes,
    open_mc_timer_log, open_packed_seq, open_seq_log,
};
pub use seq::{HasSeqStore, SeqStorageFor, SequenceNumberStorage};
pub use task::{NoRestartHook, NoSaveGuard, RESTART_SETTLE_DELAY, RestartHook, SaveGuard, restart, storage_task};
pub use zweidraehte_nv::{
    Area, ByteIo, ByteMcTimer, FlashLog, KeyValueStore, Loaded, LogGeometry, MC_TIMER_MAGIC, McTimerStore, NvError,
    NvStore, PackedSeqStore, Region, SEQUENCE_MAGIC, SectorIo, SiatStore, WearLeveledKv, region_len,
};
pub use zweidraehte_proto::security::SiatAccess;
