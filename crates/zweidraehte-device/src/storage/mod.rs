//! Device identity, the storage framework, and the medium-agnostic backends.
//!
//! This module provides:
//!
//! - [`identity`] — read-only, factory-programmed data ([`DeviceIdentity`],
//!   [`SecureDeviceIdentity`], and the compile-time-constant demo variants)
//! - [`definition`] — [`DeviceStorage`], the one capability the router and
//!   the storage task drive, and [`Storage`], the stores struct behind it
//! - [`placement`] — [`Medium`] and [`Placement`]: where a device puts each
//!   store, checked at compile time, and the `open_*` functions that open a
//!   store at its placement
//! - [`kv`] — the [`KeyValueStore`] seam between backends and views
//! - [`backends`] — the HAL-free backends over the [`SectorIo`] / [`ByteIo`]
//!   medium seams ([`WearLeveledKv`], [`NvConfig`],
//!   [`PackedSeqStore`]) the `firmware/` HAL adapters drive, each opened at
//!   the [`Area`] of a [`Placement`] the device declares
//! - [`views`] — the typed security tables over the seam ([`SiatStore`],
//!   [`McTimerStore`])
//! - [`seq`] — the [`SequenceNumberStorage`] seam and the [`HasSeqStore`]
//!   capability the secure layers pull the store through
//! - [`task`] — the generic [`storage_task`] every device spawns
//!
//! BCU-specific types like [`DeviceConfig`](crate::bcus::system_b::DeviceConfig)
//! and [`IpExtensionConfig`](crate::bcus::system_b::IpExtensionConfig) remain
//! in their respective BCU modules.

pub mod backends;
pub mod definition;
pub mod identity;
pub mod kv;
pub mod placement;
pub mod seq;
pub mod task;
pub mod views;

pub use backends::{
    Area, ByteIo, CONFIG_LOG_REC, ConfigLog, FlashLog, Loaded, LogGeometry, NvConfig, NvError, NvStore, PackedSeqStore,
    SEQUENCE_MAGIC, SectorIo, WearLeveledKv, region_len,
};
pub use definition::{
    ConfigStorage, DeviceStorage, HasDeviceConfig, McTimerSlot, McTimerStoreBackend, NoBootImage, NoMcTimer, NoSeq,
    SecureIpStorage, SecureStorage, SeqSlot, Storage,
};
pub use identity::{DeviceIdentity, SecureDeviceIdentity, StaticIdentity, StaticSecureIdentity};
pub use kv::KeyValueStore;
pub use placement::{
    Medium, Placement, assert_disjoint, checked_area, open_config_image, open_config_log, open_mc_timer_log,
    open_packed_seq, open_seq_log,
};
pub use seq::{HasSeqStore, SeqStorageFor, SequenceNumberStorage};
pub use task::{
    NoRestartHook, NoSaveGuard, RESTART_SETTLE_DELAY, RestartHook, STORAGE_TICK, SaveGuard, restart, storage_task,
};
pub use views::{MC_TIMER_MAGIC, McTimerStore, SiatAccess, SiatStore};
