//! Device identity, the storage framework, and the medium-agnostic backends.
//!
//! This module provides:
//!
//! - [`identity`] — read-only, factory-programmed data ([`DeviceIdentity`],
//!   [`SecureDeviceIdentity`], and the compile-time-constant demo variants)
//! - [`region`] — the layout framework (self-describing regions,
//!   auto-placement, typed placements)
//! - [`definition`] — [`DeviceStorage`], the one capability the router and
//!   the storage task drive, and [`Storage`], the stores struct behind it
//! - [`layout`] — the device-facing declaration surface: [`Stored`] couples
//!   each region to its store, [`StorageLayout`] + [`Placed`] derive
//!   placements, store types, and `open()` from one declaration per
//!   region + chip pair
//! - [`kv`] — the [`KeyValueStore`] seam between backends and views
//! - [`backends`] — the HAL-free backends over the [`SectorIo`] / [`ByteIo`]
//!   medium seams ([`WearLeveledKv`], [`NvConfig`],
//!   [`PackedSeqStore`](backends::PackedSeqStore),
//!   [`PackedWatermark`](backends::PackedWatermark)) the `firmware/` HAL
//!   adapters drive
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
pub mod layout;
pub mod region;
pub mod seq;
pub mod task;
pub mod views;

pub use backends::{ByteIo, Loaded, NvConfig, NvError, NvStore, SectorIo, WearLeveledKv};
pub use definition::{
    ConfigStorage, DeviceStorage, HasDeviceConfig, McTimerSlot, McTimerStoreBackend, NoBootImage, NoMcTimer, NoSeq,
    SecureIpStorage, SecureStorage, SeqSlot, Storage,
};
pub use identity::{DeviceIdentity, SecureDeviceIdentity, StaticIdentity, StaticSecureIdentity};
pub use kv::KeyValueStore;
pub use layout::{CONFIG_LOG_REC, Opens, Placed, StorageLayout, StoreOf, Stored, packed_seq_store};
pub use region::{
    Chip, ConfigLogRegion, FlashSiatRegion, FramMcTimerRegion, FramSiatRegion, McTimerRegion, Region, RegionKind,
    RegionPlacement, RegionSpec, check_layout, region_placement, region_spec,
};
pub use seq::{HasSeqStore, SeqStorageFor, SequenceNumberStorage};
pub use task::{
    NoRestartHook, NoSaveGuard, RESTART_SETTLE_DELAY, RestartHook, STORAGE_TICK, SaveGuard, restart, storage_task,
};
pub use views::{McTimerStore, SiatAccess, SiatStore};
