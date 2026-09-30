//! Device identity, the storage framework, and the medium-agnostic backends.
//!
//! This module provides:
//!
//! - [`identity`] — read-only, factory-programmed data ([`DeviceIdentity`],
//!   [`SecureDeviceIdentity`], and the compile-time-constant demo variants)
//! - [`region`] + [`definition`] — the layout framework (self-describing
//!   regions, auto-placement, typed placements) and the per-device stores
//!   structs with their capability impls
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
//! - [`flush`] — [`ConfigFlush`], the router's hook for write-through
//!   configuration storage
//! - [`task`] — the generic [`storage_task`] every device spawns
//!
//! BCU-specific types like [`DeviceConfig`](crate::bcus::system_b::DeviceConfig)
//! and [`IpExtensionConfig`](crate::bcus::system_b::IpExtensionConfig) remain
//! in their respective BCU modules.

pub mod backends;
pub mod definition;
pub mod flush;
pub mod identity;
pub mod kv;
pub mod layout;
pub mod region;
pub mod seq;
pub mod task;
pub mod views;

pub use backends::{ByteIo, Loaded, NvConfig, NvError, NvStore, SectorIo, WearLeveledKv};
pub use definition::{
    ConfigStorage, HasDeviceConfig, McTimerStoreBackend, NoBootImage, SecureIpStorage, SecureStorage, StorageHooks,
};
pub use flush::ConfigFlush;
pub use identity::{DeviceIdentity, SecureDeviceIdentity, StaticIdentity, StaticSecureIdentity};
pub use kv::KeyValueStore;
pub use layout::{CONFIG_LOG_REC, Opens, Placed, StorageLayout, StoreOf, Stored, packed_seq_store};
pub use region::{
    Chip, ConfigLogRegion, FlashSiatRegion, FramMcTimerRegion, FramSiatRegion, McTimerRegion, Region, RegionKind,
    RegionPlacement, RegionSpec, check_layout, region_placement, region_spec,
};
pub use seq::{HasSeqStore, SeqStorageFor, SequenceNumberStorage};
pub use task::{NoSaveGuard, RESTART_SETTLE_DELAY, STORAGE_TICK, SaveGuard, SaveGuardToken, restart, storage_task};
pub use views::{McTimerStore, SiatAccess, SiatStore};
