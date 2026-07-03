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
//!   medium seams ([`WearLeveledKv`], [`ConfigStore`],
//!   [`PackedSeqStore`](backends::PackedSeqStore),
//!   [`PackedWatermark`](backends::PackedWatermark)) the `cross/` HAL
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

pub use backends::{ByteIo, ConfigStore, ConfigStoreError, SectorIo, WearLeveledKv};
pub use definition::{
    ConfigStorage, ConfigStoreBackend, HasConfigStore, HasDeviceConfig, McTimerStoreBackend, SecureIpStorage,
    SecureStorage, StorageHooks,
};
pub use identity::{DeviceIdentity, SecureDeviceIdentity, StaticIdentity, StaticSecureIdentity};
pub use kv::KeyValueStore;
pub use layout::{Opens, Placed, StorageLayout, StoreOf, Stored};
pub use region::{
    Chip, ConfigRegion, FlashSiatRegion, FramMcTimerRegion, FramSiatRegion, McTimerRegion, Region, RegionKind,
    RegionPlacement, RegionSpec, check_layout, region_placement, region_spec,
};
pub use seq::{HasSeqStore, SeqStorageFor, SequenceNumberStorage};
pub use task::{DIRTY_SAVE_POLL, NoSaveGuard, RESTART_SETTLE_DELAY, SaveGuard, SaveGuardToken, storage_task};
pub use views::{McTimerStore, SiatAccess, SiatStore};
