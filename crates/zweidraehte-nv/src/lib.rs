//! HAL-free non-volatile storage for KNX devices.
//!
//! This crate holds the parts of persistence that know nothing about KNX
//! device stacks or executors, so the embassy-based full stack and the
//! polling micro stack can share them:
//!
//! - the two **medium seams**: [`SectorIo`] for erase-block flash and
//!   [`ByteIo`] for byte-writable memory (FRAM, EEPROM, shared memory). HAL
//!   adapters implement them outside this crate;
//! - the **append log** ([`AppendLog`]): variable-length, CRC-checked records
//!   appended to erased flash, replayed in write order at boot, and compacted
//!   into a fresh bank when the active one fills;
//! - the **key/value view** on top of the log ([`WearLeveledKv`]), used for
//!   hot per-frame state such as the Data Secure SIAT and sequence counters;
//! - the **stores** ([`stores`]), one module for each kind of data this crate
//!   persists, owning its magic, its key/value namespaces and its layout:
//!   - [`stores::config`]: a device state's configuration as numbered
//!     [`sections`](stores::config::sections), and the store that moves them
//!     to and from a medium ([`NvStore`]): [`ByteNv`] for byte media,
//!     [`FlashLog`] for flash, [`SplitNv`] across two of them;
//!   - [`stores::sequence`]: the Data Secure sending and tool counters plus the
//!     Security Individual Address Table, as [`SiatStore`] (a RAM-mirrored
//!     view over a [`KeyValueStore`], for flash) or [`PackedSeqStore`] (a
//!     fixed layout served straight from byte media). Both implement the
//!     `zweidraehte_proto::security` traits the secure layers of either stack
//!     consume;
//!   - [`stores::mc_timer`]: the KNX IP Secure multicast-timer watermark
//!     ([`McTimerStore`]), as [`ByteMcTimer`] on byte media or a one-key
//!     [`WearLeveledKv`] log on flash;
//!   - [`stores::provisioning`]: the serial, FDSK and MAC written once on the
//!     production line, its codec and its flash I/O.
//!
//! Everything is synchronous and allocation-free. The `mock` feature adds a
//! host-side NOR flash model with a power-cut write budget for tests.

#![no_std]

#[cfg(any(test, feature = "mock"))]
extern crate std;

mod area;
mod byte_io;
mod crc;
mod kv;
mod log;
mod mirror;
mod region;
mod sector_io;
pub mod stores;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

// The shared machinery.
pub use area::Area;
pub use byte_io::ByteIo;
pub use kv::{KV_RECORD, KeyValueStore, MAX_KEY, MAX_VAL, SINGLETON_KEY, WearLeveledKv};
pub use log::{AppendLog, Compactor, LogGeometry};
pub use mirror::{Mirror, MirrorEntry};
pub use region::Region;
pub use sector_io::SectorIo;

// The store types. Magics, namespaces and layout helpers stay reachable only
// through their store's module, so each on-media identity has one home.
pub use stores::config::{ByteNv, FlashLog, Flusher, Loaded, NvError, NvStore, Routes, SplitError, SplitNv};
pub use stores::mc_timer::{ByteMcTimer, McTimerStore};
pub use stores::sequence::{PackedSeqStore, SiatStore};

#[cfg(test)]
mod tests;
