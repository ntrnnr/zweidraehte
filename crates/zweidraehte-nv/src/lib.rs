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
//! - the **Data Secure sequence state** — sending and tool counters plus the
//!   Security Individual Address Table — in the two shapes the media call for:
//!   [`SiatStore`], a RAM-mirrored view over a [`KeyValueStore`] for flash, and
//!   [`PackedSeqStore`], a fixed layout served straight from byte media. Both
//!   implement the `zweidraehte_proto::security` traits the secure layers of
//!   either stack consume;
//! - the **section vocabulary** ([`sections`]) a device state uses to split
//!   its configuration into independently persisted units, and the
//!   **configuration store** ([`NvStore`]) that moves sections to and from a
//!   medium: [`ByteNv`] for byte media, [`FlashLog`] for flash.
//!
//! Everything is synchronous and allocation-free. The `mock` feature adds a
//! host-side NOR flash model with a power-cut write budget for tests.

#![no_std]

#[cfg(any(test, feature = "mock"))]
extern crate std;

mod byte_io;
mod byte_nv;
mod crc;
mod flash_log;
mod kv;
mod log;
mod mirror;
mod nv_store;
mod packed_seq;
pub mod sections;
mod sector_io;
mod siat;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

pub use byte_io::ByteIo;
pub use byte_nv::ByteNv;
pub use flash_log::FlashLog;
pub use kv::{
    KV_RECORD, KeyValueStore, MAX_KEY, MAX_VAL, NS_MC_TIMER, NS_SENDING, NS_SIAT, NS_TOOL, SINGLETON_KEY, WearLeveledKv,
};
pub use log::{AppendLog, Compactor, LogGeometry};
pub use mirror::{Mirror, MirrorEntry};
pub use nv_store::{Loaded, NvError, NvStore};
pub use packed_seq::{PackedSeqStore, region_len};
pub use sector_io::SectorIo;
pub use siat::SiatStore;

#[cfg(test)]
mod tests;
