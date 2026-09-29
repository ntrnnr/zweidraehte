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
//!   hot per-frame state such as the Data Secure SIAT and sequence counters.
//!
//! Everything is synchronous and allocation-free. The `mock` feature adds a
//! host-side NOR flash model with a power-cut write budget for tests.

#![no_std]

#[cfg(any(test, feature = "mock"))]
extern crate std;

mod byte_io;
mod crc;
mod kv;
mod log;
mod mirror;
mod sector_io;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

pub use byte_io::ByteIo;
pub use kv::{KV_RECORD, KeyValueStore, MAX_KEY, MAX_VAL, WearLeveledKv};
pub use log::{AppendLog, Compactor, LogGeometry};
pub use mirror::{Mirror, MirrorEntry};
pub use sector_io::SectorIo;

#[cfg(test)]
mod tests;
