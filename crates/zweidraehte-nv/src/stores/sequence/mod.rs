//! The Data Secure sequence state: the sending and tool-access counters and
//! the Security Individual Address Table.
//!
//! Two shapes, for the two kinds of media: [`SiatStore`], a RAM-mirrored view
//! over a [`KeyValueStore`](crate::KeyValueStore) for flash, and
//! [`PackedSeqStore`], a fixed layout served straight from byte media. Both
//! implement the `zweidraehte_proto::security` traits the secure layers of
//! either stack consume.

mod packed_seq;
mod siat;

pub use packed_seq::{PackedSeqStore, region_len};
pub use siat::SiatStore;

/// The header magic of a sequence store, on every medium: a
/// [`PackedSeqStore`] on byte media and the
/// [`WearLeveledKv`](crate::WearLeveledKv) under a [`SiatStore`] on flash. A
/// store that finds another magic reads as a fresh device.
///
/// A product may pass its own tag instead, so that a layout of its own never
/// reads as this one (the micro targets' FRAM store does).
pub const MAGIC: u32 = u32::from_be_bytes(*b"KNXR");

/// SIAT entries: key = 0-based element index (2 bytes big-endian), value =
/// IA (2 bytes) + SeqNr (6 bytes).
pub const NS_SIAT: u8 = 0x01;
/// The single Sequence Number Sending: key = `[0]`, value = SeqNr (6 bytes).
pub const NS_SENDING: u8 = 0x02;
/// The Tool Access receiving SeqNr (a singleton, separate from the SIAT per
/// 03/03/07 NOTE 104): key = `[0]`, value = SeqNr (6 bytes).
pub const NS_TOOL: u8 = 0x03;
