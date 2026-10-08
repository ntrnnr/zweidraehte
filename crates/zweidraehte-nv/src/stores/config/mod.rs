//! The device configuration: a state's [`sections`] and the stores that move
//! them to and from a medium.
//!
//! [`NvStore`] is the store interface, [`ByteNv`] its byte-media backend and
//! [`FlashLog`] its flash backend; [`SplitNv`] spreads one state over two of
//! them.

mod byte_nv;
mod flash_log;
mod nv_store;
pub mod sections;
mod split;

pub use byte_nv::ByteNv;
pub use flash_log::FlashLog;
pub use nv_store::{Flusher, Loaded, NvError, NvStore};
pub use split::{Routes, SplitError, SplitNv};

/// The on-media identity of a configuration store. [`ByteNv`] writes it at
/// the head of its image; [`FlashLog`] mixes it into the state's layout
/// fingerprint to form its log magic, so a log written under another layout
/// reads as foreign.
pub const MAGIC: [u8; 4] = *b"KNXC";
