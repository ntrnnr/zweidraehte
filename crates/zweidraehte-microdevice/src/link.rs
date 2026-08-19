//! Link drivers: everything between a physical medium and the
//! frame-level [`crate::device::PollInput::Frame`] input.
//!
//! The core accepts one concrete representation: TP1 standard frames
//! without their checksum. A byte-oriented TPUART driver assembles
//! those frames here before the core sees them; the conformance IPC
//! adapter produces the same bytes. Nothing in this module is required
//! to use the core; a driver is just code that produces that layout.

use heapless::Vec;

/// One received frame as a byte buffer. Sized above [`crate::frame::MAX_FRAME`]
/// so a driver can deliver an extended TP1 frame and let the core's parser
/// reject it, instead of every driver duplicating the length check.
pub type RxBuf = Vec<u8, 64>;

pub mod tpuart;
