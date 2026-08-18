//! Link drivers: everything between a physical medium and the
//! frame-level [`crate::device::PollInput::Frame`] input.
//!
//! The core is deliberately frame-only — a byte-oriented medium
//! (TPUART) assembles frames here in its driver before the core sees
//! them, and frame-oriented media (the conformance IPC socket today;
//! RF and KNX/IP for the micro-System-7 family later) hand their
//! frames straight through. Nothing in this module is required to use
//! the core; a driver is just code that produces frame bytes.

use heapless::Vec;

/// One received frame as a byte buffer. Sized above [`crate::frame::MAX_FRAME`]
/// so a driver can deliver an extended frame and let the core's parser
/// reject it, instead of every driver duplicating the length check.
pub type RxBuf = Vec<u8, 64>;

pub mod tpuart;
