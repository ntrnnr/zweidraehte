//! Link drivers: everything between a physical medium and the
//! frame-level [`crate::device::PollInput::Frame`] input.
//!
//! A byte-oriented TPUART driver assembles checksum-stripped TP1 wire
//! frames here before the core's canonical boundary sees them. Nothing in
//! this module is required to use the core; a driver is just code that
//! produces that wire layout.

pub mod tpuart;
