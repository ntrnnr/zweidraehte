//! TP1 message format conversion utilities
//!
//! This module re-exports the TP1 conversion functions from `crate::encoding::tp1`.
//! See that module for detailed documentation on TP1 wire format and internal KNX format.

pub use crate::encoding::tp1::{calculate_tp1_checksum, knx_to_tp1_message, tp1_to_knx_message, validate_tp1_checksum};
