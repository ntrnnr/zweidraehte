//! Physical layer encoding/decoding for different KNX media types
//!
//! This module provides bidirectional converters between wire formats and the
//! internal `KnxMessageBuffer` representation for different physical media:
//!
//! - **cEMI** ([`cemi`]): Common External Message Interface used in KNX/IP and USB
//! - **TP1** ([`tp1`]): Twisted Pair encoding used on the KNX bus
//!
//! These modules are used by their respective link layer implementations:
//! - cEMI is used by the KNX/IP link layer (routing and tunneling)
//! - TP1 is used by the TPUART link layer for direct bus access
//!
//! # Architecture
//!
//! Each encoding module provides:
//! - Parsing functions: Wire format → `KnxMessageBuffer`
//! - Serialization functions: `KnxMessageBuffer` → Wire format
//! - Format-specific types and utilities

pub mod cemi;
pub mod tp1;
