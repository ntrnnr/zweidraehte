//! System B Device Implementation
//!
//! This module provides a complete, ready-to-use System B device implementation
//! that can be specialized for different KNX media:
//!
//! - **57B0**: KNX/IP devices
//! - **07B0**: TP1 devices (twisted pair)
//!
//! # Architecture
//!
//! A System B device consists of:
//!
//! 1. **Compile-time constants** (burned into firmware):
//!    - Mask version, serial number, hardware type, program version
//!    - Table sizing (max addresses, associations, communication objects)
//!
//! 2. **Persistent state** (loaded from storage, saved on change):
//!    - Individual address
//!    - Tables (ADT, AST, COT, APP) with their load states
//!    - Authorization keys
//!    - IP configuration (57B0 only)
//!
//! 3. **Runtime state** (volatile, reset on power cycle):
//!    - Programming mode
//!    - Current access level
//!    - Run state (application must be explicitly restarted after boot)
//!
//! # Interface Objects
//!
//! System B devices have the following interface objects:
//!
//! | Index | Object | Description |
//! |-------|--------|-------------|
//! | 0 | Device Object | Device identity and addressing |
//! | 1 | Address Table Object | Group address mapping |
//! | 2 | Association Table Object | TSAP ↔ ASAP mapping |
//! | 3 | Group Object Table Object | Communication object config |
//! | 4 | Application Program Object | Load + Run state machines |
//! | 5 | PEI Program Object | PEI Load + Run state machines |
//! | 6 | IP Parameter Object | IP config (57B0 only) |
//!
//! # Device Definition
//!
//! All device-specific configuration is done via
//! [`StackDefinition`](crate::StackDefinition). For System B devices using
//! [`SystemBMemoryMap`], implement [`SystemBStackDefinition`] to get
//! `memory_layout()` and `memory_map()` for free.

mod definition;
mod device_state;
mod extensions;
mod memory_map;
mod objects;
mod storage;

pub use definition::*;
pub use device_state::*;
pub use extensions::*;
pub use memory_map::*;
pub use objects::*;
pub use storage::*;
