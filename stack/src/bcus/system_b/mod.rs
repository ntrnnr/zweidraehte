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
//! # Example
//!
//! ```rust,ignore
//! use zweidraehte::{
//!     bcus::system_b::KnxIpDevice,
//!     dpt::DPT_Switch,
//!     ets::EtsComObjects,
//!     objects::comm::ComObject,
//! };
//!
//! // Define communication objects
//! pub mod co {
//!     use super::*;
//!     use zweidraehte::objects::comm::{ComObjectIndex, ComObjects, ComObjectInfo, ComObjectInfoMut};
//!
//!     #[derive(EtsComObjects)]
//!     pub struct SwitchObjects {
//!         #[ets(index = 1, display = "Input", function = "Switch input")]
//!         pub input: ComObject<DPT_Switch>,
//!         #[ets(index = 2, display = "Output", function = "Switch output")]
//!         pub output: ComObject<DPT_Switch>,
//!     }
//! }
//!
//! // Define device with compile-time constants
//! #[derive(Copy, Clone)]
//! pub struct MySwitchDevice;
//!
//! impl KnxIpDevice for MySwitchDevice {
//!     const INTERFACE_NAME: &'static str = "eth0";
//!     type Platform = MyPlatform;
//! }
//! ```

mod device_state;
mod identity;
mod memory_map;
mod objects;
mod storage;
mod traits;

pub use device_state::{IpLinkLayerState, IpSystemBDeviceState, SystemBDeviceState};
pub use identity::{DeviceIdentity, StaticIdentity};
pub use memory_map::{MemoryLayout, SystemBMemoryMap};
pub use objects::{
    IpObjects, KnxIpInterfaceObjects, SystemBObjects, create_knxip_objects, create_system_b_objects, device_info_from,
};
pub use storage::{LinkLayerConfig, LinkLayerState, PersistedIpConfig, PersistedState, table_sizes};
pub use traits::{KnxIpDevice, TpDevice};
