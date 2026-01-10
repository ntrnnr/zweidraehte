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
//! | 5 | IP Parameter Object | IP config (57B0 only) |
//!
//! # Example
//!
//! ```rust,ignore
//! use zweidraehte::{
//!     define_com_objects,
//!     bcus::system_b::{SystemBDevice, KnxIpDevice, KnxIpDeviceBuilder},
//!     dpt::DPT_Switch,
//! };
//!
//! // Define communication objects
//! define_com_objects! {
//!     pub mod co {
//!         pub struct SwitchObjects {
//!             1 => pub input: DPT_Switch = DPT_Switch::from(false),
//!             2 => pub output: DPT_Switch = DPT_Switch::from(false),
//!         }
//!     }
//! }
//!
//! // Define device with compile-time constants
//! #[derive(Copy, Clone)]
//! pub struct MySwitchDevice;
//!
//! impl SystemBDevice for MySwitchDevice {
//!     const MASK_VERSION: [u8; 2] = [0x57, 0xB0];
//!     const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78];
//!     const HARDWARE_TYPE: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
//!     const PROGRAM_VERSION: [u8; 5] = [0x00, 0xFA, 0x01, 0x00, 0x01];
//!
//!     const MAX_ADDRESSES: usize = 16;
//!     const MAX_ASSOCIATIONS: usize = 16;
//!     const MAX_COM_OBJECTS: usize = 8;
//!
//!     type ComObjects = co::SwitchObjects;
//!     type Storage = NoStorage;
//! }
//!
//! impl KnxIpDevice for MySwitchDevice {
//!     const INTERFACE_NAME: &'static str = "eth0";
//!     type Platform = MyPlatform;
//! }
//! ```

mod traits;
mod storage;
mod state;
mod tables;
mod memory_map;
mod objects;
mod builder;

pub use traits::{SystemBDevice, SystemBDeviceExt, KnxIpDevice, TpDevice};
pub use storage::{DeviceStorage, PersistedState, PersistedIpConfig, NoStorage, table_sizes};
pub use state::{DeviceState, IpDeviceState};
pub use tables::SystemBState;
pub use crate::memory::HasApplication;
pub use memory_map::{SystemBMemoryMap, MemoryLayout};
pub use objects::{SystemBInterfaceObjects, KnxIpInterfaceObjects, device_info_from};
pub use builder::{SystemBInterfaceObjectsBuilder, KnxIpInterfaceObjectsBuilder};
