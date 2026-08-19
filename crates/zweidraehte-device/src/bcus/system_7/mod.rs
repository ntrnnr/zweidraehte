//! System 7 BCU implementation (masks 0700h/0701h/0705h TP1, 2705h RF,
//! 5705h KNX IP).
//!
//! The management model differs from System B in four load-bearing ways:
//!
//! 1. **Fixed absolute memory map.** User EEPROM spans 4000h–CFFFh, the
//!    RT8 address table sits at exactly 4000h, the programming-mode byte
//!    at 0060h, OptionReg at 0100h. ETS writes tables and parameters
//!    with plain `A_Memory_Write`s to addresses baked into the product
//!    database — there is no relative allocation.
//! 2. **RT8 tables** ([`addr8`](crate::objects::tables::addr8),
//!    [`asso8`](crate::objects::tables::asso8)) with 1-octet counts and
//!    the device's individual address stored *inside* the address table.
//!    No Group Object Table interface object exists; GO data rides in
//!    the application segment.
//! 3. **Absolute-segment load controls**
//!    ([`AbsoluteAlloc`](crate::objects::tables::AbsoluteAlloc) policy):
//!    allocation records name fixed addresses, and ETS drives
//!    the load state machines both via `PID_LOAD_STATE_CONTROL` and via
//!    the memory-mapped load-control window (write 0104h, status
//!    B6EAh–B6EDh).
//! 4. **16 authorization access levels** (keys for 0–14, level 15 free)
//!    instead of System B's 4.
//!
//! Interface objects sit at fixed indexes 0–4: Device, Address Table,
//! Association Table, Application Program, Application Program 2.

mod config;
mod definition;
mod device_model;
mod device_state;
mod memory_map;
mod objects;
mod storage;

pub mod extensions;

pub use definition::*;
pub use device_model::*;
pub use device_state::*;
pub use extensions::*;
pub use memory_map::*;
pub use objects::*;
pub use storage::*;
