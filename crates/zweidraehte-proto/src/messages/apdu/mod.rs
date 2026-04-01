//! Typed APDU (Application Protocol Data Unit) parsers and writers.
//!
//! Each KNX application-layer service has its own APDU format: field positions,
//! bit-packing schemes, and data payloads. This module provides thin typed
//! wrappers that replace raw `buf[offsets::MSG_APCI + N]` manipulation with
//! named, documented, and unit-tested operations.
//!
//! # Design
//!
//! The APDU data lives inside a larger KNX message buffer starting at offset
//! `MSG_APCI` (= 6). The types here work as **views into that buffer**, not
//! standalone allocations. Parse types extract fields from `&[u8]`; write
//! functions modify fields in `&mut [u8]`.
//!
//! Writers integrate with `MessageBuilder::with_data(|buf| ...)` — call them
//! inside the closure to fill in the APDU region.
//!
//! # Modules
//!
//! - [`property`] — `A_PropertyValue_*` and `A_PropertyDescription_*`
//! - [`function_property`] — `A_FunctionPropertyCommand`, `A_FunctionPropertyState_*`
//! - [`memory`] — `A_Memory_*`, `A_UserMemory_*`, `A_MemoryBit_Write`
//! - [`device`] — `A_DeviceDescriptor_*`, `A_IndividualAddress*`, `A_ADC_*`
//! - [`auth`] — `A_Authorize_*`, `A_Key_*`
//! - [`property_ext`] — `A_PropertyExtValue_*` (AN163 extended interface object addressing)
//! - [`restart`] — `A_Restart` (basic and master reset)

pub mod auth;
pub mod device;
pub mod function_property;
pub mod memory;
pub mod property;
pub mod property_ext;
pub mod restart;
