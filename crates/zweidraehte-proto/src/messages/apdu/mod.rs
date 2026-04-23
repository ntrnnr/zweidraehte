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
//! - [`secure`] — Secure APDU (S-A_Data) frame parser and builder
//! - [`group_value`] — `A_GroupValue_Read`, `A_GroupValue_Write`, `A_GroupValue_Response`
//! - [`go_diagnostics`] — `PID_OPERATION_MODE` and `PID_GO_DIAGNOSTICS` function-property bodies
//! - [`system_network_parameter`] — `A_SystemNetworkParameter_Read/Response`
//! - [`network_parameter`] — `A_NetworkParameter_InfoReport`

pub mod auth;
pub mod device;
pub mod function_property;
pub mod go_diagnostics;
pub mod group_value;
pub mod memory;
pub mod network_parameter;
pub mod property;
pub mod property_ext;
pub mod restart;
pub mod secure;
pub mod system_network_parameter;
