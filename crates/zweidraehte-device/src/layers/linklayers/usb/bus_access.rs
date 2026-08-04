//! KNX USB Bus Access Server feature services — shared with client
//! implementations.
//!
//! The frame builders/parsers live in
//! [`zweidraehte_proto::usb_hid::bus_access`] so the client library's USB
//! connector can reuse them; this module re-exports them for the USB host
//! link layer here.

pub use zweidraehte_proto::usb_hid::bus_access::*;
