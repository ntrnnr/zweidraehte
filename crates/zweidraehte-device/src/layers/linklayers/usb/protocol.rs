//! KNX USB Transfer Protocol — shared with client implementations.
//!
//! The protocol codec lives in [`zweidraehte_proto::usb_hid::protocol`]
//! so the client library's USB connector can reuse it; this module
//! re-exports it for the USB host link layer here.

pub use zweidraehte_proto::usb_hid::protocol::*;
