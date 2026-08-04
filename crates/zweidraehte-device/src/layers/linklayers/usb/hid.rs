//! KNX USB HID report framing — shared with client implementations.
//!
//! The framing codec lives in [`zweidraehte_proto::usb_hid::hid`] so the
//! client library's USB connector can reuse it; this module re-exports it
//! for the USB host link layer here.

pub use zweidraehte_proto::usb_hid::hid::*;
