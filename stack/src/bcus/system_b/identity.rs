//! Device identity — re-exports from [`crate::storage`].
//!
//! The canonical definitions of [`DeviceIdentity`] and [`StaticIdentity`]
//! live in [`crate::storage`]. This module re-exports them for backwards
//! compatibility with code that imports from `bcus::system_b`.

pub use crate::storage::{DeviceIdentity, StaticIdentity};
