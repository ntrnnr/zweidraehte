//! System 7 / BIM M112 (TP1, mask 0705h): family constants, the
//! mask-fixed addresses, and the product definition that bakes the
//! boot image.

pub mod device_def;
pub mod family;
pub mod offsets;

pub use device_def::{System7CoDescriptor, System7DeviceDefinition};
pub use family::System7Family;
