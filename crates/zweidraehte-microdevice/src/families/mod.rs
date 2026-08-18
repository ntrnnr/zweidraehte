//! One module per BCU-era management model.
//!
//! Each family owns everything the core is generic over: the
//! [`crate::family::MicroDeviceFamily`] impl, the family's fixed EEPROM
//! offsets, and the device-definition type whose `build_eeprom` bakes
//! the boot image.

pub mod bcu2;
pub mod system7;
