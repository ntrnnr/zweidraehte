//! BCU2 / System 2 (TP1, mask 0020h): family constants, fixed EEPROM
//! offsets, and the product definition that bakes the boot image.

pub mod device_def;
pub mod family;
pub mod offsets;

pub use device_def::{Bcu2CoDescriptor, Bcu2DeviceDefinition};
pub use family::{BCU2_EEPROM_SIZE, Bcu2Family};
