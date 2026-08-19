//! BCU1 / System 1 (TP1, mask 0012h): family constants, fixed EEPROM
//! offsets, and the product definition that bakes the boot image.

pub mod device_def;
pub mod family;
pub mod offsets;

pub use device_def::{Bcu1CoDescriptor, Bcu1DeviceDefinition};
pub use family::{BCU1_EEPROM_SIZE, Bcu1Family};
