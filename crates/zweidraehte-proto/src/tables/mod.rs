//! Ownership-free views over standardized KNX table formats.
//!
//! These views describe bytes shared by management clients and device
//! implementations. They deliberately do not own storage or implement load
//! state machines: full devices can keep typed table objects, while BCU-era
//! devices can continue to expose one flat EEPROM image.

pub mod address;
