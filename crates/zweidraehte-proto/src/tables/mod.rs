//! Ownership-free views over standardized KNX table formats.
//!
//! These views describe bytes shared by management clients and device
//! implementations. They deliberately do not own storage or implement load
//! state machines: full devices can keep typed table objects, while BCU-era
//! devices can continue to expose one flat EEPROM image.
//!
//! Preserve format selection in the type: each device has one format per
//! table, so its codec must specialize without retaining runtime alternatives.
//! Sharing a borrowed view must not replace its format parameter with an enum
//! or trait object. Hosts can dispatch to typed codecs at their runtime boundary.

pub mod address;
pub mod association;
pub mod com_object;
