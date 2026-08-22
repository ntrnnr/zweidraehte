//! The light switch on the polling microdevice stack.
//!
//! BCU2 and micro System 7 targets share the full-stack product configuration
//! and behavior, but use baked memory images, raw object slots, and a polling
//! loop instead of the composable runtime.

mod app;
mod definition;

pub use app::LightSwitchMicroApp;
pub use definition::{
    BCU2_PARAMS_IMAGE_OFFSET, BCU2_SECURE_GROUP_KEY_CAPACITY, BCU2_SECURE_GROUP_OBJECT_CAPACITY,
    BCU2_SECURE_P2P_KEY_CAPACITY, BCU2_SECURE_SIAT_CAPACITY, LightSwitchS7Family, S7_PARAMS_IMAGE_OFFSET,
    bcu2_definition, secure_bcu2_definition, system7_definition,
};
