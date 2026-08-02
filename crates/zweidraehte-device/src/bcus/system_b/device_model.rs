//! System B device model.
//!
//! System B's lifecycle side effects are exactly the standard ones, so
//! the family aliases [`StandardDeviceModel`]. The generic device-model
//! vocabulary (events, notifier, trait, the standard implementation)
//! lives in [`crate::device_model`].

use crate::device_model::StandardDeviceModel;

/// Device model for System B devices — the standard implementation under
/// its family name.
pub type SystemBDeviceModel<'a, D> = StandardDeviceModel<'a, D>;
