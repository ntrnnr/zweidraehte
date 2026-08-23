//! System 7 device model.
//!
//! System 7's lifecycle side effects are the standard ones —
//! [`StandardDeviceModel`] already handles the optional Interface Program
//! through the [`RunTarget::Pei`] role its
//! interface object and the memory map's load-control window both use.
//!
//! [`RunTarget::Pei`]: crate::device_model::RunTarget::Pei

use crate::device_model::StandardDeviceModel;

/// Device model for System 7 devices — the standard implementation under
/// its family name.
pub type System7DeviceModel<'a, D> = StandardDeviceModel<'a, D>;
