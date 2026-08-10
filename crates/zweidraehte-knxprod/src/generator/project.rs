//! Device instances a caller registers on a [`KnxprodBuilder`].
//!
//! Only the input type lives here, unconditionally: a builder collects
//! device instances regardless of whether it will ever package them.
//! The XML generator that consumes them is packaging-only and lives in
//! [`super::project_gen`].
//!
//! [`KnxprodBuilder`]: super::KnxprodBuilder

use super::builder::{AppProgramRef, HardwareRef};

// ============================================================================
// Public Input Type
// ============================================================================

/// Definition of a device instance to include in the project.
///
/// Each device instance becomes a `<DeviceInstance>` element inside
/// `<UnassignedDevices>` in the project topology.
pub struct DeviceInstanceDef<'a> {
    /// Display name for the device instance in the project.
    pub name: &'a str,
    /// Which hardware definition this instance references.
    pub hardware: HardwareRef,
    /// Which product within that hardware (identified by order number).
    pub product_order_number: &'a str,
    /// Which application program this instance uses.
    pub application_program: AppProgramRef,
}
