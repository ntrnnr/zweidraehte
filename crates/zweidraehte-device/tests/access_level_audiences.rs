//! An interface object states *who* a property is for, not what number.
//!
//! 03/04/01 §4.3.2.2 Table 1 maps five audiences onto access levels, and
//! the mapping depends on whether the hosting profile has 4 or 16
//! authorisation levels. Only the runtime audience moves (3 → 15); the
//! other four are fixed. Crucially, `3` therefore denotes two different
//! audiences on a 16-level device — a controller adjusting an end-user
//! parameter stays at 3 while a runtime read becomes 15 — so a level
//! written as a bare number cannot be translated between models.
//!
//! `#[interface_object(..., levels = N)]` states the profile once and
//! the named audiences resolve against it at const-evaluation time.

use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{InterfaceObjectType, PDT_UnsignedInt};
use zweidraehte_proto::properties::PropertyDescriptor;

use zweidraehte_device::objects::interface::{interface_object, pid};

/// The same property surface declared for a 4-level profile...
#[interface_object(object_type = InterfaceObjectType::Security, levels = 4)]
struct FourLevelObject {
    #[io(pid = pid::OBJECT_NAME, pdt = PDT_UnsignedInt, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Configuration)]
    name: PDT_UnsignedInt,

    #[io(pid = pid::LOAD_STATE_CONTROL, pdt = PDT_UnsignedInt, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = ProductManufacturer)]
    load: PDT_UnsignedInt,
}

/// ...and for a 16-level one. Identical but for the `levels`.
#[interface_object(object_type = InterfaceObjectType::Security, levels = 16)]
struct SixteenLevelObject {
    #[io(pid = pid::OBJECT_NAME, pdt = PDT_UnsignedInt, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Configuration)]
    name: PDT_UnsignedInt,

    #[io(pid = pid::LOAD_STATE_CONTROL, pdt = PDT_UnsignedInt, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Controller, wl = ProductManufacturer)]
    load: PDT_UnsignedInt,
}

fn four(prop_id: u16) -> PropertyDescriptor {
    *FourLevelObject::PROPERTY_DESCRIPTORS.iter().find(|d| d.pid == prop_id).expect("declared")
}

fn sixteen(prop_id: u16) -> PropertyDescriptor {
    *SixteenLevelObject::PROPERTY_DESCRIPTORS.iter().find(|d| d.pid == prop_id).expect("declared")
}

#[test]
fn the_runtime_audience_follows_the_profile() {
    assert_eq!(four(pid::OBJECT_NAME).read_level, 3);
    assert_eq!(sixteen(pid::OBJECT_NAME).read_level, 15);
}

/// The case a numeric level cannot express: `Controller` and `Runtime`
/// are both 3 on a 4-level profile and part company at 16.
#[test]
fn the_controller_audience_does_not() {
    assert_eq!(four(pid::LOAD_STATE_CONTROL).read_level, 3);
    assert_eq!(sixteen(pid::LOAD_STATE_CONTROL).read_level, 3);

    // Same number on the 4-level profile, different on the 16-level one.
    assert_eq!(four(pid::OBJECT_NAME).read_level, four(pid::LOAD_STATE_CONTROL).read_level);
    assert_ne!(sixteen(pid::OBJECT_NAME).read_level, sixteen(pid::LOAD_STATE_CONTROL).read_level);
}

#[test]
fn the_fixed_audiences_are_identical_in_both_models() {
    for prop_id in [pid::OBJECT_NAME, pid::LOAD_STATE_CONTROL] {
        assert_eq!(four(prop_id).write_level, sixteen(prop_id).write_level, "PID {prop_id}");
    }
    assert_eq!(four(pid::OBJECT_NAME).write_level, 2); // Configuration
    assert_eq!(four(pid::LOAD_STATE_CONTROL).write_level, 1); // ProductManufacturer
}

/// The mandatory PID_OBJECT_TYPE descriptor the macro prepends is a
/// runtime read too, so it moves with the profile like any other.
#[test]
fn the_implicit_object_type_descriptor_follows_the_profile() {
    assert_eq!(four(pid::OBJECT_TYPE).read_level, 3);
    assert_eq!(sixteen(pid::OBJECT_TYPE).read_level, 15);
}
