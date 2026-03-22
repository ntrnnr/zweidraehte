//! Easter egg function property for the light switch.
//!
//! An [`InterfaceObjectAugment`] that intercepts function property commands
//! on the Device Object at a manufacturer-specific property ID.
//! Send certain ASCII phrases, get witty replies.
//!
//! # Wiring (KNX/IP)
//!
//! ```rust,ignore
//! use devices::light_switch::easter_egg::EasterEggAugment;
//! use zweidraehte_device::bcus::system_b::*;
//!
//! type InterfaceObjects<'a> = DefaultKnxIpInterfaceObjects<'a, MyState, EasterEggAugment>;
//!
//! fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a> {
//!     create_knxip_objects::<Self, _, _>(state, &Self::memory_layout(), EasterEggAugment)
//! }
//! ```
//!
//! # Wiring (TP1)
//!
//! ```rust,ignore
//! type InterfaceObjects<'a> = DefaultSystemBInterfaceObjects<'a, MyState, EasterEggAugment>;
//!
//! fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a> {
//!     create_system_b_objects::<Self, _, _>(state, &Self::memory_layout(), EasterEggAugment)
//! }
//! ```

use zweidraehte_device::dpt::{InterfaceObjectType, PDT_Function};
use zweidraehte_device::objects::interface::{
    FunctionPropertyRequest, FunctionPropertyResult, InterfaceObjectAugment,
    PropertyAccess, PropertyDescriptionResponse, PropertyDescriptor, PropertyError,
    PropertyLookup,
};
use zweidraehte_device::StackState;

/// Manufacturer-specific property ID used for the easter egg.
///
/// PID 255 is in the manufacturer-specific range (200-255) and unlikely
/// to conflict with any standard property.
const EASTER_EGG_PID: u8 = 255;

/// Augment that adds a hidden function property easter egg to the Device Object.
#[derive(Debug, Clone, Copy)]
pub struct EasterEggAugment;

impl<S: StackState> InterfaceObjectAugment<S> for EasterEggAugment {
    fn property_description_read(
        &self,
        _state: &S,
        object_type: InterfaceObjectType,
        object_idx: u16,
        lookup: PropertyLookup,
    ) -> Option<Result<PropertyDescriptionResponse, PropertyError>> {
        if object_type != InterfaceObjectType::Device {
            return None;
        }

        if !matches!(lookup, PropertyLookup::ByPid(EASTER_EGG_PID) | PropertyLookup::ByIndex(0)) {
            return None;
        }

        let desc = PropertyDescriptor::from_type::<PDT_Function>(
            EASTER_EGG_PID,
            PropertyAccess::ReadOnly,
            3, // read level: unrestricted
            0, // write level: most restricted (not writable)
        );
        Some(Ok(PropertyDescriptionResponse::from_descriptor(object_idx, 0, &desc)))
    }

    fn function_property_command(
        &self,
        _state: &S,
        object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        if object_type != InterfaceObjectType::Device || req.prop_id != EASTER_EGG_PID {
            return None;
        }

        // Responses must fit in MAX_FUNCTION_PROPERTY_RESPONSE (64 bytes).
        Some(match req.service_data {
            b"knock knock" => FunctionPropertyResult::success_with_data(
                b"Who's there? ...a lost packet. Wrong subnet.",
            ),
            b"42" => FunctionPropertyResult::success_with_data(
                b"Correct! But on KNX, we write it 0x2A.",
            ),
            b"hello" => FunctionPropertyResult::success_with_data(
                b"Guten Tag! I flip bits on twisted pair.",
            ),
            _ => FunctionPropertyResult::success_with_data(
                b"Try: knock knock / 42 / hello",
            ),
        })
    }
}
