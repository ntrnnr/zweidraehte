//! Easter egg function property for the light switch.
//!
//! An [`Augment<D>`](zweidraehte_device::service::Augment)
//! that intercepts function property commands on the Device Object at a
//! manufacturer-specific property ID. Send certain ASCII phrases, get
//! witty replies.
//!
//! # Wiring
//!
//! Add `EasterEggAugment` as a `#[service(augment)]` field on the
//! device's [`#[derive(ServiceRegistry)]`](zweidraehte_device::service::ServiceRegistry)
//! augment-bundle struct, alongside the medium extension's augment.
//!
//! ```rust,ignore
//! use devices::light_switch::easter_egg::EasterEggAugment;
//!
//! #[derive(zweidraehte_device::service::ServiceRegistry)]
//! pub struct MyDeviceAugments<'a> {
//!     #[service(augment)] tp1:    Tp1Augment<'a>,
//!     #[service(augment)] easter: EasterEggAugment,
//! }
//!
//! impl StackDefinition for MyDevice {
//!     type Augments<'a> = MyDeviceAugments<'a>;
//!
//!     fn create_augments<'a>(state, platform, _lctx) -> Self::Augments<'a> {
//!         MyDeviceAugments {
//!             tp1:    state.extension_state().create_augment::<Self>(platform),
//!             easter: EasterEggAugment,
//!         }
//!     }
//! }
//! ```

use zweidraehte_device::objects::interface::{
    FunctionPropertyRequest, FunctionPropertyResult, interface_object_augment,
};
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{InterfaceObjectType, PDT_Function};

/// Manufacturer-specific property ID used for the easter egg.
///
/// PID 255 is in the manufacturer-specific range (200-255) and unlikely
/// to conflict with any standard property.
mod pid {
    pub const EASTER_EGG: u16 = 255;
}

/// Augment that adds a hidden function property easter egg to the Device Object.
//
// `#[interface_object_augment]` runs first (it's an attribute proc-macro);
// the inner `#[derive]` line is forwarded by the macro and applied to the
// generated unit struct. The order matters: derives placed *before* this
// attribute would see the original AST (with the placeholder field) and
// emit `Debug` / `Clone` / `Copy` impls referencing a field that the
// macro then strips.
#[interface_object_augment(target_objects = [InterfaceObjectType::Device])]
#[derive(Debug, Clone, Copy)]
pub struct EasterEggAugment {
    // Function-property only — readable as a "Function" descriptor but the
    // actual interaction is via `A_FunctionPropertyCommand`. Marked
    // `intercepts` because the Device Object is base-owned.
    #[io(
        pid = pid::EASTER_EGG,
        pdt = PDT_Function,
        access = RO,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL,
        rl = 3, wl = 0,
        intercepts,
        function_command = |_this: &Self, _ctx, req: &FunctionPropertyRequest<'_>| -> FunctionPropertyResult {
            // Responses must fit in MAX_FUNCTION_PROPERTY_RESPONSE (64 bytes).
            match req.service_data {
                b"knock knock" => FunctionPropertyResult::success_with_data(
                    b"Who's there? ...a lost packet. Wrong subnet.",
                ),
                b"42" => FunctionPropertyResult::success_with_data(
                    b"Correct! But on KNX, we write it 0x2A.",
                ),
                b"hello" => FunctionPropertyResult::success_with_data(
                    b"Guten Tag! I flip bits on twisted pair.",
                ),
                _ => FunctionPropertyResult::success_with_data(b"Try: knock knock / 42 / hello"),
            }
        },
    )]
    easter_egg: (),
}
