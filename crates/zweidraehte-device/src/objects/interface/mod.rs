//! KNX Interface Objects
//!
//! This module implements the KNX Interface Object model as per KNX specification.
//! Interface Objects provide a standardized way to access device properties and
//! configuration through the management layer.
//!
//! # Architecture
//!
//! The design separates concerns between the stack and application:
//!
//! - **Stack side**: Uses [`PropertyServiceHandler`] trait to access interface objects.
//!   This trait is object-safe and allows the stack to handle property read/write
//!   requests without knowing the concrete container type.
//!
//! - **Application side**: Defines interface object containers that implement
//!   [`PropertyServiceHandler`]. The container manages the objects internally and
//!   dispatches requests by object index.
//!
//! # Usage Pattern
//!
//! Applications implement `create_interface_objects` on their `StackDefinition` type:
//!
//! ```rust,ignore
//! impl StackDefinition for MyDevice {
//!     type InterfaceObjects<'a> = MyInterfaceObjects<'a, Self::State>;
//!
//!     fn create_interface_objects<'a>(tables: &'a Self::Tables, state: &'a Self::State) -> Self::InterfaceObjects<'a>
//!     where
//!         Self::Tables: 'a,
//!         Self::State: 'a,
//!     {
//!         MyInterfaceObjects::new(tables, state)
//!     }
//! }
//! ```
//!
//! The `InterfaceObjects` type must implement [`PropertyServiceHandler`], which handles
//! property requests by dispatching to the appropriate object based on index.
//!
//! # Standard Object Layout
//!
//! A typical KNX device has these interface objects:
//!
//! | Index | Object Type | Description |
//! |-------|-------------|-------------|
//! | 0 | Device Object | Basic device information (mandatory) |
//! | 1 | Address Table Object | Group address table |
//! | 2 | Association Table Object | TSAP/ASAP mapping |
//! | 3 | Application Program Object | Application info |
//! | 4 | Group Object Table Object | Communication object descriptors |
//! | 5 | IP Parameter Object | KNXnet/IP configuration (for KNXnet/IP devices) |

mod standard;
mod traits;

pub use standard::*;
pub use traits::*;
pub use zweidraehte_proto::properties::*;

// Re-export the attribute macros so users can write
// `#[interface_object(object_type = ...)]` without depending on
// `zweidraehte-device-macros` directly.
pub use zweidraehte_device_macros::{interface_object, interface_object_augment};

/// Property ID constants as defined in KNX specification
// The constants themselves are pure wire vocabulary and live in the
// proto crate (shared with the client's download engine); this
// re-export keeps every `objects::interface::pid::…` path working.
pub use zweidraehte_proto::pid;

/// Carrier for the compile-fail test below; it has no other purpose.
///
/// `rl` / `wl` take an audience from 03/04/01 §4.3.2.2 Table 1, never a
/// number. The restriction is not stylistic: 06 Profiles Annex A prints
/// its levels in the 4-level notation whatever the mask's own model
/// (§A.1.2.1 NOTE 2), so a `3` copied out of it stands for both
/// [`Controller`](zweidraehte_proto::access::AccessLevel::Controller)
/// and [`Runtime`](zweidraehte_proto::access::AccessLevel::Runtime) —
/// which are 3 and 15 on a 16-level profile. The number follows from
/// the audience and the profile; the audience does not follow from the
/// number, so accepting one would silently pick an answer.
///
/// A named audience compiles:
///
/// ```
/// use zweidraehte_device::objects::interface::{interface_object, pid};
/// use zweidraehte_proto::access::AccessPolicy;
/// use zweidraehte_proto::dpt::{InterfaceObjectType, PDT_UnsignedInt};
///
/// #[interface_object(object_type = InterfaceObjectType::Device)]
/// struct Named {
///     #[io(pid = pid::device::ROUTING_COUNT, pdt = PDT_UnsignedInt, access = RW,
///          policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime)]
///     routing_count: PDT_UnsignedInt,
/// }
/// ```
///
/// The same property with the number that audience resolves to on
/// System B does not, because `3` cannot say which audience it meant:
///
/// ```compile_fail
/// use zweidraehte_device::objects::interface::{interface_object, pid};
/// use zweidraehte_proto::access::AccessPolicy;
/// use zweidraehte_proto::dpt::{InterfaceObjectType, PDT_UnsignedInt};
///
/// #[interface_object(object_type = InterfaceObjectType::Device)]
/// struct Numbered {
///     #[io(pid = pid::device::ROUTING_COUNT, pdt = PDT_UnsignedInt, access = RW,
///          policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3)]
///     routing_count: PDT_UnsignedInt,
/// }
/// ```
#[allow(dead_code)]
struct AccessLevelsAreNamed;
