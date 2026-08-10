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
