//! System B Device Implementation
//!
//! This module provides a complete, ready-to-use System B device implementation
//! that can be specialized for different KNX media:
//!
//! - **57B0**: KNX/IP devices
//! - **07B0**: TP1 devices (twisted pair)
//!
//! # Architecture
//!
//! A System B device consists of:
//!
//! 1. **Compile-time constants** (burned into firmware):
//!    - Mask version, serial number, hardware type, program version
//!    - Table sizing (max addresses, associations, communication objects)
//!
//! 2. **Persistent state** (loaded from storage, saved on change):
//!    - Individual address
//!    - Tables (ADT, AST, COT, APP) with their load states
//!    - Authorization keys
//!    - IP configuration (57B0 only)
//!
//! 3. **Runtime state** (volatile, reset on power cycle):
//!    - Programming mode
//!    - Current access level
//!    - Run state (application must be explicitly restarted after boot)
//!
//! # Interface Objects
//!
//! System B devices have the following interface objects:
//!
//! | Index | Object | Description |
//! |-------|--------|-------------|
//! | 0 | Device Object | Device identity and addressing |
//! | 1 | Address Table Object | Group address mapping |
//! | 2 | Association Table Object | TSAP ↔ ASAP mapping |
//! | 3 | Group Object Table Object | Communication object config |
//! | 4 | Application Program Object | Load + Run state machines |
//! | 5 | PEI Program Object | PEI Load + Run state machines |
//! | 6 | IP Parameter Object | IP config (57B0 only) |
//!
//! # Device Definition
//!
//! All device-specific configuration is done via
//! [`StackDefinition`](crate::StackDefinition). For System B devices using
//! [`SystemBMemoryMap`], implement [`SystemBStackDefinition`] to get
//! `memory_layout()` and `memory_map()` for free.

mod definition;
mod device_model;
mod device_state;
mod extensions;
mod memory_map;
mod objects;
mod storage;

pub use definition::*;
pub use device_model::SystemBDeviceModel;
pub use device_state::*;
pub use extensions::*;
pub use memory_map::*;
pub use objects::*;
pub use storage::*;

/// The standard AL service set under its System B name.
///
/// Identical to [`StandardAlServices`](crate::layers::application::services::StandardAlServices);
/// spell it this way in a System B `StackDefinition` for discoverability.
pub type SystemBAlServices = crate::layers::application::services::StandardAlServices;

/// The Secure AL service set under its System B name.
///
/// Identical to [`StandardSecureAlServices`](crate::layers::application::services::StandardSecureAlServices).
pub type SystemBSecureAlServices = crate::layers::application::services::StandardSecureAlServices;

/// Generate the standard pure-delegation trait impls for a newtype that
/// wraps a [`SystemBDeviceState`] (or any state with the same trait
/// surface) in a named field.
///
/// Emits forwarding impls for the fourteen state-surface traits a
/// wrapper almost never customises: [`HasSecurityMode`](crate::HasSecurityMode),
/// [`HasPersistence`](crate::HasPersistence),
/// [`HasAuthorization`](crate::HasAuthorization),
/// [`HasExtensionState`](crate::HasExtensionState),
/// [`HasAddressTable`](crate::objects::tables::HasAddressTable),
/// [`HasAssociationTable`](crate::objects::tables::HasAssociationTable),
/// [`HasCommunicationObjectTable`](crate::objects::tables::HasCommunicationObjectTable),
/// [`HasCommObjects`](crate::objects::comm::HasCommObjects),
/// [`HasGoSecurityView`](crate::objects::comm::HasGoSecurityView),
/// [`HasDiagnosticsContext`](crate::HasDiagnosticsContext),
/// [`HasApplication`](crate::objects::tables::HasApplication),
/// [`HasPeiApplication`](crate::objects::tables::HasPeiApplication),
/// [`HasRoutingCount`](crate::objects::interface::HasRoutingCount), and
/// `HasConnectionAuth` (from `zweidraehte_proto`).
///
/// `StackState` and `DeviceModelNotifier` are deliberately **not**
/// generated: wrappers usually exist precisely to customise those (a
/// fixed APDU length, a custom device-model notification slot, …) —
/// hand-write them next to the macro call. For forwarding a single
/// trait with hand-picked items, use `forward_to_field!` instead.
///
/// ```rust,ignore
/// forward_system_b_state_traits!(impl ConformanceState => self.inner: InnerState);
/// ```
#[macro_export]
macro_rules! forward_system_b_state_traits {
    (impl $outer:ty => self.$field:ident: $inner:ty) => {
        impl $crate::HasSecurityMode for $outer {
            fn security_mode_enabled(&self) -> bool {
                self.$field.security_mode_enabled()
            }
            fn log_access_denied(&self, source_addr: u16) {
                self.$field.log_access_denied(source_addr);
            }
            fn has_group_key(&self, tsap: u16) -> bool {
                self.$field.has_group_key(tsap)
            }
        }

        impl $crate::HasPersistence for $outer {
            fn mark_dirty(&self) {
                self.$field.mark_dirty();
            }
            fn is_dirty(&self) -> bool {
                self.$field.is_dirty()
            }
            fn clear_dirty(&self) {
                self.$field.clear_dirty();
            }
            fn apply_erase_code(&self, code: $crate::restart::EraseCode) {
                self.$field.apply_erase_code(code);
            }
        }

        impl $crate::HasAuthorization for $outer {
            fn max_access_levels(&self) -> u8 {
                self.$field.max_access_levels()
            }
            fn default_access_level(&self) -> u8 {
                self.$field.default_access_level()
            }
            fn authorize(&self, key: &[u8; 4]) -> u8 {
                self.$field.authorize(key)
            }
            fn key_write(&self, level: u8, key: &[u8; 4], ctx: $crate::__macro_support::access::AccessContext) -> u8 {
                self.$field.key_write(level, key, ctx)
            }
        }

        impl $crate::HasExtensionState for $outer {
            type ES = <$inner as $crate::HasExtensionState>::ES;
            fn extension_state(&self) -> &Self::ES {
                self.$field.extension_state()
            }
        }

        impl $crate::objects::tables::HasAddressTable for $outer {
            type ADT = <$inner as $crate::objects::tables::HasAddressTable>::ADT;
            fn adt(&self) -> &core::cell::RefCell<Self::ADT> {
                self.$field.adt()
            }
        }

        impl $crate::objects::tables::HasAssociationTable for $outer {
            type AST = <$inner as $crate::objects::tables::HasAssociationTable>::AST;
            fn ast(&self) -> &core::cell::RefCell<Self::AST> {
                self.$field.ast()
            }
        }

        impl $crate::objects::tables::HasCommunicationObjectTable for $outer {
            type COT = <$inner as $crate::objects::tables::HasCommunicationObjectTable>::COT;
            fn cot(&self) -> &core::cell::RefCell<Self::COT> {
                self.$field.cot()
            }
        }

        impl $crate::objects::comm::HasCommObjects for $outer {
            type CO = <$inner as $crate::objects::comm::HasCommObjects>::CO;
            fn comm_objects(&self) -> &core::cell::RefCell<Self::CO> {
                self.$field.comm_objects()
            }
        }

        impl $crate::objects::comm::HasGoSecurityView for $outer {
            fn required_security_for_asap(
                &self,
                asap: u16,
            ) -> $crate::__macro_support::messages::knx::RequiredSecurity {
                self.$field.required_security_for_asap(asap)
            }
            fn required_security_for_p2p(
                &self,
                peer_ia: u16,
            ) -> $crate::__macro_support::messages::knx::RequiredSecurity {
                self.$field.required_security_for_p2p(peer_ia)
            }
            fn required_security_for_broadcast(&self) -> $crate::__macro_support::messages::knx::RequiredSecurity {
                self.$field.required_security_for_broadcast()
            }
            fn required_security_for_tool_access(&self) -> $crate::__macro_support::messages::knx::RequiredSecurity {
                self.$field.required_security_for_tool_access()
            }
        }

        impl $crate::HasDiagnosticsContext for $outer {
            type Diagnostics = <$inner as $crate::HasDiagnosticsContext>::Diagnostics;
            fn diagnostics(&self) -> &Self::Diagnostics {
                self.$field.diagnostics()
            }
        }

        impl $crate::objects::tables::HasApplication for $outer {
            type APP = <$inner as $crate::objects::tables::HasApplication>::APP;
            fn app(&self) -> &core::cell::RefCell<Self::APP> {
                self.$field.app()
            }
        }

        impl $crate::objects::tables::HasPeiApplication for $outer {
            type PEI = <$inner as $crate::objects::tables::HasPeiApplication>::PEI;
            fn pei(&self) -> &core::cell::RefCell<Self::PEI> {
                self.$field.pei()
            }
        }

        impl $crate::objects::interface::HasRoutingCount for $outer {
            fn routing_count(&self) -> u8 {
                self.$field.routing_count()
            }
            fn set_routing_count(&self, value: u8) {
                self.$field.set_routing_count(value)
            }
        }

        impl $crate::__macro_support::access::HasConnectionAuth for $outer {
            fn connection_access(&self, slot: u8) -> $crate::__macro_support::access::AccessContext {
                self.$field.connection_access(slot)
            }
            fn set_connection_access(&self, slot: u8, ctx: $crate::__macro_support::access::AccessContext) {
                self.$field.set_connection_access(slot, ctx);
            }
            fn reset_connection_access(&self, slot: u8, default_level: u8) {
                self.$field.reset_connection_access(slot, default_level);
            }
        }
    };
}
