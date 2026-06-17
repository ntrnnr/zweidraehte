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

// ============================================================================
// Trait-forwarding macro
// ============================================================================

/// Forward a medium-accessor trait to a struct field by pure delegation.
///
/// Two layers of the System B stack re-expose the same accessor traits by
/// forwarding every method to a field:
///
/// - **`SystemBDeviceState`** re-exposes the extension's accessor traits by
///   forwarding to its `extension_state` field, so the router and link
///   layers reach them through `D::State` without knowing the concrete
///   `ES`. Setters additionally call `self.mark_dirty()` so the runtime
///   change is persisted on the next save.
/// - **Wrapper extensions** (`SecureExtensionState`, which wraps any inner
///   extension, and `RfRetransmitterExtension`, which wraps
///   `RfExtensionState`) stay *transparent* to the inner extension's
///   accessor traits by forwarding to their `inner` field. These have no
///   persistence side-effect — the device state above is what marks dirty.
///
/// In every case the body is mechanical: each method calls
/// `self.<field>.<same method>(<same args>)`. This macro generates that
/// delegation from the method signatures alone, so a call site declares
/// only *which* traits it forwards, the target field, and (for the device
/// state) whether setters mark the device dirty.
///
/// # Invocation shapes
///
/// The impl header is passed as a bracketed generics list plus the target
/// type; an empty `[]` is a non-generic impl. After the body block the
/// target field is named with `=> self.<field>`, optionally followed by
/// `, mark_dirty` to fire `self.mark_dirty()` at the end of every setter.
///
/// ```ignore
/// // SystemBDeviceState: forward to `extension_state`, dirty on write.
/// forward_to_field! {
///     impl<[const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize,
///           D: StackDefinition, ES: ExtensionState + HasMaxRetryCount]>
///         HasMaxRetryCount for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>
///     {
///         get fn max_retry_count(&self) -> u8;
///         set fn set_max_retry_count(&self, value: u8);
///     } => self.extension_state, mark_dirty
/// }
///
/// // Wrapper extension: forward to `inner`, no side-effect. Buffer-output
/// // and associated-const items are supported.
/// forward_to_field! {
///     impl<[Inner: ExtensionState + HasDomainAddress, SEQ,
///           const GRP: usize, const P2P: usize, const GO: usize]>
///         HasDomainAddress for SecureExtensionState<Inner, SEQ, GRP, P2P, GO>
///     {
///         const DOMAIN_ADDRESS_LENGTH: usize = Inner::DOMAIN_ADDRESS_LENGTH;
///         out fn domain_address(&self, buf: &mut [u8]);
///         set fn set_domain_address(&self, addr: &[u8]);
///     } => self.inner
/// }
/// ```
///
/// Each item carries a kind keyword that disambiguates the method form
/// (`get` returns by value, `set` takes args and returns unit, `out` takes
/// args and returns unit — `set` vs `out` differ only in whether the
/// `mark_dirty` post-hook fires). The keywords also keep the `fn name(&self`
/// prefix — common to every form — unambiguous to the macro matcher.
macro_rules! forward_to_field {
    // Generic header (possibly empty `[]`), no `mark_dirty`.
    (
        impl<[$($generics:tt)*]> $trait:ident for $self_ty:ty {
            $($items:tt)*
        } => self.$field:ident
    ) => {
        impl<$($generics)*> $trait for $self_ty {
            forward_to_field!(@items [no_dirty] $field, $($items)*);
        }
    };

    // Generic header (possibly empty `[]`), setters fire `mark_dirty`.
    (
        impl<[$($generics:tt)*]> $trait:ident for $self_ty:ty {
            $($items:tt)*
        } => self.$field:ident, mark_dirty
    ) => {
        impl<$($generics)*> $trait for $self_ty {
            forward_to_field!(@items [dirty] $field, $($items)*);
        }
    };

    // ---- item expansion ----------------------------------------------------
    // Peels one item at a time so consts and the method kinds each get their
    // own shape; `$dirty` carries the setter post-hook policy. Ends on the
    // empty tail.
    (@items [$dirty:tt] $field:ident,) => {};

    // Associated const, carrying its own value expression.
    (@items [$dirty:tt] $field:ident, const $name:ident: $ty:ty = $value:expr; $($rest:tt)*) => {
        const $name: $ty = $value;
        forward_to_field!(@items [$dirty] $field, $($rest)*);
    };

    // `get`: returns by value, with or without arguments (never dirties —
    // a read forwards verbatim).
    (@items [$dirty:tt] $field:ident, get fn $method:ident(&self $(, $arg:ident: $arg_ty:ty)* $(,)?) -> $ret:ty; $($rest:tt)*) => {
        fn $method(&self $(, $arg: $arg_ty)*) -> $ret {
            self.$field.$method($($arg),*)
        }
        forward_to_field!(@items [$dirty] $field, $($rest)*);
    };

    // `set`: args, returns unit, fires `mark_dirty` iff the policy is `[dirty]`.
    (@items [dirty] $field:ident, set fn $method:ident(&self, $($arg:ident: $arg_ty:ty),+ $(,)?); $($rest:tt)*) => {
        fn $method(&self, $($arg: $arg_ty),+) {
            self.$field.$method($($arg),+);
            self.mark_dirty();
        }
        forward_to_field!(@items [dirty] $field, $($rest)*);
    };
    (@items [no_dirty] $field:ident, set fn $method:ident(&self, $($arg:ident: $arg_ty:ty),+ $(,)?); $($rest:tt)*) => {
        fn $method(&self, $($arg: $arg_ty),+) {
            self.$field.$method($($arg),+);
        }
        forward_to_field!(@items [no_dirty] $field, $($rest)*);
    };

    // `out`: args (output-buffer form), returns unit, never dirties.
    (@items [$dirty:tt] $field:ident, out fn $method:ident(&self, $($arg:ident: $arg_ty:ty),+ $(,)?); $($rest:tt)*) => {
        fn $method(&self, $($arg: $arg_ty),+) {
            self.$field.$method($($arg),+);
        }
        forward_to_field!(@items [$dirty] $field, $($rest)*);
    };
}

// `forward_to_field!` is visible to every child module declared below by
// textual macro scoping; no `use` re-export is needed.

mod definition;
mod device_state;
mod extensions;
mod memory_map;
mod objects;
mod storage;

pub use definition::*;
pub use device_state::*;
pub use extensions::*;
pub use memory_map::*;
pub use objects::*;
pub use storage::*;

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
/// trait with hand-picked items, use [`forward_to_field!`] instead.
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
