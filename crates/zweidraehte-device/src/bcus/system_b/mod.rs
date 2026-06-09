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
///           const GRP: usize, const P2P: usize, const SIAT: usize, const GO: usize]>
///         HasDomainAddress for SecureExtensionState<Inner, SEQ, GRP, P2P, SIAT, GO>
///     {
///         const DOMAIN_ADDRESS_LENGTH: usize = Inner::DOMAIN_ADDRESS_LENGTH;
///         out fn domain_address(&self, buf: &mut [u8]);
///         out fn set_domain_address(&self, addr: &[u8]);
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
