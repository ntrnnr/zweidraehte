//! Extension vocabulary — persistence and interface-object augmentation
//! for composable device extensions, independent of any BCU family.
//!
//! An *extension* is a unit of optional device functionality (a medium
//! extension like TP1 or IP, a security extension, …) that may contribute
//! two things to a stack:
//!
//! - **persistent state** — survives power cycles, round-trips through
//!   storage ([`ExtensionState`] / [`ExtensionConfig`]), and
//! - **interface-object augmentation** — extra objects or properties
//!   ([`Extension`], building an [`Augment`]).
//!
//! # `Config` / `State` / `Resources` vocabulary
//!
//! The three suffixes carry stable meaning across the stack:
//!
//! - `*Config` — serialisable persisted form. Round-trips through `serde`.
//! - `*State` — runtime in-memory form with interior mutability
//!   (`Cell`/`RefCell`). Converts to/from `Config` via
//!   [`ExtensionState::from_config`] / [`ExtensionState::to_config`].
//! - `*Resources` — non-persistent construction-time inputs (pre-allocated
//!   channels, `MaybeUninit` buffers, factory-programmed keys such as
//!   FDSK, platform handles). Never serialised. Fed into
//!   [`ExtensionState::from_config`] as the second argument.
//!
//! Each BCU family adds its own device-level counterparts on top (for
//! System B: `DeviceConfig` and `SystemBStateInit` in
//! [`crate::bcus::system_b`]).

use serde::{Deserialize, Serialize};

/// `#[derive(ExtensionState)]` — generates the `*Config` mirror and the
/// `ExtensionState` impl from a runtime `*State` struct. Shares the trait's
/// name so a single `use` brings both into scope.
pub use zweidraehte_device_macros::ExtensionState;

use crate::{StackDefinition, objects::comm::HasGoSecurityView, restart::EraseCode, service::Augment};

/// Trait for extension-specific persistent configuration.
///
/// Each extension state type has a corresponding config type that
/// implements this trait. The config is what gets serialized to storage.
/// Implementations must be serializable and provide factory defaults.
pub trait ExtensionConfig: Default + Serialize + for<'de> Deserialize<'de> {}

impl ExtensionConfig for () {}

// Tuple combinator. Aggregating extension types like
// `IpInterfaceExtension` (IP + tunnelling) carry a tuple of inner
// configs as their `ExtensionState::Config`; this blanket impl lets
// the tuple round-trip through storage without a wrapping newtype.
// `serde` already derives `Serialize` / `Deserialize` for tuples
// whose elements satisfy them, and `Default` for the unit value
// `(A::default(), B::default())` is automatic.
impl<A: ExtensionConfig, B: ExtensionConfig> ExtensionConfig for (A, B) {}

/// Runtime state for extension-specific persistent configuration.
///
/// This trait bridges the serializable config ([`ExtensionConfig`]) and
/// the runtime representation with interior mutability (`Cell`/`RefCell`
/// fields). The runtime form allows `&self` mutation through accessor
/// traits (e.g., `IpStateView`, `HasMaxRetryCount`), while the config
/// form is what gets serialized.
///
/// Devices that need multiple extension concerns (e.g., IP config +
/// custom augment state) should define a single struct that combines
/// them and implements this trait directly.
///
/// For the common leaf-extension case — where the persisted config is
/// the runtime state with `Cell`/`RefCell` unwrapped — derive this trait
/// (and its `*Config` mirror) with `#[derive(ExtensionState)]` instead of
/// hand-writing `from_config`/`to_config`/`on_erase`. The derive shares
/// this trait's name; `use zweidraehte_device::extension::ExtensionState`
/// brings both the trait and the derive into scope.
pub trait ExtensionState: Sized {
    /// The serializable config type for this extension state.
    type Config: ExtensionConfig;

    /// Non-serialisable construction inputs.
    ///
    /// Bundles platform-owned handles (sequence-number storage), keys
    /// that must be baked into the extension at construction time (the
    /// FDSK for secure extensions), and similar resources that cannot
    /// live in [`Self::Config`] because they do not round-trip through
    /// serde. Extensions without such resources use `()`.
    type Resources;

    /// Create runtime state from a persisted config and construction-time
    /// resources.
    ///
    /// Callers construct `Resources` once and hand ownership over; the
    /// extension is fully valid the moment this call returns — no
    /// post-construction setters.
    fn from_config(config: Self::Config, resources: Self::Resources) -> Self;

    /// Export current runtime state to serializable config.
    fn to_config(&self) -> Self::Config;

    /// Handle an erase code from a master reset.
    ///
    /// Extensions decide per-code what to clear. Called from the device
    /// state during `factory_reset()` and `execute_reset()`. Secure
    /// extensions fold the FDSK tool-key re-seed into the
    /// `FactoryReset` arm so the caller does not need to know about it
    /// (03/05/01 §6.1.4).
    fn on_erase(&self, code: EraseCode);
}

// The empty extension state has no security policy — every send is plain.
impl HasGoSecurityView for () {}

impl ExtensionState for () {
    type Config = ();
    type Resources = ();

    fn from_config(_config: (), _resources: ()) -> Self {}

    fn to_config(&self) {}

    fn on_erase(&self, _code: EraseCode) {
        // No extension state to reset.
    }
}

/// A medium extension that contributes persistent state AND interface
/// object augmentation to the device stack.
///
/// Unifies [`ExtensionState`] (persistence) with
/// [`Augment<D>`](crate::service::Augment) (property
/// handling) into a single concept. Each extension knows how to create
/// its own augment given a reference to the platform.
///
/// # Type Parameter
///
/// `Platform` flows from [`StackDefinition::Platform`].
/// Extensions that need no external context (e.g., TP1) use `Platform = ()`.
/// Extensions that need platform state (e.g., IP) are generic over
/// `P: IpPlatform`.
///
/// # Implementations
///
/// - `()` — no extension, no augment
/// - [`Tp1ExtensionState`](crate::bcus::system_b::Tp1ExtensionState) — creates a
///   [`Tp1Augment`](crate::bcus::system_b::Tp1Augment) borrowing self
/// - [`IpExtensionState`](crate::bcus::system_b::IpExtensionState) — creates an
///   [`IpAugment`](crate::bcus::system_b::IpAugment) from self + platform
pub trait Extension<Platform = ()>: ExtensionState {
    /// The augment type this extension creates.
    ///
    /// Bound is [`Augment<D>`](crate::service::Augment)
    /// — the trait surface the IO container dispatches through.
    /// Leaf augments satisfy it via `#[interface_object_augment]`
    /// codegen; composed bundles satisfy it via
    /// [`#[derive(ServiceRegistry)]`](crate::service::ServiceRegistry);
    /// the `()` impl covers the no-augment case.
    ///
    /// For TP1: `Tp1Augment<'a>` (borrows the extension state).
    /// For IP: `IpAugment<'a, P, CAPS>` (wraps extension + platform).
    /// For `Secure(Inner)`: `SecureAugmentBundle<'a, Inner::Augment, …>`
    ///   (a `#[derive(ServiceRegistry)]` struct holding the inner
    ///   augment plus `SecurityAugment`).
    /// For `()`: `()` (no augmentation).
    type Augment<'a, D: StackDefinition>: Augment<D>
    where
        Self: 'a,
        Platform: 'a;

    /// Create the augment from this extension state and the platform.
    fn create_augment<'a, D: StackDefinition>(&'a self, platform: &'a Platform) -> Self::Augment<'a, D>
    where
        Platform: 'a;
}

impl Extension<()> for () {
    type Augment<'a, D: StackDefinition>
        = ()
    where
        Self: 'a;

    fn create_augment<'a, D: StackDefinition>(&'a self, _platform: &'a ()) -> Self::Augment<'a, D>
    where
        (): 'a,
    {
    }
}
