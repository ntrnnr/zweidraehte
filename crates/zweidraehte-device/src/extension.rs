//! Extension vocabulary — persistence and interface-object augmentation
//! for composable device extensions, independent of any BCU family.
//!
//! An *extension* is a unit of optional device functionality (a medium
//! extension like TP1 or IP, a security extension, …) that may contribute
//! two things to a stack:
//!
//! - **persistent state** — runtime state that survives power cycles
//!   through its persistent sections ([`ExtensionState`] plus
//!   [`ExtensionSections`](crate::sections::ExtensionSections)), and
//! - **interface-object augmentation** — extra objects or properties
//!   ([`Extension`], building an [`Augment`]).
//!
//! # `State` / `Resources` vocabulary
//!
//! - `*State` — the runtime form with interior mutability
//!   (`Cell`/`RefCell`). It is the only form of the configuration: a
//!   factory-fresh state comes from [`ExtensionState::new`], a configured one
//!   from applying the durable sections over it.
//! - `*Resources` — non-persistent construction-time inputs (pre-allocated
//!   channels, factory-programmed keys such as the FDSK, platform handles).
//!   Never persisted. Fed into [`ExtensionState::new`].
//!
//! Each BCU family adds its own device-level counterpart on top (for
//! System B: `SystemBStateInit` in [`crate::bcus::system_b`]).

use crate::{StackDefinition, objects::comm::HasGoSecurityView, restart::EraseCode, service::Augment};

/// The runtime state of an extension's persistent configuration.
///
/// The state's fields are interior-mutable, so accessor traits (e.g.
/// `IpStateView`, `HasMaxRetryCount`) and property handlers change them
/// through `&self`. Its sections persist them; each persisted record has
/// one factory value, which [`new`](Self::new), [`on_erase`](Self::on_erase)
/// and the section reset all take from the same constant.
pub trait ExtensionState: Sized {
    /// Construction-time inputs that are not configuration: platform-owned
    /// handles, and keys baked in at construction (the FDSK for secure
    /// extensions). Extensions without any use `()`.
    type Resources;

    /// A factory-fresh state.
    ///
    /// Callers construct `Resources` once and hand ownership over; the
    /// extension is fully valid the moment this call returns — no
    /// post-construction setters.
    fn new(resources: Self::Resources) -> Self;

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
    type Resources = ();

    fn new(_resources: ()) -> Self {}

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
