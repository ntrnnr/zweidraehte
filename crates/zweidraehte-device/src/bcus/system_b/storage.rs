//! Persistence infrastructure for System B devices.
//!
//! This module provides [`SystemBStateInit`], the constructor-args envelope
//! for a System B device state. The BCU-agnostic extension vocabulary —
//! [`ExtensionState`] and the [`Extension`] trait unifying persistence with
//! interface object augmentation — lives in [`crate::extension`] and is
//! re-exported here.
//!
//! A device's configuration has one form, the runtime state: a factory-fresh
//! state comes from `SystemBDeviceState::new`, and the stored configuration
//! is applied over it as persistent sections when the stack is built (see
//! [`crate::sections`]). The storage framework lives in [`crate::storage`].
//!
//! # Two Composition Paths
//!
//! ## Persisted extensions (`Extension<Platform>`)
//!
//! For state that must survive power cycles and also contributes interface
//! object properties. Implement [`ExtensionState`] and
//! [`ExtensionSections`](crate::sections::ExtensionSections) for persistence
//! and [`Extension`] for augmentation. The augment is built by
//! [`StackDefinition::create_augments`](crate::StackDefinition::create_augments)
//! via `state.extension_state().create_augment::<Self>(platform)`,
//! and passed into the IO container by the runner.
//!
//! Examples: TP1 retry count, KNX/IP config, Security Interface Object.
//!
//! ## Runtime-only augments
//!
//! For state that does NOT survive power cycles and therefore needs no
//! persistent sections. Store the state as a field on your state type
//! (either a custom wrapper or `SystemBDeviceState`) and add the augment as
//! a `#[service(augment)]` field on the device's
//! [`#[derive(ServiceRegistry)]`](crate::service::ServiceRegistry)
//! augment-bundle struct. Access the state from layers via a `Has*`
//! context trait.
//!
//! Examples: `OperationModeState` (diagnostic mode), `CertificationObjectAugment`.

pub use crate::extension::{Extension, ExtensionState};

// ============================================================================
// SystemBStateInit — boilerplate-free `StateInit` envelope for System B
// ============================================================================

/// Standard `StateInit` shape for [`SystemBDeviceState`](super::SystemBDeviceState)-based devices.
///
/// Bundles the two things every System B device's `create_state` needs:
///
/// - `identity` — factory-programmed identity, threaded into the state.
/// - `resources` — construction inputs for the extension state that are not
///   configuration. `()` for non-secure stacks; for KNX Data Secure stacks, a
///   [`SecureResources`](super::SecureResources) carrying the FDSK.
///
/// Pair with [`SystemBDeviceState::from_init`](super::SystemBDeviceState::from_init):
///
/// ```rust,ignore
/// type StateInit = SystemBStateInit<MyIdentity>;
///
/// fn create_state(init: Self::StateInit) -> Self::State {
///     <Self::State>::from_init(init)
/// }
/// ```
///
/// Devices with a non-`()` resource type (secure stacks) use the second type
/// parameter:
///
/// ```rust,ignore
/// type StateInit = SystemBStateInit<FlashSecureIdentityData, SecureResources<()>>;
/// ```
pub struct SystemBStateInit<I, R = ()> {
    /// Factory-programmed device identity.
    pub identity: I,
    /// Construction inputs for the extension state that are not configuration.
    pub resources: R,
}

impl<I> SystemBStateInit<I, ()> {
    /// The init envelope for a non-secure stack (resources defaulted to `()`).
    pub fn new(identity: I) -> Self {
        Self { identity, resources: () }
    }
}
