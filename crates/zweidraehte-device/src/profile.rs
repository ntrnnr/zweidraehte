//! Inputs shared by the standard stack presets.
//!
//! Normal firmware implements [`DeviceDefinition`] and selects a ready-made
//! stack type, for example `bcus::system_b::Tp1<MyDevice>`. The preset owns the
//! correlated state, services, interface objects, and layer composition.
//!
//! Unusual devices remain free to implement [`StackDefinition`] directly. A
//! reusable custom preset is just another generic type with a
//! `StackDefinition` implementation, following the same pattern as the built-in
//! presets.

use const_default::ConstDefault;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use zerocopy::{Immutable, IntoBytes, KnownLayout};
use zweidraehte_proto::device::DeviceDescriptor;

use crate::context::layer::LayerContext;
use crate::layers::LinkLayerBuilderBase;
use crate::objects::comm::{ComObjectBusHook, ComObjects};
use crate::rng::{NoRng, Rng};
use crate::service::Augment;
use crate::storage::{DeviceIdentity, StaticIdentity};
use crate::{StackDefinition, config};

/// Product, application, and hardware choices consumed by standard presets.
///
/// The trait deliberately contains no protocol-stack internals. Choosing
/// `Tp1<Self>`, `Rf<Self>`, or another preset is what supplies those correlated
/// types; it is not another associated type hidden inside this definition.
pub trait DeviceDefinition: 'static {
    /// Device and application-program descriptor.
    const DEVICE: &'static DeviceDescriptor;

    /// Maximum wire APDU length used for compile-time buffer allocation.
    const MAX_APDU_LENGTH: u16 = config::MAX_APDU_LENGTH_EXTENDED;

    /// Optional Device Descriptor Type 2.
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = None;

    /// Optional three-byte User Manufacturer Info payload.
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = None;

    /// Mutex used by channels shared with application tasks.
    type Mutex: RawMutex + 'static = NoopRawMutex;

    /// Random source used by secure presets.
    type Rng: Rng = NoRng;

    /// Platform state, normally `()` outside KNX/IP devices.
    type Platform: 'static = ();

    /// ETS application parameter block.
    type Params: ConstDefault + IntoBytes + KnownLayout + Immutable;

    /// Communication-object container.
    type ComObjects: ComObjects + ComObjectBusHook;

    /// Physical/link-layer builder selected by the hardware integration.
    type LinkLayer: LinkLayerBuilderBase;

    /// Factory-programmed identity.
    type Identity: DeviceIdentity = StaticIdentity;

    /// Persistent-storage capability bundle.
    type Storage: Copy + 'static = ();

    /// Optional application-specific interface-object hooks.
    ///
    /// Presets install their mandatory medium/security augments first and append
    /// these hooks afterwards.
    type Hooks: DeviceHooks = NoDeviceHooks;
}

/// Application-specific augment provider for standard stack presets.
///
/// The provider is generic over the resolved stack at the method level. This
/// keeps the definition independent of the preset that consumes it and lets
/// [`NoDeviceHooks`] work for every standard stack without a recursive trait
/// bound.
pub trait DeviceHooks {
    /// Augment bundle contributed by the application.
    type Augments<'a, D: StackDefinition>: Augment<D>;

    /// Construct the application-specific augment bundle.
    fn create_augments<'a, D: StackDefinition>(
        state: &'a D::State,
        platform: &'a D::Platform,
        layer_ctx: &'a LayerContext<D>,
    ) -> Self::Augments<'a, D>;
}

/// Default hook provider for devices with no application-specific augments.
pub struct NoDeviceHooks;

impl DeviceHooks for NoDeviceHooks {
    type Augments<'a, D: StackDefinition> = ();

    fn create_augments<'a, D: StackDefinition>(
        _state: &'a D::State,
        _platform: &'a D::Platform,
        _layer_ctx: &'a LayerContext<D>,
    ) -> Self::Augments<'a, D> {
    }
}
