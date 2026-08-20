//! Ready-made System 7 stack types.
//!
//! System 7 keeps its product-defined communication-object-table address as
//! an explicit const parameter: unlike System B, the mask contributes no
//! device-side location resource for that table. Everything else in the
//! standard TP1 composition derives from the device descriptor.

use core::marker::PhantomData;

use crate::SecureRng;
use crate::StackDefinition;
use crate::bcus::system_7::{
    DefaultSystem7InterfaceObjects, System7DeviceModel, System7DeviceState, System7MemoryMap, System7ProductLayout,
    System7StackDefinition, System7StateInit, Tp1ExtensionState, create_system_7_objects,
};
use crate::bcus::system_b::{
    DiagnosticsAugment, Extension, GroupObjectTableAugment, SecureAugmentBundle, SecureExtensionState, SecureResources,
    WithSecureGoSend,
};
use crate::composition::{PlainDeviceBuilder, SecureDeviceBuilder};
use crate::context::layer::LayerContext;
use crate::layers::application::services::{StandardAlServices, StandardSecureAlServices};
use crate::layers::secure_application::{NoP2p, P2pFeature};
use crate::layers::transport::TlStyle;
use crate::profile::{DeviceDefinition, DeviceHooks};
use crate::service::AugmentChain;
use crate::storage::{HasDeviceConfig, HasSeqStore, SecureDeviceIdentity, SeqStorageFor};
use zweidraehte_proto::device::MaskVersion;

#[doc(hidden)]
pub const fn address_table_size(device: &zweidraehte_proto::device::DeviceDescriptor) -> usize {
    3 + device.max_address_table_entries as usize * 2
}

#[doc(hidden)]
pub const fn association_table_size(device: &zweidraehte_proto::device::DeviceDescriptor) -> usize {
    1 + device.max_association_table_entries as usize * 2
}

#[doc(hidden)]
pub const fn communication_object_table_size(device: &zweidraehte_proto::device::DeviceDescriptor) -> usize {
    3 + device.max_com_objects as usize * 4
}

#[doc(hidden)]
pub const fn address_table_entries(device: &zweidraehte_proto::device::DeviceDescriptor) -> usize {
    device.max_address_table_entries as usize
}

#[doc(hidden)]
pub const fn communication_object_entries(device: &zweidraehte_proto::device::DeviceDescriptor) -> usize {
    device.max_com_objects as usize
}

fn assert_table_capacities<D: StackDefinition, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize>() {
    assert!(ADT_SIZE == address_table_size(D::DEVICE), "address-table capacity differs from DEVICE");
    assert!(AST_SIZE == association_table_size(D::DEVICE), "association-table capacity differs from DEVICE");
    assert!(
        COT_SIZE == communication_object_table_size(D::DEVICE),
        "communication-object capacity differs from DEVICE"
    );
}

/// Plain System 7 TP1 stack (mask 0705).
///
/// `COT_ADDRESS` is the product database's absolute communication-object-table
/// placement. The trailing table-size parameters are implementation details;
/// their defaults encode the System 7 table formats and device code should
/// omit them.
pub struct Tp1<
    C: DeviceDefinition,
    const COT_ADDRESS: u16,
    const ADT_SIZE: usize = { address_table_size(C::DEVICE) },
    const AST_SIZE: usize = { association_table_size(C::DEVICE) },
    const COT_SIZE: usize = { communication_object_table_size(C::DEVICE) },
>(PhantomData<fn() -> C>);

impl<C, const COT_ADDRESS: u16, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize> Clone
    for Tp1<C, COT_ADDRESS, ADT_SIZE, AST_SIZE, COT_SIZE>
where
    C: DeviceDefinition,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<C, const COT_ADDRESS: u16, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize> Copy
    for Tp1<C, COT_ADDRESS, ADT_SIZE, AST_SIZE, COT_SIZE>
where
    C: DeviceDefinition,
{
}

impl<C, const COT_ADDRESS: u16, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize>
    Tp1<C, COT_ADDRESS, ADT_SIZE, AST_SIZE, COT_SIZE>
where
    C: DeviceDefinition,
    Self: StackDefinition<Mem = System7MemoryMap>,
{
    /// Construct the stateless System 7 memory map.
    pub const fn memory_map() -> System7MemoryMap {
        System7MemoryMap::new()
    }
}

impl<C, const COT_ADDRESS: u16, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize>
    System7ProductLayout for Tp1<C, COT_ADDRESS, ADT_SIZE, AST_SIZE, COT_SIZE>
where
    C: DeviceDefinition<Platform = ()>,
    C::Params: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    const COT_ADDRESS: u16 = COT_ADDRESS;
}

impl<C, const COT_ADDRESS: u16, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize> StackDefinition
    for Tp1<C, COT_ADDRESS, ADT_SIZE, AST_SIZE, COT_SIZE>
where
    C: DeviceDefinition<Platform = ()>,
    C::Params: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    const DEVICE: &'static zweidraehte_proto::device::DeviceDescriptor = C::DEVICE;
    const MAX_APDU_LENGTH: u16 = C::MAX_APDU_LENGTH;
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = C::DEVICE_DESCRIPTOR_TYPE2;
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = C::USER_MANUFACTURER_INFO;
    const FIRST_ASAP: u16 = 0;
    const TL_STYLE: TlStyle = TlStyle::Style3;

    type Mutex = C::Mutex;
    type Rng = C::Rng;
    type Platform = C::Platform;
    type P = C::Params;
    type CO = C::ComObjects;
    type LLB = C::LinkLayer;
    type ES = Tp1ExtensionState;
    type State = System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, Self, Tp1ExtensionState>;
    type Identity = C::Identity;
    type Storage = C::Storage;
    type StateInit = System7StateInit<Self::Identity, <Self::State as HasDeviceConfig>::Config>;

    fn create_state(init: Self::StateInit) -> Self::State {
        assert!(
            matches!(Self::DEVICE.mask_version, MaskVersion::System7Tp1),
            "System 7 TP1 preset requires a 0705 descriptor"
        );
        assert_table_capacities::<Self, ADT_SIZE, AST_SIZE, COT_SIZE>();
        Self::State::from_init(init)
    }

    type Mem = System7MemoryMap;

    type Augments<'a>
        = AugmentChain<
        <Tp1ExtensionState as Extension<()>>::Augment<'a, Self>,
        <C::Hooks as DeviceHooks>::Augments<'a, Self>,
    >
    where
        Self::State: 'a,
        Self::Platform: 'a;

    fn create_augments<'a>(
        state: &'a Self::State,
        platform: &'a Self::Platform,
        layer_ctx: &'a LayerContext<Self>,
    ) -> Self::Augments<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        let profile = state.extension_state().create_augment::<Self>(platform);
        let device = C::Hooks::create_augments::<Self>(state, platform, layer_ctx);
        AugmentChain::new(profile, device)
    }

    type InterfaceObjects<'a>
        = DefaultSystem7InterfaceObjects<'a, Self, Self::Augments<'a>>
    where
        Self::State: 'a;

    fn create_interface_objects<'a>(
        state: &'a Self::State,
        _platform: &'a Self::Platform,
        layer_ctx: &'a LayerContext<Self>,
        augments: &'a Self::Augments<'a>,
    ) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        create_system_7_objects::<Self, _>(state, layer_ctx, augments)
    }

    type AlExtensions = StandardAlServices;

    type DeviceModel<'a>
        = System7DeviceModel<'a, Self>
    where
        Self::State: 'a;

    fn create_device_model<'a>(
        state: &'a Self::State,
        layer_ctx: &'a LayerContext<Self>,
        interface_objects: &'a Self::InterfaceObjects<'static>,
    ) -> Self::DeviceModel<'a>
    where
        Self::State: 'a,
    {
        System7DeviceModel::new(state, layer_ctx, interface_objects)
    }

    type LayerBuilder = PlainDeviceBuilder;
}

/// KNX Data Secure System 7 TP1 stack.
///
/// Data Security is composed as a profile module without changing the 0705
/// mask. The preset adds the Security Interface Object and, because System 7's
/// base object roster has no Group Object Table Object, supplies that object as
/// the mandatory home of GO Diagnostics. Group-only devices use the default
/// `NoP2p`/zero-key-table configuration.
pub struct SecureTp1<
    C: DeviceDefinition,
    const COT_ADDRESS: u16,
    P2P: P2pFeature = NoP2p,
    const P2P_KEYS: usize = 0,
    const ADT_SIZE: usize = { address_table_size(C::DEVICE) },
    const AST_SIZE: usize = { association_table_size(C::DEVICE) },
    const COT_SIZE: usize = { communication_object_table_size(C::DEVICE) },
    const ADT_ENTRIES: usize = { address_table_entries(C::DEVICE) },
    const COT_ENTRIES: usize = { communication_object_entries(C::DEVICE) },
>(PhantomData<fn() -> (C, P2P)>);

impl<
    C: DeviceDefinition,
    const COT_ADDRESS: u16,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> Clone for SecureTp1<C, COT_ADDRESS, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<
    C: DeviceDefinition,
    const COT_ADDRESS: u16,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> Copy for SecureTp1<C, COT_ADDRESS, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
{
}

impl<
    C: DeviceDefinition,
    const COT_ADDRESS: u16,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> System7StackDefinition
    for SecureTp1<C, COT_ADDRESS, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
where
    Self: StackDefinition<Mem = System7MemoryMap> + System7ProductLayout,
{
    const ADT_SIZE: usize = ADT_SIZE;
    const AST_SIZE: usize = AST_SIZE;
    const COT_SIZE: usize = COT_SIZE;
    const ADT_ENTRIES: usize = ADT_ENTRIES;
    const COT_ENTRIES: usize = COT_ENTRIES;
}

impl<
    C,
    const COT_ADDRESS: u16,
    P2P,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> SecureTp1<C, COT_ADDRESS, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
where
    C: DeviceDefinition,
    P2P: P2pFeature,
    Self: StackDefinition<Mem = System7MemoryMap>,
{
    /// Construct the stateless System 7 memory map.
    pub const fn memory_map() -> System7MemoryMap {
        System7MemoryMap::new()
    }
}

impl<
    C,
    const COT_ADDRESS: u16,
    P2P,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> System7ProductLayout
    for SecureTp1<C, COT_ADDRESS, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
where
    C: DeviceDefinition<Platform = ()>,
    C::Params: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
    C::Identity: SecureDeviceIdentity,
    C::Rng: SecureRng,
    P2P: P2pFeature,
{
    const COT_ADDRESS: u16 = COT_ADDRESS;
}

impl<
    C,
    const COT_ADDRESS: u16,
    P2P,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> StackDefinition for SecureTp1<C, COT_ADDRESS, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
where
    C: DeviceDefinition<Platform = ()>,
    C::Params: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
    C::Identity: SecureDeviceIdentity,
    C::Rng: SecureRng,
    C::Storage: HasSeqStore,
    P2P: P2pFeature,
{
    const DEVICE: &'static zweidraehte_proto::device::DeviceDescriptor = C::DEVICE;
    const MAX_APDU_LENGTH: u16 = C::MAX_APDU_LENGTH;
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = C::DEVICE_DESCRIPTOR_TYPE2;
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = C::USER_MANUFACTURER_INFO;
    const FIRST_ASAP: u16 = 0;
    const TL_STYLE: TlStyle = TlStyle::Style3;

    type Mutex = C::Mutex;
    type Rng = C::Rng;
    type Platform = C::Platform;
    type P = C::Params;
    type CO = C::ComObjects;
    type LLB = C::LinkLayer;
    type ES = SecureExtensionState<Tp1ExtensionState, ADT_ENTRIES, P2P_KEYS, COT_ENTRIES>;
    type State = System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, Self, Self::ES>;
    type Identity = C::Identity;
    type Storage = C::Storage;
    type StateInit =
        System7StateInit<Self::Identity, <Self::State as HasDeviceConfig>::Config, SecureResources<Tp1ExtensionState>>;

    fn create_state(init: Self::StateInit) -> Self::State {
        assert!(
            matches!(Self::DEVICE.mask_version, MaskVersion::System7Tp1),
            "System 7 TP1 preset requires a 0705 descriptor"
        );
        assert_table_capacities::<Self, ADT_SIZE, AST_SIZE, COT_SIZE>();
        assert!(
            ADT_ENTRIES == Self::DEVICE.max_address_table_entries as usize,
            "group-key capacity differs from DEVICE"
        );
        assert!(COT_ENTRIES == Self::DEVICE.max_com_objects as usize, "GO-security capacity differs from DEVICE");
        assert!(P2P::ENABLED || P2P_KEYS == 0, "P2P key capacity requires P2P support");
        Self::State::from_init(init)
    }

    type Mem = System7MemoryMap;

    type Augments<'a>
        = AugmentChain<
        SecureAugmentBundle<
            'a,
            <Tp1ExtensionState as Extension<()>>::Augment<'a, Self>,
            SeqStorageFor<Self>,
            ADT_ENTRIES,
            P2P_KEYS,
            COT_ENTRIES,
        >,
        AugmentChain<
            GroupObjectTableAugment,
            AugmentChain<DiagnosticsAugment<'a, WithSecureGoSend>, <C::Hooks as DeviceHooks>::Augments<'a, Self>>,
        >,
    >
    where
        Self::State: 'a,
        Self::Platform: 'a;

    fn create_augments<'a>(
        state: &'a Self::State,
        platform: &'a Self::Platform,
        layer_ctx: &'a LayerContext<Self>,
    ) -> Self::Augments<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        let secure = state.extension_state().create_secure_augment(platform, layer_ctx);
        let diagnostics = DiagnosticsAugment::<WithSecureGoSend>::new(&state.operation_mode);
        let device = C::Hooks::create_augments::<Self>(state, platform, layer_ctx);
        AugmentChain::new(
            secure,
            AugmentChain::new(GroupObjectTableAugment::new(), AugmentChain::new(diagnostics, device)),
        )
    }

    type InterfaceObjects<'a>
        = DefaultSystem7InterfaceObjects<'a, Self, Self::Augments<'a>>
    where
        Self::State: 'a;

    fn create_interface_objects<'a>(
        state: &'a Self::State,
        _platform: &'a Self::Platform,
        layer_ctx: &'a LayerContext<Self>,
        augments: &'a Self::Augments<'a>,
    ) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        create_system_7_objects::<Self, _>(state, layer_ctx, augments)
    }

    type AlExtensions = StandardSecureAlServices;

    type DeviceModel<'a>
        = System7DeviceModel<'a, Self>
    where
        Self::State: 'a;

    fn create_device_model<'a>(
        state: &'a Self::State,
        layer_ctx: &'a LayerContext<Self>,
        interface_objects: &'a Self::InterfaceObjects<'static>,
    ) -> Self::DeviceModel<'a>
    where
        Self::State: 'a,
    {
        System7DeviceModel::new(state, layer_ctx, interface_objects)
    }

    type LayerBuilder = SecureDeviceBuilder<P2P>;
}
