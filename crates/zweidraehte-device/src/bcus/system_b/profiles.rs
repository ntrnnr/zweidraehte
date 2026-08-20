//! Ready-made System B stack types.
//!
//! Each preset is a generic zero-sized device type with a direct
//! [`StackDefinition`] implementation. Its definition parameter supplies only
//! product/application/hardware choices; the preset supplies the protocol
//! composition as one coherent unit.

use core::marker::PhantomData;

use crate::SecureRng;
use crate::StackDefinition;
use crate::bcus::system_b::{
    DefaultSystemBInterfaceObjects, DiagnosticsAugment, Extension, MemoryLayout, RfExtensionState,
    RfRetransmitterExtension, SecureAugmentBundle, SecureExtensionState, SecureResources, SystemBDeviceModel,
    SystemBDeviceState, SystemBMemoryMap, SystemBStackDefinition, SystemBStateInit, Tp1ExtensionState,
    WithSecureGoSend, create_system_b_objects,
};
use crate::composition::{PlainDeviceBuilder, SecureDeviceBuilder};
use crate::context::layer::LayerContext;
use crate::layers::application::services::{DomainAddressService, RfDomainAddressService, StandardSecureAlServices};
use crate::layers::secure_application::{NoP2p, P2pFeature};
use crate::layers::transport::TlStyle;
use crate::profile::{DeviceDefinition, DeviceHooks};
use crate::service::AugmentChain;
use crate::storage::{HasDeviceConfig, HasSeqStore, SecureDeviceIdentity, SeqStorageFor};
use zweidraehte_proto::device::MaskVersion;

#[cfg(feature = "knxip")]
use crate::IpPlatform;
#[cfg(feature = "ip-secure")]
use crate::bcus::system_b::IpSecureInterfaceExtension;
#[cfg(feature = "knxip")]
use crate::bcus::system_b::{IpExtensionState, IpInterfaceExtension};
#[cfg(feature = "knxip")]
use crate::composition::PlainIpDeviceBuilder;
#[cfg(feature = "ip-secure")]
use crate::composition::SecureIpDeviceBuilder;
#[cfg(feature = "knxip")]
use crate::layers::linklayers::knxip::{
    KnxNetIpDefinition,
    features::{FeatureSet, TunnelingFeature},
};

fn memory_layout<D: StackDefinition>() -> MemoryLayout {
    MemoryLayout::from_descriptor(SystemBMemoryMap::DEFAULT_BASE_ADDRESS, D::DEVICE, core::mem::size_of::<D::P>())
}

fn memory_map<D: StackDefinition>() -> SystemBMemoryMap {
    SystemBMemoryMap::new(memory_layout::<D>())
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
    // Rust currently cannot normalize these descriptor-derived expressions
    // directly inside a generic `State` type without overflowing trait
    // resolution. Defaulted const parameters keep normal preset types concise;
    // reject explicit values that would break the descriptor invariant.
    assert!(ADT_SIZE == D::DEVICE.address_table_size(), "address-table capacity differs from DEVICE");
    assert!(AST_SIZE == D::DEVICE.association_table_size(), "association-table capacity differs from DEVICE");
    assert!(COT_SIZE == D::DEVICE.comm_object_table_size(), "communication-object capacity differs from DEVICE");
}

/// Plain System B TP1 stack (mask family 07B0).
///
/// `C` supplies the product and hardware choices through
/// [`DeviceDefinition`]. The link-layer builder remains a definition input
/// because selecting UARTs and pins is hardware integration, not a KNX profile
/// choice. The trailing const parameters are implementation details whose
/// defaults derive table capacities from `C::DEVICE`; device code should omit
/// them so the descriptor remains the single source of truth.
pub struct Tp1<
    C: DeviceDefinition,
    const ADT_SIZE: usize = { C::DEVICE.address_table_size() },
    const AST_SIZE: usize = { C::DEVICE.association_table_size() },
    const COT_SIZE: usize = { C::DEVICE.comm_object_table_size() },
>(PhantomData<fn() -> C>);

impl<C, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize> Clone
    for Tp1<C, ADT_SIZE, AST_SIZE, COT_SIZE>
where
    C: DeviceDefinition,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<C, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize> Copy
    for Tp1<C, ADT_SIZE, AST_SIZE, COT_SIZE>
where
    C: DeviceDefinition,
{
}

impl<C, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize> Tp1<C, ADT_SIZE, AST_SIZE, COT_SIZE>
where
    C: DeviceDefinition,
    Self: StackDefinition<Mem = SystemBMemoryMap>,
{
    /// Construct the descriptor-derived System B memory map.
    pub fn memory_map() -> SystemBMemoryMap {
        memory_map::<Self>()
    }
}

impl<C, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize> StackDefinition
    for Tp1<C, ADT_SIZE, AST_SIZE, COT_SIZE>
where
    C: DeviceDefinition<Platform = ()>,
    C::Params: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    const DEVICE: &'static zweidraehte_proto::device::DeviceDescriptor = C::DEVICE;
    const MAX_APDU_LENGTH: u16 = C::MAX_APDU_LENGTH;
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = C::DEVICE_DESCRIPTOR_TYPE2;
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = C::USER_MANUFACTURER_INFO;
    const FIRST_ASAP: u16 = 1;
    const TL_STYLE: TlStyle = TlStyle::Style3;

    type Mutex = C::Mutex;
    type Rng = C::Rng;
    type Platform = C::Platform;
    type P = C::Params;
    type CO = C::ComObjects;
    type LLB = C::LinkLayer;
    type ES = Tp1ExtensionState;
    type State = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, Self, Tp1ExtensionState>;
    type Identity = C::Identity;
    type Storage = C::Storage;
    type StateInit = SystemBStateInit<Self::Identity, <Self::State as HasDeviceConfig>::Config>;

    fn create_state(init: Self::StateInit) -> Self::State {
        assert!(matches!(Self::DEVICE.mask_version, MaskVersion::SystemBTp1), "TP1 preset requires a 07B0 descriptor");
        assert_table_capacities::<Self, ADT_SIZE, AST_SIZE, COT_SIZE>();
        Self::State::from_init(init)
    }

    type Mem = SystemBMemoryMap;

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
        = DefaultSystemBInterfaceObjects<'a, Self, Self::Augments<'a>>
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
        let layout = memory_layout::<Self>();
        create_system_b_objects::<Self, _>(state, layer_ctx, &layout, augments)
    }

    type AlExtensions = super::SystemBAlServices;

    type DeviceModel<'a>
        = SystemBDeviceModel<'a, Self>
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
        SystemBDeviceModel::new(state, layer_ctx, interface_objects)
    }

    type LayerBuilder = PlainDeviceBuilder;
}

/// Plain System B KNX-RF stack (mask family 27B0).
///
/// The preset supplies the RF Medium Object and both RF domain-address
/// management services. `C::LinkLayer` selects the concrete radio and whether
/// the hardware integration needs any non-standard link-layer policy.
pub struct Rf<
    C: DeviceDefinition,
    const ADT_SIZE: usize = { C::DEVICE.address_table_size() },
    const AST_SIZE: usize = { C::DEVICE.association_table_size() },
    const COT_SIZE: usize = { C::DEVICE.comm_object_table_size() },
>(PhantomData<fn() -> C>);

impl<C, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize> Clone
    for Rf<C, ADT_SIZE, AST_SIZE, COT_SIZE>
where
    C: DeviceDefinition,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<C, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize> Copy
    for Rf<C, ADT_SIZE, AST_SIZE, COT_SIZE>
where
    C: DeviceDefinition,
{
}

impl<C, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize> Rf<C, ADT_SIZE, AST_SIZE, COT_SIZE>
where
    C: DeviceDefinition,
    Self: StackDefinition<Mem = SystemBMemoryMap>,
{
    /// Construct the descriptor-derived System B memory map.
    pub fn memory_map() -> SystemBMemoryMap {
        memory_map::<Self>()
    }
}

impl<C, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize> StackDefinition
    for Rf<C, ADT_SIZE, AST_SIZE, COT_SIZE>
where
    C: DeviceDefinition<Platform = ()>,
    C::Params: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    const DEVICE: &'static zweidraehte_proto::device::DeviceDescriptor = C::DEVICE;
    const MAX_APDU_LENGTH: u16 = C::MAX_APDU_LENGTH;
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = C::DEVICE_DESCRIPTOR_TYPE2;
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = C::USER_MANUFACTURER_INFO;
    const FIRST_ASAP: u16 = 1;
    const TL_STYLE: TlStyle = TlStyle::Style3;

    type Mutex = C::Mutex;
    type Rng = C::Rng;
    type Platform = C::Platform;
    type P = C::Params;
    type CO = C::ComObjects;
    type LLB = C::LinkLayer;
    type ES = RfExtensionState;
    type State = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, Self, RfExtensionState>;
    type Identity = C::Identity;
    type Storage = C::Storage;
    type StateInit = SystemBStateInit<Self::Identity, <Self::State as HasDeviceConfig>::Config>;

    fn create_state(init: Self::StateInit) -> Self::State {
        assert!(matches!(Self::DEVICE.mask_version, MaskVersion::SystemBRf), "RF preset requires a 27B0 descriptor");
        assert_table_capacities::<Self, ADT_SIZE, AST_SIZE, COT_SIZE>();
        Self::State::from_init(init)
    }

    type Mem = SystemBMemoryMap;

    type Augments<'a>
        = AugmentChain<
        <RfExtensionState as Extension<()>>::Augment<'a, Self>,
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
        = DefaultSystemBInterfaceObjects<'a, Self, Self::Augments<'a>>
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
        create_system_b_objects::<Self, _>(state, layer_ctx, &memory_layout::<Self>(), augments)
    }

    type AlExtensions = (super::SystemBAlServices, DomainAddressService, RfDomainAddressService);

    type DeviceModel<'a>
        = SystemBDeviceModel<'a, Self>
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
        SystemBDeviceModel::new(state, layer_ctx, interface_objects)
    }

    type LayerBuilder = PlainDeviceBuilder;
}

/// Plain System B KNX/IP device stack (mask family 57B0).
///
/// `C` also implements [`KnxNetIpDefinition`] to select the transport,
/// feature set, and link-layer capacities. This preset provides the basic IP
/// Parameter Object; use [`IpInterface`] when tunnelling slots must also be
/// represented by the interface-object model.
#[cfg(feature = "knxip")]
pub struct Ip<
    C: DeviceDefinition + KnxNetIpDefinition,
    const ADT_SIZE: usize = { C::DEVICE.address_table_size() },
    const AST_SIZE: usize = { C::DEVICE.association_table_size() },
    const COT_SIZE: usize = { C::DEVICE.comm_object_table_size() },
    const CAPS: u16 = { <C::Features as FeatureSet>::KNXNETIP_DEVICE_CAPABILITIES },
>(PhantomData<fn() -> C>);

#[cfg(feature = "knxip")]
impl<C, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const CAPS: u16> Clone
    for Ip<C, ADT_SIZE, AST_SIZE, COT_SIZE, CAPS>
where
    C: DeviceDefinition + KnxNetIpDefinition,
{
    fn clone(&self) -> Self {
        *self
    }
}

#[cfg(feature = "knxip")]
impl<C, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const CAPS: u16> Copy
    for Ip<C, ADT_SIZE, AST_SIZE, COT_SIZE, CAPS>
where
    C: DeviceDefinition + KnxNetIpDefinition,
{
}

#[cfg(feature = "knxip")]
impl<C, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const CAPS: u16> KnxNetIpDefinition
    for Ip<C, ADT_SIZE, AST_SIZE, COT_SIZE, CAPS>
where
    C: DeviceDefinition + KnxNetIpDefinition,
{
    type Transport = C::Transport;
    type Features = C::Features;
    type Rng = <C as DeviceDefinition>::Rng;

    const TUNNEL_CAPACITY: usize = C::TUNNEL_CAPACITY;
    const MAX_TCP_STREAMS: usize = C::MAX_TCP_STREAMS;
    const MAX_TCP_CHANNELS: usize = C::MAX_TCP_CHANNELS;
    const MAX_CONNECTIONS: usize = C::MAX_CONNECTIONS;
    const MAX_UDP_SOCKETS: usize = C::MAX_UDP_SOCKETS;
    const TCP_SCRATCH_BUF_SIZE: usize = C::TCP_SCRATCH_BUF_SIZE;
    const MAX_SECURE_SESSIONS: usize = C::MAX_SECURE_SESSIONS;
}

#[cfg(feature = "knxip")]
impl<C, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const CAPS: u16>
    Ip<C, ADT_SIZE, AST_SIZE, COT_SIZE, CAPS>
where
    C: DeviceDefinition + KnxNetIpDefinition,
    Self: StackDefinition<Mem = SystemBMemoryMap>,
{
    /// Construct the descriptor-derived System B memory map.
    pub fn memory_map() -> SystemBMemoryMap {
        memory_map::<Self>()
    }
}

#[cfg(feature = "knxip")]
impl<C, const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const CAPS: u16> StackDefinition
    for Ip<C, ADT_SIZE, AST_SIZE, COT_SIZE, CAPS>
where
    C: DeviceDefinition + KnxNetIpDefinition,
    C::Platform: IpPlatform,
    C::Params: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    const DEVICE: &'static zweidraehte_proto::device::DeviceDescriptor = C::DEVICE;
    const MAX_APDU_LENGTH: u16 = C::MAX_APDU_LENGTH;
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = C::DEVICE_DESCRIPTOR_TYPE2;
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = C::USER_MANUFACTURER_INFO;
    const FIRST_ASAP: u16 = 1;
    const TL_STYLE: TlStyle = TlStyle::Style3;

    type Mutex = C::Mutex;
    type Rng = <C as DeviceDefinition>::Rng;
    type Platform = C::Platform;
    type P = C::Params;
    type CO = C::ComObjects;
    type LLB = C::LinkLayer;
    type ES = IpExtensionState<CAPS>;
    type State = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, Self, Self::ES>;
    type Identity = C::Identity;
    type Storage = C::Storage;
    type StateInit = SystemBStateInit<Self::Identity, <Self::State as HasDeviceConfig>::Config>;

    fn create_state(init: Self::StateInit) -> Self::State {
        assert!(matches!(Self::DEVICE.mask_version, MaskVersion::SystemBKnxIp), "IP preset requires a 57B0 descriptor");
        assert_table_capacities::<Self, ADT_SIZE, AST_SIZE, COT_SIZE>();
        assert!(
            CAPS == <C::Features as FeatureSet>::KNXNETIP_DEVICE_CAPABILITIES,
            "KNX/IP capabilities differ from the feature set"
        );
        Self::State::from_init(init)
    }

    type Mem = SystemBMemoryMap;

    type Augments<'a>
        = AugmentChain<
        <Self::ES as Extension<Self::Platform>>::Augment<'a, Self>,
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
        = DefaultSystemBInterfaceObjects<'a, Self, Self::Augments<'a>>
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
        create_system_b_objects::<Self, _>(state, layer_ctx, &memory_layout::<Self>(), augments)
    }

    type AlExtensions = (super::SystemBAlServices, DomainAddressService);

    type DeviceModel<'a>
        = SystemBDeviceModel<'a, Self>
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
        SystemBDeviceModel::new(state, layer_ctx, interface_objects)
    }

    type LayerBuilder = PlainIpDeviceBuilder;
}

/// KNX Data Secure System B TP1 stack.
///
/// The preset owns the complete secure profile composition: TP1 medium state,
/// Security Interface Object, secure application layer, and GO Diagnostics.
/// `P2P` selects whether the secure application layer includes peer-to-peer
/// sync support, while `P2P_KEYS` sizes the optional peer key table. Group-only
/// devices use the defaults and simply write `SecureTp1<MyDevice>`.
pub struct SecureTp1<
    C: DeviceDefinition,
    P2P: P2pFeature = NoP2p,
    const P2P_KEYS: usize = 0,
    const ADT_SIZE: usize = { C::DEVICE.address_table_size() },
    const AST_SIZE: usize = { C::DEVICE.association_table_size() },
    const COT_SIZE: usize = { C::DEVICE.comm_object_table_size() },
    const ADT_ENTRIES: usize = { address_table_entries(C::DEVICE) },
    const COT_ENTRIES: usize = { communication_object_entries(C::DEVICE) },
>(PhantomData<fn() -> (C, P2P)>);

impl<
    C: DeviceDefinition,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> Clone for SecureTp1<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<
    C: DeviceDefinition,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> Copy for SecureTp1<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
{
}

impl<
    C: DeviceDefinition,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> SystemBStackDefinition for SecureTp1<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
where
    Self: StackDefinition<Mem = SystemBMemoryMap>,
{
    const ADT_SIZE: usize = ADT_SIZE;
    const AST_SIZE: usize = AST_SIZE;
    const COT_SIZE: usize = COT_SIZE;
    const ADT_ENTRIES: usize = ADT_ENTRIES;
    const COT_ENTRIES: usize = COT_ENTRIES;
}

impl<
    C,
    P2P,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> SecureTp1<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
where
    C: DeviceDefinition,
    P2P: P2pFeature,
    Self: StackDefinition<Mem = SystemBMemoryMap>,
{
    /// Construct the descriptor-derived System B memory map.
    pub fn memory_map() -> SystemBMemoryMap {
        memory_map::<Self>()
    }
}

impl<
    C,
    P2P,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> StackDefinition for SecureTp1<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
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
    const FIRST_ASAP: u16 = 1;
    const TL_STYLE: TlStyle = TlStyle::Style3;

    type Mutex = C::Mutex;
    type Rng = C::Rng;
    type Platform = C::Platform;
    type P = C::Params;
    type CO = C::ComObjects;
    type LLB = C::LinkLayer;
    type ES = SecureExtensionState<Tp1ExtensionState, ADT_ENTRIES, P2P_KEYS, COT_ENTRIES>;
    type State = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, Self, Self::ES>;
    type Identity = C::Identity;
    type Storage = C::Storage;
    type StateInit =
        SystemBStateInit<Self::Identity, <Self::State as HasDeviceConfig>::Config, SecureResources<Tp1ExtensionState>>;

    fn create_state(init: Self::StateInit) -> Self::State {
        assert!(matches!(Self::DEVICE.mask_version, MaskVersion::SystemBTp1), "TP1 preset requires a 07B0 descriptor");
        assert_table_capacities::<Self, ADT_SIZE, AST_SIZE, COT_SIZE>();
        assert!(
            ADT_ENTRIES == Self::DEVICE.max_address_table_entries as usize,
            "group-key capacity differs from DEVICE"
        );
        assert!(COT_ENTRIES == Self::DEVICE.max_com_objects as usize, "GO-security capacity differs from DEVICE");
        assert!(P2P::ENABLED || P2P_KEYS == 0, "P2P key capacity requires P2P support");
        Self::State::from_init(init)
    }

    type Mem = SystemBMemoryMap;

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
        AugmentChain<DiagnosticsAugment<'a, WithSecureGoSend>, <C::Hooks as DeviceHooks>::Augments<'a, Self>>,
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
        AugmentChain::new(secure, AugmentChain::new(diagnostics, device))
    }

    type InterfaceObjects<'a>
        = DefaultSystemBInterfaceObjects<'a, Self, Self::Augments<'a>>
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
        create_system_b_objects::<Self, _>(state, layer_ctx, &memory_layout::<Self>(), augments)
    }

    type AlExtensions = StandardSecureAlServices;

    type DeviceModel<'a>
        = SystemBDeviceModel<'a, Self>
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
        SystemBDeviceModel::new(state, layer_ctx, interface_objects)
    }

    type LayerBuilder = SecureDeviceBuilder<P2P>;
}

/// KNX Data Secure System B RF stack.
///
/// This is the secure counterpart of [`Rf`]; it retains both RF domain-address
/// management services and adds the Security Interface Object, secure AL, and
/// mandatory GO Diagnostics.
pub struct SecureRf<
    C: DeviceDefinition,
    P2P: P2pFeature = NoP2p,
    const P2P_KEYS: usize = 0,
    const ADT_SIZE: usize = { C::DEVICE.address_table_size() },
    const AST_SIZE: usize = { C::DEVICE.association_table_size() },
    const COT_SIZE: usize = { C::DEVICE.comm_object_table_size() },
    const ADT_ENTRIES: usize = { address_table_entries(C::DEVICE) },
    const COT_ENTRIES: usize = { communication_object_entries(C::DEVICE) },
>(PhantomData<fn() -> (C, P2P)>);

impl<
    C: DeviceDefinition,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> Clone for SecureRf<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<
    C: DeviceDefinition,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> Copy for SecureRf<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
{
}

impl<
    C: DeviceDefinition,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> SystemBStackDefinition for SecureRf<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
where
    Self: StackDefinition<Mem = SystemBMemoryMap>,
{
    const ADT_SIZE: usize = ADT_SIZE;
    const AST_SIZE: usize = AST_SIZE;
    const COT_SIZE: usize = COT_SIZE;
    const ADT_ENTRIES: usize = ADT_ENTRIES;
    const COT_ENTRIES: usize = COT_ENTRIES;
}

impl<
    C,
    P2P,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> SecureRf<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
where
    C: DeviceDefinition,
    P2P: P2pFeature,
    Self: StackDefinition<Mem = SystemBMemoryMap>,
{
    /// Construct the descriptor-derived System B memory map.
    pub fn memory_map() -> SystemBMemoryMap {
        memory_map::<Self>()
    }
}

impl<
    C,
    P2P,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> StackDefinition for SecureRf<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
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
    const FIRST_ASAP: u16 = 1;
    const TL_STYLE: TlStyle = TlStyle::Style3;

    type Mutex = C::Mutex;
    type Rng = C::Rng;
    type Platform = C::Platform;
    type P = C::Params;
    type CO = C::ComObjects;
    type LLB = C::LinkLayer;
    type ES = SecureExtensionState<RfExtensionState, ADT_ENTRIES, P2P_KEYS, COT_ENTRIES>;
    type State = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, Self, Self::ES>;
    type Identity = C::Identity;
    type Storage = C::Storage;
    type StateInit =
        SystemBStateInit<Self::Identity, <Self::State as HasDeviceConfig>::Config, SecureResources<RfExtensionState>>;

    fn create_state(init: Self::StateInit) -> Self::State {
        assert!(matches!(Self::DEVICE.mask_version, MaskVersion::SystemBRf), "RF preset requires a 27B0 descriptor");
        assert_table_capacities::<Self, ADT_SIZE, AST_SIZE, COT_SIZE>();
        assert!(
            ADT_ENTRIES == Self::DEVICE.max_address_table_entries as usize,
            "group-key capacity differs from DEVICE"
        );
        assert!(COT_ENTRIES == Self::DEVICE.max_com_objects as usize, "GO-security capacity differs from DEVICE");
        assert!(P2P::ENABLED || P2P_KEYS == 0, "P2P key capacity requires P2P support");
        Self::State::from_init(init)
    }

    type Mem = SystemBMemoryMap;

    type Augments<'a>
        = AugmentChain<
        SecureAugmentBundle<
            'a,
            <RfExtensionState as Extension<()>>::Augment<'a, Self>,
            SeqStorageFor<Self>,
            ADT_ENTRIES,
            P2P_KEYS,
            COT_ENTRIES,
        >,
        AugmentChain<DiagnosticsAugment<'a, WithSecureGoSend>, <C::Hooks as DeviceHooks>::Augments<'a, Self>>,
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
        AugmentChain::new(secure, AugmentChain::new(diagnostics, device))
    }

    type InterfaceObjects<'a>
        = DefaultSystemBInterfaceObjects<'a, Self, Self::Augments<'a>>
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
        create_system_b_objects::<Self, _>(state, layer_ctx, &memory_layout::<Self>(), augments)
    }

    type AlExtensions = (StandardSecureAlServices, DomainAddressService, RfDomainAddressService);

    type DeviceModel<'a>
        = SystemBDeviceModel<'a, Self>
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
        SystemBDeviceModel::new(state, layer_ctx, interface_objects)
    }

    type LayerBuilder = SecureDeviceBuilder<P2P>;
}

/// KNX Data Secure System B RF retransmitter stack.
///
/// The preset fixes the medium extension to [`RfRetransmitterExtension`]. The
/// hardware definition still selects a retransmitting RF link-layer builder,
/// whose context bound verifies that both halves were chosen together.
pub struct SecureRfRetransmitter<
    C: DeviceDefinition,
    P2P: P2pFeature = NoP2p,
    const P2P_KEYS: usize = 0,
    const ADT_SIZE: usize = { C::DEVICE.address_table_size() },
    const AST_SIZE: usize = { C::DEVICE.association_table_size() },
    const COT_SIZE: usize = { C::DEVICE.comm_object_table_size() },
    const ADT_ENTRIES: usize = { address_table_entries(C::DEVICE) },
    const COT_ENTRIES: usize = { communication_object_entries(C::DEVICE) },
>(PhantomData<fn() -> (C, P2P)>);

impl<
    C: DeviceDefinition,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> Clone for SecureRfRetransmitter<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<
    C: DeviceDefinition,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> Copy for SecureRfRetransmitter<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
{
}

impl<
    C: DeviceDefinition,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> SystemBStackDefinition
    for SecureRfRetransmitter<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
where
    Self: StackDefinition<Mem = SystemBMemoryMap>,
{
    const ADT_SIZE: usize = ADT_SIZE;
    const AST_SIZE: usize = AST_SIZE;
    const COT_SIZE: usize = COT_SIZE;
    const ADT_ENTRIES: usize = ADT_ENTRIES;
    const COT_ENTRIES: usize = COT_ENTRIES;
}

impl<
    C,
    P2P,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> SecureRfRetransmitter<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
where
    C: DeviceDefinition,
    P2P: P2pFeature,
    Self: StackDefinition<Mem = SystemBMemoryMap>,
{
    /// Construct the descriptor-derived System B memory map.
    pub fn memory_map() -> SystemBMemoryMap {
        memory_map::<Self>()
    }
}

impl<
    C,
    P2P,
    const P2P_KEYS: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
> StackDefinition for SecureRfRetransmitter<C, P2P, P2P_KEYS, ADT_SIZE, AST_SIZE, COT_SIZE, ADT_ENTRIES, COT_ENTRIES>
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
    const FIRST_ASAP: u16 = 1;
    const TL_STYLE: TlStyle = TlStyle::Style3;

    type Mutex = C::Mutex;
    type Rng = C::Rng;
    type Platform = C::Platform;
    type P = C::Params;
    type CO = C::ComObjects;
    type LLB = C::LinkLayer;
    type ES = SecureExtensionState<RfRetransmitterExtension, ADT_ENTRIES, P2P_KEYS, COT_ENTRIES>;
    type State = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, Self, Self::ES>;
    type Identity = C::Identity;
    type Storage = C::Storage;
    type StateInit = SystemBStateInit<
        Self::Identity,
        <Self::State as HasDeviceConfig>::Config,
        SecureResources<RfRetransmitterExtension>,
    >;

    fn create_state(init: Self::StateInit) -> Self::State {
        assert!(matches!(Self::DEVICE.mask_version, MaskVersion::SystemBRf), "RF preset requires a 27B0 descriptor");
        assert_table_capacities::<Self, ADT_SIZE, AST_SIZE, COT_SIZE>();
        assert!(
            ADT_ENTRIES == Self::DEVICE.max_address_table_entries as usize,
            "group-key capacity differs from DEVICE"
        );
        assert!(COT_ENTRIES == Self::DEVICE.max_com_objects as usize, "GO-security capacity differs from DEVICE");
        assert!(P2P::ENABLED || P2P_KEYS == 0, "P2P key capacity requires P2P support");
        Self::State::from_init(init)
    }

    type Mem = SystemBMemoryMap;

    type Augments<'a>
        = AugmentChain<
        SecureAugmentBundle<
            'a,
            <RfRetransmitterExtension as Extension<()>>::Augment<'a, Self>,
            SeqStorageFor<Self>,
            ADT_ENTRIES,
            P2P_KEYS,
            COT_ENTRIES,
        >,
        AugmentChain<DiagnosticsAugment<'a, WithSecureGoSend>, <C::Hooks as DeviceHooks>::Augments<'a, Self>>,
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
        AugmentChain::new(secure, AugmentChain::new(diagnostics, device))
    }

    type InterfaceObjects<'a>
        = DefaultSystemBInterfaceObjects<'a, Self, Self::Augments<'a>>
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
        create_system_b_objects::<Self, _>(state, layer_ctx, &memory_layout::<Self>(), augments)
    }

    type AlExtensions = (StandardSecureAlServices, DomainAddressService, RfDomainAddressService);

    type DeviceModel<'a>
        = SystemBDeviceModel<'a, Self>
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
        SystemBDeviceModel::new(state, layer_ctx, interface_objects)
    }

    type LayerBuilder = SecureDeviceBuilder<P2P>;
}

/// Combined KNX/IP Secure and KNX Data Secure System B stack.
///
/// The defaults describe the common routing-only device: no Data Secure P2P
/// keys, one IP Secure password slot, and no tunnelling-user table. Advanced
/// products can override those capacities and the `P2P` feature type without
/// replacing the standard composition.
#[cfg(feature = "ip-secure")]
pub struct SecureIp<
    C: DeviceDefinition + KnxNetIpDefinition,
    P2P: P2pFeature = NoP2p,
    const P2P_KEYS: usize = 0,
    const MAX_PW: usize = 1,
    const MAX_TU: usize = 0,
    const ADT_SIZE: usize = { C::DEVICE.address_table_size() },
    const AST_SIZE: usize = { C::DEVICE.association_table_size() },
    const COT_SIZE: usize = { C::DEVICE.comm_object_table_size() },
    const ADT_ENTRIES: usize = { address_table_entries(C::DEVICE) },
    const COT_ENTRIES: usize = { communication_object_entries(C::DEVICE) },
    const TUNNEL_CAPACITY: usize = { <<C::Features as FeatureSet>::Tunneling as TunnelingFeature>::CAPACITY },
    const CAPS: u16 = { <C::Features as FeatureSet>::KNXNETIP_DEVICE_CAPABILITIES },
>(PhantomData<fn() -> (C, P2P)>);

#[cfg(feature = "ip-secure")]
impl<
    C: DeviceDefinition + KnxNetIpDefinition,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const MAX_PW: usize,
    const MAX_TU: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
    const TUNNEL_CAPACITY: usize,
    const CAPS: u16,
> Clone
    for SecureIp<
        C,
        P2P,
        P2P_KEYS,
        MAX_PW,
        MAX_TU,
        ADT_SIZE,
        AST_SIZE,
        COT_SIZE,
        ADT_ENTRIES,
        COT_ENTRIES,
        TUNNEL_CAPACITY,
        CAPS,
    >
{
    fn clone(&self) -> Self {
        *self
    }
}

#[cfg(feature = "ip-secure")]
impl<
    C: DeviceDefinition + KnxNetIpDefinition,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const MAX_PW: usize,
    const MAX_TU: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
    const TUNNEL_CAPACITY: usize,
    const CAPS: u16,
> Copy
    for SecureIp<
        C,
        P2P,
        P2P_KEYS,
        MAX_PW,
        MAX_TU,
        ADT_SIZE,
        AST_SIZE,
        COT_SIZE,
        ADT_ENTRIES,
        COT_ENTRIES,
        TUNNEL_CAPACITY,
        CAPS,
    >
{
}

#[cfg(feature = "ip-secure")]
impl<
    C: DeviceDefinition + KnxNetIpDefinition,
    P2P: P2pFeature,
    const P2P_KEYS: usize,
    const MAX_PW: usize,
    const MAX_TU: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
    const TUNNEL_CAPACITY: usize,
    const CAPS: u16,
> SystemBStackDefinition
    for SecureIp<
        C,
        P2P,
        P2P_KEYS,
        MAX_PW,
        MAX_TU,
        ADT_SIZE,
        AST_SIZE,
        COT_SIZE,
        ADT_ENTRIES,
        COT_ENTRIES,
        TUNNEL_CAPACITY,
        CAPS,
    >
where
    Self: StackDefinition<Mem = SystemBMemoryMap>,
{
    const ADT_SIZE: usize = ADT_SIZE;
    const AST_SIZE: usize = AST_SIZE;
    const COT_SIZE: usize = COT_SIZE;
    const ADT_ENTRIES: usize = ADT_ENTRIES;
    const COT_ENTRIES: usize = COT_ENTRIES;
}

#[cfg(feature = "ip-secure")]
impl<
    C,
    P2P,
    const P2P_KEYS: usize,
    const MAX_PW: usize,
    const MAX_TU: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
    const TUNNEL_CAPACITY: usize,
    const CAPS: u16,
> KnxNetIpDefinition
    for SecureIp<
        C,
        P2P,
        P2P_KEYS,
        MAX_PW,
        MAX_TU,
        ADT_SIZE,
        AST_SIZE,
        COT_SIZE,
        ADT_ENTRIES,
        COT_ENTRIES,
        TUNNEL_CAPACITY,
        CAPS,
    >
where
    C: DeviceDefinition + KnxNetIpDefinition,
    P2P: P2pFeature,
{
    type Transport = C::Transport;
    type Features = C::Features;
    type Rng = <C as DeviceDefinition>::Rng;

    const TUNNEL_CAPACITY: usize = C::TUNNEL_CAPACITY;
    const MAX_TCP_STREAMS: usize = C::MAX_TCP_STREAMS;
    const MAX_TCP_CHANNELS: usize = C::MAX_TCP_CHANNELS;
    const MAX_CONNECTIONS: usize = C::MAX_CONNECTIONS;
    const MAX_UDP_SOCKETS: usize = C::MAX_UDP_SOCKETS;
    const TCP_SCRATCH_BUF_SIZE: usize = C::TCP_SCRATCH_BUF_SIZE;
    const MAX_SECURE_SESSIONS: usize = C::MAX_SECURE_SESSIONS;
}

#[cfg(feature = "ip-secure")]
impl<
    C,
    P2P,
    const P2P_KEYS: usize,
    const MAX_PW: usize,
    const MAX_TU: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
    const TUNNEL_CAPACITY: usize,
    const CAPS: u16,
>
    SecureIp<
        C,
        P2P,
        P2P_KEYS,
        MAX_PW,
        MAX_TU,
        ADT_SIZE,
        AST_SIZE,
        COT_SIZE,
        ADT_ENTRIES,
        COT_ENTRIES,
        TUNNEL_CAPACITY,
        CAPS,
    >
where
    C: DeviceDefinition + KnxNetIpDefinition,
    P2P: P2pFeature,
    Self: StackDefinition<Mem = SystemBMemoryMap>,
{
    /// Construct the descriptor-derived System B memory map.
    pub fn memory_map() -> SystemBMemoryMap {
        memory_map::<Self>()
    }
}

#[cfg(feature = "ip-secure")]
impl<
    C,
    P2P,
    const P2P_KEYS: usize,
    const MAX_PW: usize,
    const MAX_TU: usize,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const ADT_ENTRIES: usize,
    const COT_ENTRIES: usize,
    const TUNNEL_CAPACITY: usize,
    const CAPS: u16,
> StackDefinition
    for SecureIp<
        C,
        P2P,
        P2P_KEYS,
        MAX_PW,
        MAX_TU,
        ADT_SIZE,
        AST_SIZE,
        COT_SIZE,
        ADT_ENTRIES,
        COT_ENTRIES,
        TUNNEL_CAPACITY,
        CAPS,
    >
where
    C: DeviceDefinition + KnxNetIpDefinition,
    C::Platform: IpPlatform,
    C::Params: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
    C::Identity: SecureDeviceIdentity,
    <C as DeviceDefinition>::Rng: SecureRng,
    C::Storage: HasSeqStore,
    P2P: P2pFeature,
{
    const DEVICE: &'static zweidraehte_proto::device::DeviceDescriptor = C::DEVICE;
    const MAX_APDU_LENGTH: u16 = C::MAX_APDU_LENGTH;
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = C::DEVICE_DESCRIPTOR_TYPE2;
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = C::USER_MANUFACTURER_INFO;
    const FIRST_ASAP: u16 = 1;
    const TL_STYLE: TlStyle = TlStyle::Style3;

    type Mutex = C::Mutex;
    type Rng = <C as DeviceDefinition>::Rng;
    type Platform = C::Platform;
    type P = C::Params;
    type CO = C::ComObjects;
    type LLB = C::LinkLayer;
    type ES = SecureExtensionState<
        IpSecureInterfaceExtension<TUNNEL_CAPACITY, CAPS, MAX_PW, MAX_TU>,
        ADT_ENTRIES,
        P2P_KEYS,
        COT_ENTRIES,
    >;
    type State = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, Self, Self::ES>;
    type Identity = C::Identity;
    type Storage = C::Storage;
    type StateInit = SystemBStateInit<
        Self::Identity,
        <Self::State as HasDeviceConfig>::Config,
        SecureResources<IpSecureInterfaceExtension<TUNNEL_CAPACITY, CAPS, MAX_PW, MAX_TU>>,
    >;

    fn create_state(init: Self::StateInit) -> Self::State {
        assert!(matches!(Self::DEVICE.mask_version, MaskVersion::SystemBKnxIp), "IP preset requires a 57B0 descriptor");
        assert_table_capacities::<Self, ADT_SIZE, AST_SIZE, COT_SIZE>();
        assert!(
            ADT_ENTRIES == Self::DEVICE.max_address_table_entries as usize,
            "group-key capacity differs from DEVICE"
        );
        assert!(COT_ENTRIES == Self::DEVICE.max_com_objects as usize, "GO-security capacity differs from DEVICE");
        assert!(P2P::ENABLED || P2P_KEYS == 0, "P2P key capacity requires P2P support");
        assert!(
            TUNNEL_CAPACITY == <<C::Features as FeatureSet>::Tunneling as TunnelingFeature>::CAPACITY,
            "KNX/IP tunnel capacity differs from the feature set"
        );
        assert!(TUNNEL_CAPACITY == C::TUNNEL_CAPACITY, "KNX/IP tunnel capacity differs from the link-layer definition");
        assert!(
            CAPS == <C::Features as FeatureSet>::KNXNETIP_DEVICE_CAPABILITIES,
            "KNX/IP capabilities differ from the feature set"
        );
        Self::State::from_init(init)
    }

    type Mem = SystemBMemoryMap;

    type Augments<'a>
        = AugmentChain<
        SecureAugmentBundle<
            'a,
            <IpSecureInterfaceExtension<TUNNEL_CAPACITY, CAPS, MAX_PW, MAX_TU> as Extension<C::Platform>>::Augment<
                'a,
                Self,
            >,
            SeqStorageFor<Self>,
            ADT_ENTRIES,
            P2P_KEYS,
            COT_ENTRIES,
        >,
        AugmentChain<DiagnosticsAugment<'a, WithSecureGoSend>, <C::Hooks as DeviceHooks>::Augments<'a, Self>>,
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
        AugmentChain::new(secure, AugmentChain::new(diagnostics, device))
    }

    type InterfaceObjects<'a>
        = DefaultSystemBInterfaceObjects<'a, Self, Self::Augments<'a>>
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
        create_system_b_objects::<Self, _>(state, layer_ctx, &memory_layout::<Self>(), augments)
    }

    type AlExtensions = (StandardSecureAlServices, DomainAddressService);

    type DeviceModel<'a>
        = SystemBDeviceModel<'a, Self>
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
        SystemBDeviceModel::new(state, layer_ctx, interface_objects)
    }

    type LayerBuilder = SecureIpDeviceBuilder<P2P>;
}

/// Plain System B KNX/IP interface stack.
///
/// This is the tunnelling-capable counterpart of [`Ip`]. It composes the
/// tunnelling-address properties into the IP Parameter Object while leaving
/// the physical link-layer builder configurable. In particular, an IP-to-TP1
/// interface can retain its TP1 System B mask while exposing KNX/IP as a
/// secondary interface.
#[cfg(feature = "knxip")]
pub struct IpInterface<
    C: DeviceDefinition + KnxNetIpDefinition,
    const ADT_SIZE: usize = { C::DEVICE.address_table_size() },
    const AST_SIZE: usize = { C::DEVICE.association_table_size() },
    const COT_SIZE: usize = { C::DEVICE.comm_object_table_size() },
    const TUNNEL_CAPACITY: usize = { <<C::Features as FeatureSet>::Tunneling as TunnelingFeature>::CAPACITY },
    const CAPS: u16 = { <C::Features as FeatureSet>::KNXNETIP_DEVICE_CAPABILITIES },
>(PhantomData<fn() -> C>);

#[cfg(feature = "knxip")]
impl<
    C,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const TUNNEL_CAPACITY: usize,
    const CAPS: u16,
> Clone for IpInterface<C, ADT_SIZE, AST_SIZE, COT_SIZE, TUNNEL_CAPACITY, CAPS>
where
    C: DeviceDefinition + KnxNetIpDefinition,
{
    fn clone(&self) -> Self {
        *self
    }
}

#[cfg(feature = "knxip")]
impl<
    C,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const TUNNEL_CAPACITY: usize,
    const CAPS: u16,
> Copy for IpInterface<C, ADT_SIZE, AST_SIZE, COT_SIZE, TUNNEL_CAPACITY, CAPS>
where
    C: DeviceDefinition + KnxNetIpDefinition,
{
}

#[cfg(feature = "knxip")]
impl<
    C,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const TUNNEL_CAPACITY: usize,
    const CAPS: u16,
> KnxNetIpDefinition for IpInterface<C, ADT_SIZE, AST_SIZE, COT_SIZE, TUNNEL_CAPACITY, CAPS>
where
    C: DeviceDefinition + KnxNetIpDefinition,
{
    type Transport = C::Transport;
    type Features = C::Features;
    type Rng = <C as DeviceDefinition>::Rng;

    const TUNNEL_CAPACITY: usize = C::TUNNEL_CAPACITY;
    const MAX_TCP_STREAMS: usize = C::MAX_TCP_STREAMS;
    const MAX_TCP_CHANNELS: usize = C::MAX_TCP_CHANNELS;
    const MAX_CONNECTIONS: usize = C::MAX_CONNECTIONS;
    const MAX_UDP_SOCKETS: usize = C::MAX_UDP_SOCKETS;
    const TCP_SCRATCH_BUF_SIZE: usize = C::TCP_SCRATCH_BUF_SIZE;
    const MAX_SECURE_SESSIONS: usize = C::MAX_SECURE_SESSIONS;
}

#[cfg(feature = "knxip")]
impl<
    C,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const TUNNEL_CAPACITY: usize,
    const CAPS: u16,
> IpInterface<C, ADT_SIZE, AST_SIZE, COT_SIZE, TUNNEL_CAPACITY, CAPS>
where
    C: DeviceDefinition + KnxNetIpDefinition,
    Self: StackDefinition<Mem = SystemBMemoryMap>,
{
    /// Construct the descriptor-derived System B memory map.
    pub fn memory_map() -> SystemBMemoryMap {
        memory_map::<Self>()
    }
}

#[cfg(feature = "knxip")]
impl<
    C,
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const TUNNEL_CAPACITY: usize,
    const CAPS: u16,
> StackDefinition for IpInterface<C, ADT_SIZE, AST_SIZE, COT_SIZE, TUNNEL_CAPACITY, CAPS>
where
    C: DeviceDefinition + KnxNetIpDefinition,
    C::Platform: IpPlatform,
    C::Params: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    const DEVICE: &'static zweidraehte_proto::device::DeviceDescriptor = C::DEVICE;
    const MAX_APDU_LENGTH: u16 = C::MAX_APDU_LENGTH;
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = C::DEVICE_DESCRIPTOR_TYPE2;
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = C::USER_MANUFACTURER_INFO;
    const FIRST_ASAP: u16 = 1;
    const TL_STYLE: TlStyle = TlStyle::Style3;

    type Mutex = C::Mutex;
    type Rng = <C as DeviceDefinition>::Rng;
    type Platform = C::Platform;
    type P = C::Params;
    type CO = C::ComObjects;
    type LLB = C::LinkLayer;
    type ES = IpInterfaceExtension<TUNNEL_CAPACITY, CAPS>;
    type State = SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, Self, Self::ES>;
    type Identity = C::Identity;
    type Storage = C::Storage;
    type StateInit = SystemBStateInit<Self::Identity, <Self::State as HasDeviceConfig>::Config>;

    fn create_state(init: Self::StateInit) -> Self::State {
        assert!(
            matches!(Self::DEVICE.mask_version, MaskVersion::SystemBTp1 | MaskVersion::SystemBKnxIp),
            "IP-interface preset requires a System B TP1 or IP descriptor"
        );
        assert_table_capacities::<Self, ADT_SIZE, AST_SIZE, COT_SIZE>();
        assert!(
            TUNNEL_CAPACITY == <<C::Features as FeatureSet>::Tunneling as TunnelingFeature>::CAPACITY,
            "KNX/IP tunnel capacity differs from the feature set"
        );
        assert!(TUNNEL_CAPACITY == C::TUNNEL_CAPACITY, "KNX/IP tunnel capacity differs from the link-layer definition");
        assert!(
            CAPS == <C::Features as FeatureSet>::KNXNETIP_DEVICE_CAPABILITIES,
            "KNX/IP capabilities differ from the feature set"
        );
        Self::State::from_init(init)
    }

    type Mem = SystemBMemoryMap;

    type Augments<'a>
        = AugmentChain<
        <Self::ES as Extension<Self::Platform>>::Augment<'a, Self>,
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
        = DefaultSystemBInterfaceObjects<'a, Self, Self::Augments<'a>>
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
        create_system_b_objects::<Self, _>(state, layer_ctx, &memory_layout::<Self>(), augments)
    }

    type AlExtensions = (super::SystemBAlServices, DomainAddressService);

    type DeviceModel<'a>
        = SystemBDeviceModel<'a, Self>
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
        SystemBDeviceModel::new(state, layer_ctx, interface_objects)
    }

    type LayerBuilder = PlainIpDeviceBuilder;
}
