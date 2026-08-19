//! Compile-time stack configuration trait.
//!
//! [`StackDefinition`] is the central type-level "bill of materials" for a
//! KNX device. It declares the device descriptor, table types, state type,
//! link-layer builder, and layer composition strategy. The stack is fully
//! generic over this trait, allowing the same code to drive TP1 bus devices,
//! KNX/IP devices, USB devices, and mock test fixtures.

use const_default::ConstDefault;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};

use zerocopy::{Immutable, IntoBytes, KnownLayout};
use zweidraehte_proto::device::DeviceDescriptor;

use crate::{
    LayerStackBuilder, config,
    context::StackContext,
    context::layer::LayerContext,
    layers,
    layers::transport::TlStyle,
    memory::MemoryMap,
    objects::{
        comm::{ComObjectBusHook, ComObjects},
        interface::{HasDeviceObject, PropertyServiceHandler},
    },
    rng::{NoRng, Rng},
    service::{ApciHandler, Augment, LifecycleHook},
    state::CoreDeviceState,
    storage::{DeviceIdentity, StaticIdentity},
};

// ============================================================================
// Empty parameter block
// ============================================================================

/// [`StackDefinition::P`] for devices with no application parameters.
///
/// Bridge/interface products configured purely through interface-object
/// properties still have to name a parameter type. Without this they each
/// declare a `#[repr(C)]` struct wrapping a `_private: ()` field plus a
/// hand-written [`ConstDefault`] impl, only to satisfy the bounds.
///
/// ```rust,ignore
/// type P = NoParams;
/// ```
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
)]
#[repr(C)]
pub struct NoParams {
    // A ZST would not satisfy `IntoBytes`'s layout requirements as a bare
    // unit struct here, so the private unit field stands in — the same trick
    // each device previously wrote out by hand.
    _private: (),
}

impl ConstDefault for NoParams {
    const DEFAULT: Self = Self { _private: () };
}

impl NoParams {
    /// Empty parameter list — nothing is ETS-visible.
    pub const ETS_PARAMS_EXT: &'static [zweidraehte_ets_model::EtsParamDefExt] = &[];
}

pub trait StackDefinition: Copy + 'static {
    /// Device descriptor containing all device identification and configuration.
    ///
    /// This is the **single source of truth** for device identity including:
    /// - Hardware identification (mask version, manufacturer ID, serial number, hardware type)
    /// - Application program info (app ID, version)
    /// - Table capacities (max addresses, associations, communication objects)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use zweidraehte_proto::device::DeviceDescriptor;
    ///
    /// const MY_DEVICE: DeviceDescriptor = DeviceDescriptor {
    ///     mask_version: MaskVersion::SystemBTp1,
    ///     manufacturer_id: 0x00FA,
    ///     hardware_type: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    ///     application_id: 0xF023,
    ///     application_version: 0x01,
    ///     max_address_table_entries: 64,
    ///     max_association_table_entries: 64,
    ///     max_com_objects: 32,
    ///     pei_type: 0,
    /// };
    ///
    /// impl StackDefinition for MyDevice {
    ///     const DEVICE: &'static DeviceDescriptor = &MY_DEVICE;
    ///     // ... other fields
    /// }
    /// ```
    ///
    /// # Note on Serial Number
    ///
    /// The serial number is NOT part of the device descriptor because it's unique
    /// per physical device instance (factory-programmed). Serial number should be
    /// stored in runtime state and read from persistent storage or hardware.
    const DEVICE: &'static DeviceDescriptor;

    /// Maximum APDU length for compile-time buffer allocation.
    ///
    /// This is the APDU payload size (not the full buffer size). The actual buffer
    /// size is calculated by [`config::buffer_size_for_apdu()`] which adds:
    /// - Frame overhead (6 bytes): ctrl + src + dst + npdu
    /// - Headroom (16 bytes): for cEMI expansion + KNXnet/IP headers
    ///
    /// For the actual runtime limit (which can be lower based on detected hardware),
    /// see [`StackState::max_apdu_length()`](crate::StackState::max_apdu_length).
    /// The runtime limit is what gets reported via PID 56 (MAX_APDU_LENGTH) in the Device Object.
    ///
    /// Common values:
    /// - [`config::MAX_APDU_LENGTH_TP1_STANDARD`] (14): Standard TP1 without EFF
    /// - [`config::MAX_APDU_LENGTH_EXTENDED`] (255): TP1 with EFF or KNX/IP
    ///
    /// Default is 255 (full support for extended frames).
    const MAX_APDU_LENGTH: u16 = config::MAX_APDU_LENGTH_EXTENDED;

    /// Device descriptor type 2 (14 bytes, optional).
    ///
    /// DD2 contains extended device information:
    /// - Bytes 0-1: Application manufacturer code (16-bit)
    /// - Bytes 2-3: Manufacturer-specific device type (16-bit)
    /// - Byte 4: Version of manufacturer-specific device type (8-bit)
    /// - Byte 5: Link management support (bit 7) + Logical tag base (bits 0-5)
    /// - Bytes 6-13: Channel information (4 channels, 2 bytes each)
    ///
    /// Set to `None` if DD2 is not supported. If `None`, the stack will return
    /// error code 0x3F when DD2 is requested.
    const DEVICE_DESCRIPTOR_TYPE2: Option<&'static [u8; 14]> = None;

    /// User Manufacturer Info (3 bytes, optional).
    ///
    /// Contains:
    /// - Byte 0: KNX Manufacturer ID (8-bit)
    /// - Bytes 1-2: Manufacturer-specific data (16-bit)
    ///
    /// Set to `None` if not supported. If `None`, the stack will not respond
    /// to A_UserManufacturerInfo_Read requests.
    const USER_MANUFACTURER_INFO: Option<&'static [u8; 3]> = None;

    /// Maximum incoming transport-layer connections (from remote devices).
    ///
    /// A typical KNX device accepts 1 incoming connection (from ETS or a
    /// configurator). Routers or gateways may need more. Default: 1.
    ///
    /// # Important: overrides are currently ignored by the standard builders
    ///
    /// Due to a `generic_const_exprs` limitation, the standard layer builders
    /// ([`PlainDeviceBuilder`](crate::PlainDeviceBuilder),
    /// [`PlainIpDeviceBuilder`](crate::PlainIpDeviceBuilder), and
    /// [`SecureDeviceBuilder`](crate::SecureDeviceBuilder)) always construct
    /// `TransportLayer` with the hard-coded defaults (1 incoming, 0 outgoing).
    /// Overriding this constant on your `StackDefinition` is **silently a
    /// no-op** with those builders. To use a non-default value you must write
    /// a custom `LayerStackBuilder` that passes explicit const generics to
    /// `TransportLayer::new`.
    const TL_MAX_INCOMING: usize = 1;

    /// Maximum outgoing transport-layer connections (initiated by us).
    ///
    /// A typical KNX device has 0 outgoing connections. Routers or gateways
    /// that actively connect to other devices need more. Default: 0.
    ///
    /// Only valid with [`TlStyle::Style3`] or higher — the transport layer
    /// will panic at startup if `TL_MAX_OUTGOING > 0` with a style that
    /// does not support outgoing connections.
    ///
    /// # Important: overrides are currently ignored by the standard builders
    ///
    /// See [`TL_MAX_INCOMING`](Self::TL_MAX_INCOMING) — the same limitation
    /// applies here.
    const TL_MAX_OUTGOING: usize = 0;

    /// The wire ASAP of the device's first communication object.
    ///
    /// `#[ets(index = N)]` is a family-agnostic 0-based logical index; the
    /// value ETS shows as the object `Number`, writes into the association
    /// table, and that the group-object tables are keyed by is
    /// `logical + FIRST_ASAP`. System 7 numbers objects from 0
    /// (`FIRST_ASAP = 0`); System B numbers from 1 (`FIRST_ASAP = 1`),
    /// because its RealizationType-7 CO table cannot express ASAP 0.
    ///
    /// No default: the wrong base silently shifts every group-object
    /// lookup by one, so each family's stack macro states it explicitly
    /// (`system_b_standard_stack!` emits 1, the System 7 macros 0).
    const FIRST_ASAP: u16;

    /// Transport layer state machine style per KNX spec 03/03/04 section 5.4.
    ///
    /// Determines connection-oriented error recovery behavior. Must be chosen
    /// explicitly — there is no default, because the profile mandates it:
    /// 06 Profiles v02.02.01 §4.1.2 requires Style 3 for System B (and
    /// Style 2 / Style 1 for System 1 / System 2 respectively), so System B
    /// devices use [`TlStyle::Style3`].
    const TL_STYLE: TlStyle;

    /// Mutex type for channels shared between the stack runner and user code.
    ///
    /// Use [`NoopRawMutex`]
    /// (default) when the stack runner and user code share the same executor.
    /// Use [`CriticalSectionRawMutex`](embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex)
    /// when the stack runs on an `InterruptExecutor` while user code runs on
    /// the thread executor — the interrupt executor can preempt mid-borrow,
    /// which requires a real mutex to prevent `BorrowMutError` panics.
    type Mutex: RawMutex + 'static = NoopRawMutex;

    /// Random byte source for KNX Data Secure.
    ///
    /// Stateless trait implemented on a ZST; plugs into the Secure
    /// Application Layer's `S-A_Sync` challenge/nonce generation.
    /// The default [`NoRng`](crate::rng::NoRng) is adequate for
    /// insecure stacks — it panics on use, but the
    /// [`SecureDeviceBuilder`](crate::SecureDeviceBuilder)'s
    /// `where D::Rng: SecureRng` bound rejects it at compile time for
    /// secure compositions. Secure firmware must set this to a type
    /// implementing both [`Rng`](crate::rng::Rng) and
    /// [`SecureRng`](crate::rng::SecureRng).
    type Rng: Rng = NoRng;

    /// Platform abstraction for querying/applying network configuration.
    ///
    /// For KNX/IP devices, implement [`NetworkInfo`](crate::IpPlatform) +
    /// [`NetworkConfig`](crate::IpPlatformConfig) on your platform type.
    /// For non-IP devices (TP1, USB), use the default `()`.
    ///
    /// The platform is stored in the stack's `Inner` and passed to
    /// [`Extension::create_augment`](crate::extension::Extension::create_augment)
    /// during interface object construction.
    type Platform: 'static = ();

    /// Application parameter struct.
    ///
    /// Must implement:
    /// - [`ConstDefault`] — zero-arg const construction for stack startup.
    /// - [`IntoBytes`] — no padding bytes, so that `ApplicationImpl`
    ///   can expose the raw memory of `D` as a `&[u8]` slice without reading
    ///   uninitialized padding bytes (which would be UB in the Rust abstract
    ///   machine).
    /// - [`KnownLayout`] and [`Immutable`] — required by
    ///   the `IntoBytes` derive.
    ///
    /// Add `#[derive(IntoBytes, KnownLayout, Immutable)]` to the params struct.
    /// Union fields declared with `#[ets_union]` carry their own padding and
    /// `IntoBytes` check, so structs containing them derive cleanly too — a
    /// manual `unsafe impl` is never the right answer here. See the
    /// `ApplicationImpl` documentation for the full contract.
    type P: ConstDefault + IntoBytes + KnownLayout + Immutable;

    /// Communication-object container. Must also implement
    /// [`ComObjectBusHook`](crate::objects::comm::ComObjectBusHook) —
    /// most devices pick up an empty impl (either written by hand or
    /// emitted by `#[derive(EtsComObjects)]`); harnesses that need
    /// bus-inbound side effects (e.g. BCU1-style shadow objects)
    /// override the trait's default no-op methods.
    type CO: ComObjects + ComObjectBusHook;

    type LLB: layers::LinkLayerBuilderBase + for<'a> layers::LinkLayerBuilder<StackContext<'a, Self>>;

    /// Medium extension state (persistence + interface-object augmentation).
    ///
    /// Most extensions implement [`Extension`](crate::extension::Extension) so the default
    /// [`create_augments`](Self::create_augments) path can build their
    /// augment from the platform alone; the macro-emitted default bounds on
    /// it at the use site. `SecureExtensionState` deliberately does not —
    /// its Security IO augment needs the storage-layer-owned sequence store
    /// from the layer context, so secure devices build their augment bundle
    /// with `create_secure_augment(platform, layer_ctx)` in a custom
    /// `augments:` block instead.
    ///
    /// Common choices:
    /// - `()` — no extension (mock/test devices)
    /// - [`Tp1ExtensionState`](crate::bcus::system_b::Tp1ExtensionState) — TP1 devices
    /// - [`IpExtensionState`](crate::bcus::system_b::IpExtensionState) — KNX/IP devices
    type ES;

    /// Unified device state containing both runtime state and tables.
    ///
    /// This type holds all device state:
    /// - Runtime state (individual address, authorization keys)
    /// - ETS-loaded tables (ADT, AST, COT, APP)
    /// - Per-connection authorization levels
    /// - Routing count and device model notifications
    ///
    /// Every KNX device requires address tables, association tables,
    /// communication object tables, an application program, per-connection
    /// authentication, a routing count, and device model lifecycle
    /// orchestration. These bounds are enforced here so that
    /// [`Runner::run()`](crate::Runner::run) and layer builders don't need
    /// to repeat them.
    ///
    /// For System B devices, use [`SystemBDeviceState`](crate::bcus::system_b::SystemBDeviceState)
    /// or [`IpSystemBDeviceState`](crate::bcus::system_b::IpSystemBDeviceState).
    type State: CoreDeviceState<Self::CO>;

    /// Factory-programmed device identity type.
    ///
    /// Owned by the device state and threaded through constructors.
    /// Use [`StaticIdentity`] for non-secure devices. For Data Secure
    /// devices, set this to a type that implements
    /// [`SecureDeviceIdentity`](crate::storage::SecureDeviceIdentity)
    /// — e.g. [`StaticSecureIdentity`](crate::storage::StaticSecureIdentity)
    /// — and the secure layer reaches the FDSK via
    /// [`StackState::identity`](crate::StackState::identity) bounded on
    /// `SecureDeviceIdentity` at the call site.
    type Identity: DeviceIdentity = StaticIdentity;

    /// The device's whole storage handle: e.g. `&'static ConfigStorage<…>`, pointing
    /// at its stores struct ([`ConfigStorage`](crate::storage::ConfigStorage)
    /// and friends, or a hand-written equivalent). Carried on the
    /// [`LayerContext`](crate::context::layer::LayerContext) so stack
    /// components pull the stores they need through the capability traits
    /// (which forward through the reference — bounds read
    /// `D::Storage: HasSeqStore`): the secure layers reach the sequence/SIAT
    /// store through [`HasSeqStore`](crate::storage::HasSeqStore) on the
    /// handle, and the storage task drives the config/mc_timer stores.
    ///
    /// Defaults to `()` for devices with no persistent storage at all (demo
    /// stacks, the conformance DUTs' shm-persisted variants); `()` implements
    /// no storage capability, so every storage-consuming bound stays a
    /// compile-time gate.
    type Storage: Copy + 'static = ();

    /// Constructor-args envelope passed to [`create_state`](Self::create_state).
    ///
    /// This is a construction-time envelope, not a serialisable `*Config`
    /// (see the vocabulary block at the top of
    /// `bcus::system_b::storage`). It
    /// bundles the inputs `create_state` needs to produce a runtime
    /// `Self::State`: typically an optional
    /// [`DeviceConfig`](crate::bcus::system_b::DeviceConfig) snapshot
    /// loaded from storage plus non-persisted identity data (serial
    /// number, FDSK).
    ///
    /// For `SystemBDeviceState`-based stacks this is usually an enum of
    /// fresh-factory vs. loaded-snapshot variants.
    type StateInit;

    /// Create device state from an init envelope.
    ///
    /// Called by the runner during stack initialization.
    fn create_state(init: Self::StateInit) -> Self::State;

    /// Memory map for A_Memory_Read/Write services.
    ///
    /// The memory map receives a reference to your `State` type when processing
    /// memory read/write requests. You implement the dispatch logic to map
    /// addresses to the appropriate tables stored in the state.
    ///
    /// Use [`memory::NoMemoryMap`](crate::memory::NoMemoryMap) if you don't
    /// need memory services.
    type Mem: MemoryMap<Self::State> + 'static;

    /// Interface objects container type.
    ///
    /// This holds all interface objects for property service handling.
    /// The container must implement `PropertyServiceHandler` for property access
    /// and `HasDeviceObject` for device-level configuration (programming mode,
    /// verify mode, etc.).
    type InterfaceObjects<'a>: PropertyServiceHandler + HasDeviceObject
    where
        Self::State: 'a;

    /// Create interface objects container.
    ///
    /// This method is called during stack initialization to create the interface
    /// objects that handle property service requests (A_PropertyValue_Read/Write, etc.).
    ///
    /// # Arguments
    /// * `state` - Reference to the unified device state (contains both runtime state and tables)
    /// * `platform` - Reference to the platform abstraction (for IP property dispatch)
    /// * `layer_ctx` - Shared runtime infrastructure (outbox, buffer manager, channels).
    /// * `augments` - The device-wide augment chain. The container borrows this for the
    ///   lifetime of the stack and routes property hooks through
    ///   [`Augment`](crate::service::Augment).
    ///
    /// # Returns
    /// The container holding all interface objects for this device.
    fn create_interface_objects<'a>(
        state: &'a Self::State,
        platform: &'a Self::Platform,
        layer_ctx: &'a LayerContext<Self>,
        augments: &'a Self::Augments<'a>,
    ) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a;

    /// Application Layer APCI extension set.
    ///
    /// Threaded through [`ApplicationLayer`](crate::layers::application::ApplicationLayer)
    /// and [`SecureApplicationLayer`](crate::layers::secure_application::SecureApplicationLayer)
    /// as the `Ext` parameter. The AL handles its built-in APCIs inline and
    /// falls through to this set for anything else. Default `()` handles
    /// nothing (zero overhead). Compose via tuples: `type AlExtensions = (A, B);`.
    ///
    /// Use [`DomainAddressService`](crate::layers::application::services::domain_addr::DomainAddressService)
    /// for KNX/IP devices that need `A_DomainAddressSerialNumber_*` services.
    type AlExtensions: ApciHandler<Self> + Default = ();

    /// Device-wide augment chain.
    ///
    /// Adds extra interface objects beyond the System B base set
    /// (Security IO 0x11, KNXnet/IP Parameter 0x0B, etc.) and
    /// intercepts property dispatch on base interface objects.
    /// The IO container borrows `&Self::Augments<'a>` and routes
    /// hooks through the [`Augment<Self>`] surface.
    ///
    /// Default `()` is the empty chain — no extra objects, no hooks.
    /// Devices that need augments derive a struct of `#[service(augment)]`
    /// fields with [`#[derive(ServiceRegistry)]`](crate::service::ServiceRegistry).
    type Augments<'a>: Augment<Self>
        = ()
    where
        Self::State: 'a,
        Self::Platform: 'a;

    /// Build the device-wide augment chain.
    ///
    /// Called by the runner before [`create_interface_objects`](Self::create_interface_objects)
    /// so the IO container can borrow `&Self::Augments<'a>` for the
    /// lifetime of the stack.
    ///
    /// Devices without augments return `()`:
    ///
    /// ```rust,ignore
    /// fn create_augments<'a>(_: &'a Self::State, _: &'a Self::Platform, _: &'a LayerContext<Self>) {}
    /// ```
    fn create_augments<'a>(
        state: &'a Self::State,
        platform: &'a Self::Platform,
        layer_ctx: &'a LayerContext<Self>,
    ) -> Self::Augments<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a;

    /// Device-model lifecycle hook run by the layer-stack router.
    ///
    /// Wired into [`StandardLayerStack`](crate::composition::StandardLayerStack)
    /// and [`IpLayerStack`](crate::composition::IpLayerStack) as the
    /// `#[service(lifecycle)]` field: its [`init`](LifecycleHook::init) runs
    /// once before the router loop and [`drain_events`](LifecycleHook::drain_events)
    /// after each dispatch cycle.
    ///
    /// No default — this trait is BCU-agnostic. System B devices get
    /// `SystemBDeviceModel` from
    /// [`system_b_standard_stack!`](crate::system_b_standard_stack); a
    /// different BCU names its own hook here, paired with
    /// [`create_device_model`](Self::create_device_model).
    type DeviceModel<'a>: LifecycleHook<Self>
    where
        Self::State: 'a;

    /// Construct the device model for a stack run.
    ///
    /// Called by the layer-stack builders before the router loop, with the
    /// borrows the model holds for the stack's lifetime. Paired with
    /// [`DeviceModel`](Self::DeviceModel); for the System B
    /// `SystemBDeviceModel` this is
    /// `SystemBDeviceModel::new(state, layer_context, interface_objects)`, which
    /// [`system_b_standard_stack!`](crate::system_b_standard_stack) emits.
    fn create_device_model<'a>(
        state: &'a Self::State,
        layer_context: &'a LayerContext<Self>,
        interface_objects: &'a Self::InterfaceObjects<'static>,
    ) -> Self::DeviceModel<'a>
    where
        Self::State: 'a;

    /// Layer stack builder that handles channel creation, layer construction,
    /// and link-layer endpoint wiring.
    ///
    /// Use [`PlainDeviceBuilder`](crate::PlainDeviceBuilder) for standard
    /// `(NL, TL, AL)` stacks or [`PlainIpDeviceBuilder`](crate::PlainIpDeviceBuilder)
    /// for KNX/IP `(NL, CemiTL<TL>, AL)` stacks.
    type LayerBuilder: LayerStackBuilder<Self>;
}
