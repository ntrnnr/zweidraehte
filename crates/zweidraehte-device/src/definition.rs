//! Compile-time stack configuration trait.
//!
//! [`StackDefinition`] is the central type-level "bill of materials" for a
//! KNX device. It declares the device descriptor, table types, state type,
//! link-layer builder, and layer composition strategy. The stack is fully
//! generic over this trait, allowing the same code to drive TP1 bus devices,
//! KNX/IP devices, USB devices, and mock test fixtures.

use const_default::ConstDefault;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};

use crate::{
    LayerStackBuilder,
    bcus::system_b::Extension,
    config,
    context::StackContext,
    context::layer::LayerContext,
    ets, layers,
    layers::transport::TlStyle,
    memory::MemoryMap,
    objects::{
        comm::{ComObjectBusHook, ComObjects},
        interface::{HasDeviceObject, PropertyServiceHandler},
    },
    rng::{NoRng, Rng},
    service::{ApciHandler, Augment},
    state::CoreDeviceState,
    storage::{DeviceIdentity, StaticIdentity},
};

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
    /// use zweidraehte_device::ets::DeviceDescriptor;
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
    const DEVICE: &'static ets::DeviceDescriptor;

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
    /// ([`InsecureDeviceBuilder`](crate::InsecureDeviceBuilder),
    /// [`InsecureIpDeviceBuilder`](crate::InsecureIpDeviceBuilder), and
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

    /// Transport layer state machine style per KNX spec 03/03/04 section 5.4.
    ///
    /// Determines connection-oriented error recovery behavior. Must be chosen
    /// explicitly — there is no default.
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
    /// [`Extension::create_augment`](crate::bcus::system_b::Extension::create_augment)
    /// during interface object construction.
    type Platform: 'static = ();

    type P: ConstDefault;
    /// Communication-object container. Must also implement
    /// [`ComObjectBusHook`](crate::objects::comm::ComObjectBusHook) —
    /// most devices pick up an empty impl (either written by hand or
    /// emitted by `#[derive(EtsComObjects)]`); harnesses that need
    /// bus-inbound side effects (e.g. BCU1-style shadow objects)
    /// override the trait's default no-op methods.
    type CO: ComObjects + ComObjectBusHook;
    type LLB: layers::LinkLayerBuilderBase + for<'a> layers::LinkLayerBuilder<StackContext<'a, Self>>;

    /// Medium extension providing both state persistence and interface
    /// object augmentation.
    ///
    /// The `Extension<Platform>` trait unifies what were previously
    /// separate `ExtensionState` and `Augment<D>` concerns.
    /// Each extension knows how to create its own augment given a
    /// reference to the platform.
    ///
    /// Common choices:
    /// - `()` — no extension (mock/test devices)
    /// - [`Tp1ExtensionState`](crate::bcus::system_b::Tp1ExtensionState) — TP1 devices
    /// - [`IpExtensionState`](crate::bcus::system_b::IpExtensionState) — KNX/IP devices
    type ES: Extension<Self::Platform>;

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

    /// Constructor-args envelope passed to [`create_state`](Self::create_state).
    ///
    /// This is a construction-time envelope, not a serialisable `*Config`
    /// (see the vocabulary block at the top of
    /// [`bcus::system_b::storage`](crate::bcus::system_b::storage)). It
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

    /// Layer stack builder that handles channel creation, layer construction,
    /// and link-layer endpoint wiring.
    ///
    /// Use [`InsecureDeviceBuilder`](crate::InsecureDeviceBuilder) for standard
    /// `(NL, TL, AL)` stacks or [`InsecureIpDeviceBuilder`](crate::InsecureIpDeviceBuilder)
    /// for KNX/IP `(NL, CemiTL<TL>, AL)` stacks.
    type LayerBuilder: LayerStackBuilder<Self>;
}
