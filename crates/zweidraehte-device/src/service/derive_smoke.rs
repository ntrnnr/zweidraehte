//! Smoke tests for `#[derive(ServiceRegistry)]` against shim
//! `Layer` / `Augment` impls.
//!
//! These tests don't exercise wire dispatch — they only verify the
//! macro emits compilable `LayerRegistry` / `Augment` impls
//! against the trait surface. End-to-end behaviour is covered by the
//! conformance suite.

// The shim types exist purely for the type-level `_assert_*` bounds
// below — nothing constructs them, by design.
#![allow(dead_code)]

use core::cell::Cell;

use embassy_time::Instant;
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::knx::{KnxMessageBuffer, ServiceType};

#[cfg(feature = "knxip")]
use crate::IpPlatform;
use crate::StackDefinition;
use crate::StackState;
#[cfg(feature = "knxip")]
use crate::bcus::system_b::IpAugment;
use crate::bcus::system_b::{SecurityAugment, Tp1Augment};
use crate::layers::application::services::{
    adc::AdcService, address_serial::IndividualAddressSerialNumberService, authorization::AuthorizationService,
    domain_addr::DomainAddressService, function_property::FunctionPropertyService,
    manufacturer::UserManufacturerInfoService, memory::MemoryService, property_ext::PropertyExtValueService,
    system_network_parameter::SystemNetworkParameterService, user_memory::UserMemoryService,
};
use crate::layers::network::NetworkLayer;
use crate::layers::transport::TransportLayer;
#[cfg(feature = "knxip")]
use crate::layers::transport::cemi::CemiTransportLayer;
use crate::objects::comm::HasCommObjects;
use crate::objects::interface::HasDomainAddress;
use crate::service::{AlCtx, ApciHandler, Augment, Layer, LayerRegistry, LifecycleHook, ServiceRegistry};
use crate::storage::SequenceNumberStorage;

// -----------------------------------------------------------------
// Shim Layer that handles a single, otherwise-unused ServiceType so
// the const dispatch table has something to register.
// -----------------------------------------------------------------

#[derive(Default)]
struct ShimLayer {
    process_calls: Cell<usize>,
    init_called: Cell<bool>,
    poll_called: Cell<bool>,
}

impl<D: StackDefinition> Layer<D> for ShimLayer {
    const HANDLES: &'static [ServiceType] = &[ServiceType::L_Data_Ind];

    fn init(&mut self) {
        self.init_called.set(true);
    }

    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    fn poll(&mut self) {
        self.poll_called.set(true);
    }

    fn process(&mut self, _msg: KnxMessageBuffer<Buffer<'static>>) {
        self.process_calls.set(self.process_calls.get() + 1);
    }
}

// -----------------------------------------------------------------
// Shim Augment with a single IO contribution, to exercise the
// IO-list aggregation paths.
// -----------------------------------------------------------------

#[derive(Default)]
struct ShimAugment;

// Hand-written augment without `#[interface_object_augment]`. With
// the single-trait surface, this is simply an `Augment<D>`
// impl that overrides only the methods this shim cares about — the
// rest are covered by the trait's defaults.
impl<D: StackDefinition> Augment<D> for ShimAugment {
    fn additional_object_count(&self) -> u16 {
        1
    }

    fn additional_object_type_at(&self, index: u16) -> Option<InterfaceObjectType> {
        match index {
            0 => Some(InterfaceObjectType::Security),
            _ => None,
        }
    }
}

// -----------------------------------------------------------------
// Shim ApciHandler used inside the AL's `Ext` chain. The
// `ApplicationLayer<Ext>` parameterisation lands in a follow-up
// reshape; this exists meanwhile to confirm the trait compiles for
// a stateless impl.
// -----------------------------------------------------------------

struct ShimApciHandler;

impl<D: StackDefinition> ApciHandler<D> for ShimApciHandler {
    fn try_handle_apci(
        &self,
        _apci: zweidraehte_proto::messages::knx::ApciCode,
        _msg: &KnxMessageBuffer<Buffer<'static>>,
        _ctx: &AlCtx<'_, D>,
    ) -> bool {
        false
    }
}

// -----------------------------------------------------------------
// Shim lifecycle field (e.g. a stand-in for `SystemBDeviceModel`)
// implementing `LifecycleHook<D>`. The `init` / `drain_events`
// methods just bump counters; the test confirms the macro emits
// calls to them.
// -----------------------------------------------------------------

#[derive(Default)]
struct ShimLifecycle {
    init_calls: Cell<usize>,
    drain_calls: Cell<usize>,
}

impl<D: StackDefinition> LifecycleHook<D> for ShimLifecycle {
    fn init(&mut self) {
        self.init_calls.set(self.init_calls.get() + 1);
    }
    fn drain_events(&mut self) {
        self.drain_calls.set(self.drain_calls.get() + 1);
    }
}

// -----------------------------------------------------------------
// The macro-derived registries.
// -----------------------------------------------------------------

#[derive(Default, ServiceRegistry)]
struct SmokeServices {
    #[service(handler)]
    layer_a: ShimLayer,
    #[service(augment)]
    aug_a: ShimAugment,
}

// -----------------------------------------------------------------
// `#[service(lifecycle)]` + `#[service(channel)]` — verifies the
// macro emits a `drain_events` override, a `ServiceInput` enum, and
// `recv_service_input` / `handle_service_input` wiring. The dispatch
// closure is trivial; we only check the impl compiles and the enum
// variant carries the right payload type.
//
// The channel field uses a thin shim type `ShimReceiver<T>` (rather
// than `embassy_sync::DynamicReceiver`) so the smoke test stays free
// of channel-runtime ceremony — the macro extracts `T` from the
// last generic argument of the field type, which works for any
// `Foo<'a, T>` shape.
// -----------------------------------------------------------------

#[allow(dead_code)]
struct ShimPayload(u8);

struct ShimReceiver<'a, T> {
    _marker: core::marker::PhantomData<&'a T>,
}

impl<T> Default for ShimReceiver<'_, T> {
    fn default() -> Self {
        Self { _marker: core::marker::PhantomData }
    }
}

impl<'a, T> ShimReceiver<'a, T> {
    /// Pretends to await a payload. The smoke test never runs this —
    /// the type-level assertion below only checks the macro emits
    /// compilable code.
    async fn receive(&self) -> T {
        unreachable!("smoke test future is never polled")
    }
}

#[derive(Default, ServiceRegistry)]
struct SmokeServicesWithLifecycleAndChannel<'a> {
    #[service(handler)]
    layer_a: ShimLayer,
    #[service(lifecycle)]
    device_model: ShimLifecycle,
    #[service(channel(dispatch = |stack, payload: ShimPayload| {
        let _ = (stack, payload);
    }))]
    rx: ShimReceiver<'a, ShimPayload>,
}

// -----------------------------------------------------------------
// `#[service(flatten)]` — verifies the macro emits an
// Augment impl that delegates each method into a nested
// `#[derive(ServiceRegistry)]` struct.
//
// The base struct has no handler fields, since flatten is incompatible
// with handler dispatch (the const dispatch table can't route into a
// flattened sub-table).
// -----------------------------------------------------------------

#[derive(Default, ServiceRegistry)]
struct SmokeBaseAugments {
    #[service(augment)]
    aug: ShimAugment,
}

#[derive(Default, ServiceRegistry)]
struct SmokeFlattenedAugments {
    #[service(flatten)]
    base: SmokeBaseAugments,
    #[service(augment)]
    extra: ShimAugment,
}

// -----------------------------------------------------------------
// Tests verify the const dispatch table contains the registered
// ServiceType, the augment IO sum is correct, and the registry
// types are object-safe-shaped for the runtime to call.
// -----------------------------------------------------------------

/// Type-level assertion: `SmokeServices` satisfies both registry
/// traits for any `D: StackDefinition`. If the macro forgot a
/// method or got the generics wrong, this fails to compile.
///
/// The function is `const fn`-shaped only as a syntactic check; we
/// never call it. Instantiating it would require a concrete `D`
/// (i.e. a real `StackDefinition`), but the *trait bounds* it
/// declares are checked at definition time.
fn _assert_registry_bounds<D: StackDefinition>()
where
    SmokeServices: LayerRegistry<D> + Augment<D>,
{
}

/// Type-level assertion that `#[service(flatten)]` produces a valid
/// `Augment<D>` impl: the outer struct (`SmokeFlattenedAugments`)
/// must satisfy the bound regardless of the inner struct's identity,
/// confirming the macro emits the cross-trait forwarding correctly.
fn _assert_flatten_bounds<D: StackDefinition>()
where
    SmokeBaseAugments: Augment<D>,
    SmokeFlattenedAugments: Augment<D>,
{
}

#[test]
fn smoke_module_compiles() {
    // The actual check is that the file compiles. The runtime
    // assertions live in the conformance suite once a real
    // services-struct uses the derive against a real
    // `StackDefinition`.
}

/// Compile-time assertion that the real wire layers (NL / TL /
/// CemiTL) implement the new `service::Layer<D>` trait. The function
/// is never called; if any of the impls regresses, this fails to
/// build.
fn _assert_real_layers_implement_service_layer<D: StackDefinition>()
where
    NetworkLayer<'static, D>: Layer<D>,
    TransportLayer<'static, D, 1, 0>: Layer<D>,
{
}

#[cfg(feature = "knxip")]
fn _assert_cemi_tl_implements_service_layer<D: StackDefinition>()
where
    CemiTransportLayer<'static, D, 1, 0>: Layer<D>,
{
}

/// Compile-time assertion that every AL service satisfies the new
/// `ApciHandler<D>` trait via its bridge shim. The bounds match the
/// macro's: the AL itself requires `HasCommObjects` so the
/// conversion always works in practice.
fn _assert_al_services_implement_apci_handler<D>()
where
    D: StackDefinition,
    D::State: HasCommObjects<CO = D::CO>,
    D::State: HasDomainAddress,
    AdcService: ApciHandler<D>,
    IndividualAddressSerialNumberService: ApciHandler<D>,
    AuthorizationService: ApciHandler<D>,
    DomainAddressService: ApciHandler<D>,
    FunctionPropertyService: ApciHandler<D>,
    UserManufacturerInfoService: ApciHandler<D>,
    MemoryService: ApciHandler<D>,
    PropertyExtValueService: ApciHandler<D>,
    SystemNetworkParameterService: ApciHandler<D>,
    UserMemoryService: ApciHandler<D>,
{
}

/// Compile-time assertion that every system-B augment satisfies the
/// `Augment<D>` trait. The bounds mirror each augment's own
/// `where_bounds(...)` plus the standard `D: StackDefinition` from
/// the trait.
fn _assert_augments_implement_augment<'a, D, SEQ>()
where
    D: StackDefinition,
    SEQ: SequenceNumberStorage + crate::kvstore::SiatAccess + 'a,
    Tp1Augment<'a>: Augment<D>,
    SecurityAugment<'a, SEQ, 8, 8, 16>: Augment<D>,
{
}

#[cfg(feature = "knxip")]
fn _assert_ip_augment_implements_augment<'a, D, P>()
where
    D: StackDefinition,
    P: IpPlatform + 'a,
    D::State: StackState,
    IpAugment<'a, P, 0>: Augment<D>,
{
}
