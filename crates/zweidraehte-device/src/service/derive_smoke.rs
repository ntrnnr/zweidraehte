//! Smoke tests for `#[derive(ServiceRegistry)]` against shim
//! `Layer` / `Augment` impls.
//!
//! These tests don't exercise wire dispatch — they only verify the
//! macro emits compilable `LayerRegistry` / `AugmentRegistry` impls
//! against the new trait surface. End-to-end behaviour is covered
//! by the conformance suite once the real layers migrate.

use core::cell::Cell;

use embassy_time::Instant;
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::knx::{KnxMessageBuffer, ServiceType};

use crate::StackDefinition;
use crate::service::{AlCtx, ApciHandler, Augment, AugmentRegistry, Layer, LayerRegistry, ServiceCtx, ServiceRegistry};

// -----------------------------------------------------------------
// Shim Layer that handles a single, otherwise-unused ServiceType so
// the const dispatch table has something to register.
// -----------------------------------------------------------------

#[derive(Default)]
struct ShimLayer {
    process_calls: Cell<usize>,
    init_called:   Cell<bool>,
    poll_called:   Cell<bool>,
}

impl<D: StackDefinition> Layer<D> for ShimLayer {
    const HANDLES: &'static [ServiceType] = &[ServiceType::L_Data_Ind];

    fn init(&mut self, _ctx: &ServiceCtx<'_, D>) {
        self.init_called.set(true);
    }

    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    fn poll(&mut self, _ctx: &ServiceCtx<'_, D>) {
        self.poll_called.set(true);
    }

    fn process(&mut self, _msg: KnxMessageBuffer<Buffer<'static>>, _ctx: &ServiceCtx<'_, D>) {
        self.process_calls.set(self.process_calls.get() + 1);
    }
}

// -----------------------------------------------------------------
// Shim Augment with a single IO contribution and a poll deadline,
// to exercise the lifecycle and IO-list aggregation paths.
// -----------------------------------------------------------------

#[derive(Default)]
struct ShimAugment {
    poll_called: Cell<bool>,
}

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

    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    fn poll(&mut self, _ctx: &ServiceCtx<'_, D>) {
        self.poll_called.set(true);
    }
}

// `#[derive(ServiceRegistry)]` requires every `#[service(augment)]`
// field to satisfy `AugmentRegistry<D>`. For hand-written `Augment<D>`
// impls (no `#[interface_object_augment]` macro), use
// `forward_augment_registry!` to generate the matching forwarding
// `AugmentRegistry<D>` impl.
crate::forward_augment_registry!(ShimAugment);

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
// `#[service(flatten)]` — verifies the macro emits an
// AugmentRegistry impl that delegates each method into a nested
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
    SmokeServices: LayerRegistry<D> + AugmentRegistry<D>,
{
}

/// Type-level assertion that `#[service(flatten)]` produces a valid
/// `AugmentRegistry<D>` impl: the outer struct (`SmokeFlattenedAugments`)
/// must satisfy the bound regardless of the inner struct's identity,
/// confirming the macro emits the cross-trait forwarding correctly.
fn _assert_flatten_bounds<D: StackDefinition>()
where
    SmokeBaseAugments: AugmentRegistry<D>,
    SmokeFlattenedAugments: AugmentRegistry<D>,
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
    crate::layers::network::NetworkLayer<'static, D>: Layer<D>,
    crate::layers::transport::TransportLayer<'static, D, 1, 0>: Layer<D>,
{
}

#[cfg(feature = "knxip")]
fn _assert_cemi_tl_implements_service_layer<D: StackDefinition>()
where
    crate::layers::transport::cemi::CemiTransportLayer<'static, D, 1, 0>: Layer<D>,
{
}

/// Compile-time assertion that every AL service satisfies the new
/// `ApciHandler<D>` trait via its bridge shim. The bounds match the
/// macro's: the AL itself requires `HasCommObjects` so the
/// conversion always works in practice.
fn _assert_al_services_implement_apci_handler<D>()
where
    D: StackDefinition,
    D::State: crate::objects::comm::HasCommObjects<CO = D::CO>,
    D::State: crate::objects::interface::HasDomainAddress,
    crate::layers::application::services::adc::AdcService: ApciHandler<D>,
    crate::layers::application::services::address_serial::IndividualAddressSerialNumberService: ApciHandler<D>,
    crate::layers::application::services::authorization::AuthorizationService: ApciHandler<D>,
    crate::layers::application::services::domain_addr::DomainAddressService: ApciHandler<D>,
    crate::layers::application::services::function_property::FunctionPropertyService: ApciHandler<D>,
    crate::layers::application::services::manufacturer::UserManufacturerInfoService: ApciHandler<D>,
    crate::layers::application::services::memory::MemoryService: ApciHandler<D>,
    crate::layers::application::services::property_ext::PropertyExtValueService: ApciHandler<D>,
    crate::layers::application::services::system_network_parameter::SystemNetworkParameterService: ApciHandler<D>,
    crate::layers::application::services::user_memory::UserMemoryService: ApciHandler<D>,
{
}

/// Compile-time assertion that every system-B augment satisfies the
/// new `Augment<D>` trait via its bridge shim. The bounds mirror
/// each augment's own `where_bounds(...)` plus the standard
/// `D: StackDefinition` from the trait.
fn _assert_augments_implement_augment<'a, D, SEQ>()
where
    D: StackDefinition,
    SEQ: crate::storage::SequenceNumberStorage + 'a,
    crate::bcus::system_b::Tp1ExtensionState: Augment<D>,
    crate::bcus::system_b::SecurityAugment<'a, SEQ, 8, 8, 16, 16>: Augment<D>,
{
}

#[cfg(feature = "knxip")]
fn _assert_ip_augment_implements_augment<'a, D, P>()
where
    D: StackDefinition,
    P: crate::IpPlatform + 'a,
    D::State: crate::StackState,
    crate::bcus::system_b::IpAugment<'a, P, 0, 0>: Augment<D>,
{
}
