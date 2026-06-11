//! Services-struct aggregator trait that the runtime calls into.
//!
//! [`LayerRegistry`] is implemented exclusively by the
//! `#[derive(ServiceRegistry)]` macro on a struct whose fields are
//! tagged with `#[service(handler | flatten)]` — the runtime reaches
//! into `D::Services` via this trait only; [`Layer<D>`](crate::service::Layer)
//! / [`ApciHandler<D>`](crate::service::ApciHandler) are not visible
//! there.
//!
//! The augment side has no separate aggregator trait — both leaf
//! augments and services-struct bundles implement the same
//! [`Augment<D>`](crate::service::Augment) (defined in
//! [`crate::service::traits`]).

use embassy_time::Instant;

use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::knx::KnxMessageBuffer;

use crate::definition::StackDefinition;
use crate::router::DispatchTable;

// =============================================================================
// LayerRegistry
// =============================================================================

/// Wire dispatch + layer-side lifecycle aggregation.
///
/// Implemented exactly once per device, on the services struct, by
/// the `#[derive(ServiceRegistry)]` macro. Lists every
/// `#[service(handler)]` field plus the `#[service(handler)]` fields
/// from any `#[service(flatten)]` embedded sub-struct.
///
/// # Const dispatch table
///
/// [`DISPATCH_TABLE`](Self::DISPATCH_TABLE) is built at compile time
/// by walking each `#[service(handler)]` field's
/// [`Layer::HANDLES`](crate::service::Layer::HANDLES) and registering
/// `(ServiceType, field_index)` pairs. Duplicate registrations
/// across different handler fields fail to compile via
/// [`DispatchTable::register`](crate::router::DispatchTable::register)'s
/// const assertion, preserving the today's "exactly one layer
/// owns each ServiceType" guarantee.
pub trait LayerRegistry<D: StackDefinition> {
    /// Compile-time `ServiceType → field-index` table built from
    /// every `#[service(handler)]` field's `HANDLES`.
    const DISPATCH_TABLE: DispatchTable;

    /// Route a wire message to the field that registered for this
    /// `ServiceType`. The router has already resolved the field index
    /// via [`Self::DISPATCH_TABLE`].
    fn dispatch_wire(&mut self, idx: u8, msg: KnxMessageBuffer<Buffer<'static>>);

    /// Initialise every `#[service(handler)]` field. Called once
    /// before the router loop starts.
    fn init_layers(&mut self);

    /// Tick every `#[service(handler)]` field's `poll`. Called when
    /// the router's selected timer arm fires.
    fn poll_layers(&mut self);

    /// Earliest deadline across every `#[service(handler)]` field, or
    /// `None` if none of them have a pending timer.
    fn next_layer_deadline(&self) -> Option<Instant>;

    // -------------------------------------------------------------
    // Service inputs and side-effect events
    //
    // The router runs `select` over LL ind/conf, layer timers, and
    // [`recv_service_input`](Self::recv_service_input). The default
    // is a never-resolving future, fine for stacks with no
    // user-side actor channels.
    //
    // `drain_events` is invoked after every dispatch cycle so
    // stack-level coordination state (DeviceModel transitions,
    // run-state-machine ticks) can fire side effects.
    // -------------------------------------------------------------

    /// Event type returned by [`recv_service_input`](Self::recv_service_input).
    /// Defaults to the never type for stacks with no service inputs.
    type ServiceInput = !;

    /// Wait for a service input event (e.g. an actor request from
    /// user code, or a cEMI event from an IP runtime task).
    ///
    /// Default: pends forever.
    fn recv_service_input(&self) -> impl core::future::Future<Output = Self::ServiceInput> + '_ {
        core::future::pending()
    }

    /// Process a service input that [`recv_service_input`](Self::recv_service_input) resolved with.
    ///
    /// Default `match input {}` — works against the never type.
    fn handle_service_input(&mut self, _input: Self::ServiceInput) {}

    /// Drain stack-level coordination events emitted during the
    /// dispatch cycle (e.g. DeviceModel transitions). Called after
    /// the outbox drain completes.
    ///
    /// Default no-op.
    fn drain_events(&mut self) {}
}

// =============================================================================
// LifecycleHook
// =============================================================================

/// Stack-level lifecycle hook for fields that aren't `Layer<D>` or
/// `Augment<D>` but still need an init pass and per-cycle drain.
///
/// Used by `#[service(lifecycle)]` fields on a `#[derive(ServiceRegistry)]`
/// stack. The macro emits one `LifecycleHook::init(&mut self.field)`
/// call per lifecycle field at the top of `init_layers`, and one
/// `LifecycleHook::drain_events(&mut self.field)` per field inside
/// the generated `drain_events` override.
pub trait LifecycleHook<D: StackDefinition> {
    /// Run once before the router loop starts.
    fn init(&mut self);

    /// Run after each dispatch cycle (after the outbox drain).
    fn drain_events(&mut self);
}
