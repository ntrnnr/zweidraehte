//! Registry traits implemented on the device's services struct.
//!
//! [`LayerRegistry`] and [`AugmentRegistry`] are the
//! services-struct-side surface that the runtime calls into. They are
//! never implemented by individual services — the
//! `#[derive(ServiceRegistry)]` macro emits both of them on a struct
//! whose fields are tagged with `#[service(handler | augment | flatten)]`.
//!
//! The runtime side reaches into `D::Services` via these traits only;
//! `Layer<D>` / `ApciHandler<D>` / `Augment<D>` themselves are not
//! visible there.

use embassy_time::Instant;

use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::knx::KnxMessageBuffer;

use crate::definition::StackDefinition;
use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult,
    PropertyDescriptionResponse, PropertyDescriptor, PropertyError, PropertyLookup, WriteResponse,
};
use crate::router::DispatchTable;
use crate::service::ctx::ServiceCtx;

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
    fn dispatch_wire(&mut self, idx: u8, msg: KnxMessageBuffer<Buffer<'static>>, ctx: &ServiceCtx<'_, D>);

    /// Initialise every `#[service(handler)]` field. Called once
    /// before the router loop starts; `ctx.access` is
    /// `AccessContext::default()`.
    fn init_layers(&mut self, ctx: &ServiceCtx<'_, D>);

    /// Tick every `#[service(handler)]` field's `poll`. Called when
    /// the router's selected timer arm fires.
    fn poll_layers(&mut self, ctx: &ServiceCtx<'_, D>);

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
    fn handle_service_input(&mut self, _input: Self::ServiceInput, _ctx: &ServiceCtx<'_, D>) {}

    /// Drain stack-level coordination events emitted during the
    /// dispatch cycle (e.g. DeviceModel transitions). Called after
    /// the outbox drain completes.
    ///
    /// Default no-op.
    fn drain_events(&mut self, _ctx: &ServiceCtx<'_, D>) {}
}

// =============================================================================
// AugmentRegistry
// =============================================================================

/// Property-hook chain + IO list contribution + augment-side
/// lifecycle aggregation.
///
/// Implemented exactly once per device, on the services struct, by
/// the `#[derive(ServiceRegistry)]` macro. Lists every
/// `#[service(augment)]` field plus the `#[service(augment)]` fields
/// from any `#[service(flatten)]` embedded sub-struct.
///
/// # Hook chaining
///
/// Each property-hook method walks the augment fields left-to-right;
/// the first to return `Some` claims the request. Mirrors the
/// existing `(Head, Tail)` chain shape of
/// [`InterfaceObjectAugment`](crate::objects::interface::InterfaceObjectAugment),
/// flattened across named fields.
///
/// # IO list aggregation
///
/// [`additional_object_count`](Self::additional_object_count) sums
/// across every augment.
/// [`additional_object_type_at`](Self::additional_object_type_at)
/// walks the augments in order; the first to claim an
/// in-range index returns it.
pub trait AugmentRegistry<D: StackDefinition> {
    // -------------------------------------------------------------
    // Property-hook chain
    // -------------------------------------------------------------

    fn get_property_descriptor(
        &self,
        object_type: InterfaceObjectType,
        prop_id: u16,
    ) -> Option<PropertyDescriptor>;

    fn property_description_read(
        &self,
        ctx: &ServiceCtx<'_, D>,
        object_type: InterfaceObjectType,
        object_idx: u16,
        lookup: PropertyLookup,
    ) -> Option<Result<PropertyDescriptionResponse, PropertyError>>;

    fn property_value_read(
        &self,
        ctx: &ServiceCtx<'_, D>,
        object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>>;

    fn property_value_write(
        &self,
        ctx: &ServiceCtx<'_, D>,
        object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>>;

    fn function_property_command(
        &self,
        ctx: &ServiceCtx<'_, D>,
        object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult>;

    fn function_property_state_read(
        &self,
        ctx: &ServiceCtx<'_, D>,
        object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult>;

    // -------------------------------------------------------------
    // IO list aggregation
    // -------------------------------------------------------------

    /// Total IO objects added across every augment.
    fn additional_object_count(&self) -> u16;

    /// Walks augments in order; converts a registry-global index into
    /// the corresponding augment-local index and delegates.
    fn additional_object_type_at(&self, index: u16) -> Option<InterfaceObjectType>;

    // -------------------------------------------------------------
    // Augment-side lifecycle
    // -------------------------------------------------------------

    /// Tick every augment that wants a timer.
    fn poll_augments(&mut self, ctx: &ServiceCtx<'_, D>);

    /// Earliest augment deadline across every `#[service(augment)]`
    /// field, or `None` if none have a pending timer.
    fn next_augment_deadline(&self) -> Option<Instant>;
}

// =============================================================================
// AugmentRegistry for () — the empty-augments default
// =============================================================================

/// Empty augment chain — every hook is `None`, contributes 0 IO objects,
/// has no deadline. Used as the default for [`StackDefinition::Augments`]
/// so devices without augments don't have to write any boilerplate.
impl<D: StackDefinition> AugmentRegistry<D> for () {
    fn get_property_descriptor(
        &self,
        _object_type: InterfaceObjectType,
        _prop_id: u16,
    ) -> Option<PropertyDescriptor> {
        None
    }

    fn property_description_read(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        _object_idx: u16,
        _lookup: PropertyLookup,
    ) -> Option<Result<PropertyDescriptionResponse, PropertyError>> {
        None
    }

    fn property_value_read(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        _req: &FullPropertyReadRequest,
        _buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        None
    }

    fn property_value_write(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        _req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        None
    }

    fn function_property_command(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        _req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        None
    }

    fn function_property_state_read(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        _req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        None
    }

    fn additional_object_count(&self) -> u16 {
        0
    }

    fn additional_object_type_at(&self, _index: u16) -> Option<InterfaceObjectType> {
        None
    }

    fn poll_augments(&mut self, _ctx: &ServiceCtx<'_, D>) {}

    fn next_augment_deadline(&self) -> Option<Instant> {
        None
    }
}
