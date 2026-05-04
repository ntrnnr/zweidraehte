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
/// [`Augment<D>`](crate::service::Augment),
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
// AugmentRegistry impls for the legacy Augment<D> chain shapes
// =============================================================================
//
// The IO container's `augments: &'a Aug` field accepts anything
// satisfying `AugmentRegistry<D>`. To preserve compatibility with
// the existing right-nested `(Head, Tail)` tuple chain that today's
// devices use, the unit `()`, the tuple form, and shared-ref `&A`
// each get an explicit `AugmentRegistry<D>` impl that forwards to
// their `Augment<D>` impl one-to-one.
//
// We intentionally do NOT use a blanket `impl<A: Augment<D>>
// AugmentRegistry<D> for A` because that would conflict with the
// macro-derived impls per Rust's coherence rules ("downstream crates
// may implement Augment for SmokeServices").

/// Empty augment chain — no IO objects, no hooks, no deadline.
/// Default for [`StackDefinition::Augments`] on devices without
/// augments.
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

/// Shared-ref forwarding. Hooks are `&self`; only `poll_augments`
/// needs special handling because it's `&mut self` on the trait but
/// can't be on a shared reference. Implemented by ignoring the poll
/// call — devices using `&A` cannot drive their augment's lifecycle
/// through that reference, which is consistent with how the IO
/// container holds `&'a D::Augments<'a>`: lifecycle ticks happen
/// through the runner's `&mut augments_owner`, not through the IO
/// container's shared borrow.
impl<D: StackDefinition, A: AugmentRegistry<D>> AugmentRegistry<D> for &A {
    fn get_property_descriptor(
        &self,
        object_type: InterfaceObjectType,
        prop_id: u16,
    ) -> Option<PropertyDescriptor> {
        (**self).get_property_descriptor(object_type, prop_id)
    }
    fn property_description_read(
        &self,
        ctx: &ServiceCtx<'_, D>,
        object_type: InterfaceObjectType,
        object_idx: u16,
        lookup: PropertyLookup,
    ) -> Option<Result<PropertyDescriptionResponse, PropertyError>> {
        (**self).property_description_read(ctx, object_type, object_idx, lookup)
    }
    fn property_value_read(
        &self,
        ctx: &ServiceCtx<'_, D>,
        object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        (**self).property_value_read(ctx, object_type, req, buf)
    }
    fn property_value_write(
        &self,
        ctx: &ServiceCtx<'_, D>,
        object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        (**self).property_value_write(ctx, object_type, req)
    }
    fn function_property_command(
        &self,
        ctx: &ServiceCtx<'_, D>,
        object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        (**self).function_property_command(ctx, object_type, req)
    }
    fn function_property_state_read(
        &self,
        ctx: &ServiceCtx<'_, D>,
        object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        (**self).function_property_state_read(ctx, object_type, req)
    }
    fn additional_object_count(&self) -> u16 {
        (**self).additional_object_count()
    }
    fn additional_object_type_at(&self, index: u16) -> Option<InterfaceObjectType> {
        (**self).additional_object_type_at(index)
    }
    fn poll_augments(&mut self, _ctx: &ServiceCtx<'_, D>) {
        // No-op: a shared ref cannot drive `&mut self` lifecycle. The
        // owner runs `poll_augments` on the augment chain directly.
    }
    fn next_augment_deadline(&self) -> Option<Instant> {
        (**self).next_augment_deadline()
    }
}

// =============================================================================
// forward_augment_registry! — forward AugmentRegistry to a type's Augment impl
// =============================================================================

/// Generate an `AugmentRegistry<D>` impl for a concrete augment type
/// by forwarding every method to its existing [`Augment<D>`](crate::service::Augment)
/// impl.
///
/// Why this exists: a blanket `impl<A: Augment<D>> AugmentRegistry<D>
/// for A` would conflict with the macro-derived `AugmentRegistry<D>`
/// impls per Rust's coherence rules. Concrete-type impls are
/// unambiguous, so we generate them per augment via this macro.
///
/// # Usage
///
/// ```rust,ignore
/// pub struct MyAugment { /* … */ }
///
/// impl<D: StackDefinition> Augment<D> for MyAugment { /* … */ }
///
/// // Generates: impl<D: StackDefinition> AugmentRegistry<D> for MyAugment { … }
/// zweidraehte_device::service::forward_augment_registry!(MyAugment);
/// ```
///
/// For augments with their own generics:
///
/// ```rust,ignore
/// zweidraehte_device::service::forward_augment_registry!(
///     <'a, P: IpPlatform, const N: usize, const C: u16>
///     IpAugment<'a, P, N, C>
/// );
/// ```
///
/// The forwarding impl mirrors the explicit `for ()` impl shape:
/// every hook delegates straight to the matching `Augment<D>` method,
/// `poll_augments` calls `Augment::poll`, and `next_augment_deadline`
/// calls `Augment::next_deadline`.
#[macro_export]
macro_rules! forward_augment_registry {
    // Generic form, bracketed parameter list to avoid macro_rules ambiguity
    (
        [$($g:tt)*] $ty:ty $(where [$($bounds:tt)*])?
    ) => {
        impl<D: $crate::StackDefinition, $($g)*> $crate::service::AugmentRegistry<D> for $ty
        $(where $($bounds)*)?
        {
            fn get_property_descriptor(
                &self,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                prop_id: u16,
            ) -> ::core::option::Option<$crate::objects::interface::PropertyDescriptor> {
                $crate::service::Augment::<D>::get_property_descriptor(self, object_type, prop_id)
            }
            fn property_description_read(
                &self,
                ctx: &$crate::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                object_idx: u16,
                lookup: $crate::objects::interface::PropertyLookup,
            ) -> ::core::option::Option<::core::result::Result<
                $crate::objects::interface::PropertyDescriptionResponse,
                $crate::objects::interface::PropertyError,
            >> {
                $crate::service::Augment::<D>::property_description_read(self, ctx, object_type, object_idx, lookup)
            }
            fn property_value_read(
                &self,
                ctx: &$crate::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                req: &$crate::objects::interface::FullPropertyReadRequest,
                buf: &mut [u8],
            ) -> ::core::option::Option<::core::result::Result<usize, $crate::objects::interface::PropertyError>> {
                $crate::service::Augment::<D>::property_value_read(self, ctx, object_type, req, buf)
            }
            fn property_value_write(
                &self,
                ctx: &$crate::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                req: &$crate::objects::interface::FullPropertyWriteRequest<'_>,
            ) -> ::core::option::Option<::core::result::Result<
                $crate::objects::interface::WriteResponse,
                $crate::objects::interface::PropertyError,
            >> {
                $crate::service::Augment::<D>::property_value_write(self, ctx, object_type, req)
            }
            fn function_property_command(
                &self,
                ctx: &$crate::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                req: &$crate::objects::interface::FunctionPropertyRequest<'_>,
            ) -> ::core::option::Option<$crate::objects::interface::FunctionPropertyResult> {
                $crate::service::Augment::<D>::function_property_command(self, ctx, object_type, req)
            }
            fn function_property_state_read(
                &self,
                ctx: &$crate::service::ServiceCtx<'_, D>,
                object_type: ::zweidraehte_proto::dpt::InterfaceObjectType,
                req: &$crate::objects::interface::FunctionPropertyRequest<'_>,
            ) -> ::core::option::Option<$crate::objects::interface::FunctionPropertyResult> {
                $crate::service::Augment::<D>::function_property_state_read(self, ctx, object_type, req)
            }
            fn additional_object_count(&self) -> u16 {
                $crate::service::Augment::<D>::additional_object_count(self)
            }
            fn additional_object_type_at(
                &self,
                index: u16,
            ) -> ::core::option::Option<::zweidraehte_proto::dpt::InterfaceObjectType> {
                $crate::service::Augment::<D>::additional_object_type_at(self, index)
            }
            fn poll_augments(&mut self, ctx: &$crate::service::ServiceCtx<'_, D>) {
                $crate::service::Augment::<D>::poll(self, ctx);
            }
            fn next_augment_deadline(&self) -> ::core::option::Option<::embassy_time::Instant> {
                $crate::service::Augment::<D>::next_deadline(self)
            }
        }
    };
    // Simple form: no generics, no bounds
    ($ty:ty) => {
        $crate::forward_augment_registry!([] $ty);
    };
}
