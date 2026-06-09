//! The three single-service traits: [`Layer`], [`ApciHandler`], and
//! [`Augment`].
//!
//! See the module-level documentation in [`crate::service`] for the
//! big-picture rationale and how they relate to
//! [`LayerRegistry`](crate::service::LayerRegistry) (the
//! services-struct aggregator built by `#[derive(ServiceRegistry)]`).

use embassy_time::Instant;

use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::knx::{ApciCode, KnxMessageBuffer, ServiceType};

use crate::definition::StackDefinition;
use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult,
    PropertyDescriptionResponse, PropertyDescriptor, PropertyError, PropertyLookup, WriteResponse,
};
use crate::service::ctx::{AlCtx, ServiceCtx};

// =============================================================================
// Layer — wire-message handler with full lifecycle.
// =============================================================================

/// Implemented by NL / TL / AL / SecureAL — services that consume
/// [`ServiceType`]s off the router's dispatch table.
///
/// `&mut self` everywhere so connection tables, hop counters, and
/// other working state are plain fields without `RefCell` boilerplate.
/// The router's wire-dispatch resolves to one `&mut self.<field>`
/// borrow per call (see [`crate::service`] mutability story).
///
/// # Lifecycle
///
/// - [`init`](Self::init) runs once before the router loop starts.
/// - [`next_deadline`](Self::next_deadline) and [`poll`](Self::poll)
///   together implement the timer loop. The router computes
///   `min(deadlines)` across every layer, sleeps until then, and
///   calls [`poll`](Self::poll) on layers that wanted a deadline.
pub trait Layer<D: StackDefinition> {
    /// `ServiceType`s this layer wants to receive.
    ///
    /// Used at compile time to build the device's
    /// [`DispatchTable`](crate::router::DispatchTable). Each
    /// `ServiceType` may appear in `HANDLES` of at most one layer
    /// across the device's services struct.
    const HANDLES: &'static [ServiceType];

    /// One-time setup. Called once before the router loop starts;
    /// `ctx.access` is `AccessContext::default()`.
    fn init(&mut self, _ctx: &ServiceCtx<'_, D>) {}

    /// Earliest time this layer wants [`poll`](Self::poll) called, or
    /// `None` if it has no pending timer.
    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    /// Called when [`next_deadline`](Self::next_deadline) has elapsed.
    /// `ctx.access` is `AccessContext::default()`.
    fn poll(&mut self, _ctx: &ServiceCtx<'_, D>) {}

    /// Process a routed wire message. Push outputs to
    /// [`ServiceCtx::outbox`].
    fn process(&mut self, msg: KnxMessageBuffer<Buffer<'static>>, ctx: &ServiceCtx<'_, D>);
}

// =============================================================================
// ApciHandler — APCI fall-through inside the AL.
// =============================================================================

/// Implemented by AL extensions (Memory, Authorization,
/// PropertyExtValue, DomainAddress, …) — services that handle APCI
/// codes the AL does not handle inline.
///
/// Receives an [`AlCtx`] (the rich AL-side context: state, layer
/// context, access plus the interface-objects container and memory
/// map). `&self` because the AL fans into its `Ext` chain
/// mid-`process()`, re-entrantly. Services that need state use
/// interior mutability (`Cell` / `RefCell`).
///
/// # Composition
///
/// `Ext` for an [`ApplicationLayer<Ext>`](crate::service::Layer) is
/// either a single `ApciHandler` impl, the empty handler `()`, or a
/// tuple `(A, B, C, …)` of `ApciHandler`s. The tuple impl tries each
/// member left-to-right; the first to return `true` claims the APCI.
/// Tuple arities `()` and 1..=12 are provided.
pub trait ApciHandler<D: StackDefinition> {
    /// Try to handle an APCI indication. Returns `true` if claimed
    /// (even if the response was suppressed), `false` to allow the
    /// next member of the chain to try.
    fn try_handle_apci(&self, apci: ApciCode, msg: &KnxMessageBuffer<Buffer<'static>>, ctx: &AlCtx<'_, D>) -> bool;
}

// =============================================================================
// Augment — interface-object property hooks + IO list contribution.
// =============================================================================

/// Property-hook chain, IO list contribution, and augment-side
/// lifecycle.
///
/// This trait wears two hats:
///
/// 1. **Leaf augment**: a single contributor (e.g. `IpAugment`,
///    `SecurityAugment`, `Tp1ExtensionState`) intercepting property
///    dispatch on existing or augment-added interface objects, and/or
///    adding new interface objects to the device's IO list. Authored
///    via [`#[interface_object_augment]`](::zweidraehte_device_macros::interface_object_augment),
///    which generates the impl from `#[io(...)]` field annotations.
///    Hand-rolled impls override only the hooks they service — every
///    method has a default returning `None` / `0` / no-op.
///
/// 2. **Aggregator**: a services-struct field bundle, generated by
///    `#[derive(ServiceRegistry)]` from `#[service(augment | flatten)]`
///    fields. Each property-hook method walks the augment fields
///    left-to-right; the first to return `Some` claims the request.
///    [`additional_object_count`](Self::additional_object_count) sums
///    across fields;
///    [`additional_object_type_at`](Self::additional_object_type_at)
///    walks them in order, converting a registry-global index into
///    the corresponding augment-local index.
///
/// The runtime consumes augments exclusively through this trait; both
/// authoring and aggregation use the same surface.
pub trait Augment<D: StackDefinition> {
    // -------------------------------------------------------------
    // Property-hook chain (defaults: don't intercept anything)
    // -------------------------------------------------------------

    /// Property descriptor lookup for an augment-provided property.
    ///
    /// Used by the IO container to check access policies before
    /// dispatching reads/writes. Returns `None` if this augment
    /// doesn't handle `(object_type, prop_id)`.
    fn get_property_descriptor(&self, _object_type: InterfaceObjectType, _prop_id: u16) -> Option<PropertyDescriptor> {
        None
    }

    /// Optional override for `A_PropertyDescription_Read`.
    fn property_description_read(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        _object_idx: u16,
        _lookup: PropertyLookup,
    ) -> Option<Result<PropertyDescriptionResponse, PropertyError>> {
        None
    }

    /// Optional override for `A_PropertyValue_Read`.
    fn property_value_read(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        _req: &FullPropertyReadRequest,
        _buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        None
    }

    /// Optional override for `A_PropertyValue_Write`.
    fn property_value_write(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        _req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        None
    }

    /// Optional override for `A_FunctionPropertyCommand`.
    fn function_property_command(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        _req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        None
    }

    /// Optional override for `A_FunctionPropertyState_Read`.
    fn function_property_state_read(
        &self,
        _ctx: &ServiceCtx<'_, D>,
        _object_type: InterfaceObjectType,
        _req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        None
    }

    // -------------------------------------------------------------
    // IO list contribution (defaults: contributes nothing)
    // -------------------------------------------------------------

    /// Number of additional interface objects added to the device's
    /// IO list. Aggregator impls sum across every augment; leaf
    /// impls return their own count. Default: 0.
    fn additional_object_count(&self) -> u16 {
        0
    }

    /// Object type for the `index`-th additional IO object. Aggregator
    /// impls walk fields in order, subtracting each field's count
    /// until they hit the field whose range covers `index`. Leaf
    /// impls treat `index` as augment-local. Default: `None`.
    fn additional_object_type_at(&self, _index: u16) -> Option<InterfaceObjectType> {
        None
    }

    /// Number of `A_PropertyDescription_Read`-visible property descriptors this
    /// augment contributes for `object_type`.
    ///
    /// This is what lets *two* augments contribute to the **same** interface
    /// object: the [`ServiceRegistry`](crate::service::ServiceRegistry)
    /// aggregator sums it across the augments declared before a given field, so
    /// an index-based property scan can rebase the requested index into each
    /// augment's own descriptor table instead of every augment starting at
    /// index 0 (which made a second augment's properties unreachable by index).
    ///
    /// Leaf augments return the count of their declared descriptors for
    /// `object_type`; aggregator impls sum across fields. Default: 0.
    fn descriptor_count_for(&self, _object_type: InterfaceObjectType) -> u16 {
        0
    }

    // -------------------------------------------------------------
    // Augment-side lifecycle (defaults: no timer)
    // -------------------------------------------------------------

    /// Tick every augment that wants a timer. Aggregator impls fan
    /// out across every `#[service(augment | flatten)]` field; leaf
    /// impls drive their own state forward (e.g. Security's rekey
    /// timer, Diagnostics' auto-revert). Default: no-op.
    fn poll_augments(&mut self, _ctx: &ServiceCtx<'_, D>) {}

    /// Earliest augment deadline. Aggregator impls take the `min`
    /// across every field; leaf impls return their own pending
    /// deadline, or `None` if none. Default: `None`.
    fn next_augment_deadline(&self) -> Option<Instant> {
        None
    }
}

// =============================================================================
// Augment — convenience impls
// =============================================================================

/// Empty augment chain — no IO objects, no hooks, no deadline. The
/// trait's defaults already cover every method, but having an
/// explicit `()` impl lets devices that don't use augments name `()`
/// as their `StackDefinition::Augments` without any custom type.
impl<D: StackDefinition> Augment<D> for () {}

// A `&A: Augment<D>` shared-ref forwarding impl used to live here, solely so
// the TP1 extension's `&'a Tp1ExtensionState` augment satisfied `Augment<D>`.
// TP1 now hands out a by-value `Tp1Augment<'a>` like the other extensions, so
// nothing borrows its augment through a shared ref any more and the forwarding
// impl (whose `poll_augments` was a forced no-op) was removed as dead code.
