//! The three focused service traits: [`Layer`], [`ApciHandler`], and
//! [`Augment`].
//!
//! See the module-level documentation in [`crate::service`] for the
//! big-picture rationale and how the three relate to one another.

use embassy_time::Instant;

use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::knx::{ApciCode, KnxMessageBuffer, ServiceType};

use crate::definition::StackDefinition;
use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult,
    PropertyDescriptionResponse, PropertyDescriptor, PropertyError, PropertyLookup, WriteResponse,
};
use crate::service::ctx::ServiceCtx;

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
/// `&self` because the AL fans into its `Ext` chain mid-`process()`,
/// re-entrantly. Services that need state use interior mutability
/// (`Cell` / `RefCell`).
///
/// # Composition
///
/// `Ext` for an [`ApplicationLayer<Ext>`](crate::service::Layer) is
/// either a single `ApciHandler` impl, the empty handler `()`, or a
/// tuple `(A, B, C, …)` of `ApciHandler`s. The tuple impl tries each
/// member left-to-right; the first to return `true` claims the APCI.
/// Tuple arities `()` and 1..=8 are provided.
pub trait ApciHandler<D: StackDefinition> {
    /// Try to handle an APCI indication. Returns `true` if claimed
    /// (even if the response was suppressed), `false` to allow the
    /// next member of the chain to try.
    fn try_handle_apci(
        &self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &ServiceCtx<'_, D>,
    ) -> bool;
}

// =============================================================================
// Augment — interface-object property hooks + IO list contribution.
// =============================================================================

/// Implemented by IO-list contributors and property-hook intercepts
/// (Security, IpExt, Diagnostics, …).
///
/// One trait covers two responsibilities:
///
/// 1. **Adding interface objects** to the device's IO list (e.g.
///    `Security` adds IO type 0x11). Default: contributes nothing.
/// 2. **Intercepting property dispatch** on existing or augment-added
///    IOs. Each hook returns `Option<…>`; `Some` claims the request,
///    `None` chains to the next augment, then to the base IO impl.
///    All defaults return `None`.
///
/// Augments with temporal behaviour (Security's rekey timer,
/// Diagnostics' auto-revert) opt into lifecycle by overriding
/// [`next_deadline`](Self::next_deadline) and [`poll`](Self::poll).
/// Most augments leave them at the default no-op.
///
/// `&self` for the property hooks (re-entrant from inside layer
/// `process()`); `&mut self` for `poll` because lifecycle ticks come
/// from the router loop with exclusive access.
pub trait Augment<D: StackDefinition> {
    // -------------------------------------------------------------
    // IO contribution (defaults: contributes nothing)
    // -------------------------------------------------------------

    /// Number of additional interface objects this augment adds to
    /// the device's IO list. Default: 0.
    fn additional_object_count(&self) -> u16 {
        0
    }

    /// Object type for this augment's `index`-th additional IO
    /// object. `index` is augment-local. Default: `None`.
    fn additional_object_type_at(&self, _index: u16) -> Option<InterfaceObjectType> {
        None
    }

    /// Property descriptor lookup for an augment-provided property.
    ///
    /// Used by the IO container to check access policies before
    /// dispatching reads/writes. Returns `None` if this augment
    /// doesn't handle `(object_type, prop_id)`.
    fn get_property_descriptor(
        &self,
        _object_type: InterfaceObjectType,
        _prop_id: u16,
    ) -> Option<PropertyDescriptor> {
        None
    }

    // -------------------------------------------------------------
    // Property-hook dispatch (defaults: don't intercept anything)
    // -------------------------------------------------------------

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
    // Optional lifecycle (defaults: no timer)
    // -------------------------------------------------------------

    /// Earliest time this augment wants [`poll`](Self::poll) called,
    /// or `None` if no pending timer.
    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    /// Called when [`next_deadline`](Self::next_deadline) has elapsed.
    /// `ctx.access` is `AccessContext::default()`.
    fn poll(&mut self, _ctx: &ServiceCtx<'_, D>) {}
}
