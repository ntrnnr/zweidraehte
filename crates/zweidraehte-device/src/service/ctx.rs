//! [`ServiceCtx`] and [`AlCtx`] — the per-request contexts handed to
//! augment hooks and AL services.
//!
//! Both are built at dispatch time by the AL or the IO container,
//! carrying the *request's* [`AccessContext`] — they are never threaded
//! through the router or the [`Layer`](crate::service::Layer) trait
//! (layers capture their environment at construction instead).
//!
//! - [`ServiceCtx`] is the lean, augment-friendly bundle: state,
//!   layer context, access context. Anyone that can borrow these
//!   three references can build one. Carries the convenience
//!   accessors (`buffer_manager`, capability senders, APDU
//!   budget helpers).
//! - [`AlCtx`] wraps a `ServiceCtx` (as the public `base` field) and
//!   adds the AL-only handles — the interface-objects container and
//!   the memory map — that AL services need to dispatch property /
//!   memory operations. Lean state is reached explicitly through
//!   `ctx.base.…`; there is deliberately no `Deref` sugar.
//!
//! The split exists because the IO container — which is *itself*
//! the interface-objects container — needs to call augments without
//! self-referencing into a `ServiceCtx`. Augments take the lean ctx
//! so the IO container can manufacture one trivially. AL services
//! continue to receive the rich ctx so they can dispatch property
//! and memory ops without extra plumbing.

use zweidraehte_proto::access::{AccessContext, SecurityMode};
use zweidraehte_proto::config::max_outgoing_msg_len;
use zweidraehte_proto::messages::buffers::DynBufferManager;

use crate::StackState;
use crate::context::layer::LayerContext;
use crate::definition::StackDefinition;
use crate::layers::application::group_data::GroupDataProvider;
use crate::layers::secure_application::SecureGroupDataProvider;

/// Lean per-call context handed to augments and any handler that
/// only needs state / layer-context / access.
///
/// Field access is `pub` so handlers can reach the underlying
/// references directly. The convenience accessors below mirror the
/// most frequently used capability shortcuts (buffer manager, APDU
/// budget helpers, capability senders) without forcing handlers to
/// chase trait re-exports. To enqueue outgoing wire messages, call
/// [`LayerContext::push_outbox`] directly on `ctx.lctx`.
///
/// # Lifetime
///
/// `'a` is the construction-time lifetime of [`StackResources`](crate::StackResources).
/// Every reference here lives for the entire runtime of the stack.
pub struct ServiceCtx<'a, D: StackDefinition> {
    /// Unified device state (tables, runtime config, optional storage
    /// for legacy `Has*`-on-state extensions).
    pub state: &'a D::State,

    /// Shared runtime infrastructure: outbox, buffer manager, channels,
    /// shared group-data bookkeeping.
    pub lctx: &'a LayerContext<D>,

    /// Access context of the request that triggered this dispatch.
    /// Carries the caller's authorization level and whether the
    /// request arrived via KNX Data Secure. Lifecycle ticks (`init` /
    /// `poll`) pass `AccessContext::default()`.
    pub access: AccessContext,
}

impl<'a, D: StackDefinition> ServiceCtx<'a, D> {
    /// Construct a lean `ServiceCtx`.
    #[inline]
    pub fn new(state: &'a D::State, lctx: &'a LayerContext<D>, access: AccessContext) -> Self {
        Self { state, lctx, access }
    }

    // -----------------------------------------------------------------
    // Convenience accessors. Keep this surface small — direct field
    // access through the public fields is the canonical path.
    // -----------------------------------------------------------------

    /// Buffer manager for response-buffer allocation.
    #[inline]
    pub fn buffer_manager(&self) -> &'a DynBufferManager<'static> {
        &self.lctx.buffer_manager
    }

    /// Maximum on-wire APDU bytes available for an outgoing response,
    /// accounting for the secure envelope when the request arrived
    /// secured.
    ///
    /// Returns `state.max_apdu_length()` (already clamped to
    /// `D::MAX_APDU_LENGTH` and to any lower link-layer ceiling),
    /// reduced by the secure-envelope overhead when `access.security`
    /// is not `Plain`.
    #[inline]
    pub fn effective_apdu_budget(&self) -> usize {
        max_outgoing_msg_len(self.state.max_apdu_length(), self.access.security != SecurityMode::Plain)
    }

    /// Largest payload a response may carry given a fixed header
    /// length. Saturating at zero so pathological budgets don't
    /// underflow.
    #[inline]
    pub fn response_payload_cap(&self, header_len: usize) -> usize {
        self.effective_apdu_budget().saturating_sub(header_len)
    }

    /// Whether a response of total `msg_len` (internal-format frame
    /// length from offset 0) fits within the effective APDU budget.
    #[inline]
    pub fn response_fits(&self, msg_len: usize) -> bool {
        msg_len <= self.effective_apdu_budget()
    }

    /// Capability handle for outgoing group-value reads/writes by ASAP.
    ///
    /// Builds a transient
    /// [`GroupDataProvider`] backed by the current state and layer
    /// context. Persistent bookkeeping (pending sends, read-on-init
    /// progress) lives on the shared [`LayerContext`], so per-call
    /// construction is cheap.
    #[inline]
    pub fn group_value_sender(&self) -> GroupDataProvider<'a, D> {
        GroupDataProvider::new(self.state, self.lctx)
    }

    /// Capability handle for outgoing *secure* group-value emissions
    /// addressed by TSAP.
    ///
    /// The provider's [`SecureGroupValueAddressedSender`](crate::layers::application::capabilities::SecureGroupValueAddressedSender)
    /// impl is gated on the device having the necessary secure-side
    /// state (group-key table + sending-side seq-number storage); on
    /// stacks without those bounds, the value here exists but its
    /// sender methods aren't callable.
    #[inline]
    pub fn secure_group_value_sender(&self) -> SecureGroupDataProvider<'a, D> {
        SecureGroupDataProvider::new(self.state, self.lctx)
    }
}

/// Rich AL-side context — bundles a [`ServiceCtx`] with the
/// interface-objects container and the memory map that AL services
/// dispatch property / memory operations through.
///
/// Lean state is reached explicitly through the public `base` field —
/// there is deliberately no `Deref` to `ServiceCtx` (contexts are not
/// smart pointers, and the explicit path keeps it obvious which half
/// a handler touches):
///
/// ```rust,ignore
/// fn handle(ctx: &AlCtx<'_, D>) {
///     // Lean half, through `base`:
///     let _ = ctx.base.state;
///     let _ = ctx.base.buffer_manager();
///
///     // Rich-only fields:
///     let _ = ctx.interface_objects;
///     let _ = ctx.memory_map;
/// }
/// ```
pub struct AlCtx<'a, D: StackDefinition> {
    /// The lean per-call context: state, layer context, access.
    pub base: ServiceCtx<'a, D>,

    /// Interface objects container — the AL's built-in property
    /// dispatch and AN163 extended property services route through
    /// this.
    pub interface_objects: &'a D::InterfaceObjects<'static>,

    /// Memory map for `A_Memory_Read` / `A_Memory_Write` and
    /// `A_MemoryExtended_*` services.
    pub memory_map: &'a D::Mem,
}

impl<'a, D: StackDefinition> AlCtx<'a, D> {
    /// Build an `AlCtx` from a lean `ServiceCtx` and the AL-only
    /// references the AL has at hand.
    #[inline]
    pub fn new(
        base: ServiceCtx<'a, D>,
        interface_objects: &'a D::InterfaceObjects<'static>,
        memory_map: &'a D::Mem,
    ) -> Self {
        Self { base, interface_objects, memory_map }
    }
}
