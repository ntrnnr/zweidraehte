//! [`ServiceCtx`] — the shared per-call context for all service traits.
//!
//! Carries references to state, layer infrastructure, interface
//! objects, memory map, and the access context derived from the
//! incoming request. One bundle covers every service trait.

use core::cell::RefCell;

use zweidraehte_proto::access::{AccessContext, SecurityMode};
use zweidraehte_proto::config::max_outgoing_msg_len;
use zweidraehte_proto::messages::buffers::DynBufferManager;

use crate::StackState;
use crate::context::layer::LayerContext;
use crate::definition::StackDefinition;
use crate::layers::application::group_data::GroupDataProvider;
use crate::layers::secure_application::SecureGroupDataProvider;
use crate::router::Outbox;

/// Per-call context handed to every service trait method.
///
/// Field access is `pub` so services can reach the underlying handles
/// directly — the convenience accessors below mirror the most
/// frequently used capability shortcuts (outbox, buffer manager,
/// group-value senders) without forcing services to chase trait
/// re-exports.
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

    /// Interface objects container — used by the AL's built-in
    /// property dispatch and by `Augment` impls that read/write
    /// existing IOs.
    pub interface_objects: &'a D::InterfaceObjects<'static>,

    /// Memory map for `A_Memory_Read` / `A_Memory_Write`.
    pub memory_map: &'a D::Mem,

    /// Access context of the request that triggered this dispatch.
    /// Carries the caller's authorization level and whether the
    /// request arrived via KNX Data Secure. Lifecycle ticks pass
    /// `AccessContext::default()`.
    pub access: AccessContext,
}

impl<'a, D: StackDefinition> ServiceCtx<'a, D> {
    /// Construct a `ServiceCtx`. Most call sites build this from
    /// `Inner` + `D::InterfaceObjects` + the resolved `AccessContext`
    /// for the in-flight message; lifecycle ticks (`init` / `poll`)
    /// pass `AccessContext::default()`.
    #[inline]
    pub fn new(
        state: &'a D::State,
        lctx: &'a LayerContext<D>,
        interface_objects: &'a D::InterfaceObjects<'static>,
        memory_map: &'a D::Mem,
        access: AccessContext,
    ) -> Self {
        Self { state, lctx, interface_objects, memory_map, access }
    }

    // -----------------------------------------------------------------
    // Convenience accessors. Keep this surface small — direct field
    // access through the public fields is the canonical path.
    // -----------------------------------------------------------------

    /// Shared outbox; push wire messages here from inside `process`.
    #[inline]
    pub fn outbox(&self) -> &'a RefCell<Outbox> {
        &self.lctx.outbox
    }

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
