//! Application layer service trait.
//!
//! [`AlService`] is the unified trait for application-layer service
//! logic. It handles APCI codes that arrive at the AL, composes via
//! tuples for multi-service devices, and uses `&self` with interior
//! mutability so services can be called from anywhere that holds a
//! shared reference (including interface object augments).
//!
//! # Composition
//!
//! Services compose via tuples: `(A, B)` tries `A` first, then `B`. The
//! `()` type is the empty service (handles nothing). Device definitions
//! combine multiple independent services:
//!
//! ```rust,ignore
//! type Services = (DomainAddressService, MemoryService);
//! ```
//!
//! # Design
//!
//! All methods take `&self`. Implementations use [`core::cell::Cell`]
//! or [`core::cell::RefCell`] for mutable state. This lets services be
//! accessed from multiple call sites within a single dispatch cycle
//! (e.g., an interface object augment invoking a service capability
//! while the AL is in the middle of processing a message).
//!
//! # Relationship to AL core handlers
//!
//! Today the AL contains built-in handlers (group data, property
//! services, device management) that are not yet `AlService` impls.
//! New functionality is added as `AlService` impls alongside. Built-in
//! handlers may migrate into services incrementally without requiring
//! a big-bang AL split.

use crate::{
    definition::StackDefinition};
use zweidraehte_proto::access::AccessContext;
use zweidraehte_proto::messages::{
        buffers::{Buffer, DynBufferManager},
        knx::{ApciCode, KnxMessageBuffer},
    };

// ============================================================================
// Service Context
// ============================================================================

/// Shared resources available to AL service handlers.
///
/// Bundles the resources the AL and its services commonly need: device
/// state, shared layer infrastructure, interface objects, memory map,
/// and the access context derived from the incoming message.
pub struct AlServiceContext<'a, D: StackDefinition> {
    /// Unified device state (tables + runtime configuration).
    pub state: &'a D::State,

    pub lctx: &'a crate::layer_context::LayerContext<D>,

    /// Interface objects container for property access.
    pub interface_objects: &'a D::InterfaceObjects<'static>,

    /// Memory map for memory services.
    pub memory_map: &'a D::Mem,

    /// Communication objects for direct GO value access (e.g., GO diagnostics).
    pub comm_objects: &'a core::cell::RefCell<D::CO>,

    /// Access context associated with the incoming message.
    pub access_ctx: AccessContext,
}

impl<'a, D: StackDefinition> AlServiceContext<'a, D> {
    /// Access the buffer manager for allocating response buffers.
    pub fn buffer_manager(&self) -> &'a DynBufferManager<'static> {
        &self.lctx.buffer_manager
    }
}

// ============================================================================
// Service Trait
// ============================================================================

/// Unified application-layer service trait.
///
/// Implementations handle APCI codes at the application layer. The AL
/// calls [`try_handle`](Self::try_handle) on its `Services` tuple for
/// each incoming indication; any service that returns `true` is taken
/// as having handled the code.
///
/// # Implementing
///
/// - Match on the APCI codes handled, returning `true`.
/// - Return `false` for unrecognized codes to allow chaining.
/// - Use `ctx` to access device state and allocate response buffers.
///
/// Handlers may silently ignore an APCI (e.g., response codes that the
/// device sends but should not process) and still return `true` to
/// indicate recognition.
///
/// # Interior mutability
///
/// All methods take `&self`. Services that carry mutable state should
/// wrap their fields in [`core::cell::Cell`] or [`core::cell::RefCell`].
pub trait AlService<D: StackDefinition> {
    /// Try to handle an APCI indication.
    ///
    /// Returns `true` if the service was handled (even if silently ignored),
    /// `false` if the APCI is not recognized by this service.
    fn try_handle(
        &self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlServiceContext<'_, D>,
    ) -> bool;
}

// ============================================================================
// Blanket Implementations
// ============================================================================

/// Empty service — handles nothing, zero-size.
impl<D: StackDefinition> AlService<D> for () {
    #[inline(always)]
    fn try_handle(
        &self,
        _apci: ApciCode,
        _msg: &KnxMessageBuffer<Buffer<'static>>,
        _ctx: &AlServiceContext<'_, D>,
    ) -> bool {
        false
    }
}

/// Tuple composition — try head, then tail.
impl<D, A, B> AlService<D> for (A, B)
where
    D: StackDefinition,
    A: AlService<D>,
    B: AlService<D>,
{
    #[inline]
    fn try_handle(
        &self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlServiceContext<'_, D>,
    ) -> bool {
        self.0.try_handle(apci, msg, ctx) || self.1.try_handle(apci, msg, ctx)
    }
}
