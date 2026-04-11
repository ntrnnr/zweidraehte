//! Application layer service extension trait.
//!
//! [`AlServiceExtension`] allows device profiles to handle APCI codes that
//! are not part of the core AL dispatch (e.g., DomainAddress services for
//! KNX/IP). The AL calls [`AlServiceExtension::try_handle`] for any
//! unrecognized APCI before logging a warning.
//!
//! # Composition
//!
//! Extensions compose via tuples: `(A, B)` tries `A` first, then `B`.
//! The `()` type is the empty extension (handles nothing). This allows
//! device definitions to combine multiple independent extensions:
//!
//! ```rust,ignore
//! type AlExtension = (DomainAddressExtension, SomeOtherExtension);
//! ```
//!
//! # Future Migration Path
//!
//! The context struct provides the same resources that core AL handlers
//! use, so an extension handler is functionally equivalent to a built-in
//! handler. This allows eventual migration of core services into
//! extensions for devices that don't need them.

use crate::{
    access::AccessContext,
    definition::StackDefinition,
    messages::{
        buffers::{Buffer, DynBufferManager},
        knx::{ApciCode, KnxMessageBuffer},
    },
};

// ============================================================================
// Extension Context
// ============================================================================

/// Shared resources available to AL service extension handlers.
///
/// This bundles the same set of resources that core AL handlers use,
/// enabling extensions to build responses, access device state, and
/// query interface objects identically to built-in handlers.
pub struct AlExtensionContext<'a, D: StackDefinition> {
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

impl<'a, D: StackDefinition> AlExtensionContext<'a, D> {
    /// Access the buffer manager for allocating response buffers.
    pub fn buffer_manager(&self) -> &'a DynBufferManager<'static> {
        &self.lctx.buffer_manager
    }
}

// ============================================================================
// Extension Trait
// ============================================================================

/// Extension trait for optional application-layer service groups.
///
/// Implementations handle APCI codes that are not part of the core AL
/// dispatch. The AL calls [`try_handle`](Self::try_handle) for any
/// unrecognized APCI before logging a warning.
///
/// # Implementing
///
/// Extension handlers should:
/// - Match on the APCI codes they handle, returning `true`
/// - Return `false` for unrecognized codes to allow chaining
/// - Use `ctx` to access device state and allocate response buffers
///
/// Handlers may silently ignore an APCI (e.g., response codes the device
/// sends but should not process) and still return `true` to indicate the
/// code was recognized.
pub trait AlServiceExtension<D: StackDefinition> {
    /// Try to handle an APCI indication.
    ///
    /// Returns `true` if the service was handled (even if silently ignored),
    /// `false` if the APCI is not recognized by this extension.
    fn try_handle(
        &mut self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlExtensionContext<'_, D>,
    ) -> bool;
}

// ============================================================================
// Blanket Implementations
// ============================================================================

/// Empty extension — handles nothing, zero-size.
impl<D: StackDefinition> AlServiceExtension<D> for () {
    #[inline(always)]
    fn try_handle(
        &mut self,
        _apci: ApciCode,
        _msg: &KnxMessageBuffer<Buffer<'static>>,
        _ctx: &AlExtensionContext<'_, D>,
    ) -> bool {
        false
    }
}

/// Tuple composition — try head, then tail.
impl<D, A, B> AlServiceExtension<D> for (A, B)
where
    D: StackDefinition,
    A: AlServiceExtension<D>,
    B: AlServiceExtension<D>,
{
    #[inline]
    fn try_handle(
        &mut self,
        apci: ApciCode,
        msg: &KnxMessageBuffer<Buffer<'static>>,
        ctx: &AlExtensionContext<'_, D>,
    ) -> bool {
        self.0.try_handle(apci, msg, ctx) || self.1.try_handle(apci, msg, ctx)
    }
}
