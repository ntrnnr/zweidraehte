//! Pre-allocated resources for the KNX stack.

use core::mem::MaybeUninit;

use crate::{context::layer::LayerContext, definition::StackDefinition, inner::Inner, layers::LinkLayerBuilderBase};
use zweidraehte_proto::messages::buffers::BufferManager;

/// Pre-allocated resources for the KNX stack.
///
/// # Buffer Sizing
///
/// The buffer size should be calculated from [`StackDefinition::MAX_APDU_LENGTH`]
/// using [`config::buffer_size_for_apdu()`](crate::config::buffer_size_for_apdu). This includes:
/// - Frame overhead (9 bytes): for cEMI compatibility
/// - APDU data (up to `MAX_APDU_LENGTH`)
/// - Headroom (16 bytes): for zero-copy header prepending
///
/// # Canonical incantation
///
/// Most devices should spell their static resources as:
///
/// ```ignore
/// use static_cell::StaticCell;
/// use zweidraehte_device::{StackDefinition, StackResources, config::buffer_size_for_apdu};
///
/// static RESOURCES: StaticCell<
///     StackResources<
///         MyDevice,
///         { buffer_size_for_apdu(<MyDevice as StackDefinition>::MAX_APDU_LENGTH) },
///     >,
/// > = StaticCell::new();
/// ```
///
/// A `DefaultStackResources<D>` type alias that automatically derives `BUF_SZ`
/// from `D::MAX_APDU_LENGTH` would be nicer, but Rust's `generic_const_exprs`
/// feature currently causes overflow errors when the expression is used in a
/// `static` declaration (because the compiler must evaluate the const in a
/// context where the where-clauses are fully resolved, and the current
/// `generic_const_exprs` implementation does not support that for trait-
/// associated consts). Once the feature stabilises this can be revisited.
///
/// # Type Parameters
///
/// - `D`: Your stack definition implementing [`StackDefinition`]
/// - `BUF_SZ`: Size of each buffer. Use `buffer_size_for_apdu(D::MAX_APDU_LENGTH)`
/// - `NUM_BUFS`: Number of buffers in the pool (default: 8). The cEMI device
///   management path can hold up to 4 buffers simultaneously, so values below
///   5 risk deadlocks under concurrent load.
pub struct StackResources<D: StackDefinition, const BUF_SZ: usize, const NUM_BUFS: usize = 8> {
    pub(crate) inner: MaybeUninit<Inner<D>>,
    pub(crate) buffers: MaybeUninit<[[u8; BUF_SZ]; NUM_BUFS]>,
    pub(crate) buffer_manager: MaybeUninit<BufferManager<NUM_BUFS>>,
    pub(crate) layer_context: MaybeUninit<LayerContext<D>>,
    pub(crate) link_layer_resources: MaybeUninit<<D::LLB as LinkLayerBuilderBase>::Resources>,
    pub(crate) augments: MaybeUninit<D::Augments<'static>>,
    pub(crate) interface_objects: MaybeUninit<D::InterfaceObjects<'static>>,
}

impl<D: StackDefinition, const BUF_SZ: usize, const NUM_BUFS: usize> Default for StackResources<D, BUF_SZ, NUM_BUFS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: StackDefinition, const BUF_SZ: usize, const NUM_BUFS: usize> StackResources<D, BUF_SZ, NUM_BUFS> {
    pub fn new() -> Self {
        Self {
            inner: MaybeUninit::uninit(),
            buffers: MaybeUninit::uninit(),
            buffer_manager: MaybeUninit::uninit(),
            layer_context: MaybeUninit::uninit(),
            link_layer_resources: MaybeUninit::uninit(),
            augments: MaybeUninit::uninit(),
            interface_objects: MaybeUninit::uninit(),
        }
    }
}
