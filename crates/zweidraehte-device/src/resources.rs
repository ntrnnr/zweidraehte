//! Pre-allocated resources for the KNX stack.

use core::mem::MaybeUninit;

use crate::{
    config::buffer_size_for_apdu, context::layer::LayerContext, definition::StackDefinition,
    layers::LinkLayerBuilderBase, stack_core::StackCore,
};
use zweidraehte_proto::messages::buffers::BufferPool;

/// Pre-allocated resources for the KNX stack.
///
/// # Buffer Sizing
///
/// [`StackDefinition::BUFFER_SIZE`] defaults to [`StackDefinition::MAX_APDU_LENGTH`]
/// plus the overhead calculated by [`buffer_size_for_apdu()`]. This includes:
/// - Frame overhead (9 bytes): for cEMI compatibility
/// - APDU data (up to `MAX_APDU_LENGTH`)
/// - Headroom (16 bytes): for zero-copy header prepending
///
/// Device definitions select the buffer size and pool capacity, so
/// resource declarations only need the definition type:
///
/// ```ignore
/// use static_cell::StaticCell;
/// use zweidraehte_device::StackResources;
///
/// static RESOURCES: StaticCell<StackResources<LightSwitch>> = StaticCell::new();
/// ```
///
/// Keeping `BUF_SZ` as a defaulted const parameter lets generic construction
/// code infer the storage size without propagating generic-const-expression
/// bounds. It must match the definition's size; configure larger buffers through
/// `BUFFER_SIZE` on the definition rather than a separate resource setting.
///
/// # Type Parameters
///
/// - `D`: Your stack definition implementing [`StackDefinition`]
/// - `BUF_SZ`: Inferred storage size, matching `D::BUFFER_SIZE`
///
/// The device selects pool capacity through [`StackDefinition::Buffers`]
/// (default: eight buffers). cEMI device management can hold four at once;
/// fewer than five buffers risk deadlocks under concurrent load.
pub struct StackResources<D: StackDefinition, const BUF_SZ: usize = { D::BUFFER_SIZE }> {
    pub(crate) inner: MaybeUninit<StackCore<D>>,
    pub(crate) buffers: MaybeUninit<<D::Buffers as BufferPool>::Storage<BUF_SZ>>,
    pub(crate) buffer_manager: MaybeUninit<D::Buffers>,
    pub(crate) layer_context: MaybeUninit<LayerContext<D>>,
    pub(crate) link_layer_resources: MaybeUninit<<D::LLB as LinkLayerBuilderBase>::Resources>,
    pub(crate) augments: MaybeUninit<D::Augments<'static>>,
    pub(crate) interface_objects: MaybeUninit<D::InterfaceObjects<'static>>,
}

impl<D: StackDefinition, const BUF_SZ: usize> Default for StackResources<D, BUF_SZ> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: StackDefinition, const BUF_SZ: usize> StackResources<D, BUF_SZ> {
    /// Reserve stack storage, rejecting buffers smaller than the advertised
    /// APDU limit plus framing and headroom.
    ///
    /// # Panics
    ///
    /// Panics if the definition's buffer size cannot hold the maximum APDU plus
    /// overhead, or if `BUF_SZ` differs from the definition's size.
    pub fn new() -> Self {
        assert!(
            D::BUFFER_SIZE >= buffer_size_for_apdu(D::MAX_APDU_LENGTH),
            "buffer size must cover the device's maximum APDU and framing"
        );
        assert_eq!(BUF_SZ, D::BUFFER_SIZE, "buffer size must match StackDefinition::BUFFER_SIZE");

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
