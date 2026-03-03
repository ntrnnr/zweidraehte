//! Pre-allocated resources for the KNX stack.

use core::mem::MaybeUninit;

use crate::{
    definition::StackDefinition,
    inner::Inner,
    layers::LinkLayerBuilderBase,
    messages::buffers::BufferManager,
};

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
/// # Example
///
/// ```ignore
/// use zweidraehte::config::{MAX_APDU_LENGTH_TP1_STANDARD, buffer_size_for_apdu};
///
/// impl StackDefinition for MyDevice {
///     const MASK_VERSION: &'static [u8; 2] = &[0x07, 0xB0];
///     const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_TP1_STANDARD; // 14 bytes
///     // ... other fields
/// }
///
/// // Buffer size is 39 bytes (14 + 9 overhead + 16 headroom)
/// static RESOURCES: StaticCell<StackResources<MyDevice, { buffer_size_for_apdu(MyDevice::MAX_APDU_LENGTH) }>> = StaticCell::new();
/// ```
///
/// # Type Parameters
///
/// - `D`: Your stack definition implementing [`StackDefinition`]
/// - `BUF_SZ`: Size of each buffer. Use `buffer_size_for_apdu(D::MAX_APDU_LENGTH)`
/// - `NUM_BUFS`: Number of buffers in the pool (default: 8). The cEMI device
///   management path can hold up to 4 buffers simultaneously, so values below
///   5 risk deadlocks under concurrent load.
///
/// # Note on Buffer Size
///
/// We would like to automatically derive `BUF_SZ` from `D::MAX_APDU_LENGTH`,
/// but Rust's `generic_const_exprs` feature is still incomplete and causes
/// overflow errors when used with static declarations. Until this is fixed,
/// users must explicitly specify the buffer size.
pub struct StackResources<D: StackDefinition, const BUF_SZ: usize, const NUM_BUFS: usize = 8> {
    pub(crate) inner: MaybeUninit<Inner<D>>,
    pub(crate) buffers: MaybeUninit<[[u8; BUF_SZ]; NUM_BUFS]>,
    pub(crate) buffer_manager: MaybeUninit<BufferManager<NUM_BUFS>>,
    pub(crate) link_layer_resources: MaybeUninit<<D::LLB as LinkLayerBuilderBase>::Resources>,
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
            link_layer_resources: MaybeUninit::uninit(),
            interface_objects: MaybeUninit::uninit(),
        }
    }
}
