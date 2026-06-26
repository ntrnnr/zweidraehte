//! Internal stack state storage.
//!
//! [`StackCore`] holds all shared state for a running KNX stack instance:
//! device state, platform abstraction, memory map, and a reference to the
//! persistent [`LayerContext`](crate::context::LayerContext). The transient
//! bundle passed to link layers lives in
//! [`crate::context::StackContext`](crate::context::StackContext); see
//! that module for why it is kept separate.

use crate::{context::layer::LayerContext, definition::StackDefinition};

/// Core stack interior: state + platform + memory map.
pub(crate) struct StackCore<D: StackDefinition> {
    /// Unified device state containing runtime state, tables, and configuration.
    pub(crate) state: D::State,
    /// Platform abstraction for querying/applying network configuration.
    ///
    /// For KNX/IP devices this provides current IP, MAC, capabilities, etc.
    /// For non-IP devices this is `()`.
    pub(crate) platform: D::Platform,
    /// Memory map for A_Memory_Read/Write services.
    pub(crate) memory_map: D::Mem,
    /// Shared runtime infrastructure.
    pub(crate) layer_context: &'static LayerContext<D>,
}

impl<D: StackDefinition> StackCore<D> {
    /// Execute a closure with mutable access to communication objects.
    /// Ensures the borrow is properly scoped and released.
    pub(crate) fn with_comm_objs<R>(&self, f: impl FnOnce(&mut D::CO) -> R) -> R {
        use crate::objects::comm::HasCommObjects;
        let mut comm_objs = self.state.comm_objects().borrow_mut();
        f(&mut comm_objs)
    }
}
