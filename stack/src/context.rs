//! Context traits for KNX stack layers
//!
//! This module defines trait-based interfaces for accessing stack resources.
//! Layers depend only on the specific context traits they need, making them
//! easier to test and more modular.

use core::cell::RefCell;

use crate::messages::buffers::DynBufferManager;
use crate::objects::interface::PropertyServiceHandler;

/// Provides access to the buffer manager for allocating and freeing message buffers
pub trait BufferManagerContext {
    /// Get a reference to the buffer manager
    fn buffer_manager(&self) -> &RefCell<DynBufferManager<'static>>;

    /// Get the maximum APDU length this device can handle.
    ///
    /// This is the runtime limit based on `StackState::max_apdu_length()`,
    /// which may be lower than the compile-time `StackDefinition::MAX_APDU_LENGTH`.
    /// Link layers should use this to filter/reject oversized incoming frames.
    fn max_apdu_length(&self) -> u16;

    /// Set the maximum APDU length this device can handle.
    ///
    /// This is called by link layers after detecting hardware capabilities.
    /// For example, a USB link layer may read the interface's MAX_APDU_LENGTH
    /// property and update the stack state accordingly.
    ///
    /// The value should not exceed the compile-time `StackDefinition::MAX_APDU_LENGTH`.
    fn set_max_apdu_length(&self, length: u16);
}

/// Provides access to the device's property service handler.
///
/// This allows link layers that implement connection-oriented management
/// protocols (e.g., KNX/IP Device Management) to read and write interface
/// object properties on behalf of remote clients like ETS.
pub trait PropertyServiceContext {
    /// Get a reference to the property service handler.
    fn property_handler(&self) -> &dyn PropertyServiceHandler;
}

