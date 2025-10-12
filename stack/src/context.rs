//! Context traits for KNX stack layers
//!
//! This module defines trait-based interfaces for accessing stack resources.
//! Layers depend only on the specific context traits they need, making them
//! easier to test and more modular.

use core::cell::RefCell;

use crate::messages::buffers::DynBufferManager;

/// Provides access to the buffer manager for allocating and freeing message buffers
pub trait BufferManagerContext {
    /// Get a reference to the buffer manager
    fn buffer_manager(&self) -> &RefCell<DynBufferManager<'static>>;
}

// TODO: Add more context traits as needed:
// - AddressTableContext
// - AssociationTableContext
// - CommunicationObjectTableContext
// - CommunicationObjectsContext
// - EventChannelContext
