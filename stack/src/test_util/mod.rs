//! Testing utilities for layer testing
//!
//! This module provides test helpers for testing individual layers
//! without requiring a full stack setup.

use core::cell::{Cell, RefCell};

use crate::{context::BufferManagerContext, messages::buffers::DynBufferManager};

/// Mock context for testing link layers
///
/// This provides a minimal implementation of the required context traits
/// for testing link layers in isolation.
pub struct MockContext {
    buffer_manager: RefCell<DynBufferManager<'static>>,
    max_apdu_length: Cell<u16>,
}

impl MockContext {
    /// Create a new mock context with the provided buffer manager
    pub fn new(buffer_manager: DynBufferManager<'static>) -> Self {
        Self { buffer_manager: RefCell::new(buffer_manager), max_apdu_length: Cell::new(crate::config::MAX_APDU_LENGTH_EXTENDED) }
    }

    /// Create a new mock context with a custom max APDU length
    pub fn with_max_apdu_length(buffer_manager: DynBufferManager<'static>, max_apdu_length: u16) -> Self {
        Self { buffer_manager: RefCell::new(buffer_manager), max_apdu_length: Cell::new(max_apdu_length) }
    }
}

impl BufferManagerContext for &MockContext {
    fn buffer_manager(&self) -> &RefCell<DynBufferManager<'static>> {
        &self.buffer_manager
    }

    fn max_apdu_length(&self) -> u16 {
        self.max_apdu_length.get()
    }

    fn set_max_apdu_length(&self, length: u16) {
        self.max_apdu_length.set(length);
    }
}

impl BufferManagerContext for &mut MockContext {
    fn buffer_manager(&self) -> &RefCell<DynBufferManager<'static>> {
        &self.buffer_manager
    }

    fn max_apdu_length(&self) -> u16 {
        self.max_apdu_length.get()
    }

    fn set_max_apdu_length(&self, length: u16) {
        self.max_apdu_length.set(length);
    }
}

/// A dummy StackDefinition for testing link layers in isolation
///
/// This is a zero-sized type that satisfies the StackDefinition requirements
/// but isn't actually used. It allows link layers to be tested without a full stack.
#[derive(Debug, Clone, Copy)]
pub struct DummyStackDef;
