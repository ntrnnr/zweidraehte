//! Testing utilities for layer testing
//!
//! This module provides test helpers for testing individual layers
//! without requiring a full stack setup.

use core::cell::RefCell;

use crate::{context::BufferManagerContext, messages::buffers::DynBufferManager};

/// Mock context for testing link layers
///
/// This provides a minimal implementation of the required context traits
/// for testing link layers in isolation.
pub struct MockContext {
    buffer_manager: RefCell<DynBufferManager<'static>>,
}

impl MockContext {
    /// Create a new mock context with the provided buffer manager
    pub fn new(buffer_manager: DynBufferManager<'static>) -> Self {
        Self { buffer_manager: RefCell::new(buffer_manager) }
    }
}

impl BufferManagerContext for &MockContext {
    fn buffer_manager(&self) -> &RefCell<DynBufferManager<'static>> {
        &self.buffer_manager
    }
}

impl BufferManagerContext for &mut MockContext {
    fn buffer_manager(&self) -> &RefCell<DynBufferManager<'static>> {
        &self.buffer_manager
    }
}

/// A dummy StackDefinition for testing link layers in isolation
///
/// This is a zero-sized type that satisfies the StackDefinition requirements
/// but isn't actually used. It allows link layers to be tested without a full stack.
#[derive(Debug, Clone, Copy)]
pub struct DummyStackDef;
