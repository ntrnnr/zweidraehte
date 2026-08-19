//! Message buffer management for the KNX stack.
//!
//! This module provides:
//! - [`MessageBuffer`] trait for buffers with headroom support
//! - [`Buffer`] - a managed buffer from the pool (feature `buffer-pool`)
//! - [`BufferManager`] - pre-allocated buffer pool (feature `buffer-pool`)
//! - [`DynBufferManager`] - dynamic interface to the buffer pool
//!   (feature `buffer-pool`)
//!
//! # Buffer Sizing
//!
//! Use [`crate::config::buffer_size_for_apdu`] to calculate the required buffer size
//! based on the maximum APDU length your device supports:
//!
//! ```ignore
//! use zweidraehte_device::config::{buffer_size_for_apdu, MAX_APDU_LENGTH_EXTENDED};
//!
//! // For a KNX/IP device with full APDU support
//! const BUFFER_SIZE: usize = buffer_size_for_apdu(MAX_APDU_LENGTH_EXTENDED); // 280
//!
//! // Create stack resources with this buffer size
//! let resources = StackResources::<MyDevice, BUFFER_SIZE, 4>::new();
//! ```

use core::ops::{Deref, DerefMut};

// The pool hands freed buffers back through an embassy channel; that
// is the crate's only embassy dependency, so the whole submodule sits
// behind the `buffer-pool` feature while the `MessageBuffer` trait
// stays unconditional.
#[cfg(feature = "buffer-pool")]
mod pool;
#[cfg(feature = "buffer-pool")]
pub use pool::{Buffer, BufferManager, DynBufferManager};

/// Error type for buffer operations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BufferError {
    /// Not enough capacity at the end of the buffer
    InsufficientCapacity { requested: usize, available: usize },
    /// Not enough headroom at the start of the buffer
    InsufficientHeadroom { requested: usize, available: usize },
}

/// Trait for message buffers with headroom support.
///
/// Message buffers support efficient zero-copy operations:
/// - **Headroom**: Reserved space at the front for prepending headers
/// - **Spare capacity**: Space at the end for appending data
/// - **In-place operations**: Grow/shrink from either end without copying
///
/// Buffer layout:
/// ```text
/// +------------------+------------------------+------------------+
/// | HEADROOM         | ACTIVE DATA            | SPARE CAPACITY   |
/// | (reserved)       | (current message)      | (for growth)     |
/// +------------------+------------------------+------------------+
/// ^                  ^                        ^                  ^
/// 0                  start                    start+len          raw_capacity
/// ```
pub trait MessageBuffer: Deref<Target = [u8]> + DerefMut<Target = [u8]> + Sized {
    // ========================================================================
    // Core properties
    // ========================================================================

    /// Length of the active data region.
    fn len(&self) -> usize;

    /// Whether the active data region is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set the length of the active data region.
    ///
    /// # Panics
    /// Panics if `len` exceeds available capacity (spare capacity + current len).
    fn set_len(&mut self, len: usize);

    /// Total capacity available for data (excluding headroom).
    fn capacity(&self) -> usize;

    /// Available headroom at the front of the buffer.
    fn headroom(&self) -> usize;

    // ========================================================================
    // Headroom operations (grow/shrink from front)
    // ========================================================================

    /// Grow the data region backwards into headroom.
    ///
    /// After this call, `len` increases by `count` and `headroom` decreases by `count`.
    /// The new bytes at the front are uninitialized.
    ///
    /// # Panics
    /// Panics if `count` exceeds available headroom.
    fn grow_front(&mut self, count: usize);

    /// Try to grow the data region backwards into headroom.
    ///
    /// Returns `Err` if insufficient headroom is available.
    fn try_grow_front(&mut self, count: usize) -> Result<(), BufferError> {
        if count > self.headroom() {
            return Err(BufferError::InsufficientHeadroom { requested: count, available: self.headroom() });
        }
        self.grow_front(count);
        Ok(())
    }

    /// Shrink the data region from the front, reclaiming headroom.
    ///
    /// After this call, `len` decreases by `count` and `headroom` increases by `count`.
    ///
    /// # Panics
    /// Panics if `count` exceeds current length.
    fn shrink_front(&mut self, count: usize);

    /// Prepend data at the front using headroom.
    ///
    /// # Panics
    /// Panics if insufficient headroom.
    fn prepend(&mut self, data: &[u8]) {
        self.grow_front(data.len());
        self[..data.len()].copy_from_slice(data);
    }

    /// Try to prepend data at the front using headroom.
    fn try_prepend(&mut self, data: &[u8]) -> Result<(), BufferError> {
        self.try_grow_front(data.len())?;
        self[..data.len()].copy_from_slice(data);
        Ok(())
    }

    // ========================================================================
    // Capacity operations (grow/shrink from back)
    // ========================================================================

    /// Remaining capacity at the end of the buffer.
    fn remaining_capacity(&self) -> usize {
        self.capacity() - self.len()
    }

    /// Extend the length without initializing new bytes.
    ///
    /// Use this after writing to `spare_capacity_mut()`.
    ///
    /// # Panics
    /// Panics if the new length exceeds capacity.
    fn extend_len(&mut self, additional: usize) {
        self.set_len(self.len() + additional);
    }

    /// Try to extend the length.
    fn try_extend_len(&mut self, additional: usize) -> Result<(), BufferError> {
        let new_len = self.len() + additional;
        if new_len > self.capacity() {
            return Err(BufferError::InsufficientCapacity { requested: new_len, available: self.capacity() });
        }
        self.set_len(new_len);
        Ok(())
    }

    /// Get a mutable slice to the spare capacity (unwritten portion).
    ///
    /// Write to this slice, then call `extend_len()` to include the written bytes.
    fn spare_capacity_mut(&mut self) -> &mut [u8];

    // ========================================================================
    // Write operations
    // ========================================================================

    /// Append a single byte.
    fn push(&mut self, byte: u8) {
        let spare = self.spare_capacity_mut();
        spare[0] = byte;
        self.extend_len(1);
    }

    /// Append data at the end.
    fn push_slice(&mut self, data: &[u8]) {
        let start = self.len();
        self.extend_len(data.len());
        self[start..start + data.len()].copy_from_slice(data);
    }

    /// Write data at a specific offset, extending length if needed.
    ///
    /// If the write extends past the current length, the buffer is extended.
    /// Bytes between old length and offset (if any) are uninitialized.
    fn write_at(&mut self, offset: usize, data: &[u8]) {
        let end = offset + data.len();
        if end > self.len() {
            self.set_len(end);
        }
        self[offset..end].copy_from_slice(data);
    }

    /// Replace entire contents with data from a slice.
    fn fill_from_slice(&mut self, data: &[u8]) {
        self.set_len(data.len());
        self[..data.len()].copy_from_slice(data);
    }

    // ========================================================================
    // Fluent builders
    // ========================================================================

    /// Set length and return self (fluent API).
    fn with_len(mut self, len: usize) -> Self {
        self.set_len(len);
        self
    }

    /// Fill from slice and return self (fluent API).
    fn with_slice(mut self, data: &[u8]) -> Self {
        self.fill_from_slice(data);
        self
    }

    // ========================================================================
    // Legacy/compatibility (consider deprecating)
    // ========================================================================

    /// Try to set length, returning error instead of panicking.
    fn try_set_len(&mut self, len: usize) -> Result<(), BufferError> {
        if len > self.capacity() {
            return Err(BufferError::InsufficientCapacity { requested: len, available: self.capacity() });
        }
        self.set_len(len);
        Ok(())
    }

    /// Resize the buffer, filling new bytes with a value.
    ///
    /// Note: Prefer `extend_len()` + direct writes over `resize()` with zero fill
    /// when you're going to overwrite the bytes anyway.
    fn resize(&mut self, new_len: usize, fill_value: u8) {
        let old_len = self.len();
        if new_len > old_len {
            self.set_len(new_len);
            self[old_len..new_len].fill(fill_value);
        } else {
            self.set_len(new_len);
        }
    }
}

// ============================================================================
// Vec<u8> implementation (requires alloc)
// ============================================================================

/// `MessageBuffer` implementation for `Vec<u8>`.
///
/// This enables using `Vec<u8>` with functions like [`cemi_to_knx_message`]
/// in `std`/`alloc` environments (e.g., the client crate).
///
/// `Vec` has no headroom concept, so `grow_front` and `shrink_front` use
/// copying (`insert`/`drain`). This is fine for occasional use but not
/// suitable for hot paths that rely on zero-copy prepending.
///
/// [`cemi_to_knx_message`]: crate::encoding::cemi::cemi_to_knx_message
#[cfg(feature = "alloc")]
impl MessageBuffer for alloc::vec::Vec<u8> {
    fn len(&self) -> usize {
        alloc::vec::Vec::len(self)
    }

    fn set_len(&mut self, len: usize) {
        self.resize(len, 0);
    }

    fn capacity(&self) -> usize {
        alloc::vec::Vec::capacity(self)
    }

    fn headroom(&self) -> usize {
        0
    }

    fn grow_front(&mut self, count: usize) {
        // Insert zeroed bytes at the front. This shifts all existing data
        // right by `count` bytes — O(n) but acceptable for non-hot paths.
        self.splice(..0, core::iter::repeat_n(0, count));
    }

    fn shrink_front(&mut self, count: usize) {
        assert!(
            count <= alloc::vec::Vec::len(self),
            "cannot shrink more than length: requested {}, length {}",
            count,
            alloc::vec::Vec::len(self),
        );
        self.drain(..count);
    }

    fn spare_capacity_mut(&mut self) -> &mut [u8] {
        let len = alloc::vec::Vec::len(self);
        let cap = alloc::vec::Vec::capacity(self);
        // Safety: the bytes between len and capacity are allocated but
        // uninitialized. Callers must write before reading, then call
        // extend_len() to include the written bytes.
        unsafe { core::slice::from_raw_parts_mut(self.as_mut_ptr().add(len), cap - len) }
    }
}
