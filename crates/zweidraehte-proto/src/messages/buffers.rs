//! Message buffer management for the KNX stack.
//!
//! This module provides:
//! - [`MessageBuffer`] trait for buffers with headroom support
//! - [`Buffer`] - a managed buffer from the pool
//! - [`BufferManager`] - pre-allocated buffer pool
//! - [`DynBufferManager`] - dynamic interface to the buffer pool
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

use core::{
    cell::Cell,
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{self, Channel, DynamicReceiver, DynamicSender},
};

use crate::config::DEFAULT_HEADROOM;

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
            return Err(BufferError::InsufficientHeadroom {
                requested: count,
                available: self.headroom(),
            });
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
            return Err(BufferError::InsufficientCapacity {
                requested: new_len,
                available: self.capacity(),
            });
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
    fn from_slice(mut self, data: &[u8]) -> Self {
        self.fill_from_slice(data);
        self
    }

    // ========================================================================
    // Legacy/compatibility (consider deprecating)
    // ========================================================================

    /// Try to set length, returning error instead of panicking.
    fn try_set_len(&mut self, len: usize) -> Result<(), BufferError> {
        if len > self.capacity() {
            return Err(BufferError::InsufficientCapacity {
                requested: len,
                available: self.capacity(),
            });
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
        self.splice(..0, core::iter::repeat(0).take(count));
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

/// A message buffer managed by the [`BufferManager`].
///
/// This buffer has built-in headroom support for zero-copy format conversions.
/// When allocated, the buffer starts with [`DEFAULT_HEADROOM`] bytes reserved
/// at the front, allowing headers to be prepended without copying.
#[clippy::has_significant_drop]
pub struct Buffer<'a> {
    /// Pointer to the underlying memory (full allocation including headroom).
    buffer: NonNull<[u8]>,
    /// Start offset of active data (headroom is before this).
    start: usize,
    /// Length of active data.
    len: usize,
    /// Channel to return the buffer to the pool.
    sender: channel::DynamicSender<'a, NonNull<[u8]>>,
    /// Shared counter of currently allocated buffers (decremented on drop).
    allocated_count: &'a Cell<u8>,
}

// Safety: Buffer is Send if the underlying memory and sender are Send.
// The NonNull<[u8]> points to memory managed by BufferManager which ensures
// proper synchronization through the channel.
unsafe impl Send for Buffer<'_> {}

impl MessageBuffer for Buffer<'_> {
    fn len(&self) -> usize {
        self.len
    }

    fn set_len(&mut self, len: usize) {
        if len > self.capacity() {
            panic!(
                "Length exceeds buffer capacity: {} > {}",
                len,
                self.capacity()
            );
        }
        self.len = len;
    }

    fn capacity(&self) -> usize {
        // Capacity is everything after the current start position
        self.raw_capacity() - self.start
    }

    fn headroom(&self) -> usize {
        self.start
    }

    fn grow_front(&mut self, count: usize) {
        if count > self.start {
            panic!(
                "Headroom exceeded: requested {}, available {}",
                count, self.start
            );
        }
        self.start -= count;
        self.len += count;
    }

    fn shrink_front(&mut self, count: usize) {
        if count > self.len {
            panic!(
                "Cannot shrink more than length: requested {}, length {}",
                count, self.len
            );
        }
        self.start += count;
        self.len -= count;
    }

    fn spare_capacity_mut(&mut self) -> &mut [u8] {
        let end = self.start + self.len;
        let cap = self.raw_capacity();
        unsafe { &mut self.buffer.as_mut()[end..cap] }
    }
}

impl Buffer<'_> {
    /// Raw capacity of the entire underlying buffer (including headroom).
    fn raw_capacity(&self) -> usize {
        unsafe { self.buffer.as_ref().len() }
    }

    /// Get a slice of the entire underlying buffer (for serialization).
    ///
    /// This is used internally for operations that need access to the full
    /// buffer including headroom.
    #[allow(dead_code)]
    fn raw_buffer(&self) -> &[u8] {
        unsafe { self.buffer.as_ref() }
    }

    /// Get a mutable slice of the entire underlying buffer.
    #[allow(dead_code)]
    fn raw_buffer_mut(&mut self) -> &mut [u8] {
        unsafe { self.buffer.as_mut() }
    }
}

impl Deref for Buffer<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { &self.buffer.as_ref()[self.start..self.start + self.len] }
    }
}

impl DerefMut for Buffer<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut self.buffer.as_mut()[self.start..self.start + self.len] }
    }
}

impl Drop for Buffer<'_> {
    fn drop(&mut self) {
        // Clear the entire buffer (including headroom) for security
        unsafe {
            self.buffer.as_mut().fill(0);
        }

        // Send the buffer back to the manager.
        // This operation cannot fail, as we allocated a capacity equal to the
        // number of buffers we create and manage.
        let _ = self.sender.try_send(self.buffer);

        // Decrement the pool usage counter.
        self.allocated_count
            .set(self.allocated_count.get().saturating_sub(1));
    }
}

impl core::fmt::Debug for Buffer<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Buffer")
            .field("headroom", &self.start)
            .field("len", &self.len)
            .field("capacity", &self.capacity())
            .field("data", &&self[..])
            .finish()
    }
}

impl crate::util::packets::SerializeBuffer for Buffer<'_> {
    fn serialize<P: crate::util::packets::SerializablePacket>(
        &mut self,
        packet: &P,
    ) -> (&mut [u8], &mut [u8]) {
        // Append after existing data (spare capacity starts here)
        let start = self.start + self.len;
        let full_buffer = unsafe { self.buffer.as_mut() };
        let usable = &mut full_buffer[start..];
        let original_len = usable.len();

        // Create a temporary mutable reference for serialization
        let mut temp = &mut usable[..];
        packet.serialize(&mut &mut temp);

        // temp now points to remaining bytes
        let written = original_len - temp.len();

        // Extend the buffer's length by the newly written bytes
        self.len += written;

        // Split the newly written region into written and remaining portions
        let full_buffer = unsafe { self.buffer.as_mut() };
        let usable = &mut full_buffer[start..];
        let (written_portion, remaining_portion) = usable.split_at_mut(written);
        (written_portion, remaining_portion)
    }
}

/// A dynamic [`BufferManager`] with generics elided.
///
/// Provides both blocking (`alloc`) and non-blocking (`try_alloc`) allocation,
/// plus pool usage diagnostics via [`allocated_count`](Self::allocated_count)
/// and [`free_count`](Self::free_count).
#[derive(Clone, Copy)]
pub struct DynBufferManager<'a> {
    buffer_sender: DynamicSender<'a, NonNull<[u8]>>,
    buffer_receiver: DynamicReceiver<'a, NonNull<[u8]>>,
    /// Default headroom for new allocations
    default_headroom: usize,
    /// Total number of buffers in the pool.
    pool_size: u8,
    /// Shared counter of currently allocated (in-use) buffers.
    allocated_count: &'a Cell<u8>,
}

impl<'a> DynBufferManager<'a> {
    // ========================================================================
    // Pool diagnostics
    // ========================================================================

    /// Number of buffers currently allocated (in use).
    pub fn allocated_count(&self) -> u8 {
        self.allocated_count.get()
    }

    /// Total number of buffers in the pool.
    pub fn pool_size(&self) -> u8 {
        self.pool_size
    }

    /// Number of free (available) buffers.
    pub fn free_count(&self) -> u8 {
        self.pool_size.saturating_sub(self.allocated_count.get())
    }

    /// Increment the counter and build a `Buffer` from a raw pointer.
    fn finish_alloc(&self, buffer: NonNull<[u8]>, start: usize) -> Buffer<'a> {
        let count = self.allocated_count.get() + 1;
        self.allocated_count.set(count);
        if count >= self.pool_size {
            warn!(
                "Buffer pool exhausted ({}/{} allocated)",
                count, self.pool_size
            );
        }
        Buffer {
            buffer,
            start,
            len: 0,
            sender: self.buffer_sender,
            allocated_count: self.allocated_count,
        }
    }

    // ========================================================================
    // Blocking allocation (async — waits for a free buffer)
    // ========================================================================

    /// Allocate a new [`Buffer`] with default headroom.
    ///
    /// The buffer starts empty (len=0) with [`DEFAULT_HEADROOM`] bytes reserved
    /// at the front for prepending headers.
    ///
    /// If no free buffers are available, this function blocks asynchronously.
    /// A warning is logged when the pool is fully exhausted.
    pub async fn alloc(&self) -> Buffer<'a> {
        let ptr = self.buffer_receiver.receive().await;
        self.finish_alloc(ptr, self.default_headroom)
    }

    /// Allocate a new [`Buffer`] with specified headroom.
    ///
    /// Use this when you need more or less headroom than the default.
    pub async fn alloc_with_headroom(&self, headroom: usize) -> Buffer<'a> {
        let ptr = self.buffer_receiver.receive().await;
        self.finish_alloc(ptr, headroom)
    }

    /// Allocate a new [`Buffer`] with no headroom.
    ///
    /// Use this when you know you won't need to prepend any data.
    pub async fn alloc_no_headroom(&self) -> Buffer<'a> {
        let ptr = self.buffer_receiver.receive().await;
        self.finish_alloc(ptr, 0)
    }

    /// Allocate a new [`Buffer`] and fill it with data from a slice.
    ///
    /// The buffer will have default headroom before the data.
    pub async fn alloc_from_slice(&self, data: &[u8]) -> Buffer<'a> {
        let mut buffer = self.alloc().await;
        buffer.fill_from_slice(data);
        buffer
    }

    /// Allocate a new [`Buffer`] with the specified size.
    ///
    /// **Note**: The bytes are uninitialized. If you need zeroed memory,
    /// use `alloc_zeroed()` instead.
    pub async fn alloc_with_size(&self, size: usize) -> Buffer<'a> {
        let mut buffer = self.alloc().await;
        buffer.set_len(size);
        buffer
    }

    /// Allocate a new [`Buffer`] with the specified size, filled with zeros.
    pub async fn alloc_zeroed(&self, size: usize) -> Buffer<'a> {
        let mut buffer = self.alloc().await;
        buffer.resize(size, 0);
        buffer
    }

    // ========================================================================
    // Non-blocking allocation (returns None if pool is empty)
    // ========================================================================

    /// Try to allocate a [`Buffer`] without blocking.
    ///
    /// Returns `None` if no free buffers are available. Use this in code
    /// paths where blocking could cause a deadlock and the operation can
    /// be gracefully skipped (e.g., retransmit copies, ACK responses).
    pub fn try_alloc(&self) -> Option<Buffer<'a>> {
        match self.buffer_receiver.try_receive() {
            Ok(ptr) => Some(self.finish_alloc(ptr, self.default_headroom)),
            Err(_) => None,
        }
    }

    /// Try to allocate a [`Buffer`] with the specified size, without blocking.
    ///
    /// Returns `None` if no free buffers are available.
    pub fn try_alloc_with_size(&self, size: usize) -> Option<Buffer<'a>> {
        let mut buffer = self.try_alloc()?;
        buffer.set_len(size);
        Some(buffer)
    }

    /// Try to allocate a [`Buffer`] filled from a slice, without blocking.
    ///
    /// Returns `None` if no free buffers are available.
    pub fn try_alloc_from_slice(&self, data: &[u8]) -> Option<Buffer<'a>> {
        let mut buffer = self.try_alloc()?;
        buffer.fill_from_slice(data);
        Some(buffer)
    }

    /// Try to allocate a [`Buffer`] with no headroom, without blocking.
    ///
    /// Returns `None` if no free buffers are available.
    pub fn try_alloc_no_headroom(&self) -> Option<Buffer<'a>> {
        match self.buffer_receiver.try_receive() {
            Ok(ptr) => Some(self.finish_alloc(ptr, 0)),
            Err(_) => None,
        }
    }
}

/// A manager for a number of pre-allocated chunks of memory represented by
/// the [`Buffer`] object.
///
/// Each buffer in the pool has capacity for both data and headroom.
/// The effective usable capacity is `BUFFER_SIZE - DEFAULT_HEADROOM`.
pub struct BufferManager<const NUM_BUFS: usize> {
    buffers: channel::Channel<NoopRawMutex, NonNull<[u8]>, NUM_BUFS>,
    /// Tracks how many buffers are currently allocated (in use).
    allocated_count: Cell<u8>,
}

impl<const NUM_BUFS: usize> BufferManager<NUM_BUFS> {
    /// Create a new [`BufferManager`] which manages the provided buffers.
    ///
    /// Each buffer should have size `BUFFER_SIZE`. The effective usable capacity
    /// will be `BUFFER_SIZE - DEFAULT_HEADROOM` bytes, with `DEFAULT_HEADROOM`
    /// bytes reserved for prepending headers.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the buffers remain valid for the lifetime
    /// of the BufferManager and all Buffers allocated from it.
    pub unsafe fn new<const BUFFER_SIZE: usize>(
        buffers: &mut [[u8; BUFFER_SIZE]; NUM_BUFS],
    ) -> Self {
        let queue = Channel::new();

        for buffer in buffers {
            let _ = queue.try_send(NonNull::from(buffer.as_mut_slice()));
        }

        Self {
            buffers: queue,
            allocated_count: Cell::new(0),
        }
    }

    /// Acquire a [`DynBufferManager`].
    ///
    /// This allows you to allocate buffers from the manager.
    pub fn dyn_buffer_manager(&self) -> DynBufferManager<'_> {
        DynBufferManager {
            buffer_sender: self.buffers.dyn_sender(),
            buffer_receiver: self.buffers.dyn_receiver(),
            default_headroom: DEFAULT_HEADROOM,
            pool_size: NUM_BUFS as u8,
            allocated_count: &self.allocated_count,
        }
    }

    /// Acquire a [`DynBufferManager`] with custom default headroom.
    pub fn dyn_buffer_manager_with_headroom(&self, headroom: usize) -> DynBufferManager<'_> {
        DynBufferManager {
            buffer_sender: self.buffers.dyn_sender(),
            buffer_receiver: self.buffers.dyn_receiver(),
            default_headroom: headroom,
            pool_size: NUM_BUFS as u8,
            allocated_count: &self.allocated_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_buffer(data: &mut [u8], headroom: usize) -> Buffer<'static> {
        let buffer_ptr = core::ptr::NonNull::from(data.as_mut());
        let channel =
            Channel::<embassy_sync::blocking_mutex::raw::NoopRawMutex, core::ptr::NonNull<[u8]>, 1>::new();
        // Leak the channel and counter to get 'static lifetime for testing
        let channel = Box::leak(Box::new(channel));
        let counter = Box::leak(Box::new(Cell::new(0u8)));
        let sender = channel.sender();
        Buffer {
            buffer: buffer_ptr,
            start: headroom,
            len: 0,
            sender: sender.into(),
            allocated_count: counter,
        }
    }

    #[test]
    fn test_buffer_with_headroom() {
        let mut data = [0u8; 64];
        let mut buffer = make_test_buffer(&mut data, 16);

        // Initial state
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.headroom(), 16);
        assert_eq!(buffer.capacity(), 48); // 64 - 16

        // Write some data
        buffer.push_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(buffer.len(), 5);
        assert_eq!(&buffer[..], &[1, 2, 3, 4, 5]);

        // Prepend using headroom
        buffer.prepend(&[0xAA, 0xBB]);
        assert_eq!(buffer.len(), 7);
        assert_eq!(buffer.headroom(), 14);
        assert_eq!(&buffer[..], &[0xAA, 0xBB, 1, 2, 3, 4, 5]);

        // Shrink from front
        buffer.shrink_front(2);
        assert_eq!(buffer.len(), 5);
        assert_eq!(buffer.headroom(), 16);
        assert_eq!(&buffer[..], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_grow_front() {
        let mut data = [0u8; 32];
        let mut buffer = make_test_buffer(&mut data, 8);

        buffer.push_slice(&[1, 2, 3]);
        assert_eq!(buffer.len(), 3);

        // Grow front (bytes are uninitialized)
        buffer.grow_front(4);
        assert_eq!(buffer.len(), 7);
        assert_eq!(buffer.headroom(), 4);

        // Write to the new front
        buffer[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(&buffer[..], &[0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3]);
    }

    #[test]
    fn test_spare_capacity() {
        let mut data = [0u8; 32];
        let mut buffer = make_test_buffer(&mut data, 8);

        assert_eq!(buffer.remaining_capacity(), 24); // 32 - 8

        // Write directly to spare capacity
        let spare = buffer.spare_capacity_mut();
        spare[..5].copy_from_slice(&[10, 20, 30, 40, 50]);
        buffer.extend_len(5);

        assert_eq!(buffer.len(), 5);
        assert_eq!(&buffer[..], &[10, 20, 30, 40, 50]);
    }

    #[test]
    fn test_write_at() {
        let mut data = [0u8; 32];
        let mut buffer = make_test_buffer(&mut data, 8);

        // Write at offset 0
        buffer.write_at(0, &[1, 2, 3]);
        assert_eq!(buffer.len(), 3);

        // Write at offset past current length
        buffer.write_at(5, &[10, 11]);
        assert_eq!(buffer.len(), 7);
        assert_eq!(&buffer[5..7], &[10, 11]);

        // Overwrite existing data
        buffer.write_at(1, &[0xFF, 0xFF]);
        assert_eq!(&buffer[..], &[1, 0xFF, 0xFF, 0, 0, 10, 11]);
    }

    #[test]
    fn test_try_operations() {
        let mut data = [0u8; 32];
        let mut buffer = make_test_buffer(&mut data, 8);

        // try_grow_front success
        assert!(buffer.try_grow_front(4).is_ok());
        assert_eq!(buffer.headroom(), 4);

        // try_grow_front failure
        let result = buffer.try_grow_front(10);
        assert!(matches!(
            result,
            Err(BufferError::InsufficientHeadroom { requested: 10, available: 4 })
        ));

        // try_extend_len success
        assert!(buffer.try_extend_len(10).is_ok());
        assert_eq!(buffer.len(), 14);

        // try_extend_len failure
        let result = buffer.try_extend_len(100);
        assert!(matches!(
            result,
            Err(BufferError::InsufficientCapacity { .. })
        ));
    }

    #[test]
    #[should_panic(expected = "Headroom exceeded")]
    fn test_grow_front_panic() {
        let mut data = [0u8; 32];
        let mut buffer = make_test_buffer(&mut data, 4);

        buffer.grow_front(10); // Should panic
    }

    #[test]
    #[should_panic(expected = "Cannot shrink more than length")]
    fn test_shrink_front_panic() {
        let mut data = [0u8; 32];
        let mut buffer = make_test_buffer(&mut data, 8);

        buffer.push_slice(&[1, 2, 3]);
        buffer.shrink_front(5); // Should panic
    }

    #[test]
    fn test_zero_headroom() {
        let mut data = [0u8; 32];
        let mut buffer = make_test_buffer(&mut data, 0);

        assert_eq!(buffer.headroom(), 0);
        assert_eq!(buffer.capacity(), 32);

        buffer.push_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(buffer.len(), 5);

        // Cannot prepend with no headroom
        let result = buffer.try_prepend(&[0xAA]);
        assert!(matches!(result, Err(BufferError::InsufficientHeadroom { .. })));
    }

    #[test]
    fn test_fill_from_slice() {
        let mut data = [0u8; 32];
        let mut buffer = make_test_buffer(&mut data, 8);

        let test_data = [1, 2, 3, 4, 5];
        buffer.fill_from_slice(&test_data);
        assert_eq!(buffer.len(), 5);
        assert_eq!(&buffer[..], &test_data);

        // fill_from_slice replaces content
        buffer.fill_from_slice(&[10, 20]);
        assert_eq!(buffer.len(), 2);
        assert_eq!(&buffer[..], &[10, 20]);
    }

    #[test]
    fn test_fluent_api() {
        let mut data = [0u8; 32];
        let buffer_ptr = core::ptr::NonNull::from(data.as_mut_slice());
        let channel =
            Channel::<embassy_sync::blocking_mutex::raw::NoopRawMutex, core::ptr::NonNull<[u8]>, 1>::new();
        let channel = Box::leak(Box::new(channel));
        let counter = Box::leak(Box::new(Cell::new(0u8)));
        let sender = channel.sender();
        let buffer = Buffer {
            buffer: buffer_ptr,
            start: 8,
            len: 0,
            sender: sender.into(),
            allocated_count: counter,
        };

        let buffer = buffer.from_slice(&[1, 2, 3]);
        assert_eq!(buffer.len(), 3);
        assert_eq!(&buffer[..], &[1, 2, 3]);
    }

    #[test]
    fn test_debug_format() {
        let mut data = [0u8; 32];
        let mut buffer = make_test_buffer(&mut data, 8);
        buffer.push_slice(&[1, 2, 3]);

        let debug = format!("{:?}", buffer);
        assert!(debug.contains("headroom: 8"));
        assert!(debug.contains("len: 3"));
    }
}
