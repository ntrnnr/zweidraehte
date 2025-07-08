use core::{
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{self, Channel, DynamicReceiver, DynamicSender},
};

/// Error type for buffer operations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BufferError {
    InsufficientCapacity { requested: usize, available: usize },
}

pub trait MessageBuffer: Deref<Target = [u8]> + DerefMut<Target = [u8]> + Sized {
    fn with_len(mut self, len: usize) -> Self {
        self.set_len(len);
        self
    }

    fn from_slice(mut self, data: &[u8]) -> Self {
        self.fill_from_slice(data);
        self
    }

    fn fill_from_slice(&mut self, data: &[u8]) {
        self.set_len(data.len());
        self[..data.len()].copy_from_slice(data);
    }

    fn push(&mut self, byte: u8) {
        let old_len = self.len();
        self.set_len(old_len + 1);

        self[old_len] = byte;
    }

    fn try_set_len(&mut self, len: usize) -> Result<(), BufferError> {
        if len > self.capacity() {
            return Err(BufferError::InsufficientCapacity { requested: len, available: self.capacity() });
        }
        self.set_len(len);
        Ok(())
    }

    fn len(&self) -> usize;
    fn set_len(&mut self, len: usize);
    fn capacity(&self) -> usize;
    fn resize(&mut self, new_len: usize, fill_value: u8);
}

/// A message buffer managed by the [`BufferManager`]
#[clippy::has_significant_drop]
pub struct Buffer<'a> {
    buffer: NonNull<[u8]>,
    len: usize,
    sender: channel::DynamicSender<'a, NonNull<[u8]>>,
}

impl MessageBuffer for Buffer<'_> {
    fn len(&self) -> usize {
        self.len
    }

    fn set_len(&mut self, len: usize) {
        if len > self.capacity() {
            panic!("Length exceeds buffer capacity: {} > {}", len, self.capacity());
        }

        self.len = len;
    }

    fn capacity(&self) -> usize {
        unsafe { self.buffer.as_ref().len() }
    }

    fn resize(&mut self, new_len: usize, fill_value: u8) {
        if new_len > self.capacity() {
            panic!("Length exceeds buffer capacity: {} > {}", new_len, self.capacity());
        }

        let old_len = self.len;
        if new_len > old_len {
            self.len = new_len;
            self[old_len..new_len].fill(fill_value);
        } else {
            self.len = new_len;
        }
    }
}

impl Deref for Buffer<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { &self.buffer.as_ref()[0..self.len] }
    }
}

impl DerefMut for Buffer<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut self.buffer.as_mut()[0..self.len] }
    }
}

impl Drop for Buffer<'_> {
    fn drop(&mut self) {
        // Clear the buffer
        unsafe {
            self.buffer.as_mut().fill(0);
        }

        // Send the buffer back to the manager.
        // This operation cannot fail, as we allocated a capacity equal to the
        // number of buffers we create and manage.
        let _ = self.sender.try_send(self.buffer);
    }
}

impl core::fmt::Debug for Buffer<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Buffer").field("buffer", &self.buffer).finish()
    }
}

/// A dynamic [`BufferManager`] with generics elided.
#[derive(Clone, Copy)]
pub struct DynBufferManager<'a> {
    buffer_sender: DynamicSender<'a, NonNull<[u8]>>,
    buffer_receiver: DynamicReceiver<'a, NonNull<[u8]>>,
}
impl<'a> DynBufferManager<'a> {
    /// Allocate a new [`Buffer`].
    ///
    /// In case no free buffers are available, this function will asynchronously block.
    pub async fn alloc(&self) -> Buffer<'a> {
        Buffer { buffer: self.buffer_receiver.receive().await, len: 0, sender: self.buffer_sender }
    }

    /// Allocate a new [`Buffer`] with the specified size.
    ///
    /// In case no free buffers are available, this function will asynchronously block.
    pub async fn alloc_with_size(&self, size: usize) -> Buffer<'a> {
        let mut buffer = self.alloc().await;
        buffer.set_len(size);
        buffer
    }

    /// Allocate a new [`Buffer`] and fill it with data from a slice.
    ///
    /// In case no free buffers are available, this function will asynchronously block.
    pub async fn alloc_from_slice(&self, data: &[u8]) -> Buffer<'a> {
        let mut buffer = self.alloc().await;
        buffer.fill_from_slice(data);
        buffer
    }

    /// Allocate a new [`Buffer`] with the specified size, filled with zeros.
    ///
    /// In case no free buffers are available, this function will asynchronously block.
    pub async fn alloc_zeroed(&self, size: usize) -> Buffer<'a> {
        let mut buffer = self.alloc().await;
        buffer.resize(size, 0);
        buffer
    }
}

/// A manager for a number of pre-allocated chunks of memory represented by
/// the [`Buffer`] object.
pub struct BufferManager<const NUM_BUFS: usize> {
    buffers: channel::Channel<NoopRawMutex, NonNull<[u8]>, NUM_BUFS>,
}

impl<const NUM_BUFS: usize> BufferManager<NUM_BUFS> {
    /// Create a new [`BufferManager`] which managed the provided buffers.
    pub unsafe fn new<const BUFFER_SIZE: usize>(buffers: &mut [[u8; BUFFER_SIZE]; NUM_BUFS]) -> Self {
        let queue = Channel::new();

        for buffer in buffers {
            let _ = queue.try_send(NonNull::from(buffer.as_mut_slice()));
        }

        Self { buffers: queue }
    }
    /// Acquire a [`DynBufferManager`].
    ///
    /// This allows you to allocate buffers from the manager.
    pub fn dyn_buffer_manager(&self) -> DynBufferManager<'_> {
        DynBufferManager { buffer_sender: self.buffers.dyn_sender(), buffer_receiver: self.buffers.dyn_receiver() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_api_improvements() {
        // Create a simple buffer for testing
        let mut data = [0u8; 64];
        let buffer_ptr = core::ptr::NonNull::from(data.as_mut_slice());

        // Create a mock channel for the buffer
        let channel = Channel::<embassy_sync::blocking_mutex::raw::NoopRawMutex, core::ptr::NonNull<[u8]>, 1>::new();
        let sender = channel.sender();
        let mut buffer = Buffer { buffer: buffer_ptr, len: 0, sender: sender.into() };

        // Test basic functionality
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.capacity(), 64);

        // Test set_len
        buffer.set_len(10);
        assert_eq!(buffer.len(), 10);

        // Test try_set_len success
        assert!(buffer.try_set_len(20).is_ok());
        assert_eq!(buffer.len(), 20);

        // Test try_set_len failure
        assert!(buffer.try_set_len(100).is_err());
        if let Err(BufferError::InsufficientCapacity { requested, available }) = buffer.try_set_len(100) {
            assert_eq!(requested, 100);
            assert_eq!(available, 64);
        }

        // Test fill_from_slice
        let test_data = [1, 2, 3, 4, 5];
        buffer.fill_from_slice(&test_data);
        assert_eq!(buffer.len(), 5);
        assert_eq!(&buffer[..], &test_data);

        // Test resize with fill
        buffer.resize(10, 0xFF);
        assert_eq!(buffer.len(), 10);
        assert_eq!(&buffer[..5], &test_data);
        assert_eq!(&buffer[5..], &[0xFF; 5]);

        // Test resize smaller
        buffer.resize(3, 0x00);
        assert_eq!(buffer.len(), 3);
        assert_eq!(&buffer[..], &[1, 2, 3]);

        // Test push
        buffer.push(42);
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer[3], 42);
    }

    #[test]
    fn test_fluent_api() {
        let mut data = [0u8; 32];
        let buffer_ptr = core::ptr::NonNull::from(data.as_mut_slice());

        let channel = Channel::<embassy_sync::blocking_mutex::raw::NoopRawMutex, core::ptr::NonNull<[u8]>, 1>::new();
        let sender = channel.sender();
        let buffer = Buffer { buffer: buffer_ptr, len: 0, sender: sender.into() };

        // Test with_len
        let buffer = buffer.with_len(5);
        assert_eq!(buffer.len(), 5);

        // Test from_slice
        let test_data = [10, 20, 30];
        let buffer = buffer.from_slice(&test_data);
        assert_eq!(buffer.len(), 3);
        assert_eq!(&buffer[..], &test_data);
    }

    #[test]
    #[should_panic(expected = "Length exceeds buffer capacity")]
    fn test_set_len_panic() {
        let mut data = [0u8; 16];
        let buffer_ptr = core::ptr::NonNull::from(data.as_mut_slice());

        let channel = Channel::<embassy_sync::blocking_mutex::raw::NoopRawMutex, core::ptr::NonNull<[u8]>, 1>::new();
        let sender = channel.sender();
        let mut buffer = Buffer { buffer: buffer_ptr, len: 0, sender: sender.into() };

        buffer.set_len(32); // Should panic
    }

    #[test]
    #[should_panic(expected = "Length exceeds buffer capacity")]
    fn test_resize_panic() {
        let mut data = [0u8; 16];
        let buffer_ptr = core::ptr::NonNull::from(data.as_mut_slice());

        let channel = Channel::<embassy_sync::blocking_mutex::raw::NoopRawMutex, core::ptr::NonNull<[u8]>, 1>::new();
        let sender = channel.sender();
        let mut buffer = Buffer { buffer: buffer_ptr, len: 0, sender: sender.into() };

        buffer.resize(32, 0xFF); // Should panic
    }
}
