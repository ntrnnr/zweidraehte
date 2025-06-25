use core::{
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{self, Channel, DynamicReceiver, DynamicSender},
};

/// A message buffer managed by the [`BufferManager`]
#[clippy::has_significant_drop]
pub struct Buffer<'a> {
    buffer: NonNull<[u8]>,
    len: usize,
    sender: channel::DynamicSender<'a, NonNull<[u8]>>,
}

impl Buffer<'_> {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn set_len(&mut self, len: usize) {
        if len > self.buffer.len() {
            panic!("Length exceeds buffer size");
        }

        self.len = len;
    }

    pub fn push(&mut self, byte: u8) {
        let old_len = self.len();
        self.set_len(old_len + 1);

        self[old_len] = byte;
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

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_buffers() {
//         let mut buffers: [[u8; _]; _] = [[0u8; 32]; 10];
//         let allocator = unsafe { BufferManager::new(&mut buffers) };

//         let a = allocator.dyn_buffer_manager();
//         let b = allocator.dyn_buffer_manager();

//         // FIXME: need proper tests with async runtime
//     }
// }
