use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::{Channel, Receiver, Sender};

/// A generic dequeue (double-ended queue) implementation using embassy channels
/// This allows for efficient async queuing with backpressure
pub struct Dequeue<T, const N: usize> {
    channel: Channel<NoopRawMutex, T, N>,
}

impl<T, const N: usize> Default for Dequeue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Dequeue<T, N> {
    /// Create a new dequeue with capacity N
    pub const fn new() -> Self {
        Self { channel: Channel::new() }
    }

    /// Get sender for this dequeue
    pub fn sender(&self) -> Sender<'_, NoopRawMutex, T, N> {
        self.channel.sender()
    }

    /// Get receiver for this dequeue  
    pub fn receiver(&self) -> Receiver<'_, NoopRawMutex, T, N> {
        self.channel.receiver()
    }

    /// Send an item to the back of the dequeue
    /// This will block if the dequeue is full (providing backpressure)
    pub async fn send(&self, item: T) {
        self.channel.send(item).await;
    }

    /// Receive an item from the front of the dequeue
    /// This will block if the dequeue is empty
    pub async fn receive(&self) -> T {
        self.channel.receive().await
    }

    /// Try to send an item without blocking
    /// Returns Ok(()) if successful, Err(item) if the dequeue is full
    pub fn try_send(&self, item: T) -> Result<(), T> {
        match self.channel.try_send(item) {
            Ok(()) => Ok(()),
            Err(embassy_sync::channel::TrySendError::Full(item)) => Err(item),
        }
    }

    /// Try to receive an item without blocking
    /// Returns Some(item) if successful, None if the dequeue is empty
    pub fn try_receive(&self) -> Option<T> {
        self.channel.try_receive().ok()
    }

    /// Check if the dequeue is empty without removing items
    pub fn is_empty(&self) -> bool {
        self.channel.len() == 0
    }

    /// Check if the dequeue is full without adding items
    pub fn is_full(&self) -> bool {
        self.channel.len() == N
    }

    /// Get the current number of items in the dequeue
    pub fn len(&self) -> usize {
        self.channel.len()
    }
}
