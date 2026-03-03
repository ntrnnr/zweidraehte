#![allow(async_fn_in_trait)]

//! Actor-style request/response channel infrastructure.
//!
//! Provides [`Request<M, R>`] — a one-shot request carrying a message `M` and
//! an embedded reply channel for `R` — and the [`ActorRequest`] trait for
//! sending a request and awaiting its response through a temporary channel.
//!
//! Used by the application layer's service channel, the restart channel, and
//! [`Stack`](crate::Stack) public API methods.

// The following part has been taken from `ector`: https://github.com/drogue-iot/ector
// Original Apache License 2.0 and Copyright of the original authors applies

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{Channel, DynamicSender, Sender};

// ============================================================================
// DropBomb — panic guard for cancelled requests
// ============================================================================

/// Panics if it is improperly disposed of.
///
/// This is to forbid cancelling a future/request.
///
/// To properly dispose, call the [defuse](Self::defuse) method before this object is dropped.
#[must_use = "to delay the drop bomb invocation to the end of the scope"]
struct DropBomb;
impl DropBomb {
    pub fn new() -> Self {
        Self
    }

    /// Defuses the bomb, rendering it safe to drop.
    pub fn defuse(self) {
        core::mem::forget(self)
    }
}

impl Drop for DropBomb {
    fn drop(&mut self) {
        panic!("Dropped before the request completed. You cannot cancel an ongoing request")
    }
}

// ============================================================================
// Request<M, R>
// ============================================================================

pub struct Request<M, R>
where
    R: 'static,
{
    message: Option<M>,
    reply_to: &'static DynamicSender<'static, R>,
}

unsafe impl<M, R> Send for Request<M, R> {}

impl<M, R> Request<M, R> {
    fn new(message: M, reply_to: &'static DynamicSender<'static, R>) -> Self {
        Self { message: Some(message), reply_to }
    }

    /// Process the message using a closure.
    ///
    /// The return value of the closure is used as the response.
    pub async fn process<F: FnOnce(M) -> R>(mut self, f: F) {
        let reply = f(self.message.take().unwrap());
        self.reply_to.send(reply).await;
    }

    /// Reply to the request using the provided value.
    pub async fn reply(self, value: R) {
        self.reply_to.send(value).await
    }

    /// Reply to the request synchronously (non-blocking).
    ///
    /// Uses `try_send` on the underlying channel. Returns `Ok(())` if the
    /// reply was delivered, or `Err` if the channel was full.
    pub fn try_reply(&self, value: R) -> Result<(), embassy_sync::channel::TrySendError<R>> {
        self.reply_to.try_send(value)
    }

    /// Get a reference to the underlying message
    pub fn get(&self) -> &M {
        self.message.as_ref().unwrap()
    }

    /// Get a mutable reference to the underlying message
    pub fn get_mut(&mut self) -> &mut M {
        self.message.as_mut().unwrap()
    }
}

impl<M, R> AsRef<M> for Request<M, R> {
    fn as_ref(&self) -> &M {
        self.message.as_ref().unwrap()
    }
}

impl<M, R> AsMut<M> for Request<M, R> {
    fn as_mut(&mut self) -> &mut M {
        self.message.as_mut().unwrap()
    }
}

// ============================================================================
// ActorRequest trait + impls
// ============================================================================

/// Send a request and await the response through a temporary channel.
///
/// The `MUT` parameter controls the mutex type of the temporary response
/// channel. Use [`NoopRawMutex`](embassy_sync::blocking_mutex::raw::NoopRawMutex) when requester and replier share the same
/// executor; use [`CriticalSectionRawMutex`](embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex)
/// when they may run on different executors (e.g. interrupt vs thread).
///
/// Configured via [`StackDefinition::Mutex`](crate::StackDefinition::Mutex).
pub trait ActorRequest<MUT: RawMutex, M, R> {
    /// Attempts to send a message and wait for the response
    async fn request(&self, message: M) -> R;
}

/// ActorRequest implementation for Request channels with any lifetime.
///
/// This supports both `'static` and non-`'static` channel references,
/// needed for layers that don't have `'static` references to their channels,
/// such as the application layer's restart_sender.
impl<'a, MUT: RawMutex, M, R> ActorRequest<MUT, M, R> for DynamicSender<'a, Request<M, R>> {
    async fn request(&self, message: M) -> R {
        let channel: Channel<MUT, R, 1> = Channel::new();
        let sender: DynamicSender<'_, R> = channel.sender().into();
        let bomb = DropBomb::new();

        // We guarantee that channel lives until we've been notified on it, at which
        // point its out of reach for the replier.
        let reply_to = unsafe {
            core::mem::transmute::<
                &embassy_sync::channel::DynamicSender<'_, R>,
                &embassy_sync::channel::DynamicSender<'_, R>,
            >(&sender)
        };
        let message = Request::new(message, reply_to);
        self.send(message).await;
        let res = channel.receive().await;

        bomb.defuse();
        res
    }
}

impl<MUT: RawMutex, OuterMut: RawMutex, M, R, const N: usize> ActorRequest<MUT, M, R> for Sender<'static, OuterMut, Request<M, R>, N> {
    async fn request(&self, message: M) -> R {
        let channel: Channel<MUT, R, 1> = Channel::new();
        let sender: DynamicSender<'_, R> = channel.sender().into();
        let bomb = DropBomb::new();

        // We guarantee that channel lives until we've been notified on it, at which
        // point its out of reach for the replier.
        let reply_to = unsafe {
            core::mem::transmute::<
                &embassy_sync::channel::DynamicSender<'_, R>,
                &embassy_sync::channel::DynamicSender<'_, R>,
            >(&sender)
        };
        let message = Request::new(message, reply_to);
        self.send(message).await;
        let res = channel.receive().await;

        bomb.defuse();
        res
    }
}
