#![allow(async_fn_in_trait)]

use core::ops::{Deref, DerefMut};

use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::channel::{Channel, DynamicSender, Receiver, Sender};

pub trait Inbox<M> {
    #[must_use = "Must set response for message"]
    async fn next(&mut self) -> M;
}

impl<'ch, M, MUT, const QUEUE_SIZE: usize> Inbox<M> for Receiver<'ch, MUT, M, QUEUE_SIZE>
where
    M: 'ch,
    MUT: RawMutex,
{
    async fn next(&mut self) -> M {
        self.receive().await
    }
}

pub enum LayerOp<T: 'static> {
    Indication(T),
    Request { message: T, response_tx: DynamicSender<'static, T> },
}

impl<T> core::fmt::Debug for LayerOp<T>
where
    T: core::fmt::Debug + 'static,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LayerOp::Indication(msg) => write!(f, "Indication({:?})", msg),
            LayerOp::Request { message, response_tx: _ } => write!(f, "Request({:?})", message),
        }
    }
}

// impl<T> Deref for LayerOp<T> {
//     type Target = T;

//     fn deref(&self) -> &Self::Target {
//         match self {
//             LayerOp::Indication(msg) => msg,
//             LayerOp::Request { message, .. } => message,
//         }
//     }
// }

// impl<T> DerefMut for LayerOp<T> {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         match self {
//             LayerOp::Indication(msg) => msg,
//             LayerOp::Request { message, .. } => message,
//         }
//     }
// }

impl<T: 'static> LayerOp<T> {
    /// Creates a LayerOp::Request using the safe ActorRequest pattern.
    /// This is used internally by the ActorRequest implementation.
    fn create_request_internal(message: T, response_tx: DynamicSender<'static, T>) -> Self {
        LayerOp::Request { message, response_tx }
    }
}

pub trait Layer<'a>: Sized {
    type Message: 'static;

    async fn process<M>(&mut self, _: M) -> !
    where
        M: Inbox<LayerOp<Self::Message>>;
}

// ############################################################################

// The following part has been taken from `ector`: https://github.com/drogue-iot/ector
// Original Apache License 2.0 and Copyright of the original authors applies

/// Panics if it is improperly disposed of.
///
/// This is to forbid cancelling a future/request.
///
/// To properly dispose, call the [defuse](Self::defuse) method before this object is dropped.
#[must_use = "to delay the drop bomb invokation to the end of the scope"]
pub struct DropBomb;
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
        panic!("Dropped before the request completed. You  cannot cancel an ongoing request")
    }
}

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

pub trait ActorRequest<M, R> {
    /// Attempts to send a message and wait for the response
    async fn request(&self, message: M) -> R;
}

impl<M, R> ActorRequest<M, R> for DynamicSender<'static, Request<M, R>> {
    async fn request(&self, message: M) -> R {
        let channel: Channel<NoopRawMutex, R, 1> = Channel::new();
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

impl<M, R, const N: usize> ActorRequest<M, R> for Sender<'static, NoopRawMutex, Request<M, R>, N> {
    async fn request(&self, message: M) -> R {
        let channel: Channel<NoopRawMutex, R, 1> = Channel::new();
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

/// ActorRequest implementation for LayerOp communication.
/// This allows layers to make requests to other layers and await responses.
impl<'a, T: 'static> ActorRequest<T, T> for DynamicSender<'a, LayerOp<T>> {
    async fn request(&self, message: T) -> T {
        let channel: Channel<NoopRawMutex, T, 1> = Channel::new();
        let sender: DynamicSender<'_, T> = channel.sender().into();
        let bomb = DropBomb::new();

        // We guarantee that channel lives until we've been notified on it, at which
        // point its out of reach for the replier.
        let response_tx = unsafe {
            core::mem::transmute::<
                &embassy_sync::channel::DynamicSender<'_, T>,
                &embassy_sync::channel::DynamicSender<'_, T>,
            >(&sender)
        };
        let layer_op = LayerOp::create_request_internal(message, response_tx.clone());
        self.send(layer_op).await;
        let res = channel.receive().await;

        bomb.defuse();
        res
    }
}

impl<'a, T: 'static, const N: usize> ActorRequest<T, T> for Sender<'a, NoopRawMutex, LayerOp<T>, N> {
    async fn request(&self, message: T) -> T {
        let channel: Channel<NoopRawMutex, T, 1> = Channel::new();
        let sender: DynamicSender<'_, T> = channel.sender().into();
        let bomb = DropBomb::new();

        // We guarantee that channel lives until we've been notified on it, at which
        // point its out of reach for the replier.
        let response_tx = unsafe {
            core::mem::transmute::<
                &embassy_sync::channel::DynamicSender<'_, T>,
                &embassy_sync::channel::DynamicSender<'_, T>,
            >(&sender)
        };
        let layer_op = LayerOp::create_request_internal(message, response_tx.clone());
        self.send(layer_op).await;
        let res = channel.receive().await;

        bomb.defuse();
        res
    }
}

// ############################################################################

pub mod application;
pub mod network;
pub mod test_linklayer;
pub mod transport;
