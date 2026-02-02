#![allow(async_fn_in_trait)]

use core::ops::Deref;

use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::channel::{Channel, DynamicSender, Receiver, Sender};

use crate::messages::builder::{ConfirmationMessage, IndicationMessage, RequestMessage};

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

/// Layer operation with compile-time direction safety
///
/// - `Indication`: Can only contain an `IndicationMessage` (data flowing UP the stack)
/// - `Request`: Can only contain a `RequestMessage` (request flowing DOWN the stack)
///   with a response channel that only accepts `ConfirmationMessage`
///
/// This prevents accidentally sending a request as an indication or vice versa.
pub enum LayerOp<B: Deref<Target = [u8]> + 'static> {
    /// Data received from lower layer, flowing UP the stack
    Indication(IndicationMessage<B>),
    /// Request to lower layer, flowing DOWN the stack
    Request {
        message: RequestMessage<B>,
        response_tx: DynamicSender<'static, ConfirmationMessage<B>>,
    },
}

impl<B> core::fmt::Debug for LayerOp<B>
where
    B: Deref<Target = [u8]> + core::fmt::Debug + 'static,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LayerOp::Indication(msg) => write!(f, "Indication({:?})", msg),
            LayerOp::Request { message, response_tx: _ } => write!(f, "Request({:?})", message),
        }
    }
}

pub trait Layer<'a>: Sized {
    /// The buffer type used in messages (e.g., `Buffer<'static>`)
    type Buffer: Deref<Target = [u8]> + 'static;

    async fn process<M>(&mut self, _: M) -> !
    where
        M: Inbox<LayerOp<Self::Buffer>>;
}

/// Trait for building link layers
///
/// Link layer builders are responsible for constructing configured link layer
/// instances that can be run in the KNX stack. Different link layer implementations
/// (TPUART, KNX/IP, Mock, etc.) provide their own builders that implement this trait.
///
/// This trait uses a factory pattern where the builder is consumed to produce a link layer.
/// The link layer must be able to run indefinitely using the `Layer` trait's process method.
///
/// The builder accepts a generic context `CTX` that implements the required context traits
/// (e.g., `BufferManagerContext`). This allows for easy mocking and testing of link layers
/// without requiring the full stack infrastructure.
///
/// Each link layer implementation defines its own `Resources` type that contains all
/// statically allocated resources needed by that link layer (e.g., sockets, channels).
/// This enables flexible resource allocation for different link layer types (KNX/IP, KNX-RF, etc.)
/// while maintaining a no_std, zero-allocation design.
pub trait LinkLayerBuilder: Sized {
    /// The resource type required by this link layer implementation
    type Resources: Sized + 'static;

    /// Create the resources needed by this link layer
    fn create_resources(&self) -> Self::Resources;

    /// Build and return the configured link layer instance
    ///
    /// # Arguments
    /// * `resources` - Mutable reference to the link layer's resources
    /// * `context` - Reference to a context implementing required traits (e.g., BufferManagerContext)
    /// * `network_layer` - Channel sender to communicate with the network layer
    /// * `inbox` - Channel receiver for layer operations from the network layer
    ///
    /// # Returns
    /// A future that when awaited, runs the link layer to completion (never returns)
    fn build_and_run<'a, CTX>(
        self,
        resources: &'a mut Self::Resources,
        context: &'a CTX,
        network_layer: DynamicSender<'a, LayerOp<crate::messages::buffers::Buffer<'static>>>,
        inbox: impl Inbox<LayerOp<crate::messages::buffers::Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a
    where
        CTX: crate::context::BufferManagerContext;
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

/// ActorRequest implementation for Request channels with any lifetime.
///
/// This supports both `'static` and non-`'static` channel references,
/// needed for layers that don't have `'static` references to their channels,
/// such as the application layer's restart_sender.
impl<'a, M, R> ActorRequest<M, R> for DynamicSender<'a, Request<M, R>> {
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

/// ActorRequest implementation for LayerOp communication with typed messages.
///
/// This allows layers to send `RequestMessage`s and receive `ConfirmationMessage`s.
/// The type system ensures you can't accidentally send the wrong message type.
impl<'a, B: Deref<Target = [u8]> + 'static> ActorRequest<RequestMessage<B>, ConfirmationMessage<B>> for DynamicSender<'a, LayerOp<B>> {
    async fn request(&self, message: RequestMessage<B>) -> ConfirmationMessage<B> {
        let channel: Channel<NoopRawMutex, ConfirmationMessage<B>, 1> = Channel::new();
        let sender: DynamicSender<'_, ConfirmationMessage<B>> = channel.sender().into();
        let bomb = DropBomb::new();

        // We guarantee that channel lives until we've been notified on it, at which
        // point its out of reach for the replier.
        let response_tx = unsafe {
            core::mem::transmute::<
                &embassy_sync::channel::DynamicSender<'_, ConfirmationMessage<B>>,
                &embassy_sync::channel::DynamicSender<'_, ConfirmationMessage<B>>,
            >(&sender)
        };
        let layer_op = LayerOp::Request { message, response_tx: response_tx.clone() };
        self.send(layer_op).await;
        let res = channel.receive().await;

        bomb.defuse();
        res
    }
}

impl<'a, B: Deref<Target = [u8]> + 'static, const N: usize> ActorRequest<RequestMessage<B>, ConfirmationMessage<B>>
    for Sender<'a, NoopRawMutex, LayerOp<B>, N>
{
    async fn request(&self, message: RequestMessage<B>) -> ConfirmationMessage<B> {
        let channel: Channel<NoopRawMutex, ConfirmationMessage<B>, 1> = Channel::new();
        let sender: DynamicSender<'_, ConfirmationMessage<B>> = channel.sender().into();
        let bomb = DropBomb::new();

        // We guarantee that channel lives until we've been notified on it, at which
        // point its out of reach for the replier.
        let response_tx = unsafe {
            core::mem::transmute::<
                &embassy_sync::channel::DynamicSender<'_, ConfirmationMessage<B>>,
                &embassy_sync::channel::DynamicSender<'_, ConfirmationMessage<B>>,
            >(&sender)
        };
        let layer_op = LayerOp::Request { message, response_tx: response_tx.clone() };
        self.send(layer_op).await;
        let res = channel.receive().await;

        bomb.defuse();
        res
    }
}

// ############################################################################

pub mod application;
pub mod linklayers;
pub mod network;
pub mod transport;
