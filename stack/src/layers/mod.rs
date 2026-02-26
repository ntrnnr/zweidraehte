#![allow(async_fn_in_trait)]

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{Channel, DynamicSender, Receiver, Sender};

use crate::messages::builder::{ConfirmationMessage, IndicationMessage};
use crate::messages::buffers::Buffer;

/// Async message inbox that yields one message per call.
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

// ============================================================================
// Link Layer Builder Traits
// ============================================================================

/// Resource allocation for link layer builders.
///
/// Each link layer implementation defines its own `Resources` type containing
/// all statically allocated resources it needs (e.g., sockets, channels, buffers).
/// This enables flexible resource allocation for different link layer types
/// (KNX/IP, USB, TPUART, etc.) while maintaining a no\_std, zero-allocation design.
///
/// This trait is separated from [`LinkLayerBuilder`] so that `Resources` can be
/// projected without binding to a specific context lifetime — the stack stores
/// `<LLB as LinkLayerBuilderBase>::Resources` in its pre-allocated resource struct,
/// where no runtime context exists yet.
///
/// # Implementing
///
/// Every link layer builder must implement this trait. The companion trait
/// [`LinkLayerBuilder<CTX>`] adds the ability to build and run the link layer
/// with a specific runtime context.
///
/// In [`StackDefinition`](crate::StackDefinition), the associated type `LLB`
/// requires both:
///
/// ```rust,ignore
/// type LLB: LinkLayerBuilderBase
///         + for<'a> LinkLayerBuilder<StackContext<'a, Self>>;
/// ```
pub trait LinkLayerBuilderBase: Sized {
    /// The resource type required by this link layer implementation.
    ///
    /// Examples: socket pools for KNX/IP, empty structs for mock link layers.
    type Resources: Sized + 'static;

    /// Create the resources needed by this link layer.
    ///
    /// Called once during stack initialization. The returned resources are stored
    /// in [`StackResources`](crate::StackResources) and passed by mutable
    /// reference to [`LinkLayerBuilder::build_and_run`] when the stack runs.
    fn create_resources(&self) -> Self::Resources;
}

/// Build and run a link layer with a given runtime context.
///
/// This trait extends [`LinkLayerBuilderBase`] with the ability to consume the
/// builder, producing a future that runs the link layer to completion (never
/// returns).
///
/// # Per-implementation context bounds
///
/// The `CTX` type parameter is a trait-level generic so that each implementation
/// declares only the context traits it actually needs:
///
/// | Link layer | Context bounds |
/// |------------|---------------|
/// | Mock | *(none — `impl<CTX> LinkLayerBuilder<CTX>`)* |
/// | USB | [`BufferManagerContext`](crate::context::BufferManagerContext) |
/// | KNX/IP | [`BufferManagerContext`](crate::context::BufferManagerContext) + [`PropertyServiceContext`](crate::context::PropertyServiceContext) |
///
/// At stack level the concrete context is [`StackContext`](crate::StackContext),
/// which implements both `BufferManagerContext` and `PropertyServiceContext`,
/// so it satisfies all implementations.
///
/// # Channel architecture
///
/// Each link layer communicates with the network layer through three
/// unidirectional typed channels instead of a single bidirectional
/// `LayerOp` channel. This eliminates deadlocks caused by blocking
/// request-response patterns through bounded channels.
///
/// - `ind_tx`: Send indications (received frames) up to the network layer
/// - `conf_tx`: Send confirmations (transmission results) up to the network layer
/// - `req_rx`: Receive transmission requests from the network layer
pub trait LinkLayerBuilder<CTX>: LinkLayerBuilderBase {
    /// Build the link layer and return a future that runs it indefinitely.
    ///
    /// The builder is consumed. The returned future drives the link layer's
    /// receive/transmit loop and never returns (`-> !`).
    ///
    /// # Arguments
    /// * `resources` - Mutable reference to the resources created by
    ///   [`LinkLayerBuilderBase::create_resources`]
    /// * `context` - Runtime context providing access to buffer management
    ///   and (optionally) property services, depending on this impl's bounds
    /// * `ind_tx` - Channel sender for passing received frame indications
    ///   up to the network layer
    /// * `conf_tx` - Channel sender for passing transmission confirmations
    ///   up to the network layer
    /// * `req_rx` - Channel receiver for transmission requests from the
    ///   network layer
    fn build_and_run<'a>(
        self,
        resources: &'a mut Self::Resources,
        context: &'a CTX,
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl Inbox<crate::messages::builder::RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a;
}

// ============================================================================
// Actor-Style Request/Response (for app_service_channel, restart_channel)
// ============================================================================

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

/// Send a request and await the response through a temporary channel.
///
/// The `MUT` parameter controls the mutex type of the temporary response
/// channel. Use [`NoopRawMutex`] when requester and replier share the same
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

impl<MUT: RawMutex, OUTER_MUT: RawMutex, M, R, const N: usize> ActorRequest<MUT, M, R> for Sender<'static, OUTER_MUT, Request<M, R>, N> {
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

// ############################################################################

pub mod application;
pub mod linklayers;
pub mod network;
pub mod transport;
