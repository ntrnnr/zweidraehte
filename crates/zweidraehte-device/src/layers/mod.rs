// All traits here are crate-internal; `Send` bounds on async trait
// futures are irrelevant in our single-executor embedded context.
#![allow(async_fn_in_trait)]

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{DynamicSender, Receiver};

use crate::messages::buffers::Buffer;
use crate::messages::builder::{ConfirmationMessage, IndicationMessage};

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

    /// Extra inter-layer endpoints the link layer needs beyond the standard
    /// ind/conf/req channels.
    ///
    /// Created by [`LayerStackBuilder::run_link_layer`](crate::LayerStackBuilder::run_link_layer)
    /// from the shared channel storage and passed to
    /// [`build_and_run`](LinkLayerBuilder::build_and_run).
    ///
    /// Defaults to `()` for link layers that don't need extra channels.
    /// KNX/IP uses [`CemiTransportLayerEndpoints`](crate::context::CemiTransportLayerEndpoints).
    type LLEndpoints<'a> = ();

    /// Create the resources needed by this link layer.
    ///
    /// Called once during stack initialization. The returned resources are stored
    /// in [`StackResources`](crate::StackResources) and passed by mutable
    /// reference to [`LinkLayerBuilder::build_and_run`] when the stack runs.
    fn create_resources(&self) -> Self::Resources;
}

/// Link-layer-derived device capabilities.
///
/// Allows the stack to query compile-time metadata from the link layer
/// builder without the rest of the stack being parameterised on the
/// builder's own type parameters (e.g. `FeatureSet`).
///
/// The default returns `0` for every constant, which is correct for all
/// non-IP link layers (TPUART, USB, mock). The KNX/IP builder overrides
/// [`KNXNETIP_DEVICE_CAPABILITIES`](Self::KNXNETIP_DEVICE_CAPABILITIES)
/// by forwarding the value from its `FeatureSet`.
pub trait LinkLayerCapabilities {
    /// PID\_KNXNETIP\_DEVICE\_CAPABILITIES (PID 68) bitfield.
    ///
    /// Non-IP link layers leave this at the default `0`.
    /// KNX/IP builders derive it from their [`FeatureSet`](crate::layers::linklayers::knxip::features::FeatureSet).
    const KNXNETIP_DEVICE_CAPABILITIES: u16 = 0;
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
/// | Link layer | Context bounds | LLEndpoints |
/// |------------|---------------|-------------|
/// | Mock | *(none — `impl<CTX> LinkLayerBuilder<CTX>`)* | `()` |
/// | USB | [`BufferManagerContext`](crate::context::BufferManagerContext) | `()` |
/// | TPUART | [`BufferManagerContext`](crate::context::BufferManagerContext) | `()` |
/// | KNX/IP | [`KnxNetIpContext`](crate::layers::linklayers::knxip::KnxNetIpContext) | [`CemiTransportLayerEndpoints`](crate::context::CemiTransportLayerEndpoints) |
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
    /// * `ll_endpoints` - Extra inter-layer endpoints from
    ///   [`LayerStackBuilder::run_link_layer`](crate::LayerStackBuilder::run_link_layer).
    ///   `()` for link layers that don't need them.
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
        ll_endpoints: Self::LLEndpoints<'a>,
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl Inbox<crate::messages::builder::RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a;
}

pub mod application;
pub mod linklayers;

// Backward-compatible re-exports for the old flat module paths.
pub use application::extensions::traits as al_extension;
pub use application::extensions::domain_addr as al_ext_domain_addr;
pub use application::extensions::property_ext as al_ext_property_ext;
pub mod network;
pub mod secure_application;
pub mod transport;
