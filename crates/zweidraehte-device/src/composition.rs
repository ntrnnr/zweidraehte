//! Layer composition: builders, layer stacks, and constructors.
//!
//! This module contains the types that connect the protocol layers (NL, TL, AL)
//! into a composed stack and wire them to the link layer. Two built-in builders
//! are provided:
//!
//! - [`InsecureDeviceBuilder`] — standard `(NL, TL, AL)` stack
//! - [`InsecureIpDeviceBuilder`] — KNX/IP `(NL, CemiTL<TL>, AL)` stack (requires `knxip` feature)

#[allow(async_fn_in_trait)]

use core::cell::Cell;

use embassy_sync::channel::{DynamicReceiver, DynamicSender};

use crate::{
    access::HasConnectionAuth,
    actor::Request,
    definition::StackDefinition,
    inner::StackContext,
    layers::{
        self, LinkLayerBuilder,
        application::{ApplicationLayer, ApplicationLayerService, ApplicationLayerServiceResponse},
        network::NetworkLayer,
        transport::TransportLayer,
    },
    messages::buffers::{Buffer, DynBufferManager},
    objects::{
        comm::{ComObjectEvent, ComObjects, LifecycleEvent},
        interface::{HasDeviceObject, HasRoutingCount},
        tables::{
            HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable,
        },
    },
    restart,
    router::{self, LayerStack},
};

use core::cell::RefCell;
use embassy_sync::pubsub::PubSubChannel;

use crate::messages::knx::KnxMessageBuffer;

// ============================================================================
// LayerContext
// ============================================================================

/// Context passed to [`LayerStackBuilder::build`] for constructing the
/// layer stack.
///
/// Bundles all shared stack resources that protocol layers may need.
/// Custom layer stacks can pick the fields they care about and ignore
/// the rest.
pub struct LayerContext<'a, D: StackDefinition> {
    /// Buffer allocator for building outgoing messages.
    pub buffer_manager: &'a DynBufferManager<'static>,
    /// Unified device state (tables + runtime configuration).
    pub state: &'a D::State,
    /// Communication objects (group objects).
    pub comm_objs: &'a RefCell<D::CO>,
    /// Hook context for communication object hooks.
    pub hook_context: &'a <D::CO as ComObjects>::HookContext,
    /// Pub/sub channel for communication object events.
    pub event_channel:
        &'a PubSubChannel<D::Mutex, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent), 4, 2, 1>,
    /// Pub/sub channel for application lifecycle events.
    pub lifecycle_channel: &'a PubSubChannel<D::Mutex, LifecycleEvent, 4, 2, 1>,
    /// Interface objects container for property service handling.
    pub interface_objects: &'a D::InterfaceObjects<'static>,
    /// Memory map for A_Memory_Read/Write services.
    pub memory_map: &'a D::Mem,
    /// Sender for restart requests from AL to user code.
    pub restart_sender: DynamicSender<'a, restart::RestartRequest>,
    /// Receiver for application service requests from user code
    /// (GroupValueWrite/Read via [`Stack::update_object`](crate::Stack::update_object)).
    pub app_service_receiver: DynamicReceiver<'a, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
}

// ============================================================================
// Layer stack builders
// ============================================================================

/// Builder for constructing a layer stack and running its link layer.
///
/// Encapsulates channel creation, layer construction, and link-layer
/// endpoint wiring. Each builder knows:
///
/// - What shared channels are needed between layers and the link layer
/// - How to build the layer stack from a [`LayerContext`]
/// - How to extract link-layer endpoints and start the link layer
///
/// Two built-in builders are provided:
/// - [`InsecureDeviceBuilder`] — standard `(NL, TL, AL)` stack, no extra channels
/// - [`InsecureIpDeviceBuilder`] — `(NL, CemiTL<TL>, AL)` stack with cEMI channels
pub trait LayerStackBuilder<D: StackDefinition>: Sized {
    /// Composed layer stack produced by [`build`](Self::build).
    type Stack<'a>: router::LayerStack
    where
        D: 'a;

    /// Owned channel storage shared between the layer stack and the link
    /// layer. Created as a stack-local in [`Runner::run()`](crate::Runner::run) before layer
    /// construction, so both the router task and the LL task can borrow
    /// from it.
    ///
    /// `()` when no extra channels are needed (standard TP1 devices).
    type Channels: Default + 'static;

    /// Build the layer stack from a [`LayerContext`] and the shared channels.
    fn build<'a>(ctx: &'a LayerContext<'a, D>, channels: &'a Self::Channels) -> Self::Stack<'a>
    where
        D: 'a;

    /// Start the link layer, extracting LL endpoints from the shared channels.
    ///
    /// The builder knows how to connect its channel type to the link layer
    /// builder's [`LLEndpoints`](layers::LinkLayerBuilderBase::LLEndpoints).
    fn run_link_layer<'a>(
        channels: &'a Self::Channels,
        builder: D::LLB,
        resources: &'a mut <D::LLB as layers::LinkLayerBuilderBase>::Resources,
        context: &'a StackContext<'a, D>,
        ind_tx: DynamicSender<'a, crate::messages::builder::IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, crate::messages::builder::ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl layers::Inbox<crate::messages::builder::RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a;
}

/// Builder for standard `(NL, TL, AL)` layer stacks.
///
/// Produces [`StandardDeviceLayers`] with no extra inter-layer channels.
/// The link layer builder must have `LLEndpoints = ()` (the default).
pub struct InsecureDeviceBuilder;

impl<D: StackDefinition> LayerStackBuilder<D> for InsecureDeviceBuilder
where
    D::State: HasAddressTable
        + HasApplication
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasConnectionAuth
        + HasRoutingCount,
    D::InterfaceObjects<'static>: HasDeviceObject,
    for<'a> <D::LLB as layers::LinkLayerBuilderBase>::LLEndpoints<'a>: Default,
    D::LLB: for<'a> layers::LinkLayerBuilder<StackContext<'a, D>>,
{
    type Stack<'a>
        = StandardDeviceLayers<'a, D>
    where
        D: 'a;
    type Channels = ();

    fn build<'a>(ctx: &'a LayerContext<'a, D>, _channels: &'a ()) -> StandardDeviceLayers<'a, D>
    where
        D: 'a,
    {
        InsecureDeviceLayers::standard(ctx)
    }

    fn run_link_layer<'a>(
        _channels: &'a (),
        builder: D::LLB,
        resources: &'a mut <D::LLB as layers::LinkLayerBuilderBase>::Resources,
        context: &'a StackContext<'a, D>,
        ind_tx: DynamicSender<'a, crate::messages::builder::IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, crate::messages::builder::ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl layers::Inbox<crate::messages::builder::RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        builder.build_and_run(resources, context, Default::default(), ind_tx, conf_tx, req_rx)
    }
}

/// Builder for KNX/IP `(NL, CemiTL<TL>, AL)` layer stacks.
///
/// Produces [`IpDeviceLayers`] with a [`CemiTransportLayerChannelPair`](crate::context::CemiTransportLayerChannelPair)
/// for Device Management connections. The link layer builder's
/// [`LLEndpoints`](layers::LinkLayerBuilderBase::LLEndpoints) must be
/// [`CemiTransportLayerEndpoints`](crate::context::CemiTransportLayerEndpoints).
#[cfg(feature = "knxip")]
pub struct InsecureIpDeviceBuilder;

#[cfg(feature = "knxip")]
impl<D: StackDefinition> LayerStackBuilder<D> for InsecureIpDeviceBuilder
where
    D::State: HasAddressTable
        + HasApplication
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasConnectionAuth
        + HasRoutingCount,
    D::InterfaceObjects<'static>: HasDeviceObject,
    D::LLB: for<'a> layers::LinkLayerBuilder<
            StackContext<'a, D>,
            LLEndpoints<'a> = crate::context::CemiTransportLayerEndpoints<'a>,
        >,
{
    type Stack<'a>
        = IpDeviceLayers<'a, D>
    where
        D: 'a;
    type Channels = crate::context::CemiTransportLayerChannelPair;

    fn build<'a>(
        ctx: &'a LayerContext<'a, D>,
        channels: &'a crate::context::CemiTransportLayerChannelPair,
    ) -> IpDeviceLayers<'a, D>
    where
        D: 'a,
    {
        InsecureDeviceLayers::with_cemi(ctx, channels)
    }

    fn run_link_layer<'a>(
        channels: &'a crate::context::CemiTransportLayerChannelPair,
        builder: D::LLB,
        resources: &'a mut <D::LLB as layers::LinkLayerBuilderBase>::Resources,
        context: &'a StackContext<'a, D>,
        ind_tx: DynamicSender<'a, crate::messages::builder::IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, crate::messages::builder::ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl layers::Inbox<crate::messages::builder::RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        builder.build_and_run(resources, context, channels.ll_endpoints(), ind_tx, conf_tx, req_rx)
    }
}

// ============================================================================
// Layer stack implementations
// ============================================================================

/// Composable layer stack: `(NetworkLayer, TL, ApplicationLayer)` with
/// optional extra side inputs.
///
/// The `TL` parameter is the transport-layer-slot type:
/// - Standard devices: [`TransportLayer`]
/// - KNX/IP devices: [`CemiTransportLayer`](crate::layers::transport::cemi::CemiTransportLayer),
///   which *wraps* a `TransportLayer` and intercepts connection-oriented
///   requests when a Device Management connection is active.
///
/// The `Extra` parameter adds side-input sources beyond the always-present
/// app service channel. Use [`ExtraSideInput`](router::ExtraSideInput)
/// implementations to inject events from link layers, external tasks, or
/// other upper layers.
///
/// # Type Aliases
///
/// - [`StandardDeviceLayers`] — `InsecureDeviceLayers<D, TransportLayer, ()>`
/// - [`IpDeviceLayers`] — `InsecureDeviceLayers<D, CemiTransportLayer, CemiSideInput>`
///
/// # Custom Layer Stacks
///
/// For layer stacks that don't fit the `(NL, TL, AL)` pattern, implement
/// [`LayerStack`] directly on a different type and use a custom
/// [`LayerStackBuilder`].
pub struct InsecureDeviceLayers<'a, D: StackDefinition, TL: router::Layer, Extra = ()> {
    layers: (NetworkLayer<'a, D>, TL, ApplicationLayer<'a, D>),
    app_service_receiver: DynamicReceiver<'a, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
    pending_app_request: Cell<Option<Request<ApplicationLayerService, ApplicationLayerServiceResponse>>>,
    extra: Extra,
}

/// Standard layer stack: `(NL, TL, AL)` with no extra side inputs.
pub type StandardDeviceLayers<'a, D> =
    InsecureDeviceLayers<'a, D, TransportLayer<'a, D>>;

/// KNX/IP layer stack: `(NL, CemiTL<TL>, AL)` with cEMI side input.
#[cfg(feature = "knxip")]
pub type IpDeviceLayers<'a, D> =
    InsecureDeviceLayers<'a, D, layers::transport::cemi::CemiTransportLayer<'a, D>, layers::transport::cemi::CemiSideInput<'a>>;

// ----------------------------------------------------------------------------
// Constructors
// ----------------------------------------------------------------------------

impl<'a, D: StackDefinition> InsecureDeviceLayers<'a, D, TransportLayer<'a, D>, ()>
where
    D::State: HasAddressTable
        + HasApplication
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasConnectionAuth
        + HasRoutingCount,
    D::InterfaceObjects<'static>: HasDeviceObject,
{
    /// Construct the standard `(NL, TL, AL)` layer stack.
    pub fn standard(ctx: &'a LayerContext<'a, D>) -> Self {
        let network_layer = NetworkLayer::new(ctx.state, ctx.interface_objects);

        // TODO: Use `{ D::TL_MAX_INCOMING }` and `{ D::TL_MAX_OUTGOING }` as const
        // generics here once `generic_const_exprs` no longer overflows for trait
        // consts forwarded through where-clauses.
        let transport_layer = TransportLayer::new(ctx.buffer_manager, ctx.state, D::TL_STYLE);

        let application_layer = ApplicationLayer::new(
            ctx.buffer_manager,
            ctx.state,
            ctx.comm_objs,
            ctx.hook_context,
            ctx.event_channel,
            ctx.lifecycle_channel,
            ctx.interface_objects,
            ctx.memory_map,
            ctx.restart_sender,
        );

        Self {
            layers: (network_layer, transport_layer, application_layer),
            app_service_receiver: ctx.app_service_receiver,
            pending_app_request: Cell::new(None),
            extra: (),
        }
    }
}

#[cfg(feature = "knxip")]
impl<'a, D: StackDefinition> InsecureDeviceLayers<'a, D, layers::transport::cemi::CemiTransportLayer<'a, D>, layers::transport::cemi::CemiSideInput<'a>>
where
    D::State: HasAddressTable
        + HasApplication
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasConnectionAuth
        + HasRoutingCount,
    D::InterfaceObjects<'static>: HasDeviceObject,
{
    /// Construct the KNX/IP `(NL, CemiTL<TL>, AL)` layer stack.
    ///
    /// The [`CemiTransportLayer`](crate::layers::transport::cemi::CemiTransportLayer)
    /// wraps a standard [`TransportLayer`] and adds cEMI Device Management
    /// support. Under normal operation, all messages delegate to the inner TL.
    /// Only when a Device Management connection activates does it lock the
    /// inner TL's incoming connections and intercept connection-oriented AL
    /// requests, routing them to the cEMI response channel.
    pub fn with_cemi(ctx: &'a LayerContext<'a, D>, channels: &'a crate::context::CemiTransportLayerChannelPair) -> Self {
        let network_layer = NetworkLayer::new(ctx.state, ctx.interface_objects);

        let transport_layer = TransportLayer::new(ctx.buffer_manager, ctx.state, D::TL_STYLE);

        let cemi_response_sender = channels.response.sender().into();
        let cemi_transport_layer =
            layers::transport::cemi::CemiTransportLayer::new(transport_layer, cemi_response_sender);

        let application_layer = ApplicationLayer::new(
            ctx.buffer_manager,
            ctx.state,
            ctx.comm_objs,
            ctx.hook_context,
            ctx.event_channel,
            ctx.lifecycle_channel,
            ctx.interface_objects,
            ctx.memory_map,
            ctx.restart_sender,
        );

        let cemi_event_receiver = channels.event.receiver().into();

        Self {
            layers: (network_layer, cemi_transport_layer, application_layer),
            app_service_receiver: ctx.app_service_receiver,
            pending_app_request: Cell::new(None),
            extra: layers::transport::cemi::CemiSideInput::new(cemi_event_receiver),
        }
    }
}

// ----------------------------------------------------------------------------
// LayerStack impl — generic over TL and Extra
// ----------------------------------------------------------------------------

impl<'a, D: StackDefinition, TL: router::Layer, Extra> LayerStack for InsecureDeviceLayers<'a, D, TL, Extra>
where
    D::State: HasAddressTable
        + HasApplication
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasConnectionAuth
        + HasRoutingCount,
    D::InterfaceObjects<'static>: HasDeviceObject,
    Extra: router::ExtraSideInput<(NetworkLayer<'a, D>, TL, ApplicationLayer<'a, D>)>,
{
    const DISPATCH_TABLE: router::DispatchTable = {
        type Inner<'a, D, TL> = (NetworkLayer<'a, D>, TL, ApplicationLayer<'a, D>);
        <Inner<'_, D, TL> as LayerStack>::DISPATCH_TABLE
    };

    fn dispatch(&mut self, layer_idx: u8, msg: KnxMessageBuffer<Buffer<'static>>, outbox: &mut router::Outbox) {
        self.layers.dispatch(layer_idx, msg, outbox);
    }

    fn next_deadline(&self) -> Option<embassy_time::Instant> {
        self.layers.next_deadline()
    }

    fn poll(&mut self, outbox: &mut router::Outbox) {
        self.layers.poll(outbox);
    }

    fn init(&mut self) {
        self.layers.init();
    }

    fn recv_side_input(&self) -> impl core::future::Future<Output = ()> + '_ {
        use embassy_futures::select::{Either, select};

        async {
            match select(self.app_service_receiver.receive(), self.extra.recv()).await {
                Either::First(req) => {
                    self.pending_app_request.set(Some(req));
                }
                Either::Second(()) => {
                    // Extra side input already buffered its event internally.
                }
            }
        }
    }

    fn handle_side_input(&mut self, outbox: &mut router::Outbox) {
        if let Some(req) = self.pending_app_request.take() {
            self.layers.2.handle_app_request(&req, outbox);
        }
        self.extra.handle(&mut self.layers, outbox);
    }
}
