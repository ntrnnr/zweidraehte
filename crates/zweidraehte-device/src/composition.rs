//! Layer composition: builders, layer stacks, and constructors.
//!
//! This module contains the types that connect the protocol layers (NL, TL, AL)
//! into a composed stack and wire them to the link layer. Two built-in builders
//! are provided:
//!
//! - [`InsecureDeviceBuilder`] — standard `(NL, TL, AL)` stack
//! - [`InsecureIpDeviceBuilder`] — KNX/IP `(NL, CemiTL<TL>, AL)` stack (requires `knxip` feature)

use embassy_sync::channel::{DynamicReceiver, DynamicSender};

#[cfg(feature = "knxip")]
use crate::layers::transport::cemi::{CemiEvent, CemiTransportLayer};
use crate::{
    actor::Request,
    definition::StackDefinition,
    device_model::{self, DeviceModel as _},
    inner::StackContext,
    layers::{
        self, LinkLayerBuilder,
        application::{ApplicationLayer, ApplicationLayerService, ApplicationLayerServiceResponse},
        network::NetworkLayer,
        transport::TransportLayer,
    },
    messages::buffers::{Buffer, DynBufferManager},
    objects::comm::{ComObjectEvent, ComObjects, LifecycleEvent},
    restart,
    router::{self, LayerStack},
    storage::HasSequenceStorage,
};
use crate::bcus::system_b::{HasExtensionState, HasSeqStorage};

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
    for<'a> <D::LLB as layers::LinkLayerBuilderBase>::LLEndpoints<'a>: Default,
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

// ============================================================================
// Service inputs — events from outside the dispatch table
// ============================================================================

/// Service input events for the device layer stack.
///
/// These are events injected into the router loop from async channels,
/// outside the normal [`ServiceType`](crate::messages::knx::ServiceType)
/// dispatch table flow.
pub enum ServiceInput {
    /// Application service request from user code (group value write/read
    /// via [`Stack::update_object`](crate::Stack::update_object)).
    AppRequest(Request<ApplicationLayerService, ApplicationLayerServiceResponse>),

    /// cEMI event from a KNX/IP Device Management connection.
    #[cfg(feature = "knxip")]
    CemiEvent(CemiEvent),
}

/// Holds all service input receivers.
///
/// Optional receivers (e.g. cEMI) use `Option` and fall back to
/// `pending()` when absent, adding zero overhead for device
/// configurations that don't use them.
struct ServiceInputs<'a> {
    app_rx: DynamicReceiver<'a, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,

    #[cfg(feature = "knxip")]
    cemi_rx: Option<DynamicReceiver<'a, CemiEvent>>,
}

// ============================================================================
// InsecureDeviceLayers
// ============================================================================

/// Composable layer stack: `(NetworkLayer, TL, ApplicationLayer)` with
/// unified service inputs.
///
/// The `TL` parameter is the transport-layer-slot type:
/// - Standard devices: [`TransportLayer`]
/// - KNX/IP devices: [`CemiTransportLayer`](crate::layers::transport::cemi::CemiTransportLayer),
///   which *wraps* a `TransportLayer` and intercepts connection-oriented
///   requests when a Device Management connection is active.
///
/// # Type Aliases
///
/// - [`StandardDeviceLayers`] — `InsecureDeviceLayers<D, TransportLayer>`
/// - [`IpDeviceLayers`] — `InsecureDeviceLayers<D, CemiTransportLayer>`
///
/// # Custom Layer Stacks
///
/// For layer stacks that don't fit the `(NL, TL, AL)` pattern, implement
/// [`LayerStack`] directly on a different type and use a custom
/// [`LayerStackBuilder`].
pub struct InsecureDeviceLayers<'a, D: StackDefinition, TL: router::Layer> {
    layers: (NetworkLayer<'a, D>, TL, ApplicationLayer<'a, D>),
    device_model: device_model::SystemBDeviceModel<'a, D>,
    service_inputs: ServiceInputs<'a>,
}

/// Standard layer stack: `(NL, TL, AL)` with no cEMI service inputs.
pub type StandardDeviceLayers<'a, D> = InsecureDeviceLayers<'a, D, TransportLayer<'a, D>>;

/// KNX/IP layer stack: `(NL, CemiTL<TL>, AL)` with cEMI service inputs.
#[cfg(feature = "knxip")]
pub type IpDeviceLayers<'a, D> = InsecureDeviceLayers<'a, D, CemiTransportLayer<'a, D>>;

// ----------------------------------------------------------------------------
// Constructors
// ----------------------------------------------------------------------------

impl<'a, D: StackDefinition> InsecureDeviceLayers<'a, D, TransportLayer<'a, D>> {
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
            ctx.interface_objects,
            ctx.memory_map,
            ctx.restart_sender,
        );

        let device_model = device_model::SystemBDeviceModel::new(
            ctx.state,
            ctx.comm_objs,
            ctx.lifecycle_channel,
            ctx.interface_objects,
        );

        Self {
            layers: (network_layer, transport_layer, application_layer),
            device_model,
            service_inputs: ServiceInputs {
                app_rx: ctx.app_service_receiver,
                #[cfg(feature = "knxip")]
                cemi_rx: None,
            },
        }
    }
}

#[cfg(feature = "knxip")]
impl<'a, D: StackDefinition> InsecureDeviceLayers<'a, D, CemiTransportLayer<'a, D>> {
    /// Construct the KNX/IP `(NL, CemiTL<TL>, AL)` layer stack.
    ///
    /// The [`CemiTransportLayer`](crate::layers::transport::cemi::CemiTransportLayer)
    /// wraps a standard [`TransportLayer`] and adds cEMI Device Management
    /// support. Under normal operation, all messages delegate to the inner TL.
    /// Only when a Device Management connection activates does it lock the
    /// inner TL's incoming connections and intercept connection-oriented AL
    /// requests, routing them to the cEMI response channel.
    pub fn with_cemi(
        ctx: &'a LayerContext<'a, D>,
        channels: &'a crate::context::CemiTransportLayerChannelPair,
    ) -> Self {
        let network_layer = NetworkLayer::new(ctx.state, ctx.interface_objects);

        let transport_layer = TransportLayer::new(ctx.buffer_manager, ctx.state, D::TL_STYLE);

        let cemi_response_sender = channels.response.sender().into();
        let cemi_transport_layer = CemiTransportLayer::new(transport_layer, cemi_response_sender);

        let application_layer = ApplicationLayer::new(
            ctx.buffer_manager,
            ctx.state,
            ctx.comm_objs,
            ctx.hook_context,
            ctx.event_channel,
            ctx.interface_objects,
            ctx.memory_map,
            ctx.restart_sender,
        );

        let device_model = device_model::SystemBDeviceModel::new(
            ctx.state,
            ctx.comm_objs,
            ctx.lifecycle_channel,
            ctx.interface_objects,
        );

        let cemi_event_receiver = channels.event.receiver().into();

        Self {
            layers: (network_layer, cemi_transport_layer, application_layer),
            device_model,
            service_inputs: ServiceInputs { app_rx: ctx.app_service_receiver, cemi_rx: Some(cemi_event_receiver) },
        }
    }
}

// ----------------------------------------------------------------------------
// LayerStack impl — generic over TL, unified service inputs
// ----------------------------------------------------------------------------

impl<'a, D: StackDefinition, TL: router::Layer + HandlesCemiEvent> LayerStack for InsecureDeviceLayers<'a, D, TL> {
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
        self.device_model.init();
        self.layers.init();
    }

    type ServiceInput = ServiceInput;

    fn recv_service_input(&self) -> impl core::future::Future<Output = ServiceInput> + '_ {
        async {
            #[cfg(feature = "knxip")]
            {
                use embassy_futures::select::{Either, select};

                match select(self.service_inputs.app_rx.receive(), recv_cemi_or_pend(&self.service_inputs.cemi_rx))
                    .await
                {
                    Either::First(req) => ServiceInput::AppRequest(req),
                    Either::Second(evt) => ServiceInput::CemiEvent(evt),
                }
            }

            #[cfg(not(feature = "knxip"))]
            {
                ServiceInput::AppRequest(self.service_inputs.app_rx.receive().await)
            }
        }
    }

    fn handle_service_input(&mut self, input: ServiceInput, outbox: &mut router::Outbox) {
        match input {
            ServiceInput::AppRequest(req) => {
                self.layers.2.handle_app_request(&req, outbox);
            }
            #[cfg(feature = "knxip")]
            ServiceInput::CemiEvent(evt) => {
                self.layers.1.handle_cemi_event(evt, outbox);
            }
        }
    }

    fn drain_events(&mut self, _outbox: &mut router::Outbox) {
        self.device_model.drain_dm_events();
    }
}

// ============================================================================
// HandlesCemiEvent — trait for TL types that can process cEMI events
// ============================================================================

/// Trait for transport layer types that can handle cEMI events.
///
/// When `knxip` is enabled, this trait requires a `handle_cemi_event` method
/// that `CemiTransportLayer` and `TransportLayer` both implement.
/// When `knxip` is disabled, the trait is empty and blanket-implemented for
/// all types, so `TL: HandlesCemiEvent` is always satisfied without requiring
/// each transport layer to opt in.
#[cfg(feature = "knxip")]
pub(crate) trait HandlesCemiEvent {
    fn handle_cemi_event(&mut self, event: CemiEvent, outbox: &mut router::Outbox);
}

#[cfg(not(feature = "knxip"))]
pub(crate) trait HandlesCemiEvent {}

#[cfg(not(feature = "knxip"))]
impl<T> HandlesCemiEvent for T {}

#[cfg(feature = "knxip")]
impl<D: StackDefinition, const MI: usize, const MO: usize> HandlesCemiEvent for CemiTransportLayer<'_, D, MI, MO> {
    fn handle_cemi_event(&mut self, event: CemiEvent, outbox: &mut router::Outbox) {
        self.handle_cemi_event(event, outbox);
    }
}

#[cfg(feature = "knxip")]
impl<D: StackDefinition, const MI: usize, const MO: usize> HandlesCemiEvent for TransportLayer<'_, D, MI, MO> {
    fn handle_cemi_event(&mut self, _event: CemiEvent, _outbox: &mut router::Outbox) {
        // StandardDeviceLayers uses TransportLayer which never receives
        // cEMI events (the cemi_rx is None), so this is unreachable.
        unreachable!("TransportLayer does not handle cEMI events");
    }
}

/// Receive from an optional cEMI event channel, or pend forever if absent.
#[cfg(feature = "knxip")]
async fn recv_cemi_or_pend(rx: &Option<DynamicReceiver<'_, CemiEvent>>) -> CemiEvent {
    match rx {
        Some(rx) => rx.receive().await,
        None => core::future::pending().await,
    }
}

// ============================================================================
// Secure Device Layers
// ============================================================================

use crate::layers::secure_application::SecureApplicationLayer;

/// Layer stack with Data Secure support: `(NL, TL, SecureAL<AL>)`.
///
/// Mirrors [`InsecureDeviceLayers`] but wraps the Application Layer with
/// [`SecureApplicationLayer`] for KNX Data Secure processing.
///
/// In Phase 4a, the S-AL is a transparent pass-through — all messages
/// are forwarded to the inner AL without security processing.
pub struct SecureDeviceLayers<'a, D: StackDefinition + HasSequenceStorage, TL: router::Layer> {
    layers: (NetworkLayer<'a, D>, TL, SecureApplicationLayer<'a, D, D::SeqStorage>),
    device_model: device_model::SystemBDeviceModel<'a, D>,
    service_inputs: ServiceInputs<'a>,
}

/// Standard secure layer stack: `(NL, TL, SecureAL<AL>)`.
pub type StandardSecureDeviceLayers<'a, D> = SecureDeviceLayers<'a, D, TransportLayer<'a, D>>;

// Constructors

impl<'a, D: StackDefinition + HasSequenceStorage> SecureDeviceLayers<'a, D, TransportLayer<'a, D>>
where
    D::State: crate::bcus::system_b::HasExtensionState,
    <D::State as crate::bcus::system_b::HasExtensionState>::ES: crate::bcus::system_b::HasSeqStorage<SeqStorage = D::SeqStorage>,
{
    /// Construct the standard secure `(NL, TL, SecureAL<AL>)` layer stack.
    pub fn standard(ctx: &'a LayerContext<'a, D>) -> Self {
        let network_layer = NetworkLayer::new(ctx.state, ctx.interface_objects);
        let transport_layer = TransportLayer::new(ctx.buffer_manager, ctx.state, D::TL_STYLE);

        let application_layer = ApplicationLayer::new(
            ctx.buffer_manager,
            ctx.state,
            ctx.comm_objs,
            ctx.hook_context,
            ctx.event_channel,
            ctx.interface_objects,
            ctx.memory_map,
            ctx.restart_sender,
        );

        let seq_storage = ctx.state.extension_state().seq_storage();
        let secure_al = SecureApplicationLayer::new(application_layer, ctx.state, seq_storage);

        let device_model = device_model::SystemBDeviceModel::new(
            ctx.state,
            ctx.comm_objs,
            ctx.lifecycle_channel,
            ctx.interface_objects,
        );

        Self {
            layers: (network_layer, transport_layer, secure_al),
            device_model,
            service_inputs: ServiceInputs {
                app_rx: ctx.app_service_receiver,
                #[cfg(feature = "knxip")]
                cemi_rx: None,
            },
        }
    }
}

// LayerStack impl for SecureDeviceLayers

impl<'a, D: StackDefinition + HasSequenceStorage, TL: router::Layer + HandlesCemiEvent> LayerStack
    for SecureDeviceLayers<'a, D, TL>
where
    D::State: crate::bcus::system_b::HasExtensionState,
    <D::State as crate::bcus::system_b::HasExtensionState>::ES: crate::bcus::system_b::HasSecurityState,
{
    const DISPATCH_TABLE: router::DispatchTable = {
        type Inner<'a, D: StackDefinition + HasSequenceStorage, TL> =
            (NetworkLayer<'a, D>, TL, SecureApplicationLayer<'a, D, D::SeqStorage>);
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
        self.device_model.init();
        self.layers.init();
    }

    type ServiceInput = ServiceInput;

    fn recv_service_input(&self) -> impl core::future::Future<Output = ServiceInput> + '_ {
        async {
            #[cfg(feature = "knxip")]
            {
                use embassy_futures::select::{Either, select};
                match select(self.service_inputs.app_rx.receive(), recv_cemi_or_pend(&self.service_inputs.cemi_rx))
                    .await
                {
                    Either::First(req) => ServiceInput::AppRequest(req),
                    Either::Second(evt) => ServiceInput::CemiEvent(evt),
                }
            }

            #[cfg(not(feature = "knxip"))]
            {
                ServiceInput::AppRequest(self.service_inputs.app_rx.receive().await)
            }
        }
    }

    fn handle_service_input(&mut self, input: ServiceInput, outbox: &mut router::Outbox) {
        match input {
            ServiceInput::AppRequest(req) => {
                self.layers.2.inner_mut().handle_app_request(&req, outbox);
            }
            #[cfg(feature = "knxip")]
            ServiceInput::CemiEvent(evt) => {
                self.layers.1.handle_cemi_event(evt, outbox);
            }
        }
    }

    fn drain_events(&mut self, _outbox: &mut router::Outbox) {
        self.device_model.drain_dm_events();
    }
}

// ============================================================================
// Secure Device Builder
// ============================================================================

/// Builder for secure `(NL, TL, SecureAL<AL>)` layer stacks.
///
/// Drop-in replacement for [`InsecureDeviceBuilder`] in a device's
/// [`StackDefinition::LayerBuilder`] to enable Data Secure support.
pub struct SecureDeviceBuilder;

impl<D: StackDefinition + HasSequenceStorage> LayerStackBuilder<D> for SecureDeviceBuilder
where
    for<'a> <D::LLB as layers::LinkLayerBuilderBase>::LLEndpoints<'a>: Default,
    D::State: HasExtensionState,
    <D::State as HasExtensionState>::ES: crate::bcus::system_b::HasSecurityState + HasSeqStorage<SeqStorage = D::SeqStorage>,
{
    type Stack<'a>
        = StandardSecureDeviceLayers<'a, D>
    where
        D: 'a;
    type Channels = ();

    fn build<'a>(ctx: &'a LayerContext<'a, D>, _channels: &'a ()) -> StandardSecureDeviceLayers<'a, D>
    where
        D: 'a,
    {
        SecureDeviceLayers::standard(ctx)
    }

    fn run_link_layer<'a>(
        _channels: &'a (),
        builder: D::LLB,
        resources: &'a mut <D::LLB as layers::LinkLayerBuilderBase>::Resources,
        context: &'a crate::inner::StackContext<'a, D>,
        ind_tx: DynamicSender<'a, crate::messages::builder::IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, crate::messages::builder::ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl layers::Inbox<crate::messages::builder::RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        builder.build_and_run(resources, context, Default::default(), ind_tx, conf_tx, req_rx)
    }
}
