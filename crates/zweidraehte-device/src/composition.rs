//! Layer composition: builders, layer stacks, and constructors.
//!
//! This module contains the types that connect the protocol layers (NL, TL, AL)
//! into a composed stack and wire them to the link layer. Two built-in builders
//! are provided:
//!
//! - [`InsecureDeviceBuilder`] — standard `(NL, TL, AL)` stack
//! - [`InsecureIpDeviceBuilder`] — KNX/IP `(NL, CemiTL<TL>, AL)` stack (requires `knxip` feature)

use embassy_sync::channel::{DynamicReceiver, DynamicSender};

use crate::HasSecureIdentity;
use crate::bcus::system_b::{HasExtensionState, HasSecurityState, HasSeqStorage};
#[cfg(feature = "knxip")]
use crate::layers::transport::cemi::{CemiEvent, CemiTransportLayer};
use crate::{
    actor::Request,
    definition::StackDefinition,
    device_model::{self, DeviceModel as _},
    inner::StackContext,
    layer_context::HasLayerContext,
    layers::{
        self, LinkLayerBuilder,
        application::{ApplicationLayer, ApplicationLayerService, ApplicationLayerServiceResponse},
        network::NetworkLayer,
        transport::TransportLayer,
    },
    messages::buffers::Buffer,
    restart,
    router::{self, LayerStack},
    storage::HasSequenceStorage,
};

use crate::messages::knx::KnxMessageBuffer;

// ============================================================================
// LayerBuildContext
// ============================================================================

/// Context passed to [`LayerStackBuilder::build`] for constructing the
/// layer stack.
///
/// Channels and buffer management are accessible through
/// `state.layer_context()`. This struct provides the remaining
/// resources that can't be reached through the state.
pub struct LayerBuildContext<'a, D: StackDefinition> {
    /// Unified device state (tables + runtime configuration).
    /// Also provides access to [`LayerContext`](crate::layer_context::LayerContext)
    /// via [`HasLayerContext`](crate::layer_context::HasLayerContext).
    pub state: &'a D::State,
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
/// - How to build the layer stack from a [`LayerBuildContext`]
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

    /// Build the layer stack from a [`LayerBuildContext`] and the shared channels.
    fn build<'a>(ctx: &'a LayerBuildContext<'a, D>, channels: &'a Self::Channels) -> Self::Stack<'a>
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

    fn build<'a>(ctx: &'a LayerBuildContext<'a, D>, _channels: &'a ()) -> StandardDeviceLayers<'a, D>
    where
        D: 'a,
    {
        DeviceLayerStack::standard(ctx)
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
        ctx: &'a LayerBuildContext<'a, D>,
        channels: &'a crate::context::CemiTransportLayerChannelPair,
    ) -> IpDeviceLayers<'a, D>
    where
        D: 'a,
    {
        DeviceLayerStack::with_cemi(ctx, channels)
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
// HasAppRequest — trait for AL types that handle application service requests
// ============================================================================

/// Application layer types that can handle service requests from user code.
///
/// Both [`ApplicationLayer`] and [`SecureApplicationLayer`] implement this.
/// Used as a bound on the `AL` parameter of [`DeviceLayerStack`] so that
/// `handle_service_input` can dispatch to the correct layer.
pub trait HasAppRequest {
    fn handle_app_request(&mut self, request: &Request<ApplicationLayerService, ApplicationLayerServiceResponse>);
}

impl<D: StackDefinition> HasAppRequest for ApplicationLayer<'_, D> {
    fn handle_app_request(&mut self, request: &Request<ApplicationLayerService, ApplicationLayerServiceResponse>) {
        self.handle_app_request(request);
    }
}

use crate::layers::secure_application::SecureApplicationLayer;
use crate::objects::tables::{HasAddressTable, HasAssociationTable};
use crate::storage::SequenceNumberStorage;

impl<D: StackDefinition, SEQ: SequenceNumberStorage> HasAppRequest for SecureApplicationLayer<'_, D, SEQ>
where
    D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    fn handle_app_request(&mut self, request: &Request<ApplicationLayerService, ApplicationLayerServiceResponse>) {
        self.handle_app_request(request);
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
    fn handle_cemi_event(&mut self, event: CemiEvent);
}

#[cfg(not(feature = "knxip"))]
pub(crate) trait HandlesCemiEvent {}

#[cfg(not(feature = "knxip"))]
impl<T> HandlesCemiEvent for T {}

#[cfg(feature = "knxip")]
impl<D: StackDefinition, const MI: usize, const MO: usize> HandlesCemiEvent for CemiTransportLayer<'_, D, MI, MO> {
    fn handle_cemi_event(&mut self, event: CemiEvent) {
        self.handle_cemi_event(event);
    }
}

#[cfg(feature = "knxip")]
impl<D: StackDefinition, const MI: usize, const MO: usize> HandlesCemiEvent for TransportLayer<'_, D, MI, MO> {
    fn handle_cemi_event(&mut self, _event: CemiEvent) {
        // Standard device stacks use TransportLayer which never receives
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
// DeviceLayerStack — unified (NL, TL, AL) composition
// ============================================================================

/// Composed layer stack: `(NetworkLayer, TL, AL)` with unified service inputs
/// and device model lifecycle.
///
/// Generic over both the transport layer slot (`TL`) and the application
/// layer slot (`AL`), replacing the former `InsecureDeviceLayers` and
/// `SecureDeviceLayers` with a single type.
///
/// - `TL`: [`TransportLayer`] for standard devices,
///   [`CemiTransportLayer`](crate::layers::transport::cemi::CemiTransportLayer)
///   for KNX/IP devices.
/// - `AL`: [`ApplicationLayer`] for standard devices,
///   [`SecureApplicationLayer`] for Data Secure devices.
///
/// # Type Aliases
///
/// - [`StandardDeviceLayers`] — `DeviceLayerStack<D, TransportLayer, ApplicationLayer>`
/// - [`StandardSecureDeviceLayers`] — `DeviceLayerStack<D, TransportLayer, SecureApplicationLayer>`
/// - [`IpDeviceLayers`] — `DeviceLayerStack<D, CemiTransportLayer, ApplicationLayer>`
///
/// # Custom Layer Stacks
///
/// For layer stacks that don't fit the `(NL, TL, AL)` pattern, implement
/// [`LayerStack`] directly on a different type and use a custom
/// [`LayerStackBuilder`].
pub struct DeviceLayerStack<'a, D: StackDefinition, TL: router::Layer, AL: router::Layer + HasAppRequest> {
    layers: (NetworkLayer<'a, D>, TL, AL),
    device_model: device_model::SystemBDeviceModel<'a, D>,
    service_inputs: ServiceInputs<'a>,
}

/// Standard layer stack: `(NL, TL, AL)`.
pub type StandardDeviceLayers<'a, D> = DeviceLayerStack<'a, D, TransportLayer<'a, D>, ApplicationLayer<'a, D>>;

/// Standard secure layer stack: `(NL, TL, SecureAL<AL>)`.
pub type StandardSecureDeviceLayers<'a, D> = DeviceLayerStack<
    'a,
    D,
    TransportLayer<'a, D>,
    SecureApplicationLayer<'a, D, <D as HasSequenceStorage>::SeqStorage>,
>;

/// KNX/IP layer stack: `(NL, CemiTL<TL>, AL)`.
#[cfg(feature = "knxip")]
pub type IpDeviceLayers<'a, D> = DeviceLayerStack<'a, D, CemiTransportLayer<'a, D>, ApplicationLayer<'a, D>>;

// Backward-compatible type aliases — these will be removed in a future cleanup.
// Intentionally not documented.
pub type InsecureDeviceLayers<'a, D, TL> = DeviceLayerStack<'a, D, TL, ApplicationLayer<'a, D>>;

// ----------------------------------------------------------------------------
// Constructors
// ----------------------------------------------------------------------------

impl<'a, D: StackDefinition> DeviceLayerStack<'a, D, TransportLayer<'a, D>, ApplicationLayer<'a, D>> {
    /// Construct the standard `(NL, TL, AL)` layer stack.
    pub fn standard(ctx: &'a LayerBuildContext<'a, D>) -> Self {
        // TODO: Use `{ D::TL_MAX_INCOMING }` and `{ D::TL_MAX_OUTGOING }` as const
        // generics here once `generic_const_exprs` no longer overflows for trait
        // consts forwarded through where-clauses.
        let network_layer = NetworkLayer::new(ctx);
        let transport_layer = TransportLayer::new(ctx);
        let application_layer = ApplicationLayer::new(ctx);

        let device_model = device_model::SystemBDeviceModel::new(
            ctx.state,
            &ctx.state.layer_context().lifecycle_channel,
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
impl<'a, D: StackDefinition> DeviceLayerStack<'a, D, CemiTransportLayer<'a, D>, ApplicationLayer<'a, D>> {
    /// Construct the KNX/IP `(NL, CemiTL<TL>, AL)` layer stack.
    pub fn with_cemi(
        ctx: &'a LayerBuildContext<'a, D>,
        channels: &'a crate::context::CemiTransportLayerChannelPair,
    ) -> Self {
        let network_layer = NetworkLayer::new(ctx);
        let transport_layer = TransportLayer::new(ctx);

        let cemi_response_sender = channels.response.sender().into();
        let cemi_transport_layer = CemiTransportLayer::new(transport_layer, cemi_response_sender);

        let application_layer = ApplicationLayer::new(ctx);

        let device_model = device_model::SystemBDeviceModel::new(
            ctx.state,
            &ctx.state.layer_context().lifecycle_channel,
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

impl<'a, D: StackDefinition + HasSequenceStorage>
    DeviceLayerStack<'a, D, TransportLayer<'a, D>, SecureApplicationLayer<'a, D, D::SeqStorage>>
where
    D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as HasExtensionState>::ES: HasSecurityState + HasSeqStorage<SeqStorage = D::SeqStorage>,
{
    /// Construct the standard secure `(NL, TL, SecureAL<AL>)` layer stack.
    pub fn standard_secure(ctx: &'a LayerBuildContext<'a, D>) -> Self {
        let network_layer = NetworkLayer::new(ctx);
        let transport_layer = TransportLayer::new(ctx);
        let application_layer = ApplicationLayer::new(ctx);

        let seq_storage = ctx.state.extension_state().seq_storage();
        let secure_al = SecureApplicationLayer::new(application_layer, ctx.state, seq_storage);

        let device_model = device_model::SystemBDeviceModel::new(
            ctx.state,
            &ctx.state.layer_context().lifecycle_channel,
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

// ----------------------------------------------------------------------------
// LayerStack impl — single implementation for all DeviceLayerStack variants
// ----------------------------------------------------------------------------

impl<'a, D: StackDefinition, TL: router::Layer + HandlesCemiEvent, AL: router::Layer + HasAppRequest> LayerStack
    for DeviceLayerStack<'a, D, TL, AL>
{
    const DISPATCH_TABLE: router::DispatchTable = {
        type Layers<'a, D, TL, AL> = (NetworkLayer<'a, D>, TL, AL);
        <Layers<'_, D, TL, AL> as LayerStack>::DISPATCH_TABLE
    };

    fn dispatch(&mut self, layer_idx: u8, msg: KnxMessageBuffer<Buffer<'static>>) {
        self.layers.dispatch(layer_idx, msg);
    }

    fn next_deadline(&self) -> Option<embassy_time::Instant> {
        self.layers.next_deadline()
    }

    fn poll(&mut self) {
        self.layers.poll();
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

    fn handle_service_input(&mut self, input: ServiceInput) {
        match input {
            ServiceInput::AppRequest(req) => {
                self.layers.2.handle_app_request(&req);
            }
            #[cfg(feature = "knxip")]
            ServiceInput::CemiEvent(evt) => {
                self.layers.1.handle_cemi_event(evt);
            }
        }
    }

    fn drain_events(&mut self) {
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
    D::State: HasSecureIdentity + HasExtensionState,
    <D::State as HasExtensionState>::ES: HasSecurityState + HasSeqStorage<SeqStorage = D::SeqStorage>,
{
    type Stack<'a>
        = StandardSecureDeviceLayers<'a, D>
    where
        D: 'a;
    type Channels = ();

    fn build<'a>(ctx: &'a LayerBuildContext<'a, D>, _channels: &'a ()) -> StandardSecureDeviceLayers<'a, D>
    where
        D: 'a,
    {
        DeviceLayerStack::standard_secure(ctx)
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
