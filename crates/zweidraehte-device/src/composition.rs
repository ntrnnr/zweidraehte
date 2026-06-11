//! Layer composition: builders, layer stacks, and constructors.
//!
//! This module contains the types that connect the protocol layers (NL, TL, AL)
//! into a composed stack and wire them to the link layer. Two built-in builders
//! are provided:
//!
//! - [`InsecureDeviceBuilder`] — standard `(NL, TL, AL)` stack
//! - [`InsecureIpDeviceBuilder`] — KNX/IP `(NL, CemiTL<TL>, AL)` stack (requires `knxip` feature)

use embassy_sync::channel::{DynamicReceiver, DynamicSender};

use crate::bcus::system_b::{HasSecurityState, HasSeqStorage};
#[cfg(feature = "knxip")]
use crate::layers::transport::cemi::{
    CemiEvent, CemiTransportLayer, CemiTransportLayerChannelPair, CemiTransportLayerEndpoints,
};
use crate::rng::SecureRng;
use crate::service::{Layer, LayerRegistry};
use crate::storage::SecureDeviceIdentity;
use crate::{HasExtensionState, StackState};
use crate::{
    actor::Request,
    context::StackContext,
    definition::StackDefinition,
    device_model,
    layers::{
        self, LinkLayerBuilder,
        application::{ApplicationLayer, ApplicationLayerService, ApplicationLayerServiceResponse},
        network::NetworkLayer,
        secure_application::{NoP2p, P2pFeature, SecureApplicationLayer},
        transport::TransportLayer,
    },
    objects::tables::{HasAddressTable, HasAssociationTable},
    storage::{HasSequenceStorage, SequenceNumberStorage},
};

use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::builder::{ConfirmationMessage, IndicationMessage, RequestMessage};

// ============================================================================
// Link-layer channel type aliases
// ============================================================================
//
// The three channel ends handed to `run_link_layer` are spelled out identically
// in the trait definition and in every impl. Centralising them here avoids the
// repetition and keeps the parameter list readable.

/// Sender end of the indication channel into the router task.
pub type LlIndicationSender<'a> = DynamicSender<'a, IndicationMessage<Buffer<'static>>>;

/// Sender end of the confirmation channel into the router task.
pub type LlConfirmationSender<'a> = DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>;

// The request-receiver end (`req_rx`) uses `impl layers::Inbox<…> + 'a` directly
// in each method signature. A type alias for that would require `type_alias_impl_trait`,
// which is not yet stabilised, so it stays spelled out at each call site.

// ============================================================================
// Layer stack builders
// ============================================================================

/// Builder for constructing a layer stack and running its link layer.
///
/// Encapsulates channel creation, layer construction, and link-layer
/// endpoint wiring. Each builder knows:
///
/// - What shared channels are needed between layers and the link layer
/// - How to build the layer stack from a [`StackContext`]
/// - How to extract link-layer endpoints and start the link layer
///
/// Two built-in builders are provided:
/// - [`InsecureDeviceBuilder`] — standard `(NL, TL, AL)` stack, no extra channels
/// - [`InsecureIpDeviceBuilder`] — `(NL, CemiTL<TL>, AL)` stack with cEMI channels
pub trait LayerStackBuilder<D: StackDefinition>: Sized {
    /// Composed layer stack produced by [`build`](Self::build).
    type Stack<'a>: LayerRegistry<D>
    where
        D: 'a;

    /// Owned channel storage shared between the layer stack and the link
    /// layer. Created as a stack-local in [`Runner::run()`](crate::Runner::run) before layer
    /// construction, so both the router task and the LL task can borrow
    /// from it.
    ///
    /// `()` when no extra channels are needed (standard TP1 devices).
    type Channels: Default + 'static;

    /// Build the layer stack from a [`StackContext`] and the shared channels.
    fn build<'a>(ctx: &'a StackContext<'a, D>, channels: &'a Self::Channels) -> Self::Stack<'a>
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
        ind_tx: LlIndicationSender<'a>,
        conf_tx: LlConfirmationSender<'a>,
        req_rx: impl layers::Inbox<RequestMessage<Buffer<'static>>> + 'a,
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

    fn build<'a>(ctx: &'a StackContext<'a, D>, _channels: &'a ()) -> StandardDeviceLayers<'a, D>
    where
        D: 'a,
    {
        StandardLayerStack::standard(ctx)
    }

    fn run_link_layer<'a>(
        _channels: &'a (),
        builder: D::LLB,
        resources: &'a mut <D::LLB as layers::LinkLayerBuilderBase>::Resources,
        context: &'a StackContext<'a, D>,
        ind_tx: LlIndicationSender<'a>,
        conf_tx: LlConfirmationSender<'a>,
        req_rx: impl layers::Inbox<RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        builder.build_and_run(resources, context, Default::default(), ind_tx, conf_tx, req_rx)
    }
}

/// Builder for KNX/IP `(NL, CemiTL<TL>, AL)` layer stacks.
///
/// Produces [`IpDeviceLayers`] with a [`CemiTransportLayerChannelPair`](crate::layers::transport::cemi::CemiTransportLayerChannelPair)
/// for Device Management connections. The link layer builder's
/// [`LLEndpoints`](layers::LinkLayerBuilderBase::LLEndpoints) must be
/// [`CemiTransportLayerEndpoints`](crate::layers::transport::cemi::CemiTransportLayerEndpoints).
#[cfg(feature = "knxip")]
pub struct InsecureIpDeviceBuilder;

#[cfg(feature = "knxip")]
impl<D: StackDefinition> LayerStackBuilder<D> for InsecureIpDeviceBuilder
where
    D::LLB: for<'a> layers::LinkLayerBuilder<StackContext<'a, D>, LLEndpoints<'a> = CemiTransportLayerEndpoints<'a>>,
{
    type Stack<'a>
        = IpDeviceLayers<'a, D>
    where
        D: 'a;
    type Channels = CemiTransportLayerChannelPair;

    fn build<'a>(ctx: &'a StackContext<'a, D>, channels: &'a CemiTransportLayerChannelPair) -> IpDeviceLayers<'a, D>
    where
        D: 'a,
    {
        IpLayerStack::with_cemi(ctx, channels)
    }

    fn run_link_layer<'a>(
        channels: &'a CemiTransportLayerChannelPair,
        builder: D::LLB,
        resources: &'a mut <D::LLB as layers::LinkLayerBuilderBase>::Resources,
        context: &'a StackContext<'a, D>,
        ind_tx: LlIndicationSender<'a>,
        conf_tx: LlConfirmationSender<'a>,
        req_rx: impl layers::Inbox<RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        builder.build_and_run(resources, context, channels.ll_endpoints(), ind_tx, conf_tx, req_rx)
    }
}

// ============================================================================
// HasAppRequest — trait for AL types that handle application service requests
// ============================================================================

/// Application layer types that can handle service requests from user code.
///
/// Both [`ApplicationLayer`] and [`SecureApplicationLayer`] implement this.
/// Used as a bound on the `AL` parameter of layer stacks so that
/// `handle_service_input` can dispatch to the correct layer.
pub trait HasAppRequest {
    fn handle_app_request(&mut self, request: &Request<ApplicationLayerService, ApplicationLayerServiceResponse>);
}

impl<D: StackDefinition> HasAppRequest for ApplicationLayer<'_, D> {
    fn handle_app_request(&mut self, request: &Request<ApplicationLayerService, ApplicationLayerServiceResponse>) {
        self.handle_app_request(request);
    }
}

impl<D: StackDefinition, SEQ: SequenceNumberStorage, P2P: P2pFeature> HasAppRequest
    for SecureApplicationLayer<'_, D, SEQ, P2P>
where
    D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as StackState>::Identity: SecureDeviceIdentity,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    fn handle_app_request(&mut self, request: &Request<ApplicationLayerService, ApplicationLayerServiceResponse>) {
        // Call the inherent method explicitly so method resolution can't
        // fall back to this trait method and recurse infinitely.
        SecureApplicationLayer::handle_app_request(self, request);
    }
}

// ============================================================================
// Standard Layer Stack — (NL, TL, AL)
// ============================================================================

/// Standard, composed layer stack: `(NetworkLayer, TransportLayer, AL)`.
///
/// Generic over the application layer slot (`AL`), supporting both
/// [`ApplicationLayer`] and [`SecureApplicationLayer`].
///
/// `LayerRegistry<D>` is generated by `#[derive(ServiceRegistry)]`:
/// `nl`, `tl`, and `al` are `#[service(handler)]` slots that
/// participate in dispatch / init / poll / deadline aggregation;
/// `device_model` is a `#[service(lifecycle)]` field whose
/// `LifecycleHook<D>` impl drives `init_layers` and `drain_events`;
/// `app_rx` is a `#[service(channel)]` field whose dispatch closure
/// forwards `Request<...>` to `al.handle_app_request`.
#[derive(crate::service::ServiceRegistry)]
pub struct StandardLayerStack<'a, D, AL>
where
    D: StackDefinition,
    AL: Layer<D> + HasAppRequest,
{
    #[service(handler)]
    nl: NetworkLayer<'a, D>,

    #[service(handler)]
    tl: TransportLayer<'a, D>,

    #[service(handler)]
    al: AL,

    // TODO: `SystemBDeviceModel` is hardcoded here, coupling this generic layer
    // stack to the System B BCU. A future pass should parameterise the device
    // model type on `StackDefinition` (or derive it from a trait bound) so
    // non-System-B BCUs can compose their own lifecycle hook without forking
    // `StandardLayerStack`.
    #[service(lifecycle)]
    device_model: device_model::SystemBDeviceModel<'a, D>,

    #[service(channel(dispatch = |stack, req| {
        stack.al.handle_app_request(&req);
    }))]
    app_rx: DynamicReceiver<'a, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
}

/// Standard layer stack: `(NL, TL, AL)`.
pub type StandardDeviceLayers<'a, D> = StandardLayerStack<'a, D, ApplicationLayer<'a, D>>;

/// Standard secure layer stack: `(NL, TL, SecureAL<AL>)`.
///
/// `P2P` selects the P2P feature variant. Defaults to
/// [`NoP2p`](NoP2p) so group-only
/// devices don't pay for SIAT-driven sync code. Use
/// [`WithP2p`](crate::layers::secure_application::WithP2p) for
/// devices that need S-A_Sync.
pub type StandardSecureDeviceLayers<'a, D, P2P = NoP2p> =
    StandardLayerStack<'a, D, SecureApplicationLayer<'a, D, <D as HasSequenceStorage>::SeqStorage, P2P>>;

impl<'a, D: StackDefinition> StandardLayerStack<'a, D, ApplicationLayer<'a, D>> {
    /// Construct the standard `(NL, TL, AL)` layer stack.
    pub fn standard(ctx: &'a StackContext<'a, D>) -> Self {
        // TODO: Use `{ D::TL_MAX_INCOMING }` and `{ D::TL_MAX_OUTGOING }` as const
        // generics here once `generic_const_exprs` no longer overflows for trait
        // consts forwarded through where-clauses.
        //
        // Until then, non-default values of TL_MAX_INCOMING / TL_MAX_OUTGOING are
        // silently ignored. The asserts below catch an accidental override at
        // runtime; a custom LayerStackBuilder is required to honour them.
        debug_assert_eq!(
            D::TL_MAX_INCOMING,
            1,
            "TL_MAX_INCOMING override has no effect with InsecureDeviceBuilder; \
             write a custom LayerStackBuilder that passes the const to TransportLayer::new"
        );
        debug_assert_eq!(
            D::TL_MAX_OUTGOING,
            0,
            "TL_MAX_OUTGOING override has no effect with InsecureDeviceBuilder; \
             write a custom LayerStackBuilder that passes the const to TransportLayer::new"
        );
        let nl = NetworkLayer::new(ctx);
        let tl = TransportLayer::new(ctx);
        let al = ApplicationLayer::new(ctx);

        let device_model = device_model::SystemBDeviceModel::new(
            ctx.state(),
            &ctx.layer_context().lifecycle_channel,
            ctx.interface_objects(),
        );

        Self { nl, tl, al, device_model, app_rx: ctx.layer_context().app_service_channel.receiver().into() }
    }
}

impl<'a, D: StackDefinition + HasSequenceStorage, P2P: P2pFeature>
    StandardLayerStack<'a, D, SecureApplicationLayer<'a, D, D::SeqStorage, P2P>>
where
    D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as StackState>::Identity: SecureDeviceIdentity,
    <D::State as HasExtensionState>::ES:
        HasSecurityState + HasSeqStorage<SeqStorage = <D as HasSequenceStorage>::SeqStorage>,
{
    /// Construct the standard secure `(NL, TL, SecureAL<AL>)` layer stack.
    pub fn standard_secure(ctx: &'a StackContext<'a, D>) -> Self {
        debug_assert_eq!(
            D::TL_MAX_INCOMING,
            1,
            "TL_MAX_INCOMING override has no effect with SecureDeviceBuilder; \
             write a custom LayerStackBuilder that passes the const to TransportLayer::new"
        );
        debug_assert_eq!(
            D::TL_MAX_OUTGOING,
            0,
            "TL_MAX_OUTGOING override has no effect with SecureDeviceBuilder; \
             write a custom LayerStackBuilder that passes the const to TransportLayer::new"
        );
        let nl = NetworkLayer::new(ctx);
        let tl = TransportLayer::new(ctx);
        let application_layer = ApplicationLayer::new(ctx);

        let seq_storage = ctx.state().extension_state().seq_storage();
        let al = SecureApplicationLayer::new(application_layer, seq_storage);

        let device_model = device_model::SystemBDeviceModel::new(
            ctx.state(),
            &ctx.layer_context().lifecycle_channel,
            ctx.interface_objects(),
        );

        Self { nl, tl, al, device_model, app_rx: ctx.layer_context().app_service_channel.receiver().into() }
    }
}

// ============================================================================
// Secure Device Builder
// ============================================================================

/// Builder for secure `(NL, TL, SecureAL<AL>)` layer stacks.
///
/// Drop-in replacement for [`InsecureDeviceBuilder`] in a device's
/// [`StackDefinition::LayerBuilder`] to enable Data Secure support.
///
/// The `P2P` type parameter selects KNX Data Secure P2P support:
/// - [`NoP2p`](NoP2p) (default):
///   omit SIAT-driven S-A_Sync code. Appropriate for group-only
///   devices that only need tool-key commissioning + group keys.
/// - [`WithP2p`](crate::layers::secure_application::WithP2p):
///   compile in the full S-A_Sync protocol.
///
/// Use via `type LayerBuilder = SecureDeviceBuilder<WithP2p>` in a
/// device's [`StackDefinition`] impl.
pub struct SecureDeviceBuilder<P2P: P2pFeature = NoP2p> {
    _phantom: core::marker::PhantomData<P2P>,
}

impl<D: StackDefinition + HasSequenceStorage, P2P: P2pFeature> LayerStackBuilder<D> for SecureDeviceBuilder<P2P>
where
    for<'a> <D::LLB as layers::LinkLayerBuilderBase>::LLEndpoints<'a>: Default,
    D::State: HasExtensionState,
    <D::State as StackState>::Identity: SecureDeviceIdentity,
    <D::State as HasExtensionState>::ES:
        HasSecurityState + HasSeqStorage<SeqStorage = <D as HasSequenceStorage>::SeqStorage>,
    // Forbid `NoRng` on secure stacks. Without this, forgetting to
    // set `type Rng = …` would still compile (the default is
    // `NoRng`) and the first `S-A_Sync` would panic at runtime. The
    // `SecureRng` marker is implemented by every real RNG but not
    // by `NoRng`, so this turns the misconfiguration into a
    // compile-time error at secure-stack assembly.
    D::Rng: SecureRng,
{
    type Stack<'a>
        = StandardSecureDeviceLayers<'a, D, P2P>
    where
        D: 'a;
    type Channels = ();

    fn build<'a>(ctx: &'a StackContext<'a, D>, _channels: &'a ()) -> StandardSecureDeviceLayers<'a, D, P2P>
    where
        D: 'a,
    {
        StandardLayerStack::standard_secure(ctx)
    }

    fn run_link_layer<'a>(
        _channels: &'a (),
        builder: D::LLB,
        resources: &'a mut <D::LLB as layers::LinkLayerBuilderBase>::Resources,
        context: &'a StackContext<'a, D>,
        ind_tx: LlIndicationSender<'a>,
        conf_tx: LlConfirmationSender<'a>,
        req_rx: impl layers::Inbox<RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        builder.build_and_run(resources, context, Default::default(), ind_tx, conf_tx, req_rx)
    }
}

// ============================================================================
// IP Layer Stack — (NL, CemiTL<TL>, AL)
// ============================================================================

/// IP layer stack: `(NL, CemiTL<TL>, AL)` plus a cEMI event channel.
///
/// Same shape as [`StandardLayerStack`] except (1) the TL slot is
/// [`CemiTransportLayer`] instead of [`TransportLayer`] (so KNX/IP
/// device-management connections see the cEMI framing layer they
/// expect), and (2) a second `#[service(channel)]` field
/// (`cemi_rx`) routes cEMI events from the link-layer task into
/// the cEMI TL via `handle_cemi_event`.
///
/// The two-channel `recv_service_input` `select` is generated by
/// `#[derive(ServiceRegistry)]` from the field declarations.
#[cfg(feature = "knxip")]
#[derive(crate::service::ServiceRegistry)]
pub struct IpLayerStack<'a, D, AL>
where
    D: StackDefinition,
    AL: Layer<D> + HasAppRequest,
{
    #[service(handler)]
    nl: NetworkLayer<'a, D>,

    #[service(handler)]
    tl: CemiTransportLayer<'a, D>,

    #[service(handler)]
    al: AL,

    // TODO: same `SystemBDeviceModel` coupling as in `StandardLayerStack` above.
    #[service(lifecycle)]
    device_model: device_model::SystemBDeviceModel<'a, D>,

    #[service(channel(dispatch = |stack, req| {
        stack.al.handle_app_request(&req);
    }))]
    app_rx: DynamicReceiver<'a, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,

    #[service(channel(dispatch = |stack, evt| {
        stack.tl.handle_cemi_event(evt);
    }))]
    cemi_rx: DynamicReceiver<'a, CemiEvent>,
}

#[cfg(feature = "knxip")]
pub type IpDeviceLayers<'a, D> = IpLayerStack<'a, D, ApplicationLayer<'a, D>>;

#[cfg(feature = "knxip")]
impl<'a, D: StackDefinition> IpLayerStack<'a, D, ApplicationLayer<'a, D>> {
    pub fn with_cemi(ctx: &'a StackContext<'a, D>, channels: &'a CemiTransportLayerChannelPair) -> Self {
        debug_assert_eq!(
            D::TL_MAX_INCOMING,
            1,
            "TL_MAX_INCOMING override has no effect with InsecureIpDeviceBuilder; \
             write a custom LayerStackBuilder that passes the const to TransportLayer::new"
        );
        debug_assert_eq!(
            D::TL_MAX_OUTGOING,
            0,
            "TL_MAX_OUTGOING override has no effect with InsecureIpDeviceBuilder; \
             write a custom LayerStackBuilder that passes the const to TransportLayer::new"
        );
        let nl = NetworkLayer::new(ctx);
        let transport_layer = TransportLayer::new(ctx);

        let cemi_response_sender = channels.response.sender().into();
        let tl = CemiTransportLayer::new(transport_layer, ctx.layer_context(), cemi_response_sender);

        let al = ApplicationLayer::new(ctx);

        let device_model = device_model::SystemBDeviceModel::new(
            ctx.state(),
            &ctx.layer_context().lifecycle_channel,
            ctx.interface_objects(),
        );

        let cemi_event_receiver = channels.event.receiver().into();

        Self {
            nl,
            tl,
            al,
            device_model,
            app_rx: ctx.layer_context().app_service_channel.receiver().into(),
            cemi_rx: cemi_event_receiver,
        }
    }
}
