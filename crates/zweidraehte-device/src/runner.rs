//! KNX stack runner and factory function.
//!
//! The [`Runner`] drives the stack's async event loop. The [`new()`] factory
//! creates both a [`Stack`] handle and a `Runner` from pre-allocated resources.

use core::cell::RefCell;

use embassy_sync::{
    blocking_mutex::raw::{NoopRawMutex, RawMutex},
    channel::{Channel, DynamicReceiver, DynamicSender},
    pubsub::PubSubChannel,
};

use crate::{
    access::HasConnectionAuth,
    composition::{LayerContext, LayerStackBuilder},
    definition::StackDefinition,
    inner::{Inner, StackContext},
    layers::{
        LinkLayerBuilderBase,
        transport::TlStyle,
    },
    messages::buffers::{Buffer, BufferManager},
    objects::{
        comm::ComObjects,
        interface::{HasDeviceObject, HasRoutingCount},
        tables::{
            HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable,
        },
    },
    resources::StackResources,
    restart,
    stack_handle::Stack,
    StackState,
};

// ============================================================================
// Runner
// ============================================================================

/// KNX stack runner.
///
/// You must call [`Runner::run()`] in a background task for the KNX stack to work.
pub struct Runner<'d, D: StackDefinition> {
    pub(crate) stack: Stack<'d, D>,
    pub(crate) interface_objects: &'d D::InterfaceObjects<'static>,
    pub(crate) restart_sender: DynamicSender<'static, restart::RestartRequest>,
    pub(crate) link_layer_builder: D::LLB,
    pub(crate) link_layer_resources: &'d mut <D::LLB as LinkLayerBuilderBase>::Resources,
}

impl<'d, D: StackDefinition> Runner<'d, D> {
    /// Run the KNX stack.
    ///
    /// You must call this in a background task, to process KNX messages.
    // FIXME: Figure out how to get rid of the trait bounds here on all the tables
    //        Problem is all the process() methods in the layers require these traits
    pub async fn run(self) -> !
    where
        D::State: HasAddressTable
            + HasApplication
            + HasAssociationTable
            + HasCommunicationObjectTable
            + HasConnectionAuth
            + HasRoutingCount,
        D::InterfaceObjects<'static>: HasDeviceObject,
    {
        // Validate that outgoing connections require Style 3 (which has the
        // CONNECTING state needed for client-initiated connections).
        assert!(
            D::TL_MAX_OUTGOING == 0 || D::TL_STYLE == TlStyle::Style3,
            "TL_MAX_OUTGOING > 0 requires TlStyle::Style3 (has CONNECTING state for client connections)"
        );

        // Run state machine initialization, DeviceControl sync, and lifecycle
        // events are handled by the DeviceModel in InsecureDeviceLayers::init().

        use embassy_futures::select::{Either, select, select3};
        use embassy_time::Timer;
        use crate::messages::builder::{ConfirmationMessage, IndicationMessage, RequestMessage};
        use crate::messages::knx::ServiceType;
        use crate::router::{LayerStack, Outbox};

        // ================================================================
        // Link layer channels
        // ================================================================
        //
        // The link layer stays as a separate async task connected via three
        // channels. The router replaces the inter-layer channels (NL<->TL,
        // TL<->AL) with a synchronous dispatch table.

        let ll_req: Channel<NoopRawMutex, RequestMessage<Buffer<'static>>, 1> = Channel::new();
        let ll_ind: Channel<NoopRawMutex, IndicationMessage<Buffer<'static>>, 1> = Channel::new();
        let ll_conf: Channel<NoopRawMutex, ConfirmationMessage<Buffer<'static>>, 1> = Channel::new();

        // ================================================================
        // Shared inter-layer channels (driven by LayerStackBuilder)
        // ================================================================
        //
        // The builder decides what shared channels are needed between
        // layers and the link layer. For InsecureIpDeviceBuilder this is
        // a CemiTransportLayerChannelPair; for InsecureDeviceBuilder it's ().

        type B<D> = <D as StackDefinition>::LayerBuilder;
        type Layers<'a, D> = <B<D> as LayerStackBuilder<D>>::Stack<'a>;

        let layer_channels = <B<D> as LayerStackBuilder<D>>::Channels::default();

        // ================================================================
        // Layer construction (via LayerStackBuilder)
        // ================================================================

        // SAFETY: We are creating a static reference to the channel held by the `Inner` struct.
        // This is safe because `Inner` lives in `StackResources` which outlives this function.
        let app_service_receiver: DynamicReceiver<'static, _> = unsafe {
            core::mem::transmute::<DynamicReceiver<'_, _>, DynamicReceiver<'static, _>>(
                self.stack.inner.app_service_channel.receiver().into(),
            )
        };

        let layer_context = LayerContext {
            buffer_manager: &self.stack.inner.buffer_manager,
            state: &self.stack.inner.state,
            comm_objs: &self.stack.inner.comm_objs,
            hook_context: &self.stack.inner.hook_context,
            event_channel: &self.stack.inner.event_channel,
            lifecycle_channel: &self.stack.inner.lifecycle_channel,
            interface_objects: self.interface_objects,
            memory_map: &self.stack.inner.memory_map,
            restart_sender: self.restart_sender,
            app_service_receiver,
        };

        let mut layers = B::<D>::build(&layer_context, &layer_channels);

        // Initialize all layers (e.g., AL starts read-on-init cycle if
        // the application is already running).
        layers.init();

        // ================================================================
        // Link layer task
        // ================================================================

        let stack_context = StackContext { inner: self.stack.inner, interface_objects: self.interface_objects };
        let ll_task = B::<D>::run_link_layer(
            &layer_channels,
            self.link_layer_builder,
            self.link_layer_resources,
            &stack_context,
            ll_ind.sender().into(),
            ll_conf.sender().into(),
            ll_req.receiver(),
        );

        // ================================================================
        // Router dispatch loop
        // ================================================================
        //
        // A single async loop replaces the previous 3 concurrent layer
        // tasks. Messages flow through the synchronous dispatch table:
        //
        //   LL -> (L_Data_Ind) -> NL -> (N_*_Ind) -> TL -> (T_*_Ind) -> AL
        //   AL -> (T_*_Req)    -> TL -> (N_*_Req) -> NL -> (L_Data_Req) -> LL
        //
        // Each ServiceType maps to exactly one layer. The outbox collects
        // outputs; the drain loop re-dispatches until all messages are
        // consumed or sent to the LL.
        //
        // The router is fully generic: it only uses the `LayerStack` trait.
        // Side inputs (e.g., app service requests from user code) are
        // handled through `recv_side_input` / `handle_side_input`.

        let router_task = async {
            loop {
                let mut outbox = Outbox::new();

                let layer_deadline = layers.next_deadline();
                if layer_deadline.is_some() {
                    debug!("Router: layer_deadline is Some, will poll on timer");
                }

                // Wait for the next event: LL indication, LL confirmation,
                // layer side input, or layer timer.
                match select3(
                    ll_ind.receive(),
                    ll_conf.receive(),
                    select(layers.recv_side_input(), async {
                        match layer_deadline {
                            Some(deadline) => Timer::at(deadline).await,
                            // No deadline -> sleep forever (select will pick
                            // another branch).
                            None => core::future::pending().await,
                        }
                    }),
                )
                .await
                {
                    // LL indication -> push to outbox for dispatch
                    embassy_futures::select::Either3::First(ind) => {
                        outbox.push(ind.into_inner());
                    }
                    // LL confirmation -> push to outbox for dispatch
                    embassy_futures::select::Either3::Second(conf) => {
                        outbox.push(conf.into_inner());
                    }
                    embassy_futures::select::Either3::Third(third) => {
                        match third {
                            // Side input resolved -> let layers process it
                            Either::First(()) => {
                                layers.handle_side_input(&mut outbox);
                            }
                            // Timer expired -> poll layers with expired deadlines
                            Either::Second(_) => {
                                debug!("Router: timer expired, polling layers");
                                layers.poll(&mut outbox);
                            }
                        }
                    }
                }

                // Drain the outbox: dispatch each message through the table
                // until all messages are consumed or sent to the LL.
                while let Some(msg) = outbox.take_next() {
                    let st = msg.service_type();
                    if st == ServiceType::L_Data_Req {
                        // Terminal: send to link layer
                        ll_req.send(RequestMessage::request(msg)).await;
                    } else if let Some(layer_idx) = Layers::<'_, D>::DISPATCH_TABLE.get(st) {
                        layers.dispatch(layer_idx, msg, &mut outbox);
                    } else {
                        warn!("Router: no layer for {:?}, dropping", st);
                        // Buffer is dropped, returned to pool
                    }
                }
            }
        };

        // Run link layer and router concurrently
        embassy_futures::join::join(ll_task, router_task).await;

        unreachable!();
    }
}

// ============================================================================
// Factory function
// ============================================================================

fn create_request_response_pair<M: RawMutex, MSG, const N: usize>(
    channel: &'static Channel<M, MSG, N>,
) -> (DynamicSender<'static, MSG>, DynamicReceiver<'static, MSG>) {
    let sender: DynamicSender<'_, MSG> = channel.sender().into();
    let receiver: DynamicReceiver<'_, MSG> = channel.receiver().into();
    (sender, receiver)
}

/// Create a new KNX stack.
///
/// The `state` parameter contains the unified device state including:
/// - Individual address, authentication keys, and other runtime configuration
/// - ETS-loaded tables (ADT, AST, COT, APP)
///
/// Use the device state constructor or storage to create it:
/// - `SystemBDeviceState::new(storage.identity())` for fresh state
/// - `storage.load()` to restore from persistent storage
///
/// The `memory_map` parameter defines how memory addresses are mapped to tables
/// for A_Memory_Read/Write services. It must be configured with the same table
/// sizes as used for the device's tables (ADT, AST, COT sizes). Use
/// `SystemBMemoryMap::for_device()` with your device's MAX_ADDRESSES, MAX_ASSOCIATIONS,
/// etc. constants to create a properly configured memory map.
pub fn new<'d, D: StackDefinition + Copy, const BUF_SZ: usize, const NUM_BUFS: usize>(
    resources: &'d mut StackResources<D, BUF_SZ, NUM_BUFS>,
    comm_objs: D::CO,
    hook_context: <D::CO as ComObjects>::HookContext,
    link_layer_builder: D::LLB,
    state: D::State,
    memory_map: D::Mem,
) -> (Stack<'d, D>, Runner<'d, D>) {
    // Validate that runtime max_apdu_length doesn't exceed compile-time buffer allocation
    let runtime_max_apdu = state.max_apdu_length();
    assert!(
        runtime_max_apdu <= D::MAX_APDU_LENGTH,
        "StackState::max_apdu_length() ({}) exceeds StackDefinition::MAX_APDU_LENGTH ({}). \
         The runtime limit must not exceed the compile-time buffer allocation.",
        runtime_max_apdu,
        D::MAX_APDU_LENGTH
    );

    // SAFETY: We are creating a reference to the buffers that are stored in the `StackResources` struct,
    //         which lives at least as long as `Inner`
    let buffers = resources.buffers.write([[0; _]; _]);
    let buffer_manager: &'static mut BufferManager<NUM_BUFS> =
        unsafe { core::mem::transmute(resources.buffer_manager.write(BufferManager::new(buffers))) };

    let inner = Inner {
        buffer_manager: buffer_manager.dyn_buffer_manager(),
        app_service_channel: Channel::new(),
        comm_objs: RefCell::new(comm_objs),
        event_channel: PubSubChannel::new(),
        lifecycle_channel: PubSubChannel::new(),
        restart_channel: Channel::new(),
        state,
        hook_context,
        memory_map,
    };

    let inner = &*resources.inner.write(inner);

    // Build interface objects with reference to the state stored in Inner.
    // SAFETY: Inner is now stable in memory (written to StackResources), so we can safely
    //         transmute the state reference to 'static lifetime. The actual lifetime is 'd
    //         but the interface objects container needs 'static for its type parameter.
    let interface_objects = {
        let state_ref: &'static D::State = unsafe { core::mem::transmute(&inner.state) };
        D::create_interface_objects(state_ref)
    };
    let interface_objects = &*resources.interface_objects.write(interface_objects);

    // SAFETY: We are creating a static reference to the channel held by the `Inner` struct,
    //         which is safe because it is guaranteed to live as long as the `Stack` or the `Runner`.
    let app_request_sender: DynamicSender<'static, _> = unsafe {
        core::mem::transmute::<DynamicSender<'_, _>, DynamicSender<'static, _>>(
            inner.app_service_channel.sender().into(),
        )
    };

    // Create restart channel sender/receiver pair.
    // The sender goes to the Runner (passed to ApplicationLayer), receiver goes to Stack (for user code).
    let (restart_sender, restart_receiver) =
        create_request_response_pair::<D::Mutex, _, 1>(unsafe { core::mem::transmute(&inner.restart_channel) });

    // Initialize link layer resources using the builder
    let link_layer_resources = resources.link_layer_resources.write(link_layer_builder.create_resources());

    let stack = Stack { inner, interface_objects, app_request_sender, restart_receiver };
    let runner = Runner { stack, interface_objects, restart_sender, link_layer_builder, link_layer_resources };

    (stack, runner)
}
