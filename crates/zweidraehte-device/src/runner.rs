//! KNX stack runner and factory function.
//!
//! The [`Runner`] drives the stack's async event loop. The [`new()`] factory
//! creates both a [`Stack`] handle and a `Runner` from pre-allocated resources.

use embassy_sync::{
    blocking_mutex::raw::{NoopRawMutex, RawMutex},
    channel::{Channel, DynamicReceiver, DynamicSender},
};

use crate::{
    StackState,
    composition::{LayerBuildContext, LayerStackBuilder},
    definition::StackDefinition,
    inner::{Inner, StackContext},
    layer_context::HasLayerContext,
    layers::{LinkLayerBuilderBase, transport::TlStyle},
    messages::buffers::{Buffer, BufferManager},
    resources::StackResources,
    restart,
    stack_handle::Stack,
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
    pub async fn run(self) -> ! {
        // Validate that outgoing connections require Style 3 (which has the
        // CONNECTING state needed for client-initiated connections).
        assert!(
            D::TL_MAX_OUTGOING == 0 || D::TL_STYLE == TlStyle::Style3,
            "TL_MAX_OUTGOING > 0 requires TlStyle::Style3 (has CONNECTING state for client connections)"
        );

        // Run state machine initialization, DeviceControl sync, and lifecycle
        // events are handled by the DeviceModel in InsecureDeviceLayers::init().

        use crate::messages::builder::{ConfirmationMessage, IndicationMessage, RequestMessage};
        use crate::messages::knx::ServiceType;
        use crate::router::LayerStack;
        use embassy_futures::select::{Either, select, select3};
        use embassy_time::Timer;

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

        let lctx = self.stack.inner.state.layer_context();

        // SAFETY: LayerContext lives in StackResources which outlives this function.
        let app_service_receiver: DynamicReceiver<'static, _> = unsafe {
            core::mem::transmute::<DynamicReceiver<'_, _>, DynamicReceiver<'static, _>>(
                lctx.app_service_channel.receiver().into(),
            )
        };

        let layer_context = LayerBuildContext {
            state: &self.stack.inner.state,
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
        // Service inputs (e.g., app service requests from user code, cEMI
        // events) are handled through `recv_service_input` /
        // `handle_service_input`.

        let router_task = async {
            let outbox = &lctx.outbox;

            loop {
                let layer_deadline = layers.next_deadline();
                if layer_deadline.is_some() {
                    debug!("Router: layer_deadline is Some, will poll on timer");
                }

                // Wait for the next event: LL indication, LL confirmation,
                // service input, or layer timer.
                match select3(
                    ll_ind.receive(),
                    ll_conf.receive(),
                    select(layers.recv_service_input(), async {
                        match layer_deadline {
                            Some(deadline) => Timer::at(deadline).await,
                            None => core::future::pending().await,
                        }
                    }),
                )
                .await
                {
                    // LL indication -> push to outbox for dispatch
                    embassy_futures::select::Either3::First(ind) => {
                        outbox.borrow_mut().push(ind.into_inner());
                    }
                    // LL confirmation -> push to outbox for dispatch
                    embassy_futures::select::Either3::Second(conf) => {
                        outbox.borrow_mut().push(conf.into_inner());
                    }
                    embassy_futures::select::Either3::Third(third) => match third {
                        Either::First(input) => {
                            layers.handle_service_input(input);
                        }
                        Either::Second(_) => {
                            debug!("Router: timer expired, polling layers");
                            layers.poll();
                        }
                    },
                }

                // Drain the outbox: dispatch each message through the table
                // until all messages are consumed or sent to the LL.
                //
                // Each take_next() is a short-lived RefCell borrow, released
                // before dispatch() — which may push new messages.
                //
                // After each LL send we yield so the LL task can transmit
                // the frame before the router produces the next one. This
                // preserves wire ordering (e.g., ACK before data response)
                // which matters for conformance tests that check message
                // order.
                loop {
                    let msg = outbox.borrow_mut().take_next();
                    let Some(msg) = msg else { break };

                    let st = msg.service_type();
                    if st == ServiceType::L_Data_Req {
                        ll_req.send(RequestMessage::request(msg)).await;
                        embassy_futures::yield_now().await;
                    } else if let Some(layer_idx) = Layers::<'_, D>::DISPATCH_TABLE.get(st) {
                        layers.dispatch(layer_idx, msg);
                    } else {
                        warn!("Router: no layer for {:?}, dropping", st);
                    }
                }

                // Handle side-effect events emitted during this dispatch cycle
                // (e.g., run state machine transitions).
                layers.drain_events();
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
/// The runner creates the [`LayerContext`](crate::layer_context::LayerContext)
/// (buffer manager, outbox, channels) first, then calls
/// [`D::create_state()`](StackDefinition::create_state) so the device state
/// has access to runtime infrastructure from birth — no two-phase init.
///
/// # Arguments
///
/// * `resources` - Pre-allocated memory for the stack
/// * `link_layer_builder` - Link layer builder (e.g., TPUART, KNX/IP, mock)
/// * `state_config` - Configuration for state construction (identity, persisted snapshot, etc.)
/// * `platform` - Platform abstraction (IP config for KNX/IP, `()` for TP1)
/// * `memory_map` - Memory map for A_Memory_Read/Write services
pub fn new<'d, D: StackDefinition + Copy, const BUF_SZ: usize, const NUM_BUFS: usize>(
    resources: &'d mut StackResources<D, BUF_SZ, NUM_BUFS>,
    link_layer_builder: D::LLB,
    state_config: D::StateConfig,
    platform: D::Platform,
    memory_map: D::Mem,
) -> (Stack<'d, D>, Runner<'d, D>) {
    use crate::layer_context::LayerContext;

    // ================================================================
    // Step 1: Allocate buffers
    // ================================================================

    // SAFETY: We are creating a reference to the buffers that are stored in the `StackResources` struct,
    //         which lives at least as long as `Inner`
    let buffers = resources.buffers.write([[0; _]; _]);
    let buffer_manager: &'static mut BufferManager<NUM_BUFS> =
        unsafe { core::mem::transmute(resources.buffer_manager.write(BufferManager::new(buffers))) };

    // ================================================================
    // Step 2: Create LayerContext (before the state)
    // ================================================================

    let layer_context = LayerContext::new(buffer_manager.dyn_buffer_manager());
    let layer_context = &*resources.layer_context.write(layer_context);

    // SAFETY: layer_context lives in StackResources which outlives everything.
    // The actual lifetime is 'd but we need 'static for the state field.
    let layer_ctx_static: &'static LayerContext<D> = unsafe { core::mem::transmute(layer_context) };

    // ================================================================
    // Step 3: Create state via D::create_state()
    // ================================================================

    let state = D::create_state(state_config, layer_ctx_static);

    // Validate that runtime max_apdu_length doesn't exceed compile-time buffer allocation
    let runtime_max_apdu = state.max_apdu_length();
    assert!(
        runtime_max_apdu <= D::MAX_APDU_LENGTH,
        "StackState::max_apdu_length() ({}) exceeds StackDefinition::MAX_APDU_LENGTH ({}). \
         The runtime limit must not exceed the compile-time buffer allocation.",
        runtime_max_apdu,
        D::MAX_APDU_LENGTH
    );

    // ================================================================
    // Step 4: Create Inner and interface objects
    // ================================================================

    let inner = Inner { state, platform, memory_map };
    let inner = &*resources.inner.write(inner);

    // Build interface objects with reference to the state stored in Inner.
    // SAFETY: Inner is now stable in memory (written to StackResources), so we can safely
    //         transmute the state reference to 'static lifetime. The actual lifetime is 'd
    //         but the interface objects container needs 'static for its type parameter.
    let interface_objects = {
        let state_ref: &'static D::State = unsafe { core::mem::transmute(&inner.state) };
        let platform_ref: &'static D::Platform = unsafe { core::mem::transmute(&inner.platform) };
        D::create_interface_objects(state_ref, platform_ref)
    };
    let interface_objects = &*resources.interface_objects.write(interface_objects);

    // Channels live on LayerContext (inside the state). Create sender/receiver
    // pairs for the Stack handle and the Runner.
    let lctx: &'static crate::layer_context::LayerContext<D> =
        unsafe { core::mem::transmute(inner.state.layer_context()) };

    let app_request_sender: DynamicSender<'static, _> = lctx.app_service_channel.sender().into();

    // The sender goes to the Runner (passed to ApplicationLayer), receiver goes to Stack (for user code).
    let (restart_sender, restart_receiver) = create_request_response_pair::<D::Mutex, _, 1>(&lctx.restart_channel);

    // Initialize link layer resources using the builder
    let link_layer_resources = resources.link_layer_resources.write(link_layer_builder.create_resources());

    let stack = Stack { inner, interface_objects, app_request_sender, restart_receiver };
    let runner = Runner { stack, interface_objects, restart_sender, link_layer_builder, link_layer_resources };

    (stack, runner)
}
