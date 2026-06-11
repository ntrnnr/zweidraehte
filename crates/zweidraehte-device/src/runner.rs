//! KNX stack runner and factory function.
//!
//! The [`Runner`] drives the stack's async event loop. The [`new()`] factory
//! creates both a [`Stack`] handle and a `Runner` from pre-allocated resources.

use embassy_futures::select::{Either, select, select3};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicReceiver, DynamicSender},
};
use embassy_time::Timer;

use crate::{
    StackState, composition::LayerStackBuilder, context::StackContext, context::layer::LayerContext,
    definition::StackDefinition, inner::Inner, layers::LinkLayerBuilderBase, resources::StackResources,
    service::LayerRegistry, stack_handle::Stack,
};
use zweidraehte_proto::messages::buffers::{Buffer, BufferManager};
use zweidraehte_proto::messages::builder::{ConfirmationMessage, IndicationMessage, RequestMessage};
use zweidraehte_proto::messages::knx::ServiceType;

// ============================================================================
// Runner
// ============================================================================

/// KNX stack runner.
///
/// You must call [`Runner::run()`] in a background task for the KNX stack to work.
pub struct Runner<'d, D: StackDefinition> {
    pub(crate) stack: Stack<'d, D>,
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
        //
        // Would ideally live in a `const { assert!(...) }` block that runs at
        // monomorphisation time, but rustc refuses to evaluate the expression
        // because it depends on `StackDefinition` associated consts
        // (`overly complex generic constant`). Keep the runtime assert until
        // const-eval limitations ease.
        assert!(
            D::TL_MAX_OUTGOING == 0 || D::TL_STYLE.supports_outgoing_connections(),
            "TL_MAX_OUTGOING > 0 requires TlStyle::Style3 (has CONNECTING state for client connections)",
        );

        // Run state machine initialization, DeviceControl sync, and lifecycle
        // events are handled by the DeviceModel in InsecureDeviceLayers::init().

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

        let stack_context = StackContext::new(self.stack.inner, self.stack.interface_objects);

        let mut layers = B::<D>::build(&stack_context, &layer_channels);

        // Initialize all layers (e.g., AL starts read-on-init cycle if
        // the application is already running).
        layers.init_layers();

        // Do one poll pass straight after init so the layers get a
        // chance to evaluate their startup state — the AL uses this
        // to either begin read-on-init or settle on "nothing to do"
        // without waiting for the first timer deadline (which may
        // never arrive on a DUT with no application loaded).
        layers.poll_layers();

        // ================================================================
        // Link layer task
        // ================================================================

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
            let lctx = self.stack.inner.layer_context;
            let outbox = &lctx.outbox;

            loop {
                let layer_deadline = layers.next_layer_deadline();
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
                            layers.poll_layers();
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
                        layers.dispatch_wire(layer_idx, msg);
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

/// Create a new KNX stack.
///
/// The runner creates the [`LayerContext`](crate::context::layer::LayerContext)
/// (buffer manager, outbox, channels) first, then calls
/// [`D::create_state()`](StackDefinition::create_state) so the device state
/// has access to runtime infrastructure from birth — no two-phase init.
///
/// # Arguments
///
/// * `resources` - Pre-allocated memory for the stack
/// * `link_layer_builder` - Link layer builder (e.g., TPUART, KNX/IP, mock)
/// * `state_init` - Inputs for state construction (identity, persisted snapshot, etc.)
/// * `platform` - Platform abstraction (IP config for KNX/IP, `()` for TP1)
/// * `memory_map` - Memory map for A_Memory_Read/Write services
pub fn new<D: StackDefinition + Copy, const BUF_SZ: usize, const NUM_BUFS: usize>(
    resources: &'static mut StackResources<D, BUF_SZ, NUM_BUFS>,
    link_layer_builder: D::LLB,
    state_init: D::StateInit,
    platform: D::Platform,
    memory_map: D::Mem,
) -> (Stack<'static, D>, Runner<'static, D>) {
    // ================================================================
    // Step 1: Allocate buffers
    // ================================================================

    let buffers = resources.buffers.write([[0; _]; _]);
    let buffer_manager: &'static mut BufferManager<NUM_BUFS> =
        resources.buffer_manager.write(unsafe { BufferManager::new(buffers) });

    // ================================================================
    // Step 2: Create LayerContext (before the state)
    // ================================================================

    let layer_context = LayerContext::new(buffer_manager.dyn_buffer_manager());
    let layer_ctx_static: &'static LayerContext<D> = resources.layer_context.write(layer_context);

    // ================================================================
    // Step 3: Create state via D::create_state()
    // ================================================================

    let state = D::create_state(state_init);

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

    let inner = Inner { state, platform, memory_map, layer_context: layer_ctx_static };
    let inner: &'static Inner<D> = resources.inner.write(inner);

    // Build the device-wide augment chain. Borrowed by the IO container
    // for the lifetime of the stack — must outlive interface_objects.
    let augments = D::create_augments(&inner.state, &inner.platform, inner.layer_context);
    let augments: &'static D::Augments<'static> = resources.augments.write(augments);

    // Build interface objects with reference to the state stored in Inner.
    let interface_objects = D::create_interface_objects(&inner.state, &inner.platform, inner.layer_context, augments);
    let interface_objects: &'static D::InterfaceObjects<'static> = resources.interface_objects.write(interface_objects);

    // Channels live on LayerContext. Create sender/receiver
    // pairs for the Stack handle and the Runner.
    let lctx: &'static LayerContext<D> = inner.layer_context;

    let app_request_sender: DynamicSender<'static, _> = lctx.app_service_channel.sender().into();

    // Only the receiver side is taken here — the sending side is managed
    // by `LayerContext::try_send_restart_request`.
    let restart_receiver: DynamicReceiver<'static, _> = lctx.restart_channel.receiver().into();

    // Initialize link layer resources using the builder
    let link_layer_resources = resources.link_layer_resources.write(link_layer_builder.create_resources());

    let stack = Stack { inner, interface_objects, app_request_sender, restart_receiver };
    let runner = Runner { stack, link_layer_builder, link_layer_resources };

    (stack, runner)
}
