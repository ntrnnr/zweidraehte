use embassy_futures::select::{Either, select};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicSender, Receiver, Sender, TrySendError},
};

use crate::context::BufferManagerContext;
use crate::layers::{Inbox, LinkLayerBuilder, LinkLayerBuilderBase, LinkLayerCapabilities};
use zweidraehte_proto::encoding::tp1;
use zweidraehte_proto::messages::{
    buffers::{Buffer, DynBufferManager},
    builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage, RequestMessage},
    knx::*,
};

/// A mock link layer that allows injecting messages via a channel
///
/// This is useful for testing and debugging without requiring physical hardware.
/// Messages can be injected using the injection sender, and the link layer will
/// pass them up to the network layer as indications.
///
/// Optionally, outgoing messages (requests from upper layers) can be captured
/// and forwarded to a capture channel for test verification.
pub struct MockLinkLayer<'a, const N: usize, const C: usize = 8> {
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
    injection_receiver: Receiver<'static, NoopRawMutex, InjectedFrame, N>,
    // The injection channel carries raw frame bytes, so the link layer
    // allocates a pool buffer here from the shared buffer manager (handed in
    // from the stack context). This keeps buffer ownership inside the stack and
    // off the public test-injection API.
    buffer_manager: &'a DynBufferManager<'static>,
    capture_sender: Option<Sender<'static, NoopRawMutex, CapturedLinkLayerMessage, C>>,
}

/// Capture buffer size for [`CapturedLinkLayerMessage`].
///
/// Large enough for every telegram the test suites assert on (standard
/// frames; extended frames near the full APDU budget would be truncated
/// — bump this if a test ever needs to capture one).
pub const CAPTURE_BUF_SIZE: usize = 64;

/// Maximum size of a frame queued through [`MockLinkLayerHandle::inject_bytes`].
///
/// Large enough for every telegram the test suites inject (standard frames);
/// bytes beyond this are truncated — bump it if a test ever injects an
/// extended frame near the full APDU budget.
pub const INJECT_BUF_SIZE: usize = 64;

/// A raw KNX frame queued for injection: TP1-like bytes with no checksum,
/// exactly the shape [`MockLinkLayerHandle::inject_bytes`] accepts. The mock
/// link layer allocates a pool buffer from these bytes on receipt.
pub type InjectedFrame = heapless::Vec<u8, INJECT_BUF_SIZE>;

/// A captured message from the link layer (outgoing from stack to wire)
#[derive(Debug, Clone)]
pub struct CapturedLinkLayerMessage {
    /// The service type of the captured message
    pub service_type: ServiceType,
    /// The raw message bytes
    pub data: heapless::Vec<u8, CAPTURE_BUF_SIZE>,
}

impl<'a, const N: usize, const C: usize> MockLinkLayer<'a, N, C> {
    /// Create a new Mock Link Layer
    pub fn new(
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        injection_receiver: Receiver<'static, NoopRawMutex, InjectedFrame, N>,
        buffer_manager: &'a DynBufferManager<'static>,
    ) -> Self {
        Self { ind_tx, conf_tx, injection_receiver, buffer_manager, capture_sender: None }
    }

    /// Create a new Mock Link Layer with capture support
    pub fn with_capture(
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        injection_receiver: Receiver<'static, NoopRawMutex, InjectedFrame, N>,
        buffer_manager: &'a DynBufferManager<'static>,
        capture_sender: Sender<'static, NoopRawMutex, CapturedLinkLayerMessage, C>,
    ) -> Self {
        Self { ind_tx, conf_tx, injection_receiver, buffer_manager, capture_sender: Some(capture_sender) }
    }

    /// Run the mock link layer event loop
    ///
    /// Concurrently waits for:
    /// - Requests from the network layer (via `req_rx`), which are processed
    ///   and confirmed via `conf_tx`
    /// - Injected messages (via `injection_receiver`), which are forwarded
    ///   up to the network layer as indications via `ind_tx`
    async fn run<M>(&mut self, mut req_rx: M) -> !
    where
        M: Inbox<RequestMessage<Buffer<'static>>>,
    {
        loop {
            match select(req_rx.next(), self.injection_receiver.receive()).await {
                Either::First(request) => {
                    trace!("Mock LL received request: {:?}", request);
                    let response = self.handle_request(request).await;
                    self.conf_tx.send(response).await;
                }
                Either::Second(raw) => {
                    // The channel carries raw frame bytes; allocate a pool
                    // buffer for them, then convert from TP1-like format (no
                    // checksum) to the internal frame format. Injected frames
                    // are always L_Data indications (the only thing tests inject).
                    let buf = self.buffer_manager.alloc_from_slice(&raw).await;
                    let converted_buf = tp1::tp1_to_knx_message_no_checksum(buf);
                    let internal_msg = KnxMessageBuffer::new(converted_buf, ServiceType::L_Data_Ind);
                    debug!("Mock LL injecting message: {:?}", internal_msg);
                    self.ind_tx.send(IndicationMessage::indication(internal_msg)).await;
                }
            }
        }
    }

    async fn handle_request(
        &mut self,
        request: RequestMessage<Buffer<'static>>,
    ) -> ConfirmationMessage<Buffer<'static>> {
        // Unwrap the typed message to get the inner KnxMessageBuffer
        let msg = request.into_inner();
        trace!("Mock LL processing request: {:?}", msg);

        // Capture the outgoing message if a capture sender is configured
        if let Some(ref capture_sender) = self.capture_sender {
            // Convert from internal format to TP1-like format (no checksum) for capture
            let data = tp1::knx_to_tp1_bytes_no_checksum::<64>(&msg.buf()[..msg.len()]);
            let captured = CapturedLinkLayerMessage { service_type: msg.service_type(), data };

            // Use try_send to avoid blocking - drop if buffer is full
            match capture_sender.try_send(captured) {
                Ok(()) => trace!("Mock LL: captured outgoing message"),
                Err(TrySendError::Full(_)) => warn!("Mock LL: capture buffer full, dropping message"),
            }
        }

        match msg.service_type() {
            // Just pretend we sent the message and issue a confirmation back
            ServiceType::L_Data_Req => {
                debug!("Mock LL: simulating L_Data_Con for L_Data_Req");
                let confirmation = msg.confirm().build();
                trace!("Mock LL returning confirmation: {:?}", confirmation);
                confirmation
            }

            // Everything else is unhandled - return error confirmation
            _ => {
                warn!("Mock LL: unhandled request service type: {:?}", msg.service_type());
                msg.error().build()
            }
        }
    }
}

/// Handle for injecting messages into a MockLinkLayer
///
/// This handle is returned when creating a MockLinkLayerBuilder and allows
/// you to inject messages into the mock link layer for testing.
#[derive(Clone)]
pub struct MockLinkLayerHandle<const N: usize, const C: usize = 8> {
    injection_sender: Sender<'static, NoopRawMutex, InjectedFrame, N>,
    capture_receiver: Option<Receiver<'static, NoopRawMutex, CapturedLinkLayerMessage, C>>,
}

impl<const N: usize, const C: usize> MockLinkLayerHandle<N, C> {
    /// Inject a raw KNX frame into the mock link layer.
    ///
    /// `bytes` is a TP1-like frame with no checksum (the same shape the bus
    /// would deliver). The mock link layer allocates a pool buffer for it and
    /// passes it up to the network layer as an `L_Data` indication. Frames
    /// longer than [`INJECT_BUF_SIZE`] are truncated.
    pub async fn inject_bytes(&self, bytes: &[u8]) {
        let mut frame = InjectedFrame::new();
        let len = bytes.len().min(INJECT_BUF_SIZE);
        // `extend_from_slice` only errors on capacity overflow, which the clamp
        // above rules out.
        frame.extend_from_slice(&bytes[..len]).expect("slice clamped to INJECT_BUF_SIZE");
        self.injection_sender.send(frame).await;
    }

    /// Receive a captured outgoing message from the link layer
    ///
    /// This blocks until a message is available. Only available if the builder
    /// was created with `with_capture`.
    pub async fn receive_captured(&self) -> Option<CapturedLinkLayerMessage> {
        if let Some(ref capture_receiver) = self.capture_receiver {
            Some(capture_receiver.receive().await)
        } else {
            None
        }
    }

    /// Try to receive a captured outgoing message without blocking
    pub fn try_receive_captured(&self) -> Option<CapturedLinkLayerMessage> {
        if let Some(ref capture_receiver) = self.capture_receiver { capture_receiver.try_receive().ok() } else { None }
    }
}

/// Resources for [`MockLinkLayer`] (empty — no resources needed).
#[derive(Default)]
pub struct MockLinkLayerResources;

impl MockLinkLayerResources {
    /// Creates empty resources for the mock link layer.
    pub const fn new() -> Self {
        Self
    }
}

/// Builder for the MockLinkLayer
///
/// This builder creates a mock link layer. Call `new()` to create both
/// the builder and a handle for message injection.
pub struct MockLinkLayerBuilder<const N: usize, const C: usize = 8> {
    injection_channel: &'static Channel<NoopRawMutex, InjectedFrame, N>,
    capture_channel: Option<&'static Channel<NoopRawMutex, CapturedLinkLayerMessage, C>>,
}

impl<const N: usize, const C: usize> MockLinkLayerBuilder<N, C> {
    /// Create a new MockLinkLayerBuilder and Handle
    ///
    /// Returns a tuple of (builder, handle) where:
    /// - `builder` is consumed when creating the stack
    /// - `handle` can be kept to inject messages into the link layer
    ///
    /// # Arguments
    /// * `injection_channel` - A static channel that will be used to inject messages
    pub fn new(
        injection_channel: &'static Channel<NoopRawMutex, InjectedFrame, N>,
    ) -> (Self, MockLinkLayerHandle<N, C>) {
        let builder = Self { injection_channel, capture_channel: None };
        let handle = MockLinkLayerHandle { injection_sender: injection_channel.sender(), capture_receiver: None };
        (builder, handle)
    }

    /// Create a new MockLinkLayerBuilder and Handle with capture support
    ///
    /// Returns a tuple of (builder, handle) where:
    /// - `builder` is consumed when creating the stack
    /// - `handle` can be kept to inject messages and receive captured outgoing messages
    ///
    /// # Arguments
    /// * `injection_channel` - A static channel that will be used to inject messages
    /// * `capture_channel` - A static channel that will receive captured outgoing messages
    pub fn with_capture(
        injection_channel: &'static Channel<NoopRawMutex, InjectedFrame, N>,
        capture_channel: &'static Channel<NoopRawMutex, CapturedLinkLayerMessage, C>,
    ) -> (Self, MockLinkLayerHandle<N, C>) {
        let builder = Self { injection_channel, capture_channel: Some(capture_channel) };
        let handle = MockLinkLayerHandle {
            injection_sender: injection_channel.sender(),
            capture_receiver: Some(capture_channel.receiver()),
        };
        (builder, handle)
    }
}

impl<const N: usize, const C: usize> LinkLayerBuilderBase for MockLinkLayerBuilder<N, C> {
    type Resources = MockLinkLayerResources;

    fn create_resources(&self) -> Self::Resources {
        MockLinkLayerResources::new()
    }
}

impl<const N: usize, const C: usize> LinkLayerCapabilities for MockLinkLayerBuilder<N, C> {}

impl<CTX: BufferManagerContext, const N: usize, const C: usize> LinkLayerBuilder<CTX> for MockLinkLayerBuilder<N, C> {
    fn build_and_run<'a>(
        self,
        _resources: &'a mut Self::Resources,
        context: &'a CTX,
        _ll_endpoints: (),
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl Inbox<RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        // The mock allocates injected-frame buffers from the stack's shared
        // pool, reached through the context's buffer manager.
        let buffer_manager = context.buffer_manager();
        let mut link_layer = if let Some(capture_channel) = self.capture_channel {
            MockLinkLayer::with_capture(
                ind_tx,
                conf_tx,
                self.injection_channel.receiver(),
                buffer_manager,
                capture_channel.sender(),
            )
        } else {
            MockLinkLayer::new(ind_tx, conf_tx, self.injection_channel.receiver(), buffer_manager)
        };
        async move { link_layer.run(req_rx).await }
    }
}
