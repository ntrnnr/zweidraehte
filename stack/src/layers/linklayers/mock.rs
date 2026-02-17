use core::mem::MaybeUninit;
use embassy_futures::select::{Either, select};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicSender, Receiver, Sender, TrySendError},
};

use crate::{
    encoding::tp1,
    layers::{Inbox, Layer, LayerOp, LinkLayerBuilder, LinkLayerBuilderBase},
    messages::{
        buffers::Buffer,
        builder::ConfirmationExt,
        knx::*,
    },
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
    network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    injection_receiver: Receiver<'static, NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
    capture_sender: Option<Sender<'static, NoopRawMutex, CapturedLinkLayerMessage, C>>,
}

/// A captured message from the link layer (outgoing from stack to wire)
#[derive(Debug, Clone)]
pub struct CapturedLinkLayerMessage {
    /// The service type of the captured message
    pub service_type: ServiceType,
    /// The raw message bytes
    pub data: heapless::Vec<u8, 64>,
}

impl<'a, const N: usize, const C: usize> MockLinkLayer<'a, N, C> {
    /// Create a new Mock Link Layer
    pub fn new(
        network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
        injection_receiver: Receiver<'static, NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
    ) -> Self {
        Self { network_layer, injection_receiver, capture_sender: None }
    }

    /// Create a new Mock Link Layer with capture support
    pub fn with_capture(
        network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
        injection_receiver: Receiver<'static, NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
        capture_sender: Sender<'static, NoopRawMutex, CapturedLinkLayerMessage, C>,
    ) -> Self {
        Self { network_layer, injection_receiver, capture_sender: Some(capture_sender) }
    }
}

impl<'a, const N: usize, const C: usize> Layer<'a> for MockLinkLayer<'a, N, C> {
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Message>>,
    {
        loop {
            match select(inbox.next(), self.injection_receiver.receive()).await {
                Either::First(layer_op) => {
                    trace!("Mock LL received layer op: {:?}", layer_op);

                    match layer_op {
                        LayerOp::Indication(_) => {
                            // Link layer typically doesn't receive indications from upper layers
                            warn!("Mock Link Layer received unexpected indication");
                        }
                        LayerOp::Request { message: msg, response_tx } => {
                            let response = self.handle_request(msg).await;
                            response_tx.send(response).await;
                        }
                    }
                }
                Either::Second(injection_msg) => {
                    // Convert from TP1-like format (no checksum) to internal format
                    // Extract the buffer, apply conversion, wrap back
                    let service_type = injection_msg.service_type();
                    let inner_buf = injection_msg.into_inner();
                    let converted_buf = tp1::tp1_to_knx_message_no_checksum(inner_buf);
                    let internal_msg = KnxMessageBuffer::new(converted_buf, service_type);
                    debug!("Mock LL injecting message: {:?}", internal_msg);
                    self.network_layer.send(LayerOp::Indication(internal_msg)).await;
                }
            }
        }
    }
}

impl<'a, const N: usize, const C: usize> MockLinkLayer<'a, N, C> {
    async fn handle_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> KnxMessageBuffer<Buffer<'static>> {
        trace!("Mock LL received request: {:?}", msg);

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
    injection_sender: Sender<'static, NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
    capture_receiver: Option<Receiver<'static, NoopRawMutex, CapturedLinkLayerMessage, C>>,
}

impl<const N: usize, const C: usize> MockLinkLayerHandle<N, C> {
    /// Inject a message into the mock link layer
    ///
    /// The message will be passed up to the network layer as an indication.
    pub async fn inject(&self, msg: KnxMessageBuffer<Buffer<'static>>) {
        self.injection_sender.send(msg).await;
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

/// Resources for MockLinkLayer (empty - no resources needed)
pub struct MockLinkLayerResources {
    _private: MaybeUninit<()>,
}

impl MockLinkLayerResources {
    /// Create new empty resources for mock link layer
    pub const fn new() -> Self {
        Self { _private: MaybeUninit::uninit() }
    }
}

/// Builder for the MockLinkLayer
///
/// This builder creates a mock link layer. Call `new()` to create both
/// the builder and a handle for message injection.
pub struct MockLinkLayerBuilder<const N: usize, const C: usize = 8> {
    injection_channel: &'static Channel<NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
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
        injection_channel: &'static Channel<NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
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
        injection_channel: &'static Channel<NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
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

impl<CTX, const N: usize, const C: usize> LinkLayerBuilder<CTX> for MockLinkLayerBuilder<N, C> {
    fn build_and_run<'a>(
        self,
        _resources: &'a mut Self::Resources,
        _context: &'a CTX,
        network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
        inbox: impl Inbox<LayerOp<KnxMessageBuffer<Buffer<'static>>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        let mut link_layer = if let Some(capture_channel) = self.capture_channel {
            MockLinkLayer::with_capture(network_layer, self.injection_channel.receiver(), capture_channel.sender())
        } else {
            MockLinkLayer::new(network_layer, self.injection_channel.receiver())
        };
        async move { link_layer.process(inbox).await }
    }
}
