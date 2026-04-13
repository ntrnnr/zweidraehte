//! Mock Link Layer for testing
//!
//! This module provides a mock link layer that allows injecting messages via a channel.
//! It's useful for testing and debugging without requiring physical hardware.

use core::mem::MaybeUninit;
use embassy_futures::select::{Either, select};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicSender, Receiver, Sender, TrySendError},
};

use zweidraehte_device::{
    layers::{Inbox, LinkLayerBuilder, LinkLayerBuilderBase}};
use zweidraehte_proto::encoding::tp1;
use zweidraehte_proto::messages::{
        buffers::Buffer,
        builder::{ConfirmationMessage, IndicationMessage, RequestMessage},
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
    injection_receiver: Receiver<'static, NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
    capture_sender: Option<Sender<'static, NoopRawMutex, CapturedLinkLayerMessage, C>>,
}

/// A captured message from the link layer (outgoing from stack to wire)
#[derive(Debug, Clone)]
pub struct CapturedLinkLayerMessage {
    /// The service type of the captured message
    pub service_type: ServiceType,
    /// The raw message bytes in TP1 format (no checksum)
    pub data: Vec<u8>,
}

impl<'a, const N: usize, const C: usize> MockLinkLayer<'a, N, C> {
    /// Create a new Mock Link Layer
    pub fn new(
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        injection_receiver: Receiver<'static, NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
    ) -> Self {
        Self { ind_tx, conf_tx, injection_receiver, capture_sender: None }
    }

    /// Create a new Mock Link Layer with capture support
    pub fn with_capture(
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        injection_receiver: Receiver<'static, NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
        capture_sender: Sender<'static, NoopRawMutex, CapturedLinkLayerMessage, C>,
    ) -> Self {
        Self { ind_tx, conf_tx, injection_receiver, capture_sender: Some(capture_sender) }
    }
}

impl<'a, const N: usize, const C: usize> MockLinkLayer<'a, N, C> {
    async fn process(&mut self, mut req_rx: impl Inbox<RequestMessage<Buffer<'static>>>) -> ! {
        loop {
            match select(req_rx.next(), self.injection_receiver.receive()).await {
                Either::First(msg) => {
                    log::trace!("Mock LL received request: {:?}", msg);
                    let response = self.handle_request(msg).await;
                    self.conf_tx.send(response).await;
                }
                Either::Second(injection_msg) => {
                    // Convert from TP1-like format (no checksum) to internal format
                    let service_type = injection_msg.service_type();
                    let inner_buf = injection_msg.into_inner();
                    let converted_buf = tp1::tp1_to_knx_message_no_checksum(inner_buf);
                    let internal_msg = KnxMessageBuffer::new(converted_buf, service_type);
                    log::debug!("Mock LL injecting message: {:x?}", internal_msg);
                    self.ind_tx.send(IndicationMessage::indication(internal_msg)).await;
                }
            }
        }
    }
}

impl<'a, const N: usize, const C: usize> MockLinkLayer<'a, N, C> {
    async fn handle_request(&mut self, msg: RequestMessage<Buffer<'static>>) -> ConfirmationMessage<Buffer<'static>> {
        log::trace!("Mock LL received request: {:?}", msg);

        // Capture the outgoing message if a capture sender is configured
        if let Some(ref capture_sender) = self.capture_sender {
            // Convert from internal format to TP1-like format (no checksum) for capture
            let data = knx_to_tp1_vec_no_checksum(&msg.buf()[..msg.len()]);
            let captured = CapturedLinkLayerMessage { service_type: msg.service_type(), data };

            // Use try_send to avoid blocking - drop if buffer is full
            match capture_sender.try_send(captured) {
                Ok(()) => log::trace!("Mock LL: captured outgoing message"),
                Err(TrySendError::Full(_)) => log::warn!("Mock LL: capture buffer full, dropping message"),
            }
        }

        // Get inner message to mutate for confirmation
        let mut inner = msg.into_inner();

        match inner.service_type() {
            // Just pretend we sent the message and issue a confirmation back
            ServiceType::L_Data_Req => {
                log::debug!("Mock LL: simulating L_Data_Con for L_Data_Req");

                // Create confirmation by converting the request
                inner.ctrl_field_mut().set_c(Confirm::NoError);
                inner.set_service_type(ServiceType::L_Data_Con);

                log::trace!("Mock LL returning confirmation: {:?}", inner);
                ConfirmationMessage::confirmation(inner)
            }

            // Everything else is unhandled - return error confirmation
            _ => {
                log::warn!("Mock LL: unhandled request service type: {:?}", inner.service_type());
                inner.ctrl_field_mut().set_c(Confirm::Err);
                ConfirmationMessage::confirmation(inner)
            }
        }
    }
}

/// Convert internal KNX message bytes to TP1 format (no checksum) using Vec
fn knx_to_tp1_vec_no_checksum(src: &[u8]) -> Vec<u8> {
    let len = src.len();

    // Check for standard frame: length <= 23 and lower 4 bits of NPDU are 0
    if (len < 23) && ((src[5] & 0x0f) == 0) {
        // Standard frame - copy with modified control and length fields
        let mut data = src.to_vec();
        data[5] = (data[5] & 0xf0) | ((len - 7) as u8);
        data[0] = (data[0] & 0x0c) | 0xb0;
        data
    } else {
        // Extended frame - need to insert extended control field
        let orig_npdu = src[5];
        let mut data = Vec::with_capacity(len + 1);

        // Control byte with extended frame marker
        data.push((src[0] & 0x0C) | 0x30);
        // Insert extended control field
        data.push(orig_npdu);
        // Copy bytes 1-5 (source addr, dest addr, NPDU high nibble)
        data.extend_from_slice(&src[1..5]);
        // Insert length field
        data.push((len - 7) as u8);
        // Copy remaining data (APDU)
        data.extend_from_slice(&src[6..]);
        data
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

    /// Drain all pending captured messages from the channel
    ///
    /// This is useful for clearing leftover messages between tests.
    /// Returns the number of messages drained.
    pub fn drain_captured(&self) -> usize {
        let mut count = 0;
        while self.try_receive_captured().is_some() {
            count += 1;
        }
        if count > 0 {
            log::debug!("Drained {} captured messages from channel", count);
        }
        count
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

impl Default for MockLinkLayerResources {
    fn default() -> Self {
        Self::new()
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

impl<const N: usize, const C: usize> zweidraehte_device::layers::LinkLayerCapabilities for MockLinkLayerBuilder<N, C> {}

impl<CTX, const N: usize, const C: usize> LinkLayerBuilder<CTX> for MockLinkLayerBuilder<N, C> {
    fn build_and_run<'a>(
        self,
        _resources: &'a mut Self::Resources,
        _context: &'a CTX,
        _ll_endpoints: (),
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl Inbox<RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        let mut link_layer = if let Some(capture_channel) = self.capture_channel {
            MockLinkLayer::with_capture(ind_tx, conf_tx, self.injection_channel.receiver(), capture_channel.sender())
        } else {
            MockLinkLayer::new(ind_tx, conf_tx, self.injection_channel.receiver())
        };
        async move { link_layer.process(req_rx).await }
    }
}
