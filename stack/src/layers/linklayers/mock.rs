use core::cell::RefCell;

use embassy_futures::select::{Either, select};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicSender, Receiver, Sender},
};

use crate::{
    address::IndividualAddress,
    layers::{Inbox, Layer, LayerOp, LinkLayerBuilder},
    messages::{
        buffers::{Buffer, DynBufferManager},
        knx::*,
    },
};

/// A mock link layer that allows injecting messages via a channel
///
/// This is useful for testing and debugging without requiring physical hardware.
/// Messages can be injected using the injection sender, and the link layer will
/// pass them up to the network layer as indications.
pub struct MockLinkLayer<'a, const N: usize> {
    network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    injection_receiver: Receiver<'static, NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
}

impl<'a, const N: usize> MockLinkLayer<'a, N> {
    /// Create a new Mock Link Layer
    pub fn new(
        network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
        injection_receiver: Receiver<'static, NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
    ) -> Self {
        Self { network_layer, injection_receiver }
    }
}

impl<'a, const N: usize> Layer<'a> for MockLinkLayer<'a, N> {
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Message>>,
    {
        loop {
            match select(inbox.next(), self.injection_receiver.receive()).await {
                Either::First(layer_op) => {
                    trace!("Mock Link Layer received layer op: {:?}", layer_op);

                    match layer_op {
                        LayerOp::Indication(_msg) => {
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
                    trace!("Injecting mock linklayer message: {:x?}", injection_msg);
                    self.network_layer.send(LayerOp::Indication(injection_msg)).await;
                }
            }
        }
    }
}

impl<'a, const N: usize> MockLinkLayer<'a, N> {
    async fn handle_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> KnxMessageBuffer<Buffer<'static>> {
        trace!("Mock Link Layer received request: {:?}", msg);

        match msg.service_type() {
            // Just pretend we sent the message and issue a confirmation back
            ServiceType::L_Data_Req => {
                trace!("Mock Link Layer: simulating successful transmission of L_Data_Req");

                // Create confirmation by converting the request
                msg.ctrl_field_mut().set_c(Confirm::NoError);
                msg.set_service_type(ServiceType::L_Data_Con);

                trace!("Mock Link Layer returning confirmation: {:?}", msg);
                msg
            }

            // Everything else is unhandled - return error confirmation
            _ => {
                trace!("Mock Link Layer: unhandled request service type: {:?}", msg.service_type());
                msg.ctrl_field_mut().set_c(Confirm::Err);
                msg
            }
        }
    }
}

/// Handle for injecting messages into a MockLinkLayer
///
/// This handle is returned when creating a MockLinkLayerBuilder and allows
/// you to inject messages into the mock link layer for testing.
#[derive(Clone)]
pub struct MockLinkLayerHandle<const N: usize> {
    injection_sender: Sender<'static, NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
}

impl<const N: usize> MockLinkLayerHandle<N> {
    /// Inject a message into the mock link layer
    ///
    /// The message will be passed up to the network layer as an indication.
    pub async fn inject(&self, msg: KnxMessageBuffer<Buffer<'static>>) {
        self.injection_sender.send(msg).await;
    }
}

/// Builder for the MockLinkLayer
///
/// This builder creates a mock link layer. Call `new()` to create both
/// the builder and a handle for message injection.
pub struct MockLinkLayerBuilder<const N: usize> {
    injection_channel: &'static Channel<NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, N>,
}

impl<const N: usize> MockLinkLayerBuilder<N> {
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
    ) -> (Self, MockLinkLayerHandle<N>) {
        let builder = Self { injection_channel };
        let handle = MockLinkLayerHandle { injection_sender: injection_channel.sender() };
        (builder, handle)
    }
}

impl<const N: usize> LinkLayerBuilder for MockLinkLayerBuilder<N> {
    fn build_and_run<'a, CTX>(
        self,
        _context: &'a CTX,
        network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
        inbox: impl Inbox<LayerOp<KnxMessageBuffer<Buffer<'static>>>> + 'a,
    ) -> impl Future<Output = !> + 'a
    where
        CTX: crate::context::BufferManagerContext,
    {
        let mut link_layer = MockLinkLayer::new(network_layer, self.injection_channel.receiver());
        async move { link_layer.process(inbox).await }
    }
}
