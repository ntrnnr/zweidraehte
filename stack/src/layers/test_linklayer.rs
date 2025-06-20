use embassy_futures::select::{Either, select};
use embassy_sync::channel::{DynamicReceiver, DynamicSender};

use crate::messages::knx::*;
use crate::{address::IndividualAddress, messages::buffers::Buffer};

use super::{Inbox, Layer, LayerOp};

/// Link layer for the KNX stack
pub struct LinkLayer<'a> {
    device_addr: IndividualAddress,
    network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    injection_receiver: DynamicReceiver<'a, KnxMessageBuffer<Buffer<'static>>>,
}

impl<'a> LinkLayer<'a> {
    /// Create a new Link Layer with the device's individual address
    pub fn new(
        device_addr: IndividualAddress,
        network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
        injection_receiver: DynamicReceiver<'a, KnxMessageBuffer<Buffer<'static>>>,
    ) -> Self {
        Self { device_addr, network_layer, injection_receiver }
    }
}

impl<'a> Layer<'a> for LinkLayer<'a> {
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Message>>,
    {
        loop {
            match select(inbox.next(), self.injection_receiver.receive()).await {
                Either::First(layer_op) => {
                    trace!("Link Layer received layer op: {:?}", layer_op);

                    match layer_op {
                        LayerOp::Indication(msg) => {
                            self.handle_indication(msg).await;
                        }
                        LayerOp::Request { message: msg, response_tx } => {
                            let response = self.handle_request(msg).await;
                            response_tx.send(response).await;
                        }
                    }
                }
                Either::Second(injection_msg) => {
                    trace!("Injecting linklayer message: {:x?}", injection_msg);
                    self.network_layer.send(LayerOp::Indication(injection_msg)).await;
                }
            }
        }
    }
}

impl<'a> LinkLayer<'a> {
    async fn handle_indication(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
        trace!("Link Layer received indication: {:?}", msg);

        match msg.service_type() {
            // Everything else is unhandled for indications
            _ => {}
        }
    }

    async fn handle_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> KnxMessageBuffer<Buffer<'static>> {
        trace!("Link Layer received request: {:?}", msg);

        match msg.service_type() {
            // Just pretend we sent the message and issue a confirmation back
            ServiceType::L_Data_Req => {
                trace!("Test Link Layer: simulating successful transmission of L_Data_Req");

                // Create confirmation by converting the request
                msg.ctrl_field_mut().set_c(Confirm::NoError);
                msg.set_service_type(ServiceType::L_Data_Con);

                trace!("Test Link Layer returning confirmation: {:?}", msg);
                msg
            }

            // Everything else is unhandled - return error confirmation
            _ => {
                trace!("Test Link Layer: unhandled request service type: {:?}", msg.service_type());
                msg.ctrl_field_mut().set_c(Confirm::Err);
                msg
            }
        }
    }
}
