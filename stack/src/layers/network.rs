use embassy_sync::channel::DynamicSender;

use crate::messages::builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage, RequestMessage};
use crate::messages::knx::*;
use crate::objects::interface::HasDeviceObject;
use crate::{StackState, messages::buffers::Buffer};

use super::{ActorRequest, Inbox, Layer, LayerOp};

/// Network layer for the KNX stack
pub struct NetworkLayer<'a, S: StackState, IO: HasDeviceObject> {
    state: &'a S,
    interface_objects: &'a IO,

    link_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
    transport_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
}

impl<'a, S: StackState, IO: HasDeviceObject> NetworkLayer<'a, S, IO> {
    /// Create a new Network Layer with a reference to the shared stack state
    /// and interface objects.
    ///
    /// The routing count (hop count) for outgoing messages is read dynamically
    /// from the device object in the interface objects.
    pub fn new(
        state: &'a S,
        interface_objects: &'a IO,

        link_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
        transport_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
    ) -> Self {
        Self { state, interface_objects, link_layer, transport_layer }
    }

    /// Get the current routing count from the device object.
    #[inline]
    fn routing_count(&self) -> u8 {
        self.interface_objects.routing_count_value()
    }
}

impl<'a, S: StackState, IO: HasDeviceObject> Layer<'a> for NetworkLayer<'a, S, IO> {
    type Buffer = Buffer<'static>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Buffer>>,
    {
        loop {
            let layer_op = inbox.next().await;
            trace!("NL received: {:?}", layer_op);

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
    }
}

impl<'a, S: StackState, IO: HasDeviceObject> NetworkLayer<'a, S, IO> {
    async fn handle_indication(&mut self, mut msg: IndicationMessage<Buffer<'static>>) {
        debug!("NL indication: {:?}", msg);

        match msg.service_type() {
            // Incoming indication message from link layer
            ServiceType::L_Data_Ind => {
                trace!("NL L_Data_Ind addr_typ: {:?}", msg.get_address_type());

                // Check for individual address duplication.
                // If we receive a message with our own individual address as source,
                // another device on the bus has the same address - set the duplication flag.
                // This is a "sticky" flag that stays set until device reset.
                if msg.get_source_addr() == self.state.individual_address() {
                    if !self.interface_objects.device_control().address_duplication() {
                        warn!("NL: Individual address duplication detected!");
                        self.interface_objects.set_address_duplication(true);
                    }
                }

                match msg.get_address_type() {
                    AddressType::Group => msg.set_service_type(ServiceType::N_GroupData_Ind),
                    AddressType::Broadcast => msg.set_service_type(ServiceType::N_Broadcast_Ind),
                    AddressType::Individual => msg.set_service_type(ServiceType::N_Data_Ind),
                    AddressType::SystemBroadcast => msg.set_service_type(ServiceType::N_SystemBroadcast_Ind),
                    _ => unreachable!(),
                }

                msg.convert_hop_count_to_hop_count_type();

                // Send message up to transport layer
                debug!("NL -> TL: {:?}", msg);
                self.transport_layer.send(LayerOp::Indication(msg)).await;
            }

            // Everything else is unhandled
            _ => {}
        }
    }

    async fn handle_request(&mut self, msg: RequestMessage<Buffer<'static>>) -> ConfirmationMessage<Buffer<'static>> {
        debug!("NL request: {:?}", msg);

        // Extract inner message - we need to work with the KnxMessageBuffer directly
        // because we're transforming a request into a different request for the link layer
        let mut msg = msg.into_inner();

        match msg.service_type() {
            // Incoming requests from transport layer
            s @ (ServiceType::N_Data_Req
            | ServiceType::N_GroupData_Req
            | ServiceType::N_Broadcast_Req
            | ServiceType::N_SystemBroadcast_Req) => {
                // Build a proper control field, this essentially only leaves the priority untouched
                let ctrl = msg.ctrl_field_mut();
                ctrl.set_ft(FrameType::Standard);
                ctrl.set_r(Repetition::AllowRepetition);
                ctrl.set_a(AckType::AckDontCare);
                ctrl.set_c(Confirm::NoError);

                msg.convert_hop_count_type_to_hop_count(self.routing_count());
                msg.set_source_addr(self.state.individual_address());
                msg.set_service_type(ServiceType::L_Data_Req);

                // This also sets the SBC flag in CTRL and the
                // destination address to 0 for the broadcasts
                match s {
                    ServiceType::N_Data_Req => {
                        msg.set_address_type(AddressType::Individual);
                    }
                    ServiceType::N_GroupData_Req => {
                        msg.set_address_type(AddressType::Group);
                    }
                    ServiceType::N_Broadcast_Req => {
                        msg.set_dest_addr(DestinationAddress::Broadcast);
                    }
                    ServiceType::N_SystemBroadcast_Req => {
                        msg.set_dest_addr(DestinationAddress::SystemBroadcast);
                    }
                    _ => unreachable!(),
                }

                debug!("NL -> LL: {:?}", msg);

                // Send to link layer using request pattern to get confirmation
                // Wrap as RequestMessage for the link layer
                let link_confirmation = self.link_layer.request(RequestMessage::request(msg)).await;

                // Convert link confirmation back to network confirmation
                // We need to transform the confirmation message's service type
                let mut network_confirmation = link_confirmation.into_inner();
                match network_confirmation.get_address_type() {
                    AddressType::Group => network_confirmation.set_service_type(ServiceType::N_GroupData_Con),
                    AddressType::Broadcast => network_confirmation.set_service_type(ServiceType::N_Broadcast_Con),
                    AddressType::Individual => network_confirmation.set_service_type(ServiceType::N_Data_Con),
                    AddressType::SystemBroadcast => {
                        network_confirmation.set_service_type(ServiceType::N_SystemBroadcast_Con)
                    }
                    _ => unreachable!(),
                }

                network_confirmation.convert_hop_count_to_hop_count_type();

                ConfirmationMessage::confirmation(network_confirmation)
            }

            // Everything else is unhandled - return error confirmation
            _ => {
                warn!("NL unhandled service type: {:?}", msg.service_type());
                msg.error().build()
            }
        }
    }
}
