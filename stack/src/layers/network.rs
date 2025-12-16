use embassy_sync::channel::DynamicSender;

use crate::messages::knx::*;
use crate::{address::IndividualAddress, messages::buffers::Buffer};

use super::{ActorRequest, Inbox, Layer, LayerOp};

/// Network layer for the KNX stack
pub struct NetworkLayer<'a> {
    device_addr: IndividualAddress,
    default_hop_count: u8,

    link_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    transport_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
}

impl<'a> NetworkLayer<'a> {
    /// Create a new Network Layer with the device's individual address
    pub fn new(
        device_addr: IndividualAddress,
        default_hop_count: u8,

        link_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
        transport_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    ) -> Self {
        Self { device_addr, default_hop_count, link_layer, transport_layer }
    }
}

impl<'a> Layer<'a> for NetworkLayer<'a> {
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Message>>,
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

impl<'a> NetworkLayer<'a> {
    async fn handle_indication(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
        debug!("NL indication: {:?}", msg);

        match msg.service_type() {
            // Incoming indication message from link layer
            ServiceType::L_Data_Ind => {
                trace!("NL L_Data_Ind addr_typ: {:?}", msg.get_address_type());

                match msg.get_address_type() {
                    AddressType::Group => msg.set_service_type(ServiceType::N_GroupData_Ind),
                    AddressType::Broadcast => msg.set_service_type(ServiceType::N_Broadcast_Ind),
                    AddressType::Individual => msg.set_service_type(ServiceType::N_Data_Ind),
                    AddressType::SystemBroadcast => msg.set_service_type(ServiceType::N_SystemBroadcast_Ind),
                    _ => unreachable!(),
                }

                msg.convert_hop_count_to_hop_count_type();

                // Send message up to transport layer
                debug!("NL -> TL: {:x?}", msg);
                self.transport_layer.send(LayerOp::Indication(msg)).await;
            }

            // Everything else is unhandled
            _ => {}
        }
    }

    async fn handle_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> KnxMessageBuffer<Buffer<'static>> {
        debug!("NL request: {:?}", msg);

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

                msg.convert_hop_count_type_to_hop_count(self.default_hop_count);
                msg.set_source_addr(self.device_addr);
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

                debug!("NL -> LL: {:x?}", msg);

                // Send to link layer using request pattern to get confirmation
                let link_confirmation = self.link_layer.request(msg).await;

                // Convert link confirmation back to network confirmation
                let mut network_confirmation = link_confirmation;
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

                network_confirmation
            }

            // Everything else is unhandled - return error confirmation
            _ => {
                warn!("NL unhandled service type: {:?}", msg.service_type());
                // Set error and return
                msg.ctrl_field_mut().set_c(Confirm::Err);
                msg
            }
        }
    }
}
