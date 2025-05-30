use embassy_sync::channel::DynamicSender;

use super::{Inbox, Layer};

use crate::messages::knx::*;
use crate::{address::IndividualAddress, messages::buffers::Buffer};

/// Network layer for the KNX stack
pub struct NetworkLayer<'a> {
    device_addr: IndividualAddress,
    default_hop_count: u8,

    link_layer: DynamicSender<'a, KnxMessageBuffer<Buffer<'static>>>,
    transport_layer: DynamicSender<'a, KnxMessageBuffer<Buffer<'static>>>,
}

impl<'a> NetworkLayer<'a> {
    /// Create a new Network Layer with the device's individual address
    pub fn new(
        device_addr: IndividualAddress,
        default_hop_count: u8,

        link_layer: DynamicSender<'a, KnxMessageBuffer<Buffer<'static>>>,
        transport_layer: DynamicSender<'a, KnxMessageBuffer<Buffer<'static>>>,
    ) -> Self {
        Self {
            device_addr,
            default_hop_count,
            link_layer,
            transport_layer,
        }
    }
}

impl<'a> Layer<'a> for NetworkLayer<'a> {
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<Self::Message>,
    {
        loop {
            let mut msg = inbox.next().await;
            trace!(
                "Network Layer received message: {:?} {:x?}",
                msg,
                &msg.buf()[..]
            );

            match msg.service_type() {
                // Incoming indication message from link layer
                ServiceType::L_Data_Ind => {
                    match msg.get_address_type() {
                        AddressType::Group => msg.set_service_type(ServiceType::N_GroupData_Ind),
                        AddressType::Broadcast => {
                            msg.set_service_type(ServiceType::N_Broadcast_Ind)
                        }
                        AddressType::Individual => msg.set_service_type(ServiceType::N_Data_Ind),
                        AddressType::SystemBroadcast => {
                            msg.set_service_type(ServiceType::N_SystemBroadcast_Ind)
                        }
                        _ => unreachable!(),
                    }

                    msg.convert_hop_count_to_hop_count_type();

                    // Send message up to transport layer
                    self.transport_layer.send(msg).await;
                }

                // Incoming requests from transport layer
                s @ (ServiceType::N_Data_Req
                | ServiceType::N_GroupData_Req
                | ServiceType::N_Broadcast_Req
                | ServiceType::N_SystemBroadcast_Req) => {
                    // Build a proper control field, this essentially only leaves the priority untouched
                    let ctrl = msg.ctrl_field_mut();
                    ctrl.set_ft(FrameType::Standard);
                    ctrl.set_r(Repetition::WasNotRepeated);
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

                    // Send message down to link layer
                    trace!("Network Layer sending to Link layer: {:x?}", &msg.buf()[..]);
                    self.link_layer.send(msg).await;
                }

                // Everything else is unhandled
                _ => {}
            }
        }
    }
}
