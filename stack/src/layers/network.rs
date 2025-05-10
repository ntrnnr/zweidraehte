use std::ops::{Deref, DerefMut};

use ector::{Actor, DynamicAddress, Inbox};

use crate::address::IndividualAddress;
use crate::messages::knx::*;

/// Network layer for the KNX stack
pub struct NetworkLayer<B: Deref<Target = [u8]> + 'static> {
    device_addr: IndividualAddress,
    default_hop_count: u8,

    _phantom: std::marker::PhantomData<B>,
    //link_layer: DynamicAddress<KnxMessageBuffer<B>>,
    transport_layer: DynamicAddress<KnxMessageBuffer<B>>,
}

impl<B: DerefMut<Target = [u8]>> NetworkLayer<B> {
    /// Create a new Network Layer with the device's individual address
    pub fn new(
        device_addr: IndividualAddress,
        default_hop_count: u8,

        //link_layer: DynamicAddress<KnxMessageBuffer<B>>,
        transport_layer: DynamicAddress<KnxMessageBuffer<B>>,
    ) -> Self {
        Self {
            device_addr,
            default_hop_count,
            _phantom: std::marker::PhantomData,
            //link_layer,
            transport_layer,
        }
    }
}

impl<B: DerefMut<Target = [u8]> + std::fmt::Debug> Actor for NetworkLayer<B> {
    type Message = KnxMessageBuffer<B>;

    async fn on_mount<M>(&mut self, _: DynamicAddress<Self::Message>, mut inbox: M) -> !
    where
        M: Inbox<Self::Message>,
    {
        loop {
            let mut msg = inbox.next().await;
            println!("Network Layer received message: {:x?}", msg);

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
                    //self.transport_layer.send(msg).await;
                }

                // Everything else is unhandled
                _ => {}
            }
        }
    }
}
