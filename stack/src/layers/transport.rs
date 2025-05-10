use std::ops::{Deref, DerefMut};

use ector::{Actor, DynamicAddress, Inbox};

use crate::messages::knx::*;

/// Transport layer for the KNX stack
pub struct TransportLayer<B: Deref<Target = [u8]> + 'static> {
    //device_addr: IndividualAddress,
    _phantom: std::marker::PhantomData<B>,
    //network_layer: DynamicAddress<KnxMessageBuffer<B>>,
    //application_layer: DynamicAddress<KnxMessageBuffer<B>>,
}

impl<B: DerefMut<Target = [u8]>> TransportLayer<B> {
    /// Create a new Transport Layer with the device's individual address
    pub fn new(//device_addr: IndividualAddress,
        //network_layer: DynamicAddress<KnxMessageBuffer<B>>,
        //application_layer: DynamicAddress<KnxMessageBuffer<B>>,
    ) -> Self {
        Self {
            //device_addr,
            _phantom: std::marker::PhantomData,
            //network_layer,
            //application_layer,
        }
    }
}

impl<B: DerefMut<Target = [u8]> + std::fmt::Debug> Actor for TransportLayer<B> {
    type Message = KnxMessageBuffer<B>;

    async fn on_mount<M>(&mut self, _: DynamicAddress<Self::Message>, mut inbox: M) -> !
    where
        M: Inbox<Self::Message>,
    {
        loop {
            let mut msg = inbox.next().await;
            println!("Transport Layer received message: {:x?}", msg);

            match msg.service_type() {
                // Incoming indication and confirmation message from network layer
                ServiceType::N_GroupData_Ind => {
                    // TODO: check if TPCI is unnumbered data
                    //       sequence number needs to be zero (need to check this on bit level if it makes sense)
                    //       ADT needs to be loaded
                    //       Group address needs to be converted to connection number using ADT

                    msg.set_service_type(ServiceType::T_GroupData_Ind);

                    // Send message down to application layer
                    //self.application_layer.send(msg).await;
                }
                ServiceType::N_GroupData_Con => {}

                ServiceType::N_Broadcast_Ind => {}
                ServiceType::N_Broadcast_Con => {}
                ServiceType::N_SystemBroadcast_Ind => {}
                //ServiceType::N_SystemBroadcast_Con => {}
                ServiceType::N_Data_Ind => {}
                //ServiceType::N_Data_Con => {}

                // Incoming requests from application layer
                ServiceType::T_GroupData_Req => {}
                ServiceType::T_Broadcast_Req => {}
                ServiceType::T_SystemBroadcast_Req => {}
                ServiceType::T_Data_Con => {}

                // Everything else is unhandled
                _ => {}
            }
        }
    }
}
