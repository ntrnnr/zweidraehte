use std::ops::{Deref, DerefMut};

use embassy_sync::channel::DynamicSender;

use super::{Inbox, Layer};

use crate::{
    Shared, StackDefinition,
    messages::knx::*,
    objects::tables::{AddressTable, LoadableTable},
};

/// Transport layer for the KNX stack
pub struct TransportLayer<'a, B: Deref<Target = [u8]>, D: StackDefinition> {
    adt: &'a mut Shared<'a, D::ADT>,
    network_layer: DynamicSender<'a, KnxMessageBuffer<B>>,
    application_layer: DynamicSender<'a, KnxMessageBuffer<B>>,
    _phantom: std::marker::PhantomData<B>,
}

impl<'a, B: DerefMut<Target = [u8]>, D: StackDefinition> TransportLayer<'a, B, D> {
    /// Create a new Transport Layer with the device's individual address
    pub fn new(
        adt: &'a mut Shared<'a, D::ADT>,
        network_layer: DynamicSender<'a, KnxMessageBuffer<B>>,
        application_layer: DynamicSender<'a, KnxMessageBuffer<B>>,
    ) -> Self {
        Self {
            adt,
            network_layer,
            application_layer,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, B: DerefMut<Target = [u8]> + std::fmt::Debug, D: StackDefinition> Layer<'a>
    for TransportLayer<'a, B, D>
{
    type Message = KnxMessageBuffer<B>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<Self::Message>,
    {
        loop {
            let mut msg = inbox.next().await;
            println!("Transport Layer received message: {:x?}", msg);

            match msg.service_type() {
                // Incoming indication and confirmation message from network layer
                t @ (ServiceType::N_GroupData_Ind | ServiceType::N_GroupData_Con) => {
                    // To forward this indication to the application layer, the following conditions must be met:
                    //   1. TPCI is unnumbered data group
                    //   2. ADT needs to be loaded
                    //   3. Group address needs to be converted to connection number using ADT
                    if let Some(Tpci::DataGroup) = msg.get_tpci()
                        && let DestinationAddress::Group(g) = msg.get_dest_addr()
                        && let Some(conn_nr) = self
                            .adt
                            .with(|x| x.is_loaded().then_some(()).and_then(|_| x.get_tsap(g)))
                    {
                        // TODO: set connection number

                        match t {
                            ServiceType::N_GroupData_Ind => {
                                msg.set_service_type(ServiceType::T_GroupData_Ind)
                            }
                            ServiceType::N_GroupData_Con => {
                                msg.set_service_type(ServiceType::T_GroupData_Con)
                            }
                            _ => unreachable!(),
                        };

                        self.application_layer.send(msg).await;
                    }
                }

                t @ (ServiceType::N_Broadcast_Ind | ServiceType::N_Broadcast_Con) => {
                    if let Some(Tpci::DataBroadcast) = msg.get_tpci() {
                        match t {
                            ServiceType::N_Broadcast_Ind => {
                                msg.set_service_type(ServiceType::T_Broadcast_Ind)
                            }
                            ServiceType::N_Broadcast_Con => {
                                msg.set_service_type(ServiceType::T_Broadcast_Con)
                            }
                            _ => unreachable!(),
                        };

                        self.application_layer.send(msg).await;
                    }
                }

                t @ (ServiceType::N_SystemBroadcast_Ind | ServiceType::N_SystemBroadcast_Con) => {
                    if let Some(Tpci::DataSystemBroadcast) = msg.get_tpci() {
                        match t {
                            ServiceType::N_SystemBroadcast_Ind => {
                                msg.set_service_type(ServiceType::T_SystemBroadcast_Ind)
                            }
                            ServiceType::N_SystemBroadcast_Con => {
                                msg.set_service_type(ServiceType::T_SystemBroadcast_Con)
                            }
                            _ => unreachable!(),
                        };

                        self.application_layer.send(msg).await;
                    }
                }

                // FIXME: maximum connection state machine action going on here - implement this later
                ServiceType::N_Data_Ind => {}
                ServiceType::N_Data_Con => {}

                // Incoming requests from application layer
                ServiceType::T_GroupData_Req => {
                    // if ADT loaded && ConnNrToGroupAddr(&GroupAddr) conversion success {
                    //      TPCI = 0
                    //      SequNr = 0
                    //      DestAddr = GroupAddr
                    //      msg.set_service_type(ServiceType::N_GroupData_Req);
                    //      self.network_layer.send(msg).await;
                    //} else {
                    //      msg.set_service_type(ServiceType::T_GroupData_Con);
                    //      msgPtr[MSG_CONTROL] |= CF_CONFIRM;
                    //      self.application_layer.send(msg).await;
                    //}
                }

                ServiceType::T_Broadcast_Req => {
                    msg.set_tpci(Tpci::DataBroadcast);
                    msg.set_service_type(ServiceType::N_Broadcast_Req);
                    self.network_layer.send(msg).await;
                }

                ServiceType::T_SystemBroadcast_Req => {
                    msg.set_tpci(Tpci::DataSystemBroadcast);
                    msg.set_service_type(ServiceType::N_SystemBroadcast_Req);
                    self.network_layer.send(msg).await;
                }

                // FIXME: maximum connection state machine action going on here - implement this later
                ServiceType::T_Data_Req => {}

                // Everything else is unhandled
                _ => {}
            }
        }
    }
}
