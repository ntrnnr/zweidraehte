use core::cell::RefCell;

use embassy_sync::channel::DynamicSender;

use super::{Inbox, Layer};

use crate::{
    StackDefinition,
    messages::{buffers::Buffer, knx::*},
    objects::tables::{AddressTable, LoadableTable},
};

/// Transport layer for the KNX stack
pub struct TransportLayer<'a, D: StackDefinition> {
    adt: &'a RefCell<D::ADT>,
    network_layer: DynamicSender<'a, KnxMessageBuffer<Buffer<'static>>>,
    application_layer: DynamicSender<'a, KnxMessageBuffer<Buffer<'static>>>,
}

impl<'a, D: StackDefinition> TransportLayer<'a, D> {
    /// Create a new Transport Layer with the device's individual address
    pub fn new(
        adt: &'a RefCell<D::ADT>,
        network_layer: DynamicSender<'a, KnxMessageBuffer<Buffer<'static>>>,
        application_layer: DynamicSender<'a, KnxMessageBuffer<Buffer<'static>>>,
    ) -> Self {
        Self { adt, network_layer, application_layer }
    }
}

impl<'a, D: StackDefinition> Layer<'a> for TransportLayer<'a, D> {
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<Self::Message>,
    {
        loop {
            let mut msg = inbox.next().await;
            trace!("Transport Layer received message: {:?}", msg);

            match msg.service_type() {
                // Incoming indication and confirmation message from network layer
                t @ (ServiceType::N_GroupData_Ind | ServiceType::N_GroupData_Con) => {
                    // To forward this indication to the application layer, the following conditions must be met:
                    //   1. TPCI is unnumbered data group
                    //   2. ADT needs to be loaded
                    //   3. Group address needs to be converted to connection number using ADT
                    if let Some(Tpci::DataGroup) = msg.get_tpci()
                        && let DestinationAddress::Group(g) = msg.get_dest_addr()
                        && self.adt.borrow().is_loaded()
                        && let Some(conn_nr) = self.adt.borrow().get_tsap(g)
                    {
                        msg.set_connection_nr(conn_nr);

                        match t {
                            ServiceType::N_GroupData_Ind => msg.set_service_type(ServiceType::T_GroupData_Ind),
                            ServiceType::N_GroupData_Con => msg.set_service_type(ServiceType::T_GroupData_Con),
                            _ => unreachable!(),
                        };

                        trace!("Transport layer sending to Application layer: {:x?}", msg);
                        self.application_layer.send(msg).await;
                    }
                }

                t @ (ServiceType::N_Broadcast_Ind | ServiceType::N_Broadcast_Con) => {
                    if let Some(Tpci::DataBroadcast) = msg.get_tpci() {
                        match t {
                            ServiceType::N_Broadcast_Ind => msg.set_service_type(ServiceType::T_Broadcast_Ind),
                            ServiceType::N_Broadcast_Con => msg.set_service_type(ServiceType::T_Broadcast_Con),
                            _ => unreachable!(),
                        };

                        trace!("Transport layer sending to Application layer: {:x?}", msg);
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

                        trace!("Transport layer sending to Application layer: {:x?}", msg);
                        self.application_layer.send(msg).await;
                    }
                }

                // FIXME: maximum connection state machine action going on here - implement this later
                ServiceType::N_Data_Ind => {}
                ServiceType::N_Data_Con => {}

                // Incoming requests from application layer
                // ADT must be loaded and the TSAP must be converted to a group address
                ServiceType::T_GroupData_Req => {
                    trace!("Received T_GroupData_Req: {:?}", msg);

                    if self.adt.borrow().is_loaded()
                        && let Some(dst_addr) = self.adt.borrow().get_address(msg.get_connection_nr())
                    {
                        trace!("Converting connection number to group address: {}", dst_addr);

                        msg.set_tpci(Tpci::DataGroup);
                        msg.set_dest_addr(DestinationAddress::Group(dst_addr));
                        msg.set_service_type(ServiceType::N_GroupData_Req);

                        trace!("Transport layer sending to Network layer: {:x?}", msg);
                        self.network_layer.send(msg).await;
                    } else {
                        trace!("ADT not loaded or invalid connection number: {}", msg.get_connection_nr());

                        msg.set_service_type(ServiceType::T_GroupData_Con);
                        msg.ctrl_field_mut().set_c(Confirm::Err);
                        trace!("Transport layer sending to Application layer: {:x?}", msg);
                        self.application_layer.send(msg).await;
                    }
                }

                ServiceType::T_Broadcast_Req => {
                    msg.set_tpci(Tpci::DataBroadcast);
                    msg.set_service_type(ServiceType::N_Broadcast_Req);
                    trace!("Transport layer sending to Network layer: {:x?}", msg);
                    self.network_layer.send(msg).await;
                }

                ServiceType::T_SystemBroadcast_Req => {
                    msg.set_tpci(Tpci::DataSystemBroadcast);
                    msg.set_service_type(ServiceType::N_SystemBroadcast_Req);
                    trace!("Transport layer sending to Network layer: {:x?}", msg);
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
