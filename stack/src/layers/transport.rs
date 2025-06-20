use core::cell::RefCell;

use embassy_sync::channel::DynamicSender;

use crate::{
    StackDefinition,
    messages::{buffers::Buffer, knx::*},
    objects::tables::{AddressTable, LoadableTable},
};

use super::{ActorRequest, Inbox, Layer, LayerOp};

/// Transport layer for the KNX stack
pub struct TransportLayer<'a, D: StackDefinition> {
    adt: &'a RefCell<D::ADT>,
    network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    application_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
}

impl<'a, D: StackDefinition> TransportLayer<'a, D> {
    /// Create a new Transport Layer with the device's individual address
    pub fn new(
        adt: &'a RefCell<D::ADT>,
        network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
        application_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    ) -> Self {
        Self { adt, network_layer, application_layer }
    }

    async fn handle_indication(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
        trace!("Transport Layer received message: {:?}", msg);

        match msg.service_type() {
            // Incoming indication message from network layer
            ServiceType::N_GroupData_Ind => {
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
                    msg.set_service_type(ServiceType::T_GroupData_Ind);

                    trace!("Transport layer sending to Application layer: {:x?}", msg);
                    self.application_layer.send(LayerOp::Indication(msg)).await;
                }
            }

            ServiceType::N_Broadcast_Ind => {
                if let Some(Tpci::DataBroadcast) = msg.get_tpci() {
                    msg.set_service_type(ServiceType::T_Broadcast_Ind);

                    trace!("Transport layer sending to Application layer: {:x?}", msg);
                    self.application_layer.send(LayerOp::Indication(msg)).await;
                }
            }

            ServiceType::N_SystemBroadcast_Ind => {
                if let Some(Tpci::DataSystemBroadcast) = msg.get_tpci() {
                    msg.set_service_type(ServiceType::T_SystemBroadcast_Ind);

                    trace!("Transport layer sending to Application layer: {:x?}", msg);
                    self.application_layer.send(LayerOp::Indication(msg)).await;
                }
            }

            // FIXME: maximum connection state machine action going on here - implement this later
            ServiceType::N_Data_Ind => {}

            // Everything else is unhandled
            _ => {}
        }
    }

    async fn handle_request(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> KnxMessageBuffer<Buffer<'static>> {
        trace!("Transport Layer received request: {:?}", msg);

        match msg.service_type() {
            // Incoming requests from application layer
            // ADT must be loaded and the TSAP must be converted to a group address
            ServiceType::T_GroupData_Req => {
                trace!("Received T_GroupData_Req: {:?}", msg);

                if self.adt.borrow().is_loaded()
                    && let Some(dst_addr) = self.adt.borrow().get_address(msg.get_connection_nr())
                {
                    trace!("Converting connection number to group address: {}", dst_addr);

                    // Store original service type and connection number for confirmation
                    let original_conn_nr = msg.get_connection_nr();

                    // Prepare message for network layer
                    msg.set_tpci(Tpci::DataGroup);
                    msg.set_dest_addr(DestinationAddress::Group(dst_addr));
                    msg.set_service_type(ServiceType::N_GroupData_Req);

                    trace!("Transport layer sending to Network layer: {:x?}", msg);

                    // Send to network layer using request pattern to get confirmation
                    let network_confirmation = self.network_layer.request(msg).await;

                    // Convert network confirmation to transport confirmation
                    let mut transport_confirmation = network_confirmation;
                    transport_confirmation.set_service_type(ServiceType::T_GroupData_Con);
                    transport_confirmation.set_connection_nr(original_conn_nr);

                    transport_confirmation
                } else {
                    trace!("ADT not loaded or invalid connection number: {}", msg.get_connection_nr());

                    msg.set_service_type(ServiceType::T_GroupData_Con);
                    msg.ctrl_field_mut().set_c(Confirm::Err);
                    msg
                }
            }

            ServiceType::T_Broadcast_Req => {
                msg.set_tpci(Tpci::DataBroadcast);
                msg.set_service_type(ServiceType::N_Broadcast_Req);
                trace!("Transport layer sending to Network layer: {:x?}", msg);

                // Send to network layer using request pattern to get confirmation
                let network_confirmation = self.network_layer.request(msg).await;

                // Convert network confirmation to transport confirmation
                let mut transport_confirmation = network_confirmation;
                transport_confirmation.set_service_type(ServiceType::T_Broadcast_Con);

                transport_confirmation
            }

            ServiceType::T_SystemBroadcast_Req => {
                msg.set_tpci(Tpci::DataSystemBroadcast);
                msg.set_service_type(ServiceType::N_SystemBroadcast_Req);
                trace!("Transport layer sending to Network layer: {:x?}", msg);

                // Send to network layer using request pattern to get confirmation
                let network_confirmation = self.network_layer.request(msg).await;

                // Convert network confirmation to transport confirmation
                let mut transport_confirmation = network_confirmation;
                transport_confirmation.set_service_type(ServiceType::T_SystemBroadcast_Con);

                transport_confirmation
            }

            // FIXME: maximum connection state machine action going on here - implement this later
            ServiceType::T_Data_Req => {
                // For now, return a dummy confirmation
                msg.set_service_type(ServiceType::T_Data_Con);
                msg.ctrl_field_mut().set_c(Confirm::NoError);
                msg
            }

            // Everything else is unhandled - return error confirmation
            _ => {
                trace!("Unhandled request service type: {:?}", msg.service_type());
                // Try to create an appropriate error response
                // This is a best-effort attempt to create a sensible error response
                match msg.service_type() {
                    ServiceType::T_GroupData_Req => {
                        msg.set_service_type(ServiceType::T_GroupData_Con);
                        msg.ctrl_field_mut().set_c(Confirm::Err);
                        msg
                    }
                    _ => {
                        // For unknown types, just set error and return
                        msg.ctrl_field_mut().set_c(Confirm::Err);
                        msg
                    }
                }
            }
        }
    }
}

impl<'a, D: StackDefinition> Layer<'a> for TransportLayer<'a, D> {
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Message>>,
    {
        loop {
            let layer_op = inbox.next().await;
            trace!("Transport Layer received layer op: {:?}", layer_op);

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
