use heapless::Deque;

use crate::{StackDefinition, StackState};
use crate::messages::knx::*;
use crate::messages::buffers::Buffer;
use crate::objects::interface::{HasDeviceObject, HasRoutingCount};
use crate::router::{Layer, Outbox};

/// Network layer for the KNX stack.
///
/// Transforms service types between the link layer (L_Data) and the transport
/// layer (N_Data, N_GroupData, etc.), handles hop count conversion, source
/// address injection, and individual address duplication detection.
///
/// In the router architecture, NL is a synchronous [`Layer`] that the
/// router dispatches messages to based on ServiceType. NL pushes
/// transformed messages to the [`Outbox`] for further routing.
pub struct NetworkLayer<'a, D: StackDefinition> {
    state: &'a D::State,
    interface_objects: &'a D::InterfaceObjects<'static>,

    /// FIFO of address types from outgoing requests, needed to transform each
    /// LL confirmation's service type back to the correct N_*_Con form.
    /// Multiple requests can be in-flight because TL sends fire-and-forget;
    /// confirmations arrive in the same order as requests.
    pending_addr_types: Deque<AddressType, 4>,
}

impl<'a, D: StackDefinition> NetworkLayer<'a, D> {
    /// Create a new Network Layer.
    pub fn new(
        state: &'a D::State,
        interface_objects: &'a D::InterfaceObjects<'static>,
    ) -> Self {
        Self { state, interface_objects, pending_addr_types: Deque::new() }
    }
}

impl<D: StackDefinition> Layer for NetworkLayer<'_, D> {
    const HANDLES: &'static [ServiceType] = &[
        // Indications from LL (upward)
        ServiceType::L_Data_Ind,
        // Confirmations from LL (upward)
        ServiceType::L_Data_Con,
        // Requests from TL (downward)
        ServiceType::N_Data_Req,
        ServiceType::N_GroupData_Req,
        ServiceType::N_Broadcast_Req,
        ServiceType::N_SystemBroadcast_Req,
    ];

    fn process(
        &mut self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
        outbox: &mut Outbox,
    ) {
        match msg.service_type() {
            // =================================================================
            // Indications from link layer (upward: L_Data_Ind → N_*_Ind)
            // =================================================================
            ServiceType::L_Data_Ind => {
                debug!("NL indication: {:?}", msg);
                trace!("NL L_Data_Ind addr_typ: {:?}", msg.get_address_type());

                // Check for individual address duplication.
                // If we receive a message with our own individual address as source,
                // another device on the bus has the same address — set the
                // duplication flag. This is a "sticky" flag that stays set until
                // device reset.
                if msg.get_source_addr() == self.state.individual_address()
                    && !self.interface_objects.device_control().address_duplication()
                {
                    warn!("NL: Individual address duplication detected!");
                    self.interface_objects.set_address_duplication(true);
                }

                match msg.get_address_type() {
                    AddressType::Group => msg.set_service_type(ServiceType::N_GroupData_Ind),
                    AddressType::Broadcast => msg.set_service_type(ServiceType::N_Broadcast_Ind),
                    AddressType::Individual => msg.set_service_type(ServiceType::N_Data_Ind),
                    AddressType::SystemBroadcast => {
                        msg.set_service_type(ServiceType::N_SystemBroadcast_Ind)
                    }
                    _ => unreachable!(),
                }

                msg.convert_hop_count_to_hop_count_type();

                debug!("NL -> TL: {:?}", msg);
                outbox.push(msg);
            }

            // =================================================================
            // Requests from transport layer (downward: N_*_Req → L_Data_Req)
            // =================================================================
            s @ (ServiceType::N_Data_Req
            | ServiceType::N_GroupData_Req
            | ServiceType::N_Broadcast_Req
            | ServiceType::N_SystemBroadcast_Req) => {
                debug!("NL request: {:?}", msg);

                // Build a proper control field — only the priority is preserved
                // from the incoming message.
                let ctrl = msg.ctrl_field_mut();
                ctrl.set_ft(FrameType::Standard);
                ctrl.set_r(Repetition::AllowRepetition);
                ctrl.set_a(AckType::AckDontCare);
                ctrl.set_c(Confirm::NoError);

                msg.convert_hop_count_type_to_hop_count(self.state.routing_count());
                msg.set_source_addr(self.state.individual_address());
                msg.set_service_type(ServiceType::L_Data_Req);

                // Set address type and destination address. For broadcasts,
                // also sets the SBC flag in CTRL and the destination address
                // to 0.
                let addr_type = match s {
                    ServiceType::N_Data_Req => {
                        msg.set_address_type(AddressType::Individual);
                        AddressType::Individual
                    }
                    ServiceType::N_GroupData_Req => {
                        msg.set_address_type(AddressType::Group);
                        AddressType::Group
                    }
                    ServiceType::N_Broadcast_Req => {
                        msg.set_dest_addr(DestinationAddress::Broadcast);
                        AddressType::Broadcast
                    }
                    ServiceType::N_SystemBroadcast_Req => {
                        msg.set_dest_addr(DestinationAddress::SystemBroadcast);
                        AddressType::SystemBroadcast
                    }
                    _ => unreachable!(),
                };

                // Push the address type so we can transform the confirmation
                // back to the correct N_*_Con service type when it arrives.
                // Multiple requests can be in-flight because TL sends
                // fire-and-forget; the FIFO matches them in order.
                if self.pending_addr_types.push_back(addr_type).is_err() {
                    error!("NL pending address type queue full, dropping");
                }

                debug!("NL -> LL: {:?}", msg);
                outbox.push(msg);
            }

            // =================================================================
            // Confirmations from link layer (upward: L_Data_Con → N_*_Con)
            // =================================================================
            ServiceType::L_Data_Con => {
                debug!("NL LL confirmation: {:?}", msg);

                // Pop the address type from the FIFO — confirmations arrive in
                // the same order as the requests that produced them.
                if let Some(addr_type) = self.pending_addr_types.pop_front() {
                    match addr_type {
                        AddressType::Group => {
                            msg.set_service_type(ServiceType::N_GroupData_Con)
                        }
                        AddressType::Broadcast => {
                            msg.set_service_type(ServiceType::N_Broadcast_Con)
                        }
                        AddressType::Individual => {
                            msg.set_service_type(ServiceType::N_Data_Con)
                        }
                        AddressType::SystemBroadcast => {
                            msg.set_service_type(ServiceType::N_SystemBroadcast_Con)
                        }
                        _ => unreachable!(),
                    }

                    msg.convert_hop_count_to_hop_count_type();
                } else {
                    warn!("NL received LL confirmation with no pending request");
                }

                outbox.push(msg);
            }

            // Unreachable: the dispatch table only routes HANDLES to us.
            _ => unreachable!(),
        }
    }
}
