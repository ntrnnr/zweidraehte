use embassy_futures::select::{Either3, select3};
use embassy_sync::channel::DynamicSender;
use heapless::Deque;

use crate::messages::builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage, RequestMessage};
use crate::messages::knx::*;
use crate::objects::interface::HasDeviceObject;
use crate::{StackState, messages::buffers::Buffer};

use super::Inbox;

/// Network layer for the KNX stack.
///
/// Transforms service types between the link layer (L_Data) and the transport
/// layer (N_Data, N_GroupData, etc.), handles hop count conversion, source
/// address injection, and individual address duplication detection.
///
/// # Channel architecture
///
/// The NL communicates with its neighbors through three pairs of typed channels
/// (one pair per neighbor), with no blocking request-response patterns:
///
/// - From LL: indications (`ind_rx`) and confirmations (`conf_rx`)
/// - To LL: requests (`ll_request_tx`)
/// - To TL: indications (`tl_ind_tx`) and confirmations (`tl_conf_tx`)
/// - From TL: requests (`req_rx`)
pub struct NetworkLayer<'a, S: StackState, IO: HasDeviceObject> {
    state: &'a S,
    interface_objects: &'a IO,

    // Outgoing channels (to LL)
    ll_request_tx: DynamicSender<'a, RequestMessage<Buffer<'static>>>,

    // Outgoing channels (to TL)
    tl_ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    tl_conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,

    /// FIFO of address types from outgoing requests, needed to transform each
    /// LL confirmation's service type back to the correct N_*_Con form.
    /// Multiple requests can be in-flight because TL sends fire-and-forget;
    /// confirmations arrive in the same order as requests.
    pending_addr_types: Deque<AddressType, 4>,
}

impl<'a, S: StackState, IO: HasDeviceObject> NetworkLayer<'a, S, IO> {
    /// Create a new Network Layer.
    pub fn new(
        state: &'a S,
        interface_objects: &'a IO,
        ll_request_tx: DynamicSender<'a, RequestMessage<Buffer<'static>>>,
        tl_ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        tl_conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
    ) -> Self {
        Self { state, interface_objects, ll_request_tx, tl_ind_tx, tl_conf_tx, pending_addr_types: Deque::new() }
    }

    /// Get the current routing count from the device object.
    #[inline]
    fn routing_count(&self) -> u8 {
        self.interface_objects.routing_count_value()
    }

    /// Run the network layer event loop.
    ///
    /// Simultaneously awaits:
    /// - Requests from TL (to transform and forward to LL)
    /// - Indications from LL (to transform and forward to TL)
    /// - Confirmations from LL (to transform and forward to TL)
    pub async fn run(
        &mut self,
        mut req_rx: impl Inbox<RequestMessage<Buffer<'static>>>,
        mut ind_rx: impl Inbox<IndicationMessage<Buffer<'static>>>,
        mut conf_rx: impl Inbox<ConfirmationMessage<Buffer<'static>>>,
    ) -> ! {
        loop {
            match select3(req_rx.next(), ind_rx.next(), conf_rx.next()).await {
                Either3::First(msg) => {
                    self.handle_request(msg).await;
                }
                Either3::Second(msg) => {
                    self.handle_indication(msg).await;
                }
                Either3::Third(conf) => {
                    self.handle_ll_confirmation(conf).await;
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
                if msg.get_source_addr() == self.state.individual_address()
                    && !self.interface_objects.device_control().address_duplication() {
                        warn!("NL: Individual address duplication detected!");
                        self.interface_objects.set_address_duplication(true);
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
                self.tl_ind_tx.send(msg).await;
            }

            // Everything else is unhandled
            _ => {}
        }
    }

    /// Handle a request from the transport layer.
    ///
    /// Transforms the N_*_Req into an L_Data_Req and sends it to the LL
    /// (fire-and-forget). The confirmation will arrive later on `conf_rx`
    /// and be forwarded back to TL via `handle_ll_confirmation`.
    async fn handle_request(&mut self, msg: RequestMessage<Buffer<'static>>) {
        debug!("NL request: {:?}", msg);

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
                self.ll_request_tx.send(RequestMessage::request(msg)).await;
            }

            // Everything else is unhandled - return error confirmation directly
            _ => {
                warn!("NL unhandled service type: {:?}", msg.service_type());
                let conf = msg.error().build();
                self.tl_conf_tx.send(conf).await;
            }
        }
    }

    /// Handle a confirmation from the link layer.
    ///
    /// Transforms the L_Data_Con back into the appropriate N_*_Con and
    /// forwards it to the transport layer.
    async fn handle_ll_confirmation(&mut self, conf: ConfirmationMessage<Buffer<'static>>) {
        debug!("NL LL confirmation: {:?}", conf);

        let mut msg = conf.into_inner();

        // Pop the address type from the FIFO — confirmations arrive in the same
        // order as the requests that produced them.
        if let Some(addr_type) = self.pending_addr_types.pop_front() {
            match addr_type {
                AddressType::Group => msg.set_service_type(ServiceType::N_GroupData_Con),
                AddressType::Broadcast => msg.set_service_type(ServiceType::N_Broadcast_Con),
                AddressType::Individual => msg.set_service_type(ServiceType::N_Data_Con),
                AddressType::SystemBroadcast => {
                    msg.set_service_type(ServiceType::N_SystemBroadcast_Con)
                }
                _ => unreachable!(),
            }

            msg.convert_hop_count_to_hop_count_type();
        } else {
            warn!("NL received LL confirmation with no pending request");
        }

        self.tl_conf_tx.send(ConfirmationMessage::confirmation(msg)).await;
    }
}
