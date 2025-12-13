use core::cell::RefCell;

use embassy_futures::select::{Either, select};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{DynamicReceiver, DynamicSender},
    pubsub::{PubSubBehavior, PubSubChannel},
};

use super::{ActorRequest, Inbox, Layer, LayerOp, Request};

use crate::{
    StackDefinition,
    messages::{
        buffers::{Buffer, DynBufferManager},
        knx::*,
    },
    objects::{
        comm::{ComObjectEvent, ComObjectIndex, ComObjectStatus, ComObjects},
        tables::{AssociationTable, CommunicationObjectTable},
    },
};

#[derive(Debug)]
pub enum ApplicationLayerService {
    GroupValueWriteRequest(u16),
    GroupValueReadRequest(u16),
}

#[derive(Debug)]
pub enum ApplicationLayerServiceResponse {
    GroupValueWriteResponse,
    GroupValueReadResponse,
}

/// Application layer for the KNX stack
pub struct ApplicationLayer<'a, D: StackDefinition> {
    // Shared stack resources
    buffer_manager: &'a RefCell<DynBufferManager<'static>>,
    ast: &'a RefCell<D::AST>,
    cot: &'a RefCell<D::COT>,
    comm_objects: &'a RefCell<D::CO>,
    event_channel:
        &'a PubSubChannel<NoopRawMutex, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent), 4, 2, 1>,

    // Receiver for requests from the application to the application layer
    app_request_receiver: DynamicReceiver<'a, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,

    // Communication channel to the transport layer
    transport_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
}

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
    /// Create a new Application Layer
    pub fn new(
        buffer_manager: &'a RefCell<DynBufferManager<'static>>,
        ast: &'a RefCell<D::AST>,
        cot: &'a RefCell<D::COT>,
        comm_objects: &'a RefCell<D::CO>,
        event_channel: &'a PubSubChannel<
            NoopRawMutex,
            (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent),
            4,
            2,
            1,
        >,
        app_request_receiver: DynamicReceiver<'a, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
        transport_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    ) -> Self {
        Self { buffer_manager, ast, cot, comm_objects, event_channel, app_request_receiver, transport_layer }
    }
}

impl<'a, D: StackDefinition> Layer<'a> for ApplicationLayer<'a, D> {
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Message>>,
    {
        loop {
            match select(inbox.next(), self.app_request_receiver.receive()).await {
                Either::First(msg) => {
                    trace!("Application Layer received message: {:?}", msg);

                    match msg {
                        LayerOp::Indication(mut ind) => match ind.get_apci_code() {
                            a @ (ApciCode::GroupValueWrite | ApciCode::GroupValueResponse) => {
                                trace!("Received {:?}", a);
                                // FIXME: check if application is running (also check if tables are loaded?)

                                trace!("Incoming TSAP: {:?}", ind.get_connection_nr());

                                for asap in self.ast.borrow().asaps_for_tsap(ind.get_connection_nr()) {
                                    trace!("Processing ASAP: {}", asap);

                                    let Some(cot_info) = self.cot.borrow().get_object(asap) else {
                                        error!("Invalid ASAP: {}", asap);
                                        continue;
                                    };

                                    if matches!(a, ApciCode::GroupValueWrite)
                                        && (!cot_info.flags.communication_enable() || !cot_info.flags.write_enable())
                                    {
                                        trace!(
                                            "Received GroupValueWrite.ind for ASAP {}, but comm or write flag isn't set",
                                            asap
                                        );
                                        continue;
                                    }

                                    if matches!(a, ApciCode::GroupValueResponse)
                                        && (!cot_info.flags.communication_enable() || !cot_info.flags.update_enable())
                                    {
                                        trace!(
                                            "Received GroupValueResponse.ind for ASAP {}, but comm or update flag isn't set",
                                            asap
                                        );
                                        continue;
                                    }

                                    let (object_size, msg_offset) = match cot_info.object_type.size_in_bytes() {
                                        (s, true) => (s, offsets::MSG_APCI + 1),
                                        (s, false) => (s, offsets::MSG_APDU),
                                    };

                                    // FIXME: -1?
                                    // Check if incoming message is long enough to carry a comm object value
                                    if ind.len() as usize == object_size + msg_offset {
                                        // Set the APCI to all zeros, because we don't need it anymore
                                        // We do that so that we can just copy out the DPT even if the
                                        // object type is one of the small ones with <= 6 bit. If the APCI
                                        // wasn't all zeros in this case, we would copy the two lowermost
                                        // bits of the "small" APCI code with the comm object value

                                        ind.set_apci_code(ApciCode::Empty);

                                        {
                                            let mut objs = self.comm_objects.borrow_mut();

                                            objs.value_mut(asap)
                                                .copy_from_slice(&ind.buf()[msg_offset..msg_offset + object_size]);
                                            objs.set_status(asap, ComObjectStatus::Updated);
                                        }

                                        // Publish event to the event channel
                                        if let Some(index) =
                                            <<D as StackDefinition>::CO as ComObjects>::Index::from_index(asap)
                                        {
                                            match a {
                                                ApciCode::GroupValueWrite => {
                                                    self.event_channel
                                                        .publish_immediate((index, ComObjectEvent::Updated));
                                                }
                                                ApciCode::GroupValueResponse => {
                                                    self.event_channel
                                                        .publish_immediate((index, ComObjectEvent::ReadResponse));
                                                }
                                                _ => unreachable!(),
                                            }
                                        }

                                        trace!(
                                            "ASAP {} updated due to {:?}: {:x?}",
                                            asap,
                                            a,
                                            self.comm_objects.borrow().value(asap)
                                        );
                                    } else {
                                        error!("Length of telegram not enough to contain object value");
                                    }
                                }
                            }
                            ApciCode::GroupValueRead => {
                                trace!("Received GroupValueRead");

                                let tsap = ind.get_connection_nr();
                                trace!("Incoming TSAP: {:?}", tsap);

                                for asap in self.ast.borrow().asaps_for_tsap(tsap) {
                                    trace!("Processing GroupValueRead for ASAP: {}", asap);

                                    let Some(cot_info) = self.cot.borrow().get_object(asap) else {
                                        error!("Invalid ASAP: {}", asap);
                                        continue;
                                    };

                                    // Check if communication and read are enabled for this object
                                    if !cot_info.flags.communication_enable() || !cot_info.flags.read_enable() {
                                        trace!(
                                            "Received GroupValueRead.ind for ASAP {}, but comm or read flag isn't set",
                                            asap
                                        );
                                        continue;
                                    }

                                    // Determine the size and offset for the response
                                    let (object_size, msg_offset) = match cot_info.object_type.size_in_bytes() {
                                        (s, true) => (s, offsets::MSG_APCI + 1),
                                        (s, false) => (s, offsets::MSG_APDU),
                                    };

                                    trace!(
                                        "Sending GroupValueResponse for ASAP {} with TSAP {}, size {}",
                                        asap, tsap, object_size
                                    );

                                    // Allocate a new message for the response
                                    let msg_buf =
                                        self.buffer_manager.borrow().alloc_with_size(object_size + msg_offset).await;
                                    let mut msg = KnxMessageBuffer::new(msg_buf, ServiceType::T_GroupData_Req);

                                    // Fill in the message fields (but not APCI yet - it might overlap with data)
                                    msg.ctrl_field_mut().set_priority(cot_info.flags.priority());
                                    msg.set_connection_nr(tsap);

                                    // Copy the current value from the communication object
                                    msg.buf_mut()[msg_offset..msg_offset + object_size]
                                        .copy_from_slice(self.comm_objects.borrow().value(asap));

                                    // Set APCI code AFTER copying data to avoid overwriting when data fits in 6 bits
                                    msg.set_apci_code(ApciCode::GroupValueResponse);

                                    // Send the response to the transport layer and wait for confirmation
                                    let confirmation = self.transport_layer.request(msg).await;
                                    trace!(
                                        "Received confirmation for GroupValueResponse ASAP {} with TSAP {}: {:?}",
                                        asap,
                                        tsap,
                                        confirmation.service_type()
                                    );

                                    trace!(
                                        "Sent GroupValueResponse for ASAP {}: {:x?}",
                                        asap,
                                        self.comm_objects.borrow().value(asap)
                                    );

                                    // Publish read event to the event channel
                                    if let Some(index) =
                                        <<D as StackDefinition>::CO as ComObjects>::Index::from_index(asap)
                                    {
                                        self.event_channel.publish_immediate((index, ComObjectEvent::Read));
                                    }
                                }
                            }
                            _ => {
                                error!("Application Layer received unimplemented APCI: {:?}", ind.get_apci_code());
                                unimplemented!();
                            }
                        },
                        _ => unimplemented!(),
                    }
                }
                Either::Second(request) => match request.get() {
                    r @ ApplicationLayerService::GroupValueWriteRequest(asap) => {
                        trace!("Application Layer received group value write request: {:?}", r);

                        self.send_group_value_request(*asap, false).await;
                        request.reply(ApplicationLayerServiceResponse::GroupValueWriteResponse).await;
                    }
                    r @ ApplicationLayerService::GroupValueReadRequest(asap) => {
                        trace!("Application Layer received group value read request: {:?}", r);

                        self.send_group_value_request(*asap, true).await;
                        request.reply(ApplicationLayerServiceResponse::GroupValueWriteResponse).await;
                    }
                },
            }
        }
    }
}

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
    async fn send_group_value_request(&self, asap: u16, read: bool) {
        // FIXME: check if device is configured at all:
        //        following needs to be loaded: Addr, Assoc, Cotab and App

        let Some(cot_info) = self.cot.borrow().get_object(asap) else {
            error!("Invalid ASAP: {}", asap);
            // FIXME: return error to caller?
            return;
        };

        let status = *self.comm_objects.borrow().info(asap).status;

        if !read && status != ComObjectStatus::WriteRequest {
            return;
        }

        if read && status != ComObjectStatus::ReadRequest {
            return;
        }

        if !cot_info.flags.communication_enable() {
            self.comm_objects.borrow_mut().set_status(asap, ComObjectStatus::IdleOk);

            // FIXME: Tell caller about success?
            trace!("Communication object {} is not enabled for communication", asap);
            return;
        }

        if cot_info.flags.transmission_enable() {
            self.comm_objects.borrow_mut().set_status(asap, ComObjectStatus::Busy);

            // We only send to the first TSAP per spec
            if let Some(tsap) = self.ast.borrow().get_sending_tsap(asap) {
                trace!("Found sending TSAP {} for ASAP {}", tsap, asap);

                // Determine the length of this comm obj and the offset in the message
                // The offset can be 7 for objects with len <= 6 bits because it fits
                // into the unused six bits of the short APCI codes.
                let (object_size, msg_offset) = match (read, cot_info.object_type.size_in_bytes()) {
                    // GroupValueWrite.req
                    (false, (s, true)) => (s, offsets::MSG_APCI + 1),
                    (false, (s, false)) => (s, offsets::MSG_APDU),

                    // GroupValueRead.req
                    // We need at least 1 byte for the lowermost two bits of the APCI code,
                    // the lowermost six bits of this byte are unused
                    (true, _) => (1, offsets::MSG_APCI + 1),
                };

                trace!(
                    "Preparing {} request for ASAP {} with TSAP {}, comm object size {} and message offset {}",
                    if read { "GroupValueRead" } else { "GroupValueWrite" },
                    asap,
                    tsap,
                    object_size,
                    msg_offset
                );

                // Allocate a new message with the required size
                let msg_buf = self.buffer_manager.borrow().alloc_with_size(object_size + msg_offset).await;
                let mut msg = KnxMessageBuffer::new(msg_buf, ServiceType::T_GroupData_Req);

                // Fill in a few other fields
                msg.ctrl_field_mut().set_priority(cot_info.flags.priority());
                if read {
                    msg.set_apci_code(ApciCode::GroupValueRead);
                } else {
                    // Copy the value of the communication objet into the message
                    msg.buf_mut()[msg_offset..msg_offset + object_size]
                        .copy_from_slice(self.comm_objects.borrow().value(asap));

                    msg.set_apci_code(ApciCode::GroupValueWrite);
                }

                // Set connection number from sending assoc nr
                msg.set_connection_nr(tsap);

                // Send the request to the transport layer and wait for confirmation
                let confirmation = self.transport_layer.request(msg).await;
                trace!("Received confirmation for ASAP {} with TSAP {}: {:?}", asap, tsap, confirmation.service_type());

                // Update communication object status based on confirmation
                if confirmation.ctrl_field().c() == Confirm::NoError {
                    self.comm_objects.borrow_mut().set_status(asap, ComObjectStatus::IdleOk);
                } else {
                    self.comm_objects.borrow_mut().set_status(asap, ComObjectStatus::IdleError);
                }
            } else {
                self.comm_objects.borrow_mut().set_status(asap, ComObjectStatus::IdleError);

                error!(
                    "No sending TSAP for or transmission flag not set for ASAP {} - Flags: {:?}",
                    asap, cot_info.flags
                );
                trace!("{}", cot_info.flags.transmission_enable());
            }
        }
    }
}
