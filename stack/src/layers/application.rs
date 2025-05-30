use core::cell::RefCell;

use embassy_futures::select::{Either, select};
use embassy_sync::channel::{DynamicReceiver, DynamicSender};

use super::{Inbox, Layer, Request};

use crate::{
    StackDefinition,
    messages::{
        buffers::{Buffer, DynBufferManager},
        knx::*,
    },
    objects::{
        comm::{ComObjectStatus, ComObjects},
        tables::{AssociationTable, CommunicationObjectTable},
    },
};

#[derive(Debug)]
pub enum ApplicationLayerService {
    GroupValueWriteRequest(u16),
}

#[derive(Debug)]
pub enum ApplicationLayerServiceResponse {
    GroupValueWriteResponse,
}

/// Application layer for the KNX stack
pub struct ApplicationLayer<'a, D: StackDefinition> {
    buffer_manager: &'a RefCell<DynBufferManager<'static>>,
    ast: &'a RefCell<D::AST>,
    cot: &'a RefCell<D::COT>,
    comm_objects: &'a RefCell<D::CO>,
    app_request_receiver:
        DynamicReceiver<'a, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
    transport_layer: DynamicSender<'a, KnxMessageBuffer<Buffer<'static>>>,
}

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
    /// Create a new Application Layer with the device's individual address
    pub fn new(
        buffer_manager: &'a RefCell<DynBufferManager<'static>>,
        ast: &'a RefCell<D::AST>,
        cot: &'a RefCell<D::COT>,
        comm_objects: &'a RefCell<D::CO>,
        app_request_receiver: DynamicReceiver<
            'a,
            Request<ApplicationLayerService, ApplicationLayerServiceResponse>,
        >,
        transport_layer: DynamicSender<'a, KnxMessageBuffer<Buffer<'static>>>,
    ) -> Self {
        Self {
            buffer_manager,
            ast,
            cot,
            comm_objects,
            app_request_receiver,
            transport_layer,
        }
    }
}

impl<'a, D: StackDefinition> Layer<'a> for ApplicationLayer<'a, D> {
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<Self::Message>,
    {
        loop {
            match select(inbox.next(), self.app_request_receiver.receive()).await {
                Either::First(msg) => {
                    let msg = inbox.next().await;
                    trace!("Application Layer received message: {:?}", msg);

                    match msg.service_type() {
                        // Everything else is unhandled
                        _ => {}
                    }
                }
                Either::Second(request) => match request.get() {
                    r @ ApplicationLayerService::GroupValueWriteRequest(asap) => {
                        trace!("Application Layer received request: {:?}", r);

                        // FIXME: check if device is configured at all:
                        //        following needs to be loaded: Addr, Assoc, Cotab and App

                        // FIXME: if we store pending TX, check if TX is pending, otherwise block

                        // FIXME: check if we even have a sending connection number (AL_GetSendingConnNr)

                        let Some(cot_info) = self.cot.borrow().get_object(*asap) else {
                            error!("Invalid ASAP: {}", asap);
                            // FIXME: return error to caller?
                            continue;
                        };

                        let state = *self.comm_objects.borrow().info(*asap).status;

                        if state != ComObjectStatus::WriteRequest {
                            continue;
                        }

                        if !cot_info.flags.communication_enable() {
                            self.comm_objects
                                .borrow_mut()
                                .set_status(*asap, ComObjectStatus::IdleOk);

                            // FIXME: Tell caller about success?
                            trace!(
                                "Communication object {} is not enabled for communication",
                                asap
                            );

                            continue;
                        }

                        if cot_info.flags.transmission_enable()
                            && let Some(conn_nr) = self.ast.borrow().get_sending_tsap(*asap)
                        {
                            self.comm_objects
                                .borrow_mut()
                                .set_status(*asap, ComObjectStatus::Busy);

                            // Determine the length of this comm obj and the offset in the message
                            // The offset can be 7 for objects with len <= 6 bits because it fits
                            // into the unused six bits of the short APCI codes.
                            let (object_size, msg_offset) =
                                match cot_info.object_type.size_in_bytes() {
                                    (s, true) => (s, offsets::MSG_APCI + 1),
                                    (s, false) => (s, offsets::MSG_APDU),
                                };

                            trace!(
                                "Preparing GroupValueWrite request for ASAP {} with connection number {}, comm object size {} and message offset {}",
                                asap, conn_nr, object_size, msg_offset
                            );

                            // Allocate a new message, set its type and length
                            let msg_buf = self.buffer_manager.borrow().alloc().await;
                            let mut msg = KnxMessageBuffer::new(
                                msg_buf,
                                ServiceType::T_GroupData_Req,
                                (object_size + msg_offset).try_into().unwrap(),
                            );

                            // Copy the value of the communication objet into the message
                            msg.buf_mut()[msg_offset..msg_offset + object_size]
                                .copy_from_slice(self.comm_objects.borrow().value(*asap));

                            // Fill in a few other fields
                            msg.ctrl_field_mut().set_priority(cot_info.flags.priority());
                            msg.set_apci_code(ApciCode::GroupValueWrite);

                            // Set connection number from sending assoc nr
                            msg.set_connection_nr(conn_nr);

                            // Hand message over to transport layer
                            self.transport_layer.send(msg).await;

                            trace!(
                                "Sent GroupValueWrite request to TL for ASAP {} with connection number {}",
                                asap, conn_nr
                            );

                            // FIXME: Store pending TX ASAP nr to react to when confirmation arrived?
                            // message.reply_to is channel to notify application about success
                        } else {
                            self.comm_objects
                                .borrow_mut()
                                .set_status(*asap, ComObjectStatus::IdleError);

                            error!(
                                "No sending connection number for or transmission flag not set for ASAP {} - Flags: {:?}",
                                asap, cot_info.flags
                            );
                            trace!("{}", cot_info.flags.transmission_enable());

                            // FIXME: Tell caller about error?
                        }

                        // request
                        //     .reply(ApplicationLayerServiceResponse::GroupValueWriteResponse)
                        //     .await;
                    }
                },
            }
        }
    }
}
