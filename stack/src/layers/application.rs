use std::{
    cell::RefCell,
    ops::{Deref, DerefMut},
};

use embassy_futures::select::{Either, select};
use embassy_sync::{blocking_mutex::Mutex, channel::DynamicSender};
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::DynamicReceiver};

use super::{Inbox, Layer, Request};

use crate::{StackDefinition, messages::knx::*};

#[derive(Debug)]
pub enum ApplicationLayerService {
    GroupValueWriteRequest(u16),
}

#[derive(Debug)]
pub enum ApplicationLayerServiceResponse {
    GroupValueWriteResponse,
}

/// Application layer for the KNX stack
pub struct ApplicationLayer<'a, B: Deref<Target = [u8]>, D: StackDefinition> {
    ast: &'a Mutex<NoopRawMutex, RefCell<D::AST>>,
    comm_objects: &'a Mutex<NoopRawMutex, RefCell<D::COMM_OBJS>>,
    app_request_receiver:
        DynamicReceiver<'static, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
    _transport_layer: DynamicSender<'a, KnxMessageBuffer<B>>,
    _phantom: std::marker::PhantomData<(B, D)>,
}

impl<'a, B: DerefMut<Target = [u8]>, D: StackDefinition> ApplicationLayer<'a, B, D> {
    /// Create a new Application Layer with the device's individual address
    pub fn new(
        ast: &'a Mutex<NoopRawMutex, RefCell<D::AST>>,
        comm_objects: &'a Mutex<NoopRawMutex, RefCell<D::COMM_OBJS>>,
        app_request_receiver: DynamicReceiver<
            'static,
            Request<ApplicationLayerService, ApplicationLayerServiceResponse>,
        >,
        transport_layer: DynamicSender<'a, KnxMessageBuffer<B>>,
    ) -> Self {
        Self {
            ast,
            comm_objects,
            app_request_receiver,
            _transport_layer: transport_layer,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, B: DerefMut<Target = [u8]> + std::fmt::Debug, D: StackDefinition> Layer<'a>
    for ApplicationLayer<'a, B, D>
{
    type Message = KnxMessageBuffer<B>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<Self::Message>,
    {
        loop {
            match select(inbox.next(), self.app_request_receiver.receive()).await {
                Either::First(msg) => {
                    let msg = inbox.next().await;
                    println!("Application Layer received message: {:x?}", msg);

                    match msg.service_type() {
                        // Everything else is unhandled
                        _ => {}
                    }
                }
                Either::Second(request) => match request.get() {
                    r @ ApplicationLayerService::GroupValueWriteRequest(_group_address) => {
                        println!("Application Layer received request: {:?}", r);
                        request
                            .reply(ApplicationLayerServiceResponse::GroupValueWriteResponse)
                            .await;
                    }
                },
            }
        }
    }
}
