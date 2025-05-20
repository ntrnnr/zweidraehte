use std::ops::{Deref, DerefMut};

use embassy_sync::channel::DynamicSender;

use super::{Inbox, Layer};

use crate::{Shared, StackDefinition, messages::knx::*};

/// Application layer for the KNX stack
pub struct ApplicationLayer<'a, B: Deref<Target = [u8]>, D: StackDefinition> {
    ast: &'a mut Shared<'a, D::AST>,
    comm_objects: &'a mut Shared<'a, D::COMM_OBJS>,
    _transport_layer: DynamicSender<'a, KnxMessageBuffer<B>>,
    _phantom: std::marker::PhantomData<(B, D)>,
}

impl<'a, B: DerefMut<Target = [u8]>, D: StackDefinition> ApplicationLayer<'a, B, D> {
    /// Create a new Application Layer with the device's individual address
    pub fn new(
        ast: &'a mut Shared<'a, D::AST>,
        comm_objects: &'a mut Shared<'a, D::COMM_OBJS>,
        transport_layer: DynamicSender<'a, KnxMessageBuffer<B>>,
    ) -> Self {
        Self {
            ast,
            comm_objects,
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
        //self.comm_objects.with(|x| x.)

        loop {
            let msg = inbox.next().await;
            println!("Application Layer received message: {:x?}", msg);

            match msg.service_type() {
                // Everything else is unhandled
                _ => {}
            }
        }
    }
}
