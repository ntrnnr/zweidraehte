use embassy_sync::channel::DynamicSender;

use super::{Inbox, Layer};

use crate::messages::knx::*;
use crate::{address::IndividualAddress, messages::buffers::Buffer};

/// Link layer for the KNX stack
pub struct LinkLayer<'a> {
    device_addr: IndividualAddress,
    network_layer: DynamicSender<'a, KnxMessageBuffer<Buffer<'static>>>,
}

impl<'a> LinkLayer<'a> {
    /// Create a new Link Layer with the device's individual address
    pub fn new(
        device_addr: IndividualAddress,
        network_layer: DynamicSender<'a, KnxMessageBuffer<Buffer<'static>>>,
    ) -> Self {
        Self {
            device_addr,
            network_layer,
        }
    }
}

impl<'a> Layer<'a> for LinkLayer<'a> {
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<Self::Message>,
    {
        loop {
            let mut msg = inbox.next().await;
            trace!(
                "Link Layer received message: {:?} {:x?}",
                msg,
                &msg.buf()[..]
            );

            match msg.service_type() {
                // Everything else is unhandled
                _ => {}
            }
        }
    }
}
