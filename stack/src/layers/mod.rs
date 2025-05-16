#![allow(async_fn_in_trait)]

use ector::mutex::RawMutex;
use embassy_sync::channel::Receiver;

pub trait Inbox<M> {
    #[must_use = "Must set response for message"]
    async fn next(&mut self) -> M;
}

impl<'ch, M, MUT, const QUEUE_SIZE: usize> Inbox<M> for Receiver<'ch, MUT, M, QUEUE_SIZE>
where
    M: 'ch,
    MUT: RawMutex,
{
    async fn next(&mut self) -> M {
        self.receive().await
    }
}

pub trait Layer<'a>: Sized {
    type Message;

    async fn process<M>(&mut self, _: M) -> !
    where
        M: Inbox<Self::Message>;
}

pub mod application;
pub mod network;
pub mod transport;
