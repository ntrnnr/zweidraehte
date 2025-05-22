#![allow(async_fn_in_trait)]

use embassy_sync::blocking_mutex::raw::RawMutex;
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

// ############################################################################

// use embassy_sync::blocking_mutex::raw::NoopRawMutex;
// use embassy_sync::channel::{Channel, DynamicSender, Sender};

// pub struct Request<'a, M, R> {
//     message: Option<M>,
//     reply_to: &'a DynamicSender<'a, R>,
// }

// unsafe impl<'a, M, R> Send for Request<'a, M, R> {}

// impl<'a, M, R> Request<'a, M, R> {
//     fn new(message: M, reply_to: &'a DynamicSender<'a, R>) -> Self {
//         Self {
//             message: Some(message),
//             reply_to,
//         }
//     }

//     /// Process the message using a closure.
//     ///
//     /// The return value of the closure is used as the response.
//     pub async fn process<F: FnOnce(M) -> R>(mut self, f: F) {
//         let reply = f(self.message.take().unwrap());
//         self.reply_to.send(reply).await;
//     }

//     /// Reply to the request using the provided value.
//     pub async fn reply(self, value: R) {
//         self.reply_to.send(value).await
//     }

//     /// Get a reference to the underlying message
//     pub fn get(&self) -> &M {
//         self.message.as_ref().unwrap()
//     }

//     /// Get a mutable reference to the underlying message
//     pub fn get_mut(&mut self) -> &mut M {
//         self.message.as_mut().unwrap()
//     }
// }

// impl<'a, M, R> AsRef<M> for Request<'a, M, R> {
//     fn as_ref(&self) -> &M {
//         self.message.as_ref().unwrap()
//     }
// }

// impl<'a, M, R> AsMut<M> for Request<'a, M, R> {
//     fn as_mut(&mut self) -> &mut M {
//         self.message.as_mut().unwrap()
//     }
// }

// pub trait ActorRequest<M, R> {
//     /// Attempts to send a message and wait for the response
//     async fn request(&self, message: M) -> Option<R>;
// }

// impl<'a, M, R> ActorRequest<M, R> for DynamicSender<'a, Request<'a, M, R>> {
//     async fn request(&self, message: M) -> Option<R> {
//         // let channel: Channel<NoopRawMutex, R, 1> = Channel::new();
//         // let sender: DynamicSender<'_, R> = channel.sender().into();
//         // //let bomb = DropBomb::new();

//         // // We guarantee that channel lives until we've been notified on it, at which
//         // // point its out of reach for the replier.
//         // let reply_to = unsafe {
//         //     core::mem::transmute::<
//         //         &embassy_sync::channel::DynamicSender<'_, R>,
//         //         &embassy_sync::channel::DynamicSender<'_, R>,
//         //     >(&sender)
//         // };
//         // let message = Request::new(message, reply_to);
//         // self.notify(message).await;
//         // let res = channel.receive().await;

//         // //bomb.defuse();
//         // res

//         None
//     }
// }

// impl<'a, M, R, const N: usize> ActorRequest<M, R>
//     for Sender<'a, NoopRawMutex, Request<'a, M, R>, N>
// {
//     async fn request(&self, message: M) -> Option<R> {
//         // let channel: Channel<NoopRawMutex, R, 1> = Channel::new();
//         // let sender: DynamicSender<'_, R> = channel.sender().into();
//         // //let bomb = DropBomb::new();

//         // // We guarantee that channel lives until we've been notified on it, at which
//         // // point its out of reach for the replier.
//         // let reply_to = unsafe {
//         //     core::mem::transmute::<
//         //         &embassy_sync::channel::DynamicSender<'_, R>,
//         //         &embassy_sync::channel::DynamicSender<'_, R>,
//         //     >(&sender)
//         // };
//         // let message = Request::new(message, reply_to);
//         // self.notify(message).await;
//         // let res = channel.receive().await;

//         // //bomb.defuse();
//         // res

//         None
//     }
// }

// ############################################################################

pub mod application;
pub mod network;
pub mod transport;
