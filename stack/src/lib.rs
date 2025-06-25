#![cfg_attr(not(test), no_std)]
#![feature(slice_as_array)]
#![feature(const_trait_impl)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![feature(generic_arg_infer)]
#![feature(type_alias_impl_trait)]
#![feature(never_type)]

mod fmt;

#[macro_use]
mod macros;

pub mod address;
pub mod bcus;
pub mod dpt;
pub mod error;
pub mod layers;
pub mod messages;
pub mod objects;
pub mod util;

use core::{cell::RefCell, mem::MaybeUninit};

use const_default::ConstDefault;
use embassy_sync::{
    blocking_mutex::raw::{NoopRawMutex, RawMutex},
    channel::{Channel, DynamicReceiver, DynamicSender, Receiver, Sender},
};
use messages::knx::KnxMessageBuffer;
use objects::tables::AssociationTable;

use crate::layers::{
    ActorRequest, Layer, Request,
    application::{ApplicationLayer, ApplicationLayerService, ApplicationLayerServiceResponse},
    network::NetworkLayer,
    test_linklayer::LinkLayer,
    transport::TransportLayer,
};
use crate::messages::buffers::{Buffer, BufferManager, DynBufferManager};
use crate::objects::{
    comm::{ComObjectStatus, ComObjects},
    tables::{AddressTable, CommunicationObjectTable, TableMemory},
};
use crate::{address::IndividualAddress, layers::LayerOp};

pub trait StackDefinition {
    type ADT: AddressTable;
    type AST: AssociationTable;
    type COT: CommunicationObjectTable;
    type P: ConstDefault;
    type CO: ComObjects;
}

pub struct StackResources<D: StackDefinition, const BUF_SZ: usize = 128, const NUM_BUFS: usize = 4>
where
    D::ADT: AddressTable,
    D::AST: TableMemory,
    D::COT: CommunicationObjectTable,
    D::CO: ComObjects,
{
    inner: MaybeUninit<Inner<D>>,
    buffers: MaybeUninit<[[u8; BUF_SZ]; NUM_BUFS]>,
    buffer_manager: MaybeUninit<BufferManager<NUM_BUFS>>,
}

impl<D: StackDefinition, const BUF_SZ: usize, const NUM_BUFS: usize> StackResources<D, BUF_SZ, NUM_BUFS> {
    pub fn new() -> Self {
        Self { inner: MaybeUninit::uninit(), buffers: MaybeUninit::uninit(), buffer_manager: MaybeUninit::uninit() }
    }
}

/// KNX stack runner.
///
/// You must call [`Runner::run()`] in a background task for the KNX stack to work.
pub struct Runner<'d, D: StackDefinition> {
    stack: Stack<'d, D>,
    app_request_receiver: DynamicReceiver<'static, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
    linklayer_inject_receiver: DynamicReceiver<'static, KnxMessageBuffer<Buffer<'static>>>,
}

/// KNX stack handle
///
/// Use this to interact with the stack. It's `Copy`, so you can pass
/// it by value instead of by reference.
#[derive(Copy, Clone)]
pub struct Stack<'d, D: StackDefinition> {
    inner: &'d Inner<D>,
    app_request_sender: DynamicSender<'static, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
    linklayer_inject_sender: DynamicSender<'static, KnxMessageBuffer<Buffer<'static>>>,
}

pub(crate) struct Inner<D: StackDefinition> {
    buffer_manager: RefCell<DynBufferManager<'static>>,
    app_service_channel: Channel<NoopRawMutex, Request<ApplicationLayerService, ApplicationLayerServiceResponse>, 1>,
    linklayer_inject_channel: Channel<NoopRawMutex, KnxMessageBuffer<Buffer<'static>>, 1>,
    adt: RefCell<D::ADT>,
    ast: RefCell<D::AST>,
    cot: RefCell<D::COT>,
    comm_objs: RefCell<D::CO>,
}

fn _assert_covariant<'a, 'b: 'a, D: StackDefinition>(x: Stack<'b, D>) -> Stack<'a, D> {
    x
}

// fn create_request_response_pair<M: RawMutex, MSG, RESP, const N: usize>(
//     channel: &'static Channel<M, Request<MSG, RESP>, N>,
// ) -> (DynamicSender<'static, Request<MSG, RESP>>, DynamicReceiver<'static, Request<MSG, RESP>>) {
//     let sender: DynamicSender<'_, Request<MSG, RESP>> = channel.sender().into();
//     let receiver: DynamicReceiver<'_, Request<MSG, RESP>> = channel.receiver().into();
//     (sender.into(), receiver.into())
// }

fn create_request_response_pair<M: RawMutex, MSG, const N: usize>(
    channel: &'static Channel<M, MSG, N>,
) -> (DynamicSender<'static, MSG>, DynamicReceiver<'static, MSG>) {
    let sender: DynamicSender<'_, MSG> = channel.sender().into();
    let receiver: DynamicReceiver<'_, MSG> = channel.receiver().into();
    (sender.into(), receiver.into())
}

pub fn new<'d, D: StackDefinition + Copy, const BUF_SZ: usize, const NUM_BUFS: usize>(
    resources: &'d mut StackResources<D, BUF_SZ, NUM_BUFS>,
    adt: D::ADT,
    ast: D::AST,
    cot: D::COT,
    comm_objs: D::CO,
) -> (Stack<'d, D>, Runner<'d, D>) {
    // SAFETY: We are creating a reference to the buffers that are stored in the `StackResources` struct,
    //         which lives at least as long as `Inner`
    let buffers = resources.buffers.write([[0; _]; _]);
    let buffer_manager: &'static mut BufferManager<NUM_BUFS> =
        unsafe { core::mem::transmute(resources.buffer_manager.write(BufferManager::new(buffers))) };

    let inner = Inner {
        buffer_manager: RefCell::new(buffer_manager.dyn_buffer_manager()),
        app_service_channel: Channel::new(),
        linklayer_inject_channel: Channel::new(),
        adt: RefCell::new(adt),
        ast: RefCell::new(ast),
        cot: RefCell::new(cot),
        comm_objs: RefCell::new(comm_objs),
    };

    let inner = &*resources.inner.write(inner);

    // SAFETY: We are creating a static reference to the channel held by the `Inner` struct,
    //         which is safe because it is guaranteed to live as long as the `Stack` or the `Runner`.
    let (app_request_sender, app_request_receiver) =
        create_request_response_pair::<NoopRawMutex, _, 1>(unsafe { core::mem::transmute(&inner.app_service_channel) });

    let (linklayer_inject_sender, linklayer_inject_receiver) =
        create_request_response_pair::<NoopRawMutex, _, 1>(unsafe {
            core::mem::transmute(&inner.linklayer_inject_channel)
        });

    let stack = Stack {
        inner,
        app_request_sender: app_request_sender.into(),
        linklayer_inject_sender: linklayer_inject_sender.into(),
    };
    let runner = Runner {
        stack,
        app_request_receiver: app_request_receiver.into(),
        linklayer_inject_receiver: linklayer_inject_receiver.into(),
    };

    (stack, runner)
}

impl<'d, D: StackDefinition> Runner<'d, D> {
    /// Run the KNX stack.app_service_channel
    ///
    /// You must call this in a background task, to process KNX messages.
    pub async fn run(self) -> ! {
        let ind_addr = IndividualAddress::new(1, 0, 1);

        // Create all the channels for layer to layer communication
        let ll_channel: Channel<NoopRawMutex, LayerOp<KnxMessageBuffer<Buffer<'static>>>, 1> = Channel::new();
        let nl_channel: Channel<NoopRawMutex, LayerOp<KnxMessageBuffer<Buffer<'static>>>, 1> = Channel::new();
        let tl_channel: Channel<NoopRawMutex, LayerOp<KnxMessageBuffer<Buffer<'static>>>, 1> = Channel::new();
        let al_channel: Channel<NoopRawMutex, LayerOp<KnxMessageBuffer<Buffer<'static>>>, 1> = Channel::new();

        // Create a link layer
        let mut link_layer =
            LinkLayer::new(ind_addr.clone(), nl_channel.sender().into(), self.linklayer_inject_receiver);

        // Create a network layer
        let mut network_layer = NetworkLayer::new(ind_addr, 6, ll_channel.sender().into(), tl_channel.sender().into());

        // Create a transport layer
        let mut transport_layer =
            TransportLayer::<'_, D>::new(&self.stack.inner.adt, nl_channel.sender().into(), al_channel.sender().into());

        // Create an application layer
        let mut application_layer = ApplicationLayer::<'_, D>::new(
            &self.stack.inner.buffer_manager,
            &self.stack.inner.ast,
            &self.stack.inner.cot,
            &self.stack.inner.comm_objs,
            self.app_request_receiver,
            tl_channel.sender().into(),
        );

        // Spawn and await all the tasks
        let ll_task = link_layer.process(ll_channel.receiver());
        let nl_task = network_layer.process(nl_channel.receiver());
        let tl_task = transport_layer.process(tl_channel.receiver());
        let al_task = application_layer.process(al_channel.receiver());
        let tasks = embassy_futures::join::join4(ll_task, nl_task, tl_task, al_task);
        tasks.await;

        unreachable!();
    }
}

impl<'d, D: StackDefinition> Stack<'d, D> {
    pub async fn group_value_write_request<T: AsRef<[u8]>>(&self, asap: u16, value: T) {
        // FIXME: check if app is running, if not, don't do anything?
        // FIXME: check if transmission state is not transmitting yet

        // Make sure the mutable borrow is dropped before sending the request
        // FIXME: Introduce a with()-closure to avoid this?
        {
            let mut comm_objs = self.inner.comm_objs.borrow_mut();
            comm_objs.set_status(asap, ComObjectStatus::WriteRequest);

            comm_objs.info_mut(asap).value.copy_from_slice(value.as_ref());
        }

        self.app_request_sender.request(ApplicationLayerService::GroupValueWriteRequest(asap)).await;
    }

    pub async fn group_value_read_request(&self, asap: u16) {
        // FIXME: check if app is running, if not, don't do anything?
        // FIXME: check if transmission state is not transmitting yet

        // Make sure the mutable borrow is dropped before sending the request
        // FIXME: Introduce a with()-closure to avoid this?
        {
            let mut comm_objs = self.inner.comm_objs.borrow_mut();
            comm_objs.set_status(asap, ComObjectStatus::ReadRequest);
        }

        self.app_request_sender.request(ApplicationLayerService::GroupValueReadRequest(asap)).await;
    }

    pub async fn debug_inject_linklayer_message(&self, msg: &[u8]) {
        use messages::knx::ServiceType;

        debug!("Injecting linklayer message: {:x?}", msg);

        let mut buffer = self.inner.buffer_manager.borrow_mut().alloc().await;
        // FIXME: add .fill_from_slice() to Buffer which sets the len and fills it?
        buffer.set_len(msg.len());
        buffer[..msg.len()].copy_from_slice(msg);

        let knx_buffer = KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind);
        self.linklayer_inject_sender.send(knx_buffer).await;
    }
}
