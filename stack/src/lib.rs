#![feature(slice_as_array)]
#![feature(const_trait_impl)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![feature(generic_arg_infer)]
#![feature(type_alias_impl_trait)]
#![feature(never_type)]

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

use address::IndividualAddress;
use const_default::ConstDefault;
use embassy_sync::{
    blocking_mutex::{Mutex, raw::NoopRawMutex},
    channel::{Channel, DynamicReceiver, DynamicSender, Receiver, Sender},
};
use layers::{
    ActorRequest, Layer, Request,
    application::{ApplicationLayer, ApplicationLayerService, ApplicationLayerServiceResponse},
    network::NetworkLayer,
    transport::TransportLayer,
};
use messages::buffers::Buffer;
use objects::{
    comm::{self, ComObjects},
    tables::{AddressTable, TableMemory, app::Application},
};

// FIXME: Introduce traits for AST, COT
pub trait StackDefinition {
    type ADT: AddressTable;
    type AST: TableMemory;
    type COT: TableMemory;
    type P: ConstDefault;
    type COMM_OBJS: ComObjects;
}

pub struct StackResources<D: StackDefinition> {
    inner: MaybeUninit<Inner<D>>,
    // pub ind_addr: IndividualAddress,
    // pub adt: D::ADT,
    // pub ast: D::AST,
    // pub cot: D::COT,
    // pub app: Application<D::P>,
    // pub comm_objs: D::COMM_OBJS,
}

impl<D: StackDefinition> StackResources<D> {
    pub fn new() -> Self {
        Self {
            inner: MaybeUninit::uninit(),
        }
    }
}

/// KNX stack runner.
///
/// You must call [`Runner::run()`] in a background task for the KNX stack to work.
pub struct Runner<'d, D: StackDefinition> {
    stack: Stack<'d, D>,
    app_request_receiver:
        DynamicReceiver<'static, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
}

/// KNX stack handle
///
/// Use this to interact with the stack. It's `Copy`, so you can pass
/// it by value instead of by reference.
#[derive(Copy, Clone)]
pub struct Stack<'d, D: StackDefinition> {
    inner: &'d Inner<D>,
    app_request_sender:
        DynamicSender<'static, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
}

pub(crate) struct Inner<D: StackDefinition> {
    app_service_channel:
        Channel<NoopRawMutex, Request<ApplicationLayerService, ApplicationLayerServiceResponse>, 1>,
    adt: Mutex<NoopRawMutex, RefCell<D::ADT>>,
    ast: Mutex<NoopRawMutex, RefCell<D::AST>>,
    comm_objs: Mutex<NoopRawMutex, RefCell<D::COMM_OBJS>>,
}

fn _assert_covariant<'a, 'b: 'a, D: StackDefinition>(x: Stack<'b, D>) -> Stack<'a, D> {
    x
}

pub fn new<'d, D: StackDefinition + Copy>(
    resources: &'d mut StackResources<D>,
    adt: D::ADT,
    ast: D::AST,
    comm_objs: D::COMM_OBJS,
) -> (Stack<'d, D>, Runner<'d, D>) {
    let inner = Inner {
        app_service_channel: Channel::new(),
        adt: Mutex::new(RefCell::new(adt)),
        ast: Mutex::new(RefCell::new(ast)),
        comm_objs: Mutex::new(RefCell::new(comm_objs)),
    };

    let inner = &*resources.inner.write(inner);

    // SAFETY: We are creating a static reference to the channel held by the `Inner` struct,
    //         which is safe because it is guaranteed to live as long as the `Stack` or the `Runner`.
    let app_request_sender: Sender<
        'static,
        NoopRawMutex,
        Request<ApplicationLayerService, ApplicationLayerServiceResponse>,
        1,
    > = unsafe { core::mem::transmute(inner.app_service_channel.sender()) };

    let app_request_receiver: Receiver<
        'static,
        NoopRawMutex,
        Request<ApplicationLayerService, ApplicationLayerServiceResponse>,
        1,
    > = unsafe { core::mem::transmute(inner.app_service_channel.receiver()) };

    let stack = Stack {
        inner,
        app_request_sender: app_request_sender.into(),
    };

    let runner = Runner {
        stack,
        app_request_receiver: app_request_receiver.into(),
    };

    (stack, runner)
}

impl<'d, D: StackDefinition> Runner<'d, D> {
    /// Run the KNX stack.
    ///
    /// You must call this in a background task, to process KNX messages.
    pub async fn run(self) -> ! {
        let ind_addr = IndividualAddress::new(1, 0, 1);

        // Create all the channels for layer to layer communication
        let nl_channel: Channel<NoopRawMutex, _, 1> = Channel::new();
        let tl_channel: Channel<NoopRawMutex, _, 1> = Channel::new();
        let al_channel: Channel<NoopRawMutex, _, 1> = Channel::new();

        // Create a network layer
        let mut network_layer = NetworkLayer::new(ind_addr, 6, tl_channel.sender().into());

        // Create a transport layer
        //let mut tl_adt = core::pin::pin!(unsafe { adt_ref.duplicate() });
        let mut transport_layer = TransportLayer::<'_, Buffer<'_>, D>::new(
            &self.stack.inner.adt,
            nl_channel.sender().into(),
            al_channel.sender().into(),
        );

        // Create an application layer
        let mut application_layer = ApplicationLayer::<'_, Buffer<'_>, D>::new(
            &self.stack.inner.ast,
            &self.stack.inner.comm_objs,
            self.app_request_receiver,
            tl_channel.sender().into(),
        );

        // Spawn and await all the tasks
        let nl_task = network_layer.process(nl_channel.receiver());
        let tl_task = transport_layer.process(tl_channel.receiver());
        let al_task = application_layer.process(al_channel.receiver());
        let tasks = embassy_futures::join::join3(nl_task, tl_task, al_task);
        tasks.await;

        unreachable!();
    }
}

impl<'d, D: StackDefinition> Stack<'d, D> {
    pub async fn comm_obj_write_request(&self, asap: u16) -> ApplicationLayerServiceResponse {
        self.app_request_sender
            .request(ApplicationLayerService::GroupValueWriteRequest(asap))
            .await
            .unwrap()
    }

    pub fn something(&self) {
        self.inner.adt.lock(|adt| {
            let adt = adt.borrow();
            println!("Max ADT entries: {}", adt.max_entries());
        });
    }
}
