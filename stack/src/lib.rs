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

use core::marker::PhantomData;
use core::pin::Pin;

use address::IndividualAddress;
use const_default::ConstDefault;
use ector::mutex::NoopRawMutex;
use embassy_sync::channel::Channel;
use layers::{
    Layer, application::ApplicationLayer, network::NetworkLayer, transport::TransportLayer,
};
use messages::buffers::Buffer;
use objects::{
    comm::ComObjects,
    tables::{AddressTable, TableMemory, app::Application},
};

// FIXME: Introduce traits for AST, COT
pub trait StackDefinition {
    type ADT: AddressTable;
    type AST: TableMemory;
    type COT: TableMemory;
    type P: ConstDefault;
    type R: ComObjects;
}

pub struct StackResources<D: StackDefinition> {
    pub ind_addr: IndividualAddress,
    pub adt: D::ADT,
    pub ast: D::AST,
    pub cot: D::COT,
    pub app: Application<D::P>,
    pub ram: D::R,
}

pub struct StackRunner<D: StackDefinition> {
    ind_addr: IndividualAddress,
    adt: D::ADT,
    _phantom: PhantomData<D>,
}

impl<D: StackDefinition> StackRunner<D> {
    pub fn new(resources: StackResources<D>) -> Self {
        StackRunner {
            ind_addr: resources.ind_addr,
            adt: resources.adt,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Run the KNX stack.
    ///
    /// You must call this in a background task, to process KNX messages.
    pub async fn run(mut self) -> ! {
        // SAFETY: The SharedCell can be used here because the StackRunner
        //         is not Sync. The SharedCell can share data between async
        //         tasks as long as all of them run in the same thread.
        let mut adt_ref = SharedCell::new(&mut self.adt);

        // Create all the channels for layer to layer communication
        let nl_channel: Channel<NoopRawMutex, _, 1> = Channel::new();
        let tl_channel: Channel<NoopRawMutex, _, 1> = Channel::new();
        let al_channel: Channel<NoopRawMutex, _, 1> = Channel::new();

        // Create a network layer
        let mut network_layer = NetworkLayer::new(self.ind_addr, 6, tl_channel.sender().into());

        // Create a transport layer
        let mut tl_adt = core::pin::pin!(unsafe { adt_ref.duplicate() });
        let mut transport_layer = TransportLayer::<'_, Buffer<'_>, D>::new(
            &mut tl_adt,
            nl_channel.sender().into(),
            al_channel.sender().into(),
        );

        // Create an application layer
        let mut application_layer =
            ApplicationLayer::<'_, Buffer<'_>, D>::new(tl_channel.sender().into());

        // Spawn and await all the tasks
        let nl_task = network_layer.process(nl_channel.receiver());
        let tl_task = transport_layer.process(tl_channel.receiver());
        let al_task = application_layer.process(al_channel.receiver());
        let tasks = embassy_futures::join::join3(nl_task, tl_task, al_task);
        tasks.await;

        unreachable!();
    }
}

// pub struct ProtocolStack<D: StackDefinition> {
//     _phantom: std::marker::PhantomData<D>,
// }

use core::cell::Cell;
use core::marker::PhantomPinned;

pub type Shared<'a, T> = Pin<&'a mut SharedCell<'a, T>>;

pub struct SharedCell<'a, T: ?Sized>(&'a Cell<T>, PhantomPinned);

impl<'a, T: ?Sized> SharedCell<'a, T> {
    /// Create a new [`SharedCell`].
    pub fn new(value: &'a mut T) -> Self {
        Self(Cell::from_mut(value), PhantomPinned)
    }

    /// Duplicate the [`SharedCell`].
    ///
    /// # Safety
    ///
    ///  - The duplicated [`SharedCell`] may only be used in a scope where no
    ///    other [`SharedCell`] instance is used.
    ///  - The scope containing the duplicated [`SharedCell`] must not have the
    ///    ability to resume execution of an asynchronous task that holds onto
    ///    another [`SharedCell`].
    pub unsafe fn duplicate(&mut self) -> Self {
        Self(self.0, PhantomPinned)
    }

    /// Acquire a mutable reference to the cell's interior value.
    pub fn with<R>(self: &mut Pin<&mut Self>, f: impl FnOnce(&mut T) -> R) -> R {
        // SAFETY: By isolating the `SharedCell` to one instance per scope, we
        // prevent reëntrant calls to `with()`.
        //
        // SAFETY: Cannot yield to code that could call `with()` due to safety
        // invariant on `duplicate()`.
        unsafe { f(&mut *self.0.as_ptr()) }
    }
}
