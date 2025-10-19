#![cfg_attr(not(test), no_std)]
#![feature(slice_as_array)]
#![feature(const_trait_impl)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![feature(type_alias_impl_trait)]
#![feature(never_type)]

mod fmt;

#[macro_use]
mod macros;

pub mod address;
pub mod bcus;
pub mod context;
pub mod dpt;
pub mod error;
pub mod layers;
pub mod messages;
pub mod objects;
pub mod util;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

use core::{cell::RefCell, mem::MaybeUninit};

use const_default::ConstDefault;
use embassy_sync::{
    blocking_mutex::raw::{NoopRawMutex, RawMutex},
    channel::{Channel, DynamicReceiver, DynamicSender},
    pubsub::{PubSubBehavior, PubSubChannel},
};
use embassy_time::{Duration, TimeoutError, with_timeout};
use messages::knx::KnxMessageBuffer;

use crate::{
    address::IndividualAddress,
    context::BufferManagerContext,
    layers::{
        ActorRequest, Layer, LayerOp, LinkLayerBuilder, Request,
        application::{ApplicationLayer, ApplicationLayerService, ApplicationLayerServiceResponse},
        network::NetworkLayer,
        transport::TransportLayer,
    },
    messages::buffers::{Buffer, BufferManager, DynBufferManager},
    objects::{
        comm::{ComObjectEvent, ComObjectIndex, ComObjectStatus, ComObjects},
        tables::{AddressTable, AssociationTable, CommunicationObjectTable, TableMemory},
    },
};

/// Error type for read object operations with timeout
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadObjectError {
    /// The read request timed out without receiving a response
    Timeout,
}

pub trait StackDefinition: Copy {
    type ADT: AddressTable;
    type AST: AssociationTable;
    type COT: CommunicationObjectTable;
    type P: ConstDefault;
    type CO: ComObjects;
    type LLB: layers::LinkLayerBuilder;
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
    link_layer_builder: D::LLB,
}

/// KNX stack handle for interacting with the KNX protocol stack.
///
/// This is the main interface for applications to interact with the KNX stack.
/// It provides methods to update and read communication objects, subscribe to
/// events, and debug the system. The handle is `Copy`, so you can pass it by
/// value instead of by reference, making it easy to share across tasks.
///
/// # Usage
/// The Stack handle is obtained by calling [`new()`] along with a [`Runner`].
/// The Runner must be executed in a background task for the stack to function.
///
/// # Example
/// ```rust,ignore
/// // Define your stack configuration types that implement the required traits
/// struct MyStackDefinition;
/// impl StackDefinition for MyStackDefinition {
///     type ADT = MyAddressTable;      // implements AddressTable
///     type AST = MyAssociationTable;  // implements AssociationTable  
///     type COT = MyComObjectTable;    // implements CommunicationObjectTable
///     type P = MyParameters;          // implements ConstDefault
///     type CO = MyComObjects;         // implements ComObjects
/// }
///
/// // Create stack resources and configuration
/// let mut resources = StackResources::<MyStackDefinition>::new();
/// let (stack, runner) = new(&mut resources, addr_tab, asso_tab, co_tab, comm_objs);
///
/// // Start the stack runner in a background task
/// embassy_executor::Spawner::spawn(async { runner.run().await }).unwrap();
///
/// // Use the stack handle to interact with KNX
/// stack.update_object(object_index, new_value).await;
/// stack.read_object(object_index).await;
/// ```
///
/// For a complete working example with all the trait implementations,
/// see the `testutil` crate in this repository.
#[derive(Copy, Clone)]
pub struct Stack<'d, D: StackDefinition> {
    inner: &'d Inner<D>,
    app_request_sender: DynamicSender<'static, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
}

pub(crate) struct Inner<D: StackDefinition> {
    pub(crate) buffer_manager: RefCell<DynBufferManager<'static>>,
    pub(crate) app_service_channel:
        Channel<NoopRawMutex, Request<ApplicationLayerService, ApplicationLayerServiceResponse>, 1>,
    pub(crate) adt: RefCell<D::ADT>,
    pub(crate) ast: RefCell<D::AST>,
    pub(crate) cot: RefCell<D::COT>,
    pub(crate) comm_objs: RefCell<D::CO>,
    pub(crate) event_channel:
        PubSubChannel<NoopRawMutex, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent), 4, 2, 1>,
}

// Implement context traits for Inner
impl<D: StackDefinition> BufferManagerContext for &Inner<D> {
    fn buffer_manager(&self) -> &RefCell<DynBufferManager<'static>> {
        &self.buffer_manager
    }
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
    link_layer_builder: D::LLB,
) -> (Stack<'d, D>, Runner<'d, D>) {
    // SAFETY: We are creating a reference to the buffers that are stored in the `StackResources` struct,
    //         which lives at least as long as `Inner`
    let buffers = resources.buffers.write([[0; _]; _]);
    let buffer_manager: &'static mut BufferManager<NUM_BUFS> =
        unsafe { core::mem::transmute(resources.buffer_manager.write(BufferManager::new(buffers))) };

    let inner = Inner {
        buffer_manager: RefCell::new(buffer_manager.dyn_buffer_manager()),
        app_service_channel: Channel::new(),
        adt: RefCell::new(adt),
        ast: RefCell::new(ast),
        cot: RefCell::new(cot),
        comm_objs: RefCell::new(comm_objs),
        event_channel: PubSubChannel::new(),
    };

    let inner = &*resources.inner.write(inner);

    // SAFETY: We are creating a static reference to the channel held by the `Inner` struct,
    //         which is safe because it is guaranteed to live as long as the `Stack` or the `Runner`.
    let (app_request_sender, app_request_receiver) =
        create_request_response_pair::<NoopRawMutex, _, 1>(unsafe { core::mem::transmute(&inner.app_service_channel) });

    let stack = Stack { inner, app_request_sender: app_request_sender.into() };
    let runner = Runner { stack, app_request_receiver: app_request_receiver.into(), link_layer_builder };

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
            &self.stack.inner.event_channel,
            self.app_request_receiver,
            tl_channel.sender().into(),
        );

        // Build and run the link layer using the provided builder
        let ll_task =
            self.link_layer_builder.build_and_run(&self.stack.inner, nl_channel.sender().into(), ll_channel.receiver());

        // Spawn and await all the upper layer tasks
        let nl_task = network_layer.process(nl_channel.receiver());
        let tl_task = transport_layer.process(tl_channel.receiver());
        let al_task = application_layer.process(al_channel.receiver());
        let tasks = embassy_futures::join::join4(ll_task, nl_task, tl_task, al_task);
        tasks.await;

        unreachable!();
    }
}

impl<'d, D: StackDefinition> Stack<'d, D> {
    // FIMXE: We cannot use D::CO::Index here for the asap, because the compiler
    //        doesn't support projections through associated types yet
    //        Keep an eye on https://github.com/rust-lang/rust/pull/126651

    /// Update a communication object with a new value and send it to the KNX bus.
    ///
    /// This method updates the local communication object value and sends a GroupValueWrite
    /// request to the KNX bus to inform other devices of the change.
    ///
    /// # Arguments
    /// * `asap` - The communication object index to update
    /// * `value` - The new value to set. Must implement `AsRef<[u8]>` to provide the raw bytes
    ///
    /// # Behavior
    /// 1. Sets the communication object status to `WriteRequest`
    /// 2. Updates the local object value with the provided data
    /// 3. Publishes a `LocallyUpdated` event to notify subscribers
    /// 4. Sends a GroupValueWrite request to the KNX bus
    ///
    /// # Example
    /// ```rust,ignore
    /// # async fn example(stack: zweidraehte::Stack<'_, MyStackDef>, switch_index: MyComObjectIndex) {
    /// use zweidraehte::dpt::DPT_Switch;
    ///
    /// // Update a boolean switch object
    /// stack.update_object(switch_index, DPT_Switch::from(true)).await;
    ///
    /// // Update with raw bytes
    /// stack.update_object(switch_index, &[0x01]).await;
    /// # }
    /// ```
    pub async fn update_object<T: AsRef<[u8]>>(
        &self,
        asap: <<D as StackDefinition>::CO as ComObjects>::Index,
        value: T,
    ) {
        // FIXME: check if app is running, if not, don't do anything?
        // FIXME: check if transmission state is not transmitting yet

        // Make sure the mutable borrow is dropped before sending the request
        // FIXME: Introduce a with()-closure to avoid this?
        {
            let mut comm_objs = self.inner.comm_objs.borrow_mut();
            comm_objs.set_status(asap.index(), ComObjectStatus::WriteRequest);
            comm_objs.info_mut(asap.index()).value.copy_from_slice(value.as_ref());
        }

        self.inner.event_channel.publish_immediate((asap.clone(), ComObjectEvent::LocallyUpdated));

        self.app_request_sender.request(ApplicationLayerService::GroupValueWriteRequest(asap.index())).await;
    }

    /// Send a read request for a communication object.
    ///
    /// This method sends the read request and returns immediately without waiting for a response.
    /// Use `read_object_with_timeout` if you need to wait for the response.
    pub async fn read_object(&self, asap: <<D as StackDefinition>::CO as ComObjects>::Index) {
        let _ = self.read_object_with_timeout(asap, None).await;
    }

    /// Send a read request for a communication object and optionally wait for the response.
    ///
    /// # Arguments
    /// * `asap` - The communication object index to read
    /// * `timeout` - Optional timeout duration. If `None`, the method returns immediately after
    ///               sending the request (same behavior as `read_object`). If `Some(duration)`,
    ///               it waits for a `ReadResponse` event for up to the specified duration.
    ///
    /// # Returns
    /// * `Ok(())` - The read request was sent successfully and (if timeout was specified) a response was received
    /// * `Err(ReadObjectError::Timeout)` - A timeout was specified but no response was received within the timeout period
    ///
    /// # Example
    /// ```rust,ignore
    /// # use embassy_time::Duration;
    /// # async fn example(stack: zweidraehte::Stack<'_, MyStackDef>, asap: MyComObjectIndex) {
    /// // Fire-and-forget read request
    /// stack.read_object(asap).await;
    ///
    /// // Read request with 1 second timeout
    /// match stack.read_object_with_timeout(asap, Some(Duration::from_secs(1))).await {
    ///     Ok(()) => println!("Response received!"),
    ///     Err(zweidraehte::ReadObjectError::Timeout) => println!("No response within timeout"),
    /// }
    /// # }
    /// ```
    pub async fn read_object_with_timeout(
        &self,
        asap: <<D as StackDefinition>::CO as ComObjects>::Index,
        timeout: Option<Duration>,
    ) -> Result<(), ReadObjectError> {
        // FIXME: check if app is running, if not, don't do anything?
        // FIXME: check if transmission state is not transmitting yet

        // Make sure the mutable borrow is dropped before sending the request
        // FIXME: Introduce a with()-closure to avoid this?
        {
            let mut comm_objs = self.inner.comm_objs.borrow_mut();
            comm_objs.set_status(asap.index(), ComObjectStatus::ReadRequest);
        }

        // If no timeout is specified, just send the request and return immediately
        let Some(timeout_duration) = timeout else {
            self.app_request_sender.request(ApplicationLayerService::GroupValueReadRequest(asap.index())).await;
            return Ok(());
        };

        // Subscribe to events before sending the request to avoid race conditions
        let mut event_subscriber = self.events();

        // Send the read request
        self.app_request_sender.request(ApplicationLayerService::GroupValueReadRequest(asap.index())).await;

        // Wait for ReadResponse event with timeout
        let wait_for_response = async {
            loop {
                let event = event_subscriber.next_message_pure().await;
                let (event_asap, event_type) = event;
                if event_asap.index() == asap.index() {
                    match event_type {
                        ComObjectEvent::ReadResponse => {
                            return;
                        }
                        ComObjectEvent::Updated | ComObjectEvent::LocallyUpdated => {
                            // Continue waiting - these are not read responses
                            continue;
                        }
                    }
                }
                // Event for different object, keep waiting
            }
        };

        match with_timeout(timeout_duration, wait_for_response).await {
            Ok(()) => Ok(()),
            Err(TimeoutError) => Err(ReadObjectError::Timeout),
        }
    }

    /// Get access to the communication objects container.
    ///
    /// Returns a reference to the `RefCell` containing all communication objects.
    /// Use this to read object values, check statuses, or perform other operations
    /// on the communication objects.
    ///
    /// # Returns
    /// A reference to the `RefCell<D::CO>` containing all communication objects
    ///
    /// # Example
    /// ```rust,ignore
    /// # fn example(stack: zweidraehte::Stack<'_, MyStackDef>, switch_index: MyComObjectIndex) {
    /// // Read the current value of a communication object
    /// let objects = stack.objects();
    /// let current_value = objects.borrow().value(switch_index.index());
    ///
    /// // Check the status of a communication object
    /// let status = objects.borrow().status(switch_index.index());
    /// println!("Object status: {:?}", status);
    /// # }
    /// ```
    pub fn objects(&self) -> &RefCell<D::CO> {
        &self.inner.comm_objs
    }

    /// Subscribe to communication object events.
    ///
    /// Returns a subscriber that receives events when communication objects are updated.
    /// This is useful for monitoring changes to objects caused by incoming KNX messages
    /// or local updates.
    ///
    /// # Returns
    /// A `DynSubscriber` that yields tuples of `(object_index, event_type)`
    ///
    /// # Events
    /// * `ComObjectEvent::Updated` - Object was updated by an incoming GroupValueWrite
    /// * `ComObjectEvent::LocallyUpdated` - Object was updated locally via `update_object`
    /// * `ComObjectEvent::ReadResponse` - A response to a read request was received
    ///
    /// # Example
    /// ```rust,ignore
    /// # async fn example(stack: zweidraehte::Stack<'_, MyStackDef>) {
    /// use embassy_sync::pubsub::WaitResult;
    /// use zweidraehte::objects::comm::ComObjectEvent;
    ///
    /// let mut events = stack.events();
    ///
    /// loop {
    ///     match events.next_message().await {
    ///         WaitResult::Message((index, event)) => {
    ///             match event {
    ///                 ComObjectEvent::Updated => {
    ///                     println!("Object {:?} was updated remotely", index);
    ///                 }
    ///                 ComObjectEvent::LocallyUpdated => {
    ///                     println!("Object {:?} was updated locally", index);
    ///                 }
    ///                 ComObjectEvent::ReadResponse => {
    ///                     println!("Received read response for object {:?}", index);
    ///                 }
    ///             }
    ///         }
    ///         WaitResult::Lagged(count) => {
    ///             println!("Missed {} events due to slow processing", count);
    ///         }
    ///     }
    /// }
    /// # }
    /// ```
    pub fn events(
        &self,
    ) -> embassy_sync::pubsub::DynSubscriber<'_, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent)>
    {
        self.inner.event_channel.dyn_subscriber().unwrap()
    }

    /// Allocate a KNX message buffer from raw bytes.
    ///
    /// This is useful for testing and debugging, particularly with mock link layers
    /// where you want to inject messages into the stack.
    ///
    /// # Arguments
    /// * `msg` - Raw message bytes to allocate into a buffer
    ///
    /// # Returns
    /// A `KnxMessageBuffer` that can be injected into a mock link layer
    ///
    /// # Example
    /// ```rust,ignore
    /// # async fn example(
    /// #     stack: zweidraehte::Stack<'_, MyStackDef>,
    /// #     mock_ll: zweidraehte::layers::linklayers::mock::MockLinkLayerHandle
    /// # ) {
    /// use zweidraehte::messages::knx::ServiceType;
    ///
    /// // Allocate a message buffer
    /// let msg = stack.alloc_message(&[0xbc, 0x10, 0x1, 0x8, 0x4, 0xe0, 0x0, 0x81]).await;
    ///
    /// // Inject it into the mock link layer
    /// mock_ll.inject(msg).await;
    /// # }
    /// ```
    pub async fn alloc_message(&self, msg: &[u8]) -> KnxMessageBuffer<Buffer<'static>> {
        let buffer = self.inner.buffer_manager.borrow_mut().alloc_from_slice(msg).await;
        KnxMessageBuffer::new(buffer, messages::knx::ServiceType::L_Data_Ind)
    }
}
