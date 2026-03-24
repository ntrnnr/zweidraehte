//! KNX stack handle — the main user-facing API for interacting with the
//! running KNX protocol stack.

use core::cell::RefCell;

use embassy_sync::channel::DynamicSender;
use embassy_sync::pubsub::PubSubBehavior;
use embassy_time::{Duration, TimeoutError, with_timeout};

use crate::{
    actor::{ActorRequest, Request},
    address::IndividualAddress,
    definition::StackDefinition,
    inner::Inner,
    layers::application::{ApplicationLayerService, ApplicationLayerServiceResponse},
    messages::{
        buffers::Buffer,
        knx::KnxMessageBuffer,
    },
    objects::{
        comm::{ComObjectEvent, ComObjectIndex, ComObjectStatus, ComObjects, LifecycleEvent},
        tables::{
            HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable,
            HasRunStateMachine,
        },
    },
    restart,
    ReadObjectError, StackState, UpdateObjectError,
};

use embassy_sync::channel::DynamicReceiver;

/// KNX stack handle for interacting with the KNX protocol stack.
///
/// This is the main interface for applications to interact with the KNX stack.
/// It provides methods to update and read communication objects, subscribe to
/// events, and debug the system. The handle is `Copy`, so you can pass it by
/// value instead of by reference, making it easy to share across tasks.
///
/// # Usage
/// The Stack handle is obtained by calling [`new()`](crate::new) along with a [`Runner`](crate::Runner).
/// The Runner must be executed in a background task for the stack to function.
///
/// # Example
/// ```rust,ignore
/// // Define your stack configuration types that implement the required traits
/// struct MyStackDefinition;
/// impl StackDefinition for MyStackDefinition {
///     const MASK_VERSION: &'static [u8; 2] = &[0x07, 0xb0];
///     type ADT = MyAddressTable;      // implements AddressTable
///     type AST = MyAssociationTable;  // implements AssociationTable
///     type COT = MyComObjectTable;    // implements CommunicationObjectTable
///     type P = MyParameters;          // implements ConstDefault
///     type CO = MyComObjects;         // implements ComObjects
///     type State = SystemBDeviceState<..>;  // implements StackState
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
pub struct Stack<'d, D: StackDefinition> {
    pub(crate) inner: &'d Inner<D>,
    pub(crate) interface_objects: &'d D::InterfaceObjects<'static>,
    pub(crate) app_request_sender: DynamicSender<'static, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
    pub(crate) restart_receiver: DynamicReceiver<'static, restart::RestartRequest>,
}

impl<'d, D: StackDefinition> Copy for Stack<'d, D> {}

impl<'d, D: StackDefinition> Clone for Stack<'d, D> {
    fn clone(&self) -> Self {
        *self
    }
}

fn _assert_covariant<'a, 'b: 'a, D: StackDefinition>(x: Stack<'b, D>) -> Stack<'a, D> {
    x
}

impl<'d, D: StackDefinition> Stack<'d, D> {
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
    /// # Returns
    /// * `Ok(())` - The update was accepted and will be transmitted
    /// * `Err(UpdateObjectError::Busy)` - The object is already transmitting
    ///
    /// # Example
    /// ```rust,ignore
    /// # async fn example(stack: zweidraehte_device::Stack<'_, MyStackDef>, switch_index: MyComObjectIndex) {
    /// use zweidraehte_device::dpt::DPT_Switch;
    ///
    /// // Update a boolean switch object
    /// if stack.update_object(switch_index, DPT_Switch::from(true)).await.is_ok() {
    ///     println!("Update accepted");
    /// }
    /// # }
    /// ```
    pub async fn update_object<T: AsRef<[u8]>>(
        &self,
        asap: <<D as StackDefinition>::CO as ComObjects>::Index,
        value: T,
    ) -> Result<(), UpdateObjectError> {
        // Reject only if the object is actively being transmitted (Busy).
        let accepted = self.inner.with_comm_objs(|co| {
            if co.status(asap.index()) == ComObjectStatus::Busy {
                return false;
            }
            co.set_status(asap.index(), ComObjectStatus::WriteRequest);
            co.info_mut(asap.index()).value.copy_from_slice(value.as_ref());
            true
        });

        if !accepted {
            return Err(UpdateObjectError::Busy);
        }

        self.inner.event_channel.publish_immediate((asap.clone(), ComObjectEvent::LocallyUpdated));

        ActorRequest::<D::Mutex, _, _>::request(
            &self.app_request_sender,
            ApplicationLayerService::GroupValueWriteRequest(asap.index()),
        )
        .await;
        Ok(())
    }

    /// Send a write request for a communication object using its current value.
    ///
    /// Unlike `update_object`, this method does not modify the object's value - it simply
    /// sends the current value to the KNX bus. This is useful when the value has already
    /// been set through other means (e.g., via a shadow object in conformance testing).
    ///
    /// # Arguments
    /// * `asap` - The communication object index to send
    ///
    /// # Behavior
    /// 1. Sets the communication object status to `WriteRequest`
    /// 2. Sends a GroupValueWrite request with the object's current value to the KNX bus
    ///
    /// Note: This does NOT publish a `LocallyUpdated` event since the value is not being
    /// changed, only transmitted.
    ///
    /// # Returns
    /// * `Ok(())` - The write request was accepted
    /// * `Err(UpdateObjectError::Busy)` - The object is already transmitting
    pub async fn write_object(
        &self,
        asap: <<D as StackDefinition>::CO as ComObjects>::Index,
    ) -> Result<(), UpdateObjectError> {
        self.write_object_by_asap(asap.index()).await
    }

    /// Send a write request for a communication object by ASAP number.
    ///
    /// This is a lower-level version of `write_object` that takes a raw ASAP number
    /// instead of the type-safe Index type.
    ///
    /// # Returns
    /// * `Ok(())` - The write request was accepted
    /// * `Err(UpdateObjectError::Busy)` - The object is already transmitting
    pub async fn write_object_by_asap(&self, asap: u16) -> Result<(), UpdateObjectError> {
        let accepted = self.inner.with_comm_objs(|co| {
            // Reject only if the object is actively being transmitted (Busy).
            // Other states (including WriteRequest set via flag manipulation)
            // are fine — the AL serializes requests through a size-1 channel.
            if co.status(asap) == ComObjectStatus::Busy {
                return false;
            }
            co.set_status(asap, ComObjectStatus::WriteRequest);
            true
        });

        if !accepted {
            return Err(UpdateObjectError::Busy);
        }

        ActorRequest::<D::Mutex, _, _>::request(
            &self.app_request_sender,
            ApplicationLayerService::GroupValueWriteRequest(asap),
        )
        .await;
        Ok(())
    }

    /// Send a read request for a communication object.
    ///
    /// This method sends the read request and returns immediately without waiting for a response.
    /// Use `read_object_with_timeout` if you need to wait for the response.
    ///
    /// # Returns
    /// * `Ok(())` - The read request was accepted
    /// * `Err(ReadObjectError::Busy)` - The object is already transmitting
    pub async fn read_object(
        &self,
        asap: <<D as StackDefinition>::CO as ComObjects>::Index,
    ) -> Result<(), ReadObjectError> {
        self.read_object_by_asap(asap.index()).await
    }

    /// Send a read request for a communication object by ASAP number.
    ///
    /// This is a lower-level version of `read_object` that takes a raw ASAP number
    /// instead of the type-safe Index type.
    ///
    /// # Returns
    /// * `Ok(())` - The read request was accepted
    /// * `Err(ReadObjectError::Busy)` - The object is already transmitting
    pub async fn read_object_by_asap(&self, asap: u16) -> Result<(), ReadObjectError> {
        let accepted = self.inner.with_comm_objs(|co| {
            // Reject only if the object is actively being transmitted (Busy).
            if co.status(asap) == ComObjectStatus::Busy {
                return false;
            }
            co.set_status(asap, ComObjectStatus::ReadRequest);
            true
        });

        if !accepted {
            return Err(ReadObjectError::Busy);
        }

        ActorRequest::<D::Mutex, _, _>::request(
            &self.app_request_sender,
            ApplicationLayerService::GroupValueReadRequest(asap),
        )
        .await;
        Ok(())
    }

    /// Send a read request for a communication object and optionally wait for the response.
    ///
    /// # Arguments
    /// * `asap` - The communication object index to read
    /// * `timeout` - Optional timeout duration. If `None`, the method returns immediately after
    ///   sending the request (same behavior as `read_object`). If `Some(duration)`,
    ///   it waits for a `ReadResponse` event for up to the specified duration.
    ///
    /// # Returns
    /// * `Ok(())` - The read request was sent successfully and (if timeout was specified) a response was received
    /// * `Err(ReadObjectError::Timeout)` - A timeout was specified but no response was received within the timeout period
    /// * `Err(ReadObjectError::Busy)` - The object is already transmitting
    ///
    /// # Example
    /// ```rust,ignore
    /// # use embassy_time::Duration;
    /// # async fn example(stack: zweidraehte_device::Stack<'_, MyStackDef>, asap: MyComObjectIndex) {
    /// // Fire-and-forget read request
    /// let _ = stack.read_object(asap).await;
    ///
    /// // Read request with 1 second timeout
    /// match stack.read_object_with_timeout(asap, Some(Duration::from_secs(1))).await {
    ///     Ok(()) => println!("Response received!"),
    ///     Err(zweidraehte_device::ReadObjectError::Timeout) => println!("No response within timeout"),
    ///     Err(zweidraehte_device::ReadObjectError::Busy) => println!("Object is busy"),
    /// }
    /// # }
    /// ```
    pub async fn read_object_with_timeout(
        &self,
        asap: <<D as StackDefinition>::CO as ComObjects>::Index,
        timeout: Option<Duration>,
    ) -> Result<(), ReadObjectError> {
        // Reject only if the object is actively being transmitted (Busy).
        let accepted = self.inner.with_comm_objs(|co| {
            if co.status(asap.index()) == ComObjectStatus::Busy {
                return false;
            }
            co.set_status(asap.index(), ComObjectStatus::ReadRequest);
            true
        });

        if !accepted {
            return Err(ReadObjectError::Busy);
        }

        // If no timeout is specified, just send the request and return immediately
        let Some(timeout_duration) = timeout else {
            ActorRequest::<D::Mutex, _, _>::request(
                &self.app_request_sender,
                ApplicationLayerService::GroupValueReadRequest(asap.index()),
            )
            .await;
            return Ok(());
        };

        // Subscribe to events before sending the request to avoid race conditions
        let mut event_subscriber = self.events();

        // Send the read request
        ActorRequest::<D::Mutex, _, _>::request(
            &self.app_request_sender,
            ApplicationLayerService::GroupValueReadRequest(asap.index()),
        )
        .await;

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
                        ComObjectEvent::Updated | ComObjectEvent::LocallyUpdated | ComObjectEvent::Read => {
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
    /// # fn example(stack: zweidraehte_device::Stack<'_, MyStackDef>, switch_index: MyComObjectIndex) {
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

    /// Get access to the interface objects container.
    ///
    /// Returns a reference to the interface objects container created during
    /// stack initialization. The container type is determined by the
    /// `InterfaceObjects` associated type in the `StackDefinition`.
    ///
    /// # Returns
    /// A reference to the interface objects container
    pub fn interface_objects(&self) -> &D::InterfaceObjects<'static> {
        self.interface_objects
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
    /// # async fn example(stack: zweidraehte_device::Stack<'_, MyStackDef>) {
    /// use embassy_sync::pubsub::WaitResult;
    /// use zweidraehte_device::objects::comm::ComObjectEvent;
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

    /// Subscribe to application lifecycle events.
    ///
    /// Returns a subscriber that receives events when the application transitions
    /// into or out of the RUNNING state. This includes transitions caused by:
    /// - ETS programming completing (load state machine cascade)
    /// - Explicit run state control commands
    /// - Device startup with persisted loaded state
    ///
    /// # Example
    /// ```rust,ignore
    /// # async fn example(stack: zweidraehte_device::Stack<'_, MyStackDef>) {
    /// use zweidraehte_device::prelude::LifecycleEvent;
    ///
    /// let mut lifecycle = stack.lifecycle_events();
    ///
    /// loop {
    ///     match lifecycle.next_message_pure().await {
    ///         LifecycleEvent::ApplicationStarted => {
    ///             // Read parameters, initialize outputs, start timers
    ///         }
    ///         LifecycleEvent::ApplicationStopped => {
    ///             // Set outputs to safe state, stop timers
    ///         }
    ///     }
    /// }
    /// # }
    /// ```
    pub fn lifecycle_events(&self) -> embassy_sync::pubsub::DynSubscriber<'_, LifecycleEvent> {
        self.inner.lifecycle_channel.dyn_subscriber().unwrap()
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
    /// #     stack: zweidraehte_device::Stack<'_, MyStackDef>,
    /// #     mock_ll: zweidraehte_device::layers::linklayers::mock::MockLinkLayerHandle
    /// # ) {
    /// use zweidraehte_device::messages::knx::ServiceType;
    ///
    /// // Allocate a message buffer
    /// let msg = stack.alloc_message(&[0xbc, 0x10, 0x1, 0x8, 0x4, 0xe0, 0x0, 0x81]).await;
    ///
    /// // Inject it into the mock link layer
    /// mock_ll.inject(msg).await;
    /// # }
    /// ```
    pub async fn alloc_message(&self, msg: &[u8]) -> KnxMessageBuffer<Buffer<'static>> {
        let buffer = self.inner.buffer_manager.alloc_from_slice(msg).await;
        KnxMessageBuffer::new(buffer, crate::messages::knx::ServiceType::L_Data_Ind)
    }

    /// Get the device's individual address.
    ///
    /// This is the unique address assigned to this device on the KNX bus.
    /// It is used as the source address for outgoing messages.
    ///
    /// # Returns
    /// The device's individual address
    pub fn individual_address(&self) -> IndividualAddress {
        self.inner.state.individual_address()
    }

    /// Set the device's individual address.
    ///
    /// This is typically set during device configuration or via
    /// `A_IndividualAddress_Write` when in programming mode.
    ///
    /// # Arguments
    /// * `addr` - The new individual address
    pub fn set_individual_address(&self, addr: IndividualAddress) {
        self.inner.state.set_individual_address(addr);
    }

    /// Get access to the runtime state.
    ///
    /// Returns a reference to the runtime state containing programming mode
    /// and other shared configuration.
    pub fn state(&self) -> &D::State {
        &self.inner.state
    }

    /// Get access to the hook context for communication object hooks.
    ///
    /// This is useful for setting up hook context after stack initialization,
    /// for example when the hook context needs references to stack-internal
    /// structures like the COT.
    pub fn hook_context(&self) -> &<D::CO as ComObjects>::HookContext {
        &self.inner.hook_context
    }

    /// Receive the next restart request from the application layer.
    ///
    /// When the stack receives an A_Restart message from the KNX bus, it validates
    /// the request, sends the bus response immediately, and forwards the request
    /// here for user code to act on. User code should:
    ///
    /// 1. Call this method to receive the request
    /// 2. Execute the appropriate reset based on [`restart::EraseCode`]
    /// 3. Flush storage to persist any changes
    /// 4. Trigger platform restart
    ///
    /// The bus response (A_Restart_Response) is sent by the application layer
    /// before this request arrives — no response channel is needed.
    ///
    /// # Example
    /// ```rust,ignore
    /// # async fn handle_restart(stack: zweidraehte_device::Stack<'_, MyDevice>) {
    /// use zweidraehte_device::restart::{RestartRequest, EraseCode};
    ///
    /// loop {
    ///     let request = stack.receive_restart_request().await;
    ///
    ///     // Execute reset based on erase code
    ///     match request.erase_code {
    ///         EraseCode::Basic | EraseCode::Confirmed => {}
    ///         EraseCode::FactoryReset => {
    ///             device_state.factory_reset();
    ///         }
    ///         _ => continue, // Unsupported erase code — AL already rejected on bus
    ///     }
    ///
    ///     // Trigger platform restart
    ///     embassy_time::Timer::after(embassy_time::Duration::from_millis(100)).await;
    ///     use zweidraehte_platform::SystemControl;
    ///     let mut system = zweidraehte_platform::LinuxSystem;
    ///     let Err(e) = system.restart().await;
    ///     panic!("Failed to restart: {:?}", e);
    /// }
    /// # }
    /// ```
    pub async fn receive_restart_request(&self) -> restart::RestartRequest {
        self.restart_receiver.receive().await
    }

    /// Returns the current buffer pool usage as `(allocated, total)`.
    ///
    /// Useful for monitoring pool pressure and diagnosing potential deadlocks
    /// in production. When `allocated` approaches `total`, incoming allocations
    /// may block.
    pub fn buffer_pool_status(&self) -> (u8, u8) {
        let bm = &self.inner.buffer_manager;
        (bm.allocated_count(), bm.pool_size())
    }
}

// Table accessor methods - only available when State implements the appropriate traits
impl<'d, D: StackDefinition> Stack<'d, D> {
    /// Get access to the address table.
    ///
    /// Returns a reference to the `RefCell` containing the address table.
    /// The address table maps TSAPs (Transport Service Access Points) to group addresses.
    ///
    /// # Returns
    /// A reference to the `RefCell` containing the address table
    pub fn address_table(&self) -> &RefCell<<D::State as HasAddressTable>::ADT> {
        self.inner.state.adt()
    }
}

impl<'d, D: StackDefinition> Stack<'d, D> {
    /// Get access to the association table.
    ///
    /// Returns a reference to the `RefCell` containing the association table.
    /// The association table maps TSAPs to ASAPs (Application Service Access Points).
    ///
    /// # Returns
    /// A reference to the `RefCell` containing the association table
    pub fn association_table(&self) -> &RefCell<<D::State as HasAssociationTable>::AST> {
        self.inner.state.ast()
    }
}

impl<'d, D: StackDefinition> Stack<'d, D> {
    /// Get access to the communication object table.
    ///
    /// Returns a reference to the `RefCell` containing the communication object table.
    /// The communication object table contains type and flag information for each
    /// communication object (separate from the values stored in `objects()`).
    ///
    /// # Returns
    /// A reference to the `RefCell` containing the communication object table
    pub fn communication_object_table(&self) -> &RefCell<<D::State as HasCommunicationObjectTable>::COT> {
        self.inner.state.cot()
    }
}

impl<'d, D: StackDefinition> Stack<'d, D> {
    /// Check if the application is currently running.
    ///
    /// The application is running when the run state machine is in the RUNNING state.
    /// This requires the application program to be loaded (either from ETS programming
    /// or from persisted state).
    pub fn is_running(&self) -> bool {
        self.inner.state.app().borrow().is_running()
    }
}
