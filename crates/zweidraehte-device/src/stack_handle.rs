//! KNX stack handle — the main user-facing API for interacting with the
//! running KNX protocol stack.

use core::cell::RefCell;

use embassy_sync::channel::DynamicSender;
use embassy_sync::pubsub::PubSubBehavior;
use embassy_time::{Duration, TimeoutError, with_timeout};

use crate::{
    ReadObjectError, StackState, UpdateObjectError,
    actor::{ActorRequest, Request},
    definition::StackDefinition,
    stack_core::StackCore,
    layers::application::{ApplicationLayerService, ApplicationLayerServiceResponse},
    lifecycle::LifecycleEvent,
    objects::{
        comm::{ComObjectEvent, ComObjectIndex, ComObjectStatus, ComObjects, HasCommObjects},
        tables::{
            HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasRunStateMachine,
        },
    },
    persist, restart,
};
use zweidraehte_proto::address::IndividualAddress;

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
    pub(crate) inner: &'d StackCore<D>,
    pub(crate) interface_objects: &'d D::InterfaceObjects<'static>,
    pub(crate) app_request_sender:
        DynamicSender<'static, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
    pub(crate) restart_receiver: DynamicReceiver<'static, restart::RestartRequest>,
    pub(crate) persist_receiver: DynamicReceiver<'static, Request<persist::PersistRequest, ()>>,
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
    /// Try to claim an object for transmission by setting its status.
    ///
    /// Returns `true` if the object was claimed (status was not `Busy`),
    /// `false` if it was already busy transmitting.
    fn try_claim_object(&self, asap: u16, status: ComObjectStatus) -> bool {
        self.inner.with_comm_objs(|co| {
            if co.status(asap) == Some(ComObjectStatus::Busy) {
                return false;
            }
            co.set_status(asap, status);
            true
        })
    }

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
    /// use zweidraehte_proto::dpt::DPT_Switch;
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
        // Claim the object and set its value atomically within one borrow.
        let accepted = self.inner.with_comm_objs(|co| {
            if co.status(asap.index()) == Some(ComObjectStatus::Busy) {
                return false;
            }
            co.set_status(asap.index(), ComObjectStatus::WriteRequest);
            co.info_mut(asap.index())
                .expect("typed comm-object Index is always in range")
                .value
                .copy_from_slice(value.as_ref());
            true
        });
        if !accepted {
            return Err(UpdateObjectError::Busy);
        }

        self.inner.layer_context.event_channel.publish_immediate((asap.clone(), ComObjectEvent::LocallyUpdated));

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
        if !self.try_claim_object(asap, ComObjectStatus::WriteRequest) {
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
        if !self.try_claim_object(asap, ComObjectStatus::ReadRequest) {
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
        if !self.try_claim_object(asap.index(), ComObjectStatus::ReadRequest) {
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
        self.inner.state.comm_objects()
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

    /// Initiate an S-A_Sync_Req to a peer.
    ///
    /// Sends a sync request to the specified individual address to
    /// synchronize sequence numbers. Returns `true` if the request was
    /// successfully sent, `false` if key lookup or buffer allocation failed.
    pub async fn initiate_sync(&self, peer_ia: u16, tool_access: bool, is_broadcast: bool) -> bool {
        let resp =
            ActorRequest::<D::Mutex, _, _>::request(&self.app_request_sender, ApplicationLayerService::SyncRequest {
                peer_ia,
                tool_access,
                is_broadcast,
            })
            .await;
        matches!(resp, ApplicationLayerServiceResponse::SyncInitiated)
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
    /// # Subscriber limit
    /// At most **4** dynamic subscribers can be active simultaneously. Calling
    /// this method when 4 are already live panics. If you need more, raise the
    /// `SUBS` const in `context/layer.rs` (`PubSubChannel<…, 4, SUBS, 1>`).
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
        self.inner.layer_context.event_channel.dyn_subscriber().expect(
            "too many event subscribers: LayerContext event_channel allows at most 4; raise SUBS in context/layer.rs",
        )
    }

    /// Subscribe to application lifecycle events.
    ///
    /// Returns a subscriber that receives events when the application transitions
    /// into or out of the RUNNING state. This includes transitions caused by:
    /// - ETS programming completing (load state machine cascade)
    /// - Explicit run state control commands
    /// - Device startup with persisted loaded state
    ///
    /// # Subscriber limit
    /// At most **4** dynamic subscribers can be active simultaneously. Calling
    /// this method when 4 are already live panics. If you need more, raise the
    /// `SUBS` const in `context/layer.rs` (`PubSubChannel<…, 4, SUBS, 1>`).
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
        self.inner.layer_context.lifecycle_channel.dyn_subscriber().expect(
            "too many lifecycle subscribers: LayerContext lifecycle_channel allows at most 4; raise SUBS in context/layer.rs",
        )
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

    /// Receive the next on-demand persistence request from the stack.
    ///
    /// The stack asks for an immediate save when waiting for the next
    /// periodic poll or restart would be wrong:
    ///
    /// - [`PersistRequest::McTimerWatermark`](persist::PersistRequest::McTimerWatermark):
    ///   the KNX IP Secure multicast timer watermark advanced
    ///   (03/08/09 §2.2.4.2). The link layer holds back the frame that
    ///   would exceed the previously persisted watermark until the save
    ///   is confirmed.
    /// - [`PersistRequest::EtsDownloadComplete`](persist::PersistRequest::EtsDownloadComplete):
    ///   an ETS download finished — a natural moment to save the new
    ///   configuration.
    ///
    /// # Contract
    ///
    /// After attempting the save, **always** call
    /// [`Request::reply`]`(())` — also when the save failed (log and
    /// continue). Gated requesters are blocked until the reply arrives
    /// (never replying wedges the KNX/IP send path, and dropping the
    /// request without replying panics the requester — see
    /// [`actor`](crate::actor) cancellation semantics); for advisory
    /// fire-and-forget requests the reply is a no-op, so user code
    /// needs no branching.
    ///
    /// # Example
    /// ```rust,ignore
    /// loop {
    ///     let request = stack.receive_persist_request().await;
    ///     if stack.state().is_dirty() {
    ///         if let Err(e) = storage.save(stack.state()) {
    ///             warn!("Persist-on-demand save failed: {:?}", e);
    ///         }
    ///     }
    ///     request.reply(()).await;
    /// }
    /// ```
    pub async fn receive_persist_request(&self) -> Request<persist::PersistRequest, ()> {
        self.persist_receiver.receive().await
    }

    /// Yield until the router's outbox has no pending messages.
    ///
    /// Call sites that mutate device state in reaction to stack events
    /// (most notably restart handlers after a `FactoryReset`) need to
    /// let the router drain any already-queued frames before wiping
    /// state. Otherwise the in-flight `A_Restart_Response` — pushed to
    /// the outbox by the application layer before the handler was
    /// woken — picks up the zeroed individual address on its way out.
    ///
    /// The wait polls the outbox per yield. There is no embedded
    /// timeout: callers with a timing budget should wrap this in
    /// `embassy_futures::select` against a `Timer`.
    pub async fn await_outbox_drained(&self) {
        loop {
            if self.inner.layer_context.outbox.borrow().is_fully_empty() {
                return;
            }
            embassy_futures::yield_now().await;
        }
    }

    /// Returns the current buffer pool usage as `(allocated, total)`.
    ///
    /// Useful for monitoring pool pressure and diagnosing potential deadlocks
    /// in production. When `allocated` approaches `total`, incoming allocations
    /// may block.
    pub fn buffer_pool_status(&self) -> (u8, u8) {
        let bm = &self.inner.layer_context.buffer_manager;
        (bm.allocated_count(), bm.pool_size())
    }
}

// Table accessor methods
impl<'d, D: StackDefinition> Stack<'d, D> {
    /// Get access to the address table.
    ///
    /// The address table maps TSAPs (Transport Service Access Points) to group addresses.
    pub fn address_table(&self) -> &RefCell<<D::State as HasAddressTable>::ADT> {
        self.inner.state.adt()
    }

    /// Get access to the association table.
    ///
    /// The association table maps TSAPs to ASAPs (Application Service Access Points).
    pub fn association_table(&self) -> &RefCell<<D::State as HasAssociationTable>::AST> {
        self.inner.state.ast()
    }

    /// Get access to the communication object table.
    ///
    /// Contains type and flag information for each communication object
    /// (separate from the values stored in [`objects()`](Self::objects)).
    pub fn communication_object_table(&self) -> &RefCell<<D::State as HasCommunicationObjectTable>::COT> {
        self.inner.state.cot()
    }

    /// Check if the application is currently running.
    ///
    /// The application is running when the run state machine is in the RUNNING state.
    pub fn is_running(&self) -> bool {
        self.inner.state.app().borrow().is_running()
    }
}
