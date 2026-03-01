//! Application Layer
//!
//! The application layer handles all application-level KNX services:
//!
//! ## Group Communication (A_GroupValue_*)
//! - `A_GroupValue_Read.ind` - Respond with current communication object value
//! - `A_GroupValue_Write.ind` / `A_GroupValue_Response.ind` - Update communication objects
//! - `A_GroupValue_Read.req` / `A_GroupValue_Write.req` - Send requests from local application
//!
//! ## Property Services (A_PropertyValue_*, A_PropertyDescription_*)
//! - Property read/write for interface objects
//! - Property description queries
//!
//! ## Device Management (A_DeviceDescriptor_*, A_Restart, etc.) - TODO
//! - Device descriptor read
//! - Restart commands
//! - Individual address read/write

use core::cell::RefCell;

use embassy_sync::{
    channel::DynamicSender,
    pubsub::{PubSubBehavior, PubSubChannel},
};

use super::Request;

use crate::{
    AccessContext, AccessSource, HasConnectionAuth, StackDefinition, StackState,
    address::GroupAddress,
    messages::{
        buffers::{Buffer, DynBufferManager},
        knx::*,
    },
    objects::{
        comm::{ComObjectEvent, ComObjectIndex, ComObjectStatus, ComObjects, LifecycleEvent},
        interface::{FullPropertyReadRequest, FullPropertyWriteRequest, HasDeviceObject, PropertyServiceHandler, pid},
        tables::{
            AssociationTable, CommunicationObjectTable, HasApplication, HasAssociationTable,
            HasCommunicationObjectTable, HasLoadStateMachine, HasRunStateMachine,
        },
    },
    restart::{EraseCode, RestartError, RestartRequest},
    router::{Layer, Outbox},
};

// ============================================================================
// Service Types
// ============================================================================

/// Service requests from the application to the application layer
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ApplicationLayerService {
    /// Request to send a `A_GroupValue_Write.req` for the given ASAP
    GroupValueWriteRequest(u16),
    /// Request to send a `A_GroupValue_Read.req` for the given ASAP
    GroupValueReadRequest(u16),
}

/// Service responses from the application layer back to the application
#[derive(Debug)]
pub enum ApplicationLayerServiceResponse {
    /// `A_GroupValue_Write.req` completed
    GroupValueWriteResponse,
    /// `A_GroupValue_Read.req` completed
    GroupValueReadResponse,
    /// Request rejected because the application is not running
    ApplicationNotRunning,
}

// ============================================================================
// Application Layer
// ============================================================================

/// Application layer for the KNX stack
///
/// Handles group communication, property services, and device management.
/// Receives indications from the transport layer and requests from the
/// local application.
pub struct ApplicationLayer<'a, D: StackDefinition> {
    // --- Shared stack resources ---
    buffer_manager: &'a DynBufferManager<'static>,
    /// Unified device state (contains tables and runtime configuration)
    state: &'a D::State,
    comm_objects: &'a RefCell<D::CO>,
    hook_context: &'a <D::CO as ComObjects>::HookContext,
    event_channel:
        &'a PubSubChannel<D::Mutex, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent), 4, 2, 1>,
    lifecycle_channel: &'a PubSubChannel<D::Mutex, LifecycleEvent, 4, 2, 1>,

    // --- Interface objects ---
    /// Interface objects container with typed access to device properties.
    /// Provides both PropertyServiceHandler for management protocol and
    /// HasDeviceObject for direct property access.
    interface_objects: &'a D::InterfaceObjects<'static>,

    // --- Memory access ---
    /// Memory map for A_Memory_Read/Write services
    memory_map: &'a D::Mem,

    // --- Communication channels ---
    /// Channel for sending restart requests to user code
    restart_sender: DynamicSender<'a, RestartRequest>,

    /// Read-on-init cursor. When `Scanning(idx)`, the AL will process one
    /// ROI object per main-loop iteration, starting from ASAP `idx`. Set to
    /// `Scanning(1)` when the application transitions to RUNNING (COT is
    /// 1-indexed); returns to
    /// `Idle` when the scan completes or the application stops.
    ///
    /// After a successful L2 send, the object transitions to `IdleOk` (like
    /// the CO-idle action). If a response arrives later, it will
    /// update the value; if not, the object simply stays idle with its value
    /// uninitialized — no application-level timeout is needed.
    read_on_init: ReadOnInitState,

    /// Pending group value send awaiting TL confirmation. When set, the next
    /// TL confirmation updates the communication object status accordingly.
    pending_group_send: Option<PendingGroupSend>,
}

/// Tracks a pending group value send for deferred CO status update.
#[derive(Debug)]
struct PendingGroupSend {
    /// The ASAP (communication object index) being sent
    asap: u16,
    /// Whether this was a read request (vs write)
    read: bool,
}

/// State machine for the read-on-init cycle.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum ReadOnInitState {
    /// No ROI cycle active.
    Idle,
    /// Scanning objects, sending reads. The `u16` is the next ASAP to check.
    Scanning(u16),
}

// ============================================================================
// Construction
// ============================================================================

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
    /// Create a new Application Layer
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        buffer_manager: &'a DynBufferManager<'static>,
        state: &'a D::State,
        comm_objects: &'a RefCell<D::CO>,
        hook_context: &'a <D::CO as ComObjects>::HookContext,
        event_channel: &'a PubSubChannel<
            D::Mutex,
            (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent),
            4,
            2,
            1,
        >,
        lifecycle_channel: &'a PubSubChannel<D::Mutex, LifecycleEvent, 4, 2, 1>,
        interface_objects: &'a D::InterfaceObjects<'static>,
        memory_map: &'a D::Mem,
        restart_sender: DynamicSender<'a, RestartRequest>,
    ) -> Self {
        Self {
            buffer_manager,
            state,
            comm_objects,
            hook_context,
            event_channel,
            lifecycle_channel,
            interface_objects,
            memory_map,
            restart_sender,
            read_on_init: ReadOnInitState::Idle,
            pending_group_send: None,
        }
    }

    /// Resolve the effective [`AccessContext`] for a message.
    ///
    /// - [`AccessSource::Default`] → default access level from device state
    /// - [`AccessSource::Connection(slot)`] → look up from shared access store
    /// - [`AccessSource::Explicit(ctx)`] → use as-is (e.g. KNX/IP Device Mgmt)
    fn resolve_access(&self, msg: &KnxMessageBuffer<Buffer<'static>>) -> AccessContext
    where
        D::State: HasConnectionAuth,
    {
        match msg.access_source() {
            AccessSource::Default => AccessContext::new(self.state.default_access_level()),
            AccessSource::Connection(slot) => self.state.connection_access(slot),
            AccessSource::Explicit(ctx) => ctx,
        }
    }
}

// ============================================================================
// Layer Implementation (Main Event Loop)
// ============================================================================

// ============================================================================
// Layer Trait Implementation
// ============================================================================

impl<D: StackDefinition> Layer for ApplicationLayer<'_, D>
where
    D::State: HasApplication + HasAssociationTable + HasCommunicationObjectTable + HasConnectionAuth,
    D::InterfaceObjects<'static>: HasDeviceObject,
{
    const HANDLES: &'static [ServiceType] = &[
        // Indications from TL (upward — group communication)
        ServiceType::T_GroupData_Ind,
        // Indications from TL (upward — broadcast / system broadcast)
        ServiceType::T_Broadcast_Ind,
        ServiceType::T_SystemBroadcast_Ind,
        // Indications from TL (upward — connection-oriented and unacknowledged)
        ServiceType::T_Data_Ind,
        ServiceType::T_DataUnack_Ind,
        // Confirmations from TL (upward)
        ServiceType::T_GroupData_Con,
        ServiceType::T_Broadcast_Con,
        ServiceType::T_SystemBroadcast_Con,
        ServiceType::T_Data_Con,
        ServiceType::T_DataUnack_Con,
    ];

    fn process(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        match msg.service_type() {
            // =================================================================
            // Confirmations from TL — complete pending group sends
            // =================================================================
            ServiceType::T_GroupData_Con
            | ServiceType::T_Broadcast_Con
            | ServiceType::T_SystemBroadcast_Con
            | ServiceType::T_Data_Con
            | ServiceType::T_DataUnack_Con => {
                self.handle_tl_confirmation(&msg);
            }

            // =================================================================
            // Indications from TL — dispatch by APCI
            // =================================================================
            _ => {
                trace!("AL received indication: {:?}", msg);

                let apci = msg.get_apci_code();
                debug!("AL APCI code: {:?}", apci);

                // Service-level access check (first line of defense).
                // Handlers may perform additional fine-grained checks.
                let access_ctx = self.resolve_access(&msg);
                match crate::access_policy::check_service_access(apci, &access_ctx) {
                    crate::access_policy::AccessDecision::Denied => {
                        warn!("AL service {:?} denied: {:?}", apci, access_ctx);
                        return;
                    }
                    _ => {} // Allowed or Defer — proceed to handler
                }

                match apci {
                    // --- Group Communication ---
                    a @ (ApciCode::GroupValueWrite | ApciCode::GroupValueResponse) => {
                        self.handle_group_value_write_or_response(&mut msg, a, outbox);
                    }
                    ApciCode::GroupValueRead => {
                        self.handle_group_value_read(&msg, outbox);
                    }

                    // --- Property Services ---
                    ApciCode::PropertyDescriptionRead => {
                        self.handle_property_description_read(&msg, outbox);
                    }
                    ApciCode::PropertyValueRead => {
                        self.handle_property_value_read(&msg, outbox);
                    }
                    ApciCode::PropertyValueWrite => {
                        self.handle_property_value_write(&msg, outbox);
                    }

                    // --- Device Management ---
                    ApciCode::DeviceDescriptorRead => {
                        self.handle_device_descriptor_read(&msg, outbox);
                    }
                    ApciCode::IndividualAddressRead => {
                        self.handle_individual_address_read(&msg, outbox);
                    }
                    ApciCode::IndividualAddressWrite => {
                        self.handle_individual_address_write(&msg, outbox);
                    }
                    ApciCode::IndividualAddressSerialNumberRead => {
                        self.handle_individual_address_serial_number_read(&msg, outbox);
                    }
                    ApciCode::IndividualAddressSerialNumberWrite => {
                        self.handle_individual_address_serial_number_write(&msg, outbox);
                    }
                    ApciCode::AdcRead => {
                        self.handle_adc_read(&msg, outbox);
                    }
                    ApciCode::MemoryRead => {
                        self.handle_memory_read(&msg, outbox);
                    }
                    ApciCode::MemoryWrite => {
                        self.handle_memory_write(&msg, outbox);
                    }
                    ApciCode::MemoryBitWrite => {
                        self.handle_memorybit_write(&msg, outbox);
                    }
                    ApciCode::UserMemoryRead => {
                        self.handle_user_memory_read(&msg, outbox);
                    }
                    ApciCode::UserMemoryWrite => {
                        self.handle_user_memory_write(&msg, outbox);
                    }
                    ApciCode::UserManufacturerInfoRead => {
                        self.handle_user_manufacturer_info_read(&msg, outbox);
                    }
                    ApciCode::AuthorizeRequest => {
                        self.handle_authorize_request(&msg, outbox);
                    }
                    ApciCode::KeyWrite => {
                        self.handle_key_write(&msg, outbox);
                    }
                    ApciCode::Restart => {
                        self.handle_restart(&msg, outbox);
                    }
                    _ => {
                        warn!("Unhandled APCI code: {:?}", msg.get_apci_code());
                    }
                }
            }
        }
    }

    fn next_deadline(&self) -> Option<embassy_time::Instant> {
        match self.read_on_init {
            // When ROI is active, request immediate poll
            ReadOnInitState::Scanning(cursor) => {
                debug!("AL next_deadline: ROI active (cursor={}), returning now", cursor);
                Some(embassy_time::Instant::now())
            }
            ReadOnInitState::Idle => None,
        }
    }

    fn poll(&mut self, outbox: &mut Outbox) {
        debug!("AL poll called, ROI state: {:?}", self.read_on_init);
        self.read_on_init_step(outbox);
    }

    fn init(&mut self) {
        self.init_read_on_init();
    }
}

impl<'a, D: StackDefinition> ApplicationLayer<'a, D>
where
    D::State: HasApplication + HasAssociationTable + HasCommunicationObjectTable + HasConnectionAuth,
    D::InterfaceObjects<'static>: HasDeviceObject,
{
    /// Initialize the read-on-init cycle if the application is already running.
    ///
    /// Called by the router after constructing the handler set, before entering
    /// the main event loop.
    pub fn init_read_on_init(&mut self) {
        let running = self.state.app().borrow().is_running();
        let loaded = self.state.ast().borrow().is_loaded();
        debug!("AL init_read_on_init: app_running={}, ast_loaded={}", running, loaded);
        if running && loaded {
            info!("AL read-on-init: starting cycle (app already running at startup)");
            self.read_on_init = ReadOnInitState::Scanning(1);
        }
    }

    /// Handle a confirmation from the transport layer.
    ///
    /// If a group value send is pending, updates the communication object
    /// status based on the confirmation result. Otherwise the confirmation
    /// is for a response (e.g., property read reply) and can be dropped.
    fn handle_tl_confirmation(&mut self, conf: &KnxMessageBuffer<Buffer<'static>>) {
        if let Some(pending) = self.pending_group_send.take() {
            debug!("AL TL confirmation for ASAP {}: {:?}", pending.asap, conf.service_type());

            if conf.ctrl_field().c() == Confirm::NoError {
                if pending.read {
                    self.comm_objects.borrow_mut().set_status(pending.asap, ComObjectStatus::ReadRequest);
                } else {
                    self.comm_objects.borrow_mut().set_status(pending.asap, ComObjectStatus::IdleOk);
                }
            } else {
                let new_status =
                    if pending.read { ComObjectStatus::ReadRequestError } else { ComObjectStatus::WriteRequestError };
                self.comm_objects.borrow_mut().set_status(pending.asap, new_status);
            }
        } else {
            // Confirmation for a send_response call — just log
            trace!("AL TL confirmation (response): {:?}", conf.service_type());
        }
    }

    /// Handle an application service request from user code.
    ///
    /// Called by the router when an app request arrives (not via the dispatch
    /// table, since these aren't KnxMessageBuffer messages).
    pub fn handle_app_request(
        &mut self,
        request: &Request<ApplicationLayerService, ApplicationLayerServiceResponse>,
        outbox: &mut Outbox,
    ) {
        match request.get() {
            r @ ApplicationLayerService::GroupValueWriteRequest(asap) => {
                debug!("AL GroupValueWrite.req: {:?}", r);

                let response = if self.send_group_value_request(*asap, false, outbox) {
                    ApplicationLayerServiceResponse::GroupValueWriteResponse
                } else {
                    ApplicationLayerServiceResponse::ApplicationNotRunning
                };
                request.try_reply(response).ok();
            }
            r @ ApplicationLayerService::GroupValueReadRequest(asap) => {
                debug!("AL GroupValueRead.req: {:?}", r);

                let response = if self.send_group_value_request(*asap, true, outbox) {
                    ApplicationLayerServiceResponse::GroupValueReadResponse
                } else {
                    ApplicationLayerServiceResponse::ApplicationNotRunning
                };
                request.try_reply(response).ok();
            }
        }
    }
}

// ============================================================================
// Group Communication Services (A_GroupValue_*)
// ============================================================================

impl<'a, D: StackDefinition> ApplicationLayer<'a, D>
where
    D::State: HasApplication + HasAssociationTable + HasCommunicationObjectTable,
{
    /// Handle `A_GroupValue_Write.ind` or `A_GroupValue_Response.ind`
    ///
    /// Updates local communication objects with values received from the bus.
    /// Only valid for `T_GroupData_Ind` service type.
    fn handle_group_value_write_or_response(
        &mut self,
        ind: &mut KnxMessageBuffer<Buffer<'static>>,
        apci: ApciCode,
        _outbox: &mut Outbox,
    ) {
        // Validate service type
        if ind.service_type() != ServiceType::T_GroupData_Ind {
            warn!("AL {:?} with unexpected service type: {:?}", apci, ind.service_type());
            return;
        }

        debug!("AL received {:?}", apci);

        // Check if application is running before processing group data
        if !self.state.app().borrow().is_running() {
            debug!("AL {:?} ignored: application not running", apci);
            return;
        }

        // Check if association table is loaded before processing
        if !self.state.ast().borrow().is_loaded() {
            debug!("AL {:?} ignored: AST not loaded", apci);
            return;
        }

        trace!("AL incoming TSAP: {:?}", ind.get_connection_nr());

        for asap in self.state.ast().borrow().asaps_for_tsap(ind.get_connection_nr()) {
            trace!("AL processing ASAP: {}", asap);

            let Some(cot_info) = self.state.cot().borrow().get_object(asap) else {
                error!("Invalid ASAP: {}", asap);
                continue;
            };

            // Check communication enable flag first (applies to both Write and Response)
            if !cot_info.flags.communication_enable() {
                debug!("AL {:?} for ASAP {} ignored (comm disabled)", apci, asap);
                continue;
            }

            // For GroupValue_Write: check write_enable
            // For GroupValue_Response: check BOTH write_enable AND update_enable
            // BCU1/BCU2 behavior: write_enable gates both Write and Response processing
            if matches!(apci, ApciCode::GroupValueWrite) && !cot_info.flags.write_enable() {
                debug!("AL GroupValueWrite for ASAP {} ignored (write disabled)", asap);
                continue;
            }

            if matches!(apci, ApciCode::GroupValueResponse)
                && (!cot_info.flags.write_enable() || !cot_info.flags.update_enable())
            {
                debug!("AL GroupValueResponse for ASAP {} ignored (write/update disabled)", asap);
                continue;
            }

            let (object_size, msg_offset) = Self::get_object_size_and_offset(&cot_info);

            // Check if incoming message is long enough to carry a comm object value
            if ind.len() == object_size + msg_offset {
                // Set the APCI to all zeros, because we don't need it anymore
                // We do that so that we can just copy out the DPT even if the
                // object type is one of the small ones with <= 6 bit. If the APCI
                // wasn't all zeros in this case, we would copy the two lowermost
                // bits of the "small" APCI code with the comm object value

                ind.set_apci_code(ApciCode::Empty);

                {
                    let mut objs = self.comm_objects.borrow_mut();

                    objs.value_mut(asap).copy_from_slice(&ind.buf()[msg_offset..msg_offset + object_size]);
                    objs.set_status(asap, ComObjectStatus::Updated);

                    // Call write hook
                    objs.handle_write(asap, self.hook_context);
                }

                // Publish event to the event channel
                if let Some(index) = <<D as StackDefinition>::CO as ComObjects>::Index::from_index(asap) {
                    match apci {
                        ApciCode::GroupValueWrite => {
                            self.event_channel.publish_immediate((index, ComObjectEvent::Updated));
                        }
                        ApciCode::GroupValueResponse => {
                            self.event_channel.publish_immediate((index, ComObjectEvent::ReadResponse));
                        }
                        _ => unreachable!(),
                    }
                }

                debug!(
                    "AL ASAP {} updated via {:?}: {:?}",
                    asap,
                    apci,
                    crate::fmt::Bytes(self.comm_objects.borrow().value(asap))
                );
            } else {
                error!("Length of telegram not enough to contain object value");
            }
        }
    }

    /// Handle `A_GroupValue_Read.ind`
    ///
    /// Responds with the current value of the communication object.
    /// Only valid for `T_GroupData_Ind` service type.
    fn handle_group_value_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        // Validate service type
        if ind.service_type() != ServiceType::T_GroupData_Ind {
            warn!("AL GroupValueRead with unexpected service type: {:?}", ind.service_type());
            return;
        }

        // Per KNX spec, GroupValue_Read should have a data field of 0x00
        // Some implementations (test case 1.4.1.7) send non-zero values which should be ignored
        let short_data = ind.get_short_apci_data();
        if short_data != 0 {
            debug!("AL GroupValueRead ignored: invalid data field 0x{:02X} (expected 0x00)", short_data);
            return;
        }

        debug!("AL received GroupValueRead");

        // Check if application is running before processing group data
        if !self.state.app().borrow().is_running() {
            debug!("AL GroupValueRead ignored: application not running");
            return;
        }

        // Check if association table is loaded before processing
        if !self.state.ast().borrow().is_loaded() {
            debug!("AL GroupValueRead ignored: AST not loaded");
            return;
        }

        // Get the priority from the incoming request - response should mirror it
        // This is BCU1/BCU2 compatible behavior as per EITT tests
        let request_priority = ind.ctrl_field().priority();

        let tsap = ind.get_connection_nr();
        trace!("AL incoming TSAP: {:?}", tsap);

        for asap in self.state.ast().borrow().asaps_for_tsap(tsap) {
            trace!("AL processing GroupValueRead for ASAP: {}", asap);

            let Some(cot_info) = self.state.cot().borrow().get_object(asap) else {
                error!("Invalid ASAP: {}", asap);
                continue;
            };

            // Check if communication and read are enabled for this object
            if !cot_info.flags.communication_enable() || !cot_info.flags.read_enable() {
                debug!("AL GroupValueRead for ASAP {} ignored (comm/read flag)", asap);
                continue;
            }

            // Determine the size and offset for the response
            let (object_size, msg_offset) = Self::get_object_size_and_offset(&cot_info);

            info!("AL sending GroupValueResponse for ASAP {} TSAP {} size {}", asap, tsap, object_size);

            // Call read hook
            self.comm_objects.borrow_mut().prepare_read(asap, self.hook_context);

            // Allocate a new message for the response
            let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(object_size + msg_offset) else {
                warn!("AL no buffer for response");
                return;
            };

            // Build the GroupValueResponse message
            // Note: We can't use respond_with() because group communication uses connection_nr (TSAP)
            // instead of individual addressing, so we manually build with the required fields
            let mut msg = KnxMessageBuffer::new(msg_buf, ServiceType::T_GroupData_Req);
            // Mirror the priority from the incoming request (BCU1/BCU2 compatible behavior)
            msg.ctrl_field_mut().set_priority(request_priority);
            msg.set_connection_nr(tsap);

            // Copy the current value from the communication object
            msg.buf_mut()[msg_offset..msg_offset + object_size].copy_from_slice(self.comm_objects.borrow().value(asap));

            // Set APCI code AFTER copying data to avoid overwriting when data fits in 6 bits
            msg.set_apci_code(ApciCode::GroupValueResponse);

            // Send the response
            outbox.push(msg);

            trace!(
                "AL sent GroupValueResponse for ASAP {}: {:?}",
                asap,
                crate::fmt::Bytes(self.comm_objects.borrow().value(asap))
            );

            // Publish read event to the event channel
            if let Some(index) = <<D as StackDefinition>::CO as ComObjects>::Index::from_index(asap) {
                self.event_channel.publish_immediate((index, ComObjectEvent::Read));
            }
        }
    }

    /// Send `A_GroupValue_Write.req` or `A_GroupValue_Read.req`
    ///
    /// Called when the local application wants to send a group value to the bus.
    /// Returns `true` if the request was processed, `false` if rejected because
    /// the application is not running.
    fn send_group_value_request(&mut self, asap: u16, read: bool, outbox: &mut Outbox) -> bool {
        // Check if application is running before sending group data
        if !self.state.app().borrow().is_running() {
            debug!("AL GroupValue request ignored: application not running");
            return false;
        }

        // Check if association table is loaded before sending
        if !self.state.ast().borrow().is_loaded() {
            debug!("AL GroupValue request ignored: AST not loaded");
            return true; // Not an "app not running" error, just a config issue
        }

        let Some(cot_info) = self.state.cot().borrow().get_object(asap) else {
            error!("Invalid ASAP: {}", asap);
            return true; // Not an "app not running" error
        };

        let status = *self.comm_objects.borrow().info(asap).status;

        if !read && status != ComObjectStatus::WriteRequest {
            return true;
        }

        if read && status != ComObjectStatus::ReadRequest {
            return true;
        }

        if !cot_info.flags.communication_enable() {
            // Communication disabled - set error status but preserve the request type
            // BCU1/BCU2 behavior: Read/Write request stays pending with error indication
            let new_status = if read { ComObjectStatus::ReadRequestError } else { ComObjectStatus::WriteRequestError };
            self.comm_objects.borrow_mut().set_status(asap, new_status);

            debug!("AL comm object {} not enabled for communication (flags=0x{:02x})", asap, cot_info.flags.to_byte());
            return true;
        }

        if !cot_info.flags.transmission_enable() {
            // Transmission disabled - set error status but preserve the request type
            let new_status = if read { ComObjectStatus::ReadRequestError } else { ComObjectStatus::WriteRequestError };
            self.comm_objects.borrow_mut().set_status(asap, new_status);

            debug!("AL comm object {} transmission not enabled", asap);
            return true;
        }

        self.comm_objects.borrow_mut().set_status(asap, ComObjectStatus::Busy);

        // We only send to the first TSAP per spec.
        // Extract TSAP before entering the block to avoid holding the RefCell
        // borrow across the buffer allocation and transport layer awaits below.
        let sending_tsap = self.state.ast().borrow().get_sending_tsap(asap);
        if let Some(tsap) = sending_tsap {
            trace!("AL found sending TSAP {} for ASAP {}", tsap, asap);

            // Determine the length of this comm obj and the offset in the message
            // The offset can be 7 for objects with len <= 6 bits because it fits
            // into the unused six bits of the short APCI codes.
            let (object_size, msg_offset) = match (read, cot_info.object_type.size_in_bytes()) {
                // GroupValueWrite.req
                (false, (s, true)) => (s, offsets::MSG_APCI + 1),
                (false, (s, false)) => (s, offsets::MSG_APDU),

                // GroupValueRead.req
                // We need at least 1 byte for the lowermost two bits of the APCI code,
                // the lowermost six bits of this byte are unused
                (true, _) => (1, offsets::MSG_APCI + 1),
            };

            debug!(
                "AL preparing {} ASAP {} TSAP {} size {} offset {}",
                if read { "GroupValueRead" } else { "GroupValueWrite" },
                asap,
                tsap,
                object_size,
                msg_offset
            );

            // Allocate a new message with the required size
            let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(object_size + msg_offset) else {
                warn!("AL no buffer for response");
                return true;
            };

            // Note: We don't use MessageBuilder here because group communication uses
            // connection_nr (TSAP) instead of individual addressing, which the builder
            // doesn't support yet. Group services have different semantics.
            let mut msg = KnxMessageBuffer::new(msg_buf, ServiceType::T_GroupData_Req);

            // Fill in a few other fields
            msg.ctrl_field_mut().set_priority(cot_info.flags.priority());
            if read {
                msg.set_apci_code(ApciCode::GroupValueRead);
            } else {
                // Copy the value of the communication objet into the message
                msg.buf_mut()[msg_offset..msg_offset + object_size]
                    .copy_from_slice(self.comm_objects.borrow().value(asap));

                msg.set_apci_code(ApciCode::GroupValueWrite);
            }

            // Set connection number from sending assoc nr
            msg.set_connection_nr(tsap);

            // Store pending state so the TL confirmation (arriving later on
            // conf_rx) can update the CO status.
            self.pending_group_send = Some(PendingGroupSend { asap, read });

            // Send fire-and-forget to TL — confirmation handled in handle_tl_confirmation
            debug!("AL -> TL: GroupValue {} ASAP {} TSAP {}", if read { "Read" } else { "Write" }, asap, tsap);
            outbox.push(msg);
        } else {
            // No sending TSAP found - error
            let new_status = if read { ComObjectStatus::ReadRequestError } else { ComObjectStatus::WriteRequestError };
            self.comm_objects.borrow_mut().set_status(asap, new_status);

            error!("AL no sending TSAP or transmission flag not set for ASAP {} - Flags: {:?}", asap, cot_info.flags);
        }

        true
    }

    // ========================================================================
    // Read-On-Init
    // ========================================================================

    /// Process one step of the read-on-init cycle.
    ///
    /// Scans forward from the current cursor position to find the next
    /// communication object eligible for a read-on-init request and sends
    /// a `A_GroupValue_Read.req` for it. One object is processed per call
    /// to avoid blocking normal traffic.
    ///
    /// An object is eligible when ALL of these hold:
    /// 1. Its COT entry has the ROI flag set
    /// 2. Its runtime status is `Uninitialized` (value not yet valid)
    /// 3. It has at least one association in the AST (is linked)
    ///
    /// Objects that are `Uninitialized` are transitioned to `IdleOk` during
    /// the scan regardless of ROI eligibility, per the conformance suite
    /// behavior of clearing RAM flags as it walks through objects.
    ///
    /// After a successful L2 send, the object goes to `IdleOk` (matching
    /// the CO-idle action). If a `GroupValue_Response` arrives
    /// later, it will update the value normally. If nobody answers, the
    /// object simply stays idle — no application-level timeout is needed.
    fn read_on_init_step(&mut self, outbox: &mut Outbox) {
        let ReadOnInitState::Scanning(start) = self.read_on_init else {
            return;
        };

        // Cancel if app is no longer running or AST not loaded.
        if !self.state.app().borrow().is_running() {
            debug!("AL read-on-init: cancelled (app not running)");
            self.read_on_init = ReadOnInitState::Idle;
            return;
        }
        if !self.state.ast().borrow().is_loaded() {
            debug!("AL read-on-init: cancelled (AST not loaded)");
            self.read_on_init = ReadOnInitState::Idle;
            return;
        }

        let entry_count = self.state.cot().borrow().entry_count();
        let mut cursor = start;

        // COT is 1-indexed: valid ASAPs are 1..=entry_count.
        while cursor <= entry_count {
            let asap = cursor;
            cursor += 1;

            let Some(cot_info) = self.state.cot().borrow().get_object(asap) else {
                continue;
            };

            // Transition Uninitialized objects to IdleOk (clear RAM
            // flags). Capture whether the object was uninitialized before
            // the transition so we can check value validity.
            let was_uninitialized = {
                let status = self.comm_objects.borrow().status(asap);
                if status == ComObjectStatus::Uninitialized {
                    self.comm_objects.borrow_mut().set_status(asap, ComObjectStatus::IdleOk);
                    true
                } else {
                    false
                }
            };

            // 1. ROI flag must be set
            if !cot_info.flags.read_on_init() {
                continue;
            }

            // 2. Value must not have been valid (was Uninitialized)
            if !was_uninitialized {
                debug!("AL read-on-init: ASAP {} skipped (value already valid)", asap);
                continue;
            }

            // 3. Object must be linked (has an association)
            if self.state.ast().borrow().get_sending_tsap(asap).is_none() {
                debug!("AL read-on-init: ASAP {} skipped (not linked)", asap);
                continue;
            }

            // Found an eligible object — send GroupValueRead.req.
            // The CO status update (ReadRequest → IdleOk or error) happens
            // asynchronously when the TL confirmation arrives on conf_rx.
            info!("AL read-on-init: sending GroupValueRead for ASAP {}", asap);
            self.comm_objects.borrow_mut().set_status(asap, ComObjectStatus::ReadRequest);
            self.send_group_value_request(asap, true, outbox);

            // Save cursor for next call and return (one object per step)
            self.read_on_init = ReadOnInitState::Scanning(cursor);
            return;
        }

        // All objects scanned — cycle complete.
        info!("AL read-on-init: cycle complete ({} objects scanned)", entry_count);
        self.read_on_init = ReadOnInitState::Idle;
    }
}

// ============================================================================
// Property Services (A_PropertyDescription_*, A_PropertyValue_*)
// ============================================================================

impl<'a, D: StackDefinition> ApplicationLayer<'a, D>
where
    D::State: HasApplication + HasConnectionAuth,
    D::InterfaceObjects<'static>: HasDeviceObject,
{
    /// Handle `A_PropertyDescription_Read.ind`
    ///
    /// Returns property metadata (type, max elements, access rights) for an interface object.
    ///
    /// This service can arrive via:
    /// - `T_Data_Ind` (connection-oriented) → respond with `T_Data_Req`
    /// - `T_DataUnack_Ind` (connectionless) → respond with `T_DataUnack_Req`
    ///
    /// Message format (incoming):
    /// - APDU[0-1]: APCI (0x03D8 for PropertyDescriptionRead)
    /// - APDU[2]: Object Index
    /// - APDU[3]: Property ID (0 = search by prop_idx)
    /// - APDU[4]: Property Index
    ///
    /// Response format:
    /// - APDU[0-1]: APCI (0x03D9 for PropertyDescriptionResponse)
    /// - APDU[2]: Object Index
    /// - APDU[3]: Property ID
    /// - APDU[4]: Property Index
    /// - APDU[5-6]: Type + MaxElements
    /// - APDU[7]: Read/Write Access Levels
    fn handle_property_description_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::messages::builder::IndicationExt;

        // Determine response service type based on incoming service type
        let response_service_type = match ind.service_type() {
            ServiceType::T_Data_Ind => ServiceType::T_Data_Req,
            ServiceType::T_DataUnack_Ind => ServiceType::T_DataUnack_Req,
            other => {
                warn!("AL PropertyDescriptionRead unexpected service type: {:?}", other);
                return;
            }
        };

        // PropertyDescriptionRead APDU: [APCI:2][ObjIdx:1][PropId:1][PropIdx:1]
        // Minimum length: MSG_APCI + 5 = 11 bytes
        const MIN_LEN: usize = offsets::MSG_APCI + 5;

        if (ind.len()) < MIN_LEN {
            error!("PropertyDescriptionRead message too short: {} < {}", ind.len(), MIN_LEN);
            return;
        }

        let buf = ind.buf();
        let object_idx = buf[offsets::MSG_APCI + 2] as u16;
        let prop_id = buf[offsets::MSG_APCI + 3];
        let prop_idx = buf[offsets::MSG_APCI + 4];

        debug!("AL PropertyDescriptionRead: obj={}, prop_id={}, prop_idx={}", object_idx, prop_id, prop_idx);

        // Query the interface object server
        let response = self.interface_objects.property_description_read(object_idx, prop_id, prop_idx);

        match response {
            Ok(desc) => {
                // Allocate response message: APCI(2) + ObjectIdx(1) + PropId(1) + PropIdx(1) + Type(1) + MaxElements(2) + Access(1) = 9
                const RESPONSE_LEN: usize = offsets::MSG_APCI + 9;
                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(RESPONSE_LEN) else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg = ind
                    .respond_with(msg_buf)
                    .with_application(ApciCode::PropertyDescriptionResponse, response_service_type)
                    .with_data(|data| {
                        // Encode the response into the message buffer
                        let response_buf = &mut data[offsets::MSG_APCI + 2..];
                        let _len = desc.encode(response_buf);
                    });

                debug!("AL sending PropertyDescriptionResponse: {:?}", desc);

                // Send the response
                outbox.push(msg.into_inner());
            }
            Err(e) => {
                // Send negative response: echo back ObjIdx and PID, set all descriptor fields to 0
                warn!("AL PropertyDescriptionRead failed: {:?}", e);

                // Full response: APCI(2) + ObjIdx(1) + PID(1) + PropIdx(1) + Type(1) + MaxNo(2) + Access(1) = 9
                const ERROR_RESPONSE_LEN: usize = offsets::MSG_APCI + 9;
                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(ERROR_RESPONSE_LEN) else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg = ind
                    .respond_with(msg_buf)
                    .with_application(ApciCode::PropertyDescriptionResponse, response_service_type)
                    .with_data(|data| {
                        // Echo back ObjIdx, PID, PropIdx from request; set descriptor fields to 0
                        data[offsets::MSG_APCI + 2] = object_idx as u8;
                        data[offsets::MSG_APCI + 3] = prop_id;
                        data[offsets::MSG_APCI + 4] = prop_idx;
                        data[offsets::MSG_APCI + 5] = 0; // Type (WrEnab=0, PDT=0)
                        data[offsets::MSG_APCI + 6] = 0; // MaxNo high byte
                        data[offsets::MSG_APCI + 7] = 0; // MaxNo low byte
                        data[offsets::MSG_APCI + 8] = 0; // Access (ReadAcc=0, WriteAcc=0)
                    });

                outbox.push(msg.into_inner());
            }
        }
    }

    /// Handle `A_PropertyValue_Read.ind`
    ///
    /// Reads property data from an interface object.
    ///
    /// This service can arrive via:
    /// - `T_Data_Ind` (connection-oriented) → respond with `T_Data_Req`
    /// - `T_DataUnack_Ind` (connectionless) → respond with `T_DataUnack_Req`
    ///
    /// Message format (incoming):
    /// - APDU[0-1]: APCI (0x03D5 for PropertyValueRead)
    /// - APDU[2]: Object Index
    /// - APDU[3]: Property ID
    /// - APDU[4-5]: [Count:4bits][StartIndex:12bits]
    ///
    /// Response format:
    /// - APDU[0-1]: APCI (0x03D6 for PropertyValueResponse)
    /// - APDU[2]: Object Index
    /// - APDU[3]: Property ID
    /// - APDU[4-5]: [Count:4bits][StartIndex:12bits]
    /// - APDU[6..]: Data
    fn handle_property_value_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::messages::builder::IndicationExt;

        // Determine response service type based on incoming service type
        let response_service_type = match ind.service_type() {
            ServiceType::T_Data_Ind => ServiceType::T_Data_Req,
            ServiceType::T_DataUnack_Ind => ServiceType::T_DataUnack_Req,
            other => {
                warn!("AL PropertyValueRead unexpected service type: {:?}", other);
                return;
            }
        };

        // PropertyValueRead APDU: [APCI:2][ObjIdx:1][PropId:1][Count+StartIdx:2]
        // Minimum length: MSG_APCI + 6 = 12 bytes
        const MIN_LEN: usize = offsets::MSG_APCI + 6;

        if ind.len() < MIN_LEN {
            error!("PropertyValueRead message too short: {} < {}", ind.len(), MIN_LEN);
            return;
        }

        let buf = ind.buf();
        let object_idx = buf[offsets::MSG_APCI + 2] as u16;
        let prop_id = buf[offsets::MSG_APCI + 3];
        let count_start = ((buf[offsets::MSG_APCI + 4] as u16) << 8) | (buf[offsets::MSG_APCI + 5] as u16);
        let count = count_start >> 12;
        let start_idx = count_start & 0x0FFF;

        let access_ctx = self.resolve_access(ind);
        debug!(
            "AL PropertyValueRead: obj={}, prop_id={}, count={}, start={}, access_ctx={:?}",
            object_idx, prop_id, count, start_idx, access_ctx
        );

        // Allocate a buffer for the response data
        // Max APDU size is typically 14 bytes for TP1, so max data is about 8 bytes
        // We'll use a reasonable max and let the handler limit it
        const MAX_PROPERTY_DATA: usize = 64;
        let mut data_buf = [0u8; MAX_PROPERTY_DATA];

        // Query the interface object server
        let req = FullPropertyReadRequest { object_idx, pid: prop_id, start_idx, count, ctx: access_ctx };
        let result = self.interface_objects.property_value_read(&req, &mut data_buf);

        match result {
            Ok(data_len) => {
                // Allocate response message: APCI(2) + ObjIdx(1) + PropId(1) + Count+StartIdx(2) + Data(N)
                let response_len = offsets::MSG_APCI + 6 + data_len;
                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(response_len) else {
                    warn!("AL no buffer for response");
                    return;
                };

                // Build the response count_start field
                // Per KNX spec: if start_idx=0 (element count query), response must have nr_of_elem=1
                let response_count_start = if start_idx == 0 {
                    // Element count query: respond with count=1, start_idx=0
                    1u16 << 12
                } else {
                    // Normal read: echo back the original count_start
                    count_start
                };

                let msg = ind
                    .respond_with(msg_buf)
                    .with_application(ApciCode::PropertyValueResponse, response_service_type)
                    .with_data(|data| {
                        // Fill in the response header
                        data[offsets::MSG_APCI + 2] = object_idx as u8;
                        data[offsets::MSG_APCI + 3] = prop_id;
                        data[offsets::MSG_APCI + 4] = (response_count_start >> 8) as u8;
                        data[offsets::MSG_APCI + 5] = response_count_start as u8;

                        // Copy the data
                        data[offsets::MSG_APCI + 6..offsets::MSG_APCI + 6 + data_len]
                            .copy_from_slice(&data_buf[..data_len]);
                    });

                debug!("AL sending PropertyValueResponse: {} bytes", data_len);

                // Send the response
                outbox.push(msg.into_inner());
            }
            Err(e) => {
                // Send error response with count = 0
                warn!("AL PropertyValueRead failed: {:?}", e);

                const ERROR_RESPONSE_LEN: usize = offsets::MSG_APCI + 6;
                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(ERROR_RESPONSE_LEN) else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg = ind
                    .respond_with(msg_buf)
                    .with_application(ApciCode::PropertyValueResponse, response_service_type)
                    .with_data(|data| {
                        // Error response: count = 0 indicates error
                        data[offsets::MSG_APCI + 2] = object_idx as u8;
                        data[offsets::MSG_APCI + 3] = prop_id;
                        // Count = 0, keep start_idx
                        data[offsets::MSG_APCI + 4] = (start_idx >> 8) as u8;
                        data[offsets::MSG_APCI + 5] = start_idx as u8;
                    });

                outbox.push(msg.into_inner());
            }
        }
    }

    /// Handle `A_PropertyValue_Write.ind`
    ///
    /// Writes property data to an interface object.
    ///
    /// This service can arrive via:
    /// - `T_Data_Ind` (connection-oriented) → respond with `T_Data_Req`
    /// - `T_DataUnack_Ind` (connectionless) → respond with `T_DataUnack_Req`
    ///
    /// Message format (incoming):
    /// - APDU[0-1]: APCI (0x03D7 for PropertyValueWrite)
    /// - APDU[2]: Object Index
    /// - APDU[3]: Property ID
    /// - APDU[4-5]: [Count:4bits][StartIndex:12bits]
    /// - APDU[6..]: Data to write
    ///
    /// Response format (same as PropertyValueResponse):
    /// - APDU[0-1]: APCI (0x03D6 for PropertyValueResponse)
    /// - APDU[2]: Object Index
    /// - APDU[3]: Property ID
    /// - APDU[4-5]: [Count:4bits][StartIndex:12bits] (count=0 on error)
    /// - APDU[6..]: Written data (echo back on success)
    fn handle_property_value_write(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::messages::builder::IndicationExt;

        // Determine response service type based on incoming service type
        let response_service_type = match ind.service_type() {
            ServiceType::T_Data_Ind => ServiceType::T_Data_Req,
            ServiceType::T_DataUnack_Ind => ServiceType::T_DataUnack_Req,
            other => {
                warn!("AL PropertyValueWrite unexpected service type: {:?}", other);
                return;
            }
        };

        // PropertyValueWrite APDU: [APCI:2][ObjIdx:1][PropId:1][Count+StartIdx:2][Data:N]
        // Minimum length: MSG_APCI + 6 = 12 bytes (at least header, data can be 0 for some cases)
        const MIN_LEN: usize = offsets::MSG_APCI + 6;

        if ind.len() < MIN_LEN {
            error!("PropertyValueWrite message too short: {} < {}", ind.len(), MIN_LEN);
            return;
        }

        let buf = ind.buf();
        let object_idx = buf[offsets::MSG_APCI + 2] as u16;
        let prop_id = buf[offsets::MSG_APCI + 3];
        let count_start = ((buf[offsets::MSG_APCI + 4] as u16) << 8) | (buf[offsets::MSG_APCI + 5] as u16);
        let count = count_start >> 12;
        let start_idx = count_start & 0x0FFF;

        // Extract the data to write
        let data_start = offsets::MSG_APCI + 6;
        let data_len = ind.len() - data_start;
        let data = &buf[data_start..data_start + data_len];

        let access_ctx = self.resolve_access(ind);
        debug!(
            "AL PropertyValueWrite: obj={}, prop_id={}, count={}, start={}, data_len={}, access_ctx={:?}",
            object_idx, prop_id, count, start_idx, data_len, access_ctx
        );

        // Capture run state before property writes that might change it.
        // Both LOAD_STATE_CONTROL and RUN_STATE_CONTROL can affect the run state:
        // LOAD_STATE_CONTROL cascades into the RSM via RunnableApplication::write_lsm()
        // (e.g., LoadCompleted triggers HALTED → READY → RUNNING automatically).
        let was_running = if prop_id == pid::LOAD_STATE_CONTROL || prop_id == pid::RUN_STATE_CONTROL {
            Some(self.state.app().borrow().is_running())
        } else {
            None
        };

        // Perform the write - the response may differ from written data (e.g., LOAD_STATE_CONTROL)
        let req = FullPropertyWriteRequest { object_idx, pid: prop_id, start_idx, data, ctx: access_ctx };
        let result = self.interface_objects.property_value_write(&req);

        // Sync DeviceControl.user_stopped and publish lifecycle events on run state transitions.
        if let Some(was_running) = was_running
            && result.is_ok()
        {
            let is_running = self.state.app().borrow().is_running();
            if was_running != is_running {
                self.interface_objects.set_user_stopped(!is_running);
                self.lifecycle_channel.publish_immediate(if is_running {
                    LifecycleEvent::ApplicationStarted
                } else {
                    LifecycleEvent::ApplicationStopped
                });

                // Activate or cancel the read-on-init cycle.
                if is_running {
                    info!("AL read-on-init: starting cycle (app transitioned to running)");
                    self.read_on_init = ReadOnInitState::Scanning(1);
                } else {
                    self.read_on_init = ReadOnInitState::Idle;
                }
            }
        }

        match result {
            Ok(write_response) => {
                // Success: send response with the data returned by the write operation
                // WriteResponse::Echo means echo back the original data
                // WriteResponse::Data contains transformed data (e.g., LOAD_STATE_CONTROL)
                let response_data: &[u8] = write_response.as_slice().unwrap_or(data);
                let response_data_len = response_data.len();
                let response_len = offsets::MSG_APCI + 6 + response_data_len;
                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(response_len) else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg = ind
                    .respond_with(msg_buf)
                    .with_application(ApciCode::PropertyValueResponse, response_service_type)
                    .with_data(|response_buf| {
                        response_buf[offsets::MSG_APCI + 2] = object_idx as u8;
                        response_buf[offsets::MSG_APCI + 3] = prop_id;
                        response_buf[offsets::MSG_APCI + 4] = (count_start >> 8) as u8;
                        response_buf[offsets::MSG_APCI + 5] = count_start as u8;

                        // Copy response data (echoed write data or transformed data like load state)
                        response_buf[offsets::MSG_APCI + 6..offsets::MSG_APCI + 6 + response_data_len]
                            .copy_from_slice(response_data);
                    });

                debug!("AL sending PropertyValueResponse (write success): {} bytes", response_data_len);

                outbox.push(msg.into_inner());
            }
            Err(e) => {
                // Error: respond with count = 0
                warn!("AL PropertyValueWrite failed: {:?}", e);

                const ERROR_RESPONSE_LEN: usize = offsets::MSG_APCI + 6;
                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(ERROR_RESPONSE_LEN) else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg = ind
                    .respond_with(msg_buf)
                    .with_application(ApciCode::PropertyValueResponse, response_service_type)
                    .with_data(|response_buf| {
                        // Error response: count = 0 indicates error
                        response_buf[offsets::MSG_APCI + 2] = object_idx as u8;
                        response_buf[offsets::MSG_APCI + 3] = prop_id;
                        // Count = 0, keep start_idx
                        response_buf[offsets::MSG_APCI + 4] = (start_idx >> 8) as u8;
                        response_buf[offsets::MSG_APCI + 5] = start_idx as u8;
                    });

                outbox.push(msg.into_inner());
            }
        }
    }
}

// ============================================================================
// Device Management Services (A_DeviceDescriptor_Read, ...)
// ============================================================================

impl<'a, D: StackDefinition> ApplicationLayer<'a, D>
where
    D::State: HasConnectionAuth,
    D::InterfaceObjects<'static>: HasDeviceObject,
{
    /// Handle `A_DeviceDescriptor_Read.ind`
    ///
    /// Responds with the device descriptor (mask version) for descriptor type 0.
    /// For any other descriptor type, responds with an error (type 0x3F, no data).
    ///
    /// This service can arrive via:
    /// - `T_Data_Ind` (connection-oriented) → respond with `T_Data_Req`
    /// - `T_DataUnack_Ind` (connectionless) → respond with `T_DataUnack_Req`
    ///
    /// Message format (incoming):
    /// - APDU[0-1]: APCI (contains DeviceDescriptorRead code with descriptor type in low 6 bits)
    ///
    /// Response format:
    /// - APDU[0-1]: APCI (DeviceDescriptorResponse with descriptor type in low 6 bits)
    /// - APDU[2-3]: Mask version (only if descriptor type is 0)
    fn handle_device_descriptor_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::messages::builder::IndicationExt;

        // DeviceDescriptorRead APDU: [APCI:2] where the descriptor type is in the lower 6 bits
        // Minimum length: MSG_APCI + 2 = 8 bytes
        const MIN_LEN: usize = offsets::MSG_APCI + 2;

        if ind.len() < MIN_LEN {
            error!("DeviceDescriptorRead message too short: {} < {}", ind.len(), MIN_LEN);
            return;
        }

        // Extract descriptor type from the lower 6 bits of the APCI
        let buf = ind.buf();
        let descriptor_type = buf[offsets::MSG_APCI + 1] & 0x3F;

        debug!("AL DeviceDescriptorRead: descriptor_type={}", descriptor_type);

        // Determine transport service type
        let transport_service = match ind.service_type() {
            ServiceType::T_Data_Ind => ServiceType::T_Data_Req,
            ServiceType::T_DataUnack_Ind => ServiceType::T_DataUnack_Req,
            other => {
                warn!("AL DeviceDescriptorRead unexpected service type: {:?}", other);
                return;
            }
        };

        if descriptor_type == 0 {
            // Descriptor type 0: respond with mask version (2 bytes)
            const RESPONSE_LEN: usize = offsets::MSG_APCI + 4; // APCI(2) + MaskVersion(2)
            let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(RESPONSE_LEN) else {
                warn!("AL no buffer for response");
                return;
            };

            let msg = ind
                .respond_with(msg_buf)
                .with_application(ApciCode::DeviceDescriptorResponse, transport_service)
                .with_data(|data| {
                    // Set descriptor type to 0 in the response
                    data[offsets::MSG_APCI + 1] = data[offsets::MSG_APCI + 1] & 0xC0;
                    // Copy mask version from device descriptor
                    let mask_version = D::DEVICE.mask_version_bytes();
                    data[offsets::MSG_APCI + 2..offsets::MSG_APCI + 4].copy_from_slice(&mask_version);
                });

            debug!("AL sending DeviceDescriptorResponse: mask_version={}", D::DEVICE.mask_version);

            outbox.push(msg.into_inner());
        } else if descriptor_type == 2 {
            // Descriptor type 2: respond with extended device info (14 bytes) if supported
            if let Some(dd2) = D::DEVICE_DESCRIPTOR_TYPE2 {
                const RESPONSE_LEN: usize = offsets::MSG_APCI + 16; // APCI(2) + DD2(14)
                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(RESPONSE_LEN) else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg = ind
                    .respond_with(msg_buf)
                    .with_application(ApciCode::DeviceDescriptorResponse, transport_service)
                    .with_data(|data| {
                        // Set descriptor type to 2 in the response
                        data[offsets::MSG_APCI + 1] = (data[offsets::MSG_APCI + 1] & 0xC0) | 0x02;
                        // Copy DD2 data
                        data[offsets::MSG_APCI + 2..offsets::MSG_APCI + 16].copy_from_slice(dd2);
                    });

                debug!("AL sending DeviceDescriptorResponse (DD2): {:?}", crate::fmt::Bytes(dd2));

                outbox.push(msg.into_inner());
            } else {
                // DD2 not supported: error response with type = 0x3F
                const ERROR_RESPONSE_LEN: usize = offsets::MSG_APCI + 2;
                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(ERROR_RESPONSE_LEN) else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg = ind
                    .respond_with(msg_buf)
                    .with_application(ApciCode::DeviceDescriptorResponse, transport_service)
                    .with_data(|data| {
                        data[offsets::MSG_APCI + 1] = (data[offsets::MSG_APCI + 1] & 0xC0) | 0x3F;
                    });

                debug!("AL sending DeviceDescriptorResponse (error, DD2 not supported): descriptor_type=0x3F");

                outbox.push(msg.into_inner());
            }
        } else {
            // Any other descriptor type: error response with type = 0x3F, no data
            const ERROR_RESPONSE_LEN: usize = offsets::MSG_APCI + 2; // APCI(2) only, no data
            let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(ERROR_RESPONSE_LEN) else {
                warn!("AL no buffer for response");
                return;
            };

            let msg = ind
                .respond_with(msg_buf)
                .with_application(ApciCode::DeviceDescriptorResponse, transport_service)
                .with_data(|data| {
                    // Set descriptor type to 0x3F (all 6 bits set) to indicate error
                    data[offsets::MSG_APCI + 1] = (data[offsets::MSG_APCI + 1] & 0xC0) | 0x3F;
                });

            debug!("AL sending DeviceDescriptorResponse (error): descriptor_type=0x3F");

            outbox.push(msg.into_inner());
        }
    }

    /// Handle `A_IndividualAddress_Read.ind`
    ///
    /// Responds with the device's individual address if the device is in programming mode.
    /// This service arrives via `T_Broadcast_Ind` and responds via `T_Broadcast_Req`.
    ///
    /// Message format (incoming):
    /// - APDU[0-1]: APCI (IndividualAddressRead, no additional data)
    ///
    /// Response format:
    /// - APDU[0-1]: APCI (IndividualAddressResponse, no additional data)
    ///
    /// Note: The individual address is taken from the source address field of the
    /// response frame, not from the APDU payload.
    fn handle_individual_address_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::messages::builder::MessageBuilder;

        // Validate service type - must be broadcast
        if ind.service_type() != ServiceType::T_Broadcast_Ind {
            warn!("AL IndividualAddressRead with unexpected service type: {:?}", ind.service_type());
            return;
        }

        debug!("AL IndividualAddressRead received");

        // Only respond if device is in programming mode
        // Per KNX spec, A_IndividualAddress_Read should only be responded to when
        // the device is in programming mode (e.g., programming button pressed)
        if !self.interface_objects.is_programming_mode() {
            trace!("AL IndividualAddressRead ignored (not in programming mode)");
            return;
        }

        // IndividualAddressResponse: APCI only, no payload
        // The individual address is conveyed in the source address field of the L_Data frame
        const RESPONSE_LEN: usize = offsets::MSG_APCI + 2;
        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(RESPONSE_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        // Build broadcast response
        // Note: For IndividualAddressResponse, we broadcast to 0x0000 (all devices)
        let msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::T_Broadcast_Req,
            ind.ctrl_field().priority(),
            DestinationAddress::Group(GroupAddress::from_bytes(&[0x00, 0x00])), // Broadcast address
        )
        .with_application(ApciCode::IndividualAddressResponse, ServiceType::T_Broadcast_Req)
        .build();

        debug!("AL sending IndividualAddressResponse");

        outbox.push(msg.into_inner());
    }

    /// Handle `A_IndividualAddress_Write.ind`
    ///
    /// Sets the device's individual address if the device is in programming mode.
    /// This service arrives via `T_Broadcast_Ind` and requires no response.
    ///
    /// Message format (incoming):
    /// - APDU[0-1]: APCI (IndividualAddressWrite, code 3)
    /// - APDU[2-3]: New individual address (2 bytes, big-endian)
    ///
    /// Per KNX spec, this service only takes effect when the device is in programming mode.
    fn handle_individual_address_write(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, _outbox: &mut Outbox) {
        use crate::address::IndividualAddress;

        // Validate service type - must be broadcast
        if ind.service_type() != ServiceType::T_Broadcast_Ind {
            warn!("AL IndividualAddressWrite with unexpected service type: {:?}", ind.service_type());
            return;
        }

        // Only accept if device is in programming mode
        if !self.interface_objects.is_programming_mode() {
            trace!("AL IndividualAddressWrite ignored (not in programming mode)");
            return;
        }

        // Validate APDU length: APCI (2 bytes) + address (2 bytes) = 4 bytes minimum
        const MIN_LEN: usize = offsets::MSG_APCI + 4;
        if ind.len() < MIN_LEN {
            error!("IndividualAddressWrite message too short: {} < {}", ind.len(), MIN_LEN);
            return;
        }

        // Extract new individual address from APDU[2-3]
        let buf = ind.buf();
        let new_addr_bytes = &buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 4];
        let new_addr = IndividualAddress::from_bytes(new_addr_bytes);

        debug!("AL IndividualAddressWrite: setting address to {}", new_addr);

        // Update the device's individual address
        self.state.set_individual_address(new_addr);

        // No response is sent for IndividualAddressWrite
    }

    /// Handle `A_IndividualAddressSerialNumber_Read.ind`
    ///
    /// Responds with the device's individual address if the serial number matches.
    /// This service arrives via `T_Broadcast_Ind` and responds via `T_Broadcast_Req`.
    ///
    /// Message format (incoming):
    /// - APDU[0-1]: APCI (IndividualAddressSerialNumberRead, code 0xDC)
    /// - APDU[2-7]: Serial number to match (6 bytes)
    ///
    /// Response format:
    /// - APDU[0-1]: APCI (IndividualAddressSerialNumberResponse, code 0xDD)
    /// - APDU[2-7]: Serial number (6 bytes)
    /// - APDU[8-11]: Domain address / reserved (4 bytes, zero)
    fn handle_individual_address_serial_number_read(
        &mut self,
        ind: &KnxMessageBuffer<Buffer<'static>>,
        outbox: &mut Outbox,
    ) {
        use crate::messages::builder::MessageBuilder;

        // Validate service type - must be broadcast
        if ind.service_type() != ServiceType::T_Broadcast_Ind {
            warn!("AL IndividualAddressSerialNumberRead with unexpected service type: {:?}", ind.service_type());
            return;
        }

        // Validate APDU length: APCI (2 bytes) + serial number (6 bytes) = 8 bytes minimum
        const MIN_LEN: usize = offsets::MSG_APCI + 8;
        if ind.len() < MIN_LEN {
            error!("IndividualAddressSerialNumberRead message too short: {} < {}", ind.len(), MIN_LEN);
            return;
        }

        // Extract serial number from APDU[2-7]
        let buf = ind.buf();
        let received_serial = &buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8];

        // Only respond if serial number matches
        if received_serial != self.state.serial_number() {
            trace!("AL IndividualAddressSerialNumberRead ignored (serial mismatch)");
            return;
        }

        debug!("AL IndividualAddressSerialNumberRead: serial matches, sending response");

        // Response: APCI (2) + serial (6) + domain/reserved (4) = 12 bytes APDU
        const RESPONSE_LEN: usize = offsets::MSG_APCI + 12;
        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(RESPONSE_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        // Build broadcast response
        let mut msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::T_Broadcast_Req,
            ind.ctrl_field().priority(),
            DestinationAddress::Group(GroupAddress::from_bytes(&[0x00, 0x00])),
        )
        .with_application(ApciCode::IndividualAddressSerialNumberResponse, ServiceType::T_Broadcast_Req)
        .build();

        // Copy serial number to response (APDU bytes 2-7)
        msg.buf_mut()[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8].copy_from_slice(self.state.serial_number());
        // Domain address / reserved (4 bytes, zero) - already zeroed by alloc

        outbox.push(msg.into_inner());
    }

    /// Handle `A_IndividualAddressSerialNumber_Write.ind`
    ///
    /// Sets the device's individual address if the serial number matches.
    /// This service arrives via `T_Broadcast_Ind` and requires no response.
    ///
    /// Message format (incoming):
    /// - APDU[0-1]: APCI (IndividualAddressSerialNumberWrite, code 0xDE)
    /// - APDU[2-7]: Serial number (6 bytes)
    /// - APDU[8-9]: New individual address (2 bytes)
    /// - APDU[10-13]: Reserved (4 bytes)
    fn handle_individual_address_serial_number_write(
        &mut self,
        ind: &KnxMessageBuffer<Buffer<'static>>,
        _outbox: &mut Outbox,
    ) {
        use crate::address::IndividualAddress;

        // Validate service type - must be broadcast
        if ind.service_type() != ServiceType::T_Broadcast_Ind {
            warn!("AL IndividualAddressSerialNumberWrite with unexpected service type: {:?}", ind.service_type());
            return;
        }

        // Validate APDU length: APCI (2) + serial (6) + addr (2) + reserved (4) = 14 bytes
        const MIN_LEN: usize = offsets::MSG_APCI + 14;
        if ind.len() < MIN_LEN {
            error!("IndividualAddressSerialNumberWrite message too short: {} < {}", ind.len(), MIN_LEN);
            return;
        }

        let buf = ind.buf();

        // Extract serial number from APDU[2-7]
        let received_serial = &buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 8];

        // Only accept if serial number matches
        if received_serial != self.state.serial_number() {
            trace!("AL IndividualAddressSerialNumberWrite ignored (serial mismatch)");
            return;
        }

        // Extract new individual address from APDU[8-9]
        let new_addr_bytes = &buf[offsets::MSG_APCI + 8..offsets::MSG_APCI + 10];
        let new_addr = IndividualAddress::from_bytes(new_addr_bytes);

        debug!("AL IndividualAddressSerialNumberWrite: setting address to {}", new_addr);

        // Update the device's individual address
        self.state.set_individual_address(new_addr);

        // No response is sent
    }

    /// Handle `A_ADC_Read.ind`
    ///
    /// Reads an analog-to-digital converter channel and returns the sum of readings.
    /// This is a legacy service used by older KNX devices.
    ///
    /// Message format (incoming):
    /// - APDU[0]: High 2 bits of APCI
    /// - APDU[1]: 0x80 | channel (6 bits) - AdcRead code with channel number
    /// - APDU[2]: count - number of readings to sum
    ///
    /// Response format:
    /// - APDU[0]: High 2 bits of APCI
    /// - APDU[1]: 0xC0 | channel (6 bits) - AdcResponse code with channel number
    /// - APDU[2]: count - 0 if channel unsupported, otherwise same as request
    /// - APDU[3-4]: sum of readings (2 bytes, big-endian)
    fn handle_adc_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::messages::builder::IndicationExt;

        // ADC_Read APDU: [APCI:2 (with channel in low 6 bits)] [count:1]
        // Minimum length: MSG_APCI + 3 = 9 bytes
        const MIN_LEN: usize = offsets::MSG_APCI + 3;

        if ind.len() < MIN_LEN {
            error!("ADC_Read message too short: {} < {}", ind.len(), MIN_LEN);
            return;
        }

        let buf = ind.buf();
        let channel = buf[offsets::MSG_APCI + 1] & 0x3F;
        let count = buf[offsets::MSG_APCI + 2];

        debug!("AL ADC_Read: channel={}, count={}", channel, count);

        // ADC_Read is only valid in connection-oriented mode (T_Data_Ind)
        // Per KNX spec and conformance test M-2.20, ADC services require a connection
        let transport_service = match ind.service_type() {
            ServiceType::T_Data_Ind => ServiceType::T_Data_Req,
            other => {
                debug!("AL ADC_Read requires connection-oriented mode, got {:?}", other);
                return;
            }
        };

        // Response: APCI(2) + count(1) + sum(2) = 5 bytes APDU
        const RESPONSE_LEN: usize = offsets::MSG_APCI + 5;
        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(RESPONSE_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        // We support channels 0-5 (typical KNX ADC channels), return 0 for unsupported
        // For supported channels, we return dummy values (0x0000 for the sum)
        let (response_count, sum) = if channel <= 5 {
            // Supported channel - return requested count and dummy sum
            (count, 0x0000u16)
        } else {
            // Unsupported channel - return count=0 and sum=0
            (0u8, 0x0000u16)
        };

        let msg =
            ind.respond_with(msg_buf).with_application(ApciCode::AdcResponse, transport_service).with_data(|data| {
                // Set channel in low 6 bits of APCI byte 1
                data[offsets::MSG_APCI + 1] = (data[offsets::MSG_APCI + 1] & 0xC0) | channel;
                // Count
                data[offsets::MSG_APCI + 2] = response_count;
                // Sum (big-endian)
                data[offsets::MSG_APCI + 3] = (sum >> 8) as u8;
                data[offsets::MSG_APCI + 4] = sum as u8;
            });

        debug!("AL sending ADC_Response: channel={}, count={}, sum={}", channel, response_count, sum);

        outbox.push(msg.into_inner());
    }

    /// Handle `A_Memory_Read.ind`
    ///
    /// Reads from device memory at the specified address.
    ///
    /// Message format (incoming):
    /// - APDU[0]: High 2 bits of APCI
    /// - APDU[1]: 0x00 | count (6 bits) - MemoryRead code with byte count
    /// - APDU[2-3]: Address (2 bytes, big-endian)
    ///
    /// Response format:
    /// - APDU[0]: High 2 bits of APCI
    /// - APDU[1]: 0x40 | count (6 bits) - MemoryResponse code with byte count (0 on error)
    /// - APDU[2-3]: Address (2 bytes, big-endian)
    /// - APDU[4+]: Data (count bytes, if successful)
    fn handle_memory_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::memory::MemoryMap;
        use crate::messages::builder::IndicationExt;

        // Memory_Read is only valid on connection-oriented transport
        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL Memory_Read rejected: connection-oriented only");
            return;
        }

        // Memory_Read APDU: [APCI:2] [address:2]
        // Minimum length: MSG_APCI + 4 = 10 bytes
        const MIN_LEN: usize = offsets::MSG_APCI + 4;

        if ind.len() < MIN_LEN {
            error!("Memory_Read message too short: {} < {}", ind.len(), MIN_LEN);
            return;
        }

        let buf = ind.buf();
        let count = buf[offsets::MSG_APCI + 1] & 0x3F;
        let address = u16::from_be_bytes([buf[offsets::MSG_APCI + 2], buf[offsets::MSG_APCI + 3]]);

        debug!("AL Memory_Read: address=0x{:04X}, count={}", address, count);

        // Read from memory map first to determine response size
        // Pass access level from the message (set by transport layer from connection state)
        let access_ctx = self.resolve_access(ind);
        let mut data = [0u8; 63]; // Max count is 63 (6 bits)
        let result = self.memory_map.read(self.state, address, &mut data[..(count as usize)], access_ctx);

        let response_count = match result {
            Ok(bytes_read) => bytes_read as u8,
            Err(_) => 0, // Error: return count=0
        };

        // Response: APCI(2) + address(2) + data(response_count) = 4 + response_count bytes APDU
        // On error, response_count is 0 and no data is sent (just APCI + address)
        let response_len = offsets::MSG_APCI + 4 + (response_count as usize);
        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(response_len) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind
            .respond_with(msg_buf)
            .with_application(ApciCode::MemoryReadResponse, ServiceType::T_Data_Req)
            .with_data(|msg_data| {
                // Set count in low 6 bits of APCI byte 1
                msg_data[offsets::MSG_APCI + 1] = (msg_data[offsets::MSG_APCI + 1] & 0xC0) | response_count;
                // Address (big-endian)
                msg_data[offsets::MSG_APCI + 2] = (address >> 8) as u8;
                msg_data[offsets::MSG_APCI + 3] = address as u8;
                // Copy data if successful
                if response_count > 0 {
                    msg_data[offsets::MSG_APCI + 4..offsets::MSG_APCI + 4 + response_count as usize]
                        .copy_from_slice(&data[..response_count as usize]);
                }
            });

        debug!("AL sending Memory_Response: address=0x{:04X}, count={}", address, response_count);

        outbox.push(msg.into_inner());
    }

    /// Handle `A_Memory_Write.ind`
    ///
    /// Writes to device memory at the specified address.
    ///
    /// Message format (incoming):
    /// - APDU[0]: High 2 bits of APCI
    /// - APDU[1]: 0x80 | count (6 bits) - MemoryWrite code with byte count
    /// - APDU[2-3]: Address (2 bytes, big-endian)
    /// - APDU[4+]: Data (count bytes)
    ///
    /// If the Verify flag is set in DEVICE_CONTROL (PID 14), a Memory_Response is sent.
    fn handle_memory_write(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::memory::MemoryMap;
        use crate::messages::builder::IndicationExt;

        // Memory_Write is only valid on connection-oriented transport
        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL Memory_Write rejected: connection-oriented only");
            return;
        }

        // Memory_Write APDU: [APCI:2] [address:2] [data:count]
        // Minimum length without data: MSG_APCI + 4 = 10 bytes
        const MIN_LEN: usize = offsets::MSG_APCI + 4;

        if ind.len() < MIN_LEN {
            error!("Memory_Write message too short: {} < {}", ind.len(), MIN_LEN);
            return;
        }

        let buf = ind.buf();
        let count = buf[offsets::MSG_APCI + 1] & 0x3F;
        let address = u16::from_be_bytes([buf[offsets::MSG_APCI + 2], buf[offsets::MSG_APCI + 3]]);

        // Verify data length matches count field exactly (length consistency check)
        let expected_len = offsets::MSG_APCI + 4 + (count as usize);
        let length_inconsistent = ind.len() != expected_len;

        if length_inconsistent {
            warn!(
                "Memory_Write length inconsistency: expected {} bytes, got {} (count={})",
                expected_len,
                ind.len(),
                count
            );
        }

        let data = &buf[offsets::MSG_APCI + 4..core::cmp::min(ind.len(), offsets::MSG_APCI + 4 + count as usize)];

        debug!("AL Memory_Write: address=0x{:04X}, count={}", address, count);

        // Get access level from the message (set by transport layer from connection state)
        let access_ctx = self.resolve_access(ind);

        // If length is inconsistent, don't write and respond with count=0
        // Otherwise, write to memory map
        let response_count = if length_inconsistent {
            0 // Length inconsistency: response with count=0
        } else {
            match self.memory_map.write(self.state, address, data, access_ctx) {
                Ok(bytes_written) => {
                    debug!("AL Memory_Write: wrote {} bytes to 0x{:04X}", bytes_written, address);
                    self.state.mark_dirty();
                    bytes_written as u8
                }
                Err(e) => {
                    warn!("AL Memory_Write failed: address=0x{:04X}, error={:?}", address, e);
                    0 // Error: response with count=0
                }
            }
        };

        // Check if Verify flag is set in DEVICE_CONTROL (Object 0, PID 14)
        // Using the typed accessor from HasDeviceObject trait
        if !self.interface_objects.verify_mode() {
            // No response when Verify is not enabled
            return;
        }

        // Send Memory_Response with written data (or count=0 on error)
        // Response: APCI(2) + address(2) + data(response_count) = 4 + response_count bytes APDU
        let response_len = offsets::MSG_APCI + 4 + (response_count as usize);
        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(response_len) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind
            .respond_with(msg_buf)
            .with_application(ApciCode::MemoryReadResponse, ServiceType::T_Data_Req)
            .with_data(|msg_data| {
                // Set count in low 6 bits of APCI byte 1
                msg_data[offsets::MSG_APCI + 1] = (msg_data[offsets::MSG_APCI + 1] & 0xC0) | response_count;
                // Address (big-endian)
                msg_data[offsets::MSG_APCI + 2] = (address >> 8) as u8;
                msg_data[offsets::MSG_APCI + 3] = address as u8;
                // Copy data if successful
                if response_count > 0 {
                    msg_data[offsets::MSG_APCI + 4..offsets::MSG_APCI + 4 + response_count as usize]
                        .copy_from_slice(data);
                }
            });

        debug!("AL sending Memory_Response (verify): address=0x{:04X}, count={}", address, response_count);

        outbox.push(msg.into_inner());
    }

    /// Handle `A_MemoryBit_Write.ind`
    ///
    /// Performs atomic bit-level memory manipulation using AND and XOR masks.
    /// Formula: new_value = (old_value AND and_mask) XOR xor_mask
    ///
    /// Message format (incoming):
    /// - APDU[0-1]: APCI (0x1D0 with count in low 4 bits of byte 1)
    /// - APDU[2-3]: Address (2 bytes, big-endian)
    /// - APDU[4..4+count]: AND masks (count bytes)
    /// - APDU[4+count..4+2*count]: XOR masks (count bytes)
    ///
    /// Response format (if Verify enabled):
    /// - APDU[0-1]: APCI (0x140 with count in low 4 bits of byte 1)
    /// - APDU[2-3]: Address (2 bytes, big-endian)
    /// - APDU[4..4+count]: Resulting data (count bytes)
    ///
    /// Legal length: count must be 1-5 bytes
    fn handle_memorybit_write(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::memory::MemoryMap;

        // MemoryBit_Write is only valid on connection-oriented transport
        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL MemoryBit_Write rejected: connection-oriented only");
            return;
        }

        // MemoryBit_Write APDU: [APCI:2] [address:2] [AND_masks:count] [XOR_masks:count]
        // Minimum length with count=1: MSG_APCI + 4 + 1 + 1 = 12 bytes
        const MIN_LEN: usize = offsets::MSG_APCI + 6;

        if ind.len() < MIN_LEN {
            error!("MemoryBit_Write message too short: {} < {}", ind.len(), MIN_LEN);
            return;
        }

        let buf = ind.buf();
        // For MemoryBit_Write with extended APCI 0x1D0:
        // Format: [APCI:2] [count:1] [address:2] [AND_masks:count] [XOR_masks:count]
        // The count is at MSG_APCI+2 (first byte after the 2-byte APCI field)
        let count = buf[offsets::MSG_APCI + 2] & 0x0F; // Only low 4 bits for count
        let address = u16::from_be_bytes([buf[offsets::MSG_APCI + 3], buf[offsets::MSG_APCI + 4]]);

        // Legal count is 1-5 bytes
        if count == 0 || count > 5 {
            warn!("MemoryBit_Write illegal count: {} (APCI+1={:02X})", count, buf[offsets::MSG_APCI + 1]);
            // Respond with count=0 on illegal length
            self.send_memorybit_response(ind, address, 0, &[], outbox);
            return;
        }

        // Verify data length: need 2 (APCI) + 1 (count) + 2 (address) + count (AND) + count (XOR) bytes
        let expected_len = offsets::MSG_APCI + 5 + (count as usize) * 2;
        if ind.len() != expected_len {
            warn!(
                "MemoryBit_Write length mismatch: expected {} bytes, got {} (count={})",
                expected_len,
                ind.len(),
                count
            );
            // Respond with count=0 on length mismatch
            self.send_memorybit_response(ind, address, 0, &[], outbox);
            return;
        }

        debug!("AL MemoryBit_Write: address=0x{:04X}, count={}", address, count);

        // AND masks start after APCI (2 bytes) + count (1 byte) + address (2 bytes) = MSG_APCI + 5
        let and_masks = &buf[offsets::MSG_APCI + 5..offsets::MSG_APCI + 5 + count as usize];
        // XOR masks follow AND masks
        let xor_masks = &buf[offsets::MSG_APCI + 5 + count as usize..offsets::MSG_APCI + 5 + 2 * count as usize];

        // Get access level from the message
        let access_ctx = self.resolve_access(ind);

        // Read current memory values
        let mut current_data = [0u8; 5]; // Max 5 bytes
        let read_count = current_data[..count as usize].len();

        let read_result = self.memory_map.read(self.state, address, &mut current_data[..read_count], access_ctx);

        match read_result {
            Ok(_) => {
                // Apply bit manipulation: new = (old AND and_mask) XOR xor_mask
                let mut new_data = [0u8; 5];
                for i in 0..count as usize {
                    new_data[i] = (current_data[i] & and_masks[i]) ^ xor_masks[i];
                }

                // Write back the modified data
                match self.memory_map.write(self.state, address, &new_data[..count as usize], access_ctx) {
                    Ok(_) => {
                        debug!("AL MemoryBit_Write: wrote {} bytes to 0x{:04X}", count, address);
                        // Check if Verify is enabled - if so, send response with new data
                        self.send_memorybit_response(ind, address, count, &new_data[..count as usize], outbox);
                    }
                    Err(e) => {
                        warn!("AL MemoryBit_Write write failed: address=0x{:04X}, error={:?}", address, e);
                        // Respond with count=0 on write error
                        self.send_memorybit_response(ind, address, 0, &[], outbox);
                    }
                }
            }
            Err(e) => {
                warn!("AL MemoryBit_Write read failed: address=0x{:04X}, error={:?}", address, e);
                // Respond with count=0 on read error
                self.send_memorybit_response(ind, address, 0, &[], outbox);
            }
        }
    }

    /// Send A_Memory_Response (in response to A_MemoryBit_Write)
    ///
    /// Per KNX spec 3.5.5: "the TSDU is an A_Memory_Response-PDU"
    /// Only sends a response if Verify flag is enabled in DEVICE_CONTROL (Object 0, PID 14, bit 2)
    fn send_memorybit_response(
        &mut self,
        ind: &KnxMessageBuffer<Buffer<'static>>,
        address: u16,
        count: u8,
        data: &[u8],
        outbox: &mut Outbox,
    ) {
        use crate::messages::builder::IndicationExt;

        // Check if Verify flag is set in DEVICE_CONTROL (Object 0, PID 14)
        // Using the typed accessor from HasDeviceObject trait
        if !self.interface_objects.verify_mode() {
            // No response when Verify is not enabled
            return;
        }

        // Send A_Memory_Response (same format as response to A_Memory_Read)
        // Response format: [APCI:2 with count in low 4 bits of byte 1] [address:2] [data:count]
        // The count is embedded in the APCI code (0x140 | count), same as A_Memory_Response
        let response_len = offsets::MSG_APCI + 4 + (count as usize);
        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(response_len) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind
            .respond_with(msg_buf)
            .with_application(ApciCode::MemoryReadResponse, ServiceType::T_Data_Req)
            .with_data(|msg_data| {
                // Override the APCI encoding - A_Memory_Response has count embedded
                // APCI 0x140 with count in bits 0-3 spans across MSG_APCI and MSG_APCI+1
                // MSG_APCI bits 1-0 contain upper bits of APCI (should be 10 = 2 for 0x140)
                // MSG_APCI+1 contains 0x40 | count
                msg_data[offsets::MSG_APCI] = (msg_data[offsets::MSG_APCI] & 0xFC) | 2;
                msg_data[offsets::MSG_APCI + 1] = 0x40 | (count & 0x0F);
                // Address (big-endian)
                msg_data[offsets::MSG_APCI + 2] = (address >> 8) as u8;
                msg_data[offsets::MSG_APCI + 3] = address as u8;
                // Copy data if count > 0
                if count > 0 {
                    msg_data[offsets::MSG_APCI + 4..offsets::MSG_APCI + 4 + count as usize].copy_from_slice(data);
                }
            });

        debug!("AL sending A_Memory_Response (for MemoryBit_Write): address=0x{:04X}, count={}", address, count);

        outbox.push(msg.into_inner());
    }

    /// Handle `A_UserMemory_Read.ind`
    ///
    /// Reads from user memory at the specified 20-bit address.
    /// User memory uses a 4-bit address extension in the APCI byte combined with
    /// a 16-bit address to provide a 20-bit address space.
    ///
    /// Message format (incoming):
    /// - APDU[0]: High 2 bits of APCI (TPCI/APCI byte)
    /// - APDU[1]: 0xC0 | addr_ext (4 bits) - UserMemoryRead code with address extension
    /// - APDU[2]: count (8 bits) - byte count
    /// - APDU[3-4]: Address (16 bits, big-endian)
    ///
    /// Response format:
    /// - APDU[0]: High 2 bits of APCI
    /// - APDU[1]: 0xC1 | addr_ext (4 bits) - UserMemoryResponse code with address extension
    /// - APDU[2]: count (8 bits) - byte count (0 on error)
    /// - APDU[3-4]: Address (16 bits, big-endian)
    /// - APDU[5+]: Data (count bytes, if successful)
    fn handle_user_memory_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::memory::MemoryMap;
        use crate::messages::builder::IndicationExt;

        // UserMemory_Read is only valid on connection-oriented transport
        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL UserMemory_Read rejected: connection-oriented only");
            return;
        }

        // UserMemory_Read APDU: [APCI:2] [count:1] [address:2]
        // Minimum length: MSG_APCI + 5 = 11 bytes
        const MIN_LEN: usize = offsets::MSG_APCI + 5;

        if ind.len() < MIN_LEN {
            error!("UserMemory_Read message too short: {} < {}", ind.len(), MIN_LEN);
            return;
        }

        let buf = ind.buf();
        // Address extension is in bits 3-2 of the second APCI byte (bits 1-0 = sub-type)
        let addr_ext = ((buf[offsets::MSG_APCI + 1] >> 2) & 0x03) as u32;
        let count = buf[offsets::MSG_APCI + 2];
        let address_low = u16::from_be_bytes([buf[offsets::MSG_APCI + 3], buf[offsets::MSG_APCI + 4]]);
        // Full 18-bit address = (addr_ext << 16) | address_low
        let full_address = (addr_ext << 16) | (address_low as u32);

        debug!("AL UserMemory_Read: address=0x{:05X}, count={}", full_address, count);

        // Read from memory map first to determine response size
        // Pass access level from the message (set by transport layer from connection state)
        let access_ctx = self.resolve_access(ind);
        let mut data = [0u8; 255]; // Max count is 255 (8 bits)
        let max_read = core::cmp::min(count as usize, data.len());
        // UserMemory uses 16-bit address for the memory map interface (address extension is for user address space)
        let result = self.memory_map.read(self.state, address_low, &mut data[..max_read], access_ctx);

        let response_count = match result {
            Ok(bytes_read) => bytes_read as u8,
            Err(_) => 0, // Error: return count=0
        };

        // Response: APCI(2) + count(1) + address(2) + data(response_count) = 5 + response_count bytes APDU
        // On error, response_count is 0 and no data is sent (just APCI + count + address)
        let response_len = offsets::MSG_APCI + 5 + (response_count as usize);
        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(response_len) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind
            .respond_with(msg_buf)
            .with_application(ApciCode::UserMemoryResponse, ServiceType::T_Data_Req)
            .with_data(|msg_data| {
                // Address extension goes in bits 3-2 of APCI byte 1 (bits 1-0 contain sub-type Read/Response/Write)
                msg_data[offsets::MSG_APCI + 1] =
                    (msg_data[offsets::MSG_APCI + 1] & 0xF3) | ((addr_ext as u8 & 0x03) << 2);
                // Count
                msg_data[offsets::MSG_APCI + 2] = response_count;
                // Address (big-endian)
                msg_data[offsets::MSG_APCI + 3] = (address_low >> 8) as u8;
                msg_data[offsets::MSG_APCI + 4] = address_low as u8;
                // Copy data if successful
                if response_count > 0 {
                    msg_data[offsets::MSG_APCI + 5..offsets::MSG_APCI + 5 + response_count as usize]
                        .copy_from_slice(&data[..response_count as usize]);
                }
            });

        debug!("AL sending UserMemory_Response: address=0x{:05X}, count={}", full_address, response_count);

        outbox.push(msg.into_inner());
    }

    /// Handle `A_UserMemory_Write.ind`
    ///
    /// Writes to user memory at the specified 20-bit address.
    /// User memory uses a 4-bit address extension in the APCI byte combined with
    /// a 16-bit address to provide a 20-bit address space.
    ///
    /// Message format (incoming):
    /// - APDU[0]: High 2 bits of APCI (TPCI/APCI byte)
    /// - APDU[1]: 0xC2 | addr_ext (4 bits) - UserMemoryWrite code with address extension
    /// - APDU[2]: count (8 bits) - byte count
    /// - APDU[3-4]: Address (16 bits, big-endian)
    /// - APDU[5+]: Data (count bytes)
    ///
    /// If the Verify flag is set in DEVICE_CONTROL (PID 14), a UserMemory_Response is sent.
    fn handle_user_memory_write(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::memory::MemoryMap;
        use crate::messages::builder::IndicationExt;

        // UserMemory_Write is only valid on connection-oriented transport
        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL UserMemory_Write rejected: connection-oriented only");
            return;
        }

        // UserMemory_Write APDU: [APCI:2] [count:1] [address:2] [data:count]
        // Minimum length without data: MSG_APCI + 5 = 11 bytes
        const MIN_LEN: usize = offsets::MSG_APCI + 5;

        if ind.len() < MIN_LEN {
            error!("UserMemory_Write message too short: {} < {}", ind.len(), MIN_LEN);
            return;
        }

        let buf = ind.buf();
        // Address extension is in bits 3-2 of the second APCI byte (bits 1-0 = sub-type)
        let addr_ext = ((buf[offsets::MSG_APCI + 1] >> 2) & 0x03) as u32;
        let count = buf[offsets::MSG_APCI + 2];
        let address_low = u16::from_be_bytes([buf[offsets::MSG_APCI + 3], buf[offsets::MSG_APCI + 4]]);
        // Full 18-bit address = (addr_ext << 16) | address_low
        let full_address = (addr_ext << 16) | (address_low as u32);

        // Verify data length matches count field exactly (length consistency check)
        let expected_len = offsets::MSG_APCI + 5 + (count as usize);
        let length_inconsistent = ind.len() != expected_len;

        if length_inconsistent {
            warn!(
                "UserMemory_Write length inconsistency: expected {} bytes, got {} (count={})",
                expected_len,
                ind.len(),
                count
            );
        }

        let data = &buf[offsets::MSG_APCI + 5..core::cmp::min(ind.len(), offsets::MSG_APCI + 5 + count as usize)];

        debug!("AL UserMemory_Write: address=0x{:05X}, count={}", full_address, count);

        // Get access level from the message (set by transport layer from connection state)
        let access_ctx = self.resolve_access(ind);

        // If length is inconsistent, don't write and respond with count=0
        // Otherwise, write to memory map
        let response_count = if length_inconsistent {
            0 // Length inconsistency: response with count=0
        } else {
            match self.memory_map.write(self.state, address_low, data, access_ctx) {
                Ok(bytes_written) => {
                    debug!("AL UserMemory_Write: wrote {} bytes to 0x{:05X}", bytes_written, full_address);
                    self.state.mark_dirty();
                    bytes_written as u8
                }
                Err(e) => {
                    warn!("AL UserMemory_Write failed: address=0x{:05X}, error={:?}", full_address, e);
                    0 // Error: response with count=0
                }
            }
        };

        // Check if Verify flag is set in DEVICE_CONTROL (Object 0, PID 14)
        // Using the typed accessor from HasDeviceObject trait
        if !self.interface_objects.verify_mode() {
            // No response when Verify is not enabled
            return;
        }

        // Send UserMemory_Response with written data (or count=0 on error)
        // Response: APCI(2) + count(1) + address(2) + data(response_count) = 5 + response_count bytes APDU
        let response_len = offsets::MSG_APCI + 5 + (response_count as usize);
        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(response_len) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind
            .respond_with(msg_buf)
            .with_application(ApciCode::UserMemoryResponse, ServiceType::T_Data_Req)
            .with_data(|msg_data| {
                // Address extension goes in bits 3-2 of APCI byte 1 (bits 1-0 contain sub-type Read/Response/Write)
                msg_data[offsets::MSG_APCI + 1] =
                    (msg_data[offsets::MSG_APCI + 1] & 0xF3) | ((addr_ext as u8 & 0x03) << 2);
                // Count
                msg_data[offsets::MSG_APCI + 2] = response_count;
                // Address (big-endian)
                msg_data[offsets::MSG_APCI + 3] = (address_low >> 8) as u8;
                msg_data[offsets::MSG_APCI + 4] = address_low as u8;
                // Copy data if successful
                if response_count > 0 {
                    msg_data[offsets::MSG_APCI + 5..offsets::MSG_APCI + 5 + response_count as usize]
                        .copy_from_slice(data);
                }
            });

        debug!("AL sending UserMemory_Response (verify): address=0x{:05X}, count={}", full_address, response_count);

        outbox.push(msg.into_inner());
    }

    /// Handle `A_UserManufacturerInfo_Read.ind`
    ///
    /// Responds with the manufacturer ID and manufacturer-specific data.
    ///
    /// Message format (incoming):
    /// - APDU[0-1]: APCI (0x0BC5 - UserManufacturerInfo_Read via User escape)
    ///
    /// Response format:
    /// - APDU[0-1]: APCI (0x0BC6 - UserManufacturerInfo_Response via User escape)
    /// - APDU[2]: Manufacturer ID (8-bit)
    /// - APDU[3-4]: Manufacturer-specific data (16-bit)
    fn handle_user_manufacturer_info_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::messages::builder::IndicationExt;

        // Check if USER_MANUFACTURER_INFO is configured
        let Some(info) = D::USER_MANUFACTURER_INFO else {
            debug!("AL UserManufacturerInfo_Read: not supported (no USER_MANUFACTURER_INFO configured)");
            return;
        };

        // Determine transport service type
        let transport_service = match ind.service_type() {
            ServiceType::T_Data_Ind => ServiceType::T_Data_Req,
            ServiceType::T_DataUnack_Ind => ServiceType::T_DataUnack_Req,
            other => {
                warn!("AL UserManufacturerInfo_Read unexpected service type: {:?}", other);
                return;
            }
        };

        // Response: APCI(2) + Manufacturer ID(2) + Device Type(1) = 5 bytes
        const RESPONSE_LEN: usize = offsets::MSG_APCI + 5;
        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(RESPONSE_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind
            .respond_with(msg_buf)
            .with_application(ApciCode::UserManufacturerInfoResponse, transport_service)
            .with_data(|data| {
                // Copy the 3-byte manufacturer info (Manufacturer ID + Device Type)
                data[offsets::MSG_APCI + 2..offsets::MSG_APCI + 5].copy_from_slice(info);
            });

        debug!("AL sending UserManufacturerInfo_Response: {:?}", crate::fmt::Bytes(info));

        outbox.push(msg.into_inner());
    }

    /// Handle `A_Authorize_Request.ind`
    ///
    /// Authorizes with a 4-byte key and responds with the associated access level.
    ///
    /// Message format (incoming):
    /// - APDU[0-1]: APCI (0x03D1 - Authorize_Request)
    /// - APDU[2]: Reserved (should be 0)
    /// - APDU[3-6]: Key (4 bytes, big-endian)
    ///
    /// Response format:
    /// - APDU[0-1]: APCI (0x03D2 - Authorize_Response)
    /// - APDU[2]: Access level (0 = max access, 3 or 15 = min access)
    fn handle_authorize_request(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::messages::builder::IndicationExt;

        // Authorize_Request APDU: [APCI:2][Reserved:1][Key:4] = 7 bytes
        const EXPECTED_LEN: usize = offsets::MSG_APCI + 7;

        if ind.len() < EXPECTED_LEN {
            error!("Authorize_Request message too short: {} < {}", ind.len(), EXPECTED_LEN);
            return;
        }

        let buf = ind.buf();
        let key: [u8; 4] = [
            buf[offsets::MSG_APCI + 3],
            buf[offsets::MSG_APCI + 4],
            buf[offsets::MSG_APCI + 5],
            buf[offsets::MSG_APCI + 6],
        ];

        debug!("AL Authorize_Request: key={:?}", crate::fmt::Bytes(&key));

        // Authorize with the key - returns the access level for this key
        let access_level = self.state.authorize(&key);

        debug!("AL Authorize_Request: granted level {}", access_level);

        // Authorize is only valid on connection-oriented transport
        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL Authorize_Request rejected: connection-oriented only");
            return;
        }

        // Write the granted level directly to the shared access store so it
        // takes effect immediately — no piggybacking on the response message.
        if let AccessSource::Connection(slot) = ind.access_source() {
            self.state.set_connection_access(slot, AccessContext::new(access_level));
        }

        let transport_service = ServiceType::T_Data_Req;

        // Response: APCI(2) + Level(1) = 3 bytes
        const RESPONSE_LEN: usize = offsets::MSG_APCI + 3;
        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(RESPONSE_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind.respond_with(msg_buf).with_application(ApciCode::AuthorizeResponse, transport_service).with_data(
            |data| {
                data[offsets::MSG_APCI + 2] = access_level;
            },
        );

        debug!("AL sending Authorize_Response: level={}", access_level);

        outbox.push(msg.into_inner());
    }

    /// Handle `A_Key_Write.ind`
    ///
    /// Writes a new key for a specific access level.
    ///
    /// Message format (incoming):
    /// - APDU[0-1]: APCI (0x03D3 - Key_Write)
    /// - APDU[2]: Access level to set key for
    /// - APDU[3-6]: New key (4 bytes)
    ///
    /// Response format:
    /// - APDU[0-1]: APCI (0x03D4 - Key_Response)
    /// - APDU[2]: Access level (or 0xFF on error)
    fn handle_key_write(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::messages::builder::IndicationExt;

        // Key_Write APDU: [APCI:2][Level:1][Key:4] = 7 bytes
        const EXPECTED_LEN: usize = offsets::MSG_APCI + 7;

        if ind.len() < EXPECTED_LEN {
            error!("Key_Write message too short: {} < {}", ind.len(), EXPECTED_LEN);
            return;
        }

        let buf = ind.buf();
        let level = buf[offsets::MSG_APCI + 2];
        let key: [u8; 4] = [
            buf[offsets::MSG_APCI + 3],
            buf[offsets::MSG_APCI + 4],
            buf[offsets::MSG_APCI + 5],
            buf[offsets::MSG_APCI + 6],
        ];

        // Get current access context from the message (set by transport layer from connection)
        let current_ctx = self.resolve_access(ind);
        debug!("AL Key_Write: level={}, key={:?}, current_ctx={:?}", level, crate::fmt::Bytes(&key), current_ctx);

        // Perform the key write
        let result_level = self.state.key_write(level, &key, current_ctx);

        debug!("AL Key_Write: result={}", result_level);

        // Key_Write is only valid on connection-oriented transport
        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL Key_Write rejected: connection-oriented only");
            return;
        }
        let transport_service = ServiceType::T_Data_Req;

        // Response: APCI(2) + Level(1) = 3 bytes
        const RESPONSE_LEN: usize = offsets::MSG_APCI + 3;
        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(RESPONSE_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg =
            ind.respond_with(msg_buf).with_application(ApciCode::KeyResponse, transport_service).with_data(|data| {
                data[offsets::MSG_APCI + 2] = result_level;
            });

        debug!("AL sending Key_Response: level={}", result_level);

        outbox.push(msg.into_inner());
    }

    /// Handle `A_Restart.ind`
    ///
    /// Handles both basic A_Restart (software restart) and extended A_Restart (master reset)
    /// with various erase codes for different reset behaviors.
    ///
    /// Message formats:
    /// - Basic restart: APDU[0-1] = APCI (0x0380)
    /// - Master reset: APDU[0-1] = APCI (0x0381), APDU[2] = erase_code, APDU[3] = channel
    ///
    /// Response (for master reset): APDU[0-1] = APCI (0x03A1), APDU[2] = error, APDU[3-4] = process_time
    fn handle_restart(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        let buf = ind.buf();
        let len = ind.len();

        // Determine restart type from APCI low bits
        // Basic restart: 0x0380 (bit 0 = 0)
        // Master reset:  0x0381 (bit 0 = 1)
        let is_master_reset = (len > offsets::MSG_APCI + 1) && (buf[offsets::MSG_APCI + 1] & 0x01) == 1;

        let (erase_code, channel, needs_response) = if is_master_reset {
            // Master reset: APCI[0-1] + EraseCode + Channel = at least 4 bytes from APCI
            if len < offsets::MSG_APCI + 4 {
                warn!("AL Restart (master reset) message too short: {}", len);
                return;
            }
            let code = EraseCode::from(buf[offsets::MSG_APCI + 2]);
            let ch = buf[offsets::MSG_APCI + 3];
            (code, ch, true)
        } else {
            // Basic restart: no payload, no response
            (EraseCode::Basic, 0, false)
        };

        let restart_ctx = self.resolve_access(ind);
        debug!(
            "AL Restart: erase_code={}, channel={}, needs_response={}, access_ctx={:?}",
            erase_code, channel, needs_response, restart_ctx
        );

        // Check for unknown erase code (Other variant from create_protocol_enum!)
        if matches!(erase_code, EraseCode::Other(_)) {
            warn!("AL Restart: unsupported erase code {:?}", erase_code);
            if needs_response {
                self.send_restart_response(ind, RestartError::UnsupportedEraseCode, 0, outbox);
            }
            return;
        }

        // Validate channel number. Only channel 0 is supported.
        if channel != 0 {
            warn!("AL Restart: invalid channel number {}", channel);
            if needs_response {
                self.send_restart_response(ind, RestartError::InvalidChannel, 0, outbox);
            }
            return;
        }

        // For master reset operations (not basic/confirmed), check access level.
        // Basic and Confirmed restart can be done by anyone, but other erase codes
        // typically require higher access (level 0).
        let required_level = match erase_code {
            EraseCode::Basic | EraseCode::Confirmed => 3, // Anyone
            _ => 0,                                       // System access required for other erase codes
        };

        if !restart_ctx.has_level(required_level) {
            warn!("AL Restart: access denied ({:?}, required={})", restart_ctx, required_level);
            if needs_response {
                self.send_restart_response(ind, RestartError::AccessDenied, 0, outbox);
            }
            return;
        }

        // Send restart request to user code (fire-and-forget in synchronous model)
        let request = RestartRequest { erase_code, channel, access_ctx: restart_ctx, needs_response };

        debug!("AL Restart: sending request to user code");
        self.restart_sender.try_send(request).ok();

        // In the synchronous router model we cannot await the restart response.
        // The restart handler in user code will process it asynchronously.
        // For master reset, send a default success response immediately.
        if needs_response {
            self.send_restart_response(ind, RestartError::NoError, 0, outbox);
        }
    }

    /// Send A_Restart_Response message
    fn send_restart_response(
        &mut self,
        ind: &KnxMessageBuffer<Buffer<'static>>,
        error: RestartError,
        process_time_100ms: u16,
        outbox: &mut Outbox,
    ) {
        use crate::messages::builder::IndicationExt;

        // Determine transport service based on incoming service type.
        // Connection-oriented data arrives as T_Data_Ind, connectionless
        // individual data as T_DataUnack_Ind, and broadcast as T_Broadcast_Ind.
        let transport_service = match ind.service_type() {
            ServiceType::T_Data_Ind => ServiceType::T_Data_Req,
            ServiceType::T_DataUnack_Ind => ServiceType::T_DataUnack_Req,
            _ => ServiceType::T_Broadcast_Req,
        };

        // Response: APCI(2) + Error(1) + ProcessTime(2) = 5 bytes total APDU
        const RESPONSE_LEN: usize = offsets::MSG_APCI + 5;
        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(RESPONSE_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        // Build response using Restart APCI as base, then modify the APCI bytes in with_data
        // to set the correct A_Restart_Response format: 0x03 0xA1
        let msg = ind.respond_with(msg_buf).with_application(ApciCode::Restart, transport_service).with_data(|data| {
            // Manually set APCI bytes for A_Restart_Response: 0x03 0xA1
            // The first byte (0x03) encodes the APCI high bits
            // The second byte (0xA1) encodes: bit 7=1 (response), bits 0-5 = channel info
            data[offsets::MSG_APDU] = 0x03;
            data[offsets::MSG_APCI + 1] = 0xA1;
            data[offsets::MSG_APCI + 2] = error.into();
            data[offsets::MSG_APCI + 3] = (process_time_100ms >> 8) as u8;
            data[offsets::MSG_APCI + 4] = process_time_100ms as u8;
        });

        debug!("AL sending Restart_Response: error={}, process_time={}ms", error, process_time_100ms as u32 * 100);

        outbox.push(msg.into_inner());
    }
}

// ============================================================================
// Helpers
// ============================================================================

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
    /// Get the object size and message offset for a communication object.
    ///
    /// Returns `(size_in_bytes, offset)` where offset is either:
    /// - `offsets::MSG_APCI + 1` for objects > 6 bits (data starts after APCI byte)
    /// - `offsets::MSG_APDU` for objects <= 6 bits (data fits in APCI low bits)
    fn get_object_size_and_offset(cot_info: &crate::objects::tables::ComObjectTableEntry) -> (usize, usize) {
        match cot_info.object_type.size_in_bytes() {
            (s, true) => (s, offsets::MSG_APCI + 1),
            (s, false) => (s, offsets::MSG_APDU),
        }
    }
}
