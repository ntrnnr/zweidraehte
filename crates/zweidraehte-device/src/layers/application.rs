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

use crate::{
    AccessContext, AccessSource, HasConnectionAuth, StackDefinition, StackState,
    actor::Request,
    address::GroupAddress,
    messages::{
        buffers::{Buffer, DynBufferManager},
        builder::MessageBuilder,
        knx::*,
    },
    objects::{
        comm::{ComObjectEvent, ComObjectIndex, ComObjectStatus, ComObjects},
        interface::{FullPropertyReadRequest, FullPropertyWriteRequest, HasDeviceObject, PropertyServiceHandler},
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
    /// 1-indexed); transitions to `Done` when the scan completes, and resets
    /// to `Idle` when the application stops (enabling a fresh scan on
    /// restart).
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
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum ReadOnInitState {
    /// No ROI cycle active — ready to start on next app startup.
    Idle,
    /// Scanning objects, sending reads. The `u16` is the next ASAP to check.
    Scanning(u16),
    /// Scan completed for this app run. Resets to `Idle` when the app stops
    /// (so a restart triggers a fresh scan).
    Done,
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
    fn resolve_access(&self, msg: &KnxMessageBuffer<Buffer<'static>>) -> AccessContext {
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

impl<D: StackDefinition> Layer for ApplicationLayer<'_, D> {
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
                if crate::access_policy::check_service_access(apci, &access_ctx)
                    == crate::access_policy::AccessDecision::Denied
                {
                    warn!("AL service {:?} denied: {:?}", apci, access_ctx);
                    return;
                }
                // Allowed or Defer — proceed to handler

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

                    // --- Function Property Services ---
                    ApciCode::FunctionPropertyCommand => {
                        self.handle_function_property_command(&msg, outbox);
                    }
                    ApciCode::FunctionPropertyStateRead => {
                        self.handle_function_property_state_read(&msg, outbox);
                    }
                    // FunctionPropertyStateResponse is a response APCI — ignore if received.
                    ApciCode::FunctionPropertyStateResponse => {
                        debug!("AL ignoring FunctionPropertyStateResponse (response APCI)");
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
            ReadOnInitState::Scanning(cursor) => {
                debug!("AL next_deadline: ROI active (cursor={}), next step in 100ms", cursor);
                Some(embassy_time::Instant::now() + embassy_time::Duration::from_millis(100))
            }
            ReadOnInitState::Idle => {
                // Self-detect: when the app is running and AST is loaded but
                // comm objects are still Uninitialized (the DeviceModel resets
                // them on app start), a ROI scan is needed.
                if self.state.app().borrow().is_running()
                    && self.state.ast().borrow().is_loaded()
                    && self.comm_objects.borrow().status(1) == ComObjectStatus::Uninitialized
                {
                    Some(embassy_time::Instant::now())
                } else {
                    None
                }
            }
            ReadOnInitState::Done => None,
        }
    }

    fn poll(&mut self, outbox: &mut Outbox) {
        // Reset Done → Idle when the app stops, so the next startup triggers
        // a fresh ROI scan.
        if self.read_on_init == ReadOnInitState::Done && !self.state.app().borrow().is_running() {
            self.read_on_init = ReadOnInitState::Idle;
        }

        // Start ROI scan if the conditions are met (app running, AST loaded,
        // comm objects still uninitialized from DeviceModel reset).
        if self.read_on_init == ReadOnInitState::Idle
            && self.state.app().borrow().is_running()
            && self.state.ast().borrow().is_loaded()
            && self.comm_objects.borrow().status(1) == ComObjectStatus::Uninitialized
        {
            info!("AL read-on-init: starting cycle (detected uninitialized objects)");
            self.read_on_init = ReadOnInitState::Scanning(1);
        }

        self.read_on_init_step(outbox);
    }
}

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
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

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
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
                    zweidraehte_util::fmt::Bytes(self.comm_objects.borrow().value(asap))
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

            let msg = MessageBuilder::new_request(
                msg_buf,
                ServiceType::T_GroupData_Req,
                request_priority,
                DestinationAddress::ConnectionNr(tsap),
            )
            .with_application(ApciCode::GroupValueResponse)
            .with_data(|buf| {
                buf[msg_offset..msg_offset + object_size].copy_from_slice(self.comm_objects.borrow().value(asap));
            });

            outbox.push(msg.into_inner());

            trace!(
                "AL sent GroupValueResponse for ASAP {}: {:?}",
                asap,
                zweidraehte_util::fmt::Bytes(self.comm_objects.borrow().value(asap))
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

            let msg = if read {
                MessageBuilder::new_request(
                    msg_buf,
                    ServiceType::T_GroupData_Req,
                    cot_info.flags.priority(),
                    DestinationAddress::ConnectionNr(tsap),
                )
                .with_application(ApciCode::GroupValueRead)
                .build()
            } else {
                MessageBuilder::new_request(
                    msg_buf,
                    ServiceType::T_GroupData_Req,
                    cot_info.flags.priority(),
                    DestinationAddress::ConnectionNr(tsap),
                )
                .with_application(ApciCode::GroupValueWrite)
                .with_data(|buf| {
                    buf[msg_offset..msg_offset + object_size].copy_from_slice(self.comm_objects.borrow().value(asap));
                })
            };

            // Store pending state so the TL confirmation (arriving later on
            // conf_rx) can update the CO status.
            self.pending_group_send = Some(PendingGroupSend { asap, read });

            // Send fire-and-forget to TL — confirmation handled in handle_tl_confirmation
            debug!("AL -> TL: GroupValue {} ASAP {} TSAP {}", if read { "Read" } else { "Write" }, asap, tsap);
            outbox.push(msg.into_inner());
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
    /// Objects that are not eligible (no ROI flag, already have a value,
    /// or not linked) are left untouched — they keep their current status.
    /// In particular, non-ROI objects stay `Uninitialized` until they
    /// actually receive a value via a write or response from the bus.
    fn read_on_init_step(&mut self, outbox: &mut Outbox) {
        let ReadOnInitState::Scanning(start) = self.read_on_init else {
            return;
        };

        // Cancel if app is no longer running or AST not loaded. Reset to
        // Idle (not Done) so a subsequent app restart triggers a fresh scan.
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

            // 1. ROI flag must be set
            if !cot_info.flags.read_on_init() {
                continue;
            }

            // 2. Object must still be uninitialized (value not yet valid)
            if self.comm_objects.borrow().status(asap) != ComObjectStatus::Uninitialized {
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
        self.read_on_init = ReadOnInitState::Done;
    }
}

// ============================================================================
// Property Services (A_PropertyDescription_*, A_PropertyValue_*)
// ============================================================================

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
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
        use crate::messages::{
            apdu::property::{PropertyDescriptionRead, PropertyDescriptionResponse},
            builder::IndicationExt,
        };

        if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
            warn!("AL PropertyDescriptionRead unexpected service type: {:?}", ind.service_type());
            return;
        }

        let Some(req) = PropertyDescriptionRead::parse(ind.buf()) else {
            error!("PropertyDescriptionRead message too short: {}", ind.len());
            return;
        };

        debug!(
            "AL PropertyDescriptionRead: obj={}, prop_id={}, prop_idx={}",
            req.object_idx, req.prop_id, req.prop_idx
        );

        let response = self.interface_objects.property_description_read(req.object_idx, req.prop_id, req.prop_idx);

        match response {
            Ok(desc) => {
                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(PropertyDescriptionResponse::MSG_LEN)
                else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg = ind.respond_with(msg_buf).with_application(ApciCode::PropertyDescriptionResponse).with_data(
                    |data| {
                        // Success case: the descriptor encodes itself directly
                        let response_buf = &mut data[offsets::MSG_APCI + 2..];
                        let _len = desc.encode(response_buf);
                    },
                );

                debug!("AL sending PropertyDescriptionResponse: {:?}", desc);
                outbox.push(msg.into_inner());
            }
            Err(e) => {
                warn!("AL PropertyDescriptionRead failed: {:?}", e);

                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(PropertyDescriptionResponse::MSG_LEN)
                else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg = ind.respond_with(msg_buf).with_application(ApciCode::PropertyDescriptionResponse).with_data(
                    |data| {
                        PropertyDescriptionResponse::write_error(data, req.object_idx as u8, req.prop_id, req.prop_idx);
                    },
                );

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
        use crate::messages::{
            apdu::property::{PropertyValueHeader, PropertyValueResponse},
            builder::IndicationExt,
        };

        if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
            warn!("AL PropertyValueRead unexpected service type: {:?}", ind.service_type());
            return;
        }

        let Some(hdr) = PropertyValueHeader::parse(ind.buf()) else {
            error!("PropertyValueRead message too short: {}", ind.len());
            return;
        };

        let access_ctx = self.resolve_access(ind);
        debug!(
            "AL PropertyValueRead: obj={}, prop_id={}, count={}, start={}, access_ctx={:?}",
            hdr.object_idx, hdr.prop_id, hdr.count, hdr.start_idx, access_ctx
        );

        const MAX_PROPERTY_DATA: usize = 64;
        let mut data_buf = [0u8; MAX_PROPERTY_DATA];

        let req = FullPropertyReadRequest {
            object_idx: hdr.object_idx,
            pid: hdr.prop_id,
            start_idx: hdr.start_idx,
            count: hdr.count,
            ctx: access_ctx,
        };
        let result = self.interface_objects.property_value_read(&req, &mut data_buf);

        match result {
            Ok(data_len) => {
                let response_len = PropertyValueResponse::msg_len(data_len);
                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(response_len) else {
                    warn!("AL no buffer for response");
                    return;
                };

                // Per KNX spec: if start_idx=0 (element count query), response count=1
                let response_count = if hdr.start_idx == 0 { 1 } else { hdr.count };

                let msg =
                    ind.respond_with(msg_buf).with_application(ApciCode::PropertyValueResponse).with_data(|buf| {
                        PropertyValueResponse::write(
                            buf,
                            hdr.object_idx as u8,
                            hdr.prop_id,
                            response_count,
                            hdr.start_idx,
                            &data_buf[..data_len],
                        );
                    });

                debug!("AL sending PropertyValueResponse: {} bytes", data_len);
                outbox.push(msg.into_inner());
            }
            Err(e) => {
                warn!("AL PropertyValueRead failed: {:?}", e);

                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(PropertyValueResponse::ERROR_MSG_LEN)
                else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg =
                    ind.respond_with(msg_buf).with_application(ApciCode::PropertyValueResponse).with_data(|buf| {
                        PropertyValueResponse::write_error(buf, hdr.object_idx as u8, hdr.prop_id, hdr.start_idx);
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
        use crate::messages::{
            apdu::property::{PropertyValueHeader, PropertyValueResponse},
            builder::IndicationExt,
        };

        if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
            warn!("AL PropertyValueWrite unexpected service type: {:?}", ind.service_type());
            return;
        }

        let Some(hdr) = PropertyValueHeader::parse(ind.buf()) else {
            error!("PropertyValueWrite message too short: {}", ind.len());
            return;
        };
        let data = hdr.data(ind.buf());

        let access_ctx = self.resolve_access(ind);
        debug!(
            "AL PropertyValueWrite: obj={}, prop_id={}, count={}, start={}, data_len={}, access_ctx={:?}",
            hdr.object_idx,
            hdr.prop_id,
            hdr.count,
            hdr.start_idx,
            data.len(),
            access_ctx
        );

        let req = FullPropertyWriteRequest {
            object_idx: hdr.object_idx,
            pid: hdr.prop_id,
            start_idx: hdr.start_idx,
            data,
            ctx: access_ctx,
        };
        let result = self.interface_objects.property_value_write(&req);

        match result {
            Ok(write_response) => {
                // WriteResponse::Echo means echo back the original data;
                // WriteResponse::Data contains transformed data (e.g., LOAD_STATE_CONTROL)
                let response_data: &[u8] = write_response.as_slice().unwrap_or(data);
                let response_len = PropertyValueResponse::msg_len(response_data.len());
                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(response_len) else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg =
                    ind.respond_with(msg_buf).with_application(ApciCode::PropertyValueResponse).with_data(|buf| {
                        PropertyValueResponse::write(
                            buf,
                            hdr.object_idx as u8,
                            hdr.prop_id,
                            hdr.count,
                            hdr.start_idx,
                            response_data,
                        );
                    });

                debug!("AL sending PropertyValueResponse (write success): {} bytes", response_data.len());
                outbox.push(msg.into_inner());
            }
            Err(e) => {
                warn!("AL PropertyValueWrite failed: {:?}", e);

                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(PropertyValueResponse::ERROR_MSG_LEN)
                else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg =
                    ind.respond_with(msg_buf).with_application(ApciCode::PropertyValueResponse).with_data(|buf| {
                        PropertyValueResponse::write_error(buf, hdr.object_idx as u8, hdr.prop_id, hdr.start_idx);
                    });

                outbox.push(msg.into_inner());
            }
        }
    }
}

// ============================================================================
// Function Property Services (A_FunctionPropertyCommand, ...)
// ============================================================================

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
    /// Handle `A_FunctionPropertyCommand.ind`
    fn handle_function_property_command(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        self.handle_function_property(ind, outbox, true);
    }

    /// Handle `A_FunctionPropertyState_Read.ind`
    fn handle_function_property_state_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        self.handle_function_property(ind, outbox, false);
    }

    /// Shared implementation for function property command and state read.
    ///
    /// Both services share the same wire format and response format, differing
    /// only in which trait method is called on the interface objects.
    fn handle_function_property(
        &mut self,
        ind: &KnxMessageBuffer<Buffer<'static>>,
        outbox: &mut Outbox,
        is_command: bool,
    ) {
        use crate::messages::{
            apdu::function_property::{FunctionPropertyHeader, FunctionPropertyResponse as FpResponseWriter},
            builder::IndicationExt,
        };
        use crate::objects::interface::FunctionPropertyRequest;

        if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
            warn!("AL FunctionProperty unexpected service type: {:?}", ind.service_type());
            return;
        }

        let Some(hdr) = FunctionPropertyHeader::parse(ind.buf()) else {
            error!("FunctionProperty message too short: {}", ind.len());
            return;
        };
        let service_data = hdr.data(ind.buf());

        let access_ctx = self.resolve_access(ind);
        let label = if is_command { "Command" } else { "StateRead" };
        debug!(
            "AL FunctionProperty{}: obj={}, prop_id={}, service_data_len={}, access_ctx={:?}",
            label,
            hdr.object_idx,
            hdr.prop_id,
            service_data.len(),
            access_ctx
        );

        let req = FunctionPropertyRequest {
            object_idx: hdr.object_idx as u16,
            prop_id: hdr.prop_id,
            service_data,
            ctx: access_ctx,
        };

        let result = if is_command {
            self.interface_objects.function_property_command(&req)
        } else {
            self.interface_objects.function_property_state_read(&req)
        };

        let response_data = result.data.as_slice();
        let response_len = FpResponseWriter::msg_len(response_data.len());

        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(response_len) else {
            warn!("AL no buffer for FunctionProperty response");
            return;
        };

        let msg =
            ind.respond_with(msg_buf).with_application(ApciCode::FunctionPropertyStateResponse).with_data(|buf| {
                FpResponseWriter::write(buf, hdr.object_idx, hdr.prop_id, result.return_code, response_data);
            });

        debug!(
            "AL sending FunctionPropertyStateResponse: rc=0x{:02X}, data_len={}",
            result.return_code,
            response_data.len()
        );
        outbox.push(msg.into_inner());
    }
}

// ============================================================================
// Device Management Services (A_DeviceDescriptor_Read, ...)
// ============================================================================

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
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
        use crate::messages::{
            apdu::device::{DeviceDescriptorRead, DeviceDescriptorResponse},
            builder::IndicationExt,
        };

        let Some(req) = DeviceDescriptorRead::parse(ind.buf()) else {
            error!("DeviceDescriptorRead message too short: {}", ind.len());
            return;
        };

        debug!("AL DeviceDescriptorRead: descriptor_type={}", req.descriptor_type);

        if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
            warn!("AL DeviceDescriptorRead unexpected service type: {:?}", ind.service_type());
            return;
        }

        if req.descriptor_type == 0 {
            let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(DeviceDescriptorResponse::TYPE0_MSG_LEN) else {
                warn!("AL no buffer for response");
                return;
            };

            let msg = ind.respond_with(msg_buf).with_application(ApciCode::DeviceDescriptorResponse).with_data(|buf| {
                DeviceDescriptorResponse::write_type0(buf, &D::DEVICE.mask_version_bytes());
            });

            debug!("AL sending DeviceDescriptorResponse: mask_version={}", D::DEVICE.mask_version);
            outbox.push(msg.into_inner());
        } else if req.descriptor_type == 2 {
            if let Some(dd2) = D::DEVICE_DESCRIPTOR_TYPE2 {
                let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(DeviceDescriptorResponse::TYPE2_MSG_LEN)
                else {
                    warn!("AL no buffer for response");
                    return;
                };

                let dd2_arr: &[u8; 14] = dd2;
                let msg =
                    ind.respond_with(msg_buf).with_application(ApciCode::DeviceDescriptorResponse).with_data(|buf| {
                        DeviceDescriptorResponse::write_type2(buf, dd2_arr);
                    });

                debug!("AL sending DeviceDescriptorResponse (DD2): {:?}", zweidraehte_util::fmt::Bytes(dd2));
                outbox.push(msg.into_inner());
            } else {
                self.send_dd_error(ind, outbox);
            }
        } else {
            self.send_dd_error(ind, outbox);
        }
    }

    /// Send a DeviceDescriptorResponse error (descriptor_type = 0x3F).
    fn send_dd_error(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        use crate::messages::{apdu::device::DeviceDescriptorResponse, builder::IndicationExt};

        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(DeviceDescriptorResponse::ERROR_MSG_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind.respond_with(msg_buf).with_application(ApciCode::DeviceDescriptorResponse).with_data(|buf| {
            DeviceDescriptorResponse::write_error(buf);
        });

        debug!("AL sending DeviceDescriptorResponse (error): descriptor_type=0x3F");
        outbox.push(msg.into_inner());
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
        use crate::messages::{apdu::device, builder::MessageBuilder};

        if ind.service_type() != ServiceType::T_Broadcast_Ind {
            warn!("AL IndividualAddressRead with unexpected service type: {:?}", ind.service_type());
            return;
        }

        debug!("AL IndividualAddressRead received");

        if !self.interface_objects.is_programming_mode() {
            trace!("AL IndividualAddressRead ignored (not in programming mode)");
            return;
        }

        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(device::APCI_ONLY_MSG_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        // IndividualAddressResponse: broadcast to 0x0000, address conveyed in source field
        let msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::T_Broadcast_Req,
            ind.ctrl_field().priority(),
            DestinationAddress::Group(GroupAddress::from_bytes(&[0x00, 0x00])),
        )
        .with_application(ApciCode::IndividualAddressResponse)
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
        use crate::{address::IndividualAddress, messages::apdu::device::IndividualAddressWrite};

        if ind.service_type() != ServiceType::T_Broadcast_Ind {
            warn!("AL IndividualAddressWrite with unexpected service type: {:?}", ind.service_type());
            return;
        }

        if !self.interface_objects.is_programming_mode() {
            trace!("AL IndividualAddressWrite ignored (not in programming mode)");
            return;
        }

        let Some(addr_bytes) = IndividualAddressWrite::address_bytes(ind.buf()) else {
            error!("IndividualAddressWrite message too short: {}", ind.len());
            return;
        };

        let new_addr = IndividualAddress::from_bytes(addr_bytes);
        debug!("AL IndividualAddressWrite: setting address to {}", new_addr);
        self.state.set_individual_address(new_addr);
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
        use crate::messages::{
            apdu::device::{IndividualAddressSerialNumberRead, IndividualAddressSerialNumberResponse},
            builder::MessageBuilder,
        };

        if ind.service_type() != ServiceType::T_Broadcast_Ind {
            warn!("AL IndividualAddressSerialNumberRead with unexpected service type: {:?}", ind.service_type());
            return;
        }

        let Some(received_serial) = IndividualAddressSerialNumberRead::serial_number(ind.buf()) else {
            error!("IndividualAddressSerialNumberRead message too short: {}", ind.len());
            return;
        };

        if received_serial != self.state.serial_number() {
            trace!("AL IndividualAddressSerialNumberRead ignored (serial mismatch)");
            return;
        }

        debug!("AL IndividualAddressSerialNumberRead: serial matches, sending response");

        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(IndividualAddressSerialNumberResponse::MSG_LEN)
        else {
            warn!("AL no buffer for response");
            return;
        };

        let mut msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::T_Broadcast_Req,
            ind.ctrl_field().priority(),
            DestinationAddress::Group(GroupAddress::from_bytes(&[0x00, 0x00])),
        )
        .with_application(ApciCode::IndividualAddressSerialNumberResponse)
        .build();

        let serial: &[u8; 6] = self.state.serial_number();
        IndividualAddressSerialNumberResponse::write_serial(msg.buf_mut(), serial);

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
        use crate::{address::IndividualAddress, messages::apdu::device::IndividualAddressSerialNumberWrite};

        if ind.service_type() != ServiceType::T_Broadcast_Ind {
            warn!("AL IndividualAddressSerialNumberWrite with unexpected service type: {:?}", ind.service_type());
            return;
        }

        let buf = ind.buf();

        let Some(received_serial) = IndividualAddressSerialNumberWrite::serial_number(buf) else {
            error!("IndividualAddressSerialNumberWrite message too short: {}", ind.len());
            return;
        };

        if received_serial != self.state.serial_number() {
            trace!("AL IndividualAddressSerialNumberWrite ignored (serial mismatch)");
            return;
        }

        // address_bytes() can't fail here since serial_number() already validated the length
        let new_addr_bytes = IndividualAddressSerialNumberWrite::address_bytes(buf)
            .expect("length already validated by serial_number check");
        let new_addr = IndividualAddress::from_bytes(new_addr_bytes);

        debug!("AL IndividualAddressSerialNumberWrite: setting address to {}", new_addr);
        self.state.set_individual_address(new_addr);
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
        use crate::messages::{
            apdu::device::{AdcRead, AdcResponse},
            builder::IndicationExt,
        };

        let Some(req) = AdcRead::parse(ind.buf()) else {
            error!("ADC_Read message too short: {}", ind.len());
            return;
        };

        debug!("AL ADC_Read: channel={}, count={}", req.channel, req.count);

        // ADC_Read is only valid in connection-oriented mode
        if ind.service_type() != ServiceType::T_Data_Ind {
            debug!("AL ADC_Read requires connection-oriented mode, got {:?}", ind.service_type());
            return;
        }

        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(AdcResponse::MSG_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        // Channels 0-5 are supported; return dummy sum 0x0000
        let (response_count, sum) = if req.channel <= 5 { (req.count, 0x0000u16) } else { (0u8, 0x0000u16) };

        let msg = ind.respond_with(msg_buf).with_application(ApciCode::AdcResponse).with_data(|buf| {
            AdcResponse::write(buf, req.channel, response_count, sum);
        });

        debug!("AL sending ADC_Response: channel={}, count={}, sum={}", req.channel, response_count, sum);
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
        use crate::messages::{
            apdu::memory::{MemoryAccess, MemoryResponse},
            builder::IndicationExt,
        };

        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL Memory_Read rejected: connection-oriented only");
            return;
        }

        let Some(acc) = MemoryAccess::parse_read(ind.buf()) else {
            error!("Memory_Read message too short: {}", ind.len());
            return;
        };

        debug!("AL Memory_Read: address=0x{:04X}, count={}", acc.address, acc.count);

        let access_ctx = self.resolve_access(ind);
        let mut data = [0u8; 63]; // Max count is 63 (6 bits)
        let result = self.memory_map.read(self.state, acc.address, &mut data[..(acc.count as usize)], access_ctx);

        let response_count = match result {
            Ok(bytes_read) => bytes_read as u8,
            Err(_) => 0,
        };

        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(MemoryResponse::msg_len(response_count as usize))
        else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind.respond_with(msg_buf).with_application(ApciCode::MemoryReadResponse).with_data(|buf| {
            MemoryResponse::write(buf, response_count, acc.address, &data[..response_count as usize]);
        });

        debug!("AL sending Memory_Response: address=0x{:04X}, count={}", acc.address, response_count);
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
        use crate::messages::{
            apdu::memory::{MemoryAccess, MemoryResponse},
            builder::IndicationExt,
        };

        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL Memory_Write rejected: connection-oriented only");
            return;
        }

        let Some(acc) = MemoryAccess::parse_write(ind.buf()) else {
            error!("Memory_Write message too short: {}", ind.len());
            return;
        };

        let length_inconsistent = !acc.is_length_consistent(ind.len());
        if length_inconsistent {
            warn!(
                "Memory_Write length inconsistency: expected {} bytes, got {} (count={})",
                offsets::MSG_APCI + 4 + acc.count as usize,
                ind.len(),
                acc.count
            );
        }

        debug!("AL Memory_Write: address=0x{:04X}, count={}", acc.address, acc.count);

        let access_ctx = self.resolve_access(ind);

        let response_count = if length_inconsistent {
            0
        } else {
            match self.memory_map.write(self.state, acc.address, acc.data, access_ctx) {
                Ok(bytes_written) => {
                    debug!("AL Memory_Write: wrote {} bytes to 0x{:04X}", bytes_written, acc.address);
                    self.state.mark_dirty();
                    bytes_written as u8
                }
                Err(e) => {
                    warn!("AL Memory_Write failed: address=0x{:04X}, error={:?}", acc.address, e);
                    0
                }
            }
        };

        if !self.interface_objects.verify_mode() {
            return;
        }

        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(MemoryResponse::msg_len(response_count as usize))
        else {
            warn!("AL no buffer for response");
            return;
        };

        // Error responses (count=0) must not include the original request data,
        // which would overflow the buffer sized for zero data bytes.
        let response_data = if response_count > 0 { acc.data } else { &[] };
        let msg = ind.respond_with(msg_buf).with_application(ApciCode::MemoryReadResponse).with_data(|buf| {
            MemoryResponse::write(buf, response_count, acc.address, response_data);
        });

        debug!("AL sending Memory_Response (verify): address=0x{:04X}, count={}", acc.address, response_count);
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
        use crate::messages::apdu::memory::MemoryBitWrite;

        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL MemoryBit_Write rejected: connection-oriented only");
            return;
        }

        // Extract header fields (count + address) before full parse, so we can
        // send an error response even when the message is too short for its
        // declared mask count.
        let raw = ind.buf();
        if raw.len() < MemoryBitWrite::MIN_MSG_LEN {
            error!("MemoryBit_Write message too short: {}", ind.len());
            return;
        }
        let header_count = raw[offsets::MSG_APCI + 2] & 0x0F;
        let header_address = u16::from_be_bytes([raw[offsets::MSG_APCI + 3], raw[offsets::MSG_APCI + 4]]);

        // Reject illegal count (must be 1-5) or truncated messages up front,
        // sending an error response so the remote side isn't left waiting.
        if !(1..=5).contains(&header_count) {
            warn!("MemoryBit_Write illegal count: {}", header_count);
            self.send_memorybit_response(ind, header_address, 0, &[], outbox);
            return;
        }
        let expected_len = MemoryBitWrite::expected_msg_len(header_count as usize);
        if ind.len() != expected_len {
            warn!(
                "MemoryBit_Write length mismatch: expected {} bytes, got {} (count={})",
                expected_len,
                ind.len(),
                header_count
            );
            self.send_memorybit_response(ind, header_address, 0, &[], outbox);
            return;
        }

        // Full parse is safe now — header, count, and mask lengths are validated.
        let mbw = MemoryBitWrite::parse(raw).expect("header and length already validated");

        debug!("AL MemoryBit_Write: address=0x{:04X}, count={}", mbw.address, mbw.count);

        let access_ctx = self.resolve_access(ind);

        // Read current memory values
        let mut current_data = [0u8; 5];
        let read_result =
            self.memory_map.read(self.state, mbw.address, &mut current_data[..mbw.count as usize], access_ctx);

        match read_result {
            Ok(_) => {
                // Apply bit manipulation: new = (old AND and_mask) XOR xor_mask
                let mut new_data = [0u8; 5];
                for i in 0..mbw.count as usize {
                    new_data[i] = (current_data[i] & mbw.and_masks[i]) ^ mbw.xor_masks[i];
                }

                match self.memory_map.write(self.state, mbw.address, &new_data[..mbw.count as usize], access_ctx) {
                    Ok(_) => {
                        debug!("AL MemoryBit_Write: wrote {} bytes to 0x{:04X}", mbw.count, mbw.address);
                        self.send_memorybit_response(
                            ind,
                            mbw.address,
                            mbw.count,
                            &new_data[..mbw.count as usize],
                            outbox,
                        );
                    }
                    Err(e) => {
                        warn!("AL MemoryBit_Write write failed: address=0x{:04X}, error={:?}", mbw.address, e);
                        self.send_memorybit_response(ind, mbw.address, 0, &[], outbox);
                    }
                }
            }
            Err(e) => {
                warn!("AL MemoryBit_Write read failed: address=0x{:04X}, error={:?}", mbw.address, e);
                self.send_memorybit_response(ind, mbw.address, 0, &[], outbox);
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
        use crate::messages::{apdu::memory::MemoryResponse, builder::IndicationExt};

        if !self.interface_objects.verify_mode() {
            return;
        }

        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(MemoryResponse::msg_len(count as usize)) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind.respond_with(msg_buf).with_application(ApciCode::MemoryReadResponse).with_data(|buf| {
            MemoryResponse::write(buf, count, address, data);
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
        use crate::messages::{
            apdu::memory::{UserMemoryAccess, UserMemoryResponse},
            builder::IndicationExt,
        };

        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL UserMemory_Read rejected: connection-oriented only");
            return;
        }

        let Some(acc) = UserMemoryAccess::parse_read(ind.buf()) else {
            error!("UserMemory_Read message too short: {}", ind.len());
            return;
        };

        debug!("AL UserMemory_Read: address=0x{:05X}, count={}", acc.full_address(), acc.count);

        let access_ctx = self.resolve_access(ind);
        let mut data = [0u8; 255];
        let max_read = core::cmp::min(acc.count as usize, data.len());
        let result = self.memory_map.read(self.state, acc.address_low, &mut data[..max_read], access_ctx);

        let response_count = match result {
            Ok(bytes_read) => bytes_read as u8,
            Err(_) => 0,
        };

        let Some(msg_buf) =
            self.buffer_manager.try_alloc_with_size(UserMemoryResponse::msg_len(response_count as usize))
        else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind.respond_with(msg_buf).with_application(ApciCode::UserMemoryResponse).with_data(|buf| {
            UserMemoryResponse::write(
                buf,
                acc.addr_ext,
                response_count,
                acc.address_low,
                &data[..response_count as usize],
            );
        });

        debug!("AL sending UserMemory_Response: address=0x{:05X}, count={}", acc.full_address(), response_count);
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
        use crate::messages::{
            apdu::memory::{UserMemoryAccess, UserMemoryResponse},
            builder::IndicationExt,
        };

        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL UserMemory_Write rejected: connection-oriented only");
            return;
        }

        let Some(acc) = UserMemoryAccess::parse_write(ind.buf()) else {
            error!("UserMemory_Write message too short: {}", ind.len());
            return;
        };

        let length_inconsistent = !acc.is_length_consistent(ind.len());
        if length_inconsistent {
            warn!(
                "UserMemory_Write length inconsistency: expected {} bytes, got {} (count={})",
                offsets::MSG_APCI + 5 + acc.count as usize,
                ind.len(),
                acc.count
            );
        }

        debug!("AL UserMemory_Write: address=0x{:05X}, count={}", acc.full_address(), acc.count);

        let access_ctx = self.resolve_access(ind);

        let response_count = if length_inconsistent {
            0
        } else {
            match self.memory_map.write(self.state, acc.address_low, acc.data, access_ctx) {
                Ok(bytes_written) => {
                    debug!("AL UserMemory_Write: wrote {} bytes to 0x{:05X}", bytes_written, acc.full_address());
                    self.state.mark_dirty();
                    bytes_written as u8
                }
                Err(e) => {
                    warn!("AL UserMemory_Write failed: address=0x{:05X}, error={:?}", acc.full_address(), e);
                    0
                }
            }
        };

        if !self.interface_objects.verify_mode() {
            return;
        }

        let Some(msg_buf) =
            self.buffer_manager.try_alloc_with_size(UserMemoryResponse::msg_len(response_count as usize))
        else {
            warn!("AL no buffer for response");
            return;
        };

        // Error responses (count=0) must not include the original request data,
        // which would overflow the buffer sized for zero data bytes.
        let response_data = if response_count > 0 { acc.data } else { &[] };
        let msg = ind.respond_with(msg_buf).with_application(ApciCode::UserMemoryResponse).with_data(|buf| {
            UserMemoryResponse::write(buf, acc.addr_ext, response_count, acc.address_low, response_data);
        });

        debug!(
            "AL sending UserMemory_Response (verify): address=0x{:05X}, count={}",
            acc.full_address(),
            response_count
        );
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

        if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
            warn!("AL UserManufacturerInfo_Read unexpected service type: {:?}", ind.service_type());
            return;
        }

        // Response: APCI(2) + Manufacturer ID(2) + Device Type(1) = 5 bytes
        const RESPONSE_LEN: usize = offsets::MSG_APCI + 5;
        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(RESPONSE_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg =
            ind.respond_with(msg_buf).with_application(ApciCode::UserManufacturerInfoResponse).with_data(|data| {
                // Copy the 3-byte manufacturer info (Manufacturer ID + Device Type)
                data[offsets::MSG_APCI + 2..offsets::MSG_APCI + 5].copy_from_slice(info);
            });

        debug!("AL sending UserManufacturerInfo_Response: {:?}", zweidraehte_util::fmt::Bytes(info));

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
        use crate::messages::{
            apdu::auth::{AuthorizeRequest, AuthorizeResponse},
            builder::IndicationExt,
        };

        let Some(req) = AuthorizeRequest::parse(ind.buf()) else {
            error!("Authorize_Request message too short: {}", ind.len());
            return;
        };

        debug!("AL Authorize_Request: key={:?}", zweidraehte_util::fmt::Bytes(&req.key));

        let access_level = self.state.authorize(&req.key);
        debug!("AL Authorize_Request: granted level {}", access_level);

        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL Authorize_Request rejected: connection-oriented only");
            return;
        }

        // Write the granted level directly to the shared access store so it
        // takes effect immediately — no piggybacking on the response message.
        if let AccessSource::Connection(slot) = ind.access_source() {
            self.state.set_connection_access(slot, AccessContext::new(access_level));
        }

        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(AuthorizeResponse::MSG_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind.respond_with(msg_buf).with_application(ApciCode::AuthorizeResponse).with_data(|buf| {
            AuthorizeResponse::write(buf, access_level);
        });

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
        use crate::messages::{
            apdu::auth::{KeyResponse, KeyWrite},
            builder::IndicationExt,
        };

        let Some(req) = KeyWrite::parse(ind.buf()) else {
            error!("Key_Write message too short: {}", ind.len());
            return;
        };

        let current_ctx = self.resolve_access(ind);
        debug!(
            "AL Key_Write: level={}, key={:?}, current_ctx={:?}",
            req.level,
            zweidraehte_util::fmt::Bytes(&req.key),
            current_ctx
        );

        let result_level = self.state.key_write(req.level, &req.key, current_ctx);
        debug!("AL Key_Write: result={}", result_level);

        if ind.service_type() != ServiceType::T_Data_Ind {
            warn!("AL Key_Write rejected: connection-oriented only");
            return;
        }

        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(KeyResponse::MSG_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind.respond_with(msg_buf).with_application(ApciCode::KeyResponse).with_data(|buf| {
            KeyResponse::write(buf, result_level);
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
        use crate::messages::apdu::restart::RestartParsed;

        let Some(parsed) = RestartParsed::parse(ind.buf()) else {
            warn!("AL Restart message too short: {}", ind.len());
            return;
        };

        let (erase_code, channel, needs_response) = if parsed.is_master_reset {
            (EraseCode::from(parsed.erase_code), parsed.channel, true)
        } else {
            (EraseCode::Basic, 0, false)
        };

        let restart_ctx = self.resolve_access(ind);
        debug!(
            "AL Restart: erase_code={}, channel={}, needs_response={}, access_ctx={:?}",
            erase_code, channel, needs_response, restart_ctx
        );

        if matches!(erase_code, EraseCode::Other(_)) {
            warn!("AL Restart: unsupported erase code {:?}", erase_code);
            if needs_response {
                self.send_restart_response(ind, RestartError::UnsupportedEraseCode, 0, outbox);
            }
            return;
        }

        if channel != 0 {
            warn!("AL Restart: invalid channel number {}", channel);
            if needs_response {
                self.send_restart_response(ind, RestartError::InvalidChannel, 0, outbox);
            }
            return;
        }

        let required_level = match erase_code {
            EraseCode::Basic | EraseCode::Confirmed => 3,
            _ => 0,
        };

        if !restart_ctx.has_level(required_level) {
            warn!("AL Restart: access denied ({:?}, required={})", restart_ctx, required_level);
            if needs_response {
                self.send_restart_response(ind, RestartError::AccessDenied, 0, outbox);
            }
            return;
        }

        let request = RestartRequest { erase_code, channel, access_ctx: restart_ctx, needs_response };
        debug!("AL Restart: sending request to user code");
        self.restart_sender.try_send(request).ok();

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
        use crate::messages::{apdu::restart::RestartResponse, builder::IndicationExt};

        let Some(msg_buf) = self.buffer_manager.try_alloc_with_size(RestartResponse::MSG_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind.respond_with(msg_buf).with_application(ApciCode::Restart).with_data(|buf| {
            RestartResponse::write(buf, error.into(), process_time_100ms);
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
