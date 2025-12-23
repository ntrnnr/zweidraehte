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

use embassy_futures::select::{Either, select};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{DynamicReceiver, DynamicSender},
    pubsub::{PubSubBehavior, PubSubChannel},
};

use super::{ActorRequest, Inbox, Layer, LayerOp, Request};

use crate::{
    StackDefinition, StackState,
    address::GroupAddress,
    memory::{HasAssociationTable, HasCommunicationObjectTable},
    messages::{
        buffers::{Buffer, DynBufferManager},
        builder::{IndicationMessage, RequestMessage},
        knx::*,
    },
    objects::{
        comm::{ComObjectEvent, ComObjectIndex, ComObjectStatus, ComObjects},
        interface::PropertyServiceHandler,
        tables::{AssociationTable, CommunicationObjectTable},
    },
};

// ============================================================================
// Service Types
// ============================================================================

/// Service requests from the application to the application layer
#[derive(Debug)]
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
    buffer_manager: &'a RefCell<DynBufferManager<'static>>,
    /// User-defined tables container (for accessing AST/COT via accessor traits)
    tables: &'a D::Tables,
    comm_objects: &'a RefCell<D::CO>,
    hook_context: &'a <D::CO as ComObjects>::HookContext,
    event_channel:
        &'a PubSubChannel<NoopRawMutex, (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent), 4, 2, 1>,

    // --- Property services ---
    #[allow(dead_code)] // TODO: implement property services
    interface_object_server: &'a dyn PropertyServiceHandler,

    // --- Device state ---
    /// Runtime state (programming mode, etc.)
    state: &'a D::State,

    // --- Memory access ---
    /// Memory map for A_Memory_Read/Write services
    memory_map: &'a D::Mem,

    // --- Communication channels ---
    app_request_receiver: DynamicReceiver<'a, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
    transport_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
}

// ============================================================================
// Construction
// ============================================================================

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
    /// Create a new Application Layer
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        buffer_manager: &'a RefCell<DynBufferManager<'static>>,
        tables: &'a D::Tables,
        comm_objects: &'a RefCell<D::CO>,
        hook_context: &'a <D::CO as ComObjects>::HookContext,
        event_channel: &'a PubSubChannel<
            NoopRawMutex,
            (<<D as StackDefinition>::CO as ComObjects>::Index, ComObjectEvent),
            4,
            2,
            1,
        >,
        interface_object_server: &'a dyn PropertyServiceHandler,
        state: &'a D::State,
        memory_map: &'a D::Mem,
        app_request_receiver: DynamicReceiver<'a, Request<ApplicationLayerService, ApplicationLayerServiceResponse>>,
        transport_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
    ) -> Self {
        Self {
            buffer_manager,
            tables,
            comm_objects,
            hook_context,
            event_channel,
            interface_object_server,
            state,
            memory_map,
            app_request_receiver,
            transport_layer,
        }
    }
}

// ============================================================================
// Layer Implementation (Main Event Loop)
// ============================================================================

impl<'a, D: StackDefinition> Layer<'a> for ApplicationLayer<'a, D>
where
    D::Tables: HasAssociationTable + HasCommunicationObjectTable,
{
    type Buffer = Buffer<'static>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Buffer>>,
    {
        loop {
            match select(inbox.next(), self.app_request_receiver.receive()).await {
                Either::First(msg) => {
                    trace!("AL received: {:?}", msg);

                    match msg {
                        LayerOp::Indication(mut ind) => {
                            debug!("AL APCI code: {:?}", ind.get_apci_code());
                            match ind.get_apci_code() {
                            // --- Group Communication ---
                            a @ (ApciCode::GroupValueWrite | ApciCode::GroupValueResponse) => {
                                self.handle_group_value_write_or_response(&mut ind, a).await;
                            }
                            ApciCode::GroupValueRead => {
                                self.handle_group_value_read(&ind).await;
                            }

                            // --- Property Services ---
                            // FIXME: Not validated to work yet
                            ApciCode::PropertyDescriptionRead => {
                                self.handle_property_description_read(&ind).await;
                            }
                            ApciCode::PropertyValueRead => {
                                self.handle_property_value_read(&ind).await;
                            }
                            ApciCode::PropertyValueWrite => {
                                self.handle_property_value_write(&ind).await;
                            }

                            // --- Device Management ---
                            ApciCode::DeviceDescriptorRead => {
                                self.handle_device_descriptor_read(&ind).await;
                            }
                            ApciCode::IndividualAddressRead => {
                                self.handle_individual_address_read(&ind).await;
                            }
                            ApciCode::IndividualAddressWrite => {
                                self.handle_individual_address_write(&ind).await;
                            }
                            ApciCode::IndividualAddressSerialNumberRead => {
                                self.handle_individual_address_serial_number_read(&ind).await;
                            }
                            ApciCode::IndividualAddressSerialNumberWrite => {
                                self.handle_individual_address_serial_number_write(&ind).await;
                            }
                            ApciCode::AdcRead => {
                                self.handle_adc_read(&ind).await;
                            }
                            ApciCode::MemoryRead => {
                                self.handle_memory_read(&ind).await;
                            }
                            ApciCode::MemoryWrite => {
                                self.handle_memory_write(&ind).await;
                            }
                            // ApciCode::Restart => { ... }
                            _ => {
                                warn!("Unhandled APCI code: {:?}", ind.get_apci_code());
                            }
                        }},
                        _ => {
                            warn!("AL unexpected LayerOp variant");
                        }
                    }
                }
                Either::Second(request) => match request.get() {
                    r @ ApplicationLayerService::GroupValueWriteRequest(asap) => {
                        debug!("AL GroupValueWrite.req: {:?}", r);

                        self.send_group_value_request(*asap, false).await;
                        request.reply(ApplicationLayerServiceResponse::GroupValueWriteResponse).await;
                    }
                    r @ ApplicationLayerService::GroupValueReadRequest(asap) => {
                        debug!("AL GroupValueRead.req: {:?}", r);

                        self.send_group_value_request(*asap, true).await;
                        request.reply(ApplicationLayerServiceResponse::GroupValueWriteResponse).await;
                    }
                },
            }
        }
    }
}

// ============================================================================
// Group Communication Services (A_GroupValue_*)
// ============================================================================

impl<'a, D: StackDefinition> ApplicationLayer<'a, D>
where
    D::Tables: HasAssociationTable + HasCommunicationObjectTable,
{
    /// Handle `A_GroupValue_Write.ind` or `A_GroupValue_Response.ind`
    ///
    /// Updates local communication objects with values received from the bus.
    /// Only valid for `T_GroupData_Ind` service type.
    async fn handle_group_value_write_or_response(
        &mut self,
        ind: &mut IndicationMessage<Buffer<'static>>,
        apci: ApciCode,
    ) {
        // Validate service type
        if ind.service_type() != ServiceType::T_GroupData_Ind {
            warn!("AL {:?} with unexpected service type: {:?}", apci, ind.service_type());
            return;
        }

        debug!("AL received {:?}", apci);
        // FIXME: check if application is running (also check if tables are loaded?)

        trace!("AL incoming TSAP: {:?}", ind.get_connection_nr());

        for asap in self.tables.ast().borrow().asaps_for_tsap(ind.get_connection_nr()) {
            trace!("AL processing ASAP: {}", asap);

            let Some(cot_info) = self.tables.cot().borrow().get_object(asap) else {
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
            if ind.len() as usize == object_size + msg_offset {
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

                debug!("AL ASAP {} updated via {:?}: {:x?}", asap, apci, self.comm_objects.borrow().value(asap));
            } else {
                error!("Length of telegram not enough to contain object value");
            }
        }
    }

    /// Handle `A_GroupValue_Read.ind`
    ///
    /// Responds with the current value of the communication object.
    /// Only valid for `T_GroupData_Ind` service type.
    async fn handle_group_value_read(&mut self, ind: &IndicationMessage<Buffer<'static>>) {
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

        // Get the priority from the incoming request - response should mirror it
        // This is BCU1/BCU2 compatible behavior as per EITT tests
        let request_priority = ind.ctrl_field().priority();

        let tsap = ind.get_connection_nr();
        trace!("AL incoming TSAP: {:?}", tsap);

        for asap in self.tables.ast().borrow().asaps_for_tsap(tsap) {
            trace!("AL processing GroupValueRead for ASAP: {}", asap);

            let Some(cot_info) = self.tables.cot().borrow().get_object(asap) else {
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
            let msg_buf = self.buffer_manager.borrow().alloc_with_size(object_size + msg_offset).await;

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

            // Send the response to the transport layer and wait for confirmation
            let confirmation = self.transport_layer.request(RequestMessage::request(msg)).await;
            debug!("AL GroupValueResponse confirmation ASAP {} TSAP {}: {:?}", asap, tsap, confirmation.service_type());

            trace!("AL sent GroupValueResponse for ASAP {}: {:x?}", asap, self.comm_objects.borrow().value(asap));

            // Publish read event to the event channel
            if let Some(index) = <<D as StackDefinition>::CO as ComObjects>::Index::from_index(asap) {
                self.event_channel.publish_immediate((index, ComObjectEvent::Read));
            }
        }
    }

    /// Send `A_GroupValue_Write.req` or `A_GroupValue_Read.req`
    ///
    /// Called when the local application wants to send a group value to the bus.
    async fn send_group_value_request(&self, asap: u16, read: bool) {
        // FIXME: check if device is configured at all:
        //        following needs to be loaded: Addr, Assoc, Cotab and App

        let Some(cot_info) = self.tables.cot().borrow().get_object(asap) else {
            error!("Invalid ASAP: {}", asap);
            // FIXME: return error to caller?
            return;
        };

        let status = *self.comm_objects.borrow().info(asap).status;

        if !read && status != ComObjectStatus::WriteRequest {
            return;
        }

        if read && status != ComObjectStatus::ReadRequest {
            return;
        }

        if !cot_info.flags.communication_enable() {
            // Communication disabled - set error status but preserve the request type
            // BCU1/BCU2 behavior: Read/Write request stays pending with error indication
            let new_status = if read { ComObjectStatus::ReadRequestError } else { ComObjectStatus::WriteRequestError };
            self.comm_objects.borrow_mut().set_status(asap, new_status);

            debug!("AL comm object {} not enabled for communication", asap);
            return;
        }

        if !cot_info.flags.transmission_enable() {
            // Transmission disabled - set error status but preserve the request type
            let new_status = if read { ComObjectStatus::ReadRequestError } else { ComObjectStatus::WriteRequestError };
            self.comm_objects.borrow_mut().set_status(asap, new_status);

            debug!("AL comm object {} transmission not enabled", asap);
            return;
        }

        self.comm_objects.borrow_mut().set_status(asap, ComObjectStatus::Busy);

        // We only send to the first TSAP per spec
        if let Some(tsap) = self.tables.ast().borrow().get_sending_tsap(asap) {
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
            let msg_buf = self.buffer_manager.borrow().alloc_with_size(object_size + msg_offset).await;

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

            // Send the request to the transport layer and wait for confirmation
            let confirmation = self.transport_layer.request(RequestMessage::request(msg)).await;
            debug!("AL confirmation for ASAP {} TSAP {}: {:?}", asap, tsap, confirmation.service_type());

            // Update communication object status based on confirmation
            // BCU1/BCU2 behavior: Read request stays pending (waiting for response)
            // Write request clears after successful transmission
            if confirmation.ctrl_field().c() == Confirm::NoError {
                if read {
                    // Read request: keep pending, waiting for GroupValue_Response
                    self.comm_objects.borrow_mut().set_status(asap, ComObjectStatus::ReadRequestOk);
                } else {
                    // Write request: transmission complete
                    self.comm_objects.borrow_mut().set_status(asap, ComObjectStatus::IdleOk);
                }
            } else {
                // Transmission failed
                let new_status =
                    if read { ComObjectStatus::ReadRequestError } else { ComObjectStatus::WriteRequestError };
                self.comm_objects.borrow_mut().set_status(asap, new_status);
            }
        } else {
            // No sending TSAP found - error
            let new_status = if read { ComObjectStatus::ReadRequestError } else { ComObjectStatus::WriteRequestError };
            self.comm_objects.borrow_mut().set_status(asap, new_status);

            error!("AL no sending TSAP or transmission flag not set for ASAP {} - Flags: {:?}", asap, cot_info.flags);
        }
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
    async fn handle_property_description_read(&mut self, ind: &IndicationMessage<Buffer<'static>>) {
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
        let response = self.interface_object_server.property_description_read(object_idx, prop_id, prop_idx);

        match response {
            Ok(desc) => {
                // Allocate response message: APCI(2) + ObjectIdx(1) + PropId(1) + PropIdx(1) + TypeMax(2) + Access(1) = 8
                const RESPONSE_LEN: usize = offsets::MSG_APCI + 8;
                let msg_buf = self.buffer_manager.borrow().alloc_with_size(RESPONSE_LEN).await;

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
                let confirmation = self.transport_layer.request(msg).await;
                trace!("AL PropertyDescriptionResponse confirmation: {:?}", confirmation.service_type());
            }
            Err(e) => {
                // Send negative response with prop_id = 0 to indicate error
                warn!("AL PropertyDescriptionRead failed: {:?}", e);

                const ERROR_RESPONSE_LEN: usize = offsets::MSG_APCI + 5;
                let msg_buf = self.buffer_manager.borrow().alloc_with_size(ERROR_RESPONSE_LEN).await;

                let msg = ind
                    .respond_with(msg_buf)
                    .with_application(ApciCode::PropertyDescriptionResponse, response_service_type)
                    .with_data(|data| {
                        // Error response: prop_id = 0 indicates "no such property"
                        data[offsets::MSG_APCI + 2] = object_idx as u8;
                        data[offsets::MSG_APCI + 3] = 0; // prop_id = 0 indicates error
                        data[offsets::MSG_APCI + 4] = prop_idx;
                    });

                let confirmation = self.transport_layer.request(msg).await;
                trace!("AL PropertyDescriptionResponse (error) confirmation: {:?}", confirmation.service_type());
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
    async fn handle_property_value_read(&mut self, ind: &IndicationMessage<Buffer<'static>>) {
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
        let count = (count_start >> 12) as u16;
        let start_idx = count_start & 0x0FFF;

        debug!("AL PropertyValueRead: obj={}, prop_id={}, count={}, start={}", object_idx, prop_id, count, start_idx);

        // Allocate a buffer for the response data
        // Max APDU size is typically 14 bytes for TP1, so max data is about 8 bytes
        // We'll use a reasonable max and let the handler limit it
        const MAX_PROPERTY_DATA: usize = 64;
        let mut data_buf = [0u8; MAX_PROPERTY_DATA];

        // Query the interface object server
        let result =
            self.interface_object_server.property_value_read(object_idx, prop_id, start_idx, count, &mut data_buf);

        match result {
            Ok(data_len) => {
                // Allocate response message: APCI(2) + ObjIdx(1) + PropId(1) + Count+StartIdx(2) + Data(N)
                let response_len = offsets::MSG_APCI + 6 + data_len;
                let msg_buf = self.buffer_manager.borrow().alloc_with_size(response_len).await;

                let msg = ind
                    .respond_with(msg_buf)
                    .with_application(ApciCode::PropertyValueResponse, response_service_type)
                    .with_data(|data| {
                        // Fill in the response header
                        data[offsets::MSG_APCI + 2] = object_idx as u8;
                        data[offsets::MSG_APCI + 3] = prop_id;
                        data[offsets::MSG_APCI + 4] = (count_start >> 8) as u8;
                        data[offsets::MSG_APCI + 5] = count_start as u8;

                        // Copy the data
                        data[offsets::MSG_APCI + 6..offsets::MSG_APCI + 6 + data_len]
                            .copy_from_slice(&data_buf[..data_len]);
                    });

                debug!("AL sending PropertyValueResponse: {} bytes", data_len);

                // Send the response
                let confirmation = self.transport_layer.request(msg).await;
                trace!("AL PropertyValueResponse confirmation: {:?}", confirmation.service_type());
            }
            Err(e) => {
                // Send error response with count = 0
                warn!("AL PropertyValueRead failed: {:?}", e);

                const ERROR_RESPONSE_LEN: usize = offsets::MSG_APCI + 6;
                let msg_buf = self.buffer_manager.borrow().alloc_with_size(ERROR_RESPONSE_LEN).await;

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

                let confirmation = self.transport_layer.request(msg).await;
                trace!("AL PropertyValueResponse (error) confirmation: {:?}", confirmation.service_type());
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
    async fn handle_property_value_write(&mut self, ind: &IndicationMessage<Buffer<'static>>) {
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
        let count = (count_start >> 12) as u16;
        let start_idx = count_start & 0x0FFF;

        // Extract the data to write
        let data_start = offsets::MSG_APCI + 6;
        let data_len = ind.len() - data_start;
        let data = &buf[data_start..data_start + data_len];

        debug!(
            "AL PropertyValueWrite: obj={}, prop_id={}, count={}, start={}, data_len={}",
            object_idx, prop_id, count, start_idx, data_len
        );

        // Perform the write
        let result = self.interface_object_server.property_value_write(object_idx, prop_id, start_idx, data);

        match result {
            Ok(()) => {
                // Success: echo back the written data
                let response_len = offsets::MSG_APCI + 6 + data_len;
                let msg_buf = self.buffer_manager.borrow().alloc_with_size(response_len).await;

                let msg = ind
                    .respond_with(msg_buf)
                    .with_application(ApciCode::PropertyValueResponse, response_service_type)
                    .with_data(|response_buf| {
                        response_buf[offsets::MSG_APCI + 2] = object_idx as u8;
                        response_buf[offsets::MSG_APCI + 3] = prop_id;
                        response_buf[offsets::MSG_APCI + 4] = (count_start >> 8) as u8;
                        response_buf[offsets::MSG_APCI + 5] = count_start as u8;

                        // Echo back the written data
                        response_buf[offsets::MSG_APCI + 6..offsets::MSG_APCI + 6 + data_len].copy_from_slice(data);
                    });

                debug!("AL sending PropertyValueResponse (write success): {} bytes", data_len);

                let confirmation = self.transport_layer.request(msg).await;
                trace!("AL PropertyValueResponse (write) confirmation: {:?}", confirmation.service_type());
            }
            Err(e) => {
                // Error: respond with count = 0
                warn!("AL PropertyValueWrite failed: {:?}", e);

                const ERROR_RESPONSE_LEN: usize = offsets::MSG_APCI + 6;
                let msg_buf = self.buffer_manager.borrow().alloc_with_size(ERROR_RESPONSE_LEN).await;

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

                let confirmation = self.transport_layer.request(msg).await;
                trace!("AL PropertyValueResponse (write error) confirmation: {:?}", confirmation.service_type());
            }
        }
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
    async fn handle_device_descriptor_read(&mut self, ind: &IndicationMessage<Buffer<'static>>) {
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
            let msg_buf = self.buffer_manager.borrow().alloc_with_size(RESPONSE_LEN).await;

            let msg = ind
                .respond_with(msg_buf)
                .with_application(ApciCode::DeviceDescriptorResponse, transport_service)
                .with_data(|data| {
                    // Set descriptor type to 0 in the response
                    data[offsets::MSG_APCI + 1] = (data[offsets::MSG_APCI + 1] & 0xC0) | 0x00;
                    // Copy mask version
                    data[offsets::MSG_APCI + 2..offsets::MSG_APCI + 4].copy_from_slice(D::MASK_VERSION);
                });

            debug!("AL sending DeviceDescriptorResponse: mask_version={:02x?}", D::MASK_VERSION);

            let confirmation = self.transport_layer.request(msg).await;
            trace!("AL DeviceDescriptorResponse confirmation: {:?}", confirmation.service_type());
        } else {
            // Any other descriptor type: error response with type = 0x3F, no data
            const ERROR_RESPONSE_LEN: usize = offsets::MSG_APCI + 2; // APCI(2) only, no data
            let msg_buf = self.buffer_manager.borrow().alloc_with_size(ERROR_RESPONSE_LEN).await;

            let msg = ind
                .respond_with(msg_buf)
                .with_application(ApciCode::DeviceDescriptorResponse, transport_service)
                .with_data(|data| {
                    // Set descriptor type to 0x3F (all 6 bits set) to indicate error
                    data[offsets::MSG_APCI + 1] = (data[offsets::MSG_APCI + 1] & 0xC0) | 0x3F;
                });

            debug!("AL sending DeviceDescriptorResponse (error): descriptor_type=0x3F");

            let confirmation = self.transport_layer.request(msg).await;
            trace!("AL DeviceDescriptorResponse (error) confirmation: {:?}", confirmation.service_type());
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
    async fn handle_individual_address_read(&mut self, ind: &IndicationMessage<Buffer<'static>>) {
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
        if !self.state.programming_mode() {
            trace!("AL IndividualAddressRead ignored (not in programming mode)");
            return;
        }

        // IndividualAddressResponse: APCI only, no payload
        // The individual address is conveyed in the source address field of the L_Data frame
        const RESPONSE_LEN: usize = offsets::MSG_APCI + 2;
        let msg_buf = self.buffer_manager.borrow().alloc_with_size(RESPONSE_LEN).await;

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

        let confirmation = self.transport_layer.request(msg).await;
        trace!("AL IndividualAddressResponse confirmation: {:?}", confirmation.service_type());
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
    async fn handle_individual_address_write(&mut self, ind: &IndicationMessage<Buffer<'static>>) {
        use crate::address::IndividualAddress;

        // Validate service type - must be broadcast
        if ind.service_type() != ServiceType::T_Broadcast_Ind {
            warn!("AL IndividualAddressWrite with unexpected service type: {:?}", ind.service_type());
            return;
        }

        // Only accept if device is in programming mode
        if !self.state.programming_mode() {
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
    async fn handle_individual_address_serial_number_read(&mut self, ind: &IndicationMessage<Buffer<'static>>) {
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
        let msg_buf = self.buffer_manager.borrow().alloc_with_size(RESPONSE_LEN).await;

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

        let confirmation = self.transport_layer.request(msg).await;
        trace!("AL IndividualAddressSerialNumberResponse confirmation: {:?}", confirmation.service_type());
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
    async fn handle_individual_address_serial_number_write(&mut self, ind: &IndicationMessage<Buffer<'static>>) {
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
    async fn handle_adc_read(&mut self, ind: &IndicationMessage<Buffer<'static>>) {
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

        // Determine transport service type
        let transport_service = match ind.service_type() {
            ServiceType::T_Data_Ind => ServiceType::T_Data_Req,
            ServiceType::T_DataUnack_Ind => ServiceType::T_DataUnack_Req,
            other => {
                warn!("AL ADC_Read unexpected service type: {:?}", other);
                return;
            }
        };

        // Response: APCI(2) + count(1) + sum(2) = 5 bytes APDU
        const RESPONSE_LEN: usize = offsets::MSG_APCI + 5;
        let msg_buf = self.buffer_manager.borrow().alloc_with_size(RESPONSE_LEN).await;

        // We support channels 0-5 (typical KNX ADC channels), return 0 for unsupported
        // For supported channels, we return dummy values (0x0000 for the sum)
        let (response_count, sum) = if channel <= 5 {
            // Supported channel - return requested count and dummy sum
            (count, 0x0000u16)
        } else {
            // Unsupported channel - return count=0 and sum=0
            (0u8, 0x0000u16)
        };

        let msg = ind
            .respond_with(msg_buf)
            .with_application(ApciCode::AdcResponse, transport_service)
            .with_data(|data| {
                // Set channel in low 6 bits of APCI byte 1
                data[offsets::MSG_APCI + 1] = (data[offsets::MSG_APCI + 1] & 0xC0) | channel;
                // Count
                data[offsets::MSG_APCI + 2] = response_count;
                // Sum (big-endian)
                data[offsets::MSG_APCI + 3] = (sum >> 8) as u8;
                data[offsets::MSG_APCI + 4] = sum as u8;
            });

        debug!("AL sending ADC_Response: channel={}, count={}, sum={}", channel, response_count, sum);

        let confirmation = self.transport_layer.request(msg).await;
        trace!("AL ADC_Response confirmation: {:?}", confirmation.service_type());
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
    async fn handle_memory_read(&mut self, ind: &IndicationMessage<Buffer<'static>>) {
        use crate::memory::MemoryMap;
        use crate::messages::builder::IndicationExt;

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

        // Determine transport service type
        let transport_service = match ind.service_type() {
            ServiceType::T_Data_Ind => ServiceType::T_Data_Req,
            ServiceType::T_DataUnack_Ind => ServiceType::T_DataUnack_Req,
            other => {
                warn!("AL Memory_Read unexpected service type: {:?}", other);
                return;
            }
        };

        // Read from memory map first to determine response size
        let mut data = [0u8; 63]; // Max count is 63 (6 bits)
        let result = self.memory_map.read(self.tables, address, &mut data[..(count as usize)]);

        let response_count = match result {
            Ok(bytes_read) => bytes_read as u8,
            Err(_) => 0, // Error: return count=0
        };

        // Response: APCI(2) + address(2) + data(response_count) = 4 + response_count bytes APDU
        // On error, response_count is 0 and no data is sent (just APCI + address)
        let response_len = offsets::MSG_APCI + 4 + (response_count as usize);
        let msg_buf = self.buffer_manager.borrow().alloc_with_size(response_len).await;

        let msg = ind
            .respond_with(msg_buf)
            .with_application(ApciCode::MemoryReadResponse, transport_service)
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

        let confirmation = self.transport_layer.request(msg).await;
        trace!("AL Memory_Response confirmation: {:?}", confirmation.service_type());
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
    async fn handle_memory_write(&mut self, ind: &IndicationMessage<Buffer<'static>>) {
        use crate::memory::MemoryMap;
        use crate::messages::builder::IndicationExt;
        use crate::objects::interface::pid;

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

        // If length is inconsistent, don't write and respond with count=0
        // Otherwise, write to memory map
        let response_count = if length_inconsistent {
            0 // Length inconsistency: response with count=0
        } else {
            match self.memory_map.write(self.tables, address, data) {
                Ok(bytes_written) => {
                    debug!("AL Memory_Write: wrote {} bytes to 0x{:04X}", bytes_written, address);
                    bytes_written as u8
                }
                Err(e) => {
                    warn!("AL Memory_Write failed: address=0x{:04X}, error={:?}", address, e);
                    0 // Error: response with count=0
                }
            }
        };

        // Check if Verify flag is set in DEVICE_CONTROL (Object 0, PID 14)
        // Bit 2 (0x04) is the Verify flag
        let mut device_control = [0u8; 1];
        let verify_enabled = self
            .interface_object_server
            .property_value_read(0, pid::DEVICE_CONTROL, 1, 1, &mut device_control)
            .map(|_| device_control[0] & 0x04 != 0)
            .unwrap_or(false);

        if !verify_enabled {
            // No response when Verify is not enabled
            return;
        }

        // Determine transport service type
        let transport_service = match ind.service_type() {
            ServiceType::T_Data_Ind => ServiceType::T_Data_Req,
            ServiceType::T_DataUnack_Ind => ServiceType::T_DataUnack_Req,
            other => {
                warn!("AL Memory_Write unexpected service type: {:?}", other);
                return;
            }
        };

        // Send Memory_Response with written data (or count=0 on error)
        // Response: APCI(2) + address(2) + data(response_count) = 4 + response_count bytes APDU
        let response_len = offsets::MSG_APCI + 4 + (response_count as usize);
        let msg_buf = self.buffer_manager.borrow().alloc_with_size(response_len).await;

        let msg = ind
            .respond_with(msg_buf)
            .with_application(ApciCode::MemoryReadResponse, transport_service)
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

        let confirmation = self.transport_layer.request(msg).await;
        trace!("AL Memory_Response confirmation: {:?}", confirmation.service_type());
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
