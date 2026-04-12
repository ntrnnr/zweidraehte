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

pub mod services;
pub(crate) mod group_data;

use crate::context::RestartPublisherContext;
use crate::{
    AccessContext, AccessSource, HasAuthorization, HasConnectionAuth, StackDefinition, StackState,
    actor::Request,
    address::GroupAddress,
    inner::StackContext,
    layer_context::HasOutbox,
    messages::{
        buffers::{Buffer, DynBufferManager},
        knx::*,
    },
    objects::{
        comm::HasCommObjects,
        interface::{FullPropertyReadRequest, FullPropertyWriteRequest, HasDeviceObject, PropertyServiceHandler},
    },
    restart::{EraseCode, RestartError, RestartRequest},
    router::Layer,
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
    /// Request to initiate an S-A_Sync_Req to a peer.
    SyncRequest { peer_ia: u16, tool_access: bool, is_broadcast: bool },
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
    /// S-A_Sync_Req was successfully sent.
    SyncInitiated,
    /// S-A_Sync_Req failed (no key, no buffer, non-secure stack).
    SyncFailed,
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
    /// Unified device state (contains tables and runtime configuration)
    state: &'a D::State,

    lctx: &'a crate::layer_context::LayerContext<D>,

    // --- Interface objects ---
    /// Interface objects container with typed access to device properties.
    /// Provides both PropertyServiceHandler for management protocol and
    /// HasDeviceObject for direct property access.
    interface_objects: &'a D::InterfaceObjects<'static>,

    // --- Memory access ---
    /// Memory map for A_Memory_Read/Write services
    memory_map: &'a D::Mem,

    /// Group data handler — owns read-on-init state, pending group sends,
    /// and all incoming/outgoing group communication logic.
    group_data: group_data::GroupDataHandler<'a, D>,

    /// Optional service extension for profile-specific APCI handlers.
    services: D::Services,
}

// ============================================================================
// Construction
// ============================================================================

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
    /// Create a new Application Layer from a [`StackContext`].
    pub fn new(ctx: &'a StackContext<'a, D>) -> Self {
        Self {
            state: ctx.state(),
            lctx: ctx.layer_context(),
            interface_objects: ctx.interface_objects(),
            memory_map: ctx.memory_map(),
            group_data: group_data::GroupDataHandler::new(ctx.state(), ctx.layer_context()),
            services: Default::default(),
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

    /// Access the buffer manager for allocating response buffers.
    pub(crate) fn buffer_manager(&self) -> &'a DynBufferManager<'static> {
        &self.lctx.buffer_manager
    }

    /// Access the unified device state.
    pub(crate) fn state(&self) -> &'a D::State {
        self.state
    }

    /// Access the layer context.
    pub(crate) fn lctx(&self) -> &'a crate::layer_context::LayerContext<D> {
        self.lctx
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

    fn process(&mut self, mut msg: KnxMessageBuffer<Buffer<'static>>) {
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
                        self.group_data.handle_write_or_response(&mut msg, a);
                    }
                    ApciCode::GroupValueRead => {
                        self.group_data.handle_read(&msg);
                    }

                    // --- Property Services ---
                    ApciCode::PropertyDescriptionRead => {
                        self.handle_property_description_read(&msg);
                    }
                    ApciCode::PropertyValueRead => {
                        self.handle_property_value_read(&msg);
                    }
                    ApciCode::PropertyValueWrite => {
                        self.handle_property_value_write(&msg);
                    }

                    // --- Function Property Services ---
                    ApciCode::FunctionPropertyCommand => {
                        self.handle_function_property_command(&msg);
                    }
                    ApciCode::FunctionPropertyStateRead => {
                        self.handle_function_property_state_read(&msg);
                    }
                    // FunctionPropertyStateResponse is a response APCI — ignore if received.
                    ApciCode::FunctionPropertyStateResponse => {
                        debug!("AL ignoring FunctionPropertyStateResponse (response APCI)");
                    }

                    // --- Device Management ---
                    ApciCode::DeviceDescriptorRead => {
                        self.handle_device_descriptor_read(&msg);
                    }
                    ApciCode::IndividualAddressRead => {
                        self.handle_individual_address_read(&msg);
                    }
                    ApciCode::IndividualAddressWrite => {
                        self.handle_individual_address_write(&msg);
                    }
                    ApciCode::Restart => {
                        self.handle_restart(&msg);
                    }
                    _ => {
                        use crate::layers::application::services::{AlService as _, AlServiceContext};
                        let ctx = AlServiceContext {
                            state: self.state,
                            lctx: self.lctx,
                            interface_objects: self.interface_objects,
                            memory_map: self.memory_map,
                            comm_objects: self.state.comm_objects(),
                            access_ctx,
                        };
                        if !self.services.try_handle(apci, &msg, &ctx) {
                            warn!("Unhandled APCI code: {:?}", msg.get_apci_code());
                        }
                    }
                }
            }
        }
    }

    fn next_deadline(&self) -> Option<embassy_time::Instant> {
        self.group_data.next_deadline()
    }

    fn poll(&mut self) {
        self.group_data.poll();
    }
}

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
    /// Handle a confirmation from the transport layer.
    ///
    /// If a group value send is pending, updates the communication object
    /// status based on the confirmation result. Otherwise the confirmation
    /// is for a response (e.g., property read reply) and can be dropped.
    fn handle_tl_confirmation(&mut self, conf: &KnxMessageBuffer<Buffer<'static>>) {
        if !self.group_data.handle_tl_confirmation(conf) {
            // Confirmation for a send_response call — just log
            trace!("AL TL confirmation (response): {:?}", conf.service_type());
        }
    }

    /// Handle an application service request from user code.
    ///
    /// Called by the router when an app request arrives (not via the dispatch
    /// table, since these aren't KnxMessageBuffer messages).
    pub fn handle_app_request(&mut self, request: &Request<ApplicationLayerService, ApplicationLayerServiceResponse>) {
        match request.get() {
            r @ ApplicationLayerService::GroupValueWriteRequest(asap) => {
                debug!("AL GroupValueWrite.req: {:?}", r);

                let response = if self.group_data.send_group_value_request(*asap, false) {
                    ApplicationLayerServiceResponse::GroupValueWriteResponse
                } else {
                    ApplicationLayerServiceResponse::ApplicationNotRunning
                };
                request.try_reply(response).ok();
            }
            r @ ApplicationLayerService::GroupValueReadRequest(asap) => {
                debug!("AL GroupValueRead.req: {:?}", r);

                let response = if self.group_data.send_group_value_request(*asap, true) {
                    ApplicationLayerServiceResponse::GroupValueReadResponse
                } else {
                    ApplicationLayerServiceResponse::ApplicationNotRunning
                };
                request.try_reply(response).ok();
            }
            ApplicationLayerService::SyncRequest { .. } => {
                // Sync requests are intercepted by the Secure Application
                // Layer wrapper. If we reach here on a non-secure stack,
                // reply with failure.
                request.try_reply(ApplicationLayerServiceResponse::SyncFailed).ok();
            }
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
    fn handle_property_description_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>) {
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

        let access_ctx = self.resolve_access(ind);
        let response =
            self.interface_objects.property_description_read(req.object_idx, req.prop_id, req.prop_idx as u16);

        // Apply per-property Data Secure access policy: if the caller can't
        // read the property value, hide the descriptor too. This prevents
        // the non-ext service from leaking property metadata that the ext
        // version would hide.
        let response = match response {
            Ok(desc) => {
                let test_req = FullPropertyReadRequest {
                    object_idx: req.object_idx,
                    pid: desc.prop_id,
                    start_idx: 0,
                    count: 1,
                    ctx: access_ctx,
                };
                let mut dummy = [0u8; 4];
                match self.interface_objects.property_value_read(&test_req, &mut dummy) {
                    Err(crate::objects::interface::PropertyError::AccessDenied) => {
                        Err(crate::objects::interface::PropertyError::AccessDenied)
                    }
                    _ => Ok(desc),
                }
            }
            err => err,
        };

        match response {
            Ok(desc) => {
                let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(PropertyDescriptionResponse::MSG_LEN)
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
                self.lctx.push_outbox(msg.into_inner());
            }
            Err(e) => {
                warn!("AL PropertyDescriptionRead failed: {:?}", e);

                let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(PropertyDescriptionResponse::MSG_LEN)
                else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg = ind.respond_with(msg_buf).with_application(ApciCode::PropertyDescriptionResponse).with_data(
                    |data| {
                        PropertyDescriptionResponse::write_error(data, req.object_idx as u8, req.prop_id, req.prop_idx);
                    },
                );

                self.lctx.push_outbox(msg.into_inner());
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
    fn handle_property_value_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>) {
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
                let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(response_len) else {
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
                self.lctx.push_outbox(msg.into_inner());
            }
            Err(e) => {
                warn!("AL PropertyValueRead failed: {:?}", e);

                let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(PropertyValueResponse::ERROR_MSG_LEN)
                else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg =
                    ind.respond_with(msg_buf).with_application(ApciCode::PropertyValueResponse).with_data(|buf| {
                        PropertyValueResponse::write_error(buf, hdr.object_idx as u8, hdr.prop_id, hdr.start_idx);
                    });

                self.lctx.push_outbox(msg.into_inner());
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
    fn handle_property_value_write(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>) {
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
            count: hdr.count,
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
                let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(response_len) else {
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
                self.lctx.push_outbox(msg.into_inner());
            }
            Err(e) => {
                warn!("AL PropertyValueWrite failed: {:?}", e);

                let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(PropertyValueResponse::ERROR_MSG_LEN)
                else {
                    warn!("AL no buffer for response");
                    return;
                };

                let msg =
                    ind.respond_with(msg_buf).with_application(ApciCode::PropertyValueResponse).with_data(|buf| {
                        PropertyValueResponse::write_error(buf, hdr.object_idx as u8, hdr.prop_id, hdr.start_idx);
                    });

                self.lctx.push_outbox(msg.into_inner());
            }
        }
    }
}

// ============================================================================
// Function Property Services (A_FunctionPropertyCommand, ...)
// ============================================================================

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
    /// Handle `A_FunctionPropertyCommand.ind`
    fn handle_function_property_command(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>) {
        self.handle_function_property(ind, true);
    }

    /// Handle `A_FunctionPropertyState_Read.ind`
    fn handle_function_property_state_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>) {
        self.handle_function_property(ind, false);
    }

    /// Shared implementation for function property command and state read.
    ///
    /// Both services share the same wire format and response format, differing
    /// only in which trait method is called on the interface objects.
    fn handle_function_property(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>, is_command: bool) {
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

        let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(response_len) else {
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
        self.lctx.push_outbox(msg.into_inner());
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
    fn handle_device_descriptor_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>) {
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
            let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(DeviceDescriptorResponse::TYPE0_MSG_LEN)
            else {
                warn!("AL no buffer for response");
                return;
            };

            // Access policy 3FF/0CC at data level: when security mode is on
            // and the request lacks sufficient access (e.g. plain or auth-only),
            // return FF FF (masked) instead of the real device descriptor.
            use crate::access::AccessPolicy;
            let access_ctx = self.resolve_access(ind);
            let security_on = self.state.security_mode_enabled();
            let mask_version = if AccessPolicy::READ_OPEN_WRITE_TOOL.can_read(&access_ctx, security_on) {
                D::DEVICE.mask_version_bytes()
            } else {
                [0xFF, 0xFF]
            };

            let msg = ind.respond_with(msg_buf).with_application(ApciCode::DeviceDescriptorResponse).with_data(|buf| {
                DeviceDescriptorResponse::write_type0(buf, &mask_version);
            });

            debug!("AL sending DeviceDescriptorResponse: mask_version={}", D::DEVICE.mask_version);
            self.lctx.push_outbox(msg.into_inner());
        } else if req.descriptor_type == 2 {
            if let Some(dd2) = D::DEVICE_DESCRIPTOR_TYPE2 {
                let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(DeviceDescriptorResponse::TYPE2_MSG_LEN)
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
                self.lctx.push_outbox(msg.into_inner());
            } else {
                self.send_dd_error(ind);
            }
        } else {
            self.send_dd_error(ind);
        }
    }

    /// Send a DeviceDescriptorResponse error (descriptor_type = 0x3F).
    fn send_dd_error(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>) {
        use crate::messages::{apdu::device::DeviceDescriptorResponse, builder::IndicationExt};

        let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(DeviceDescriptorResponse::ERROR_MSG_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind.respond_with(msg_buf).with_application(ApciCode::DeviceDescriptorResponse).with_data(|buf| {
            DeviceDescriptorResponse::write_error(buf);
        });

        debug!("AL sending DeviceDescriptorResponse (error): descriptor_type=0x3F");
        self.lctx.push_outbox(msg.into_inner());
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
    fn handle_individual_address_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>) {
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

        let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(device::APCI_ONLY_MSG_LEN) else {
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
        self.lctx.push_outbox(msg.into_inner());
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
    fn handle_individual_address_write(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>) {
        use crate::{address::IndividualAddress, messages::apdu::device::IndividualAddressWrite};

        if ind.service_type() != ServiceType::T_Broadcast_Ind {
            warn!("AL IndividualAddressWrite with unexpected service type: {:?}", ind.service_type());
            return;
        }

        if !self.interface_objects.is_programming_mode() {
            trace!("AL IndividualAddressWrite ignored (not in programming mode)");
            return;
        }

        // Access policy 3FF/00C: everyone can write when security mode is off;
        // when security mode is on, only Tool A+C can write.
        use crate::access::AccessPolicy;
        let access_ctx = self.resolve_access(ind);
        let security_on = self.state.security_mode_enabled();
        if !AccessPolicy::OPEN_OFF_TOOL_ON.can_write(&access_ctx, security_on) {
            debug!("AL IndividualAddressWrite denied by access policy");
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
    fn handle_restart(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>) {
        if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
            warn!("AL Restart with unexpected service type: {:?}", ind.service_type());
            return;
        }

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
                self.send_restart_response(ind, RestartError::UnsupportedEraseCode, 0);
            }
            return;
        }

        if channel != 0 {
            warn!("AL Restart: invalid channel number {}", channel);
            if needs_response {
                self.send_restart_response(ind, RestartError::InvalidChannel, 0);
            }
            return;
        }

        // Security-mode access policy: AP 3FF/00C for all restart types.
        // When security mode is off, all callers can restart (0x3FF = all bits set).
        // When security mode is on, only Tool A+C is allowed (0x00C).
        use crate::access::AccessPolicy;
        let security_on = self.state.security_mode_enabled();
        if !AccessPolicy::OPEN_OFF_TOOL_ON.can_write(&restart_ctx, security_on) {
            warn!("AL Restart: access denied by security policy ({:?}, sec_on={})", restart_ctx, security_on);
            if needs_response {
                self.send_restart_response(ind, RestartError::AccessDenied, 0);
            }
            return;
        }

        // Legacy access level check (non-secure fallback).
        let required_level = match erase_code {
            EraseCode::Basic | EraseCode::Confirmed => 3,
            _ => 0,
        };

        if !restart_ctx.has_level(required_level) {
            warn!("AL Restart: access denied ({:?}, required={})", restart_ctx, required_level);
            if needs_response {
                self.send_restart_response(ind, RestartError::AccessDenied, 0);
            }
            return;
        }

        let request = RestartRequest { erase_code, channel, access_ctx: restart_ctx, needs_response };
        debug!("AL Restart: sending request to user code");
        self.lctx.try_send_restart_request(request);

        if needs_response {
            self.send_restart_response(ind, RestartError::NoError, 0);
        }
    }

    /// Send A_Restart_Response message
    fn send_restart_response(
        &mut self,
        ind: &KnxMessageBuffer<Buffer<'static>>,
        error: RestartError,
        process_time_100ms: u16,
    ) {
        use crate::messages::{apdu::restart::RestartResponse, builder::IndicationExt};

        let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(RestartResponse::MSG_LEN) else {
            warn!("AL no buffer for response");
            return;
        };

        let msg = ind.respond_with(msg_buf).with_application(ApciCode::Restart).with_data(|buf| {
            RestartResponse::write(buf, error.into(), process_time_100ms);
        });

        debug!("AL sending Restart_Response: error={}, process_time={}ms", error, process_time_100ms as u32 * 100);
        self.lctx.push_outbox(msg.into_inner());
    }
}

