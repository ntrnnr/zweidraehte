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
//! ## Device Management (A_DeviceDescriptor_*, A_Restart, etc.)
//! - Device descriptor read
//! - Restart commands (validated here, executed by user code via the
//!   restart channel)
//! - Individual address read/write

pub mod capabilities;
mod erase_policy;
pub(crate) mod group_data;
pub mod services;

#[cfg(test)]
mod restart_tests;

pub use erase_policy::{EraseCodePolicy, PlainEraseCodes, SecureEraseCodes};

use crate::access_policy::{AccessDecision, check_service_access, restart_access_policy, restart_required_level};
use crate::context::layer::{LayerContext, ResponseTarget};
use crate::objects::interface::PropertyError;
use crate::service::{AlCtx, ApciHandler as _, Layer, ServiceCtx};
use crate::{
    HasAuthorization, HasSecurityMode, StackDefinition, StackState,
    actor::Request,
    context::StackContext,
    objects::interface::{FullPropertyReadRequest, FullPropertyWriteRequest, HasDeviceObject, PropertyServiceHandler},
    restart::{RestartError, RestartRequest, RestartType},
};
use zweidraehte_proto::AccessContext;
use zweidraehte_proto::AccessSource;
use zweidraehte_proto::HasConnectionAuth;
use zweidraehte_proto::messages::{
    buffers::{Buffer, DynBufferManager},
    knx::*,
};

// ============================================================================
// Service Types
// ============================================================================

/// Service requests from the application to the application layer
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ApplicationLayerService {
    /// Request to send a `A_GroupValue_Write.req` for the object at the
    /// given logical (DSL) index
    GroupValueWriteRequest(u16),
    /// Request to send a `A_GroupValue_Read.req` for the object at the
    /// given logical (DSL) index
    GroupValueReadRequest(u16),
    /// Request to initiate an S-A_Sync_Req to a peer, naming the peer's
    /// (assumed) KNX Serial Number; see [`SyncOptions`](crate::stack_handle::SyncOptions).
    SyncRequest { peer_ia: u16, tool_access: bool, is_broadcast: bool, serial_number: [u8; 6] },
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
///
/// [`StackDefinition::EraseCodePolicy`] fixes erase-code availability,
/// independently of runtime Security Mode. The plain constructor cannot
/// construct an inner layer for a secure definition:
///
/// ```compile_fail,E0599
/// use zweidraehte_device::{StackDefinition, context::StackContext};
/// use zweidraehte_device::layers::application::{ApplicationLayer, SecureEraseCodes};
/// fn standalone_secure<'a, D: StackDefinition<EraseCodePolicy = SecureEraseCodes>>(
///     ctx: &'a StackContext<'a, D>,
/// ) {
///     let _ = ApplicationLayer::<D>::new(ctx);
/// }
/// ```
pub struct ApplicationLayer<'a, D: StackDefinition> {
    /// Unified device state (contains tables and runtime configuration)
    state: &'a D::State,

    lctx: &'a LayerContext<D>,

    // --- Interface objects ---
    /// Interface objects container with typed access to device properties.
    /// Provides both PropertyServiceHandler for management protocol and
    /// HasDeviceObject for direct property access.
    interface_objects: &'a D::InterfaceObjects<'static>,

    // --- Memory access ---
    /// Memory map for A_Memory_Read/Write services
    memory_map: &'a D::Mem,

    /// Borrowed handle for group-data handling. Mutable bookkeeping lives
    /// on [`LayerContext`], so this is a thin two-field view built once at
    /// construction and shared by all group-data methods.
    group_data: group_data::GroupDataProvider<'a, D>,

    /// Optional APCI extension set for profile-specific handlers.
    extensions: D::AlExtensions,
}

// ============================================================================
// Construction
// ============================================================================

impl<'a, D: StackDefinition<EraseCodePolicy = PlainEraseCodes>> ApplicationLayer<'a, D> {
    /// Create a new Application Layer from a [`StackContext`].
    pub fn new(ctx: &'a StackContext<'a, D>) -> Self {
        Self::from_context(ctx)
    }
}

impl<'a, D: StackDefinition> ApplicationLayer<'a, D> {
    // SecureApplicationLayer owns construction of the secure variant, so its
    // profile policy cannot be selected independently of the secure wrapper.
    pub(super) fn from_context(ctx: &'a StackContext<'a, D>) -> Self {
        Self {
            state: ctx.state(),
            lctx: ctx.layer_context(),
            interface_objects: ctx.interface_objects(),
            memory_map: ctx.memory_map(),
            group_data: group_data::GroupDataProvider::new(ctx.state(), ctx.layer_context()),
            extensions: Default::default(),
        }
    }

    /// Resolve the effective [`AccessContext`] for a message.
    ///
    /// - [`AccessSource::Default`] → default access level from device state
    /// - [`AccessSource::Connection(slot)`] → look up from shared access store
    /// - [`AccessSource::Explicit(ctx)`] → use as-is (e.g. KNX/IP Device Mgmt)
    fn resolve_access(&self, msg: &KnxMessageBuffer<Buffer<'static>>) -> AccessContext {
        let mut ctx = match msg.access_source() {
            AccessSource::Default => AccessContext::new(self.state.default_access_level()),
            AccessSource::Connection(slot) => self.state.connection_access(slot),
            AccessSource::Explicit(ctx) => ctx,
        };
        // The failure log records the offender's IA, and `check_access`
        // treats a zero source as "nobody to blame" and skips the log
        // entry. A *plain* request refused by a secured property is a
        // failure against Access and Roles all the same (03/05/01 §6.3.9;
        // TSS J 3.8.12.1 counts its two refused plain reads), so give the
        // default context the frame's real source.
        if ctx.source_addr == 0 {
            ctx.source_addr = u16::from_be_bytes(msg.get_source_addr().0);
        }
        ctx
    }

    /// Access the buffer manager for allocating response buffers.
    pub(crate) fn buffer_manager(&self) -> &'a DynBufferManager<'static> {
        &self.lctx.buffer_manager
    }

    /// Effective APDU budget for an outgoing response, accounting for
    /// the secure envelope when the request arrived secured. See
    /// [`ServiceCtx::effective_apdu_budget`](crate::service::ServiceCtx::effective_apdu_budget).
    fn effective_apdu_budget(&self, access_ctx: AccessContext) -> usize {
        use zweidraehte_proto::access::SecurityMode;
        zweidraehte_proto::config::max_outgoing_msg_len(
            self.state.max_apdu_length(),
            access_ctx.security != SecurityMode::Plain,
        )
    }

    /// Access the unified device state.
    pub(crate) fn state(&self) -> &'a D::State {
        self.state
    }

    /// Access the layer context.
    pub(crate) fn lctx(&self) -> &'a LayerContext<D> {
        self.lctx
    }
}

// ============================================================================
// Layer Implementation (Main Event Loop)
// ============================================================================

// ============================================================================
// Layer Trait Implementation
// ============================================================================

impl<D: StackDefinition> Layer<D> for ApplicationLayer<'_, D> {
    const HANDLES: &'static [ServiceType] = &[
        // Indications from TL (upward — group communication)
        ServiceType::T_GroupData_Ind,
        // Indications from TL (upward — broadcast / system broadcast)
        ServiceType::T_Broadcast_Ind,
        ServiceType::T_SystemBroadcast_Ind,
        // Indications from TL (upward — connection-oriented and unacknowledged)
        ServiceType::T_Data_Ind,
        ServiceType::T_DataUnack_Ind,
        // Transport session lifecycle indications. The TL owns the session
        // state; AL consumes the primitives so they do not fall through the
        // generic router as unhandled traffic.
        ServiceType::T_Connect_Ind,
        ServiceType::T_Disconnect_Ind,
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
            // Session lifecycle — TL owns all connection state
            // =================================================================
            ServiceType::T_Connect_Ind | ServiceType::T_Disconnect_Ind => {
                debug!("AL observed transport session event: {:?}", msg.service_type());
            }

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
                if check_service_access(apci, &access_ctx) == AccessDecision::Denied {
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
                        let ctx = AlCtx::new(
                            ServiceCtx::new(self.state, self.lctx, access_ctx),
                            self.interface_objects,
                            self.memory_map,
                        );
                        if !self.extensions.try_handle_apci(apci, &msg, &ctx) {
                            warn!("Unhandled APCI code: {:?}", msg.get_apci_code());
                        }
                    }
                }
            }
        }
    }

    fn next_deadline(&self) -> Option<embassy_time::Instant> {
        match (self.group_data.next_deadline(), self.extensions.next_deadline()) {
            (Some(group_data), Some(extensions)) => Some(group_data.min(extensions)),
            (group_data, extensions) => group_data.or(extensions),
        }
    }

    fn poll(&mut self) {
        self.group_data.poll();

        // Deferred extension work has no request behind it, so it runs
        // with the default access context, like every lifecycle tick.
        let ctx = AlCtx::new(
            ServiceCtx::new(self.state, self.lctx, AccessContext::default()),
            self.interface_objects,
            self.memory_map,
        );
        self.extensions.poll(&ctx);
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
        use zweidraehte_proto::messages::apdu::property::{PropertyDescriptionRead, PropertyDescriptionResponse};

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

        // The description is readable by whoever may read *or* write the
        // value, or call it as a function (AN193 §2.2.4.4): the Tool sees
        // the write-only PID_TOOL_KEY's description. Anyone else gets the
        // error response with its descriptor fields zeroed (AN193 §2.2.1),
        // exactly as the extended service answers.
        let response = match response {
            Ok(desc)
                if !self.interface_objects.property_description_visible(req.object_idx, desc.prop_id, &access_ctx) =>
            {
                Err(PropertyError::AccessDenied)
            }
            response => response,
        };

        let apci = ApciCode::PropertyDescriptionResponse;
        let len = PropertyDescriptionResponse::MSG_LEN;
        match response {
            Ok(desc) => {
                debug!("AL sending PropertyDescriptionResponse: {:?}", desc);
                // The descriptor encodes itself directly after the APCI.
                self.lctx.respond(ind, apci, len, |data| {
                    let _len = desc.encode(&mut data[offsets::MSG_APCI + 2..]);
                });
            }
            Err(e) => {
                warn!("AL PropertyDescriptionRead failed: {:?}", e);
                self.lctx.respond(ind, apci, len, |data| {
                    PropertyDescriptionResponse::write_error(data, req.object_idx as u8, req.prop_id, req.prop_idx);
                });
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
        use zweidraehte_proto::messages::apdu::property::{PropertyValueHeader, PropertyValueResponse};

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

        // Local scratch buffer for property data — upper bound on what a
        // single read will ever produce. Not a protocol cap: the actual
        // response length is gated by the APDU budget below so the
        // response always fits on the wire.
        const DATA_SCRATCH: usize = 64;
        let mut data_buf = [0u8; DATA_SCRATCH];

        let budget = self.effective_apdu_budget(access_ctx);
        let payload_cap = budget.saturating_sub(PropertyValueResponse::msg_len(0)).min(DATA_SCRATCH);

        let req = FullPropertyReadRequest {
            object_idx: hdr.object_idx,
            pid: hdr.prop_id,
            start_idx: hdr.start_idx,
            count: hdr.count,
            ctx: access_ctx,
        };
        let result = self.interface_objects.property_value_read(&req, &mut data_buf[..payload_cap]);

        match result {
            Ok(data_len) if PropertyValueResponse::msg_len(data_len) <= budget => {
                // Per KNX spec: if start_idx=0 (element count query), response count=1
                let response_count = if hdr.start_idx == 0 { 1 } else { hdr.count };

                debug!("AL sending PropertyValueResponse: {} bytes", data_len);
                let response_len = PropertyValueResponse::msg_len(data_len);
                self.lctx.respond(ind, ApciCode::PropertyValueResponse, response_len, |buf| {
                    PropertyValueResponse::write(
                        buf,
                        hdr.object_idx as u8,
                        hdr.prop_id,
                        response_count,
                        hdr.start_idx,
                        &data_buf[..data_len],
                    );
                });
            }
            // Data too big for the effective APDU budget — spec
            // 03/03/07 §3.3 return codes: respond with an error
            // response. The write_error helper produces a count=0
            // response, signalling to the MaC that the read failed.
            // (Property service responses have no dedicated 0xF4 field
            // in this encoding path — count=0 is the error signal.)
            Ok(_) | Err(_) => {
                if let Err(e) = &result {
                    warn!("AL PropertyValueRead failed: {:?}", e);
                } else {
                    warn!("AL PropertyValueRead result too large for APDU budget ({})", budget);
                }

                self.send_property_value_error(ind, &hdr);
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
        use zweidraehte_proto::messages::apdu::property::{PropertyValueHeader, PropertyValueResponse};

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

        // Validate data length against the property descriptor when one
        // exists. Properties served by augments may have no entry in the
        // descriptor table, so we skip validation rather than blocking them.
        //
        // This mirrors the per-element-size check in the extended write path
        // (property_ext.rs) but uses the standard error response format
        // (count=0) instead of an ext return code.
        if let Ok(desc) = self.interface_objects.property_description_read(hdr.object_idx, hdr.prop_id, 0) {
            // Only validate when we know the fixed element size (returns 0 for
            // variable-size or unknown PDTs) and the write targets elements
            // rather than the count field (start_idx > 0).
            use crate::layers::application::services::property_ext::pdt_element_size;
            let elem_size = pdt_element_size(desc.pdt);
            if elem_size > 0 && hdr.count > 0 && hdr.start_idx > 0 && data.len() != hdr.count as usize * elem_size {
                warn!(
                    "AL PropertyValueWrite: data size {} != count {} × elem_size {} (pid={}, obj={})",
                    data.len(),
                    hdr.count,
                    elem_size,
                    hdr.prop_id,
                    hdr.object_idx
                );
                self.send_property_value_error(ind, &hdr);
                return;
            }
        }

        let req = FullPropertyWriteRequest {
            object_idx: hdr.object_idx,
            pid: hdr.prop_id,
            count: hdr.count,
            start_idx: hdr.start_idx,
            data,
            ctx: access_ctx,
        };
        let result = self.interface_objects.property_value_write(&req);

        // WriteResponse::Echo means echo back the original data;
        // WriteResponse::Data contains transformed data (e.g., LOAD_STATE_CONTROL)
        let response_data: &[u8] = match &result {
            Ok(write_response) => write_response.as_slice().unwrap_or(data),
            Err(e) => {
                warn!("AL PropertyValueWrite failed: {:?}", e);
                self.send_property_value_error(ind, &hdr);
                return;
            }
        };

        // A verify echo that does not fit the wire is answered like a
        // failed write (count=0) — same convention as the read path.
        let response_len = PropertyValueResponse::msg_len(response_data.len());
        let budget = self.effective_apdu_budget(access_ctx);
        if response_len > budget {
            warn!("AL PropertyValueWrite verify response too large for APDU budget ({} > {})", response_len, budget);
            self.send_property_value_error(ind, &hdr);
            return;
        }

        debug!("AL sending PropertyValueResponse (write success): {} bytes", response_data.len());
        self.lctx.respond(ind, ApciCode::PropertyValueResponse, response_len, |buf| {
            PropertyValueResponse::write(
                buf,
                hdr.object_idx as u8,
                hdr.prop_id,
                hdr.count,
                hdr.start_idx,
                response_data,
            );
        });
    }

    /// Answer a property value read or write with the error response:
    /// count 0, no data (03/03/07 §3.4.7).
    fn send_property_value_error(
        &self,
        ind: &KnxMessageBuffer<Buffer<'static>>,
        hdr: &zweidraehte_proto::messages::apdu::property::PropertyValueHeader,
    ) {
        use zweidraehte_proto::messages::apdu::property::PropertyValueResponse;

        self.lctx.respond(ind, ApciCode::PropertyValueResponse, PropertyValueResponse::ERROR_MSG_LEN, |buf| {
            PropertyValueResponse::write_error(buf, hdr.object_idx as u8, hdr.prop_id, hdr.start_idx);
        });
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
        use zweidraehte_proto::messages::apdu::device::{DeviceDescriptorRead, DeviceDescriptorResponse};

        let Some(req) = DeviceDescriptorRead::parse(ind.buf()) else {
            error!("DeviceDescriptorRead message too short: {}", ind.len());
            return;
        };

        debug!("AL DeviceDescriptorRead: descriptor_type={}", req.descriptor_type);

        if !matches!(ind.service_type(), ServiceType::T_Data_Ind | ServiceType::T_DataUnack_Ind) {
            warn!("AL DeviceDescriptorRead unexpected service type: {:?}", ind.service_type());
            return;
        }

        // Access Policy 3FF/0CC at data level, for every descriptor type
        // (AN193 §2.2.4.5, 03/03/07 §3.4.2.1). A caller without the
        // permission gets DD0 masked as FFFFh and any other type the
        // 3Fh error, which is also the answer for an unsupported type.
        use zweidraehte_proto::access::AccessPolicy;
        let access_ctx = self.resolve_access(ind);
        let permitted = AccessPolicy::READ_OPEN_WRITE_TOOL.can_read(&access_ctx, self.state.security_mode_enabled());

        let apci = ApciCode::DeviceDescriptorResponse;
        match (req.descriptor_type, permitted, D::DEVICE_DESCRIPTOR_TYPE2) {
            (0, _, _) => {
                let mask_version = if permitted { D::DEVICE.mask_version_bytes() } else { [0xFF, 0xFF] };
                debug!("AL sending DeviceDescriptorResponse: mask_version={}", D::DEVICE.mask_version);
                self.lctx.respond(ind, apci, DeviceDescriptorResponse::TYPE0_MSG_LEN, |buf| {
                    DeviceDescriptorResponse::write_type0(buf, &mask_version);
                });
            }
            (2, true, Some(dd2)) => {
                debug!("AL sending DeviceDescriptorResponse (DD2): {:?}", zweidraehte_util::fmt::Bytes(dd2));
                self.lctx.respond(ind, apci, DeviceDescriptorResponse::TYPE2_MSG_LEN, |buf| {
                    DeviceDescriptorResponse::write_type2(buf, dd2);
                });
            }
            _ => {
                debug!("AL sending DeviceDescriptorResponse (error): descriptor_type=0x3F");
                self.lctx.respond(
                    ind,
                    apci,
                    DeviceDescriptorResponse::ERROR_MSG_LEN,
                    DeviceDescriptorResponse::write_error,
                );
            }
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
    fn handle_individual_address_read(&mut self, ind: &KnxMessageBuffer<Buffer<'static>>) {
        use zweidraehte_proto::messages::apdu::device;

        if ind.service_type() != ServiceType::T_Broadcast_Ind {
            warn!("AL IndividualAddressRead with unexpected service type: {:?}", ind.service_type());
            return;
        }

        debug!("AL IndividualAddressRead received");

        if !self.interface_objects.is_programming_mode() {
            trace!("AL IndividualAddressRead ignored (not in programming mode)");
            return;
        }

        // IndividualAddressResponse: a broadcast, the address conveyed in
        // the source field.
        debug!("AL sending IndividualAddressResponse");
        self.lctx.respond_to(
            ind,
            ResponseTarget::Broadcast(Some(ServiceType::T_Broadcast_Req)),
            ApciCode::IndividualAddressResponse,
            device::APCI_ONLY_MSG_LEN,
            |_| {},
        );
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
        use zweidraehte_proto::address::IndividualAddress;
        use zweidraehte_proto::messages::apdu::device::IndividualAddressWrite;

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
        use zweidraehte_proto::access::AccessPolicy;
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

        use zweidraehte_proto::messages::apdu::restart::RestartParsed;

        let Some(parsed) = RestartParsed::parse(ind.buf()) else {
            warn!("AL Restart message too short: {}", ind.len());
            return;
        };

        // Only a Master Reset carries an erase code and is answered. Its
        // reserved codes (00h, 09h-FFh; 03/05/02 §3.7.1.2.3 Table 4) parse
        // as `EraseCode::Other` and are refused as unsupported below.
        let restart = parsed.restart_type();
        let channel = parsed.channel;
        let needs_response = matches!(restart, RestartType::MasterReset(_));

        let restart_ctx = self.resolve_access(ind);
        debug!("AL Restart: {:?}, channel={}, access_ctx={:?}", restart, channel, restart_ctx);

        // Unimplemented and reserved codes are unsupported, and so are
        // ResetIA and ResetAP on every Data Secure profile (06 Profiles
        // §9.1.2.5.1). This precedes the policy check: AN193 §2.2.4.3
        // gives ResetIA and ResetAP a policy, and applying it would answer
        // `AccessDenied` for a code this device is not allowed to have.
        if let RestartType::MasterReset(erase_code) = restart
            && !D::EraseCodePolicy::supports(erase_code)
        {
            warn!("AL Restart: unsupported erase code {:?}", erase_code);
            self.send_restart_response(ind, RestartError::UnsupportedEraseCode, 0);
            return;
        }

        if channel != 0 {
            warn!("AL Restart: invalid channel number {}", channel);
            if needs_response {
                self.send_restart_response(ind, RestartError::InvalidChannel, 0);
            }
            return;
        }

        // Per-request Access Policy (AN193 v04 §2.2.4.3): ResetIA is refused
        // to everyone while Security Mode is on (3FF/000), the restarts that
        // erase nothing are 3FF/0CC, the other master resets 3FF/00C.
        let security_on = self.state.security_mode_enabled();
        let policy = restart_access_policy(restart);
        if !policy.can_write(&restart_ctx, security_on) {
            warn!("AL Restart: access denied by security policy ({:?}, sec_on={})", restart_ctx, security_on);
            if needs_response {
                self.send_restart_response(ind, RestartError::AccessDenied, 0);
            }
            return;
        }

        // Legacy access level check (non-secure fallback).
        let required_level = restart_required_level(restart).for_levels(self.state.max_access_levels());

        if !restart_ctx.has_level(required_level) {
            warn!("AL Restart: access denied ({:?}, required={})", restart_ctx, required_level);
            if needs_response {
                self.send_restart_response(ind, RestartError::AccessDenied, 0);
            }
            return;
        }

        let request = RestartRequest { restart, channel, access_ctx: restart_ctx, needs_response };
        debug!("AL Restart: sending request to user code");
        if !self.lctx.try_send_restart_request(request) {
            // The restart channel holds one entry, so this means a restart is
            // already queued and undrained. We still answer NoError below:
            // the peer asked for a restart and one *is* pending, and changing
            // the wire response here would need spec backing.
            warn!("AL Restart: restart channel full, request dropped (one already pending)");
        }

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
        use zweidraehte_proto::messages::apdu::restart::RestartResponse;

        debug!("AL sending Restart_Response: error={}, process_time={}ms", error, process_time_100ms as u32 * 100);
        self.lctx.respond(ind, ApciCode::Restart, RestartResponse::MSG_LEN, |buf| {
            RestartResponse::write(buf, error.into(), process_time_100ms);
        });
    }
}
