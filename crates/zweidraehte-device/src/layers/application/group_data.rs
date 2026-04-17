//! Group Data Handling
//!
//! Handles all group communication services (A_GroupValue_*):
//! - Incoming `A_GroupValue_Write.ind` / `A_GroupValue_Response.ind`
//! - Incoming `A_GroupValue_Read.ind` with `A_GroupValue_Response` reply
//! - Outgoing `A_GroupValue_Write.req` / `A_GroupValue_Read.req`
//! - Read-on-init cycle for uninitialized communication objects
//! - TL confirmation tracking for pending group sends

use crate::{
    StackDefinition,
    context::EventPublisherContext,
    context::layer::{HasOutbox, LayerContext},
    layers::application::capabilities::{GroupValueAddressedSender, GroupValueEncoding, GroupValueSender},
    objects::{
        comm::{ComObjectEvent, ComObjectIndex, ComObjectStatus, ComObjects, HasCommObjects},
        tables::{
            AssociationTable, CommunicationObjectTable, HasApplication, HasAssociationTable,
            HasCommunicationObjectTable, HasLoadStateMachine, HasRunStateMachine,
        },
    },
};
use zweidraehte_proto::messages::{
    apdu::group_value::{GroupValueReadRequest, GroupValueWriteRequest},
    buffers::{Buffer, DynBufferManager},
    builder::MessageBuilder,
    knx::*,
};

// ============================================================================
// Types
// ============================================================================

/// Tracks a pending group value send for deferred CO status update.
#[derive(Debug, Clone, Copy)]
pub struct PendingGroupSend {
    /// The ASAP (communication object index) being sent
    pub asap: u16,
    /// Whether this was a read request (vs write)
    pub read: bool,
}

/// State machine for the read-on-init cycle.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ReadOnInitState {
    /// No ROI cycle active — ready to start on next app startup.
    Idle,
    /// Scanning objects, sending reads. The `u16` is the next ASAP to check.
    Scanning(u16),
    /// Scan completed for this app run. Resets to `Idle` when the app stops
    /// (so a restart triggers a fresh scan).
    Done,
}

/// Mutable bookkeeping shared between the AL's built-in group-data
/// handler and the [`GroupDataProvider`] capability used by augments.
///
/// Stored on [`LayerContext`](crate::context::layer::LayerContext) rather
/// than on `GroupDataProvider` itself — providers are transient views
/// built per call. Keeping the state behind interior mutability means a
/// fresh provider always sees the latest `read_on_init` cursor and
/// `pending_group_send` slot.
#[derive(Debug)]
pub struct GroupDataState {
    /// Read-on-init scan cursor. Advanced by the AL poll loop; restarted
    /// when the application transitions from stopped to running.
    pub(crate) read_on_init: core::cell::Cell<ReadOnInitState>,

    /// Pending group value send awaiting TL confirmation. When
    /// populated, the next TL confirmation resolves the matching
    /// communication object status.
    pub(crate) pending_group_send: core::cell::Cell<Option<PendingGroupSend>>,
}

impl GroupDataState {
    pub const fn new() -> Self {
        Self {
            read_on_init: core::cell::Cell::new(ReadOnInitState::Idle),
            pending_group_send: core::cell::Cell::new(None),
        }
    }
}

impl Default for GroupDataState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GroupDataProvider
// ============================================================================

/// Borrowed handle combining device state and runtime context for group data
/// handling.
///
/// All mutable bookkeeping (`read_on_init`, `pending_group_send`) lives on
/// [`LayerContext`] behind [`Cell`](core::cell::Cell), so a provider is a
/// transient two-field view built on demand — callers can construct one per
/// call without losing state between calls. The application layer builds one
/// for its built-in handlers, and interface object augments can build one via
/// [`AugmentContext::group_value_sender`](crate::objects::interface::AugmentContext::group_value_sender)
/// to request group sends through the same logic.
pub struct GroupDataProvider<'a, D: StackDefinition> {
    state: &'a D::State,
    lctx: &'a LayerContext<D>,
}

impl<'a, D: StackDefinition> GroupDataProvider<'a, D> {
    pub fn new(state: &'a D::State, lctx: &'a LayerContext<D>) -> Self {
        Self { state, lctx }
    }

    fn buffer_manager(&self) -> &'a DynBufferManager<'static> {
        &self.lctx.buffer_manager
    }

    // ========================================================================
    // Incoming Group Data
    // ========================================================================

    /// Handle `A_GroupValue_Write.ind` or `A_GroupValue_Response.ind`
    ///
    /// Updates local communication objects with values received from the bus.
    /// Only valid for `T_GroupData_Ind` service type.
    pub fn handle_write_or_response(&self, ind: &mut KnxMessageBuffer<Buffer<'static>>, apci: ApciCode) {
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

        // Check diagnostic source address filter: in diagnostic mode, if a
        // filter is set, only accept group telegrams from the filtered source.
        {
            use crate::bcus::system_b::{DiagnosticsContext, HasDiagnosticsContext};
            let diag = self.state.diagnostics();
            if let Some(filter_ia) = diag.diagnostic_source_filter() {
                let src = u16::from_be_bytes(ind.get_source_addr().0);
                if src != filter_ia {
                    debug!(
                        "AL {:?} ignored: source 0x{:04X} doesn't match diagnostic filter 0x{:04X}",
                        apci, src, filter_ia
                    );
                    return;
                }
            }
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

            let (object_size, msg_offset) = get_object_size_and_offset(&cot_info);

            // Check if incoming message is long enough to carry a comm object value
            if ind.len() == object_size + msg_offset {
                // Set the APCI to all zeros, because we don't need it anymore
                // We do that so that we can just copy out the DPT even if the
                // object type is one of the small ones with <= 6 bit. If the APCI
                // wasn't all zeros in this case, we would copy the two lowermost
                // bits of the "small" APCI code with the comm object value

                ind.set_apci_code(ApciCode::Empty);

                {
                    let mut objs = self.state.comm_objects().borrow_mut();

                    objs.value_mut(asap).copy_from_slice(&ind.buf()[msg_offset..msg_offset + object_size]);
                    objs.set_status(asap, ComObjectStatus::Updated);

                    // Call write hook
                    objs.handle_write(asap, self.state.hook_context());
                }

                // Publish event to the event channel
                if let Some(index) = <<D as StackDefinition>::CO as ComObjects>::Index::from_index(asap) {
                    match apci {
                        ApciCode::GroupValueWrite => {
                            self.lctx.publish_event(index, ComObjectEvent::Updated);
                        }
                        ApciCode::GroupValueResponse => {
                            self.lctx.publish_event(index, ComObjectEvent::ReadResponse);
                        }
                        _ => unreachable!(),
                    }
                }

                debug!(
                    "AL ASAP {} updated via {:?}: {:?}",
                    asap,
                    apci,
                    zweidraehte_util::fmt::Bytes(self.state.comm_objects().borrow().value(asap))
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
    pub fn handle_read(&self, ind: &KnxMessageBuffer<Buffer<'static>>) {
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
            let (object_size, msg_offset) = get_object_size_and_offset(&cot_info);

            // Use the ASAP's sending TSAP for the response destination.
            // For GOs with separate receive/send GAs, this differs from the
            // incoming TSAP (which is the receiving GA's TSAP).
            let response_tsap = self.state.ast().borrow().get_sending_tsap(asap).unwrap_or(tsap);

            info!("AL sending GroupValueResponse for ASAP {} TSAP {} size {}", asap, response_tsap, object_size);

            // Call read hook
            self.state.comm_objects().borrow_mut().prepare_read(asap, self.state.hook_context());

            // Allocate a new message for the response
            let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(object_size + msg_offset) else {
                warn!("AL no buffer for response");
                return;
            };

            let msg = MessageBuilder::new_request(
                msg_buf,
                ServiceType::T_GroupData_Req,
                request_priority,
                DestinationAddress::ConnectionNr(response_tsap),
            )
            .with_application(ApciCode::GroupValueResponse)
            .with_data(|buf| {
                buf[msg_offset..msg_offset + object_size]
                    .copy_from_slice(self.state.comm_objects().borrow().value(asap));
            });

            self.lctx.push_outbox(msg.into_inner());

            trace!(
                "AL sent GroupValueResponse for ASAP {}: {:?}",
                asap,
                zweidraehte_util::fmt::Bytes(self.state.comm_objects().borrow().value(asap))
            );

            // Publish read event to the event channel
            if let Some(index) = <<D as StackDefinition>::CO as ComObjects>::Index::from_index(asap) {
                self.lctx.publish_event(index, ComObjectEvent::Read);
            }
        }
    }

    // ========================================================================
    // Outgoing Group Data
    // ========================================================================

    /// Send `A_GroupValue_Write.req` or `A_GroupValue_Read.req`
    ///
    /// Called when the local application wants to send a group value to the bus.
    /// Returns `true` if the request was processed, `false` if rejected because
    /// the application is not running.
    pub fn send_group_value_request(&self, asap: u16, read: bool) -> bool {
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

        let status = *self.state.comm_objects().borrow().info(asap).status;

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
            self.state.comm_objects().borrow_mut().set_status(asap, new_status);

            debug!("AL comm object {} not enabled for communication (flags=0x{:02x})", asap, cot_info.flags.to_byte());
            return true;
        }

        if !cot_info.flags.transmission_enable() {
            // Transmission disabled - set error status but preserve the request type
            let new_status = if read { ComObjectStatus::ReadRequestError } else { ComObjectStatus::WriteRequestError };
            self.state.comm_objects().borrow_mut().set_status(asap, new_status);

            debug!("AL comm object {} transmission not enabled", asap);
            return true;
        }

        self.state.comm_objects().borrow_mut().set_status(asap, ComObjectStatus::Busy);

        // We only send to the first TSAP per spec.
        // Extract TSAP before entering the block to avoid holding the RefCell
        // borrow across the buffer allocation and transport layer awaits below.
        let sending_tsap = self.state.ast().borrow().get_sending_tsap(asap);
        if let Some(tsap) = sending_tsap {
            trace!("AL found sending TSAP {} for ASAP {}", tsap, asap);

            // The outbound message length depends on the APCI service and,
            // for writes, on whether the object's DPT fits in the short
            // encoding (value packed into the second APCI byte) or needs
            // full APDU bytes. Size helpers live in
            // `apdu::group_value::GroupValue{Read,Write}Request`.
            let (object_size, is_short) = cot_info.object_type.size_in_bytes();
            let msg_len = if read {
                GroupValueReadRequest::MSG_LEN
            } else if is_short {
                GroupValueWriteRequest::SHORT_MSG_LEN
            } else {
                GroupValueWriteRequest::full_msg_len(object_size)
            };

            debug!(
                "AL preparing {} ASAP {} TSAP {} size {} msg_len {}",
                if read { "GroupValueRead" } else { "GroupValueWrite" },
                asap,
                tsap,
                object_size,
                msg_len,
            );

            let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(msg_len) else {
                warn!("AL no buffer for response");
                return true;
            };

            let builder = MessageBuilder::new_request(
                msg_buf,
                ServiceType::T_GroupData_Req,
                cot_info.flags.priority(),
                DestinationAddress::ConnectionNr(tsap),
            );

            let msg = if read {
                builder.with_application(ApciCode::GroupValueRead).build()
            } else if is_short {
                // Short write: first byte of the CO value carries bits 5..0
                // in the second APCI byte. Multi-byte values never take
                // this branch because `size_in_bytes()` returns `(_, false)`
                // for them.
                let value_byte = self.state.comm_objects().borrow().value(asap).first().copied().unwrap_or(0);
                builder
                    .with_application(ApciCode::GroupValueWrite)
                    .with_data(|buf| GroupValueWriteRequest::write_short(buf, value_byte))
            } else {
                // Full write: copy the CO value into the APDU area.
                let co = self.state.comm_objects().borrow();
                let value = co.value(asap);
                builder
                    .with_application(ApciCode::GroupValueWrite)
                    .with_data(|buf| GroupValueWriteRequest::write_full(buf, value))
            };

            // Store pending state so the TL confirmation (arriving later on
            // conf_rx) can update the CO status.
            self.lctx.group_data.pending_group_send.set(Some(PendingGroupSend { asap, read }));

            // Send fire-and-forget to TL — confirmation handled in handle_tl_confirmation
            debug!("AL -> TL: GroupValue {} ASAP {} TSAP {}", if read { "Read" } else { "Write" }, asap, tsap);
            self.lctx.push_outbox(msg.into_inner());
        } else {
            // No sending TSAP found - error
            let new_status = if read { ComObjectStatus::ReadRequestError } else { ComObjectStatus::WriteRequestError };
            self.state.comm_objects().borrow_mut().set_status(asap, new_status);

            error!("AL no sending TSAP or transmission flag not set for ASAP {} - Flags: {:?}", asap, cot_info.flags);
        }

        true
    }

    // ========================================================================
    // TL Confirmation
    // ========================================================================

    /// Handle TL confirmation for a pending group send.
    ///
    /// Returns `true` if a pending group send was found and processed,
    /// `false` if no group send was pending (confirmation is for something else).
    pub fn handle_tl_confirmation(&self, conf: &KnxMessageBuffer<Buffer<'static>>) -> bool {
        let Some(pending) = self.lctx.group_data.pending_group_send.take() else {
            return false;
        };

        debug!("AL TL confirmation for ASAP {}: {:?}", pending.asap, conf.service_type());

        if conf.ctrl_field().c() == Confirm::NoError {
            if pending.read {
                self.state.comm_objects().borrow_mut().set_status(pending.asap, ComObjectStatus::ReadRequest);
            } else {
                self.state.comm_objects().borrow_mut().set_status(pending.asap, ComObjectStatus::IdleOk);
            }
        } else {
            let new_status =
                if pending.read { ComObjectStatus::ReadRequestError } else { ComObjectStatus::WriteRequestError };
            self.state.comm_objects().borrow_mut().set_status(pending.asap, new_status);
        }

        true
    }

    // ========================================================================
    // Read-On-Init
    // ========================================================================

    /// Returns the next deadline for the read-on-init cycle, if active.
    pub fn next_deadline(&self) -> Option<embassy_time::Instant> {
        match self.lctx.group_data.read_on_init.get() {
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
                    && self.state.comm_objects().borrow().status(1) == ComObjectStatus::Uninitialized
                {
                    Some(embassy_time::Instant::now())
                } else {
                    None
                }
            }
            ReadOnInitState::Done => None,
        }
    }

    /// Poll the read-on-init state machine.
    ///
    /// Manages transitions between ROI states and processes one ROI step
    /// per call when scanning.
    pub fn poll(&self) {
        // Reset Done → Idle when the app stops, so the next startup triggers
        // a fresh ROI scan.
        if self.lctx.group_data.read_on_init.get() == ReadOnInitState::Done && !self.state.app().borrow().is_running() {
            self.lctx.group_data.read_on_init.set(ReadOnInitState::Idle);
        }

        // Start ROI scan if the conditions are met (app running, AST loaded,
        // comm objects still uninitialized from DeviceModel reset).
        if self.lctx.group_data.read_on_init.get() == ReadOnInitState::Idle
            && self.state.app().borrow().is_running()
            && self.state.ast().borrow().is_loaded()
            && self.state.comm_objects().borrow().status(1) == ComObjectStatus::Uninitialized
        {
            info!("AL read-on-init: starting cycle (detected uninitialized objects)");
            self.lctx.group_data.read_on_init.set(ReadOnInitState::Scanning(1));
        }

        self.read_on_init_step();
    }

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
    fn read_on_init_step(&self) {
        let ReadOnInitState::Scanning(start) = self.lctx.group_data.read_on_init.get() else {
            return;
        };

        // Cancel if app is no longer running or AST not loaded. Reset to
        // Idle (not Done) so a subsequent app restart triggers a fresh scan.
        if !self.state.app().borrow().is_running() {
            debug!("AL read-on-init: cancelled (app not running)");
            self.lctx.group_data.read_on_init.set(ReadOnInitState::Idle);
            return;
        }
        if !self.state.ast().borrow().is_loaded() {
            debug!("AL read-on-init: cancelled (AST not loaded)");
            self.lctx.group_data.read_on_init.set(ReadOnInitState::Idle);
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
            if self.state.comm_objects().borrow().status(asap) != ComObjectStatus::Uninitialized {
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
            self.state.comm_objects().borrow_mut().set_status(asap, ComObjectStatus::ReadRequest);
            self.send_group_value_request(asap, true);

            // Save cursor for next call and return (one object per step)
            self.lctx.group_data.read_on_init.set(ReadOnInitState::Scanning(cursor));
            return;
        }

        // All objects scanned — cycle complete.
        info!("AL read-on-init: cycle complete ({} objects scanned)", entry_count);
        self.lctx.group_data.read_on_init.set(ReadOnInitState::Done);
    }
}

// ============================================================================
// Capability impl — GroupValueSender
// ============================================================================

impl<D: StackDefinition> GroupValueSender for GroupDataProvider<'_, D> {
    #[inline]
    fn request_group_write(&self, asap: u16) -> bool {
        self.send_group_value_request(asap, false)
    }

    #[inline]
    fn request_group_read(&self, asap: u16) -> bool {
        self.send_group_value_request(asap, true)
    }
}

impl<D: StackDefinition> GroupValueAddressedSender for GroupDataProvider<'_, D> {
    fn send_group_write_tsap(&self, tsap: u16, priority: Priority, encoding: GroupValueEncoding, data: &[u8]) {
        let msg_len = match encoding {
            GroupValueEncoding::Short => GroupValueWriteRequest::SHORT_MSG_LEN,
            GroupValueEncoding::Full => GroupValueWriteRequest::full_msg_len(data.len()),
        };

        let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(msg_len) else {
            warn!("GroupValueAddressedSender: no buffer for GroupValue_Write to TSAP {}", tsap);
            return;
        };

        let msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::T_GroupData_Req,
            priority,
            DestinationAddress::ConnectionNr(tsap),
        )
        .with_application(ApciCode::GroupValueWrite)
        .with_data(|buf| match encoding {
            GroupValueEncoding::Short => {
                // Callers guarantee the value fits in 6 bits. An empty
                // slice would leave the APCI bits untouched, which is
                // the same observable behaviour as the previous inline
                // code — no need to special-case it here.
                if let Some(&v) = data.first() {
                    GroupValueWriteRequest::write_short(buf, v);
                }
            }
            GroupValueEncoding::Full => {
                GroupValueWriteRequest::write_full(buf, data);
            }
        });

        self.lctx.outbox.borrow_mut().push_deferred(msg.into_inner());
    }

    fn send_group_read_tsap(&self, tsap: u16, priority: Priority) {
        let Some(msg_buf) = self.buffer_manager().try_alloc_with_size(GroupValueReadRequest::MSG_LEN) else {
            warn!("GroupValueAddressedSender: no buffer for GroupValue_Read to TSAP {}", tsap);
            return;
        };

        let msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::T_GroupData_Req,
            priority,
            DestinationAddress::ConnectionNr(tsap),
        )
        .with_application(ApciCode::GroupValueRead)
        .build();

        self.lctx.outbox.borrow_mut().push_deferred(msg.into_inner());
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Get the object size and message offset for a communication object.
///
/// Returns `(size_in_bytes, offset)` where offset is either:
/// - `offsets::MSG_APCI + 1` for objects > 6 bits (data starts after APCI byte)
/// - `offsets::MSG_APDU` for objects <= 6 bits (data fits in APCI low bits)
pub(crate) fn get_object_size_and_offset(cot_info: &crate::objects::tables::ComObjectTableEntry) -> (usize, usize) {
    match cot_info.object_type.size_in_bytes() {
        (s, true) => (s, offsets::MSG_APCI + 1),
        (s, false) => (s, offsets::MSG_APDU),
    }
}
