//! Diagnostics extension for KNX diagnostic mode and GO diagnostics.
//!
//! Provides two function properties:
//! - PID_OPERATION_MODE (PID 52) on the Application Program Object
//!   (IOT 0x0003) — switches the device between Normal and Diagnostic Mode.
//! - PID_GO_DIAGNOSTICS (PID 66) on the Group Object Table Object
//!   (IOT 0x0009) — diagnostic control of individual group objects.
//!
//! In Diagnostic Mode:
//! - The application has no access to Group Object values or runtime flags
//! - Incoming Group Object updates are filtered by source address
//! - The mode auto-returns to Normal after a configurable timeout
//!
//! # Architecture
//!
//! - [`DiagnosticsContext`] — trait for querying diagnostic mode state
//! - [`HasDiagnosticsContext`] — trait for device states that provide diagnostics
//! - [`OperationModeState`] — concrete state implementation
//! - [`DiagnosticsAugment`] — interface object augment for PID 52 and PID 66

use core::cell::Cell;

use embassy_time::Instant;

use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{InterfaceObjectType, PDT_Function, PropertyDataDefinition};
use zweidraehte_proto::messages::knx::Priority;
use crate::layers::application::capabilities::{GroupValueAddressedSender, GroupValueEncoding};
use crate::objects::comm::{ComObjects, HasCommObjects};
use crate::objects::interface::{
    AugmentContext, FunctionPropertyRequest, FunctionPropertyResult, InterfaceObjectAugment, PropertyAccess,
    PropertyBuf, PropertyDescriptionResponse, PropertyDescriptor, PropertyError, PropertyLookup, pid,
};
use crate::{StackDefinition, StackState};
use crate::objects::tables::{
    AddressTable, AssociationTable, CommunicationObjectTable, HasAddressTable, HasApplication, HasAssociationTable,
    HasCommunicationObjectTable, HasRunStateMachine,
};

// ============================================================================
// Traits
// ============================================================================

/// Context trait for querying diagnostic mode state.
///
/// Implement on `()` with no-op defaults so devices without diagnostics
/// support can use `()` as their diagnostics context.
pub trait DiagnosticsContext {
    /// Whether the device is currently in diagnostic mode.
    fn is_diagnostic_mode(&self) -> bool {
        false
    }

    /// Current operation mode byte (0x00=normal, 0x01=diagnostic).
    fn operation_mode(&self) -> u8 {
        0x00
    }

    /// Remaining time in the current operation mode (0xFF = no timeout).
    fn time_left(&self) -> u8 {
        0xFF
    }

    /// Source address filter for incoming GO updates in diagnostic mode.
    /// `None` means no filter (all sources blocked in diagnostic mode).
    fn diagnostic_source_filter(&self) -> Option<u16> {
        None
    }

    /// Set the source address filter for diagnostic mode.
    fn set_diagnostic_source_filter(&self, _ia: Option<u16>) {}
}

impl DiagnosticsContext for () {}

/// Trait for device states that provide a diagnostics context.
///
/// The application layer and stack handle use this to check diagnostic
/// mode state without coupling to the concrete state type.
pub trait HasDiagnosticsContext {
    /// The concrete diagnostics context type.
    type Diagnostics: DiagnosticsContext;

    /// Get a reference to the diagnostics context.
    fn diagnostics(&self) -> &Self::Diagnostics;
}

// ============================================================================
// State
// ============================================================================

/// Concrete diagnostic mode state.
///
/// Holds the current operation mode, timeout deadline, and source filter.
/// The timeout is tracked using `embassy_time::Instant` — when the
/// deadline passes, the mode auto-returns to Normal.
pub struct OperationModeState {
    mode: Cell<u8>,
    deadline: Cell<Option<Instant>>,
    source_filter: Cell<Option<u16>>,
    /// Timeout in seconds when diagnostic mode is activated.
    timeout_secs: u8,
}

impl OperationModeState {
    /// Create a new operation mode state with the given diagnostic timeout.
    ///
    /// `timeout_secs` is the number of seconds diagnostic mode stays active
    /// before auto-returning to normal. The spec requires at least 30s.
    pub fn new(timeout_secs: u8) -> Self {
        Self { mode: Cell::new(0x00), deadline: Cell::new(None), source_filter: Cell::new(None), timeout_secs }
    }

    /// Set the operation mode. Returns `true` if the mode was changed.
    ///
    /// When switching to diagnostic mode, sets the timeout deadline.
    /// When switching to normal mode, clears the deadline and source filter.
    pub fn set_mode(&self, mode: u8) {
        self.mode.set(mode);
        if mode == 0x01 {
            // Diagnostic mode: start timeout countdown.
            let deadline = Instant::now() + embassy_time::Duration::from_secs(self.timeout_secs as u64);
            self.deadline.set(Some(deadline));
        } else {
            // Normal mode: clear deadline and source filter.
            self.deadline.set(None);
            self.source_filter.set(None);
        }
    }

    /// Check if the diagnostic timeout has expired and auto-return to normal
    /// if so. Call this before reading the current state.
    fn check_timeout(&self) {
        if self.mode.get() == 0x01 {
            if let Some(deadline) = self.deadline.get() {
                if Instant::now() >= deadline {
                    self.mode.set(0x00);
                    self.deadline.set(None);
                    self.source_filter.set(None);
                }
            }
        }
    }

    /// Compute the time_left value for the response.
    fn compute_time_left(&self) -> u8 {
        if self.mode.get() == 0x00 {
            return 0xFF; // Normal mode: no timeout.
        }
        match self.deadline.get() {
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    0
                } else {
                    let remaining = (deadline - now).as_secs();
                    // Clamp to 0-254 range (0xFF is reserved for "no timeout").
                    remaining.min(254) as u8
                }
            }
            None => 0xFF,
        }
    }
}

impl DiagnosticsContext for OperationModeState {
    fn is_diagnostic_mode(&self) -> bool {
        self.check_timeout();
        self.mode.get() == 0x01
    }

    fn operation_mode(&self) -> u8 {
        self.check_timeout();
        self.mode.get()
    }

    fn time_left(&self) -> u8 {
        self.check_timeout();
        self.compute_time_left()
    }

    fn diagnostic_source_filter(&self) -> Option<u16> {
        if self.is_diagnostic_mode() { self.source_filter.get() } else { None }
    }

    fn set_diagnostic_source_filter(&self, ia: Option<u16>) {
        self.source_filter.set(ia);
    }
}

// ============================================================================
// Augment
// ============================================================================

/// Property descriptor for PID_OPERATION_MODE.
///
/// Access policy 15F/00C means: plain read always allowed (15F),
/// write requires A+C in security mode (00C). Access level 3/3.
const OPERATION_MODE_DESCRIPTOR: PropertyDescriptor = PropertyDescriptor::with_policy(
    pid::OPERATION_MODE,
    PDT_Function::ID,
    1,
    PropertyAccess::ReadWrite,
    3,
    3,
    AccessPolicy::new(0x15F, 0x00C),
);

/// Interface object augment for diagnostics: PID_OPERATION_MODE (PID 52)
/// on the Application Program Object and PID_GO_DIAGNOSTICS (PID 66) on
// ============================================================================
// GO Diagnostics Response Helpers
// ============================================================================

/// Build a GO diagnostics success response with the standard envelope.
///
/// Format: `[service_id, go_idx_hi, go_idx_lo, status, ...value]`
/// with return code 0x21 (success with data).
fn go_diag_success(service_id: u8, go_idx: u16, status: u8, value: &[u8]) -> FunctionPropertyResult {
    let mut resp = [0u8; 64];
    resp[0] = service_id;
    resp[1..3].copy_from_slice(&go_idx.to_be_bytes());
    resp[3] = status;
    let data_len = value.len().min(60);
    resp[4..4 + data_len].copy_from_slice(&value[..data_len]);
    FunctionPropertyResult { return_code: 0x21, data: PropertyBuf::new(&resp[..4 + data_len]) }
}

/// the Group Object Table Object.
///
/// This augment does NOT add additional objects — it extends existing
/// objects with function properties for diagnostic mode and GO control.
///
/// Telegram emission is done through the shared [`AugmentContext`]
/// (outbox + buffer manager accessors) or, for the `transmit`
/// diagnostic that maps onto a normal CO send, through the
/// [`GroupValueSender`] capability. The augment itself holds only
/// its own operation-mode state.
pub struct DiagnosticsAugment<'a> {
    state: &'a OperationModeState,
}

impl<'a> DiagnosticsAugment<'a> {
    pub fn new(state: &'a OperationModeState) -> Self {
        Self { state }
    }

    // ================================================================
    // FunctionProperty handlers
    // ================================================================

    /// Handle FunctionPropertyExtCommand for PID_OPERATION_MODE.
    ///
    /// WriteServiceID 0x00: Write the Operation Mode.
    /// Service data: [reserved, service_id, operation_mode]
    fn handle_command<S: StackState + HasApplication>(
        &self,
        stack_state: &S,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult {
        // Response format: [return_code, service_id, operation_mode, time_left]
        // On error: [0xA0, service_id_echo, current_mode, current_time_left]

        let current_mode = self.state.operation_mode();
        let current_time_left = self.state.time_left();

        // Validate data length: exactly 3 bytes (reserved + service_id + mode).
        if req.service_data.len() != 3 {
            let svc_id = if req.service_data.len() >= 2 { req.service_data[1] } else { 0x00 };
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: PropertyBuf::new(&[svc_id, current_mode, current_time_left]),
            };
        }

        let reserved = req.service_data[0];
        let service_id = req.service_data[1];
        let requested_mode = req.service_data[2];

        // Validate reserved octet.
        if reserved != 0x00 {
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: PropertyBuf::new(&[service_id, current_mode, current_time_left]),
            };
        }

        // Validate service ID.
        if service_id != 0x00 {
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: PropertyBuf::new(&[service_id, current_mode, current_time_left]),
            };
        }

        // Validate operation mode value.
        if requested_mode > 0x01 {
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: PropertyBuf::new(&[service_id, current_mode, current_time_left]),
            };
        }

        // Check that the application is running.
        if !stack_state.app().borrow().is_running() {
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: PropertyBuf::new(&[service_id, current_mode, current_time_left]),
            };
        }

        // Set the requested operation mode.
        self.state.set_mode(requested_mode);

        let new_mode = self.state.operation_mode();
        let new_time_left = self.state.time_left();

        FunctionPropertyResult {
            return_code: 0x20, // E_OM_CURRENT_OPERATION_MODE
            data: PropertyBuf::new(&[service_id, new_mode, new_time_left]),
        }
    }

    /// Handle FunctionPropertyExtStateRead for PID_OPERATION_MODE.
    ///
    /// ReadServiceID 0x00: Read the Operation Mode.
    /// Service data: [reserved, service_id]
    fn handle_state_read<S: StackState + HasApplication>(
        &self,
        _stack_state: &S,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult {
        let current_mode = self.state.operation_mode();
        let current_time_left = self.state.time_left();

        // Validate data length: exactly 2 bytes (reserved + service_id).
        if req.service_data.len() != 2 {
            let svc_id = if !req.service_data.is_empty() { req.service_data[0] } else { 0x00 };
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: PropertyBuf::new(&[svc_id, current_mode, current_time_left]),
            };
        }

        let reserved = req.service_data[0];
        let service_id = req.service_data[1];

        // Validate reserved octet.
        if reserved != 0x00 {
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: PropertyBuf::new(&[service_id, current_mode, current_time_left]),
            };
        }

        // Validate service ID.
        if service_id != 0x00 {
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: PropertyBuf::new(&[service_id, current_mode, current_time_left]),
            };
        }

        // State reads always succeed — even when the app is halted.
        // Per spec §4.4.1 and conformance test 6.1.11: reads return the
        // current state regardless of the Run State Machine.
        FunctionPropertyResult {
            return_code: 0x20, // E_OM_CURRENT_OPERATION_MODE
            data: PropertyBuf::new(&[service_id, current_mode, current_time_left]),
        }
    }

    // ================================================================
    // PID_GO_DIAGNOSTICS handlers
    // ================================================================

    /// Handle FunctionPropertyExtCommand for PID_GO_DIAGNOSTICS.
    fn handle_go_diag_command<D: crate::StackDefinition>(
        &self,
        ctx: &AugmentContext<'_, D>,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult
    where
        D::State: StackState
            + HasCommunicationObjectTable
            + HasCommObjects
            + HasAddressTable
            + HasAssociationTable,
    {
        // Minimum: [reserved, service_id]
        if req.service_data.len() < 2 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }

        let reserved = req.service_data[0];
        let service_id = req.service_data[1];

        // Validate reserved octet (bits 5-7 of first byte encode the write
        // service ID, bits 0-2 encode the read service ID; for a Command,
        // the write service ID is in bits 5-7 and must be non-zero or zero
        // depending on the service). Actually, looking at the XML more
        // carefully: byte 0 is [reserved:3 | writeServiceID:5] for commands.
        // Wait — the XML shows: `00 05 00 07 AA` where 00=reserved, 05=serviceID.
        // So byte 0 = reserved (must be 0x00), byte 1 = service_id.
        if reserved != 0x00 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }

        match service_id {
            0x00 => self.handle_go_diag_write_local(ctx.state, req),
            0x01 => self.handle_go_diag_direct_write(ctx, req),
            0x02 => self.handle_go_diag_transmit(ctx, req),
            0x03 => self.handle_go_diag_direct_read(ctx, req),
            0x04 => self.handle_go_diag_set_filter(req),
            _ => {
                // Invalid WriteServiceID → F2 (E_COMMAND_INVALID).
                FunctionPropertyResult { return_code: 0xF2, data: PropertyBuf::new(&[service_id]) }
            }
        }
    }

    /// Handle FunctionPropertyExtStateRead for PID_GO_DIAGNOSTICS.
    fn handle_go_diag_state_read<S: StackState + HasCommunicationObjectTable + HasCommObjects + HasAddressTable>(
        &self,
        state: &S,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult {
        if req.service_data.len() < 2 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }

        let reserved = req.service_data[0];
        let service_id = req.service_data[1];

        if reserved != 0x00 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }

        match service_id {
            0x00 => self.handle_go_diag_read_config(state, req),
            0x01 => self.handle_go_diag_read_value(state, req),
            _ => {
                // Invalid ReadServiceID → F2 (E_COMMAND_INVALID).
                FunctionPropertyResult { return_code: 0xF2, data: PropertyBuf::new(&[service_id]) }
            }
        }
    }

    // ================================================================
    // WriteServiceID 0x00: Set Local GO Value
    // ================================================================

    /// Set a group object's value locally without bus transmission.
    ///
    /// Request: [reserved, 0x00, GO_idx_hi, GO_idx_lo, value...]
    /// Success: rc=0x21, [service_id, GO_idx_hi, GO_idx_lo, status, value...]
    fn handle_go_diag_write_local<S: StackState + HasCommunicationObjectTable + HasCommObjects>(
        &self,
        state: &S,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult {
        let data = req.service_data;
        // Need at least: reserved(1) + serviceID(1) + GO_idx(2) + value(1)
        if data.len() < 5 {
            return FunctionPropertyResult {
                return_code: 0xA3, // Size mismatch — not enough data.
                data: PropertyBuf::new(&[0x00]),
            };
        }

        let go_idx = u16::from_be_bytes([data[2], data[3]]);
        let value_data = &data[4..];

        let cot = state.cot().borrow();

        // Validate GO exists.
        let Some(entry) = cot.get_object(go_idx) else {
            return FunctionPropertyResult {
                return_code: 0xA1, // E_GD_GO_VOID
                data: PropertyBuf::new(&[0x00]),
            };
        };

        // Check C (communication enable) and W (write enable) flags.
        if !entry.flags.communication_enable() || !entry.flags.write_enable() {
            return FunctionPropertyResult {
                return_code: 0xA2, // E_GD_CONFIG_FLAGS
                data: PropertyBuf::new(&[0x00]),
            };
        }

        // Validate data size matches GO type.
        let (expected_size, _short) = entry.object_type.size_in_bytes();
        if value_data.len() != expected_size {
            return FunctionPropertyResult {
                return_code: 0xA3, // E_GD_GO_SIZE_MISMATCH
                data: PropertyBuf::new(&[0x00]),
            };
        }

        drop(cot); // Release borrow before accessing comm objects.

        // Write the value to the comm object.
        {
            let mut co = state.comm_objects().borrow_mut();
            let dest = co.value_mut(go_idx);
            dest[..value_data.len()].copy_from_slice(value_data);
        }

        // Build success response with current value and status.
        let co = state.comm_objects().borrow();
        // GO diagnostics status uses only the low nibble of the flags byte
        // (stripping the idle indicator in bit 6).
        let status = co.status(go_idx).to_flags_byte() & 0x0F;
        go_diag_success(0x00, go_idx, status, co.value(go_idx))
    }

    // ================================================================
    // WriteServiceID 0x01: Direct GroupValue_Write
    // ================================================================

    /// Send a GroupValue_Write to a specific group address with given data.
    ///
    /// Request: [reserved, 0x01, flags, GA_hi, GA_lo, value...]
    /// Success: rc=0x00, [service_id]
    ///
    /// On success, builds and pushes a GroupValue_Write telegram to the
    /// outbox before returning the response.
    fn handle_go_diag_direct_write<D: crate::StackDefinition>(
        &self,
        ctx: &AugmentContext<'_, D>,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult
    where
        D::State: StackState + HasCommunicationObjectTable + HasCommObjects + HasAddressTable,
    {
        let data = req.service_data;
        // Need at least: reserved(1) + serviceID(1) + flags(1) + GA(2) + value(1)
        if data.len() < 6 {
            return FunctionPropertyResult { return_code: 0xF2, data: PropertyBuf::new(&[0x01]) };
        }

        let flags = data[2];
        // Validate flags: bits 2-6 must be zero.
        if flags & 0x7C != 0 {
            return FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[0x01]) };
        }

        // Security bits (0-1): 00=no security, 01=auth, 10=invalid, 11=auth+conf
        let sec_bits = flags & 0x03;
        if sec_bits == 0x02 {
            return FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[0x01]) };
        }

        // Validate that the GA exists in the device's address table.
        let ga = zweidraehte_proto::address::GroupAddress([data[3], data[4]]);
        let tsap = ctx.state.adt().borrow().get_tsap(ga);

        let Some(tsap) = tsap else {
            return FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[0x01]) };
        };

        // When security bits are non-zero, check that a group key is
        // available for the GA's TSAP.
        if sec_bits != 0 && !ctx.state.has_group_key(tsap) {
            return FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[0x01]) };
        }

        // ================================================================
        // Send GroupValue_Write via the addressed-sender capability
        //
        // This is an arbitrary GA-addressed write with a caller-supplied
        // value, so the `GroupValueSender` ASAP-based capability doesn't
        // apply. Use `GroupValueAddressedSender` on the provider instead
        // — it knows how to frame and queue the telegram.
        // ================================================================

        let value = &data[5..];
        // Bit 7 of flags: 1 = next full octet, 0 = 6 trailing bits after APCI.
        let full_octet = flags & 0x80 != 0;
        let encoding = if !full_octet && value.len() == 1 && value[0] < 64 {
            GroupValueEncoding::Short
        } else {
            GroupValueEncoding::Full
        };

        debug!(
            "GO diag: stashing GroupValue_Write to TSAP {} (GA 0x{:04X})",
            tsap,
            u16::from_be_bytes([data[3], data[4]])
        );
        ctx.group_value_sender().send_group_write_tsap(tsap, Priority::Low, encoding, value);

        FunctionPropertyResult { return_code: 0x00, data: PropertyBuf::new(&[0x01]) }
    }

    // ================================================================
    // WriteServiceID 0x02: Transmit Current GO Value
    // ================================================================

    /// Transmit the current value of a group object as GroupValue_Write.
    ///
    /// Request: [reserved, 0x02, GO_idx_hi, GO_idx_lo]
    /// Success: rc=0x21, [service_id, GO_idx_hi, GO_idx_lo, status, value...]
    ///
    /// On success, builds and pushes a GroupValue_Write telegram with the
    /// GO's current value and configured priority.
    fn handle_go_diag_transmit<D: crate::StackDefinition>(
        &self,
        ctx: &AugmentContext<'_, D>,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult
    where
        D::State: StackState + HasCommunicationObjectTable + HasCommObjects + HasAssociationTable,
    {
        let data = req.service_data;
        // Need exactly: reserved(1) + serviceID(1) + GO_idx(2)
        if data.len() != 4 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }

        let go_idx = u16::from_be_bytes([data[2], data[3]]);
        let asap = go_idx;

        let cot = ctx.state.cot().borrow();

        // Validate GO exists.
        let Some(entry) = cot.get_object(go_idx) else {
            return FunctionPropertyResult { return_code: 0xA1, data: PropertyBuf::new(&[0x02]) };
        };

        // Check C (communication enable) and T (transmission enable) flags.
        if !entry.flags.communication_enable() || !entry.flags.transmission_enable() {
            return FunctionPropertyResult { return_code: 0xA2, data: PropertyBuf::new(&[0x02]) };
        }

        let (object_size, short_format) = entry.object_type.size_in_bytes();
        let priority = entry.flags.priority();
        drop(cot);

        // Look up the sending TSAP for this ASAP.
        let Some(tsap) = ctx.state.ast().borrow().get_sending_tsap(asap) else {
            debug!("GO diag: no sending TSAP for ASAP {}", asap);
            return FunctionPropertyResult { return_code: 0xA1, data: PropertyBuf::new(&[0x02]) };
        };

        // Build success response with current value (before building the
        // telegram, since we need the borrow for the value data).
        let co = ctx.state.comm_objects().borrow();
        let status = co.status(go_idx).to_flags_byte() & 0x0F;
        let value = co.value(go_idx);
        let resp = go_diag_success(0x02, go_idx, status, value);

        // ================================================================
        // Send GroupValue_Write via the addressed-sender capability
        //
        // This transmits the current CO value bypassing the normal
        // queueing / request-status flow — diagnostic behaviour, not a
        // user-initiated send — so the `GroupValueSender` capability
        // (which honours `ComObjectStatus::WriteRequest` gating) is
        // intentionally not used here. Use `GroupValueAddressedSender`,
        // which frames the telegram against the supplied TSAP.
        // ================================================================

        let encoding = if short_format { GroupValueEncoding::Short } else { GroupValueEncoding::Full };

        debug!("GO diag: stashing GroupValue_Write (transmit) ASAP {} TSAP {}", asap, tsap);
        // The sender only touches `lctx` (buffer manager + outbox), so
        // holding the CO borrow across this call is fine — `value` stays
        // valid for the duration of the send.
        ctx.group_value_sender().send_group_write_tsap(tsap, priority, encoding, &value[..object_size]);
        drop(co);

        resp
    }

    // ================================================================
    // WriteServiceID 0x03: Direct GroupValue_Read
    // ================================================================

    /// Send a GroupValue_Read to a specific group address.
    ///
    /// Request: [reserved, 0x03, flags, GA_hi, GA_lo]
    /// Success: rc=0x00, [service_id]
    ///
    /// On success, builds and pushes a GroupValue_Read telegram to the
    /// outbox before returning the response.
    fn handle_go_diag_direct_read<D: crate::StackDefinition>(
        &self,
        ctx: &AugmentContext<'_, D>,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult
    where
        D::State: StackState + HasCommunicationObjectTable + HasCommObjects + HasAddressTable,
    {
        let data = req.service_data;
        if data.len() != 5 {
            return FunctionPropertyResult { return_code: 0xF2, data: PropertyBuf::new(&[0x03]) };
        }

        let flags = data[2];
        // Validate flags: bits 2-7 must be zero (bit 7 / full-octet flag
        // is not valid for reads since there is no value data to format).
        if flags & 0xFC != 0 {
            return FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[0x03]) };
        }

        let sec_bits = flags & 0x03;
        if sec_bits == 0x02 {
            return FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[0x03]) };
        }

        // Validate that the GA exists in the device's address table.
        let ga = zweidraehte_proto::address::GroupAddress([data[3], data[4]]);
        let tsap = ctx.state.adt().borrow().get_tsap(ga);

        let Some(tsap) = tsap else {
            return FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[0x03]) };
        };

        // When security bits are non-zero, check that a group key is
        // available for the GA's TSAP.
        if sec_bits != 0 && !ctx.state.has_group_key(tsap) {
            return FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[0x03]) };
        }

        // ================================================================
        // Send GroupValue_Read via the addressed-sender capability
        //
        // Like the direct write above, this is GA-addressed rather than
        // ASAP-addressed, so the `GroupValueSender` capability does not
        // apply. Use `GroupValueAddressedSender` for the queued read.
        // ================================================================

        debug!(
            "GO diag: stashing GroupValue_Read to TSAP {} (GA 0x{:04X})",
            tsap,
            u16::from_be_bytes([data[3], data[4]])
        );
        ctx.group_value_sender().send_group_read_tsap(tsap, Priority::Low);

        FunctionPropertyResult { return_code: 0x00, data: PropertyBuf::new(&[0x03]) }
    }

    // ================================================================
    // WriteServiceID 0x04: Set Source Address Filter
    // ================================================================

    /// Set the source address filter for GO updates in diagnostic mode.
    ///
    /// Request: [reserved, 0x04, IA_hi, IA_lo]
    /// Success: rc=0x00, [service_id]
    fn handle_go_diag_set_filter(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        let data = req.service_data;

        // Must be in diagnostic mode.
        if !self.state.is_diagnostic_mode() {
            return FunctionPropertyResult {
                return_code: 0xF3, // E_GD_NO_DIAGNOSTIC_MODE
                data: PropertyBuf::new(&[0x04]),
            };
        }

        // Need exactly: reserved(1) + serviceID(1) + GO_idx(2) + IA(2)
        if data.len() != 6 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }

        let ia = u16::from_be_bytes([data[4], data[5]]);
        self.state.set_diagnostic_source_filter(Some(ia));

        FunctionPropertyResult { return_code: 0x00, data: PropertyBuf::new(&[0x04]) }
    }

    // ================================================================
    // ReadServiceID 0x00: Get GO Config
    // ================================================================

    /// Read the configuration of a group object.
    ///
    /// Request: [reserved, 0x00, GO_idx_hi, GO_idx_lo]
    /// Success: rc=0x20, [service_id, GO_idx_hi, GO_idx_lo, linked, sec_flags,
    ///          config_flags, priority, size_hi, size_lo]
    fn handle_go_diag_read_config<S: StackState + HasCommunicationObjectTable + HasCommObjects>(
        &self,
        state: &S,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult {
        let data = req.service_data;
        if data.len() != 4 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }

        let go_idx = u16::from_be_bytes([data[2], data[3]]);
        let cot = state.cot().borrow();

        let Some(entry) = cot.get_object(go_idx) else {
            return FunctionPropertyResult { return_code: 0xA1, data: PropertyBuf::new(&[0x00]) };
        };

        let (size_bytes, _short) = entry.object_type.size_in_bytes();
        let priority = u8::from(entry.flags.priority());
        let config_flags = entry.flags.to_byte();

        // TODO: linked flag from association table, security flags from
        // security state. For now use placeholders.
        let linked: u8 = 0x00;
        let sec_flags: u8 = 0x00;

        let mut resp = [0u8; 16];
        resp[0] = 0x00; // service_id echo
        resp[1] = data[2]; // GO_idx_hi
        resp[2] = data[3]; // GO_idx_lo
        resp[3] = linked;
        resp[4] = sec_flags;
        resp[5] = config_flags;
        resp[6] = priority;
        resp[7] = (size_bytes >> 8) as u8;
        resp[8] = size_bytes as u8;
        // DPT ID (2 bytes) — not tracked in the CO table, so zero.
        resp[9] = 0x00;
        resp[10] = 0x00;

        FunctionPropertyResult { return_code: 0x20, data: PropertyBuf::new(&resp[..11]) }
    }

    // ================================================================
    // ReadServiceID 0x01: Get Local GO Value
    // ================================================================

    /// Read the current value of a group object.
    ///
    /// Request: [reserved, 0x01, GO_idx_hi, GO_idx_lo]
    /// Success: rc=0x21, [service_id, GO_idx_hi, GO_idx_lo, status, value...]
    fn handle_go_diag_read_value<S: StackState + HasCommunicationObjectTable + HasCommObjects>(
        &self,
        state: &S,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult {
        let data = req.service_data;
        if data.len() != 4 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }

        let go_idx = u16::from_be_bytes([data[2], data[3]]);
        let cot = state.cot().borrow();

        // Validate GO exists.
        if cot.get_object(go_idx).is_none() {
            return FunctionPropertyResult { return_code: 0xA1, data: PropertyBuf::new(&[0x01]) };
        }
        drop(cot);

        let co = state.comm_objects().borrow();
        // GO diagnostics status uses only the low nibble (strip idle indicator).
        let status = co.status(go_idx).to_flags_byte() & 0x0F;
        go_diag_success(0x01, go_idx, status, co.value(go_idx))
    }
}

/// Property descriptor for PID_GO_DIAGNOSTICS.
///
/// Same access policy as PID_OPERATION_MODE: 15F/00C.
const GO_DIAGNOSTICS_DESCRIPTOR: PropertyDescriptor = PropertyDescriptor::with_policy(
    pid::GO_DIAGNOSTICS,
    PDT_Function::ID,
    1,
    PropertyAccess::ReadWrite,
    3,
    3,
    AccessPolicy::new(0x15F, 0x00C),
);

impl<'a, D> InterfaceObjectAugment<D> for DiagnosticsAugment<'a>
where
    D: StackDefinition,
    D::State: StackState
        + HasApplication
        + HasCommunicationObjectTable
        + HasCommObjects
        + HasAddressTable
        + HasAssociationTable,
{
    fn get_property_descriptor(&self, object_type: InterfaceObjectType, prop_id: u8) -> Option<PropertyDescriptor> {
        if object_type == InterfaceObjectType::ApplicationProgram && prop_id == pid::OPERATION_MODE {
            Some(OPERATION_MODE_DESCRIPTOR)
        } else if object_type == InterfaceObjectType::GroupObjectTable && prop_id == pid::GO_DIAGNOSTICS {
            Some(GO_DIAGNOSTICS_DESCRIPTOR)
        } else {
            None
        }
    }

    fn property_description_read(
        &self,
        _ctx: &AugmentContext<'_, D>,
        object_type: InterfaceObjectType,
        object_idx: u16,
        lookup: PropertyLookup,
    ) -> Option<Result<PropertyDescriptionResponse, PropertyError>> {
        if object_type == InterfaceObjectType::ApplicationProgram {
            match lookup {
                PropertyLookup::ByPid(p) if p == pid::OPERATION_MODE => {
                    Some(Ok(PropertyDescriptionResponse::from_descriptor(object_idx, 0, &OPERATION_MODE_DESCRIPTOR)))
                }
                PropertyLookup::ByIndex(0) => {
                    Some(Ok(PropertyDescriptionResponse::from_descriptor(object_idx, 0, &OPERATION_MODE_DESCRIPTOR)))
                }
                _ => None,
            }
        } else if object_type == InterfaceObjectType::GroupObjectTable {
            match lookup {
                PropertyLookup::ByPid(p) if p == pid::GO_DIAGNOSTICS => {
                    Some(Ok(PropertyDescriptionResponse::from_descriptor(object_idx, 0, &GO_DIAGNOSTICS_DESCRIPTOR)))
                }
                PropertyLookup::ByIndex(0) => {
                    Some(Ok(PropertyDescriptionResponse::from_descriptor(object_idx, 0, &GO_DIAGNOSTICS_DESCRIPTOR)))
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn function_property_command(
        &self,
        ctx: &AugmentContext<'_, D>,
        object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        if object_type == InterfaceObjectType::ApplicationProgram && req.prop_id == pid::OPERATION_MODE {
            Some(self.handle_command(ctx.state, req))
        } else if object_type == InterfaceObjectType::GroupObjectTable && req.prop_id == pid::GO_DIAGNOSTICS {
            Some(self.handle_go_diag_command(ctx, req))
        } else {
            None
        }
    }

    fn function_property_state_read(
        &self,
        ctx: &AugmentContext<'_, D>,
        object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        if object_type == InterfaceObjectType::ApplicationProgram && req.prop_id == pid::OPERATION_MODE {
            Some(self.handle_state_read(ctx.state, req))
        } else if object_type == InterfaceObjectType::GroupObjectTable && req.prop_id == pid::GO_DIAGNOSTICS {
            Some(self.handle_go_diag_state_read(ctx.state, req))
        } else {
            None
        }
    }
}
