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

use crate::bcus::system_b::HasSecurityMode;
use crate::bcus::system_b::{HasExtensionState, HasSecurityState, HasSeqStorage};
use crate::layers::application::capabilities::{
    GroupValueAddressedSender, GroupValueEncoding, RequestedSecurity, SecureGroupValueAddressedSender,
};
use crate::objects::comm::{ComObjects, HasCommObjects};
use crate::objects::interface::{
    FunctionPropertyRequest, FunctionPropertyResult, PropertyBuf, interface_object_augment, pid,
};
use crate::objects::tables::{
    AddressTable, AssociationTable, CommunicationObjectTable, HasAddressTable, HasApplication, HasAssociationTable,
    HasCommunicationObjectTable, HasRunStateMachine,
};
use crate::service::ServiceCtx;
use crate::{StackDefinition, StackState};
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{InterfaceObjectType, PDT_Function};
use zweidraehte_proto::messages::apdu::go_diagnostics::{
    GoConfigResponse, GoStatusValueResponse, OperationModeResponse,
};
use zweidraehte_proto::messages::knx::Priority;

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
}

impl Default for OperationModeState {
    fn default() -> Self {
        // Normal mode (0x00), no active timeout, no source filter.
        Self { mode: Cell::new(0x00), deadline: Cell::new(None), source_filter: Cell::new(None) }
    }
}

impl OperationModeState {
    /// Diagnostic-mode auto-return timeout. The spec mandates ≥ 30 s
    /// and we don't expose a runtime override.
    pub const DIAGNOSTIC_TIMEOUT_SECS: u8 = 30;

    /// Create a new operation mode state in Normal mode.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the operation mode. Returns `true` if the mode was changed.
    ///
    /// When switching to diagnostic mode, sets the timeout deadline.
    /// When switching to normal mode, clears the deadline and source filter.
    pub fn set_mode(&self, mode: u8) {
        self.mode.set(mode);
        if mode == 0x01 {
            // Diagnostic mode: start timeout countdown.
            let deadline = Instant::now() + embassy_time::Duration::from_secs(Self::DIAGNOSTIC_TIMEOUT_SECS as u64);
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
// Secure-send strategy
// ============================================================================

/// Outcome of a GO-diagnostics secure-send attempt, mapped to the
/// spec-mandated Function Property return codes by the caller.
pub enum SecureSendOutcome {
    /// The secure telegram was built and queued — caller returns `E_SUCCESS` (0x00).
    Queued,
    /// No group key was available for the requested GA (or the device has no
    /// secure capability at all) — caller returns `F8 E_DATA_VOID`, per
    /// 03/05/01 §4.8.1.3.3 Table 37 ("Security is requested for GA for which
    /// there is no GA Key").
    NoKey,
}

/// Strategy for the *secure* half of GO diagnostics (PID 66): the secure
/// `GroupValue_Write`/`Read` sends (WriteServiceID 0x01 / ReadServiceID 0x03)
/// and the per-GO security-flags read used by the config report.
///
/// [`DiagnosticsAugment`] is generic over this strategy so a **non-secure**
/// device carries no security concept at all — it composes the augment with
/// [`SecureGoSendAbsent`], whose methods need no security state and report
/// "no key" / "plain". A secure device composes it with
/// [`SecureGoSendPresent`], whose impl is the only place the Data Secure
/// bounds (`HasSecurityState + HasSeqStorage`) appear.
///
/// The trait is parameterised on `D` precisely so the two impls can differ in
/// their `D`-bounds: `SecureGoSendAbsent` is unconditional, `SecureGoSendPresent`
/// requires the secure extension state. (A method-level `where` clause cannot
/// express that, and the crate does not enable `specialization`, so a blanket
/// no-op plus a bounded real impl is not an option — two distinct concrete
/// implementor types are.)
pub trait SecureGoSender<D: StackDefinition> {
    /// Send a secure `A_GroupValue_Write` to `tsap`, or report `NoKey`.
    fn send_write_secure(
        ctx: &ServiceCtx<'_, D>,
        tsap: u16,
        priority: Priority,
        encoding: GroupValueEncoding,
        value: &[u8],
        security: RequestedSecurity,
    ) -> SecureSendOutcome;

    /// Send a secure `A_GroupValue_Read` to `tsap`, or report `NoKey`.
    fn send_read_secure(
        ctx: &ServiceCtx<'_, D>,
        tsap: u16,
        priority: Priority,
        security: RequestedSecurity,
    ) -> SecureSendOutcome;

    /// Per-GO security flags (`auth`/`conf` bits) for the GO config-read
    /// response. Folds the read-side security touch into the same seam, so a
    /// non-secure device never names `HasSecurityState` here either. Returns
    /// `0` (plain) on a non-secure device.
    fn go_security_flags(ctx: &ServiceCtx<'_, D>, go_idx: u16) -> u8;
}

/// Secure-send strategy for a **non-secure** device: there is no group-key
/// table and no sequence-number storage, so every secure send reports
/// [`SecureSendOutcome::NoKey`] (→ `F8`) and every GO reports plain (`0`)
/// security flags. Carries no security bound — this is the default strategy.
pub struct SecureGoSendAbsent;

impl<D: StackDefinition> SecureGoSender<D> for SecureGoSendAbsent {
    fn send_write_secure(
        _ctx: &ServiceCtx<'_, D>,
        _tsap: u16,
        _priority: Priority,
        _encoding: GroupValueEncoding,
        _value: &[u8],
        _security: RequestedSecurity,
    ) -> SecureSendOutcome {
        SecureSendOutcome::NoKey
    }

    fn send_read_secure(
        _ctx: &ServiceCtx<'_, D>,
        _tsap: u16,
        _priority: Priority,
        _security: RequestedSecurity,
    ) -> SecureSendOutcome {
        SecureSendOutcome::NoKey
    }

    fn go_security_flags(_ctx: &ServiceCtx<'_, D>, _go_idx: u16) -> u8 {
        0
    }
}

/// Secure-send strategy for a **secure** device: drives
/// [`SecureGroupValueAddressedSender`] and reads the real per-GO security
/// flags. This is the only place the Data Secure bounds appear, so a device
/// only composes [`DiagnosticsAugment`] with this strategy when its extension
/// state actually carries security.
pub struct SecureGoSendPresent;

impl<D: StackDefinition> SecureGoSender<D> for SecureGoSendPresent
where
    D::State: StackState + HasExtensionState + HasAddressTable,
    <D::State as HasExtensionState>::ES: HasSecurityState + HasSeqStorage,
{
    fn send_write_secure(
        ctx: &ServiceCtx<'_, D>,
        tsap: u16,
        priority: Priority,
        encoding: GroupValueEncoding,
        value: &[u8],
        security: RequestedSecurity,
    ) -> SecureSendOutcome {
        ctx.secure_group_value_sender().send_group_write_tsap_secure(tsap, priority, encoding, value, security);
        SecureSendOutcome::Queued
    }

    fn send_read_secure(
        ctx: &ServiceCtx<'_, D>,
        tsap: u16,
        priority: Priority,
        security: RequestedSecurity,
    ) -> SecureSendOutcome {
        ctx.secure_group_value_sender().send_group_read_tsap_secure(tsap, priority, security);
        SecureSendOutcome::Queued
    }

    fn go_security_flags(ctx: &ServiceCtx<'_, D>, go_idx: u16) -> u8 {
        ctx.state.extension_state().go_security_flags_for(go_idx).unwrap_or(0)
    }
}

// ============================================================================
// Augment
// ============================================================================

/// Interface object augment for diagnostics: PID_OPERATION_MODE (PID 52)
/// on the Application Program Object and PID_GO_DIAGNOSTICS (PID 66) on
/// the Group Object Table Object.
///
/// This augment does NOT add additional objects — it extends existing
/// objects with function properties for diagnostic mode and GO control.
///
/// Telegram emission is done through the shared [`ServiceCtx`]
/// (outbox + buffer manager accessors) or, for the `transmit`
/// diagnostic that maps onto a normal CO send, through the
/// [`GroupValueSender`] capability. The augment itself holds only
/// its own operation-mode state.
// Both PIDs use PDT_FUNCTION and dispatch via FunctionPropertyCommand /
// FunctionPropertyStateRead. The macro generates the descriptor table,
// `get_property_descriptor`, `property_description_read`, and the
// per-target object-type guards; the hand-written closures below carry
// the imperative service-frame parsing logic.
//
// The `where_bounds(...)` argument adds the bounds on `D::State` that
// the function-property handlers need (state lookups for application,
// communication objects, tables). The *secure* GO-diagnostics services
// (secure GroupValue send + the GO security-flags read) are not bounded
// here: they go through the `GS: SecureGoSender<D>` strategy, so a
// non-secure device composes this augment with `SecureGoSendAbsent` and
// names no security trait at all.
#[interface_object_augment(
    target_objects = [
        InterfaceObjectType::ApplicationProgram,
        InterfaceObjectType::GroupObjectTable,
    ],
    where_bounds(
        D::State: StackState
            + HasApplication
            + HasCommunicationObjectTable
            + HasCommObjects
            + HasAddressTable
            + HasAssociationTable,
        GS: SecureGoSender<D>,
    ),
)]
pub struct DiagnosticsAugment<'a, GS = SecureGoSendAbsent> {
    state: &'a OperationModeState,
    /// Selects the secure-send strategy without storing any data — both
    /// strategy types are zero-sized. A non-secure device uses the default
    /// `SecureGoSendAbsent`; a secure device names `SecureGoSendPresent`.
    _sender: core::marker::PhantomData<GS>,

    // PID_OPERATION_MODE (52) on the ApplicationProgram object.
    // Access policy `3FF/00C` per AN193 v04 §"Object Type 3" — plain
    // mode is fully open; with Security Mode on, only Tool A+C may
    // read or write. Access level 3/3.
    #[io(
        pid = pid::application::OPERATION_MODE,
        pdt = PDT_Function,
        access = RW,
        policy = AccessPolicy::new(0x3FF, 0x00C),
        rl = 3, wl = 3,
        intercepts,
        target = InterfaceObjectType::ApplicationProgram,
        function_command = |this: &Self, ctx: &ServiceCtx<'_, _>, req: &FunctionPropertyRequest<'_>| -> FunctionPropertyResult {
            this.handle_command(ctx.state, req)
        },
        function_state_read = |this: &Self, ctx: &ServiceCtx<'_, _>, req: &FunctionPropertyRequest<'_>| -> FunctionPropertyResult {
            this.handle_state_read(ctx.state, req)
        },
    )]
    _operation_mode_io: (),

    // PID_GO_DIAGNOSTICS (66) on the GroupObjectTable object.
    // Access policy `3FF/0CC` per AN193 v04 §"Object Type 9" — the
    // standard `READ_OPEN_WRITE_TOOL` baseline (read open, write
    // restricted to Tool in Security Mode). Note this is *more*
    // permissive than PID_OPERATION_MODE: roles may still trigger GO
    // diagnostics with A or A+C in Security Mode.
    #[io(
        pid = pid::group_object::GO_DIAGNOSTICS,
        pdt = PDT_Function,
        access = RW,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL,
        rl = 3, wl = 3,
        intercepts,
        target = InterfaceObjectType::GroupObjectTable,
        function_command = |this: &Self, ctx: &ServiceCtx<'_, _>, req: &FunctionPropertyRequest<'_>| -> FunctionPropertyResult {
            this.handle_go_diag_command(ctx, req)
        },
        function_state_read = |this: &Self, ctx: &ServiceCtx<'_, _>, req: &FunctionPropertyRequest<'_>| -> FunctionPropertyResult {
            this.handle_go_diag_state_read(ctx, req)
        },
    )]
    _go_diagnostics_io: (),
}

// ============================================================================
// GO Diagnostics Response Helpers
// ============================================================================

/// Build a `PropertyBuf` carrying the three-byte `PID_OPERATION_MODE`
/// response body (`[service_id, mode, time_left]`). Works for both the
/// success (return code 0x20) and negative acknowledgement (0xA0)
/// paths, which share the same data layout.
fn operation_mode_buf<const N: usize>(service_id: u8, mode: u8, time_left: u8) -> PropertyBuf<N> {
    let mut scratch = [0u8; OperationModeResponse::LEN];
    PropertyBuf::new(OperationModeResponse { service_id, operation_mode: mode, time_left }.write(&mut scratch))
}

/// Build a GO diagnostics success response (return code 0x21 —
/// `E_GD_GO_STATUS_VALUE`) with the standard `[service_id, go_idx,
/// status, value...]` envelope, serialised by
/// [`GoStatusValueResponse`].
fn go_diag_success(service_id: u8, go_idx: u16, status: u8, value: &[u8]) -> FunctionPropertyResult {
    // 4-byte header + up to 60 value bytes fits comfortably inside
    // `PropertyBuf`. Values longer than this are truncated per the
    // GoStatusValueResponse contract — consistent with the prior
    // implementation's `.min(60)`.
    let mut resp = [0u8; 64];
    let out = GoStatusValueResponse { service_id, go_idx, status, value }.write(&mut resp);
    FunctionPropertyResult { return_code: 0x21, data: PropertyBuf::new(out) }
}

impl<'a, GS> DiagnosticsAugment<'a, GS> {
    pub fn new(state: &'a OperationModeState) -> Self {
        // Both strategy types are zero-sized, so no `GS` value is needed.
        Self { state, _sender: core::marker::PhantomData }
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
                data: operation_mode_buf(svc_id, current_mode, current_time_left),
            };
        }

        let reserved = req.service_data[0];
        let service_id = req.service_data[1];
        let requested_mode = req.service_data[2];

        // Validate reserved octet.
        if reserved != 0x00 {
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: operation_mode_buf(service_id, current_mode, current_time_left),
            };
        }

        // Validate service ID.
        if service_id != 0x00 {
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: operation_mode_buf(service_id, current_mode, current_time_left),
            };
        }

        // Validate operation mode value.
        if requested_mode > 0x01 {
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: operation_mode_buf(service_id, current_mode, current_time_left),
            };
        }

        // Check that the application is running.
        if !stack_state.app().borrow().is_running() {
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: operation_mode_buf(service_id, current_mode, current_time_left),
            };
        }

        // Set the requested operation mode.
        self.state.set_mode(requested_mode);

        let new_mode = self.state.operation_mode();
        let new_time_left = self.state.time_left();

        FunctionPropertyResult {
            return_code: 0x20, // E_OM_CURRENT_OPERATION_MODE
            data: operation_mode_buf(service_id, new_mode, new_time_left),
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
                data: operation_mode_buf(svc_id, current_mode, current_time_left),
            };
        }

        let reserved = req.service_data[0];
        let service_id = req.service_data[1];

        // Validate reserved octet.
        if reserved != 0x00 {
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: operation_mode_buf(service_id, current_mode, current_time_left),
            };
        }

        // Validate service ID.
        if service_id != 0x00 {
            return FunctionPropertyResult {
                return_code: 0xA0,
                data: operation_mode_buf(service_id, current_mode, current_time_left),
            };
        }

        // State reads always succeed — even when the app is halted.
        // Per spec §4.4.1 and conformance test 6.1.11: reads return the
        // current state regardless of the Run State Machine.
        FunctionPropertyResult {
            return_code: 0x20, // E_OM_CURRENT_OPERATION_MODE
            data: operation_mode_buf(service_id, current_mode, current_time_left),
        }
    }

    // ================================================================
    // PID_GO_DIAGNOSTICS handlers
    // ================================================================

    /// Handle FunctionPropertyExtCommand for PID_GO_DIAGNOSTICS.
    fn handle_go_diag_command<D: StackDefinition>(
        &self,
        ctx: &ServiceCtx<'_, D>,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult
    where
        D::State: StackState + HasCommunicationObjectTable + HasCommObjects + HasAddressTable + HasAssociationTable,
        GS: SecureGoSender<D>,
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
    fn handle_go_diag_state_read<D: StackDefinition>(
        &self,
        ctx: &ServiceCtx<'_, D>,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult
    where
        D::State: StackState + HasCommunicationObjectTable + HasCommObjects + HasAddressTable + HasAssociationTable,
        GS: SecureGoSender<D>,
    {
        if req.service_data.len() < 2 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }

        let reserved = req.service_data[0];
        let service_id = req.service_data[1];

        if reserved != 0x00 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }

        match service_id {
            // read-config needs the per-GO security flags via the strategy, so
            // it takes the full `ctx`; read-value is security-free.
            0x00 => self.handle_go_diag_read_config(ctx, req),
            0x01 => self.handle_go_diag_read_value(ctx.state, req),
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
        // Spec §4.8.1.3.2 splits the short-request cases:
        //   - `data.len() < 4` (no full GO index) — malformed; no
        //     specific RC is enumerated in Table 36, so fall through
        //     to the catchall `FF E_ERROR`.
        //   - `data.len() == 4` (GO index present but no value) —
        //     Table 36 explicitly calls this out as `A3 E_GD_GO_SIZE_-
        //     MISMATCH` ("the field Data is missing").
        if data.len() < 4 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }
        if data.len() < 5 {
            return FunctionPropertyResult {
                return_code: 0xA3, // E_GD_GO_SIZE_MISMATCH
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
    fn handle_go_diag_direct_write<D: StackDefinition>(
        &self,
        ctx: &ServiceCtx<'_, D>,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult
    where
        D::State: StackState + HasCommunicationObjectTable + HasCommObjects + HasAddressTable,
        GS: SecureGoSender<D>,
    {
        let data = req.service_data;
        // Need at least: reserved(1) + serviceID(1) + flags(1) + GA(2) + value(1).
        // Spec §4.8.1.3.3 Table 37 allows only `F8 E_DATA_VOID` and
        // `FF E_ERROR` as negative RCs — a malformed request that's
        // shorter than the fixed header isn't specifically enumerated,
        // so fall through to `FF` per §4.8.1.1.7.
        if data.len() < 6 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
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

        let value = &data[5..];

        // Bounds-check the forwarded value against the effective APDU
        // budget before we try to emit. Per spec 03/05/01 §4.8.1.3.3
        // Table 37 + NOTE 39, data-size mismatch has no dedicated
        // return code — `FFh E_ERROR` is the catchall when no other RC
        // applies. A `Full`-encoded `GroupValue_Write` places `value`
        // at offset `MSG_APDU`, so the largest permissible length is
        // `budget - MSG_APDU`.
        let budget = ctx.effective_apdu_budget();
        let max_value_len = budget.saturating_sub(zweidraehte_proto::messages::knx::offsets::MSG_APDU);
        if value.len() > max_value_len {
            warn!(
                "GO diag: direct-write value too large for APDU budget (value_len={}, max={})",
                value.len(),
                max_value_len,
            );
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[0x01]) };
        }

        // Bit 7 of flags: 1 = next full octet, 0 = 6 trailing bits after APCI.
        let full_octet = flags & 0x80 != 0;
        let encoding = if !full_octet && value.len() == 1 && value[0] < 64 {
            GroupValueEncoding::Short
        } else {
            GroupValueEncoding::Full
        };

        debug!(
            "GO diag: stashing GroupValue_Write to TSAP {} (GA 0x{:04X}) sec_bits={:#04X}",
            tsap,
            u16::from_be_bytes([data[3], data[4]]),
            sec_bits
        );

        // ================================================================
        // Dispatch via the right sender capability
        //
        // Plain (sec_bits == 0) goes through `GroupValueAddressedSender`
        // exactly like before. Secure (auth-only / auth+conf) goes through
        // the `GS: SecureGoSender<D>` strategy: on a secure device it builds
        // a fully-wrapped KNX Data Secure frame using the TSAP's group key;
        // on a non-secure device (`SecureGoSendAbsent`) it reports `NoKey`,
        // which maps to `F8` per 03/05/01 §4.8.1.3.3 Table 37 ("Security is
        // requested for GA for which there is no GA Key"). The `has_group_key`
        // guard above already returns `F8` for non-secure devices before we
        // get here, so the strategy `NoKey` arm is the belt-and-braces path.
        // ================================================================
        match sec_bits {
            0x00 => {
                ctx.group_value_sender().send_group_write_tsap(tsap, Priority::Low, encoding, value);
                FunctionPropertyResult { return_code: 0x00, data: PropertyBuf::new(&[0x01]) }
            }
            0x01 | 0x03 => {
                let security = if sec_bits == 0x01 { RequestedSecurity::AuthOnly } else { RequestedSecurity::AuthConf };
                match GS::send_write_secure(ctx, tsap, Priority::Low, encoding, value, security) {
                    SecureSendOutcome::Queued => {
                        FunctionPropertyResult { return_code: 0x00, data: PropertyBuf::new(&[0x01]) }
                    }
                    SecureSendOutcome::NoKey => {
                        FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[0x01]) }
                    }
                }
            }
            // sec_bits == 0x02 was rejected as invalid earlier.
            _ => unreachable!("invalid sec_bits {:#04X} — should have been rejected", sec_bits),
        }
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
    fn handle_go_diag_transmit<D: StackDefinition>(
        &self,
        ctx: &ServiceCtx<'_, D>,
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
    fn handle_go_diag_direct_read<D: StackDefinition>(
        &self,
        ctx: &ServiceCtx<'_, D>,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult
    where
        D::State: StackState + HasCommunicationObjectTable + HasCommObjects + HasAddressTable,
        GS: SecureGoSender<D>,
    {
        let data = req.service_data;
        // Spec §4.8.1.3.5 Figure 39: `[reserved, 0x03, flags, GA(2)]`.
        // Table 39 lists only `F2`, `F8`, `FF` as allowed negative RCs;
        // a malformed length maps to `FF E_ERROR` per §4.8.1.1.7 —
        // `F2` is reserved for "command not supported" which this isn't.
        if data.len() != 5 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
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

        debug!(
            "GO diag: stashing GroupValue_Read to TSAP {} (GA 0x{:04X}) sec_bits={:#04X}",
            tsap,
            u16::from_be_bytes([data[3], data[4]]),
            sec_bits
        );

        // Plain reads go through `GroupValueAddressedSender`; secure reads go
        // through the `GS` strategy (real send on a secure device, `NoKey`→`F8`
        // on a non-secure one — see `handle_go_diag_direct_write`).
        match sec_bits {
            0x00 => {
                ctx.group_value_sender().send_group_read_tsap(tsap, Priority::Low);
                FunctionPropertyResult { return_code: 0x00, data: PropertyBuf::new(&[0x03]) }
            }
            0x01 | 0x03 => {
                let security = if sec_bits == 0x01 { RequestedSecurity::AuthOnly } else { RequestedSecurity::AuthConf };
                match GS::send_read_secure(ctx, tsap, Priority::Low, security) {
                    SecureSendOutcome::Queued => {
                        FunctionPropertyResult { return_code: 0x00, data: PropertyBuf::new(&[0x03]) }
                    }
                    SecureSendOutcome::NoKey => {
                        FunctionPropertyResult { return_code: 0xF8, data: PropertyBuf::new(&[0x03]) }
                    }
                }
            }
            // sec_bits == 0x02 was rejected as invalid earlier.
            _ => unreachable!("invalid sec_bits {:#04X} — should have been rejected", sec_bits),
        }
    }

    // ================================================================
    // WriteServiceID 0x04: Set Source Address Filter
    // ================================================================

    /// Set the source-address filter for GO updates in diagnostic mode.
    ///
    /// Per spec §4.8.1.3.6 Figure 40 the command has no GO index — it
    /// limits **all** incoming group communication (A_GroupValue_Read /
    /// _Write) to a single sender IA. The filter is per-device and the
    /// MaS clears it automatically when leaving Diagnostic Mode.
    ///
    /// Request: `[reserved=0x00, 0x04, IA_hi, IA_lo]` (4 bytes total).
    /// Success: rc=0x00, `[service_id]`.
    fn handle_go_diag_set_filter(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        let data = req.service_data;

        // Spec §4.8.1.3.6 Table 40: requires Diagnostic Mode; otherwise
        // `F3h E_COMMAND_IMPOSSIBLE`. This check runs before the length
        // check so malformed requests outside Diagnostic Mode still
        // report the mode error (matches the conformance 6.2.22 behaviour).
        if !self.state.is_diagnostic_mode() {
            return FunctionPropertyResult {
                return_code: 0xF3, // E_COMMAND_IMPOSSIBLE
                data: PropertyBuf::new(&[0x04]),
            };
        }

        // Spec §4.8.1.3.6 Figure 40: `[reserved, 0x04, Sender_IA(2)]`.
        // Any other length is malformed — no Return Code fits precisely
        // (Table 40 lists only `E_COMMAND_IMPOSSIBLE`), so fall through
        // to the catchall `FFh E_ERROR` per §4.8.1.1.7. Conformance 6.2.23
        // verifies `FF` alone (no service-ID echo) on both too-few and
        // too-many-byte variants.
        if data.len() != 4 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }

        let ia = u16::from_be_bytes([data[2], data[3]]);
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
    fn handle_go_diag_read_config<D: StackDefinition>(
        &self,
        ctx: &ServiceCtx<'_, D>,
        req: &FunctionPropertyRequest<'_>,
    ) -> FunctionPropertyResult
    where
        D::State: StackState + HasCommunicationObjectTable + HasCommObjects + HasAssociationTable,
        GS: SecureGoSender<D>,
    {
        let data = req.service_data;
        if data.len() != 4 {
            return FunctionPropertyResult { return_code: 0xFF, data: PropertyBuf::new(&[]) };
        }

        let go_idx = u16::from_be_bytes([data[2], data[3]]);
        let cot = ctx.state.cot().borrow();

        let Some(entry) = cot.get_object(go_idx) else {
            return FunctionPropertyResult { return_code: 0xA1, data: PropertyBuf::new(&[0x00]) };
        };

        // Spec §4.8.1.1.6 Figure 23 defines `GO_config` as a packed 16-bit
        // BE word. The low octet is identical to the Group Object
        // Descriptor high octet (`[U T I W R C Prio(2)]`), which is
        // exactly what `ComObjectFlags::to_byte()` already encodes
        // (Realisation Type 7, Table 87). No re-packing needed.
        let descriptor_hi = entry.flags.to_byte();
        drop(cot);

        // Linked: spec §4.8.1.1.6 NOTE 31 — set iff at least one GA is
        // linked to this GO; calculated at query time from the
        // association table.
        let linked = ctx.state.ast().borrow().tsaps_for_asap(go_idx).next().is_some();

        // Security flags: per-GO `auth` / `conf` bits from PID_GO_SECURITY_FLAGS,
        // obtained through the secure-send strategy so a non-secure device
        // reports 0 (plain) without naming any security trait. A missing entry
        // is also reported as 0, matching devices without secure group objects.
        let sec_raw = GS::go_security_flags(ctx, go_idx);
        let auth = sec_raw & 0x01 != 0;
        let conf = sec_raw & 0x02 != 0;

        // `Size` is the Value Field Type code per Realisation Type 7
        // Table 87 — exactly the `ComObjectType` enum's `u8` repr, not
        // a raw byte count. Example codes: `0` = Uint1, `7` = Byte1,
        // `9` = Byte3.
        let size_code: u8 = u8::from(entry.object_type);

        let mut resp = [0u8; GoConfigResponse::LEN];
        // DPT_ID stays zero — spec §4.8.1.1.6 explicitly permits
        // reporting `00000000h` when the CO table does not track
        // datapoint identifiers.
        let out = GoConfigResponse {
            service_id: 0x00,
            go_idx,
            go_config: GoConfigResponse::pack_config(linked, conf, auth, descriptor_hi),
            size: size_code,
            dpt_main: 0x0000,
            dpt_sub: 0x0000,
        }
        .write(&mut resp);

        FunctionPropertyResult { return_code: 0x20, data: PropertyBuf::new(out) }
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

// `Augment<D>` impl is generated by the
// `#[interface_object_augment(...)]` attribute on the struct above.
