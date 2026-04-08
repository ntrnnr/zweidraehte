//! Operation Mode extension for KNX diagnostic mode.
//!
//! Provides PID_OPERATION_MODE (PID 52) on the Application Program Object
//! (IOT 0x0003). This enables a Management Client (MaC) to switch the
//! device between Normal Mode and Diagnostic Mode.
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
//! - [`OperationModeAugment`] — interface object augment for PID 52

use core::cell::Cell;

use embassy_time::Instant;

use crate::StackState;
use crate::access::AccessPolicy;
use crate::dpt::{InterfaceObjectType, PDT_Function, PropertyDataDefinition};
use crate::objects::interface::{
    FunctionPropertyRequest, FunctionPropertyResult, InterfaceObjectAugment, PropertyAccess, PropertyBuf,
    PropertyDescriptionResponse, PropertyDescriptor, PropertyError, PropertyLookup, pid,
};
use crate::objects::tables::{HasApplication, HasRunStateMachine};

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

/// Interface object augment for PID_OPERATION_MODE on the Application
/// Program Object.
///
/// This augment does NOT add additional objects — it extends the existing
/// Application Program Object with the OPERATION_MODE function property.
pub struct OperationModeAugment<'a> {
    state: &'a OperationModeState,
}

impl<'a> OperationModeAugment<'a> {
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
}

impl<'a, S: StackState + HasApplication> InterfaceObjectAugment<S> for OperationModeAugment<'a> {
    fn get_property_descriptor(&self, object_type: InterfaceObjectType, prop_id: u8) -> Option<PropertyDescriptor> {
        if object_type == InterfaceObjectType::ApplicationProgram && prop_id == pid::OPERATION_MODE {
            Some(OPERATION_MODE_DESCRIPTOR)
        } else {
            None
        }
    }

    fn property_description_read(
        &self,
        _state: &S,
        object_type: InterfaceObjectType,
        object_idx: u16,
        lookup: PropertyLookup,
    ) -> Option<Result<PropertyDescriptionResponse, PropertyError>> {
        if object_type != InterfaceObjectType::ApplicationProgram {
            return None;
        }

        match lookup {
            PropertyLookup::ByPid(p) if p == pid::OPERATION_MODE => {
                // Property index within the object. The augment's property
                // is appended after the base object's properties (index 7,
                // since the base has 7 properties at indices 0-6).
                // However, the dispatch adjusts the index before calling us,
                // so we report index 0 relative to the augment.
                Some(Ok(PropertyDescriptionResponse::from_descriptor(object_idx, 0, &OPERATION_MODE_DESCRIPTOR)))
            }
            PropertyLookup::ByIndex(0) => {
                Some(Ok(PropertyDescriptionResponse::from_descriptor(object_idx, 0, &OPERATION_MODE_DESCRIPTOR)))
            }
            _ => None,
        }
    }

    fn function_property_command(
        &self,
        state: &S,
        object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        if object_type != InterfaceObjectType::ApplicationProgram || req.prop_id != pid::OPERATION_MODE {
            return None;
        }
        Some(self.handle_command(state, req))
    }

    fn function_property_state_read(
        &self,
        state: &S,
        object_type: InterfaceObjectType,
        req: &FunctionPropertyRequest<'_>,
    ) -> Option<FunctionPropertyResult> {
        if object_type != InterfaceObjectType::ApplicationProgram || req.prop_id != pid::OPERATION_MODE {
            return None;
        }
        Some(self.handle_state_read(state, req))
    }
}
