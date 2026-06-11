//! A_Restart service types and traits.
//!
//! This module provides types for handling the KNX A_Restart application layer service,
//! which supports basic software restarts and various master reset operations.
//!
//! # Message Formats
//!
//! - **Basic A_Restart**: `03 80` - Simple software restart, config preserved
//! - **Master Reset**: `03 81 <erase_code> <channel>` - Reset with specific erase behavior
//! - **A_Restart_Response**: `03 A1 <error> <time_hi> <time_lo>` - Response to master reset
//!
//! # Erase Codes
//!
//! Different erase codes control what data is reset:
//! - `0x00` Basic - Software restart only
//! - `0x01` Confirmed - Basic restart with response
//! - `0x02` Factory Reset - Reset everything including individual address
//! - `0x03` Reset IA - Reset individual address only
//! - `0x04` Reset AP - Reset application program
//! - `0x05` Reset Param - Reset parameters only
//! - `0x06` Reset Links - Reset address and association tables
//! - `0x07` Factory Reset (keep IA) - Reset everything except individual address
//!
//! # Usage
//!
//! The stack sends [`RestartRequest`] events when A_Restart messages are received.
//! User code should:
//! 1. Execute the appropriate reset based on the erase code (for System B
//!    devices, `SystemBDeviceState::apply_erase_code` is the canonical
//!    per-code dispatch)
//! 2. Flush storage
//! 3. Send a [`RestartResponse`] back to the stack
//! 4. Trigger the platform restart after the response is sent

create_protocol_enum!(
    /// Erase codes for A_Restart Master Reset.
    ///
    /// These codes specify what data should be reset during a master reset operation.
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum EraseCode: u8 {
        Basic,              0x00, "Basic restart";
        Confirmed,          0x01, "Confirmed restart";
        FactoryReset,       0x02, "Factory reset";
        ResetIA,            0x03, "Reset IA";
        ResetAP,            0x04, "Reset application program";
        ResetParam,         0x05, "Reset parameters";
        ResetLinks,         0x06, "Reset links";
        FactoryResetKeepIA, 0x07, "Factory reset (keep IA)";
        _, "Unknown erase code 0x{:x}";
    }
);

create_protocol_enum!(
    /// Error codes for A_Restart_Response.
    ///
    /// These codes indicate the result of a master reset operation.
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum RestartError: u8 {
        NoError,              0x00, "No error";
        AccessDenied,         0x01, "Access denied";
        UnsupportedEraseCode, 0x02, "Unsupported erase code";
        InvalidChannel,       0x03, "Invalid channel number";
        _, "Unknown error code 0x{:x}";
    }
);

/// Restart request event sent from the stack to user code.
///
/// When the stack receives an A_Restart message, it validates the request and
/// sends this event to user code. User code should:
/// 1. Execute the reset for [`erase_code`](Self::erase_code) (for System B
///    devices, `SystemBDeviceState::apply_erase_code` is the canonical
///    per-code dispatch)
/// 2. Flush storage
/// 3. Send a [`RestartResponse`] back via [`Request::reply()`](crate::actor::Request::reply)
/// 4. Trigger platform restart after response is sent
#[derive(Debug, Clone, Copy)]
pub struct RestartRequest {
    /// Erase code specifying what to reset.
    pub erase_code: EraseCode,
    /// Channel number (usually 0 for all channels, used by multi-channel devices).
    pub channel: u8,
    /// Access context of the requester.
    pub access_ctx: zweidraehte_proto::AccessContext,
    /// Whether an A_Restart_Response should be sent.
    ///
    /// This is true for master reset requests (erase codes 0x01-0x07)
    /// and false for basic restart (0x00).
    pub needs_response: bool,
}

/// Response from user code after handling a restart request.
///
/// This is sent back to the stack after executing the reset operations.
/// The stack uses this to construct the A_Restart_Response message.
#[derive(Debug, Clone, Copy)]
pub struct RestartResponse {
    /// Error code indicating the result of the reset operation.
    pub error: RestartError,
    /// Processing time in 100ms units (max 65535 = ~109 minutes).
    ///
    /// Set to 0 for instant operations. Use non-zero values if the reset
    /// involves slow operations like flash erase.
    pub process_time_100ms: u16,
}

impl RestartResponse {
    /// Create a successful response with zero process time.
    pub fn success() -> Self {
        Self { error: RestartError::NoError, process_time_100ms: 0 }
    }

    /// Create a successful response with the given process time.
    pub fn success_with_time(process_time_100ms: u16) -> Self {
        Self { error: RestartError::NoError, process_time_100ms }
    }

    /// Create an error response.
    pub fn error(error: RestartError) -> Self {
        Self { error, process_time_100ms: 0 }
    }
}

// A `RestartHandler` trait (supports_erase_code / execute_reset /
// flush_storage) used to live here. It was never consumed by the stack:
// the application layer validates A_Restart itself (access policy +
// erase-code checks in `handle_restart`) and hands the request to user
// code via the restart channel, where the reset is applied with the
// inherent `SystemBDeviceState::apply_erase_code` / reset methods. The
// trait was deleted rather than kept as a second, diverging definition
// of the same dispatch.
