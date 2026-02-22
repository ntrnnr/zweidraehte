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
//! 1. Execute the appropriate reset based on the erase code
//! 2. Flush storage
//! 3. Send a [`RestartResponse`] back to the stack
//! 4. Trigger the platform restart after the response is sent
//!
//! See [`RestartHandler`] trait for implementing device-specific reset behavior.

create_protocol_enum!(
    /// Erase codes for A_Restart Master Reset.
    ///
    /// These codes specify what data should be reset during a master reset operation.
    /// Not all devices support all erase codes - use [`RestartHandler::supports_erase_code`]
    /// to check support.
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
/// 1. Execute the reset using [`RestartHandler::execute_reset`]
/// 2. Flush storage
/// 3. Send a [`RestartResponse`] back via [`Stack::restart_respond`]
/// 4. Trigger platform restart after response is sent
#[derive(Debug, Clone, Copy)]
pub struct RestartRequest {
    /// Erase code specifying what to reset.
    pub erase_code: EraseCode,
    /// Channel number (usually 0 for all channels, used by multi-channel devices).
    pub channel: u8,
    /// Access context of the requester.
    pub access_ctx: crate::AccessContext,
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

/// Trait for handling restart/reset operations.
///
/// Implementations define which erase codes they support and what data gets reset
/// for each code. This allows different device types (07B0, 57B0, etc.) to have
/// different reset behaviors.
///
/// # Example
///
/// ```rust,ignore
/// impl RestartHandler for MyDeviceState {
///     fn supports_erase_code(&self, code: EraseCode) -> bool {
///         matches!(code,
///             EraseCode::Basic | EraseCode::Confirmed |
///             EraseCode::FactoryReset | EraseCode::FactoryResetKeepIA
///         )
///     }
///
///     fn execute_reset(&mut self, code: EraseCode, _channel: u8) -> Result<u16, RestartError> {
///         match code {
///             EraseCode::Basic | EraseCode::Confirmed => Ok(0),
///             EraseCode::FactoryReset => {
///                 self.reset_to_factory_defaults();
///                 Ok(0)
///             }
///             EraseCode::FactoryResetKeepIA => {
///                 let ia = self.individual_address();
///                 self.reset_to_factory_defaults();
///                 self.set_individual_address(ia);
///                 Ok(0)
///             }
///             _ => Err(RestartError::UnsupportedEraseCode),
///         }
///     }
///
///     fn flush_storage(&mut self) -> Result<(), RestartError> {
///         self.storage.flush().map_err(|_| RestartError::NoError)
///     }
/// }
/// ```
pub trait RestartHandler {
    /// Check if an erase code is supported by this device.
    ///
    /// Returns `true` if the device can handle the given erase code.
    /// The stack will respond with [`RestartError::UnsupportedEraseCode`] for
    /// unsupported codes.
    fn supports_erase_code(&self, code: EraseCode) -> bool;

    /// Get the required access level for an erase code.
    ///
    /// Returns the minimum access level (0 = highest, 3 = lowest) required
    /// to execute the given erase code.
    ///
    /// Default implementation:
    /// - Basic/Confirmed restart: level 3 (anyone)
    /// - All other resets: level 0 (system access)
    fn required_access_level(&self, code: EraseCode) -> u8 {
        match code {
            EraseCode::Basic | EraseCode::Confirmed => 3, // Anyone can do basic restart
            _ => 0, // Master reset operations require system access
        }
    }

    /// Execute the reset for the given erase code.
    ///
    /// This method should reset the appropriate data based on the erase code.
    /// It should NOT:
    /// - Flush storage (call `flush_storage` separately)
    /// - Perform the actual restart (user code does this after responding)
    ///
    /// # Arguments
    /// - `code`: The erase code specifying what to reset
    /// - `channel`: Channel number (0 for all channels)
    ///
    /// # Returns
    /// - `Ok(process_time)`: Reset successful, process time in 100ms units
    /// - `Err(error)`: Reset failed with the given error
    fn execute_reset(&mut self, code: EraseCode, channel: u8) -> Result<u16, RestartError>;

    /// Flush any pending storage writes.
    ///
    /// Called after `execute_reset` to ensure all changes are persisted
    /// before the device restarts.
    fn flush_storage(&mut self) -> Result<(), RestartError>;
}
