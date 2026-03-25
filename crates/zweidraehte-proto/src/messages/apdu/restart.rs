//! Restart APDUs (`A_Restart`, `A_Restart_Response`).
//!
//! Basic restart has no payload. Master reset (bit 0 set) carries an erase
//! code and channel number. The response has a special APCI encoding (0x03A1)
//! that doesn't map cleanly to a single `ApciCode` variant.

use crate::messages::knx::offsets;

// ============================================================================
// Restart (Request parsing)
// ============================================================================

/// Parsed fields from `A_Restart`.
///
/// ## Wire format
///
/// Basic restart:
/// ```text
/// APDU[0-1]: APCI (0x0380, bit 0 = 0)
/// ```
///
/// Master reset:
/// ```text
/// APDU[0-1]: APCI (0x0381, bit 0 = 1)
/// APDU[2]:   Erase code
/// APDU[3]:   Channel number
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RestartParsed {
    pub is_master_reset: bool,
    pub erase_code: u8,
    pub channel: u8,
}

impl RestartParsed {
    /// Minimum message length for basic restart.
    pub const BASIC_MIN_MSG_LEN: usize = offsets::MSG_APCI + 2;
    /// Minimum message length for master reset.
    pub const MASTER_MIN_MSG_LEN: usize = offsets::MSG_APCI + 4;

    /// Parse a restart request from a full message buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::BASIC_MIN_MSG_LEN {
            return None;
        }
        let is_master_reset = (buf[offsets::MSG_APCI + 1] & 0x01) == 1;

        if is_master_reset {
            if buf.len() < Self::MASTER_MIN_MSG_LEN {
                return None;
            }
            Some(Self {
                is_master_reset: true,
                erase_code: buf[offsets::MSG_APCI + 2],
                channel: buf[offsets::MSG_APCI + 3],
            })
        } else {
            Some(Self { is_master_reset: false, erase_code: 0, channel: 0 })
        }
    }
}

// ============================================================================
// Restart Response
// ============================================================================

/// Writer for `A_Restart_Response` (master reset response).
///
/// The response uses a special APCI encoding (0x03A1) that differs from the
/// request. The writer sets the raw APCI bytes directly.
pub struct RestartResponse;

impl RestartResponse {
    /// Response: APCI(2) + Error(1) + ProcessTime(2) = 5 bytes APDU.
    pub const MSG_LEN: usize = offsets::MSG_APCI + 5;

    /// Write a restart response into the message buffer.
    ///
    /// Overrides the APCI byte 1 to 0xA1 (A_Restart_Response encoding),
    /// then writes the error code and process time into the data fields.
    ///
    /// The caller should have called `with_application(ApciCode::Restart)`
    /// first, which sets the APCI high bits in byte 0. This writer then
    /// overrides byte 1 (MSG_APCI+1) with 0xA1 for the response variant.
    pub fn write(buf: &mut [u8], error: u8, process_time_100ms: u16) {
        buf[offsets::MSG_APCI + 1] = 0xA1;
        buf[offsets::MSG_APCI + 2] = error;
        buf[offsets::MSG_APCI + 3] = (process_time_100ms >> 8) as u8;
        buf[offsets::MSG_APCI + 4] = process_time_100ms as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_restart_parse() {
        let mut buf = [0u8; 8];
        buf[offsets::MSG_APCI + 1] = 0x80; // bit 0 = 0 → basic
        let r = RestartParsed::parse(&buf).unwrap();
        assert!(!r.is_master_reset);
    }

    #[test]
    fn master_reset_parse() {
        let mut buf = [0u8; 10];
        buf[offsets::MSG_APCI + 1] = 0x81; // bit 0 = 1 → master reset
        buf[offsets::MSG_APCI + 2] = 0x01; // ConfirmedRestart erase code
        buf[offsets::MSG_APCI + 3] = 0x00; // channel 0
        let r = RestartParsed::parse(&buf).unwrap();
        assert!(r.is_master_reset);
        assert_eq!(r.erase_code, 0x01);
        assert_eq!(r.channel, 0x00);
    }

    #[test]
    fn master_reset_too_short() {
        let mut buf = [0u8; 9];
        buf[offsets::MSG_APCI + 1] = 0x81; // master reset but buffer too short
        assert!(RestartParsed::parse(&buf).is_none());
    }

    #[test]
    fn restart_response_write() {
        let mut buf = [0u8; 12];
        RestartResponse::write(&mut buf, 0x00, 150);
        // APCI byte 1 is overridden to 0xA1 (A_Restart_Response encoding).
        // The APCI high byte (MSG_APCI + 0) is set by MessageBuilder before
        // this writer runs, so we don't check it here.
        assert_eq!(buf[offsets::MSG_APCI + 1], 0xA1);
        assert_eq!(buf[offsets::MSG_APCI + 2], 0x00); // NoError
        assert_eq!(buf[offsets::MSG_APCI + 3], 0x00); // 150 >> 8
        assert_eq!(buf[offsets::MSG_APCI + 4], 150); // 150 & 0xFF
    }
}
