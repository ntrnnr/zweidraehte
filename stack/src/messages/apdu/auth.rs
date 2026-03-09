//! Authorization APDUs (`A_Authorize_*`, `A_Key_*`).
//!
//! These use escaped APCIs with clean data separation at APDU byte 2.

use crate::messages::knx::offsets;

// ============================================================================
// Authorize (Request / Response)
// ============================================================================

/// Parsed fields from `A_Authorize_Request`.
///
/// ## Wire format
///
/// ```text
/// APDU[0-1]: APCI (0x03D1)
/// APDU[2]:   Reserved (should be 0)
/// APDU[3-6]: Key (4 bytes)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct AuthorizeRequest {
    pub key: [u8; 4],
}

impl AuthorizeRequest {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 7;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(Self {
            key: [
                buf[offsets::MSG_APCI + 3],
                buf[offsets::MSG_APCI + 4],
                buf[offsets::MSG_APCI + 5],
                buf[offsets::MSG_APCI + 6],
            ],
        })
    }
}

/// Writer for `A_Authorize_Response`.
pub struct AuthorizeResponse;

impl AuthorizeResponse {
    /// Response: APCI(2) + access_level(1) = 3 bytes APDU.
    pub const MSG_LEN: usize = offsets::MSG_APCI + 3;

    pub fn write(buf: &mut [u8], access_level: u8) {
        buf[offsets::MSG_APCI + 2] = access_level;
    }
}

// ============================================================================
// Key (Write / Response)
// ============================================================================

/// Parsed fields from `A_Key_Write`.
///
/// ## Wire format
///
/// ```text
/// APDU[0-1]: APCI (0x03D3)
/// APDU[2]:   Access level to set key for
/// APDU[3-6]: New key (4 bytes)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct KeyWrite {
    pub level: u8,
    pub key: [u8; 4],
}

impl KeyWrite {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 7;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(Self {
            level: buf[offsets::MSG_APCI + 2],
            key: [
                buf[offsets::MSG_APCI + 3],
                buf[offsets::MSG_APCI + 4],
                buf[offsets::MSG_APCI + 5],
                buf[offsets::MSG_APCI + 6],
            ],
        })
    }
}

/// Writer for `A_Key_Response`.
pub struct KeyResponse;

impl KeyResponse {
    /// Response: APCI(2) + access_level(1) = 3 bytes APDU.
    pub const MSG_LEN: usize = offsets::MSG_APCI + 3;

    pub fn write(buf: &mut [u8], result_level: u8) {
        buf[offsets::MSG_APCI + 2] = result_level;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_request_parse() {
        let mut buf = [0u8; 13];
        buf[offsets::MSG_APCI + 3] = 0x11;
        buf[offsets::MSG_APCI + 4] = 0x22;
        buf[offsets::MSG_APCI + 5] = 0x33;
        buf[offsets::MSG_APCI + 6] = 0x44;
        let req = AuthorizeRequest::parse(&buf).unwrap();
        assert_eq!(req.key, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn authorize_response_write() {
        let mut buf = [0u8; 9];
        AuthorizeResponse::write(&mut buf, 3);
        assert_eq!(buf[offsets::MSG_APCI + 2], 3);
    }

    #[test]
    fn key_write_parse() {
        let mut buf = [0u8; 13];
        buf[offsets::MSG_APCI + 2] = 2;
        buf[offsets::MSG_APCI + 3] = 0xAA;
        buf[offsets::MSG_APCI + 4] = 0xBB;
        buf[offsets::MSG_APCI + 5] = 0xCC;
        buf[offsets::MSG_APCI + 6] = 0xDD;
        let kw = KeyWrite::parse(&buf).unwrap();
        assert_eq!(kw.level, 2);
        assert_eq!(kw.key, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn key_response_write() {
        let mut buf = [0u8; 9];
        KeyResponse::write(&mut buf, 0xFF);
        assert_eq!(buf[offsets::MSG_APCI + 2], 0xFF);
    }

    #[test]
    fn too_short_buffers() {
        let short = [0u8; 5];
        assert!(AuthorizeRequest::parse(&short).is_none());
        assert!(KeyWrite::parse(&short).is_none());
    }
}
