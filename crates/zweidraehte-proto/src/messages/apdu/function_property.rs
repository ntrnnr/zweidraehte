//! Function property APDUs (`A_FunctionPropertyCommand`, `A_FunctionPropertyState_Read`,
//! `A_FunctionPropertyState_Response`).
//!
//! Function properties use "user" APCI codes (category 0x80), so the full
//! opcode is in byte 1 and data starts at APDU byte 2.
//!
//! ## Wire format
//!
//! ```text
//! APDU[0-1]: APCI (user: 0x87 Command, 0x88 StateRead, 0x89 StateResponse)
//! APDU[2]:   Object Index
//! APDU[3]:   Property ID
//! APDU[4..]: Service data
//! ```
//!
//! For `Command` and `StateRead`, the service data is opaque and
//! function-specific. For `StateResponse`, `APDU[4]` is a return code
//! and `APDU[5..]` contains the response data.

use crate::messages::knx::offsets;

// ============================================================================
// FunctionProperty (Command / StateRead)
// ============================================================================

/// Parsed header from `A_FunctionPropertyCommand` or
/// `A_FunctionPropertyState_Read`.
///
/// Both share the same wire format: object index, property ID, then
/// variable-length service data.
#[derive(Debug, Clone, Copy)]
pub struct FunctionPropertyHeader {
    pub object_idx: u8,
    pub prop_id: u16,
}

impl FunctionPropertyHeader {
    /// Minimum message length for a function property header (no service data).
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 4;

    /// Parse the fixed header from a full message buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(Self { object_idx: buf[offsets::MSG_APCI + 2], prop_id: buf[offsets::MSG_APCI + 3] as u16 })
    }

    /// Return a slice over the service data following the header.
    pub fn data<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let start = offsets::MSG_APCI + 4;
        if buf.len() > start { &buf[start..] } else { &[] }
    }

    /// Write the header fields into a message buffer.
    pub fn write(buf: &mut [u8], object_idx: u8, prop_id: u16, service_data: &[u8]) {
        buf[offsets::MSG_APCI + 2] = object_idx;
        buf[offsets::MSG_APCI + 3] = prop_id as u8;
        if !service_data.is_empty() {
            let start = offsets::MSG_APCI + 4;
            buf[start..start + service_data.len()].copy_from_slice(service_data);
        }
    }

    /// Compute total message length for a given service data size.
    pub const fn msg_len(service_data_len: usize) -> usize {
        offsets::MSG_APCI + 4 + service_data_len
    }
}

// ============================================================================
// FunctionPropertyState Response
// ============================================================================

/// Parsed fields from `A_FunctionPropertyState_Response`.
///
/// The response includes a return code byte before the response data.
///
/// ## Wire format
///
/// ```text
/// APDU[0-1]: APCI (0x89)
/// APDU[2]:   Object Index
/// APDU[3]:   Property ID
/// APDU[4]:   Return Code
/// APDU[5..]: Response data (variable)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FunctionPropertyResponse {
    pub object_idx: u8,
    pub prop_id: u16,
    pub return_code: u8,
}

impl FunctionPropertyResponse {
    /// Minimum message length: header + return code, no response data.
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 5;

    /// Parse the response header from a full message buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(Self {
            object_idx: buf[offsets::MSG_APCI + 2],
            prop_id: buf[offsets::MSG_APCI + 3] as u16,
            return_code: buf[offsets::MSG_APCI + 4],
        })
    }

    /// Return a slice over the response data following the return code.
    pub fn data<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let start = offsets::MSG_APCI + 5;
        if buf.len() > start { &buf[start..] } else { &[] }
    }

    /// Write a response into a message buffer.
    pub fn write(buf: &mut [u8], object_idx: u8, prop_id: u16, return_code: u8, data: &[u8]) {
        buf[offsets::MSG_APCI + 2] = object_idx;
        buf[offsets::MSG_APCI + 3] = prop_id as u8;
        buf[offsets::MSG_APCI + 4] = return_code;
        if !data.is_empty() {
            let start = offsets::MSG_APCI + 5;
            buf[start..start + data.len()].copy_from_slice(data);
        }
    }

    /// Compute total message length for a given response data size.
    pub const fn msg_len(data_len: usize) -> usize {
        offsets::MSG_APCI + 5 + data_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_property_header_parse() {
        let mut buf = [0u8; 16];
        FunctionPropertyHeader::write(&mut buf, 3, 42, &[0x01, 0x02]);

        let hdr = FunctionPropertyHeader::parse(&buf).unwrap();
        assert_eq!(hdr.object_idx, 3);
        assert_eq!(hdr.prop_id, 42);
        assert_eq!(hdr.data(&buf), &[0x01, 0x02, 0, 0, 0, 0]);
    }

    #[test]
    fn function_property_header_no_data() {
        let mut buf = [0u8; 10];
        FunctionPropertyHeader::write(&mut buf, 1, 7, &[]);

        let hdr = FunctionPropertyHeader::parse(&buf).unwrap();
        assert_eq!(hdr.object_idx, 1);
        assert_eq!(hdr.prop_id, 7);
    }

    #[test]
    fn function_property_header_too_short() {
        let buf = [0u8; 5];
        assert!(FunctionPropertyHeader::parse(&buf).is_none());
    }

    #[test]
    fn function_property_response_parse() {
        let mut buf = [0u8; 16];
        FunctionPropertyResponse::write(&mut buf, 2, 15, 0x00, &[0xAB, 0xCD]);

        let resp = FunctionPropertyResponse::parse(&buf).unwrap();
        assert_eq!(resp.object_idx, 2);
        assert_eq!(resp.prop_id, 15);
        assert_eq!(resp.return_code, 0x00);
        assert_eq!(&resp.data(&buf)[..2], &[0xAB, 0xCD]);
    }

    #[test]
    fn function_property_response_error() {
        // Use exactly MIN_MSG_LEN so there's no trailing data.
        let mut buf = [0u8; FunctionPropertyResponse::MIN_MSG_LEN];
        FunctionPropertyResponse::write(&mut buf, 0, 1, 0x05, &[]);

        let resp = FunctionPropertyResponse::parse(&buf).unwrap();
        assert_eq!(resp.return_code, 0x05);
        assert!(resp.data(&buf).is_empty());
    }

    #[test]
    fn function_property_response_too_short() {
        let buf = [0u8; 8];
        assert!(FunctionPropertyResponse::parse(&buf).is_none());
    }

    #[test]
    fn msg_len_calculations() {
        assert_eq!(FunctionPropertyHeader::msg_len(0), offsets::MSG_APCI + 4);
        assert_eq!(FunctionPropertyHeader::msg_len(4), offsets::MSG_APCI + 8);
        assert_eq!(FunctionPropertyResponse::msg_len(0), offsets::MSG_APCI + 5);
        assert_eq!(FunctionPropertyResponse::msg_len(3), offsets::MSG_APCI + 8);
    }
}
