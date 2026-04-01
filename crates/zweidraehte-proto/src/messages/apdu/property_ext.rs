//! Extended property service APDUs (`A_PropertyExtValue_*`).
//!
//! AN163 "Extended Interface Object Addressing" services. These use
//! `(interface_object_type, object_instance)` addressing (both 16-bit)
//! instead of the flat 8-bit `object_index` used by regular property
//! services.
//!
//! ## Wire format differences from regular property services
//!
//! - Object addressed by `(IOT: u16, instance: u16)` instead of `index: u8`
//! - `nr_of_elem` is 8 bits (regular: 4 bits packed with start_index)
//! - `start_index` is 16 bits (regular: 12 bits packed with nr_of_elem)
//! - Error responses carry a 1-byte return code instead of count=0
//!
//! ## Common header layout (APDU-relative byte offsets)
//!
//! ```text
//! [0-1]: APCI (escaped, 10-bit)
//! [2-3]: interface_object_type (u16 big-endian)
//! [4-5]: object_instance (u16 big-endian)
//! [6]:   property_id
//! [7]:   nr_of_elem
//! [8-9]: start_index (u16 big-endian)
//! [10+]: data (Read response / WriteCon request) or return_code (WriteConRes)
//! ```

use crate::messages::knx::offsets;

// ============================================================================
// Extended PropertyValue Header
// ============================================================================

/// Parsed header from extended property service PDUs.
///
/// Used by `A_PropertyExtValue_Read`, `A_PropertyExtValue_Response`,
/// `A_PropertyExtValue_WriteCon`, `A_PropertyExtValue_WriteConRes`,
/// `A_PropertyExtValue_WriteUnCon`, and `A_PropertyExtValue_InfoReport`.
#[derive(Debug, Clone, Copy)]
pub struct PropertyExtValueHeader {
    pub object_type: u16,
    pub object_instance: u16,
    pub prop_id: u8,
    pub count: u8,
    pub start_idx: u16,
}

impl PropertyExtValueHeader {
    /// Minimum message length for the header (no data payload).
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 10;

    /// Parse the fixed header from a full message buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        let base = offsets::MSG_APCI;
        Some(Self {
            object_type: u16::from_be_bytes([buf[base + 2], buf[base + 3]]),
            object_instance: u16::from_be_bytes([buf[base + 4], buf[base + 5]]),
            prop_id: buf[base + 6],
            count: buf[base + 7],
            start_idx: u16::from_be_bytes([buf[base + 8], buf[base + 9]]),
        })
    }

    /// Return a slice over the data payload following the header.
    pub fn data<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let start = offsets::MSG_APCI + 10;
        if buf.len() > start { &buf[start..] } else { &[] }
    }

    /// Write the common header fields into a message buffer.
    fn write_header(buf: &mut [u8], object_type: u16, object_instance: u16, prop_id: u8, count: u8, start_idx: u16) {
        let base = offsets::MSG_APCI;
        let ot = object_type.to_be_bytes();
        buf[base + 2] = ot[0];
        buf[base + 3] = ot[1];
        let oi = object_instance.to_be_bytes();
        buf[base + 4] = oi[0];
        buf[base + 5] = oi[1];
        buf[base + 6] = prop_id;
        buf[base + 7] = count;
        let si = start_idx.to_be_bytes();
        buf[base + 8] = si[0];
        buf[base + 9] = si[1];
    }
}

// ============================================================================
// Response Writer (for Read and WriteCon responses)
// ============================================================================

/// Writer for `A_PropertyExtValue_Response` (0xCD).
pub struct PropertyExtValueResponse;

impl PropertyExtValueResponse {
    /// Write a successful response with data payload.
    pub fn write(
        buf: &mut [u8],
        object_type: u16,
        object_instance: u16,
        prop_id: u8,
        count: u8,
        start_idx: u16,
        data: &[u8],
    ) {
        PropertyExtValueHeader::write_header(buf, object_type, object_instance, prop_id, count, start_idx);
        if !data.is_empty() {
            let start = offsets::MSG_APCI + 10;
            buf[start..start + data.len()].copy_from_slice(data);
        }
    }

    /// Write an error response: count=0, data=return_code.
    pub fn write_error(
        buf: &mut [u8],
        object_type: u16,
        object_instance: u16,
        prop_id: u8,
        start_idx: u16,
        return_code: u8,
    ) {
        PropertyExtValueHeader::write_header(buf, object_type, object_instance, prop_id, 0, start_idx);
        buf[offsets::MSG_APCI + 10] = return_code;
    }

    /// Compute total message length for a given data size.
    pub const fn msg_len(data_len: usize) -> usize {
        offsets::MSG_APCI + 10 + data_len
    }

    /// Message length for an error response (header + 1 byte return code).
    pub const ERROR_MSG_LEN: usize = offsets::MSG_APCI + 11;
}

// ============================================================================
// WriteConRes Writer
// ============================================================================

/// Writer for `A_PropertyExtValue_WriteConRes` (0xCF).
///
/// The response echoes the header fields and carries a return code.
/// On success, count echoes the request count and data is the written values.
/// On error, count=0 and a 1-byte return code follows.
pub struct PropertyExtValueWriteConRes;

impl PropertyExtValueWriteConRes {
    /// Write a success response echoing back written data.
    pub fn write_success(
        buf: &mut [u8],
        object_type: u16,
        object_instance: u16,
        prop_id: u8,
        count: u8,
        start_idx: u16,
        return_code: u8,
    ) {
        PropertyExtValueHeader::write_header(buf, object_type, object_instance, prop_id, count, start_idx);
        buf[offsets::MSG_APCI + 10] = return_code;
    }

    /// Write an error response: count=0, 1-byte return code.
    pub fn write_error(
        buf: &mut [u8],
        object_type: u16,
        object_instance: u16,
        prop_id: u8,
        start_idx: u16,
        return_code: u8,
    ) {
        PropertyExtValueHeader::write_header(buf, object_type, object_instance, prop_id, 0, start_idx);
        buf[offsets::MSG_APCI + 10] = return_code;
    }

    /// Message length for a WriteConRes (header + 1 byte return code).
    pub const MSG_LEN: usize = offsets::MSG_APCI + 11;
}

// ============================================================================
// Return Codes (spec section 3.4.5.5)
// ============================================================================

/// Return codes for extended property service responses.
///
/// These are defined in spec 03_03_07 section 3.4.5.5 "Return Codes".
#[allow(dead_code)]
pub mod return_code {
    pub const E_SUCCESS: u8 = 0x00;
    pub const E_ACCESS_WRITE_ONLY: u8 = 0xFA;
    pub const E_ACCESS_READ_ONLY: u8 = 0xFB;
    pub const E_ACCESS_DENIED: u8 = 0xFC;
    pub const E_ADDRESS_VOID: u8 = 0xFD;
    pub const E_DATA_TYPE_CONFLICT: u8 = 0xFE;
    pub const E_ERROR: u8 = 0xFF;
    pub const E_LENGTH_EXCEEDS_MAX_APDU_LENGTH: u8 = 0xF4;
    pub const E_DATA_OVERFLOW: u8 = 0xF5;
    pub const E_DATA_MIN: u8 = 0xF6;
    pub const E_DATA_MAX: u8 = 0xF7;
    pub const E_DATA_VOID: u8 = 0xF8;
    pub const E_TEMPORARILY_NOT_AVAILABLE: u8 = 0xF9;
    pub const E_MEMORY_ERROR: u8 = 0xF1;
}

// ============================================================================
// Function Property Extended Header
// ============================================================================

/// Parsed header from extended function property service PDUs.
///
/// Used by `A_FunctionPropertyExtCommand`, `A_FunctionPropertyExtState_Read`,
/// and `A_FunctionPropertyExtState_Response`.
///
/// ## Wire format (APDU-relative offsets)
///
/// ```text
/// [0-1]: APCI
/// [2-3]: interface_object_type (u16 big-endian)
/// [4-5]: object_instance (u16 big-endian)
/// [6]:   property_id
/// [7+]:  data (command/state-read) or return_code + data (response)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FunctionPropertyExtHeader {
    pub object_type: u16,
    pub object_instance: u16,
    pub prop_id: u8,
}

impl FunctionPropertyExtHeader {
    /// Minimum message length (APCI + IOT + instance + PID, no data).
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 7;

    /// Parse the fixed header from a full message buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        let base = offsets::MSG_APCI;
        Some(Self {
            object_type: u16::from_be_bytes([buf[base + 2], buf[base + 3]]),
            object_instance: u16::from_be_bytes([buf[base + 4], buf[base + 5]]),
            prop_id: buf[base + 6],
        })
    }

    /// Service data following the header (for Command / StateRead).
    pub fn data<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let start = offsets::MSG_APCI + 7;
        if buf.len() > start { &buf[start..] } else { &[] }
    }

    /// Write the header fields into a buffer.
    pub fn write_header(buf: &mut [u8], object_type: u16, object_instance: u16, prop_id: u8) {
        let base = offsets::MSG_APCI;
        let ot = object_type.to_be_bytes();
        buf[base + 2] = ot[0];
        buf[base + 3] = ot[1];
        let oi = object_instance.to_be_bytes();
        buf[base + 4] = oi[0];
        buf[base + 5] = oi[1];
        buf[base + 6] = prop_id;
    }
}

/// Writer for `A_FunctionPropertyExtState_Response`.
pub struct FunctionPropertyExtResponse;

impl FunctionPropertyExtResponse {
    /// Write a response with return code and optional data.
    pub fn write(
        buf: &mut [u8],
        object_type: u16,
        object_instance: u16,
        prop_id: u8,
        return_code: u8,
        data: &[u8],
    ) {
        FunctionPropertyExtHeader::write_header(buf, object_type, object_instance, prop_id);
        buf[offsets::MSG_APCI + 7] = return_code;
        if !data.is_empty() {
            let start = offsets::MSG_APCI + 8;
            buf[start..start + data.len()].copy_from_slice(data);
        }
    }

    /// Write a response with no return_code and no data (non-function PDT error).
    pub fn write_empty(buf: &mut [u8], object_type: u16, object_instance: u16, prop_id: u8) {
        FunctionPropertyExtHeader::write_header(buf, object_type, object_instance, prop_id);
    }

    /// Message length for a response with the given data size.
    pub const fn msg_len(data_len: usize) -> usize {
        offsets::MSG_APCI + 8 + data_len
    }

    /// Message length for an empty response (no return_code, no data).
    pub const EMPTY_MSG_LEN: usize = offsets::MSG_APCI + 7;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parse_roundtrip() {
        let mut buf = [0u8; 24];
        PropertyExtValueResponse::write(&mut buf, 0x0011, 0x0010, 56, 1, 42, &[0xAB, 0xCD]);

        let hdr = PropertyExtValueHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.object_type, 0x0011);
        assert_eq!(hdr.object_instance, 0x0010);
        assert_eq!(hdr.prop_id, 56);
        assert_eq!(hdr.count, 1);
        assert_eq!(hdr.start_idx, 42);
        assert_eq!(&hdr.data(&buf)[..2], &[0xAB, 0xCD]);
    }

    #[test]
    fn error_response_format() {
        let mut buf = [0u8; 20];
        PropertyExtValueResponse::write_error(&mut buf, 0x0011, 0x0010, 12, 1, return_code::E_ADDRESS_VOID);

        let hdr = PropertyExtValueHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.object_type, 0x0011);
        assert_eq!(hdr.object_instance, 0x0010);
        assert_eq!(hdr.prop_id, 12);
        assert_eq!(hdr.count, 0); // error indicator
        assert_eq!(hdr.start_idx, 1);
        assert_eq!(hdr.data(&buf)[0], return_code::E_ADDRESS_VOID);
    }

    #[test]
    fn write_con_res_error() {
        let mut buf = [0u8; 20];
        PropertyExtValueWriteConRes::write_error(&mut buf, 0x0000, 0x0001, 54, 1, return_code::E_ACCESS_DENIED);

        let hdr = PropertyExtValueHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.count, 0);
        assert_eq!(hdr.data(&buf)[0], return_code::E_ACCESS_DENIED);
    }

    #[test]
    fn write_con_res_success() {
        let mut buf = [0u8; 20];
        PropertyExtValueWriteConRes::write_success(&mut buf, 0x0011, 0x0010, 56, 1, 1, return_code::E_SUCCESS);

        let hdr = PropertyExtValueHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.count, 1);
        assert_eq!(hdr.data(&buf)[0], return_code::E_SUCCESS);
    }

    #[test]
    fn count_and_start_full_range() {
        let mut buf = [0u8; 20];
        // Max 8-bit count (255) and max 16-bit start (65535)
        PropertyExtValueResponse::write(&mut buf, 0, 0, 0, 255, 65535, &[]);
        let hdr = PropertyExtValueHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.count, 255);
        assert_eq!(hdr.start_idx, 65535);
    }

    #[test]
    fn header_too_short() {
        let buf = [0u8; 10]; // Needs at least MSG_APCI + 10 = 16
        assert!(PropertyExtValueHeader::parse(&buf).is_none());
    }

    #[test]
    fn data_accessor_empty() {
        let buf = [0u8; 16]; // Exactly header size, no data
        let hdr = PropertyExtValueHeader::parse(&buf).expect("parse should succeed");
        assert!(hdr.data(&buf).is_empty());
    }
}
