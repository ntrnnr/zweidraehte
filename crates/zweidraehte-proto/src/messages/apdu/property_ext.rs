//! Extended property service APDUs (`A_PropertyExtValue_*`).
//!
//! AN163 "Extended Interface Object Addressing" services. These use
//! `(interface_object_type, object_instance)` addressing to reach
//! Interface Objects that cannot be enumerated in the 8-bit
//! `object_index` space of the regular property services.
//!
//! ## Wire format
//!
//! Per KNX spec 03_03_07 §3.4.3.2 / §3.4.5.1 (see Figure 44, 49). The
//! `object_instance` and `property_id` fields are each **12 bits** and
//! share three bytes back-to-back:
//!
//! ```text
//! APCI-relative offset:
//! [0-1]: APCI (escaped, 10-bit)
//! [2-3]: interface_object_type (u16 big-endian)
//! [4]:   object_instance[11..4]              (high 8 bits)
//! [5]:   object_instance[3..0] | property_id[11..8]
//! [6]:   property_id[7..0]                   (low 8 bits)
//! [7]:   nr_of_elem                          (Value services only)
//! [8-9]: start_index (u16 big-endian)        (Value services only)
//! [10+]: data payload / return_code
//! ```
//!
//! Per spec 03_05_01 §4.18.5.2.5, `object_instance` **starts with 1**
//! for the first Interface Object of each type and ascends with the
//! local object index.
//!
//! The older test templates that inject raw wire bytes like
//! `... 00 10 0C ...` decode correctly under this layout:
//! `object_instance = 0x001`, `property_id = 0x00C`.
//!
//! ## Other differences from regular property services
//!
//! - `nr_of_elem` is 8 bits (regular: 4 bits packed with `start_index`).
//! - `start_index` is 16 bits (regular: 12 bits packed with `nr_of_elem`).
//! - Error responses carry a 1-byte return code instead of `count == 0`.

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
    /// 12-bit object instance (valid range 0x001..=0xFFF per spec
    /// 03_05_01 §4.18.5.2.5).
    pub object_instance: u16,
    /// 12-bit property identifier (valid range 0..=0xFFF per spec
    /// 03_03_07 §3.4.3.2). Carried as `u16` even though every
    /// currently-defined KNX PID fits in one byte.
    pub prop_id: u16,
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
        let (object_instance, prop_id) = unpack_instance_and_pid(buf[base + 4], buf[base + 5], buf[base + 6]);
        Some(Self {
            object_type: u16::from_be_bytes([buf[base + 2], buf[base + 3]]),
            object_instance,
            prop_id,
            count: buf[base + 7],
            start_idx: u16::from_be_bytes([buf[base + 8], buf[base + 9]]),
        })
    }

    /// Return a slice over the data payload following the header.
    pub fn data<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let start = offsets::MSG_APCI + 10;
        if buf.len() > start { &buf[start..] } else { &[] }
    }

    /// Write the common header fields into a message buffer. Both
    /// `object_instance` and `prop_id` are masked to 12 bits.
    fn write_header(buf: &mut [u8], object_type: u16, object_instance: u16, prop_id: u16, count: u8, start_idx: u16) {
        let base = offsets::MSG_APCI;
        let ot = object_type.to_be_bytes();
        buf[base + 2] = ot[0];
        buf[base + 3] = ot[1];
        let [b4, b5, b6] = pack_instance_and_pid(object_instance, prop_id);
        buf[base + 4] = b4;
        buf[base + 5] = b5;
        buf[base + 6] = b6;
        buf[base + 7] = count;
        let si = start_idx.to_be_bytes();
        buf[base + 8] = si[0];
        buf[base + 9] = si[1];
    }
}

/// Split the three-byte `instance[11:0] | property_id[11:0]` packing
/// into its two 12-bit fields (spec 03_03_07 §3.4.3.2).
fn unpack_instance_and_pid(b4: u8, b5: u8, b6: u8) -> (u16, u16) {
    let object_instance = ((b4 as u16) << 4) | ((b5 as u16) >> 4);
    let property_id = (((b5 as u16) & 0x0F) << 8) | (b6 as u16);
    (object_instance, property_id)
}

/// Inverse of [`unpack_instance_and_pid`]. Both fields are masked to
/// 12 bits — excess bits are silently dropped (caller is expected to
/// validate input ranges when they matter).
fn pack_instance_and_pid(object_instance: u16, property_id: u16) -> [u8; 3] {
    let oi = object_instance & 0x0FFF;
    let pi = property_id & 0x0FFF;
    let b4 = (oi >> 4) as u8;
    let b5 = (((oi & 0x000F) << 4) | (pi >> 8)) as u8;
    let b6 = (pi & 0x00FF) as u8;
    [b4, b5, b6]
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
        prop_id: u16,
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
        prop_id: u16,
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
        prop_id: u16,
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
        prop_id: u16,
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
/// The wire layout of the common `(object_type, object_instance,
/// property_id)` prefix is the same as in
/// [`PropertyExtValueHeader`] — see that type's module docs for the
/// 12/12-bit packing of `object_instance | property_id`.
///
/// ## Wire format (APCI-relative offsets)
///
/// ```text
/// [0-1]: APCI
/// [2-3]: interface_object_type (u16 big-endian)
/// [4-5-6]: object_instance (12 bit) | property_id (12 bit)
/// [7+]:  data (command/state-read) or return_code + data (response)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FunctionPropertyExtHeader {
    pub object_type: u16,
    pub object_instance: u16,
    pub prop_id: u16,
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
        let (object_instance, prop_id) = unpack_instance_and_pid(buf[base + 4], buf[base + 5], buf[base + 6]);
        Some(Self { object_type: u16::from_be_bytes([buf[base + 2], buf[base + 3]]), object_instance, prop_id })
    }

    /// Service data following the header (for Command / StateRead).
    pub fn data<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let start = offsets::MSG_APCI + 7;
        if buf.len() > start { &buf[start..] } else { &[] }
    }

    /// Write the header fields into a buffer.
    pub fn write_header(buf: &mut [u8], object_type: u16, object_instance: u16, prop_id: u16) {
        let base = offsets::MSG_APCI;
        let ot = object_type.to_be_bytes();
        buf[base + 2] = ot[0];
        buf[base + 3] = ot[1];
        let [b4, b5, b6] = pack_instance_and_pid(object_instance, prop_id);
        buf[base + 4] = b4;
        buf[base + 5] = b5;
        buf[base + 6] = b6;
    }
}

/// Writer for `A_FunctionPropertyExtState_Response`.
pub struct FunctionPropertyExtResponse;

impl FunctionPropertyExtResponse {
    /// Write a response with return code and optional data.
    pub fn write(buf: &mut [u8], object_type: u16, object_instance: u16, prop_id: u16, return_code: u8, data: &[u8]) {
        FunctionPropertyExtHeader::write_header(buf, object_type, object_instance, prop_id);
        buf[offsets::MSG_APCI + 7] = return_code;
        if !data.is_empty() {
            let start = offsets::MSG_APCI + 8;
            buf[start..start + data.len()].copy_from_slice(data);
        }
    }

    /// Write a response with no return_code and no data (non-function PDT error).
    pub fn write_empty(buf: &mut [u8], object_type: u16, object_instance: u16, prop_id: u16) {
        FunctionPropertyExtHeader::write_header(buf, object_type, object_instance, prop_id);
    }

    /// Message length for a response with the given data size.
    pub const fn msg_len(data_len: usize) -> usize {
        offsets::MSG_APCI + 8 + data_len
    }

    /// Message length for an empty response (no return_code, no data).
    pub const EMPTY_MSG_LEN: usize = offsets::MSG_APCI + 7;
}

// ============================================================================
// Property Description (Extended) Header + Response Writer
// ============================================================================

/// Parsed request header for `A_PropertyExtDescription_Read`.
///
/// ## Wire format (APCI-relative offsets)
///
/// ```text
/// [0-1]: APCI (0x01D2)
/// [2-3]: interface_object_type (u16 big-endian)
/// [4-6]: object_instance (12 bit) | property_id (12 bit)
/// [7]:   desc_type (high nibble) | prop_idx[11:8] (low nibble)
/// [8]:   prop_idx[7:0]
/// ```
///
/// Per spec 03_03_07 §3.4.3.3, `prop_id == 0` means "look up by
/// `prop_idx`" (property-scanning path). A non-zero `prop_id`
/// addresses a specific property and `prop_idx` is ignored by the
/// responder.
#[derive(Debug, Clone, Copy)]
pub struct PropertyExtDescriptionHeader {
    pub object_type: u16,
    pub object_instance: u16,
    pub prop_id: u16,
    /// 4-bit property description type selector.
    pub desc_type: u8,
    /// 12-bit property index (used when `prop_id == 0`).
    pub prop_idx: u16,
}

impl PropertyExtDescriptionHeader {
    /// Minimum message length: APCI + IOT + (inst|pid) + (desc_type|prop_idx).
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 9;

    /// Parse the fixed header from a full message buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        let base = offsets::MSG_APCI;
        let (object_instance, prop_id) = unpack_instance_and_pid(buf[base + 4], buf[base + 5], buf[base + 6]);
        let desc_type = buf[base + 7] >> 4;
        let prop_idx = (((buf[base + 7] & 0x0F) as u16) << 8) | buf[base + 8] as u16;
        Some(Self {
            object_type: u16::from_be_bytes([buf[base + 2], buf[base + 3]]),
            object_instance,
            prop_id,
            desc_type,
            prop_idx,
        })
    }
}

/// Writer for `A_PropertyExtDescription_Response` (APCI 0x01D3).
///
/// Response layout (APCI-relative, total fixed length 17 bytes from
/// `MSG_APCI`, i.e. 15 bytes of descriptor payload + 2 bytes APCI):
///
/// ```text
/// [0-1]: APCI
/// [2-3]: interface_object_type (echoed)
/// [4-6]: object_instance | response_pid (12/12-bit packed)
/// [7]:   desc_type (success: 0) | prop_idx[11:8]
/// [8]:   prop_idx[7:0]
/// [9]:   writeable (bit 7) | PDT[5:0]
/// [10-11]: PDT[hi 4] | max_elements[11:0]  (big-endian)
/// [12]:  read_level (high nibble) | write_level (low nibble)
/// [13-15]: reserved, zero
/// ```
///
/// Error responses echo the request's wire `prop_id`, `desc_type`
/// and `prop_idx` bytes; `[9..=15]` are zeroed.
pub struct PropertyExtDescriptionResponse;

impl PropertyExtDescriptionResponse {
    /// Total message length including APCI. The response is fixed-size.
    pub const MSG_LEN: usize = offsets::MSG_APCI + 17;

    /// Write a successful description response. `prop_id` is typically
    /// `desc.prop_id` (resolved by the responder, not echoed from the
    /// request) and `prop_idx` likewise comes from `desc`.
    pub fn write(
        buf: &mut [u8],
        object_type: u16,
        object_instance: u16,
        desc: &crate::properties::PropertyDescriptionResponse,
    ) {
        let base = offsets::MSG_APCI;
        write_ext_description_prefix(buf, object_type, object_instance, desc.prop_id);

        // desc_type (high nibble = 0 on success) | prop_idx[11:8].
        buf[base + 7] = (desc.prop_idx >> 8) as u8 & 0x0F;
        buf[base + 8] = desc.prop_idx as u8;

        // Writeable (bit 7) | PDT[5:0].
        buf[base + 9] = if desc.writeable { 0x80 } else { 0x00 } | (desc.pdt & 0x3F);

        // PDT[hi 4] | max_elements[11:0].
        let pdt_max = ((desc.pdt as u16 & 0x3F) << 12) | (desc.max_elements & 0x0FFF);
        buf[base + 10] = (pdt_max >> 8) as u8;
        buf[base + 11] = pdt_max as u8;

        // Access levels (read in high nibble, write in low nibble).
        buf[base + 12] = (desc.read_level << 4) | desc.write_level;

        // Reserved / padding to 16-byte APDU.
        for i in (base + 13)..(base + 16) {
            buf[i] = 0;
        }
    }

    /// Write an error response. The request's `prop_id`, `desc_type`,
    /// and `prop_idx` are echoed verbatim; all descriptor fields are
    /// zero.
    pub fn write_error(
        buf: &mut [u8],
        object_type: u16,
        object_instance: u16,
        prop_id: u16,
        desc_type: u8,
        prop_idx: u16,
    ) {
        let base = offsets::MSG_APCI;
        write_ext_description_prefix(buf, object_type, object_instance, prop_id);

        buf[base + 7] = ((desc_type & 0x0F) << 4) | ((prop_idx >> 8) as u8 & 0x0F);
        buf[base + 8] = prop_idx as u8;

        for i in (base + 9)..(base + 16) {
            buf[i] = 0;
        }
    }
}

/// Shared prefix writer for the Extended Description response —
/// octets [2..=6]: `object_type | instance | prop_id`.
fn write_ext_description_prefix(buf: &mut [u8], object_type: u16, object_instance: u16, prop_id: u16) {
    let base = offsets::MSG_APCI;
    let ot = object_type.to_be_bytes();
    buf[base + 2] = ot[0];
    buf[base + 3] = ot[1];
    let [b4, b5, b6] = pack_instance_and_pid(object_instance, prop_id);
    buf[base + 4] = b4;
    buf[base + 5] = b5;
    buf[base + 6] = b6;
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::messages::knx::offsets;

    #[test]
    fn header_parse_roundtrip() {
        let mut buf = [0u8; 24];
        PropertyExtValueResponse::write(&mut buf, 0x0011, 0x001, 56, 1, 42, &[0xAB, 0xCD]);

        let hdr = PropertyExtValueHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.object_type, 0x0011);
        assert_eq!(hdr.object_instance, 0x001);
        assert_eq!(hdr.prop_id, 56);
        assert_eq!(hdr.count, 1);
        assert_eq!(hdr.start_idx, 42);
        assert_eq!(&hdr.data(&buf)[..2], &[0xAB, 0xCD]);
    }

    /// Reference decode: raw bytes `00 10 0C` (as seen in the conformance
    /// test templates) must split into `object_instance = 1`,
    /// `property_id = 0x0C` per spec 03_03_07 §3.4.3.2.
    #[test]
    fn first_instance_wire_format() {
        let mut buf = [0u8; 24];
        let base = offsets::MSG_APCI;
        // object_type = 0 (Device), instance bytes = 00 10, pid byte = 0x0C.
        buf[base + 2] = 0x00;
        buf[base + 3] = 0x00;
        buf[base + 4] = 0x00;
        buf[base + 5] = 0x10;
        buf[base + 6] = 0x0C;
        buf[base + 7] = 1;
        buf[base + 8] = 0x00;
        buf[base + 9] = 0x01;

        let hdr = PropertyExtValueHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.object_type, 0x0000);
        assert_eq!(hdr.object_instance, 0x001);
        assert_eq!(hdr.prop_id, 0x0C);
    }

    /// Full 12-bit PID range must round-trip correctly, since the spec
    /// allows PIDs up to 0xFFF and conformance test 4.1.4 exercises PID 0x800
    /// as a "non-existing PID" negative case.
    #[test]
    fn property_id_full_12bit_range_roundtrip() {
        let mut buf = [0u8; 20];
        PropertyExtValueResponse::write(&mut buf, 0, 1, 0x0FFF, 0, 0, &[]);
        let hdr = PropertyExtValueHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.object_instance, 1);
        assert_eq!(hdr.prop_id, 0x0FFF);

        // Reference decode from the 4.1.4 wire: bytes 00 18 00
        // mean instance=1, property_id=0x800.
        let base = offsets::MSG_APCI;
        buf = [0u8; 20];
        buf[base + 4] = 0x00;
        buf[base + 5] = 0x18;
        buf[base + 6] = 0x00;
        let hdr = PropertyExtValueHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.object_instance, 1);
        assert_eq!(hdr.prop_id, 0x800);
    }

    #[test]
    fn error_response_format() {
        let mut buf = [0u8; 20];
        PropertyExtValueResponse::write_error(&mut buf, 0x0011, 0x001, 12, 1, return_code::E_ADDRESS_VOID);

        let hdr = PropertyExtValueHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.object_type, 0x0011);
        assert_eq!(hdr.object_instance, 0x001);
        assert_eq!(hdr.prop_id, 12);
        assert_eq!(hdr.count, 0); // error indicator
        assert_eq!(hdr.start_idx, 1);
        assert_eq!(hdr.data(&buf)[0], return_code::E_ADDRESS_VOID);
    }

    #[test]
    fn write_con_res_error() {
        let mut buf = [0u8; 20];
        PropertyExtValueWriteConRes::write_error(&mut buf, 0x0000, 0x001, 54, 1, return_code::E_ACCESS_DENIED);

        let hdr = PropertyExtValueHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.count, 0);
        assert_eq!(hdr.data(&buf)[0], return_code::E_ACCESS_DENIED);
    }

    #[test]
    fn write_con_res_success() {
        let mut buf = [0u8; 20];
        PropertyExtValueWriteConRes::write_success(&mut buf, 0x0011, 0x001, 56, 1, 1, return_code::E_SUCCESS);

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
    fn instance_full_12bit_range_roundtrip() {
        let mut buf = [0u8; 20];
        PropertyExtValueResponse::write(&mut buf, 0, 0x0FFF, 200, 0, 0, &[]);
        let hdr = PropertyExtValueHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.object_instance, 0x0FFF);
        assert_eq!(hdr.prop_id, 200);
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

    // ========================================================================
    // PropertyExtDescription header + response writer
    // ========================================================================

    /// Parse a request with `desc_type = 0xA`, `prop_idx = 0x123`, and
    /// a 12-bit `prop_id`. Octets 7/8 pack `desc_type | prop_idx`.
    #[test]
    fn ext_description_header_parse_roundtrip() {
        let mut buf = [0u8; 24];
        let base = offsets::MSG_APCI;
        buf[base + 2] = 0x00;
        buf[base + 3] = 0x11;
        // instance = 1, prop_id = 0x0C.
        buf[base + 4] = 0x00;
        buf[base + 5] = 0x10;
        buf[base + 6] = 0x0C;
        // desc_type = 0xA, prop_idx = 0x123.
        buf[base + 7] = 0xA1;
        buf[base + 8] = 0x23;

        let hdr = PropertyExtDescriptionHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.object_type, 0x0011);
        assert_eq!(hdr.object_instance, 0x001);
        assert_eq!(hdr.prop_id, 0x00C);
        assert_eq!(hdr.desc_type, 0xA);
        assert_eq!(hdr.prop_idx, 0x123);
    }

    #[test]
    fn ext_description_response_success_bytes() {
        let mut buf = [0u8; 24];
        let desc = crate::properties::PropertyDescriptionResponse {
            object_idx: 0,
            prop_id: 0x0B,
            prop_idx: 0x008,
            writeable: true,
            pdt: 0x17,
            max_elements: 0x123,
            read_level: 2,
            write_level: 1,
        };
        PropertyExtDescriptionResponse::write(&mut buf, 0x0000, 0x001, &desc);

        let base = offsets::MSG_APCI;
        // object_type echoed big-endian.
        assert_eq!(buf[base + 2], 0x00);
        assert_eq!(buf[base + 3], 0x00);
        // instance=1, response_pid=0x00B packed.
        assert_eq!(buf[base + 4], 0x00);
        assert_eq!(buf[base + 5], 0x10);
        assert_eq!(buf[base + 6], 0x0B);
        // desc_type = 0 on success, prop_idx[11:8] = 0 (prop_idx = 0x008).
        assert_eq!(buf[base + 7], 0x00);
        assert_eq!(buf[base + 8], 0x08);
        // writeable | pdt[5:0].
        assert_eq!(buf[base + 9], 0x80 | 0x17);
        // pdt[hi 4] | max_elements[11:0] big-endian. pdt=0x17 & 0x3F = 0x17
        // → (0x17 << 12) & 0xFFFF = 0x7000; combined with 0x123 = 0x7123.
        assert_eq!(buf[base + 10], 0x71);
        assert_eq!(buf[base + 11], 0x23);
        // read=2 | write=1.
        assert_eq!(buf[base + 12], 0x21);
        // Padding zero.
        for i in (base + 13)..(base + 16) {
            assert_eq!(buf[i], 0, "padding byte {} non-zero", i);
        }
    }

    #[test]
    fn ext_description_response_error_echoes_request() {
        let mut buf = [0u8; 24];
        PropertyExtDescriptionResponse::write_error(&mut buf, 0x0000, 0x001, 0x0800, 0x5, 0x0AB);

        let base = offsets::MSG_APCI;
        // Echo prop_id = 0x800: instance=1 | pid=0x800 packed.
        assert_eq!(buf[base + 4], 0x00);
        assert_eq!(buf[base + 5], 0x18);
        assert_eq!(buf[base + 6], 0x00);
        // desc_type=5, prop_idx=0x0AB.
        assert_eq!(buf[base + 7], 0x50);
        assert_eq!(buf[base + 8], 0xAB);
        // Descriptor fields zeroed.
        for i in (base + 9)..(base + 16) {
            assert_eq!(buf[i], 0, "descriptor byte {} non-zero on error", i);
        }
    }

    #[test]
    fn ext_description_prop_idx_full_12bit_range() {
        let mut buf = [0u8; 24];
        let base = offsets::MSG_APCI;
        buf[base + 7] = 0xFF;
        buf[base + 8] = 0xFF;
        let hdr = PropertyExtDescriptionHeader::parse(&buf).expect("parse should succeed");
        assert_eq!(hdr.desc_type, 0xF);
        assert_eq!(hdr.prop_idx, 0xFFF);
    }

    #[test]
    fn ext_description_response_msg_len_const() {
        assert_eq!(PropertyExtDescriptionResponse::MSG_LEN, offsets::MSG_APCI + 17);
    }
}
