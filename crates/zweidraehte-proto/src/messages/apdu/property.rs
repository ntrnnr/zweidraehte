//! Property service APDUs (`A_PropertyValue_*`, `A_PropertyDescription_*`).
//!
//! Property services use an "escaped" APCI (full 10-bit code in bytes 0-1),
//! so data starts cleanly at APDU byte 2 with no APCI bit overlap.

use crate::messages::knx::offsets;

// ============================================================================
// PropertyValue (Read / Response / Write)
// ============================================================================

/// Parsed header from `A_PropertyValue_Read`, `A_PropertyValue_Write`, or
/// `A_PropertyValue_Response`.
///
/// ## Wire format
///
/// ```text
/// APDU[0-1]: APCI
/// APDU[2]:   Object Index
/// APDU[3]:   Property ID
/// APDU[4-5]: Count (4 bits) | StartIndex (12 bits), big-endian
/// APDU[6..]: Data (variable, present in Write and Response)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyValueHeader {
    pub object_idx: u16,
    pub prop_id: u16,
    pub count: u16,
    pub start_idx: u16,
}

impl PropertyValueHeader {
    /// Header length after the two APCI octets have been removed.
    pub const PAYLOAD_HEADER_LEN: usize = 4;
    /// Minimum message length for a PropertyValue header (no data payload).
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 2 + Self::PAYLOAD_HEADER_LEN;

    /// Parse the fixed header from a full message buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        Self::parse_payload(buf.get(offsets::MSG_APCI + 2..)?)
    }

    /// Parse the fixed header from an APCI-stripped APDU payload.
    ///
    /// This is the boundary used by stacks that decode TPCI/APCI before
    /// dispatch instead of retaining one full internal message buffer.
    pub fn parse_payload(payload: &[u8]) -> Option<Self> {
        let header = payload.get(..Self::PAYLOAD_HEADER_LEN)?;
        let count_start = u16::from_be_bytes([header[2], header[3]]);
        Some(Self {
            object_idx: u16::from(header[0]),
            prop_id: u16::from(header[1]),
            count: count_start >> 12,
            start_idx: count_start & 0x0FFF,
        })
    }

    /// Return a slice over the data payload following the header (for Write messages).
    pub fn data<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.payload_data(buf.get(offsets::MSG_APCI + 2..).unwrap_or_default())
    }

    /// Return the data following this header in an APCI-stripped payload.
    pub fn payload_data<'a>(&self, payload: &'a [u8]) -> &'a [u8] {
        payload.get(Self::PAYLOAD_HEADER_LEN..).unwrap_or_default()
    }

    /// Encode the fixed part of an APCI-stripped property-value payload.
    pub fn encode_payload(object_idx: u8, prop_id: u16, count: u16, start_idx: u16) -> [u8; Self::PAYLOAD_HEADER_LEN] {
        let [count_start_hi, count_start_lo] = Self::pack_count_start(count, start_idx);
        [object_idx, prop_id as u8, count_start_hi, count_start_lo]
    }

    /// Encode count (4 bits) and start_idx (12 bits) into the packed big-endian
    /// format used on the wire.
    fn pack_count_start(count: u16, start_idx: u16) -> [u8; 2] {
        let packed = (count << 12) | (start_idx & 0x0FFF);
        packed.to_be_bytes()
    }
}

/// Writer for `A_PropertyValue_Response`.
pub struct PropertyValueResponse;

impl PropertyValueResponse {
    /// Write a successful response header and data payload.
    pub fn write(buf: &mut [u8], object_idx: u8, prop_id: u16, count: u16, start_idx: u16, data: &[u8]) {
        let header = PropertyValueHeader::encode_payload(object_idx, prop_id, count, start_idx);
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 6].copy_from_slice(&header);
        if !data.is_empty() {
            let start = offsets::MSG_APCI + 6;
            buf[start..start + data.len()].copy_from_slice(data);
        }
    }

    /// Write an error response (count = 0, no data payload).
    pub fn write_error(buf: &mut [u8], object_idx: u8, prop_id: u16, start_idx: u16) {
        let header = PropertyValueHeader::encode_payload(object_idx, prop_id, 0, start_idx);
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 6].copy_from_slice(&header);
    }

    /// Compute total message length for a given data size.
    pub const fn msg_len(data_len: usize) -> usize {
        offsets::MSG_APCI + 6 + data_len
    }

    /// Message length for an error response (header only, no data).
    pub const ERROR_MSG_LEN: usize = offsets::MSG_APCI + 6;
}

// ============================================================================
// PropertyDescription (Read / Response)
// ============================================================================

/// Parsed fields from `A_PropertyDescription_Read`.
///
/// ## Wire format
///
/// ```text
/// APDU[0-1]: APCI
/// APDU[2]:   Object Index
/// APDU[3]:   Property ID (0 = search by prop_idx)
/// APDU[4]:   Property Index
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyDescriptionRead {
    pub object_idx: u16,
    pub prop_id: u16,
    pub prop_idx: u8,
}

impl PropertyDescriptionRead {
    /// Request length after the two APCI octets have been removed.
    pub const PAYLOAD_LEN: usize = 3;
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 2 + Self::PAYLOAD_LEN;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        Self::parse_payload(buf.get(offsets::MSG_APCI + 2..)?)
    }

    /// Parse an `A_PropertyDescription_Read` after APCI removal.
    pub fn parse_payload(payload: &[u8]) -> Option<Self> {
        let payload = payload.get(..Self::PAYLOAD_LEN)?;
        Some(Self { object_idx: u16::from(payload[0]), prop_id: u16::from(payload[1]), prop_idx: payload[2] })
    }

    /// Encode an APCI-stripped `A_PropertyDescription_Read` payload.
    pub const fn encode_payload(obj_idx: u8, prop_id: u16, prop_idx: u8) -> [u8; Self::PAYLOAD_LEN] {
        [obj_idx, prop_id as u8, prop_idx]
    }

    /// Write an `A_PropertyDescription_Read` request into a message buffer.
    pub fn write(buf: &mut [u8], obj_idx: u8, prop_id: u16, prop_idx: u8) {
        let payload = Self::encode_payload(obj_idx, prop_id, prop_idx);
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 5].copy_from_slice(&payload);
    }
}

/// Writer for `A_PropertyDescription_Response` error case.
///
/// The success case uses `PropertyDescription::encode()` from the interface
/// objects module, so only the error path needs a manual writer.
pub struct PropertyDescriptionResponse;

impl PropertyDescriptionResponse {
    /// Response length after the two APCI octets have been removed.
    pub const PAYLOAD_LEN: usize = 7;
    /// Message length (same for success and error — always 9 bytes of APDU).
    pub const MSG_LEN: usize = offsets::MSG_APCI + 2 + Self::PAYLOAD_LEN;

    /// Encode a negative APCI-stripped response payload.
    pub const fn encode_error_payload(object_idx: u8, prop_id: u16, prop_idx: u8) -> [u8; Self::PAYLOAD_LEN] {
        [object_idx, prop_id as u8, prop_idx, 0, 0, 0, 0]
    }

    /// Write an error response: echo back ObjIdx, PID, PropIdx; zero out
    /// descriptor fields.
    pub fn write_error(buf: &mut [u8], object_idx: u8, prop_id: u16, prop_idx: u8) {
        let payload = Self::encode_error_payload(object_idx, prop_id, prop_idx);
        buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 9].copy_from_slice(&payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_value_header_parse_roundtrip() {
        let mut buf = [0u8; 20];
        // Set up a PropertyValueRead/Write header
        PropertyValueResponse::write(&mut buf, 3, 56, 1, 42, &[0xAB, 0xCD]);

        let hdr = PropertyValueHeader::parse(&buf).unwrap();
        assert_eq!(hdr.object_idx, 3);
        assert_eq!(hdr.prop_id, 56);
        assert_eq!(hdr.count, 1);
        assert_eq!(hdr.start_idx, 42);
        assert_eq!(buf[offsets::MSG_APCI + 6], 0xAB);
        assert_eq!(buf[offsets::MSG_APCI + 7], 0xCD);
    }

    #[test]
    fn property_value_payload_codec_matches_full_message_codec() {
        let header_bytes = PropertyValueHeader::encode_payload(3, 56, 1, 0xABC);
        let payload = [header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3], 0x11, 0x22, 0x33];

        let header = PropertyValueHeader::parse_payload(&payload).expect("header parses");
        assert_eq!(header.object_idx, 3);
        assert_eq!(header.prop_id, 56);
        assert_eq!(header.count, 1);
        assert_eq!(header.start_idx, 0xABC);
        assert_eq!(header.payload_data(&payload), &[0x11, 0x22, 0x33]);

        let mut full = [0u8; 20];
        PropertyValueResponse::write(&mut full, 3, 56, 1, 0xABC, &[0x11, 0x22, 0x33]);
        assert_eq!(&full[offsets::MSG_APCI + 2..offsets::MSG_APCI + 9], &payload);
    }

    #[test]
    fn property_value_count_start_packing() {
        // count=15 (max 4-bit), start_idx=4095 (max 12-bit)
        let mut buf = [0u8; 12];
        PropertyValueResponse::write(&mut buf, 0, 0, 15, 4095, &[]);
        let hdr = PropertyValueHeader::parse(&buf).unwrap();
        assert_eq!(hdr.count, 15);
        assert_eq!(hdr.start_idx, 4095);
    }

    #[test]
    fn property_value_error_response() {
        let mut buf = [0u8; 12];
        PropertyValueResponse::write_error(&mut buf, 2, 99, 0xABC);
        let hdr = PropertyValueHeader::parse(&buf).unwrap();
        assert_eq!(hdr.object_idx, 2);
        assert_eq!(hdr.prop_id, 99);
        assert_eq!(hdr.count, 0); // error indicator
        assert_eq!(hdr.start_idx, 0xABC);
    }

    #[test]
    fn property_description_read_parse() {
        let mut buf = [0u8; 11];
        buf[offsets::MSG_APCI + 2] = 5;
        buf[offsets::MSG_APCI + 3] = 21;
        buf[offsets::MSG_APCI + 4] = 3;
        let req = PropertyDescriptionRead::parse(&buf).unwrap();
        assert_eq!(req.object_idx, 5);
        assert_eq!(req.prop_id, 21);
        assert_eq!(req.prop_idx, 3);
    }

    #[test]
    fn property_description_payload_codec_matches_full_message_codec() {
        let payload = PropertyDescriptionRead::encode_payload(5, 21, 3);
        assert_eq!(
            PropertyDescriptionRead::parse_payload(&payload),
            Some(PropertyDescriptionRead { object_idx: 5, prop_id: 21, prop_idx: 3 })
        );

        let mut full = [0u8; 11];
        PropertyDescriptionRead::write(&mut full, 5, 21, 3);
        assert_eq!(&full[offsets::MSG_APCI + 2..offsets::MSG_APCI + 5], &payload);
    }

    #[test]
    fn property_description_error_response() {
        let mut buf = [0u8; 15];
        PropertyDescriptionResponse::write_error(&mut buf, 5, 21, 3);
        assert_eq!(
            &buf[offsets::MSG_APCI + 2..offsets::MSG_APCI + 9],
            &PropertyDescriptionResponse::encode_error_payload(5, 21, 3)
        );
        assert_eq!(buf[offsets::MSG_APCI + 2], 5);
        assert_eq!(buf[offsets::MSG_APCI + 3], 21);
        assert_eq!(buf[offsets::MSG_APCI + 4], 3);
        // All descriptor fields should be zero
        assert_eq!(buf[offsets::MSG_APCI + 5], 0);
        assert_eq!(buf[offsets::MSG_APCI + 6], 0);
        assert_eq!(buf[offsets::MSG_APCI + 7], 0);
        assert_eq!(buf[offsets::MSG_APCI + 8], 0);
    }

    #[test]
    fn property_value_header_too_short() {
        let buf = [0u8; 5]; // Way too short
        assert!(PropertyValueHeader::parse(&buf).is_none());
    }

    #[test]
    fn property_value_data_accessor() {
        let mut buf = [0u8; 16];
        PropertyValueResponse::write(&mut buf, 0, 1, 1, 1, &[0x11, 0x22, 0x33]);
        let hdr = PropertyValueHeader::parse(&buf).unwrap();
        let data = hdr.data(&buf);
        assert_eq!(&data[..3], &[0x11, 0x22, 0x33]);
    }
}
