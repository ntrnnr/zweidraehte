//! Group value service APDUs (`A_GroupValue_Read`, `A_GroupValue_Write`,
//! `A_GroupValue_Response`).
//!
//! GroupValue services use short APCIs (10-bit). For payloads up to 6 bits
//! the value is packed into the low 6 bits of the second APCI byte so the
//! whole APDU fits within two bytes; larger payloads follow after the APCI
//! in the APDU area. The short/long distinction is encoded in the
//! communication object descriptor (clause 4.18.6.2 of spec 03/05/01) and
//! does not change the APCI code itself.
//!
//! All writers here assume the caller has already populated the APCI code
//! via `MessageBuilder::with_application(...)`; they only fill in the
//! service-specific payload bytes and return the on-wire message length.

use crate::messages::knx::offsets;

// ============================================================================
// GroupValueEncoding
// ============================================================================

/// Encoding used when serialising a `GroupValue_Write` or `_Response` APDU.
///
/// Small values (≤ 6 bits) can be packed into the low bits of the second
/// APCI byte, saving a whole APDU byte on the wire — valid only for
/// communication objects whose DPT fits in 6 bits (booleans, 3-bit
/// control, dimming steps, ...). The full encoding places the value in
/// one or more APDU bytes after the APCI field.
///
/// The encoding is determined by the communication object descriptor and
/// is chosen at the call site; the serializers in this module respect the
/// caller's choice and do not infer it from the data length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GroupValueEncoding {
    /// Pack `data[0] & 0x3F` into the low 6 bits of the second APCI byte.
    /// Only valid for single-byte values where the top 2 bits are zero.
    Short,
    /// Place the value in one or more APDU bytes after the APCI byte.
    Full,
}

// ============================================================================
// GroupValueRead
// ============================================================================

/// Writer for `A_GroupValue_Read` requests.
///
/// The APDU carries no payload beyond the short APCI code — the builder's
/// `with_application(GroupValueRead)` already populates everything needed.
/// This type exists so the three call sites can compute the length through
/// a single symbol instead of recomputing `offsets::MSG_APCI + 1 + 1`.
pub struct GroupValueReadRequest;

impl GroupValueReadRequest {
    /// On-wire length of an `A_GroupValue_Read` message, in bytes.
    ///
    /// The short APCI occupies the upper 4 bits of `MSG_APCI + 1`; the low
    /// 6 bits are zero for a plain read. One byte after the APCI position
    /// is enough to hold the APCI itself — no data payload.
    pub const MSG_LEN: usize = offsets::MSG_APCI + 1 + 1;

    /// No-op payload writer, kept for symmetry with the write counterparts.
    ///
    /// `MessageBuilder::with_application(GroupValueRead)` leaves the buffer
    /// in the correct state; this function exists so call sites use a
    /// uniform `MessageBuilder::with_application(...).with_data(|buf|
    /// GroupValueReadRequest::write(buf))` shape.
    pub fn write(_buf: &mut [u8]) {}
}

// ============================================================================
// GroupValueWrite / GroupValueResponse
// ============================================================================

/// Writer for `A_GroupValue_Write` requests.
///
/// Two separate entry points for the two encodings, rather than an enum
/// parameter, so each call site selects the right length constant at
/// compile time and the short path can't be fed a multi-byte payload by
/// accident.
///
/// The caller has already set the APCI code via
/// `MessageBuilder::with_application(GroupValueWrite)`; these writers
/// only fill in the payload bytes.
pub struct GroupValueWriteRequest;

impl GroupValueWriteRequest {
    /// On-wire length for a short-encoded `A_GroupValue_Write`.
    ///
    /// The value shares its byte with the APCI code, so the APDU ends
    /// right after `MSG_APCI + 1`.
    pub const SHORT_MSG_LEN: usize = offsets::MSG_APCI + 1 + 1;

    /// On-wire length for a full-encoded `A_GroupValue_Write` carrying
    /// `data_len` payload bytes after the APCI.
    pub const fn full_msg_len(data_len: usize) -> usize {
        offsets::MSG_APDU + data_len
    }

    /// Write a short-encoded value: the low 6 bits of `value` are OR-ed
    /// into the second APCI byte, preserving the APCI code bits that the
    /// builder already wrote into the high 4 bits.
    pub fn write_short(buf: &mut [u8], value: u8) {
        buf[offsets::MSG_APCI + 1] |= value & 0x3F;
    }

    /// Write a full-encoded payload verbatim at the start of the APDU
    /// area (`offsets::MSG_APDU`). The slice length drives the copy — no
    /// padding, no length prefix.
    pub fn write_full(buf: &mut [u8], data: &[u8]) {
        buf[offsets::MSG_APDU..offsets::MSG_APDU + data.len()].copy_from_slice(data);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Short-encoded write packs the low 6 bits of the value into the APCI
    /// byte without disturbing the bits the APCI code owns.
    #[test]
    fn short_write_ors_into_apci() {
        let mut buf = [0u8; 16];
        // Simulate `with_application(GroupValueWrite)` having set bits 7..4
        // of the second APCI byte (0b1000_0000 is the GroupValueWrite short
        // code high-nibble in this stack's encoding).
        buf[offsets::MSG_APCI + 1] = 0x80;
        GroupValueWriteRequest::write_short(&mut buf, 0x2A);
        assert_eq!(buf[offsets::MSG_APCI + 1], 0x80 | 0x2A);
    }

    /// Short-encoded write masks off bits above 6 so the APCI code region
    /// stays intact even if a caller passes a raw byte with high bits set.
    #[test]
    fn short_write_masks_high_bits() {
        let mut buf = [0u8; 16];
        buf[offsets::MSG_APCI + 1] = 0x80;
        GroupValueWriteRequest::write_short(&mut buf, 0xFF);
        assert_eq!(buf[offsets::MSG_APCI + 1], 0x80 | 0x3F);
    }

    /// Full-encoded write copies the payload verbatim starting at MSG_APDU.
    #[test]
    fn full_write_copies_payload() {
        let mut buf = [0u8; 32];
        GroupValueWriteRequest::write_full(&mut buf, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(&buf[offsets::MSG_APDU..offsets::MSG_APDU + 4], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn msg_len_constants() {
        assert_eq!(GroupValueReadRequest::MSG_LEN, offsets::MSG_APCI + 2);
        assert_eq!(GroupValueWriteRequest::SHORT_MSG_LEN, offsets::MSG_APCI + 2);
        assert_eq!(GroupValueWriteRequest::full_msg_len(4), offsets::MSG_APDU + 4);
    }
}
