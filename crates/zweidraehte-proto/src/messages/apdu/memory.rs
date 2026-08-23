//! Memory service APDUs (`A_Memory_*`, `A_UserMemory_*`, `A_MemoryBit_Write`).
//!
//! Memory services use "short" APCIs where the data count shares bits with the
//! APCI code in byte 1. The write functions preserve the APCI high bits while
//! setting the count in the low bits.

use crate::messages::apdu::property_ext::PropertyReturnCode;
use crate::messages::knx::offsets;

// ============================================================================
// Memory (Read / Response / Write)
// ============================================================================

/// Parsed fields from `A_Memory_Read` or `A_Memory_Write`.
///
/// ## Wire format
///
/// ```text
/// APDU[0]:   High 2 bits of APCI
/// APDU[1]:   APCI variant | count (6 bits)
/// APDU[2-3]: Address (16-bit, big-endian)
/// APDU[4..]: Data (count bytes, Write only)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct MemoryAccess<'a> {
    pub count: u8,
    pub address: u16,
    pub data: &'a [u8],
}

impl<'a> MemoryAccess<'a> {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 4;

    /// Parse an `A_Memory_Read` (no data payload).
    pub fn parse_read(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(Self {
            count: buf[offsets::MSG_APCI + 1] & 0x3F,
            address: u16::from_be_bytes([buf[offsets::MSG_APCI + 2], buf[offsets::MSG_APCI + 3]]),
            data: &[],
        })
    }

    /// Parse an `A_Memory_Write` (includes data payload).
    pub fn parse_write(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        let count = buf[offsets::MSG_APCI + 1] & 0x3F;
        let address = u16::from_be_bytes([buf[offsets::MSG_APCI + 2], buf[offsets::MSG_APCI + 3]]);
        let data_start = offsets::MSG_APCI + 4;
        let data_end = core::cmp::min(buf.len(), data_start + count as usize);
        Some(Self { count, address, data: &buf[data_start..data_end] })
    }

    /// Check whether the total message length is consistent with the count field.
    pub fn is_length_consistent(&self, msg_len: usize) -> bool {
        msg_len == offsets::MSG_APCI + 4 + self.count as usize
    }
}

/// Writer for `A_Memory_Read` requests.
pub struct MemoryReadRequest;

impl MemoryReadRequest {
    /// Message length for a memory read request (no data payload).
    pub const MSG_LEN: usize = MemoryAccess::MIN_MSG_LEN;

    /// Write an `A_Memory_Read` request into a message buffer.
    ///
    /// Sets count in the low 6 bits of APCI byte 1 (preserving the high bits
    /// set by `set_apci_code`) and the 16-bit address.
    pub fn write(buf: &mut [u8], count: u8, address: u16) {
        buf[offsets::MSG_APCI + 1] = (buf[offsets::MSG_APCI + 1] & 0xC0) | (count & 0x3F);
        buf[offsets::MSG_APCI + 2] = (address >> 8) as u8;
        buf[offsets::MSG_APCI + 3] = address as u8;
    }
}

/// Writer for `A_Memory_Write` requests.
pub struct MemoryWriteRequest;

impl MemoryWriteRequest {
    /// Compute total message length for a given data size.
    pub const fn msg_len(data_len: usize) -> usize {
        offsets::MSG_APCI + 4 + data_len
    }

    /// Write an `A_Memory_Write` request into a message buffer.
    ///
    /// Sets count in the low 6 bits of APCI byte 1, the address, and copies
    /// the data payload.
    pub fn write(buf: &mut [u8], address: u16, data: &[u8]) {
        let count = data.len() as u8;
        buf[offsets::MSG_APCI + 1] = (buf[offsets::MSG_APCI + 1] & 0xC0) | (count & 0x3F);
        buf[offsets::MSG_APCI + 2] = (address >> 8) as u8;
        buf[offsets::MSG_APCI + 3] = address as u8;
        if !data.is_empty() {
            let start = offsets::MSG_APCI + 4;
            buf[start..start + data.len()].copy_from_slice(data);
        }
    }
}

/// Writer/parser for `A_Memory_Response`.
pub struct MemoryResponse;

impl MemoryResponse {
    /// Parse a memory response (client side).
    ///
    /// The wire format is identical to `A_Memory_Write` (count | APCI,
    /// address, data), so this reuses [`MemoryAccess::parse_write`]. A
    /// response with `count == 0` signals a refused read (the device-side
    /// error encoding, see [`write_error`](Self::write_error)).
    pub fn parse(buf: &[u8]) -> Option<MemoryAccess<'_>> {
        MemoryAccess::parse_write(buf)
    }

    /// Write a memory response into a message buffer.
    ///
    /// Sets count in the low 6 bits of APCI byte 1 (preserving the high 2 bits
    /// set by `set_apci_code`), the address, and copies data.
    pub fn write(buf: &mut [u8], count: u8, address: u16, data: &[u8]) {
        buf[offsets::MSG_APCI + 1] = (buf[offsets::MSG_APCI + 1] & 0xC0) | (count & 0x3F);
        buf[offsets::MSG_APCI + 2] = (address >> 8) as u8;
        buf[offsets::MSG_APCI + 3] = address as u8;
        if !data.is_empty() {
            let start = offsets::MSG_APCI + 4;
            buf[start..start + data.len()].copy_from_slice(data);
        }
    }

    /// Write an error response (count = 0, no data).
    pub fn write_error(buf: &mut [u8], address: u16) {
        Self::write(buf, 0, address, &[]);
    }

    /// Compute total message length for a given byte count.
    pub const fn msg_len(count: usize) -> usize {
        offsets::MSG_APCI + 4 + count
    }
}

// ============================================================================
// UserMemory (Read / Response / Write)
// ============================================================================

/// Parsed fields from `A_UserMemory_Read` or `A_UserMemory_Write`.
///
/// User memory extends the 16-bit address space with a 4-bit extension.
/// The extension and count share the first octet following the APCI.
///
/// ## Wire format
///
/// ```text
/// APDU[0]:   High 2 bits of APCI
/// APDU[1]:   APCI
/// APDU[2]:   Address extension (bits 7:4) | count (bits 3:0)
/// APDU[3-4]: Address low (16-bit, big-endian)
/// APDU[5..]: Data (count bytes, Write only)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct UserMemoryAccess<'a> {
    /// 4-bit address extension (bits 19:16 of the full 20-bit address).
    pub addr_ext: u8,
    pub count: u8,
    /// Low 16 bits of the address.
    pub address_low: u16,
    pub data: &'a [u8],
}

impl<'a> UserMemoryAccess<'a> {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 5;

    /// Parse an `A_UserMemory_Read` (no data payload).
    pub fn parse_read(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        Some(Self {
            addr_ext: buf[offsets::MSG_APCI + 2] >> 4,
            count: buf[offsets::MSG_APCI + 2] & 0x0F,
            address_low: u16::from_be_bytes([buf[offsets::MSG_APCI + 3], buf[offsets::MSG_APCI + 4]]),
            data: &[],
        })
    }

    /// Parse an `A_UserMemory_Write` (includes data payload).
    pub fn parse_write(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        let addr_ext = buf[offsets::MSG_APCI + 2] >> 4;
        let count = buf[offsets::MSG_APCI + 2] & 0x0F;
        let address_low = u16::from_be_bytes([buf[offsets::MSG_APCI + 3], buf[offsets::MSG_APCI + 4]]);
        let data_start = offsets::MSG_APCI + 5;
        let data_end = core::cmp::min(buf.len(), data_start + count as usize);
        Some(Self { addr_ext, count, address_low, data: &buf[data_start..data_end] })
    }

    /// Reconstruct the full 20-bit address from extension and low parts.
    pub fn full_address(&self) -> u32 {
        ((self.addr_ext as u32) << 16) | (self.address_low as u32)
    }

    /// Check whether the total message length is consistent with the count field.
    pub fn is_length_consistent(&self, msg_len: usize) -> bool {
        msg_len == offsets::MSG_APCI + 5 + self.count as usize
    }
}

/// Writer for `A_UserMemory_Response`.
pub struct UserMemoryResponse;

impl UserMemoryResponse {
    /// Write a user memory response into a message buffer.
    ///
    /// Packs the address extension and count into the first octet after the
    /// APCI, then writes the address and data.
    pub fn write(buf: &mut [u8], addr_ext: u8, count: u8, address_low: u16, data: &[u8]) {
        buf[offsets::MSG_APCI + 2] = ((addr_ext & 0x0F) << 4) | (count & 0x0F);
        buf[offsets::MSG_APCI + 3] = (address_low >> 8) as u8;
        buf[offsets::MSG_APCI + 4] = address_low as u8;
        if !data.is_empty() {
            let start = offsets::MSG_APCI + 5;
            buf[start..start + data.len()].copy_from_slice(data);
        }
    }

    /// Write an error response (count = 0, no data).
    pub fn write_error(buf: &mut [u8], addr_ext: u8, address_low: u16) {
        Self::write(buf, addr_ext, 0, address_low, &[]);
    }

    /// Compute total message length for a given byte count.
    pub const fn msg_len(count: usize) -> usize {
        offsets::MSG_APCI + 5 + count
    }
}

// ============================================================================
// MemoryBitWrite
// ============================================================================

/// Parsed fields from `A_MemoryBit_Write`.
///
/// ## Wire format
///
/// ```text
/// APDU[0-1]: APCI (escaped, 0x1D0)
/// APDU[2]:   Count (low 4 bits, 1-5)
/// APDU[3-4]: Address (16-bit, big-endian)
/// APDU[5..5+count]:         AND masks
/// APDU[5+count..5+2*count]: XOR masks
/// ```
///
/// Formula: `new_value = (old_value AND and_mask) XOR xor_mask`
#[derive(Debug, Clone, Copy)]
pub struct MemoryBitWrite<'a> {
    pub count: u8,
    pub address: u16,
    pub and_masks: &'a [u8],
    pub xor_masks: &'a [u8],
}

impl<'a> MemoryBitWrite<'a> {
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 6; // header + at least 1 AND + 1 XOR

    /// Parse an `A_MemoryBit_Write` from a full message buffer.
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        let count = buf[offsets::MSG_APCI + 2] & 0x0F;
        let address = u16::from_be_bytes([buf[offsets::MSG_APCI + 3], buf[offsets::MSG_APCI + 4]]);
        let masks_start = offsets::MSG_APCI + 5;
        let and_end = masks_start + count as usize;
        let xor_end = and_end + count as usize;
        if buf.len() < xor_end {
            return None;
        }
        Some(Self { count, address, and_masks: &buf[masks_start..and_end], xor_masks: &buf[and_end..xor_end] })
    }

    /// Whether count is in the legal range (1-5).
    pub fn is_count_legal(&self) -> bool {
        self.count >= 1 && self.count <= 5
    }

    /// Expected total message length for a given count.
    pub const fn expected_msg_len(count: usize) -> usize {
        offsets::MSG_APCI + 5 + count * 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Memory ----

    #[test]
    fn memory_read_parse() {
        let mut buf = [0u8; 10];
        buf[offsets::MSG_APCI + 1] = 0xC0 | 12; // APCI bits + count=12
        buf[offsets::MSG_APCI + 2] = 0x01;
        buf[offsets::MSG_APCI + 3] = 0x23;
        let acc = MemoryAccess::parse_read(&buf).unwrap();
        assert_eq!(acc.count, 12);
        assert_eq!(acc.address, 0x0123);
        assert!(acc.data.is_empty());
    }

    #[test]
    fn memory_response_roundtrip() {
        let mut buf = [0u8; 16];
        buf[offsets::MSG_APCI + 1] = 0xC0; // Simulate APCI high bits
        MemoryResponse::write(&mut buf, 5, 0x1234, &[1, 2, 3, 4, 5]);
        let acc = MemoryAccess::parse_read(&buf).unwrap();
        assert_eq!(acc.count, 5);
        assert_eq!(acc.address, 0x1234);
        // Verify APCI high bits preserved
        assert_eq!(buf[offsets::MSG_APCI + 1] & 0xC0, 0xC0);
        // Verify data
        assert_eq!(&buf[offsets::MSG_APCI + 4..offsets::MSG_APCI + 9], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn memory_response_parse_client_side() {
        let mut buf = [0u8; 16];
        buf[offsets::MSG_APCI + 1] = 0x40; // APCI high bits
        MemoryResponse::write(&mut buf, 3, 0x4000, &[0xAA, 0xBB, 0xCC]);
        let acc = MemoryResponse::parse(&buf[..MemoryResponse::msg_len(3)]).unwrap();
        assert_eq!(acc.count, 3);
        assert_eq!(acc.address, 0x4000);
        assert_eq!(acc.data, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn memory_error_response() {
        let mut buf = [0u8; 10];
        buf[offsets::MSG_APCI + 1] = 0xC0;
        MemoryResponse::write_error(&mut buf, 0xABCD);
        let acc = MemoryAccess::parse_read(&buf).unwrap();
        assert_eq!(acc.count, 0);
        assert_eq!(acc.address, 0xABCD);
    }

    #[test]
    fn memory_write_parse() {
        let mut buf = [0u8; 14];
        buf[offsets::MSG_APCI + 1] = 0x80 | 3; // MemoryWrite + count=3
        buf[offsets::MSG_APCI + 2] = 0x00;
        buf[offsets::MSG_APCI + 3] = 0x60;
        buf[offsets::MSG_APCI + 4] = 0xAA;
        buf[offsets::MSG_APCI + 5] = 0xBB;
        buf[offsets::MSG_APCI + 6] = 0xCC;
        let acc = MemoryAccess::parse_write(&buf).unwrap();
        assert_eq!(acc.count, 3);
        assert_eq!(acc.address, 0x0060);
        assert_eq!(acc.data, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn memory_length_consistency() {
        let acc = MemoryAccess { count: 4, address: 0, data: &[] };
        assert!(acc.is_length_consistent(offsets::MSG_APCI + 8));
        assert!(!acc.is_length_consistent(offsets::MSG_APCI + 7));
    }

    // ---- UserMemory ----

    #[test]
    fn user_memory_read_parse() {
        let mut buf = [0u8; 11];
        buf[offsets::MSG_APCI + 1] = 0xC0;
        buf[offsets::MSG_APCI + 2] = 0xAA; // addr_ext=A, count=10
        buf[offsets::MSG_APCI + 3] = 0xAB;
        buf[offsets::MSG_APCI + 4] = 0xCD;
        let acc = UserMemoryAccess::parse_read(&buf).unwrap();
        assert_eq!(acc.addr_ext, 0x0A);
        assert_eq!(acc.count, 10);
        assert_eq!(acc.address_low, 0xABCD);
        assert_eq!(acc.full_address(), 0xAABCD);
    }

    #[test]
    fn user_memory_write_parse() {
        let mut buf = [0u8; 14];
        buf[offsets::MSG_APCI + 1] = 0xC2;
        buf[offsets::MSG_APCI + 2] = 0xB3; // addr_ext=B, count=3
        buf[offsets::MSG_APCI + 3] = 0x12;
        buf[offsets::MSG_APCI + 4] = 0x34;
        buf[offsets::MSG_APCI + 5..offsets::MSG_APCI + 8].copy_from_slice(&[0x55, 0x66, 0x77]);

        let acc = UserMemoryAccess::parse_write(&buf).expect("complete user-memory write");
        assert_eq!(acc.addr_ext, 0x0B);
        assert_eq!(acc.count, 3);
        assert_eq!(acc.full_address(), 0xB1234);
        assert_eq!(acc.data, &[0x55, 0x66, 0x77]);
        assert!(acc.is_length_consistent(buf.len()));
    }

    #[test]
    fn user_memory_response_roundtrip() {
        let mut buf = [0u8; 16];
        buf[offsets::MSG_APCI + 1] = 0xC1; // UserMemoryResponse variant bits
        UserMemoryResponse::write(&mut buf, 0x0A, 2, 0x1234, &[0x55, 0x66]);

        // The writer preserves the APCI and packs extension + count after it.
        assert_eq!(buf[offsets::MSG_APCI + 1], 0xC1);
        assert_eq!(buf[offsets::MSG_APCI + 2], 0xA2);
        // Verify address
        assert_eq!(buf[offsets::MSG_APCI + 3], 0x12);
        assert_eq!(buf[offsets::MSG_APCI + 4], 0x34);
        // Verify data
        assert_eq!(&buf[offsets::MSG_APCI + 5..offsets::MSG_APCI + 7], &[0x55, 0x66]);
    }

    // ---- MemoryBitWrite ----

    #[test]
    fn memory_bit_write_parse() {
        let mut buf = [0u8; 15];
        buf[offsets::MSG_APCI + 2] = 2; // count
        buf[offsets::MSG_APCI + 3] = 0x00;
        buf[offsets::MSG_APCI + 4] = 0x60;
        // AND masks
        buf[offsets::MSG_APCI + 5] = 0xFF;
        buf[offsets::MSG_APCI + 6] = 0x0F;
        // XOR masks
        buf[offsets::MSG_APCI + 7] = 0x01;
        buf[offsets::MSG_APCI + 8] = 0x02;
        let mbw = MemoryBitWrite::parse(&buf).unwrap();
        assert_eq!(mbw.count, 2);
        assert_eq!(mbw.address, 0x0060);
        assert_eq!(mbw.and_masks, &[0xFF, 0x0F]);
        assert_eq!(mbw.xor_masks, &[0x01, 0x02]);
        assert!(mbw.is_count_legal());
    }

    #[test]
    fn memory_bit_write_illegal_count() {
        let mut buf = [0u8; 15];
        buf[offsets::MSG_APCI + 2] = 0; // count=0 is illegal
        let mbw = MemoryBitWrite::parse(&buf);
        // parse succeeds (it doesn't enforce legal count, caller checks)
        assert!(!mbw.unwrap().is_count_legal());
    }

    #[test]
    fn memory_bit_write_too_short() {
        let buf = [0u8; 10]; // Only enough for count+address, not masks
        // count=3 would need 5 + 2*3 = 11 bytes from APCI
        let mut buf2 = [0u8; 14];
        buf2[offsets::MSG_APCI + 2] = 3;
        assert!(MemoryBitWrite::parse(&buf2).is_none()); // needs 17, only 14
        assert!(MemoryBitWrite::parse(&buf).is_none());
    }
}

// ============================================================================
// A_MemoryExtended_Read / _Write (03/03/07 §3.4.9)
// ============================================================================
//
// The extended memory services widen the address to three octets and the
// count to a full octet, and — unlike the classic services — answer with an
// explicit return code rather than signalling failure by a zero count. They
// are `M` for the KNX Data Security profile module (06 Profiles §9.1.2.3.3),
// and are what an ETS download to a secure device actually uses: the bench
// MV-0021 trace carries 361 `A_MemoryExtended_Write` and no classic memory
// write at all.

/// Parsed `A_MemoryExtended_Read` / `A_MemoryExtended_Write` request.
///
/// ```text
/// [0-1]: APCI
/// [2]:   number of octets
/// [3-5]: address (3 octets, big-endian)
/// [6+]:  data (write only)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct MemoryExtendedAccess<'a> {
    pub count: u8,
    pub address: u32,
    /// Empty for a read request.
    pub data: &'a [u8],
}

impl<'a> MemoryExtendedAccess<'a> {
    /// Minimum message length: APCI, count and the three address octets.
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 6;

    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        let base = offsets::MSG_APCI;
        Some(Self {
            count: buf[base + 2],
            address: (u32::from(buf[base + 3]) << 16) | (u32::from(buf[base + 4]) << 8) | u32::from(buf[base + 5]),
            data: &buf[base + 6..],
        })
    }

    /// Whether the declared count matches the data actually carried.
    ///
    /// Only meaningful for a write; a read carries no data.
    pub fn is_write_length_consistent(&self) -> bool {
        self.data.len() == self.count as usize
    }

    /// Write a read or write request. Reads carry an empty `data` slice and
    /// provide their requested count separately; writes use `data.len()` as
    /// the count.
    pub fn write(buf: &mut [u8], count: u8, address: u32, data: &[u8]) {
        let base = offsets::MSG_APCI;
        buf[base + 2] = count;
        buf[base + 3] = (address >> 16) as u8;
        buf[base + 4] = (address >> 8) as u8;
        buf[base + 5] = address as u8;
        if !data.is_empty() {
            buf[base + 6..base + 6 + data.len()].copy_from_slice(data);
        }
    }

    pub const fn msg_len(data_len: usize) -> usize {
        offsets::MSG_APCI + 6 + data_len
    }
}

/// Parsed result of an extended-memory response.
#[derive(Debug, Clone, Copy)]
pub struct MemoryExtendedResult<'a> {
    pub return_code: PropertyReturnCode,
    pub address: u32,
    pub data: &'a [u8],
}

/// Writer for `A_MemoryExtended_ReadResponse` / `_WriteResponse`.
///
/// ```text
/// [0-1]: APCI
/// [2]:   return code
/// [3-5]: address (echoed)
/// [6+]:  data (read response only)
/// ```
pub struct MemoryExtendedResponse;

impl MemoryExtendedResponse {
    /// Message length for a response carrying `data_len` octets. A write
    /// response carries none.
    pub const fn msg_len(data_len: usize) -> usize {
        offsets::MSG_APCI + 6 + data_len
    }

    /// Length of a response with no data — every write response, and any
    /// read that failed.
    pub const EMPTY_MSG_LEN: usize = Self::msg_len(0);

    pub fn write(buf: &mut [u8], return_code: PropertyReturnCode, address: u32, data: &[u8]) {
        let base = offsets::MSG_APCI;
        buf[base + 2] = return_code.into();
        buf[base + 3] = (address >> 16) as u8;
        buf[base + 4] = (address >> 8) as u8;
        buf[base + 5] = address as u8;
        if !data.is_empty() {
            buf[base + 6..base + 6 + data.len()].copy_from_slice(data);
        }
    }

    pub fn parse(buf: &[u8]) -> Option<MemoryExtendedResult<'_>> {
        if buf.len() < Self::EMPTY_MSG_LEN {
            return None;
        }
        let base = offsets::MSG_APCI;
        Some(MemoryExtendedResult {
            return_code: PropertyReturnCode::from(buf[base + 2]),
            address: (u32::from(buf[base + 3]) << 16) | (u32::from(buf[base + 4]) << 8) | u32::from(buf[base + 5]),
            data: &buf[base + 6..],
        })
    }
}

#[cfg(test)]
mod extended_tests {
    use super::*;

    #[test]
    fn parses_a_three_octet_address() {
        // APCI(2) + count + 0x004000 + two data octets.
        let buf = [0u8, 0, 0, 0, 0, 0, 0x01, 0xFB, 0x02, 0x00, 0x40, 0x00, 0xAA, 0xBB];
        let req = MemoryExtendedAccess::parse(&buf).expect("well-formed");
        assert_eq!(req.count, 2);
        assert_eq!(req.address, 0x004000);
        assert_eq!(req.data, &[0xAA, 0xBB]);
        assert!(req.is_write_length_consistent());
    }

    #[test]
    fn a_count_that_disagrees_with_the_data_is_caught() {
        let buf = [0u8, 0, 0, 0, 0, 0, 0x01, 0xFB, 0x05, 0x00, 0x40, 0x00, 0xAA];
        let req = MemoryExtendedAccess::parse(&buf).expect("well-formed header");
        assert!(!req.is_write_length_consistent(), "declared 5, carries 1");
    }

    #[test]
    fn a_response_echoes_the_full_address() {
        let mut buf = [0u8; MemoryExtendedResponse::msg_len(2)];
        MemoryExtendedResponse::write(&mut buf, PropertyReturnCode::Success, 0x123456, &[0xDE, 0xAD]);
        assert_eq!(&buf[offsets::MSG_APCI + 2..], &[0x00, 0x12, 0x34, 0x56, 0xDE, 0xAD]);
    }
}
