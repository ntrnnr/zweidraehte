//! Memory service APDUs (`A_Memory_*`, `A_UserMemory_*`, `A_MemoryBit_Write`).
//!
//! Memory services use "short" APCIs where the data count shares bits with the
//! APCI code in byte 1. The write functions preserve the APCI high bits while
//! setting the count in the low bits.

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

/// Writer for `A_Memory_Response`.
pub struct MemoryResponse;

impl MemoryResponse {
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
/// User memory extends the 16-bit address space with a 2-bit extension
/// stored in bits 3:2 of the second APCI byte.
///
/// ## Wire format
///
/// ```text
/// APDU[0]:   High 2 bits of APCI
/// APDU[1]:   APCI variant (bits 7:4, 1:0) | addr_ext (bits 3:2)
/// APDU[2]:   Count (8 bits)
/// APDU[3-4]: Address low (16-bit, big-endian)
/// APDU[5..]: Data (count bytes, Write only)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct UserMemoryAccess<'a> {
    /// 2-bit address extension (bits 17:16 of the full 18-bit address).
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
            addr_ext: (buf[offsets::MSG_APCI + 1] >> 2) & 0x03,
            count: buf[offsets::MSG_APCI + 2],
            address_low: u16::from_be_bytes([buf[offsets::MSG_APCI + 3], buf[offsets::MSG_APCI + 4]]),
            data: &[],
        })
    }

    /// Parse an `A_UserMemory_Write` (includes data payload).
    pub fn parse_write(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < Self::MIN_MSG_LEN {
            return None;
        }
        let addr_ext = (buf[offsets::MSG_APCI + 1] >> 2) & 0x03;
        let count = buf[offsets::MSG_APCI + 2];
        let address_low = u16::from_be_bytes([buf[offsets::MSG_APCI + 3], buf[offsets::MSG_APCI + 4]]);
        let data_start = offsets::MSG_APCI + 5;
        let data_end = core::cmp::min(buf.len(), data_start + count as usize);
        Some(Self { addr_ext, count, address_low, data: &buf[data_start..data_end] })
    }

    /// Reconstruct the full 18-bit address from extension and low parts.
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
    /// Sets the addr_ext in bits 3:2 of APCI byte 1 (preserving the APCI
    /// variant bits), the count, address, and data.
    pub fn write(buf: &mut [u8], addr_ext: u8, count: u8, address_low: u16, data: &[u8]) {
        buf[offsets::MSG_APCI + 1] = (buf[offsets::MSG_APCI + 1] & 0xF3) | ((addr_ext & 0x03) << 2);
        buf[offsets::MSG_APCI + 2] = count;
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
        // addr_ext=2 in bits 3:2 → 0b0000_1000 = 0x08
        buf[offsets::MSG_APCI + 1] = 0xC0 | 0x08; // APCI + addr_ext=2
        buf[offsets::MSG_APCI + 2] = 10; // count
        buf[offsets::MSG_APCI + 3] = 0xAB;
        buf[offsets::MSG_APCI + 4] = 0xCD;
        let acc = UserMemoryAccess::parse_read(&buf).unwrap();
        assert_eq!(acc.addr_ext, 2);
        assert_eq!(acc.count, 10);
        assert_eq!(acc.address_low, 0xABCD);
        assert_eq!(acc.full_address(), 0x2ABCD);
    }

    #[test]
    fn user_memory_response_roundtrip() {
        let mut buf = [0u8; 16];
        buf[offsets::MSG_APCI + 1] = 0xC1; // UserMemoryResponse variant bits
        UserMemoryResponse::write(&mut buf, 3, 2, 0x1234, &[0x55, 0x66]);

        // Verify addr_ext in bits 3:2
        assert_eq!((buf[offsets::MSG_APCI + 1] >> 2) & 0x03, 3);
        // Verify variant bits preserved (bits 7:4 and 1:0)
        assert_eq!(buf[offsets::MSG_APCI + 1] & 0xF3, 0xC1);
        // Verify count
        assert_eq!(buf[offsets::MSG_APCI + 2], 2);
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
