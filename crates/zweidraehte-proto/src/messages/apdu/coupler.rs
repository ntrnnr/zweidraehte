//! Legacy coupler memory service APDUs (03/03/07 §3.6).
//!
//! Published coupler profiles use two distinct 16-bit address spaces with an
//! identical wire layout: Filter Table memory and Router memory. A Filter
//! Table transfer starts with `A_FilterTable_Open`; the specification defines
//! no matching close service. The surrounding point-to-point transport
//! disconnect terminates the management procedure.

use crate::messages::knx::offsets;

/// Largest count defined by the legacy coupler memory services.
pub const MAX_COUPLER_MEMORY_COUNT: usize = 254;

/// Parsed fields shared by Filter Table and Router memory messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CouplerMemoryAccess<'a> {
    pub count: u8,
    pub address: u16,
    pub data: &'a [u8],
}

impl<'a> CouplerMemoryAccess<'a> {
    /// APCI, one count octet and a 16-bit start address.
    pub const MIN_MSG_LEN: usize = offsets::MSG_APCI + 5;

    /// Parse the fixed fields of a read request, which has no data payload.
    pub fn parse_read(buf: &'a [u8]) -> Option<Self> {
        let (count, address) = parse_header(buf)?;

        Some(Self { count, address, data: &[] })
    }

    /// Parse a write or response and require all declared data octets.
    pub fn parse_data(buf: &'a [u8]) -> Option<Self> {
        let (count, address) = parse_header(buf)?;
        let data_start = offsets::MSG_APCI + 5;
        let data_end = data_start.checked_add(usize::from(count))?;
        let data = buf.get(data_start..data_end)?;

        Some(Self { count, address, data })
    }

    /// Whether the complete message contains exactly the declared data.
    pub fn is_length_consistent(&self, msg_len: usize) -> bool {
        msg_len == Self::MIN_MSG_LEN + usize::from(self.count)
    }
}

/// Empty request that selects the legacy Filter Table access procedure.
pub struct FilterTableOpenRequest;

impl FilterTableOpenRequest {
    pub const MSG_LEN: usize = offsets::MSG_APCI + 2;
}

/// `A_FilterTable_Read` request.
pub struct FilterTableReadRequest;

impl FilterTableReadRequest {
    pub const MSG_LEN: usize = CouplerMemoryAccess::MIN_MSG_LEN;

    pub fn write(buf: &mut [u8], address: u16, count: u8) {
        write_header(buf, address, count);
    }
}

/// `A_FilterTable_Write` request.
pub struct FilterTableWriteRequest;

impl FilterTableWriteRequest {
    pub const fn msg_len(data_len: usize) -> usize {
        CouplerMemoryAccess::MIN_MSG_LEN + data_len
    }

    pub fn write(buf: &mut [u8], address: u16, data: &[u8]) {
        write_data(buf, address, data);
    }
}

/// `A_FilterTable_Response` parser and writer.
pub struct FilterTableResponse;

impl FilterTableResponse {
    pub fn parse(buf: &[u8]) -> Option<CouplerMemoryAccess<'_>> {
        CouplerMemoryAccess::parse_data(buf)
    }

    pub const fn msg_len(data_len: usize) -> usize {
        CouplerMemoryAccess::MIN_MSG_LEN + data_len
    }

    pub fn write(buf: &mut [u8], address: u16, data: &[u8]) {
        write_data(buf, address, data);
    }
}

/// `A_RouterMemory_Read` request.
pub struct RouterMemoryReadRequest;

impl RouterMemoryReadRequest {
    pub const MSG_LEN: usize = CouplerMemoryAccess::MIN_MSG_LEN;

    pub fn write(buf: &mut [u8], address: u16, count: u8) {
        write_header(buf, address, count);
    }
}

/// `A_RouterMemory_Write` request.
pub struct RouterMemoryWriteRequest;

impl RouterMemoryWriteRequest {
    pub const fn msg_len(data_len: usize) -> usize {
        CouplerMemoryAccess::MIN_MSG_LEN + data_len
    }

    pub fn write(buf: &mut [u8], address: u16, data: &[u8]) {
        write_data(buf, address, data);
    }
}

/// `A_RouterMemory_Response` parser and writer.
pub struct RouterMemoryResponse;

impl RouterMemoryResponse {
    pub fn parse(buf: &[u8]) -> Option<CouplerMemoryAccess<'_>> {
        CouplerMemoryAccess::parse_data(buf)
    }

    pub const fn msg_len(data_len: usize) -> usize {
        CouplerMemoryAccess::MIN_MSG_LEN + data_len
    }

    pub fn write(buf: &mut [u8], address: u16, data: &[u8]) {
        write_data(buf, address, data);
    }
}

fn parse_header(buf: &[u8]) -> Option<(u8, u16)> {
    if buf.len() < CouplerMemoryAccess::MIN_MSG_LEN {
        return None;
    }

    let base = offsets::MSG_APCI;
    let count = buf[base + 2];
    let address = u16::from_be_bytes([buf[base + 3], buf[base + 4]]);

    Some((count, address))
}

fn write_header(buf: &mut [u8], address: u16, count: u8) {
    let base = offsets::MSG_APCI;
    buf[base + 2] = count;
    buf[base + 3..base + 5].copy_from_slice(&address.to_be_bytes());
}

fn write_data(buf: &mut [u8], address: u16, data: &[u8]) {
    write_header(buf, address, data.len() as u8);

    let data_start = offsets::MSG_APCI + 5;
    buf[data_start..data_start + data.len()].copy_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_table_read_has_count_and_big_endian_address() {
        let mut buf = [0u8; FilterTableReadRequest::MSG_LEN];
        FilterTableReadRequest::write(&mut buf, 0x1234, 0xFE);

        let request = CouplerMemoryAccess::parse_read(&buf).expect("complete filter-table read");
        assert_eq!(request.count, 0xFE);
        assert_eq!(request.address, 0x1234);
        assert!(request.data.is_empty());
    }

    #[test]
    fn filter_table_response_roundtrips() {
        let data = [0xAA, 0xBB, 0xCC];
        let mut buf = [0u8; FilterTableResponse::msg_len(3)];
        FilterTableResponse::write(&mut buf, 0x4000, &data);

        let response = FilterTableResponse::parse(&buf).expect("complete filter-table response");
        assert_eq!(response.address, 0x4000);
        assert_eq!(response.count, 3);
        assert_eq!(response.data, data);
        assert!(response.is_length_consistent(buf.len()));
    }

    #[test]
    fn router_memory_write_roundtrips() {
        let data = [0x12, 0x34];
        let mut buf = [0u8; RouterMemoryWriteRequest::msg_len(2)];
        RouterMemoryWriteRequest::write(&mut buf, 0xFEDC, &data);

        let write = CouplerMemoryAccess::parse_data(&buf).expect("complete router-memory write");
        assert_eq!(write.address, 0xFEDC);
        assert_eq!(write.count, 2);
        assert_eq!(write.data, data);
    }

    #[test]
    fn response_rejects_truncated_data() {
        let mut buf = [0u8; RouterMemoryResponse::msg_len(1)];
        write_header(&mut buf, 0x0100, 2);

        assert!(RouterMemoryResponse::parse(&buf).is_none());
    }
}
