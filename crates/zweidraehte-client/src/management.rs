//! Typed wrappers for KNX management APDUs.
//!
//! Each function builds the APCI+payload bytes for a specific management
//! service. The caller is responsible for wrapping these in the appropriate
//! transport (connected or unconnected) and cEMI framing.

use crate::error::{Error, Result};

// ============================================================================
// Result types
// ============================================================================

/// Result of a function property command or state read.
#[derive(Debug, Clone)]
pub struct FunctionPropertyResult {
    pub return_code: u8,
    pub data: Vec<u8>,
}

/// Result of a property description read.
#[derive(Debug, Clone)]
pub struct PropertyDescription {
    pub prop_id: u8,
    pub prop_idx: u8,
    pub write_enabled: bool,
    pub pdt: u8,
    pub max_elements: u16,
    pub read_access: u8,
    pub write_access: u8,
}

// ============================================================================
// APCI data builders
// ============================================================================

// The APCI data builders produce the bytes that go after the TPCI byte
// in the KNX frame. The first byte or two contain the APCI code, followed
// by service-specific fields.
//
// For "short" APCI codes (0x00-0x0F), the code is packed into the upper
// bits of a 2-byte APCI field. For "user" codes (0x80-0xBF) and "escaped"
// codes (0xC0-0xFF), the full code occupies byte 1.
//
// Rather than manually encoding APCI bytes, we use a buffer with
// KnxMessageBuffer::set_apci_code and then extract the APCI region.

/// Build APCI data for `A_DeviceDescriptor_Read`.
pub fn build_device_descriptor_read(descriptor_type: u8) -> Vec<u8> {
    // Short APCI: DeviceDescriptorRead (0x0c), 6-bit data = descriptor_type.
    // Wire: APCI high nibble = 0x30, low byte = 0x00 | descriptor_type
    // Encoding: 2 bytes
    let mut buf = [0u8; 2];
    buf[0] = 0x03; // APCI prefix for DeviceDescriptorRead
    buf[1] = descriptor_type & 0x3F;
    buf.to_vec()
}

/// Build APCI data for `A_PropertyValue_Read`.
pub fn build_property_read(obj_idx: u8, prop_id: u8, count: u16, start_idx: u16) -> Vec<u8> {
    // Escaped APCI: PropertyValueRead (0xD5).
    // Wire: byte 0 = 0x03 (escape prefix high), byte 1 = 0xD5
    //        byte 2 = obj_idx, byte 3 = prop_id
    //        byte 4-5 = count(4) | start_idx(12)
    let packed = ((count & 0x0F) << 12) | (start_idx & 0x0FFF);
    let mut buf = vec![0x03, 0xD5, obj_idx, prop_id];
    buf.extend_from_slice(&packed.to_be_bytes());
    buf
}

/// Build APCI data for `A_PropertyValue_Write`.
pub fn build_property_write(
    obj_idx: u8,
    prop_id: u8,
    count: u16,
    start_idx: u16,
    data: &[u8],
) -> Vec<u8> {
    let packed = ((count & 0x0F) << 12) | (start_idx & 0x0FFF);
    let mut buf = vec![0x03, 0xD7, obj_idx, prop_id];
    buf.extend_from_slice(&packed.to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Build APCI data for `A_PropertyDescription_Read`.
pub fn build_property_description_read(obj_idx: u8, prop_id: u8, prop_idx: u8) -> Vec<u8> {
    vec![0x03, 0xD8, obj_idx, prop_id, prop_idx]
}

/// Build APCI data for `A_FunctionPropertyCommand`.
pub fn build_function_property_command(obj_idx: u8, prop_id: u8, service_data: &[u8]) -> Vec<u8> {
    // User APCI: FunctionPropertyCommand (0x87).
    // Wire: byte 0 = 0x02 (user prefix high), byte 1 = 0xC7 (0x87 | 0xC0)
    let mut buf = vec![0x02, 0xC7, obj_idx, prop_id];
    buf.extend_from_slice(service_data);
    buf
}

/// Build APCI data for `A_FunctionPropertyState_Read`.
pub fn build_function_property_state_read(obj_idx: u8, prop_id: u8, service_data: &[u8]) -> Vec<u8> {
    // User APCI: FunctionPropertyStateRead (0x88).
    // Wire: byte 0 = 0x02 (user prefix high), byte 1 = 0xC8 (0x88 | 0xC0)
    let mut buf = vec![0x02, 0xC8, obj_idx, prop_id];
    buf.extend_from_slice(service_data);
    buf
}

/// Build APCI data for `A_Memory_Read`.
pub fn build_memory_read(count: u8, address: u16) -> Vec<u8> {
    // Short APCI: MemoryRead (0x08).
    // Wire: byte 0 high nibble = 0x02 (APCI prefix), byte 1 low 6 bits = count
    //        byte 2-3 = address
    let mut buf = vec![0x02, count & 0x3F];
    buf.extend_from_slice(&address.to_be_bytes());
    buf
}

/// Build APCI data for `A_Memory_Write`.
pub fn build_memory_write(address: u16, data: &[u8]) -> Vec<u8> {
    let count = data.len() as u8;
    let mut buf = vec![0x02, 0x80 | (count & 0x3F)];
    buf.extend_from_slice(&address.to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Build APCI data for `A_Authorize_Request`.
pub fn build_authorize_request(key: &[u8; 4]) -> Vec<u8> {
    // Escaped APCI: AuthorizeRequest (0xD1).
    let mut buf = vec![0x03, 0xD1, 0x00]; // byte 2 = 0x00 (reserved)
    buf.extend_from_slice(key);
    buf
}

/// Build APCI data for `A_Restart` (basic restart).
pub fn build_restart() -> Vec<u8> {
    // Short APCI: Restart (0x0e).
    // Wire: 0x03, 0x80
    vec![0x03, 0x80]
}

// ============================================================================
// Response parsers
// ============================================================================

/// Parse a device descriptor response from raw APCI data.
///
/// The `apci_data` starts at the APCI region (TPCI has been stripped).
/// Returns the descriptor bytes.
pub fn parse_device_descriptor_response(apci_data: &[u8]) -> Result<Vec<u8>> {
    if apci_data.len() < 2 {
        return Err(Error::Parse("DeviceDescriptorResponse too short"));
    }
    // Descriptor data starts at byte 2.
    Ok(apci_data[2..].to_vec())
}

/// Parse a property value response.
///
/// Returns (count, start_idx, data). Count=0 indicates an error response.
pub fn parse_property_value_response(apci_data: &[u8]) -> Result<(u16, u16, Vec<u8>)> {
    if apci_data.len() < 6 {
        return Err(Error::Parse("PropertyValueResponse too short"));
    }
    let count_start = u16::from_be_bytes([apci_data[4], apci_data[5]]);
    let count = count_start >> 12;
    let start_idx = count_start & 0x0FFF;
    let data = if apci_data.len() > 6 { apci_data[6..].to_vec() } else { Vec::new() };
    Ok((count, start_idx, data))
}

/// Parse a function property state response.
pub fn parse_function_property_response(apci_data: &[u8]) -> Result<FunctionPropertyResult> {
    if apci_data.len() < 5 {
        return Err(Error::Parse("FunctionPropertyResponse too short"));
    }
    let return_code = apci_data[4];
    let data = if apci_data.len() > 5 { apci_data[5..].to_vec() } else { Vec::new() };
    Ok(FunctionPropertyResult { return_code, data })
}

/// Parse a property description response.
pub fn parse_property_description_response(apci_data: &[u8]) -> Result<PropertyDescription> {
    if apci_data.len() < 9 {
        return Err(Error::Parse("PropertyDescriptionResponse too short"));
    }
    let prop_id = apci_data[3];
    let prop_idx = apci_data[4];
    let type_byte = apci_data[5];
    let write_enabled = (type_byte & 0x80) != 0;
    let pdt = type_byte & 0x3F;
    let max_elements = u16::from_be_bytes([apci_data[6], apci_data[7]]);
    let access = apci_data[8];
    let read_access = (access >> 4) & 0x0F;
    let write_access = access & 0x0F;

    Ok(PropertyDescription {
        prop_id,
        prop_idx,
        write_enabled,
        pdt,
        max_elements,
        read_access,
        write_access,
    })
}

/// Parse an authorize response. Returns the granted access level.
pub fn parse_authorize_response(apci_data: &[u8]) -> Result<u8> {
    if apci_data.len() < 3 {
        return Err(Error::Parse("AuthorizeResponse too short"));
    }
    Ok(apci_data[2])
}
