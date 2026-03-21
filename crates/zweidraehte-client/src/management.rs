//! Typed wrappers for KNX management APDUs.
//!
//! Each function builds the APCI+payload bytes for a specific management
//! service. The caller is responsible for wrapping these in the appropriate
//! transport (connected or unconnected) and cEMI framing.

use zweidraehte_proto::messages::knx::ApciCode;

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
// APCI request/response mapping
// ============================================================================

/// Map a request APCI code to the expected response APCI code.
pub fn expected_response_apci(request: ApciCode) -> Option<ApciCode> {
    match request {
        ApciCode::DeviceDescriptorRead => Some(ApciCode::DeviceDescriptorResponse),
        ApciCode::PropertyValueRead | ApciCode::PropertyValueWrite => {
            Some(ApciCode::PropertyValueResponse)
        }
        ApciCode::PropertyDescriptionRead => Some(ApciCode::PropertyDescriptionResponse),
        ApciCode::FunctionPropertyCommand | ApciCode::FunctionPropertyStateRead => {
            Some(ApciCode::FunctionPropertyStateResponse)
        }
        ApciCode::MemoryRead => Some(ApciCode::MemoryReadResponse),
        ApciCode::AuthorizeRequest => Some(ApciCode::AuthorizeResponse),
        _ => None,
    }
}
