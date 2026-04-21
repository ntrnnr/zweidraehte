//! Typed wrappers for KNX management service results and APCI mapping.
//!
//! Request construction is handled by the proto crate's APDU writers
//! (`PropertyValueResponse::write`, `FunctionPropertyHeader::write`, etc.)
//! and `KnxMessageBuffer::set_apci_code`. This module provides result types
//! for parsed responses and the request→response APCI mapping.

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
    pub prop_id: u16,
    pub prop_idx: u8,
    pub write_enabled: bool,
    pub pdt: u8,
    pub max_elements: u16,
    pub read_access: u8,
    pub write_access: u8,
}

// ============================================================================
// APCI request/response mapping
// ============================================================================

/// Map a request APCI code to the expected response APCI code.
pub fn expected_response_apci(request: ApciCode) -> Option<ApciCode> {
    match request {
        ApciCode::DeviceDescriptorRead => Some(ApciCode::DeviceDescriptorResponse),
        ApciCode::PropertyValueRead | ApciCode::PropertyValueWrite => Some(ApciCode::PropertyValueResponse),
        ApciCode::PropertyDescriptionRead => Some(ApciCode::PropertyDescriptionResponse),
        ApciCode::FunctionPropertyCommand | ApciCode::FunctionPropertyStateRead => {
            Some(ApciCode::FunctionPropertyStateResponse)
        }
        ApciCode::MemoryRead => Some(ApciCode::MemoryReadResponse),
        ApciCode::AuthorizeRequest => Some(ApciCode::AuthorizeResponse),
        _ => None,
    }
}
