//! Typed wrappers for KNX management service results, APCI mapping, and
//! response matching.
//!
//! Request construction is handled by the proto crate's APDU writers
//! (`PropertyValueResponse::write`, `FunctionPropertyHeader::write`, etc.)
//! and `KnxMessageBuffer::set_apci_code`. This module provides result types
//! for parsed responses, the request→response APCI mapping, and the pure
//! matcher the driver uses to pick a procedure's answer out of the bus
//! traffic.

use std::time::Duration;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::knx::{ApciCode, decode_apci_code, offsets};

/// How long a management procedure waits for the device's answer once the
/// request is out (03/05/02 §1.3 connectionless/connected response time).
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

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

impl PropertyDescription {
    /// Parse an `A_PropertyDescription_Response` from an internal-format
    /// frame.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        // APCI(2) + obj_idx + prop_id + prop_idx + type + max_elems(2) + access.
        if buf.len() < offsets::MSG_APCI + 9 {
            return None;
        }
        let base = offsets::MSG_APCI;
        let type_byte = buf[base + 5];
        Some(Self {
            prop_id: buf[base + 3] as u16,
            prop_idx: buf[base + 4],
            write_enabled: (type_byte & 0x80) != 0,
            pdt: type_byte & 0x3F,
            max_elements: u16::from_be_bytes([buf[base + 6], buf[base + 7]]),
            read_access: (buf[base + 8] >> 4) & 0x0F,
            write_access: buf[base + 8] & 0x0F,
        })
    }
}

// ============================================================================
// APCI request/response mapping
// ============================================================================

/// Map a request APCI code to the expected response APCI code.
pub fn expected_response_apci(request: ApciCode) -> Option<ApciCode> {
    match request {
        ApciCode::DeviceDescriptorRead => Some(ApciCode::DeviceDescriptorResponse),
        ApciCode::PropertyValueRead | ApciCode::PropertyValueWrite => Some(ApciCode::PropertyValueResponse),
        ApciCode::PropertyExtValueRead => Some(ApciCode::PropertyExtValueResponse),
        ApciCode::PropertyExtValueWriteCon => Some(ApciCode::PropertyExtValueWriteConRes),
        ApciCode::PropertyDescriptionRead => Some(ApciCode::PropertyDescriptionResponse),
        ApciCode::FunctionPropertyCommand | ApciCode::FunctionPropertyStateRead => {
            Some(ApciCode::FunctionPropertyStateResponse)
        }
        ApciCode::FunctionPropertyExtCommand | ApciCode::FunctionPropertyExtStateRead => {
            Some(ApciCode::FunctionPropertyExtStateResponse)
        }
        ApciCode::MemoryRead => Some(ApciCode::MemoryReadResponse),
        ApciCode::MemoryExtendedRead => Some(ApciCode::MemoryExtendedReadResponse),
        ApciCode::MemoryExtendedWrite => Some(ApciCode::MemoryExtendedWriteResponse),
        ApciCode::AuthorizeRequest => Some(ApciCode::AuthorizeResponse),
        ApciCode::IndividualAddressRead => Some(ApciCode::IndividualAddressResponse),
        ApciCode::IndividualAddressSerialNumberRead => Some(ApciCode::IndividualAddressSerialNumberResponse),
        _ => None,
    }
}

// ============================================================================
// Response matching
// ============================================================================

/// Filter deciding whether a received application frame answers the
/// procedure currently in flight.
///
/// Both filters are optional: `source` guards against another device
/// talking at the same time, `apci` against unrelated services from the
/// same device (e.g. a spontaneous info report).
#[derive(Debug, Clone, Copy)]
pub struct ResponseMatcher {
    pub source: Option<IndividualAddress>,
    pub apci: Option<ApciCode>,
}

impl ResponseMatcher {
    /// Check an internal-format frame against the filters.
    pub fn matches(&self, internal: &[u8]) -> bool {
        if internal.len() < offsets::MSG_APCI + 1 {
            return false;
        }
        if let Some(expected) = self.source {
            let source =
                IndividualAddress::from_bytes(&internal[offsets::MSG_SOURCE_ADDR..offsets::MSG_SOURCE_ADDR + 2]);
            if source != expected {
                return false;
            }
        }
        if let Some(expected) = self.apci
            && decode_apci_code(internal) != Some(expected)
        {
            return false;
        }
        true
    }
}
