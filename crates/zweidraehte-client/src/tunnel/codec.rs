//! cEMI frame building and parsing helpers for the client.
//!
//! Outgoing messages are built in the internal KNX message format using
//! `KnxMessageBuffer` and then converted to cEMI via `knx_to_cemi_message()`.
//! Incoming cEMI frames are parsed using the proto crate's cEMI parser.

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::encoding::cemi::{CemiLData, CemiMessageCode, knx_to_cemi_message};
use zweidraehte_proto::util::packets::ParseBuffer;

use crate::error::{Error, Result};

/// Which cEMI framing mode to use for tunneled data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CemiMode {
    /// Standard L_Data.req: full cEMI telegram with control fields and addresses.
    /// Works with all KNX/IP interfaces in link layer tunnel mode.
    LData,
    /// T_Data_Individual.req: transport layer cEMI mode (msg code 0x4A).
    /// Uses 6 reserved zero bytes instead of control fields + addresses.
    /// Only relevant for interfaces using transport layer tunnel mode.
    TDataIndividual,
}

// ============================================================================
// Building outgoing cEMI frames
// ============================================================================

/// Convert an internal-format KNX message to a cEMI L_Data.req frame.
///
/// The internal format is 7+ bytes: ctrl1, src(2), dst(2), npdu, tpci/apci...
/// The cEMI format adds msg_code, add_info_len, and ctrl2 (3 extra bytes).
pub fn internal_to_cemi(internal: &[u8], msg_code: CemiMessageCode) -> Vec<u8> {
    let mut buf = vec![0u8; internal.len() + 3];
    buf[..internal.len()].copy_from_slice(internal);
    let final_len = knx_to_cemi_message(&mut buf, 0, internal.len(), msg_code);
    buf.truncate(final_len);
    buf
}

// ============================================================================
// Parsing incoming cEMI frames
// ============================================================================

/// Parse a cEMI L_Data frame from raw tunnel payload bytes.
pub fn parse_cemi_ldata<'a>(data: &'a mut &[u8]) -> Result<CemiLData<&'a [u8]>> {
    data.parse::<CemiLData<&[u8]>>().map_err(|_| Error::Parse("invalid cEMI L_Data frame"))
}

/// Extract source address from the cEMI body (after msg_code and add_info_len).
///
/// In cEMI L_Data, source address is at bytes 2-3 of the body (after ctrl1, ctrl2).
pub fn get_source_addr(cemi_body: &[u8]) -> Option<IndividualAddress> {
    if cemi_body.len() < 5 {
        return None;
    }
    // cEMI body: [ctrl1, ctrl2, src_hi, src_lo, dst_hi, dst_lo, ...]
    Some(IndividualAddress::from_bytes(&cemi_body[2..4]))
}

/// Check if an L_Data.con frame has a positive confirmation.
///
/// In cEMI L_Data.con, control byte 1 bit 0 indicates:
/// - 0 = positive confirmation (success)
/// - 1 = negative confirmation (NACK from bus)
pub fn is_positive_confirmation(cemi_body: &[u8]) -> bool {
    if cemi_body.is_empty() {
        return false;
    }
    // ctrl1 is byte 0 of the cEMI body
    (cemi_body[0] & 0x01) == 0
}
