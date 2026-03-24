//! cEMI frame building helpers for the client.
//!
//! Outgoing messages are built in the internal KNX message format using
//! `KnxMessageBuffer` and then converted to cEMI via `knx_to_cemi_message()`.

use zweidraehte_proto::encoding::cemi::{CemiMessageCode, knx_to_cemi_message};

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
