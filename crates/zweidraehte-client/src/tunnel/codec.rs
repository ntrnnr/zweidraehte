//! cEMI frame building and parsing helpers for the client.
//!
//! Builds complete cEMI L_Data.req frames for sending through a KNX/IP tunnel.
//! The cEMI L_Data format is:
//!
//! ```text
//! [0]     Message code (0x11 = L_Data.req)
//! [1]     Additional info length (0x00)
//! [2]     Control field 1 (frame type, repeat, priority)
//! [3]     Control field 2 (address type, hop count, EFF)
//! [4-5]   Source address
//! [6-7]   Destination address
//! [8]     NPDU length (number of TPCI/APCI/data bytes - 1)
//! [9+]    TPCI/APCI + data
//! ```

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::encoding::cemi::{CemiLData, CemiMessageCode};
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

/// Build a complete cEMI L_Data.req frame for an individually-addressed message.
///
/// `tpci_apci_data` is the combined TPCI/APCI region: the first byte's upper
/// bits are the TPCI field, the lower bits are the APCI prefix, followed by
/// the rest of the APCI and any payload data.
pub fn build_ldata_req(
    source: IndividualAddress,
    dest: IndividualAddress,
    tpci_apci_data: &[u8],
) -> Vec<u8> {
    // NPDU length = number of octets following the NPDU length field.
    // That's the TPCI/APCI/data region, minus 1 because the length field
    // itself counts the TPCI byte as part of the transport header, not the
    // data.
    //
    // Per the spec: NPDU length = total TPCI+APCI+data bytes - 1.
    let npdu_len = if tpci_apci_data.is_empty() {
        0
    } else {
        tpci_apci_data.len() - 1
    };

    let total_len = 9 + tpci_apci_data.len(); // header(2) + ctrl1 + ctrl2 + src(2) + dst(2) + npdu_len(1) + data
    let mut buf = vec![0u8; total_len];

    // cEMI header
    buf[0] = CemiMessageCode::LDataReq.into();
    buf[1] = 0x00; // no additional info

    // Control field 1:
    //   Bit 7: frame type (1 = standard)
    //   Bit 5: repeat (1 = do not repeat)
    //   Bit 4: system broadcast (1 = normal broadcast)
    //   Bit 2-3: priority (11 = low)
    //   Bit 0: confirm (0 = no error)
    buf[2] = 0xB0; // standard frame, no repeat, broadcast domain, priority low

    // Control field 2:
    //   Bit 7: address type (0 = individual, 1 = group)
    //   Bit 4-6: hop count (6 = default)
    //   Bit 0-3: extended frame format (0 = standard)
    buf[3] = 0x60; // AT=0 (individual), hop count=6, EFF=0

    // Source address
    buf[4] = source.as_bytes()[0];
    buf[5] = source.as_bytes()[1];

    // Destination address
    buf[6] = dest.as_bytes()[0];
    buf[7] = dest.as_bytes()[1];

    // NPDU length
    buf[8] = npdu_len as u8;

    // TPCI + APCI + data
    buf[9..9 + tpci_apci_data.len()].copy_from_slice(tpci_apci_data);

    buf
}

/// Build a cEMI T_Data_Individual.req frame.
///
/// Transport layer cEMI mode: the frame contains 6 reserved zero bytes
/// (no source/dest addresses), followed by the TPDU length and TPDU data.
pub fn build_tdata_individual_req(tpdu: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 2 + 6 + 1 + tpdu.len()];
    buf[0] = CemiMessageCode::TDataIndividualReq.into();
    buf[1] = 0x00; // no additional info
    // bytes 2-7 already zero (reserved)
    buf[8] = tpdu.len() as u8;
    buf[9..9 + tpdu.len()].copy_from_slice(tpdu);
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
