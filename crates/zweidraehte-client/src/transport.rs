//! Client-side KNX transport layer.
//!
//! Provides connected (point-to-point) and unconnected transport services.
//! This is a simplified client-side implementation — not the full device
//! stack state machine.

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::knx::offsets;

use crate::tunnel::codec::{self, CemiMode};

// ============================================================================
// TPCI byte patterns
// ============================================================================

/// TPCI for T_Connect: 0x80
const TPCI_CONNECT: u8 = 0x80;

/// TPCI for T_Disconnect: 0x81
const TPCI_DISCONNECT: u8 = 0x81;

/// TPCI for T_ACK: 0xC2 (with seq=0, will be OR'd with seq << 2)
const TPCI_ACK_BASE: u8 = 0xC2;

/// TPCI for T_Data_Connected: 0x40 (with seq=0, will be OR'd with seq << 2)
const TPCI_DATA_CONNECTED_BASE: u8 = 0x40;

// ============================================================================
// cEMI frame building
// ============================================================================

/// Build a cEMI frame for an unconnected (connectionless) message.
///
/// `apci_data` contains the combined TPCI+APCI region bytes. For unconnected
/// data, the TPCI bits (upper 6 bits of the first byte) are 0x00. The
/// management builders produce bytes where these upper bits are already zero,
/// so `apci_data` is passed through directly.
pub fn build_unconnected_cemi(
    source: IndividualAddress,
    dest: IndividualAddress,
    apci_data: &[u8],
    cemi_mode: CemiMode,
) -> Vec<u8> {
    match cemi_mode {
        CemiMode::LData => codec::build_ldata_req(source, dest, apci_data),
        CemiMode::TDataIndividual => {
            // TODO: Implement T_Data_Individual cEMI mode (msg code 0x4A).
            // For now, use L_Data mode.
            codec::build_ldata_req(source, dest, apci_data)
        }
    }
}

/// Build a cEMI frame for T_Connect (open transport connection).
pub fn build_connect_cemi(
    source: IndividualAddress,
    dest: IndividualAddress,
) -> Vec<u8> {
    codec::build_ldata_req(source, dest, &[TPCI_CONNECT])
}

/// Build a cEMI frame for T_Disconnect (close transport connection).
pub fn build_disconnect_cemi(
    source: IndividualAddress,
    dest: IndividualAddress,
) -> Vec<u8> {
    codec::build_ldata_req(source, dest, &[TPCI_DISCONNECT])
}

/// Build a cEMI frame for T_Data_Connected (numbered data in a transport connection).
///
/// The TPCI bits (0x40 | seq<<2) are OR'd into the first byte of `apci_data`,
/// since TPCI and the first APCI byte share the same byte in the KNX frame.
pub fn build_connected_data_cemi(
    source: IndividualAddress,
    dest: IndividualAddress,
    seq_no: u8,
    apci_data: &[u8],
) -> Vec<u8> {
    let tpci_bits = TPCI_DATA_CONNECTED_BASE | ((seq_no & 0x0F) << 2);
    let mut tpci_apci = apci_data.to_vec();
    if !tpci_apci.is_empty() {
        tpci_apci[0] |= tpci_bits;
    }
    codec::build_ldata_req(source, dest, &tpci_apci)
}

/// Build a cEMI frame for T_ACK (acknowledge a connected data packet).
pub fn build_ack_cemi(
    source: IndividualAddress,
    dest: IndividualAddress,
    seq_no: u8,
) -> Vec<u8> {
    let tpci_byte = TPCI_ACK_BASE | ((seq_no & 0x0F) << 2);
    codec::build_ldata_req(source, dest, &[tpci_byte])
}

// ============================================================================
// Response parsing helpers
// ============================================================================

/// Extract TPCI from the cEMI body's data region.
///
/// In cEMI L_Data, the TPCI byte is at body offset 7 (after ctrl1, ctrl2,
/// src(2), dst(2), npdu_len).
pub fn get_tpci(cemi_body: &[u8]) -> Option<u8> {
    if cemi_body.len() > 7 {
        Some(cemi_body[7])
    } else {
        None
    }
}

/// Check if the TPCI indicates a T_ACK.
pub fn is_tack(tpci: u8) -> bool {
    (tpci & 0xC3) == 0xC2
}

/// Get the sequence number from a T_ACK or T_Data_Connected TPCI.
pub fn get_seq_no(tpci: u8) -> u8 {
    (tpci >> 2) & 0x0F
}

/// Check if the TPCI indicates T_Data_Connected.
pub fn is_data_connected(tpci: u8) -> bool {
    (tpci & 0xC0) == 0x40
}

/// Check if the TPCI indicates unconnected data.
pub fn is_unconnected(tpci: u8) -> bool {
    (tpci & 0xC0) == 0x00
}
