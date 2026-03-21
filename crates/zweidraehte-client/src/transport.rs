//! Client-side KNX transport layer.
//!
//! Builds outgoing KNX messages using `KnxMessageBuffer<Vec<u8>>` in internal
//! format, then converts to cEMI for transmission through the tunnel. Also
//! provides helpers for parsing incoming cEMI transport fields.

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::encoding::cemi::CemiMessageCode;
use zweidraehte_proto::messages::knx::{
    ApciCode, DestinationAddress, KnxMessageBuffer, Priority, ServiceType, Tpci, offsets,
};

use crate::tunnel::codec::{self, CemiMode};

// ============================================================================
// Internal message construction
// ============================================================================

/// Build a transport-only cEMI frame (no application data).
///
/// Used for T_Connect, T_Disconnect, T_ACK — messages that carry only a TPCI
/// byte with no APCI payload.
fn build_transport_cemi(
    source: IndividualAddress,
    dest: IndividualAddress,
    tpci: Tpci,
) -> Vec<u8> {
    // Internal format: ctrl(1) + src(2) + dst(2) + npdu(1) + tpci(1) = 7 bytes
    let mut msg = KnxMessageBuffer::new(vec![0u8; offsets::MSG_TPCI + 1], ServiceType::L_Data_Req);
    msg.ctrl_field_mut().set_priority(Priority::System);
    msg.set_source_addr(source);
    msg.set_dest_addr(DestinationAddress::Individual(dest));
    msg.set_tpci(tpci);
    codec::internal_to_cemi(&msg.into_inner(), CemiMessageCode::LDataReq)
}

/// Build a cEMI frame carrying an application-layer message.
///
/// Sets TPCI, APCI code, and calls `data_writer` to fill in the APDU payload.
/// Used for both connected and unconnected data messages.
fn build_app_cemi(
    source: IndividualAddress,
    dest: IndividualAddress,
    tpci: Tpci,
    apci: ApciCode,
    msg_len: usize,
    data_writer: impl FnOnce(&mut [u8]),
) -> Vec<u8> {
    let mut msg = KnxMessageBuffer::new(vec![0u8; msg_len], ServiceType::L_Data_Req);
    msg.ctrl_field_mut().set_priority(Priority::System);
    msg.set_source_addr(source);
    msg.set_dest_addr(DestinationAddress::Individual(dest));
    msg.set_tpci(tpci);
    msg.set_apci_code(apci);
    data_writer(msg.buf_mut());
    codec::internal_to_cemi(&msg.into_inner(), CemiMessageCode::LDataReq)
}

// ============================================================================
// Public cEMI frame builders
// ============================================================================

/// Build a cEMI frame for an unconnected (connectionless) application message.
pub fn build_unconnected_cemi(
    source: IndividualAddress,
    dest: IndividualAddress,
    apci: ApciCode,
    msg_len: usize,
    data_writer: impl FnOnce(&mut [u8]),
    _cemi_mode: CemiMode,
) -> Vec<u8> {
    // TODO: Implement T_Data_Individual cEMI mode (msg code 0x4A).
    // For now, all modes use L_Data framing.
    build_app_cemi(source, dest, Tpci::DataIndividual, apci, msg_len, data_writer)
}

/// Build a cEMI frame for T_Connect (open transport connection).
pub fn build_connect_cemi(
    source: IndividualAddress,
    dest: IndividualAddress,
) -> Vec<u8> {
    build_transport_cemi(source, dest, Tpci::Connect)
}

/// Build a cEMI frame for T_Disconnect (close transport connection).
pub fn build_disconnect_cemi(
    source: IndividualAddress,
    dest: IndividualAddress,
) -> Vec<u8> {
    build_transport_cemi(source, dest, Tpci::Disconnect)
}

/// Build a cEMI frame for T_Data_Connected (numbered data in a transport connection).
pub fn build_connected_data_cemi(
    source: IndividualAddress,
    dest: IndividualAddress,
    seq_no: u8,
    apci: ApciCode,
    msg_len: usize,
    data_writer: impl FnOnce(&mut [u8]),
) -> Vec<u8> {
    build_app_cemi(source, dest, Tpci::DataConnected(seq_no), apci, msg_len, data_writer)
}

/// Build a cEMI frame for T_ACK (acknowledge a connected data packet).
pub fn build_ack_cemi(
    source: IndividualAddress,
    dest: IndividualAddress,
    seq_no: u8,
) -> Vec<u8> {
    build_transport_cemi(source, dest, Tpci::Ack(seq_no))
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
