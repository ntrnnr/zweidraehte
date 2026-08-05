//! Frame construction and conversion for outgoing client traffic.
//!
//! Frames are built in the internal KNX message format (the compact 7-byte
//! layout the proto crate's APDU writers expect) using
//! `KnxMessageBuffer<Vec<u8>>`, and converted to cEMI right before they go
//! into a connector. Keeping the internal format up to the driver lets it
//! stamp the connected-transport sequence number without re-parsing cEMI.

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::encoding::cemi::{CemiMessageCode, cemi_to_knx_message, knx_to_cemi_message};
use zweidraehte_proto::messages::knx::{
    ApciCode, DestinationAddress, KnxMessageBuffer, Priority, ServiceType, Tpci, offsets,
};

// ============================================================================
// Internal ⇄ cEMI conversion
// ============================================================================

/// Convert an internal-format KNX message to a cEMI frame.
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

/// Convert a received cEMI frame to the internal format.
pub fn cemi_to_internal(cemi: &[u8]) -> Vec<u8> {
    cemi_to_knx_message(cemi.to_vec())
}

// ============================================================================
// Internal-format frame builders
// ============================================================================

fn new_frame(msg_len: usize, priority: Priority) -> KnxMessageBuffer<Vec<u8>> {
    let mut msg = KnxMessageBuffer::new(vec![0u8; msg_len], ServiceType::L_Data_Req);
    msg.ctrl_field_mut().set_priority(priority);
    msg
}

/// Build a transport-control frame (no application data): T_Connect,
/// T_Disconnect, T_ACK, T_NAK.
pub fn build_transport_frame(source: IndividualAddress, dest: IndividualAddress, tpci: Tpci) -> Vec<u8> {
    let mut msg = new_frame(offsets::MSG_TPCI + 1, Priority::System);
    msg.set_source_addr(source);
    msg.set_dest_addr(DestinationAddress::Individual(dest));
    msg.set_tpci(tpci);
    msg.into_inner()
}

/// Build an individually addressed application frame.
///
/// `tpci` selects connectionless (`Tpci::DataIndividual`) or connected
/// (`Tpci::DataConnected(0)`) transport; for connected frames the driver
/// stamps the live sequence number via [`set_connected_seq`] right before
/// sending.
pub fn build_individual_frame(
    source: IndividualAddress,
    dest: IndividualAddress,
    tpci: Tpci,
    apci: ApciCode,
    msg_len: usize,
    data_writer: impl FnOnce(&mut [u8]),
) -> Vec<u8> {
    let mut msg = new_frame(msg_len, Priority::System);
    msg.set_source_addr(source);
    msg.set_dest_addr(DestinationAddress::Individual(dest));
    msg.set_tpci(tpci);
    msg.set_apci_code(apci);
    data_writer(msg.buf_mut());
    msg.into_inner()
}

/// Build a broadcast application frame (NM_* services: programming-mode IA
/// read/write, serial-number services).
pub fn build_broadcast_frame(
    source: IndividualAddress,
    apci: ApciCode,
    msg_len: usize,
    data_writer: impl FnOnce(&mut [u8]),
) -> Vec<u8> {
    let mut msg = new_frame(msg_len, Priority::System);
    msg.set_source_addr(source);
    msg.set_dest_addr(DestinationAddress::Broadcast);
    msg.set_tpci(Tpci::DataBroadcast);
    msg.set_apci_code(apci);
    data_writer(msg.buf_mut());
    msg.into_inner()
}

/// Build a group application frame (A_GroupValue_Read/Write).
pub fn build_group_frame(
    source: IndividualAddress,
    group: GroupAddress,
    apci: ApciCode,
    msg_len: usize,
    data_writer: impl FnOnce(&mut [u8]),
) -> Vec<u8> {
    let mut msg = new_frame(msg_len, Priority::Low);
    msg.set_source_addr(source);
    msg.set_dest_addr(DestinationAddress::Group(group));
    msg.set_tpci(Tpci::DataGroup);
    msg.set_apci_code(apci);
    data_writer(msg.buf_mut());
    msg.into_inner()
}

/// Build a complete S-A_Sync_Req frame (tool access, P2P, connectionless).
///
/// The sync service may ride `T_Data_Individual` or `T_Data_Connected`
/// per 03/03/07 §5.3.2; we send it connectionless, like ETS and the
/// device stack's own sync initiator, so it stays outside the TL
/// sequence numbering.
///
/// Unlike the other builders this one takes the real `source` address —
/// it is part of the CCM nonce, so the MAC is only valid for the
/// address actually stamped on the wire. The serial-number field is
/// all-zero (valid for P2P; a serial is only required on broadcast).
///
/// `seq_nr_local` is the channel's peeked tool sequence number — the
/// sync service advertises the *next* number to be used, so nothing is
/// consumed here.
pub fn build_sync_req_frame(
    source: IndividualAddress,
    dest: IndividualAddress,
    key: &[u8; 16],
    seq_nr_local: &[u8; 6],
    challenge: &[u8; 6],
) -> Vec<u8> {
    use zweidraehte_proto::crypto::ccm::{self, CcmContext};
    use zweidraehte_proto::crypto::scf::{SecureServiceType, SecurityControlField};
    use zweidraehte_proto::messages::apdu::secure::{self, sync};

    let mut msg = new_frame(sync::FRAME_LEN, Priority::System);
    msg.set_source_addr(source);
    msg.set_dest_addr(DestinationAddress::Individual(dest));
    msg.set_tpci(Tpci::DataIndividual);

    let scf_byte = SecurityControlField {
        service: SecureServiceType::SyncRequest,
        system_broadcast: false,
        confidentiality: true,
        tool_access: true,
    }
    .encode();

    let buf = msg.buf_mut();
    let tpci_high = buf[offsets::MSG_TPCI] & 0xFC;
    buf[offsets::MSG_TPCI] = tpci_high | 0x03;
    buf[offsets::MSG_TPCI + 1] = 0xF1;
    buf[secure::SCF] = scf_byte;
    buf[secure::SEQ_NR..secure::SEQ_NR + 6].copy_from_slice(seq_nr_local);
    buf[sync::SERIAL_NUMBER..sync::SERIAL_NUMBER + 6].fill(0);

    let ccm_ctx = CcmContext {
        seq_nr: *seq_nr_local,
        src: u16::from_be_bytes(source.0),
        dst: u16::from_be_bytes(dest.0),
        addr_type: buf[offsets::MSG_ADDR_TYPE] & 0x80,
        tpci_apci: u16::from_be_bytes([tpci_high | 0x03, 0xF1]),
    };
    let mut challenge_enc = *challenge;
    let mac = ccm::encrypt_and_mac_sync_req(key, &ccm_ctx, scf_byte, &[0u8; 6], &mut challenge_enc);

    buf[sync::CHALLENGE..sync::CHALLENGE + 6].copy_from_slice(&challenge_enc);
    buf[sync::FRAME_LEN - secure::MAC_LEN..sync::FRAME_LEN].copy_from_slice(&mac);

    msg.into_inner()
}

/// Stamp the connected-transport sequence number into an already built
/// internal-format frame (built with `Tpci::DataConnected(0)`).
///
/// Numbered-data TPCI layout (03/03/04 §1.4): bits 7..6 = 01, bits 5..2 =
/// sequence number, bits 1..0 = APCI high bits — only the four sequence
/// bits change here.
pub fn set_connected_seq(internal: &mut [u8], seq: u8) {
    internal[offsets::MSG_TPCI] = (internal[offsets::MSG_TPCI] & !0x3C) | ((seq & 0x0F) << 2);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_seq_stamp_roundtrips() {
        let mut frame = build_individual_frame(
            IndividualAddress::new(15, 15, 250),
            IndividualAddress::new(1, 1, 42),
            Tpci::DataConnected(0),
            ApciCode::MemoryRead,
            offsets::MSG_APCI + 4,
            |_| {},
        );
        set_connected_seq(&mut frame, 11);

        let msg = KnxMessageBuffer::from_buffer(frame);
        assert_eq!(msg.get_tpci(), Some(Tpci::DataConnected(11)));
        assert_eq!(msg.get_apci_code(), ApciCode::MemoryRead);
        assert_eq!(msg.get_dest_addr(), DestinationAddress::Individual(IndividualAddress::new(1, 1, 42)));
    }

    #[test]
    fn broadcast_frame_shape() {
        let frame = build_broadcast_frame(
            IndividualAddress::new(15, 15, 250),
            ApciCode::IndividualAddressRead,
            offsets::MSG_APCI + 2,
            |_| {},
        );
        let msg = KnxMessageBuffer::from_buffer(frame);
        assert_eq!(msg.get_tpci(), Some(Tpci::DataBroadcast));
        assert_eq!(msg.get_dest_addr(), DestinationAddress::Broadcast);
        assert_eq!(msg.get_apci_code(), ApciCode::IndividualAddressRead);
    }
}
