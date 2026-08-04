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
