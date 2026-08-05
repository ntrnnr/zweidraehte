//! Group telegram types and decoding.

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::messages::knx::{ApciCode, DestinationAddress, KnxMessageBuffer, offsets};

/// The group-communication service a telegram carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupService {
    /// A_GroupValue_Read — a request for the current value; carries no data.
    Read,
    /// A_GroupValue_Write — an unsolicited value update.
    Write,
    /// A_GroupValue_Response — the answer to a read.
    Response,
}

/// One group telegram observed on the bus.
///
/// `data` is the raw APDU payload: for short-encoded values (6-bit DPTs)
/// it is a single byte holding the 6-bit value, for full-encoded values
/// the DPT-encoded bytes. DPT decoding is left to the consumer — see
/// [`zweidraehte_proto::dpt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupTelegram {
    pub source: IndividualAddress,
    pub group: GroupAddress,
    pub service: GroupService,
    pub data: Vec<u8>,
    /// Whether the telegram arrived in a KNX Data Secure envelope and
    /// was authenticated (and decrypted) under the group key. Plaintext
    /// telegrams on a secured group address never reach subscribers, so
    /// on such addresses this is always `true`.
    pub secured: bool,
}

impl GroupTelegram {
    /// Decode a group telegram from an internal-format L_Data.ind frame.
    ///
    /// Returns `None` for frames that are not group-addressed or don't
    /// carry a group-value APCI (e.g. A_GroupPropValue services).
    pub fn parse(internal: &[u8]) -> Option<Self> {
        if internal.len() < offsets::MSG_APCI + 2 {
            return None;
        }
        let msg = KnxMessageBuffer::from_buffer(internal);
        let DestinationAddress::Group(group) = msg.get_dest_addr() else {
            return None;
        };
        let source = msg.get_source_addr();

        let (service, data) = match msg.get_apci_code() {
            ApciCode::GroupValueRead => (GroupService::Read, Vec::new()),
            ApciCode::GroupValueWrite => (GroupService::Write, Self::value_bytes(internal)),
            ApciCode::GroupValueResponse => (GroupService::Response, Self::value_bytes(internal)),
            _ => return None,
        };

        Some(Self { source, group, service, data, secured: false })
    }

    /// Extract the value payload, handling both encodings: a frame ending
    /// right after the APCI byte carries a short (6-bit) value packed into
    /// that byte; anything longer carries the value in the APDU area.
    fn value_bytes(internal: &[u8]) -> Vec<u8> {
        if internal.len() <= offsets::MSG_APDU {
            vec![internal[offsets::MSG_APCI + 1] & 0x3F]
        } else {
            internal[offsets::MSG_APDU..].to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::frames::build_group_frame;
    use zweidraehte_proto::messages::apdu::group_value::{GroupValueEncoding, GroupValueWriteRequest};

    fn ga() -> GroupAddress {
        GroupAddress::from_three_level(2, 0, 3)
    }

    type ApduWriter = Box<dyn FnOnce(&mut [u8])>;

    fn build_write(data: &[u8], encoding: GroupValueEncoding) -> Vec<u8> {
        let (msg_len, writer): (usize, ApduWriter) = match encoding {
            GroupValueEncoding::Short => {
                let v = data[0];
                (
                    GroupValueWriteRequest::SHORT_MSG_LEN,
                    Box::new(move |buf: &mut [u8]| GroupValueWriteRequest::write_short(buf, v)),
                )
            }
            GroupValueEncoding::Full => {
                let d = data.to_vec();
                (
                    GroupValueWriteRequest::full_msg_len(data.len()),
                    Box::new(move |buf: &mut [u8]| GroupValueWriteRequest::write_full(buf, &d)),
                )
            }
        };
        build_group_frame(IndividualAddress::new(1, 1, 1), ga(), ApciCode::GroupValueWrite, msg_len, writer)
    }

    #[test]
    fn short_write_roundtrip() {
        let frame = build_write(&[1], GroupValueEncoding::Short);
        let tg = GroupTelegram::parse(&frame).expect("group frame parses");
        assert_eq!(tg.group, ga());
        assert_eq!(tg.service, GroupService::Write);
        assert_eq!(tg.data, vec![1]);
    }

    #[test]
    fn full_write_roundtrip() {
        let frame = build_write(&[0x12, 0x34], GroupValueEncoding::Full);
        let tg = GroupTelegram::parse(&frame).expect("group frame parses");
        assert_eq!(tg.data, vec![0x12, 0x34]);
    }

    #[test]
    fn read_has_no_data() {
        use zweidraehte_proto::messages::apdu::group_value::GroupValueReadRequest;
        let frame = build_group_frame(
            IndividualAddress::new(1, 1, 1),
            ga(),
            ApciCode::GroupValueRead,
            GroupValueReadRequest::MSG_LEN,
            GroupValueReadRequest::write,
        );
        let tg = GroupTelegram::parse(&frame).expect("group frame parses");
        assert_eq!(tg.service, GroupService::Read);
        assert!(tg.data.is_empty());
    }

    #[test]
    fn individual_frame_is_not_a_group_telegram() {
        use zweidraehte_proto::messages::knx::Tpci;
        let frame = crate::core::frames::build_individual_frame(
            IndividualAddress::new(1, 1, 1),
            IndividualAddress::new(1, 1, 2),
            Tpci::DataIndividual,
            ApciCode::DeviceDescriptorRead,
            offsets::MSG_APCI + 2,
            |_| {},
        );
        assert!(GroupTelegram::parse(&frame).is_none());
    }
}
