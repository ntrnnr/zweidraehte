//use packet::{
//    BufferView, BufferViewMut, FragmentedBytesMut, PacketBuilder, PacketConstraints,
//    ParsablePacket, ParseMetadata, SerializeTarget,
//};
//use zerocopy::{IntoBytes, Ref, SplitByteSlice};
use zerocopy::SplitByteSlice;

//use crate::packets::address::KNXAddress;
//use crate::packets::error::{ParseError, ParseResult};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NPDU<B: SplitByteSlice> {
    length: u8,
    hop_count: u8,
    tpdu: TPDU<B>,
}

impl<B: SplitByteSlice> NPDU<B> {
    pub fn len(&self) -> u8 {
        self.length
    }

    pub fn hop_count(&self) -> u8 {
        self.hop_count
    }

    pub fn tpdu(self) -> TPDU<B> {
        self.tpdu
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TPDU<B: SplitByteSlice> {
    DataBroadcast(APDU<B>),
    DataGroup(APDU<B>),
    DataTagGroup,
    DataIndividual(APDU<B>),
    DataConnected(u8, APDU<B>),
    Connect,
    Disconnect,
    Ack(u8),
    Nak(u8),
}

create_protocol_enum!(
    #[allow(missing_docs)]
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
    pub enum ApplicationLayerService: u16 {
        GroupValueRead, 0x00, "A_GroupValue_Read";
        GroupValueResponse, 0x01, "A_GroupValue_Response";
        GroupValueWrite, 0x02, "A_GroupValue_Write";

        IndividualAddressWrite, 0x03, "A_IndividualAddress_Write";
        IndividualAddressRead, 0x04, "A_IndividualAddress_Read";
        IndividualAddressResponse, 0x05, "A_IndividualAddress_Response";

        AdcRead, 0x06, "A_ADC_Read";
        AdcResponse, 0x07, "A_ADC_Response";

        SystemNetworkParameterRead, 0x01C8, "A_SystemNetworkParameter_Read";
        SystemNetworkParameterResponse, 0x01C9, "A_SystemNetworkParameter_Response";
        SystemNetworkParameterWrite, 0x01CA, "A_SystemNetworkParameter_Write";

        PropertyExtValueRead, 0x01CC, "A_PropertyExtValue_Read";
        PropertyExtValueResponse, 0x01CD, "A_PropertyExtValue_Response";
        PropertyExtValueWriteCon, 0x01CE, "A_PropertyExtValue_WriteCon";
        PropertyExtValueWriteConRes, 0x01CF, "A_PropertyExtValue_WriteConRes";
        PropertyExtValueWriteUnCon, 0x01D0, "A_PropertyExtValue_WriteUnCon";
        PropertyExtValueInfoReport, 0x01D1, "A_PropertyExtValue_InfoReport";

        PropertyExtDescriptionRead, 0x01D2, "A_PropertyExtDescription_Read";
        PropertyExtDescriptionResponse, 0x01D3, "A_PropertyExtDescription_Response";

        FunctionPropertyExtCommand, 0x01D4, "A_FunctionPropertyExtCommand";
        FunctionPropertyExtStateRead, 0x01D5, "A_FunctionPropertyExtState_Read";
        FunctionPropertyExtStateResponse, 0x01D6, "A_FunctionPropertyExtState_Response";

        MemoryExtendedWrite, 0x01FB, "A_MemoryExtended_Write";
        MemoryExtendedWriteResponse, 0x01FC, "A_MemoryExtended_WriteResponse";
        MemoryExtendedRead, 0x01FD, "A_MemoryExtended_Read";
        MemoryExtendedReadResponse, 0x01FE, "A_MemoryExtended_ReadResponse";

        UserMemoryRead, 0x08, "A_Memory_Read";
        UserMemoryResponse, 0x09, "A_Memory_Response";
        UserMemoryWrite, 0x0A, "A_Memory_Write";

        _, "Unknown Version 0x{:x}";
    }
);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum APDU<B: SplitByteSlice> {
    ShortAPCI(ApplicationLayerService, u8, B),
    LongAPCI(ApplicationLayerService, B),
}

// #[derive(Debug)]
// pub struct NPDUParseArgs {
//     pub dst_addr: KNXAddress,
//     pub hop_count: u8, // FIXME: it's annoying that we need this, but the packet
//                        //        layout is so braindead, that L3 info (the hop count)
//                        //        is right in the middle of L2 data (03.02.02/2.2.5.1 Figure 33)
//                        //        We can't parse this just from packet data, because this field
//                        //        is in a part of the buffer that was already consumed, so we pass it in
// }

// impl<B: SplitByteSlice> ParsablePacket<B, NPDUParseArgs> for NPDU<B> {
//     type Error = ParseError;

//     fn parse_metadata(&self) -> ParseMetadata {
//         ParseMetadata::from_packet(1, 0, 0)
//     }

//     fn parse<BV: BufferView<B>>(mut buffer: BV, args: NPDUParseArgs) -> ParseResult<Self> {
//         // FIXME: add 2 to the length for len-field and TCPI?
//         let length = buffer
//             .take_byte_front()
//             .ok_or_else(debug_err_fn!(ParseError::Format, "too few bytes for NPDU"))?;

//         let tpci: Ref<B, [u8]> = buffer.take_slice_front(2).ok_or_else(debug_err_fn!(
//             ParseError::Format,
//             "too few bytes for TPDU and APDU"
//         ))?;

//         let ctrl = (tpci[0] & 0x80) != 0;
//         let numbered = (tpci[0] & 0x40) != 0;

//         // Parse the APDU
//         let apdu = if ctrl {
//             None
//         } else {
//             let apci_word = u16::from_be_bytes(tpci.as_bytes().try_into().unwrap()) & 0x03ff;
//             let apci = apci_word >> 6;

//             if apci < 11 && apci != 7 {
//                 Some(APDU::ShortAPCI(
//                     apci.into(),
//                     (apci_word & 0x003F) as u8,
//                     buffer.into_rest(),
//                 ))
//             } else {
//                 Some(APDU::LongAPCI(apci.into(), buffer.into_rest()))
//             }
//         };

//         // Parse the TPDU after we know if there is an APDU
//         let tpdu = if ctrl {
//             // If ctrl bit is set, we have 8 bits for the TPCI
//             if numbered {
//                 if (tpci[0] & 0x03) == 0b10 {
//                     TPDU::Ack((tpci[0] >> 2) & 0x0F)
//                 } else if (tpci[0] & 0x03) == 0b11 {
//                     TPDU::Nak((tpci[0] >> 2) & 0x0F)
//                 } else {
//                     return debug_err!(
//                         Err(ParseError::NotExpected),
//                         "Unexpected numbered control bit combo"
//                     );
//                 }
//             } else {
//                 if tpci[0] & 0x3F == 0 {
//                     TPDU::Connect
//                 } else if tpci[0] & 0x3F == 1 {
//                     TPDU::Disconnect
//                 } else {
//                     return debug_err!(
//                         Err(ParseError::NotExpected),
//                         "Unexpected unnumbered control bit combo"
//                     );
//                 }
//             }
//         } else {
//             if let Some(apdu) = apdu {
//                 // ... otherwise it's only 6 bits
//                 if args.dst_addr.is_group_address()
//                     && args.dst_addr.as_bytes() == &[0, 0]
//                     && (tpci[0] & 0x3F) == 0x00
//                 {
//                     TPDU::DataBroadcast(apdu)
//                 } else if args.dst_addr.is_group_address()
//                     && args.dst_addr.as_bytes() != &[0, 0]
//                     && (tpci[0] & 0x3F) == 0x00
//                 {
//                     TPDU::DataGroup(apdu)
//                 } else if numbered {
//                     TPDU::DataConnected((tpci[0] >> 2) & 0x0F, apdu)
//                 } else if args.dst_addr.is_individual_address() && (tpci[0] >> 2) & 0x0F == 0 {
//                     TPDU::DataIndividual(apdu)
//                 } else {
//                     return debug_err!(
//                         Err(ParseError::NotExpected),
//                         "Unexpected data bit combo with APDU"
//                     );
//                 }
//             } else {
//                 return debug_err!(
//                     Err(ParseError::NotExpected),
//                     "Unexpected data bit combo without APDU"
//                 );
//             }
//         };

//         Ok(NPDU {
//             length,
//             hop_count: args.hop_count,
//             tpdu,
//         })
//     }
// }

// #[derive(Debug)]
// pub struct NPDUBuilder;

// impl NPDUBuilder {
//     pub fn new() -> Self {
//         Self
//     }
// }

// impl PacketBuilder for NPDUBuilder {
//     fn constraints(&self) -> PacketConstraints {
//         // FIXME: differentiate between standard and extended frames?
//         //        They have different max body lengths

//         // For extended frames:
//         // Minimum length is 1, because the length is counted AFTER the TCPI octet
//         // Maximum length is 254 for the data and 1 for the TPCI octet
//         // The NPDU itself is just one byte containing the length octet
//         PacketConstraints::new(1, 0, 1, 254 + 1)
//     }

//     fn serialize(&self, target: &mut SerializeTarget<'_>, body: FragmentedBytesMut<'_, '_>) {
//         let mut prefix = &mut &mut target.header[..];

//         let mut l = prefix
//             .take_obj_front_zero::<u8>()
//             .expect("too few bytes for length octet in NPDU");

//         // FIXME: TEST THIS LOGIC!
//         // -1 should be correct here, because the length octet contains the length after the TPCI octet
//         // we didn't take the NPDU len octet into account yet, because this is what we are adding here
//         // then after this, the TPCI octet follows which is already part of the body that is wrapped here,
//         // so we subtract one byte
//         *l = (body.len() - 1)
//             .try_into()
//             .expect("body length overflowing octet length field in NPDU");
//     }
// }

// #[cfg(test)]
// mod test {
//     use packet::{ParsablePacket, ParseBuffer, Serializer};
//     use zerocopy::IntoBytes;

//     use crate::packets::{
//         address::{KNXAddress, KNXGroupAddress},
//         knx::cemi::{APDU, ApplicationLayerService, TPDU},
//     };

//     use super::{NPDU, NPDUParseArgs};

//     #[test]
//     fn test_parse() {
//         let reference = [1u8, 0, 0x80];
//         let parse_args = NPDUParseArgs {
//             dst_addr: KNXAddress::Group(KNXGroupAddress::from_three_level(1, 0, 0)),
//             hop_count: 3,
//         };

//         let mut buf = reference.as_ref();
//         let parsed = NPDU::parse(&mut buf, parse_args).unwrap();

//         assert_eq!(
//             NPDU {
//                 hop_count: 3,
//                 length: 1,
//                 tpdu: TPDU::DataGroup(APDU::ShortAPCI(
//                     ApplicationLayerService::GroupValueWrite,
//                     0,
//                     &[][..]
//                 ))
//             },
//             parsed
//         );
//     }
// }
