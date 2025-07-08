use core::ops::{Deref, DerefMut};

use crate::address::{GroupAddress, IndividualAddress};

// Message offsets based on the KAIstack constants
// This is essentially the TP1 frame format
// FIXME: What about the length fied in 5[0..3]?
pub mod offsets {
    pub const MSG_CONTROL: usize = 0;
    pub const MSG_SOURCE_ADDR: usize = 1;
    pub const MSG_DEST_ADDR: usize = 3;
    pub const MSG_CONN_NR: usize = MSG_DEST_ADDR;
    pub const MSG_NPDU: usize = 5;
    pub const MSG_ADDR_TYPE: usize = 5; // address type (bit 7)
    pub const MSG_ROUTE_CNT: usize = 5; // routing count (bit 4-6)
    pub const MSG_TPCI: usize = 6;
    pub const MSG_APCI: usize = 6;
    pub const MSG_APDU: usize = 8;
}

create_protocol_enum!(
    /// KNX service types
    #[derive(Eq, PartialEq, Copy, Clone)]
    #[allow(non_camel_case_types)]
    pub enum ServiceType: u8 {
        L_Data_Req,                 0x11,   "L_Data.req";
        L_Data_Ind,                 0x29,   "L_Data.ind";
        L_Data_Con,                 0x2e,   "L_Data.con";
        N_GroupData_Req,            0x22,   "N_GroupData.req";
        N_GroupData_Ind,            0x3a,   "N_GroupData.ind";
        N_GroupData_Con,            0x3e,   "N_GroupData.con";
        N_Data_Req,                 0x21,   "N_Data.req";
        N_Data_Ind,                 0x49,   "N_Data.ind";
        N_Data_Con,                 0x4e,   "N_Data.con";
        N_Broadcast_Req,            0x2c,   "N_Broadcast.req";
        N_Broadcast_Ind,            0x4d,   "N_Broadcast.ind";
        N_Broadcast_Con,            0x4f,   "N_Broadcast.con";
        N_SystemBroadcast_Req,      0x27,   "N_SystemBroadcast.req";
        N_SystemBroadcast_Ind,      0x48,   "N_SystemBroadcast.ind";
        N_SystemBroadcast_Con,      0x45,   "N_SystemBroadcast.con";
        T_Data_Req,                 0x41,   "T_Data.req";
        T_Data_Ind,                 0x89,   "T_Data.ind";
        T_Data_Con,                 0x8e,   "T_Data.con";
        T_GroupData_Req,            0x32,   "T_GroupData.req";
        T_GroupData_Ind,            0x7a,   "T_GroupData.ind";
        T_GroupData_Con,            0x7e,   "T_GroupData.con";
        T_Broadcast_Req,            0x4c,   "T_Broadcast.req";
        T_Broadcast_Ind,            0x8d,   "T_Broadcast.ind";
        T_Broadcast_Con,            0x8f,   "T_Broadcast.con";
        T_SystemBroadcast_Req,      0x47,   "T_SystemBroadcast.req";
        T_SystemBroadcast_Ind,      0x98,   "T_SystemBroadcast.ind";
        T_SystemBroadcast_Con,      0x95,   "T_SystemBroadcast.con";
        T_DataUnack_Req,            0x4a,   "T_DataUnack.req";
        T_DataUnack_Ind,            0x94,   "T_DataUnack.ind";
        T_DataUnack_Con,            0x9c,   "T_DataUnack.con";
        T_Connect_Req,              0x43,   "T_Connect.req";
        T_Connect_Ind,              0x85,   "T_Connect.ind";
        T_Connect_Con,              0x86,   "T_Connect.con";
        T_Disconnect_Req,           0x44,   "T_Disconnect.req";
        T_Disconnect_Ind,           0x87,   "T_Disconnect.ind";
        T_Disconnect_Con,           0x88,   "T_Disconnect.con";
        _,                                  "Unknown service type 0x{:x}";
    }
);

create_protocol_enum!(
    /// Priority levels
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum Priority: u8 {
        System,                     0,      "System";
        High,                       1,      "High";
        Alarm,                      2,      "Alarm";
        Low,                        3,      "Low";
        _,                                  "Unknown priority 0x{:x}";
    }
);

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Tpci {
    // FIXME: Individual, Group, Broadcast, SystemBroadcast are network layer things to be precise
    //        Change this to unnumbered/numbered control/data packets??
    DataBroadcast,
    DataSystemBroadcast,
    DataGroup,
    //DataTagGroup,
    DataIndividual,
    DataConnected(u8),
    Connect,
    Disconnect,
    Ack(u8),
    Nack(u8),
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum DestinationAddress {
    Individual(IndividualAddress),
    Group(GroupAddress),
    Broadcast,
    SystemBroadcast,
}

create_protocol_enum!(
    /// APCI codes
    ///
    /// This uses an internal coding scheme which is converted to the actual
    /// codes in the `get_apci_code` and `set_apci_code` methods.
    ///
    /// The code itself is just the lower 6 bits, the upper 2 bits are used fo
    /// a category which is then blown up to the remaining 4 bits in the encoded
    /// message. They are also weirdly split among multiple bytes - see spec. 03/03/07
    ///
    /// 0000 xxxx   - Short APCI codes (opcode is only the lower 4 bits)
    /// 01xx xxxx   - Extended APCI codes
    /// 10xx xxxx   - User APCI codes
    /// 11xx xxxx   - Escaped APCI codes
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum ApciCode: u8 {
        GroupValueRead,             0,      "A_GroupValue_Read";
        GroupValueResponse,         1,      "A_GroupValue_Response";
        GroupValueWrite,            2,      "A_GroupValue_Write";
        IndividualAddressWrite,     3,      "A_IndividualAddress_Write";
        IndividualAddressRead,      4,      "A_IndividualAddress_Read";
        IndividualAddressResponse,  5,      "A_IndividualAddress_Response";
        AdcRead,                    6,      "A_ADC_Read";
        AdcResponse,                7,      "A_ADC_Response";
        MemoryRead,                 8,      "A_Memory_Read";
        MemoryReadResponse,         9,      "A_Memory_Response";
        MemoryWrite,                0x0a,   "A_Memory_Write";
        UserMessage,                0x0b,   "A_UserMsg";
        DeviceDescriptorRead,       0x0c,   "A_DeviceDescriptor_Read";
        DeviceDescriptorResponse,   0x0d,   "A_DeviceDescriptor_Response";
        Restart,                    0x0e,   "A_Restart";
        Escape,                     0x0f,   "A_Escape";

        SystemNetworkParameterRead, 0x48,   "A_SystemNetworkParameter_Read";

        FunctionPropertyCommand,    0x87,   "A_FunctionPropertyCommand";

        PropertyValueRead,          0xd5,   "A_PropertyValue_Read";

        Empty,                      0,      "<Empty>";
        _,                                  "Unknown APCI code 0x{:x}";
    }
);

create_protocol_enum!(
    /// Address types
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum AddressType: u8 {
        Individual,                 0,      "Individual address";
        Broadcast,                  0x90,   "Broadcast address";
        SystemBroadcast,            0x91,   "System broadcast address";
        Group,                      0x80,   "Group address";
        _,                                  "Unknown address type 0x{:x}";
    }
);

create_protocol_enum!(
    /// Hop count types
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum HopCountType: u8 {
        Unlimited,                  7,      "Hop count = 7 (unlimited)";
        Default,                    0,      "Default hop count as set by network layer";
        _,                                  "Unknown address type 0x{:x}";
    }
);

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum FrameType: bool {
        Standard, true, "Standard";
        Extended, false, "Extended";
    }
);

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum Repetition: bool {
        WasNotRepeated, true, "not repeated";
        WasRepeated, false, "repeated";

        AllowRepetition, true, "Allow repetitions";
        DoNotRepeat, false, "Do not repeat";
    }
);

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum SystemBroadcast: bool {
        NoSysBroadcast, true, "No System Broadcast";
        SysBroadcast, false, "System Broadcast";
    }
);

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum AckType: bool {
        AckRequested, true, "ACK requested";
        AckDontCare, false, "ACK don't care";
    }
);

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum Confirm: bool {
        Err, true, "Error";
        NoError, false, "No error";
    }
);

/// A KNX message CTRL1 field.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Ctrl1Field(u8);

impl Ctrl1Field {
    const FT_FLAG_MASK: u8 = 0b10000000;
    const R_FLAG_MASK: u8 = 0b00100000;
    const SB_FLAG_MASK: u8 = 0b00010000;
    const A_FLAG_MASK: u8 = 0b00000010;
    const C_FLAG_MASK: u8 = 0b00000001;

    const P_SHIFT: u8 = 2;
    const P_LEN: u8 = 2;
    const P_MAX: u8 = (1 << Self::P_LEN) - 1;
    const P_MASK: u8 = (Self::P_MAX as u8) << Self::P_SHIFT;

    pub fn new(flags: u8) -> Self {
        Self(flags)
    }

    fn get_flag(&self, mask: u8) -> bool {
        self.0 & mask > 0
    }

    fn set_flag(&mut self, mask: u8, set: bool) {
        let v = self.0;
        self.0 = if set { v | mask } else { v & !mask };
    }

    pub fn ft(&self) -> FrameType {
        self.get_flag(Self::FT_FLAG_MASK).try_into().unwrap()
    }

    pub fn set_ft<FT: Into<bool>>(&mut self, ft: FT) {
        self.set_flag(Self::FT_FLAG_MASK, ft.into());
    }

    pub fn r(&self) -> Repetition {
        self.get_flag(Self::R_FLAG_MASK).try_into().unwrap()
    }

    pub fn set_r<R: Into<bool>>(&mut self, r: R) {
        self.set_flag(Self::R_FLAG_MASK, r.into());
    }

    pub fn sb(&self) -> SystemBroadcast {
        self.get_flag(Self::SB_FLAG_MASK).try_into().unwrap()
    }

    pub fn set_sb<SB: Into<bool>>(&mut self, sb: SB) {
        self.set_flag(Self::SB_FLAG_MASK, sb.into());
    }

    pub fn priority(&self) -> Priority {
        ((self.0 & Self::P_MASK) >> Self::P_SHIFT).try_into().unwrap()
    }

    pub fn set_priority<P: Into<u8>>(&mut self, priority: P) {
        let priority: u8 = priority.into();
        debug_assert!(priority <= Self::P_MAX);
        let v = self.0;
        self.0 = (v & !Self::P_MASK) | (priority) << Self::P_SHIFT;
    }

    // FIXME: A should only be valid for L_Data.req
    pub fn a(&self) -> AckType {
        self.get_flag(Self::A_FLAG_MASK).try_into().unwrap()
    }

    pub fn set_a<A: Into<bool>>(&mut self, a: A) {
        self.set_flag(Self::A_FLAG_MASK, a.into());
    }

    // FIXME: C should only be valid for L_Data.con
    pub fn c(&self) -> Confirm {
        self.get_flag(Self::C_FLAG_MASK).try_into().unwrap()
    }

    pub fn set_c(&mut self, c: Confirm) {
        self.set_flag(Self::C_FLAG_MASK, c.into());
    }
}

impl From<u8> for Ctrl1Field {
    fn from(value: u8) -> Self {
        Ctrl1Field(value)
    }
}

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum DataControl: bool {
        Control, true, "Control";
        Data, false, "Data";
    }
);

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum Numbered: bool {
        Numbered, true, "Numbered";
        Unnumbered, false, "Unnumbered";
    }
);

create_protocol_enum!(
    /// TPCI Control Type
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum ControlType: u8 {
        Connect,    0,  "Connect";
        Disconnect, 1,  "Disconnect";
        ACK,        2,  "ACK";
        NACK,       3,  "NACK";
        _,              "Unknown control type 0x{:x}";
    }
);

/// A KNX message TPCI field.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct TpciField(u8);

impl TpciField {
    const DC_FLAG_MASK: u8 = 0b10000000;
    const N_FLAG_MASK: u8 = 0b01000000;

    const SEQNO_SHIFT: u8 = 2;
    const SEQNO_LEN: u8 = 4;
    const SEQNO_MAX: u8 = (1 << Self::SEQNO_LEN) - 1;
    const SEQNO_MASK: u8 = (Self::SEQNO_MAX as u8) << Self::SEQNO_SHIFT;

    const CTRLT_SHIFT: u8 = 0;
    const CTRLT_LEN: u8 = 2;
    const CTRLT_MAX: u8 = (1 << Self::CTRLT_LEN) - 1;
    const CTRLT_MASK: u8 = (Self::CTRLT_MAX as u8) << Self::CTRLT_SHIFT;

    pub fn new(flags: u8) -> Self {
        Self(flags)
    }

    fn get_flag(&self, mask: u8) -> bool {
        self.0 & mask > 0
    }

    fn set_flag(&mut self, mask: u8, set: bool) {
        let v = self.0;
        self.0 = if set { v | mask } else { v & !mask };
    }

    pub fn dc(&self) -> DataControl {
        self.get_flag(Self::DC_FLAG_MASK).try_into().unwrap()
    }

    pub fn set_dc<DC: Into<bool>>(&mut self, dc: DC) {
        self.set_flag(Self::DC_FLAG_MASK, dc.into());
    }

    pub fn n(&self) -> Numbered {
        self.get_flag(Self::N_FLAG_MASK).try_into().unwrap()
    }

    pub fn set_n<N: Into<bool>>(&mut self, n: N) {
        self.set_flag(Self::N_FLAG_MASK, n.into());
    }

    pub fn seqno(&self) -> u8 {
        ((self.0 & Self::SEQNO_MASK) >> Self::SEQNO_SHIFT).try_into().unwrap()
    }

    pub fn set_seqno<S: Into<u8>>(&mut self, seqno: S) {
        let seqno: u8 = seqno.into();
        debug_assert!(seqno <= Self::SEQNO_MAX);
        let v = self.0;
        self.0 = (v & !Self::SEQNO_MASK) | (seqno) << Self::SEQNO_SHIFT;
    }

    pub fn ctrl_type(&self) -> ControlType {
        ((self.0 & Self::CTRLT_MASK) >> Self::CTRLT_SHIFT).into()
    }

    pub fn set_ctrl_type<C: Into<u8>>(&mut self, ctrl_type: C) {
        let ctrl_type: u8 = ctrl_type.into();
        debug_assert!(ctrl_type <= Self::CTRLT_MAX);
        let v = self.0;
        self.0 = (v & !Self::CTRLT_MASK) | (ctrl_type) << Self::CTRLT_SHIFT;
    }
}

/// A KNX message buffer
///
/// This represents a KNX message in EMI2 format
pub struct KnxMessageBuffer<B: Deref<Target = [u8]>> {
    service_type: ServiceType,
    buf: B,
}

impl<B: Deref<Target = [u8]>> core::fmt::Debug for KnxMessageBuffer<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KnxMessage {{ {:?}: {:x?} }}", self.service_type, self.buf.as_ref())
    }
}

impl<B: Deref<Target = [u8]>> KnxMessageBuffer<B> {
    pub fn new(buf: B, service_type: ServiceType) -> Self {
        KnxMessageBuffer { service_type, buf }
    }

    pub fn into_inner(self) -> B {
        self.buf
    }

    pub fn buf(&self) -> &B {
        &self.buf
    }

    pub fn service_type(&self) -> ServiceType {
        self.service_type
    }

    pub fn set_service_type(&mut self, service_type: ServiceType) {
        self.service_type = service_type;
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Helper function to get an integer from a byte array
    fn read_u16_be(&self, pos: usize) -> u16 {
        u16::from_be_bytes([self.buf[pos], self.buf[pos + 1]])
    }

    pub fn ctrl_field(&self) -> &Ctrl1Field {
        use offsets::*;
        unsafe { &*(&self.buf[MSG_CONTROL] as *const u8 as *const Ctrl1Field) }
    }

    pub fn tpci_field(&self) -> &TpciField {
        use offsets::*;
        unsafe { &*(&self.buf[MSG_TPCI] as *const u8 as *const TpciField) }
    }

    /// Get the APCI value from the message as an enum
    pub fn get_apci_code(&self) -> ApciCode {
        use offsets::*;

        // The first six bits of the APCI field either directly contain the
        // short APCIs or an escape code for the extended and user codes.
        let apci_raw = ((self.read_u16_be(MSG_APCI) & 0x03C0) >> 6) as u8;

        if apci_raw == ApciCode::UserMessage.into() {
            // User messages
            ApciCode::from(self.buf[MSG_APCI + 1] & 0xbf)
        } else if apci_raw == ApciCode::Escape.into() {
            // Escaped messages
            ApciCode::from(self.buf[MSG_APCI + 1])
        } else if apci_raw == 7 && ((self.buf[MSG_APCI + 1] & 0x3f) > 7) {
            // Extended messages
            ApciCode::from(self.buf[MSG_APCI + 1] & 0x7f)
        } else {
            // Short messages
            ApciCode::from(apci_raw)
        }
    }

    /// Get the source address from the message
    pub fn get_source_addr(&self) -> IndividualAddress {
        use offsets::*;
        IndividualAddress::from_bytes(&self.buf[MSG_SOURCE_ADDR..MSG_SOURCE_ADDR + 2])
    }

    /// Get the destination address from the message
    pub fn get_dest_addr(&self) -> DestinationAddress {
        use offsets::*;

        let addr_type = self.buf[MSG_ADDR_TYPE] & 0x80;

        if addr_type != 0 && self.read_u16_be(MSG_DEST_ADDR) == 0 {
            if (self.buf[MSG_CONTROL] & 0x10) == 0 {
                return DestinationAddress::SystemBroadcast;
            } else {
                return DestinationAddress::Broadcast;
            }
        } else if addr_type != 0 {
            return DestinationAddress::Group(GroupAddress::from_bytes(&self.buf[MSG_DEST_ADDR..MSG_DEST_ADDR + 2]));
        } else {
            return DestinationAddress::Individual(IndividualAddress::from_bytes(
                &self.buf[MSG_DEST_ADDR..MSG_DEST_ADDR + 2],
            ));
        }
    }

    /// Get the connection nr from the message
    ///
    /// This is stored instead of the destination address in the message and
    /// is replaced by the transport layer with the real group address through
    /// the grouap address table (ADT).
    pub fn get_connection_nr(&self) -> u16 {
        use offsets::*;
        self.read_u16_be(MSG_DEST_ADDR)
    }

    /// Get the address type from the message as an enum based on the address type and system broadcast flags
    pub fn get_address_type(&self) -> AddressType {
        use offsets::*;

        let addr_type = self.buf[MSG_ADDR_TYPE] & 0x80;

        if addr_type != 0 && self.read_u16_be(MSG_DEST_ADDR) == 0 {
            if self.ctrl_field().sb() == SystemBroadcast::SysBroadcast {
                return AddressType::SystemBroadcast;
            } else {
                return AddressType::Broadcast;
            }
        } else if addr_type != 0 {
            return AddressType::Group;
        } else {
            return AddressType::Individual;
        }
    }

    /// Get the TPCI from the message as an enum
    pub fn get_tpci(&self) -> Option<Tpci> {
        // FIXME: Strictly speaking, the address type is part of the network layer

        let addr_type = self.get_address_type();
        let control = self.tpci_field().dc();
        let numbered = self.tpci_field().n();
        let seqno = self.tpci_field().seqno();
        let ctrl_type = self.tpci_field().ctrl_type();

        match (addr_type, control, numbered, seqno, ctrl_type) {
            (AddressType::Broadcast, DataControl::Data, Numbered::Unnumbered, 0, _) => Some(Tpci::DataBroadcast),
            (AddressType::SystemBroadcast, DataControl::Data, Numbered::Unnumbered, 0, _) => {
                Some(Tpci::DataSystemBroadcast)
            }

            (AddressType::Group, DataControl::Data, Numbered::Unnumbered, 0, _) => Some(Tpci::DataGroup),
            (AddressType::Individual, DataControl::Data, Numbered::Unnumbered, 0, _) => Some(Tpci::DataIndividual),
            (AddressType::Individual, DataControl::Data, Numbered::Numbered, _, _) => Some(Tpci::DataConnected(seqno)),
            (AddressType::Individual, DataControl::Control, Numbered::Unnumbered, 0, ControlType::Connect) => {
                Some(Tpci::Connect)
            }
            (AddressType::Individual, DataControl::Control, Numbered::Unnumbered, 0, ControlType::Disconnect) => {
                Some(Tpci::Disconnect)
            }
            (AddressType::Individual, DataControl::Control, Numbered::Numbered, _, ControlType::ACK) => {
                Some(Tpci::Ack(seqno))
            }
            (AddressType::Individual, DataControl::Control, Numbered::Numbered, _, ControlType::NACK) => {
                Some(Tpci::Nack(seqno))
            }
            _ => None,
        }
    }

    /// Get the hop count from the message
    pub fn get_hop_count(&self) -> u8 {
        use offsets::*;
        (self.buf[MSG_ROUTE_CNT] & 0x70) >> 4
    }

    /// Get the hop count type from the message as a HopCountType enum
    pub fn get_hop_count_type(&self) -> HopCountType {
        use offsets::*;
        HopCountType::from(self.buf[MSG_ROUTE_CNT] & 0x70 >> 4)
    }
}

impl<B: DerefMut<Target = [u8]>> KnxMessageBuffer<B> {
    /// Helper function to set an integer in a byte array
    fn write_u16_be(&mut self, pos: usize, value: u16) {
        let bytes = value.to_be_bytes();
        self.buf[pos] = bytes[0];
        self.buf[pos + 1] = bytes[1];
    }

    pub fn buf_mut(&mut self) -> &mut B {
        &mut self.buf
    }

    /// Get a mutable reference to the CTRL1 field
    pub fn ctrl_field_mut(&mut self) -> &mut Ctrl1Field {
        use offsets::*;
        unsafe { &mut *(&mut self.buf[MSG_CONTROL] as *const u8 as *mut Ctrl1Field) }
    }

    /// Get a mutable reference to the TPCI field
    pub fn tpci_field_mut(&mut self) -> &mut TpciField {
        use offsets::*;
        unsafe { &mut *(&mut self.buf[MSG_TPCI] as *const u8 as *mut TpciField) }
    }

    /// Set the APCI value in the message from an enum
    pub fn set_apci_code(&mut self, apci: ApciCode) {
        use offsets::*;

        let apci_value: u8 = apci.into();
        let category = (apci_value & 0xc0) as u8;

        match category {
            // Extended
            0x40 => {
                self.buf[MSG_APCI] = (self.buf[MSG_APCI] & 0xfc) | 1;
                self.buf[MSG_APCI + 1] = (apci_value | 0xc0) as u8;
            }
            // User
            0x80 => {
                self.buf[MSG_APCI] = (self.buf[MSG_APCI] & 0xfc) | 2;
                self.buf[MSG_APCI + 1] = (apci_value | 0xc0) as u8;
            }
            // Escaped
            0xc0 => {
                self.buf[MSG_APCI] = (self.buf[MSG_APCI] & 0xfc) | 3;
                self.buf[MSG_APCI + 1] = apci_value as u8;
            }
            // Short
            _ => {
                let tmp = self.read_u16_be(MSG_APCI);
                self.write_u16_be(MSG_APCI, (tmp & !0x3C0) | ((apci_value as u16) << 6));
            }
        }
    }

    /// Set the source address in the message
    pub fn set_source_addr(&mut self, addr: IndividualAddress) {
        use offsets::*;
        self.buf[MSG_SOURCE_ADDR..MSG_SOURCE_ADDR + 2].copy_from_slice(addr.as_bytes());
    }

    /// Set the destination address in the message
    ///
    /// This also sets the appropriate flags for the address type and system broadcast
    /// In case of Broadcast and SystemBroadcast the destination address is set to 0
    pub fn set_dest_addr(&mut self, addr: DestinationAddress) {
        use offsets::*;

        match addr {
            DestinationAddress::Individual(a) => {
                self.set_address_type(AddressType::Individual);
                self.buf[MSG_DEST_ADDR..MSG_DEST_ADDR + 2].copy_from_slice(a.as_bytes());
            }
            DestinationAddress::Group(a) => {
                self.set_address_type(AddressType::Group);
                self.buf[MSG_DEST_ADDR..MSG_DEST_ADDR + 2].copy_from_slice(a.as_bytes());
            }
            DestinationAddress::Broadcast => {
                self.set_address_type(AddressType::Broadcast);
            }
            DestinationAddress::SystemBroadcast => {
                self.set_address_type(AddressType::SystemBroadcast);
            }
        }
    }

    /// Set the destination address without touching the address type or system broadcast flags
    pub fn set_dest_addr_raw(&mut self, addr: &[u8; 2]) {
        use offsets::*;
        self.buf[MSG_DEST_ADDR..MSG_DEST_ADDR + 2].copy_from_slice(addr);
    }

    /// Set the connection nr int the message
    ///
    /// This is stored instead of the destination address in the message and
    /// is replaced by the transport layer with the real group address through
    /// the grouap address table (ADT).
    pub fn set_connection_nr(&mut self, conn_nr: u16) {
        use offsets::*;
        self.write_u16_be(MSG_DEST_ADDR, conn_nr);
    }

    /// Set the address type and system broadcast flags in the message
    ///
    /// In case of Broadcast and SystemBroadcast the destination address is set to 0
    pub fn set_address_type(&mut self, addr_type: AddressType) {
        use offsets::*;

        match addr_type {
            AddressType::Individual => {
                self.buf[MSG_ADDR_TYPE] &= !0x80;
                self.ctrl_field_mut().set_sb(SystemBroadcast::NoSysBroadcast);
            }
            AddressType::Group => {
                self.buf[MSG_ADDR_TYPE] |= 0x80;
                self.ctrl_field_mut().set_sb(SystemBroadcast::NoSysBroadcast);
            }
            AddressType::Broadcast => {
                self.buf[MSG_ADDR_TYPE] &= !0x80;
                self.ctrl_field_mut().set_sb(SystemBroadcast::NoSysBroadcast);
                self.buf[MSG_DEST_ADDR..MSG_DEST_ADDR + 2].copy_from_slice(&[0, 0]);
            }
            AddressType::SystemBroadcast => {
                self.buf[MSG_ADDR_TYPE] &= !0x80;
                self.ctrl_field_mut().set_sb(SystemBroadcast::SysBroadcast);
                self.buf[MSG_DEST_ADDR..MSG_DEST_ADDR + 2].copy_from_slice(&[0, 0]);
            }
            _ => panic!("Invalid address type"),
        }
    }

    /// Set the TPCI value in the message from an enum
    pub fn set_tpci(&mut self, tpci: Tpci) {
        // FIXME: Strictly speaking, the address type is part of the network layer

        let (addr_type, control, numbered, seqno, ctrl_type) = match tpci {
            Tpci::DataBroadcast => (AddressType::Broadcast, DataControl::Data, Numbered::Unnumbered, 0, None),
            Tpci::DataSystemBroadcast => {
                (AddressType::SystemBroadcast, DataControl::Data, Numbered::Unnumbered, 0, None)
            }
            Tpci::DataGroup => (AddressType::Group, DataControl::Data, Numbered::Unnumbered, 0, None),
            Tpci::DataIndividual => (AddressType::Individual, DataControl::Data, Numbered::Unnumbered, 0, None),
            Tpci::DataConnected(seqno) => (AddressType::Individual, DataControl::Data, Numbered::Numbered, seqno, None),
            Tpci::Connect => {
                (AddressType::Individual, DataControl::Control, Numbered::Unnumbered, 0, Some(ControlType::Connect))
            }
            Tpci::Disconnect => {
                (AddressType::Individual, DataControl::Control, Numbered::Unnumbered, 0, Some(ControlType::Disconnect))
            }
            Tpci::Ack(seqno) => {
                (AddressType::Individual, DataControl::Control, Numbered::Numbered, seqno, Some(ControlType::ACK))
            }
            Tpci::Nack(seqno) => {
                (AddressType::Individual, DataControl::Control, Numbered::Numbered, seqno, Some(ControlType::NACK))
            }
        };

        self.set_address_type(addr_type);
        self.tpci_field_mut().set_dc(control);
        self.tpci_field_mut().set_n(numbered);
        self.tpci_field_mut().set_seqno(seqno);
        if let Some(ctrl_type) = ctrl_type {
            self.tpci_field_mut().set_ctrl_type(ctrl_type);
        }
    }

    /// Set the hop count in the message
    pub fn set_hop_count(&mut self, hop_count: u8) {
        use offsets::*;
        self.buf[MSG_ROUTE_CNT] = (self.buf[MSG_ROUTE_CNT] & 0x8f) | ((hop_count & 0x07) << 4);
    }

    /// Set the hop count type in the message using the HopCountType enum
    pub fn set_hop_count_type(&mut self, hop_count_type: HopCountType) {
        use offsets::*;

        let hop_count_type: u8 = hop_count_type.into();
        self.buf[MSG_ROUTE_CNT] = (self.buf[MSG_ROUTE_CNT] & 0x8f) | (hop_count_type << 4);
    }

    /// Convert an incoming hop count to a HopCountType according to the KNX network layer specification
    pub fn convert_hop_count_to_hop_count_type(&mut self) {
        if self.get_hop_count() == 7 {
            self.set_hop_count_type(HopCountType::Unlimited);
        } else {
            self.set_hop_count_type(HopCountType::Default);
        }
    }

    /// Convert an incoming HopCountType to a hop count according to the KNX network layer specification
    pub fn convert_hop_count_type_to_hop_count(&mut self, default_hop_count: u8) {
        if self.get_hop_count_type() == HopCountType::Unlimited {
            self.set_hop_count(7);
        } else {
            self.set_hop_count(default_hop_count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1. Standard Group Value Write frame (switching off a light)
    // Format: Length + Service code + Control byte 1/2 + Destination address + Source address + NPDU length + TPCI/APCI + Data
    const GROUP_VALUE_WRITE: &[u8] = &[
        0xBC, // Control byte 1: 10111100 (Standard frame, priority 3, no repetition, broadcast)
        0x11, 0x22, // Source address: 1.1.34 (physical address)
        0x11, 0x01, // Destination address: 1/1/1 (group address in 3-level format)
        0x80, // Control byte 2: 10000000 (AT: Group address, default hop count, no eff)
        0x00, // TPCI: 000000 (Unnumbered data packet), short APCI + data (binary value 0)
        0x80,
    ];

    // 2. Group Value Read frame (reading the state of a group address)
    const GROUP_VALUE_READ: &[u8] = &[
        0xBC, // Control byte 1: 10111100 (Standard frame, priority 3, no repetition, broadcast)
        0x11, 0x02, // Destination address: 1/1/2 (group address)
        0x11, 0x22, // Source address: 1.1.34 (physical address)
        0x80, // Control byte 2: 10000000 (AT: Group address, default hop count, no eff)
        0x00, // TPCI: 000000 (Unnumbered data packet), short APCI + data (binary value 0)
        0x00,
    ];

    // 3. Memory write
    const MEMORY_WRITE: &[u8] = &[
        0xBC, // Control byte 1: 10111100 (Standard frame, priority 3, no repetition, broadcast)
        0x11, 0x22, // Source address: 1.1.34 (physical address)
        0x11, 0x23, // Destination address: 1.1.35 (physical address)
        0x00, // Control byte 2: 00000000 (AT: Individual address, default hop count, no eff)
        0x46, // TPCI: 010001 (Numbered data packet, seqno 1), first 2 bits of APCI: 10 (Memory write)
        0x84, // APCI: (10) 10 (Memory write) 000100 (4 bytes)
        0x80, 0x00, // Address: 0x8000
        0x01, 0x02, 0x03, 0x04, // Data: 0x01020304
    ];

    // 4. Property value read
    const PROPERTY_VALUE_READ: &[u8] = &[
        0xBC, // Control byte 1: 10111100 (Standard frame, priority 3, no repetition, broadcast)
        0x11, 0x22, // Source address: 1.1.34 (physical address)
        0x11, 0x23, // Destination address: 1.1.35 (physical address)
        0x00, // Control byte 2: 00000000 (AT: Individual address, default hop count, no eff)
        0x47, // TPCI: 010001 (Numbered data packet, seqno 1), first 2 bits of APCI: 11 (Escape)
        0xD5, // APCI: (11) 11 (Escape) 010101 (Property Value Read)
        0x01, // Object index: 1
        0x02, // Property ID: 2
        0x10, // Number of elements: 1, start index upper 4 bits: 0
        0x00, // Start index lower 8 bits: 0
        0x01, 0x02, 0x03, 0x04, // Data: 0x01020304
    ];

    // 5. System network parameter read
    const SYSTEM_NETWORK_PARAMETER_READ: &[u8] = &[
        0xAC, // Control byte 1: 10101100 (Standard frame, priority 3, no repetition, system broadcast)
        0x11, 0x22, // Source address: 1.1.34 (physical address)
        0x00, 0x00, // Destination address: 0/0/0 (broadcast)
        0x80, // Control byte 2: 10000000 (AT: Group address, default hop count, no eff)
        0x01, // TPCI: 000000 (Unnumbered data packet), first 2 bits of APCI: 01 (Extended)
        0xC8, // APCI: (01) 11 (Extended) 001000 (System Network Parameter Read)
        0x00, 0x01, // Object type: 1
        0x00, 0x00, // PID: 0
        0x55, // Operand: 0x55
    ];

    // 6. Function property command
    const FUNCTION_PROPERTY_COMMAND: &[u8] = &[
        0xBC, // Control byte 1: 10101100 (Standard frame, priority 3, no repetition, system broadcast)
        0x11, 0x22, // Source address: 1.1.34 (physical address)
        0x11, 0x23, // Destination address: 1.1.35 (physical address)
        0x00, // Control byte 2: 00000000 (AT: Individual address, default hop count, no eff)
        0x46, // TPCI: 010001 (Numbered data packet, seqno 1), first 2 bits of APCI: 10 (User)
        0xC7, // APCI: (10) 11 (User) 000111 (Function Property Command)
        0x01, // Object index: 1
        0x02, // Property ID: 2
        0x01, 0x02, 0x03, 0x04, // Data: 0x01020304
    ];

    // Collection of all KNX TP1 test frames for easy iteration
    pub const KNX_TP1_TEST_FRAMES: &[&[u8]] = &[
        GROUP_VALUE_WRITE,
        GROUP_VALUE_READ,
        MEMORY_WRITE,
        PROPERTY_VALUE_READ,
        SYSTEM_NETWORK_PARAMETER_READ,
        FUNCTION_PROPERTY_COMMAND,
    ];

    #[test]
    fn test_apci() {
        const EXPECTED_APCIS: &[ApciCode] = &[
            ApciCode::GroupValueWrite,
            ApciCode::GroupValueRead,
            ApciCode::MemoryWrite,
            ApciCode::PropertyValueRead,
            ApciCode::SystemNetworkParameterRead,
            ApciCode::FunctionPropertyCommand,
        ];

        for (t, e) in KNX_TP1_TEST_FRAMES.iter().zip(EXPECTED_APCIS.iter()) {
            let msg = KnxMessageBuffer::new(*t, ServiceType::L_Data_Ind);
            assert_eq!(msg.get_apci_code(), *e, "APCI code mismatch for test frame: {:x?}", t);
        }
    }

    #[test]
    fn test_tpci() {
        const EXPECTED_TPCIS: &[Option<Tpci>] = &[
            Some(Tpci::DataGroup),
            Some(Tpci::DataGroup),
            Some(Tpci::DataConnected(1)),
            Some(Tpci::DataConnected(1)),
            Some(Tpci::DataSystemBroadcast),
            Some(Tpci::DataConnected(1)),
        ];

        for (t, e) in KNX_TP1_TEST_FRAMES.iter().zip(EXPECTED_TPCIS.iter()) {
            let msg = KnxMessageBuffer { buf: *t, service_type: ServiceType::L_Data_Ind };
            assert_eq!(msg.get_tpci(), *e, "TPCI code mismatch for test frame: {:x?}", t);
        }
    }
}
