use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::address::{GroupAddress, IndividualAddress};
use crate::messages::buffers::MessageBuffer;
use crate::{AccessContext, AccessSource};

/// Offsets to fields in the KNX message buffers
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

impl ServiceType {
    /// Convert a request service type to its confirmation variant.
    ///
    /// This is used when building confirmation messages in response to requests.
    /// For non-request types (indications, confirmations, or unknown), returns self unchanged.
    ///
    /// # Examples
    /// ```ignore
    /// assert_eq!(ServiceType::T_Data_Req.to_confirmation(), ServiceType::T_Data_Con);
    /// assert_eq!(ServiceType::N_GroupData_Req.to_confirmation(), ServiceType::N_GroupData_Con);
    /// ```
    pub fn to_confirmation(self) -> ServiceType {
        match self {
            // Link layer
            ServiceType::L_Data_Req => ServiceType::L_Data_Con,
            // Network layer
            ServiceType::N_Data_Req => ServiceType::N_Data_Con,
            ServiceType::N_GroupData_Req => ServiceType::N_GroupData_Con,
            ServiceType::N_Broadcast_Req => ServiceType::N_Broadcast_Con,
            ServiceType::N_SystemBroadcast_Req => ServiceType::N_SystemBroadcast_Con,
            // Transport layer
            ServiceType::T_Data_Req => ServiceType::T_Data_Con,
            ServiceType::T_GroupData_Req => ServiceType::T_GroupData_Con,
            ServiceType::T_Broadcast_Req => ServiceType::T_Broadcast_Con,
            ServiceType::T_SystemBroadcast_Req => ServiceType::T_SystemBroadcast_Con,
            ServiceType::T_DataUnack_Req => ServiceType::T_DataUnack_Con,
            ServiceType::T_Connect_Req => ServiceType::T_Connect_Con,
            ServiceType::T_Disconnect_Req => ServiceType::T_Disconnect_Con,
            // Already a confirmation, indication, or unknown - panic
            _ => panic!("Cannot convert non-request service type {:?} to confirmation", self),
        }
    }
}

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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Tpci {
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

/// Destination address types
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum DestinationAddress {
    Individual(IndividualAddress),
    Group(GroupAddress),
    Broadcast,
    SystemBroadcast,
    /// TSAP-based addressing for group communication. The connection number
    /// occupies the destination address bytes and is resolved by the transport
    /// layer to a real group address via the address table.
    ConnectionNr(u16),
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

        UserMemoryRead,             0x80,   "A_UserMemory_Read";
        UserMemoryResponse,         0x81,   "A_UserMemory_Response";
        UserMemoryWrite,            0x82,   "A_UserMemory_Write";

        UserManufacturerInfoRead,   0x85,   "A_UserManufacturerInfo_Read";
        UserManufacturerInfoResponse, 0x86, "A_UserManufacturerInfo_Response";
        FunctionPropertyCommand,    0x87,   "A_FunctionPropertyCommand";
        FunctionPropertyStateRead,  0x88,   "A_FunctionPropertyState_Read";
        FunctionPropertyStateResponse, 0x89, "A_FunctionPropertyState_Response";

        // Extended property services (AN163). Wire bytes: 0x01C8–0x01D1.
        // Decoded via apci_raw=7 branch with & 0x7F mask, so stored codes
        // are the low 7 bits of the wire byte.
        PropertyExtValueRead,           0x4c,   "A_PropertyExtValue_Read";
        PropertyExtValueResponse,       0x4d,   "A_PropertyExtValue_Response";
        PropertyExtValueWriteCon,       0x4e,   "A_PropertyExtValue_WriteCon";
        PropertyExtValueWriteConRes,    0x4f,   "A_PropertyExtValue_WriteConRes";
        PropertyExtValueWriteUnCon,     0x50,   "A_PropertyExtValue_WriteUnCon";
        PropertyExtValueInfoReport,     0x51,   "A_PropertyExtValue_InfoReport";
        // Extended function property services (AN163). Wire: 0x01D4–0x01D6.
        PropertyExtDescriptionRead,     0x52,   "A_PropertyExtDescription_Read";
        PropertyExtDescriptionResponse, 0x53,   "A_PropertyExtDescription_Response";
        MemoryExtendedWrite,            0x7b,   "A_MemoryExtended_Write";
        MemoryExtendedWriteResponse,    0x7c,   "A_MemoryExtended_WriteResponse";
        MemoryExtendedRead,             0x7d,   "A_MemoryExtended_Read";
        MemoryExtendedReadResponse,     0x7e,   "A_MemoryExtended_ReadResponse";
        FunctionPropertyExtCommand,     0x54,   "A_FunctionPropertyExtCommand";
        FunctionPropertyExtStateRead,   0x55,   "A_FunctionPropertyExtState_Read";
        FunctionPropertyExtStateResponse, 0x56, "A_FunctionPropertyExtState_Response";

        MemoryBitWrite,             0xd0,   "A_MemoryBit_Write";
        AuthorizeRequest,           0xd1,   "A_Authorize_Request";
        AuthorizeResponse,          0xd2,   "A_Authorize_Response";
        KeyWrite,                   0xd3,   "A_Key_Write";
        KeyResponse,                0xd4,   "A_Key_Response";
        PropertyValueRead,          0xd5,   "A_PropertyValue_Read";
        PropertyValueResponse,      0xd6,   "A_PropertyValue_Response";
        PropertyValueWrite,         0xd7,   "A_PropertyValue_Write";
        PropertyDescriptionRead,    0xd8,   "A_PropertyDescription_Read";
        PropertyDescriptionResponse, 0xd9,  "A_PropertyDescription_Response";

        IndividualAddressSerialNumberRead,      0xdc,   "A_IndividualAddressSerialNumber_Read";
        IndividualAddressSerialNumberResponse,  0xdd,   "A_IndividualAddressSerialNumber_Response";
        IndividualAddressSerialNumberWrite,     0xde,   "A_IndividualAddressSerialNumber_Write";

        DomainAddressWrite,                     0xe0,   "A_DomainAddress_Write";
        DomainAddressRead,                      0xe1,   "A_DomainAddress_Read";
        DomainAddressResponse,                  0xe2,   "A_DomainAddress_Response";

        DomainAddressSerialNumberRead,          0xec,   "A_DomainAddressSerialNumber_Read";
        DomainAddressSerialNumberResponse,      0xed,   "A_DomainAddressSerialNumber_Response";
        DomainAddressSerialNumberWrite,         0xee,   "A_DomainAddressSerialNumber_Write";

        SecureService,                          0xf1,   "A_Secure_Service";

        Empty,                      0,      "<Empty>";
        _,                                  "Unknown APCI code 0x{:x}";
    }
);

/// Decode an [`ApciCode`] from a raw internal-format message buffer.
///
/// This is the standalone equivalent of [`KnxMessageBuffer::get_apci_code`],
/// usable without constructing a full message buffer. The buffer must start at
/// offset 0 of the internal format (ctrl byte) and contain at least
/// `MSG_APCI + 2` bytes.
pub fn decode_apci_code(buf: &[u8]) -> Option<ApciCode> {
    use offsets::MSG_APCI;

    if buf.len() < MSG_APCI + 2 {
        return None;
    }

    let apci_u16 = u16::from_be_bytes([buf[MSG_APCI], buf[MSG_APCI + 1]]);
    let apci_raw = ((apci_u16 & 0x03C0) >> 6) as u8;

    Some(if apci_raw == ApciCode::UserMessage.into() {
        ApciCode::from(buf[MSG_APCI + 1] & 0xbf)
    } else if apci_raw == ApciCode::Escape.into() {
        ApciCode::from(buf[MSG_APCI + 1])
    } else if apci_raw == 7 && ((buf[MSG_APCI + 1] & 0x3f) > 7) {
        ApciCode::from(buf[MSG_APCI + 1] & 0x7f)
    } else {
        ApciCode::from(apci_raw)
    })
}

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
    /// Frame types
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum FrameType: bool {
        Standard, true, "Standard";
        Extended, false, "Extended";
    }
);

create_protocol_enum!(
    /// Frame repition flag values
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum Repetition: bool {
        WasNotRepeated, true, "not repeated";
        WasRepeated, false, "repeated";

        AllowRepetition, true, "Allow repetitions";
        DoNotRepeat, false, "Do not repeat";
    }
);

create_protocol_enum!(
    /// System broadcast flag values
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum SystemBroadcast: bool {
        NoSysBroadcast, true, "No System Broadcast";
        SysBroadcast, false, "System Broadcast";
    }
);

create_protocol_enum!(
    /// ACK type flag values
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum AckType: bool {
        AckRequested, true, "ACK requested";
        AckDontCare, false, "ACK don't care";
    }
);

create_protocol_enum!(
    /// Confirmation flag values
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum Confirm: bool {
        Err, true, "Error";
        NoError, false, "No error";
    }
);

/// A KNX message CTRL1 field
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
    const P_MASK: u8 = Self::P_MAX << Self::P_SHIFT;

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
        ((self.0 & Self::P_MASK) >> Self::P_SHIFT).into()
    }

    pub fn set_priority<P: Into<u8>>(&mut self, priority: P) {
        let priority: u8 = priority.into();
        debug_assert!(priority <= Self::P_MAX);
        let v = self.0;
        self.0 = (v & !Self::P_MASK) | (priority) << Self::P_SHIFT;
    }

    /// Get the acknowledge request flag.
    /// Note: This field is only meaningful for L_Data.req messages.
    pub fn a(&self) -> AckType {
        self.get_flag(Self::A_FLAG_MASK).try_into().unwrap()
    }

    /// Set the acknowledge request flag.
    /// Note: This field is only meaningful for L_Data.req messages.
    pub fn set_a<A: Into<bool>>(&mut self, a: A) {
        self.set_flag(Self::A_FLAG_MASK, a.into());
    }

    /// Get the confirmation flag.
    /// Note: This field is only meaningful for L_Data.con messages.
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
    /// TPCI Data or Control packet flag
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum DataControl: bool {
        Control, true, "Control";
        Data, false, "Data";
    }
);

create_protocol_enum!(
    /// TPCI Numbered or unnumbered packet flag
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

/// A KNX message TPCI field
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct TpciField(u8);

impl TpciField {
    const DC_FLAG_MASK: u8 = 0b10000000;
    const N_FLAG_MASK: u8 = 0b01000000;

    const SEQNO_SHIFT: u8 = 2;
    const SEQNO_LEN: u8 = 4;
    const SEQNO_MAX: u8 = (1 << Self::SEQNO_LEN) - 1;
    const SEQNO_MASK: u8 = Self::SEQNO_MAX << Self::SEQNO_SHIFT;

    const CTRLT_SHIFT: u8 = 0;
    const CTRLT_LEN: u8 = 2;
    const CTRLT_MAX: u8 = (1 << Self::CTRLT_LEN) - 1;
    const CTRLT_MASK: u8 = Self::CTRLT_MAX << Self::CTRLT_SHIFT;

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
        (self.0 & Self::SEQNO_MASK) >> Self::SEQNO_SHIFT
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
/// This represents a KNX message in a format that resembles the TP1 standard
/// frame format, but with the change that the length field is omitted and
/// replaced with the EFF field that could be present in the extended control
/// field in an extended TP1 frame. The length is determined by the size of the
/// used part of the buffer holding this message and needs to be tracked by the
/// inner buffer itself.
///
///  +--------+---------+---------+--------+---------+--------------------+
///  | CTRL   | SRC     | DEST    | AT/HC/ | TPCI    | DATA               |
///  | Field  | Address | Address | EFF    | /APCI   | (variable length)  |
///  +--------+---------+---------+--------+---------+--------------------+
///  | 1 byte | 2 bytes | 2 bytes | 1 byte | 1 byte  | 0..(buffer_size-7) |
///  +--------+---------+---------+--------+---------+--------------------+
///
///   Bit breakdown for CTRL field (Ctrl1Field, byte 0):
///     7   6   5   4   3   2   1   0
///   +---+---+---+---+---+---+---+---+
///   |FT | - | R | SB| PR| PR| A | C |
///   +---+---+---+---+---+---+---+---+
///   FT  = Frame Type (bit 7, 0: standard, 1: extended)
///       -   = (bit 6, unused)
///       R   = Repeat Flag (bit 5)
///       SB  = System Broadcast (bit 4)
///       PR  = Priority (bits 3-2, 2 bits)
///       A   = Acknowledge (bit 1, only valid for L_Data.req)
///       C   = Confirm (bit 0, only valid for L_Data.con)
///
///   Field meanings:
///   - FT: Frame type (standard/extended)
///   - R: Repeat flag
///   - SB: System broadcast
///   - PR: Priority
///   - A: Acknowledge (L_Data.req only)
///   - C: Confirm (L_Data.con only)
///
/// Default access level for messages (minimum access = level 3)
pub const DEFAULT_MESSAGE_ACCESS_LEVEL: u8 = AccessContext::MIN_ACCESS.access_level;

// ============================================================================
// Message Format Markers
// ============================================================================

/// Marker trait for message format types.
///
/// This trait is sealed and cannot be implemented outside this crate.
pub trait MessageFormat: private::Sealed {}

mod private {
    pub trait Sealed {}
    impl Sealed for super::InternalFormat {}
    impl Sealed for super::CemiFormat {}
    impl Sealed for super::Tp1Format {}
}

/// Internal KNX message format used within the stack.
///
/// This is the canonical format used after link layer processing.
/// Messages in this format can be parsed and modified using `KnxMessageBuffer` methods.
///
/// Layout:
/// ```text
/// +--------+---------+---------+--------+---------+--------------------+
/// | CTRL   | SRC     | DEST    | AT/HC/ | TPCI    | DATA               |
/// | Field  | Address | Address | EFF    | /APCI   | (variable length)  |
/// +--------+---------+---------+--------+---------+--------------------+
/// | 1 byte | 2 bytes | 2 bytes | 1 byte | 1 byte  | 0..(buffer_size-7) |
/// +--------+---------+---------+--------+---------+--------------------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalFormat;
impl MessageFormat for InternalFormat {}

/// cEMI (Common External Message Interface) format.
///
/// Used by KNX/IP and USB link layers. This format has additional header bytes
/// compared to the internal format:
/// - Message code (1 byte)
/// - Additional info length (1 byte)
/// - Additional info (variable, usually 0)
/// - Control field 2 (1 byte) - contains AT/HC that's in NPDU for internal format
///
/// Converting from cEMI to Internal removes 3+ bytes from the front.
/// Converting from Internal to cEMI requires 3 bytes of headroom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CemiFormat;
impl MessageFormat for CemiFormat {}

/// TP1 wire format as used on the twisted pair bus.
///
/// Similar to internal format but includes:
/// - Length field embedded in NPDU (for standard frames)
/// - Extended control field (for extended frames)
/// - Checksum byte at the end
///
/// Used by TPUART link layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tp1Format;
impl MessageFormat for Tp1Format {}

// ============================================================================
// KnxMessageBuffer
// ============================================================================

/// A KNX message buffer with compile-time format tracking.
///
/// The format parameter `F` indicates what wire format the message data is in:
/// - [`InternalFormat`]: The canonical format used within the stack (default)
/// - [`CemiFormat`]: cEMI format used by KNX/IP and USB
/// - [`Tp1Format`]: TP1 wire format used on the bus
///
/// Format-specific methods are only available when the buffer is in the correct format.
/// Use conversion methods like `into_internal()` or `into_cemi()` to change formats.
///
/// # Example
///
/// ```ignore
/// // Receive cEMI from KNX/IP
/// let cemi_msg = KnxMessageBuffer::<_, CemiFormat>::from_cemi(buffer);
///
/// // Convert to internal format for stack processing
/// let internal_msg = cemi_msg.into_internal();
///
/// // Now we can use internal format methods
/// let apci = internal_msg.get_apci_code();
/// ```
pub struct KnxMessageBuffer<B: Deref<Target = [u8]>, F: MessageFormat = InternalFormat> {
    service_type: ServiceType,
    buf: B,
    /// Where to look up the access level for this message.
    /// Set by the transport layer (or link layer for special paths like
    /// KNX/IP Device Management).
    access_source: AccessSource,
    /// Marker for the message format
    _format: PhantomData<F>,
}

impl<B: Deref<Target = [u8]>, F: MessageFormat> core::fmt::Debug for KnxMessageBuffer<B, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KnxMessage {{ {:?}: {:x?} }}", self.service_type, self.buf.as_ref())
    }
}

#[cfg(feature = "defmt")]
impl<B: Deref<Target = [u8]>, F: MessageFormat> defmt::Format for KnxMessageBuffer<B, F> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "KnxMessage {{ {}: {:02x} }}", self.service_type, self.buf.as_ref())
    }
}

// ============================================================================
// Methods available for any format
// ============================================================================

impl<B: Deref<Target = [u8]>, F: MessageFormat> KnxMessageBuffer<B, F> {
    /// Consume the message and return the inner buffer.
    pub fn into_inner(self) -> B {
        self.buf
    }

    /// Consume the message and return both the buffer and service type.
    ///
    /// This is useful when you need to transform a message while preserving
    /// its service type (e.g., for confirmations).
    pub fn into_parts(self) -> (B, ServiceType) {
        (self.buf, self.service_type)
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

    /// Get the access source for this message.
    pub fn access_source(&self) -> AccessSource {
        self.access_source
    }

    /// Set the access source for this message.
    pub fn set_access_source(&mut self, source: AccessSource) {
        self.access_source = source;
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.len() == 0
    }
}

// ============================================================================
// Constructors and methods for InternalFormat (the default)
// ============================================================================

impl<B: Deref<Target = [u8]>> KnxMessageBuffer<B, InternalFormat> {
    /// Create a new KnxMessageBuffer in internal format.
    pub fn new(buf: B, service_type: ServiceType) -> Self {
        KnxMessageBuffer { service_type, buf, access_source: AccessSource::Default, _format: PhantomData }
    }

    /// Create a KnxMessageBuffer from a buffer, using a default service type.
    ///
    /// This is useful when reconstructing a message from a raw buffer where
    /// the service type will be set separately.
    pub fn from_buffer(buf: B) -> Self {
        KnxMessageBuffer {
            service_type: ServiceType::L_Data_Ind,
            buf,
            access_source: AccessSource::Default,
            _format: PhantomData,
        }
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

    /// Get the APCI value from the message as an enum.
    ///
    /// See also [`decode_apci_code`] for a standalone version that works on
    /// raw `&[u8]` slices without a `KnxMessageBuffer`.
    pub fn get_apci_code(&self) -> ApciCode {
        // The buffer is guaranteed to be at least MSG_APCI + 2 bytes for any
        // valid message, so unwrap is safe here.
        decode_apci_code(&self.buf).expect("message buffer too short for APCI")
    }

    /// Get the 6-bit data field from a short APCI message.
    ///
    /// For short APCI codes (GroupValueRead, GroupValueResponse, GroupValueWrite, etc.),
    /// the lower 6 bits of the second APCI byte contain a small data payload.
    /// This is commonly used for:
    /// - GroupValueRead: Should always be 0x00 for a valid read request
    /// - GroupValueResponse/Write with 1-bit data: Contains the 1-bit value in bit 0
    ///
    /// # Returns
    /// The 6-bit data value (0x00-0x3F)
    pub fn get_short_apci_data(&self) -> u8 {
        use offsets::*;
        self.buf[MSG_APCI + 1] & 0x3F
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
                DestinationAddress::SystemBroadcast
            } else {
                DestinationAddress::Broadcast
            }
        } else if addr_type != 0 {
            DestinationAddress::Group(GroupAddress::from_bytes(&self.buf[MSG_DEST_ADDR..MSG_DEST_ADDR + 2]))
        } else {
            DestinationAddress::Individual(IndividualAddress::from_bytes(&self.buf[MSG_DEST_ADDR..MSG_DEST_ADDR + 2]))
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
                AddressType::SystemBroadcast
            } else {
                AddressType::Broadcast
            }
        } else if addr_type != 0 {
            AddressType::Group
        } else {
            AddressType::Individual
        }
    }

    /// Get the TPCI from the message as an enum.
    ///
    /// Note: This method uses the address type to determine the TPCI variant,
    /// even though address type is conceptually part of the network layer.
    /// This is a practical trade-off for message parsing convenience.
    pub fn get_tpci(&self) -> Option<Tpci> {
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

// ============================================================================
// Mutable methods for any format
// ============================================================================

impl<B: DerefMut<Target = [u8]>, F: MessageFormat> KnxMessageBuffer<B, F> {
    pub fn buf_mut(&mut self) -> &mut B {
        &mut self.buf
    }
}

// ============================================================================
// Mutable methods for InternalFormat
// ============================================================================

impl<B: DerefMut<Target = [u8]>> KnxMessageBuffer<B, InternalFormat> {
    /// Helper function to set an integer in a byte array
    fn write_u16_be(&mut self, pos: usize, value: u16) {
        let bytes = value.to_be_bytes();
        self.buf[pos] = bytes[0];
        self.buf[pos + 1] = bytes[1];
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
        let category = apci_value & 0xc0;

        match category {
            // Extended
            0x40 => {
                self.buf[MSG_APCI] = (self.buf[MSG_APCI] & 0xfc) | 1;
                self.buf[MSG_APCI + 1] = apci_value | 0xc0;
            }
            // User
            0x80 => {
                self.buf[MSG_APCI] = (self.buf[MSG_APCI] & 0xfc) | 2;
                self.buf[MSG_APCI + 1] = apci_value | 0xc0;
            }
            // Escaped
            0xc0 => {
                self.buf[MSG_APCI] = (self.buf[MSG_APCI] & 0xfc) | 3;
                self.buf[MSG_APCI + 1] = apci_value;
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
            DestinationAddress::ConnectionNr(nr) => {
                self.set_connection_nr(nr);
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
                // Broadcast uses group address format (AT=1) with destination 0x0000
                self.buf[MSG_ADDR_TYPE] |= 0x80;
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

    /// Set the TPCI value in the message from an enum.
    ///
    /// Note: This method also sets the address type based on the TPCI variant,
    /// even though address type is conceptually part of the network layer.
    /// This is a practical trade-off for message construction convenience.
    pub fn set_tpci(&mut self, tpci: Tpci) {
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

// ============================================================================
// CemiFormat constructors and methods
// ============================================================================

impl<B: Deref<Target = [u8]>> KnxMessageBuffer<B, CemiFormat> {
    /// Create a new cEMI format message buffer.
    ///
    /// The service type is derived from the cEMI message code (first byte).
    pub fn from_cemi(buf: B) -> Self {
        let message_code = buf[0];
        let service_type = ServiceType::from(message_code);
        KnxMessageBuffer { service_type, buf, access_source: AccessSource::Default, _format: PhantomData }
    }

    /// Get the cEMI message code byte.
    pub fn message_code(&self) -> u8 {
        self.buf[0]
    }

    /// Get the additional info length.
    pub fn additional_info_len(&self) -> usize {
        self.buf[1] as usize
    }

    /// Get the additional info bytes.
    pub fn additional_info(&self) -> &[u8] {
        let len = self.additional_info_len();
        &self.buf[2..2 + len]
    }

    /// Get the cEMI frame data (after message code + additional info).
    pub fn frame_data(&self) -> &[u8] {
        let start = 2 + self.additional_info_len();
        &self.buf[start..]
    }
}

/// cEMI expansion size: msg_code(1) + add_info_len(1) + ctrl2(1) = 3 bytes
pub const CEMI_EXPANSION: usize = 3;

// ============================================================================
// Format conversions
// ============================================================================

impl<B: MessageBuffer> KnxMessageBuffer<B, CemiFormat> {
    /// Convert from cEMI format to internal format.
    ///
    /// This removes the cEMI header bytes and adjusts the buffer in-place.
    /// Uses `shrink_front()` to reclaim the header bytes as headroom.
    pub fn into_internal(mut self) -> KnxMessageBuffer<B, InternalFormat> {
        let add_info_len = self.buf[1] as usize;
        let data_start = 2 + add_info_len;

        if self.buf.len() < data_start + 7 {
            // Not enough data - return as-is with zero length
            // This shouldn't happen with valid cEMI data
            return KnxMessageBuffer {
                service_type: self.service_type,
                buf: self.buf,
                access_source: self.access_source,
                _format: PhantomData,
            };
        }

        let ctrl1 = self.buf[data_start];
        let ctrl2 = self.buf[data_start + 1];

        // Merge control fields:
        // Keep FT(7), R(5), SB(4), PR(3-2), A(1), C(0) from ctrl1
        let ctrl = ctrl1 & 0xBF; // Clear bit 6 (reserved in cEMI)

        // NPDU field: AT from ctrl2(7), HC from ctrl2(6-4)
        let npdu = ctrl2 & 0xF0;

        // We need to shrink by: msg_code(1) + add_info_len(1) + add_info(N) + ctrl2(1) = data_start + 1
        // But we also need to remove the npdu_len byte
        // The conversion removes these bytes and shifts data left

        // First, read the source, dest, tpci/apci data
        let src_high = self.buf[data_start + 2];
        let src_low = self.buf[data_start + 3];
        let dst_high = self.buf[data_start + 4];
        let dst_low = self.buf[data_start + 5];
        // npdu_len is at data_start + 6
        let _npdu_len = self.buf[data_start + 6];

        // Data after npdu_len
        let data_after_npdu = data_start + 7;
        let remaining_len = self.buf.len() - data_after_npdu;

        // Build internal format: ctrl(1) + src(2) + dst(2) + npdu(1) + tpci/apci/data
        // Total internal length = 6 + remaining_len

        // Shift data to internal format positions
        self.buf[0] = ctrl;
        self.buf[1] = src_high;
        self.buf[2] = src_low;
        self.buf[3] = dst_high;
        self.buf[4] = dst_low;
        self.buf[5] = npdu;

        // Copy remaining data (TPCI/APCI + payload)
        for i in 0..remaining_len {
            self.buf[6 + i] = self.buf[data_after_npdu + i];
        }

        // Set the new length
        let new_len = 6 + remaining_len;
        self.buf.set_len(new_len);

        KnxMessageBuffer {
            service_type: self.service_type,
            buf: self.buf,
            access_source: self.access_source,
            _format: PhantomData,
        }
    }
}

impl<B: MessageBuffer> KnxMessageBuffer<B, InternalFormat> {
    /// Convert from internal format to cEMI format.
    ///
    /// The cEMI message code is derived from the service type.
    /// This uses headroom to prepend the cEMI header bytes.
    /// Requires at least [`CEMI_EXPANSION`] bytes of headroom.
    ///
    /// # Panics
    /// Panics if insufficient headroom is available.
    pub fn into_cemi(mut self) -> KnxMessageBuffer<B, CemiFormat> {
        let knx_len = self.buf.len();

        // Save the original NPDU value (needed for ctrl2)
        let orig_npdu = self.buf[5];

        // Grow the buffer by 3 bytes using headroom
        self.buf.grow_front(3);

        // After grow_front(3):
        // buf[0..3] = garbage/headroom
        // buf[3] = old ctrl1
        // buf[4..6] = old src
        // buf[6..8] = old dst
        // buf[8] = old npdu
        // buf[9..] = old tpci/apci/data

        // We want:
        // buf[0] = msg_code
        // buf[1] = 0 (add_info_len)
        // buf[2] = ctrl1 (need to copy from buf[3])
        // buf[3] = ctrl2 (= orig_npdu)
        // buf[4..6] = src (already in place!)
        // buf[6..8] = dst (already in place!)
        // buf[8] = npdu_len (overwrite old npdu position)
        // buf[9..] = tpci/apci/data (already in place!)

        let ctrl1 = self.buf[3];
        self.buf[0] = self.service_type.into();
        self.buf[1] = 0; // add_info_len
        self.buf[2] = ctrl1;
        self.buf[3] = orig_npdu; // ctrl2
        // src and dst are already in the right place (positions 4-7)
        // NPDU length field = (TPCI + APCI + data length) - 1
        // Internal format has 6 header bytes, so APDU starts at byte 6
        // NPDU length = (total_length - 6) - 1 = total_length - 7
        self.buf[8] = (knx_len - 7) as u8; // npdu_len: (TPCI/APCI + data length) - 1
        // tpci/apci/data is already in the right place (position 9+)

        KnxMessageBuffer {
            service_type: self.service_type,
            buf: self.buf,
            access_source: self.access_source,
            _format: PhantomData,
        }
    }

    /// Try to convert from internal format to cEMI format.
    ///
    /// Returns `Err` if insufficient headroom is available.
    pub fn try_into_cemi(
        self,
    ) -> Result<KnxMessageBuffer<B, CemiFormat>, (Self, crate::messages::buffers::BufferError)> {
        let headroom = self.buf.headroom();
        if headroom < CEMI_EXPANSION {
            return Err((self, crate::messages::buffers::BufferError::InsufficientHeadroom {
                requested: CEMI_EXPANSION,
                available: headroom,
            }));
        }
        Ok(self.into_cemi())
    }
}

// ============================================================================
// Tp1Format constructors (basic, conversions can be added later)
// ============================================================================

impl<B: Deref<Target = [u8]>> KnxMessageBuffer<B, Tp1Format> {
    /// Create a new KnxMessageBuffer wrapping a TP1-formatted buffer.
    pub fn from_tp1(buf: B, service_type: ServiceType) -> Self {
        KnxMessageBuffer { service_type, buf, access_source: AccessSource::Default, _format: PhantomData }
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

    // 7. Function property state read
    const FUNCTION_PROPERTY_STATE_READ: &[u8] = &[
        0xBC, // Control byte 1: Standard frame, priority 3
        0x11, 0x22, // Source address: 1.1.34
        0x11, 0x23, // Destination address: 1.1.35
        0x00, // Control byte 2: Individual address
        0x46, // TPCI: Numbered data packet seqno 1, first 2 bits of APCI: 10 (User)
        0xC8, // APCI: (10) 11 (User) 001000 (Function Property State Read)
        0x01, // Object index: 1
        0x02, // Property ID: 2
        0x01, 0x02, 0x03, 0x04, // Data: 0x01020304
    ];

    // 8. Function property state response
    const FUNCTION_PROPERTY_STATE_RESPONSE: &[u8] = &[
        0xBC, // Control byte 1: Standard frame, priority 3
        0x11, 0x22, // Source address: 1.1.34
        0x11, 0x23, // Destination address: 1.1.35
        0x00, // Control byte 2: Individual address
        0x46, // TPCI: Numbered data packet seqno 1, first 2 bits of APCI: 10 (User)
        0xC9, // APCI: (10) 11 (User) 001001 (Function Property State Response)
        0x01, // Object index: 1
        0x02, // Property ID: 2
        0x00, // Return code: 0 (success)
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
        FUNCTION_PROPERTY_STATE_READ,
        FUNCTION_PROPERTY_STATE_RESPONSE,
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
            ApciCode::FunctionPropertyStateRead,
            ApciCode::FunctionPropertyStateResponse,
        ];

        for (t, e) in KNX_TP1_TEST_FRAMES.iter().zip(EXPECTED_APCIS.iter()) {
            let msg = KnxMessageBuffer::new(*t, ServiceType::L_Data_Ind);
            assert_eq!(msg.get_apci_code(), *e, "APCI code mismatch for test frame: {:x?}", t);
        }
    }

    #[test]
    fn test_decode_apci_code_matches_get_apci_code() {
        const EXPECTED_APCIS: &[ApciCode] = &[
            ApciCode::GroupValueWrite,
            ApciCode::GroupValueRead,
            ApciCode::MemoryWrite,
            ApciCode::PropertyValueRead,
            ApciCode::SystemNetworkParameterRead,
            ApciCode::FunctionPropertyCommand,
            ApciCode::FunctionPropertyStateRead,
            ApciCode::FunctionPropertyStateResponse,
        ];

        for (t, e) in KNX_TP1_TEST_FRAMES.iter().zip(EXPECTED_APCIS.iter()) {
            let result = decode_apci_code(t);
            assert_eq!(result, Some(*e), "decode_apci_code mismatch for test frame: {:x?}", t);
        }
    }

    #[test]
    fn test_decode_apci_code_too_short() {
        assert_eq!(decode_apci_code(&[0; 7]), None);
        assert!(decode_apci_code(&[0; 8]).is_some());
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
            Some(Tpci::DataConnected(1)),
            Some(Tpci::DataConnected(1)),
        ];

        for (t, e) in KNX_TP1_TEST_FRAMES.iter().zip(EXPECTED_TPCIS.iter()) {
            let msg = KnxMessageBuffer::new(*t, ServiceType::L_Data_Ind);
            assert_eq!(msg.get_tpci(), *e, "TPCI code mismatch for test frame: {:x?}", t);
        }
    }

    #[test]
    fn test_set_get_apci_short_codes() {
        // Test all short APCI codes (0-15)
        let short_codes = [
            ApciCode::GroupValueRead,
            ApciCode::GroupValueResponse,
            ApciCode::GroupValueWrite,
            ApciCode::IndividualAddressWrite,
            ApciCode::IndividualAddressRead,
            ApciCode::IndividualAddressResponse,
            ApciCode::AdcRead,
            ApciCode::AdcResponse,
            ApciCode::MemoryRead,
            ApciCode::MemoryReadResponse,
            ApciCode::MemoryWrite,
            //ApciCode::UserMessage,
            ApciCode::DeviceDescriptorRead,
            ApciCode::DeviceDescriptorResponse,
            ApciCode::Restart,
            //ApciCode::Escape,
        ];

        for code in &short_codes {
            let mut buf = [0u8; 16];
            let mut msg = KnxMessageBuffer::new(&mut buf[..], ServiceType::T_GroupData_Req);

            // Set the APCI code
            msg.set_apci_code(*code);

            // Read it back
            let read_code = msg.get_apci_code();

            assert_eq!(
                read_code, *code,
                "APCI code mismatch for {:?}. Bytes at APCI position: {:02x} {:02x}",
                code, msg.buf[6], msg.buf[7]
            );
        }
    }
}
