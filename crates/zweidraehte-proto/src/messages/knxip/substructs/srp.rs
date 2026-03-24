use core::mem;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, SplitByteSlice, SplitByteSliceMut, Unaligned};

use zweidraehte_platform::address::EthernetAddress;

use crate::messages::knxip::error::{ParseError, ParseResult};
use crate::messages::knxip::messages::KNXnetIPServiceFamily;
use crate::util::packets::{
    BufferView, BufferViewMut, ParsablePacket, SerializablePacket,
    records::{
        ParsedRecord, RecordBuilder, RecordParseResult, RecordSequenceBuilder, Records, RecordsImpl, RecordsImplLayout,
    },
};

// ============================================================================
// INTERNAL WIRE FORMAT - ZEROCOPY TYPES
// ============================================================================

mod raw {
    use super::*;

    /// Wire format for SRP header (2 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct SRPHeader {
        pub struct_len: u8,
        pub search_request_parameter_type: u8,
    }

    /// Wire format for Select by MAC Address (6 bytes payload)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct SelectByMacAddress {
        pub mac_address: EthernetAddress,
    }

    /// Wire format for Select by Service (2 bytes payload)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct SelectByService {
        pub service_family: u8,
        pub version: u8,
    }

    /// Wire format for Request DIBs (variable length payload)
    /// Each DIB selector is 1 byte
    #[allow(dead_code)] // KNX spec: not yet used
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct RequestDIBsHeader {
        // DIB selectors follow
    }
}

// ============================================================================
// PROTOCOL ENUMS
// ============================================================================

create_protocol_enum!(
    #[allow(missing_docs)]
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum SRPType: u8 {
        Invalid, 0x00, "Invalid";
        SelectByProgrammingMode, 0x01, "Select by Programming Mode";
        SelectByMacAddress, 0x02, "Select by MAC Address";
        SelectByService, 0x03, "Select by Service";
        RequestDIBs, 0x04, "Request DIBs";
        _, "Unknown SRP Type 0x{:x}";
    }
);

/// The M (mandatory) bit occupies bit 7 of the SRP type code byte on the wire.
/// When set, the server MUST be able to evaluate the SRP to respond; if it cannot,
/// it must not respond. When clear, the server MAY ignore SRPs it doesn't understand.
const SRP_MANDATORY_BIT: u8 = 0x80;
const SRP_TYPE_MASK: u8 = 0x7F;

// ============================================================================
// RECORDS IMPLEMENTATION FOR DIB SELECTORS
// ============================================================================

/// Records implementation for parsing DIB selector entries (uses KNXnetIPServiceFamily)
#[derive(Debug)]
pub struct DIBSelectorsRecordImpl;

impl RecordsImplLayout for DIBSelectorsRecordImpl {
    type Context = ();
    type Error = ParseError;
}

impl RecordsImpl for DIBSelectorsRecordImpl {
    type Record<'a> = KNXnetIPServiceFamily;

    fn parse_with_context<'a, BV: BufferView<&'a [u8]>>(
        data: &mut BV,
        _context: &mut (),
    ) -> RecordParseResult<Self::Record<'a>, Self::Error> {
        if data.is_empty() {
            return Ok(ParsedRecord::Done);
        }

        let selector_byte = data.take_byte_front().ok_or(ParseError::Format)?;

        // If this is a padding byte (0x00) and we're at an odd position, treat it as done
        if selector_byte == 0x00 {
            // Check if there's more data - if not, this is padding
            if data.is_empty() {
                return Ok(ParsedRecord::Done);
            }
        }

        Ok(ParsedRecord::Parsed(KNXnetIPServiceFamily::from(selector_byte)))
    }
}

impl RecordBuilder for KNXnetIPServiceFamily {
    fn serialized_len(&self) -> usize {
        1
    }

    fn serialize_into(&self, data: &mut [u8]) {
        let selector_byte: u8 = (*self).into();
        data[0] = selector_byte;
    }
}
pub type DIBSelectorsRecords<B> = Records<B, DIBSelectorsRecordImpl>;

// ============================================================================
// PUBLIC API - OWNED TYPES
// ============================================================================

/// Search Request Parameter
///
/// Used in extended search requests to filter devices or request specific information.
/// Per KNX spec 3/8/2 §7.6.3.3, each SRP carries an M (mandatory) bit: if M is set
/// and the server cannot evaluate the SRP, it must not respond.
#[derive(Debug)]
pub enum SearchRequestParameter<B: SplitByteSlice = &'static [u8]> {
    /// Select devices in programming mode (no payload, header only)
    SelectByProgrammingMode,
    /// Select device by MAC address
    SelectByMacAddress { mac_address: EthernetAddress },
    /// Select devices supporting a specific service (with minimum version)
    SelectByService { service_family: u8, version: u8 },
    /// Request specific DIBs in the response
    RequestDIBs { selectors: DIBSelectorsRecords<B> },
    /// Invalid SRP (type code 0x00). Per spec Table 6, this is a test mechanism
    /// for verifying server behavior with unknown SRPs. The server never evaluates
    /// it — it only checks the M bit to decide whether to suppress the response.
    Invalid { mandatory: bool },
    /// Unknown/unrecognized SRP type. The body bytes are consumed but not interpreted.
    /// Like Invalid, the server uses the M bit to decide whether to suppress.
    Unknown { type_code: u8, mandatory: bool },
}

impl<B: SplitByteSlice> SearchRequestParameter<B> {
    /// Get the SRP type for this parameter
    pub fn srp_type(&self) -> SRPType {
        match self {
            Self::SelectByProgrammingMode => SRPType::SelectByProgrammingMode,
            Self::SelectByMacAddress { .. } => SRPType::SelectByMacAddress,
            Self::SelectByService { .. } => SRPType::SelectByService,
            Self::RequestDIBs { .. } => SRPType::RequestDIBs,
            Self::Invalid { .. } => SRPType::Invalid,
            Self::Unknown { type_code, .. } => SRPType::Other(*type_code),
        }
    }

    /// Whether this SRP has the mandatory bit set.
    ///
    /// For standard SRP types (ProgrammingMode, MAC, Service, RequestDIBs) the M bit
    /// is always set per spec Table 6. For Invalid and Unknown, it's whatever was on
    /// the wire.
    pub fn is_mandatory(&self) -> bool {
        match self {
            // Standard types: M bit is always set (spec Table 6)
            Self::SelectByProgrammingMode
            | Self::SelectByMacAddress { .. }
            | Self::SelectByService { .. }
            | Self::RequestDIBs { .. } => true,
            Self::Invalid { mandatory } | Self::Unknown { mandatory, .. } => *mandatory,
        }
    }
}

impl<B: SplitByteSlice> SearchRequestParameter<B> {
    /// Iterate over DIB selectors (if this is a RequestDIBs variant)
    pub fn iter_selectors(&self) -> Option<impl Iterator<Item = KNXnetIPServiceFamily> + '_> {
        match self {
            Self::RequestDIBs { selectors } => Some(selectors.iter()),
            _ => None,
        }
    }

    /// Count of DIB selectors (if this is a RequestDIBs variant)
    pub fn selectors_count(&self) -> Option<usize> {
        match self {
            Self::RequestDIBs { selectors } => Some(selectors.iter().count()),
            _ => None,
        }
    }

    /// Whether this SRP is a selection filter (as opposed to a meta-parameter
    /// like RequestDIBs, or an unknown/invalid type).
    pub fn is_selection_filter(&self) -> bool {
        matches!(
            self,
            Self::SelectByProgrammingMode | Self::SelectByMacAddress { .. } | Self::SelectByService { .. }
        )
    }
}

/// Builder-style constructors (for non-RequestDIBs types)
impl<B: SplitByteSlice> SearchRequestParameter<B> {
    /// Create a new SelectByProgrammingMode SRP
    pub const fn select_by_programming_mode() -> Self {
        Self::SelectByProgrammingMode
    }

    /// Create a new SelectByMacAddress SRP
    pub const fn select_by_mac_address(mac_address: EthernetAddress) -> Self {
        Self::SelectByMacAddress { mac_address }
    }

    /// Create a new SelectByService SRP
    pub const fn select_by_service(service_family: u8, version: u8) -> Self {
        Self::SelectByService { service_family, version }
    }
}

// ============================================================================
// PARSING: zerocopy wire format -> owned
// ============================================================================

impl<B: SplitByteSlice> ParsablePacket<B, ()> for SearchRequestParameter<B> {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> ParseResult<Self> {
        // Parse header
        let header = buffer.take_obj_front::<raw::SRPHeader>().ok_or_else(|| {
            debug!("too few bytes for SRP header");
            ParseError::Format
        })?;

        // The M (mandatory) bit is in bit 7 of the type code byte (spec §7.6.3.3).
        // Mask it off to get the actual type code.
        let raw_type = header.search_request_parameter_type;
        let mandatory = raw_type & SRP_MANDATORY_BIT != 0;
        let srp_type = SRPType::from(raw_type & SRP_TYPE_MASK);

        // Body length (total struct length minus the 2-byte header)
        let payload_len = header.struct_len.saturating_sub(2) as usize;

        match srp_type {
            SRPType::SelectByProgrammingMode => {
                // No payload - header only
                Ok(Self::SelectByProgrammingMode)
            }
            SRPType::SelectByMacAddress => {
                let body = buffer.take_obj_front::<raw::SelectByMacAddress>().ok_or_else(|| {
                    debug!("too few bytes for SelectByMacAddress body");
                    ParseError::Format
                })?;

                Ok(Self::SelectByMacAddress { mac_address: body.mac_address })
            }
            SRPType::SelectByService => {
                let body = buffer.take_obj_front::<raw::SelectByService>().ok_or_else(|| {
                    debug!("too few bytes for SelectByService body");
                    ParseError::Format
                })?;

                Ok(Self::SelectByService { service_family: body.service_family, version: body.version })
            }
            SRPType::RequestDIBs => {
                let selectors_bytes = buffer.take_front(payload_len).ok_or_else(|| {
                    debug!("too few bytes for DIB selectors");
                    ParseError::Format
                })?;

                let selectors = DIBSelectorsRecords::parse(selectors_bytes)?;

                Ok(Self::RequestDIBs { selectors })
            }
            SRPType::Invalid => {
                // Consume any body bytes (spec says struct_len=2, but be robust)
                if payload_len > 0 {
                    let _ = buffer.take_front(payload_len).ok_or_else(|| {
                        debug!("too few bytes for Invalid SRP body");
                        ParseError::Format
                    })?;
                }
                Ok(Self::Invalid { mandatory })
            }
            SRPType::Other(type_code) => {
                // Unknown SRP type — consume body bytes based on struct_len so parsing
                // can continue to the next SRP in the sequence.
                if payload_len > 0 {
                    let _ = buffer.take_front(payload_len).ok_or_else(|| {
                        debug!("too few bytes for unknown SRP type 0x{:02x} body", type_code);
                        ParseError::Format
                    })?;
                }
                debug!("unknown SRP type 0x{:02x}, mandatory={}", type_code, mandatory);
                Ok(Self::Unknown { type_code, mandatory })
            }
        }
    }
}

// ============================================================================
// BUILDERS FOR SERIALIZATION
// ============================================================================

/// Builder for Search Request Parameters
///
/// Used to serialize SRP messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchRequestParameterBuilder<'a> {
    /// Select devices in programming mode (no payload, header only)
    SelectByProgrammingMode,
    /// Select device by MAC address
    SelectByMacAddress { mac_address: EthernetAddress },
    /// Select devices supporting a specific service (with minimum version)
    SelectByService { service_family: u8, version: u8 },
    /// Request specific DIBs in the response
    RequestDIBs { selectors: &'a [KNXnetIPServiceFamily] },
}

impl<'a> SearchRequestParameterBuilder<'a> {
    /// Get the SRP type for this parameter
    pub fn srp_type(&self) -> SRPType {
        match self {
            Self::SelectByProgrammingMode => SRPType::SelectByProgrammingMode,
            Self::SelectByMacAddress { .. } => SRPType::SelectByMacAddress,
            Self::SelectByService { .. } => SRPType::SelectByService,
            Self::RequestDIBs { .. } => SRPType::RequestDIBs,
        }
    }

    /// Create a new SelectByProgrammingMode SRP
    pub const fn select_by_programming_mode() -> Self {
        Self::SelectByProgrammingMode
    }

    /// Create a new SelectByMacAddress SRP
    pub const fn select_by_mac_address(mac_address: EthernetAddress) -> Self {
        Self::SelectByMacAddress { mac_address }
    }

    /// Create a new SelectByService SRP
    pub const fn select_by_service(service_family: u8, version: u8) -> Self {
        Self::SelectByService { service_family, version }
    }

    /// Create a new RequestDIBs SRP
    pub const fn request_dibs(selectors: &'a [KNXnetIPServiceFamily]) -> Self {
        Self::RequestDIBs { selectors }
    }
}

impl<'a> SerializablePacket for SearchRequestParameterBuilder<'a> {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::SRPHeader>()
            + match self {
                Self::SelectByProgrammingMode => 0, // No payload
                Self::SelectByMacAddress { .. } => mem::size_of::<raw::SelectByMacAddress>(),
                Self::SelectByService { .. } => mem::size_of::<raw::SelectByService>(),
                Self::RequestDIBs { selectors } => {
                    // Must be even length - add padding byte if odd
                    let len = selectors.len();
                    if len % 2 == 1 { len + 1 } else { len }
                }
            }
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        // Write header using zerocopy. Per spec Table 6, the M bit (bit 7) is always
        // set for all standard SRP types.
        let mut header = bv.take_obj_front_zero::<raw::SRPHeader>().expect("too few bytes for SRP header");
        header.struct_len = self.bytes_len() as u8;
        let type_code: u8 = self.srp_type().into();
        header.search_request_parameter_type = type_code | SRP_MANDATORY_BIT;

        // Write body using zerocopy
        match self {
            Self::SelectByProgrammingMode => {
                // No payload to write
            }
            Self::SelectByMacAddress { mac_address } => {
                let mut body = bv.take_obj_front_zero::<raw::SelectByMacAddress>().expect("too few bytes for SRP body");
                body.mac_address = *mac_address;
            }
            Self::SelectByService { service_family, version } => {
                let mut body = bv.take_obj_front_zero::<raw::SelectByService>().expect("too few bytes for SRP body");
                body.service_family = *service_family;
                body.version = *version;
            }
            Self::RequestDIBs { selectors } => {
                let records_builder: RecordSequenceBuilder<KNXnetIPServiceFamily, _> =
                    RecordSequenceBuilder::new(selectors.iter());
                records_builder.serialize(bv);

                // Add padding byte if odd number of selectors to make structure length even
                if selectors.len() % 2 == 1 {
                    let padding: u8 = 0x00;
                    bv.write_obj_front(&padding).expect("too few bytes for padding");
                }
            }
        }
    }
}

// ============================================================================
// HELPER FUNCTIONS (can peek at raw format without full parse)
// ============================================================================

/// Peek at an SRP header to see what type is present.
///
/// This is useful when you need to determine the SRP type before
/// doing a full parse. The M bit is masked off — only the type code is returned.
pub fn peek_srp_type(bytes: &[u8]) -> ParseResult<SRPType> {
    let (header, _) = Ref::<_, raw::SRPHeader>::from_prefix(bytes).map_err(|_| {
        debug!("too few bytes for SRP header");
        ParseError::Format
    })?;

    Ok(SRPType::from(header.search_request_parameter_type & SRP_TYPE_MASK))
}

/// Peek at the structure length field in the SRP header.
pub fn peek_srp_structure_length(bytes: &[u8]) -> ParseResult<u8> {
    let (header, _) = Ref::<_, raw::SRPHeader>::from_prefix(bytes).map_err(|_| {
        debug!("too few bytes for SRP header");
        ParseError::Format
    })?;

    Ok(header.struct_len)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::packets::{ParseBuffer, SerializeBuffer};

    // ========================================================================
    // Parsing tests — wire format uses M bit (0x80) on the type code byte
    // ========================================================================

    #[test]
    fn test_parse_select_by_programming_mode() {
        let data = [
            0x02, 0x81, // length=2, type=0x01|M
        ];

        let mut slice = &data[..];
        let srp: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        assert!(matches!(srp, SearchRequestParameter::SelectByProgrammingMode));
        assert!(srp.is_mandatory());
    }

    #[test]
    fn test_parse_select_by_programming_mode_without_m_bit() {
        // Parser should still recognize the type even without M bit
        let data = [
            0x02, 0x01, // length=2, type=0x01 (no M bit)
        ];

        let mut slice = &data[..];
        let srp: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        assert!(matches!(srp, SearchRequestParameter::SelectByProgrammingMode));
    }

    #[test]
    fn test_parse_select_by_mac_address() {
        let data = [
            0x08, 0x82, // length=8, type=0x02|M
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];

        let mut slice = &data[..];
        let srp: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        match srp {
            SearchRequestParameter::SelectByMacAddress { mac_address } => {
                assert_eq!(mac_address.0, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
            }
            _ => panic!("Wrong SRP type"),
        }
    }

    #[test]
    fn test_parse_select_by_service() {
        let data = [
            0x04, 0x83, // length=4, type=0x03|M
            0x05, 0x01,
        ];

        let mut slice = &data[..];
        let srp: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        match srp {
            SearchRequestParameter::SelectByService { service_family, version } => {
                assert_eq!(service_family, 0x05);
                assert_eq!(version, 0x01);
            }
            _ => panic!("Wrong SRP type"),
        }
    }

    #[test]
    fn test_parse_request_dibs() {
        let data = [
            0x05, 0x84, // length=5, type=0x04|M
            0x01, 0x02, 0x03,
        ];

        let mut slice = &data[..];
        let srp: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        match srp {
            SearchRequestParameter::RequestDIBs { selectors } => {
                let items: heapless::Vec<_, 16> = selectors.iter().collect();
                assert_eq!(items.len(), 3);
                assert_eq!(items[0], KNXnetIPServiceFamily::DeviceInfo);
                assert_eq!(items[1], KNXnetIPServiceFamily::SupportedServiceFamilies);
                assert_eq!(items[2], KNXnetIPServiceFamily::IPConfig);
            }
            _ => panic!("Wrong SRP type"),
        }
    }

    #[test]
    fn test_parse_request_dibs_odd_padding() {
        let data = [
            0x04, 0x84, // length=4, type=0x04|M
            0x01, // DeviceInfo
            0x00, // Padding
        ];

        let mut slice = &data[..];
        let srp: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        match srp {
            SearchRequestParameter::RequestDIBs { selectors } => {
                let items: heapless::Vec<_, 16> = selectors.iter().collect();
                assert_eq!(items.len(), 1);
                assert_eq!(items[0], KNXnetIPServiceFamily::DeviceInfo);
            }
            _ => panic!("Wrong SRP type"),
        }
    }

    // ========================================================================
    // Invalid SRP (type code 0x00) — conformance test mechanism
    // ========================================================================

    #[test]
    fn test_parse_invalid_srp_mandatory() {
        // Invalid SRP with M bit set — server must not respond
        let data = [
            0x02, 0x80, // length=2, type=0x00|M
        ];

        let mut slice = &data[..];
        let srp: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        match srp {
            SearchRequestParameter::Invalid { mandatory } => assert!(mandatory),
            _ => panic!("Expected Invalid SRP"),
        }
    }

    #[test]
    fn test_parse_invalid_srp_not_mandatory() {
        // Invalid SRP without M bit — server should ignore it
        let data = [
            0x02, 0x00, // length=2, type=0x00 (no M bit)
        ];

        let mut slice = &data[..];
        let srp: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        match srp {
            SearchRequestParameter::Invalid { mandatory } => assert!(!mandatory),
            _ => panic!("Expected Invalid SRP"),
        }
    }

    // ========================================================================
    // Unknown SRP types — graceful body consumption
    // ========================================================================

    #[test]
    fn test_parse_unknown_srp_mandatory() {
        // Unknown type 0x05 with M bit, 2-byte body
        let data = [
            0x04, 0x85, // length=4, type=0x05|M
            0xAA, 0xBB, // body (consumed but not interpreted)
        ];

        let mut slice = &data[..];
        let srp: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        match srp {
            SearchRequestParameter::Unknown { type_code, mandatory } => {
                assert_eq!(type_code, 0x05);
                assert!(mandatory);
            }
            _ => panic!("Expected Unknown SRP"),
        }
        // Buffer should be fully consumed
        assert!(slice.is_empty());
    }

    #[test]
    fn test_parse_unknown_srp_not_mandatory() {
        // Unknown type 0x7F without M bit, no body
        let data = [
            0x02, 0x7F, // length=2, type=0x7F (no M bit)
        ];

        let mut slice = &data[..];
        let srp: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        match srp {
            SearchRequestParameter::Unknown { type_code, mandatory } => {
                assert_eq!(type_code, 0x7F);
                assert!(!mandatory);
            }
            _ => panic!("Expected Unknown SRP"),
        }
    }

    #[test]
    fn test_parse_unknown_srp_with_body_followed_by_known() {
        // Unknown SRP followed by a known SRP — the unknown body must be consumed
        // cleanly so the next SRP can be parsed.
        let data = [
            0x04, 0x85, // Unknown type 0x05|M, length=4
            0xAA, 0xBB, // body (2 bytes)
            0x02, 0x81, // SelectByProgrammingMode, length=2, type=0x01|M
        ];

        let mut slice = &data[..];
        let srp1: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        assert!(matches!(srp1, SearchRequestParameter::Unknown { type_code: 0x05, mandatory: true }));

        let srp2: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        assert!(matches!(srp2, SearchRequestParameter::SelectByProgrammingMode));
    }

    // ========================================================================
    // Serialization tests — output must include M bit
    // ========================================================================

    #[test]
    fn test_serialize_select_by_programming_mode() {
        let srp = SearchRequestParameterBuilder::SelectByProgrammingMode;

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&srp);

        let expected = [
            0x02, 0x81, // length=2, type=0x01|M
        ];
        assert_eq!(written, &expected[..]);
    }

    #[test]
    fn test_serialize_select_by_mac_address() {
        let mac = EthernetAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let srp = SearchRequestParameterBuilder::SelectByMacAddress { mac_address: mac };

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&srp);

        let expected = [
            0x08, 0x82, // length=8, type=0x02|M
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];
        assert_eq!(written, &expected[..]);
    }

    #[test]
    fn test_serialize_request_dibs() {
        let selectors = [KNXnetIPServiceFamily::DeviceInfo, KNXnetIPServiceFamily::SupportedServiceFamilies];
        let srp = SearchRequestParameterBuilder::RequestDIBs { selectors: &selectors };

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&srp);

        let expected = [
            0x04, 0x84, // length=4, type=0x04|M
            0x01, 0x02,
        ];
        assert_eq!(written, &expected[..]);
    }

    #[test]
    fn test_serialize_request_dibs_odd_padding() {
        let selectors = [KNXnetIPServiceFamily::DeviceInfo];
        let srp = SearchRequestParameterBuilder::RequestDIBs { selectors: &selectors };

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&srp);

        let expected = [
            0x04, 0x84, // length=4, type=0x04|M (includes padding)
            0x01, // DeviceInfo
            0x00, // Padding
        ];
        assert_eq!(written, &expected[..]);
    }

    // ========================================================================
    // Round-trip tests
    // ========================================================================

    #[test]
    fn test_round_trip_select_by_service() {
        let builder = SearchRequestParameterBuilder::SelectByService { service_family: 0x04, version: 0x01 };

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Verify M bit is set in serialized output
        assert_eq!(written[1], 0x83); // 0x03 | 0x80

        let mut parse_buf = &written[..];
        let parsed: SearchRequestParameter<&[u8]> = parse_buf.parse().unwrap();
        match parsed {
            SearchRequestParameter::SelectByService { service_family, version } => {
                assert_eq!(service_family, 0x04);
                assert_eq!(version, 0x01);
            }
            _ => panic!("Wrong SRP type after round trip"),
        }
    }

    #[test]
    fn test_round_trip_select_by_programming_mode() {
        let builder = SearchRequestParameterBuilder::SelectByProgrammingMode;

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        let mut parse_buf = &written[..];
        let parsed: SearchRequestParameter<&[u8]> = parse_buf.parse().unwrap();
        assert!(matches!(parsed, SearchRequestParameter::SelectByProgrammingMode));
    }

    // ========================================================================
    // Peek helpers
    // ========================================================================

    #[test]
    fn test_peek_srp_type_masks_m_bit() {
        // With M bit set
        let data = [0x02, 0x81]; // type=0x01|M
        assert_eq!(peek_srp_type(&data).unwrap(), SRPType::SelectByProgrammingMode);

        // Without M bit
        let data = [0x02, 0x01]; // type=0x01
        assert_eq!(peek_srp_type(&data).unwrap(), SRPType::SelectByProgrammingMode);

        // Invalid with M bit
        let data = [0x02, 0x80]; // type=0x00|M
        assert_eq!(peek_srp_type(&data).unwrap(), SRPType::Invalid);
    }

    #[test]
    fn test_peek_srp_structure_length() {
        let data = [
            0x05, 0x84, // length=5, type=0x04|M
            0x01, 0x02, 0x03,
        ];
        assert_eq!(peek_srp_structure_length(&data).unwrap(), 5);
    }

    // ========================================================================
    // is_mandatory helper
    // ========================================================================

    #[test]
    fn test_is_mandatory() {
        // Standard types are always mandatory
        assert!(SearchRequestParameter::<&[u8]>::SelectByProgrammingMode.is_mandatory());
        assert!(SearchRequestParameter::<&[u8]>::SelectByMacAddress {
            mac_address: EthernetAddress([0; 6])
        }
        .is_mandatory());
        assert!(SearchRequestParameter::<&[u8]>::SelectByService { service_family: 0, version: 0 }.is_mandatory());

        // Invalid/Unknown depend on the wire M bit
        assert!(SearchRequestParameter::<&[u8]>::Invalid { mandatory: true }.is_mandatory());
        assert!(!SearchRequestParameter::<&[u8]>::Invalid { mandatory: false }.is_mandatory());
        assert!(SearchRequestParameter::<&[u8]>::Unknown { type_code: 0x05, mandatory: true }.is_mandatory());
        assert!(!SearchRequestParameter::<&[u8]>::Unknown { type_code: 0x05, mandatory: false }.is_mandatory());
    }
}
