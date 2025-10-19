use core::mem;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, SplitByteSlice, SplitByteSliceMut, Unaligned};

use platform::address::EthernetAddress;

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
        SelectByProgrammingMode, 0x01, "Select by Programming Mode";
        SelectByMacAddress, 0x02, "Select by MAC Address";
        SelectByService, 0x03, "Select by Service";
        RequestDIBs, 0x04, "Request DIBs";
        _, "Unknown SRP Type 0x{:x}";
    }
);

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
}

impl<B: SplitByteSlice> SearchRequestParameter<B> {
    /// Get the SRP type for this parameter
    pub fn srp_type(&self) -> SRPType {
        match self {
            Self::SelectByProgrammingMode => SRPType::SelectByProgrammingMode,
            Self::SelectByMacAddress { .. } => SRPType::SelectByMacAddress,
            Self::SelectByService { .. } => SRPType::SelectByService,
            Self::RequestDIBs { .. } => SRPType::RequestDIBs,
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

        // Match on SRP type and parse body
        let srp_type = SRPType::try_from(header.search_request_parameter_type).map_err(|_| {
            debug!("unrecognized SRP type: {:x}", header.search_request_parameter_type);
            ParseError::NotSupported
        })?;

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
                // Calculate number of bytes for selectors based on length
                let payload_len = header.struct_len.saturating_sub(2); // subtract header size
                let selectors_bytes = buffer.take_front(payload_len as usize).ok_or_else(|| {
                    debug!("too few bytes for DIB selectors");
                    ParseError::Format
                })?;

                let selectors = DIBSelectorsRecords::parse(selectors_bytes)?;

                Ok(Self::RequestDIBs { selectors })
            }
            SRPType::Other(_) => {
                debug!("unsupported SRP type: {:?}", srp_type);
                Err(ParseError::NotSupported)
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
        // Write header using zerocopy
        let mut header = bv.take_obj_front_zero::<raw::SRPHeader>().expect("too few bytes for SRP header");
        header.struct_len = self.bytes_len() as u8;
        header.search_request_parameter_type = self.srp_type().into();

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
/// doing a full parse.
pub fn peek_srp_type(bytes: &[u8]) -> ParseResult<SRPType> {
    let (header, _) = Ref::<_, raw::SRPHeader>::from_prefix(bytes).map_err(|_| {
        debug!("too few bytes for SRP header");
        ParseError::Format
    })?;

    SRPType::try_from(header.search_request_parameter_type).map_err(|_| {
        debug!("unrecognized SRP type: {:x}", header.search_request_parameter_type);
        ParseError::NotSupported
    })
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

    #[test]
    fn test_parse_select_by_programming_mode() {
        let data = [
            0x02, 0x01, // header: length=2, type=SelectByProgrammingMode (no payload)
        ];

        let mut slice = &data[..];
        let srp: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        match srp {
            SearchRequestParameter::SelectByProgrammingMode => {
                // Success - no fields to check
            }
            _ => panic!("Wrong SRP type"),
        }
    }

    #[test]
    fn test_parse_select_by_mac_address() {
        let data = [
            0x08, 0x02, // header: length=8, type=SelectByMacAddress
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // MAC address
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
            0x04, 0x03, // header: length=4, type=SelectByService
            0x05, // service family (using 0x05 for test)
            0x01, // version
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
            0x05, 0x04, // header: length=5, type=RequestDIBs
            0x01, // DeviceInfo
            0x02, // SupportedServiceFamilies
            0x03, // IPConfig
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
    fn test_serialize_select_by_programming_mode() {
        let srp = SearchRequestParameterBuilder::SelectByProgrammingMode;

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&srp);

        let expected = [
            0x02, 0x01, // header: length=2, type=SelectByProgrammingMode (no payload)
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
            0x08, 0x02, // header: length=8, type=SelectByMacAddress
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // MAC address
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
            0x04, 0x04, // header: length=4, type=RequestDIBs
            0x01, // DeviceInfo
            0x02, // SupportedServiceFamilies
        ];

        assert_eq!(written, &expected[..]);
    }

    #[test]
    fn test_serialize_request_dibs_odd_padding() {
        // Test with odd number of selectors - should add padding
        let selectors = [KNXnetIPServiceFamily::DeviceInfo];
        let srp = SearchRequestParameterBuilder::RequestDIBs { selectors: &selectors };

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&srp);

        let expected = [
            0x04, 0x04, // header: length=4, type=RequestDIBs (includes padding)
            0x01, // DeviceInfo
            0x00, // Padding to make length even
        ];

        assert_eq!(written, &expected[..]);
    }

    #[test]
    fn test_parse_request_dibs_odd_padding() {
        // Test parsing with padding byte
        let data = [
            0x04, 0x04, // header: length=4, type=RequestDIBs
            0x01, // DeviceInfo
            0x00, // Padding
        ];

        let mut slice = &data[..];
        let srp: SearchRequestParameter<&[u8]> = slice.parse().unwrap();
        match srp {
            SearchRequestParameter::RequestDIBs { selectors } => {
                let items: heapless::Vec<_, 16> = selectors.iter().collect();
                // Should have only 1 selector, padding should be ignored
                assert_eq!(items.len(), 1);
                assert_eq!(items[0], KNXnetIPServiceFamily::DeviceInfo);
            }
            _ => panic!("Wrong SRP type"),
        }
    }

    #[test]
    fn test_round_trip_select_by_service() {
        let builder = SearchRequestParameterBuilder::SelectByService { service_family: 0x04, version: 0x01 };

        // Serialize
        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = &written[..];
        let parsed: SearchRequestParameter<&[u8]> = parse_buf.parse().unwrap();

        // Compare
        match parsed {
            SearchRequestParameter::SelectByService { service_family, version } => {
                assert_eq!(service_family, 0x04);
                assert_eq!(version, 0x01);
            }
            _ => panic!("Wrong SRP type after round trip"),
        }
    }

    #[test]
    fn test_peek_srp_type() {
        let data = [
            0x02, 0x01, // header: length=2, type=SelectByProgrammingMode (no payload)
        ];

        let srp_type = peek_srp_type(&data).unwrap();
        assert_eq!(srp_type, SRPType::SelectByProgrammingMode);
    }

    #[test]
    fn test_peek_srp_structure_length() {
        let data = [
            0x05, 0x04, // header: length=5, type=RequestDIBs
            0x01, 0x02, 0x03, // selectors
        ];

        let length = peek_srp_structure_length(&data).unwrap();
        assert_eq!(length, 5);
    }
}
