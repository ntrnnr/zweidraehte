//! KNX/IP Discovery Messages (SEARCH_REQUEST, SEARCH_RESPONSE, DESCRIPTION_REQUEST, DESCRIPTION_RESPONSE)

use core::mem;

use zerocopy::{SplitByteSlice, SplitByteSliceMut, big_endian::U16};

use crate::{
    messages::knxip::error::*,
    util::packets::{records::RecordSequenceBuilder, *},
};

use super::{super::substructs::*, KNXnetIPServiceType, KNXnetIPVersion, raw};

// ============================================================================
// SEARCH REQUEST
// ============================================================================

/// KNXnet/IP SEARCH_REQUEST
///
/// Used to discover KNXnet/IP servers on the network
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    pub discovery_endpoint: HPAI,
}

impl SearchRequest {
    /// Create a new SEARCH_REQUEST with the given discovery endpoint
    pub fn new(discovery_endpoint: HPAI) -> Self {
        Self { discovery_endpoint }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for SearchRequest {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        // Parse header
        let header = buffer.take_obj_front::<raw::KNXnetIPHeader>().ok_or(ParseError::Format)?;

        // Verify it's a SEARCH_REQUEST
        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::SearchRequest
        {
            return Err(ParseError::Format);
        }

        // Parse discovery endpoint
        let discovery_endpoint = HPAI::parse(buffer, ())?;

        Ok(SearchRequest { discovery_endpoint })
    }
}

impl SearchRequest {
    /// Convert this packet into a builder for serialization
    pub fn into_builder(self) -> SearchRequestBuilder {
        SearchRequestBuilder { discovery_endpoint: self.discovery_endpoint }
    }
}

/// Builder for SearchRequest message
pub struct SearchRequestBuilder {
    pub discovery_endpoint: HPAI,
}

impl SearchRequestBuilder {
    pub fn new(discovery_endpoint: HPAI) -> Self {
        Self { discovery_endpoint }
    }
}

impl SerializablePacket for SearchRequestBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::KNXnetIPHeader>() + self.discovery_endpoint.bytes_len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::KNXnetIPHeader {
            header_size: mem::size_of::<raw::KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::SearchRequest)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        self.discovery_endpoint.serialize(bv);
    }
}

// ============================================================================
// SEARCH REQUEST EXTENDED
// ============================================================================

/// KNXnet/IP SEARCH_REQUEST (Extended)
///
/// Used to discover KNXnet/IP servers on the network with additional search parameters
#[derive(Debug)]
pub struct SearchRequestExtended<B: SplitByteSlice = &'static [u8]> {
    pub discovery_endpoint: HPAI,
    pub search_request_parameters: heapless::Vec<SearchRequestParameter<B>, 16>,
}

impl<B: SplitByteSlice> SearchRequestExtended<B> {
    /// Create a new SEARCH_REQUEST_EXTENDED with the given discovery endpoint and SRPs
    pub fn new(
        discovery_endpoint: HPAI,
        search_request_parameters: heapless::Vec<SearchRequestParameter<B>, 16>,
    ) -> Self {
        Self { discovery_endpoint, search_request_parameters }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for SearchRequestExtended<B> {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        // Parse header
        let header = buffer.take_obj_front::<raw::KNXnetIPHeader>().ok_or(ParseError::Format)?;

        // Verify it's a SEARCH_REQUEST_EXTENDED
        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::SearchRequestExtended
        {
            return Err(ParseError::Format);
        }

        // Parse discovery endpoint
        let discovery_endpoint = HPAI::parse(buffer, ())?;

        // Parse all SRPs until buffer is empty
        let mut search_request_parameters = heapless::Vec::new();
        while !buffer.is_empty() {
            let srp = SearchRequestParameter::parse(buffer, ())?;
            search_request_parameters.push(srp).map_err(|_| ParseError::Format)?;
        }

        Ok(SearchRequestExtended { discovery_endpoint, search_request_parameters })
    }
}

/// Builder for SearchRequestExtended message
pub struct SearchRequestExtendedBuilder<'a> {
    pub discovery_endpoint: HPAI,
    pub search_request_parameters: &'a [SearchRequestParameterBuilder<'a>],
}

impl<'a> SearchRequestExtendedBuilder<'a> {
    pub fn new(discovery_endpoint: HPAI, search_request_parameters: &'a [SearchRequestParameterBuilder<'a>]) -> Self {
        Self { discovery_endpoint, search_request_parameters }
    }
}

impl<'a> SerializablePacket for SearchRequestExtendedBuilder<'a> {
    fn bytes_len(&self) -> usize {
        let srps_len: usize = self.search_request_parameters.iter().map(|srp| srp.bytes_len()).sum();
        mem::size_of::<raw::KNXnetIPHeader>() + self.discovery_endpoint.bytes_len() + srps_len
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::KNXnetIPHeader {
            header_size: mem::size_of::<raw::KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::SearchRequestExtended)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        self.discovery_endpoint.serialize(bv);

        for srp in self.search_request_parameters {
            srp.serialize(bv);
        }
    }
}

// ============================================================================
// SEARCH RESPONSE
// ============================================================================

/// KNXnet/IP SEARCH_RESPONSE
///
/// Response to a SEARCH_REQUEST containing device information
#[derive(Debug)]
pub struct SearchResponse<B: SplitByteSlice> {
    pub control_endpoint: HPAI,
    pub device_hardware: DeviceInformation,
    pub supported_services: SupportedServiceFamilies<B>,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for SearchResponse<B> {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        // Parse header
        let header = buffer.take_obj_front::<raw::KNXnetIPHeader>().ok_or(ParseError::Format)?;

        // Verify it's a SEARCH_RESPONSE
        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::SearchResponse
        {
            return Err(ParseError::Format);
        }

        // Parse control endpoint - now buffer is &mut BV
        let control_endpoint = HPAI::parse(buffer, ())?;

        // Parse device hardware DIB
        let device_hardware = DeviceInformation::parse(buffer, ())?;

        // Parse supported services DIB
        let supported_services = SupportedServiceFamilies::parse(buffer, ())?;

        Ok(SearchResponse { control_endpoint, device_hardware, supported_services })
    }
}

/// Builder for SearchResponse message
///
/// Since SearchResponse contains SupportedServiceFamilies which uses Records,
/// we need a builder to serialize it properly.
pub struct SearchResponseBuilder<'a> {
    pub control_endpoint: HPAI,
    pub device_hardware: DeviceInformation,
    pub supported_services: &'a [SupportedService],
}

impl<'a> SearchResponseBuilder<'a> {
    pub fn new(
        control_endpoint: HPAI,
        device_hardware: DeviceInformation,
        supported_services: &'a [SupportedService],
    ) -> Self {
        Self { control_endpoint, device_hardware, supported_services }
    }
}

impl<'a> SerializablePacket for SearchResponseBuilder<'a> {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::KNXnetIPHeader>()
            + self.control_endpoint.bytes_len()
            + self.device_hardware.bytes_len()
            + SupportedServiceFamiliesBuilder::new(self.supported_services).bytes_len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::KNXnetIPHeader {
            header_size: mem::size_of::<raw::KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::SearchResponse)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        self.control_endpoint.serialize(bv);
        self.device_hardware.serialize(bv);

        let services_builder = SupportedServiceFamiliesBuilder::new(self.supported_services);
        services_builder.serialize(bv);
    }
}

// ============================================================================
// SEARCH RESPONSE EXTENDED
// ============================================================================

/// KNXnet/IP SEARCH_RESPONSE (Extended)
///
/// Response to a SEARCH_REQUEST_EXTENDED containing a variable number of DIBs
#[derive(Debug)]
pub struct SearchResponseExtended<B: SplitByteSlice = &'static [u8]> {
    pub control_endpoint: HPAI,
    pub description_information_blocks: DibRecords<B>,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for SearchResponseExtended<B> {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        // Parse header
        let header = buffer.take_obj_front::<raw::KNXnetIPHeader>().ok_or(ParseError::Format)?;

        // Verify it's a SEARCH_RESPONSE_EXTENDED
        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::SearchResponseExtended
        {
            return Err(ParseError::Format);
        }

        // Parse control endpoint
        let control_endpoint = HPAI::parse(buffer, ())?;

        let description_information_blocks = DibRecords::parse(buffer.take_rest_front())?;

        Ok(SearchResponseExtended { control_endpoint, description_information_blocks })
    }
}

/// Builder for SearchResponseExtended message
pub struct SearchResponseExtendedBuilder<'a> {
    pub control_endpoint: HPAI,
    pub description_information_blocks: &'a [DescriptionInformationBlockBuilder<'a>],
}

impl<'a> SearchResponseExtendedBuilder<'a> {
    pub fn new(
        control_endpoint: HPAI,
        description_information_blocks: &'a [DescriptionInformationBlockBuilder<'a>],
    ) -> Self {
        Self { control_endpoint, description_information_blocks }
    }
}

impl<'a> SerializablePacket for SearchResponseExtendedBuilder<'a> {
    fn bytes_len(&self) -> usize {
        let dibs: RecordSequenceBuilder<DescriptionInformationBlockBuilder, _> =
            RecordSequenceBuilder::new(self.description_information_blocks.iter());
        mem::size_of::<raw::KNXnetIPHeader>() + self.control_endpoint.bytes_len() + dibs.bytes_len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::KNXnetIPHeader {
            header_size: mem::size_of::<raw::KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::SearchResponseExtended)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        self.control_endpoint.serialize(bv);

        let dibs: RecordSequenceBuilder<DescriptionInformationBlockBuilder, _> =
            RecordSequenceBuilder::new(self.description_information_blocks.iter());
        dibs.serialize(bv);
    }
}

// ============================================================================
// DESCRIPTION REQUEST
// ============================================================================

/// KNXnet/IP DESCRIPTION_REQUEST
///
/// Request for detailed device information from a KNXnet/IP server
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptionRequest {
    pub control_endpoint: HPAI,
}

impl DescriptionRequest {
    /// Create a new DESCRIPTION_REQUEST with the given control endpoint
    pub fn new(control_endpoint: HPAI) -> Self {
        Self { control_endpoint }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for DescriptionRequest {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        // Parse header
        let header = buffer.take_obj_front::<raw::KNXnetIPHeader>().ok_or(ParseError::Format)?;

        // Verify it's a DESCRIPTION_REQUEST
        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::DescriptionRequest
        {
            return Err(ParseError::Format);
        }

        // Parse control endpoint
        let control_endpoint = HPAI::parse(buffer, ())?;

        Ok(DescriptionRequest { control_endpoint })
    }
}

impl DescriptionRequest {
    /// Convert this packet into a builder for serialization
    pub fn into_builder(self) -> DescriptionRequestBuilder {
        DescriptionRequestBuilder { control_endpoint: self.control_endpoint }
    }
}

/// Builder for DescriptionRequest message
pub struct DescriptionRequestBuilder {
    pub control_endpoint: HPAI,
}

impl DescriptionRequestBuilder {
    pub fn new(control_endpoint: HPAI) -> Self {
        Self { control_endpoint }
    }
}

impl SerializablePacket for DescriptionRequestBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::KNXnetIPHeader>() + self.control_endpoint.bytes_len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::KNXnetIPHeader {
            header_size: mem::size_of::<raw::KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::DescriptionRequest)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        self.control_endpoint.serialize(bv);
    }
}

// ============================================================================
// DESCRIPTION RESPONSE
// ============================================================================

/// KNXnet/IP DESCRIPTION_RESPONSE
///
/// Response to a DESCRIPTION_REQUEST containing detailed device information
#[derive(Debug)]
pub struct DescriptionResponse<B: SplitByteSlice> {
    pub device_hardware: DeviceInformation,
    pub supported_services: SupportedServiceFamilies<B>,
    // Note: Can contain additional optional DIBs that we currently don't parse
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for DescriptionResponse<B> {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        // Parse header
        let header = buffer.take_obj_front::<raw::KNXnetIPHeader>().ok_or(ParseError::Format)?;

        // Verify it's a DESCRIPTION_RESPONSE
        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::DescriptionResponse
        {
            return Err(ParseError::Format);
        }

        // Parse device hardware DIB
        let device_hardware = DeviceInformation::parse(buffer, ())?;

        // Parse supported services DIB
        let supported_services = SupportedServiceFamilies::parse(buffer, ())?;

        // Note: Additional optional DIBs may follow but we ignore them for now

        Ok(DescriptionResponse { device_hardware, supported_services })
    }
}

/// Builder for DescriptionResponse message
///
/// Since DescriptionResponse contains SupportedServiceFamilies which uses Records,
/// we need a builder to serialize it properly. Optional additional DIBs (e.g.,
/// IpConfig, IpCurrentConfig, KnxAddresses) can be appended after the mandatory
/// DeviceInformation and SupportedServiceFamilies.
///
/// Per spec Table 5, DescriptionResponse must NOT include TunnelingInfo or
/// ExtendedDeviceInfo — those are SearchResponseExtended-only.
pub struct DescriptionResponseBuilder<'a> {
    pub device_hardware: DeviceInformation,
    pub supported_services: &'a [SupportedService],
    pub additional_dibs: &'a [DescriptionInformationBlockBuilder<'a>],
}

impl<'a> DescriptionResponseBuilder<'a> {
    pub fn new(device_hardware: DeviceInformation, supported_services: &'a [SupportedService]) -> Self {
        Self { device_hardware, supported_services, additional_dibs: &[] }
    }

    pub fn with_additional_dibs(
        device_hardware: DeviceInformation,
        supported_services: &'a [SupportedService],
        additional_dibs: &'a [DescriptionInformationBlockBuilder<'a>],
    ) -> Self {
        Self { device_hardware, supported_services, additional_dibs }
    }
}

impl<'a> SerializablePacket for DescriptionResponseBuilder<'a> {
    fn bytes_len(&self) -> usize {
        let additional: usize = self.additional_dibs.iter().map(|dib| dib.bytes_len()).sum();
        mem::size_of::<raw::KNXnetIPHeader>()
            + self.device_hardware.bytes_len()
            + SupportedServiceFamiliesBuilder::new(self.supported_services).bytes_len()
            + additional
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::KNXnetIPHeader {
            header_size: mem::size_of::<raw::KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::DescriptionResponse)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        self.device_hardware.serialize(bv);

        let services_builder = SupportedServiceFamiliesBuilder::new(self.supported_services);
        services_builder.serialize(bv);

        for dib in self.additional_dibs {
            dib.serialize(bv);
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use super::*;
    use crate::messages::knxip::messages::KNXnetIPServiceFamily;
    use crate::util::packets::{ParseBuffer, SerializeBuffer};

    #[test]
    fn test_search_request_parse() {
        let data = [
            0x06, 0x10, 0x02, 0x01, 0x00, 0x0e, // SEARCH_REQUEST header
            0x08, 0x01, 0x12, 0x23, 0x34, 0x45, 0x13, 0x37, // HPAI (IPv4 UDP)
        ];

        let mut buffer = &data[..];
        let parsed = buffer.parse::<SearchRequest>().unwrap();

        assert_eq!(parsed.discovery_endpoint.protocol_code(), HostProtocolCode::IPv4UDP);
        assert_eq!(parsed.discovery_endpoint.address(), Ipv4Addr::new(0x12, 0x23, 0x34, 0x45));
        assert_eq!(parsed.discovery_endpoint.port(), 0x1337);
    }

    #[test]
    fn test_search_request_serialize() {
        let builder = SearchRequestBuilder::new(HPAI::ipv4_udp(Ipv4Addr::new(0x12, 0x23, 0x34, 0x45), 0x1337));

        let mut buffer = [0u8; 14];
        let mut cursor = &mut buffer[..];
        let (written, _remaining) = cursor.serialize(&builder);

        let expected = [
            0x06, 0x10, 0x02, 0x01, 0x00, 0x0e, // SEARCH_REQUEST header
            0x08, 0x01, 0x12, 0x23, 0x34, 0x45, 0x13, 0x37, // HPAI
        ];

        assert_eq!(written, &expected[..]);
    }

    #[test]
    fn test_search_request_round_trip() {
        let original = SearchRequest { discovery_endpoint: HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671) };

        // Serialize using builder (manually construct to avoid allocation)
        let builder = SearchRequestBuilder::new(original.discovery_endpoint.clone());
        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<SearchRequest>().unwrap();

        // Compare
        assert_eq!(parsed.discovery_endpoint.protocol_code(), original.discovery_endpoint.protocol_code());
        assert_eq!(parsed.discovery_endpoint.address(), original.discovery_endpoint.address());
        assert_eq!(parsed.discovery_endpoint.port(), original.discovery_endpoint.port());
    }

    #[test]
    fn test_description_request_parse() {
        let data = [
            0x06, 0x10, 0x02, 0x03, 0x00, 0x0e, // DESCRIPTION_REQUEST header
            0x08, 0x01, 0xc0, 0xa8, 0x01, 0x64, 0x0e, 0x57, // HPAI (192.168.1.100:3671)
        ];

        let mut buffer = &data[..];
        let parsed = buffer.parse::<DescriptionRequest>().unwrap();

        assert_eq!(parsed.control_endpoint.address(), Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(parsed.control_endpoint.port(), 3671);
    }

    #[test]
    fn test_description_request_serialize() {
        let builder = DescriptionRequestBuilder::new(HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671));

        let mut buffer = [0u8; 14];
        let mut cursor = &mut buffer[..];
        let (written, _remaining) = cursor.serialize(&builder);

        let expected = [
            0x06, 0x10, 0x02, 0x03, 0x00, 0x0e, // DESCRIPTION_REQUEST header
            0x08, 0x01, 0xc0, 0xa8, 0x01, 0x64, 0x0e, 0x57, // HPAI
        ];

        assert_eq!(written, &expected[..]);
    }

    #[test]
    fn test_search_response_builder() {
        use crate::messages::knxip::substructs::*;
        use platform::address::EthernetAddress;

        let control_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671);

        let device_hardware = DeviceInformation {
            medium: KNXMedium::TP1,
            device_status: DeviceStatus::None,
            individual_address: crate::address::IndividualAddress::new(1, 2, 52),
            project_installation_identifier: 0x5678,
            knx_serial_number: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            routing_multicast_address: Ipv4Addr::new(224, 0, 23, 12),
            mac_address: EthernetAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            friendly_name: *b"Test Device\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        };

        let services = [
            SupportedService { family: ServiceFamily::Core, version: 1 },
            SupportedService { family: ServiceFamily::DeviceManagement, version: 1 },
            SupportedService { family: ServiceFamily::Tunneling, version: 1 },
        ];

        let builder = SearchResponseBuilder::new(control_endpoint, device_hardware, &services);

        // Serialize
        let mut buffer = [0u8; 128];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse back
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<SearchResponse<_>>().unwrap();

        // Verify
        assert_eq!(parsed.control_endpoint.address(), control_endpoint.address());
        assert_eq!(parsed.control_endpoint.port(), control_endpoint.port());
        assert_eq!(parsed.device_hardware.individual_address, device_hardware.individual_address);
        assert_eq!(parsed.supported_services.iter().count(), 3);
    }

    #[test]
    fn test_description_response_builder() {
        use crate::messages::knxip::substructs::*;
        use platform::address::EthernetAddress;

        let device_hardware = DeviceInformation {
            medium: KNXMedium::TP1,
            device_status: DeviceStatus::None,
            individual_address: crate::address::IndividualAddress::new(1, 2, 52),
            project_installation_identifier: 0x5678,
            knx_serial_number: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            routing_multicast_address: Ipv4Addr::new(224, 0, 23, 12),
            mac_address: EthernetAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            friendly_name: *b"Test Device\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        };

        let services = [SupportedService { family: ServiceFamily::Core, version: 1 }, SupportedService {
            family: ServiceFamily::DeviceManagement,
            version: 2,
        }];

        let builder = DescriptionResponseBuilder::new(device_hardware, &services);

        // Serialize
        let mut buffer = [0u8; 128];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse back
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<DescriptionResponse<_>>().unwrap();

        // Verify
        assert_eq!(parsed.device_hardware.individual_address, device_hardware.individual_address);
        assert_eq!(parsed.device_hardware.medium, device_hardware.medium);
        assert_eq!(parsed.supported_services.iter().count(), 2);
    }

    #[test]
    fn test_search_request_extended_round_trip() {
        use crate::messages::knxip::substructs::*;
        use platform::address::EthernetAddress;

        let discovery_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671);

        // Create SRPs using builders
        let mac_addr = EthernetAddress([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
        let srps = [
            SearchRequestParameterBuilder::select_by_programming_mode(),
            SearchRequestParameterBuilder::select_by_mac_address(mac_addr),
            SearchRequestParameterBuilder::select_by_service(0x02, 0x01),
            SearchRequestParameterBuilder::request_dibs(&[
                KNXnetIPServiceFamily::DeviceInfo,
                KNXnetIPServiceFamily::SupportedServiceFamilies,
            ]),
        ];

        let builder = SearchRequestExtendedBuilder::new(discovery_endpoint, &srps);

        // Serialize
        let mut buffer = [0u8; 256];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse back
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<SearchRequestExtended<_>>().unwrap();

        // Verify
        assert_eq!(parsed.discovery_endpoint.address(), discovery_endpoint.address());
        assert_eq!(parsed.discovery_endpoint.port(), discovery_endpoint.port());
        assert_eq!(parsed.search_request_parameters.len(), 4);

        // Check first SRP (SelectByProgrammingMode)
        assert!(matches!(parsed.search_request_parameters[0], SearchRequestParameter::SelectByProgrammingMode));

        // Check second SRP (SelectByMacAddress)
        match &parsed.search_request_parameters[1] {
            SearchRequestParameter::SelectByMacAddress { mac_address } => {
                assert_eq!(*mac_address, mac_addr);
            }
            _ => panic!("Expected SelectByMacAddress"),
        }

        // Check third SRP (SelectByService)
        match &parsed.search_request_parameters[2] {
            SearchRequestParameter::SelectByService { service_family, version } => {
                assert_eq!(*service_family, 0x02);
                assert_eq!(*version, 0x01);
            }
            _ => panic!("Expected SelectByService"),
        }

        // Check fourth SRP (RequestDIBs)
        match &parsed.search_request_parameters[3] {
            SearchRequestParameter::RequestDIBs { selectors } => {
                let dibs: Vec<_> = selectors.iter().collect();
                assert_eq!(dibs.len(), 2);
                assert_eq!(dibs[0], KNXnetIPServiceFamily::DeviceInfo);
                assert_eq!(dibs[1], KNXnetIPServiceFamily::SupportedServiceFamilies);
            }
            _ => panic!("Expected RequestDIBs"),
        }
    }

    #[test]
    fn test_search_response_extended_round_trip() {
        use crate::messages::knxip::substructs::*;
        use platform::address::EthernetAddress;

        let control_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671);

        let device_hardware = DeviceInformation {
            medium: KNXMedium::TP1,
            device_status: DeviceStatus::None,
            individual_address: crate::address::IndividualAddress::new(1, 2, 52),
            project_installation_identifier: 0x5678,
            knx_serial_number: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            routing_multicast_address: Ipv4Addr::new(224, 0, 23, 12),
            mac_address: EthernetAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            friendly_name: *b"Test Device\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        };

        let services = [
            SupportedService { family: ServiceFamily::Core, version: 1 },
            SupportedService { family: ServiceFamily::DeviceManagement, version: 1 },
            SupportedService { family: ServiceFamily::Tunneling, version: 1 },
        ];

        let ip_config = IpConfig {
            ip_address: "192.168.1.100".parse().unwrap(),
            subnet_mask: "255.255.255.0".parse().unwrap(),
            default_gateway: "192.168.1.1".parse().unwrap(),
            ip_capabilities: 0x0F,
            ip_assignment_method: 0x01,
        };

        let dibs = [
            DescriptionInformationBlockBuilder::DeviceInformation(&device_hardware),
            DescriptionInformationBlockBuilder::SupportedServiceFamilies(SupportedServiceFamiliesBuilder::new(
                &services,
            )),
            DescriptionInformationBlockBuilder::IpConfig(&ip_config),
        ];

        let builder = SearchResponseExtendedBuilder::new(control_endpoint, &dibs);

        // Serialize
        let mut buffer = [0u8; 256];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse back
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<SearchResponseExtended<_>>().unwrap();

        // Verify
        assert_eq!(parsed.control_endpoint.address(), control_endpoint.address());
        assert_eq!(parsed.control_endpoint.port(), control_endpoint.port());

        let dibs: Vec<_> = parsed.description_information_blocks.iter().collect();
        assert_eq!(dibs.len(), 3);

        // Check first DIB (DeviceInformation)
        match &dibs[0] {
            DescriptionInformationBlock::DeviceInformation(info) => {
                assert_eq!(info.individual_address, device_hardware.individual_address);
                assert_eq!(info.medium, device_hardware.medium);
            }
            _ => panic!("Expected DeviceInformation"),
        }

        // Check second DIB (SupportedServiceFamilies)
        match &dibs[1] {
            DescriptionInformationBlock::SupportedServiceFamilies(families) => {
                assert_eq!(families.iter().count(), 3);
            }
            _ => panic!("Expected SupportedServiceFamilies"),
        }

        // Check third DIB (IpConfig)
        match &dibs[2] {
            DescriptionInformationBlock::IpConfig(config) => {
                assert_eq!(config.ip_address, ip_config.ip_address);
                assert_eq!(config.subnet_mask, ip_config.subnet_mask);
            }
            _ => panic!("Expected IpConfig"),
        }
    }
}
