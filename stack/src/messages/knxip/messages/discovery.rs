//! KNX/IP Discovery Messages (SEARCH_REQUEST, SEARCH_RESPONSE, DESCRIPTION_REQUEST, DESCRIPTION_RESPONSE)

use core::mem;

use zerocopy::{SplitByteSlice, SplitByteSliceMut, big_endian::U16};

use crate::{messages::knxip::error::*, util::packets::*};

use super::{super::substructs::*, KNXnetIPServiceType, KNXnetIPVersion, raw};

// ============================================================================
// SEARCH REQUEST
// ============================================================================

/// KNXnet/IP SEARCH_REQUEST
///
/// Used to discover KNXnet/IP servers on the network
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    pub discovery_endpoint: Endpoint,
}

impl SearchRequest {
    /// Create a new SEARCH_REQUEST with the given discovery endpoint
    pub fn new(discovery_endpoint: Endpoint) -> Self {
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
        let discovery_endpoint = Endpoint::parse(buffer, ())?;

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
    pub discovery_endpoint: Endpoint,
}

impl SearchRequestBuilder {
    pub fn new(discovery_endpoint: Endpoint) -> Self {
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
// SEARCH RESPONSE
// ============================================================================

/// KNXnet/IP SEARCH_RESPONSE
///
/// Response to a SEARCH_REQUEST containing device information
#[derive(Debug)]
pub struct SearchResponse<B: SplitByteSlice> {
    pub control_endpoint: Endpoint,
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
        let control_endpoint = Endpoint::parse(buffer, ())?;

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
    pub control_endpoint: Endpoint,
    pub device_hardware: DeviceInformation,
    pub supported_services: &'a [SupportedService],
}

impl<'a> SearchResponseBuilder<'a> {
    pub fn new(
        control_endpoint: Endpoint,
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
// DESCRIPTION REQUEST
// ============================================================================

/// KNXnet/IP DESCRIPTION_REQUEST
///
/// Request for detailed device information from a KNXnet/IP server
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptionRequest {
    pub control_endpoint: Endpoint,
}

impl DescriptionRequest {
    /// Create a new DESCRIPTION_REQUEST with the given control endpoint
    pub fn new(control_endpoint: Endpoint) -> Self {
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
        let control_endpoint = Endpoint::parse(buffer, ())?;

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
    pub control_endpoint: Endpoint,
}

impl DescriptionRequestBuilder {
    pub fn new(control_endpoint: Endpoint) -> Self {
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
/// we need a builder to serialize it properly.
pub struct DescriptionResponseBuilder<'a> {
    pub device_hardware: DeviceInformation,
    pub supported_services: &'a [SupportedService],
}

impl<'a> DescriptionResponseBuilder<'a> {
    pub fn new(device_hardware: DeviceInformation, supported_services: &'a [SupportedService]) -> Self {
        Self { device_hardware, supported_services }
    }
}

impl<'a> SerializablePacket for DescriptionResponseBuilder<'a> {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::KNXnetIPHeader>()
            + self.device_hardware.bytes_len()
            + SupportedServiceFamiliesBuilder::new(self.supported_services).bytes_len()
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
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use super::*;
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
        let builder = SearchRequestBuilder::new(Endpoint::ipv4_udp(Ipv4Addr::new(0x12, 0x23, 0x34, 0x45), 0x1337));

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
        let original = SearchRequest { discovery_endpoint: Endpoint::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671) };

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
        let builder = DescriptionRequestBuilder::new(Endpoint::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671));

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

        let control_endpoint = Endpoint::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671);

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
}
