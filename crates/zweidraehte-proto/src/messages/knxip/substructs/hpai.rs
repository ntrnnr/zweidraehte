use core::{mem, net::Ipv4Addr};

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Ref, SplitByteSlice, SplitByteSliceMut, Unaligned, big_endian::U16,
};

use crate::messages::knxip::error::{ParseError, ParseResult};
use crate::util::packets::{BufferView, BufferViewMut, ParsablePacket, SerializablePacket};

// ============================================================================
// INTERNAL WIRE FORMAT - ZEROCOPY TYPES
// ============================================================================

mod raw {
    use super::*;

    /// Wire format for HPAI header (2 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct HPAIHeader {
        pub struct_len: u8,
        pub host_protocol_code: u8,
    }

    /// Wire format for IPv4 UDP endpoint (6 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct IPv4UDP {
        pub address: [u8; 4],
        pub port: U16,
    }

    /// Wire format for IPv4 TCP endpoint (6 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct IPv4TCP {
        pub address: [u8; 4],
        pub port: U16,
    }
}

// ============================================================================
// PROTOCOL ENUMS
// ============================================================================

create_protocol_enum!(
    #[allow(missing_docs)]
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum HostProtocolCode: u8 {
        IPv4UDP, 0x01, "IPv4 UDP";
        IPv4TCP, 0x02, "IPv4 TCP";
    }
);

// ============================================================================
// PUBLIC API - OWNED TYPES
// ============================================================================

/// Host Protocol Address Information
///
/// Represents a network endpoint for KNX/IP communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HPAI {
    /// IPv4 UDP endpoint
    Ipv4Udp { addr: Ipv4Addr, port: u16 },
    /// IPv4 TCP endpoint
    Ipv4Tcp { addr: Ipv4Addr, port: u16 },
}

impl HPAI {
    /// Get the protocol code for this endpoint
    pub fn protocol_code(&self) -> HostProtocolCode {
        match self {
            Self::Ipv4Udp { .. } => HostProtocolCode::IPv4UDP,
            Self::Ipv4Tcp { .. } => HostProtocolCode::IPv4TCP,
        }
    }

    /// Get the address (works for both UDP and TCP)
    pub fn address(&self) -> Ipv4Addr {
        match self {
            Self::Ipv4Udp { addr, .. } | Self::Ipv4Tcp { addr, .. } => *addr,
        }
    }

    /// Get the port (works for both UDP and TCP)
    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4Udp { port, .. } | Self::Ipv4Tcp { port, .. } => *port,
        }
    }

    /// Create a new IPv4 UDP endpoint
    pub const fn ipv4_udp(addr: Ipv4Addr, port: u16) -> Self {
        Self::Ipv4Udp { addr, port }
    }

    /// Create a new IPv4 TCP endpoint
    pub const fn ipv4_tcp(addr: Ipv4Addr, port: u16) -> Self {
        Self::Ipv4Tcp { addr, port }
    }
}

// ============================================================================
// PARSING: zerocopy wire format -> owned
// ============================================================================

impl<B: SplitByteSlice> ParsablePacket<B, ()> for HPAI {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> ParseResult<Self> {
        // Parse header
        let header = buffer.take_obj_front::<raw::HPAIHeader>().ok_or_else(|| {
            debug!("too few bytes for HPAI header");
            ParseError::Format
        })?;

        // Match on protocol code and parse body
        let protocol = HostProtocolCode::try_from(header.host_protocol_code).map_err(|_| {
            debug!("unrecognized HPAI host protocol code: {:x}", header.host_protocol_code);
            ParseError::NotSupported
        })?;

        match protocol {
            HostProtocolCode::IPv4UDP => {
                // Parse with zerocopy
                let body = buffer.take_obj_front::<raw::IPv4UDP>().ok_or_else(|| {
                    debug!("too few bytes for IPv4 UDP HPAI body");
                    ParseError::Format
                })?;

                // Convert to owned (copies 6 bytes: 4 for IP + 2 for port)
                Ok(Self::Ipv4Udp { addr: Ipv4Addr::from(body.address), port: body.port.get() })
            }
            HostProtocolCode::IPv4TCP => {
                let body = buffer.take_obj_front::<raw::IPv4TCP>().ok_or_else(|| {
                    debug!("too few bytes for IPv4 TCP HPAI body");
                    ParseError::Format
                })?;

                Ok(Self::Ipv4Tcp { addr: Ipv4Addr::from(body.address), port: body.port.get() })
            }
        }
    }
}

// ============================================================================
// SERIALIZATION: owned -> zerocopy wire format
// ============================================================================

impl SerializablePacket for HPAI {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::HPAIHeader>()
            + match self {
                Self::Ipv4Udp { .. } => mem::size_of::<raw::IPv4UDP>(),
                Self::Ipv4Tcp { .. } => mem::size_of::<raw::IPv4TCP>(),
            }
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        // Write header using zerocopy
        let mut header = bv.take_obj_front_zero::<raw::HPAIHeader>().expect("too few bytes for HPAI header");
        header.struct_len = self.bytes_len() as u8;
        header.host_protocol_code = self.protocol_code().into();

        // Write body using zerocopy
        match self {
            Self::Ipv4Udp { addr, port } => {
                let mut body = bv.take_obj_front_zero::<raw::IPv4UDP>().expect("too few bytes for HPAI body");
                body.address = addr.octets();
                body.port = U16::new(*port);
            }
            Self::Ipv4Tcp { addr, port } => {
                let mut body = bv.take_obj_front_zero::<raw::IPv4TCP>().expect("too few bytes for HPAI body");
                body.address = addr.octets();
                body.port = U16::new(*port);
            }
        }
    }
}

// ============================================================================
// HELPER FUNCTIONS (can peek at raw format without full parse)
// ============================================================================

/// Peek at an HPAI header to see what host protocol code is present.
///
/// This is useful when you need to determine the protocol type before
/// doing a full parse.
pub fn peek_host_protocol_code(bytes: &[u8]) -> ParseResult<HostProtocolCode> {
    let (header, _) = Ref::<_, raw::HPAIHeader>::from_prefix(bytes).map_err(|_| {
        debug!("too few bytes for HPAI header");
        ParseError::Format
    })?;

    HostProtocolCode::try_from(header.host_protocol_code).map_err(|_| {
        debug!("unrecognized HPAI host protocol code: {:x}", header.host_protocol_code);
        ParseError::NotSupported
    })
}

/// Peek at the structure length field in the HPAI header.
pub fn peek_hpai_structure_length(bytes: &[u8]) -> ParseResult<u8> {
    let (header, _) = Ref::<_, raw::HPAIHeader>::from_prefix(bytes).map_err(|_| {
        debug!("too few bytes for HPAI header");
        ParseError::Format
    })?;

    Ok(header.struct_len)
}

#[cfg(test)]
mod test {
    use core::net::Ipv4Addr;

    use super::{HPAI, HostProtocolCode, ParseError, peek_host_protocol_code, peek_hpai_structure_length};
    use crate::util::packets::{ParseBuffer, SerializeBuffer};

    #[test]
    fn test_parse_ipv4_udp() {
        let data = [
            0x08, 0x01, // header: length=8, protocol=IPv4UDP
            0x12, 0x23, 0x45, 0x68, // address
            0x13, 0x37, // port
        ];

        let mut slice = &data[..];
        let endpoint: HPAI = slice.parse().unwrap();
        match endpoint {
            HPAI::Ipv4Udp { addr, port } => {
                assert_eq!(addr, Ipv4Addr::new(0x12, 0x23, 0x45, 0x68));
                assert_eq!(port, 0x1337);
            }
            _ => panic!("Wrong endpoint type"),
        }
    }

    #[test]
    fn test_parse_ipv4_tcp() {
        let data = [
            0x08, 0x02, // header: length=8, protocol=IPv4TCP
            0xC0, 0xA8, 0x01, 0x01, // 192.168.1.1
            0x0E, 0x57, // port 3671
        ];

        let mut slice = &data[..];
        let endpoint: HPAI = slice.parse().unwrap();
        match endpoint {
            HPAI::Ipv4Tcp { addr, port } => {
                assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(port, 3671);
            }
            _ => panic!("Wrong endpoint type"),
        }
    }

    #[test]
    fn test_parse_too_short() {
        let data = [0x08, 0x01, 0x12]; // Too short
        let mut slice = &data[..];
        assert_eq!(slice.parse::<HPAI>().unwrap_err(), ParseError::Format);
    }

    #[test]
    fn test_parse_invalid_protocol() {
        let data = [
            0x08, 0xFF, // Invalid protocol code
            0x12, 0x23, 0x45, 0x68, 0x13, 0x37,
        ];
        let mut slice = &data[..];
        assert_eq!(slice.parse::<HPAI>().unwrap_err(), ParseError::NotSupported);
    }

    #[test]
    fn test_peek_protocol_code() {
        let data = [0x08, 0x01, 0x12, 0x23, 0x45, 0x68, 0x13, 0x37];
        assert_eq!(peek_host_protocol_code(&data).unwrap(), HostProtocolCode::IPv4UDP);

        let data_tcp = [0x08, 0x02, 0x12, 0x23, 0x45, 0x68, 0x13, 0x37];
        assert_eq!(peek_host_protocol_code(&data_tcp).unwrap(), HostProtocolCode::IPv4TCP);
    }

    #[test]
    fn test_peek_structure_length() {
        let data = [0x08, 0x01, 0x12, 0x23, 0x45, 0x68, 0x13, 0x37];
        assert_eq!(peek_hpai_structure_length(&data).unwrap(), 8);
    }

    #[test]
    fn test_serialize_ipv4_udp() {
        let endpoint = HPAI::Ipv4Udp { addr: Ipv4Addr::new(0x12, 0x23, 0x45, 0x68), port: 0x1337 };

        let mut buffer = [0u8; 8];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&endpoint);

        assert_eq!(written.len(), 8);
        assert_eq!(written, &[
            0x08, 0x01, // header
            0x12, 0x23, 0x45, 0x68, // address
            0x13, 0x37, // port
        ]);
    }

    #[test]
    fn test_serialize_ipv4_tcp() {
        let endpoint = HPAI::Ipv4Tcp { addr: Ipv4Addr::new(192, 168, 1, 1), port: 3671 };

        let mut buffer = [0u8; 8];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&endpoint);

        assert_eq!(written.len(), 8);
        assert_eq!(written, &[
            0x08, 0x02, // header
            0xC0, 0xA8, 0x01, 0x01, // 192.168.1.1
            0x0E, 0x57, // port 3671
        ]);
    }

    #[test]
    fn test_round_trip() {
        let original = HPAI::Ipv4Udp { addr: Ipv4Addr::new(10, 0, 1, 42), port: 12345 };

        // Serialize
        let mut buffer = [0u8; 8];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&original);

        // Parse back
        let mut slice = &written[..];
        let parsed: HPAI = slice.parse().unwrap();

        assert_eq!(parsed, original);
    }

    #[test]
    fn test_endpoint_methods() {
        let endpoint = HPAI::Ipv4Udp { addr: Ipv4Addr::new(1, 2, 3, 4), port: 5678 };

        assert_eq!(endpoint.address(), Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(endpoint.port(), 5678);
        assert_eq!(endpoint.protocol_code(), HostProtocolCode::IPv4UDP);

        let endpoint_tcp = HPAI::Ipv4Tcp { addr: Ipv4Addr::new(5, 6, 7, 8), port: 9012 };

        assert_eq!(endpoint_tcp.address(), Ipv4Addr::new(5, 6, 7, 8));
        assert_eq!(endpoint_tcp.port(), 9012);
        assert_eq!(endpoint_tcp.protocol_code(), HostProtocolCode::IPv4TCP);
    }

    #[test]
    fn test_endpoint_constructors() {
        let udp = HPAI::ipv4_udp(Ipv4Addr::new(1, 2, 3, 4), 5678);
        match udp {
            HPAI::Ipv4Udp { addr, port } => {
                assert_eq!(addr, Ipv4Addr::new(1, 2, 3, 4));
                assert_eq!(port, 5678);
            }
            _ => panic!("Wrong type"),
        }

        let tcp = HPAI::ipv4_tcp(Ipv4Addr::new(5, 6, 7, 8), 9012);
        match tcp {
            HPAI::Ipv4Tcp { addr, port } => {
                assert_eq!(addr, Ipv4Addr::new(5, 6, 7, 8));
                assert_eq!(port, 9012);
            }
            _ => panic!("Wrong type"),
        }
    }
}
