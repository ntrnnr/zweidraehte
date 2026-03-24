//! KNX USB Transfer Protocol encoding/decoding
//!
//! This module implements the KNX USB Transfer Protocol layer, which sits
//! between HID reports and the EMI frames (cEMI in our case).
//!
//! The protocol header is 8 bytes and only appears in the start packet.

/// Protocol version (always 0 per spec)
pub const PROTOCOL_VERSION: u8 = 0x00;

/// Header length (always 8 per spec)
pub const HEADER_LENGTH: u8 = 0x08;

/// Protocol IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolId {
    /// Reserved
    Reserved = 0x00,
    /// KNX Tunnel (main data transfer)
    KnxTunnel = 0x01,
    /// M-Bus Tunnel
    MBusTunnel = 0x02,
    /// BatiBus Tunnel
    BatiBusTunnel = 0x03,
    /// Bus Access Server Feature Service
    BusAccessServer = 0x0F,
}

impl ProtocolId {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Reserved),
            0x01 => Some(Self::KnxTunnel),
            0x02 => Some(Self::MBusTunnel),
            0x03 => Some(Self::BatiBusTunnel),
            0x0F => Some(Self::BusAccessServer),
            _ => None,
        }
    }
}

/// EMI format IDs (for KNX Tunnel protocol)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EmiId {
    /// Reserved
    Reserved = 0x00,
    /// EMI1 format
    Emi1 = 0x01,
    /// EMI2 format
    Emi2 = 0x02,
    /// Common EMI (cEMI) format
    CEmi = 0x03,
}

impl EmiId {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Reserved),
            0x01 => Some(Self::Emi1),
            0x02 => Some(Self::Emi2),
            0x03 => Some(Self::CEmi),
            _ => None,
        }
    }
}

/// KNX USB Transfer Protocol Header (8 bytes)
#[derive(Debug, Clone, Copy)]
pub struct TransferHeader {
    /// Protocol version (always 0)
    pub protocol_version: u8,
    /// Header length (always 8)
    pub header_length: u8,
    /// Body length (EMI frame length)
    pub body_length: u16,
    /// Protocol ID
    pub protocol_id: ProtocolId,
    /// EMI ID (for KNX Tunnel) or feature service type (for Bus Access Server)
    pub emi_id_or_service: u8,
    /// Manufacturer code (0x0000 for standard)
    pub manufacturer_code: u16,
}

impl TransferHeader {
    /// Header size in bytes
    pub const SIZE: usize = 8;

    /// Create a new header for KNX Tunnel with cEMI
    pub fn new_knx_tunnel_cemi(body_length: u16) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            header_length: HEADER_LENGTH,
            body_length,
            protocol_id: ProtocolId::KnxTunnel,
            emi_id_or_service: EmiId::CEmi as u8,
            manufacturer_code: 0x0000,
        }
    }

    /// Create a new header for Bus Access Server
    pub fn new_bus_access_server(service_type: u8, body_length: u16) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            header_length: HEADER_LENGTH,
            body_length,
            protocol_id: ProtocolId::BusAccessServer,
            emi_id_or_service: service_type,
            manufacturer_code: 0x0000,
        }
    }

    /// Parse header from bytes
    pub fn parse(data: &[u8]) -> Result<Self, TransferProtocolError> {
        if data.len() < Self::SIZE {
            return Err(TransferProtocolError::HeaderTooShort);
        }

        let protocol_version = data[0];
        if protocol_version != PROTOCOL_VERSION {
            return Err(TransferProtocolError::UnsupportedVersion(protocol_version));
        }

        let header_length = data[1];
        if header_length != HEADER_LENGTH {
            return Err(TransferProtocolError::InvalidHeaderLength(header_length));
        }

        let body_length = u16::from_be_bytes([data[2], data[3]]);

        let protocol_id = ProtocolId::from_byte(data[4])
            .ok_or(TransferProtocolError::UnknownProtocolId(data[4]))?;

        let emi_id_or_service = data[5];

        // Validate EMI ID for KNX Tunnel
        if protocol_id == ProtocolId::KnxTunnel
            && (EmiId::from_byte(emi_id_or_service).is_none() || emi_id_or_service == 0)
        {
            return Err(TransferProtocolError::UnknownEmiId(emi_id_or_service));
        }

        let manufacturer_code = u16::from_be_bytes([data[6], data[7]]);

        Ok(Self {
            protocol_version,
            header_length,
            body_length,
            protocol_id,
            emi_id_or_service,
            manufacturer_code,
        })
    }

    /// Encode header to bytes
    pub fn encode(&self) -> [u8; Self::SIZE] {
        let body_len_bytes = self.body_length.to_be_bytes();
        let manufacturer_bytes = self.manufacturer_code.to_be_bytes();

        [
            self.protocol_version,
            self.header_length,
            body_len_bytes[0],
            body_len_bytes[1],
            self.protocol_id as u8,
            self.emi_id_or_service,
            manufacturer_bytes[0],
            manufacturer_bytes[1],
        ]
    }

    /// Get the EMI ID (only valid for KNX Tunnel protocol)
    pub fn emi_id(&self) -> Option<EmiId> {
        if self.protocol_id == ProtocolId::KnxTunnel {
            EmiId::from_byte(self.emi_id_or_service)
        } else {
            None
        }
    }
}

/// Error parsing transfer protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferProtocolError {
    /// Header too short
    HeaderTooShort,
    /// Unsupported protocol version
    UnsupportedVersion(u8),
    /// Invalid header length (must be 8)
    InvalidHeaderLength(u8),
    /// Unknown protocol ID
    UnknownProtocolId(u8),
    /// Unknown EMI ID
    UnknownEmiId(u8),
    /// Body length mismatch
    BodyLengthMismatch { expected: u16, actual: usize },
    /// Unsupported EMI format (we only support cEMI)
    UnsupportedEmiFormat(EmiId),
}

/// A complete KNX USB Transfer frame (header + body)
#[derive(Debug)]
pub struct TransferFrame<'a> {
    pub header: TransferHeader,
    pub body: &'a [u8],
}

impl<'a> TransferFrame<'a> {
    /// Parse a complete transfer frame from reassembled HID data
    pub fn parse(data: &'a [u8]) -> Result<Self, TransferProtocolError> {
        let header = TransferHeader::parse(data)?;

        let body_start = TransferHeader::SIZE;
        let body_end = body_start + header.body_length as usize;

        if data.len() < body_end {
            return Err(TransferProtocolError::BodyLengthMismatch {
                expected: header.body_length,
                actual: data.len() - body_start,
            });
        }

        Ok(Self {
            header,
            body: &data[body_start..body_end],
        })
    }

    /// Check if this is a KNX Tunnel frame with cEMI
    pub fn is_cemi_tunnel(&self) -> bool {
        self.header.protocol_id == ProtocolId::KnxTunnel
            && self.header.emi_id() == Some(EmiId::CEmi)
    }

    /// Check if this is a Bus Access Server frame
    pub fn is_bus_access_server(&self) -> bool {
        self.header.protocol_id == ProtocolId::BusAccessServer
    }

    /// Get the cEMI message code (first byte of body for KNX Tunnel)
    pub fn cemi_message_code(&self) -> Option<u8> {
        if self.is_cemi_tunnel() && !self.body.is_empty() {
            Some(self.body[0])
        } else {
            None
        }
    }
}

/// Encode a cEMI frame into KNX USB Transfer Protocol format
///
/// Returns a buffer containing the 8-byte header followed by the cEMI data.
pub fn encode_cemi_frame(cemi_data: &[u8], output: &mut [u8]) -> Result<usize, TransferProtocolError> {
    let total_len = TransferHeader::SIZE + cemi_data.len();
    if output.len() < total_len {
        return Err(TransferProtocolError::BodyLengthMismatch {
            expected: total_len as u16,
            actual: output.len(),
        });
    }

    let header = TransferHeader::new_knx_tunnel_cemi(cemi_data.len() as u16);
    output[..TransferHeader::SIZE].copy_from_slice(&header.encode());
    output[TransferHeader::SIZE..total_len].copy_from_slice(cemi_data);

    Ok(total_len)
}

/// Encode a Bus Access Server frame
pub fn encode_bus_access_frame(
    service_type: u8,
    data: &[u8],
    output: &mut [u8],
) -> Result<usize, TransferProtocolError> {
    let total_len = TransferHeader::SIZE + data.len();
    if output.len() < total_len {
        return Err(TransferProtocolError::BodyLengthMismatch {
            expected: total_len as u16,
            actual: output.len(),
        });
    }

    let header = TransferHeader::new_bus_access_server(service_type, data.len() as u16);
    output[..TransferHeader::SIZE].copy_from_slice(&header.encode());
    output[TransferHeader::SIZE..total_len].copy_from_slice(data);

    Ok(total_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode() {
        let header = TransferHeader::new_knx_tunnel_cemi(26);
        let encoded = header.encode();

        assert_eq!(encoded[0], 0x00); // protocol version
        assert_eq!(encoded[1], 0x08); // header length
        assert_eq!(encoded[2], 0x00); // body length high
        assert_eq!(encoded[3], 26);   // body length low
        assert_eq!(encoded[4], 0x01); // protocol ID (KNX Tunnel)
        assert_eq!(encoded[5], 0x03); // EMI ID (cEMI)
        assert_eq!(encoded[6], 0x00); // manufacturer code high
        assert_eq!(encoded[7], 0x00); // manufacturer code low

        let parsed = TransferHeader::parse(&encoded).unwrap();
        assert_eq!(parsed.protocol_id, ProtocolId::KnxTunnel);
        assert_eq!(parsed.emi_id(), Some(EmiId::CEmi));
        assert_eq!(parsed.body_length, 26);
    }

    #[test]
    fn test_bus_access_header() {
        let header = TransferHeader::new_bus_access_server(0x01, 2);
        let encoded = header.encode();

        assert_eq!(encoded[4], 0x0F); // protocol ID (Bus Access Server)
        assert_eq!(encoded[5], 0x01); // service type
    }

    #[test]
    fn test_encode_cemi_frame() {
        let cemi = [0x11, 0x00, 0xBC, 0xE0, 0x10, 0x01, 0x08, 0x01, 0x01, 0x00, 0x80];
        let mut output = [0u8; 64];

        let len = encode_cemi_frame(&cemi, &mut output).unwrap();
        assert_eq!(len, 8 + 11);

        let frame = TransferFrame::parse(&output[..len]).unwrap();
        assert!(frame.is_cemi_tunnel());
        assert_eq!(frame.body, &cemi);
        assert_eq!(frame.cemi_message_code(), Some(0x11)); // L_Data.req
    }

    #[test]
    fn test_parse_invalid_header() {
        // Too short
        assert!(TransferHeader::parse(&[0, 1, 2]).is_err());

        // Wrong version
        let mut data = [0u8; 8];
        data[0] = 0x01; // Wrong version
        data[1] = 0x08;
        assert!(matches!(
            TransferHeader::parse(&data),
            Err(TransferProtocolError::UnsupportedVersion(1))
        ));

        // Wrong header length
        data[0] = 0x00;
        data[1] = 0x10; // Wrong length
        assert!(matches!(
            TransferHeader::parse(&data),
            Err(TransferProtocolError::InvalidHeaderLength(0x10))
        ));
    }
}
