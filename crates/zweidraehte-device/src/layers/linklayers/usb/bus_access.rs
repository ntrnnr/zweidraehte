//! KNX USB Bus Access Server Feature Services
//!
//! This module implements the Bus Access Server Feature Service protocol
//! (Protocol ID 0x0F) for device discovery and configuration per KNX spec.
//!
//! Frame format (per spec Figure 20):
//! - KNX USB Transfer Protocol Header (8 bytes):
//!   - Protocol Version (1 byte): 0x00
//!   - Header Length (1 byte): 0x08
//!   - Body Length (2 bytes): length of Feature Identifier + Feature Data
//!   - Protocol Identifier (1 byte): 0x0F (Bus Access Server)
//!   - Service Identifier (1 byte): 0x01-0x04
//!   - Manufacturer Code (2 bytes): 0x0000
//! - KNX HID Transfer Protocol Body:
//!   - Feature Identifier (1 byte)
//!   - Feature Data (n bytes, depends on feature)

use super::protocol::{EmiId, TransferHeader, encode_bus_access_frame};

/// Device Feature Service Identifiers (placed in header at EMI ID position)
/// Per spec Figure 21
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ServiceId {
    /// Device Feature Get (request from client)
    Get = 0x01,
    /// Device Feature Response (reply from server)
    Response = 0x02,
    /// Device Feature Set (request from client)
    Set = 0x03,
    /// Device Feature Info (unsolicited from server)
    Info = 0x04,
}

impl ServiceId {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Get),
            0x02 => Some(Self::Response),
            0x03 => Some(Self::Set),
            0x04 => Some(Self::Info),
            _ => None,
        }
    }
}

/// Device Feature Identifiers (first byte of body)
/// Per spec Figure 29
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FeatureId {
    /// Supported EMI types (2 bytes, bitmask B16)
    SupportedEmiType = 0x01,
    /// Host Device Descriptor Type 0 (2 bytes, U4U4U4U4)
    DeviceDescriptorType0 = 0x02,
    /// Bus connection status (1 bit, B1)
    BusConnectionStatus = 0x03,
    /// KNX Manufacturer Code (2 bytes, U16)
    KnxManufacturerCode = 0x04,
    /// Active EMI type (1 byte, N8)
    ActiveEmiType = 0x05,
}

impl FeatureId {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::SupportedEmiType),
            0x02 => Some(Self::DeviceDescriptorType0),
            0x03 => Some(Self::BusConnectionStatus),
            0x04 => Some(Self::KnxManufacturerCode),
            0x05 => Some(Self::ActiveEmiType),
            _ => None,
        }
    }
}

/// Supported EMI types bitmask (2 bytes, but only low 3 bits used)
/// Per spec 3.5.3.3.2 - bit 0 = EMI1, bit 1 = EMI2, bit 2 = cEMI
#[derive(Debug, Clone, Copy, Default)]
pub struct SupportedEmiTypes(pub u16);

impl SupportedEmiTypes {
    pub const EMI1_BIT: u16 = 0x0001;
    pub const EMI2_BIT: u16 = 0x0002;
    pub const CEMI_BIT: u16 = 0x0004;

    pub fn supports_emi1(&self) -> bool {
        (self.0 & Self::EMI1_BIT) != 0
    }

    pub fn supports_emi2(&self) -> bool {
        (self.0 & Self::EMI2_BIT) != 0
    }

    pub fn supports_cemi(&self) -> bool {
        (self.0 & Self::CEMI_BIT) != 0
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() >= 2 {
            Some(Self(u16::from_be_bytes([data[0], data[1]])))
        } else if data.len() == 1 {
            // Some devices might only send 1 byte
            Some(Self(data[0] as u16))
        } else {
            None
        }
    }
}

/// Error in Bus Access Server communication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusAccessError {
    /// Frame body too short
    FrameTooShort,
    /// Unknown service ID
    UnknownServiceId(u8),
    /// Unknown feature ID
    UnknownFeatureId(u8),
    /// Output buffer too small
    BufferTooSmall,
    /// Timeout waiting for response
    Timeout,
    /// Device doesn't support cEMI
    CemiNotSupported,
}

/// Helper to build Bus Access Server request frames
///
/// Frame structure:
/// - Header (8 bytes) with Service ID in byte 5
/// - Body: Feature ID (1 byte) + optional Feature Data
pub struct BusAccessFrameBuilder;

impl BusAccessFrameBuilder {
    /// Build a Device Feature Get request
    /// Per spec Figure 22: body contains only Feature Identifier
    pub fn feature_get(feature_id: FeatureId, output: &mut [u8]) -> Result<usize, BusAccessError> {
        let body = [feature_id as u8];
        encode_bus_access_frame(ServiceId::Get as u8, &body, output)
            .map_err(|_| BusAccessError::BufferTooSmall)
    }

    /// Build a Device Feature Set request
    /// Per spec Figure 25: body contains Feature Identifier + Feature Data
    pub fn feature_set(
        feature_id: FeatureId,
        data: &[u8],
        output: &mut [u8],
    ) -> Result<usize, BusAccessError> {
        if output.len() < TransferHeader::SIZE + 1 + data.len() {
            return Err(BusAccessError::BufferTooSmall);
        }

        // Build body: Feature ID + data
        let mut body = [0u8; 64];
        body[0] = feature_id as u8;
        let body_len = 1 + data.len();
        body[1..body_len].copy_from_slice(data);

        encode_bus_access_frame(ServiceId::Set as u8, &body[..body_len], output)
            .map_err(|_| BusAccessError::BufferTooSmall)
    }

    /// Build a GetSupportedEmiType request
    pub fn get_supported_emi_type(output: &mut [u8]) -> Result<usize, BusAccessError> {
        Self::feature_get(FeatureId::SupportedEmiType, output)
    }

    /// Build a GetActiveEmiType request
    pub fn get_active_emi_type(output: &mut [u8]) -> Result<usize, BusAccessError> {
        Self::feature_get(FeatureId::ActiveEmiType, output)
    }

    /// Build a SetActiveEmiType request
    /// Per spec 3.5.3.4.2: coding is same as EMI ID in KNX USB Transfer Protocol Header
    pub fn set_active_emi_type(emi_id: EmiId, output: &mut [u8]) -> Result<usize, BusAccessError> {
        Self::feature_set(FeatureId::ActiveEmiType, &[emi_id as u8], output)
    }

    /// Build a GetBusConnectionStatus request
    pub fn get_bus_connection_status(output: &mut [u8]) -> Result<usize, BusAccessError> {
        Self::feature_get(FeatureId::BusConnectionStatus, output)
    }
}

/// Parse a Bus Access Server response body
/// The body contains: Feature Identifier (1 byte) + Feature Data (n bytes)
pub struct BusAccessResponse<'a> {
    pub feature_id: FeatureId,
    pub data: &'a [u8],
}

impl<'a> BusAccessResponse<'a> {
    /// Parse response body (after header has been stripped)
    pub fn parse(body: &'a [u8]) -> Result<Self, BusAccessError> {
        if body.is_empty() {
            return Err(BusAccessError::FrameTooShort);
        }

        let feature_id =
            FeatureId::from_byte(body[0]).ok_or(BusAccessError::UnknownFeatureId(body[0]))?;

        Ok(Self {
            feature_id,
            data: &body[1..],
        })
    }

    /// Get supported EMI types from response
    pub fn get_supported_emi_types(&self) -> Option<SupportedEmiTypes> {
        if self.feature_id == FeatureId::SupportedEmiType {
            SupportedEmiTypes::from_bytes(self.data)
        } else {
            None
        }
    }

    /// Get active EMI type from response
    pub fn get_active_emi_type(&self) -> Option<EmiId> {
        if self.feature_id == FeatureId::ActiveEmiType && !self.data.is_empty() {
            EmiId::from_byte(self.data[0])
        } else {
            None
        }
    }

    /// Get bus connection status from response
    /// Per spec: 0 = no bus connection, 1 = connected
    pub fn get_bus_connection_status(&self) -> Option<bool> {
        if self.feature_id == FeatureId::BusConnectionStatus && !self.data.is_empty() {
            Some(self.data[0] != 0)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_emi_types() {
        let types = SupportedEmiTypes(0x0007); // All three supported
        assert!(types.supports_emi1());
        assert!(types.supports_emi2());
        assert!(types.supports_cemi());

        let cemi_only = SupportedEmiTypes(0x0004);
        assert!(!cemi_only.supports_emi1());
        assert!(!cemi_only.supports_emi2());
        assert!(cemi_only.supports_cemi());
    }

    #[test]
    fn test_build_get_request() {
        let mut buf = [0u8; 64];
        let len = BusAccessFrameBuilder::get_supported_emi_type(&mut buf).unwrap();

        // Header (8 bytes) + body (1 byte Feature ID) = 9 bytes
        assert_eq!(len, 9);

        // Check header
        assert_eq!(buf[0], 0x00); // Protocol version
        assert_eq!(buf[1], 0x08); // Header length
        assert_eq!(buf[2], 0x00); // Body length high
        assert_eq!(buf[3], 0x01); // Body length low (1 byte)
        assert_eq!(buf[4], 0x0F); // Protocol ID (Bus Access Server)
        assert_eq!(buf[5], 0x01); // Service ID (Get)
        assert_eq!(buf[6], 0x00); // Manufacturer code high
        assert_eq!(buf[7], 0x00); // Manufacturer code low

        // Check body
        assert_eq!(buf[8], 0x01); // Feature ID (SupportedEmiType)
    }

    #[test]
    fn test_build_set_request() {
        let mut buf = [0u8; 64];
        let len = BusAccessFrameBuilder::set_active_emi_type(EmiId::CEmi, &mut buf).unwrap();

        // Header (8 bytes) + body (1 byte Feature ID + 1 byte data) = 10 bytes
        assert_eq!(len, 10);

        assert_eq!(buf[5], 0x03); // Service ID (Set)
        assert_eq!(buf[8], 0x05); // Feature ID (ActiveEmiType)
        assert_eq!(buf[9], 0x03); // Data (cEMI = 0x03)
    }

    #[test]
    fn test_parse_response() {
        // Simulate a response body for SupportedEmiType
        let body = [
            0x01, // Feature ID (SupportedEmiType)
            0x00, 0x04, // Data: cEMI supported (bit 2)
        ];

        let response = BusAccessResponse::parse(&body).unwrap();
        assert_eq!(response.feature_id, FeatureId::SupportedEmiType);

        let emi_types = response.get_supported_emi_types().unwrap();
        assert!(!emi_types.supports_emi1());
        assert!(!emi_types.supports_emi2());
        assert!(emi_types.supports_cemi());
    }

    #[test]
    fn test_parse_active_emi_response() {
        let body = [
            0x05, // Feature ID (ActiveEmiType)
            0x03, // Data: cEMI
        ];

        let response = BusAccessResponse::parse(&body).unwrap();
        let emi = response.get_active_emi_type().unwrap();
        assert_eq!(emi, EmiId::CEmi);
    }
}
