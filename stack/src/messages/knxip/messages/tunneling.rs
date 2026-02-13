//! KNX/IP Tunneling and Device Configuration Messages
//!
//! This module implements the KNX/IP tunneling protocol messages with a consistent builder pattern.
//!
//! ## Architecture
//!
//! - **Parsed Structs**: Tunneling and device configuration messages that implement `ParsablePacket`
//!   - Do NOT implement `SerializablePacket` (use builders instead)
//!
//! - **Builder Structs**: Builders that implement `SerializablePacket`
//!   - Enable flexible construction and serialization without heap allocation
//!
//! ## Message Types
//!
//! ### Device Configuration
//! - `DeviceConfigurationRequest` / `DeviceConfigurationRequestBuilder` - Send cEMI Local Management frame
//! - `DeviceConfigurationAck` / `DeviceConfigurationAckBuilder` - Acknowledge device configuration request
//!
//! ### Tunneling
//! - `TunnelingRequest` / `TunnelingRequestBuilder` - Send KNX data through tunnel
//! - `TunnelingAck` / `TunnelingAckBuilder` - Acknowledge tunneling request
//! - `TunnelingFeatureGet` / `TunnelingFeatureGetBuilder` - Get tunneling feature
//! - `TunnelingFeatureResponse` / `TunnelingFeatureResponseBuilder` - Feature response
//!
//! ## Connection Lifecycle
//!
//! Connection management messages (`ConnectRequest`, `ConnectResponse`,
//! `ConnectionstateRequest/Response`, `DisconnectRequest/Response`) live in the
//! sibling [`connection`](super::connection) module.

use core::mem;

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, SplitByteSlice, SplitByteSliceMut, Unaligned,
    big_endian::U16,
};

use crate::{messages::knxip::error::*, util::packets::*};

use super::{KNXnetIPServiceType, KNXnetIPVersion, raw::KNXnetIPHeader};

// Re-import ConnectionStatus from the connection module so that types in this
// module (TunnelingAck, DeviceConfigurationAck) can reference it without
// consumers needing a separate import.
use super::connection::ConnectionStatus;

// ============================================================================
// INTERNAL WIRE FORMAT - ZEROCOPY TYPES
// ============================================================================

mod raw {
    use super::*;

    /// Tunneling request/ack header (4 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct TunnelingHeader {
        pub structure_length: u8,
        pub communication_channel_id: u8,
        pub sequence_counter: u8,
        pub status_or_reserved: u8,
    }

    /// Tunneling feature header (4 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct TunnelingFeatureHeader {
        pub structure_length: u8,
        pub communication_channel_id: u8,
        pub sequence_counter: u8,
        pub feature_identifier: u8,
    }
}

// ============================================================================
// TUNNELING REQUEST
// ============================================================================

/// KNXnet/IP TUNNELING_REQUEST
///
/// Used to send KNX data through a tunnel connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelingRequest {
    pub communication_channel_id: u8,
    pub sequence_counter: u8,
}

impl TunnelingRequest {
    pub fn new(communication_channel_id: u8, sequence_counter: u8) -> Self {
        Self { communication_channel_id, sequence_counter }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for TunnelingRequest {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::TunnelingRequest
        {
            return Err(ParseError::Format);
        }

        let tun_header = buffer.take_obj_front::<raw::TunnelingHeader>().ok_or(ParseError::Format)?;

        Ok(TunnelingRequest {
            communication_channel_id: tun_header.communication_channel_id,
            sequence_counter: tun_header.sequence_counter,
        })
    }
}

impl TunnelingRequest {
    pub fn into_builder(self) -> TunnelingRequestBuilder {
        TunnelingRequestBuilder {
            communication_channel_id: self.communication_channel_id,
            sequence_counter: self.sequence_counter,
        }
    }
}

/// Builder for TunnelingRequest message
pub struct TunnelingRequestBuilder {
    pub communication_channel_id: u8,
    pub sequence_counter: u8,
}

impl TunnelingRequestBuilder {
    pub fn new(communication_channel_id: u8, sequence_counter: u8) -> Self {
        Self { communication_channel_id, sequence_counter }
    }
}

impl SerializablePacket for TunnelingRequestBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::TunnelingHeader>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::TunnelingRequest)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let tun_header = raw::TunnelingHeader {
            structure_length: mem::size_of::<raw::TunnelingHeader>() as u8,
            communication_channel_id: self.communication_channel_id,
            sequence_counter: self.sequence_counter,
            status_or_reserved: 0,
        };
        bv.write_obj_front(&tun_header).expect("too few bytes for tunneling header");
    }
}

// ============================================================================
// TUNNELING ACK
// ============================================================================

/// KNXnet/IP TUNNELING_ACK
///
/// Acknowledgment for a TUNNELING_REQUEST
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelingAck {
    pub communication_channel_id: u8,
    pub sequence_counter: u8,
    pub status: ConnectionStatus,
}

impl TunnelingAck {
    pub fn new(communication_channel_id: u8, sequence_counter: u8, status: ConnectionStatus) -> Self {
        Self { communication_channel_id, sequence_counter, status }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for TunnelingAck {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::TunnelingAck
        {
            return Err(ParseError::Format);
        }

        let tun_header = buffer.take_obj_front::<raw::TunnelingHeader>().ok_or(ParseError::Format)?;

        Ok(TunnelingAck {
            communication_channel_id: tun_header.communication_channel_id,
            sequence_counter: tun_header.sequence_counter,
            status: tun_header.status_or_reserved.into(),
        })
    }
}

impl TunnelingAck {
    pub fn into_builder(self) -> TunnelingAckBuilder {
        TunnelingAckBuilder {
            communication_channel_id: self.communication_channel_id,
            sequence_counter: self.sequence_counter,
            status: self.status,
        }
    }
}

/// Builder for TunnelingAck message
pub struct TunnelingAckBuilder {
    pub communication_channel_id: u8,
    pub sequence_counter: u8,
    pub status: ConnectionStatus,
}

impl TunnelingAckBuilder {
    pub fn new(communication_channel_id: u8, sequence_counter: u8, status: ConnectionStatus) -> Self {
        Self { communication_channel_id, sequence_counter, status }
    }
}

impl SerializablePacket for TunnelingAckBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::TunnelingHeader>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::TunnelingAck)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let tun_header = raw::TunnelingHeader {
            structure_length: mem::size_of::<raw::TunnelingHeader>() as u8,
            communication_channel_id: self.communication_channel_id,
            sequence_counter: self.sequence_counter,
            status_or_reserved: self.status.into(),
        };
        bv.write_obj_front(&tun_header).expect("too few bytes for tunneling header");
    }
}

// ============================================================================
// DEVICE CONFIGURATION REQUEST
// ============================================================================

/// KNXnet/IP DEVICE_CONFIGURATION_REQUEST
///
/// Used to send cEMI Local Management frames over a Device Management connection.
/// Wire format is identical to TunnelingRequest (same 4-byte connection header),
/// but carries M_PropRead/M_PropWrite cEMI frames instead of L_Data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceConfigurationRequest {
    pub communication_channel_id: u8,
    pub sequence_counter: u8,
}

impl DeviceConfigurationRequest {
    pub fn new(communication_channel_id: u8, sequence_counter: u8) -> Self {
        Self { communication_channel_id, sequence_counter }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for DeviceConfigurationRequest {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::DeviceConfigurationRequest
        {
            return Err(ParseError::Format);
        }

        let tun_header = buffer.take_obj_front::<raw::TunnelingHeader>().ok_or(ParseError::Format)?;

        Ok(DeviceConfigurationRequest {
            communication_channel_id: tun_header.communication_channel_id,
            sequence_counter: tun_header.sequence_counter,
        })
    }
}

impl DeviceConfigurationRequest {
    pub fn into_builder(self) -> DeviceConfigurationRequestBuilder {
        DeviceConfigurationRequestBuilder {
            communication_channel_id: self.communication_channel_id,
            sequence_counter: self.sequence_counter,
        }
    }
}

/// Builder for DeviceConfigurationRequest message.
///
/// The cEMI Local Management payload is not part of this builder — it is
/// appended separately after serializing the header, since the connection
/// manager constructs it independently.
pub struct DeviceConfigurationRequestBuilder {
    pub communication_channel_id: u8,
    pub sequence_counter: u8,
}

impl DeviceConfigurationRequestBuilder {
    pub fn new(communication_channel_id: u8, sequence_counter: u8) -> Self {
        Self { communication_channel_id, sequence_counter }
    }
}

impl SerializablePacket for DeviceConfigurationRequestBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::TunnelingHeader>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::DeviceConfigurationRequest)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let tun_header = raw::TunnelingHeader {
            structure_length: mem::size_of::<raw::TunnelingHeader>() as u8,
            communication_channel_id: self.communication_channel_id,
            sequence_counter: self.sequence_counter,
            status_or_reserved: 0,
        };
        bv.write_obj_front(&tun_header).expect("too few bytes for connection header");
    }
}

// ============================================================================
// DEVICE CONFIGURATION ACK
// ============================================================================

/// KNXnet/IP DEVICE_CONFIGURATION_ACK
///
/// Acknowledgment for a DEVICE_CONFIGURATION_REQUEST.
/// Wire format is identical to TunnelingAck (same 4-byte connection header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceConfigurationAck {
    pub communication_channel_id: u8,
    pub sequence_counter: u8,
    pub status: ConnectionStatus,
}

impl DeviceConfigurationAck {
    pub fn new(communication_channel_id: u8, sequence_counter: u8, status: ConnectionStatus) -> Self {
        Self { communication_channel_id, sequence_counter, status }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for DeviceConfigurationAck {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::DeviceConfigurationAck
        {
            return Err(ParseError::Format);
        }

        let tun_header = buffer.take_obj_front::<raw::TunnelingHeader>().ok_or(ParseError::Format)?;

        Ok(DeviceConfigurationAck {
            communication_channel_id: tun_header.communication_channel_id,
            sequence_counter: tun_header.sequence_counter,
            status: tun_header.status_or_reserved.into(),
        })
    }
}

impl DeviceConfigurationAck {
    pub fn into_builder(self) -> DeviceConfigurationAckBuilder {
        DeviceConfigurationAckBuilder {
            communication_channel_id: self.communication_channel_id,
            sequence_counter: self.sequence_counter,
            status: self.status,
        }
    }
}

/// Builder for DeviceConfigurationAck message
pub struct DeviceConfigurationAckBuilder {
    pub communication_channel_id: u8,
    pub sequence_counter: u8,
    pub status: ConnectionStatus,
}

impl DeviceConfigurationAckBuilder {
    pub fn new(communication_channel_id: u8, sequence_counter: u8, status: ConnectionStatus) -> Self {
        Self { communication_channel_id, sequence_counter, status }
    }
}

impl SerializablePacket for DeviceConfigurationAckBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::TunnelingHeader>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::DeviceConfigurationAck)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let tun_header = raw::TunnelingHeader {
            structure_length: mem::size_of::<raw::TunnelingHeader>() as u8,
            communication_channel_id: self.communication_channel_id,
            sequence_counter: self.sequence_counter,
            status_or_reserved: self.status.into(),
        };
        bv.write_obj_front(&tun_header).expect("too few bytes for connection header");
    }
}

// ============================================================================
// TUNNELING FEATURE GET
// ============================================================================

/// KNXnet/IP TUNNELING_FEATURE_GET
///
/// Request to get a tunneling feature
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelingFeatureGet {
    pub communication_channel_id: u8,
    pub sequence_counter: u8,
    pub feature_identifier: u8,
}

impl TunnelingFeatureGet {
    pub fn new(communication_channel_id: u8, sequence_counter: u8, feature_identifier: u8) -> Self {
        Self { communication_channel_id, sequence_counter, feature_identifier }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for TunnelingFeatureGet {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::TunnelingFeatureGet
        {
            return Err(ParseError::Format);
        }

        let feat_header = buffer.take_obj_front::<raw::TunnelingFeatureHeader>().ok_or(ParseError::Format)?;

        Ok(TunnelingFeatureGet {
            communication_channel_id: feat_header.communication_channel_id,
            sequence_counter: feat_header.sequence_counter,
            feature_identifier: feat_header.feature_identifier,
        })
    }
}

impl TunnelingFeatureGet {
    pub fn into_builder(self) -> TunnelingFeatureGetBuilder {
        TunnelingFeatureGetBuilder {
            communication_channel_id: self.communication_channel_id,
            sequence_counter: self.sequence_counter,
            feature_identifier: self.feature_identifier,
        }
    }
}

/// Builder for TunnelingFeatureGet message
pub struct TunnelingFeatureGetBuilder {
    pub communication_channel_id: u8,
    pub sequence_counter: u8,
    pub feature_identifier: u8,
}

impl TunnelingFeatureGetBuilder {
    pub fn new(communication_channel_id: u8, sequence_counter: u8, feature_identifier: u8) -> Self {
        Self { communication_channel_id, sequence_counter, feature_identifier }
    }
}

impl SerializablePacket for TunnelingFeatureGetBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::TunnelingFeatureHeader>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::TunnelingFeatureGet)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let feat_header = raw::TunnelingFeatureHeader {
            structure_length: mem::size_of::<raw::TunnelingFeatureHeader>() as u8,
            communication_channel_id: self.communication_channel_id,
            sequence_counter: self.sequence_counter,
            feature_identifier: self.feature_identifier,
        };
        bv.write_obj_front(&feat_header).expect("too few bytes for feature header");
    }
}

// ============================================================================
// TUNNELING FEATURE RESPONSE
// ============================================================================

/// KNXnet/IP TUNNELING_FEATURE_RESPONSE
///
/// Response containing tunneling feature information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelingFeatureResponse {
    pub communication_channel_id: u8,
    pub sequence_counter: u8,
    pub feature_identifier: u8,
    pub return_code: u8,
}

impl TunnelingFeatureResponse {
    pub fn new(communication_channel_id: u8, sequence_counter: u8, feature_identifier: u8, return_code: u8) -> Self {
        Self { communication_channel_id, sequence_counter, feature_identifier, return_code }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for TunnelingFeatureResponse {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::TunnelingFeatureResponse
        {
            return Err(ParseError::Format);
        }

        let feat_header = buffer.take_obj_front::<raw::TunnelingFeatureHeader>().ok_or(ParseError::Format)?;
        let return_code = buffer.take_byte_front().ok_or(ParseError::Format)?;

        Ok(TunnelingFeatureResponse {
            communication_channel_id: feat_header.communication_channel_id,
            sequence_counter: feat_header.sequence_counter,
            feature_identifier: feat_header.feature_identifier,
            return_code,
        })
    }
}

impl TunnelingFeatureResponse {
    pub fn into_builder(self) -> TunnelingFeatureResponseBuilder {
        TunnelingFeatureResponseBuilder {
            communication_channel_id: self.communication_channel_id,
            sequence_counter: self.sequence_counter,
            feature_identifier: self.feature_identifier,
            return_code: self.return_code,
        }
    }
}

/// Builder for TunnelingFeatureResponse message
pub struct TunnelingFeatureResponseBuilder {
    pub communication_channel_id: u8,
    pub sequence_counter: u8,
    pub feature_identifier: u8,
    pub return_code: u8,
}

impl TunnelingFeatureResponseBuilder {
    pub fn new(communication_channel_id: u8, sequence_counter: u8, feature_identifier: u8, return_code: u8) -> Self {
        Self { communication_channel_id, sequence_counter, feature_identifier, return_code }
    }
}

impl SerializablePacket for TunnelingFeatureResponseBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::TunnelingFeatureHeader>() + 1
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::TunnelingFeatureResponse)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let feat_header = raw::TunnelingFeatureHeader {
            structure_length: mem::size_of::<raw::TunnelingFeatureHeader>() as u8,
            communication_channel_id: self.communication_channel_id,
            sequence_counter: self.sequence_counter,
            feature_identifier: self.feature_identifier,
        };
        bv.write_obj_front(&feat_header).expect("too few bytes for feature header");

        bv.write_obj_front(&self.return_code).expect("too few bytes for return code");
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::packets::{ParseBuffer, SerializeBuffer};

    #[test]
    fn test_tunneling_request_round_trip() {
        let builder = TunnelingRequestBuilder::new(20, 5);

        // Serialize
        let mut buffer = [0u8; 16];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<TunnelingRequest>().unwrap();

        // Verify
        assert_eq!(parsed.communication_channel_id, 20);
        assert_eq!(parsed.sequence_counter, 5);
    }

    #[test]
    fn test_tunneling_ack_round_trip() {
        let builder = TunnelingAckBuilder::new(20, 5, ConnectionStatus::NoError);

        // Serialize
        let mut buffer = [0u8; 16];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<TunnelingAck>().unwrap();

        // Verify
        assert_eq!(parsed.communication_channel_id, 20);
        assert_eq!(parsed.sequence_counter, 5);
        assert_eq!(parsed.status, ConnectionStatus::NoError);
    }

    #[test]
    fn test_device_configuration_request_round_trip() {
        let builder = DeviceConfigurationRequestBuilder::new(30, 7);

        // Serialize
        let mut buffer = [0u8; 16];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<DeviceConfigurationRequest>().unwrap();

        // Verify
        assert_eq!(parsed.communication_channel_id, 30);
        assert_eq!(parsed.sequence_counter, 7);
    }

    #[test]
    fn test_device_configuration_ack_round_trip() {
        let builder = DeviceConfigurationAckBuilder::new(30, 7, ConnectionStatus::NoError);

        // Serialize
        let mut buffer = [0u8; 16];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<DeviceConfigurationAck>().unwrap();

        // Verify
        assert_eq!(parsed.communication_channel_id, 30);
        assert_eq!(parsed.sequence_counter, 7);
        assert_eq!(parsed.status, ConnectionStatus::NoError);
    }

    #[test]
    fn test_tunneling_feature_get_round_trip() {
        let builder = TunnelingFeatureGetBuilder::new(25, 3, 0x01);

        // Serialize
        let mut buffer = [0u8; 16];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<TunnelingFeatureGet>().unwrap();

        // Verify
        assert_eq!(parsed.communication_channel_id, 25);
        assert_eq!(parsed.sequence_counter, 3);
        assert_eq!(parsed.feature_identifier, 0x01);
    }

    #[test]
    fn test_tunneling_feature_response_round_trip() {
        let builder = TunnelingFeatureResponseBuilder::new(25, 3, 0x01, 0x00);

        // Serialize
        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<TunnelingFeatureResponse>().unwrap();

        // Verify
        assert_eq!(parsed.communication_channel_id, 25);
        assert_eq!(parsed.sequence_counter, 3);
        assert_eq!(parsed.feature_identifier, 0x01);
        assert_eq!(parsed.return_code, 0x00);
    }
}
