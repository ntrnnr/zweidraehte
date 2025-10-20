//! KNX/IP Tunneling and Connection Messages
//!
//! This module implements the KNX/IP tunneling protocol messages with a consistent builder pattern.
//!
//! ## Architecture
//!
//! - **Parsed Structs**: Connection and tunneling messages that implement `ParsablePacket`
//!   - Do NOT implement `SerializablePacket` (use builders instead)
//!
//! - **Builder Structs**: Builders that implement `SerializablePacket`
//!   - Enable flexible construction and serialization without heap allocation
//!
//! ## Message Types
//!
//! ### Connection Management
//! - `ConnectRequest` / `ConnectRequestBuilder` - Establish a connection
//! - `ConnectResponse` / `ConnectResponseBuilder` - Connection response
//! - `ConnectionstateRequest` / `ConnectionstateRequestBuilder` - Check connection state
//! - `ConnectionstateResponse` / `ConnectionstateResponseBuilder` - Connection state response
//! - `DisconnectRequest` / `DisconnectRequestBuilder` - Close a connection
//! - `DisconnectResponse` / `DisconnectResponseBuilder` - Disconnect response
//!
//! ### Tunneling
//! - `TunnelingRequest` / `TunnelingRequestBuilder` - Send KNX data through tunnel
//! - `TunnelingAck` / `TunnelingAckBuilder` - Acknowledge tunneling request
//! - `TunnelingFeatureGet` / `TunnelingFeatureGetBuilder` - Get tunneling feature
//! - `TunnelingFeatureResponse` / `TunnelingFeatureResponseBuilder` - Feature response
//!
//! ## Usage Pattern
//!
//! ```ignore
//! // Parsing
//! let mut buffer = &data[..];
//! let request = buffer.parse::<ConnectRequest>()?;
//!
//! // Serializing (via builder)
//! let cri_builder = TunnelingCRIBuilder::new(TunnelingLayer::LinkLayer);
//! let builder = ConnectRequestBuilder::new(control_endpoint, data_endpoint, cri_builder);
//! cursor.serialize(&builder);
//! ```

use core::mem;

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, SplitByteSlice, SplitByteSliceMut, Unaligned, big_endian::U16,
};

use crate::{messages::knxip::error::*, util::packets::*};

use super::{super::substructs::*, KNXnetIPServiceType, KNXnetIPVersion, raw::KNXnetIPHeader};

create_protocol_enum!(
    #[allow(missing_docs)]
    #[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
    /// Connection status codes used in various response messages
    pub enum ConnectionStatus: u8 {
        NoError, 0x00, "No Error";
        NoSuchConnectionID, 0x21, "No such connection ID";
        ConnectionTypeNotSupported, 0x22, "Connection type not supported";
        ConnectionOptionsNotSupported, 0x23, "Connection options not supported";
        NoMoreConnections, 0x24, "No more connections possible";
        DataConnectionError, 0x26, "Data connection error";
        KNXConnectionError, 0x27, "KNX connection error";
        LayerNotSupported, 0x29, "Layer not supported";
        _, "Unknown Connection Status 0x{:x}";
    }
);

// ============================================================================
// INTERNAL WIRE FORMAT - ZEROCOPY TYPES
// ============================================================================

mod raw {
    use super::*;

    /// Connection info structure (2 bytes) used in various messages
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct ConnectionInfo {
        pub communication_channel_id: u8,
        pub _reserved: u8,
    }

    /// Connect response info structure (2 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct ConnectResponseInfo {
        pub communication_channel_id: u8,
        pub status: u8,
    }

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
// CONNECT REQUEST
// ============================================================================

/// KNXnet/IP CONNECT_REQUEST
///
/// Used to establish a connection to a KNXnet/IP server
#[derive(Debug)]
pub struct ConnectRequest {
    pub control_endpoint: HPAI,
    pub data_endpoint: HPAI,
    pub connection_request: TunnelingCRI,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for ConnectRequest {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::ConnectRequest
        {
            return Err(ParseError::Format);
        }

        let control_endpoint = HPAI::parse(buffer, ())?;
        let data_endpoint = HPAI::parse(buffer, ())?;
        let connection_request = TunnelingCRI::parse(buffer, ())?;

        Ok(ConnectRequest { control_endpoint, data_endpoint, connection_request })
    }
}

impl ConnectRequest {
    /// Convert to builder for serialization
    pub fn into_builder(self) -> ConnectRequestBuilder {
        ConnectRequestBuilder {
            control_endpoint: self.control_endpoint,
            data_endpoint: self.data_endpoint,
            cri: TunnelingCRIBuilder {
                knx_layer: self.connection_request.knx_layer,
                individual_address: self.connection_request.individual_address,
            },
        }
    }
}

/// Builder for ConnectRequest message
pub struct ConnectRequestBuilder {
    pub control_endpoint: HPAI,
    pub data_endpoint: HPAI,
    pub cri: TunnelingCRIBuilder,
}

impl ConnectRequestBuilder {
    pub fn new(control_endpoint: HPAI, data_endpoint: HPAI, cri: TunnelingCRIBuilder) -> Self {
        Self { control_endpoint, data_endpoint, cri }
    }
}

impl SerializablePacket for ConnectRequestBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>()
            + self.control_endpoint.bytes_len()
            + self.data_endpoint.bytes_len()
            + self.cri.bytes_len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::ConnectRequest)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        self.control_endpoint.serialize(bv);
        self.data_endpoint.serialize(bv);
        self.cri.serialize(bv);
    }
}

// ============================================================================
// CONNECT RESPONSE
// ============================================================================

/// KNXnet/IP CONNECT_RESPONSE
///
/// Response to a CONNECT_REQUEST
#[derive(Debug)]
pub struct ConnectResponse {
    pub communication_channel_id: u8,
    pub status: ConnectionStatus,
    pub data_endpoint: HPAI,
    pub connection_response_data: Option<TunnelingCRD>,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for ConnectResponse {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::ConnectResponse
        {
            return Err(ParseError::Format);
        }

        let response_info = buffer.take_obj_front::<raw::ConnectResponseInfo>().ok_or(ParseError::Format)?;
        let communication_channel_id = response_info.communication_channel_id;
        let status: ConnectionStatus = response_info.status.into();

        let data_endpoint = HPAI::parse(buffer, ())?;

        // CRD is only present if connection was successful
        let connection_response_data = if status == ConnectionStatus::NoError && buffer.len() > 0 {
            Some(TunnelingCRD::parse(buffer, ())?)
        } else {
            None
        };

        Ok(ConnectResponse { communication_channel_id, status, data_endpoint, connection_response_data })
    }
}

/// Builder for ConnectResponse message
pub struct ConnectResponseBuilder {
    pub communication_channel_id: u8,
    pub status: ConnectionStatus,
    pub data_endpoint: HPAI,
    pub crd: Option<TunnelingCRDBuilder>,
}

impl ConnectResponseBuilder {
    pub fn new(
        communication_channel_id: u8,
        status: ConnectionStatus,
        data_endpoint: HPAI,
        crd: Option<TunnelingCRDBuilder>,
    ) -> Self {
        Self { communication_channel_id, status, data_endpoint, crd }
    }
}

impl SerializablePacket for ConnectResponseBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>()
            + mem::size_of::<raw::ConnectResponseInfo>()
            + self.data_endpoint.bytes_len()
            + self.crd.as_ref().map(|c| c.bytes_len()).unwrap_or(0)
    }

    fn serialize<B2: SplitByteSliceMut, BV: BufferViewMut<B2>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::ConnectResponse)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let response_info = raw::ConnectResponseInfo {
            communication_channel_id: self.communication_channel_id,
            status: self.status.into(),
        };
        bv.write_obj_front(&response_info).expect("too few bytes for response info");

        self.data_endpoint.serialize(bv);

        if let Some(ref crd) = self.crd {
            crd.serialize(bv);
        }
    }
}

// ============================================================================
// CONNECTIONSTATE REQUEST
// ============================================================================

/// KNXnet/IP CONNECTIONSTATE_REQUEST
///
/// Used to check if a connection is still alive
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionstateRequest {
    pub communication_channel_id: u8,
    pub control_endpoint: HPAI,
}

impl ConnectionstateRequest {
    pub fn new(communication_channel_id: u8, control_endpoint: HPAI) -> Self {
        Self { communication_channel_id, control_endpoint }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for ConnectionstateRequest {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::ConnectionstateRequest
        {
            return Err(ParseError::Format);
        }

        let conn_info = buffer.take_obj_front::<raw::ConnectionInfo>().ok_or(ParseError::Format)?;
        let control_endpoint = HPAI::parse(buffer, ())?;

        Ok(ConnectionstateRequest { communication_channel_id: conn_info.communication_channel_id, control_endpoint })
    }
}

impl ConnectionstateRequest {
    pub fn into_builder(self) -> ConnectionstateRequestBuilder {
        ConnectionstateRequestBuilder {
            communication_channel_id: self.communication_channel_id,
            control_endpoint: self.control_endpoint,
        }
    }
}

/// Builder for ConnectionstateRequest message
pub struct ConnectionstateRequestBuilder {
    pub communication_channel_id: u8,
    pub control_endpoint: HPAI,
}

impl ConnectionstateRequestBuilder {
    pub fn new(communication_channel_id: u8, control_endpoint: HPAI) -> Self {
        Self { communication_channel_id, control_endpoint }
    }
}

impl SerializablePacket for ConnectionstateRequestBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::ConnectionInfo>() + self.control_endpoint.bytes_len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::ConnectionstateRequest)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let conn_info = raw::ConnectionInfo { communication_channel_id: self.communication_channel_id, _reserved: 0 };
        bv.write_obj_front(&conn_info).expect("too few bytes for connection info");

        self.control_endpoint.serialize(bv);
    }
}

// ============================================================================
// CONNECTIONSTATE RESPONSE
// ============================================================================

/// KNXnet/IP CONNECTIONSTATE_RESPONSE
///
/// Response to a CONNECTIONSTATE_REQUEST
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionstateResponse {
    pub communication_channel_id: u8,
    pub status: ConnectionStatus,
}

impl ConnectionstateResponse {
    pub fn new(communication_channel_id: u8, status: ConnectionStatus) -> Self {
        Self { communication_channel_id, status }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for ConnectionstateResponse {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::ConnectionstateResponse
        {
            return Err(ParseError::Format);
        }

        let response_info = buffer.take_obj_front::<raw::ConnectResponseInfo>().ok_or(ParseError::Format)?;

        Ok(ConnectionstateResponse {
            communication_channel_id: response_info.communication_channel_id,
            status: response_info.status.into(),
        })
    }
}

impl ConnectionstateResponse {
    pub fn into_builder(self) -> ConnectionstateResponseBuilder {
        ConnectionstateResponseBuilder { communication_channel_id: self.communication_channel_id, status: self.status }
    }
}

/// Builder for ConnectionstateResponse message
pub struct ConnectionstateResponseBuilder {
    pub communication_channel_id: u8,
    pub status: ConnectionStatus,
}

impl ConnectionstateResponseBuilder {
    pub fn new(communication_channel_id: u8, status: ConnectionStatus) -> Self {
        Self { communication_channel_id, status }
    }
}

impl SerializablePacket for ConnectionstateResponseBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::ConnectResponseInfo>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::ConnectionstateResponse)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let response_info = raw::ConnectResponseInfo {
            communication_channel_id: self.communication_channel_id,
            status: self.status.into(),
        };
        bv.write_obj_front(&response_info).expect("too few bytes for response info");
    }
}

// ============================================================================
// DISCONNECT REQUEST
// ============================================================================

/// KNXnet/IP DISCONNECT_REQUEST
///
/// Used to close a connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisconnectRequest {
    pub communication_channel_id: u8,
    pub control_endpoint: HPAI,
}

impl DisconnectRequest {
    pub fn new(communication_channel_id: u8, control_endpoint: HPAI) -> Self {
        Self { communication_channel_id, control_endpoint }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for DisconnectRequest {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::DisconnectRequest
        {
            return Err(ParseError::Format);
        }

        let conn_info = buffer.take_obj_front::<raw::ConnectionInfo>().ok_or(ParseError::Format)?;
        let control_endpoint = HPAI::parse(buffer, ())?;

        Ok(DisconnectRequest { communication_channel_id: conn_info.communication_channel_id, control_endpoint })
    }
}

impl DisconnectRequest {
    pub fn into_builder(self) -> DisconnectRequestBuilder {
        DisconnectRequestBuilder {
            communication_channel_id: self.communication_channel_id,
            control_endpoint: self.control_endpoint,
        }
    }
}

/// Builder for DisconnectRequest message
pub struct DisconnectRequestBuilder {
    pub communication_channel_id: u8,
    pub control_endpoint: HPAI,
}

impl DisconnectRequestBuilder {
    pub fn new(communication_channel_id: u8, control_endpoint: HPAI) -> Self {
        Self { communication_channel_id, control_endpoint }
    }
}

impl SerializablePacket for DisconnectRequestBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::ConnectionInfo>() + self.control_endpoint.bytes_len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::DisconnectRequest)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let conn_info = raw::ConnectionInfo { communication_channel_id: self.communication_channel_id, _reserved: 0 };
        bv.write_obj_front(&conn_info).expect("too few bytes for connection info");

        self.control_endpoint.serialize(bv);
    }
}

// ============================================================================
// DISCONNECT RESPONSE
// ============================================================================

/// KNXnet/IP DISCONNECT_RESPONSE
///
/// Response to a DISCONNECT_REQUEST
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisconnectResponse {
    pub communication_channel_id: u8,
    pub status: ConnectionStatus,
}

impl DisconnectResponse {
    pub fn new(communication_channel_id: u8, status: ConnectionStatus) -> Self {
        Self { communication_channel_id, status }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for DisconnectResponse {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get()).map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::DisconnectResponse
        {
            return Err(ParseError::Format);
        }

        let response_info = buffer.take_obj_front::<raw::ConnectResponseInfo>().ok_or(ParseError::Format)?;

        Ok(DisconnectResponse {
            communication_channel_id: response_info.communication_channel_id,
            status: response_info.status.into(),
        })
    }
}

impl DisconnectResponse {
    pub fn into_builder(self) -> DisconnectResponseBuilder {
        DisconnectResponseBuilder { communication_channel_id: self.communication_channel_id, status: self.status }
    }
}

/// Builder for DisconnectResponse message
pub struct DisconnectResponseBuilder {
    pub communication_channel_id: u8,
    pub status: ConnectionStatus,
}

impl DisconnectResponseBuilder {
    pub fn new(communication_channel_id: u8, status: ConnectionStatus) -> Self {
        Self { communication_channel_id, status }
    }
}

impl SerializablePacket for DisconnectResponseBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<KNXnetIPHeader>() + mem::size_of::<raw::ConnectResponseInfo>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::DisconnectResponse)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let response_info = raw::ConnectResponseInfo {
            communication_channel_id: self.communication_channel_id,
            status: self.status.into(),
        };
        bv.write_obj_front(&response_info).expect("too few bytes for response info");
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
    use core::net::Ipv4Addr;

    use super::*;
    use crate::address::IndividualAddress;
    use crate::util::packets::{ParseBuffer, SerializeBuffer};

    #[test]
    fn test_connect_request_round_trip() {
        let control_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671);
        let data_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3672);
        let cri_builder = TunnelingCRIBuilder::new(TunnelingLayer::LinkLayer);

        let builder = ConnectRequestBuilder::new(control_endpoint.clone(), data_endpoint.clone(), cri_builder);

        // Serialize
        let mut buffer = [0u8; 64];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<ConnectRequest>().unwrap();

        // Verify
        assert_eq!(parsed.control_endpoint.address(), control_endpoint.address());
        assert_eq!(parsed.data_endpoint.address(), data_endpoint.address());
        assert_eq!(parsed.connection_request.knx_layer(), TunnelingLayer::LinkLayer);
    }

    #[test]
    fn test_connect_response_round_trip() {
        let data_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 1), 3671);
        let crd_builder = TunnelingCRDBuilder::new(IndividualAddress::new(1, 1, 1));

        let builder =
            ConnectResponseBuilder::new(5, ConnectionStatus::NoError, data_endpoint.clone(), Some(crd_builder));

        // Serialize
        let mut buffer = [0u8; 64];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<ConnectResponse>().unwrap();

        // Verify
        assert_eq!(parsed.communication_channel_id, 5);
        assert_eq!(parsed.status, ConnectionStatus::NoError);
        assert_eq!(parsed.data_endpoint.address(), data_endpoint.address());
        assert!(parsed.connection_response_data.is_some());
    }

    #[test]
    fn test_connectionstate_request_round_trip() {
        let control_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671);
        let builder = ConnectionstateRequestBuilder::new(10, control_endpoint.clone());

        // Serialize
        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<ConnectionstateRequest>().unwrap();

        // Verify
        assert_eq!(parsed.communication_channel_id, 10);
        assert_eq!(parsed.control_endpoint.address(), control_endpoint.address());
    }

    #[test]
    fn test_connectionstate_response_round_trip() {
        let builder = ConnectionstateResponseBuilder::new(10, ConnectionStatus::NoError);

        // Serialize
        let mut buffer = [0u8; 16];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<ConnectionstateResponse>().unwrap();

        // Verify
        assert_eq!(parsed.communication_channel_id, 10);
        assert_eq!(parsed.status, ConnectionStatus::NoError);
    }

    #[test]
    fn test_disconnect_request_round_trip() {
        let control_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671);
        let builder = DisconnectRequestBuilder::new(15, control_endpoint.clone());

        // Serialize
        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<DisconnectRequest>().unwrap();

        // Verify
        assert_eq!(parsed.communication_channel_id, 15);
        assert_eq!(parsed.control_endpoint.address(), control_endpoint.address());
    }

    #[test]
    fn test_disconnect_response_round_trip() {
        let builder = DisconnectResponseBuilder::new(15, ConnectionStatus::NoError);

        // Serialize
        let mut buffer = [0u8; 16];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<DisconnectResponse>().unwrap();

        // Verify
        assert_eq!(parsed.communication_channel_id, 15);
        assert_eq!(parsed.status, ConnectionStatus::NoError);
    }

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
