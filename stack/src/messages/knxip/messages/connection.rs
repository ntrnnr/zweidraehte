//! KNX/IP Connection Lifecycle Messages (Core 3.8.2)
//!
//! Connection management messages shared by all connection types:
//! - `ConnectRequest` / `ConnectResponseBuilder` — establish a connection
//! - `ConnectionstateRequest` / `ConnectionstateResponseBuilder` — heartbeat
//! - `DisconnectRequest` / `DisconnectResponseBuilder` — close a connection
//!
//! `ConnectRequest` and `ConnectResponse` use the [`CRI`] and [`CRD`] dispatch
//! enums for polymorphic CRI/CRD handling across connection types.

use core::mem;

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, SplitByteSlice, SplitByteSliceMut, Unaligned,
    big_endian::U16,
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
        NoMoreUniqueConnections, 0x25, "No more unique connections possible";
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

    /// Connection info structure (2 bytes) used in connectionstate and disconnect
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
}

// ============================================================================
// CONNECT REQUEST
// ============================================================================

/// KNXnet/IP CONNECT_REQUEST
///
/// Used to establish a connection to a KNXnet/IP server. The CRI (Connection
/// Request Information) is polymorphic — it can be Device Management, Tunneling,
/// etc., dispatched via the [`CRI`] enum.
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub control_endpoint: HPAI,
    pub data_endpoint: HPAI,
    pub cri: CRI,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for ConnectRequest {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get())
            .map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::ConnectRequest
        {
            return Err(ParseError::Format);
        }

        let control_endpoint = HPAI::parse(buffer, ())?;
        let data_endpoint = HPAI::parse(buffer, ())?;
        let cri = CRI::parse(buffer, ())?;

        Ok(ConnectRequest { control_endpoint, data_endpoint, cri })
    }
}

/// Builder for ConnectRequest message
pub struct ConnectRequestBuilder {
    pub control_endpoint: HPAI,
    pub data_endpoint: HPAI,
    pub cri: CRI,
}

impl ConnectRequestBuilder {
    pub fn new(control_endpoint: HPAI, data_endpoint: HPAI, cri: CRI) -> Self {
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
/// Response to a CONNECT_REQUEST. The CRD (Connection Response Data) is
/// polymorphic via the [`CRD`] enum. On error responses, `crd` is `None`.
#[derive(Debug, Clone)]
pub struct ConnectResponse {
    pub communication_channel_id: u8,
    pub status: ConnectionStatus,
    pub data_endpoint: HPAI,
    pub crd: Option<CRD>,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for ConnectResponse {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<KNXnetIPHeader>().ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get())
            .map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::ConnectResponse
        {
            return Err(ParseError::Format);
        }

        let response_info =
            buffer.take_obj_front::<raw::ConnectResponseInfo>().ok_or(ParseError::Format)?;
        let communication_channel_id = response_info.communication_channel_id;
        let status: ConnectionStatus = response_info.status.into();

        let data_endpoint = HPAI::parse(buffer, ())?;

        // CRD is only present if connection was successful
        let crd = if status == ConnectionStatus::NoError && buffer.len() > 0 {
            Some(CRD::parse(buffer, ())?)
        } else {
            None
        };

        Ok(ConnectResponse { communication_channel_id, status, data_endpoint, crd })
    }
}

/// Builder for ConnectResponse message
pub struct ConnectResponseBuilder {
    pub communication_channel_id: u8,
    pub status: ConnectionStatus,
    pub data_endpoint: HPAI,
    pub crd: Option<CRD>,
}

impl ConnectResponseBuilder {
    pub fn new(
        communication_channel_id: u8,
        status: ConnectionStatus,
        data_endpoint: HPAI,
        crd: Option<CRD>,
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

        if KNXnetIPServiceType::try_from(header.service_type.get())
            .map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::ConnectionstateRequest
        {
            return Err(ParseError::Format);
        }

        let conn_info =
            buffer.take_obj_front::<raw::ConnectionInfo>().ok_or(ParseError::Format)?;
        let control_endpoint = HPAI::parse(buffer, ())?;

        Ok(ConnectionstateRequest {
            communication_channel_id: conn_info.communication_channel_id,
            control_endpoint,
        })
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
        mem::size_of::<KNXnetIPHeader>()
            + mem::size_of::<raw::ConnectionInfo>()
            + self.control_endpoint.bytes_len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::ConnectionstateRequest)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let conn_info = raw::ConnectionInfo {
            communication_channel_id: self.communication_channel_id,
            _reserved: 0,
        };
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

        if KNXnetIPServiceType::try_from(header.service_type.get())
            .map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::ConnectionstateResponse
        {
            return Err(ParseError::Format);
        }

        let response_info =
            buffer.take_obj_front::<raw::ConnectResponseInfo>().ok_or(ParseError::Format)?;

        Ok(ConnectionstateResponse {
            communication_channel_id: response_info.communication_channel_id,
            status: response_info.status.into(),
        })
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

        if KNXnetIPServiceType::try_from(header.service_type.get())
            .map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::DisconnectRequest
        {
            return Err(ParseError::Format);
        }

        let conn_info =
            buffer.take_obj_front::<raw::ConnectionInfo>().ok_or(ParseError::Format)?;
        let control_endpoint = HPAI::parse(buffer, ())?;

        Ok(DisconnectRequest {
            communication_channel_id: conn_info.communication_channel_id,
            control_endpoint,
        })
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
        mem::size_of::<KNXnetIPHeader>()
            + mem::size_of::<raw::ConnectionInfo>()
            + self.control_endpoint.bytes_len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = KNXnetIPHeader {
            header_size: mem::size_of::<KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::DisconnectRequest)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for KNXnet/IP header");

        let conn_info = raw::ConnectionInfo {
            communication_channel_id: self.communication_channel_id,
            _reserved: 0,
        };
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

        if KNXnetIPServiceType::try_from(header.service_type.get())
            .map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::DisconnectResponse
        {
            return Err(ParseError::Format);
        }

        let response_info =
            buffer.take_obj_front::<raw::ConnectResponseInfo>().ok_or(ParseError::Format)?;

        Ok(DisconnectResponse {
            communication_channel_id: response_info.communication_channel_id,
            status: response_info.status.into(),
        })
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
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use super::*;
    use crate::address::IndividualAddress;
    use crate::util::packets::{ParseBuffer, SerializeBuffer};

    #[test]
    fn test_connect_request_round_trip_tunneling() {
        let control_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671);
        let data_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3672);
        let cri = CRI::Tunnel(TunnelingCRI::new(TunnelingLayer::LinkLayer));

        let builder = ConnectRequestBuilder::new(
            control_endpoint.clone(),
            data_endpoint.clone(),
            cri,
        );

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
        assert_eq!(parsed.cri.connection_type(), ConnectionType::Tunnel);
        match parsed.cri {
            CRI::Tunnel(ref cri) => assert_eq!(cri.knx_layer(), TunnelingLayer::LinkLayer),
            _ => panic!("expected Tunnel CRI"),
        }
    }

    #[test]
    fn test_connect_request_round_trip_device_management() {
        let control_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671);
        let data_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3672);
        let cri = CRI::DeviceManagement(DeviceManagementCRI);

        let builder = ConnectRequestBuilder::new(
            control_endpoint.clone(),
            data_endpoint.clone(),
            cri,
        );

        // Serialize
        let mut buffer = [0u8; 64];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<ConnectRequest>().unwrap();

        assert_eq!(parsed.cri.connection_type(), ConnectionType::DeviceManagement);
    }

    #[test]
    fn test_connect_response_round_trip_tunneling() {
        let data_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 1), 3671);
        let crd = CRD::Tunnel(TunnelingCRD::new(IndividualAddress::new(1, 1, 1)));

        let builder = ConnectResponseBuilder::new(
            5,
            ConnectionStatus::NoError,
            data_endpoint.clone(),
            Some(crd),
        );

        // Serialize
        let mut buffer = [0u8; 64];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        // Parse
        let mut parse_buf = written;
        let parsed = parse_buf.parse::<ConnectResponse>().unwrap();

        assert_eq!(parsed.communication_channel_id, 5);
        assert_eq!(parsed.status, ConnectionStatus::NoError);
        assert_eq!(parsed.data_endpoint.address(), data_endpoint.address());
        assert!(parsed.crd.is_some());
        match parsed.crd.unwrap() {
            CRD::Tunnel(crd) => assert_eq!(crd.individual_address, IndividualAddress::new(1, 1, 1)),
            _ => panic!("expected Tunnel CRD"),
        }
    }

    #[test]
    fn test_connect_response_round_trip_device_management() {
        let data_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 1), 3671);
        let crd = CRD::DeviceManagement(DeviceManagementCRD);

        let builder = ConnectResponseBuilder::new(
            3,
            ConnectionStatus::NoError,
            data_endpoint.clone(),
            Some(crd),
        );

        let mut buffer = [0u8; 64];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        let mut parse_buf = written;
        let parsed = parse_buf.parse::<ConnectResponse>().unwrap();

        assert_eq!(parsed.communication_channel_id, 3);
        assert_eq!(parsed.status, ConnectionStatus::NoError);
        assert!(matches!(parsed.crd, Some(CRD::DeviceManagement(_))));
    }

    #[test]
    fn test_connectionstate_request_round_trip() {
        let control_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671);
        let builder = ConnectionstateRequestBuilder::new(10, control_endpoint.clone());

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        let mut parse_buf = written;
        let parsed = parse_buf.parse::<ConnectionstateRequest>().unwrap();

        assert_eq!(parsed.communication_channel_id, 10);
        assert_eq!(parsed.control_endpoint.address(), control_endpoint.address());
    }

    #[test]
    fn test_connectionstate_response_round_trip() {
        let builder = ConnectionstateResponseBuilder::new(10, ConnectionStatus::NoError);

        let mut buffer = [0u8; 16];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        let mut parse_buf = written;
        let parsed = parse_buf.parse::<ConnectionstateResponse>().unwrap();

        assert_eq!(parsed.communication_channel_id, 10);
        assert_eq!(parsed.status, ConnectionStatus::NoError);
    }

    #[test]
    fn test_disconnect_request_round_trip() {
        let control_endpoint = HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 100), 3671);
        let builder = DisconnectRequestBuilder::new(15, control_endpoint.clone());

        let mut buffer = [0u8; 32];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        let mut parse_buf = written;
        let parsed = parse_buf.parse::<DisconnectRequest>().unwrap();

        assert_eq!(parsed.communication_channel_id, 15);
        assert_eq!(parsed.control_endpoint.address(), control_endpoint.address());
    }

    #[test]
    fn test_disconnect_response_round_trip() {
        let builder = DisconnectResponseBuilder::new(15, ConnectionStatus::NoError);

        let mut buffer = [0u8; 16];
        let mut cursor = &mut buffer[..];
        let (written, _) = cursor.serialize(&builder);

        let mut parse_buf = written;
        let parsed = parse_buf.parse::<DisconnectResponse>().unwrap();

        assert_eq!(parsed.communication_channel_id, 15);
        assert_eq!(parsed.status, ConnectionStatus::NoError);
    }
}
