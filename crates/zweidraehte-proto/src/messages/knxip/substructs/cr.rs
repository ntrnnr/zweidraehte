use core::mem;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, SplitByteSlice, SplitByteSliceMut, Unaligned};

use crate::address::IndividualAddress;
use crate::messages::knxip::error::{ParseError, ParseResult};
use crate::util::packets::*;

macro_rules! debug_err {
    ($err:expr, $($arg:tt)*) => (
        {
            debug!($($arg)*);
            $err
        }
    )
}

macro_rules! debug_err_fn {
    ($err:expr, $($arg:tt)*) => (
        || {
            debug!($($arg)*);
            $err
        }
    )
}

create_protocol_enum!(
    #[allow(missing_docs)]
    #[derive(Eq, PartialEq, Copy, Clone)]
    /// CRI/CRD connection types
    pub enum ConnectionType: u8 {
        DeviceManagement, 0x03, "Device Management";
        Tunnel, 0x04, "Tunnel";
        Remlog, 0x06, "Remlog";
        Remconf, 0x07, "Remconf";
        Objsvr, 0x08, "Object Server";
        _, "Unknown Connection Type 0x{:x}";
    }
);

create_protocol_enum!(
    #[allow(missing_docs)]
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum TunnelingLayer: u8 {
        LinkLayer, 0x02, "Data Link Layer Tunnel";
        Raw, 0x04, "Raw Tunnel";
        BusMonitor, 0x80, "Bus Monitor Tunnel";
        _, "Unknown Tunneling Layer 0x{:x}";
    }
);

// ============================================================================
// SHARED WIRE FORMAT - ZEROCOPY TYPES
// ============================================================================

mod raw {
    use super::*;

    /// Wire format for CRI/CRD header (2 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct Header {
        pub struct_len: u8,
        pub struct_type: u8,
    }

    /// Wire format for CRI body (2 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct CRIBody {
        pub knx_layer: u8,
        pub reserved: u8,
    }
}

// ============================================================================
// TUNNELING CRI (Connection Request Information)
// ============================================================================

/// Tunneling Connection Request Information
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TunnelingCRI {
    pub knx_layer: TunnelingLayer,
    pub individual_address: Option<IndividualAddress>,
}

impl TunnelingCRI {
    /// Constructs a new `TunnelingCRI`.
    pub fn new(knx_layer: TunnelingLayer) -> Self {
        Self { knx_layer, individual_address: None }
    }

    /// Constructs a new extended `TunnelingCRI` with an individual address.
    pub fn new_extended(knx_layer: TunnelingLayer, individual_address: IndividualAddress) -> Self {
        Self { knx_layer, individual_address: Some(individual_address) }
    }

    /// The tunneling layer this connection request wants to establish a connection on.
    pub fn knx_layer(&self) -> TunnelingLayer {
        self.knx_layer
    }

    /// The optional individual address an extended Tunneling CRI can carry
    pub fn individual_address(&self) -> Option<IndividualAddress> {
        self.individual_address
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for TunnelingCRI {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> ParseResult<Self> {
        let header = buffer
            .take_obj_front::<raw::Header>()
            .ok_or_else(debug_err_fn!(ParseError::Format, "too few bytes for CRI header"))?;

        if header.struct_type != ConnectionType::Tunnel.into() {
            return debug_err!(Err(ParseError::NotExpected), "unexpected tunnel connection type");
        }

        let body = buffer
            .take_obj_front::<raw::CRIBody>()
            .ok_or_else(debug_err_fn!(ParseError::Format, "too few bytes for CRI body"))?;

        let knx_layer = body.knx_layer.into();

        let individual_address = if header.struct_len == 6 {
            Some(IndividualAddress::from_bytes(
                &buffer
                    .take_front(2)
                    .ok_or_else(debug_err_fn!(ParseError::Format, "too few bytes for CRI individual address"))?,
            ))
        } else {
            None
        };

        Ok(TunnelingCRI { knx_layer, individual_address })
    }
}

/// Builder for TunnelingCRI
#[derive(Copy, Clone, Debug)]
pub struct TunnelingCRIBuilder {
    pub knx_layer: TunnelingLayer,
    pub individual_address: Option<IndividualAddress>,
}

impl TunnelingCRIBuilder {
    pub fn new(knx_layer: TunnelingLayer) -> Self {
        Self { knx_layer, individual_address: None }
    }

    pub fn new_extended(knx_layer: TunnelingLayer, individual_address: IndividualAddress) -> Self {
        Self { knx_layer, individual_address: Some(individual_address) }
    }
}

impl SerializablePacket for TunnelingCRIBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::Header>()
            + mem::size_of::<raw::CRIBody>()
            + if self.individual_address.is_some() { 2 } else { 0 }
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::Header { struct_len: self.bytes_len() as u8, struct_type: ConnectionType::Tunnel.into() };
        bv.write_obj_front(&header).expect("too few bytes for CRI header");

        let body = raw::CRIBody { knx_layer: self.knx_layer.into(), reserved: 0 };
        bv.write_obj_front(&body).expect("too few bytes for CRI body");

        if let Some(addr) = self.individual_address {
            bv.write_obj_front(&addr).expect("too few bytes for individual address");
        }
    }
}

// ============================================================================
// TUNNELING CRD (Connection Response Data)
// ============================================================================

/// Tunneling Connection Response Data
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TunnelingCRD {
    pub individual_address: IndividualAddress,
}

impl TunnelingCRD {
    /// Constructs a new `TunnelingCRD`.
    pub fn new(individual_address: IndividualAddress) -> Self {
        Self { individual_address }
    }

    /// The individual address the tunneling connection got assigned
    pub fn individual_address(&self) -> IndividualAddress {
        self.individual_address
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for TunnelingCRD {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> ParseResult<Self> {
        let header = buffer
            .take_obj_front::<raw::Header>()
            .ok_or_else(debug_err_fn!(ParseError::Format, "too few bytes for CRD header"))?;

        if header.struct_type != ConnectionType::Tunnel.into() {
            return debug_err!(Err(ParseError::NotExpected), "unexpected tunnel connection type");
        }

        let individual_address = IndividualAddress::from_bytes(
            &buffer
                .take_front(2)
                .ok_or_else(debug_err_fn!(ParseError::Format, "too few bytes for CRD individual address"))?,
        );

        Ok(TunnelingCRD { individual_address })
    }
}

/// Builder for TunnelingCRD
#[derive(Copy, Clone, Debug)]
pub struct TunnelingCRDBuilder {
    pub individual_address: IndividualAddress,
}

impl TunnelingCRDBuilder {
    pub fn new(individual_address: IndividualAddress) -> Self {
        Self { individual_address }
    }
}

impl SerializablePacket for TunnelingCRDBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::Header>() + 2 // header + individual address
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::Header { struct_len: self.bytes_len() as u8, struct_type: ConnectionType::Tunnel.into() };
        bv.write_obj_front(&header).expect("too few bytes for CRD header");

        bv.write_obj_front(&self.individual_address).expect("too few bytes for individual address");
    }
}

// ============================================================================
// DEVICE MANAGEMENT CRI (Connection Request Information)
// ============================================================================

/// Device Management Connection Request Information.
///
/// The simplest CRI — just the 2-byte header with connection type 0x03,
/// no additional fields beyond that.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DeviceManagementCRI;

impl<B: SplitByteSlice> ParsablePacket<B, ()> for DeviceManagementCRI {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> ParseResult<Self> {
        let header = buffer
            .take_obj_front::<raw::Header>()
            .ok_or_else(debug_err_fn!(ParseError::Format, "too few bytes for CRI header"))?;

        if header.struct_type != ConnectionType::DeviceManagement.into() {
            return debug_err!(Err(ParseError::NotExpected), "expected Device Management connection type");
        }

        Ok(DeviceManagementCRI)
    }
}

/// Builder for Device Management CRI
#[derive(Copy, Clone, Debug)]
pub struct DeviceManagementCRIBuilder;

impl SerializablePacket for DeviceManagementCRIBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::Header>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::Header {
            struct_len: mem::size_of::<raw::Header>() as u8,
            struct_type: ConnectionType::DeviceManagement.into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for CRI header");
    }
}

// ============================================================================
// DEVICE MANAGEMENT CRD (Connection Response Data)
// ============================================================================

/// Device Management Connection Response Data.
///
/// Like the CRI, this is just the 2-byte header with connection type 0x03.
/// No additional fields.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DeviceManagementCRD;

impl<B: SplitByteSlice> ParsablePacket<B, ()> for DeviceManagementCRD {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> ParseResult<Self> {
        let header = buffer
            .take_obj_front::<raw::Header>()
            .ok_or_else(debug_err_fn!(ParseError::Format, "too few bytes for CRD header"))?;

        if header.struct_type != ConnectionType::DeviceManagement.into() {
            return debug_err!(Err(ParseError::NotExpected), "expected Device Management connection type");
        }

        Ok(DeviceManagementCRD)
    }
}

/// Builder for Device Management CRD
#[derive(Copy, Clone, Debug)]
pub struct DeviceManagementCRDBuilder;

impl SerializablePacket for DeviceManagementCRDBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::Header>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::Header {
            struct_len: mem::size_of::<raw::Header>() as u8,
            struct_type: ConnectionType::DeviceManagement.into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for CRD header");
    }
}

// ============================================================================
// CRI DISPATCH ENUM
// ============================================================================

/// Connection Request Information — dispatched by connection type.
///
/// Follows the same enum-dispatch pattern as [`HPAI`](super::HPAI): the parser
/// peeks at the connection type in the CRI header, then delegates to the
/// appropriate typed parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CRI {
    /// Device Management (0x03)
    DeviceManagement(DeviceManagementCRI),
    /// Tunneling (0x04)
    Tunnel(TunnelingCRI),
    /// Unrecognized connection type — header was consumed, body bytes skipped.
    Unknown(ConnectionType),
}

impl CRI {
    /// The connection type this CRI represents.
    pub fn connection_type(&self) -> ConnectionType {
        match self {
            CRI::DeviceManagement(_) => ConnectionType::DeviceManagement,
            CRI::Tunnel(_) => ConnectionType::Tunnel,
            CRI::Unknown(ct) => *ct,
        }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for CRI {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> ParseResult<Self> {
        // Peek at the CRI header to determine connection type, then delegate
        // to the typed parser (which re-reads and consumes the header).
        let header = buffer
            .peek_obj_front::<raw::Header>()
            .ok_or_else(debug_err_fn!(ParseError::Format, "too few bytes for CRI header"))?;

        let connection_type: ConnectionType = header.struct_type.into();
        let struct_len = header.struct_len as usize;

        match connection_type {
            ConnectionType::DeviceManagement => Ok(CRI::DeviceManagement(DeviceManagementCRI::parse(buffer, ())?)),
            ConnectionType::Tunnel => Ok(CRI::Tunnel(TunnelingCRI::parse(buffer, ())?)),
            other => {
                // Consume the entire CRI structure (header + body)
                let _ = buffer.take_front(struct_len).ok_or_else(debug_err_fn!(
                    ParseError::Format,
                    "too few bytes for unknown CRI (struct_len={})",
                    struct_len
                ))?;
                Ok(CRI::Unknown(other))
            }
        }
    }
}

impl SerializablePacket for CRI {
    fn bytes_len(&self) -> usize {
        match self {
            CRI::DeviceManagement(_) => DeviceManagementCRIBuilder.bytes_len(),
            CRI::Tunnel(cri) => {
                TunnelingCRIBuilder { knx_layer: cri.knx_layer, individual_address: cri.individual_address }.bytes_len()
            }
            CRI::Unknown(_) => {
                // Unknown CRI cannot be serialized meaningfully — just the header
                mem::size_of::<raw::Header>()
            }
        }
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        match self {
            CRI::DeviceManagement(_) => DeviceManagementCRIBuilder.serialize(bv),
            CRI::Tunnel(cri) => {
                let builder =
                    TunnelingCRIBuilder { knx_layer: cri.knx_layer, individual_address: cri.individual_address };
                builder.serialize(bv);
            }
            CRI::Unknown(ct) => {
                let header = raw::Header { struct_len: mem::size_of::<raw::Header>() as u8, struct_type: (*ct).into() };
                bv.write_obj_front(&header).expect("too few bytes for CRI header");
            }
        }
    }
}

// ============================================================================
// CRD DISPATCH ENUM
// ============================================================================

/// Connection Response Data — dispatched by connection type.
///
/// Same enum-dispatch pattern as [`CRI`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CRD {
    /// Device Management (0x03)
    DeviceManagement(DeviceManagementCRD),
    /// Tunneling (0x04)
    Tunnel(TunnelingCRD),
}

impl CRD {
    /// The connection type this CRD represents.
    pub fn connection_type(&self) -> ConnectionType {
        match self {
            CRD::DeviceManagement(_) => ConnectionType::DeviceManagement,
            CRD::Tunnel(_) => ConnectionType::Tunnel,
        }
    }
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for CRD {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> ParseResult<Self> {
        let header = buffer
            .peek_obj_front::<raw::Header>()
            .ok_or_else(debug_err_fn!(ParseError::Format, "too few bytes for CRD header"))?;

        let connection_type: ConnectionType = header.struct_type.into();

        match connection_type {
            ConnectionType::DeviceManagement => Ok(CRD::DeviceManagement(DeviceManagementCRD::parse(buffer, ())?)),
            ConnectionType::Tunnel => Ok(CRD::Tunnel(TunnelingCRD::parse(buffer, ())?)),
            _ => {
                debug!("unsupported CRD connection type: {:?}", connection_type);
                Err(ParseError::NotSupported)
            }
        }
    }
}

impl SerializablePacket for CRD {
    fn bytes_len(&self) -> usize {
        match self {
            CRD::DeviceManagement(_) => DeviceManagementCRDBuilder.bytes_len(),
            CRD::Tunnel(crd) => TunnelingCRDBuilder::new(crd.individual_address).bytes_len(),
        }
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        match self {
            CRD::DeviceManagement(_) => DeviceManagementCRDBuilder.serialize(bv),
            CRD::Tunnel(crd) => TunnelingCRDBuilder::new(crd.individual_address).serialize(bv),
        }
    }
}
