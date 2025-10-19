use core::mem;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, SplitByteSlice, SplitByteSliceMut, Unaligned};

use crate::messages::knxip::error::{ParseError, ParseResult};
use crate::address::IndividualAddress;
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
