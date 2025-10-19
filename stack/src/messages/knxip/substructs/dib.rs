use core::mem;
use core::net::Ipv4Addr;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, SplitByteSlice, SplitByteSliceMut, Unaligned};

use crate::address::IndividualAddress;
use crate::util::packets::{
    BufferView, BufferViewMut, ParsablePacket, SerializablePacket,
    records::{
        ParsedRecord, RecordBuilder, RecordParseResult, RecordSequenceBuilder, Records, RecordsImpl, RecordsImplLayout,
    },
};

use crate::messages::knxip::error::{ParseError, ParseResult};
use crate::messages::knxip::messages::KNXnetIPServiceFamily;

use platform::address::EthernetAddress;
use zerocopy::big_endian::U16;

macro_rules! debug_err {
    ($err:expr, $($arg:tt)*) => (
        {
            debug!($($arg)*);
            $err
        }
    )
}

// ============================================================================
// INTERNAL WIRE FORMAT - ZEROCOPY TYPES
// ============================================================================

mod raw {
    use super::*;

    /// Wire format for DIB header (2 bytes)
    #[derive(Copy, Clone, Default, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct Header {
        pub struct_len: u8,
        pub description_type_code: u8,
    }

    /// Wire format for Device Information DIB
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct DeviceInformationData {
        pub medium: u8,
        pub device_status: u8,
        pub individual_address: IndividualAddress,
        pub project_installation_identifier: U16,
        pub knx_serial_number: [u8; 6],
        pub routing_multicast_address: [u8; 4],
        pub mac_address: EthernetAddress,
        pub friendly_name: [u8; 30],
    }

    /// Wire format for a single supported service record (2 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct SupportedServiceRecord {
        pub family: u8,
        pub version: u8,
    }

    /// Wire format for IP Config DIB
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct IPConfigData {
        pub ip_address: [u8; 4],
        pub subnet_mask: [u8; 4],
        pub default_gateway: [u8; 4],
        pub ip_capabilities: u8,
        pub ip_assignment_method: u8,
    }

    /// Wire format for IP Current Config DIB
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct IPCurrentConfigData {
        pub ip_address: [u8; 4],
        pub subnet_mask: [u8; 4],
        pub default_gateway: [u8; 4],
        pub dhcp_server: [u8; 4],
        pub ip_assignment_method: u8,
        pub _reserved: u8,
    }

    /// Wire format for KNX Addresses DIB (fixed part)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct KNXAddressesData {
        pub individual_address: IndividualAddress,
    }

    /// Wire format for Manufacturer Data DIB
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct ManufacturerDataData {
        pub manufacturer_id: U16,
    }

    /// Wire format for Tunneling Information DIB (fixed part)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct TunnelingInformationData {
        pub max_local_apdu_len: U16,
    }

    /// Wire format for a single tunneling slot info record (4 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub(super) struct TunnelingSlotInfoRecord {
        pub individual_address: IndividualAddress,
        pub status: U16,
    }
}

// ============================================================================
// PROTOCOL ENUMS
// ============================================================================

create_protocol_enum!(
    /// KNX medium used in a Device Information DIB
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum KNXMedium: u8 {
        TP1, 0x02, "TP1";
        PL110, 0x04, "PL110";
        RF, 0x10, "RF";
        KNXIP, 0x20, "KNX/IP";
        _, "Unknown Medium 0x{:x}";
    }
);

create_protocol_enum!(
    /// Device status used in a Device Information DIB
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum DeviceStatus: u8 {
        None, 0x00, "None";
        ProgrammingMode, 0x01, "Programming Mode";
        _, "Unknown Status 0x{:x}";
    }
);

create_protocol_enum!(
    #[allow(missing_docs)]
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
    pub enum ServiceFamily: u8 {
        Core, 0x02, "Core";
        DeviceManagement, 0x03, "Device Management";
        Tunneling, 0x04, "Tunneling";
        Routing, 0x05, "Routing";
        RemoteLogging, 0x06, "Remote Logging";
        RemoteConfigAndDiag, 0x07, "Remote Configuration and Diagnosis";
        ObjectServer, 0x08, "Object Server";
        Security, 0x09, "Security";
        _, "Unknown Service Family 0x{:x}";
    }
);

// ============================================================================
// PUBLIC API - OWNED/BORROWED TYPES
// ============================================================================

/// Device Information DIB
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInformation {
    pub medium: KNXMedium,
    pub device_status: DeviceStatus,
    pub individual_address: IndividualAddress,
    pub project_installation_identifier: u16,
    pub knx_serial_number: [u8; 6],
    pub routing_multicast_address: Ipv4Addr,
    pub mac_address: EthernetAddress,
    pub friendly_name: [u8; 30],
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for DeviceInformation {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<raw::Header>().ok_or(ParseError::Format)?;

        if header.description_type_code != KNXnetIPServiceFamily::DeviceInfo.into() {
            return Err(ParseError::Format);
        }

        let data = buffer.take_obj_front::<raw::DeviceInformationData>().ok_or(ParseError::Format)?;

        Ok(Self {
            medium: data.medium.into(),
            device_status: data.device_status.into(),
            individual_address: data.individual_address,
            project_installation_identifier: data.project_installation_identifier.get(),
            knx_serial_number: data.knx_serial_number,
            routing_multicast_address: data.routing_multicast_address.into(),
            mac_address: data.mac_address,
            friendly_name: data.friendly_name,
        })
    }
}

impl DeviceInformation {
    /// Get the description type code
    pub fn description_type_code(&self) -> KNXnetIPServiceFamily {
        KNXnetIPServiceFamily::DeviceInfo
    }
}

impl SerializablePacket for DeviceInformation {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::Header>() + mem::size_of::<raw::DeviceInformationData>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::Header {
            struct_len: self.bytes_len() as u8,
            description_type_code: KNXnetIPServiceFamily::DeviceInfo.into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for DIB header");

        let data = raw::DeviceInformationData {
            medium: self.medium.into(),
            device_status: self.device_status.into(),
            individual_address: self.individual_address,
            project_installation_identifier: self.project_installation_identifier.into(),
            knx_serial_number: self.knx_serial_number,
            routing_multicast_address: self.routing_multicast_address.octets(),
            mac_address: self.mac_address,
            friendly_name: self.friendly_name,
        };
        bv.write_obj_front(&data).expect("too few bytes for device information data");
    }
}

/// A single supported service
//FIXME: Do we want this to be zerocopyable like the other structs?
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct SupportedService {
    pub family: ServiceFamily,
    pub version: u8,
}

// Records implementation for parsing SupportedService entries
#[derive(Debug)]
pub struct SupportedServicesRecordImpl;

impl RecordsImplLayout for SupportedServicesRecordImpl {
    type Context = ();
    type Error = ParseError;
}

impl RecordsImpl for SupportedServicesRecordImpl {
    type Record<'a> = SupportedService;

    fn parse_with_context<'a, BV: BufferView<&'a [u8]>>(
        data: &mut BV,
        _context: &mut (),
    ) -> RecordParseResult<Self::Record<'a>, Self::Error> {
        if data.is_empty() {
            return Ok(ParsedRecord::Done);
        }

        let family = data.take_byte_front().ok_or(ParseError::Format)?.into();
        let version = data.take_byte_front().ok_or(ParseError::Format)?;

        Ok(ParsedRecord::Parsed(SupportedService { family, version }))
    }
}

impl RecordBuilder for SupportedService {
    fn serialized_len(&self) -> usize {
        2
    }

    fn serialize_into(&self, data: &mut [u8]) {
        let mut data = &mut &mut data[..];

        let mut f: Ref<_, u8> = data.take_obj_front_zero().expect("Buffer not long enough");
        *f = self.family.into();

        let mut v: Ref<_, u8> = data.take_obj_front_zero().expect("Buffer not long enough");
        *v = self.version;
    }
}

pub type SupportedServicesRecords<B> = Records<B, SupportedServicesRecordImpl>;

/// Supported Service Families DIB
///
/// Uses Records for zero-copy parsing of service entries
#[derive(Debug)]
pub struct SupportedServiceFamilies<B: SplitByteSlice> {
    records: SupportedServicesRecords<B>,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for SupportedServiceFamilies<B> {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<raw::Header>().ok_or(ParseError::Format)?;

        if header.description_type_code != KNXnetIPServiceFamily::SupportedServiceFamilies.into() {
            return Err(ParseError::Format);
        }

        let expected_len = header.struct_len as usize - mem::size_of::<raw::Header>();
        let services_bytes = buffer.take_front(expected_len).ok_or(ParseError::Format)?;

        let records = SupportedServicesRecords::parse(services_bytes)?;

        Ok(Self { records })
    }
}

impl<B: SplitByteSlice> SupportedServiceFamilies<B> {
    /// Get the description type code
    pub fn description_type_code(&self) -> KNXnetIPServiceFamily {
        KNXnetIPServiceFamily::SupportedServiceFamilies
    }

    /// Iterate over services
    pub fn iter(&self) -> impl Iterator<Item = SupportedService> + '_ {
        self.records.iter()
    }

    /// Count of services
    pub fn count(&self) -> usize {
        self.records.iter().count()
    }
}

/// Builder for Supported Service Families DIB
pub struct SupportedServiceFamiliesBuilder<'a> {
    services: &'a [SupportedService],
}

impl<'a> SupportedServiceFamiliesBuilder<'a> {
    pub fn new(services: &'a [SupportedService]) -> Self {
        Self { services }
    }
}

impl<'a> SerializablePacket for SupportedServiceFamiliesBuilder<'a> {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::Header>() + self.services.iter().map(|s| s.serialized_len()).sum::<usize>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::Header {
            struct_len: self.bytes_len() as u8,
            description_type_code: KNXnetIPServiceFamily::SupportedServiceFamilies.into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for DIB header");

        let records_builder: RecordSequenceBuilder<SupportedService, _> =
            RecordSequenceBuilder::new(self.services.iter());
        records_builder.serialize(bv);
    }
}

/// IP Configuration DIB
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpConfig {
    pub ip_address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub default_gateway: Ipv4Addr,
    pub ip_capabilities: u8,
    pub ip_assignment_method: u8,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for IpConfig {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<raw::Header>().ok_or(ParseError::Format)?;

        if header.description_type_code != KNXnetIPServiceFamily::IPConfig.into() {
            return Err(ParseError::Format);
        }

        let data = buffer.take_obj_front::<raw::IPConfigData>().ok_or(ParseError::Format)?;

        Ok(Self {
            ip_address: data.ip_address.into(),
            subnet_mask: data.subnet_mask.into(),
            default_gateway: data.default_gateway.into(),
            ip_capabilities: data.ip_capabilities,
            ip_assignment_method: data.ip_assignment_method,
        })
    }
}

impl IpConfig {
    /// Get the description type code
    pub fn description_type_code(&self) -> KNXnetIPServiceFamily {
        KNXnetIPServiceFamily::IPConfig
    }
}

impl SerializablePacket for IpConfig {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::Header>() + mem::size_of::<raw::IPConfigData>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::Header {
            struct_len: self.bytes_len() as u8,
            description_type_code: KNXnetIPServiceFamily::IPConfig.into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for DIB header");

        let data = raw::IPConfigData {
            ip_address: self.ip_address.octets(),
            subnet_mask: self.subnet_mask.octets(),
            default_gateway: self.default_gateway.octets(),
            ip_capabilities: self.ip_capabilities,
            ip_assignment_method: self.ip_assignment_method,
        };
        bv.write_obj_front(&data).expect("too few bytes for IP config data");
    }
}

/// IP Current Configuration DIB
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCurrentConfig {
    pub ip_address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub default_gateway: Ipv4Addr,
    pub dhcp_server: Ipv4Addr,
    pub ip_assignment_method: u8,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for IpCurrentConfig {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<raw::Header>().ok_or(ParseError::Format)?;

        if header.description_type_code != KNXnetIPServiceFamily::IPCurrentConfig.into() {
            return Err(ParseError::Format);
        }

        let data = buffer.take_obj_front::<raw::IPCurrentConfigData>().ok_or(ParseError::Format)?;

        Ok(Self {
            ip_address: data.ip_address.into(),
            subnet_mask: data.subnet_mask.into(),
            default_gateway: data.default_gateway.into(),
            dhcp_server: data.dhcp_server.into(),
            ip_assignment_method: data.ip_assignment_method,
        })
    }
}

impl IpCurrentConfig {
    /// Get the description type code
    pub fn description_type_code(&self) -> KNXnetIPServiceFamily {
        KNXnetIPServiceFamily::IPCurrentConfig
    }
}

impl SerializablePacket for IpCurrentConfig {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::Header>() + mem::size_of::<raw::IPCurrentConfigData>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::Header {
            struct_len: self.bytes_len() as u8,
            description_type_code: KNXnetIPServiceFamily::IPCurrentConfig.into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for DIB header");

        let data = raw::IPCurrentConfigData {
            ip_address: self.ip_address.octets(),
            subnet_mask: self.subnet_mask.octets(),
            default_gateway: self.default_gateway.octets(),
            dhcp_server: self.dhcp_server.octets(),
            ip_assignment_method: self.ip_assignment_method,
            _reserved: 0,
        };
        bv.write_obj_front(&data).expect("too few bytes for IP current config data");
    }
}

// ============================================================================
// KNX Addresses DIB with Records
// ============================================================================

// Records implementation for parsing IndividualAddress entries
#[derive(Debug)]
pub struct AdditionalIndividualAddressesRecordImpl;

impl RecordsImplLayout for AdditionalIndividualAddressesRecordImpl {
    type Context = ();
    type Error = ParseError;
}

impl RecordsImpl for AdditionalIndividualAddressesRecordImpl {
    type Record<'a> = Ref<&'a [u8], IndividualAddress>;

    fn parse_with_context<'a, BV: BufferView<&'a [u8]>>(
        data: &mut BV,
        _context: &mut (),
    ) -> RecordParseResult<Self::Record<'a>, Self::Error> {
        if data.is_empty() {
            return Ok(ParsedRecord::Done);
        }

        Ok(ParsedRecord::Parsed(data.take_obj_front::<IndividualAddress>().ok_or(ParseError::Format)?))
    }
}

impl RecordBuilder for IndividualAddress {
    fn serialized_len(&self) -> usize {
        mem::size_of::<IndividualAddress>()
    }

    fn serialize_into(&self, data: &mut [u8]) {
        let mut data = &mut &mut data[..];
        data.write_obj_front(self).expect("Buffer not long enough");
    }
}

pub type AdditionalIndividualAddressesRecords<B> = Records<B, AdditionalIndividualAddressesRecordImpl>;

/// KNX Addresses DIB
///
/// Contains a primary address and additional addresses (borrowed slice)
#[derive(Debug)]
pub struct KnxAddresses<B: SplitByteSlice> {
    pub individual_address: IndividualAddress,
    additional_addresses: AdditionalIndividualAddressesRecords<B>,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for KnxAddresses<B> {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<raw::Header>().ok_or(ParseError::Format)?;

        if header.description_type_code != KNXnetIPServiceFamily::KNXAddresses.into() {
            return Err(ParseError::Format);
        }

        let data = buffer.take_obj_front::<raw::KNXAddressesData>().ok_or(ParseError::Format)?;

        let expected_len =
            header.struct_len as usize - mem::size_of::<raw::Header>() - mem::size_of::<raw::KNXAddressesData>();
        let addresses_bytes = buffer.take_front(expected_len).ok_or(ParseError::Format)?;

        let additional_addresses = AdditionalIndividualAddressesRecords::parse(addresses_bytes)?;

        Ok(Self { individual_address: data.individual_address, additional_addresses })
    }
}

impl<B: SplitByteSlice> KnxAddresses<B> {
    /// Get the description type code
    pub fn description_type_code(&self) -> KNXnetIPServiceFamily {
        KNXnetIPServiceFamily::KNXAddresses
    }

    /// Iterate over additional addresses
    pub fn additional_addresses_iter(&self) -> impl Iterator<Item = Ref<&[u8], IndividualAddress>> + '_ {
        self.additional_addresses.iter()
    }

    /// Count of additional addresses
    pub fn additional_count(&self) -> usize {
        self.additional_addresses.iter().count()
    }
}

/// Builder for KNX Addresses DIB
pub struct KnxAddressesBuilder<'a> {
    individual_address: IndividualAddress,
    additional_addresses: &'a [IndividualAddress],
}

impl<'a> KnxAddressesBuilder<'a> {
    pub fn new(individual_address: IndividualAddress, additional_addresses: &'a [IndividualAddress]) -> Self {
        Self { individual_address, additional_addresses }
    }
}

impl<'a> SerializablePacket for KnxAddressesBuilder<'a> {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::Header>()
            + mem::size_of::<raw::KNXAddressesData>()
            + self.additional_addresses.iter().map(|a| a.serialized_len()).sum::<usize>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::Header {
            struct_len: self.bytes_len() as u8,
            description_type_code: KNXnetIPServiceFamily::KNXAddresses.into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for DIB header");

        let data = raw::KNXAddressesData { individual_address: self.individual_address };
        bv.write_obj_front(&data).expect("too few bytes for KNX addresses data");

        // RecordSequenceBuilder properly consumes from BufferView
        let records_builder: RecordSequenceBuilder<IndividualAddress, _> =
            RecordSequenceBuilder::new(self.additional_addresses.iter());
        records_builder.serialize(bv);
    }
}

/// Manufacturer Data DIB
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManufacturerData {
    pub manufacturer_id: u16,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for ManufacturerData {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<raw::Header>().ok_or(ParseError::Format)?;

        if header.description_type_code != KNXnetIPServiceFamily::ManufacturerData.into() {
            return Err(ParseError::Format);
        }

        let data = buffer.take_obj_front::<raw::ManufacturerDataData>().ok_or(ParseError::Format)?;

        Ok(Self { manufacturer_id: data.manufacturer_id.get() })
    }
}

impl ManufacturerData {
    /// Get the description type code
    pub fn description_type_code(&self) -> KNXnetIPServiceFamily {
        KNXnetIPServiceFamily::ManufacturerData
    }
}

impl SerializablePacket for ManufacturerData {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::Header>() + mem::size_of::<raw::ManufacturerDataData>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::Header {
            struct_len: self.bytes_len() as u8,
            description_type_code: KNXnetIPServiceFamily::ManufacturerData.into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for DIB header");

        let data = raw::ManufacturerDataData { manufacturer_id: self.manufacturer_id.into() };
        bv.write_obj_front(&data).expect("too few bytes for manufacturer data");
    }
}

// ============================================================================
// Tunneling Information DIB with Records
// ============================================================================

/// A single tunneling slot info
#[derive(Debug, Copy, Clone, Eq, PartialEq, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
#[repr(C)]
pub struct TunnelingSlotInfo {
    pub individual_address: IndividualAddress,
    pub status: U16,
}

// Records implementation for parsing TunnelingSlotInfo entries
#[derive(Debug)]
pub struct TunnelingSlotInfoRecordImpl;

impl RecordsImplLayout for TunnelingSlotInfoRecordImpl {
    type Context = ();
    type Error = ParseError;
}

impl RecordsImpl for TunnelingSlotInfoRecordImpl {
    type Record<'a> = Ref<&'a [u8], TunnelingSlotInfo>;

    fn parse_with_context<'a, BV: BufferView<&'a [u8]>>(
        data: &mut BV,
        _context: &mut (),
    ) -> RecordParseResult<Self::Record<'a>, Self::Error> {
        if data.is_empty() {
            return Ok(ParsedRecord::Done);
        }

        Ok(ParsedRecord::Parsed(data.take_obj_front::<TunnelingSlotInfo>().ok_or(ParseError::Format)?))
    }
}

impl RecordBuilder for TunnelingSlotInfo {
    fn serialized_len(&self) -> usize {
        mem::size_of::<TunnelingSlotInfo>()
    }

    fn serialize_into(&self, data: &mut [u8]) {
        let mut data = &mut &mut data[..];
        data.write_obj_front(self).expect("Buffer not long enough");
    }
}

pub type TunnelingSlotInfoRecords<B> = Records<B, TunnelingSlotInfoRecordImpl>;

/// Tunneling Information DIB
///
/// Uses Records for zero-copy parsing of slot info
#[derive(Debug)]
pub struct TunnelingInfo<B: SplitByteSlice> {
    pub max_local_apdu_len: u16,
    slots: TunnelingSlotInfoRecords<B>,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for TunnelingInfo<B> {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> Result<Self, Self::Error> {
        let header = buffer.take_obj_front::<raw::Header>().ok_or(ParseError::Format)?;

        if header.description_type_code != KNXnetIPServiceFamily::TunnelingInfo.into() {
            return Err(ParseError::Format);
        }

        let data = buffer.take_obj_front::<raw::TunnelingInformationData>().ok_or(ParseError::Format)?;

        let expected_len = header.struct_len as usize
            - mem::size_of::<raw::Header>()
            - mem::size_of::<raw::TunnelingInformationData>();
        let slots_bytes = buffer.take_front(expected_len).ok_or(ParseError::Format)?;

        let slots = TunnelingSlotInfoRecords::parse(slots_bytes)?;

        Ok(Self { max_local_apdu_len: data.max_local_apdu_len.get(), slots })
    }
}

impl<B: SplitByteSlice> TunnelingInfo<B> {
    /// Get the description type code
    pub fn description_type_code(&self) -> KNXnetIPServiceFamily {
        KNXnetIPServiceFamily::TunnelingInfo
    }

    /// Iterate over slot info
    pub fn slots_iter(&self) -> impl Iterator<Item = Ref<&[u8], TunnelingSlotInfo>> + '_ {
        self.slots.iter()
    }

    /// Count of slots
    pub fn slot_count(&self) -> usize {
        self.slots.iter().count()
    }
}

/// Builder for Tunneling Info DIB
pub struct TunnelingInfoBuilder<'a> {
    max_local_apdu_len: u16,
    slots: &'a [TunnelingSlotInfo],
}

impl<'a> TunnelingInfoBuilder<'a> {
    pub fn new(max_local_apdu_len: u16, slots: &'a [TunnelingSlotInfo]) -> Self {
        Self { max_local_apdu_len, slots }
    }
}

impl<'a> SerializablePacket for TunnelingInfoBuilder<'a> {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::Header>()
            + mem::size_of::<raw::TunnelingInformationData>()
            + self.slots.len() * mem::size_of::<TunnelingSlotInfo>()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::Header {
            struct_len: self.bytes_len() as u8,
            description_type_code: KNXnetIPServiceFamily::TunnelingInfo.into(),
        };
        bv.write_obj_front(&header).expect("too few bytes for DIB header");

        let data = raw::TunnelingInformationData { max_local_apdu_len: self.max_local_apdu_len.into() };
        bv.write_obj_front(&data).expect("too few bytes for tunneling info data");

        let records_builder: RecordSequenceBuilder<TunnelingSlotInfo, _> =
            RecordSequenceBuilder::new(self.slots.iter());
        records_builder.serialize(bv);
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/// Peek at a DIB header to see what description type code is present.
///
/// This can be used to determine which DIB type to parse.
pub fn peek_description_type_code(bytes: &[u8]) -> ParseResult<KNXnetIPServiceFamily> {
    let (hdr, _) = Ref::<_, raw::Header>::from_prefix(bytes)
        .map_err(|_| debug_err!(ParseError::Format, "too few bytes for DIB header"))?;

    KNXnetIPServiceFamily::try_from(hdr.description_type_code).map_err(|_| {
        debug_err!(ParseError::NotSupported, "unrecognized DIB description type code: {:x}", hdr.description_type_code)
    })
}

/// Peek at a DIB header to get the structure length
pub fn peek_dib_structure_length(bytes: &[u8]) -> ParseResult<u8> {
    let (hdr, _) = Ref::<_, raw::Header>::from_prefix(bytes)
        .map_err(|_| debug_err!(ParseError::Format, "too few bytes for DIB header"))?;

    Ok(hdr.struct_len)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::packets::{ParseBuffer, SerializeBuffer};

    #[test]
    fn test_device_info_parse() {
        let data = [
            54, 1, // header: length=54, type=DeviceInfo
            2, // medium=TP1
            0, // device_status=None
            0x11, 0x00, // individual_address
            0x00, 0x00, // project_installation_identifier
            0, 0, 0, 0, 0, 0, // serial number
            192, 168, 1, 1, // routing multicast address
            0, 0, 0, 0, 0, 0, // mac address
            // friendly name (30 bytes)
            b'T', b'e', b's', b't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let dib: DeviceInformation = (&data[..]).parse().unwrap();
        assert_eq!(dib.medium, KNXMedium::TP1);
        assert_eq!(dib.device_status, DeviceStatus::None);
    }

    #[test]
    fn test_supported_services_parse() {
        let data = [
            6, 2, // header: length=6, type=SupportedServiceFamilies
            2, 1, // Core version 1
            4, 2, // Tunneling version 2
        ];

        let mut slice = &data[..];
        let dib: SupportedServiceFamilies<_> = slice.parse().unwrap();
        assert_eq!(dib.count(), 2);

        let services: Vec<_> = dib.iter().collect();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].family, ServiceFamily::Core);
        assert_eq!(services[0].version, 1);
        assert_eq!(services[1].family, ServiceFamily::Tunneling);
        assert_eq!(services[1].version, 2);
    }

    #[test]
    fn test_supported_services_serialize() {
        let services = [SupportedService { family: ServiceFamily::Core, version: 1 }, SupportedService {
            family: ServiceFamily::Tunneling,
            version: 2,
        }];

        let builder = SupportedServiceFamiliesBuilder::new(&services);

        let mut buf = [0u8; 64];
        let mut slice = &mut buf[..];
        let (written, _remaining) = slice.serialize(&builder);

        assert_eq!(written, &[
            6, 2, // header
            2, 1, // Core v1
            4, 2, // Tunneling v2
        ]);
    }

    #[test]
    fn test_ip_config_round_trip() {
        let original = IpConfig {
            ip_address: "192.168.1.100".parse().unwrap(),
            subnet_mask: "255.255.255.0".parse().unwrap(),
            default_gateway: "192.168.1.1".parse().unwrap(),
            ip_capabilities: 0x0F,
            ip_assignment_method: 0x01,
        };

        let mut buf = [0u8; 64];
        let mut slice = &mut buf[..];
        let (written, _) = slice.serialize(&original);

        let mut bytes = &written[..];
        let parsed: IpConfig = bytes.parse().unwrap();
        assert_eq!(parsed, original);
    }
}
