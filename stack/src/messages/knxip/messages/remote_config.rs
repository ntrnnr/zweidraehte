//! KNX/IP Remote Diagnostic and Configuration Messages (KNX 3/8/7)
//!
//! Four service types for connectionless remote diagnostics:
//!
//! - `RemoteDiagnosticRequest` (0x0740): Query device diagnostics
//! - `RemoteDiagnosticResponse` (0x0741): Response with DIBs
//! - `RemoteBasicConfigurationRequest` (0x0742): Write IP configuration
//! - `RemoteResetRequest` (0x0743): Restart or master-reset a device

use core::mem;

use zerocopy::{SplitByteSlice, SplitByteSliceMut, big_endian::U16};

use crate::{
    messages::knxip::error::*,
    util::packets::{*, records::RecordSequenceBuilder},
};

use super::{
    super::substructs::{
        DescriptionInformationBlockBuilder, DibRecords, HPAI, Selector,
    },
    KNXnetIPServiceType, KNXnetIPVersion, raw,
};

// ============================================================================
// REMOTE DIAGNOSTIC REQUEST (0x0740)
// ============================================================================

/// KNXnet/IP REMOTE_DIAGNOSTIC_REQUEST (KNX 3/8/7 §4.4.1)
///
/// Sent on multicast or broadcast to query diagnostic information from
/// devices matching the selector. Devices respond with a
/// `RemoteDiagnosticResponse`.
///
/// Wire format: KNXnet/IP header + HPAI + Selector
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDiagnosticRequest {
    /// Endpoint for the response (0.0.0.0 = use packet source IP)
    pub discovery_endpoint: HPAI,
    /// Which devices should respond
    pub selector: Selector,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for RemoteDiagnosticRequest {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> ParseResult<Self> {
        let header = buffer
            .take_obj_front::<raw::KNXnetIPHeader>()
            .ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get())
            .map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::RemoteDiagnosticRequest
        {
            return Err(ParseError::Format);
        }

        let discovery_endpoint = HPAI::parse(buffer, ())?;
        let selector = Selector::parse(buffer, ())?;

        Ok(RemoteDiagnosticRequest { discovery_endpoint, selector })
    }
}

/// Builder for RemoteDiagnosticRequest
pub struct RemoteDiagnosticRequestBuilder {
    pub discovery_endpoint: HPAI,
    pub selector: Selector,
}

impl RemoteDiagnosticRequestBuilder {
    pub fn new(discovery_endpoint: HPAI, selector: Selector) -> Self {
        Self { discovery_endpoint, selector }
    }
}

impl SerializablePacket for RemoteDiagnosticRequestBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::KNXnetIPHeader>()
            + self.discovery_endpoint.bytes_len()
            + self.selector.bytes_len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::KNXnetIPHeader {
            header_size: mem::size_of::<raw::KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::RemoteDiagnosticRequest)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header)
            .expect("too few bytes for KNXnet/IP header");

        self.discovery_endpoint.serialize(bv);
        self.selector.serialize(bv);
    }
}

// ============================================================================
// REMOTE DIAGNOSTIC RESPONSE (0x0741)
// ============================================================================

/// KNXnet/IP REMOTE_DIAGNOSTIC_RESPONSE (KNX 3/8/7 §4.4.2)
///
/// Sent in response to `RemoteDiagnosticRequest` or
/// `RemoteBasicConfigurationRequest`. Contains the selector that was matched
/// and mandatory DIBs: IP_CONFIG (0x03), IP_CUR_CONFIG (0x04),
/// KNX_ADDRESSES (0x05).
///
/// Wire format: KNXnet/IP header + Selector + DIBs
#[derive(Debug)]
pub struct RemoteDiagnosticResponse<B: SplitByteSlice = &'static [u8]> {
    pub selector: Selector,
    pub dibs: DibRecords<B>,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for RemoteDiagnosticResponse<B> {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> ParseResult<Self> {
        let header = buffer
            .take_obj_front::<raw::KNXnetIPHeader>()
            .ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get())
            .map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::RemoteDiagnosticResponse
        {
            return Err(ParseError::Format);
        }

        let selector = Selector::parse(buffer, ())?;

        let dibs = DibRecords::parse(buffer.take_rest_front())?;

        Ok(RemoteDiagnosticResponse { selector, dibs })
    }
}

/// Builder for RemoteDiagnosticResponse
pub struct RemoteDiagnosticResponseBuilder<'a> {
    pub selector: Selector,
    pub dibs: &'a [DescriptionInformationBlockBuilder<'a>],
}

impl<'a> RemoteDiagnosticResponseBuilder<'a> {
    pub fn new(selector: Selector, dibs: &'a [DescriptionInformationBlockBuilder<'a>]) -> Self {
        Self { selector, dibs }
    }
}

impl<'a> SerializablePacket for RemoteDiagnosticResponseBuilder<'a> {
    fn bytes_len(&self) -> usize {
        let dibs: RecordSequenceBuilder<DescriptionInformationBlockBuilder, _> =
            RecordSequenceBuilder::new(self.dibs.iter());
        mem::size_of::<raw::KNXnetIPHeader>() + self.selector.bytes_len() + dibs.bytes_len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::KNXnetIPHeader {
            header_size: mem::size_of::<raw::KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::RemoteDiagnosticResponse)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header)
            .expect("too few bytes for KNXnet/IP header");

        self.selector.serialize(bv);

        let dibs: RecordSequenceBuilder<DescriptionInformationBlockBuilder, _> =
            RecordSequenceBuilder::new(self.dibs.iter());
        dibs.serialize(bv);
    }
}

// ============================================================================
// REMOTE BASIC CONFIGURATION REQUEST (0x0742)
// ============================================================================

/// KNXnet/IP REMOTE_BASIC_CONFIGURATION_REQUEST (KNX 3/8/7 §4.4.3)
///
/// Sent on multicast or broadcast to write IP configuration to devices
/// matching the selector. The device acknowledges with a
/// `RemoteDiagnosticResponse` containing its current state.
///
/// Wire format: KNXnet/IP header + HPAI + Selector + DIBs
#[derive(Debug)]
pub struct RemoteBasicConfigurationRequest<B: SplitByteSlice = &'static [u8]> {
    /// Endpoint for the response
    pub discovery_endpoint: HPAI,
    /// Which devices should be configured
    pub selector: Selector,
    /// Configuration DIBs to apply (typically IP_CONFIG)
    pub dibs: DibRecords<B>,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for RemoteBasicConfigurationRequest<B> {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> ParseResult<Self> {
        let header = buffer
            .take_obj_front::<raw::KNXnetIPHeader>()
            .ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get())
            .map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::RemoteBasicConfigurationRequest
        {
            return Err(ParseError::Format);
        }

        let discovery_endpoint = HPAI::parse(buffer, ())?;
        let selector = Selector::parse(buffer, ())?;

        let dibs = DibRecords::parse(buffer.take_rest_front())?;

        Ok(RemoteBasicConfigurationRequest { discovery_endpoint, selector, dibs })
    }
}

/// Builder for RemoteBasicConfigurationRequest
pub struct RemoteBasicConfigurationRequestBuilder<'a> {
    pub discovery_endpoint: HPAI,
    pub selector: Selector,
    pub dibs: &'a [DescriptionInformationBlockBuilder<'a>],
}

impl<'a> RemoteBasicConfigurationRequestBuilder<'a> {
    pub fn new(
        discovery_endpoint: HPAI,
        selector: Selector,
        dibs: &'a [DescriptionInformationBlockBuilder<'a>],
    ) -> Self {
        Self { discovery_endpoint, selector, dibs }
    }
}

impl<'a> SerializablePacket for RemoteBasicConfigurationRequestBuilder<'a> {
    fn bytes_len(&self) -> usize {
        let dibs: RecordSequenceBuilder<DescriptionInformationBlockBuilder, _> =
            RecordSequenceBuilder::new(self.dibs.iter());
        mem::size_of::<raw::KNXnetIPHeader>()
            + self.discovery_endpoint.bytes_len()
            + self.selector.bytes_len()
            + dibs.bytes_len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::KNXnetIPHeader {
            header_size: mem::size_of::<raw::KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(
                KNXnetIPServiceType::RemoteBasicConfigurationRequest,
            )),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header)
            .expect("too few bytes for KNXnet/IP header");

        self.discovery_endpoint.serialize(bv);
        self.selector.serialize(bv);

        let dibs: RecordSequenceBuilder<DescriptionInformationBlockBuilder, _> =
            RecordSequenceBuilder::new(self.dibs.iter());
        dibs.serialize(bv);
    }
}

// ============================================================================
// REMOTE RESET REQUEST (0x0743)
// ============================================================================

/// Reset command codes (KNX 3/8/7 §4.7)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResetCommand {
    /// Restart the device (equivalent to power cycle)
    Restart = 0x01,
    /// Master reset — restore factory defaults and restart
    MasterReset = 0x02,
}

impl ResetCommand {
    fn from_u8(value: u8) -> ParseResult<Self> {
        match value {
            0x01 => Ok(ResetCommand::Restart),
            0x02 => Ok(ResetCommand::MasterReset),
            other => {
                debug!("unknown ResetCommand: 0x{:02x}", other);
                Err(ParseError::Format)
            }
        }
    }
}

/// KNXnet/IP REMOTE_RESET_REQUEST (KNX 3/8/7 §4.4.4)
///
/// Sent on multicast or broadcast to restart or factory-reset devices
/// matching the selector. There is no response to this message.
///
/// Wire format: KNXnet/IP header + Selector + ResetCommand(1) + Reserved(1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteResetRequest {
    /// Which devices should be reset
    pub selector: Selector,
    /// The reset command to execute
    pub command: ResetCommand,
}

impl<B: SplitByteSlice> ParsablePacket<B, ()> for RemoteResetRequest {
    type Error = ParseError;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, _args: ()) -> ParseResult<Self> {
        let header = buffer
            .take_obj_front::<raw::KNXnetIPHeader>()
            .ok_or(ParseError::Format)?;

        if KNXnetIPServiceType::try_from(header.service_type.get())
            .map_err(|_| ParseError::NotSupported)?
            != KNXnetIPServiceType::RemoteResetRequest
        {
            return Err(ParseError::Format);
        }

        let selector = Selector::parse(buffer, ())?;

        let command_byte = buffer.take_byte_front().ok_or_else(|| {
            debug!("too few bytes for ResetCommand");
            ParseError::Format
        })?;
        let command = ResetCommand::from_u8(command_byte)?;

        // Reserved byte (§4.4.4: "shall be 0x00")
        let _reserved = buffer.take_byte_front().ok_or_else(|| {
            debug!("too few bytes for reserved byte in RemoteResetRequest");
            ParseError::Format
        })?;

        Ok(RemoteResetRequest { selector, command })
    }
}

/// Builder for RemoteResetRequest
pub struct RemoteResetRequestBuilder {
    pub selector: Selector,
    pub command: ResetCommand,
}

impl RemoteResetRequestBuilder {
    pub fn new(selector: Selector, command: ResetCommand) -> Self {
        Self { selector, command }
    }
}

impl SerializablePacket for RemoteResetRequestBuilder {
    fn bytes_len(&self) -> usize {
        mem::size_of::<raw::KNXnetIPHeader>()
            + self.selector.bytes_len()
            + 2 // command + reserved
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        let header = raw::KNXnetIPHeader {
            header_size: mem::size_of::<raw::KNXnetIPHeader>() as u8,
            version: KNXnetIPVersion::Version10.into(),
            service_type: U16::from(u16::from(KNXnetIPServiceType::RemoteResetRequest)),
            total_length: (self.bytes_len() as u16).into(),
        };
        bv.write_obj_front(&header)
            .expect("too few bytes for KNXnet/IP header");

        self.selector.serialize(bv);

        // Command byte + reserved byte
        let mut tail = bv
            .take_front(2)
            .expect("too few bytes for reset command + reserved");
        tail.deref_mut()[0] = self.command as u8;
        tail.deref_mut()[1] = 0x00;
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::knxip::substructs::*;
    use crate::util::packets::{ParseBuffer, SerializeBuffer};
    use core::net::Ipv4Addr;
    use platform::address::EthernetAddress;

    #[test]
    fn parse_remote_diagnostic_request_prgmode() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            // KNXnet/IP header
            0x06, 0x10, 0x07, 0x40, 0x00, 0x10,
            // HPAI (IPv4 UDP, 192.168.1.100:3671)
            0x08, 0x01, 0xc0, 0xa8, 0x01, 0x64, 0x0e, 0x57,
            // Selector: PrgMode (len=2, type=0x01)
            0x02, 0x01,
        ];

        let mut buf = &data[..];
        let parsed = buf.parse::<RemoteDiagnosticRequest>().unwrap();
        assert_eq!(parsed.discovery_endpoint.address(), Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(parsed.discovery_endpoint.port(), 3671);
        assert_eq!(parsed.selector, Selector::PrgMode);
    }

    #[test]
    fn parse_remote_diagnostic_request_mac() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            // KNXnet/IP header
            0x06, 0x10, 0x07, 0x40, 0x00, 0x16,
            // HPAI
            0x08, 0x01, 0xc0, 0xa8, 0x01, 0x64, 0x0e, 0x57,
            // Selector: MAC (len=8, type=0x02, mac)
            0x08, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];

        let mut buf = &data[..];
        let parsed = buf.parse::<RemoteDiagnosticRequest>().unwrap();
        assert_eq!(
            parsed.selector,
            Selector::Mac(EthernetAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]))
        );
    }

    #[test]
    fn remote_diagnostic_request_round_trip() {
        let original = RemoteDiagnosticRequestBuilder::new(
            HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 50), 3671),
            Selector::PrgMode,
        );

        let mut buf = [0u8; 64];
        let mut cursor = &mut buf[..];
        let (written, _) = cursor.serialize(&original);

        let mut parse_buf = written;
        let parsed = parse_buf.parse::<RemoteDiagnosticRequest>().unwrap();
        assert_eq!(parsed.discovery_endpoint.address(), Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(parsed.selector, Selector::PrgMode);
    }

    #[test]
    fn remote_diagnostic_response_round_trip() {
        let ip_config = IpConfig {
            ip_address: Ipv4Addr::new(192, 168, 1, 100),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            default_gateway: Ipv4Addr::new(192, 168, 1, 1),
            ip_capabilities: 0x07,
            ip_assignment_method: 0x01,
        };

        let ip_current = IpCurrentConfig {
            ip_address: Ipv4Addr::new(192, 168, 1, 100),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            default_gateway: Ipv4Addr::new(192, 168, 1, 1),
            dhcp_server: Ipv4Addr::UNSPECIFIED,
            ip_assignment_method: 0x01,
        };

        use crate::address::IndividualAddress;
        let knx_addr = KnxAddressesBuilder::new(IndividualAddress::new(1, 1, 0), &[]);

        let dibs = [
            DescriptionInformationBlockBuilder::IpConfig(&ip_config),
            DescriptionInformationBlockBuilder::IpCurrentConfig(&ip_current),
            DescriptionInformationBlockBuilder::KnxAddresses(knx_addr),
        ];

        let builder = RemoteDiagnosticResponseBuilder::new(Selector::PrgMode, &dibs);

        let mut buf = [0u8; 256];
        let mut cursor = &mut buf[..];
        let (written, _) = cursor.serialize(&builder);

        let mut parse_buf = written;
        let parsed = parse_buf.parse::<RemoteDiagnosticResponse<_>>().unwrap();

        assert_eq!(parsed.selector, Selector::PrgMode);

        let dibs: Vec<_> = parsed.dibs.iter().collect();
        assert_eq!(dibs.len(), 3);

        // Verify the DIB types are correct
        assert!(matches!(dibs[0], DescriptionInformationBlock::IpConfig(_)));
        assert!(matches!(dibs[1], DescriptionInformationBlock::IpCurrentConfig(_)));
        assert!(matches!(dibs[2], DescriptionInformationBlock::KnxAddresses(_)));

        // Verify IP config data survived the round-trip
        match &dibs[0] {
            DescriptionInformationBlock::IpConfig(config) => {
                assert_eq!(config.ip_address, ip_config.ip_address);
                assert_eq!(config.subnet_mask, ip_config.subnet_mask);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn parse_remote_basic_configuration_request() {
        let ip_config = IpConfig {
            ip_address: Ipv4Addr::new(10, 0, 0, 50),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            default_gateway: Ipv4Addr::new(10, 0, 0, 1),
            ip_capabilities: 0x07,
            ip_assignment_method: 0x04,
        };

        let dibs = [DescriptionInformationBlockBuilder::IpConfig(&ip_config)];

        let mac = EthernetAddress([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let builder = RemoteBasicConfigurationRequestBuilder::new(
            HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 50), 3671),
            Selector::Mac(mac),
            &dibs,
        );

        let mut buf = [0u8; 256];
        let mut cursor = &mut buf[..];
        let (written, _) = cursor.serialize(&builder);

        let mut parse_buf = written;
        let parsed = parse_buf.parse::<RemoteBasicConfigurationRequest<_>>().unwrap();

        assert_eq!(parsed.selector, Selector::Mac(mac));

        let dibs: Vec<_> = parsed.dibs.iter().collect();
        assert_eq!(dibs.len(), 1);
        match &dibs[0] {
            DescriptionInformationBlock::IpConfig(config) => {
                assert_eq!(config.ip_address, Ipv4Addr::new(10, 0, 0, 50));
                assert_eq!(config.ip_assignment_method, 0x04);
            }
            _ => panic!("Expected IpConfig DIB"),
        }
    }

    #[test]
    fn parse_remote_reset_request_restart() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            // KNXnet/IP header
            0x06, 0x10, 0x07, 0x43, 0x00, 0x0c,
            // Selector: PrgMode
            0x02, 0x01,
            // ResetCommand: Restart (0x01) + Reserved (0x00)
            0x01, 0x00,
        ];

        let mut buf = &data[..];
        let parsed = buf.parse::<RemoteResetRequest>().unwrap();
        assert_eq!(parsed.selector, Selector::PrgMode);
        assert_eq!(parsed.command, ResetCommand::Restart);
    }

    #[test]
    fn parse_remote_reset_request_master_reset() {
        let mac = EthernetAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        #[rustfmt::skip]
        let data: &[u8] = &[
            // KNXnet/IP header
            0x06, 0x10, 0x07, 0x43, 0x00, 0x12,
            // Selector: MAC
            0x08, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            // ResetCommand: MasterReset (0x02) + Reserved (0x00)
            0x02, 0x00,
        ];

        let mut buf = &data[..];
        let parsed = buf.parse::<RemoteResetRequest>().unwrap();
        assert_eq!(parsed.selector, Selector::Mac(mac));
        assert_eq!(parsed.command, ResetCommand::MasterReset);
    }

    #[test]
    fn remote_reset_request_round_trip() {
        let original = RemoteResetRequestBuilder::new(Selector::PrgMode, ResetCommand::MasterReset);

        let mut buf = [0u8; 64];
        let mut cursor = &mut buf[..];
        let (written, _) = cursor.serialize(&original);

        let mut parse_buf = written;
        let parsed = parse_buf.parse::<RemoteResetRequest>().unwrap();

        assert_eq!(parsed.selector, Selector::PrgMode);
        assert_eq!(parsed.command, ResetCommand::MasterReset);
    }

    #[test]
    fn parse_unknown_reset_command_fails() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x06, 0x10, 0x07, 0x43, 0x00, 0x0c,
            0x02, 0x01,       // Selector: PrgMode
            0x99, 0x00,       // Unknown command
        ];

        let mut buf = &data[..];
        assert!(buf.parse::<RemoteResetRequest>().is_err());
    }

    #[test]
    fn remote_diagnostic_request_mac_round_trip() {
        let mac = EthernetAddress([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
        let builder = RemoteDiagnosticRequestBuilder::new(
            HPAI::ipv4_udp(Ipv4Addr::UNSPECIFIED, 0),
            Selector::Mac(mac),
        );

        let mut buf = [0u8; 64];
        let mut cursor = &mut buf[..];
        let (written, _) = cursor.serialize(&builder);

        let mut parse_buf = written;
        let parsed = parse_buf.parse::<RemoteDiagnosticRequest>().unwrap();
        assert_eq!(parsed.selector, Selector::Mac(mac));
        // 0.0.0.0 HPAI — server resolves from packet source
        assert!(parsed.discovery_endpoint.address().is_unspecified());
    }
}
