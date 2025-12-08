create_protocol_enum!(
    #[allow(missing_docs)]
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum KNXnetIPVersion: u8 {
        Version10, 0x10, "Version 1.0";
        _, "Unknown Version 0x{:x}";
    }
);

create_protocol_enum!(
    #[allow(missing_docs)]
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum KNXnetIPServiceFamily: u8 {
        DeviceInfo, 0x01, "Device Info";
        SupportedServiceFamilies, 0x02, "Supported Service Families";
        IPConfig, 0x03, "IP Config";
        IPCurrentConfig, 0x04, "IP Current Config";
        KNXAddresses, 0x05, "KNX Addresses";
        SecuredServices, 0x06, "Secured Services";
        TunnelingInfo, 0x07, "Tunneling Info";
        ExtendedDeviceInfo, 0x08, "Extended Device Info";
        ManufacturerData, 0xFE, "Manufacturer Data";
        _, "Unknown Description Type 0x{:x}";
    }
);

create_protocol_enum!(
    #[allow(missing_docs)]
    #[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
    pub enum KNXnetIPServiceType: u16 {
        // Core Services (3.8.2)
        SearchRequest, 0x0201, "Search Request";
        SearchResponse, 0x0202, "Search Response";
        DescriptionRequest, 0x0203, "Description Request";
        DescriptionResponse, 0x0204, "Description Response";
        ConnectRequest, 0x0205, "Connect Request";
        ConnectResponse, 0x0206, "Connect Response";
        ConnectionstateRequest, 0x0207, "Connectionstate Request";
        ConnectionstateResponse, 0x0208, "Connectionstate Response";
        DisconnectRequest, 0x0209, "Disconnect Request";
        DisconnectResponse, 0x020a, "Disconnect Response";
        SearchRequestExtended, 0x020b, "Extended Search Request";
        SearchResponseExtended, 0x020c, "Extended Search Response";

        // Device Management (3.8.3)
        DeviceConfigurationRequest, 0x310, "Device Configuration Request";
        DeviceConfigurationAck, 0x311, "Device Configuration ACK";

        // Tunneling (3.8.4)
        TunnelingRequest, 0x0420, "Tunneling Request";
        TunnelingAck, 0x0421, "Tunneling ACK";
        TunnelingFeatureGet, 0x0422, "Tunneling Feature Get";
        TunnelingFeatureResponse, 0x0423, "Tunneling Feature Response";
        TunnelingFeatureSet, 0x0424, "Tunneling Feature Set";
        TunnelingFeatureInfo, 0x0425, "Tunneling Feature Info";

        // Routing (3.8.5)
        RoutingIndication, 0x0530, "Routing Indication";
        RoutingLostMessage, 0x0531, "Routing Lost Message";
        RoutingBusy, 0x0532, "Routing Busy";
        RoutingSystemBroadcast, 0x0533, "Routing System Broadcast";

        // Remote Diagnostic and Configuration (3.8.7)
        RemoteDiagnosticRequest, 0x0740, "Remote Diagnostic Request";
        RemoteDiagnosticResponse, 0x0741, "Remote Diagnostic Response";
        RemoteBasicConfigurationRequest, 0x0742, "Remote Basic Configuration Request";
        RemoteResetRequest, 0x0743, "Remote Reset Request";

        // Secure (3.8.9)
        SecureWrapper, 0x0950, "Secure Wrapper";
        SessionRequest, 0x0951, "Session Request";
        SessionResponse, 0x0952, "Session Response";
        SessionAuthenticate, 0x0953, "Session Authenticate";
        SessionStatus, 0x0954, "Session Status";
        TimerNotify, 0x0955, "Timer Notify";

        _, "Unknown Service Type 0x{:x}";
    }
);

impl Default for KNXnetIPServiceType {
    fn default() -> Self {
        KNXnetIPServiceType::Other(0)
    }
}

// ============================================================================
// SHARED WIRE FORMAT - ZEROCOPY TYPES
// ============================================================================

pub(super) mod raw {
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian::U16};

    /// Wire format for KNXnet/IP header (6 bytes)
    #[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
    #[repr(C)]
    pub struct KNXnetIPHeader {
        pub header_size: u8,
        pub version: u8,
        pub service_type: U16,
        pub total_length: U16,
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

use crate::messages::knxip::error::{ParseError, ParseResult};
use core::mem;

/// Peek at the service type in a KNXnet/IP header
pub fn peek_service_type(bytes: &[u8]) -> ParseResult<KNXnetIPServiceType> {
    if bytes.len() < mem::size_of::<raw::KNXnetIPHeader>() {
        return Err(ParseError::Format);
    }

    let service_type = u16::from_be_bytes([bytes[2], bytes[3]]);
    KNXnetIPServiceType::try_from(service_type).map_err(|_| ParseError::NotSupported)
}

mod discovery;
mod routing;
mod tunneling;

//pub use crate::messages::knxip::substructs::*;
pub use discovery::*;
pub use routing::*;
pub use tunneling::*;
