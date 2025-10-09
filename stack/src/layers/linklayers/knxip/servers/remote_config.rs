use super::{ServerError, ServerInterest};
use crate::layers::linklayers::knxip::EndpointType;
use core::net::Ipv4Addr;

// KNX/IP Remote configuration service type identifiers
const REMOTE_DIAGNOSTIC_REQUEST: u16 = 0x0740;
const REMOTE_DIAGNOSTIC_RESPONSE: u16 = 0x0741;
const REMOTE_BASIC_CONFIGURATION_REQUEST: u16 = 0x0742;
const REMOTE_RESET_REQUEST: u16 = 0x0743;

// KNX/IP standard multicast address
const KNX_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);
const KNX_PORT: u16 = 3671;

#[derive(Debug, Clone, Copy)]
pub struct RemoteConfigurationServer {
    interests: [ServerInterest; 6],
    // FIXME: Add what we need to send device info etc.
}

impl RemoteConfigurationServer {
    /// Create a new RemoteConfigurationServer
    ///
    /// Remote configuration messages are received on both multicast and broadcast,
    /// so the local HPAI is not used for this server.
    pub fn new(_local_hpai: EndpointType) -> Self {
        RemoteConfigurationServer {
            interests: [
                ServerInterest::new(
                    REMOTE_DIAGNOSTIC_REQUEST,
                    EndpointType::new_udp_multicast(KNX_MULTICAST_ADDR, KNX_PORT),
                ),
                ServerInterest::new(
                    REMOTE_BASIC_CONFIGURATION_REQUEST,
                    EndpointType::new_udp_multicast(KNX_MULTICAST_ADDR, KNX_PORT),
                ),
                ServerInterest::new(
                    REMOTE_RESET_REQUEST,
                    EndpointType::new_udp_multicast(KNX_MULTICAST_ADDR, KNX_PORT),
                ),
                ServerInterest::new(REMOTE_DIAGNOSTIC_REQUEST, EndpointType::new_udp_broadcast(KNX_PORT)),
                ServerInterest::new(REMOTE_BASIC_CONFIGURATION_REQUEST, EndpointType::new_udp_broadcast(KNX_PORT)),
                ServerInterest::new(REMOTE_RESET_REQUEST, EndpointType::new_udp_broadcast(KNX_PORT)),
            ],
        }
    }
}

impl super::KnxServer for RemoteConfigurationServer {
    const N_INTERESTS: usize = 6;

    /// Returns the list of service codes and endpoints this server is interested in
    fn interests(&self) -> &[ServerInterest; Self::N_INTERESTS] {
        &self.interests
    }

    fn handle_message(&self, service_code: u16, _data: &[u8]) -> Result<(), ServerError> {
        trace!("Remote configuration server handling service code 0x{:04x}", service_code);
        // TODO: Implement discovery protocol handling
        Ok(())
    }
}
