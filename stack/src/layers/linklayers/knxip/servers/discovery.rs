use core::net::Ipv4Addr;

use crate::{layers::linklayers::knxip::EndpointType, messages::knxip::KNXnetIPServiceType};

use super::{ServerError, ServerInterest};

// KNX/IP standard multicast address
const KNX_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);
const KNX_PORT: u16 = 3671;

#[derive(Debug, Clone, Copy)]
pub struct DiscoveryServer {
    interests: [ServerInterest; 2],
    // FIXME: Add what we need to send device info etc.
}

impl DiscoveryServer {
    /// Create a new DiscoveryServer with the given local HPAI
    ///
    /// The local HPAI's port will be used for registering unicast interests.
    pub fn new(local_hpai: EndpointType) -> Self {
        let port = local_hpai.port();

        DiscoveryServer {
            interests: [
                ServerInterest::new(
                    KNXnetIPServiceType::SearchRequest,
                    EndpointType::new_udp_multicast(KNX_MULTICAST_ADDR, KNX_PORT),
                ),
                ServerInterest::new(KNXnetIPServiceType::DescriptionRequest, EndpointType::new_udp_any(port)),
            ],
        }
    }
}

impl super::KnxServer for DiscoveryServer {
    const N_INTERESTS: usize = 2;

    /// Returns the list of service codes and endpoints this server is interested in
    fn interests(&self) -> &[ServerInterest; Self::N_INTERESTS] {
        &self.interests
    }

    fn handle_message(&self, service_code: KNXnetIPServiceType, _data: &[u8]) -> Result<(), ServerError> {
        trace!("Discovery server handling service code {:?}", service_code);
        // TODO: Implement discovery protocol handling
        Ok(())
    }
}
