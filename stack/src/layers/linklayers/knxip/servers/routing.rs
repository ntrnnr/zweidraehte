use super::{ServerError, ServerInterest};
use crate::layers::linklayers::knxip::EndpointType;
use core::net::Ipv4Addr;

// KNX/IP Routing service type identifiers
const ROUTING_INDICATION: u16 = 0x0530;
const ROUTING_LOST_MESSAGE: u16 = 0x0531;
const ROUTING_BUSY: u16 = 0x0532;

// KNX/IP standard multicast address
const KNX_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);
const KNX_PORT: u16 = 3671;

#[derive(Debug, Clone, Copy)]
pub struct RoutingServer {
    interests: [ServerInterest; 2],
    // FIXME: Add what we need to send device info etc.
}

impl RoutingServer {
    pub fn new(local_hpai: EndpointType) -> Self {
        RoutingServer {
            interests: [
                ServerInterest::new(ROUTING_INDICATION, local_hpai),
                ServerInterest::new(ROUTING_BUSY, local_hpai),
            ],
        }
    }
}

impl super::KnxServer for RoutingServer {
    const N_INTERESTS: usize = 2;

    /// Returns the list of service codes and endpoints this server is interested in
    fn interests(&self) -> &[ServerInterest; Self::N_INTERESTS] {
        &self.interests
    }

    fn handle_message(&self, service_code: u16, _data: &[u8]) -> Result<(), ServerError> {
        trace!("Routing server handling service code 0x{:04x}", service_code);
        // TODO: Implement routing protocol handling
        Ok(())
    }
}
