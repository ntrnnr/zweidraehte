use core::net::{Ipv4Addr, SocketAddrV4};

use crate::{
    address::IndividualAddress,
    messages::{
        buffers::{DynBufferManager, MessageBuffer},
        knxip::substructs::*,
    },
    util::packets::ParseBuffer,
};

use super::{EndpointType, KNXnetIPServiceType, PendingResponse, ServerError, ServerInterest};

use platform::address::EthernetAddress;

// KNX/IP standard multicast address
const KNX_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);
const KNX_PORT: u16 = 3671;

// FIXME: Strictly speaking, we should only have one server that does discovery on 224.0.23.12:3671 and
//        then multiple servers that handle the control endpoints of other service containers

#[derive(Debug, Clone, Copy)]
pub struct DiscoveryServer {
    interests: [ServerInterest; 2],
    control_endpoint: HPAI,
    device_information: DeviceInformation,
    supported_services: &'static [SupportedService],
}

impl DiscoveryServer {
    /// Create a new DiscoveryServer with the given configuration
    pub fn new(
        control_endpoint: HPAI,
        device_information: DeviceInformation,
        supported_services: &'static [SupportedService],
    ) -> Self {
        DiscoveryServer {
            interests: [
                // Listen for SearchRequests on the KNX/IP multicast address
                ServerInterest::new(
                    KNXnetIPServiceType::SearchRequest,
                    EndpointType::new_udp_multicast(KNX_MULTICAST_ADDR, KNX_PORT),
                ),
                // Listen for DescriptionRequests on our unicast endpoint
                ServerInterest::new(
                    KNXnetIPServiceType::DescriptionRequest,
                    EndpointType::new_udp_any(control_endpoint.port()),
                ),
            ],
            control_endpoint,
            device_information,
            supported_services,
        }
    }

    /// Handle a SearchRequest message
    ///
    /// According to KNX/IP spec section 3.8.1:
    /// - Parse the SearchRequest
    /// - Send SearchResponse with device information to the discovery endpoint
    async fn handle_search_request(
        &self,
        data: &[u8],
        response_handle: &super::ResponseHandle<'_>,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<(), ServerError> {
        use crate::messages::knxip::{SearchRequest, SearchResponseBuilder};
        use crate::util::packets::SerializeBuffer;

        // FIXME: check conditions when to respond or not (remote endpoint TCP etc.)

        // Parse the SearchRequest
        let mut buffer = data;
        let request = buffer.parse::<SearchRequest>().map_err(|e| {
            debug!("Failed to parse SearchRequest: {:?}", e);
            ServerError::ParseError
        })?;

        debug!(
            "Received SearchRequest from {}:{}",
            request.discovery_endpoint.address(),
            request.discovery_endpoint.port()
        );

        // Allocate a buffer for the response
        let mut response_buffer = buffer_manager.alloc().await;

        // Build and serialize the SearchResponse
        let response_builder =
            SearchResponseBuilder::new(self.control_endpoint, self.device_information, self.supported_services);

        // Serialize directly into the buffer (automatically sets length)
        response_buffer.serialize(&response_builder);

        debug!("Sending {} byte SearchResponse to discovery endpoint", response_buffer.len());

        let destination = SocketAddrV4::new(request.discovery_endpoint.address(), request.discovery_endpoint.port());

        response_handle.respond(response_buffer, destination).await;

        Ok(())
    }

    /// Handle a DescriptionRequest message
    ///
    /// According to KNX/IP spec section 3.8.2:
    /// - Parse the DescriptionRequest
    /// - Send DescriptionResponse with device information to the control endpoint
    async fn handle_description_request(
        &self,
        data: &[u8],
        response_handle: &super::ResponseHandle<'_>,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<(), ServerError> {
        use crate::messages::knxip::{DescriptionRequest, DescriptionResponseBuilder};
        use crate::util::packets::SerializeBuffer;

        // FIXME: check conditions when to respond or not (remote endpoint TCP etc.)

        // Parse the DescriptionRequest
        let mut buffer = data;
        let request = buffer.parse::<DescriptionRequest>().map_err(|e| {
            debug!("Failed to parse DescriptionRequest: {:?}", e);
            super::ServerError::ParseError
        })?;

        debug!(
            "Received DescriptionRequest from {}:{}",
            request.control_endpoint.address(),
            request.control_endpoint.port()
        );

        // Allocate a buffer for the response
        let mut response_buffer = buffer_manager.alloc().await;

        // Build and serialize the DescriptionResponse
        let response_builder = DescriptionResponseBuilder::new(self.device_information, self.supported_services);

        // Serialize directly into the buffer (automatically sets length)
        response_buffer.serialize(&response_builder);

        debug!("Sending {} byte DescriptionResponse to control endpoint", response_buffer.len());

        let destination = SocketAddrV4::new(request.control_endpoint.address(), request.control_endpoint.port());

        response_handle.respond(response_buffer, destination).await;

        Ok(())
    }
}

impl super::KnxServer for DiscoveryServer {
    const N_INTERESTS: usize = 2;

    /// Returns the list of service codes and endpoints this server is interested in
    fn interests(&self) -> &[ServerInterest; Self::N_INTERESTS] {
        &self.interests
    }

    async fn handle_message(
        &self,
        service_code: KNXnetIPServiceType,
        data: &[u8],
        response_handle: &super::ResponseHandle<'_>,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<(), super::ServerError> {
        trace!("Discovery server handling service code {:?}", service_code);

        match service_code {
            KNXnetIPServiceType::SearchRequest => {
                self.handle_search_request(data, response_handle, buffer_manager).await
            }
            KNXnetIPServiceType::DescriptionRequest => {
                self.handle_description_request(data, response_handle, buffer_manager).await
            }
            _ => {
                debug!("Discovery server received unexpected service code: {:?}", service_code);
                Err(ServerError::Unsupported)
            }
        }
    }
}
