use core::net::{Ipv4Addr, SocketAddrV4};
use heapless::Vec;

use crate::{
    address::IndividualAddress,
    messages::{
        buffers::{Buffer, MessageBuffer},
        knx::KnxMessageBuffer,
        knxip::substructs::*,
        knxip::KNXnetIPServiceType,
    },
    util::packets::ParseBuffer,
};

use super::{KnxNetIpServer, PendingResponse, ServerContext, ServerError};

use platform::address::EthernetAddress;

// KNX/IP standard multicast address
const KNX_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);
const KNX_PORT: u16 = 3671;

// FIXME: Strictly speaking, we should only have one server that does discovery on 224.0.23.12:3671 and
//        then multiple servers that handle the control endpoints of other service containers

#[derive(Debug)]
pub struct DiscoveryServer {
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
        DiscoveryServer { control_endpoint, device_information, supported_services }
    }

    /// Handle a SearchRequest message
    ///
    /// According to KNX/IP spec section 3.8.1:
    /// - Parse the SearchRequest
    /// - Send SearchResponse with device information to the discovery endpoint
    async fn handle_search_request(
        &self,
        data: &[u8],
        context: &ServerContext<'_>,
    ) -> Result<PendingResponse, ServerError> {
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
        let mut response_buffer = context.alloc_buffer().await;

        // Build and serialize the SearchResponse
        let response_builder =
            SearchResponseBuilder::new(self.control_endpoint, self.device_information, self.supported_services);

        // Serialize directly into the buffer (automatically sets length)
        response_buffer.serialize(&response_builder);

        debug!("Sending {} byte SearchResponse to discovery endpoint", response_buffer.len());

        let destination = SocketAddrV4::new(request.discovery_endpoint.address(), request.discovery_endpoint.port());

        Ok(PendingResponse { buffer: response_buffer, destination })
    }

    /// Handle a DescriptionRequest message
    ///
    /// According to KNX/IP spec section 3.8.2:
    /// - Parse the DescriptionRequest
    /// - Send DescriptionResponse with device information to the control endpoint
    async fn handle_description_request(
        &self,
        data: &[u8],
        context: &ServerContext<'_>,
    ) -> Result<PendingResponse, ServerError> {
        use crate::messages::knxip::{DescriptionRequest, DescriptionResponseBuilder};
        use crate::util::packets::SerializeBuffer;

        // FIXME: check conditions when to respond or not (remote endpoint TCP etc.)

        // Parse the DescriptionRequest
        let mut buffer = data;
        let request = buffer.parse::<DescriptionRequest>().map_err(|e| {
            debug!("Failed to parse DescriptionRequest: {:?}", e);
            ServerError::ParseError
        })?;

        debug!(
            "Received DescriptionRequest from {}:{}",
            request.control_endpoint.address(),
            request.control_endpoint.port()
        );

        // Allocate a buffer for the response
        let mut response_buffer = context.alloc_buffer().await;

        // Build and serialize the DescriptionResponse
        let response_builder = DescriptionResponseBuilder::new(self.device_information, self.supported_services);

        // Serialize directly into the buffer (automatically sets length)
        response_buffer.serialize(&response_builder);

        debug!("Sending {} byte DescriptionResponse to control endpoint", response_buffer.len());

        let destination = SocketAddrV4::new(request.control_endpoint.address(), request.control_endpoint.port());

        Ok(PendingResponse { buffer: response_buffer, destination })
    }
}

impl KnxNetIpServer for DiscoveryServer {
    async fn on_indication<'a>(
        &mut self,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        _source: SocketAddrV4,
        context: &ServerContext<'a>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        debug!("Discovery server handling {:?}", service_type);

        let response = match service_type {
            KNXnetIPServiceType::SearchRequest => self.handle_search_request(data, context).await?,
            KNXnetIPServiceType::DescriptionRequest => self.handle_description_request(data, context).await?,
            _ => {
                debug!("Discovery server received unexpected service type: {:?}", service_type);
                return Err(ServerError::Unsupported);
            }
        };

        let mut responses = Vec::new();
        let _ = responses.push(response);
        Ok(responses)
    }

    async fn on_request<'a>(
        &mut self,
        _message: &KnxMessageBuffer<Buffer<'static>>,
        _context: &ServerContext<'a>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        // Discovery server doesn't handle outgoing requests
        Err(ServerError::Unsupported)
    }

    fn supports_requests(&self) -> bool {
        false
    }
}
