use core::net::SocketAddrV4;
use heapless::Vec;

use crate::{
    messages::{
        buffers::{Buffer, MessageBuffer},
        knx::KnxMessageBuffer,
        knxip::KNXnetIPServiceType,
        knxip::substructs::*,
    },
    util::packets::ParseBuffer,
};

use super::{KnxNetIpServer, PendingResponse, ServerContext, ServerError, resolve_hpai};

// FIXME: Strictly speaking, we should only have one server that does discovery on 224.0.23.12:3671 and
//        then multiple servers that handle the control endpoints of other service containers

/// Maximum number of supported service families a discovery server can advertise
const MAX_SUPPORTED_SERVICES: usize = 5;

#[derive(Debug)]
pub struct DiscoveryServer {
    control_endpoint: HPAI,
    supported_services: Vec<SupportedService, MAX_SUPPORTED_SERVICES>,
}

impl DiscoveryServer {
    /// Create a new DiscoveryServer with the given configuration.
    ///
    /// Device information is not stored here — it is built on demand from
    /// the [`ServerContext`]'s [`DeviceInfoContext`](crate::context::DeviceInfoContext)
    /// whenever a search or description request arrives, ensuring it always
    /// reflects current device state (programming mode, individual address, etc.).
    ///
    /// The `supported_services` list is typically auto-derived by
    /// [`KnxNetIpBuilder`](super::super::KnxNetIpBuilder) from the
    /// enabled features.
    pub fn new(
        control_endpoint: HPAI,
        supported_services: Vec<SupportedService, MAX_SUPPORTED_SERVICES>,
    ) -> Self {
        DiscoveryServer { control_endpoint, supported_services }
    }

    /// Handle a SearchRequest message
    ///
    /// According to KNX/IP spec section 3.8.1:
    /// - Parse the SearchRequest
    /// - Send SearchResponse with device information to the discovery endpoint
    async fn handle_search_request(
        &self,
        data: &[u8],
        source: SocketAddrV4,
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

        // Build current device information from state
        let device_information = context.device_info().device_information();

        // Allocate a buffer for the response
        let mut response_buffer = context.alloc_buffer().await;

        // Build and serialize the SearchResponse
        let response_builder =
            SearchResponseBuilder::new(self.control_endpoint, device_information, &self.supported_services);

        // Serialize directly into the buffer (automatically sets length)
        response_buffer.serialize(&response_builder);

        debug!("Sending {} byte SearchResponse to discovery endpoint", response_buffer.len());

        let destination = resolve_hpai(&request.discovery_endpoint, source);

        Ok(PendingResponse { buffer: response_buffer, destination, socket_idx: 0 })
    }

    /// Handle a DescriptionRequest message
    ///
    /// According to KNX/IP spec section 3.8.2:
    /// - Parse the DescriptionRequest
    /// - Send DescriptionResponse with device information to the control endpoint
    async fn handle_description_request(
        &self,
        data: &[u8],
        source: SocketAddrV4,
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

        // Build current device information from state
        let device_information = context.device_info().device_information();

        // Allocate a buffer for the response
        let mut response_buffer = context.alloc_buffer().await;

        // Build and serialize the DescriptionResponse
        let response_builder = DescriptionResponseBuilder::new(device_information, &self.supported_services);

        // Serialize directly into the buffer (automatically sets length)
        response_buffer.serialize(&response_builder);

        debug!("Sending {} byte DescriptionResponse to control endpoint", response_buffer.len());

        let destination = resolve_hpai(&request.control_endpoint, source);

        Ok(PendingResponse { buffer: response_buffer, destination, socket_idx: 0 })
    }
}

impl KnxNetIpServer for DiscoveryServer {
    async fn on_indication<'a>(
        &mut self,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        source: SocketAddrV4,
        context: &ServerContext<'a>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        debug!("Discovery server handling {:?}", service_type);

        let response = match service_type {
            KNXnetIPServiceType::SearchRequest => self.handle_search_request(data, source, context).await?,
            KNXnetIPServiceType::DescriptionRequest => {
                self.handle_description_request(data, source, context).await?
            }
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
