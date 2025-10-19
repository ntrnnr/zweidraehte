use core::net::{Ipv4Addr, SocketAddrV4};

use crate::{
    address::IndividualAddress,
    messages::{
        buffers::{DynBufferManager, MessageBuffer},
        knxip::substructs::*,
    },
    util::packets::ParseBuffer,
};

use super::{EndpointType, KNXnetIPServiceType, PendingResponse, ServerError, ServerInterest, SocketHandle};

use platform::address::EthernetAddress;

// KNX/IP standard multicast address
const KNX_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 12);
const KNX_PORT: u16 = 3671;

/// Configuration for the Discovery Server
#[derive(Debug, Clone, Copy)]
pub struct DiscoveryServerConfig {
    /// The control endpoint (IP address and port) this server listens on
    pub control_endpoint: Endpoint,
    /// Device hardware information
    pub device_hardware: DeviceInformation,
    /// Supported service families
    pub supported_services: &'static [SupportedService],
}

impl DiscoveryServerConfig {
    /// Create a new DiscoveryServerConfig with default values
    ///
    /// # Arguments
    /// * `control_ip` - The IP address for the control endpoint
    /// * `control_port` - The port for the control endpoint
    /// * `individual_address` - The KNX individual address of this device
    /// * `mac_address` - The MAC address of this device
    pub const fn new(
        control_ip: Ipv4Addr,
        control_port: u16,
        individual_address: IndividualAddress,
        mac_address: EthernetAddress,
        supported_services: &'static [SupportedService],
    ) -> Self {
        Self {
            control_endpoint: Endpoint::ipv4_udp(control_ip, control_port),
            device_hardware: DeviceInformation {
                medium: KNXMedium::KNXIP,
                device_status: DeviceStatus::None,
                individual_address,
                project_installation_identifier: 0,
                knx_serial_number: [0; 6],
                routing_multicast_address: KNX_MULTICAST_ADDR,
                mac_address,
                friendly_name: *b"KNX/IP Device\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            },
            supported_services,
        }
    }

    /// Set the friendly name for the device
    ///
    /// # Arguments
    /// * `name` - A byte array of exactly 30 bytes containing the friendly name
    pub const fn with_friendly_name(mut self, name: [u8; 30]) -> Self {
        self.device_hardware.friendly_name = name;
        self
    }

    /// Set the KNX serial number
    pub const fn with_serial_number(mut self, serial: [u8; 6]) -> Self {
        self.device_hardware.knx_serial_number = serial;
        self
    }

    /// Set the project installation identifier
    pub const fn with_project_id(mut self, project_id: u16) -> Self {
        self.device_hardware.project_installation_identifier = project_id;
        self
    }

    /// Set the device status (e.g., programming mode)
    pub const fn with_device_status(mut self, status: DeviceStatus) -> Self {
        self.device_hardware.device_status = status;
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DiscoveryServer {
    interests: [ServerInterest; 2],
    config: DiscoveryServerConfig,
}

impl DiscoveryServer {
    /// Create a new DiscoveryServer with the given configuration
    pub fn new(config: DiscoveryServerConfig) -> Self {
        let port = config.control_endpoint.port();

        DiscoveryServer {
            interests: [
                // Listen for SearchRequests on the KNX/IP multicast address
                ServerInterest::new(
                    KNXnetIPServiceType::SearchRequest,
                    EndpointType::new_udp_multicast(KNX_MULTICAST_ADDR, KNX_PORT),
                ),
                // Listen for DescriptionRequests on our unicast endpoint
                ServerInterest::new(KNXnetIPServiceType::DescriptionRequest, EndpointType::new_udp_any(port)),
            ],
            config,
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
        socket: SocketHandle,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<Option<PendingResponse>, ServerError> {
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
        let response_builder = SearchResponseBuilder::new(
            self.config.control_endpoint,
            self.config.device_hardware,
            self.config.supported_services,
        );

        // Serialize directly into the buffer (automatically sets length)
        response_buffer.serialize(&response_builder);

        debug!("Sending {} byte SearchResponse to discovery endpoint", response_buffer.len());

        let destination = SocketAddrV4::new(request.discovery_endpoint.address(), request.discovery_endpoint.port());

        Ok(Some(socket.respond(response_buffer, destination)))
    }

    /// Handle a DescriptionRequest message
    ///
    /// According to KNX/IP spec section 3.8.2:
    /// - Parse the DescriptionRequest
    /// - Send DescriptionResponse with device information to the control endpoint
    async fn handle_description_request(
        &self,
        data: &[u8],
        socket: SocketHandle,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<Option<PendingResponse>, ServerError> {
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
        let response_builder =
            DescriptionResponseBuilder::new(self.config.device_hardware, self.config.supported_services);

        // Serialize directly into the buffer (automatically sets length)
        response_buffer.serialize(&response_builder);

        debug!("Sending {} byte DescriptionResponse to control endpoint", response_buffer.len());

        let destination = SocketAddrV4::new(request.control_endpoint.address(), request.control_endpoint.port());

        Ok(Some(socket.respond(response_buffer, destination)))
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
        socket: SocketHandle,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<Option<PendingResponse>, super::ServerError> {
        trace!("Discovery server handling service code {:?}", service_code);

        match service_code {
            KNXnetIPServiceType::SearchRequest => self.handle_search_request(data, socket, buffer_manager).await,
            KNXnetIPServiceType::DescriptionRequest => {
                self.handle_description_request(data, socket, buffer_manager).await
            }
            _ => {
                debug!("Discovery server received unexpected service code: {:?}", service_code);
                Err(ServerError::Unsupported)
            }
        }
    }
}
