use core::net::SocketAddrV4;
use heapless::Vec;

use zweidraehte_proto::messages::{
    buffers::{Buffer, MessageBuffer},
    knx::KnxMessageBuffer,
    knxip::KNXnetIPServiceFamily,
    knxip::KNXnetIPServiceType,
    knxip::substructs::*,
};
use zweidraehte_proto::util::packets::ParseBuffer;

use super::{KnxNetIpServer, PendingResponse, ServerContext, ServerError, resolve_hpai};

// FIXME: Strictly speaking, we should only have one server that does discovery on 224.0.23.12:3671 and
//        then multiple servers that handle the control endpoints of other service containers

/// Maximum number of supported service families a discovery server can advertise
const MAX_SUPPORTED_SERVICES: usize = 6;

/// Maximum number of DIBs we can collect for an extended search response
const MAX_RESPONSE_DIBS: usize = 8;

#[derive(Debug)]
pub struct DiscoveryServer {
    control_endpoint: HPAI,
    supported_services: Vec<SupportedService, MAX_SUPPORTED_SERVICES>,
}

impl DiscoveryServer {
    /// Create a new DiscoveryServer with the given configuration.
    ///
    /// Device information is not stored here — it is built on demand from
    /// the [`ServerContext`]'s [`DeviceInfoContext`](crate::layers::linklayers::knxip::context::DeviceInfoContext)
    /// whenever a search or description request arrives, ensuring it always
    /// reflects current device state (programming mode, individual address, etc.).
    ///
    /// The `supported_services` list is typically auto-derived by
    /// [`KnxNetIpBuilder`](super::super::KnxNetIpBuilder) from the
    /// enabled features.
    pub fn new(control_endpoint: HPAI, supported_services: Vec<SupportedService, MAX_SUPPORTED_SERVICES>) -> Self {
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
        use zweidraehte_proto::messages::knxip::{SearchRequest, SearchResponseBuilder};
        use zweidraehte_proto::util::packets::SerializeBuffer;

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

        Ok(PendingResponse { buffer: response_buffer, target: context.response_target(destination) })
    }

    // ========================================================================
    // SearchRequestExtended handling (KNX 3/8/2 §7.6.3)
    // ========================================================================

    /// Handle a SearchRequestExtended message.
    ///
    /// Evaluates SRP selection filters to decide whether to respond, collects
    /// the requested DIBs, and sends a SearchResponseExtended.
    ///
    /// Returns `Ok(empty vec)` when the device is filtered out (i.e., should
    /// not respond) — this is not an error.
    async fn handle_search_request_extended(
        &self,
        data: &[u8],
        source: SocketAddrV4,
        context: &ServerContext<'_>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        use zweidraehte_proto::messages::knxip::{SearchRequestExtended, SearchResponseExtendedBuilder};
        use zweidraehte_proto::util::packets::SerializeBuffer;

        // Parse the SearchRequestExtended and all its SRPs
        let mut buffer = data;
        let request = buffer.parse::<SearchRequestExtended<_>>().map_err(|e| {
            debug!("Failed to parse SearchRequestExtended: {:?}", e);
            ServerError::ParseError
        })?;

        debug!(
            "Received SearchRequestExtended from {}:{} with {} SRPs",
            request.discovery_endpoint.address(),
            request.discovery_endpoint.port(),
            request.search_request_parameters.len()
        );

        let device_information = context.device_info().device_information();

        // ----------------------------------------------------------------
        // Phase 1: Evaluate selection SRPs.
        //
        // Walk all SRPs and check selection filters. If any mandatory SRP
        // cannot be evaluated, or a selection filter doesn't match, we
        // suppress the response entirely (return empty vec).
        //
        // Also collect DIB type codes from RequestDIBs SRPs (at most one
        // is expected, but we handle multiples gracefully).
        // ----------------------------------------------------------------

        let mut requested_dib_types: Vec<KNXnetIPServiceFamily, 16> = Vec::new();
        let mut has_request_dibs = false;

        for srp in &request.search_request_parameters {
            match srp {
                SearchRequestParameter::SelectByProgrammingMode => {
                    if !Selector::PrgMode.matches(&device_information) {
                        debug!("Device not in programming mode, suppressing response");
                        return Ok(Vec::new());
                    }
                }
                SearchRequestParameter::SelectByMacAddress { mac_address } => {
                    if !Selector::Mac(*mac_address).matches(&device_information) {
                        debug!("MAC address mismatch, suppressing response");
                        return Ok(Vec::new());
                    }
                }
                SearchRequestParameter::SelectByService { service_family, version } => {
                    // Check if we support the requested service family at >= requested version
                    let supported = self.supported_services.iter().any(|s| {
                        let family_code: u8 = s.family.into();
                        family_code == *service_family && s.version >= *version
                    });
                    if !supported {
                        debug!(
                            "Service family 0x{:02x} v{} not supported, suppressing response",
                            service_family, version
                        );
                        return Ok(Vec::new());
                    }
                }
                SearchRequestParameter::RequestDIBs { selectors } => {
                    has_request_dibs = true;
                    for dib_type in selectors.iter() {
                        let _ = requested_dib_types.push(dib_type);
                    }
                }
                SearchRequestParameter::Invalid { mandatory } => {
                    // Invalid SRP (type code 0x00) is a conformance test mechanism.
                    // The server can never "evaluate" it, so if M is set we must not respond.
                    if *mandatory {
                        debug!("Mandatory Invalid SRP present, suppressing response");
                        return Ok(Vec::new());
                    }
                    // M not set → ignore
                }
                SearchRequestParameter::Unknown { type_code, mandatory } => {
                    // We don't know how to evaluate this SRP.
                    if *mandatory {
                        debug!("Mandatory unknown SRP type 0x{:02x}, suppressing response", type_code);
                        return Ok(Vec::new());
                    }
                    // M not set → ignore
                }
            }
        }

        // ----------------------------------------------------------------
        // Phase 2: Collect DIBs for the response.
        //
        // If RequestDIBs is present, we return the union of the requested
        // set and the mandatory set (DeviceInfo, ExtDeviceInfo,
        // SupportedServices). If not present, we return the default set.
        //
        // Per spec §7.6.3.6: default set = DeviceInfo + ExtDeviceInfo +
        // SupportedServiceFamilies. The RequestDIBs SRP adds to this.
        // ----------------------------------------------------------------

        let extended_device_info = context.device_info().extended_device_information();

        // Determine which DIB types to include. The three mandatory ones are
        // always present; additional ones come from the RequestDIBs SRP.
        let mut include_ip_config = false;
        let mut include_ip_current_config = false;
        let mut include_knx_addresses = false;
        let mut include_tunneling_info = false;
        // TODO: ManufacturerData not required for Core v2 certification

        if has_request_dibs {
            for dib_type in &requested_dib_types {
                match *dib_type {
                    // Mandatory types — always included regardless
                    KNXnetIPServiceFamily::DeviceInfo
                    | KNXnetIPServiceFamily::SupportedServiceFamilies
                    | KNXnetIPServiceFamily::ExtendedDeviceInfo => {}

                    KNXnetIPServiceFamily::IPConfig => include_ip_config = true,
                    KNXnetIPServiceFamily::IPCurrentConfig => include_ip_current_config = true,
                    KNXnetIPServiceFamily::KNXAddresses => include_knx_addresses = true,
                    KNXnetIPServiceFamily::TunnelingInfo => include_tunneling_info = true,

                    // Unknown or unsupported DIB types are silently ignored
                    _ => {
                        debug!("Ignoring unknown/unsupported DIB type request: {:?}", dib_type);
                    }
                }
            }
        }

        // Collect optional DIB data values. These must be declared before the
        // `dibs` vec so they outlive the references stored in the DIB builders.
        let ip_config = if include_ip_config { context.ip_diagnostics().map(|d| d.ip_config()) } else { None };

        let ip_current_config =
            if include_ip_current_config { context.ip_diagnostics().map(|d| d.ip_current_config()) } else { None };

        let additional_addresses = if include_knx_addresses { context.additional_individual_addresses() } else { &[] };

        // Secured Service Families list (03/08/09 §2.6.2.2): collected
        // before `dibs` so the borrow in the DIB builder outlives it.
        let secured_families: Vec<SupportedService, 3> = context
            .ip_secure()
            .map(|config| {
                [ServiceFamily::DeviceManagement, ServiceFamily::Tunneling, ServiceFamily::Routing]
                    .into_iter()
                    .filter_map(|family| {
                        let version = config.secured_service_family(family);
                        (version != 0).then_some(SupportedService { family, version })
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Build the DIB list. Mandatory DIBs first, then optional.
        let mut dibs: Vec<DescriptionInformationBlockBuilder<'_>, MAX_RESPONSE_DIBS> = Vec::new();

        let _ = dibs.push(DescriptionInformationBlockBuilder::DeviceInformation(&device_information));
        let _ = dibs.push(DescriptionInformationBlockBuilder::SupportedServiceFamilies(
            SupportedServiceFamiliesBuilder::new(&self.supported_services),
        ));
        let _ = dibs.push(DescriptionInformationBlockBuilder::ExtendedDeviceInformation(&extended_device_info));

        // Included whenever at least one family requires SECURE_WRAPPER
        // traffic per PID_SECURED_SERVICE_FAMILIES.
        if !secured_families.is_empty() {
            let _ = dibs.push(DescriptionInformationBlockBuilder::SecuredServiceFamilies(
                SecuredServiceFamiliesBuilder::new(&secured_families),
            ));
        }

        if let Some(ref cfg) = ip_config {
            let _ = dibs.push(DescriptionInformationBlockBuilder::IpConfig(cfg));
        }

        if let Some(ref cfg) = ip_current_config {
            let _ = dibs.push(DescriptionInformationBlockBuilder::IpCurrentConfig(cfg));
        }

        if include_knx_addresses {
            let knx_addr_ctx = context.knx_addresses();
            let _ = dibs.push(DescriptionInformationBlockBuilder::KnxAddresses(KnxAddressesBuilder::new(
                knx_addr_ctx.individual_address(),
                additional_addresses,
            )));
        }

        if include_tunneling_info && let Some((max_apdu_len, slots)) = context.tunneling_slot_info() {
            let _ = dibs.push(DescriptionInformationBlockBuilder::TunnelingInfo(TunnelingInfoBuilder::new(
                max_apdu_len,
                slots,
            )));
        }

        // ----------------------------------------------------------------
        // Phase 3: Serialize and send the response
        // ----------------------------------------------------------------

        let response_builder = SearchResponseExtendedBuilder::new(self.control_endpoint, &dibs);

        let mut response_buffer = context.alloc_buffer().await;
        response_buffer.serialize(&response_builder);

        debug!("Sending {} byte SearchResponseExtended to discovery endpoint", response_buffer.len());

        let destination = resolve_hpai(&request.discovery_endpoint, source);

        let mut responses = Vec::new();
        let _ =
            responses.push(PendingResponse { buffer: response_buffer, target: context.response_target(destination) });
        Ok(responses)
    }

    /// Handle a DescriptionRequest message
    ///
    /// According to KNX/IP spec section 3.8.2:
    /// - Parse the DescriptionRequest
    /// - Send DescriptionResponse with device information to the control endpoint
    ///
    /// The response includes the mandatory DeviceInformation and SupportedServiceFamilies
    /// DIBs plus optional additional DIBs (IpConfig, IpCurrentConfig, KnxAddresses)
    /// when the context can provide them.
    async fn handle_description_request(
        &self,
        data: &[u8],
        source: SocketAddrV4,
        context: &ServerContext<'_>,
    ) -> Result<PendingResponse, ServerError> {
        use zweidraehte_proto::messages::knxip::{DescriptionRequest, DescriptionResponseBuilder};
        use zweidraehte_proto::util::packets::SerializeBuffer;

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

        // Collect optional additional DIBs.
        // Per spec Table 5, DescriptionResponse must NOT include TunnelingInfo
        // or ExtendedDeviceInfo — those are SearchResponseExtended-only.

        // These must be declared before `additional_dibs` so they outlive
        // the references stored in the DIB builder vec.
        let ip_config = context.ip_diagnostics().map(|d| d.ip_config());
        let ip_current_config = context.ip_diagnostics().map(|d| d.ip_current_config());
        let knx_addr_ctx = context.knx_addresses();
        let additional_addresses = context.additional_individual_addresses();

        let mut additional_dibs: Vec<DescriptionInformationBlockBuilder<'_>, 4> = Vec::new();

        if let Some(ref cfg) = ip_config {
            let _ = additional_dibs.push(DescriptionInformationBlockBuilder::IpConfig(cfg));
        }

        if let Some(ref cfg) = ip_current_config {
            let _ = additional_dibs.push(DescriptionInformationBlockBuilder::IpCurrentConfig(cfg));
        }

        let _ = additional_dibs.push(DescriptionInformationBlockBuilder::KnxAddresses(KnxAddressesBuilder::new(
            knx_addr_ctx.individual_address(),
            additional_addresses,
        )));

        // Allocate a buffer for the response
        let mut response_buffer = context.alloc_buffer().await;

        // Build and serialize the DescriptionResponse
        let response_builder = DescriptionResponseBuilder::with_additional_dibs(
            device_information,
            &self.supported_services,
            &additional_dibs,
        );

        // Serialize directly into the buffer (automatically sets length)
        response_buffer.serialize(&response_builder);

        debug!("Sending {} byte DescriptionResponse to control endpoint", response_buffer.len());

        let destination = resolve_hpai(&request.control_endpoint, source);

        Ok(PendingResponse { buffer: response_buffer, target: context.response_target(destination) })
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

        match service_type {
            KNXnetIPServiceType::SearchRequest => {
                let response = self.handle_search_request(data, source, context).await?;
                let mut responses = Vec::new();
                let _ = responses.push(response);
                Ok(responses)
            }
            KNXnetIPServiceType::DescriptionRequest => {
                let response = self.handle_description_request(data, source, context).await?;
                let mut responses = Vec::new();
                let _ = responses.push(response);
                Ok(responses)
            }
            KNXnetIPServiceType::SearchRequestExtended => {
                self.handle_search_request_extended(data, source, context).await
            }
            _ => {
                debug!("Discovery server received unexpected service type: {:?}", service_type);
                Err(ServerError::Unsupported)
            }
        }
    }

    async fn on_request<'a>(
        &mut self,
        _message: &KnxMessageBuffer<Buffer<'static>>,
        _context: &ServerContext<'a>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        // Discovery server doesn't handle outgoing requests
        Err(ServerError::Unsupported)
    }
}
