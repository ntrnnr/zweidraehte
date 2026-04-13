//! Remote Diagnostic and Configuration Server (KNX 3/8/7)
//!
//! Connectionless protocol for querying device info and performing resets
//! without a management connection. Requests arrive on multicast
//! (224.0.23.12:3671) or broadcast.
//!
//! All four services are **mandatory** for KNX/IP certification (§6.2):
//!
//! - `RemoteDiagnosticRequest` (0x0740) → respond with DIBs
//! - `RemoteDiagnosticResponse` (0x0741) → we send this, not receive
//! - `RemoteBasicConfigurationRequest` (0x0742) → apply IP config, respond
//! - `RemoteResetRequest` (0x0743) → restart/master reset, no response

use core::net::SocketAddrV4;
use heapless::Vec;

use zweidraehte_proto::messages::{
    buffers::Buffer,
    knx::KnxMessageBuffer,
    knxip::{
        KNXnetIPServiceType,
        substructs::{DescriptionInformationBlockBuilder, KnxAddressesBuilder},
    },
};

use zweidraehte_proto::util::packets::{ParseBuffer, SerializeBuffer};

use super::{KnxNetIpServer, PendingResponse, ResponseTarget, ServerContext, ServerError, resolve_hpai};

// ============================================================================
// SERVER
// ============================================================================

/// Remote Diagnostic and Configuration Server (KNX 3/8/7).
///
/// Handles connectionless remote diagnostics on multicast/broadcast.
/// Devices respond only if they match the request's selector (PrgMode
/// or MAC address).
#[derive(Debug)]
pub struct RemoteConfigurationServer;

impl Default for RemoteConfigurationServer {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteConfigurationServer {
    pub fn new() -> Self {
        RemoteConfigurationServer
    }

    // ========================================================================
    // REMOTE_DIAGNOSTIC_REQUEST (0x0740)
    // ========================================================================

    /// Handle a RemoteDiagnosticRequest.
    ///
    /// If the device matches the selector, respond with a
    /// RemoteDiagnosticResponse containing IP_CONFIG, IP_CUR_CONFIG,
    /// and KNX_ADDRESSES DIBs.
    async fn handle_diagnostic_request(
        &self,
        data: &[u8],
        source: SocketAddrV4,
        context: &ServerContext<'_>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        use zweidraehte_proto::messages::knxip::RemoteDiagnosticRequest;

        let mut buffer = data;
        let request = buffer.parse::<RemoteDiagnosticRequest>().map_err(|e| {
            debug!("Failed to parse RemoteDiagnosticRequest: {:?}", e);
            ServerError::ParseError
        })?;

        debug!("Received RemoteDiagnosticRequest, selector: {:?}", request.selector);

        // Check if we match the selector
        let device_info = context.device_info().device_information();
        if !request.selector.matches(&device_info) {
            debug!("Selector does not match this device, ignoring");
            return Ok(Vec::new());
        }

        // We match — build the response with mandatory DIBs
        let ip_diag = context.ip_diagnostics().ok_or_else(|| {
            debug!("IP diagnostics provider not available");
            ServerError::InternalError
        })?;

        let ip_config = ip_diag.ip_config();
        let ip_current = ip_diag.ip_current_config();
        let addrs = context.knx_addresses();
        let additional_addresses = context.additional_individual_addresses();
        let knx_addresses = KnxAddressesBuilder::new(addrs.individual_address(), additional_addresses);

        let dibs = [
            DescriptionInformationBlockBuilder::IpConfig(&ip_config),
            DescriptionInformationBlockBuilder::IpCurrentConfig(&ip_current),
            DescriptionInformationBlockBuilder::KnxAddresses(knx_addresses),
        ];

        let response_builder =
            zweidraehte_proto::messages::knxip::RemoteDiagnosticResponseBuilder::new(request.selector, &dibs);

        let mut response_buffer = context.alloc_buffer().await;
        response_buffer.serialize(&response_builder);

        let destination = resolve_hpai(&request.discovery_endpoint, source);

        debug!("Sending {} byte RemoteDiagnosticResponse to {}", response_buffer.len(), destination);

        let mut responses = Vec::new();
        let _ = responses.push(PendingResponse {
            buffer: response_buffer,
            target: ResponseTarget::Udp { destination, socket_idx: 0 },
        });
        Ok(responses)
    }

    // ========================================================================
    // REMOTE_BASIC_CONFIGURATION_REQUEST (0x0742)
    // ========================================================================

    /// Handle a RemoteBasicConfigurationRequest.
    ///
    /// If the device matches the selector, acknowledge with a
    /// RemoteDiagnosticResponse containing current state. Actual IP
    /// configuration writes are not yet implemented.
    async fn handle_basic_configuration_request(
        &self,
        data: &[u8],
        source: SocketAddrV4,
        context: &ServerContext<'_>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        use zweidraehte_proto::messages::knxip::RemoteBasicConfigurationRequest;

        let mut buffer = data;
        let request = buffer.parse::<RemoteBasicConfigurationRequest<_>>().map_err(|e| {
            debug!("Failed to parse RemoteBasicConfigurationRequest: {:?}", e);
            ServerError::ParseError
        })?;

        debug!(
            "Received RemoteBasicConfigurationRequest, selector: {:?}, {} DIBs",
            request.selector,
            request.dibs.iter().len()
        );

        // Check if we match the selector
        let device_info = context.device_info().device_information();
        if !request.selector.matches(&device_info) {
            debug!("Selector does not match this device, ignoring");
            return Ok(Vec::new());
        }

        // TODO: Apply IP configuration from request.dibs. For now, we only
        // log the received DIBs and respond with the current state.
        for dib in request.dibs.iter() {
            debug!("  Configuration DIB: {:?}", dib);
        }

        // Respond with current state (same as diagnostic response)
        let ip_diag = context.ip_diagnostics().ok_or_else(|| {
            debug!("IP diagnostics provider not available");
            ServerError::InternalError
        })?;

        let ip_config = ip_diag.ip_config();
        let ip_current = ip_diag.ip_current_config();
        let addrs = context.knx_addresses();
        let additional_addresses = context.additional_individual_addresses();
        let knx_addresses = KnxAddressesBuilder::new(addrs.individual_address(), additional_addresses);

        let dibs = [
            DescriptionInformationBlockBuilder::IpConfig(&ip_config),
            DescriptionInformationBlockBuilder::IpCurrentConfig(&ip_current),
            DescriptionInformationBlockBuilder::KnxAddresses(knx_addresses),
        ];

        let response_builder =
            zweidraehte_proto::messages::knxip::RemoteDiagnosticResponseBuilder::new(request.selector, &dibs);

        let mut response_buffer = context.alloc_buffer().await;
        response_buffer.serialize(&response_builder);

        let destination = resolve_hpai(&request.discovery_endpoint, source);

        debug!("Sending {} byte RemoteDiagnosticResponse (config ack) to {}", response_buffer.len(), destination);

        let mut responses = Vec::new();
        let _ = responses.push(PendingResponse {
            buffer: response_buffer,
            target: ResponseTarget::Udp { destination, socket_idx: 0 },
        });
        Ok(responses)
    }

    // ========================================================================
    // REMOTE_RESET_REQUEST (0x0743)
    // ========================================================================

    /// Handle a RemoteResetRequest.
    ///
    /// If the device matches the selector, execute the reset command.
    /// No response is sent (KNX 3/8/7 §4.4.4).
    async fn handle_reset_request(
        &self,
        data: &[u8],
        context: &ServerContext<'_>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        use zweidraehte_proto::messages::knxip::RemoteResetRequest;

        let mut buffer = data;
        let request = buffer.parse::<RemoteResetRequest>().map_err(|e| {
            debug!("Failed to parse RemoteResetRequest: {:?}", e);
            ServerError::ParseError
        })?;

        debug!("Received RemoteResetRequest, selector: {:?}, command: {:?}", request.selector, request.command);

        // Check if we match the selector
        let device_info = context.device_info().device_information();
        if !request.selector.matches(&device_info) {
            debug!("Selector does not match this device, ignoring");
            return Ok(Vec::new());
        }

        // TODO: Execute the reset command. This needs a platform-level
        // restart mechanism that doesn't exist yet.
        match request.command {
            zweidraehte_proto::messages::knxip::ResetCommand::Restart => {
                warn!("RemoteResetRequest: Restart requested but not yet implemented");
            }
            zweidraehte_proto::messages::knxip::ResetCommand::MasterReset => {
                warn!("RemoteResetRequest: MasterReset requested but not yet implemented");
            }
        }

        // No response for reset requests (§4.4.4)
        Ok(Vec::new())
    }
}

// ============================================================================
// KnxNetIpServer IMPLEMENTATION
// ============================================================================

impl KnxNetIpServer for RemoteConfigurationServer {
    async fn on_indication<'a>(
        &mut self,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        source: SocketAddrV4,
        context: &ServerContext<'a>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        debug!("Remote config server handling {:?}", service_type);

        match service_type {
            KNXnetIPServiceType::RemoteDiagnosticRequest => self.handle_diagnostic_request(data, source, context).await,
            KNXnetIPServiceType::RemoteBasicConfigurationRequest => {
                self.handle_basic_configuration_request(data, source, context).await
            }
            KNXnetIPServiceType::RemoteResetRequest => self.handle_reset_request(data, context).await,
            _ => {
                debug!("Remote config server received unexpected service type: {:?}", service_type);
                Err(ServerError::Unsupported)
            }
        }
    }

    async fn on_request<'a>(
        &mut self,
        _message: &KnxMessageBuffer<Buffer<'static>>,
        _context: &ServerContext<'a>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        // Remote config server doesn't handle outgoing requests
        Err(ServerError::Unsupported)
    }

    fn supports_requests(&self) -> bool {
        false
    }
}
