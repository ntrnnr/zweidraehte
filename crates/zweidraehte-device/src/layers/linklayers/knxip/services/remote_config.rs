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

use super::super::KnxNetIpContext;

use crate::ip::IpStateView;

use core::net::SocketAddrV4;
use heapless::Vec;

use zweidraehte_proto::messages::{
    buffers::Buffer,
    knx::KnxMessageBuffer,
    knxip::{
        KNXnetIPServiceType, ResetCommand,
        substructs::{DescriptionInformationBlock, DescriptionInformationBlockBuilder, KnxAddressesBuilder},
    },
};

use zweidraehte_proto::AccessContext;
use zweidraehte_proto::util::packets::{ParseBuffer, SerializeBuffer};

use crate::restart::{EraseCode, RestartRequest, RestartType};

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
        context: &ServerContext<'_, impl KnxNetIpContext>,
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
        let ip_diag = context.ip_diagnostics();

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
            target: ResponseTarget::Udp { destination, socket_idx: context.socket_idx },
        });
        Ok(responses)
    }

    // ========================================================================
    // REMOTE_BASIC_CONFIGURATION_REQUEST (0x0742)
    // ========================================================================

    /// Handle a RemoteBasicConfigurationRequest.
    ///
    /// If the device matches the selector, apply the writable IP_CONFIG
    /// fields from the request's DIBs and acknowledge with a
    /// RemoteDiagnosticResponse reflecting the updated current state
    /// (§4.4.3).
    async fn handle_basic_configuration_request(
        &self,
        data: &[u8],
        source: SocketAddrV4,
        context: &ServerContext<'_, impl KnxNetIpContext>,
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

        // Apply only writable IP_CONFIG fields. The feature slot selects this
        // service; the context always supplies its concrete providers.
        // ip_capabilities is platform-reported and write-protected (§4.4.3).
        let ip_write = context.ip_config_write();
        let ip_state = ip_write.ip_state_mut();
        let mut applied = false;
        for dib in request.dibs.iter() {
            if let DescriptionInformationBlock::IpConfig(cfg) = dib {
                ip_state.set_configured_ip_address(cfg.ip_address);
                ip_state.set_configured_subnet_mask(cfg.subnet_mask);
                ip_state.set_configured_default_gateway(cfg.default_gateway);
                ip_state.set_ip_assignment_method(cfg.ip_assignment_method);
                applied = true;
            } else {
                // Other DIB types are not configurable via this service.
                debug!("  Ignoring non-IP_CONFIG configuration DIB: {:?}", dib);
            }
        }
        // Persist only if we actually changed something — the IP setters
        // themselves do not mark the device state dirty.
        if applied {
            ip_write.mark_config_dirty();
        }

        // Respond with current state (same as diagnostic response)
        let ip_diag = context.ip_diagnostics();

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
            target: ResponseTarget::Udp { destination, socket_idx: context.socket_idx },
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
        context: &ServerContext<'_, impl KnxNetIpContext>,
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

        // Raise the reset on the same restart channel the Application
        // Layer uses for A_Restart, so user code drains one queue for both.
        // The actual reset/persistence is performed by the user-code restart
        // handler (`stack.receive_restart_request()`), exactly as for an
        // A_Restart. Map the wire command onto the matching restart:
        // Restart → a restart that erases nothing, MasterReset → a full
        // factory reset (§4.7).
        let restart = match request.command {
            ResetCommand::Restart => RestartType::Basic,
            ResetCommand::MasterReset => RestartType::MasterReset(EraseCode::FactoryReset),
        };
        // A remote reset arrives unauthenticated over multicast and carries
        // no TL connection, so there is no channel or access context to
        // forward: use the lowest privilege level and no response.
        let restart =
            RestartRequest { restart, channel: 0, access_ctx: AccessContext::MIN_ACCESS, needs_response: false };
        if !context.restart_ctx().request_restart(restart) {
            warn!("RemoteResetRequest: restart channel full, reset dropped");
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
        context: &ServerContext<'a, impl KnxNetIpContext>,
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
        _context: &ServerContext<'a, impl KnxNetIpContext>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        // Remote config server doesn't handle outgoing requests
        Err(ServerError::Unsupported)
    }
}

// ============================================================================
// TESTS
// ============================================================================
//
// These exercise the two behavioural handlers that the server gained over
// the bare parse/dispatch skeleton: `REMOTE_BASIC_CONFIGURATION_REQUEST`
// (write IP config) and `REMOTE_RESET_REQUEST` (raise a restart). They drive
// the handlers with serialized request frames and a concrete test context to
// observe the side effects (setters fired,
// dirty flag set, restart request emitted) without standing up a full stack.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bcus::system_b::IpExtensionState;
    use crate::context::ApduLengthContext;
    use crate::layers::linklayers::knxip::context::{IpConfigWriteContext, IpDiagnosticsContext};
    use crate::layers::linklayers::knxip::features::{NoRemoteConfig, RemoteConfigFeature};
    use core::net::{Ipv4Addr, SocketAddrV4};
    use embassy_futures::block_on;
    use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
    use zweidraehte_platform::address::EthernetAddress;
    use zweidraehte_proto::address::IndividualAddress;
    use zweidraehte_proto::messages::builder::IndicationMessage;
    use zweidraehte_proto::messages::knx::DestinationAddress;
    use zweidraehte_proto::messages::knxip::substructs::{HPAI, IpConfig, Selector};
    use zweidraehte_proto::messages::knxip::{RemoteBasicConfigurationRequestBuilder, RemoteResetRequestBuilder};

    const TEST_MAC: EthernetAddress = EthernetAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    const OTHER_MAC: EthernetAddress = EthernetAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

    // --- Fakes -------------------------------------------------------------

    use crate::layers::linklayers::knxip::test_support::TestContext;

    // --- Harness -----------------------------------------------------------

    /// Build a serialized `REMOTE_RESET_REQUEST` frame for `selector`/`cmd`.
    fn reset_frame(selector: Selector, cmd: ResetCommand) -> ([u8; 32], usize) {
        use zweidraehte_proto::util::packets::SerializablePacket;
        let builder = RemoteResetRequestBuilder::new(selector, cmd);
        let len = builder.bytes_len();
        let mut buf = [0u8; 32];
        let mut cursor = &mut buf[..];
        cursor.serialize(&builder);
        (buf, len)
    }

    /// Build a serialized `REMOTE_BASIC_CONFIGURATION_REQUEST` carrying a
    /// single IP_CONFIG DIB.
    fn basic_config_frame(selector: Selector, cfg: &IpConfig) -> ([u8; 64], usize) {
        use zweidraehte_proto::util::packets::SerializablePacket;
        let dibs = [DescriptionInformationBlockBuilder::IpConfig(cfg)];
        let builder = RemoteBasicConfigurationRequestBuilder::new(
            HPAI::ipv4_udp(Ipv4Addr::new(192, 168, 1, 50), 3671),
            selector,
            &dibs,
        );
        let len = builder.bytes_len();
        let mut buf = [0u8; 64];
        let mut cursor = &mut buf[..];
        cursor.serialize(&builder);
        (buf, len)
    }

    /// Channel used to satisfy `ServerContext`'s `ind_tx` (unused by the
    /// handlers under test, but required to construct the context).
    fn ind_channel() -> Channel<NoopRawMutex, IndicationMessage<Buffer<'static>>, 1> {
        Channel::new()
    }

    /// The filter must read the individual address **live** on every frame, not
    /// snapshot it at construction: a virgin device boots at 15.15.255, ETS
    /// writes a new IA, then verifies by addressing the device at the new IA
    /// (03/05/02 §2.3). If the filter froze the old IA, that verify frame would
    /// be dropped and first-time assignment would fail.
    #[test]
    fn accepts_individual_reflects_live_address_change() {
        let virgin = IndividualAddress::new(15, 15, 255);
        let assigned = IndividualAddress::new(0, 0, 1);

        let device = TestContext::new(false, TEST_MAC);
        device.addresses.ia.set(virgin);
        let ind = ind_channel();
        let filter = ServerContext::new(&device, ind.dyn_sender(), &[], None, 0);

        // Before assignment: accepts the boot address, not the (future) new one.
        assert!(filter.accepts_destination(DestinationAddress::Individual(virgin)));
        assert!(!filter.accepts_destination(DestinationAddress::Individual(assigned)));

        // ETS assigns the new IA — no filter rebuild.
        device.addresses.ia.set(assigned);

        // The filter must now accept the new IA (and reject the old one).
        assert!(filter.accepts_destination(DestinationAddress::Individual(assigned)));
        assert!(!filter.accepts_destination(DestinationAddress::Individual(virgin)));

        // Broadcast is always accepted regardless of the current IA.
        assert!(filter.accepts_destination(DestinationAddress::Broadcast));
        assert!(filter.accepts_destination(DestinationAddress::SystemBroadcast));
        // Parsed destinations retain their explicit kind; raw zero-address
        // broadcast detection belongs to the TP1/RF header adapter.
        assert!(!filter.accepts_destination(DestinationAddress::Individual(IndividualAddress::new(0, 0, 0))));
        assert!(!filter.accepts_destination(DestinationAddress::ConnectionNr(1)));
    }

    #[test]
    fn server_context_keeps_provider_types_and_live_values() {
        let device = TestContext::new(false, TEST_MAC);
        let ind = ind_channel();
        let context = ServerContext::new(&device, ind.dyn_sender(), &[], None, 2);

        // These annotations also guard against helper-level type erasure.
        let diagnostics: &TestContext = context.ip_diagnostics();
        let writer: &TestContext = context.ip_config_write();
        let _restart: &TestContext = context.restart_ctx();
        let state: &IpExtensionState = writer.ip_state_mut();
        let _absent: Option<&core::convert::Infallible> = context.ip_secure();

        state.set_configured_ip_address(Ipv4Addr::new(192, 168, 1, 42));
        assert_eq!(diagnostics.ip_config().ip_address, Ipv4Addr::new(192, 168, 1, 42));
        assert_eq!(context.max_apdu_length(), 15);
        device.set_max_apdu_length(56);
        assert_eq!(context.max_apdu_length(), 56);

        let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3671);
        assert!(matches!(context.response_target(destination),
            ResponseTarget::Udp { destination: addr, socket_idx: 2 } if addr == destination));
        assert!(matches!(context.with_tcp_origin(Some(3)).response_target(destination), ResponseTarget::Tcp {
            tcp_idx: 3
        }));
    }

    #[test]
    fn disabled_remote_config_dispatch_cannot_reset_device() {
        let device = TestContext::new(true, TEST_MAC);
        let ind = ind_channel();
        let context = ServerContext::new(&device, ind.dyn_sender(), &[], None, 0);

        assert!(!NoRemoteConfig::handles(KNXnetIPServiceType::RemoteResetRequest, 0, &[0]));

        let (frame, len) = reset_frame(Selector::PrgMode, ResetCommand::MasterReset);
        let responses = block_on(NoRemoteConfig::on_indication(
            &mut (),
            KNXnetIPServiceType::RemoteResetRequest,
            &frame[..len],
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3671),
            &context,
        ))
        .expect("valid reset frame");
        assert!(responses.is_empty());
        assert!(device.restart.borrow().is_none());
    }

    #[test]
    fn discovery_ip_dibs_follow_remote_config_feature() {
        use crate::layers::linklayers::knxip::features::WithRemoteConfig;
        use crate::layers::linklayers::knxip::services::DiscoveryServer;
        use zweidraehte_proto::messages::knxip::{DescriptionRequestBuilder, DescriptionResponse};
        use zweidraehte_proto::util::packets::SerializablePacket;

        fn check<RC: RemoteConfigFeature>(expected_ip_dibs: bool) {
            let device = TestContext::new(false, TEST_MAC);
            let ind = ind_channel();
            let context = ServerContext::new(&device, ind.dyn_sender(), &[], None, 0);
            let endpoint = HPAI::ipv4_udp(Ipv4Addr::LOCALHOST, 3671);
            let mut server = DiscoveryServer::<RC>::new(endpoint, Vec::new());
            let request = DescriptionRequestBuilder::new(endpoint);
            let mut frame = [0u8; 32];
            (&mut frame[..]).serialize(&request);

            let responses = block_on(server.on_indication(
                KNXnetIPServiceType::DescriptionRequest,
                &frame[..request.bytes_len()],
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3671),
                &context,
            ))
            .expect("valid description request");
            assert_eq!(responses.len(), 1);
            let mut cursor = &responses[0].buffer[..];
            let response = cursor.parse::<DescriptionResponse<_>>().expect("description response");
            let (mut ip_config, mut ip_current, mut knx_addresses) = (false, false, false);
            for dib in response.additional_dibs.iter() {
                match dib {
                    DescriptionInformationBlock::IpConfig(_) => ip_config = true,
                    DescriptionInformationBlock::IpCurrentConfig(_) => ip_current = true,
                    DescriptionInformationBlock::KnxAddresses(_) => knx_addresses = true,
                    _ => panic!("unexpected description DIB"),
                }
            }
            assert_eq!(ip_config, expected_ip_dibs);
            assert_eq!(ip_current, expected_ip_dibs);
            assert!(knx_addresses);
        }

        check::<WithRemoteConfig>(true);
        check::<NoRemoteConfig>(false);
    }

    // --- Reset tests -------------------------------------------------------

    fn run_reset(
        prog_mode: bool,
        mac: EthernetAddress,
        selector: Selector,
        cmd: ResetCommand,
    ) -> Option<RestartRequest> {
        let device = TestContext::new(prog_mode, mac);
        let ind = ind_channel();
        let ctx = ServerContext::new(&device, ind.dyn_sender(), &[], None, 0);

        let (frame, len) = reset_frame(selector, cmd);
        let server = RemoteConfigurationServer::new();
        let result = block_on(server.handle_reset_request(&frame[..len], &ctx));
        assert!(result.expect("valid reset frame").is_empty(), "reset must never produce a response (§4.4.4)");

        *device.restart.borrow()
    }

    #[test]
    fn reset_restart_emits_basic_restart() {
        let req = run_reset(true, TEST_MAC, Selector::PrgMode, ResetCommand::Restart)
            .expect("matching selector must emit a restart request");
        assert_eq!(req.restart, RestartType::Basic);
        assert!(!req.needs_response);
    }

    #[test]
    fn reset_master_reset_emits_factory_reset_erase_code() {
        let req = run_reset(false, TEST_MAC, Selector::Mac(TEST_MAC), ResetCommand::MasterReset)
            .expect("matching MAC selector must emit a restart request");
        assert_eq!(req.restart, RestartType::MasterReset(EraseCode::FactoryReset));
    }

    #[test]
    fn reset_non_matching_selector_emits_nothing() {
        // PrgMode selector but device is not in programming mode.
        assert!(run_reset(false, TEST_MAC, Selector::PrgMode, ResetCommand::Restart).is_none());
        // MAC selector for a different device.
        assert!(run_reset(false, TEST_MAC, Selector::Mac(OTHER_MAC), ResetCommand::MasterReset).is_none());
    }

    // --- Config-write tests ------------------------------------------------

    /// Returns the fake IP state (post-handler) and whether it was marked
    /// dirty, for the given selector / programming-mode combination.
    fn run_basic_config(prog_mode: bool, selector: Selector) -> (Ipv4Addr, Ipv4Addr, Ipv4Addr, u8, bool) {
        let device = TestContext::new(prog_mode, TEST_MAC);
        let ind = ind_channel();
        let ctx = ServerContext::new(&device, ind.dyn_sender(), &[], None, 0);

        let requested = IpConfig {
            ip_address: Ipv4Addr::new(10, 0, 0, 5),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            default_gateway: Ipv4Addr::new(10, 0, 0, 1),
            ip_capabilities: 0xFF, // write-protected, must be ignored
            ip_assignment_method: 0x04,
        };
        let (frame, len) = basic_config_frame(selector, &requested);
        let server = RemoteConfigurationServer::new();
        let _ = block_on(server.handle_basic_configuration_request(
            &frame[..len],
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 50), 3671),
            &ctx,
        ))
        .expect("config request must be handled");

        (
            device.state.configured_ip_address(),
            device.state.configured_subnet_mask(),
            device.state.configured_default_gateway(),
            device.state.ip_assignment_method(),
            device.dirty.get(),
        )
    }

    #[test]
    fn basic_config_matching_selector_applies_and_marks_dirty() {
        let (ip, mask, gw, method, dirty) = run_basic_config(true, Selector::PrgMode);
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(mask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(gw, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(method, 0x04);
        assert!(dirty, "a successful config write must mark the state dirty");
    }

    #[test]
    fn basic_config_non_matching_selector_writes_nothing() {
        // Device not in programming mode → PrgMode selector does not match.
        let (ip, mask, gw, method, dirty) = run_basic_config(false, Selector::PrgMode);
        assert_eq!(ip, Ipv4Addr::UNSPECIFIED);
        assert_eq!(mask, Ipv4Addr::UNSPECIFIED);
        assert_eq!(gw, Ipv4Addr::UNSPECIFIED);
        assert_eq!(method, 0);
        assert!(!dirty);
    }
}
