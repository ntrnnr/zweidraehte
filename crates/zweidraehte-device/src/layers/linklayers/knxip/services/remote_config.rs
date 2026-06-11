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
        KNXnetIPServiceType, ResetCommand,
        substructs::{DescriptionInformationBlock, DescriptionInformationBlockBuilder, KnxAddressesBuilder},
    },
};

use zweidraehte_proto::AccessContext;
use zweidraehte_proto::util::packets::{ParseBuffer, SerializeBuffer};

use crate::restart::{EraseCode, RestartRequest};

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

        // Apply the writable fields of each incoming IP_CONFIG DIB. The
        // write context is gated identically to the diagnostics read side,
        // so its absence is the same internal error as a missing
        // `ip_diagnostics` below. `ip_capabilities` is a platform-reported
        // capability bitmask and write-protected (§4.4.3), so we never copy
        // it from the request.
        let ip_write = context.ip_config_write().ok_or_else(|| {
            debug!("IP config write context not available");
            ServerError::InternalError
        })?;
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

        // Raise the reset on the same restart channel the Application
        // Layer uses for A_Restart, so user code drains one queue for both.
        // The actual reset/persistence is performed by the user-code restart
        // handler (`stack.receive_restart_request()`), exactly as for an
        // A_Restart. Map the wire command onto the matching erase code:
        // Restart → a confirmed (state-preserving) restart, MasterReset →
        // a full factory reset (§4.7).
        let erase_code = match request.command {
            ResetCommand::Restart => EraseCode::Confirmed,
            ResetCommand::MasterReset => EraseCode::FactoryReset,
        };
        // A remote reset arrives unauthenticated over multicast and carries
        // no TL connection, so there is no channel or access context to
        // forward: use the lowest privilege level and no response.
        let restart =
            RestartRequest { erase_code, channel: 0, access_ctx: AccessContext::MIN_ACCESS, needs_response: false };
        match context.restart_ctx() {
            Some(ctx) => {
                if !ctx.request_restart(restart) {
                    warn!("RemoteResetRequest: restart channel full, reset dropped");
                }
            }
            None => warn!("RemoteResetRequest: restart context not available, reset ignored"),
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
}

// ============================================================================
// TESTS
// ============================================================================
//
// These exercise the two behavioural handlers that the server gained over
// the bare parse/dispatch skeleton: `REMOTE_BASIC_CONFIGURATION_REQUEST`
// (write IP config) and `REMOTE_RESET_REQUEST` (raise a restart). They drive
// the private handlers directly with hand-built request frames and tiny fake
// context trait objects so we can observe the side effects (setters fired,
// dirty flag set, restart request emitted) without standing up a full stack.

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};
    use core::net::{Ipv4Addr, SocketAddrV4};

    use embassy_futures::block_on;
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use embassy_sync::channel::Channel;
    use zweidraehte_platform::address::EthernetAddress;
    use zweidraehte_proto::address::IndividualAddress;
    use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};
    use zweidraehte_proto::messages::builder::IndicationMessage;
    use zweidraehte_proto::messages::knxip::substructs::{
        DeviceInformation, DeviceStatus, ExtendedDeviceInformation, HPAI, IpConfig, KNXMedium, Selector,
    };
    use zweidraehte_proto::messages::knxip::{RemoteBasicConfigurationRequestBuilder, RemoteResetRequestBuilder};

    use crate::context::KnxIndividualAddressContext;
    use crate::ip::IpStateView;
    use crate::layers::linklayers::knxip::context::{
        DeviceInfoContext, IpConfigWriteContext, IpDiagnosticsContext, RemoteRestartContext,
    };

    const TEST_MAC: EthernetAddress = EthernetAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    const OTHER_MAC: EthernetAddress = EthernetAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

    // --- Fakes -------------------------------------------------------------

    /// Fake device-info source. `prog_mode` and `mac` drive selector matching.
    struct FakeDeviceInfo {
        prog_mode: bool,
        mac: EthernetAddress,
    }

    impl DeviceInfoContext for FakeDeviceInfo {
        fn device_information(&self) -> DeviceInformation {
            DeviceInformation {
                medium: KNXMedium::KNXIP,
                device_status: if self.prog_mode { DeviceStatus::ProgrammingMode } else { DeviceStatus::None },
                individual_address: IndividualAddress::new(1, 1, 1),
                project_installation_identifier: 0,
                knx_serial_number: [0; 6],
                routing_multicast_address: Ipv4Addr::new(224, 0, 23, 12),
                mac_address: self.mac,
                friendly_name: [0; 30],
            }
        }

        fn extended_device_information(&self) -> ExtendedDeviceInformation {
            ExtendedDeviceInformation { medium_status: 0, max_local_apdu_len: 15, device_descriptor_type0: 0x07b0 }
        }

        fn manufacturer_code(&self) -> u16 {
            0x0083
        }
    }

    /// Fake KNX address source (needed by the config-ack response build).
    struct FakeKnxAddresses;
    impl KnxIndividualAddressContext for FakeKnxAddresses {
        fn individual_address(&self) -> IndividualAddress {
            IndividualAddress::new(1, 1, 1)
        }
    }

    /// Fake IP state recording every setter via `Cell`s. Getters return
    /// whatever was last written so the config-ack response can read it back.
    struct FakeIpState {
        ip: Cell<Ipv4Addr>,
        mask: Cell<Ipv4Addr>,
        gateway: Cell<Ipv4Addr>,
        method: Cell<u8>,
    }

    // `Ipv4Addr` has no `Default`, so spell it out (all-unspecified == 0.0.0.0).
    impl Default for FakeIpState {
        fn default() -> Self {
            Self {
                ip: Cell::new(Ipv4Addr::UNSPECIFIED),
                mask: Cell::new(Ipv4Addr::UNSPECIFIED),
                gateway: Cell::new(Ipv4Addr::UNSPECIFIED),
                method: Cell::new(0),
            }
        }
    }

    impl IpStateView for FakeIpState {
        fn configured_ip_address(&self) -> Ipv4Addr {
            self.ip.get()
        }
        fn set_configured_ip_address(&self, addr: Ipv4Addr) {
            self.ip.set(addr);
        }
        fn configured_subnet_mask(&self) -> Ipv4Addr {
            self.mask.get()
        }
        fn set_configured_subnet_mask(&self, mask: Ipv4Addr) {
            self.mask.set(mask);
        }
        fn configured_default_gateway(&self) -> Ipv4Addr {
            self.gateway.get()
        }
        fn set_configured_default_gateway(&self, gateway: Ipv4Addr) {
            self.gateway.set(gateway);
        }
        fn ip_assignment_method(&self) -> u8 {
            self.method.get()
        }
        fn set_ip_assignment_method(&self, method: u8) {
            self.method.set(method);
        }
        // The remaining fields are not touched by remote config; return
        // benign constants.
        fn routing_multicast_address(&self) -> Ipv4Addr {
            Ipv4Addr::new(224, 0, 23, 12)
        }
        fn set_routing_multicast_address(&self, _addr: Ipv4Addr) {}
        fn ttl(&self) -> u8 {
            16
        }
        fn set_ttl(&self, _ttl: u8) {}
        fn friendly_name_len(&self) -> usize {
            0
        }
        fn friendly_name(&self) -> [u8; 30] {
            [0; 30]
        }
        fn set_friendly_name(&self, _name: &[u8]) {}
        fn project_installation_id(&self) -> u16 {
            0
        }
        fn set_project_installation_id(&self, _id: u16) {}
    }

    /// Fake write context wrapping a `FakeIpState`, recording dirty-marks.
    struct FakeIpConfigWrite {
        state: FakeIpState,
        dirty: Cell<bool>,
    }
    impl IpConfigWriteContext for FakeIpConfigWrite {
        fn ip_state_mut(&self) -> &dyn IpStateView {
            &self.state
        }
        fn mark_config_dirty(&self) {
            self.dirty.set(true);
        }
    }

    /// Diagnostics view over the same `FakeIpState`, so the config-ack
    /// response reflects the just-written values.
    struct FakeIpDiagnostics<'a>(&'a FakeIpState);
    impl IpDiagnosticsContext for FakeIpDiagnostics<'_> {
        fn ip_config(&self) -> IpConfig {
            IpConfig {
                ip_address: self.0.configured_ip_address(),
                subnet_mask: self.0.configured_subnet_mask(),
                default_gateway: self.0.configured_default_gateway(),
                ip_capabilities: 0,
                ip_assignment_method: self.0.ip_assignment_method(),
            }
        }
        fn ip_current_config(&self) -> zweidraehte_proto::messages::knxip::substructs::IpCurrentConfig {
            zweidraehte_proto::messages::knxip::substructs::IpCurrentConfig {
                ip_address: self.0.configured_ip_address(),
                subnet_mask: self.0.configured_subnet_mask(),
                default_gateway: self.0.configured_default_gateway(),
                dhcp_server: Ipv4Addr::UNSPECIFIED,
                ip_assignment_method: self.0.ip_assignment_method(),
            }
        }
    }

    /// Fake restart publisher recording the last request it saw.
    #[derive(Default)]
    struct FakeRestart {
        last: RefCell<Option<RestartRequest>>,
    }
    impl RemoteRestartContext for FakeRestart {
        fn request_restart(&self, request: RestartRequest) -> bool {
            *self.last.borrow_mut() = Some(request);
            true
        }
    }

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

    /// Build a `'static` buffer manager. `ServerContext` requires
    /// `DynBufferManager<'static>` (its buffers escape into `Buffer<'static>`),
    /// so the backing pool must outlive the test — we leak it. Tests are
    /// short-lived processes, so the leak is harmless.
    fn leaked_buffer_manager<const N: usize, const SZ: usize>() -> &'static DynBufferManager<'static> {
        let pool: &'static mut [[u8; SZ]; N] = Box::leak(Box::new([[0u8; SZ]; N]));
        let mgr: &'static BufferManager<N> = Box::leak(Box::new(unsafe { BufferManager::new(pool) }));
        Box::leak(Box::new(mgr.dyn_buffer_manager()))
    }

    // --- Reset tests -------------------------------------------------------

    fn run_reset(
        prog_mode: bool,
        mac: EthernetAddress,
        selector: Selector,
        cmd: ResetCommand,
    ) -> Option<RestartRequest> {
        let device_info = FakeDeviceInfo { prog_mode, mac };
        let restart = FakeRestart::default();
        let knx_addrs = FakeKnxAddresses;
        let ind = ind_channel();
        // Buffer manager is unused by the reset path but `ServerContext`
        // needs one.
        let dyn_mgr = leaked_buffer_manager::<1, 64>();

        let ctx = ServerContext::new(
            dyn_mgr,
            ind.dyn_sender(),
            15,
            &device_info,
            None,
            None,
            Some(&restart),
            &[],
            &knx_addrs,
            None,
            None,
            0,
        );

        let (frame, len) = reset_frame(selector, cmd);
        let server = RemoteConfigurationServer::new();
        let result = block_on(server.handle_reset_request(&frame[..len], &ctx));
        assert!(result.unwrap().is_empty(), "reset must never produce a response (§4.4.4)");

        restart.last.borrow().clone()
    }

    #[test]
    fn reset_restart_emits_confirmed_erase_code() {
        let req = run_reset(true, TEST_MAC, Selector::PrgMode, ResetCommand::Restart)
            .expect("matching selector must emit a restart request");
        assert_eq!(req.erase_code, EraseCode::Confirmed);
        assert!(!req.needs_response);
    }

    #[test]
    fn reset_master_reset_emits_factory_reset_erase_code() {
        let req = run_reset(false, TEST_MAC, Selector::Mac(TEST_MAC), ResetCommand::MasterReset)
            .expect("matching MAC selector must emit a restart request");
        assert_eq!(req.erase_code, EraseCode::FactoryReset);
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
        let device_info = FakeDeviceInfo { prog_mode, mac: TEST_MAC };
        let write = FakeIpConfigWrite { state: FakeIpState::default(), dirty: Cell::new(false) };
        let knx_addrs = FakeKnxAddresses;
        let ind = ind_channel();
        let dyn_mgr = leaked_buffer_manager::<2, 256>();

        // The config-ack response reads back through a diagnostics view over
        // the *same* state, so it reflects any writes.
        let diag = FakeIpDiagnostics(&write.state);

        let ctx = ServerContext::new(
            dyn_mgr,
            ind.dyn_sender(),
            15,
            &device_info,
            Some(&diag),
            Some(&write),
            None,
            &[],
            &knx_addrs,
            None,
            None,
            0,
        );

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
            write.state.configured_ip_address(),
            write.state.configured_subnet_mask(),
            write.state.configured_default_gateway(),
            write.state.ip_assignment_method(),
            write.dirty.get(),
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
