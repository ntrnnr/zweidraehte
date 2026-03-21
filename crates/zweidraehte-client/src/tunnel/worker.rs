//! Background tunnel worker task.
//!
//! This module implements the event loop that manages the KNX/IP tunnel
//! connection: heartbeat, sequence numbers, and frame dispatch.

use core::net::{Ipv4Addr, SocketAddrV4};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant, timeout_at};

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::encoding::cemi::{CemiMessageCode, cemi_to_knx_message};
use zweidraehte_proto::messages::knx::{ApciCode, decode_apci_code, offsets};
use zweidraehte_proto::messages::knxip::*;
use zweidraehte_proto::messages::knxip::substructs::*;
use zweidraehte_proto::messages::knxip::tunneling_feature_id;
use zweidraehte_proto::util::packets::{ParseBuffer, SerializablePacket, SerializeBuffer};

use crate::error::{Error, Result};

// ============================================================================
// Constants
// ============================================================================

/// Heartbeat interval (client sends ConnectionstateRequest every 60s).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// Timeout for ConnectionstateResponse after sending a request.
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for TunnelingAck after sending a TunnelingRequest.
const ACK_TIMEOUT: Duration = Duration::from_secs(1);

/// Timeout for waiting for a bus response after the ACK.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum buffer size for incoming/outgoing UDP packets.
const MAX_PACKET_SIZE: usize = 512;

// ============================================================================
// Command types
// ============================================================================

/// Commands sent from the user-facing API to the worker.
pub enum Command {
    /// Send a cEMI frame through the tunnel and return the bus response.
    ///
    /// The worker wraps the cEMI in a TunnelingRequest, handles the ACK,
    /// then waits for the corresponding indication from the bus. The
    /// response is returned in internal message format (converted from cEMI).
    SendFrame {
        cemi: Vec<u8>,
        expected_source: Option<IndividualAddress>,
        expected_apci: Option<ApciCode>,
        response_tx: oneshot::Sender<Result<Vec<u8>>>,
    },
    /// Send a cEMI frame but don't wait for a bus response.
    /// Used for fire-and-forget messages (like T_Connect, T_Disconnect).
    SendFrameNoResponse {
        cemi: Vec<u8>,
        response_tx: oneshot::Sender<Result<Vec<u8>>>,
    },
    /// Disconnect from the tunnel.
    Disconnect {
        response_tx: oneshot::Sender<Result<()>>,
    },
}

/// Command channel sender half (held by the client API).
pub type CommandSender = mpsc::Sender<Command>;

/// Command channel receiver half (held by the worker).
pub type CommandReceiver = mpsc::Receiver<Command>;

// ============================================================================
// Worker state
// ============================================================================

/// Timeout for TunnelingFeatureResponse after sending a TunnelingFeatureGet.
const FEATURE_TIMEOUT: Duration = Duration::from_secs(2);

pub struct TunnelWorker {
    socket: UdpSocket,
    server_addr: SocketAddrV4,
    channel_id: u8,
    assigned_address: IndividualAddress,
    send_seq: u8,
    recv_seq: u8,
    last_heartbeat: Instant,
    /// Maximum APDU length the KNX/IP tunnel itself supports, as reported
    /// by TunnelingFeatureGet (feature 0x07). This is the IP-side limit —
    /// it does NOT account for TP1 bus-side constraints or line couplers.
    /// Falls back to 254 if the interface doesn't support the feature service.
    tunnel_max_apdu: u16,
}

impl TunnelWorker {
    // ========================================================================
    // Connection lifecycle
    // ========================================================================

    /// Establish a KNX/IP tunneling connection.
    pub async fn connect(server_addr: SocketAddrV4) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // CONNECT_REQUEST: NAT mode (0.0.0.0:0), tunnel link layer.
        let nat_hpai = HPAI::Ipv4Udp {
            addr: Ipv4Addr::UNSPECIFIED,
            port: 0,
        };
        let cri = CRI::Tunnel(TunnelingCRI::new(TunnelingLayer::LinkLayer));
        let req = ConnectRequestBuilder::new(nat_hpai.clone(), nat_hpai, cri);
        Self::send_raw(&socket, server_addr, &req).await?;

        // Wait for CONNECT_RESPONSE.
        let mut recv_buf = [0u8; MAX_PACKET_SIZE];
        let (len, _source) = socket.recv_from(&mut recv_buf).await?;
        let mut response_slice: &[u8] = &recv_buf[..len];
        let response: ConnectResponse = response_slice
            .parse()
            .map_err(|_| Error::Parse("invalid ConnectResponse"))?;

        if response.status != ConnectionStatus::NoError {
            return Err(Error::ConnectionRefused {
                addr: server_addr,
                status: response.status,
            });
        }

        let assigned_address = match response.crd {
            Some(CRD::Tunnel(crd)) => crd.individual_address,
            _ => return Err(Error::Parse("missing tunneling CRD in ConnectResponse")),
        };

        let channel_id = response.communication_channel_id;

        log::info!(
            "Tunnel connected: channel_id={}, assigned_address={}",
            channel_id,
            assigned_address,
        );

        // Query the tunnel's max APDU length via TunnelingFeatureGet.
        // This is the IP-side limit (typically 254 for extended frames).
        // It does NOT reflect TP1 bus-side constraints — the real effective
        // limit also depends on the target device's max APDU (PID 56).
        let (tunnel_max_apdu, seq_consumed) = Self::query_tunnel_max_apdu(&socket, server_addr, channel_id).await;
        let send_seq = if seq_consumed { 1 } else { 0 };

        // Drain any stale packets (e.g., unsolicited TunnelingFeatureInfo)
        // so the event loop starts with a clean socket.
        Self::drain_socket(&socket).await;

        log::info!("Tunnel max APDU: {}", tunnel_max_apdu);

        Ok(Self {
            socket,
            server_addr,
            channel_id,
            assigned_address,
            send_seq,
            recv_seq: 0,
            last_heartbeat: Instant::now(),
            tunnel_max_apdu,
        })
    }

    /// The assigned individual address for this tunnel connection.
    pub fn assigned_address(&self) -> IndividualAddress {
        self.assigned_address
    }

    /// Maximum APDU length the KNX/IP tunnel itself supports.
    ///
    /// This is the IP-side limit reported by the interface via
    /// TunnelingFeatureGet (feature 0x07). It does NOT account for TP1
    /// bus-side constraints. The effective max APDU for a target device is
    /// `min(tunnel_max_apdu, device_max_apdu)` where `device_max_apdu`
    /// comes from reading PID 56 on the target device.
    pub fn tunnel_max_apdu(&self) -> u16 {
        self.tunnel_max_apdu
    }

    /// Query the tunnel's MAX_APDU_LENGTH via TunnelingFeatureGet.
    ///
    /// Returns `(max_apdu, seq_consumed)` where `seq_consumed` is true if
    /// the interface responded (meaning seq=0 was consumed and the event
    /// loop should start at seq=1).
    async fn query_tunnel_max_apdu(
        socket: &UdpSocket,
        server_addr: SocketAddrV4,
        channel_id: u8,
    ) -> (u16, bool) {
        use zweidraehte_proto::config::MAX_APDU_LENGTH_EXTENDED;

        let req = TunnelingFeatureGetBuilder::new(
            channel_id,
            0,
            tunneling_feature_id::MAX_APDU_LENGTH,
        );

        if Self::send_raw(socket, server_addr, &req).await.is_err() {
            log::warn!("Failed to send TunnelingFeatureGet, assuming tunnel max APDU {}", MAX_APDU_LENGTH_EXTENDED);
            return (MAX_APDU_LENGTH_EXTENDED, false);
        }

        let mut recv_buf = [0u8; MAX_PACKET_SIZE];
        match tokio::time::timeout(FEATURE_TIMEOUT, socket.recv_from(&mut recv_buf)).await {
            Ok(Ok((len, _))) => {
                let mut slice: &[u8] = &recv_buf[..len];
                match slice.parse::<TunnelingFeatureResponse>() {
                    Ok(resp) if resp.return_code == 0x00 => {
                        if let Some(v) = resp.value_u16() {
                            return (v, true);
                        }
                        log::warn!("TunnelingFeatureResponse value length {}, expected 2", resp.value().len());
                        return (MAX_APDU_LENGTH_EXTENDED, true);
                    }
                    Ok(resp) => {
                        log::warn!("TunnelingFeatureResponse error 0x{:02X}", resp.return_code);
                        return (MAX_APDU_LENGTH_EXTENDED, true);
                    }
                    Err(_) => {
                        log::debug!("Response was not a TunnelingFeatureResponse");
                    }
                }
            }
            Ok(Err(e)) => {
                log::warn!("Socket error waiting for TunnelingFeatureResponse: {e}");
            }
            Err(_) => {
                log::debug!("TunnelingFeatureGet timed out, interface may not support feature service");
            }
        }

        (MAX_APDU_LENGTH_EXTENDED, false)
    }

    /// Drain any pending packets from the socket without blocking.
    async fn drain_socket(socket: &UdpSocket) {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        loop {
            match tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) => {
                    log::debug!("Drained {} bytes from socket during connect", len);
                }
                _ => break,
            }
        }
    }

    // ========================================================================
    // Main event loop
    // ========================================================================

    /// Run the worker event loop.
    ///
    /// Processes commands, incoming bus indications, and heartbeat timers.
    /// Runs until a Disconnect command or server-initiated disconnect.
    pub async fn run(&mut self, cmd_rx: &mut CommandReceiver) -> Result<()> {
        let mut recv_buf = [0u8; MAX_PACKET_SIZE];

        loop {
            let heartbeat_deadline = self.last_heartbeat + HEARTBEAT_INTERVAL;

            tokio::select! {
                recv_result = self.socket.recv_from(&mut recv_buf) => {
                    let (len, _source) = recv_result?;
                    if let Err(e) = self.handle_incoming(&recv_buf[..len]).await {
                        match e {
                            Error::Disconnected => return Err(e),
                            other => log::warn!("Error handling incoming: {}", other),
                        }
                    }
                }

                cmd = cmd_rx.recv() => {
                    let Some(cmd) = cmd else {
                        // All senders dropped — clean shutdown.
                        return Ok(());
                    };
                    match cmd {
                        Command::Disconnect { response_tx } => {
                            let result = self.disconnect().await;
                            let _ = response_tx.send(result);
                            return Ok(());
                        }
                        Command::SendFrame { cemi, expected_source, expected_apci, response_tx } => {
                            let result = self.send_and_receive(&cemi, expected_source, expected_apci).await;
                            let _ = response_tx.send(result);
                        }
                        Command::SendFrameNoResponse { cemi, response_tx } => {
                            let result = self.send_and_wait_ack(&cemi).await;
                            let _ = response_tx.send(result.map(|_| Vec::new()));
                        }
                    }
                }

                _ = tokio::time::sleep_until(heartbeat_deadline) => {
                    if let Err(e) = self.send_heartbeat().await {
                        log::error!("Heartbeat failed: {}", e);
                        return Err(e);
                    }
                }
            }
        }
    }

    // ========================================================================
    // Incoming frame handling (unsolicited)
    // ========================================================================

    async fn handle_incoming(&mut self, data: &[u8]) -> Result<()> {
        let service_type = match peek_service_type(data) {
            Ok(st) => st,
            Err(_) => {
                log::warn!("Received unparseable KNX/IP packet ({} bytes)", data.len());
                return Ok(());
            }
        };

        match service_type {
            KNXnetIPServiceType::TunnelingRequest => {
                let mut slice: &[u8] = data;
                if let Ok(req) = slice.parse::<TunnelingRequest>() {
                    if req.communication_channel_id == self.channel_id {
                        self.send_ack(req.sequence_counter).await?;
                        if req.sequence_counter == self.recv_seq {
                            self.recv_seq = self.recv_seq.wrapping_add(1);
                            let cemi_data = &data[10..];
                            log::trace!(
                                "Unsolicited indication ({} bytes cEMI)",
                                cemi_data.len()
                            );
                        }
                    }
                }
            }
            KNXnetIPServiceType::DisconnectRequest => {
                log::info!("Server sent DisconnectRequest");
                let resp = DisconnectResponseBuilder::new(
                    self.channel_id,
                    ConnectionStatus::NoError,
                );
                Self::send_raw(&self.socket, self.server_addr, &resp).await?;
                return Err(Error::Disconnected);
            }
            _ => {
                log::debug!("Ignoring service type: {}", service_type);
            }
        }

        Ok(())
    }

    // ========================================================================
    // Send and receive (request-response)
    // ========================================================================

    /// Send a cEMI frame, wait for ACK, then wait for the bus response indication.
    ///
    /// The response is returned in internal message format. Optional filters
    /// allow skipping indications that don't match the expected source address
    /// or APCI code.
    async fn send_and_receive(
        &mut self,
        cemi: &[u8],
        expected_source: Option<IndividualAddress>,
        expected_apci: Option<ApciCode>,
    ) -> Result<Vec<u8>> {
        self.send_and_wait_ack(cemi).await?;
        self.wait_for_indication(expected_source, expected_apci).await
    }

    /// Send a cEMI frame and wait for the TunnelingAck. Retries once on timeout.
    async fn send_and_wait_ack(&mut self, cemi: &[u8]) -> Result<()> {
        let req = TunnelingRequestBuilder::with_payload(self.channel_id, self.send_seq, cemi);
        Self::send_raw(&self.socket, self.server_addr, &req).await?;

        if self.wait_for_ack().await? {
            return Ok(());
        }

        // Retry once.
        Self::send_raw(&self.socket, self.server_addr, &req).await?;
        if self.wait_for_ack().await? {
            return Ok(());
        }

        Err(Error::AckTimeout)
    }

    /// Wait for a TunnelingAck matching our current send_seq.
    /// Returns true if ACK received, false on timeout.
    async fn wait_for_ack(&mut self) -> Result<bool> {
        let mut recv_buf = [0u8; MAX_PACKET_SIZE];
        let deadline = Instant::now() + ACK_TIMEOUT;

        loop {
            let recv_result = timeout_at(deadline, self.socket.recv_from(&mut recv_buf)).await;
            let (len, _) = match recv_result {
                Ok(r) => r?,
                Err(_) => return Ok(false), // Timeout
            };
            let data = &recv_buf[..len];

            if let Ok(KNXnetIPServiceType::TunnelingAck) = peek_service_type(data) {
                let mut slice: &[u8] = data;
                if let Ok(ack) = slice.parse::<TunnelingAck>() {
                    if ack.communication_channel_id == self.channel_id
                        && ack.sequence_counter == self.send_seq
                    {
                        if ack.status != ConnectionStatus::NoError {
                            return Err(Error::NegativeConfirmation);
                        }
                        self.send_seq = self.send_seq.wrapping_add(1);
                        return Ok(true);
                    }
                }
            }

            // Handle other incoming frames while waiting for ACK.
            if let Ok(KNXnetIPServiceType::TunnelingRequest) = peek_service_type(data) {
                let mut slice: &[u8] = data;
                if let Ok(req) = slice.parse::<TunnelingRequest>() {
                    if req.communication_channel_id == self.channel_id {
                        self.send_ack(req.sequence_counter).await?;
                        if req.sequence_counter == self.recv_seq {
                            self.recv_seq = self.recv_seq.wrapping_add(1);
                        }
                    }
                }
            }

            if let Ok(KNXnetIPServiceType::DisconnectRequest) = peek_service_type(data) {
                return Err(Error::Disconnected);
            }
        }
    }

    /// Wait for a bus response indication (TunnelingRequest from server
    /// containing an L_Data.ind or L_Data.con cEMI frame).
    ///
    /// The response is converted to internal message format before returning.
    /// Optional filters skip indications that don't match the expected source
    /// address or APCI code (useful when unsolicited indications arrive during
    /// a request-response exchange).
    async fn wait_for_indication(
        &mut self,
        expected_source: Option<IndividualAddress>,
        expected_apci: Option<ApciCode>,
    ) -> Result<Vec<u8>> {
        let mut recv_buf = [0u8; MAX_PACKET_SIZE];
        let deadline = Instant::now() + RESPONSE_TIMEOUT;

        // We receive the L_Data.con (confirmation) first, then the
        // actual response indication (L_Data.ind).
        // TODO: Use this to distinguish "no device response" from "no confirmation".
        let mut _got_confirmation = false;

        loop {
            let recv_result = timeout_at(deadline, self.socket.recv_from(&mut recv_buf)).await;
            let (len, _) = match recv_result {
                Ok(r) => r?,
                Err(_) => return Err(Error::Timeout),
            };
            let data = &recv_buf[..len];

            if let Ok(KNXnetIPServiceType::TunnelingRequest) = peek_service_type(data) {
                let mut slice: &[u8] = data;
                if let Ok(req) = slice.parse::<TunnelingRequest>() {
                    if req.communication_channel_id == self.channel_id {
                        self.send_ack(req.sequence_counter).await?;
                        if req.sequence_counter == self.recv_seq {
                            self.recv_seq = self.recv_seq.wrapping_add(1);

                            let cemi_data = &data[10..];
                            if cemi_data.is_empty() {
                                continue;
                            }

                            let msg_code = CemiMessageCode::from(cemi_data[0]);
                            match msg_code {
                                CemiMessageCode::LDataCon => {
                                    // Bus confirmation of our request.
                                    _got_confirmation = true;
                                    // Check for negative confirmation using internal format.
                                    let con_internal = cemi_to_knx_message(cemi_data.to_vec());
                                    if !con_internal.is_empty()
                                        && (con_internal[offsets::MSG_CONTROL] & 0x01) != 0
                                    {
                                        return Err(Error::NegativeConfirmation);
                                    }
                                }
                                CemiMessageCode::LDataInd => {
                                    // Convert to internal format.
                                    let internal = cemi_to_knx_message(cemi_data.to_vec());

                                    // Filter by source address.
                                    if let Some(expected) = expected_source {
                                        if internal.len() >= offsets::MSG_SOURCE_ADDR + 2 {
                                            let source = IndividualAddress::from_bytes(
                                                &internal[offsets::MSG_SOURCE_ADDR
                                                    ..offsets::MSG_SOURCE_ADDR + 2],
                                            );
                                            if source != expected {
                                                log::debug!(
                                                    "Skipping L_Data.ind from {} (expected {})",
                                                    source,
                                                    expected,
                                                );
                                                continue;
                                            }
                                        }
                                    }

                                    // Filter by APCI code.
                                    if let Some(expected) = expected_apci {
                                        if let Some(actual) = decode_apci_code(&internal) {
                                            if actual != expected {
                                                log::debug!(
                                                    "Skipping APCI {} (expected {})",
                                                    actual,
                                                    expected,
                                                );
                                                continue;
                                            }
                                        }
                                    }

                                    return Ok(internal);
                                }
                                _ => {
                                    log::trace!("Ignoring cEMI {}", msg_code);
                                }
                            }
                        }
                    }
                }
            } else if let Ok(KNXnetIPServiceType::DisconnectRequest) = peek_service_type(data) {
                return Err(Error::Disconnected);
            }
        }
    }

    // ========================================================================
    // Heartbeat
    // ========================================================================

    async fn send_heartbeat(&mut self) -> Result<()> {
        let nat_hpai = HPAI::Ipv4Udp {
            addr: Ipv4Addr::UNSPECIFIED,
            port: 0,
        };
        let req = ConnectionstateRequestBuilder::new(self.channel_id, nat_hpai);
        Self::send_raw(&self.socket, self.server_addr, &req).await?;

        let mut recv_buf = [0u8; MAX_PACKET_SIZE];

        // Try twice with HEARTBEAT_TIMEOUT each.
        for attempt in 0..2 {
            let deadline = Instant::now() + HEARTBEAT_TIMEOUT;
            loop {
                let recv_result =
                    timeout_at(deadline, self.socket.recv_from(&mut recv_buf)).await;
                let (len, _) = match recv_result {
                    Ok(r) => r?,
                    Err(_) => break, // Timeout — try next attempt.
                };
                let data = &recv_buf[..len];

                if let Ok(KNXnetIPServiceType::ConnectionstateResponse) =
                    peek_service_type(data)
                {
                    let mut slice: &[u8] = data;
                    if let Ok(resp) = slice.parse::<ConnectionstateResponse>() {
                        if resp.communication_channel_id == self.channel_id {
                            self.last_heartbeat = Instant::now();
                            return Ok(());
                        }
                    }
                }

                // Process other frames while waiting.
                if let Err(e) = self.handle_incoming(data).await {
                    if matches!(e, Error::Disconnected) {
                        return Err(e);
                    }
                }
            }

            if attempt == 0 {
                log::warn!("Heartbeat timeout, retrying");
                Self::send_raw(&self.socket, self.server_addr, &req).await?;
            }
        }

        Err(Error::Disconnected)
    }

    // ========================================================================
    // Disconnect
    // ========================================================================

    async fn disconnect(&mut self) -> Result<()> {
        let nat_hpai = HPAI::Ipv4Udp {
            addr: Ipv4Addr::UNSPECIFIED,
            port: 0,
        };
        let req = DisconnectRequestBuilder::new(self.channel_id, nat_hpai);
        Self::send_raw(&self.socket, self.server_addr, &req).await?;

        // Best-effort wait for DisconnectResponse.
        let mut recv_buf = [0u8; MAX_PACKET_SIZE];
        let deadline = Instant::now() + Duration::from_secs(3);

        loop {
            let recv_result = timeout_at(deadline, self.socket.recv_from(&mut recv_buf)).await;
            match recv_result {
                Ok(Ok((len, _))) => {
                    if let Ok(KNXnetIPServiceType::DisconnectResponse) =
                        peek_service_type(&recv_buf[..len])
                    {
                        break;
                    }
                }
                _ => break,
            }
        }

        log::info!("Tunnel disconnected (channel_id={})", self.channel_id);
        Ok(())
    }

    // ========================================================================
    // Low-level send helpers
    // ========================================================================

    async fn send_ack(&self, sequence_counter: u8) -> Result<()> {
        let ack = TunnelingAckBuilder {
            communication_channel_id: self.channel_id,
            sequence_counter,
            status: ConnectionStatus::NoError,
        };
        Self::send_raw(&self.socket, self.server_addr, &ack).await
    }

    async fn send_raw<P: SerializablePacket>(
        socket: &UdpSocket,
        addr: SocketAddrV4,
        packet: &P,
    ) -> Result<()> {
        let len = packet.bytes_len();
        let mut buf = vec![0u8; len];
        {
            let mut slice: &mut [u8] = &mut buf;
            slice.serialize(packet);
        }
        socket.send_to(&buf, std::net::SocketAddr::V4(addr)).await?;
        Ok(())
    }
}
