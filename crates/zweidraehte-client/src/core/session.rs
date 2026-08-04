//! Sans-io KNX/IP tunneling session state machine (03/08/04).
//!
//! Everything protocol-shaped about a tunneling connection lives here:
//! the CONNECT handshake, the MAX_APDU feature query, TunnelingRequest/Ack
//! sequence numbers on both directions, the heartbeat, and disconnects —
//! with no socket, no executor and no clock. The caller (the
//! [`IpTunnelConnector`](crate::connector::IpTunnelConnector)) feeds in
//! received UDP packets and the current time, and executes the returned
//! [`Effect`]s. Timeouts are expressed through [`next_deadline`]
//! (TunnelSession::next_deadline) + [`poll`](TunnelSession::poll): the
//! caller sleeps until the deadline and then polls.
//!
//! Being a pure `input → effects` machine makes the fiddly parts — the
//! ACK retry, the heartbeat retry, duplicate-sequence handling — unit
//! testable without a peer.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::config::MAX_APDU_LENGTH_EXTENDED;
use zweidraehte_proto::messages::knxip::substructs::*;
use zweidraehte_proto::messages::knxip::tunneling_feature_id;
use zweidraehte_proto::messages::knxip::*;
use zweidraehte_proto::util::packets::{ParseBuffer, SerializablePacket, SerializeBuffer};

// ============================================================================
// Timing constants (03/08/02 §5.4, 03/08/04 §2.6)
// ============================================================================

/// CONNECT_REQUEST → CONNECT_RESPONSE timeout (03/08/02: 10 s).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// TunnelingFeatureGet → Response timeout. Short on purpose: interfaces
/// without the feature service simply never answer, and connect latency
/// is bounded by this.
const FEATURE_TIMEOUT: Duration = Duration::from_secs(2);

/// TunnelingRequest → TunnelingAck timeout (03/08/04 §2.6: 1 s).
const ACK_TIMEOUT: Duration = Duration::from_secs(1);

/// Heartbeat interval (03/08/02 §5.4: 60 s).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// ConnectionstateResponse timeout per attempt (03/08/02 §5.4: 10 s).
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);

/// DisconnectResponse wait before giving up.
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Offset of the cEMI payload inside a TunnelingRequest packet:
/// 6-byte KNXnet/IP header + 4-byte connection header.
const CEMI_OFFSET: usize = 10;

// ============================================================================
// Effects
// ============================================================================

/// What the session wants its embedder to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Effect {
    /// Send this UDP packet to the tunnel server.
    Send(Vec<u8>),
    /// A cEMI frame arrived from the bus — hand it to the upper layer.
    DeliverCemi(Vec<u8>),
    /// The handshake finished; the tunnel is usable.
    Opened { assigned_address: IndividualAddress, max_apdu: u16 },
    /// One queued [`send_cemi`](TunnelSession::send_cemi) finished
    /// (acknowledged or failed). Completions are FIFO with respect to the
    /// `send_cemi` calls.
    SendComplete(Result<(), SessionError>),
    /// The session died. No further effects will be produced.
    Fatal(SessionError),
    /// A locally requested [`close`](TunnelSession::close) finished.
    Closed,
}

/// Session-level failures. The connector maps these onto [`crate::Error`],
/// adding context (like the server address) the session doesn't carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// CONNECT_RESPONSE carried a non-zero status.
    Refused(ConnectionStatus),
    /// No CONNECT_RESPONSE within the timeout.
    ConnectTimeout,
    /// The CONNECT_RESPONSE was missing the tunneling CRD.
    Malformed,
    /// No TunnelingAck after the retransmission (03/08/04 §2.6 mandates
    /// tearing the connection down at this point).
    AckTimeout,
    /// The server acknowledged with a non-zero status.
    NegativeAck(ConnectionStatus),
    /// Both heartbeat attempts went unanswered (03/08/02 §5.4).
    HeartbeatLost,
    /// The server sent a DisconnectRequest.
    Disconnected,
}

// ============================================================================
// Session state
// ============================================================================

#[derive(Debug)]
enum State {
    AwaitingConnectResponse {
        deadline: Instant,
    },
    /// Waiting for the MAX_APDU TunnelingFeatureResponse. `seq_zero_used`
    /// on the outer struct stays tentative until this resolves: a silent
    /// interface never consumed sequence number 0.
    AwaitingFeatureResponse {
        deadline: Instant,
    },
    Connected,
    Disconnecting {
        deadline: Instant,
    },
    Dead,
}

#[derive(Debug)]
struct AwaitingAck {
    /// The full TunnelingRequest packet, kept for the one retransmission.
    packet: Vec<u8>,
    deadline: Instant,
    retried: bool,
}

#[derive(Debug)]
struct HeartbeatWait {
    deadline: Instant,
    retried: bool,
}

/// The tunneling session state machine. See the module docs.
#[derive(Debug)]
pub struct TunnelSession {
    state: State,
    channel_id: u8,
    assigned_address: IndividualAddress,
    tunnel_max_apdu: u16,
    /// Sequence counter for TunnelingRequests we send.
    send_seq: u8,
    /// Expected sequence counter of the next TunnelingRequest from the server.
    recv_seq: u8,
    /// In-flight TunnelingRequest awaiting its ack. The tunneling window is
    /// one frame, so further sends queue behind it.
    awaiting_ack: Option<AwaitingAck>,
    /// cEMI frames waiting for the window to free up.
    send_queue: VecDeque<Vec<u8>>,
    /// When the next ConnectionstateRequest is due (None while a response
    /// is outstanding or before the handshake finishes).
    heartbeat_next: Option<Instant>,
    /// Outstanding ConnectionstateRequest.
    heartbeat_wait: Option<HeartbeatWait>,
}

fn serialize<P: SerializablePacket>(packet: &P) -> Vec<u8> {
    let mut buf = vec![0u8; packet.bytes_len()];
    {
        let mut slice: &mut [u8] = &mut buf;
        slice.serialize(packet);
    }
    buf
}

fn nat_hpai() -> HPAI {
    HPAI::Ipv4Udp { addr: Ipv4Addr::UNSPECIFIED, port: 0 }
}

impl TunnelSession {
    // ========================================================================
    // Lifecycle
    // ========================================================================

    /// Start a new session: emits the CONNECT_REQUEST (NAT mode, link-layer
    /// tunnel) and arms the connect timeout.
    pub fn start(now: Instant) -> (Self, Vec<Effect>) {
        let cri = CRI::Tunnel(TunnelingCRI::new(TunnelingLayer::LinkLayer));
        let req = ConnectRequestBuilder::new(nat_hpai(), nat_hpai(), cri);

        let session = Self {
            state: State::AwaitingConnectResponse { deadline: now + CONNECT_TIMEOUT },
            channel_id: 0,
            assigned_address: IndividualAddress::new(0, 0, 0),
            tunnel_max_apdu: MAX_APDU_LENGTH_EXTENDED,
            send_seq: 0,
            recv_seq: 0,
            awaiting_ack: None,
            send_queue: VecDeque::new(),
            heartbeat_next: None,
            heartbeat_wait: None,
        };
        (session, vec![Effect::Send(serialize(&req))])
    }

    /// Whether the handshake has completed and the session is usable.
    pub fn is_open(&self) -> bool {
        matches!(self.state, State::Connected)
    }

    /// Ask the server to close the tunnel.
    pub fn close(&mut self, now: Instant) -> Vec<Effect> {
        let req = DisconnectRequestBuilder::new(self.channel_id, nat_hpai());
        self.state = State::Disconnecting { deadline: now + DISCONNECT_TIMEOUT };
        self.awaiting_ack = None;
        self.heartbeat_next = None;
        self.heartbeat_wait = None;
        vec![Effect::Send(serialize(&req))]
    }

    // ========================================================================
    // Sending
    // ========================================================================

    /// Queue a cEMI frame for transmission through the tunnel.
    ///
    /// The matching [`Effect::SendComplete`] fires once the server has
    /// acknowledged it (or the send failed) — completions are FIFO.
    pub fn send_cemi(&mut self, cemi: Vec<u8>, now: Instant) -> Vec<Effect> {
        self.send_queue.push_back(cemi);
        self.pump_send_queue(now)
    }

    /// Send the next queued frame if the window is free.
    fn pump_send_queue(&mut self, now: Instant) -> Vec<Effect> {
        if self.awaiting_ack.is_some() || !matches!(self.state, State::Connected) {
            return Vec::new();
        }
        let Some(cemi) = self.send_queue.pop_front() else {
            return Vec::new();
        };
        let req = TunnelingRequestBuilder::with_payload(self.channel_id, self.send_seq, &cemi);
        let packet = serialize(&req);
        self.awaiting_ack = Some(AwaitingAck { packet: packet.clone(), deadline: now + ACK_TIMEOUT, retried: false });
        vec![Effect::Send(packet)]
    }

    // ========================================================================
    // Timers
    // ========================================================================

    /// The earliest instant at which [`poll`](Self::poll) has work to do.
    pub fn next_deadline(&self) -> Option<Instant> {
        let state_deadline = match self.state {
            State::AwaitingConnectResponse { deadline } => Some(deadline),
            State::AwaitingFeatureResponse { deadline } => Some(deadline),
            State::Disconnecting { deadline } => Some(deadline),
            State::Connected | State::Dead => None,
        };
        [
            state_deadline,
            self.awaiting_ack.as_ref().map(|a| a.deadline),
            self.heartbeat_next,
            self.heartbeat_wait.as_ref().map(|h| h.deadline),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Fire every timer whose deadline has passed.
    pub fn poll(&mut self, now: Instant) -> Vec<Effect> {
        let mut effects = Vec::new();

        match self.state {
            State::AwaitingConnectResponse { deadline } if now >= deadline => {
                self.state = State::Dead;
                effects.push(Effect::Fatal(SessionError::ConnectTimeout));
                return effects;
            }
            State::AwaitingFeatureResponse { deadline } if now >= deadline => {
                // Interface doesn't implement the feature service: fall back
                // to the extended-frame default. Sequence number 0 was never
                // consumed by an answer, so keep sending from 0.
                log::debug!("TunnelingFeatureGet unanswered; assuming max APDU {}", MAX_APDU_LENGTH_EXTENDED);
                self.send_seq = 0;
                effects.extend(self.enter_connected(now));
                return effects;
            }
            State::Disconnecting { deadline } if now >= deadline => {
                self.state = State::Dead;
                effects.push(Effect::Closed);
                return effects;
            }
            _ => {}
        }

        // ACK timeout: retransmit once, then the connection is dead
        // (03/08/04 §2.6).
        if let Some(awaiting) = &mut self.awaiting_ack
            && now >= awaiting.deadline
        {
            if !awaiting.retried {
                awaiting.retried = true;
                awaiting.deadline = now + ACK_TIMEOUT;
                effects.push(Effect::Send(awaiting.packet.clone()));
            } else {
                self.awaiting_ack = None;
                self.state = State::Dead;
                effects.push(Effect::SendComplete(Err(SessionError::AckTimeout)));
                effects.push(Effect::Fatal(SessionError::AckTimeout));
                return effects;
            }
        }

        // Heartbeat due?
        if let Some(next) = self.heartbeat_next
            && now >= next
        {
            self.heartbeat_next = None;
            self.heartbeat_wait = Some(HeartbeatWait { deadline: now + HEARTBEAT_TIMEOUT, retried: false });
            let req = ConnectionstateRequestBuilder::new(self.channel_id, nat_hpai());
            effects.push(Effect::Send(serialize(&req)));
        }

        // Heartbeat response overdue?
        if let Some(wait) = &mut self.heartbeat_wait
            && now >= wait.deadline
        {
            if !wait.retried {
                wait.retried = true;
                wait.deadline = now + HEARTBEAT_TIMEOUT;
                let req = ConnectionstateRequestBuilder::new(self.channel_id, nat_hpai());
                effects.push(Effect::Send(serialize(&req)));
            } else {
                self.heartbeat_wait = None;
                self.state = State::Dead;
                effects.push(Effect::Fatal(SessionError::HeartbeatLost));
            }
        }

        effects
    }

    // ========================================================================
    // Incoming packets
    // ========================================================================

    /// Process one UDP packet received from the server.
    pub fn handle_packet(&mut self, data: &[u8], now: Instant) -> Vec<Effect> {
        let Ok(service_type) = peek_service_type(data) else {
            log::warn!("Unparseable KNX/IP packet ({} bytes)", data.len());
            return Vec::new();
        };

        match self.state {
            State::AwaitingConnectResponse { .. } => self.handle_connect_response(service_type, data, now),
            State::AwaitingFeatureResponse { .. } => self.handle_feature_phase(service_type, data, now),
            State::Connected => self.handle_connected(service_type, data, now),
            State::Disconnecting { .. } => match service_type {
                KNXnetIPServiceType::DisconnectResponse => {
                    self.state = State::Dead;
                    vec![Effect::Closed]
                }
                _ => Vec::new(),
            },
            State::Dead => Vec::new(),
        }
    }

    fn handle_connect_response(&mut self, service_type: KNXnetIPServiceType, data: &[u8], now: Instant) -> Vec<Effect> {
        if service_type != KNXnetIPServiceType::ConnectResponse {
            log::debug!("Ignoring {} during connect", service_type);
            return Vec::new();
        }
        let mut slice: &[u8] = data;
        let Ok(response) = slice.parse::<ConnectResponse>() else {
            log::warn!("Malformed CONNECT_RESPONSE");
            return Vec::new();
        };

        if response.status != ConnectionStatus::NoError {
            self.state = State::Dead;
            return vec![Effect::Fatal(SessionError::Refused(response.status))];
        }
        let Some(CRD::Tunnel(crd)) = response.crd else {
            self.state = State::Dead;
            return vec![Effect::Fatal(SessionError::Malformed)];
        };

        self.channel_id = response.communication_channel_id;
        self.assigned_address = crd.individual_address;
        log::info!("Tunnel connected: channel_id={}, assigned_address={}", self.channel_id, self.assigned_address);

        // Query the tunnel's IP-side max APDU (feature 0x07). This consumes
        // sequence number 0 only if the interface answers.
        let req = TunnelingFeatureGetBuilder::new(self.channel_id, 0, tunneling_feature_id::MAX_APDU_LENGTH);
        self.send_seq = 1;
        self.state = State::AwaitingFeatureResponse { deadline: now + FEATURE_TIMEOUT };
        vec![Effect::Send(serialize(&req))]
    }

    fn handle_feature_phase(&mut self, service_type: KNXnetIPServiceType, data: &[u8], now: Instant) -> Vec<Effect> {
        match service_type {
            KNXnetIPServiceType::TunnelingFeatureResponse => {
                let mut slice: &[u8] = data;
                let Ok(resp) = slice.parse::<TunnelingFeatureResponse>() else {
                    return Vec::new();
                };
                if resp.communication_channel_id != self.channel_id {
                    return Vec::new();
                }
                if resp.return_code == 0x00 {
                    if let Some(v) = resp.value_u16() {
                        self.tunnel_max_apdu = v;
                    } else {
                        log::warn!("TunnelingFeatureResponse value length {}, expected 2", resp.value().len());
                    }
                } else {
                    log::warn!("TunnelingFeatureResponse error 0x{:02X}", resp.return_code);
                }
                self.enter_connected(now)
            }
            // Bus traffic can start before the feature query resolves —
            // process it exactly as when connected (ack + deliver), so
            // nothing is lost and the server's sequence stays aligned.
            KNXnetIPServiceType::TunnelingRequest | KNXnetIPServiceType::DisconnectRequest => {
                self.handle_connected(service_type, data, now)
            }
            _ => {
                log::debug!("Ignoring {} during feature query", service_type);
                Vec::new()
            }
        }
    }

    fn enter_connected(&mut self, now: Instant) -> Vec<Effect> {
        self.state = State::Connected;
        self.heartbeat_next = Some(now + HEARTBEAT_INTERVAL);
        log::info!("Tunnel max APDU: {}", self.tunnel_max_apdu);
        let mut effects =
            vec![Effect::Opened { assigned_address: self.assigned_address, max_apdu: self.tunnel_max_apdu }];
        effects.extend(self.pump_send_queue(now));
        effects
    }

    fn handle_connected(&mut self, service_type: KNXnetIPServiceType, data: &[u8], now: Instant) -> Vec<Effect> {
        match service_type {
            KNXnetIPServiceType::TunnelingRequest => {
                let mut slice: &[u8] = data;
                let Ok(req) = slice.parse::<TunnelingRequest>() else {
                    return Vec::new();
                };
                if req.communication_channel_id != self.channel_id {
                    return Vec::new();
                }

                // 03/08/04 §2.6: acknowledge the expected sequence number and
                // the one before it (a repeat); silently discard anything else.
                let expected = self.recv_seq;
                let previous = self.recv_seq.wrapping_sub(1);
                if req.sequence_counter == expected {
                    self.recv_seq = self.recv_seq.wrapping_add(1);
                    let mut effects = vec![Effect::Send(self.ack_packet(req.sequence_counter))];
                    if data.len() > CEMI_OFFSET {
                        effects.push(Effect::DeliverCemi(data[CEMI_OFFSET..].to_vec()));
                    }
                    effects
                } else if req.sequence_counter == previous {
                    vec![Effect::Send(self.ack_packet(req.sequence_counter))]
                } else {
                    log::warn!("Discarding TunnelingRequest with seq {} (expected {})", req.sequence_counter, expected);
                    Vec::new()
                }
            }

            KNXnetIPServiceType::TunnelingAck => {
                let mut slice: &[u8] = data;
                let Ok(ack) = slice.parse::<TunnelingAck>() else {
                    return Vec::new();
                };
                if ack.communication_channel_id != self.channel_id || self.awaiting_ack.is_none() {
                    return Vec::new();
                }
                if ack.sequence_counter != self.send_seq {
                    return Vec::new();
                }
                self.awaiting_ack = None;
                self.send_seq = self.send_seq.wrapping_add(1);
                let result = if ack.status == ConnectionStatus::NoError {
                    Ok(())
                } else {
                    Err(SessionError::NegativeAck(ack.status))
                };
                let mut effects = vec![Effect::SendComplete(result)];
                effects.extend(self.pump_send_queue(now));
                effects
            }

            KNXnetIPServiceType::ConnectionstateResponse => {
                let mut slice: &[u8] = data;
                if let Ok(resp) = slice.parse::<ConnectionstateResponse>()
                    && resp.communication_channel_id == self.channel_id
                    && self.heartbeat_wait.take().is_some()
                {
                    self.heartbeat_next = Some(now + HEARTBEAT_INTERVAL);
                }
                Vec::new()
            }

            KNXnetIPServiceType::DisconnectRequest => {
                log::info!("Server sent DisconnectRequest");
                let resp = DisconnectResponseBuilder::new(self.channel_id, ConnectionStatus::NoError);
                self.state = State::Dead;
                vec![Effect::Send(serialize(&resp)), Effect::Fatal(SessionError::Disconnected)]
            }

            // TODO: TunnelingFeatureInfo rides the connection-header sequence
            // space on some interfaces. If one misaligns recv_seq by sending
            // these unsolicited, the previous-seq ack rule above resyncs after
            // one frame; revisit if that proves insufficient in practice.
            other => {
                log::debug!("Ignoring service type: {}", other);
                Vec::new()
            }
        }
    }

    fn ack_packet(&self, sequence_counter: u8) -> Vec<u8> {
        let ack = TunnelingAckBuilder {
            communication_channel_id: self.channel_id,
            sequence_counter,
            status: ConnectionStatus::NoError,
        };
        serialize(&ack)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const CHANNEL: u8 = 21;

    fn t0() -> Instant {
        Instant::now()
    }

    fn server_connect_response() -> Vec<u8> {
        let crd = CRD::Tunnel(TunnelingCRD::new(IndividualAddress::new(15, 15, 250)));
        serialize(&ConnectResponseBuilder::new(CHANNEL, ConnectionStatus::NoError, nat_hpai(), Some(crd)))
    }

    fn server_feature_response(max_apdu: u16) -> Vec<u8> {
        serialize(&TunnelingFeatureResponseBuilder::with_value(
            CHANNEL,
            0,
            tunneling_feature_id::MAX_APDU_LENGTH,
            0x00,
            &max_apdu.to_be_bytes(),
        ))
    }

    fn server_tunneling_request(seq: u8, cemi: &[u8]) -> Vec<u8> {
        serialize(&TunnelingRequestBuilder::with_payload(CHANNEL, seq, cemi))
    }

    fn server_ack(seq: u8) -> Vec<u8> {
        serialize(&TunnelingAckBuilder {
            communication_channel_id: CHANNEL,
            sequence_counter: seq,
            status: ConnectionStatus::NoError,
        })
    }

    /// Drive a session through the full handshake, returning it Connected.
    fn connected_session(now: Instant) -> TunnelSession {
        let (mut session, effects) = TunnelSession::start(now);
        assert!(matches!(effects[..], [Effect::Send(_)]));

        let effects = session.handle_packet(&server_connect_response(), now);
        assert!(matches!(effects[..], [Effect::Send(_)])); // FeatureGet

        let effects = session.handle_packet(&server_feature_response(254), now);
        assert!(matches!(effects[0], Effect::Opened { max_apdu: 254, .. }));
        assert!(session.is_open());
        session
    }

    #[test]
    fn handshake_with_feature_response() {
        let now = t0();
        let session = connected_session(now);
        assert_eq!(session.assigned_address, IndividualAddress::new(15, 15, 250));
        assert_eq!(session.send_seq, 1); // FeatureGet consumed seq 0
    }

    #[test]
    fn handshake_feature_timeout_falls_back() {
        let now = t0();
        let (mut session, _) = TunnelSession::start(now);
        session.handle_packet(&server_connect_response(), now);

        // No feature response — poll past the deadline.
        let effects = session.poll(now + FEATURE_TIMEOUT + Duration::from_millis(1));
        assert!(matches!(effects[0], Effect::Opened { max_apdu: MAX_APDU_LENGTH_EXTENDED, .. }));
        assert_eq!(session.send_seq, 0); // seq 0 was never consumed
    }

    #[test]
    fn connect_refused() {
        let now = t0();
        let (mut session, _) = TunnelSession::start(now);
        let resp = serialize(&ConnectResponseBuilder::new(0, ConnectionStatus::NoMoreConnections, nat_hpai(), None));
        let effects = session.handle_packet(&resp, now);
        assert_eq!(effects, vec![Effect::Fatal(SessionError::Refused(ConnectionStatus::NoMoreConnections))]);
    }

    #[test]
    fn connect_timeout() {
        let now = t0();
        let (mut session, _) = TunnelSession::start(now);
        let effects = session.poll(now + CONNECT_TIMEOUT + Duration::from_millis(1));
        assert_eq!(effects, vec![Effect::Fatal(SessionError::ConnectTimeout)]);
    }

    #[test]
    fn send_acked_and_seq_advances() {
        let now = t0();
        let mut session = connected_session(now);

        let effects = session.send_cemi(vec![0x11, 0x00], now);
        assert!(matches!(effects[..], [Effect::Send(_)]));

        let effects = session.handle_packet(&server_ack(1), now);
        assert_eq!(effects, vec![Effect::SendComplete(Ok(()))]);
        assert_eq!(session.send_seq, 2);
    }

    #[test]
    fn send_window_queues_second_frame() {
        let now = t0();
        let mut session = connected_session(now);

        assert!(matches!(session.send_cemi(vec![1], now)[..], [Effect::Send(_)]));
        // Window occupied: second send queues silently.
        assert!(session.send_cemi(vec![2], now).is_empty());

        // Ack for the first frees the window and sends the second.
        let effects = session.handle_packet(&server_ack(1), now);
        assert!(matches!(effects[..], [Effect::SendComplete(Ok(())), Effect::Send(_)]));
    }

    #[test]
    fn ack_timeout_retries_then_dies() {
        let now = t0();
        let mut session = connected_session(now);
        session.send_cemi(vec![1], now);

        // First timeout: retransmit.
        let effects = session.poll(now + ACK_TIMEOUT + Duration::from_millis(1));
        assert!(matches!(effects[..], [Effect::Send(_)]));

        // Second timeout: dead.
        let effects = session.poll(now + 2 * ACK_TIMEOUT + Duration::from_millis(2));
        assert_eq!(effects, vec![
            Effect::SendComplete(Err(SessionError::AckTimeout)),
            Effect::Fatal(SessionError::AckTimeout)
        ]);
    }

    #[test]
    fn incoming_request_acked_and_delivered() {
        let now = t0();
        let mut session = connected_session(now);

        let cemi = [0x29, 0x00, 0xBC, 0xE0, 0x11, 0x01, 0x00, 0x03, 0x01, 0x00, 0x81];
        let effects = session.handle_packet(&server_tunneling_request(0, &cemi), now);
        assert!(matches!(effects[0], Effect::Send(_))); // TunnelingAck
        assert_eq!(effects[1], Effect::DeliverCemi(cemi.to_vec()));

        // A repeat of the same frame: acked again, not delivered again.
        let effects = session.handle_packet(&server_tunneling_request(0, &cemi), now);
        assert!(matches!(effects[..], [Effect::Send(_)]));

        // Far-future sequence: discarded without ack.
        let effects = session.handle_packet(&server_tunneling_request(9, &cemi), now);
        assert!(effects.is_empty());
    }

    #[test]
    fn heartbeat_answered() {
        let now = t0();
        let mut session = connected_session(now);

        let hb_at = now + HEARTBEAT_INTERVAL + Duration::from_millis(1);
        let effects = session.poll(hb_at);
        assert!(matches!(effects[..], [Effect::Send(_)])); // ConnectionstateRequest

        let resp = serialize(&ConnectionstateResponseBuilder::new(CHANNEL, ConnectionStatus::NoError));
        assert!(session.handle_packet(&resp, hb_at).is_empty());

        // Next heartbeat is scheduled one interval later, not immediately.
        assert!(session.next_deadline().expect("heartbeat scheduled") > hb_at + HEARTBEAT_INTERVAL - HEARTBEAT_TIMEOUT);
    }

    #[test]
    fn heartbeat_unanswered_twice_is_fatal() {
        let now = t0();
        let mut session = connected_session(now);

        let hb_at = now + HEARTBEAT_INTERVAL + Duration::from_millis(1);
        assert!(matches!(session.poll(hb_at)[..], [Effect::Send(_)]));

        let retry_at = hb_at + HEARTBEAT_TIMEOUT + Duration::from_millis(1);
        assert!(matches!(session.poll(retry_at)[..], [Effect::Send(_)]));

        let dead_at = retry_at + HEARTBEAT_TIMEOUT + Duration::from_millis(1);
        assert_eq!(session.poll(dead_at), vec![Effect::Fatal(SessionError::HeartbeatLost)]);
    }

    #[test]
    fn server_disconnect_is_fatal() {
        let now = t0();
        let mut session = connected_session(now);
        let req = serialize(&DisconnectRequestBuilder::new(CHANNEL, nat_hpai()));
        let effects = session.handle_packet(&req, now);
        assert!(matches!(effects[0], Effect::Send(_))); // DisconnectResponse
        assert_eq!(effects[1], Effect::Fatal(SessionError::Disconnected));
    }

    #[test]
    fn local_close_completes_on_response() {
        let now = t0();
        let mut session = connected_session(now);
        assert!(matches!(session.close(now)[..], [Effect::Send(_)]));

        let resp = serialize(&DisconnectResponseBuilder::new(CHANNEL, ConnectionStatus::NoError));
        assert_eq!(session.handle_packet(&resp, now), vec![Effect::Closed]);
    }

    #[test]
    fn local_close_completes_on_timeout() {
        let now = t0();
        let mut session = connected_session(now);
        session.close(now);
        let effects = session.poll(now + DISCONNECT_TIMEOUT + Duration::from_millis(1));
        assert_eq!(effects, vec![Effect::Closed]);
    }
}
