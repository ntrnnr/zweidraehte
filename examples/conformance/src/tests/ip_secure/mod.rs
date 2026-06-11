//! KNX IP Secure conformance tests (08_TSSK §2.2, secure unicast scope).
//!
//! These tests run over **real loopback TCP/UDP sockets** instead of the
//! TP1 IPC harness: each test spawns a fresh `conformance-dut-ip-secure`
//! process (state isolation by process lifetime), connects to its
//! KNXnet/IP control endpoint, and acts as the KNXnet/IP secure client
//! using the proto crate's IP Secure crypto directly.
//!
//! Everything here is synchronous `std` networking — the protocol under
//! test is request/response over one TCP stream, and blocking the
//! runner's executor for the duration is harmless (the TP1 harness is
//! idle while this suite runs).
//!
//! Key material matches the DUT seed (`harness::ip_secure_stack`):
//! DAC = Appendix A "trustme" key, user 1 password hash = "secret".

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use zweidraehte_proto::crypto::ip_secure_ccm::{self, IpSecureNonce};
use zweidraehte_proto::crypto::session_key;
use zweidraehte_proto::messages::knxip::{
    KNXnetIPServiceType, SecureWrapper, SecureWrapperBuilder, SessionAuthenticateBuilder, SessionRequestBuilder,
    SessionResponse, SessionStatus, SessionStatusBuilder, SessionStatusCode, peek_service_type, substructs::HPAI,
};
use zweidraehte_proto::util::packets::{ParseBuffer, SerializablePacket, SerializeBuffer};

use crate::harness::ip_secure_stack::{DUT_DEVICE_AUTH_CODE, DUT_USER1_PASSWORD_HASH, PORT_ENV};

// ============================================================================
// Harness: DUT process + TCP client
// ============================================================================

/// Time divisor passed to the DUT (mirrors the TP1 fast mode). The
/// spec windows scale to: timeoutAuthentication 10 s → 200 ms,
/// timeoutSession 60 s → 1.2 s.
const TIME_DIVISOR: u64 = 50;
const TIMEOUT_AUTHENTICATION: Duration = Duration::from_millis(10_000 / TIME_DIVISOR);
const TIMEOUT_SESSION: Duration = Duration::from_millis(60_000 / TIME_DIVISOR);

/// How long to wait for an expected response frame.
const RECV_TIMEOUT: Duration = Duration::from_millis(1000);
/// How long to wait when asserting that NO frame arrives.
const SILENCE_TIMEOUT: Duration = Duration::from_millis(300);

pub struct IpSecureHarness {
    child: Child,
    pub port: u16,
}

impl IpSecureHarness {
    /// Spawn a fresh DUT on a free loopback port and wait for its TCP
    /// listener to accept.
    pub fn spawn() -> Result<Self, String> {
        // Reserve a free port, then release it for the DUT to bind.
        let port = {
            let probe =
                std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| format!("probe port: {e}"))?;
            probe.local_addr().map_err(|e| e.to_string())?.port()
        };

        let dut_path = std::env::current_exe()
            .map(|p| p.with_file_name("conformance-dut-ip-secure"))
            .map_err(|e| e.to_string())?;
        let child = Command::new(&dut_path)
            .env(PORT_ENV, port.to_string())
            .env("KNX_TIME_DIVISOR", TIME_DIVISOR.to_string())
            .env("RUST_LOG", std::env::var("DUT_LOG").unwrap_or_else(|_| "warn".into()))
            .spawn()
            .map_err(|e| format!("spawn {}: {e}", dut_path.display()))?;

        let harness = Self { child, port };

        // Wait for the listener to come up.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match TcpStream::connect_timeout(&harness.addr().into(), Duration::from_millis(100)) {
                Ok(_) => break,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => return Err(format!("DUT TCP endpoint never came up on port {port}: {e}")),
            }
        }
        Ok(harness)
    }

    pub fn addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port)
    }

    /// Open a KNXnet/IP secure client connection.
    pub fn connect(&self) -> Result<IpSecureClient, String> {
        let stream = TcpStream::connect(self.addr()).map_err(|e| e.to_string())?;
        stream.set_nodelay(true).ok();
        Ok(IpSecureClient::new(stream))
    }
}

impl Drop for IpSecureHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ============================================================================
// Client-side session context
// ============================================================================

/// KNXnet/IP secure client over one TCP stream — the runner-side
/// counterpart of the DUT's session state machine.
pub struct IpSecureClient {
    stream: TcpStream,
    rx_buf: Vec<u8>,
    pub client_private: [u8; 32],
    pub client_public: [u8; 32],
    pub server_public: [u8; 32],
    pub session_key: [u8; 16],
    pub session_id: u16,
    pub send_seq: u64,
    /// Serial number this client stamps into its wrappers.
    pub serial: [u8; 6],
}

impl IpSecureClient {
    fn new(stream: TcpStream) -> Self {
        let mut entropy = [0u8; 32];
        getrandom::fill(&mut entropy).expect("getrandom");
        let (client_private, client_public) = session_key::generate_keypair(&entropy);
        Self {
            stream,
            rx_buf: Vec::new(),
            client_private,
            client_public,
            server_public: [0; 32],
            session_key: [0; 16],
            session_id: 0,
            send_seq: 0,
            serial: [0xAA; 6],
        }
    }

    pub fn send_raw(&mut self, frame: &[u8]) -> Result<(), String> {
        self.stream.write_all(frame).map_err(|e| e.to_string())
    }

    pub fn send_packet<P: SerializablePacket>(&mut self, packet: &P) -> Result<(), String> {
        let mut buf = vec![0u8; packet.bytes_len()];
        let mut slice = buf.as_mut_slice();
        SerializeBuffer::serialize(&mut slice, packet);
        self.send_raw(&buf)
    }

    /// Receive one KNXnet/IP frame (header-length framed) or `None` on
    /// timeout.
    pub fn recv_frame(&mut self, timeout: Duration) -> Option<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        loop {
            // A complete frame already buffered?
            if self.rx_buf.len() >= 6 {
                let total = u16::from_be_bytes([self.rx_buf[4], self.rx_buf[5]]) as usize;
                if total >= 6 && self.rx_buf.len() >= total {
                    let frame = self.rx_buf.drain(..total).collect();
                    return Some(frame);
                }
            }
            let remaining = deadline.checked_duration_since(Instant::now())?;
            self.stream.set_read_timeout(Some(remaining)).ok();
            let mut chunk = [0u8; 1024];
            match self.stream.read(&mut chunk) {
                Ok(0) => return None, // closed
                Ok(n) => self.rx_buf.extend_from_slice(&chunk[..n]),
                Err(_) => return None, // timeout
            }
        }
    }

    /// Send SESSION_REQUEST and parse the SESSION_RESPONSE (verifying
    /// its MAC against the DAC and deriving the session key).
    pub fn session_request(&mut self, dac: &[u8; 16]) -> Result<(), String> {
        let request = SessionRequestBuilder::new(HPAI::ipv4_tcp(Ipv4Addr::UNSPECIFIED, 0), self.client_public);
        self.send_packet(&request)?;

        let frame = self.recv_frame(RECV_TIMEOUT).ok_or("no SESSION_RESPONSE")?;
        let mut buf = frame.as_slice();
        let response: SessionResponse = buf.parse().map_err(|e| format!("parse SESSION_RESPONSE: {e:?}"))?;

        let xor_xy = ip_secure_ccm::xor_public_keys(&self.client_public, &response.public_key);
        ip_secure_ccm::verify_session_response_mac(dac, response.session_id, &xor_xy, &response.mac)
            .map_err(|_| "SESSION_RESPONSE MAC mismatch (wrong DAC?)".to_string())?;

        let shared = session_key::x25519_dh(&self.client_private, &response.public_key);
        self.session_key = session_key::derive_session_key(&shared);
        self.server_public = response.public_key;
        self.session_id = response.session_id;
        self.send_seq = 0;
        Ok(())
    }

    /// Build the wrapped SESSION_AUTHENTICATE for `user_id` keyed with
    /// `password_hash` and send it.
    pub fn send_authenticate(&mut self, user_id: u8, password_hash: &[u8; 16]) -> Result<(), String> {
        let xor_xy = ip_secure_ccm::xor_public_keys(&self.client_public, &self.server_public);
        let mac = ip_secure_ccm::session_authenticate_mac(password_hash, user_id, &xor_xy);
        let auth = SessionAuthenticateBuilder::new(user_id, mac);
        let mut plain = vec![0u8; auth.bytes_len()];
        let mut slice = plain.as_mut_slice();
        SerializeBuffer::serialize(&mut slice, &auth);
        self.send_wrapped(&plain)
    }

    /// Wrap a plaintext KNXnet/IP frame for the current session and send it.
    pub fn send_wrapped(&mut self, plain: &[u8]) -> Result<(), String> {
        let seq = self.send_seq;
        self.send_seq += 1;
        let seq_bytes = seq.to_be_bytes();
        let seq_info: [u8; 6] = seq_bytes[2..8].try_into().expect("48-bit seq");

        let mut payload = plain.to_vec();
        let assoc = SecureWrapper::associated_data(self.session_id, payload.len());
        let nonce = IpSecureNonce { seq_info, serial_number: self.serial, message_tag: [0xaf, 0xfe] };
        let mac = ip_secure_ccm::wrap_secure(&self.session_key, &nonce, &assoc, &mut payload);

        let wrapper = SecureWrapperBuilder::new(self.session_id, seq_info, self.serial, [0xaf, 0xfe], &payload, mac);
        self.send_packet(&wrapper)
    }

    /// Receive a SECURE_WRAPPER and return the decrypted inner frame.
    pub fn recv_wrapped(&mut self, timeout: Duration) -> Result<Vec<u8>, String> {
        let frame = self.recv_frame(timeout).ok_or("no SECURE_WRAPPER received")?;
        let mut buf = frame.as_slice();
        let wrapper: SecureWrapper = buf.parse().map_err(|e| format!("parse SECURE_WRAPPER: {e:?}"))?;
        if wrapper.session_id != self.session_id {
            return Err(format!("wrapper for session {} (expected {})", wrapper.session_id, self.session_id));
        }

        let mut payload = buf[..wrapper.payload_len].to_vec();
        let mac: [u8; 16] = buf[wrapper.payload_len..wrapper.payload_len + 16].try_into().expect("MAC");
        let assoc = SecureWrapper::associated_data(wrapper.session_id, wrapper.payload_len);
        let nonce = IpSecureNonce {
            seq_info: wrapper.seq_info,
            serial_number: wrapper.serial_number,
            message_tag: wrapper.message_tag,
        };
        ip_secure_ccm::unwrap_secure(&self.session_key, &nonce, &assoc, &mut payload, &mac)
            .map_err(|_| "server SECURE_WRAPPER failed authentication".to_string())?;
        Ok(payload)
    }

    /// Receive a wrapped SESSION_STATUS and return its code.
    pub fn recv_status(&mut self, timeout: Duration) -> Result<SessionStatusCode, String> {
        let inner = self.recv_wrapped(timeout)?;
        let mut buf = inner.as_slice();
        let status: SessionStatus = buf.parse().map_err(|e| format!("parse SESSION_STATUS: {e:?}"))?;
        Ok(status.status)
    }

    /// Full handshake: SESSION_REQUEST → verify response → AUTHENTICATE →
    /// expect STATUS AuthenticationSuccess.
    pub fn establish_session(&mut self) -> Result<(), String> {
        self.session_request(&DUT_DEVICE_AUTH_CODE)?;
        self.send_authenticate(1, &DUT_USER1_PASSWORD_HASH)?;
        match self.recv_status(RECV_TIMEOUT)? {
            SessionStatusCode::AuthenticationSuccess => Ok(()),
            other => Err(format!("expected AuthenticationSuccess, got {other:?}")),
        }
    }
}

/// Serialize a packet to bytes (helper for plain frames).
fn packet_bytes<P: SerializablePacket>(packet: &P) -> Vec<u8> {
    let mut buf = vec![0u8; packet.bytes_len()];
    let mut slice = buf.as_mut_slice();
    SerializeBuffer::serialize(&mut slice, packet);
    buf
}

/// Plain CONNECT_REQUEST (tunnel, route-back TCP HPAIs) frame bytes.
fn tunnel_connect_request() -> Vec<u8> {
    use zweidraehte_proto::messages::knxip::ConnectRequestBuilder;
    use zweidraehte_proto::messages::knxip::substructs::{CRI, TunnelingCRI, TunnelingLayer};
    let route_back = HPAI::ipv4_tcp(Ipv4Addr::UNSPECIFIED, 0);
    packet_bytes(&ConnectRequestBuilder::new(
        route_back,
        route_back,
        CRI::Tunnel(TunnelingCRI::new(TunnelingLayer::LinkLayer)),
    ))
}

// ============================================================================
// Test cases (08_TSSK §2.2 secure unicast scope)
// ============================================================================

pub struct IpSecureTest {
    pub name: &'static str,
    pub run: fn(&IpSecureHarness) -> Result<(), String>,
}

pub fn tests() -> Vec<IpSecureTest> {
    vec![
        IpSecureTest { name: "ip_secure_2_2_session_handshake", run: test_session_handshake },
        IpSecureTest { name: "ip_secure_2_2_malformed_session_request", run: test_malformed_session_request },
        IpSecureTest { name: "ip_secure_2_2_session_request_udp_ignored", run: test_session_request_udp_ignored },
        IpSecureTest { name: "ip_secure_2_2_wrong_password_rejected", run: test_wrong_password },
        IpSecureTest { name: "ip_secure_2_2_unknown_user_rejected", run: test_unknown_user },
        IpSecureTest { name: "ip_secure_2_2_authentication_timeout", run: test_authentication_timeout },
        IpSecureTest { name: "ip_secure_2_2_unauthenticated_frame", run: test_unauthenticated_frame },
        IpSecureTest { name: "ip_secure_2_2_keepalive", run: test_keepalive },
        IpSecureTest { name: "ip_secure_2_2_session_timeout", run: test_session_timeout },
        IpSecureTest { name: "ip_secure_2_2_session_close", run: test_session_close },
        IpSecureTest { name: "ip_secure_2_2_replay_rejected", run: test_replay_rejected },
        IpSecureTest { name: "ip_secure_2_2_plain_connect_rejected", run: test_plain_connect_rejected },
        IpSecureTest { name: "ip_secure_2_2_secure_tunnel_connect", run: test_secure_tunnel_connect },
    ]
}

/// 2.2.2-style: full handshake with the Appendix A key material.
fn test_session_handshake(harness: &IpSecureHarness) -> Result<(), String> {
    let mut client = harness.connect()?;
    client.session_request(&DUT_DEVICE_AUTH_CODE)?;
    if client.session_id == 0 {
        return Err("server assigned reserved session id 0".into());
    }
    client.send_authenticate(1, &DUT_USER1_PASSWORD_HASH)?;
    match client.recv_status(RECV_TIMEOUT)? {
        SessionStatusCode::AuthenticationSuccess => Ok(()),
        other => Err(format!("expected AuthenticationSuccess, got {other:?}")),
    }
}

/// 2.2.11-style: an undersized SESSION_REQUEST is discarded silently.
fn test_malformed_session_request(harness: &IpSecureHarness) -> Result<(), String> {
    let mut client = harness.connect()?;
    // SESSION_REQUEST header claiming 14 bytes total — no public key.
    client.send_raw(&[0x06, 0x10, 0x09, 0x51, 0x00, 0x0e, 0x08, 0x02, 0, 0, 0, 0, 0, 0])?;
    match client.recv_frame(SILENCE_TIMEOUT) {
        None => Ok(()),
        Some(frame) => Err(format!("expected silence, got {} byte frame", frame.len())),
    }
}

/// §2.2.3.3: secure unicast frames over UDP are discarded.
fn test_session_request_udp_ignored(harness: &IpSecureHarness) -> Result<(), String> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    socket.set_read_timeout(Some(SILENCE_TIMEOUT)).ok();

    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy).expect("getrandom");
    let (_, public) = session_key::generate_keypair(&entropy);
    let frame = packet_bytes(&SessionRequestBuilder::new(HPAI::ipv4_tcp(Ipv4Addr::UNSPECIFIED, 0), public));
    socket.send_to(&frame, harness.addr()).map_err(|e| e.to_string())?;

    let mut buf = [0u8; 128];
    match socket.recv_from(&mut buf) {
        Err(_) => Ok(()), // timeout — request discarded
        Ok((n, _)) => Err(format!("expected silence on UDP, got {n} byte response")),
    }
}

/// 2.2.15-style: a MAC keyed with the wrong password fails the session
/// (E02 → STATUS AuthenticationFailed, session deallocated).
fn test_wrong_password(harness: &IpSecureHarness) -> Result<(), String> {
    let mut client = harness.connect()?;
    client.session_request(&DUT_DEVICE_AUTH_CODE)?;
    client.send_authenticate(1, &[0x42; 16])?;
    match client.recv_status(RECV_TIMEOUT)? {
        SessionStatusCode::AuthenticationFailed => {}
        other => return Err(format!("expected AuthenticationFailed, got {other:?}")),
    }
    // The session is deallocated — further wrappers are discarded.
    client.send_wrapped(&packet_bytes(&SessionStatusBuilder::new(SessionStatusCode::Keepalive)))?;
    match client.recv_frame(SILENCE_TIMEOUT) {
        None => Ok(()),
        Some(_) => Err("dead session still answered".into()),
    }
}

/// §2.2.3.8.2: a user ID without a programmed password hash fails.
fn test_unknown_user(harness: &IpSecureHarness) -> Result<(), String> {
    let mut client = harness.connect()?;
    client.session_request(&DUT_DEVICE_AUTH_CODE)?;
    // User 0x50 is far beyond the DUT's 2 password slots.
    client.send_authenticate(0x50, &DUT_USER1_PASSWORD_HASH)?;
    match client.recv_status(RECV_TIMEOUT)? {
        SessionStatusCode::AuthenticationFailed => Ok(()),
        other => Err(format!("expected AuthenticationFailed, got {other:?}")),
    }
}

/// 2.2.16-style: no SESSION_AUTHENTICATE within timeoutAuthentication
/// → wrapped STATUS Timeout (E06/A5).
fn test_authentication_timeout(harness: &IpSecureHarness) -> Result<(), String> {
    let mut client = harness.connect()?;
    client.session_request(&DUT_DEVICE_AUTH_CODE)?;
    // Wait out the (scaled) authentication window without authenticating.
    match client.recv_status(TIMEOUT_AUTHENTICATION + RECV_TIMEOUT)? {
        SessionStatusCode::Timeout => Ok(()),
        other => Err(format!("expected Timeout, got {other:?}")),
    }
}

/// §2.2.3.5.2.5 E05 unauthenticated: a wrapped service frame before
/// authentication → STATUS Unauthenticated + session teardown (A6).
fn test_unauthenticated_frame(harness: &IpSecureHarness) -> Result<(), String> {
    let mut client = harness.connect()?;
    client.session_request(&DUT_DEVICE_AUTH_CODE)?;
    client.send_wrapped(&tunnel_connect_request())?;
    match client.recv_status(RECV_TIMEOUT)? {
        SessionStatusCode::Unauthenticated => Ok(()),
        other => Err(format!("expected Unauthenticated, got {other:?}")),
    }
}

/// 2.2.18-style: STATUS Keepalive re-arms the session timer; the
/// session must outlive the original timeoutSession window.
fn test_keepalive(harness: &IpSecureHarness) -> Result<(), String> {
    let mut client = harness.connect()?;
    client.establish_session()?;

    // Refresh the timer with keepalives spaced well inside the session
    // window, for a total elapsed time past one full window. Without A4
    // re-arming the timer the session would be torn down before we
    // finish. Each keepalive is followed by a short settle so the DUT's
    // single-threaded loop processes it before the next.
    let keepalive = packet_bytes(&SessionStatusBuilder::new(SessionStatusCode::Keepalive));
    let elapsed_target = TIMEOUT_SESSION * 3 / 2;
    let step = TIMEOUT_SESSION / 4;
    let start = Instant::now();
    while start.elapsed() < elapsed_target {
        std::thread::sleep(step);
        client.send_wrapped(&keepalive)?;
    }

    // The session must still answer — a wrapped CONNECT_REQUEST gets a
    // wrapped CONNECT_RESPONSE (proving the session is alive past the
    // original timeout).
    client.send_wrapped(&tunnel_connect_request())?;
    let inner = client.recv_wrapped(RECV_TIMEOUT)?;
    match peek_service_type(&inner) {
        Ok(KNXnetIPServiceType::ConnectResponse) => Ok(()),
        other => Err(format!("expected wrapped ConnectResponse after keepalives, got {other:?}")),
    }
}

/// 2.2.19-style: no traffic for timeoutSession → wrapped STATUS
/// Timeout and teardown (E06/A5).
fn test_session_timeout(harness: &IpSecureHarness) -> Result<(), String> {
    let mut client = harness.connect()?;
    client.establish_session()?;
    match client.recv_status(TIMEOUT_SESSION + RECV_TIMEOUT)? {
        SessionStatusCode::Timeout => Ok(()),
        other => Err(format!("expected Timeout, got {other:?}")),
    }
}

/// E03/A3: client STATUS Close → server confirms with wrapped STATUS
/// Close and deallocates.
fn test_session_close(harness: &IpSecureHarness) -> Result<(), String> {
    let mut client = harness.connect()?;
    client.establish_session()?;
    client.send_wrapped(&packet_bytes(&SessionStatusBuilder::new(SessionStatusCode::Close)))?;
    match client.recv_status(RECV_TIMEOUT)? {
        SessionStatusCode::Close => {}
        other => return Err(format!("expected Close, got {other:?}")),
    }
    // Deallocated — further wrappers are discarded.
    client.send_wrapped(&packet_bytes(&SessionStatusBuilder::new(SessionStatusCode::Keepalive)))?;
    match client.recv_frame(SILENCE_TIMEOUT) {
        None => Ok(()),
        Some(_) => Err("closed session still answered".into()),
    }
}

/// 2.2.24-style: re-sending an already-used sequence number is a
/// replay and must be discarded; the next fresh sequence still works.
fn test_replay_rejected(harness: &IpSecureHarness) -> Result<(), String> {
    let mut client = harness.connect()?;
    client.establish_session()?;

    // Replay: rewind our counter so the next wrapper reuses the
    // authenticate frame's sequence number 0.
    client.send_seq = 0;
    client.send_wrapped(&tunnel_connect_request())?;
    if client.recv_frame(SILENCE_TIMEOUT).is_some() {
        return Err("replayed sequence number was answered".into());
    }

    // Fresh sequence number (the replay consumed our local counter
    // back up to 1, which the server already saw — advance past it).
    client.send_seq = 1;
    client.send_wrapped(&tunnel_connect_request())?;
    let inner = client.recv_wrapped(RECV_TIMEOUT)?;
    match peek_service_type(&inner) {
        Ok(KNXnetIPServiceType::ConnectResponse) => Ok(()),
        other => Err(format!("expected wrapped ConnectResponse, got {other:?}")),
    }
}

/// §2.2.1.4: with the tunnelling family secured, a plain
/// CONNECT_REQUEST is discarded.
fn test_plain_connect_rejected(harness: &IpSecureHarness) -> Result<(), String> {
    let mut client = harness.connect()?;
    client.send_raw(&tunnel_connect_request())?;
    match client.recv_frame(SILENCE_TIMEOUT) {
        None => Ok(()),
        Some(frame) => Err(format!("plain CONNECT_REQUEST answered with {} byte frame", frame.len())),
    }
}

/// End-to-end: wrapped CONNECT_REQUEST inside an authenticated session
/// → wrapped CONNECT_RESPONSE with E_NO_ERROR.
fn test_secure_tunnel_connect(harness: &IpSecureHarness) -> Result<(), String> {
    use zweidraehte_proto::messages::knxip::{ConnectResponse, ConnectionStatus};

    let mut client = harness.connect()?;
    client.establish_session()?;
    client.send_wrapped(&tunnel_connect_request())?;
    let inner = client.recv_wrapped(RECV_TIMEOUT)?;
    let mut buf = inner.as_slice();
    let response: ConnectResponse = buf.parse().map_err(|e| format!("parse ConnectResponse: {e:?}"))?;
    if response.status != ConnectionStatus::NoError {
        return Err(format!("CONNECT_RESPONSE status {:?}", response.status));
    }
    if response.communication_channel_id == 0 {
        return Err("channel id 0 assigned".into());
    }
    Ok(())
}

// ============================================================================
// Suite runner
// ============================================================================

/// Run all IP Secure tests matching `filters` (empty = all). Returns
/// `(passed, failed)`.
pub fn run_all(filters: &[String]) -> (usize, usize) {
    let selected: Vec<_> = tests()
        .into_iter()
        .filter(|t| {
            filters.is_empty()
                || filters.iter().any(|f| {
                    let f = f.to_lowercase();
                    t.name.to_lowercase().contains(&f) || "ip_secure".contains(&f)
                })
        })
        .collect();

    if selected.is_empty() {
        return (0, 0);
    }

    println!("====================================================================");
    println!("Suite: KNX IP Secure (08_TSSK §2.2, socket-level)");
    println!("--------------------------------------------------------------------");

    let mut passed = 0;
    let mut failed = 0;
    for test in selected {
        // One fresh DUT process per test: full state isolation, no
        // cross-test session or sequence-number leakage.
        let result = IpSecureHarness::spawn().and_then(|harness| (test.run)(&harness));
        match result {
            Ok(()) => {
                println!("  ✅ {}", test.name);
                passed += 1;
            }
            Err(e) => {
                println!("  ❌ {} — {}", test.name, e);
                failed += 1;
            }
        }
    }
    println!();
    (passed, failed)
}
