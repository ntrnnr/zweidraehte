//! KNX IP Secure multicast routing tests (03/08/09 §2.2.2).
//!
//! The DUT runs in [`DutMode::SecureRouting`]: Routing family secured
//! (PID 94), Appendix A backbone key provisioned, routing multicast
//! retargeted to a per-spawn 239.250.x.y group on loopback.
//!
//! Loopback topology: the DUT binds `lo` and filters multicast echoes
//! by source address (its own 127.0.0.1), so the harness must inject
//! from a *different* loopback address — it sends from 127.0.0.2 and
//! receives on a group-joined socket, dropping its own echoes by the
//! same source-address rule in reverse (DUT frames come from
//! 127.0.0.1).
//!
//! On macOS this needs a one-time loopback alias, since only 127.0.0.1 is
//! assigned to `lo0` by default (Linux treats all of 127/8 as local):
//!
//! ```text
//! sudo ifconfig lo0 alias 127.0.0.2 up
//! ```
//!
//! Spec timings (compressed by `KNX_TIME_DIVISOR` in the DUT):
//! - `maxDelayInitialNotify` 10 s → 200 ms
//! - `maxDelayTimeFollowerPeriodicNotify` ≈ 12.8 s → ≈ 257 ms
//! - `maxDelayTimeFollowerUpdateNotify` ≈ 2.5 s → ≈ 51 ms
//! - mc_timer values stay *real* milliseconds — only the wall-clock
//!   notify windows compress.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use zweidraehte_proto::crypto::ip_secure_ccm::{self, IpSecureNonce};
use zweidraehte_proto::messages::knxip::{
    KNXnetIPServiceType, SecureWrapper, SecureWrapperBuilder, TimerNotify, TimerNotifyBuilder, peek_service_type,
};
use zweidraehte_proto::util::packets::ParseBuffer;

use crate::harness::ip_secure_stack::{DUT_BACKBONE_KEY, IP_SECURE_SERIAL_NUMBER};

use super::{DutMode, IpSecureHarness, IpSecureTest, TIME_DIVISOR, packet_bytes};

/// Spec-fixed KNXnet/IP port (03/02/06 §2.1).
const KNX_PORT: u16 = 3671;

/// Source address the harness injects from. The DUT's UDP manager
/// drops frames originating from its own 127.0.0.1, so the harness
/// claims a different address of the 127/8 loopback block.
const HARNESS_ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// Serial number the harness stamps into injected frames.
const HARNESS_SERIAL: [u8; 6] = [0x00, 0xFB, 0x00, 0x00, 0x00, 0x01];

/// DUT individual address (15.15.0) and the harness's fake source IA.
const DUT_IA: u16 = 0xFF00;
const HARNESS_IA: u16 = 0xFFFA;

/// Scaled wall-clock windows (mirror of the DUT-side parameter math
/// with PID 95 = 2000 ms, PID 96 = 0x1A → syncLatencyTolerance 203 ms).
const SYNC_TOLERANCE_MS: u64 = 2000 * 0x1A / 255; // 203, timer-value space
const MAX_INITIAL_NOTIFY: Duration = Duration::from_millis(10_000 / TIME_DIVISOR + 500);
const MAX_FOLLOWER_PERIODIC: Duration = Duration::from_millis((10_000 + 14 * SYNC_TOLERANCE_MS) / TIME_DIVISOR + 500);
const MAX_FOLLOWER_UPDATE: Duration = Duration::from_millis((100 + 12 * SYNC_TOLERANCE_MS) / TIME_DIVISOR + 500);

/// How long to wait when asserting that NO multicast data response
/// arrives. TIMER_NOTIFY frames are not data and are filtered by the
/// silence helpers.
const MC_SILENCE: Duration = Duration::from_millis(400);
const MC_RECV: Duration = Duration::from_millis(1500);

// ============================================================================
// Loopback multicast plumbing
// ============================================================================

pub struct McastNet {
    group: Ipv4Addr,
    recv: UdpSocket,
    send: UdpSocket,
}

impl McastNet {
    pub fn open(group: Ipv4Addr) -> Result<Self, String> {
        // Receive socket: SO_REUSEADDR so the DUT (also bound to :3671
        // on this host) and the harness coexist; joined to the test
        // group on the loopback interface.
        let recv = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| e.to_string())?;
        recv.set_reuse_address(true).map_err(|e| e.to_string())?;
        // macOS/BSD also need SO_REUSEPORT for the second bind to :3671 to
        // succeed (the DUT's platform socket sets it too). Not on Linux: there
        // SO_REUSEADDR already allows the dual bind, and SO_REUSEPORT would
        // load-balance datagrams across the group so the harness could miss the
        // DUT's frames.
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        recv.set_reuse_port(true).map_err(|e| e.to_string())?;
        recv.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, KNX_PORT).into())
            .map_err(|e| format!("bind :3671: {e}"))?;
        recv.join_multicast_v4(&group, &Ipv4Addr::LOCALHOST).map_err(|e| format!("join {group}: {e}"))?;
        let recv: UdpSocket = recv.into();

        // Send socket: sources from 127.0.0.2 (see HARNESS_ADDR) and
        // egresses through the loopback interface.
        let send = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| e.to_string())?;
        send.bind(&SocketAddrV4::new(HARNESS_ADDR, 0).into()).map_err(|e| format!("bind {HARNESS_ADDR}: {e}"))?;
        send.set_multicast_if_v4(&Ipv4Addr::LOCALHOST).map_err(|e| e.to_string())?;
        send.set_multicast_loop_v4(true).map_err(|e| e.to_string())?;
        let send: UdpSocket = send.into();

        Ok(Self { group, recv, send })
    }

    pub fn send_frame(&self, bytes: &[u8]) -> Result<(), String> {
        self.send
            .send_to(bytes, SocketAddrV4::new(self.group, KNX_PORT))
            .map(|_| ())
            .map_err(|e| format!("multicast send: {e}"))
    }

    /// Receive the next frame originating from the DUT (127.0.0.1),
    /// dropping our own multicast echoes.
    pub fn recv_from_dut(&self, timeout: Duration) -> Option<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.checked_duration_since(Instant::now())?;
            self.recv.set_read_timeout(Some(remaining)).ok();
            let mut buf = [0u8; 1024];
            match self.recv.recv_from(&mut buf) {
                Ok((n, src)) if src.ip() == std::net::IpAddr::V4(Ipv4Addr::LOCALHOST) => {
                    return Some(buf[..n].to_vec());
                }
                Ok(_) => continue, // our own echo
                Err(_) => return None,
            }
        }
    }
}

// ============================================================================
// Frame builders / parsers (backbone-key crypto)
// ============================================================================

fn seq48(value: u64) -> [u8; 6] {
    let b = value.to_be_bytes();
    [b[2], b[3], b[4], b[5], b[6], b[7]]
}

fn seq_to_u64(seq: &[u8; 6]) -> u64 {
    let mut b = [0u8; 8];
    b[2..8].copy_from_slice(seq);
    u64::from_be_bytes(b)
}

fn build_timer_notify(timer: u64, serial: [u8; 6], tag: [u8; 2]) -> Vec<u8> {
    let value = seq48(timer);
    let mac = ip_secure_ccm::timer_notify_mac(&DUT_BACKBONE_KEY, &value, &serial, &tag);
    packet_bytes(&TimerNotifyBuilder { timer_value: value, serial_number: serial, message_tag: tag, mac })
}

fn build_mc_wrapper(timer: u64, serial: [u8; 6], tag: [u8; 2], plain: &[u8]) -> Vec<u8> {
    let seq_info = seq48(timer);
    let mut payload = plain.to_vec();
    let assoc = SecureWrapper::associated_data(0, plain.len());
    let nonce = IpSecureNonce { seq_info, serial_number: serial, message_tag: tag };
    let mac = ip_secure_ccm::wrap_secure(&DUT_BACKBONE_KEY, &nonce, &assoc, &mut payload);
    packet_bytes(&SecureWrapperBuilder::new(0, seq_info, serial, tag, &payload, mac))
}

/// Parse + MAC-verify a TIMER_NOTIFY; `None` for other frames.
fn parse_timer_notify(frame: &[u8]) -> Option<TimerNotify> {
    if peek_service_type(frame) != Ok(KNXnetIPServiceType::TimerNotify) {
        return None;
    }
    let mut buf = frame;
    let notify: TimerNotify = buf.parse().ok()?;
    ip_secure_ccm::verify_timer_notify_mac(
        &DUT_BACKBONE_KEY,
        &notify.timer_value,
        &notify.serial_number,
        &notify.message_tag,
        &notify.mac,
    )
    .ok()?;
    Some(notify)
}

/// Decrypt + MAC-verify a multicast SECURE_WRAPPER; returns
/// `(timer value, inner frame)`.
fn unwrap_mc(frame: &[u8]) -> Result<(u64, Vec<u8>), String> {
    if peek_service_type(frame) != Ok(KNXnetIPServiceType::SecureWrapper) {
        return Err(format!("expected SECURE_WRAPPER, got {:?}", peek_service_type(frame)));
    }
    let mut buf = frame;
    let wrapper: SecureWrapper = buf.parse().map_err(|e| format!("parse SECURE_WRAPPER: {e:?}"))?;
    if wrapper.session_id != 0 {
        return Err(format!("multicast wrapper carries session id {}", wrapper.session_id));
    }
    let mut payload = buf[..wrapper.payload_len].to_vec();
    let mac: [u8; 16] = buf[wrapper.payload_len..wrapper.payload_len + 16].try_into().expect("MAC");
    let assoc = SecureWrapper::associated_data(0, wrapper.payload_len);
    let nonce = IpSecureNonce {
        seq_info: wrapper.seq_info,
        serial_number: wrapper.serial_number,
        message_tag: wrapper.message_tag,
    };
    ip_secure_ccm::unwrap_secure(&DUT_BACKBONE_KEY, &nonce, &assoc, &mut payload, &mac)
        .map_err(|_| "multicast wrapper failed backbone-key authentication".to_string())?;
    Ok((seq_to_u64(&wrapper.seq_info), payload))
}

// ============================================================================
// cEMI / Routing.ind builders
// ============================================================================

fn routing_indication(cemi: &[u8]) -> Vec<u8> {
    let total = (6 + cemi.len()) as u16;
    let mut frame = vec![0x06, 0x10, 0x05, 0x30, (total >> 8) as u8, total as u8];
    frame.extend_from_slice(cemi);
    frame
}

/// cEMI `L_Data.ind` with standard frame, hop count 6, individual
/// destination addressing.
fn cemi_l_data_ind(src: u16, dst: u16, tpdu: &[u8]) -> Vec<u8> {
    let mut cemi = vec![0x29, 0x00, 0xB0, 0x60];
    cemi.extend_from_slice(&src.to_be_bytes());
    cemi.extend_from_slice(&dst.to_be_bytes());
    cemi.push((tpdu.len() - 1) as u8);
    cemi.extend_from_slice(tpdu);
    cemi
}

/// `T_Connect` to the DUT's individual address.
fn cemi_t_connect() -> Vec<u8> {
    cemi_l_data_ind(HARNESS_IA, DUT_IA, &[0x80])
}

/// `T_Data_Connected` seq 0 carrying `A_DeviceDescriptor_Read` type 0 —
/// the canonical request every device answers, giving us an observable
/// outgoing Routing.ind (T_ACK + descriptor response).
fn cemi_device_descriptor_read() -> Vec<u8> {
    cemi_l_data_ind(HARNESS_IA, DUT_IA, &[0x43, 0x00])
}

// ============================================================================
// Timer sync helpers
// ============================================================================

/// Tracks the DUT's mc_timer from an observed frame so later
/// injections can stamp current values.
struct DutClock {
    base: u64,
    at: Instant,
}

impl DutClock {
    fn from_observation(timer: u64) -> Self {
        Self { base: timer, at: Instant::now() }
    }
    fn now(&self) -> u64 {
        self.base + self.at.elapsed().as_millis() as u64
    }
}

/// Wait for a (MAC-valid) TIMER_NOTIFY from the DUT.
fn wait_timer_notify(net: &McastNet, timeout: Duration) -> Result<TimerNotify, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining =
            deadline.checked_duration_since(Instant::now()).ok_or("no TIMER_NOTIFY from DUT within window")?;
        let frame = net.recv_from_dut(remaining).ok_or("no TIMER_NOTIFY from DUT within window")?;
        if let Some(notify) = parse_timer_notify(&frame) {
            return Ok(notify);
        }
    }
}

/// Complete the DUT's §2.2.2.3.2.8 authenticity acquisition: wait for
/// its initial TIMER_NOTIFY and echo it back (same serial + tag), which
/// proves an authentic group timer and opens the DUT's data path.
fn make_authentic(net: &McastNet) -> Result<DutClock, String> {
    let notify = wait_timer_notify(net, MAX_INITIAL_NOTIFY)?;
    if notify.serial_number != IP_SECURE_SERIAL_NUMBER {
        return Err(format!("initial TIMER_NOTIFY carries foreign serial {:02x?}", notify.serial_number));
    }
    let timer = seq_to_u64(&notify.timer_value);
    net.send_frame(&build_timer_notify(timer, notify.serial_number, notify.message_tag))?;
    // Give the DUT a moment to process the echo.
    std::thread::sleep(Duration::from_millis(50));
    Ok(DutClock::from_observation(timer))
}

/// Advance the DUT's mc_timer with a forward TIMER_NOTIFY. Fresh after
/// boot the timer sits near 0, where *any* stale stamp still falls
/// inside `latencyTolerance` of 0 — replay scenarios first need a
/// timer comfortably above the tolerance window.
fn advance_dut_clock(net: &McastNet, clock: &DutClock, jump: u64) -> Result<DutClock, String> {
    let target = clock.now() + jump;
    net.send_frame(&build_timer_notify(target, HARNESS_SERIAL, [0x77, 0x77]))?;
    std::thread::sleep(Duration::from_millis(50));
    Ok(DutClock::from_observation(target + 50))
}

/// Receive frames until a multicast SECURE_WRAPPER arrives (skipping
/// TIMER_NOTIFY chatter), or `None` on timeout.
fn recv_wrapper(net: &McastNet, timeout: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        let frame = net.recv_from_dut(remaining)?;
        if peek_service_type(&frame) == Ok(KNXnetIPServiceType::SecureWrapper) {
            return Some(frame);
        }
    }
}

/// Inject a wrapped device-descriptor request (T_Connect, then the
/// connected read) stamped with current timer values.
fn send_descriptor_request(net: &McastNet, clock: &DutClock) -> Result<(), String> {
    net.send_frame(&build_mc_wrapper(
        clock.now(),
        HARNESS_SERIAL,
        [0x11, 0x11],
        &routing_indication(&cemi_t_connect()),
    ))?;
    std::thread::sleep(Duration::from_millis(30));
    net.send_frame(&build_mc_wrapper(
        clock.now(),
        HARNESS_SERIAL,
        [0x11, 0x12],
        &routing_indication(&cemi_device_descriptor_read()),
    ))
}

// ============================================================================
// Test cases
// ============================================================================

pub fn tests() -> Vec<IpSecureTest> {
    use DutMode::SecureRouting;
    vec![
        IpSecureTest { name: "ip_secure_mc_initial_timer_notify", run: test_initial_timer_notify, mode: SecureRouting },
        IpSecureTest { name: "ip_secure_mc_rx_and_tx_wrapped", run: test_rx_and_tx_wrapped, mode: SecureRouting },
        IpSecureTest { name: "ip_secure_mc_replay_dropped", run: test_replay_dropped, mode: SecureRouting },
        IpSecureTest {
            name: "ip_secure_mc_plain_routing_dropped",
            run: test_plain_routing_dropped,
            mode: SecureRouting,
        },
        IpSecureTest {
            name: "ip_secure_mc_wrapped_non_routing_dropped",
            run: test_wrapped_non_routing_dropped,
            mode: SecureRouting,
        },
        IpSecureTest {
            name: "ip_secure_mc_timer_notify_advances",
            run: test_timer_notify_advances,
            mode: SecureRouting,
        },
        IpSecureTest { name: "ip_secure_mc_update_notify_echo", run: test_update_notify_echo, mode: SecureRouting },
        IpSecureTest { name: "ip_secure_mc_periodic_notify", run: test_periodic_notify, mode: SecureRouting },
        IpSecureTest { name: "ip_secure_mc_data_gated_until_authentic", run: test_data_gated, mode: SecureRouting },
    ]
}

/// §2.2.2.3.1.1 a): after power-up the DUT schedules a TIMER_NOTIFY
/// within `maxDelayInitialNotify`; it must MAC-verify against the
/// backbone key and carry the DUT's serial number.
fn test_initial_timer_notify(harness: &IpSecureHarness) -> Result<(), String> {
    let net = McastNet::open(harness.mcast_group)?;
    let notify = wait_timer_notify(&net, MAX_INITIAL_NOTIFY)?;
    if notify.serial_number != IP_SECURE_SERIAL_NUMBER {
        return Err(format!("TIMER_NOTIFY serial {:02x?} is not the DUT's", notify.serial_number));
    }
    Ok(())
}

/// §2.2.1.4.5 both directions: a fresh multicast wrapper is received
/// and processed (the inner T_Connect + A_DeviceDescriptor_Read reach
/// the transport layer), and every Routing.ind the DUT answers with is
/// wrapped — session id 0, valid backbone MAC, timer-fresh sequence
/// information.
fn test_rx_and_tx_wrapped(harness: &IpSecureHarness) -> Result<(), String> {
    let net = McastNet::open(harness.mcast_group)?;
    let clock = make_authentic(&net)?;
    send_descriptor_request(&net, &clock)?;

    // Expect at least one wrapped response (T_ACK, then the
    // descriptor response). Verify both that arrive.
    let mut seen = 0u32;
    let mut last_seq = 0u64;
    let deadline = Instant::now() + MC_RECV;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let Some(frame) = recv_wrapper(&net, remaining) else { break };
        let (seq, inner) = unwrap_mc(&frame)?;
        if peek_service_type(&inner) != Ok(KNXnetIPServiceType::RoutingIndication) {
            return Err(format!("wrapped response is not Routing.ind: {:?}", peek_service_type(&inner)));
        }
        // The DUT synced to our clock — its timer values must be fresh
        // (within the sync tolerance) and non-decreasing.
        let now = clock.now();
        if seq + SYNC_TOLERANCE_MS < now.saturating_sub(SYNC_TOLERANCE_MS) {
            return Err(format!("response timer value {seq} is stale against {now}"));
        }
        if seq < last_seq {
            return Err(format!("response timer values not monotonic: {seq} after {last_seq}"));
        }
        last_seq = seq;
        seen += 1;
        if seen >= 2 {
            break;
        }
    }
    if seen == 0 {
        return Err("no wrapped Routing.ind response from DUT".into());
    }
    Ok(())
}

/// §2.2.2.2.1 / E08: a wrapper older than `latencyTolerance` is a
/// replay — the inner frame must not be processed.
fn test_replay_dropped(harness: &IpSecureHarness) -> Result<(), String> {
    let net = McastNet::open(harness.mcast_group)?;
    let clock = make_authentic(&net)?;
    let clock = advance_dut_clock(&net, &clock, 100_000)?;

    let stale = clock.now() - 3_000; // > 2000 ms latencyTolerance behind
    net.send_frame(&build_mc_wrapper(stale, HARNESS_SERIAL, [0x22, 0x21], &routing_indication(&cemi_t_connect())))?;
    std::thread::sleep(Duration::from_millis(30));
    net.send_frame(&build_mc_wrapper(
        stale,
        HARNESS_SERIAL,
        [0x22, 0x22],
        &routing_indication(&cemi_device_descriptor_read()),
    ))?;

    match recv_wrapper(&net, MC_SILENCE) {
        None => Ok(()),
        Some(_) => Err("replayed wrapper was processed (DUT answered)".into()),
    }
}

/// §2.2.1.4.5: with the Routing family secured, plain Routing.ind
/// frames must not be received.
fn test_plain_routing_dropped(harness: &IpSecureHarness) -> Result<(), String> {
    let net = McastNet::open(harness.mcast_group)?;
    let _clock = make_authentic(&net)?;

    net.send_frame(&routing_indication(&cemi_t_connect()))?;
    std::thread::sleep(Duration::from_millis(30));
    net.send_frame(&routing_indication(&cemi_device_descriptor_read()))?;

    match recv_wrapper(&net, MC_SILENCE) {
        None => Ok(()),
        Some(_) => Err("plain Routing.ind was processed despite secured routing".into()),
    }
}

/// §2.2.1.4.5: a multicast wrapper may only carry Routing-family
/// services — a wrapped CONNECT_REQUEST must be ignored.
fn test_wrapped_non_routing_dropped(harness: &IpSecureHarness) -> Result<(), String> {
    let net = McastNet::open(harness.mcast_group)?;
    let clock = make_authentic(&net)?;

    net.send_frame(&build_mc_wrapper(clock.now(), HARNESS_SERIAL, [0x33, 0x33], &super::tunnel_connect_request()))?;

    match recv_wrapper(&net, MC_SILENCE) {
        None => Ok(()),
        Some(_) => Err("non-routing service inside multicast wrapper was answered".into()),
    }
}

/// §2.2.2.3.1.1: a TIMER_NOTIFY with a greater timer value advances
/// the DUT's mc_timer (forward-only sync) — visible in the sequence
/// information of its next responses.
fn test_timer_notify_advances(harness: &IpSecureHarness) -> Result<(), String> {
    let net = McastNet::open(harness.mcast_group)?;
    let clock = make_authentic(&net)?;

    let jumped = clock.now() + 500_000;
    net.send_frame(&build_timer_notify(jumped, HARNESS_SERIAL, [0x44, 0x44]))?;
    std::thread::sleep(Duration::from_millis(50));

    // Requests stamped at the advanced time must be answered with
    // sequence information at (or beyond) the adopted value.
    let advanced = DutClock::from_observation(jumped + 50);
    send_descriptor_request(&net, &advanced)?;
    let frame = recv_wrapper(&net, MC_RECV).ok_or("no response after timer adoption")?;
    let (seq, _) = unwrap_mc(&frame)?;
    if seq + SYNC_TOLERANCE_MS < jumped {
        return Err(format!("response timer {seq} below the adopted value {jumped} — DUT did not sync forward"));
    }
    Ok(())
}

/// §2.2.2.3.1.2 / E08 → E10 (A6): an outdated frame schedules an
/// update TIMER_NOTIFY that repeats the outdated sender's serial
/// number and message tag.
fn test_update_notify_echo(harness: &IpSecureHarness) -> Result<(), String> {
    let net = McastNet::open(harness.mcast_group)?;
    let clock = make_authentic(&net)?;

    let clock = advance_dut_clock(&net, &clock, 100_000)?;
    let outdated_serial: [u8; 6] = [0x00, 0xFC, 0xDE, 0xAD, 0xBE, 0xEF];
    let outdated_tag: [u8; 2] = [0x55, 0x66];
    let stale = clock.now() - 10_000;
    net.send_frame(&build_mc_wrapper(stale, outdated_serial, outdated_tag, &routing_indication(&cemi_t_connect())))?;

    let deadline = Instant::now() + MAX_FOLLOWER_UPDATE;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("no update TIMER_NOTIFY within maxDelayTimeFollowerUpdateNotify")?;
        let Some(frame) = net.recv_from_dut(remaining) else { continue };
        let Some(notify) = parse_timer_notify(&frame) else { continue };
        if notify.serial_number == outdated_serial && notify.message_tag == outdated_tag {
            // A6: the echoed notify carries the DUT's *current* timer.
            let value = seq_to_u64(&notify.timer_value);
            let now = clock.now();
            if value + 2 * SYNC_TOLERANCE_MS < now {
                return Err(format!("update notify timer {value} is stale against {now}"));
            }
            return Ok(());
        }
        // Other notifies (e.g. periodic with own serial) — keep waiting.
    }
}

/// §2.2.2.3.1.1 b): with no traffic for the follower periodic window,
/// the DUT re-announces its timer.
fn test_periodic_notify(harness: &IpSecureHarness) -> Result<(), String> {
    let net = McastNet::open(harness.mcast_group)?;
    let _clock = make_authentic(&net)?;

    let notify = wait_timer_notify(&net, MAX_FOLLOWER_PERIODIC)?;
    if notify.serial_number != IP_SECURE_SERIAL_NUMBER {
        return Err(format!("periodic TIMER_NOTIFY serial {:02x?} is not the DUT's", notify.serial_number));
    }
    Ok(())
}

/// §2.2.2.3.2.8: before the mc_timer authenticity acquisition
/// completes, wrapper payloads are withheld and the DUT sends no
/// wrappers; after the echo handshake the data path opens.
fn test_data_gated(harness: &IpSecureHarness) -> Result<(), String> {
    let net = McastNet::open(harness.mcast_group)?;

    // Inject immediately after spawn, before any timer sync: the DUT
    // adopts the (newer) timer value but must not process the payload
    // or answer.
    let early = DutClock::from_observation(5_000);
    send_descriptor_request(&net, &early)?;
    if recv_wrapper(&net, MC_SILENCE).is_some() {
        return Err("DUT answered before mc_timer authenticity was established".into());
    }

    // Complete the acquisition (echo its TIMER_NOTIFY), then the same
    // request must be answered.
    let clock = make_authentic(&net)?;
    send_descriptor_request(&net, &clock)?;
    match recv_wrapper(&net, MC_RECV) {
        Some(frame) => unwrap_mc(&frame).map(|_| ()),
        None => Err("DUT still silent after authenticity acquisition".into()),
    }
}
