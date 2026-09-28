//! KNX/IP Routing Server
//!
//! Implements a KNX/IP Routing server that handles:
//! - RoutingIndication messages (sending/receiving KNX frames over IP multicast)
//! - RoutingBusy messages (congestion control, both directions)
//! - RoutingLostMessage (packet loss notifications)
//!
//! The server includes a routing timekeeper that implements the KNX specification's
//! congestion control algorithm with states for Normal, Busy, Throttled, and Slow Duration.
//!
//! Received indications pass through a [`RoutingInbox`] before they reach the
//! network layer. 03/08/05 §2.3.5 asks every KNX IP device, not only routers,
//! to send ROUTING_BUSY when its incoming queue holds more than it can process
//! within Tprocess; the queue is what makes that backlog visible. Without it
//! the backlog piles up in the platform's UDP buffer, out of sight.
//!
//! ROUTING_LOST_MESSAGE (§2.3.4) reports overflow of a router's LAN-to-KNX
//! queue. A KNX IP device has no KNX side to forward to, so it never sends one.

use super::super::KnxNetIpContext;
use crate::layers::linklayers::is_secure_data_without_sbc;

use core::future::pending;
use core::net::{Ipv4Addr, SocketAddrV4};
use embassy_sync::channel::DynamicSender;
use embassy_time::{Duration, Instant};
use heapless::{Deque, Vec};

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::{
    buffers::{Buffer, DynBufferManager, MessageBuffer},
    builder::IndicationMessage,
    knx::{AddressType, CemiFormat, InternalFormat, KnxMessageBuffer, ServiceType},
    knxip::{
        DeviceState, KNXNETIP_HEADER_SIZE, KNXnetIPServiceType, RoutingBusy, RoutingBusyBuilder, RoutingIndication,
        RoutingLostMessage, RoutingSystemBroadcast,
    },
};
use zweidraehte_proto::util::packets::{ParseBuffer, SerializeBuffer};

use crate::ip::{IpStateView, SYSTEM_SETUP_MULTICAST_ADDRESS};

use super::{KnxNetIpServer, PendingResponse, ResponseTarget, ServerContext, ServerError};

/// Routing Server State Machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum RoutingState {
    /// Normal operation - no congestion
    Normal = 0,
    /// Routing Busy - waiting for congestion to clear
    Busy = 1,
    /// Throttled - random delay after busy (Trandom)
    Throttled = 2,
    /// Slow Duration - extended delay before returning to normal
    SlowDuration = 3,
}

/// Routing Timekeeper - implements KNX/IP specification congestion control
///
/// This implements the state machine and timing logic from KNX Specification 3/8/5
/// §2.3.5 (Figure 5):
///
/// - **Normal**: Standard operation. An implementation-specific send bucket throttle
///   (not from the spec) limits the send rate to prevent overwhelming multicast.
/// - **Busy**: Received RoutingBusy — blocked for `t_w` ms.
/// - **Throttled**: Random delay `t_random = [0..1] * N * 50ms` after busy clears.
/// - **SlowDuration**: Slow control phase lasting `t_slowduration = N * 100ms`.
///   Sending IS allowed during this phase, with a minimum spacing of `t_slow = 5ms`.
///   The congestion counter N decays by 1 every 5ms during this phase.
#[derive(Debug)]
struct RoutingTimekeeper {
    /// Current state of the routing timekeeper
    state: RoutingState,

    /// Next time when transmission is allowed (used in Busy and Throttled states)
    next_allowed_time: Instant,

    /// When the SlowDuration phase expires (only meaningful in SlowDuration state)
    slow_duration_end: Instant,

    /// Last time we received a RoutingBusy message
    last_busy_time: Instant,

    /// Time reference for N counter decay (set on transition to Normal or SlowDuration)
    state_transition_time: Instant,

    /// Last time the routing indication bucket was updated
    bucket_update_time: Instant,

    /// Last time we sent a RoutingIndication
    last_send_time: Instant,

    /// Routing indication bucket (decays over time)
    send_counter: u32,

    /// Congestion counter N (increments on RoutingBusy, decays over time)
    congestion_counter: u32,
}

impl RoutingTimekeeper {
    /// Create a new routing timekeeper
    fn new() -> Self {
        let now = Instant::now();
        Self {
            state: RoutingState::Normal,
            next_allowed_time: now,
            slow_duration_end: now,
            last_busy_time: now,
            state_transition_time: now,
            bucket_update_time: now,
            last_send_time: now,
            send_counter: 0,
            congestion_counter: 0,
        }
    }

    /// Called when a RoutingIndication is sent
    fn on_routing_indication_sent(&mut self) {
        let now = Instant::now();
        self.update_routing_indication_bucket(now);
        self.send_counter += 1;
        self.last_send_time = now;
    }

    /// Called when a RoutingBusy message is received
    fn on_routing_busy_received(&mut self, wait_time: u16) {
        let now = Instant::now();

        self.update_routing_busy_bucket(now);

        // Check if enough time elapsed since last busy (>= 10ms per spec)
        if now.duration_since(self.last_busy_time).as_millis() >= 10 {
            self.last_busy_time = now;

            // Increment congestion counter N, max 10
            if self.congestion_counter <= 9 {
                self.congestion_counter += 1;
            }
        }

        // State machine for handling RoutingBusy
        match self.state {
            RoutingState::Normal | RoutingState::Throttled | RoutingState::SlowDuration => {
                // Transition to Busy state
                self.state = RoutingState::Busy;
                self.next_allowed_time = now + embassy_time::Duration::from_millis(wait_time as u64);
            }
            RoutingState::Busy => {
                // Already in busy state - extend wait time if longer per spec
                let new_allowed = now + embassy_time::Duration::from_millis(wait_time as u64);
                if new_allowed > self.next_allowed_time {
                    self.next_allowed_time = new_allowed;
                }
            }
        }
    }

    /// Get the wait time before next transmission is allowed
    /// Returns wait time in milliseconds (0 = can send immediately)
    fn get_wait_time(&mut self) -> u16 {
        let now = Instant::now();
        self.update_routing_indication_bucket(now);
        self.update_routing_busy_bucket(now);

        trace!("GetWaitTime() state={:?}", self.state);

        let mut wait_time = 0u16;

        match self.state {
            RoutingState::Normal => {
                // Implementation-specific send rate limiting (not from KNX spec).
                // Prevents overwhelming the multicast group by enforcing a minimum
                // inter-frame gap that grows with the send bucket fill level.
                // Throttle time = max(5, 2 * send_counter - 80) ms.
                let throttle_time = (2 * self.send_counter as i32) - 80;
                let throttle_time = if throttle_time < 5 { 5 } else { throttle_time };

                let next_allowed = self.last_send_time + embassy_time::Duration::from_millis(throttle_time as u64);

                if now < next_allowed {
                    wait_time = next_allowed.duration_since(now).as_millis().min(u16::MAX as u64) as u16;
                }
            }

            RoutingState::Busy => {
                if now < self.next_allowed_time {
                    // Still need to wait
                    wait_time = self.next_allowed_time.duration_since(now).as_millis().min(u16::MAX as u64) as u16;
                } else {
                    // Busy period expired, transition to Throttled
                    self.state = RoutingState::Throttled;
                    self.next_allowed_time += embassy_time::Duration::from_millis(self.calculate_trandom() as u64);

                    trace!(
                        "GetWaitTime() state={:?} waitTime={}",
                        self.state,
                        if now < self.next_allowed_time {
                            self.next_allowed_time.duration_since(now).as_millis()
                        } else {
                            0
                        }
                    );

                    // Check if throttle period also expired
                    if now < self.next_allowed_time {
                        wait_time = self.next_allowed_time.duration_since(now).as_millis().min(u16::MAX as u64) as u16;
                    } else {
                        // Throttle expired, enter slow control phase
                        self.enter_slow_duration();
                        trace!("GetWaitTime() state={:?}", self.state);

                        // Check if slow duration also already expired
                        if now >= self.slow_duration_end {
                            self.state = RoutingState::Normal;
                            self.state_transition_time = now;
                            trace!("GetWaitTime() state={:?}", self.state);
                        }
                    }
                }
            }

            RoutingState::Throttled => {
                if now < self.next_allowed_time {
                    wait_time = self.next_allowed_time.duration_since(now).as_millis().min(u16::MAX as u64) as u16;
                } else {
                    // Transition to slow control phase
                    self.enter_slow_duration();
                    trace!("GetWaitTime() state={:?}", self.state);

                    if now >= self.slow_duration_end {
                        self.state = RoutingState::Normal;
                        self.state_transition_time = now;
                        trace!("GetWaitTime() state={:?}", self.state);
                    }
                }
            }

            RoutingState::SlowDuration => {
                // Slow control phase: sending IS allowed, but with a minimum
                // spacing of t_slow = 5ms between frames (spec 3/8/5 §2.3.5).
                if now >= self.slow_duration_end {
                    // Phase expired, back to normal
                    self.state = RoutingState::Normal;
                    self.state_transition_time = now;
                    trace!("GetWaitTime() state={:?}", self.state);
                } else {
                    // Enforce t_slow = 5ms minimum inter-frame gap
                    let next_allowed = self.last_send_time + embassy_time::Duration::from_millis(5);
                    if now < next_allowed {
                        wait_time = next_allowed.duration_since(now).as_millis().min(u16::MAX as u64) as u16;
                    }
                }
            }
        }

        // Sanity check: cap wait time at 500ms
        if wait_time > 500 {
            warn!("GetWaitTime() N={} returns much too high wait time {}", self.congestion_counter, wait_time);
        }

        trace!("GetWaitTime() N={} returns {}", self.congestion_counter, wait_time);

        wait_time
    }

    /// Update the routing indication bucket (decays over time)
    fn update_routing_indication_bucket(&mut self, now: Instant) {
        if self.send_counter != 0 {
            // Decay bucket by 1 every 20ms
            let elapsed = now.duration_since(self.bucket_update_time);
            let elapsed_20ms = (elapsed.as_millis() / 20) as u32;

            if elapsed_20ms != 0 {
                self.send_counter = self.send_counter.saturating_sub(elapsed_20ms);
                self.bucket_update_time = now;
            }
        }
    }

    /// Update the routing busy bucket (decays congestion counter N)
    ///
    /// Per spec 3/8/5 §2.3.5: N decays by 1 every `t_bd = 5ms` during slow control
    /// (SlowDuration) and in Normal state.
    fn update_routing_busy_bucket(&mut self, now: Instant) {
        if self.state != RoutingState::Normal && self.state != RoutingState::SlowDuration {
            return;
        }

        if self.congestion_counter != 0 {
            // Decay N by 1 every 5ms
            let elapsed = now.duration_since(self.state_transition_time);
            let elapsed_5ms = (elapsed.as_millis() / 5) as u32;

            if elapsed_5ms != 0 {
                self.congestion_counter = self.congestion_counter.saturating_sub(elapsed_5ms);

                trace!("UpdateRoutingBusyBucket() N={}", self.congestion_counter);

                self.state_transition_time = now;
            }
        }
    }

    /// Transition into the SlowDuration (slow control) phase.
    ///
    /// Sets the phase end time based on `t_slowduration = N * 100ms` and
    /// resets the N decay reference to the current transition point.
    fn enter_slow_duration(&mut self) {
        self.state = RoutingState::SlowDuration;
        self.slow_duration_end =
            self.next_allowed_time + embassy_time::Duration::from_millis(self.calculate_tslowduration() as u64);
        // N decay runs during slow control; anchor from the transition point
        self.state_transition_time = self.next_allowed_time;
    }

    /// Calculate Trandom - random delay after RoutingBusy clears
    ///
    /// Per spec: trandom = [0…1] random * N * 50 ms
    /// Implementation: (50 * N * random(0..1023)) >> 10
    /// This gives: 0 ≤ trandom ≤ N * 50 ms
    fn calculate_trandom(&self) -> u32 {
        // Use a simple pseudo-random based on current counter state
        // In a real implementation, you might want to use a proper PRNG
        let random = ((self.send_counter ^ self.congestion_counter) * 1103515245 + 12345) % 1024;

        // Calculate trandom: random[0..1] * N * 50ms
        // Using fixed-point: (random[0..1023] * N * 50) / 1024
        (50 * self.congestion_counter * random) >> 10
    }

    /// Calculate Tslowduration - extended delay before normal operation
    ///
    /// Formula: 100 * N
    fn calculate_tslowduration(&self) -> u32 {
        100 * self.congestion_counter
    }
}

// ================================================================================
// Incoming queue and ROUTING_BUSY (03/08/05 §2.3.5)
// ================================================================================

/// How many received datagrams the incoming queue holds.
///
/// 03/08/05 §2.3.5: "the incoming queue should be able to store at least 30
/// messages".
const ROUTING_QUEUE_FRAMES: usize = 30;

/// Byte capacity of the incoming queue.
///
/// 32 octets hold a standard-frame cEMI indication, so this bound only bites
/// when extended frames or additional information fill the queue first.
const ROUTING_QUEUE_BYTES: usize = ROUTING_QUEUE_FRAMES * 32;

/// Queue depth from which a ROUTING_BUSY names the sender of the last
/// ROUTING_INDICATION in its control field (03/08/05 §2.3.5, SHOULD).
const ADDRESSED_BUSY_DEPTH: usize = 5;

/// Queue depth from which a ROUTING_BUSY addresses every sender, control
/// field 0000h (03/08/05 §2.3.5, SHOULD).
const GENERAL_BUSY_DEPTH: usize = 10;

/// The incoming queue is full; the frame was not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InboxFull;

/// FIFO of received cEMI frames waiting for the network layer.
///
/// Frames are stored as bytes rather than pool buffers: the pool has only a
/// handful of buffers and the rest of the link layer needs them, whereas the
/// queue has to hold 30 frames.
///
/// The bytes form a ring, so a frame may wrap around the end of the storage;
/// [`front`](Self::front) returns it as two slices.
#[derive(Debug)]
struct RoutingInbox {
    bytes: [u8; ROUTING_QUEUE_BYTES],
    /// Offset of the first byte of the oldest frame.
    start: usize,
    /// Bytes occupied by queued frames.
    used: usize,
    /// Length of every queued frame, oldest first.
    lengths: Deque<u16, ROUTING_QUEUE_FRAMES>,
}

impl RoutingInbox {
    const fn new() -> Self {
        Self { bytes: [0; ROUTING_QUEUE_BYTES], start: 0, used: 0, lengths: Deque::new() }
    }

    /// Number of queued frames.
    fn len(&self) -> usize {
        self.lengths.len()
    }

    /// Append a frame and return the new queue depth.
    fn push(&mut self, frame: &[u8]) -> Result<usize, InboxFull> {
        if self.lengths.is_full() || frame.len() > ROUTING_QUEUE_BYTES - self.used {
            return Err(InboxFull);
        }

        // Write at the end of the occupied region, continuing at the start of
        // the storage if the frame runs past its end.
        let at = (self.start + self.used) % ROUTING_QUEUE_BYTES;
        let first = frame.len().min(ROUTING_QUEUE_BYTES - at);
        self.bytes[at..at + first].copy_from_slice(&frame[..first]);
        self.bytes[..frame.len() - first].copy_from_slice(&frame[first..]);

        self.used += frame.len();
        self.lengths.push_back(frame.len() as u16).expect("checked not full above");
        Ok(self.lengths.len())
    }

    /// The oldest frame, split where it wraps (the second part is empty
    /// unless it does).
    fn front(&self) -> Option<(&[u8], &[u8])> {
        let len = usize::from(*self.lengths.front()?);
        let first = len.min(ROUTING_QUEUE_BYTES - self.start);
        Some((&self.bytes[self.start..self.start + first], &self.bytes[..len - first]))
    }

    /// Remove the oldest frame.
    fn pop(&mut self) {
        let Some(len) = self.lengths.pop_front() else { return };
        let len = usize::from(len);
        self.start = (self.start + len) % ROUTING_QUEUE_BYTES;
        self.used -= len;
        if self.used == 0 {
            self.start = 0;
        }
    }
}

/// When this device last asked other senders to pause.
///
/// Each kind of ROUTING_BUSY goes out at most once per wait time. Without the
/// limit a burst would draw one busy per received frame beyond the threshold,
/// adding multicast load to a network that is already congested. The two kinds
/// are limited separately so a queue still growing after an addressed busy
/// escalates to a general one at once.
#[derive(Debug, Default)]
struct BusySender {
    last_addressed: Option<Instant>,
    last_general: Option<Instant>,
}

impl BusySender {
    /// Decide whether a queue of `depth` frames, just grown by a frame from
    /// `source`, calls for a ROUTING_BUSY. Returns its control field.
    fn control_field_for(
        &mut self,
        depth: usize,
        source: IndividualAddress,
        now: Instant,
        wait_time: u16,
    ) -> Option<u16> {
        let (last, control_field) = if depth >= GENERAL_BUSY_DEPTH {
            (&mut self.last_general, 0x0000)
        } else if depth >= ADDRESSED_BUSY_DEPTH {
            (&mut self.last_addressed, u16::from_be_bytes(source.0))
        } else {
            return None;
        };

        let wait_time = Duration::from_millis(u64::from(wait_time));
        if last.is_some_and(|sent| now < sent + wait_time) {
            return None;
        }
        *last = Some(now);
        Some(control_field)
    }
}

/// KNX/IP Routing Server
///
/// Handles routing of KNX frames over IP multicast with congestion control.
#[derive(Debug)]
pub struct RoutingServer {
    /// Outbound multicast address for routing (typically 224.0.23.12).
    ///
    /// Interior mutability so a write to
    /// `PID_ROUTING_MULTICAST_ADDRESS` or an
    /// `A_DomainAddressSerialNumber_Write` can retarget outgoing
    /// `ROUTING_INDICATION` frames at runtime without rebuilding the
    /// server (03/02/06 §4.3.5.3.5.1).
    multicast_addr: core::cell::Cell<Ipv4Addr>,

    /// Port for routing (spec-fixed to 3671 per 03/02/06 §2.1).
    port: u16,

    /// Routing timekeeper for congestion control
    timekeeper: RoutingTimekeeper,

    /// Received frames waiting for the network layer.
    inbox: RoutingInbox,

    /// Rate limit for the ROUTING_BUSY frames this device sends.
    busy: BusySender,
}

impl RoutingServer {
    /// Create a new routing server
    ///
    /// # Arguments
    /// * `multicast_addr` - Multicast address for routing (typically 224.0.23.12)
    /// * `port` - Port for routing (typically 3671)
    pub fn new(multicast_addr: Ipv4Addr, port: u16) -> Self {
        Self {
            multicast_addr: core::cell::Cell::new(multicast_addr),
            port,
            timekeeper: RoutingTimekeeper::new(),
            inbox: RoutingInbox::new(),
            busy: BusySender::default(),
        }
    }

    /// Retarget outbound routing traffic to a new multicast group.
    ///
    /// Called by the runtime rebind path after
    /// `PID_ROUTING_MULTICAST_ADDRESS` changes.  The next
    /// `ROUTING_INDICATION` send picks up the new value.
    pub fn set_multicast_addr(&self, addr: Ipv4Addr) {
        self.multicast_addr.set(addr);
    }

    /// Current outbound routing multicast group — also the destination
    /// of secure-routing TIMER_NOTIFY frames (03/08/09 §2.2.2.4.1).
    pub fn multicast_addr(&self) -> Ipv4Addr {
        self.multicast_addr.get()
    }

    /// Get the current wait time before transmission is allowed
    pub fn get_wait_time(&mut self) -> u16 {
        self.timekeeper.get_wait_time()
    }

    /// Create a RoutingIndication message from a KNX message.
    ///
    /// Uses zero-copy in-place operations:
    /// 1. Allocate buffer with headroom for KNXnet/IP header (6) + cEMI expansion (3)
    /// 2. Copy KNX data and convert to cEMI format (uses 3 bytes of headroom)
    /// 3. Wrap with KNXnet/IP header (uses remaining 6 bytes of headroom)
    ///
    /// Note: The cEMI message code is always set to L_Data.ind regardless of
    /// the incoming service type (which is typically L_Data_Req). This is per
    /// the KNX/IP routing protocol specification.
    ///
    /// Dispatches between `ROUTING_INDICATION` (0x0530) and
    /// `ROUTING_SYSTEM_BROADCAST` (0x0533) based on the message's address
    /// type. Per spec 03/02/06 §4.1.3 and 03/08/05 §2.3.2, SB frames MUST
    /// be sent to [`SYSTEM_SETUP_MULTICAST_ADDRESS`] regardless of
    /// `PID_ROUTING_MULTICAST_ADDRESS`; receivers only listen for SB
    /// traffic on that group.
    async fn create_routing_indication<'a>(
        &self,
        message: &KnxMessageBuffer<Buffer<'static>, InternalFormat>,
        context: &ServerContext<'a, impl KnxNetIpContext>,
    ) -> Result<PendingResponse, ServerError> {
        // Decide the wrap variant before converting to cEMI — after the
        // conversion the typed `KnxMessageBuffer` is consumed.
        let is_system_broadcast = message.get_address_type() == AddressType::SystemBroadcast;

        // Allocate a buffer and copy the KNX message into it.
        // Default headroom (16 bytes) is sufficient for:
        // - cEMI expansion: 3 bytes (msg_code + add_info_len + ctrl2)
        // - KNXnet/IP header: 6 bytes
        let mut buffer = context.alloc_buffer().await;
        buffer.push_slice(message.buf());

        // Convert to cEMI format (uses 3 bytes of headroom).
        // Always use L_Data_Ind for routing — outgoing messages from this
        // device are sent as indications on the KNX/IP multicast group.
        let internal_msg = KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind);
        let cemi_msg = internal_msg.into_cemi();

        // Extract the buffer and wrap it with the correct KNXnet/IP header.
        // This uses 6 more bytes of headroom — no additional allocation.
        let mut output_buffer = cemi_msg.into_inner();
        let dest_addr = if is_system_broadcast {
            RoutingSystemBroadcast::wrap_cemi(&mut output_buffer);
            SYSTEM_SETUP_MULTICAST_ADDRESS
        } else {
            RoutingIndication::wrap_cemi(&mut output_buffer);
            self.multicast_addr.get()
        };

        let destination = SocketAddrV4::new(dest_addr, self.port);
        Ok(PendingResponse { buffer: output_buffer, target: ResponseTarget::Udp { destination, socket_idx: 0 } })
    }

    /// Process a received cEMI frame from a routing message (RoutingIndication or
    /// RoutingSystemBroadcast). Validates the APDU length and the destination,
    /// then queues the frame for the network layer.
    ///
    /// Returns a ROUTING_BUSY when the queue has grown past a threshold.
    async fn handle_routing_cemi<'a>(
        &mut self,
        service_type: KNXnetIPServiceType,
        cemi_data: &[u8],
        context: &ServerContext<'a, impl KnxNetIpContext>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        // Check if the frame exceeds our configured maximum APDU length.
        // cEMI structure: msg_code(1) + add_info_len(1) + [add_info] + ctrl1(1) + ctrl2(1)
        //                + src(2) + dst(2) + npdu_len(1) + apdu...
        // The NPDU length byte encodes TPCI (1 byte) + APDU, so the APDU
        // length is npdu_len - 1. We compare against max_apdu + 1 to avoid
        // underflow when npdu_len is 0.
        let max_apdu = context.max_apdu_length();
        if cemi_data.len() >= 9 {
            let add_info_len = cemi_data[1] as usize;
            let npdu_len_offset = 2 + add_info_len + 6; // skip add_info + ctrl1 + ctrl2 + src + dst
            if cemi_data.len() > npdu_len_offset {
                let npdu_len = cemi_data[npdu_len_offset] as u16;
                if npdu_len > max_apdu + 1 {
                    let apdu_len = npdu_len - 1;
                    warn!("Dropping oversized frame: APDU length {} exceeds max {}", apdu_len, max_apdu);
                    return Err(ServerError::FrameTooLarge(apdu_len, max_apdu));
                }
            }
        }

        // Allocate a buffer and copy the cEMI data into it
        let mut knx_buffer = context.alloc_buffer().await;
        knx_buffer.push_slice(cemi_data);

        // Convert cEMI to internal format (service type derived from message code)
        let cemi_msg: KnxMessageBuffer<Buffer<'static>, CemiFormat> = KnxMessageBuffer::from_cemi(knx_buffer);
        let Ok(internal_msg) = cemi_msg.try_into_internal() else {
            warn!("Routing: dropping malformed cEMI frame");
            return Ok(Vec::new());
        };

        // Filter by destination address — on KNX/IP routing multicast we see
        // all traffic. Drop frames not addressed to this device (individual
        // address mismatch, or group address not in the address table). EFF
        // must be zero: reserved/LTE formats do not use this address policy.
        let rejected = internal_msg.ctrl2_field().extended_frame_format() != 0
            || !context.accepts_destination(internal_msg.get_dest_addr());

        if rejected {
            return Ok(Vec::new());
        }

        // The IP envelope defines this reception mode, independently of the
        // cEMI system-broadcast flag. Check before S-AL can change replay state
        // or log a failure; §5.2.1.3 requires these mismatches to be ignored.
        if service_type == KNXnetIPServiceType::RoutingSystemBroadcast && is_secure_data_without_sbc(internal_msg.buf())
        {
            return Ok(Vec::new());
        }

        // Queue the frame as received; the runtime converts it again when it
        // hands it on (see `forward_queued`). The pool buffer used for the
        // checks above is released here rather than held while queued.
        let source = internal_msg.get_source_addr();
        drop(internal_msg);
        if self.inbox.push(cemi_data).is_err() {
            warn!("Routing: incoming queue full, dropping frame from {}", source);
        }

        // Flow control (03/08/05 §2.3.5): ask senders to pause once the queue
        // holds more than we expect to process within Tprocess. A full queue
        // still counts, since its depth is exactly what the busy reports.
        //
        // TODO: measure the time the queue takes to drain instead of using
        // depth as a proxy for "not processable within Tprocess" (100 ms).
        // The depths are the spec's own suggested thresholds.
        let wait_time = context.ip_config_write().ip_state_mut().routing_busy_wait_time();
        let Some(control_field) = self.busy.control_field_for(self.inbox.len(), source, Instant::now(), wait_time)
        else {
            return Ok(Vec::new());
        };
        debug!("Routing: queue depth {}, sending ROUTING_BUSY {:04x}", self.inbox.len(), control_field);

        // The device state reports no KNX fault and no IP fault, matching
        // PID_KNXNETIP_DEVICE_STATE: a device receiving routing frames has IP
        // access, and an end device has no KNX side to lose. The busy goes out
        // plain: 03/08/09 §2.2.1.4.5 secures only ROUTING_INDICATION.
        let mut buffer = context.alloc_buffer().await;
        buffer.serialize(&RoutingBusyBuilder { device_state: DeviceState::none(), wait_time, control_field });
        let destination = SocketAddrV4::new(self.multicast_addr.get(), self.port);
        let mut responses = Vec::new();
        let _ = responses.push(PendingResponse {
            buffer,
            target: ResponseTarget::Udp { destination, socket_idx: context.socket_idx },
        });
        Ok(responses)
    }

    /// Hand the oldest queued frame to the network layer.
    ///
    /// Pends forever while the queue is empty. The frame stays queued: the
    /// caller removes it with [`pop_forwarded`](Self::pop_forwarded) once this
    /// future completes. A future cancelled before then, because the runtime's
    /// select took another branch, has not delivered the frame, and dropping
    /// it only returns the pool buffer.
    pub async fn forward_queued(
        &self,
        buffers: &DynBufferManager<'static>,
        ind_tx: DynamicSender<'_, IndicationMessage<Buffer<'static>>>,
    ) {
        let Some((first, second)) = self.inbox.front() else {
            return pending().await;
        };

        let mut buffer = buffers.alloc().await;
        buffer.push_slice(first);
        buffer.push_slice(second);

        // The receive path already converted this frame once to check its
        // destination, so this cannot fail; complete anyway so the frame is
        // removed rather than retried forever.
        let cemi_msg: KnxMessageBuffer<Buffer<'static>, CemiFormat> = KnxMessageBuffer::from_cemi(buffer);
        let Ok(internal_msg) = cemi_msg.try_into_internal() else {
            warn!("Routing: dropping queued frame that no longer converts");
            return;
        };
        ind_tx.send(IndicationMessage::indication(internal_msg)).await;
    }

    /// Remove the frame a completed [`forward_queued`](Self::forward_queued)
    /// delivered.
    pub fn pop_forwarded(&mut self) {
        self.inbox.pop();
    }
}

impl KnxNetIpServer for RoutingServer {
    async fn on_indication<'a>(
        &mut self,
        service_type: KNXnetIPServiceType,
        mut data: &[u8],
        _source: SocketAddrV4,
        context: &ServerContext<'a, impl KnxNetIpContext>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        match service_type {
            KNXnetIPServiceType::RoutingIndication => {
                let indication = data.parse::<RoutingIndication<_>>().map_err(|e| {
                    debug!("Failed to parse RoutingIndication: {:?}", e);
                    ServerError::ParseError
                })?;

                self.handle_routing_cemi(service_type, indication.cemi_data(), context).await
            }

            KNXnetIPServiceType::RoutingSystemBroadcast => {
                // Same wire format as RoutingIndication (KNXnet/IP header + cEMI).
                // The dispatch layer already validated the header and extracted the
                // service type, so we just skip the 6-byte header to get the cEMI.
                if data.len() <= KNXNETIP_HEADER_SIZE {
                    debug!("RoutingSystemBroadcast too short: {} bytes", data.len());
                    return Err(ServerError::ParseError);
                }
                let cemi_data = &data[KNXNETIP_HEADER_SIZE..];

                self.handle_routing_cemi(service_type, cemi_data, context).await
            }

            KNXnetIPServiceType::RoutingBusy => {
                // Parse the RoutingBusy message
                let mut buffer = data;
                let busy = buffer.parse::<RoutingBusy>().map_err(|e| {
                    debug!("Failed to parse RoutingBusy: {:?}", e);
                    ServerError::ParseError
                })?;

                self.timekeeper.on_routing_busy_received(busy.wait_time);

                debug!("RoutingBusy received: wait_time={}ms", busy.wait_time);

                // No response needed
                Ok(Vec::new())
            }

            KNXnetIPServiceType::RoutingLostMessage => {
                let lost = data.parse::<RoutingLostMessage>().map_err(|e| {
                    debug!("Failed to parse RoutingLostMessage: {:?}", e);
                    ServerError::ParseError
                })?;

                warn!("RoutingLostMessage: {} messages lost", lost.lost_message_count);

                // No response needed
                Ok(Vec::new())
            }

            _ => Err(ServerError::Unsupported),
        }
    }

    async fn on_request<'a>(
        &mut self,
        message: &KnxMessageBuffer<Buffer<'static>>,
        context: &ServerContext<'a, impl KnxNetIpContext>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        // Check if we're allowed to send
        let wait_time = self.timekeeper.get_wait_time();

        if wait_time > 0 {
            // We need to wait - caller should retry after the specified time
            trace!("RoutingServer: throttled, need to wait {}ms", wait_time);
            return Err(ServerError::Busy(wait_time));
        }

        // Create RoutingIndication packet
        let response = self.create_routing_indication(message, context).await?;

        // Update timekeeper
        self.timekeeper.on_routing_indication_sent();

        let mut responses = Vec::new();
        let _ = responses.push(response);

        Ok(responses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ApduLengthContext, BufferManagerContext};
    use crate::layers::linklayers::knxip::context::IpConfigWriteContext;
    use crate::layers::linklayers::{knxip::test_support::TestContext, test_support::secure_frame};
    use embassy_futures::{block_on, poll_once};
    use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
    use zweidraehte_platform::address::EthernetAddress;
    use zweidraehte_proto::crypto::scf::{SecureServiceType, SecurityControlField};
    use zweidraehte_proto::messages::knx::{ApciCode, DestinationAddress};

    #[test]
    fn system_broadcast_requires_sbc_only_for_secure_data() {
        let device = TestContext::new(false, EthernetAddress([1, 2, 3, 4, 5, 6]));
        device.set_max_apdu_length(64);
        let indications = Channel::<NoopRawMutex, _, 1>::new();
        let context = ServerContext::new(&device, indications.dyn_sender(), &[], None, 0);
        let mut server = RoutingServer::new(Ipv4Addr::new(224, 0, 23, 12), 3671);

        // The IP service is authoritative. Exercise both cEMI control-flag
        // values so a system-broadcast envelope cannot bypass the check by
        // carrying the ordinary-broadcast flag inside it.
        for routing in [KNXnetIPServiceType::RoutingIndication, KNXnetIPServiceType::RoutingSystemBroadcast] {
            for destination in [DestinationAddress::Broadcast, DestinationAddress::SystemBroadcast] {
                for service in
                    [SecureServiceType::Data, SecureServiceType::SyncRequest, SecureServiceType::SyncResponse]
                {
                    for confidentiality in [false, true] {
                        if service != SecureServiceType::Data && !confidentiality {
                            continue;
                        }
                        for sbc in [false, true] {
                            let internal = secure_frame(destination, SecurityControlField {
                                service,
                                system_broadcast: sbc,
                                confidentiality,
                                tool_access: true,
                            });
                            let buffer =
                                device.buffer_manager().try_alloc_from_slice(&internal).expect("free input buffer");
                            let mut wire =
                                KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind).into_cemi().into_inner();
                            if routing == KNXnetIPServiceType::RoutingSystemBroadcast {
                                RoutingSystemBroadcast::wrap_cemi(&mut wire);
                            } else {
                                RoutingIndication::wrap_cemi(&mut wire);
                            }
                            block_on(server.on_indication(
                                routing,
                                &wire,
                                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3671),
                                &context,
                            ))
                            .expect("valid routing packet");
                            let accepted = take_queued(&mut server);
                            assert_eq!(
                                accepted,
                                routing == KNXnetIPServiceType::RoutingIndication
                                    || service != SecureServiceType::Data
                                    || sbc,
                                "routing={routing:?}, destination={destination:?}, service={service:?}, SBC={sbc}, confidentiality={confidentiality}"
                            );
                        }
                    }
                }
            }
        }

        let mut plain = secure_frame(DestinationAddress::SystemBroadcast, SecurityControlField {
            service: SecureServiceType::Data,
            system_broadcast: false,
            confidentiality: true,
            tool_access: true,
        });
        KnxMessageBuffer::from_buffer(plain.as_mut_slice()).set_apci_code(ApciCode::IndividualAddressRead);
        let buffer = device.buffer_manager().try_alloc_from_slice(&plain).expect("free input buffer");
        let mut wire = KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind).into_cemi().into_inner();
        RoutingSystemBroadcast::wrap_cemi(&mut wire);
        block_on(server.on_indication(
            KNXnetIPServiceType::RoutingSystemBroadcast,
            &wire,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3671),
            &context,
        ))
        .expect("plain routing packet");
        assert!(take_queued(&mut server));
    }

    #[test]
    fn truncated_cemi_is_dropped_without_reaching_the_network_layer() {
        let device = TestContext::new(false, EthernetAddress([1, 2, 3, 4, 5, 6]));
        device.set_max_apdu_length(64);
        let indications = Channel::<NoopRawMutex, _, 1>::new();
        let context = ServerContext::new(&device, indications.dyn_sender(), &[], None, 0);
        let mut server = RoutingServer::new(Ipv4Addr::new(224, 0, 23, 12), 3671);

        let mut plain = secure_frame(DestinationAddress::SystemBroadcast, SecurityControlField {
            service: SecureServiceType::Data,
            system_broadcast: false,
            confidentiality: true,
            tool_access: true,
        });
        KnxMessageBuffer::from_buffer(plain.as_mut_slice()).set_apci_code(ApciCode::IndividualAddressRead);
        let buffer = device.buffer_manager().try_alloc_from_slice(&plain).expect("free input buffer");
        let mut wire = KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind).into_cemi().into_inner();
        RoutingSystemBroadcast::wrap_cemi(&mut wire);

        // Every proper prefix of the cEMI frame is incomplete. The one-octet
        // prefix used to panic, and prefixes short of the TPCI were passed
        // on with their cEMI bytes read as internal format.
        for cemi_len in 1..wire.len() - KNXNETIP_HEADER_SIZE {
            let responses = block_on(server.on_indication(
                KNXnetIPServiceType::RoutingSystemBroadcast,
                &wire[..KNXNETIP_HEADER_SIZE + cemi_len],
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3671),
                &context,
            ))
            .expect("a malformed cEMI frame is dropped, not a server error");
            assert!(responses.is_empty());
            assert!(!take_queued(&mut server), "accepted {cemi_len}-octet cEMI prefix");
        }

        block_on(server.on_indication(
            KNXnetIPServiceType::RoutingSystemBroadcast,
            &wire,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3671),
            &context,
        ))
        .expect("complete routing packet");
        assert!(take_queued(&mut server));
    }

    /// Whether the last indication was queued for the network layer. Empties
    /// the queue so the next indication starts from depth zero.
    fn take_queued(server: &mut RoutingServer) -> bool {
        let depth = server.inbox.len();
        assert!(depth <= 1, "one indication queued {depth} frames");
        server.inbox.pop();
        depth == 1
    }

    /// A plain broadcast from `source`, as internal-format bytes and wrapped
    /// in a ROUTING_INDICATION.
    fn routing_indication(device: &TestContext, source: IndividualAddress) -> (std::vec::Vec<u8>, Buffer<'static>) {
        let mut internal = [0xBC, 0, 0, 0, 0, 0xE0, 0x01, 0x00];
        let mut message = KnxMessageBuffer::from_buffer(internal.as_mut_slice());
        message.set_source_addr(source);
        message.set_dest_addr(DestinationAddress::Broadcast);
        message.set_apci_code(ApciCode::IndividualAddressRead);

        let buffer = device.buffer_manager().try_alloc_from_slice(&internal).expect("free input buffer");
        let mut wire = KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind).into_cemi().into_inner();
        RoutingIndication::wrap_cemi(&mut wire);
        (internal.to_vec(), wire)
    }

    fn frame(fill: u8, len: usize) -> std::vec::Vec<u8> {
        (0..len).map(|i| fill.wrapping_add(i as u8)).collect()
    }

    fn front(inbox: &RoutingInbox) -> std::vec::Vec<u8> {
        let (first, second) = inbox.front().expect("a queued frame");
        [first, second].concat()
    }

    #[test]
    fn inbox_is_fifo_across_the_end_of_its_storage() {
        let mut inbox = RoutingInbox::new();
        assert!(inbox.front().is_none());

        // 29 frames of 32 octets leave 32 octets at the end of the storage.
        // Popping three frees 96 at the start, so a 40-octet frame fits only
        // by wrapping: 32 octets at the end, 8 at the start.
        for i in 0..29 {
            assert_eq!(inbox.push(&frame(i, 32)), Ok(i as usize + 1));
        }
        for i in 0..3 {
            assert_eq!(front(&inbox), frame(i, 32));
            inbox.pop();
        }
        let wrapped = frame(0xA0, 40);
        assert_eq!(inbox.push(&wrapped), Ok(27));
        let after = frame(0xC0, 20);
        assert_eq!(inbox.push(&after), Ok(28));

        for i in 3..29 {
            assert_eq!(front(&inbox), frame(i, 32));
            inbox.pop();
        }
        let (first, second) = inbox.front().expect("the wrapped frame");
        assert_eq!((first.len(), second.len()), (32, 8));
        assert_eq!(front(&inbox), wrapped);
        inbox.pop();
        assert_eq!(front(&inbox), after);
        inbox.pop();

        assert_eq!(inbox.len(), 0);
        assert!(inbox.front().is_none());
        inbox.pop();
        assert_eq!(inbox.len(), 0);
    }

    #[test]
    fn inbox_holds_thirty_frames_within_its_byte_budget() {
        // 03/08/05 §2.3.5: at least 30 messages.
        let mut inbox = RoutingInbox::new();
        for i in 0..ROUTING_QUEUE_FRAMES {
            assert_eq!(inbox.push(&frame(i as u8, 12)), Ok(i + 1));
        }
        assert_eq!(inbox.push(&frame(0xFF, 12)), Err(InboxFull));
        inbox.pop();
        assert_eq!(inbox.push(&frame(0xFF, 12)), Ok(ROUTING_QUEUE_FRAMES));

        // Long frames exhaust the bytes before the frame count.
        let mut inbox = RoutingInbox::new();
        for i in 0..9 {
            assert_eq!(inbox.push(&frame(i, 100)), Ok(i as usize + 1));
        }
        assert_eq!(inbox.push(&frame(9, 100)), Err(InboxFull));
        assert_eq!(inbox.len(), 9);
        inbox.pop();
        assert_eq!(inbox.push(&frame(9, 100)), Ok(9));
        assert_eq!(front(&inbox), frame(1, 100));
    }

    #[test]
    fn busy_thresholds_and_rate_limit() {
        let mut busy = BusySender::default();
        let source = IndividualAddress([0x11, 0x05]);
        let start = Instant::from_millis(1_000);
        let at = |ms| start + Duration::from_millis(ms);

        // Below five queued frames nobody is asked to pause.
        for depth in 1..ADDRESSED_BUSY_DEPTH {
            assert_eq!(busy.control_field_for(depth, source, start, 100), None);
        }

        // Five: the busy names the sender of the last indication.
        assert_eq!(busy.control_field_for(5, source, start, 100), Some(0x1105));
        assert_eq!(busy.control_field_for(6, source, at(99), 100), None);

        // Ten: every sender, even while the addressed busy is still in its
        // wait time.
        assert_eq!(busy.control_field_for(10, source, at(1), 100), Some(0x0000));
        assert_eq!(busy.control_field_for(30, source, at(50), 100), None);

        // Each kind repeats once its wait time has passed, and the wait time
        // is read afresh from PID_ROUTING_BUSY_WAIT_TIME every time.
        assert_eq!(busy.control_field_for(9, source, at(100), 100), Some(0x1105));
        assert_eq!(busy.control_field_for(10, source, at(100), 100), None);
        assert_eq!(busy.control_field_for(10, source, at(101), 100), Some(0x0000));
        assert_eq!(busy.control_field_for(10, source, at(121), 20), Some(0x0000));
    }

    #[test]
    fn a_growing_queue_sends_routing_busy_to_the_routing_group() {
        let device = TestContext::new(false, EthernetAddress([1, 2, 3, 4, 5, 6]));
        device.set_max_apdu_length(64);
        device.ip_state_mut().set_routing_busy_wait_time(60);
        let indications = Channel::<NoopRawMutex, _, 1>::new();
        let context = ServerContext::new(&device, indications.dyn_sender(), &[], None, 0);
        let multicast = Ipv4Addr::new(239, 1, 2, 3);
        let mut server = RoutingServer::new(multicast, 3671);

        let mut receive = |source: [u8; 2]| {
            let (_, wire) = routing_indication(&device, IndividualAddress(source));
            let mut responses = block_on(server.on_indication(
                KNXnetIPServiceType::RoutingIndication,
                &wire,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3671),
                &context,
            ))
            .expect("valid routing packet");
            assert!(responses.len() <= 1);
            responses.pop().map(|response| {
                let ResponseTarget::Udp { destination, socket_idx } = response.target else {
                    panic!("ROUTING_BUSY goes out over UDP");
                };
                assert_eq!((destination, socket_idx), (SocketAddrV4::new(multicast, 3671), 0));
                let mut bytes = &response.buffer[..];
                let busy = bytes.parse::<RoutingBusy>().expect("a ROUTING_BUSY");
                (busy.device_state.raw, busy.wait_time, busy.control_field)
            })
        };

        for _ in 0..4 {
            assert_eq!(receive([0x12, 0x03]), None);
        }
        assert_eq!(receive([0x12, 0x05]), Some((0x00, 60, 0x1205)));

        // Frames six to nine may or may not draw another addressed busy,
        // depending on how long they took; the tenth draws the general one.
        for _ in 6..10 {
            receive([0x12, 0x03]);
        }
        assert_eq!(receive([0x12, 0x07]), Some((0x00, 60, 0x0000)));
        assert_eq!(server.inbox.len(), 10);
        assert!(indications.try_receive().is_err(), "queued frames wait for the runtime");
    }

    #[test]
    fn a_frame_leaves_the_queue_only_once_delivered() {
        let device = TestContext::new(false, EthernetAddress([1, 2, 3, 4, 5, 6]));
        device.set_max_apdu_length(64);
        let indications = Channel::<NoopRawMutex, _, 1>::new();
        let context = ServerContext::new(&device, indications.dyn_sender(), &[], None, 0);
        let mut server = RoutingServer::new(Ipv4Addr::new(224, 0, 23, 12), 3671);

        // Nothing queued: the runtime's select arm stays idle.
        assert!(poll_once(server.forward_queued(device.buffer_manager(), indications.dyn_sender())).is_pending());

        let (internal, wire) = routing_indication(&device, IndividualAddress([0x12, 0x03]));
        block_on(server.on_indication(
            KNXnetIPServiceType::RoutingIndication,
            &wire,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3671),
            &context,
        ))
        .expect("valid routing packet");
        drop(wire);

        // The network layer is busy with an earlier frame, so the forward
        // cannot complete. Cancelling it, as the select does when another
        // arm wins, must leave the frame queued.
        let earlier = device.buffer_manager().try_alloc_from_slice(&internal).expect("free buffer");
        indications
            .try_send(IndicationMessage::indication(KnxMessageBuffer::new(earlier, ServiceType::L_Data_Ind)))
            .expect("empty channel");
        assert!(poll_once(server.forward_queued(device.buffer_manager(), indications.dyn_sender())).is_pending());
        assert_eq!(server.inbox.len(), 1);
        drop(indications.try_receive().expect("the earlier frame"));

        // Once the network layer has room, the frame reaches it unchanged.
        block_on(server.forward_queued(device.buffer_manager(), indications.dyn_sender()));
        let delivered = indications.try_receive().expect("the queued frame").into_inner();
        assert_eq!(delivered.service_type(), ServiceType::L_Data_Ind);
        assert_eq!(delivered.buf()[..], internal[..]);
        assert_eq!(server.inbox.len(), 1, "the caller pops after delivery");
        server.pop_forwarded();
        assert_eq!(server.inbox.len(), 0);
    }
}
