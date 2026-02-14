//! KNX/IP Routing Server
//!
//! Implements a KNX/IP Routing server that handles:
//! - RoutingIndication messages (sending/receiving KNX frames over IP multicast)
//! - RoutingBusy messages (congestion control)
//! - RoutingLostMessage (packet loss notifications)
//!
//! The server includes a routing timekeeper that implements the KNX specification's
//! congestion control algorithm with states for Normal, Busy, Throttled, and Slow Duration.

// FIXME: When we implement a full router we need to check out the flow control again
//        We need to handle queue overflows and possibly send RoutingBusy messages ourselves
//        We also need to check what to do with RoutingLost messages

use core::net::{Ipv4Addr, SocketAddrV4};
use embassy_time::Instant;
use heapless::Vec;

use crate::{
    messages::{
        buffers::{Buffer, MessageBuffer},
        knx::{CemiFormat, InternalFormat, KnxMessageBuffer, ServiceType},
        knxip::{KNXnetIPServiceType, RoutingBusy, RoutingIndication, RoutingLostMessage},
    },
    util::packets::ParseBuffer,
};

use super::{KnxNetIpServer, PendingResponse, ServerContext, ServerError};

/// Routing Server State Machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
/// This implements the state machine and timing logic from KNX Specification 3/8/2:
/// - State 0 (Normal): Standard operation with minimal throttling
/// - State 1 (Busy): Received RoutingBusy, must wait
/// - State 2 (Throttled): Random delay after busy clears (Trandom)
/// - State 3 (SlowDuration): Extended delay before normal operation (Tslowduration)
#[derive(Debug)]
struct RoutingTimekeeper {
    /// Current state of the routing timekeeper
    state: RoutingState,

    /// Next time when transmission is allowed
    next_allowed_time: Instant,

    /// Last time we received a RoutingBusy message
    last_busy_time: Instant,

    /// Time when state last transitioned to Normal (used for N decay)
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
                // Calculate minimum wait based on throttling
                // Throttle time = 2 * send_counter - 80, minimum 5ms
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
                    self.next_allowed_time =
                        self.next_allowed_time + embassy_time::Duration::from_millis(self.calculate_trandom() as u64);

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
                        // Throttle expired, move to SlowDuration
                        self.state = RoutingState::SlowDuration;
                        self.next_allowed_time = self.next_allowed_time
                            + embassy_time::Duration::from_millis(self.calculate_tslowduration() as u64);

                        trace!(
                            "GetWaitTime() state={:?} waitTime={}",
                            self.state,
                            if now < self.next_allowed_time {
                                self.next_allowed_time.duration_since(now).as_millis()
                            } else {
                                0
                            }
                        );

                        // Check if slow duration also expired
                        if now >= self.next_allowed_time {
                            // Back to normal
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
                    // Transition to SlowDuration
                    self.state = RoutingState::SlowDuration;
                    self.next_allowed_time = self.next_allowed_time
                        + embassy_time::Duration::from_millis(self.calculate_tslowduration() as u64);

                    trace!(
                        "GetWaitTime() state={:?} waitTime={}",
                        self.state,
                        if now < self.next_allowed_time {
                            self.next_allowed_time.duration_since(now).as_millis()
                        } else {
                            0
                        }
                    );

                    if now >= self.next_allowed_time {
                        self.state = RoutingState::Normal;
                        self.state_transition_time = now;
                        trace!("GetWaitTime() state={:?}", self.state);
                    }
                }
            }

            RoutingState::SlowDuration => {
                if now < self.next_allowed_time {
                    wait_time = self.next_allowed_time.duration_since(now).as_millis().min(u16::MAX as u64) as u16;
                } else {
                    // Transition to Normal
                    if now >= self.next_allowed_time {
                        self.state = RoutingState::Normal;
                        self.state_transition_time = now;
                        trace!("GetWaitTime() state={:?}", self.state);
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
    fn update_routing_busy_bucket(&mut self, now: Instant) {
        // Only update in Normal state
        if self.state != RoutingState::Normal {
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

/// KNX/IP Routing Server
///
/// Handles routing of KNX frames over IP multicast with congestion control.
#[derive(Debug)]
pub struct RoutingServer {
    /// Multicast address for routing (typically 224.0.23.12)
    multicast_addr: Ipv4Addr,

    /// Port for routing (typically 3671)
    port: u16,

    /// Routing timekeeper for congestion control
    timekeeper: RoutingTimekeeper,
}

impl RoutingServer {
    /// Create a new routing server
    ///
    /// # Arguments
    /// * `multicast_addr` - Multicast address for routing (typically 224.0.23.12)
    /// * `port` - Port for routing (typically 3671)
    pub fn new(multicast_addr: Ipv4Addr, port: u16) -> Self {
        Self { multicast_addr, port, timekeeper: RoutingTimekeeper::new() }
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
    async fn create_routing_indication<'a>(
        &self,
        message: &KnxMessageBuffer<Buffer<'static>, InternalFormat>,
        context: &ServerContext<'a>,
    ) -> Result<PendingResponse, ServerError> {
        // Allocate a buffer and copy the KNX message into it.
        // Default headroom (16 bytes) is sufficient for:
        // - cEMI expansion: 3 bytes (msg_code + add_info_len + ctrl2)
        // - KNXnet/IP header: 6 bytes
        let mut buffer = context.alloc_buffer().await;
        buffer.push_slice(message.buf());

        // Convert to cEMI format (uses 3 bytes of headroom)
        // Always use L_Data_Ind for routing - outgoing messages from this device
        // are sent as indications on the KNX/IP routing multicast group
        let internal_msg = KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind);
        let cemi_msg = internal_msg.into_cemi();

        // Extract the buffer and wrap it with the KNXnet/IP header
        // This uses 6 more bytes of headroom - no additional allocation needed
        let mut output_buffer = cemi_msg.into_inner();
        RoutingIndication::wrap_cemi(&mut output_buffer);

        let destination = SocketAddrV4::new(self.multicast_addr, self.port);
        Ok(PendingResponse { buffer: output_buffer, destination, socket_idx: 0 })
    }
}

impl KnxNetIpServer for RoutingServer {
    async fn on_indication<'a>(
        &mut self,
        service_type: KNXnetIPServiceType,
        mut data: &[u8],
        _source: SocketAddrV4,
        context: &ServerContext<'a>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        match service_type {
            KNXnetIPServiceType::RoutingIndication => {
                // Parse the RoutingIndication message
                let indication = data.parse::<RoutingIndication<_>>().map_err(|e| {
                    debug!("Failed to parse RoutingIndication: {:?}", e);
                    ServerError::ParseError
                })?;

                let cemi_data = indication.cemi_data();

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
                            warn!(
                                "Dropping oversized frame: APDU length {} exceeds max {}",
                                apdu_len, max_apdu
                            );
                            return Err(ServerError::FrameTooLarge(apdu_len, max_apdu));
                        }
                    }
                }

                // Allocate a buffer and copy the cEMI data into it
                let mut knx_buffer = context.alloc_buffer().await;
                knx_buffer.push_slice(cemi_data);

                // Convert cEMI to internal format (service type derived from message code)
                let cemi_msg: KnxMessageBuffer<Buffer<'static>, CemiFormat> = KnxMessageBuffer::from_cemi(knx_buffer);
                let internal_msg = cemi_msg.into_internal();

                // Forward to network layer
                context.send_to_network_layer(internal_msg).await;

                // No response needed
                Ok(Vec::new())
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
        context: &ServerContext<'a>,
    ) -> Result<Vec<PendingResponse, 4>, ServerError> {
        // Check if we're allowed to send
        let wait_time = self.timekeeper.get_wait_time();

        if wait_time > 0 {
            // We need to wait - caller should retry after the specified time
            warn!("RoutingServer: throttled, need to wait {}ms", wait_time);
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

    fn supports_requests(&self) -> bool {
        true
    }
}
