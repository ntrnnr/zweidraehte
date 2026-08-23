//! Transport layer: the proto state machine plus millisecond deadlines.
//!
//! The pure style-generic state machine lives in
//! `zweidraehte_proto::transport` and knows nothing about time; this
//! wrapper owns the single connection a BCU-era device serves (the
//! family picks the style: Style 1 on BCU2, Style 2 on BCU1, Style 3
//! on System 7), translates the
//! machine's timer actions into `u32` millisecond deadlines, and hands
//! [`TlAction`]s that involve frames back to the caller. The caller
//! (the device runloop) compares deadlines against its `now_ms` on
//! every poll — no clock, no executor in here.

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::transport::{
    ActionBuffer, BasicConnection, ConnectionState, ProcessResult, TlAction, TlEvent, TlStyle, process_event_style1,
    process_event_style2, process_event_style3,
};

use crate::frame::{FrameBuf, MAX_FRAME};

/// Compile-time transport-style selection.
///
/// A micro family has one profile-mandated style. Carrying [`TlStyle`] in
/// runtime state made LLVM retain every transition table in every firmware,
/// so the family supplies one of these zero-sized markers instead.
pub trait TransportProfile: 'static {
    /// Storage for the one deferred E15 response required by styles 2 and 3.
    /// Style 1 closes the connection instead and therefore uses a zero-sized
    /// implementation: BCU2 does not pay the frame buffer in RAM.
    type Queue<const N: usize>: TransportQueue<N>;

    const STYLE: TlStyle;
    fn process(conn: &mut BasicConnection, event: TlEvent) -> ProcessResult;
}

/// Profile-selected storage for a deferred outgoing connected frame.
pub trait TransportQueue<const N: usize>: Default {
    fn store(&mut self, frame: FrameBuf<N>) -> bool;
    fn take(&mut self) -> Option<FrameBuf<N>>;
    fn clear(&mut self);
}

/// Style 1's zero-sized queue: E15 in `OPEN_WAIT` disconnects instead.
#[derive(Default)]
pub struct NoTransportQueue;

impl<const N: usize> TransportQueue<N> for NoTransportQueue {
    fn store(&mut self, _frame: FrameBuf<N>) -> bool {
        false
    }

    fn take(&mut self) -> Option<FrameBuf<N>> {
        None
    }

    fn clear(&mut self) {}
}

/// The single deferred response slot required by Style 2 and Style 3.
pub struct OneFrameQueue<const N: usize>(Option<FrameBuf<N>>);

impl<const N: usize> Default for OneFrameQueue<N> {
    fn default() -> Self {
        Self(None)
    }
}

impl<const N: usize> TransportQueue<N> for OneFrameQueue<N> {
    fn store(&mut self, frame: FrameBuf<N>) -> bool {
        if self.0.is_some() {
            return false;
        }
        self.0 = Some(frame);
        true
    }

    fn take(&mut self) -> Option<FrameBuf<N>> {
        self.0.take()
    }

    fn clear(&mut self) {
        self.0 = None;
    }
}

pub struct Style1;
pub struct Style2;
pub struct Style3;

impl TransportProfile for Style1 {
    type Queue<const N: usize> = NoTransportQueue;

    const STYLE: TlStyle = TlStyle::Style1;

    fn process(conn: &mut BasicConnection, event: TlEvent) -> ProcessResult {
        process_event_style1(conn, event)
    }
}

impl TransportProfile for Style2 {
    type Queue<const N: usize> = OneFrameQueue<N>;

    const STYLE: TlStyle = TlStyle::Style2;

    fn process(conn: &mut BasicConnection, event: TlEvent) -> ProcessResult {
        process_event_style2(conn, event)
    }
}

impl TransportProfile for Style3 {
    type Queue<const N: usize> = OneFrameQueue<N>;

    const STYLE: TlStyle = TlStyle::Style3;

    fn process(conn: &mut BasicConnection, event: TlEvent) -> ProcessResult {
        process_event_style3(conn, event)
    }
}

/// Device-side acknowledge timeout (03/03/04 §5.4, timer TACK).
const ACK_TIMEOUT_MS: u32 = 3_000;
/// Device-side connection timeout (03/03/04 §5.4, timer TCON).
const CONN_TIMEOUT_MS: u32 = 6_000;

/// The single transport connection plus its timers and retransmit slot.
///
/// `N` is the profile's frame capacity — the retransmit slot holds a whole
/// frame, so it is sized with the rest of them.
pub struct TlState<const N: usize = MAX_FRAME, P: TransportProfile = Style1> {
    conn: BasicConnection,
    ack_deadline: Option<u32>,
    conn_deadline: Option<u32>,
    /// The last numbered data frame we sent, kept for retransmission
    /// until the peer acknowledges it.
    pending_tx: Option<FrameBuf<N>>,
    /// A second AL response produced while the first is awaiting its T_ACK.
    /// The projected type is zero-sized on Style 1.
    queued_tx: P::Queue<N>,
    /// Time-scale divisor inherited from the conformance harness's
    /// fast mode (1 outside of it).
    time_divisor: u32,
}

/// What one TL step asks the embedder to do. The state machine's
/// non-frame actions are already absorbed; only frame-producing
/// obligations surface here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlOutput {
    SendAck {
        dest: IndividualAddress,
        seq: u8,
        nak: bool,
    },
    SendDisconnect {
        dest: IndividualAddress,
    },
    /// Deliver the received (already-validated) APDU to the AL.
    IndicateData {
        source: IndividualAddress,
    },
    /// The stored pending frame should be re-sent.
    Retransmit,
    /// Send new numbered data with the given sequence number; the
    /// embedder builds the frame and stores it via
    /// [`TlState::store_pending`].
    SendData {
        dest: IndividualAddress,
        seq: u8,
    },
    /// The selected style accepted E15 for deferred delivery.
    QueueSend,
    /// The queued frame became the pending frame and must be transmitted.
    TransmitPending,
    /// The connection dropped (disconnect indication).
    Disconnected,
}

/// Up to this many outputs per processed event — the largest spec
/// transition emits an ack, an indication, and timer ops.
pub type TlOutputs = heapless::Vec<TlOutput, 4>;

impl<const N: usize, P: TransportProfile> TlState<N, P> {
    pub fn new(time_divisor: u32) -> Self {
        Self {
            conn: BasicConnection::new(),
            ack_deadline: None,
            conn_deadline: None,
            pending_tx: None,
            queued_tx: P::Queue::default(),
            time_divisor: time_divisor.max(1),
        }
    }

    pub fn connected_to(&self) -> Option<IndividualAddress> {
        (self.conn.state != ConnectionState::Closed).then_some(self.conn.remote_addr)
    }

    /// Sequence number the next outgoing numbered data PDU carries.
    pub fn send_seq(&self) -> u8 {
        self.conn.seq_no_send
    }

    /// Sequence number to encode in a response produced now. In
    /// `OPEN_WAIT`, Style 2/3 defer that response until the outstanding
    /// frame is acknowledged, at which point the send sequence increments.
    pub fn reply_seq(&self) -> u8 {
        if self.can_send() { self.send_seq() } else { (self.send_seq() + 1) & 0x0F }
    }

    pub fn time_divisor(&self) -> u32 {
        self.time_divisor
    }

    pub fn store_pending(&mut self, frame: FrameBuf<N>) {
        self.pending_tx = Some(frame);
    }

    /// Retain an E15 response until the current pending frame is
    /// acknowledged. Returns false for Style 1 and when the one slot is full.
    pub fn store_queued(&mut self, frame: FrameBuf<N>) -> bool {
        self.queued_tx.store(frame)
    }

    pub fn pending(&self) -> Option<&FrameBuf<N>> {
        self.pending_tx.as_ref()
    }

    /// Whether the connection can accept a new outgoing data request
    /// (OPEN_IDLE — in OPEN_WAIT the previous send is unacknowledged).
    pub fn can_send(&self) -> bool {
        self.conn.state == ConnectionState::OpenIdle
    }

    /// Start one outgoing numbered-data exchange and return its sequence.
    ///
    /// Keeping the action-vector walk here gives ordinary AL replies and
    /// prebuilt S-AL sync responses one transport entry point. Callers must
    /// have the complete frame ready first: once this succeeds the TL is in
    /// `OPEN_WAIT` and expects that frame to be installed with
    /// [`Self::store_pending`].
    pub fn begin_send(&mut self, dest: IndividualAddress, now_ms: u32) -> Option<u8> {
        for output in self.process(TlEvent::RequestData { dest }, now_ms) {
            if let TlOutput::SendData { seq, .. } = output {
                return Some(seq);
            }
        }
        None
    }

    /// Drop all connection state (restart, master reset).
    pub fn reset(&mut self) {
        self.conn.reset();
        self.ack_deadline = None;
        self.conn_deadline = None;
        self.pending_tx = None;
        self.queued_tx.clear();
    }

    /// Feed one transport event through the state machine.
    pub fn process(&mut self, event: TlEvent, now_ms: u32) -> TlOutputs {
        let result = P::process(&mut self.conn, event);
        let mut outputs = self.run_actions(&result.actions, now_ms);
        result.apply_state(&mut self.conn);
        if self.conn.state == ConnectionState::Closed {
            self.pending_tx = None;
            self.queued_tx.clear();
        } else if self.conn.state == ConnectionState::OpenIdle
            && let Some(frame) = self.queued_tx.take()
        {
            // A8/A8b has acknowledged and cleared the old pending frame.
            // Re-enter E15 only after applying OPEN_IDLE, so A7 assigns the
            // incremented sequence and starts fresh timers.
            let dest = self.conn.remote_addr;
            let queued = P::process(&mut self.conn, TlEvent::RequestData { dest });
            let queued_outputs = self.run_actions(&queued.actions, now_ms);
            queued.apply_state(&mut self.conn);
            if queued_outputs.iter().any(|output| matches!(output, TlOutput::SendData { .. })) {
                self.pending_tx = Some(frame);
                let _ = outputs.push(TlOutput::TransmitPending);
            }
        }
        outputs
    }

    /// Fire any expired timer. Call once per poll tick.
    pub fn check_timers(&mut self, now_ms: u32) -> TlOutputs {
        // Wrapping-aware comparison: deadlines are near-future values
        // of a free-running u32 millisecond counter.
        fn expired(deadline: u32, now: u32) -> bool {
            now.wrapping_sub(deadline) < u32::MAX / 2
        }

        if let Some(deadline) = self.ack_deadline
            && expired(deadline, now_ms)
        {
            self.ack_deadline = None;
            return self.process(TlEvent::AckTimeout, now_ms);
        }
        if let Some(deadline) = self.conn_deadline
            && expired(deadline, now_ms)
        {
            self.conn_deadline = None;
            return self.process(TlEvent::ConnectionTimeout, now_ms);
        }
        TlOutputs::new()
    }

    fn run_actions(&mut self, actions: &ActionBuffer, now_ms: u32) -> TlOutputs {
        let mut out = TlOutputs::new();
        for action in actions.iter() {
            match action {
                TlAction::SendAck { dest, seq_no } => {
                    let _ = out.push(TlOutput::SendAck { dest, seq: seq_no, nak: false });
                }
                TlAction::SendNack { dest, seq_no } => {
                    let _ = out.push(TlOutput::SendAck { dest, seq: seq_no, nak: true });
                }
                TlAction::SendDisconnect { dest } => {
                    let _ = out.push(TlOutput::SendDisconnect { dest });
                }
                TlAction::SendData { dest } => {
                    let _ = out.push(TlOutput::SendData { dest, seq: self.conn.seq_no_send });
                }
                TlAction::Retransmit { .. } => {
                    let _ = out.push(TlOutput::Retransmit);
                }
                TlAction::IndicateData { source } => {
                    let _ = out.push(TlOutput::IndicateData { source });
                }
                TlAction::IndicateConnected { .. } => {
                    // A server-only device has nothing to do on connect
                    // beyond what the state machine already tracked.
                }
                TlAction::IndicateDisconnected { .. } => {
                    let _ = out.push(TlOutput::Disconnected);
                }
                TlAction::StartAckTimer => {
                    self.ack_deadline = Some(now_ms.wrapping_add(ACK_TIMEOUT_MS / self.time_divisor));
                }
                TlAction::StopAckTimer => self.ack_deadline = None,
                TlAction::StartConnTimer => {
                    self.conn_deadline = Some(now_ms.wrapping_add(CONN_TIMEOUT_MS / self.time_divisor));
                }
                TlAction::StopConnTimer => self.conn_deadline = None,
                TlAction::StorePendingMessage => {
                    // The embedder stores the frame right after it
                    // builds it (`store_pending`) — at action time the
                    // frame does not exist yet.
                }
                TlAction::ClearPendingMessage => self.pending_tx = None,
                TlAction::QueueEvent { .. } => {
                    let _ = out.push(TlOutput::QueueSend);
                }
                // Client-only actions a server never needs.
                TlAction::SendConnect { .. }
                | TlAction::DeliverQueuedData { .. }
                | TlAction::ConfirmConnect { .. }
                | TlAction::ConfirmData { .. }
                | TlAction::ConfirmDisconnect { .. } => {}
            }
        }
        out
    }
}
