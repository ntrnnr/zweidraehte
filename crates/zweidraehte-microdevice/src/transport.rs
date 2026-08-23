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
    const STYLE: TlStyle;
    fn process(conn: &mut BasicConnection, event: TlEvent) -> ProcessResult;
}

pub struct Style1;
pub struct Style2;
pub struct Style3;

impl TransportProfile for Style1 {
    const STYLE: TlStyle = TlStyle::Style1;

    fn process(conn: &mut BasicConnection, event: TlEvent) -> ProcessResult {
        process_event_style1(conn, event)
    }
}

impl TransportProfile for Style2 {
    const STYLE: TlStyle = TlStyle::Style2;

    fn process(conn: &mut BasicConnection, event: TlEvent) -> ProcessResult {
        process_event_style2(conn, event)
    }
}

impl TransportProfile for Style3 {
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
pub struct TlState<const N: usize = MAX_FRAME> {
    conn: BasicConnection,
    ack_deadline: Option<u32>,
    conn_deadline: Option<u32>,
    /// The last numbered data frame we sent, kept for retransmission
    /// until the peer acknowledges it.
    pending_tx: Option<FrameBuf<N>>,
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
    /// The connection dropped (disconnect indication).
    Disconnected,
}

/// Up to this many outputs per processed event — the largest spec
/// transition emits an ack, an indication, and timer ops.
pub type TlOutputs = heapless::Vec<TlOutput, 4>;

impl<const N: usize> TlState<N> {
    pub fn new(time_divisor: u32) -> Self {
        Self {
            conn: BasicConnection::new(),
            ack_deadline: None,
            conn_deadline: None,
            pending_tx: None,
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

    pub fn time_divisor(&self) -> u32 {
        self.time_divisor
    }

    pub fn store_pending(&mut self, frame: FrameBuf<N>) {
        self.pending_tx = Some(frame);
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
    pub fn begin_send<P: TransportProfile>(&mut self, dest: IndividualAddress, now_ms: u32) -> Option<u8> {
        for output in self.process::<P>(TlEvent::RequestData { dest }, now_ms) {
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
    }

    /// Feed one transport event through the state machine.
    pub fn process<P: TransportProfile>(&mut self, event: TlEvent, now_ms: u32) -> TlOutputs {
        let result = P::process(&mut self.conn, event);
        let outputs = self.run_actions(&result.actions, now_ms);
        result.apply_state(&mut self.conn);
        if self.conn.state == ConnectionState::Closed {
            self.pending_tx = None;
        }
        outputs
    }

    /// Fire any expired timer. Call once per poll tick.
    pub fn check_timers<P: TransportProfile>(&mut self, now_ms: u32) -> TlOutputs {
        // Wrapping-aware comparison: deadlines are near-future values
        // of a free-running u32 millisecond counter.
        fn expired(deadline: u32, now: u32) -> bool {
            now.wrapping_sub(deadline) < u32::MAX / 2
        }

        if let Some(deadline) = self.ack_deadline
            && expired(deadline, now_ms)
        {
            self.ack_deadline = None;
            return self.process::<P>(TlEvent::AckTimeout, now_ms);
        }
        if let Some(deadline) = self.conn_deadline
            && expired(deadline, now_ms)
        {
            self.conn_deadline = None;
            return self.process::<P>(TlEvent::ConnectionTimeout, now_ms);
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
                // Client-only / queueing actions a Style-1 server never
                // needs: a BCU2 answers one request at a time and
                // never opens outgoing connections.
                TlAction::SendConnect { .. }
                | TlAction::QueueEvent { .. }
                | TlAction::DeliverQueuedData { .. }
                | TlAction::ConfirmConnect { .. }
                | TlAction::ConfirmData { .. }
                | TlAction::ConfirmDisconnect { .. } => {}
            }
        }
        out
    }
}
