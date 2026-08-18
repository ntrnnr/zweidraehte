//! Transport layer: the proto state machine plus millisecond deadlines.
//!
//! The pure Style-1 state machine lives in
//! `zweidraehte_proto::transport` and knows nothing about time; this
//! wrapper owns the single connection a BCU2 serves, translates the
//! machine's timer actions into `u32` millisecond deadlines, and hands
//! [`TlAction`]s that involve frames back to the caller. The caller
//! (the device runloop) compares deadlines against its `now_ms` on
//! every poll — no clock, no executor in here.

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::transport::{
    ActionBuffer, BasicConnection, ConnectionState, TlAction, TlEvent, TlStyle, process_event,
};

use crate::frame::FrameBuf;

/// Device-side acknowledge timeout (03/03/04 §5.4, timer TACK).
const ACK_TIMEOUT_MS: u32 = 3_000;
/// Device-side connection timeout (03/03/04 §5.4, timer TCON).
const CONN_TIMEOUT_MS: u32 = 6_000;

/// The single transport connection plus its timers and retransmit slot.
pub struct TlState {
    style: TlStyle,
    conn: BasicConnection,
    ack_deadline: Option<u32>,
    conn_deadline: Option<u32>,
    /// The last numbered data frame we sent, kept for retransmission
    /// until the peer acknowledges it.
    pending_tx: Option<FrameBuf>,
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

impl TlState {
    pub fn new(style: TlStyle, time_divisor: u32) -> Self {
        Self {
            style,
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

    pub fn store_pending(&mut self, frame: FrameBuf) {
        self.pending_tx = Some(frame);
    }

    pub fn pending(&self) -> Option<&FrameBuf> {
        self.pending_tx.as_ref()
    }

    /// Whether the connection can accept a new outgoing data request
    /// (OPEN_IDLE — in OPEN_WAIT the previous send is unacknowledged).
    pub fn can_send(&self) -> bool {
        self.conn.state == ConnectionState::OpenIdle
    }

    /// Drop all connection state (restart, master reset).
    pub fn reset(&mut self) {
        self.conn.reset();
        self.ack_deadline = None;
        self.conn_deadline = None;
        self.pending_tx = None;
    }

    /// Feed one transport event through the state machine.
    pub fn process(&mut self, event: TlEvent, now_ms: u32) -> TlOutputs {
        let result = process_event(&mut self.conn, event, self.style);
        let outputs = self.run_actions(&result.actions, now_ms);
        result.apply_state(&mut self.conn);
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
