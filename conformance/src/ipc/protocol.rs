//! IPC protocol types for multi-process conformance testing.
//!
//! # Design
//!
//! The IPC between the conformance runner (parent) and the DUT (child) is
//! strictly request/response: every `RunnerMessage::Inject` carries a
//! monotonic `seq` and is acknowledged by a `DutMessage::StepComplete`
//! that carries all outbox frames produced during the inject's processing.
//! There is no separate "ack" — `StepComplete` is the ack.
//!
//! This eliminates four classes of bug from the previous fire-and-forget
//! tag protocol:
//!
//! - The runner can't send the next inject until the DUT has fully
//!   processed the previous one, so there is no "stale TL state"
//!   window after `A_Restart`.
//! - Frames produced by a single inject arrive as a batch in the
//!   `StepComplete`, removing the "did this frame come from my inject
//!   or from a timer?" ambiguity.
//! - Lifecycle transitions (`Ready`, `RoiComplete`, `Exiting`) are
//!   explicit events — no polling / timers on the runner side.
//! - `Exiting` is emitted before the DUT flushes SHM + exits, so the
//!   runner knows the child is going away without probing `try_wait`.
//!
//! Frames that arrive *between* steps (timer-driven retransmissions,
//! deferred ROI dispatches) become `DutMessage::UnsolicitedFrame` and
//! are buffered by the runner for later `Expect` steps to consume.

use serde::{Deserialize, Serialize};

/// A frame captured from the DUT's outgoing link layer.
///
/// `service_type` is the raw `ServiceType` byte; `data` is the TP1
/// wire format without checksum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedFrame {
    pub service_type: u8,
    pub data: Vec<u8>,
}

/// Reason the DUT is exiting, carried in [`DutMessage::Exiting`].
///
/// Emitted before the DUT flushes state to shared memory and calls
/// `process::exit(0)`. The runner transitions its `ChildLifecycle`
/// into `Exiting` on receipt, drains any final frames, and respawns.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExitReason {
    /// `A_Restart` accepted; the attached erase code has been applied.
    Restart { erase_code: u8 },
    /// `RunnerMessage::PowerCycle` received; state flushed, no erase.
    PowerCycle,
    /// `RunnerMessage::MasterReset` received; factory-reset-style flush.
    MasterReset { erase_code: u8 },
}

/// Command message sent from the runner (parent) to the DUT (child).
///
/// Each variant that carries a `seq` field expects exactly one
/// [`DutMessage::StepComplete`] in reply, with a matching `seq`. The
/// lifecycle-terminating commands (`PowerCycle`, `MasterReset`) reply
/// with [`DutMessage::Exiting`] followed by EOF instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RunnerMessage {
    /// Inject a TP1 frame (no checksum) into the stack as an indication.
    /// The DUT acks with `StepComplete { seq, frames: [...] }` once its
    /// router outbox has drained for this tick.
    Inject { seq: u32, data: Vec<u8> },

    /// Toggle programming mode. Acked with an empty `StepComplete`.
    SetProgrammingMode { seq: u32, enabled: bool },

    /// Trigger a GroupValue_Read on the given ASAP. Acked via
    /// `StepComplete` carrying the resulting outbox frames.
    TriggerRead { seq: u32, asap: u16 },

    /// Trigger a GroupValue_Write on the given ASAP. Acked likewise.
    TriggerWrite { seq: u32, asap: u16 },

    /// Trigger an S-A_Sync_Req to `peer_ia`. Acked likewise.
    TriggerSync { seq: u32, peer_ia: u16, tool_access: bool, is_broadcast: bool },

    /// Flush state to SHM and exit (no erase). No `StepComplete`; the
    /// runner expects an `Exiting { reason: PowerCycle }` then EOF.
    PowerCycle,

    /// Apply the erase code, flush to SHM, and exit. Erase codes match
    /// `A_Restart` encodings — see `zweidraehte-device` `EraseCode`.
    /// The runner expects `Exiting { reason: MasterReset { erase_code } }`
    /// then EOF.
    MasterReset { erase_code: u8 },
}

/// Event message sent from the DUT (child) to the runner (parent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DutMessage {
    /// Emitted once after stack init. The runner transitions from
    /// `Spawning` to `WaitingRoi`.
    Ready,

    /// Emitted after the read-on-init scan has fully drained. The
    /// runner transitions from `WaitingRoi` to `Running` and starts
    /// sending commands.
    RoiComplete,

    /// Reply to a command carrying the `seq` value from the request.
    /// `frames` is every outbox frame produced by that command, in
    /// the order the router dispatched them. May be empty.
    StepComplete { seq: u32, frames: Vec<CapturedFrame> },

    /// A frame produced outside the scope of any command (timer-driven
    /// TL retransmit, deferred ROI dispatch). Carries a monotonic
    /// `frame_seq` independent of the command `seq` space, so the
    /// runner can log / reason about inter-step ordering if needed.
    UnsolicitedFrame { frame_seq: u32, frame: CapturedFrame },

    /// DUT is about to flush state and exit. Sent from the restart /
    /// power-cycle / master-reset handler just before
    /// `shutdown(SHUT_WR)` + `process::exit(0)`, so the runner sees
    /// this frame before EOF.
    Exiting { reason: ExitReason },

    /// Forwarded log entry. `level` matches the `log::Level` numeric
    /// values (1=Error .. 5=Trace).
    Log { level: u8, target: String, message: String },
}
