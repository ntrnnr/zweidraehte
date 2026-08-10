//! Captured outbox frames seen by the conformance runner.
//!
//! The DUT child process serialises every outgoing link-layer frame into a
//! `CapturedFrame` (see [`crate::ipc::protocol`]) and sends it to the parent over
//! the postcard IPC socket. On the parent side the frame is re-wrapped into
//! [`CapturedLinkLayerMessage`] — the type the runner's `Expect*` steps
//! actually match against.
//!
//! Each buffered frame carries a [`FrameSource`] tag so that `Expect`
//! mismatches can blame their likely origin (step reply, unsolicited
//! retransmit, post-respawn ROI scan). The tag has no effect on matching
//! logic; it is diagnostic only.

use zweidraehte_proto::messages::knx::ServiceType;

/// An outbox frame captured from the DUT, expressed in TP1-like wire format
/// without the checksum byte.
#[derive(Debug, Clone)]
pub struct CapturedLinkLayerMessage {
    /// The service type of the captured message.
    pub service_type: ServiceType,
    /// Raw bytes in TP1-like format (no checksum).
    pub data: Vec<u8>,
}

/// Provenance of a buffered frame.
///
/// Tags are written on ingest in `ChildLifecycle::ingest_dut_message` and
/// preserved verbatim until the frame is consumed by an `Expect*` step.
/// When an `Expect` mismatch is reported the source is printed so the
/// reader can instantly tell whether they got hit by a stale retransmit,
/// a ROI frame bleeding in after a respawn, or a real response to the
/// preceding inject.
#[derive(Debug, Clone, Copy)]
pub enum FrameSource {
    /// Part of a `StepComplete` batch for the indicated step sequence
    /// number. This is the normal response-to-inject case.
    StepReply(u32),
    /// Arrived as a standalone `UnsolicitedFrame` — typically a
    /// timer-driven retransmit between steps, or a late ROI frame.
    Unsolicited(u32),
    /// Arrived during the post-respawn ROI scan preserved by a
    /// `WaitForRestart { preserve_roi: true }` step.
    RoiScan,
}

impl FrameSource {
    /// Short, human-readable tag for diagnostic output.
    ///
    /// Intentionally terse — the full detail lives in the runner's log
    /// buffer; this string is for the `Got: ... (source: ...)` line of
    /// a failing `Expect`.
    pub fn label(&self) -> String {
        match self {
            FrameSource::StepReply(seq) => format!("StepReply #{seq}"),
            FrameSource::Unsolicited(seq) => format!("Unsolicited #{seq}"),
            FrameSource::RoiScan => "RoiScan".to_string(),
        }
    }
}

/// A buffered frame together with its recorded source. Stored in the
/// lifecycle's `unsolicited_frames` queue and popped by `Expect` steps.
#[derive(Debug, Clone)]
pub struct TaggedFrame {
    pub source: FrameSource,
    pub message: CapturedLinkLayerMessage,
}
