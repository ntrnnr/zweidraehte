//! Parent-side DUT child-process lifecycle.
//!
//! [`ChildLifecycle`] speaks the postcard IPC protocol defined in
//! [`super::protocol`] and exposes a strictly request/response step
//! API.
//!
//! ```text
//!        spawn_and_wait_roi()           step(Inject)           wait_for_exit()
//! Dead ──────────────────────▶ Running ────────────────▶ Running
//!                                 │                         │
//!                                 │     step(PowerCycle)    │
//!                                 └───────────▶ Exiting ───▶ Dead ──▶ respawn
//! ```
//!
//! # State machine
//!
//! Every public method documents which states it is callable from and
//! which states it may transition to. Invalid transitions return a
//! descriptive `io::Error(Other, ...)`.
//!
//! # Frame buffer
//!
//! Between step calls, [`DutMessage::UnsolicitedFrame`]s arriving on
//! the socket are buffered in `unsolicited_frames`. Steps that want to
//! observe outgoing traffic (the `Expect*` test steps) drain the
//! buffer first via [`ChildLifecycle::pop_unsolicited`] and fall
//! through to [`ChildLifecycle::next_frame`] only when the buffer is
//! empty.

use std::collections::VecDeque;
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command};

use async_io::Async;
use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Timer};

use zweidraehte_proto::messages::knx::ServiceType;

use super::frame_source::{CapturedLinkLayerMessage, FrameSource, TaggedFrame};
use super::framing::{read_msg_async, write_msg_async};
use super::protocol::{CapturedFrame, DutMessage, ExitReason, RunnerMessage};
use super::secure_stack::SecureConformanceDeviceConfig;
use super::shm::SharedMemory;
use super::stack::ConformanceDeviceConfig;

use crate::logger::{self, LogEntry};

// ============================================================================
// DUT mode
// ============================================================================

/// Which DUT binary a [`ChildLifecycle`] manages. Fixed at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DutMode {
    /// `conformance-dut` — plain stack, no Data Secure.
    Plain,
    /// `conformance-dut-secure` — Data Secure enabled.
    Secure,
    /// `conformance-dut-system7` — System 7 family (mask 0705h).
    System7,
    /// `conformance-dut-system7-secure` — System 7 family with Data
    /// Secure.
    System7Secure,
}

impl DutMode {
    fn binary_name(self) -> &'static str {
        match self {
            Self::Plain => "conformance-dut",
            Self::Secure => "conformance-dut-secure",
            Self::System7 => "conformance-dut-system7",
            Self::System7Secure => "conformance-dut-system7-secure",
        }
    }
}

// ============================================================================
// Internal state
// ============================================================================

enum LifecycleState {
    Dead,
    Running {
        child: Child,
        socket: Async<UnixStream>,
    },
    /// Set by [`ChildLifecycle::step`] when the DUT replied with
    /// `Exiting` instead of `StepComplete`. The caller (usually the
    /// test runner) knows to wait for EOF + respawn.
    Exiting {
        child: Child,
        socket: Async<UnixStream>,
        /// Preserved for diagnostics / future use; the current runner
        /// only needs the state transition.
        #[allow(dead_code)]
        reason: ExitReason,
    },
}

impl LifecycleState {
    fn socket(&self) -> Option<&Async<UnixStream>> {
        match self {
            Self::Running { socket, .. } | Self::Exiting { socket, .. } => Some(socket),
            Self::Dead => None,
        }
    }

    #[allow(dead_code)]
    fn is_dead(&self) -> bool {
        matches!(self, Self::Dead)
    }
}

// ============================================================================
// ChildLifecycle
// ============================================================================

pub struct ChildLifecycle {
    shm: SharedMemory,
    state: LifecycleState,
    mode: DutMode,
    /// Monotonic counter for step `seq` values. Wraps at `u32::MAX`
    /// but a single test run never exceeds ~100 000 steps.
    next_seq: u32,
    /// Buffered outbox frames waiting to be consumed by `Expect*`
    /// steps. Each entry carries a [`FrameSource`] tag recording
    /// whether it came from a `StepComplete` batch, an
    /// `UnsolicitedFrame`, or a post-respawn ROI scan — so mismatch
    /// diagnostics can explain "this frame was a late retransmit, not
    /// your expected response".
    unsolicited_frames: VecDeque<TaggedFrame>,
}

impl ChildLifecycle {
    /// Create a new lifecycle for `mode`, seeding the shared memory
    /// with the default snapshot. Does NOT spawn the child — call
    /// [`spawn_and_wait_roi`](Self::spawn_and_wait_roi) next.
    pub fn new(mode: DutMode) -> io::Result<Self> {
        let mut shm = SharedMemory::create()?;
        match mode {
            DutMode::Plain => shm.write_state(&ConformanceDeviceConfig::default_snapshot())?,
            DutMode::Secure => shm.write_state(&SecureConformanceDeviceConfig::default_snapshot())?,
            DutMode::System7 => shm.write_state(&crate::harness::system7_stack::default_snapshot())?,
            DutMode::System7Secure => shm.write_state(&crate::harness::system7_secure_stack::default_snapshot())?,
        }
        Ok(Self { shm, state: LifecycleState::Dead, mode, next_seq: 0, unsolicited_frames: VecDeque::new() })
    }

    pub fn mode(&self) -> DutMode {
        self.mode
    }

    pub fn is_child_running(&self) -> bool {
        matches!(self.state, LifecycleState::Running { .. })
    }

    // ========================================================================
    // Lifecycle transitions
    // ========================================================================

    /// Spawn the child (if not already running), wait for its `Ready`
    /// and `RoiComplete` lifecycle events. On return, the child is in
    /// the `Running` state and ready to accept [`step`](Self::step)
    /// calls. ROI frames received during startup become
    /// [`unsolicited_frames`] so tests that care about ROI order
    /// (e.g. section 1.4.1.6) can still observe them.
    ///
    /// Callable from: `Dead`. If already `Running`, returns `Ok(())`.
    pub async fn spawn_and_wait_roi(&mut self) -> io::Result<()> {
        if self.is_child_running() {
            return Ok(());
        }
        self.reap_any_child();
        self.spawn_child_binary(self.mode.binary_name()).await?;
        self.wait_for_ready().await?;
        self.wait_for_roi_complete().await?;
        Ok(())
    }

    /// Forcibly kill the child (if any), reaping the process and
    /// clearing state. Idempotent. Any buffered unsolicited frames
    /// are discarded.
    pub async fn kill(&mut self) {
        match std::mem::replace(&mut self.state, LifecycleState::Dead) {
            LifecycleState::Running { mut child, .. } | LifecycleState::Exiting { mut child, .. } => {
                let _ = child.kill();
                let _ = child.wait();
            }
            LifecycleState::Dead => {}
        }
        self.unsolicited_frames.clear();
    }

    /// Re-initialize shared memory with the default snapshot for the
    /// lifecycle's mode. Secure mode also wipes the seqnr tail region
    /// so the respawned DUT starts with fresh per-peer counters.
    ///
    /// Call after [`kill`](Self::kill) and before
    /// [`spawn_and_wait_roi`](Self::spawn_and_wait_roi) if you need a
    /// factory-fresh DUT (`TestStep::FullReset`).
    pub fn reset_shared_memory(&mut self) -> io::Result<()> {
        match self.mode {
            DutMode::Plain => self.shm.write_state(&ConformanceDeviceConfig::default_snapshot())?,
            DutMode::System7 => self.shm.write_state(&crate::harness::system7_stack::default_snapshot())?,
            DutMode::Secure => {
                self.shm.write_state(&SecureConformanceDeviceConfig::default_snapshot())?;
                // Seq region is OUTSIDE the postcard payload (tail of
                // SHM) — clear it so the respawned secure DUT doesn't
                // replay-reject the harness's first secure frame
                // against a stale tool seq.
                self.shm.clear_seq_region();
            }
            DutMode::System7Secure => {
                self.shm.write_state(&crate::harness::system7_secure_stack::default_snapshot())?;
                // Same seq-tail contract as the System B secure DUT.
                self.shm.clear_seq_region();
            }
        }
        Ok(())
    }

    /// Factory-reset the DUT as a single transactional unit: kill the
    /// current child → reinitialise SHM with the default snapshot →
    /// respawn and wait for ROI.
    ///
    /// Keeping the sequence in one method makes it all-or-nothing: on
    /// any intermediate failure the lifecycle ends in `Dead` (never
    /// wedged between sub-steps), and the caller's next command will
    /// auto-respawn from the (possibly partially-reset) SHM. Buffered
    /// unsolicited frames are discarded either way so the next suite
    /// doesn't inherit leftover ROI.
    pub async fn full_reset(&mut self) -> io::Result<()> {
        self.kill().await;
        let reset_result = self.reset_shared_memory();
        // Always discard buffered unsolicited frames — even on partial
        // failure, what's buffered no longer reflects the DUT we're
        // about to run.
        self.discard_unsolicited();
        reset_result?;
        self.spawn_and_wait_roi().await?;
        // Drop the fresh DUT's startup ROI scan — `full_reset` is
        // used as teardown, so the next suite shouldn't inherit ROI
        // frames.
        self.discard_unsolicited();
        Ok(())
    }

    // ========================================================================
    // Step-driven command flow
    // ========================================================================

    /// Send a command and read the matching reply. Used for every
    /// request/response command (inject, trigger, programming mode).
    ///
    /// On `StepComplete`, the captured frames are appended to
    /// `unsolicited_frames` so subsequent `Expect` steps can consume
    /// them. The count of newly-appended frames is returned.
    ///
    /// On `Exiting` (`A_Restart` triggered the exit), the lifecycle
    /// transitions through `Exiting → Dead → Running` automatically:
    /// it drains the socket to EOF, reaps the child, respawns, and
    /// waits for `RoiComplete`. Tests don't need a separate
    /// `WaitForRestart` step.
    ///
    /// Callable from: `Running`. Errors if the child is not running.
    pub async fn step(&mut self, mut make_cmd: impl FnMut(u32) -> RunnerMessage) -> io::Result<usize> {
        // A previous step may have triggered an `A_Restart` and left
        // the child dead. Respawn transparently with the default
        // ROI-discard policy. Tests that want to observe
        // post-restart ROI use `TestStep::WaitForRestart` to
        // preempt this by respawning with `preserve_roi=true`
        // first.
        self.auto_respawn_if_dead(false).await?;
        let seq = self.next_seq();
        let cmd = make_cmd(seq);
        let socket = self.state.socket().expect("running state has socket");
        write_msg_async(socket, &cmd).await?;
        self.read_until_step_complete(seq).await
    }

    /// Variant of [`step`] for lifecycle-terminating commands
    /// (`PowerCycle`, `MasterReset`). These receive `Exiting` + EOF
    /// rather than `StepComplete`. On return the child has been
    /// respawned and is in the `Running` state.
    ///
    /// `timeout` bounds how long to wait for the DUT to exit; if
    /// exceeded, the child is force-killed and reaped.
    pub async fn step_exiting(&mut self, cmd: RunnerMessage, timeout: Duration) -> io::Result<ExitReason> {
        self.auto_respawn_if_dead(false).await?;
        let socket = self.state.socket().expect("running state has socket");
        write_msg_async(socket, &cmd).await?;
        let reason = self.wait_for_exit(timeout).await?;
        // Drain EOF, reap the child — the next step's
        // `auto_respawn_if_dead` brings up a fresh DUT.
        self.drain_to_eof().await;
        self.mark_dead();
        Ok(reason)
    }

    /// Pop the next buffered outbox frame from the DUT, if any.
    /// Returns `None` when the buffer is empty — callers should then
    /// fall through to [`next_frame`](Self::next_frame) to wait for
    /// more. The returned [`TaggedFrame`] exposes the frame's
    /// provenance for diagnostic output.
    pub fn pop_unsolicited(&mut self) -> Option<TaggedFrame> {
        self.unsolicited_frames.pop_front()
    }

    /// Wait (with timeout) for the next frame from the DUT. Reads
    /// socket messages and pulls captured frames out of
    /// `StepComplete` / `UnsolicitedFrame`. Log messages and
    /// `RoiComplete` in the stream are handled transparently
    /// (forwarded to the logger / ignored respectively).
    ///
    /// Returns `Ok(Some(frame))` when a frame is available,
    /// `Ok(None)` on timeout, and `Err` on socket failure. The
    /// returned [`TaggedFrame`] carries a [`FrameSource`] so callers
    /// can surface provenance in mismatch diagnostics.
    pub async fn next_frame(&mut self, timeout: Duration) -> io::Result<Option<TaggedFrame>> {
        if let Some(frame) = self.pop_unsolicited() {
            return Ok(Some(frame));
        }
        // If the child is dead (previous step's A_Restart), respawn
        // transparently and try reading from the fresh DUT. Post-
        // respawn ROI is discarded by default — use
        // `auto_respawn_if_dead(true)` via `WaitForRestart` to keep
        // ROI around for tests that want to observe it.
        if !self.is_child_running() {
            self.auto_respawn_if_dead(false).await?;
            if let Some(frame) = self.pop_unsolicited() {
                return Ok(Some(frame));
            }
        }
        let deadline = Timer::after(timeout);
        let mut deadline = std::pin::pin!(deadline);
        loop {
            if let Some(frame) = self.pop_unsolicited() {
                return Ok(Some(frame));
            }
            let socket = match self.state.socket() {
                Some(s) => s,
                None => return Ok(None),
            };
            match select(read_msg_async::<DutMessage>(socket), deadline.as_mut()).await {
                Either::First(Ok(Some(msg))) => {
                    if let Some(frame) = self.ingest_dut_message(msg) {
                        return Ok(Some(frame));
                    }
                    // continue — message was a log / RoiComplete /
                    // lifecycle event that next_frame swallows
                }
                Either::First(Ok(None)) => {
                    self.mark_dead();
                    return Ok(None);
                }
                Either::First(Err(e)) => {
                    self.mark_dead();
                    return Err(e);
                }
                Either::Second(_) => return Ok(None),
            }
        }
    }

    /// Discard every buffered unsolicited frame. Used by
    /// `TestStep::Drain` between tests so one test's leftover
    /// response doesn't match another's `Expect`.
    pub fn discard_unsolicited(&mut self) {
        self.unsolicited_frames.clear();
    }

    /// Respawn the child if it exited. Called at step boundaries so
    /// one test's `A_Restart` leaves the fresh DUT ready for the next
    /// step.
    ///
    /// `preserve_roi` controls what happens to the post-respawn
    /// read-on-init scan:
    ///
    /// - `false` (default): ROI frames are discarded so they don't
    ///   poison the next test's expects. Most tests want this.
    /// - `true`: ROI frames stay in the unsolicited buffer so the
    ///   caller can observe them. Used by `TestStep::WaitForRestart`
    ///   / test 1.4.1.6 which actually wants to verify the ROI scan.
    pub async fn auto_respawn_if_dead(&mut self, preserve_roi: bool) -> io::Result<()> {
        if !matches!(self.state, LifecycleState::Dead) {
            return Ok(());
        }
        // Frames from the previous DUT instance are stale — the
        // new DUT shares no TL state / connection / seq counters
        // with the old one, so any buffered frame must be dropped.
        self.unsolicited_frames.clear();
        self.spawn_child_binary(self.mode.binary_name()).await?;
        self.wait_for_ready().await?;
        self.wait_for_roi_complete().await?;
        // Post-respawn ROI was appended during wait_for_roi_complete.
        // Drop it unless the caller explicitly opted in via
        // `preserve_roi=true` (the `TestStep::WaitForRestart` path
        // / test 1.4.1.6 which matches the ROI scan).
        if !preserve_roi {
            self.unsolicited_frames.clear();
        }
        Ok(())
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    fn next_seq(&mut self) -> u32 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        seq
    }

    /// Read messages from the DUT until we see `StepComplete{seq}`.
    /// Frames produced along the way are appended to
    /// `unsolicited_frames`. Returns the number of frames appended
    /// (from the `StepComplete` itself plus any `UnsolicitedFrame`s
    /// that arrived while waiting).
    ///
    /// When an `A_Restart` inject triggers the DUT's restart path,
    /// the DUT first emits `StepComplete` (carrying T_ACK +
    /// restart-response frames) and then `Exiting`. After seeing the
    /// `StepComplete`, we do one extra short poll for a follow-up
    /// message to catch the `Exiting` and drive the lifecycle
    /// transition inline.
    async fn read_until_step_complete(&mut self, want_seq: u32) -> io::Result<usize> {
        let mut appended = 0;
        let mut got_step_complete = false;
        loop {
            let socket = match self.state.socket() {
                Some(s) => s,
                None => {
                    return Err(io::Error::new(io::ErrorKind::NotConnected, "child died while awaiting StepComplete"));
                }
            };

            // After StepComplete, poll briefly for a follow-up
            // `Exiting` (the DUT's restart handler writes `Exiting`
            // immediately after releasing the `STEP_SETTLED`
            // barrier, so it lands essentially back-to-back with
            // StepComplete on the socket). 2 ms is enough for the
            // kernel to deliver the follow-up; longer would add
            // dead time to every inject and push the runner's
            // inject cadence past the DUT's 60 ms TL ACK window —
            // triggering spurious retransmissions.
            let msg = if got_step_complete {
                use embassy_time::{Duration, Timer};
                let deadline = Timer::after(Duration::from_millis(2));
                let mut deadline = std::pin::pin!(deadline);
                match select(read_msg_async::<DutMessage>(socket), deadline.as_mut()).await {
                    Either::First(r) => r?,
                    Either::Second(_) => return Ok(appended),
                }
            } else {
                read_msg_async::<DutMessage>(socket).await?
            };

            match msg {
                Some(DutMessage::StepComplete { seq, frames }) => {
                    if seq != want_seq {
                        log::warn!("StepComplete seq mismatch: got {}, want {}", seq, want_seq);
                    }
                    let n = frames.len();
                    let source = FrameSource::StepReply(seq);
                    self.unsolicited_frames.extend(
                        frames
                            .into_iter()
                            .map(|frame| TaggedFrame { source, message: captured_frame_to_message(frame) }),
                    );
                    appended += n;
                    got_step_complete = true;
                }
                Some(DutMessage::UnsolicitedFrame { frame_seq, frame }) => {
                    self.unsolicited_frames.push_back(TaggedFrame {
                        source: FrameSource::Unsolicited(frame_seq),
                        message: captured_frame_to_message(frame),
                    });
                    appended += 1;
                }
                Some(DutMessage::Log { level, target, message }) => {
                    forward_log(level, target, message);
                }
                Some(DutMessage::Ready) | Some(DutMessage::RoiComplete) => {
                    // Shouldn't happen outside startup; ignore with a warning.
                    log::warn!("Unexpected lifecycle message mid-step");
                }
                Some(DutMessage::Exiting { reason }) => {
                    // The step triggered a restart / power-cycle /
                    // master-reset. Transition to `Exiting`, drain to
                    // EOF, reap the child, and return. The child stays
                    // dead; the next step's `auto_respawn_if_dead`
                    // brings up a fresh DUT, giving the caller a
                    // chance to choose whether post-respawn ROI is
                    // preserved (`WaitForRestart`) or dropped
                    // (default).
                    self.transition_to_exiting(reason);
                    self.drain_to_eof().await;
                    self.mark_dead();
                    return Ok(appended);
                }
                None => {
                    if got_step_complete {
                        // EOF right after StepComplete — the DUT
                        // exited without an explicit `Exiting` (e.g.
                        // a plain-DUT crash or an old-style direct
                        // exit). Same policy as the `Exiting` arm.
                        self.mark_dead();
                        return Ok(appended);
                    }
                    self.mark_dead();
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DUT disconnected before StepComplete"));
                }
            }
        }
    }

    /// Interpret an incoming `DutMessage`. Returns the captured frame
    /// (with its source tag) if the message carried one; otherwise
    /// returns `None` after handling it (log forwarding, lifecycle
    /// transitions).
    fn ingest_dut_message(&mut self, msg: DutMessage) -> Option<TaggedFrame> {
        match msg {
            DutMessage::UnsolicitedFrame { frame_seq, frame } => Some(TaggedFrame {
                source: FrameSource::Unsolicited(frame_seq),
                message: captured_frame_to_message(frame),
            }),
            DutMessage::StepComplete { seq, frames } => {
                // Shouldn't happen outside a `step()` context, but be
                // defensive: buffer extras and return the first.
                let source = FrameSource::StepReply(seq);
                let mut iter =
                    frames.into_iter().map(|frame| TaggedFrame { source, message: captured_frame_to_message(frame) });
                let first = iter.next();
                self.unsolicited_frames.extend(iter);
                first
            }
            DutMessage::Log { level, target, message } => {
                forward_log(level, target, message);
                None
            }
            DutMessage::Ready | DutMessage::RoiComplete => None,
            DutMessage::Exiting { reason } => {
                self.transition_to_exiting(reason);
                None
            }
        }
    }

    fn transition_to_exiting(&mut self, reason: ExitReason) {
        if let LifecycleState::Running { child, socket } = std::mem::replace(&mut self.state, LifecycleState::Dead) {
            self.state = LifecycleState::Exiting { child, socket, reason };
        }
    }

    /// Drain the socket until EOF, buffering any frames the DUT
    /// emits on the way out (the restart handler's follow-up log
    /// messages, late retransmits, etc.). Does not respawn.
    async fn drain_to_eof(&mut self) {
        loop {
            let socket = match self.state.socket() {
                Some(s) => s,
                None => break,
            };
            match read_msg_async::<DutMessage>(socket).await {
                Ok(Some(msg)) => {
                    let _ = self.ingest_dut_message(msg);
                }
                Ok(None) => break,
                Err(e) => {
                    log::warn!("Socket error while awaiting EOF: {}", e);
                    break;
                }
            }
        }
    }

    async fn wait_for_exit(&mut self, timeout: Duration) -> io::Result<ExitReason> {
        let deadline = Timer::after(timeout);
        let mut deadline = std::pin::pin!(deadline);
        loop {
            let socket = match self.state.socket() {
                Some(s) => s,
                None => {
                    return Err(io::Error::new(io::ErrorKind::NotConnected, "child not running"));
                }
            };
            match select(read_msg_async::<DutMessage>(socket), deadline.as_mut()).await {
                Either::First(Ok(Some(DutMessage::Exiting { reason }))) => {
                    self.transition_to_exiting(reason);
                    return Ok(reason);
                }
                Either::First(Ok(Some(other))) => {
                    // Buffer captures, forward logs, etc.
                    let _ = self.ingest_dut_message(other);
                }
                Either::First(Ok(None)) => {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF before Exiting"));
                }
                Either::First(Err(e)) => return Err(e),
                Either::Second(_) => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "wait_for_exit timeout"));
                }
            }
        }
    }

    async fn wait_for_ready(&mut self) -> io::Result<()> {
        loop {
            let socket = match self.state.socket() {
                Some(s) => s,
                None => {
                    return Err(io::Error::new(io::ErrorKind::NotConnected, "child not running"));
                }
            };
            match read_msg_async::<DutMessage>(socket).await {
                Ok(Some(DutMessage::Ready)) => {
                    log::info!("Child DUT is ready");
                    return Ok(());
                }
                Ok(Some(DutMessage::Log { level, target, message })) => forward_log(level, target, message),
                Ok(Some(other)) => {
                    log::warn!("Unexpected pre-Ready message: {:?}", other);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "expected Ready"));
                }
                Ok(None) => {
                    self.mark_dead();
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "child exited before Ready"));
                }
                Err(e) => {
                    self.mark_dead();
                    return Err(e);
                }
            }
        }
    }

    /// Read until `RoiComplete` arrives, buffering any
    /// `UnsolicitedFrame`s (ROI telegrams) along the way.
    async fn wait_for_roi_complete(&mut self) -> io::Result<()> {
        loop {
            let socket = match self.state.socket() {
                Some(s) => s,
                None => {
                    return Err(io::Error::new(io::ErrorKind::NotConnected, "child not running"));
                }
            };
            match read_msg_async::<DutMessage>(socket).await {
                Ok(Some(DutMessage::RoiComplete)) => return Ok(()),
                Ok(Some(DutMessage::UnsolicitedFrame { frame, .. })) => {
                    // Frames that land during `wait_for_roi_complete`
                    // are by definition the read-on-init scan — even
                    // though they arrive as `UnsolicitedFrame` on the
                    // wire, tag them as `RoiScan` so mismatch
                    // diagnostics can distinguish ROI leakage from
                    // real retransmits.
                    self.unsolicited_frames.push_back(TaggedFrame {
                        source: FrameSource::RoiScan,
                        message: captured_frame_to_message(frame),
                    });
                }
                Ok(Some(DutMessage::Log { level, target, message })) => forward_log(level, target, message),
                Ok(Some(other)) => {
                    log::warn!("Unexpected message while waiting for RoiComplete: {:?}", other);
                }
                Ok(None) => {
                    self.mark_dead();
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF before RoiComplete"));
                }
                Err(e) => {
                    self.mark_dead();
                    return Err(e);
                }
            }
        }
    }

    fn mark_dead(&mut self) {
        match std::mem::replace(&mut self.state, LifecycleState::Dead) {
            LifecycleState::Running { mut child, .. } | LifecycleState::Exiting { mut child, .. } => {
                let _ = child.wait();
            }
            LifecycleState::Dead => {}
        }
    }

    fn reap_any_child(&mut self) {
        self.mark_dead();
    }

    // ========================================================================
    // Child spawn
    // ========================================================================

    async fn spawn_child_binary(&mut self, binary_name: &str) -> io::Result<()> {
        let (parent_stream, child_stream) = UnixStream::pair()?;
        parent_stream.set_nonblocking(true)?;

        // The child inherits the SHM fd and its socket fd; clear
        // CLOEXEC on both so they survive exec.
        self.shm.clear_cloexec()?;
        let child_fd = child_stream.as_raw_fd();
        clear_cloexec(child_fd)?;

        let shm_fd_str = self.shm.fd().to_string();
        let sock_fd_str = child_fd.to_string();

        let dut_path =
            std::env::current_exe().map(|p| p.with_file_name(binary_name)).unwrap_or_else(|_| binary_name.into());

        let child = Command::new(&dut_path)
            .arg("--shm-fd")
            .arg(&shm_fd_str)
            .arg("--socket-fd")
            .arg(&sock_fd_str)
            .spawn()
            .map_err(|e| io::Error::new(e.kind(), format!("failed to spawn {}: {}", dut_path.display(), e)))?;

        drop(child_stream);
        let async_socket = Async::new(parent_stream)?;

        self.state = LifecycleState::Running { child, socket: async_socket };
        Ok(())
    }
}

impl Drop for ChildLifecycle {
    fn drop(&mut self) {
        // Kill any running child so we don't leave orphan processes
        // behind when the runner panics.
        match std::mem::replace(&mut self.state, LifecycleState::Dead) {
            LifecycleState::Running { mut child, .. } | LifecycleState::Exiting { mut child, .. } => {
                let _ = child.kill();
                let _ = child.wait();
            }
            LifecycleState::Dead => {}
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn captured_frame_to_message(frame: CapturedFrame) -> CapturedLinkLayerMessage {
    CapturedLinkLayerMessage { service_type: ServiceType::from(frame.service_type), data: frame.data }
}

fn forward_log(level: u8, target: String, message: String) {
    let level = match level {
        1 => log::Level::Error,
        2 => log::Level::Warn,
        3 => log::Level::Info,
        4 => log::Level::Debug,
        _ => log::Level::Trace,
    };
    logger::add_entry(LogEntry { level, target, message, timestamp_ms: elapsed_ms() });
}

use std::time::Instant;

static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn elapsed_ms() -> u64 {
    START_TIME.get_or_init(Instant::now).elapsed().as_millis() as u64
}

fn clear_cloexec(fd: std::os::unix::io::RawFd) -> io::Result<()> {
    use nix::fcntl;
    let flags = fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFD).map_err(io::Error::other)?;
    let mut fd_flags = nix::fcntl::FdFlag::from_bits_truncate(flags);
    fd_flags.remove(nix::fcntl::FdFlag::FD_CLOEXEC);
    fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFD(fd_flags)).map_err(io::Error::other)?;
    Ok(())
}
