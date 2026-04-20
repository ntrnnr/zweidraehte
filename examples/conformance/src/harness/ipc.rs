//! IPC link layer for multi-process conformance testing.
//!
//! Speaks the postcard-based [`RunnerMessage`] / [`DutMessage`]
//! protocol defined in [`super::protocol`] over the child's end of
//! the socketpair, and sits inside the DUT's stack as an
//! `embassy`-async link layer.
//!
//! # Protocol
//!
//! - Every [`RunnerMessage::Inject`] (and the other step-carrying
//!   commands) is answered by exactly one
//!   [`DutMessage::StepComplete`] carrying all outbox frames
//!   produced while the router drained its queue for that step. No
//!   more "was this frame caused by my inject or a timer?" race.
//! - [`DutMessage::Ready`] and [`DutMessage::RoiComplete`] are
//!   explicit lifecycle signals emitted at startup.
//! - Timer-driven retransmissions and deferred ROI frames that land
//!   between steps become [`DutMessage::UnsolicitedFrame`] with a
//!   monotonic `frame_seq` for diagnostic ordering.
//! - Restart / power-cycle / master-reset don't sleep to "drain the
//!   outbox": the `PENDING_EXIT` / `STEP_SETTLED` barrier below lets
//!   the active step flush its `StepComplete` before the exit path
//!   writes [`DutMessage::Exiting`] and shuts down the socket.

use core::future::Future;
use core::mem::MaybeUninit;
use std::io;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};

use async_io::Async;
use embassy_futures::select::{Either, select};
use embassy_futures::yield_now;
use embassy_sync::channel::DynamicSender;

use zweidraehte_device::layers::{Inbox, LinkLayerBuilder, LinkLayerBuilderBase};
use zweidraehte_proto::encoding::tp1;
use zweidraehte_proto::messages::buffers::{Buffer, MessageBuffer};
use zweidraehte_proto::messages::builder::{ConfirmationMessage, IndicationMessage, RequestMessage};
use zweidraehte_proto::messages::knx::*;

use super::framing::{read_msg_async, write_msg_async};
use super::protocol::{CapturedFrame, DutMessage, ExitReason, RunnerMessage};

/// Maximum number of outbox frames a single router tick can produce
/// before we start logging warnings. All real conformance tests
/// produce 1-3 frames per inject; 16 is a huge safety margin and
/// keeps us off the heap on the DUT side if we ever move to no_std.
const MAX_STEP_FRAMES: usize = 16;

/// Upper bound on drain-loop iterations per step. Protects against a
/// misbehaving stack that emits a frame on every confirmation forever
/// (ACK storm). Far larger than any legitimate router tick produces.
const MAX_DRAIN_ITERS: usize = 128;

// ============================================================================
// Step barrier for restart / power-cycle / master-reset
// ============================================================================
//
// Without a barrier, there is a race between the restart handler
// (which reads the `RestartRequest` from its channel and then calls
// `exit(0)`) and the IpcLinkLayer's drain loop (which still has the
// T_ACK + A_Restart_Response frames to capture and batch into a
// `StepComplete`). If the restart handler wins, the runner sees the
// `Exiting` + EOF before any captured frames — so the test's
// `Expect [T_ACK]` after an `A_Restart` inject times out.
//
// The barrier is a pair of `AtomicBool`s:
//
// - `PENDING_EXIT`: set by the lifecycle handler (restart / power-
//   cycle / master-reset) before it calls `flush_and_exit`. Signals
//   "there is an exit pending — do not yield before emitting any
//   in-flight `StepComplete`".
// - `STEP_SETTLED`: set by `IpcLinkLayer` after the current step's
//   `StepComplete` has been written (or, if there is no current step
//   because the handler was triggered by an IPC command rather than
//   an injected APDU, immediately). The lifecycle handler polls this
//   flag and proceeds with the final `Exiting` + shutdown only once
//   it flips to `true`.
//
// Both flags live in static atomics because they are shared between
// tasks that don't otherwise reference each other (the lifecycle
// handlers live in dut_common / binary-specific code; the
// IpcLinkLayer lives in this module).

static PENDING_EXIT: AtomicBool = AtomicBool::new(false);
static STEP_SETTLED: AtomicBool = AtomicBool::new(false);

/// Lifecycle handlers call this first. Once set, IpcLinkLayer will
/// emit its pending `StepComplete` immediately (cutting any drain-
/// quiet-window short) and then set `STEP_SETTLED`.
pub fn mark_pending_exit() {
    PENDING_EXIT.store(true, Ordering::Release);
}

/// Lifecycle handlers spin on this after writing their state snapshot
/// to SHM. Returns `true` once the IpcLinkLayer has finished the
/// current step.
pub fn step_settled() -> bool {
    STEP_SETTLED.load(Ordering::Acquire)
}

/// Reset the barrier — called from within `emit_step_complete` just
/// before we signal `STEP_SETTLED`, so the next step starts clean.
fn barrier_reset() {
    PENDING_EXIT.store(false, Ordering::Release);
    STEP_SETTLED.store(false, Ordering::Release);
}

// ============================================================================
// Raw-fd socket shutdown helper
// ============================================================================
//
// The DUT's exit path does `shutdown(SHUT_WR)` + `exit(0)` to guarantee
// the kernel delivers EOF to the parent only after every buffered write
// (including the final `DutMessage::Exiting`) has drained. The primary
// socket fd is registered here at startup so the lifecycle tasks can
// trigger the shutdown without holding an `Async<UnixStream>`.

use std::sync::atomic::AtomicI32;

static PRIMARY_SOCKET_FD: AtomicI32 = AtomicI32::new(-1);

/// Publish the primary socket fd so [`shutdown_ipc_socket`] can reach
/// it. Called by the DUT binaries once, immediately after `parse_args`.
pub fn set_primary_socket_fd(fd: RawFd) {
    PRIMARY_SOCKET_FD.store(fd, Ordering::Relaxed);
}

/// Half-close the write side of the primary IPC socket. The kernel
/// delivers EOF to the parent after the send buffer drains — any
/// `DutMessage::Exiting` frame written immediately before this call is
/// guaranteed to reach the parent before the EOF.
pub fn shutdown_ipc_socket() {
    let fd = PRIMARY_SOCKET_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: fd was registered from `set_primary_socket_fd` and
        // outlives the shutdown syscall. `shutdown(SHUT_WR)` is a pure
        // kernel-side flush barrier.
        let _ = unsafe { nix::libc::shutdown(fd, nix::libc::SHUT_WR) };
    }
}

// ============================================================================
// IPC command channel
// ============================================================================
//
// Non-inject commands (programming mode, triggers, power-cycle, master
// reset) are received by the link layer's main loop and dispatched to a
// separate "command handler" task via an embassy channel. The link layer
// stays single-purpose; the handler task gets the full `Stack` handle.

/// Command dispatched from the link layer to the DUT-side command
/// handler. The `seq` field is carried through so the handler can tell
/// the link layer when it's done — at which point the link layer
/// emits `StepComplete` back to the runner.
///
/// Power-cycle and master-reset don't carry a seq because they don't
/// produce a `StepComplete`; the runner sees `Exiting` + EOF instead.
#[derive(Debug)]
pub enum IpcCommand {
    SetProgrammingMode { seq: u32, enabled: bool },
    TriggerRead { seq: u32, asap: u16 },
    TriggerWrite { seq: u32, asap: u16 },
    TriggerSync { seq: u32, peer_ia: u16, tool_access: bool, is_broadcast: bool },
    /// Flush state + exit (no erase). Handler calls [`shutdown_ipc_socket`]
    /// and `exit(0)` after writing `DutMessage::Exiting`.
    PowerCycle,
    /// Apply the erase code, flush, and exit. Handler drives the same
    /// exit path as `PowerCycle` after applying state.
    MasterReset { erase_code: u8 },
}

// ============================================================================
// IPC Link Layer
// ============================================================================

/// Link layer that speaks the new postcard IPC protocol. See the module
/// docs for semantics.
pub struct IpcLinkLayer<'a> {
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
    socket: Async<UnixStream>,
    buffer_manager: zweidraehte_proto::messages::buffers::DynBufferManager<'static>,
    command_tx: DynamicSender<'a, IpcCommand>,
    /// Monotonic counter for `DutMessage::UnsolicitedFrame::frame_seq`.
    unsolicited_seq: u32,
}

impl<'a> IpcLinkLayer<'a> {
    fn new(
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        socket: Async<UnixStream>,
        buffer_manager: zweidraehte_proto::messages::buffers::DynBufferManager<'static>,
        command_tx: DynamicSender<'a, IpcCommand>,
    ) -> Self {
        Self { ind_tx, conf_tx, socket, buffer_manager, command_tx, unsolicited_seq: 0 }
    }

    async fn process(&mut self, mut req_rx: impl Inbox<RequestMessage<Buffer<'static>>>) -> ! {
        // Lifecycle step 1: tell the runner we're alive. The runner
        // transitions from `Spawning` to `WaitingRoi` on receipt.
        if let Err(e) = write_msg_async(&self.socket, &DutMessage::Ready).await {
            log::error!("IPC LL failed to send Ready: {}", e);
            std::process::exit(1);
        }

        // Lifecycle step 2: stream any frames the stack produces at
        // startup (read-on-init scan) as `UnsolicitedFrame`s. Once the
        // router settles (no frames for one full yield), we send
        // `RoiComplete` and transition to the normal step-driven loop.
        self.drain_roi_and_announce(&mut req_rx).await;

        // Main loop: step-driven with unsolicited-frame passthrough.
        loop {
            match select(read_msg_async::<RunnerMessage>(&self.socket), req_rx.next()).await {
                Either::First(Ok(Some(cmd))) => self.dispatch_command(cmd, &mut req_rx).await,
                Either::First(Ok(None)) => {
                    log::info!("IPC LL: EOF from parent, exiting");
                    std::process::exit(0);
                }
                Either::First(Err(e)) => {
                    log::error!("IPC LL: socket read error: {}", e);
                    std::process::exit(1);
                }
                // A timer-driven frame arrived while idle. Forward it
                // as UnsolicitedFrame + send the L_Data_Con.
                Either::Second(msg) => {
                    let frame = self.capture_and_confirm(msg).await;
                    let frame_seq = self.unsolicited_seq;
                    self.unsolicited_seq = self.unsolicited_seq.wrapping_add(1);
                    if let Err(e) = write_msg_async(
                        &self.socket,
                        &DutMessage::UnsolicitedFrame { frame_seq, frame },
                    )
                    .await
                    {
                        log::error!("IPC LL: failed to write UnsolicitedFrame: {}", e);
                    }
                }
            }
        }
    }

    /// Drain all outbox frames produced during startup (read-on-init
    /// scan), forwarding each as an `UnsolicitedFrame`. Once the router
    /// stays quiet for `ROI_QUIET_WINDOW` with no new frames, emit
    /// `RoiComplete`.
    ///
    /// We use unsolicited semantics (not batched) here because the test
    /// hasn't issued a command yet — there is no pending `StepComplete`
    /// to attach the frames to.
    ///
    /// # Why a timed quiet window, not a yield count
    ///
    /// The AL's read-on-init scan fires one `GroupValueRead` per
    /// object and waits for the group-value responses to come back
    /// before moving to the next object, with `Timer::after`s between
    /// CO iterations. In fast mode (`KNX_TIME_DIVISOR=50`) the
    /// observed full-scan duration is ~650 ms for the conformance
    /// device (17 GOs with 8 pending responses in between).
    ///
    /// A wall-clock quiet window long enough to cover the worst-case
    /// inter-CO gap avoids declaring `RoiComplete` mid-scan, which
    /// would leak later ROI reads as `UnsolicitedFrame`s into
    /// subsequent tests. 800 ms is comfortably longer than any
    /// observed gap and well under the test-harness per-step budget.
    ///
    /// TODO: a cleaner approach is an explicit signal from the AL
    /// when `ReadOnInitState::Done` fires. That requires plumbing
    /// through the stack; defer until after Phase 5.
    async fn drain_roi_and_announce(
        &mut self,
        req_rx: &mut impl Inbox<RequestMessage<Buffer<'static>>>,
    ) {
        use embassy_time::{Duration, Timer};

        const ROI_POLL_INTERVAL_MS: u64 = 10;
        const ROI_QUIET_WINDOW_MS: u64 = 800;
        const QUIET_TICKS: u64 = ROI_QUIET_WINDOW_MS / ROI_POLL_INTERVAL_MS;

        let mut quiet = 0u64;
        loop {
            yield_now().await;
            match req_rx.try_next() {
                Some(msg) => {
                    quiet = 0;
                    let frame = self.capture_and_confirm(msg).await;
                    let frame_seq = self.unsolicited_seq;
                    self.unsolicited_seq = self.unsolicited_seq.wrapping_add(1);
                    if let Err(e) = write_msg_async(
                        &self.socket,
                        &DutMessage::UnsolicitedFrame { frame_seq, frame },
                    )
                    .await
                    {
                        log::error!("IPC LL: failed to write ROI frame: {}", e);
                    }
                }
                None => {
                    quiet += 1;
                    if quiet >= QUIET_TICKS {
                        break;
                    }
                    Timer::after(Duration::from_millis(ROI_POLL_INTERVAL_MS)).await;
                }
            }
        }

        if let Err(e) = write_msg_async(&self.socket, &DutMessage::RoiComplete).await {
            log::error!("IPC LL: failed to send RoiComplete: {}", e);
        }
    }

    /// Execute one `RunnerMessage`, draining the outbox into a batched
    /// `StepComplete` reply. For `PowerCycle` / `MasterReset`, the
    /// command handler task drives the exit path; we just forward.
    async fn dispatch_command(
        &mut self,
        cmd: RunnerMessage,
        req_rx: &mut impl Inbox<RequestMessage<Buffer<'static>>>,
    ) {
        // Reset the restart barrier — each dispatch starts from a
        // clean slate. Old flags from a previous step's no-op
        // shouldn't leak.
        barrier_reset();

        match cmd {
            RunnerMessage::Inject { seq, data } => {
                let mut buffer = self.buffer_manager.alloc().await;
                buffer.fill_from_slice(&data);
                let msg = KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind);
                let converted_buf = tp1::tp1_to_knx_message_no_checksum(msg.into_inner());
                let internal_msg = KnxMessageBuffer::new(converted_buf, ServiceType::L_Data_Ind);
                log::debug!("IPC LL inject seq={}: {:x?}", seq, internal_msg);
                self.ind_tx.send(IndicationMessage::indication(internal_msg)).await;
                let frames = self.drain_step(req_rx).await;
                self.emit_step_complete(seq, frames).await;
            }
            RunnerMessage::SetProgrammingMode { seq, enabled } => {
                self.command_tx.send(IpcCommand::SetProgrammingMode { seq, enabled }).await;
                let frames = self.drain_step(req_rx).await;
                self.emit_step_complete(seq, frames).await;
            }
            RunnerMessage::TriggerRead { seq, asap } => {
                self.command_tx.send(IpcCommand::TriggerRead { seq, asap }).await;
                let frames = self.drain_step(req_rx).await;
                self.emit_step_complete(seq, frames).await;
            }
            RunnerMessage::TriggerWrite { seq, asap } => {
                self.command_tx.send(IpcCommand::TriggerWrite { seq, asap }).await;
                let frames = self.drain_step(req_rx).await;
                self.emit_step_complete(seq, frames).await;
            }
            RunnerMessage::TriggerSync { seq, peer_ia, tool_access, is_broadcast } => {
                self.command_tx
                    .send(IpcCommand::TriggerSync { seq, peer_ia, tool_access, is_broadcast })
                    .await;
                let frames = self.drain_step(req_rx).await;
                self.emit_step_complete(seq, frames).await;
            }
            RunnerMessage::PowerCycle => {
                self.command_tx.send(IpcCommand::PowerCycle).await;
                // No StepComplete: the handler writes Exiting + exits.
                // The main loop stays alive to forward unsolicited frames
                // that may slip in before the handler is scheduled; it
                // will observe EOF and exit naturally.
            }
            RunnerMessage::MasterReset { erase_code } => {
                self.command_tx.send(IpcCommand::MasterReset { erase_code }).await;
            }
        }
    }

    /// Drain every outbox frame produced by the current step.
    ///
    /// The router is cooperative and yields after each `ll_req.send()`,
    /// but response generation can involve a chain of ticks (AL
    /// enqueues a T_ACK + response, TL drains both onto `ll_req`,
    /// each separated by yields). A pure `yield_now`-loop can
    /// declare "drained" while the router is still mid-chain.
    ///
    /// The quiet window needs to be tight: the runner's per-step
    /// round-trip accumulates across many injects, and each extra
    /// ms pushes the total closer to the DUT's 60 ms TL ACK window
    /// (fast-mode). Cross that, and the DUT retransmits prior
    /// responses, polluting later expects.
    ///
    /// We use `YIELDS_PER_POLL` consecutive empty `yield_now`s as
    /// the quiet threshold. Yields are ~1 μs each, so this adds
    /// essentially zero wall-clock time — just enough router ticks
    /// to drain any chained sends. Chained retransmissions
    /// triggered by an inline `L_Data_Con` still get captured
    /// because `capture_and_confirm` sends the confirmation
    /// synchronously, and the next iteration re-polls the channel.
    async fn drain_step(
        &mut self,
        req_rx: &mut impl Inbox<RequestMessage<Buffer<'static>>>,
    ) -> heapless::Vec<CapturedFrame, MAX_STEP_FRAMES> {
        const YIELDS_PER_POLL: u32 = 8;

        let mut frames: heapless::Vec<CapturedFrame, MAX_STEP_FRAMES> = heapless::Vec::new();
        let mut quiet = 0u32;
        let mut iters = 0usize;
        loop {
            yield_now().await;
            match req_rx.try_next() {
                Some(msg) => {
                    quiet = 0;
                    let frame = self.capture_and_confirm(msg).await;
                    if frames.push(frame).is_err() {
                        log::warn!("IPC LL: step produced >{} frames, dropping", MAX_STEP_FRAMES);
                    }
                }
                None => {
                    // If a lifecycle handler (restart / power-cycle /
                    // master-reset) is about to exit, shortcut the
                    // drain. Those handlers set `PENDING_EXIT` before
                    // any state mutation — see `mark_pending_exit`.
                    if PENDING_EXIT.load(Ordering::Acquire) {
                        break;
                    }
                    quiet += 1;
                    if quiet >= YIELDS_PER_POLL {
                        break;
                    }
                }
            }
            iters += 1;
            if iters >= MAX_DRAIN_ITERS {
                log::warn!("IPC LL: drain_step hit iteration cap ({})", MAX_DRAIN_ITERS);
                break;
            }
        }
        frames
    }

    /// Capture one outgoing request frame (serialise to TP1), send the
    /// stack its `L_Data_Con` back, and return the captured bytes.
    async fn capture_and_confirm(&mut self, msg: RequestMessage<Buffer<'static>>) -> CapturedFrame {
        let data = knx_to_tp1_vec_no_checksum(&msg.buf()[..msg.len()]);
        let service_type: u8 = msg.service_type().into();

        // Send confirmation back up the stack.
        let mut inner = msg.into_inner();
        match inner.service_type() {
            ServiceType::L_Data_Req => {
                inner.ctrl_field_mut().set_c(Confirm::NoError);
                inner.set_service_type(ServiceType::L_Data_Con);
                self.conf_tx.send(ConfirmationMessage::confirmation(inner)).await;
            }
            other => {
                log::warn!("IPC LL: unexpected request service type: {:?}", other);
                inner.ctrl_field_mut().set_c(Confirm::Err);
                self.conf_tx.send(ConfirmationMessage::confirmation(inner)).await;
            }
        }

        CapturedFrame { service_type, data }
    }

    async fn emit_step_complete(
        &mut self,
        seq: u32,
        frames: heapless::Vec<CapturedFrame, MAX_STEP_FRAMES>,
    ) {
        // heapless::Vec → Vec so we don't force a const generic through
        // the DutMessage serde derive. Postcard serialises both the
        // same way on the wire; this is just ergonomics for the enum.
        let frames: Vec<CapturedFrame> = frames.into_iter().collect();
        if let Err(e) = write_msg_async(&self.socket, &DutMessage::StepComplete { seq, frames }).await {
            log::error!("IPC LL: failed to write StepComplete(seq={}): {}", seq, e);
        }
        // Release the barrier — any lifecycle handler that was
        // spinning on `step_settled()` may now proceed to write
        // `Exiting` + shutdown the socket.
        STEP_SETTLED.store(true, Ordering::Release);
    }
}

// ============================================================================
// Lifecycle helpers for the command handler task
// ============================================================================

/// Write `DutMessage::Exiting` on the primary socket (via a dup'd
/// blocking handle) and then half-close the write side. Called by the
/// restart / power-cycle / master-reset handlers immediately before
/// `process::exit`.
///
/// This uses a blocking write on a dup'd fd rather than the async link
/// layer's handle so the message is guaranteed to hit the socket before
/// the process exits — the async LL task may not be scheduled again
/// between our `Exiting` and the exit syscall.
pub async fn emit_exiting_and_shutdown(reason: ExitReason) {
    use embassy_time::{Duration, Instant, Timer};

    // Announce the pending exit so `IpcLinkLayer::drain_step` cuts
    // its quiet window short and emits `StepComplete` immediately.
    mark_pending_exit();

    // Cooperatively yield until the IpcLinkLayer has flushed its
    // pending StepComplete (if any). Capped at ~50 ms of wall-clock
    // to avoid a hang if the async LL task crashed earlier — we'd
    // rather exit slightly early than deadlock the DUT.
    let deadline = Instant::now() + Duration::from_millis(50);
    while !step_settled() && Instant::now() < deadline {
        Timer::after(Duration::from_millis(1)).await;
    }

    let fd = PRIMARY_SOCKET_FD.load(Ordering::Relaxed);
    if fd < 0 {
        log::error!("emit_exiting_and_shutdown: primary socket fd not registered");
        return;
    }

    // Dup so we get a blocking handle without disturbing the async
    // link layer's view of the fd. Both ends share the same kernel
    // send buffer, so `shutdown(SHUT_WR)` below still drains any
    // bytes queued by the async LL task.
    let dup_fd = match nix::unistd::dup(fd) {
        Ok(fd) => fd,
        Err(e) => {
            log::error!("emit_exiting_and_shutdown: dup failed: {}", e);
            return;
        }
    };

    // SAFETY: `dup` just returned a fresh fd that we own; wrapping it
    // in `UnixStream::from_raw_fd` transfers ownership — the stream
    // closes the fd on drop.
    let mut stream = unsafe { UnixStream::from_raw_fd(dup_fd) };
    // Non-blocking mode is a file-description-level flag shared across
    // dups on Linux. Force blocking for this final write so `write_all`
    // doesn't WouldBlock while the async LL might still be draining.
    let _ = stream.set_nonblocking(false);

    if let Err(e) = super::framing::write_msg_blocking(&mut stream, &DutMessage::Exiting { reason }) {
        log::error!("emit_exiting_and_shutdown: write failed: {}", e);
    }

    shutdown_ipc_socket();
    // `stream` closes the dup'd fd here.
}

// ============================================================================
// TP1 encoding (internal → wire)
// ============================================================================

/// Convert internal KNX message bytes to TP1 format (no checksum).
///
/// Duplicated from [`super::mock::knx_to_tp1_vec_no_checksum`] for
/// locality — the `mock` copy serves the in-process test harness
/// and the two copies are intentionally independent.
fn knx_to_tp1_vec_no_checksum(src: &[u8]) -> Vec<u8> {
    let len = src.len();
    if (len < 23) && ((src[5] & 0x0f) == 0) {
        let mut data = src.to_vec();
        data[5] = (data[5] & 0xf0) | ((len - 7) as u8);
        data[0] = (data[0] & 0x0c) | 0xb0;
        data
    } else {
        let orig_npdu = src[5];
        let mut data = Vec::with_capacity(len + 1);
        data.push((src[0] & 0x0C) | 0x30);
        data.push(orig_npdu);
        data.extend_from_slice(&src[1..5]);
        data.push((len - 7) as u8);
        data.extend_from_slice(&src[6..]);
        data
    }
}

// ============================================================================
// LinkLayerBuilder plumbing
// ============================================================================

pub struct IpcLinkLayerResources {
    _private: MaybeUninit<()>,
}

impl Default for IpcLinkLayerResources {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcLinkLayerResources {
    pub const fn new() -> Self {
        Self { _private: MaybeUninit::uninit() }
    }
}

/// Builder for the new-protocol IPC link layer. Takes the child's end
/// of the socketpair (raw fd), a buffer manager for inject allocations,
/// and a command channel sender for non-inject commands.
pub struct IpcLinkLayerBuilder {
    socket: Async<UnixStream>,
    buffer_manager: zweidraehte_proto::messages::buffers::DynBufferManager<'static>,
    command_tx: DynamicSender<'static, IpcCommand>,
}

impl IpcLinkLayerBuilder {
    pub fn new(
        socket_fd: RawFd,
        buffer_manager: zweidraehte_proto::messages::buffers::DynBufferManager<'static>,
        command_tx: DynamicSender<'static, IpcCommand>,
    ) -> io::Result<Self> {
        let stream = unsafe { UnixStream::from_raw_fd(socket_fd) };
        stream.set_nonblocking(true)?;
        let socket = Async::new(stream)?;
        Ok(Self { socket, buffer_manager, command_tx })
    }
}

impl LinkLayerBuilderBase for IpcLinkLayerBuilder {
    type Resources = IpcLinkLayerResources;

    fn create_resources(&self) -> Self::Resources {
        IpcLinkLayerResources::new()
    }
}

impl zweidraehte_device::layers::LinkLayerCapabilities for IpcLinkLayerBuilder {}

impl<CTX> LinkLayerBuilder<CTX> for IpcLinkLayerBuilder {
    fn build_and_run<'a>(
        self,
        _resources: &'a mut Self::Resources,
        _context: &'a CTX,
        _ll_endpoints: (),
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl Inbox<RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl Future<Output = !> + 'a {
        let mut ll = IpcLinkLayer::new(ind_tx, conf_tx, self.socket, self.buffer_manager, self.command_tx);
        async move { ll.process(req_rx).await }
    }
}
