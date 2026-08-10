//! IPC link layer for multi-process conformance testing.
//!
//! Speaks the postcard-based [`RunnerMessage`] / [`DutMessage`]
//! protocol defined in [`crate::ipc::protocol`] over the child's end of
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
use std::sync::atomic::Ordering;

use async_io::Async;
use embassy_futures::select::{Either, select};
use embassy_futures::yield_now;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::DynamicSender;
use embassy_sync::signal::Signal;

use zweidraehte_device::layers::{Inbox, LinkLayerBuilder, LinkLayerBuilderBase};
use zweidraehte_proto::encoding::tp1;
use zweidraehte_proto::messages::buffers::{Buffer, MessageBuffer};
use zweidraehte_proto::messages::builder::{ConfirmationMessage, IndicationMessage, RequestMessage};
use zweidraehte_proto::messages::knx::*;

use crate::ipc::framing::{read_msg_async, write_msg_async};
use crate::ipc::protocol::{CapturedFrame, DutMessage, ExitReason, RunnerMessage};

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
// The barrier state lives in process-global `embassy_sync::Signal`s
// because the lifecycle handlers (dut::common) and the `IpcLinkLayer`
// (this module) have no direct shared reference. The signals provide
// proper "wait until" semantics without polling sleeps, at the cost
// of a `CriticalSectionRawMutex` — cheap on the single-threaded
// executor used by the DUT binaries.

struct BarrierState {
    /// Carries the [`ExitReason`] from the lifecycle handler to
    /// [`IpcLinkLayer::emit_step_complete`], which writes
    /// `DutMessage::Exiting` immediately after `StepComplete` so both
    /// land back-to-back in the socket buffer.
    pending_exit: Signal<CriticalSectionRawMutex, ExitReason>,
    step_settled: Signal<CriticalSectionRawMutex, ()>,
}

impl BarrierState {
    const fn new() -> Self {
        Self { pending_exit: Signal::new(), step_settled: Signal::new() }
    }
}

static BARRIER: BarrierState = BarrierState::new();

// ============================================================================
// Read-on-init-complete signal
// ============================================================================
//
// The device stack publishes `LifecycleEvent::ReadOnInitComplete` through
// its public pub/sub channel (see `Stack::lifecycle_events`) when the AL's
// read-on-init scan reaches `Done` — or settles in `Idle` on a startup
// where preconditions can't be met (factory-reset state with no app
// loaded). A small bridge task in `dut::common` subscribes to that channel
// and fires this signal so `drain_roi_and_announce` below can wait on a
// single primitive without pulling `LifecycleEvent` into the link layer.

static ROI_DONE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Fire the "read-on-init settled" signal. Called from the DUT's
/// lifecycle-event bridge task; see `crate::dut::common`.
pub fn signal_roi_done() {
    ROI_DONE.signal(());
}

fn roi_done_signal() -> &'static Signal<CriticalSectionRawMutex, ()> {
    &ROI_DONE
}

/// Lifecycle handlers call this first, passing the reason the DUT is
/// exiting. Once signalled, the IpcLinkLayer will emit its pending
/// `StepComplete` immediately (cutting any drain quiet-window short),
/// then write `DutMessage::Exiting { reason }` back-to-back, then
/// signal `step_settled`.
///
/// Coupling the `Exiting` write into the same async task as
/// `StepComplete` removes a cross-task scheduling gap that was wide
/// enough on macOS (kqueue + smaller default unix-socket buffers) for
/// the runner to read `StepComplete`, time out its 2 ms follow-up
/// poll for `Exiting`, and then hit `EPIPE` on the next inject because
/// the lifecycle hadn't transitioned to `Dead`.
pub fn mark_pending_exit(reason: ExitReason) {
    BARRIER.pending_exit.signal(reason);
}

/// Non-blocking probe used inside the drain loop to decide whether to
/// shortcut the quiet-window wait. Does **not** consume the value —
/// `emit_step_complete` calls [`pending_exit_take`] later.
fn pending_exit_raised() -> bool {
    BARRIER.pending_exit.signaled()
}

/// Consume the pending-exit reason if one was set. Called by
/// `emit_step_complete` after the `StepComplete` write so it can append
/// `DutMessage::Exiting` from the same task.
fn pending_exit_take() -> Option<ExitReason> {
    BARRIER.pending_exit.try_take()
}

/// Reset the barrier — called from within `emit_step_complete` just
/// before we re-signal `step_settled`, so the next step starts clean.
fn barrier_reset() {
    BARRIER.pending_exit.reset();
    BARRIER.step_settled.reset();
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
// reset) are received by the link layer's main loop and forwarded to a
// separate "command handler" task via an embassy channel. The channel
// carries plain [`RunnerMessage`]s — the same type deserialised from
// the socket — so the handler side is the single source of truth for
// command semantics. Inject variants never reach the handler: the link
// layer processes those inline.
//
// An earlier revision used a dedicated `IpcCommand` enum that mirrored
// the dispatchable subset of `RunnerMessage`. It doubled the
// maintenance cost every time a new command variant was added, so the
// two enums were collapsed in Phase 9 of the conformance refactor.

/// Alias preserving a clear name for the channel item type. The link
/// layer never pushes `Inject` through the channel, but the type is
/// wide enough to carry it; the handler matches on the variants it
/// cares about and logs a warning on the rest.
pub type IpcCommand = RunnerMessage;

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
                    if let Err(e) =
                        write_msg_async(&self.socket, &DutMessage::UnsolicitedFrame { frame_seq, frame }).await
                    {
                        log::error!("IPC LL: failed to write UnsolicitedFrame: {}", e);
                    }
                }
            }
        }
    }

    /// Drain all outbox frames produced during startup (read-on-init
    /// scan), forwarding each as an `UnsolicitedFrame`. Emit
    /// `RoiComplete` once the AL has signalled that the scan has run
    /// to `ReadOnInitState::Done`.
    ///
    /// We use unsolicited semantics (not batched) here because the test
    /// hasn't issued a command yet — there is no pending `StepComplete`
    /// to attach the frames to.
    ///
    /// # Done-detection
    ///
    /// The AL publishes [`LifecycleEvent::ReadOnInitComplete`] exactly
    /// once per startup when its scan settles; a bridge task in
    /// [`crate::dut::common::bridge_lifecycle_to_ipc`] forwards that
    /// publish into the local [`ROI_DONE`] signal. We `select!` on
    /// `req_rx` and that signal, falling through with a tight
    /// safety-net timer if the signal never arrives (broken stack).
    /// After the done signal we still drain one extra pass for frames
    /// that may already sit in the request channel, since the signal
    /// fires on state transition and the request that produced the
    /// last frame may land a tick after.
    async fn drain_roi_and_announce(&mut self, req_rx: &mut impl Inbox<RequestMessage<Buffer<'static>>>) {
        use embassy_futures::select::{Either, select};
        use embassy_time::{Duration, Timer};

        // The signal is process-local (static in the DUT's address
        // space), so a respawned DUT sees a fresh `Signal` — no need
        // to reset here. Resetting would race with the bridge task's
        // `signal_roi_done()` call if the task fired before this task
        // got to `signal.wait()`.
        let signal = roi_done_signal();

        // Outer loop: pump ROI frames until the AL signals settled
        // (either `Done` or "no ROI needed on this startup"; see
        // `GroupDataProvider::poll`). The safety-net timer is a
        // belt-and-braces cap for the case where the stack hangs
        // before it can poll — it should never fire under normal
        // operation, so we keep it tight so broken runs fail fast
        // rather than idle for seconds per respawn.
        let done_fut = signal.wait();
        let deadline = Timer::after(Duration::from_millis(1000));
        let mut done_fut = core::pin::pin!(done_fut);
        let mut deadline = core::pin::pin!(deadline);

        loop {
            match select(req_rx.next(), select(done_fut.as_mut(), deadline.as_mut())).await {
                Either::First(msg) => {
                    let frame = self.capture_and_confirm(msg).await;
                    let frame_seq = self.unsolicited_seq;
                    self.unsolicited_seq = self.unsolicited_seq.wrapping_add(1);
                    if let Err(e) =
                        write_msg_async(&self.socket, &DutMessage::UnsolicitedFrame { frame_seq, frame }).await
                    {
                        log::error!("IPC LL: failed to write ROI frame: {}", e);
                    }
                }
                Either::Second(Either::First(())) => {
                    log::debug!("IPC LL: ROI settled signal received");
                    break;
                }
                Either::Second(Either::Second(_)) => {
                    log::warn!("IPC LL: ROI settled signal not received within 1s — proceeding anyway");
                    break;
                }
            }
        }

        // Final drain: pick up anything that landed after the done
        // signal but before we broke out of the loop.
        while let Some(msg) = req_rx.try_next() {
            let frame = self.capture_and_confirm(msg).await;
            let frame_seq = self.unsolicited_seq;
            self.unsolicited_seq = self.unsolicited_seq.wrapping_add(1);
            if let Err(e) = write_msg_async(&self.socket, &DutMessage::UnsolicitedFrame { frame_seq, frame }).await {
                log::error!("IPC LL: failed to write trailing ROI frame: {}", e);
            }
        }

        if let Err(e) = write_msg_async(&self.socket, &DutMessage::RoiComplete).await {
            log::error!("IPC LL: failed to send RoiComplete: {}", e);
        }
    }

    /// Execute one `RunnerMessage`, draining the outbox into a batched
    /// `StepComplete` reply. For `PowerCycle` / `MasterReset`, the
    /// command handler task drives the exit path; we just forward.
    async fn dispatch_command(&mut self, cmd: RunnerMessage, req_rx: &mut impl Inbox<RequestMessage<Buffer<'static>>>) {
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
                self.command_tx.send(IpcCommand::TriggerSync { seq, peer_ia, tool_access, is_broadcast }).await;
                let frames = self.drain_step(req_rx).await;
                self.emit_step_complete(seq, frames).await;
            }
            RunnerMessage::PowerCycle => {
                self.command_tx.send(IpcCommand::PowerCycle).await;
                self.flush_lifecycle_exit().await;
            }
            RunnerMessage::MasterReset { erase_code } => {
                self.command_tx.send(IpcCommand::MasterReset { erase_code }).await;
                self.flush_lifecycle_exit().await;
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
                    // drain. Those handlers signal `pending_exit`
                    // before any state mutation — see
                    // `mark_pending_exit`.
                    if pending_exit_raised() {
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
        let data = tp1::knx_to_tp1_vec_no_checksum(&msg.buf()[..msg.len()]);
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

    async fn emit_step_complete(&mut self, seq: u32, frames: heapless::Vec<CapturedFrame, MAX_STEP_FRAMES>) {
        // heapless::Vec → Vec so we don't force a const generic through
        // the DutMessage serde derive. Postcard serialises both the
        // same way on the wire; this is just ergonomics for the enum.
        let frames: Vec<CapturedFrame> = frames.into_iter().collect();
        if let Err(e) = write_msg_async(&self.socket, &DutMessage::StepComplete { seq, frames }).await {
            log::error!("IPC LL: failed to write StepComplete(seq={}): {}", seq, e);
        }
        // If a lifecycle handler raised `pending_exit` before this
        // step completed (restart / power-cycle / master-reset), write
        // `Exiting` from the same task immediately after
        // `StepComplete`. Both messages then sit contiguously in the
        // socket send buffer with no scheduling gap between them —
        // the runner's `read_until_step_complete` post-StepComplete
        // poll always finds `Exiting` waiting.
        if let Some(reason) = pending_exit_take() {
            if let Err(e) = write_msg_async(&self.socket, &DutMessage::Exiting { reason }).await {
                log::error!("IPC LL: failed to write Exiting: {}", e);
            }
        }
        // Release the barrier — `emit_exiting_and_shutdown` now only
        // needs to half-close the socket; the `Exiting` frame is
        // already on the wire.
        BARRIER.step_settled.signal(());
    }

    /// Write `DutMessage::Exiting` for `PowerCycle` / `MasterReset`,
    /// which dispatch their work on `command_tx` and never produce a
    /// `StepComplete`. The lifecycle handler task in `dut::common`
    /// calls `emit_exiting_and_shutdown` → `mark_pending_exit(reason)`
    /// shortly after it picks the command up. Wait for that signal,
    /// write `Exiting` from this same async task (preserving the
    /// contiguous-write invariant that `emit_step_complete` relies on
    /// for macOS), then release `step_settled` so the lifecycle
    /// handler's wait unblocks and `process::exit` can proceed.
    ///
    /// The 50 ms cap matches the safety timeout used inside
    /// `emit_exiting_and_shutdown`; if the handler never fires the
    /// signal the DUT is wedged anyway and we'd rather race to EOF
    /// than deadlock.
    async fn flush_lifecycle_exit(&mut self) {
        use embassy_time::{Duration, Timer};

        let reason = match select(BARRIER.pending_exit.wait(), Timer::after(Duration::from_millis(50))).await {
            Either::First(reason) => reason,
            Either::Second(_) => {
                log::error!("IPC LL: timed out waiting for lifecycle exit reason; closing socket without Exiting");
                BARRIER.step_settled.signal(());
                return;
            }
        };
        if let Err(e) = write_msg_async(&self.socket, &DutMessage::Exiting { reason }).await {
            log::error!("IPC LL: failed to write Exiting: {}", e);
        }
        BARRIER.step_settled.signal(());
    }
}

// ============================================================================
// Lifecycle helpers for the command handler task
// ============================================================================

/// Announce the pending exit and wait for the IpcLinkLayer to flush
/// `StepComplete` + `Exiting`, **without** closing the socket.
///
/// The actual `DutMessage::Exiting` write is performed by
/// [`IpcLinkLayer::emit_step_complete`] from the same async task that
/// just wrote `StepComplete`, so both frames sit contiguously in the
/// socket buffer. The contiguity matters: a cross-task scheduling gap
/// here lets the runner read `StepComplete` and close before `Exiting`
/// is written, which surfaces as `EPIPE` (seen on macOS).
///
/// That is also why this is separable from the shutdown. The A_Restart
/// path runs inside the device stack's generic storage task, which has
/// work to do *between* the announcement and the exit — the erase, the
/// config save, the settle delay. It announces here (from
/// `StorageHooks::on_restart`, while the response frames are still in
/// flight, which is the only moment the runner is listening) and closes
/// the socket later, from `SystemControl::restart`. The IPC-command
/// path has nothing in between and uses
/// [`emit_exiting_and_shutdown`] to do both at once.
pub async fn announce_exit(reason: ExitReason) {
    use embassy_time::{Duration, Timer};

    // Hand the exit reason off to the IpcLinkLayer, which will append
    // `Exiting` to the socket immediately after `StepComplete`. Also
    // cuts `IpcLinkLayer::drain_step`'s quiet window short.
    mark_pending_exit(reason);

    // Wait until the IpcLinkLayer has flushed both frames. Capped at
    // ~50 ms against a hang if the async LL task crashed earlier —
    // we'd rather exit slightly early than deadlock the DUT.
    let _ = select(BARRIER.step_settled.wait(), Timer::after(Duration::from_millis(50))).await;
}

/// [`announce_exit`] followed by half-closing the write side of the
/// socket. Called by the power-cycle / master-reset handlers
/// immediately before `process::exit`.
pub async fn emit_exiting_and_shutdown(reason: ExitReason) {
    announce_exit(reason).await;
    shutdown_ipc_socket();
}

// ============================================================================
// TP1 encoding (internal → wire)
// ============================================================================

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
