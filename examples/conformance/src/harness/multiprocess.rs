//! Multi-process conformance test harness.
//!
//! The parent (conformance-runner) owns persistent device state in shared
//! memory and spawns a child process (conformance-dut) that runs the actual
//! KNX stack. Communication happens over a Unix socketpair.
//!
//! On restart, the child flushes persistent state to shared memory and
//! exits. The parent detects EOF, respawns the child, and the new child
//! starts with clean volatile state (transport connections, programming
//! mode, COM object statuses) while persistent state survives.

use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command};

use async_io::Async;

use super::ipc::{
    self, SharedMemory, TAG_CAPTURED, TAG_INJECT, TAG_LOG, TAG_MASTER_RESET, TAG_POWER_CYCLE, TAG_READY,
    TAG_SET_PROGRAMMING_MODE, TAG_TRIGGER_READ, TAG_TRIGGER_SYNC, TAG_TRIGGER_WRITE,
};
use super::mock::CapturedLinkLayerMessage;
use super::secure_stack::SecureConformanceDeviceConfig;
use super::stack::ConformanceDeviceConfig;

use crate::logger::{self, LogEntry};
use zweidraehte_proto::messages::knx::ServiceType;

// ============================================================================
// Child State
// ============================================================================

enum ChildState {
    /// Child process is running.
    Running { child: Child, socket: Async<UnixStream> },
    /// Child has exited (restart, crash, or not yet started).
    Dead,
}

// ============================================================================
// DUT mode
// ============================================================================

/// Which DUT binary the harness manages for its lifetime.
///
/// The mode is chosen at harness construction and **does not change**;
/// the runner is configured up front by the user (default `Secure`, or
/// `Plain` via the `--non-secure` flag). All suites run against whichever
/// DUT was selected — with the caveat that the runner filters out
/// secure-only suites when `Plain` is active (see `TestSuite::use_secure_dut`).
///
/// Rationale: a KNX Data Secure device must behave identically to a
/// plain device when Security Mode is off, so the secure DUT is a
/// strict superset. The plain DUT exists solely to keep the non-secure
/// code paths (plain `ApplicationLayer`, no `SecurityAugment`, etc.)
/// under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DutMode {
    /// Plain DUT — the `conformance-dut` binary with no KNX Data Secure.
    Plain,
    /// Data-Secure DUT — the `conformance-dut-secure` binary.
    Secure,
}

impl DutMode {
    fn binary_name(self) -> &'static str {
        match self {
            Self::Plain => "conformance-dut",
            Self::Secure => "conformance-dut-secure",
        }
    }
}

// ============================================================================
// Multi-Process Harness
// ============================================================================

/// Multi-process conformance test harness.
///
/// The parent creates shared memory, initializes device state, and spawns
/// a child process running the DUT stack. Test steps communicate with the
/// child over a Unix socket.
///
/// The [`DutMode`] is fixed at construction: the harness never switches
/// between plain and secure DUTs at runtime. To change modes, tear the
/// harness down and build a new one.
pub struct MultiProcessHarness {
    shm: SharedMemory,
    child: ChildState,
    mode: DutMode,
    /// Set by `inject` after an `A_Restart` payload. Consumed by the
    /// next `send_command`: if the child has actually exited within a
    /// short window, respawn with a fresh DUT; otherwise (restart was
    /// rejected, e.g. bad erase code), leave the live child alone.
    restart_pending: bool,
}

impl MultiProcessHarness {
    /// Create a new harness with initialized shared memory for `mode`.
    ///
    /// Seeds the shared memory with the default persisted snapshot
    /// appropriate for the chosen DUT (plain or secure state layout)
    /// but does NOT spawn the child yet. Call [`spawn_child`] or
    /// [`ensure_child_running`] to start the DUT.
    pub fn new(mode: DutMode) -> io::Result<Self> {
        let mut shm = SharedMemory::create()?;
        match mode {
            DutMode::Plain => shm.write_state(&ConformanceDeviceConfig::default_snapshot())?,
            DutMode::Secure => shm.write_state(&SecureConformanceDeviceConfig::default_snapshot())?,
        }
        Ok(Self { shm, child: ChildState::Dead, mode, restart_pending: false })
    }

    /// Which DUT variant this harness manages.
    pub fn mode(&self) -> DutMode {
        self.mode
    }

    /// Spawn the DUT child process using the harness's configured mode.
    pub async fn spawn_child(&mut self) -> io::Result<()> {
        let binary = self.mode.binary_name();
        self.spawn_child_binary(binary).await
    }

    /// Spawn a DUT child process with the given binary name.
    ///
    /// Creates a Unix socketpair, clears CLOEXEC on the shared memory fd,
    /// and spawns the child with `--shm-fd` and `--socket-fd` arguments.
    async fn spawn_child_binary(&mut self, binary_name: &str) -> io::Result<()> {
        let (parent_stream, child_stream) = UnixStream::pair()?;
        parent_stream.set_nonblocking(true)?;

        // The child needs to inherit the shm fd and its socket fd.
        // Clear CLOEXEC on both so they survive exec.
        self.shm.clear_cloexec()?;

        let child_fd = child_stream.as_raw_fd();
        clear_cloexec(child_fd)?;

        let shm_fd_str = self.shm.fd().to_string();
        let sock_fd_str = child_fd.to_string();

        // Find the DUT binary next to the runner binary.
        let dut_path =
            std::env::current_exe().map(|p| p.with_file_name(binary_name)).unwrap_or_else(|_| binary_name.into());

        let child = Command::new(&dut_path)
            .arg("--shm-fd")
            .arg(&shm_fd_str)
            .arg("--socket-fd")
            .arg(&sock_fd_str)
            .spawn()
            .map_err(|e| io::Error::new(e.kind(), format!("failed to spawn {}: {}", dut_path.display(), e)))?;

        // Close the child's end of the socket in the parent.
        drop(child_stream);

        let async_socket = Async::new(parent_stream)?;

        self.child = ChildState::Running { child, socket: async_socket };

        // Wait for the child to signal readiness
        self.wait_for_ready().await?;

        Ok(())
    }

    /// Wait for the child to send the `Ready` frame.
    ///
    /// Log frames received before Ready are forwarded to the parent's logger.
    async fn wait_for_ready(&mut self) -> io::Result<()> {
        let socket = match &self.child {
            ChildState::Running { socket, .. } => socket,
            ChildState::Dead => return Err(io::Error::new(io::ErrorKind::NotConnected, "child not running")),
        };

        loop {
            match ipc::read_frame_async(socket).await? {
                Some(frame) if frame.tag == TAG_READY => {
                    log::info!("Child DUT is ready");
                    return Ok(());
                }
                Some(frame) if frame.tag == TAG_LOG => {
                    handle_log_frame(&frame.payload);
                }
                Some(frame) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("expected Ready frame, got tag 0x{:02x}", frame.tag),
                    ));
                }
                None => {
                    self.mark_dead();
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "child exited before sending Ready"));
                }
            }
        }
    }

    /// Ensure a child is running, spawning one if necessary.
    pub async fn ensure_child_running(&mut self) -> io::Result<()> {
        if matches!(self.child, ChildState::Dead) {
            self.spawn_child().await?;
        }
        Ok(())
    }

    fn mark_dead(&mut self) {
        if let ChildState::Running { mut child, .. } = std::mem::replace(&mut self.child, ChildState::Dead) {
            // Reap the child to avoid zombies
            let _ = child.wait();
        }
    }

    /// Kill the current child process (if running) and mark it dead.
    pub async fn kill_child(&mut self) {
        if let ChildState::Running { ref mut child, .. } = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = ChildState::Dead;
    }

    /// Re-initialize shared memory with the default snapshot for this
    /// harness's DUT mode.
    ///
    /// For [`DutMode::Secure`] this additionally wipes the sequence-number
    /// region at the tail of the SHM (see below) so the respawned DUT
    /// doesn't inherit stale counters.
    pub fn reset_shared_memory(&mut self) -> io::Result<()> {
        match self.mode {
            DutMode::Plain => self
                .shm
                .write_state(&ConformanceDeviceConfig::default_snapshot())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("write shared memory: {}", e))),
            DutMode::Secure => self.reset_shared_memory_secure_impl(),
        }
    }

    /// Secure-specific reset: default snapshot plus seqnr wipe.
    fn reset_shared_memory_secure_impl(&mut self) -> io::Result<()> {
        let snapshot = SecureConformanceDeviceConfig::default_snapshot();
        self.shm
            .write_state(&snapshot)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("write shared memory: {}", e)))?;
        // Also wipe the tail-of-SHM sequence-number region so the
        // respawned DUT doesn't inherit stale receiving/sending seq
        // counters. Without this, the newly-minted factory-default DUT
        // rejects the harness's first secure frame as a replay because
        // the SHM still holds the previous DUT's advanced tool seq.
        self.shm.clear_seq_region();
        Ok(())
    }

    fn socket(&self) -> io::Result<&Async<UnixStream>> {
        match &self.child {
            ChildState::Running { socket, .. } => Ok(socket),
            ChildState::Dead => Err(io::Error::new(io::ErrorKind::NotConnected, "child not running")),
        }
    }

    // ========================================================================
    // Test Harness Interface
    // ========================================================================
    //
    // These methods mirror the FullStackHarness API but communicate over IPC
    // instead of in-process channels.

    /// Inject a telegram into the DUT (raw TP1 bytes, no checksum).
    ///
    /// If the write fails with `BrokenPipe` (child exited due to restart),
    /// the harness automatically respawns and retries the injection.
    ///
    /// When the injected APDU carries `A_Restart`, the harness arms a
    /// short "restart settle" window that's consumed by the next
    /// `send_command` — see [`settle_pending_restart`](Self::settle_pending_restart).
    /// The DUT may still *reject* the restart (bad erase code, access
    /// denied, etc.); in that case the settle window simply times out
    /// without touching the child, and normal flow resumes.
    pub async fn inject(&mut self, data: &[u8]) -> io::Result<()> {
        let result = self.send_command(TAG_INJECT, data).await;
        if result.is_ok() && injection_is_restart(data) {
            self.restart_pending = true;
        }
        result
    }

    /// If an `A_Restart` was injected earlier, poll the DUT child: if
    /// it has actually exited, respawn with a fresh child so the next
    /// command sees clean TL state; otherwise (restart rejected, e.g.
    /// bad erase code / access denied), leave the live child alone.
    ///
    /// Polls at a short interval up to `timeout` to give the secure DUT
    /// time to finish its ~30 ms restart drain before exiting.
    ///
    /// Why: the secure DUT's restart handler holds the process open for
    /// ~30 ms after `A_Restart` so the async LL task can flush the
    /// response. During that window the still-live stack keeps
    /// processing incoming frames, which breaks restart-followed-by-
    /// reconnect tests (L-2.2.6, R-2.2.7, 6.3.1.2) — the DUT reuses the
    /// pre-restart TL connection slot with stale sequence numbers.
    /// Waiting here for the child to actually exit before the next
    /// inject forces those tests to see a clean TL.
    async fn settle_pending_restart(&mut self) {
        if !self.restart_pending {
            return;
        }

        // Non-blocking single probe. If the DUT has already exited
        // (accepted restart + finished drain), respawn now. If it's
        // still alive — either mid-drain or rejected the restart — do
        // nothing. Blocking here would hold back the next T_ACK the
        // test needs to send, causing DUT-side retransmissions that
        // reorder the frames the test expects. We leave the flag set
        // so subsequent `send_command` calls re-check: eventually,
        // for accepted restarts the DUT exits and we swap it out.
        let exited = match &mut self.child {
            ChildState::Running { child, .. } => matches!(child.try_wait(), Ok(Some(_))),
            ChildState::Dead => true,
        };
        if !exited {
            return;
        }

        self.restart_pending = false;
        self.mark_dead();
        if let Err(e) = self.spawn_child().await {
            log::warn!("Failed to respawn DUT after restart drain: {}", e);
            return;
        }
        // Drain ROI (read-on-init) frames the fresh DUT emits. Without
        // this, the test's next `expect(...)` may mismatch against a
        // stray ROI. Mirrors the broken-pipe respawn path in
        // `send_command`.
        let mut drained = 0;
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(100)).await;
            let batch = self.drain_captured();
            drained += batch;
            if batch == 0 {
                break;
            }
        }
        if drained > 0 {
            log::info!("Drained {} ROI messages after restart respawn", drained);
        }
    }

    /// Receive a captured outgoing telegram from the DUT.
    ///
    /// Log frames received while waiting are forwarded to the parent's
    /// logger. Returns `None` if the child exited (restart or crash).
    pub async fn receive_captured(&mut self) -> Option<CapturedLinkLayerMessage> {
        loop {
            let socket = match self.socket() {
                Ok(s) => s,
                Err(_) => return None,
            };

            match ipc::read_frame_async(socket).await {
                Ok(Some(frame)) if frame.tag == TAG_CAPTURED => {
                    // Payload: service_type (1 byte) + TP1 data
                    if frame.payload.is_empty() {
                        log::warn!("Captured frame has empty payload");
                        return None;
                    }
                    let service_type = ServiceType::from(frame.payload[0]);
                    let data = frame.payload[1..].to_vec();
                    return Some(CapturedLinkLayerMessage { service_type, data });
                }
                Ok(Some(frame)) if frame.tag == TAG_LOG => {
                    handle_log_frame(&frame.payload);
                }
                Ok(Some(frame)) => {
                    log::warn!("Expected captured frame, got tag 0x{:02x}", frame.tag);
                    return None;
                }
                Ok(None) => {
                    // EOF — child exited (restart)
                    log::info!("Child exited (detected via EOF)");
                    self.mark_dead();
                    return None;
                }
                Err(e) => {
                    log::error!("Socket read error: {}", e);
                    self.mark_dead();
                    return None;
                }
            }
        }
    }

    /// Non-blocking drain of pending captured messages.
    ///
    /// Log frames encountered during the drain are forwarded to the parent's
    /// logger. Returns the number of captured messages drained.
    pub fn drain_captured(&mut self) -> usize {
        let socket = match &self.child {
            ChildState::Running { socket, .. } => socket,
            ChildState::Dead => return 0,
        };

        let mut count = 0;

        loop {
            // Try a non-blocking read
            let mut header = [0u8; 3];
            match socket.get_ref().read_exact(&mut header) {
                Ok(()) => {
                    let tag = header[0];
                    let len = u16::from_le_bytes([header[1], header[2]]) as usize;
                    if len > 0 {
                        let mut buf = vec![0u8; len];
                        if socket.get_ref().read_exact(&mut buf).is_err() {
                            break;
                        }
                        if tag == TAG_LOG {
                            handle_log_frame(&buf);
                        }
                    }
                    if tag == TAG_CAPTURED {
                        count += 1;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        if count > 0 {
            log::debug!("Drained {} captured messages", count);
        }
        count
    }

    /// Set programming mode on the DUT.
    pub async fn set_programming_mode(&mut self, enabled: bool) -> io::Result<()> {
        self.send_command(TAG_SET_PROGRAMMING_MODE, &[enabled as u8]).await
    }

    /// Trigger a GroupValue_Read on the DUT for the given ASAP.
    pub async fn trigger_read(&mut self, asap: u16) -> io::Result<()> {
        self.send_command(TAG_TRIGGER_READ, &asap.to_le_bytes()).await
    }

    /// Trigger a GroupValue_Write on the DUT for the given ASAP.
    pub async fn trigger_write(&mut self, asap: u16) -> io::Result<()> {
        self.send_command(TAG_TRIGGER_WRITE, &asap.to_le_bytes()).await
    }

    /// Trigger an S-A_Sync_Req from the DUT to the specified peer.
    pub async fn trigger_sync(&mut self, peer_ia: u16, tool_access: bool, is_broadcast: bool) -> io::Result<()> {
        let ia_bytes = peer_ia.to_be_bytes();
        self.send_command(TAG_TRIGGER_SYNC, &[ia_bytes[0], ia_bytes[1], tool_access as u8, is_broadcast as u8]).await
    }

    /// Simulate a power cycle: tell the child to flush its current state
    /// into the shared memory region and exit, then wait for it to exit
    /// and respawn it.
    ///
    /// Unlike an `A_Restart` triggered via bus injection, this does not
    /// consume an application-layer service nor emit a restart response
    /// on the bus. Persisted state (Security IO properties, sequence
    /// numbers, loaded tables) survives; volatile state (transport
    /// connections, programming-mode flag, CO statuses) is reset when
    /// the new child starts.
    pub async fn power_cycle(&mut self, timeout: embassy_time::Duration) -> io::Result<()> {
        self.send_command(TAG_POWER_CYCLE, &[]).await?;
        self.wait_for_restart(timeout).await?;
        self.drain_roi_after_respawn().await;
        Ok(())
    }

    /// Simulate a master reset: tell the child to apply the given
    /// `EraseCode` (by raw byte), flush the updated state, and exit,
    /// then wait for it to exit and respawn.
    ///
    /// `erase_code` uses the same numeric encoding as the bus-level
    /// `A_Restart` service (0x03 = FactoryReset, 0x08 = FactoryResetKeepIA,
    /// etc.). See `TAG_MASTER_RESET` for the full mapping.
    pub async fn master_reset(
        &mut self,
        erase_code: u8,
        timeout: embassy_time::Duration,
    ) -> io::Result<()> {
        self.send_command(TAG_MASTER_RESET, &[erase_code]).await?;
        self.wait_for_restart(timeout).await?;
        self.drain_roi_after_respawn().await;
        Ok(())
    }

    /// Drain any Read-On-Init (or other post-startup) captured frames
    /// emitted by a freshly-respawned child. Matches the implicit drain
    /// inside `send_command()` so tests don't see stale ROI frames
    /// interleaved with their expected responses.
    async fn drain_roi_after_respawn(&mut self) {
        let mut drained = 0;
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(100)).await;
            let batch = self.drain_captured();
            drained += batch;
            if batch == 0 {
                break;
            }
        }
        if drained > 0 {
            log::info!("Drained {} ROI messages after power-cycle/master-reset", drained);
        }
    }

    /// Wait for the child to exit (restart) and respawn it.
    ///
    /// Reads frames until EOF (forwarding log and captured frames), then
    /// respawns. Unlike `send_command()`'s implicit respawn, this does NOT
    /// drain captured messages — ROI reads and other post-startup messages
    /// remain available for subsequent `receive_captured()` calls.
    pub async fn wait_for_restart(&mut self, timeout: embassy_time::Duration) -> io::Result<()> {
        let socket = self.socket()?;

        // Read frames until EOF or timeout. Any TAG_CAPTURED or TAG_LOG
        // frames that arrive before the child exits are still forwarded.
        let drain_result = embassy_futures::select::select(
            async {
                loop {
                    match ipc::read_frame_async(socket).await {
                        Ok(Some(frame)) if frame.tag == TAG_LOG => {
                            handle_log_frame(&frame.payload);
                        }
                        Ok(Some(frame)) if frame.tag == TAG_CAPTURED => {
                            // The child sent a captured frame before exiting
                            // (e.g., A_Restart_Response). Discard it — the
                            // test should have already expected it.
                            log::debug!("Discarding pre-exit captured frame");
                        }
                        Ok(Some(_)) => {
                            // Ignore other frames while draining
                        }
                        Ok(None) => {
                            // EOF — child exited
                            return Ok(());
                        }
                        Err(e) => return Err(e),
                    }
                }
            },
            embassy_time::Timer::after(timeout),
        )
        .await;

        match drain_result {
            embassy_futures::select::Either::First(result) => result?,
            embassy_futures::select::Either::Second(_) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "child did not exit within timeout"));
            }
        }

        self.mark_dead();
        self.spawn_child().await?;

        // Intentionally do NOT drain ROI messages. The TestStep
        // doc-comment for `WaitForRestart` promises that ROI frames
        // stay in the capture queue so tests (e.g. 1.4.1.6) can
        // observe Read-On-Init scans after an A_Restart. Tests that
        // don't want the ROI frames can drop them with an explicit
        // `drain(ms)` step.
        Ok(())
    }

    /// Send a command frame, respawning the child on broken pipe.
    async fn send_command(&mut self, tag: u8, payload: &[u8]) -> io::Result<()> {
        // If the previous inject was an `A_Restart`, wait for the DUT
        // to finish its restart handler and exit before sending this
        // command. Otherwise, on the secure DUT, a T_Connect sent
        // immediately after the restart lands on the still-alive stack
        // during its 30 ms drain window and reuses the stale TL slot.
        // 60 ms is twice the secure-DUT drain window plus a small
        // margin; on timeout we fall through (no restart was pending
        // after all, or the DUT hung — next write will error out
        // normally).
        self.settle_pending_restart().await;

        self.ensure_child_running().await?;
        let socket = self.socket()?;
        match ipc::write_frame_async(socket, tag, payload).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                log::info!("Command 0x{:02x}: child exited (broken pipe), respawning", tag);
                self.mark_dead();
                self.spawn_child().await?;

                // After respawn, the new child may send read-on-init (ROI)
                // messages. Drain in a loop until no new messages arrive
                // within a settle window, so they don't interfere with the
                // test's expected responses.
                let mut drained = 0;
                loop {
                    embassy_time::Timer::after(embassy_time::Duration::from_millis(100)).await;
                    let batch = self.drain_captured();
                    drained += batch;
                    if batch == 0 {
                        break;
                    }
                }
                if drained > 0 {
                    log::info!("Drained {} ROI messages after respawn", drained);
                }

                let socket = self.socket()?;
                ipc::write_frame_async(socket, tag, payload).await
            }
            Err(e) => Err(e),
        }
    }

    /// Check if the child is currently running.
    pub fn is_child_running(&self) -> bool {
        matches!(self.child, ChildState::Running { .. })
    }
}

impl Drop for MultiProcessHarness {
    fn drop(&mut self) {
        // Kill the child if still running. Dropping the socket will close
        // our end of the socketpair, causing the child to see EOF and exit.
        // We also explicitly kill to handle cases where the child is blocked.
        if let ChildState::Running { ref mut child, .. } = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

use std::io::Read;
use std::time::Instant;

/// Elapsed time since the harness started, for log timestamps.
static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn elapsed_ms() -> u64 {
    START_TIME.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Parse a TAG_LOG payload and feed the entry into the parent's logger.
///
/// Payload format: `[level: u8] [target \0] [message bytes]`
fn handle_log_frame(payload: &[u8]) {
    if payload.is_empty() {
        return;
    }

    let level = match payload[0] {
        1 => log::Level::Error,
        2 => log::Level::Warn,
        3 => log::Level::Info,
        4 => log::Level::Debug,
        _ => log::Level::Trace,
    };

    // Find NUL separator between target and message
    let rest = &payload[1..];
    let (target, message) = if let Some(nul_pos) = rest.iter().position(|&b| b == 0) {
        let target = String::from_utf8_lossy(&rest[..nul_pos]).into_owned();
        let message = String::from_utf8_lossy(&rest[nul_pos + 1..]).into_owned();
        (target, message)
    } else {
        // No NUL separator — treat entire rest as message
        (String::from("dut"), String::from_utf8_lossy(rest).into_owned())
    };

    logger::add_entry(LogEntry { level, target, message, timestamp_ms: elapsed_ms() });
}

fn clear_cloexec(fd: std::os::unix::io::RawFd) -> io::Result<()> {
    use nix::fcntl;
    let flags = fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFD).map_err(io::Error::other)?;
    let mut fd_flags = nix::fcntl::FdFlag::from_bits_truncate(flags);
    fd_flags.remove(nix::fcntl::FdFlag::FD_CLOEXEC);
    fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFD(fd_flags)).map_err(io::Error::other)?;
    Ok(())
}

/// Decide whether a TP1-wire inject carries `A_Restart`.
///
/// The runner keeps this in the harness layer so restart-triggered
/// test flows don't need to explicitly signal "DUT is about to die"
/// — the harness detects it from the frame itself. Handles both
/// standard and extended TP1 frames via `tp1_to_knx_message_no_checksum`.
fn injection_is_restart(tp1_data: &[u8]) -> bool {
    use zweidraehte_proto::encoding::tp1;
    use zweidraehte_proto::messages::knx::{ApciCode, decode_apci_code};
    // `tp1_to_knx_message_no_checksum` works on a buffer it owns and
    // doesn't return the length. We clone the data, run the conversion,
    // and decode from the result.
    let mut buf = tp1_data.to_vec();
    buf = tp1::tp1_to_knx_message_no_checksum(buf);
    decode_apci_code(&buf) == Some(ApciCode::Restart)
}
