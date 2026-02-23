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
    self, SharedMemory,
    TAG_CAPTURED, TAG_INJECT, TAG_LOG, TAG_READY, TAG_SET_PROGRAMMING_MODE,
    TAG_TRIGGER_READ, TAG_TRIGGER_WRITE,
};
use super::mock::CapturedLinkLayerMessage;
use super::stack::{ConformanceMemoryMap, ConformanceState, TestParameters, conformance_config};

use crate::logger::{self, LogEntry};
use zweidraehte::messages::knx::ServiceType;
use zweidraehte::objects::tables::{Application, HasLoadStateMachine, LoadEvent};

// ============================================================================
// Child State
// ============================================================================

enum ChildState {
    /// Child process is running.
    Running {
        child: Child,
        socket: Async<UnixStream>,
    },
    /// Child has exited (restart, crash, or not yet started).
    Dead,
}

// ============================================================================
// Multi-Process Harness
// ============================================================================

/// Multi-process conformance test harness.
///
/// The parent creates shared memory, initializes device state, and spawns
/// a child process running the DUT stack. Test steps communicate with the
/// child over a Unix socket.
pub struct MultiProcessHarness {
    shm: SharedMemory,
    child: ChildState,
}

impl MultiProcessHarness {
    /// Create a new harness with initialized shared memory.
    ///
    /// This sets up the shared memory with the default conformance test
    /// device state (address 1.0.1, loaded tables, running application)
    /// but does NOT spawn the child yet. Call `ensure_child_running()`
    /// or `spawn_child()` to start the DUT.
    pub fn new() -> io::Result<Self> {
        let mut shm = SharedMemory::create()?;

        // Build the default conformance test state and serialize it into
        // shared memory using postcard. This creates the same state as
        // ConformanceState::new() but in serialized form.
        let (addr_tab, asso_tab, co_tab) = conformance_config::ConformanceTestConfig::create_tables(
            ConformanceMemoryMap::ADT_BASE as u32,
            ConformanceMemoryMap::AST_BASE as u32,
            ConformanceMemoryMap::COT_BASE as u32,
        );

        let mut app_table = Application::<TestParameters>::new();
        app_table.write_lsm(&[LoadEvent::StartLoading.into()], None);
        app_table.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        // Build the runtime state, then snapshot it for shared memory.
        let state = ConformanceState::new(addr_tab, asso_tab, co_tab, app_table);
        let snapshot = state.to_persisted_snapshot();
        shm.write_state(&snapshot)?;

        Ok(Self { shm, child: ChildState::Dead })
    }

    /// Spawn the child process (conformance-dut).
    ///
    /// Creates a Unix socketpair, clears CLOEXEC on the shared memory fd,
    /// and spawns the child with `--shm-fd` and `--socket-fd` arguments.
    pub async fn spawn_child(&mut self) -> io::Result<()> {
        let (parent_stream, child_stream) = UnixStream::pair()?;
        parent_stream.set_nonblocking(true)?;

        // The child needs to inherit the shm fd and its socket fd.
        // Clear CLOEXEC on both so they survive exec.
        self.shm.clear_cloexec()?;

        let child_fd = child_stream.as_raw_fd();
        clear_cloexec(child_fd)?;

        let shm_fd_str = self.shm.fd().to_string();
        let sock_fd_str = child_fd.to_string();

        // Find the conformance-dut binary next to the runner binary.
        let dut_path = std::env::current_exe()
            .map(|p| p.with_file_name("conformance-dut"))
            .unwrap_or_else(|_| "conformance-dut".into());

        let child = Command::new(&dut_path)
            .arg("--shm-fd")
            .arg(&shm_fd_str)
            .arg("--socket-fd")
            .arg(&sock_fd_str)
            .spawn()
            .map_err(|e| {
                io::Error::new(e.kind(), format!("failed to spawn {}: {}", dut_path.display(), e))
            })?;

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
    pub async fn inject(&mut self, data: &[u8]) -> io::Result<()> {
        self.send_command(TAG_INJECT, data).await
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

    /// Send a command frame, respawning the child on broken pipe.
    async fn send_command(&mut self, tag: u8, payload: &[u8]) -> io::Result<()> {
        self.ensure_child_running().await?;
        let socket = self.socket()?;
        match ipc::write_frame_async(socket, tag, payload).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                log::info!("Command 0x{:02x}: child exited (broken pipe), respawning", tag);
                self.mark_dead();
                self.spawn_child().await?;

                // After respawn, the new child may send read-on-init (ROI)
                // messages. Wait for them to arrive and drain them so they
                // don't interfere with the test's expected responses.
                embassy_time::Timer::after(embassy_time::Duration::from_millis(100)).await;
                let drained = self.drain_captured();
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

    logger::add_entry(LogEntry {
        level,
        target,
        message,
        timestamp_ms: elapsed_ms(),
    });
}

fn clear_cloexec(fd: std::os::unix::io::RawFd) -> io::Result<()> {
    use nix::fcntl;
    let flags = fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFD)
        .map_err(|e| io::Error::other(e))?;
    let mut fd_flags = nix::fcntl::FdFlag::from_bits_truncate(flags);
    fd_flags.remove(nix::fcntl::FdFlag::FD_CLOEXEC);
    fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFD(fd_flags))
        .map_err(|e| io::Error::other(e))?;
    Ok(())
}
