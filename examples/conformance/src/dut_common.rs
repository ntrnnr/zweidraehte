//! Shared plumbing for both DUT binaries (`conformance-dut`,
//! `conformance-dut-secure`).
//!
//! The two DUT processes differ only in the stack type they build
//! (plain vs. Data-Secure). Everything else — command-line parsing,
//! IPC-forwarding logger, erase-code dispatch, final state flush +
//! exit — is identical and lives here.
//!
//! # Restart / power-cycle semantics
//!
//! Unlike the legacy DUT code, this module does **not** sleep before
//! exit. The new IPC protocol guarantees that when a
//! [`RunnerMessage`](crate::harness::protocol::RunnerMessage) triggers
//! an `A_Restart` / `PowerCycle` / `MasterReset`, the runner has
//! already received the corresponding
//! [`StepComplete`](crate::harness::protocol::DutMessage) carrying
//! every outbox frame (restart-response included) before the command
//! handler is scheduled. So by the time we reach
//! [`apply_erase_code`] / [`flush_state`], there is nothing left to
//! drain — we just write `Exiting`, `shutdown(SHUT_WR)` + `exit(0)`.

use std::cell::UnsafeCell;
use std::os::unix::io::RawFd;
use std::sync::{Mutex, OnceLock};

use crate::harness::framing;
use crate::harness::protocol::{DutMessage, ExitReason};

// ============================================================================
// Command-line parsing
// ============================================================================

/// Parse `--shm-fd <N> --socket-fd <M>` from the DUT process argv.
///
/// Both arguments are required; errors print a usage line to stderr
/// and call `exit(1)`.
pub fn parse_args(binary_name: &str) -> (RawFd, RawFd) {
    let args: Vec<String> = std::env::args().collect();
    let mut shm_fd = None;
    let mut socket_fd = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--shm-fd" => {
                i += 1;
                shm_fd = Some(args[i].parse::<RawFd>().expect("invalid --shm-fd value"));
            }
            "--socket-fd" => {
                i += 1;
                socket_fd = Some(args[i].parse::<RawFd>().expect("invalid --socket-fd value"));
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let Some(shm_fd) = shm_fd else {
        eprintln!("Usage: {} --shm-fd <N> --socket-fd <M>", binary_name);
        std::process::exit(1);
    };
    let Some(socket_fd) = socket_fd else {
        eprintln!("Usage: {} --shm-fd <N> --socket-fd <M>", binary_name);
        std::process::exit(1);
    };
    (shm_fd, socket_fd)
}

// ============================================================================
// IPC logger
// ============================================================================
//
// `log::*` can fire from any context (including blocking sync code
// deep in the stack), so the logger uses a blocking write on its own
// dup'd fd instead of going through the async link layer. The logger
// encodes each record as a postcard `DutMessage::Log`.

/// Blocking writer handle for the DUT's IPC logger.
///
/// Shares the same socket fd as the async link layer's primary
/// socket (via `dup`). Frames written through this handle use
/// [`framing::write_frame_blocking`], which concatenates the header
/// and payload into a single buffer so one kernel `write()` covers
/// the whole frame. On a Unix socketpair with < PIPE_BUF (4 KiB) and
/// ample send-buffer space, that single write is atomic — log
/// entries can't interleave bytes into a postcard frame the async
/// link layer is midway through sending.
static LOG_SOCKET: OnceLock<Mutex<std::os::unix::net::UnixStream>> = OnceLock::new();

struct IpcLogger {
    level: log::LevelFilter,
}

impl log::Log for IpcLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let Some(socket_mutex) = LOG_SOCKET.get() else { return };
        let Ok(mut socket) = socket_mutex.lock() else { return };

        let msg = DutMessage::Log {
            level: record.level() as u8,
            target: record.target().to_string(),
            message: format!("{}", record.args()),
        };
        // Best-effort — parent may have closed its end during
        // shutdown. Silently drop on error.
        let _ = framing::write_msg_blocking(&mut socket, &msg);
    }

    fn flush(&self) {}
}

/// Initialize the IPC-forwarding logger. Call exactly once, after
/// registering the primary socket fd with
/// [`crate::harness::ipc::set_primary_socket_fd`].
pub fn init_ipc_logger(socket_fd: RawFd, level: log::LevelFilter) {
    use std::os::unix::io::FromRawFd;
    // Dup the fd so the logger has its own handle that it can write
    // to without racing with the async link layer. The dup shares the
    // kernel-side send buffer with the original.
    let dup_fd = nix::unistd::dup(socket_fd).expect("dup socket fd for logger");
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(dup_fd) };
    LOG_SOCKET.set(Mutex::new(stream)).ok();
    log::set_boxed_logger(Box::new(IpcLogger { level })).expect("set logger");
    log::set_max_level(level);
}

/// Pick the log level from the `RUST_LOG` env var, defaulting to
/// `Debug` when unset or unrecognised.
pub fn log_level_from_env() -> log::LevelFilter {
    match std::env::var("RUST_LOG").ok().as_deref() {
        Some("error") => log::LevelFilter::Error,
        Some("warn") => log::LevelFilter::Warn,
        Some("info") => log::LevelFilter::Info,
        Some("debug") => log::LevelFilter::Debug,
        Some("trace") => log::LevelFilter::Trace,
        _ => log::LevelFilter::Debug,
    }
}

// ============================================================================
// Shared memory handle wrapper
// ============================================================================
//
// The shared-memory handle is stored in a static `ShmCell` so the
// async command handler can grab a mutable reference at exit time.
// Safety: the embassy executor is single-threaded, so there is never
// concurrent access.

pub struct ShmCell(pub UnsafeCell<crate::harness::shm::SharedMemory>);

// SAFETY: Single-threaded embassy executor — no cross-thread access.
unsafe impl Sync for ShmCell {}

impl ShmCell {
    pub fn new(shm: crate::harness::shm::SharedMemory) -> Self {
        Self(UnsafeCell::new(shm))
    }

    /// SAFETY: single-threaded executor — caller must not hold a
    /// reference across an await that also reaches this code path.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get(&self) -> &mut crate::harness::shm::SharedMemory {
        unsafe { &mut *self.0.get() }
    }
}

// ============================================================================
// State flush to shared memory
// ============================================================================

/// Flush a postcard-serializable state snapshot to the shared memory
/// region. Called from the exit paths (restart / power-cycle /
/// master-reset); failures are logged and swallowed — there's no
/// caller left to propagate to.
pub fn flush_state<T: serde::Serialize>(shm: &ShmCell, snapshot: &T) {
    // SAFETY: single-threaded executor.
    let shm_mut = unsafe { shm.get() };
    if let Err(e) = shm_mut.write_state(snapshot) {
        log::error!("flush_state: write_state failed: {}", e);
    }
}

/// Final exit sequence shared by all lifecycle-terminating paths.
///
/// 1. Mark a pending exit so the IpcLinkLayer cuts any in-progress
///    drain short and flushes its `StepComplete` immediately.
/// 2. Await until the barrier signals "step settled" (or a safety
///    timeout fires).
/// 3. Write `DutMessage::Exiting { reason }` via a blocking dup of
///    the primary socket.
/// 4. `shutdown(SHUT_WR)` so the kernel delivers EOF after all
///    buffered writes drain.
/// 5. `process::exit(0)`.
///
/// Does not return.
pub async fn exit_with_reason(reason: ExitReason) -> ! {
    crate::harness::ipc::emit_exiting_and_shutdown(reason).await;
    std::process::exit(0);
}
