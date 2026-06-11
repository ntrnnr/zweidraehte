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

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use serde::Serialize;
use serde::de::DeserializeOwned;

use zweidraehte_device::bcus::system_b::{ExtensionState, SystemBDeviceState};
use zweidraehte_device::{Stack, StackDefinition, restart::EraseCode};

use crate::harness::framing;
use crate::harness::ipc::IpcCommand;
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

// ============================================================================
// Lifecycle-event → IPC signal bridge
// ============================================================================
//
// The device stack publishes `LifecycleEvent::ReadOnInitComplete` on its
// public pub/sub channel when the AL's read-on-init scan settles. The IPC
// link layer waits on a local signal (`harness::ipc::ROI_DONE`) before
// it sends `RoiComplete` to the runner. This task bridges the two — it
// subscribes to the stack's lifecycle events and fires the IPC signal
// when `ReadOnInitComplete` arrives.
//
// We use the public subscriber API instead of a library-side hook so the
// device crate stays free of conformance-specific signalling.

/// Embassy task that forwards `LifecycleEvent::ReadOnInitComplete` from
/// the stack's public lifecycle channel to the IPC link layer's local
/// `ROI_DONE` signal.
///
/// The subscriber must be created with `'static` lifetime (both DUT
/// binaries own their `StackResources` in a `StaticCell`), which
/// callers typically achieve with a small `core::mem::transmute` after
/// `stack.lifecycle_events()`.
#[embassy_executor::task]
pub async fn bridge_lifecycle_to_ipc(
    mut events: embassy_sync::pubsub::DynSubscriber<'static, zweidraehte_device::lifecycle::LifecycleEvent>,
) {
    use embassy_sync::pubsub::WaitResult;
    use zweidraehte_device::lifecycle::LifecycleEvent;
    loop {
        match events.next_message().await {
            WaitResult::Message(LifecycleEvent::ReadOnInitComplete) => {
                crate::harness::ipc::signal_roi_done();
            }
            WaitResult::Message(_) => {
                // Other variants are not consumed by the harness today.
            }
            WaitResult::Lagged(n) => {
                log::warn!("DUT lifecycle bridge lagged by {n} messages");
            }
        }
    }
}

// ============================================================================
// ConformanceStack trait — dedupe logic between plain and secure DUT binaries
// ============================================================================
//
// The two DUT entry-points (`conformance-dut`, `conformance-dut-secure`) used
// to carry ~200 LoC of identical task bodies. They now delegate to the
// generic helpers below (`handle_ipc_command`, `handle_restart_request`),
// specialised via `<S as ConformanceStack>`. Each binary still owns its
// `StaticCell`s (embassy tasks and `StackResources` both need monomorphic
// names), but the command/restart tasks shrink to a handful of lines.

/// Stack-specific glue each conformance DUT binary must supply.
///
/// This trait bundles the two places the plain and secure DUTs genuinely
/// differ:
///
/// * the serialisable snapshot type for shared-memory persistence, and
/// * how to apply an [`EraseCode`] to the state's inner (`Tp1SystemBDeviceState`
///   variant) — the method set is identical, but the concrete inner type
///   differs, so the dispatch can't be written generically against the outer
///   `State` type alone.
pub trait ConformanceStack: StackDefinition + 'static {
    /// The `Serialize + DeserializeOwned` snapshot type persisted in shared
    /// memory across restarts.
    type DeviceConfig: Serialize + DeserializeOwned;

    /// Project the current state to a snapshot suitable for `flush_state`.
    fn to_device_config(state: &Self::State) -> Self::DeviceConfig;

    /// Apply an erase code against the inner device state.
    ///
    /// Both plain (`Tp1SystemBDeviceState`) and secure (`SecureTp1DeviceState`)
    /// variants expose the same reset methods. Implementations should usually
    /// just delegate to [`apply_erase_code_to_system_b`] with their inner
    /// state reference.
    fn apply_erase_code(state: &Self::State, code: EraseCode);
}

/// Shared `EraseCode` → reset-method dispatch for any `SystemBDeviceState<...>`.
///
/// Both conformance DUTs wrap a different `SystemBDeviceState` instantiation
/// (plain TP1 vs Data-Secure TP1). The concrete inner types differ only in
/// their `ExtensionState` parameter; `SystemBDeviceState::apply_erase_code`
/// is the canonical dispatch for both (including the `ResetLinks` →
/// `extension_state.on_erase` notification the security extension needs).
pub fn apply_erase_code_to_system_b<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D: StackDefinition,
    ES: ExtensionState,
>(
    inner: &SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>,
    code: EraseCode,
) {
    if matches!(code, EraseCode::Other(_)) {
        log::warn!("apply_erase_code: unsupported {:?}", code);
    }
    inner.apply_erase_code(code);
}

/// Handle one [`IpcCommand`] dispatched by the link layer.
///
/// Runs the command against `stack` (read/write trigger, programming mode,
/// sync-request, or lifecycle termination). For power-cycle / master-reset
/// the function does not return — it falls through to `exit_with_reason`.
pub async fn handle_ipc_command<S: ConformanceStack>(stack: Stack<'static, S>, shm: &'static ShmCell, cmd: IpcCommand) {
    use crate::harness::protocol::RunnerMessage;
    match cmd {
        RunnerMessage::Inject { seq, .. } => {
            // `Inject` is processed inline by the IPC link layer —
            // it should never reach the command handler. Log loudly
            // if the invariant breaks so we notice during any future
            // plumbing change instead of silently stalling.
            log::error!("handle_ipc_command: unexpected Inject(seq={}) on the command channel", seq);
        }
        RunnerMessage::SetProgrammingMode { enabled, .. } => {
            log::info!("CMD: SetProgrammingMode({})", enabled);
            use zweidraehte_device::objects::interface::HasDeviceObject;
            stack.interface_objects().set_programming_mode_enabled(enabled);
        }
        RunnerMessage::TriggerRead { asap, .. } => {
            log::info!("CMD: TriggerRead(ASAP {})", asap);
            let _ = stack.read_object_by_asap(asap).await;
        }
        RunnerMessage::TriggerWrite { asap, .. } => {
            log::info!("CMD: TriggerWrite(ASAP {})", asap);
            let _ = stack.write_object_by_asap(asap).await;
        }
        RunnerMessage::TriggerSync { peer_ia, tool_access, is_broadcast, .. } => {
            log::info!("CMD: TriggerSync(peer={:#06X}, tool={}, broadcast={})", peer_ia, tool_access, is_broadcast);
            // Plain stacks reply `SyncFailed` synchronously (see
            // `ApplicationLayer::handle_service`) rather than panicking, so
            // we can dispatch unconditionally and rely on the app layer to
            // fall through for non-secure builds.
            let _ = stack.initiate_sync(peer_ia, tool_access, is_broadcast).await;
        }
        RunnerMessage::PowerCycle => {
            log::info!("CMD: PowerCycle — flush + exit");
            flush_and_exit::<S>(stack, shm, None, ExitReason::PowerCycle).await;
        }
        RunnerMessage::MasterReset { erase_code } => {
            log::info!("CMD: MasterReset(erase_code=0x{:02x})", erase_code);
            let code = EraseCode::from(erase_code);
            flush_and_exit::<S>(stack, shm, Some(code), ExitReason::MasterReset { erase_code }).await;
        }
    }
}

/// Handle one `A_Restart` request delivered by the stack.
///
/// The application layer already pushed the `A_Restart_Response` to the
/// outbox before this returns, but it hasn't traversed the router yet.
/// If we mutate inner state right away — e.g. `FactoryReset` wipes the
/// individual address — the response picks up `src = FF FF` on its way
/// out. Wait for the outbox to drain via
/// [`Stack::await_outbox_drained`] before applying the erase code and
/// flushing state.
pub async fn handle_restart_request<S: ConformanceStack>(
    stack: Stack<'static, S>,
    shm: &'static ShmCell,
    erase_code: EraseCode,
) {
    if matches!(erase_code, EraseCode::Other(_)) {
        return;
    }

    stack.await_outbox_drained().await;

    let reason = ExitReason::Restart { erase_code: u8::from(erase_code) };
    flush_and_exit::<S>(stack, shm, Some(erase_code), reason).await;
}

async fn flush_and_exit<S: ConformanceStack>(
    stack: Stack<'static, S>,
    shm: &'static ShmCell,
    erase: Option<EraseCode>,
    reason: ExitReason,
) -> ! {
    let state = stack.state();
    if let Some(code) = erase {
        S::apply_erase_code(state, code);
    }
    let snapshot = S::to_device_config(state);
    flush_state(shm, &snapshot);
    exit_with_reason(reason).await
}

// `Channel` re-export for binaries — saves each bin importing both
// embassy_sync paths and keeps the dependency surface small.
pub type CommandChannel = Channel<NoopRawMutex, IpcCommand, 8>;
