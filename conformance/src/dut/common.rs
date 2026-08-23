//! Shared plumbing for both DUT binaries (`conformance-dut-systemb`,
//! `conformance-dut-systemb-secure`).
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
//! [`RunnerMessage`](crate::ipc::protocol::RunnerMessage) triggers
//! an `A_Restart` / `PowerCycle` / `MasterReset`, the runner has
//! already received the corresponding
//! [`StepComplete`](crate::ipc::protocol::DutMessage) carrying
//! every outbox frame (restart-response included) before the command
//! handler is scheduled. So by the time we reach
//! [`apply_erase_code`] / [`flush_state`], there is nothing left to
//! drain — we just write `Exiting`, `shutdown(SHUT_WR)` + `exit(0)`.

use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::os::unix::io::RawFd;
use std::sync::Mutex;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use serde::Serialize;
use serde::de::DeserializeOwned;

use zweidraehte_device::bcus::system_b::{ExtensionState, SystemBDeviceState};
use zweidraehte_device::storage::{HasConfigStore, StorageHooks};
use zweidraehte_device::{Stack, StackDefinition, SyncOptions, restart::EraseCode};

use crate::dut::link::IpcCommand;
use crate::ipc::protocol::{DutMessage, ExitReason};
use crate::ipc::shm::SharedMemory;

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
// `log::*` can fire from any context — including synchronous code deep
// inside the stack, from whichever task happens to be running. So the logger
// does not write to the socket at all: it *enqueues*, and whichever code
// owns the socket drains the queue before its next protocol frame.
//
// The obvious design — a dup'd fd and one blocking write per record — is
// what this replaces, and it was wrong in a way that took two stalled
// conformance runs to pin down. Its comment argued that a single `write()`
// below `PIPE_BUF` is atomic, which is true, and concluded that a log record
// therefore cannot land inside a protocol frame, which does not follow:
// `framing::write_frame_async` awaits `writable()` *between partial writes*,
// so the async link layer is routinely suspended midway through a frame.
// A log record written from another task at that moment splits it, and the
// parent's length-prefixed decoder never recovers — it either decodes
// garbage or waits forever for a `StepComplete` it can no longer parse.
//
// Enqueuing removes the race by construction rather than narrowing it:
// there is exactly one writer, and the logger performs no I/O and never
// yields.

/// Records waiting for the socket owner to flush them.
///
/// Bounded so a runaway log loop cannot exhaust memory; overflow drops the
/// *oldest* record, because the newest are the ones describing whatever is
/// going wrong right now.
static LOG_QUEUE: Mutex<VecDeque<DutMessage>> = Mutex::new(VecDeque::new());

/// How many records the queue holds before it starts dropping.
const LOG_QUEUE_CAPACITY: usize = 512;

/// Records dropped since the last drain, reported once when it resumes so a
/// gap in the transcript is never silent.
static LOG_DROPPED: Mutex<usize> = Mutex::new(0);

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
        let msg = DutMessage::Log {
            level: record.level() as u8,
            target: record.target().to_string(),
            message: format!("{}", record.args()),
        };
        let Ok(mut queue) = LOG_QUEUE.lock() else { return };
        if queue.len() >= LOG_QUEUE_CAPACITY {
            queue.pop_front();
            if let Ok(mut dropped) = LOG_DROPPED.lock() {
                *dropped += 1;
            }
        }
        queue.push_back(msg);
    }

    fn flush(&self) {}
}

/// Take everything the logger has queued, oldest first.
///
/// Call this immediately before writing a protocol frame — that keeps a
/// step's log records ahead of the `StepComplete` that ends it, so the
/// parent attributes them to the right step.
pub fn drain_logs() -> Vec<DutMessage> {
    let mut out = Vec::new();
    if let Ok(mut dropped) = LOG_DROPPED.lock()
        && *dropped > 0
    {
        out.push(DutMessage::Log {
            level: log::Level::Warn as u8,
            target: "dut::common".to_string(),
            message: format!("{} log records dropped: the DUT out-logged the drain", *dropped),
        });
        *dropped = 0;
    }
    if let Ok(mut queue) = LOG_QUEUE.lock() {
        out.extend(queue.drain(..));
    }
    out
}

/// Initialize the IPC-forwarding logger. Records are queued for the socket
/// owner to flush; see [`drain_logs`].
pub fn init_ipc_logger(level: log::LevelFilter) {
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
// Boot snapshot
// ============================================================================

/// Read the DUT's persisted state out of shared memory, seeding the
/// region with `factory` when the parent handed us a blank one.
///
/// The parent deliberately knows nothing about what a snapshot
/// contains. It creates a zeroed region, and for `TestStep::FullReset`
/// zeroes it again ([`SharedMemory::blank`]); deciding what "factory
/// defaults" means is the device's business, exactly as it is for real
/// firmware booting from erased flash. Keeping the knowledge on this
/// side is what lets the parent half of the crate compile without the
/// device stack at all — see the `dut` feature in `Cargo.toml`.
///
/// A seeded snapshot is written straight back rather than left for the
/// storage task: the parent may inspect or reuse the region after we
/// die, and a DUT that never reached a flush point would otherwise
/// leave it blank.
pub fn load_or_seed_snapshot<T>(shm: &mut SharedMemory, factory: fn() -> T) -> T
where
    T: Serialize + DeserializeOwned,
{
    load_or_seed_snapshot_with_status(shm, factory).0
}

/// Variant of [`load_or_seed_snapshot`] that reports whether this boot seeded
/// a blank region.
///
/// Most DUTs keep all factory state in their snapshot and do not care. A DUT
/// whose persistence is physically split can use the flag to seed its second
/// region at the same factory boundary without overwriting live state on an
/// ordinary power cycle.
pub fn load_or_seed_snapshot_with_status<T>(shm: &mut SharedMemory, factory: fn() -> T) -> (T, bool)
where
    T: Serialize + DeserializeOwned,
{
    if let Some(snapshot) = shm.read_state::<T>().expect("read shared memory") {
        return (snapshot, false);
    }
    let snapshot = factory();
    shm.write_state(&snapshot).expect("seed shared memory with the factory snapshot");
    (snapshot, true)
}

// ============================================================================
// Shared memory handle wrapper
// ============================================================================
//
// The shared-memory handle is stored in a static `ShmCell` so the
// async command handler can grab a mutable reference at exit time.
// Safety: the embassy executor is single-threaded, so there is never
// concurrent access.

pub struct ShmCell(pub UnsafeCell<SharedMemory>);

// SAFETY: Single-threaded embassy executor — no cross-thread access.
unsafe impl Sync for ShmCell {}

impl ShmCell {
    pub fn new(shm: SharedMemory) -> Self {
        Self(UnsafeCell::new(shm))
    }

    /// SAFETY: single-threaded executor — caller must not hold a
    /// reference across an await that also reaches this code path.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get(&self) -> &mut SharedMemory {
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
    crate::dut::link::emit_exiting_and_shutdown(reason).await;
    std::process::exit(0);
}

// ============================================================================
// Lifecycle-event → IPC signal bridge
// ============================================================================
//
// The device stack publishes `LifecycleEvent::ReadOnInitComplete` on its
// public pub/sub channel when the AL's read-on-init scan settles. The IPC
// link layer waits on a local signal (`dut::link::ROI_DONE`) before
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
                crate::dut::link::signal_roi_done();
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
// The two DUT entry-points (`conformance-dut-systemb`, `conformance-dut-systemb-secure`) used
// to carry ~200 LoC of identical task bodies. They now delegate to the
// generic helpers below (`handle_ipc_command`), specialised via
// `<S as ConformanceStack>`. Each binary still owns its
// `StaticCell`s (embassy tasks and `StackResources` both need monomorphic
// names), but the command task shrinks to a handful of lines.
//
// A_Restart is *not* handled here: the DUTs run the device stack's own
// `storage_task`, the same one every firmware target runs, so that its
// restart ordering is under test rather than a look-alike. See
// [`DutConfigStore`] and [`DutSystemControl`] for the two pieces that task
// needs from us.

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
pub trait ConformanceStack: StackDefinition<Storage: StorageHooks> + 'static {
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
    use crate::ipc::protocol::RunnerMessage;
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
            let _ = stack.initiate_sync(peer_ia, SyncOptions { tool_access, system_broadcast: is_broadcast }).await;
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

// ============================================================================
// The two pieces the device stack's generic `storage_task` needs from a DUT
// ============================================================================
//
// A_Restart is handled by `zweidraehte_device::storage::storage_task` — the
// same task every firmware target runs — rather than by a look-alike here.
// That is the whole point: the ordering it implements (drain the outbox
// *before* erasing, so the A_Restart_Response is stamped with the pre-erase
// individual address) is exactly what regressed once in production while
// this crate's own restart handler, which had always got it right, kept the
// suite green. Running the real task puts that ordering under test.
//
// The task is generic over two device-supplied pieces, which is what the
// rest of this section provides:
//
// * `D::Storage`, for `HasConfigStore` (load/save the config blob) and
//   `StorageHooks` (erase + the restart announcement) — `DutConfigStore`,
//   wrapped by `DutSecureStorage` on the secure DUTs, which also carry a
//   sequence/SIAT store.
// * `SystemControl`, for the reset itself — `DutSystemControl`.

/// The DUT's config store: the shared-memory snapshot, behind the interface
/// the storage task expects.
///
/// A DUT "reboots" by exiting and being respawned by the runner, so its
/// durable medium is the shm region the parent maps and the child inherits —
/// [`flush_state`] / `SharedMemory::read_state`, the same calls the exit
/// paths have always used, reached through [`HasConfigStore`] instead of
/// directly.
pub struct DutConfigStore<S: ConformanceStack> {
    shm: &'static ShmCell,
    _marker: core::marker::PhantomData<S>,
}

impl<S: ConformanceStack> DutConfigStore<S> {
    pub const fn new(shm: &'static ShmCell) -> Self {
        Self { shm, _marker: core::marker::PhantomData }
    }
}

impl<S: ConformanceStack> HasConfigStore for DutConfigStore<S> {
    type State = S::State;
    type Config = S::DeviceConfig;

    fn save_config(&self, state: &Self::State) {
        flush_state(self.shm, &S::to_device_config(state));
    }

    fn load_config(&self) -> Option<Self::Config> {
        // SAFETY: single-threaded executor.
        unsafe { self.shm.get() }.read_state().ok().flatten()
    }
}

impl<S: ConformanceStack> StorageHooks for DutConfigStore<S> {
    /// Nothing durable beyond the config blob, which the following
    /// `save_config` rewrites from the freshly-erased state.
    fn erase(&self, _code: EraseCode) {}

    /// Tell the runner the DUT is going away — while the frames from this
    /// step are still in flight.
    ///
    /// This is why `StorageHooks` has an `on_restart` at all. The runner
    /// learns of an exit from a `DutMessage::Exiting` that the IPC link
    /// layer writes back-to-back with the step's `StepComplete`, and it
    /// only polls ~2 ms after `StepComplete` for it. Announcing any later
    /// — after the erase, the save and the settle delay — would land long
    /// after the link layer had already emitted `StepComplete` alone, and
    /// the runner would carry on writing to a socket whose peer then
    /// vanishes. So the announcement has to happen here, at the top of the
    /// restart arm, which is precisely where the storage task calls this.
    async fn on_restart(&self, code: EraseCode) {
        crate::dut::link::announce_exit(ExitReason::Restart { erase_code: u8::from(code) }).await;
    }
}

/// The DUT's "reset line": exit the process, and let the runner respawn us.
///
/// The announcement and the wait for the link layer to flush already
/// happened in [`DutConfigStore::on_restart`]; all that is left is to
/// half-close the socket (so the runner sees EOF) and go. By this point the
/// storage task has erased the state and saved the snapshot the next
/// incarnation will boot from.
pub struct DutSystemControl;

impl zweidraehte_platform::SystemControl for DutSystemControl {
    type Error = core::convert::Infallible;

    async fn restart(&mut self) -> Result<!, Self::Error> {
        crate::dut::link::shutdown_ipc_socket();
        std::process::exit(0)
    }
}

async fn flush_and_exit<S: ConformanceStack>(
    stack: Stack<'static, S>,
    shm: &'static ShmCell,
    erase: Option<EraseCode>,
    reason: ExitReason,
) -> ! {
    let state = stack.state();
    if let Some(code) = erase {
        // State-side erase, then durable-storage-side erase — the same
        // order as the generic storage task. For the secure DUT the
        // storage hook applies the sending-SeqNr near-exhaustion re-init
        // to the shm-backed seq store; the plain DUT's `()` storage
        // no-ops.
        S::apply_erase_code(state, code);
        stack.storage().erase(code);
    }
    let snapshot = S::to_device_config(state);
    flush_state(shm, &snapshot);
    exit_with_reason(reason).await
}

// `Channel` re-export for binaries — saves each bin importing both
// embassy_sync paths and keeps the dependency surface small.
pub type CommandChannel = Channel<NoopRawMutex, IpcCommand, 8>;
