//! Conformance DUT (Device Under Test) child process.
//!
//! Spawned by the conformance-runner parent. Maps the parent's shared
//! memory, reconstructs device state, creates an IPC-backed KNX stack,
//! and runs until told to restart or shut down.
//!
//! Usage: conformance-dut --shm-fd <N> --socket-fd <M>

use std::cell::UnsafeCell;
use std::os::unix::io::RawFd;
use std::sync::{Mutex, OnceLock};

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;

use zweidraehte_conformance::harness::ipc::{self, IpcCommand, IpcLinkLayerBuilder, SharedMemory, TAG_LOG, TAG_READY};
use zweidraehte_conformance::harness::stack::{
    ConformanceMemoryMap, ConformanceDeviceConfig, ConformanceStateInit, IpcConformanceTestStack, device_info,
};

use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};
use zweidraehte_device::objects::interface::HasDeviceObject;
use zweidraehte_device::restart::EraseCode;
use zweidraehte_device::{Runner, Stack, StackResources};

// ============================================================================
// Static Resources
// ============================================================================

static STACK_RESOURCES: StaticCell<StackResources<IpcConformanceTestStack, { device_info::BUFFER_SIZE }, 4>> =
    StaticCell::new();

static INJECTION_BUFFERS: StaticCell<[[u8; device_info::BUFFER_SIZE]; 16]> = StaticCell::new();
static INJECTION_BUFFER_MANAGER: StaticCell<BufferManager<16>> = StaticCell::new();

/// Channel for non-INJECT IPC commands (SetProgrammingMode, TriggerRead,
/// TriggerWrite). The link layer sends commands here; the handler task
/// consumes them and executes against the stack.
static COMMAND_CHANNEL: StaticCell<Channel<NoopRawMutex, IpcCommand, 8>> = StaticCell::new();

/// Shared memory handle stored in an `UnsafeCell` so the restart handler
/// can write to it. This is safe because the embassy executor is
/// single-threaded — only one task accesses it at a time.
struct ShmCell(UnsafeCell<SharedMemory>);
unsafe impl Sync for ShmCell {}

static SHM: StaticCell<ShmCell> = StaticCell::new();

// ============================================================================
// Stack Task
// ============================================================================

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, IpcConformanceTestStack>) {
    runner.run().await;
}

// ============================================================================
// Command Handler
// ============================================================================
//
// Receives IPC commands dispatched by the link layer and executes them
// against the stack. This runs as a separate embassy task because the
// link layer doesn't have direct access to the `Stack` handle.

#[embassy_executor::task]
async fn handle_commands(
    stack: Stack<'static, IpcConformanceTestStack>,
    commands: &'static Channel<NoopRawMutex, IpcCommand, 8>,
    shm: &'static ShmCell,
) {
    loop {
        let cmd = commands.receive().await;
        match cmd {
            IpcCommand::SetProgrammingMode(enabled) => {
                log::info!("CMD: SetProgrammingMode({})", enabled);
                stack.interface_objects().set_programming_mode_enabled(enabled);
            }
            IpcCommand::TriggerRead(asap) => {
                log::info!("CMD: TriggerRead(ASAP {})", asap);
                let _ = stack.read_object_by_asap(asap).await;
            }
            IpcCommand::TriggerWrite(asap) => {
                log::info!("CMD: TriggerWrite(ASAP {})", asap);
                let _ = stack.write_object_by_asap(asap).await;
            }
            IpcCommand::TriggerSync { .. } => {
                log::warn!("CMD: TriggerSync ignored (non-secure DUT)");
            }
            IpcCommand::PowerCycle => {
                log::info!("CMD: PowerCycle — flush + exit");
                Timer::after(Duration::from_millis(1)).await;
                flush_and_exit(stack, shm, None);
            }
            IpcCommand::MasterReset { erase_code } => {
                log::info!("CMD: MasterReset(erase_code=0x{:02x}) — reset + flush + exit", erase_code);
                Timer::after(Duration::from_millis(1)).await;
                flush_and_exit(stack, shm, Some(EraseCode::from(erase_code)));
            }
        }
    }
}

fn flush_and_exit(
    stack: Stack<'static, IpcConformanceTestStack>,
    shm: &'static ShmCell,
    erase: Option<EraseCode>,
) -> ! {
    let state = stack.state();
    if let Some(code) = erase {
        match code {
            EraseCode::Basic | EraseCode::Confirmed => {}
            EraseCode::FactoryReset => state.inner().factory_reset(),
            EraseCode::ResetIA => state.inner().reset_individual_address(),
            EraseCode::ResetAP => state.inner().reset_application(),
            EraseCode::ResetParam => state.inner().reset_parameters(),
            EraseCode::ResetLinks => {
                state.inner().reset_address_table();
                state.inner().reset_association_table();
            }
            EraseCode::FactoryResetKeepIA => state.inner().factory_reset_keep_ia(),
            _ => {}
        }
    }
    let snapshot = state.to_device_config();
    let shm_mut = unsafe { &mut *shm.0.get() };
    if let Err(e) = shm_mut.write_state(&snapshot) {
        log::error!("Failed to flush state to shared memory: {}", e);
    }
    std::process::exit(0);
}

// ============================================================================
// Restart Handler
// ============================================================================
//
// On restart, the child:
// 1. Receives the restart request (the stack already sent A_Restart_Response)
// 2. Executes the appropriate reset on device state
// 3. Flushes all persistent state to shared memory
// 4. Exits the process
//
// The parent detects EOF on the socket, respawns a fresh child, and the
// new child starts with clean volatile state while persistent state
// survives in shared memory.

#[embassy_executor::task]
async fn handle_restarts(stack: Stack<'static, IpcConformanceTestStack>, shm: &'static ShmCell) {
    loop {
        let request = stack.receive_restart_request().await;
        let state = stack.state();
        let erase_code = request.erase_code;

        // The stack already sent the A_Restart_Response on the bus before
        // delivering this request. Unknown erase codes are rejected by the
        // application layer and never reach us.
        // Validate anyway: skip restart for unsupported codes.
        if matches!(erase_code, EraseCode::Other(_)) {
            continue;
        }

        // Give the stack a moment to send the response over IPC
        // before we apply state changes and exit. Over a Unix socketpair
        // this is nearly instant; 1ms is plenty.
        Timer::after(Duration::from_millis(1)).await;

        // Apply the erase-code-specific state changes.
        match erase_code {
            EraseCode::Basic | EraseCode::Confirmed => {
                // No state changes — just restart.
            }
            EraseCode::FactoryReset => state.inner().factory_reset(),
            EraseCode::ResetIA => state.inner().reset_individual_address(),
            EraseCode::ResetAP => state.inner().reset_application(),
            EraseCode::ResetParam => state.inner().reset_parameters(),
            EraseCode::ResetLinks => {
                state.inner().reset_address_table();
                state.inner().reset_association_table();
            }
            EraseCode::FactoryResetKeepIA => state.inner().factory_reset_keep_ia(),
            _ => unreachable!("unsupported erase codes filtered above"),
        }

        // Flush persistent state to shared memory, then exit.
        // The parent will detect EOF and respawn us.
        let snapshot = state.to_device_config();

        // SAFETY: Single-threaded embassy executor — no concurrent access.
        let shm_mut = unsafe { &mut *shm.0.get() };
        if let Err(e) = shm_mut.write_state(&snapshot) {
            log::error!("Failed to flush state to shared memory: {}", e);
        }

        log::info!("Restart: flushed state to shm, exiting");
        std::process::exit(0);
    }
}

// ============================================================================
// IPC Logger
// ============================================================================
//
// Instead of printing to stderr (which interleaves with the parent's test
// output), we send log entries over the IPC socket as TAG_LOG frames. The
// parent buffers them per-test and prints only on failure.

/// Socket used by the IPC logger. A dup'd copy of the main IPC socket fd,
/// so the logger can write independently of the async link layer.
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

        // Payload: [level: u8] [target \0] [message bytes]
        let level_byte = record.level() as u8;
        let target = record.target();
        let message = format!("{}", record.args());
        let mut payload = Vec::with_capacity(1 + target.len() + 1 + message.len());
        payload.push(level_byte);
        payload.extend_from_slice(target.as_bytes());
        payload.push(0); // NUL separator
        payload.extend_from_slice(message.as_bytes());

        // Best-effort — don't panic if the socket write fails (e.g. parent
        // closed during shutdown).
        let _ = ipc::write_frame_blocking(&mut socket, TAG_LOG, &payload);
    }

    fn flush(&self) {}
}

/// Initialize the IPC logger. Call after dup'ing the socket fd into
/// `LOG_SOCKET`.
fn init_ipc_logger(level: log::LevelFilter) {
    log::set_boxed_logger(Box::new(IpcLogger { level })).expect("set logger");
    log::set_max_level(level);
}

// ============================================================================
// Entry Point
// ============================================================================

fn parse_args() -> (RawFd, RawFd) {
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

    let shm_fd = shm_fd.unwrap_or_else(|| {
        eprintln!("Usage: conformance-dut --shm-fd <N> --socket-fd <M>");
        std::process::exit(1);
    });
    let socket_fd = socket_fd.unwrap_or_else(|| {
        eprintln!("Usage: conformance-dut --shm-fd <N> --socket-fd <M>");
        std::process::exit(1);
    });

    (shm_fd, socket_fd)
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let (shm_fd, socket_fd) = parse_args();

    // Set up the IPC logger before anything else. We dup the socket fd so
    // the logger has its own blocking stream independent of the async link
    // layer. This must happen before any log::* calls.
    {
        use std::os::unix::io::FromRawFd;
        let dup_fd = nix::unistd::dup(socket_fd).expect("dup socket fd for logger");
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(dup_fd) };
        LOG_SOCKET.set(Mutex::new(stream)).ok();
    }
    let log_level = match std::env::var("RUST_LOG").ok().as_deref() {
        Some("error") => log::LevelFilter::Error,
        Some("warn") => log::LevelFilter::Warn,
        Some("info") => log::LevelFilter::Info,
        Some("debug") => log::LevelFilter::Debug,
        Some("trace") => log::LevelFilter::Trace,
        _ => log::LevelFilter::Debug,
    };
    init_ipc_logger(log_level);

    // Map the parent's shared memory region.
    // SAFETY: The parent passed us valid fds via command-line args.
    let shm = unsafe { SharedMemory::from_raw_fd(shm_fd) }.expect("map shared memory");

    // Deserialize device state from shared memory.
    let snapshot: ConformanceDeviceConfig = shm
        .read_state()
        .expect("read shared memory")
        .expect("shared memory uninitialized — parent should have written initial state");

    let state_init = ConformanceStateInit::Loaded(snapshot);

    // Store shm in a static so the restart handler can access it.
    let shm = SHM.init(ShmCell(UnsafeCell::new(shm)));

    // Initialize buffer manager for the IPC link layer.
    let buffers = INJECTION_BUFFERS.init([[0u8; device_info::BUFFER_SIZE]; 16]);
    // SAFETY: Initializing the buffer manager with our static buffers.
    let buffer_manager = INJECTION_BUFFER_MANAGER.init(unsafe { BufferManager::new(buffers) });
    let dyn_buffer_manager = buffer_manager.dyn_buffer_manager();
    // SAFETY: The buffer manager lives for the entire program ('static).
    let dyn_buffer_manager: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_buffer_manager) };

    // Create command channel for non-INJECT IPC commands.
    let command_channel = COMMAND_CHANNEL.init(Channel::new());
    let command_tx = command_channel.dyn_sender();
    // SAFETY: The channel lives in a StaticCell ('static).
    let command_tx = unsafe { core::mem::transmute(command_tx) };

    // Create IPC link layer builder from the socket fd.
    let link_layer_builder =
        IpcLinkLayerBuilder::new(socket_fd, dyn_buffer_manager, command_tx).expect("create IPC link layer");

    // Create stack resources.
    let resources = STACK_RESOURCES.init(StackResources::new());

    // Create the KNX stack.
    let (stack, runner) = zweidraehte_device::new(
        resources,
        link_layer_builder,
        state_init,
        (),
        ConformanceMemoryMap,
    );

    // Patch the hook context with the COT reference.
    // SAFETY: The COT lives in StackResources which is 'static.
    unsafe {
        stack.hook_context().set_cot(stack.communication_object_table());
    }

    // Send Ready frame to the parent. We dup the socket fd and write
    // a blocking frame, then close the dup'd fd.
    {
        use std::os::unix::io::FromRawFd;
        use std::os::unix::net::UnixStream;

        let dup_fd = nix::unistd::dup(socket_fd).expect("dup socket fd for Ready frame");
        let mut stream = unsafe { UnixStream::from_raw_fd(dup_fd) };
        ipc::write_frame_blocking(&mut stream, TAG_READY, &[]).expect("send Ready frame");
    }

    // Spawn the stack runner, command handler, and restart handler.
    spawner.spawn(run_stack(runner)).expect("spawn stack runner");
    spawner.spawn(handle_commands(stack, command_channel, shm)).expect("spawn command handler");
    spawner.spawn(handle_restarts(stack, shm)).expect("spawn restart handler");

    // Keep main alive — the stack runs in background tasks.
    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}
