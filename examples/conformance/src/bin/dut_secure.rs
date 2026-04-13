//! Secure conformance DUT (Device Under Test) child process.
//!
//! Identical to `dut.rs` but uses [`IpcSecureConformanceTestStack`] with
//! KNX Data Secure enabled. Spawned by the conformance-runner parent when
//! running security test suites.
//!
//! Usage: conformance-dut-secure --shm-fd <N> --socket-fd <M>

use std::cell::UnsafeCell;
use std::os::unix::io::RawFd;
use std::sync::{Mutex, OnceLock};

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;

use zweidraehte_conformance::harness::ipc::{self, IpcCommand, IpcLinkLayerBuilder, SharedMemory, TAG_LOG, TAG_READY};
use zweidraehte_conformance::harness::secure_stack::{
    IpcSecureConformanceTestStack, SecureConformancePersistedState, SecureConformanceStateConfig,
};
use zweidraehte_conformance::harness::stack::{ConformanceMemoryMap, device_info};

use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};
use zweidraehte_device::objects::interface::HasDeviceObject;
use zweidraehte_device::restart::EraseCode;
use zweidraehte_device::storage::HasSequenceStorage;
use zweidraehte_device::{Runner, Stack, StackResources};

// ============================================================================
// Static Resources
// ============================================================================

static STACK_RESOURCES: StaticCell<StackResources<IpcSecureConformanceTestStack, { device_info::BUFFER_SIZE }, 4>> =
    StaticCell::new();

static INJECTION_BUFFERS: StaticCell<[[u8; device_info::BUFFER_SIZE]; 16]> = StaticCell::new();
static INJECTION_BUFFER_MANAGER: StaticCell<BufferManager<16>> = StaticCell::new();

static COMMAND_CHANNEL: StaticCell<Channel<NoopRawMutex, IpcCommand, 8>> = StaticCell::new();

struct ShmCell(UnsafeCell<SharedMemory>);
unsafe impl Sync for ShmCell {}

static SHM: StaticCell<ShmCell> = StaticCell::new();

// ============================================================================
// Stack Task
// ============================================================================

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, IpcSecureConformanceTestStack>) {
    runner.run().await;
}

// ============================================================================
// Command Handler
// ============================================================================

#[embassy_executor::task]
async fn handle_commands(
    stack: Stack<'static, IpcSecureConformanceTestStack>,
    commands: &'static Channel<NoopRawMutex, IpcCommand, 8>,
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
            IpcCommand::TriggerSync { peer_ia, tool_access, is_broadcast } => {
                log::info!("CMD: TriggerSync(peer={:#06X}, tool={}, broadcast={})", peer_ia, tool_access, is_broadcast);
                let _ = stack.initiate_sync(peer_ia, tool_access, is_broadcast).await;
            }
        }
    }
}

// ============================================================================
// Restart Handler
// ============================================================================

#[embassy_executor::task]
async fn handle_restarts(stack: Stack<'static, IpcSecureConformanceTestStack>, shm: &'static ShmCell) {
    loop {
        let request = stack.receive_restart_request().await;
        let state = stack.state();
        let erase_code = request.erase_code;

        if matches!(erase_code, EraseCode::Other(_)) {
            continue;
        }

        // Give the stack a moment to flush the IPC response before exit.
        Timer::after(Duration::from_millis(1)).await;

        match erase_code {
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
            _ => unreachable!("unsupported erase codes filtered above"),
        }

        let snapshot = state.to_persisted_snapshot();
        // SAFETY: Single-threaded embassy executor — no concurrent access.
        let shm_mut = unsafe { &mut *shm.0.get() };
        if let Err(e) = shm_mut.write_state(&snapshot) {
            log::error!("Failed to flush state to shared memory: {}", e);
        }

        std::process::exit(0);
    }
}

// ============================================================================
// IPC Logger (identical to dut.rs)
// ============================================================================

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

        let level_byte = record.level() as u8;
        let target = record.target();
        let message = format!("{}", record.args());
        let mut payload = Vec::with_capacity(1 + target.len() + 1 + message.len());
        payload.push(level_byte);
        payload.extend_from_slice(target.as_bytes());
        payload.push(0);
        payload.extend_from_slice(message.as_bytes());

        let _ = ipc::write_frame_blocking(&mut socket, TAG_LOG, &payload);
    }

    fn flush(&self) {}
}

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
        eprintln!("Usage: conformance-dut-secure --shm-fd <N> --socket-fd <M>");
        std::process::exit(1);
    });
    let socket_fd = socket_fd.unwrap_or_else(|| {
        eprintln!("Usage: conformance-dut-secure --shm-fd <N> --socket-fd <M>");
        std::process::exit(1);
    });

    (shm_fd, socket_fd)
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let (shm_fd, socket_fd) = parse_args();

    // Set up the IPC logger.
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
    let shm = unsafe { SharedMemory::from_raw_fd(shm_fd) }.expect("map shared memory");

    // Deserialize device state from shared memory.
    let snapshot: SecureConformancePersistedState = shm
        .read_state()
        .expect("read shared memory")
        .expect("shared memory uninitialized — parent should have written initial state");

    // Create the sequence number storage from the shared memory region,
    // then pass it as part of the state config so the runner can construct
    // the state with the layer context.
    zweidraehte_conformance::harness::secure_stack::set_seq_shm_ptr(shm.seq_region_ptr());
    let seq_storage = IpcSecureConformanceTestStack::create_seq_storage();
    let state_config = SecureConformanceStateConfig::Persisted { snapshot, seq_storage };

    let shm = SHM.init(ShmCell(UnsafeCell::new(shm)));

    let buffers = INJECTION_BUFFERS.init([[0u8; device_info::BUFFER_SIZE]; 16]);
    let buffer_manager = INJECTION_BUFFER_MANAGER.init(unsafe { BufferManager::new(buffers) });
    let dyn_buffer_manager = buffer_manager.dyn_buffer_manager();
    let dyn_buffer_manager: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_buffer_manager) };

    let command_channel = COMMAND_CHANNEL.init(Channel::new());
    let command_tx = command_channel.dyn_sender();
    let command_tx = unsafe { core::mem::transmute(command_tx) };

    let link_layer_builder =
        IpcLinkLayerBuilder::new(socket_fd, dyn_buffer_manager, command_tx).expect("create IPC link layer");

    let resources = STACK_RESOURCES.init(StackResources::new());

    let (stack, runner) = zweidraehte_device::new(
        resources,
        link_layer_builder,
        state_config,
        (),
        ConformanceMemoryMap,
    );

    // Patch the hook context with the COT reference.
    unsafe {
        stack.hook_context().set_cot(stack.communication_object_table());
    }

    // Send Ready frame to the parent.
    {
        use std::os::unix::io::FromRawFd;
        use std::os::unix::net::UnixStream;

        let dup_fd = nix::unistd::dup(socket_fd).expect("dup socket fd for Ready frame");
        let mut stream = unsafe { UnixStream::from_raw_fd(dup_fd) };
        ipc::write_frame_blocking(&mut stream, TAG_READY, &[]).expect("send Ready frame");
    }

    spawner.spawn(run_stack(runner)).expect("spawn stack runner");
    spawner.spawn(handle_commands(stack, command_channel)).expect("spawn command handler");
    spawner.spawn(handle_restarts(stack, shm)).expect("spawn restart handler");

    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}
