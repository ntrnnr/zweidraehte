//! Conformance DUT (Device Under Test) child process — plain stack.
//!
//! Spawned by the conformance-runner parent. Maps the parent's shared
//! memory, reconstructs device state, creates an IPC-backed KNX stack,
//! and runs until told to restart or power-cycle.
//!
//! Usage: `conformance-dut --shm-fd <N> --socket-fd <M>`
//!
//! # Protocol
//!
//! Speaks the new postcard-based IPC protocol defined in
//! [`zweidraehte_conformance::harness::protocol`]. See
//! [`zweidraehte_conformance::harness::ipc`] for the link-layer
//! semantics.

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;

use zweidraehte_conformance::dut_common::{self, ShmCell};
use zweidraehte_conformance::harness::shm::SharedMemory;
use zweidraehte_conformance::harness::ipc::{IpcCommand, IpcLinkLayerBuilder, set_primary_socket_fd};
use zweidraehte_conformance::harness::protocol::ExitReason;
use zweidraehte_conformance::harness::stack::{
    ConformanceDeviceConfig, ConformanceMemoryMap, ConformanceStateInit, IpcConformanceTestStack, device_info,
};

use zweidraehte_device::objects::interface::HasDeviceObject;
use zweidraehte_device::restart::EraseCode;
use zweidraehte_device::{Runner, Stack, StackResources};
use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};

// ============================================================================
// Static Resources
// ============================================================================

static STACK_RESOURCES: StaticCell<StackResources<IpcConformanceTestStack, { device_info::BUFFER_SIZE }, 4>> =
    StaticCell::new();

static INJECTION_BUFFERS: StaticCell<[[u8; device_info::BUFFER_SIZE]; 16]> = StaticCell::new();
static INJECTION_BUFFER_MANAGER: StaticCell<BufferManager<16>> = StaticCell::new();

/// Channel for the link layer → command handler dispatch.
static COMMAND_CHANNEL: StaticCell<Channel<NoopRawMutex, IpcCommand, 8>> = StaticCell::new();

static SHM: StaticCell<ShmCell> = StaticCell::new();

// ============================================================================
// Stack task
// ============================================================================

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, IpcConformanceTestStack>) {
    runner.run().await;
}

// ============================================================================
// Command handler
// ============================================================================
//
// Receives commands dispatched from the IPC link layer and runs them
// against the stack. This is a separate task because the link layer
// doesn't carry a `Stack` handle. For `PowerCycle` / `MasterReset` it
// drives the final flush + exit — no `Timer::after` drain: the new
// protocol guarantees the runner has already received every outbox
// frame via `StepComplete` before this handler runs.

#[embassy_executor::task]
async fn handle_commands(
    stack: Stack<'static, IpcConformanceTestStack>,
    commands: &'static Channel<NoopRawMutex, IpcCommand, 8>,
    shm: &'static ShmCell,
) {
    loop {
        match commands.receive().await {
            IpcCommand::SetProgrammingMode { enabled, .. } => {
                log::info!("CMD: SetProgrammingMode({})", enabled);
                stack.interface_objects().set_programming_mode_enabled(enabled);
            }
            IpcCommand::TriggerRead { asap, .. } => {
                log::info!("CMD: TriggerRead(ASAP {})", asap);
                let _ = stack.read_object_by_asap(asap).await;
            }
            IpcCommand::TriggerWrite { asap, .. } => {
                log::info!("CMD: TriggerWrite(ASAP {})", asap);
                let _ = stack.write_object_by_asap(asap).await;
            }
            IpcCommand::TriggerSync { .. } => {
                log::warn!("CMD: TriggerSync ignored (non-secure DUT)");
            }
            IpcCommand::PowerCycle => {
                log::info!("CMD: PowerCycle — flush + exit");
                flush_and_exit(stack, shm, None, ExitReason::PowerCycle).await;
            }
            IpcCommand::MasterReset { erase_code } => {
                log::info!("CMD: MasterReset(erase_code=0x{:02x})", erase_code);
                let code = EraseCode::from(erase_code);
                flush_and_exit(stack, shm, Some(code), ExitReason::MasterReset { erase_code }).await;
            }
        }
    }
}

/// Apply an optional erase code, flush state to SHM, then emit
/// `Exiting` + shutdown socket + exit(0). Shared between
/// [`handle_commands`] and [`handle_restarts`].
async fn flush_and_exit(
    stack: Stack<'static, IpcConformanceTestStack>,
    shm: &'static ShmCell,
    erase: Option<EraseCode>,
    reason: ExitReason,
) -> ! {
    let state = stack.state();
    if let Some(code) = erase {
        // Erase-code dispatch inline — `inner()` is a concrete type
        // with interior mutability; `&self` is enough.
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
            EraseCode::Other(_) => log::warn!("apply_erase_code: unsupported {:?}", code),
        }
    }
    let snapshot = state.to_device_config();
    dut_common::flush_state(shm, &snapshot);
    dut_common::exit_with_reason(reason).await
}

// ============================================================================
// Restart handler
// ============================================================================
//
// The application layer delivers `A_Restart` requests here after the
// outbox has already been drained into a `StepComplete` (the restart
// response is one of those frames). No `Timer::after` needed.

#[embassy_executor::task]
async fn handle_restarts(stack: Stack<'static, IpcConformanceTestStack>, shm: &'static ShmCell) {
    loop {
        let request = stack.receive_restart_request().await;
        let erase_code = request.erase_code;

        // Unknown codes are rejected at the application layer and
        // never reach us, but guard anyway.
        if matches!(erase_code, EraseCode::Other(_)) {
            continue;
        }

        // Yield a handful of times so the AL's just-pushed
        // A_Restart_Response transits TL → NL → link layer before
        // we mutate the inner state. Otherwise a Factory Reset
        // wipes the IA while the response is still sitting in the
        // outbox, and NL emits the response with src = `FF FF`.
        //
        // ~16 yields is plenty: the router drains one frame per
        // yield chain (indication → T_ACK → data → confirmation),
        // and the response path is at most 3-4 ticks deep. No
        // wall-clock `Timer::after` needed — yields are free.
        for _ in 0..16 {
            embassy_futures::yield_now().await;
        }

        let reason = ExitReason::Restart { erase_code: erase_code_to_u8(erase_code) };
        flush_and_exit(stack, shm, Some(erase_code), reason).await;
    }
}

fn erase_code_to_u8(code: EraseCode) -> u8 {
    match code {
        EraseCode::Basic => 0x00,
        EraseCode::Confirmed => 0x01,
        EraseCode::FactoryReset => 0x02,
        EraseCode::ResetIA => 0x03,
        EraseCode::ResetAP => 0x04,
        EraseCode::ResetParam => 0x05,
        EraseCode::ResetLinks => 0x06,
        EraseCode::FactoryResetKeepIA => 0x07,
        EraseCode::Other(x) => x,
    }
}

// ============================================================================
// Entry point
// ============================================================================

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let (shm_fd, socket_fd) = dut_common::parse_args("conformance-dut");

    // Register the socket fd so the exit path can half-close it.
    set_primary_socket_fd(socket_fd);

    // Install the IPC logger before anything else logs.
    dut_common::init_ipc_logger(socket_fd, dut_common::log_level_from_env());

    // SAFETY: the parent passed us a valid fd for a SHM region.
    let shm = unsafe { SharedMemory::from_raw_fd(shm_fd) }.expect("map shared memory");

    // Deserialize state from SHM. Parent always writes the initial
    // snapshot before spawning us.
    let snapshot: ConformanceDeviceConfig = shm
        .read_state()
        .expect("read shared memory")
        .expect("shared memory uninitialized — parent should have written initial state");

    let state_init = ConformanceStateInit::Loaded(snapshot);

    let shm = SHM.init(ShmCell::new(shm));

    let buffers = INJECTION_BUFFERS.init([[0u8; device_info::BUFFER_SIZE]; 16]);
    // SAFETY: single-threaded buffer manager over our static buffers.
    let buffer_manager = INJECTION_BUFFER_MANAGER.init(unsafe { BufferManager::new(buffers) });
    let dyn_buffer_manager = buffer_manager.dyn_buffer_manager();
    // SAFETY: buffer manager lives in a StaticCell ('static).
    let dyn_buffer_manager: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_buffer_manager) };

    let command_channel = COMMAND_CHANNEL.init(Channel::new());
    let command_tx = command_channel.dyn_sender();
    // SAFETY: the channel is static.
    let command_tx = unsafe { core::mem::transmute(command_tx) };

    let link_layer_builder =
        IpcLinkLayerBuilder::new(socket_fd, dyn_buffer_manager, command_tx).expect("build IPC link layer");

    let resources = STACK_RESOURCES.init(StackResources::new());

    let (stack, runner) = zweidraehte_device::new(resources, link_layer_builder, state_init, (), ConformanceMemoryMap);

    // SAFETY: the COT lives in StackResources which is 'static.
    unsafe {
        stack.hook_context().set_cot(stack.communication_object_table());
    }

    spawner.spawn(run_stack(runner)).expect("spawn stack runner");
    spawner.spawn(handle_commands(stack, command_channel, shm)).expect("spawn command handler");
    spawner.spawn(handle_restarts(stack, shm)).expect("spawn restart handler");

    // Main keeps the executor alive; the worker tasks handle IO.
    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}
