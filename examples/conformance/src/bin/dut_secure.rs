//! Conformance DUT (Device Under Test) child process — Data Secure
//! stack.
//!
//! Identical to [`dut.rs`](conformance-dut) but builds
//! [`IpcSecureConformanceTestStack`] with KNX Data Secure enabled. The
//! Security Interface Object appears at object index 6.
//!
//! Usage: `conformance-dut-secure --shm-fd <N> --socket-fd <M>`

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;

use zweidraehte_conformance::dut_common::{self, ShmCell};
use zweidraehte_conformance::harness::shm::SharedMemory;
use zweidraehte_conformance::harness::ipc::{IpcCommand, IpcLinkLayerBuilder, set_primary_socket_fd};
use zweidraehte_conformance::harness::protocol::ExitReason;
use zweidraehte_conformance::harness::secure_stack::{
    IpcSecureConformanceTestStack, SecureConformanceDeviceConfig, SecureConformanceStateInit,
};
use zweidraehte_conformance::harness::stack::{ConformanceMemoryMap, device_info};

use zweidraehte_device::objects::interface::HasDeviceObject;
use zweidraehte_device::restart::EraseCode;
use zweidraehte_device::storage::HasSequenceStorage;
use zweidraehte_device::{Runner, Stack, StackResources};
use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};

// ============================================================================
// Static resources
// ============================================================================

static STACK_RESOURCES: StaticCell<StackResources<IpcSecureConformanceTestStack, { device_info::BUFFER_SIZE }, 4>> =
    StaticCell::new();

static INJECTION_BUFFERS: StaticCell<[[u8; device_info::BUFFER_SIZE]; 16]> = StaticCell::new();
static INJECTION_BUFFER_MANAGER: StaticCell<BufferManager<16>> = StaticCell::new();

static COMMAND_CHANNEL: StaticCell<Channel<NoopRawMutex, IpcCommand, 8>> = StaticCell::new();

static SHM: StaticCell<ShmCell> = StaticCell::new();

// ============================================================================
// Stack task
// ============================================================================

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, IpcSecureConformanceTestStack>) {
    runner.run().await;
}

// ============================================================================
// Command handler
// ============================================================================

#[embassy_executor::task]
async fn handle_commands(
    stack: Stack<'static, IpcSecureConformanceTestStack>,
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
            IpcCommand::TriggerSync { peer_ia, tool_access, is_broadcast, .. } => {
                log::info!(
                    "CMD: TriggerSync(peer={:#06X}, tool={}, broadcast={})",
                    peer_ia, tool_access, is_broadcast
                );
                let _ = stack.initiate_sync(peer_ia, tool_access, is_broadcast).await;
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

/// Apply an optional erase code, flush state to SHM, emit `Exiting` +
/// shutdown + exit(0).
async fn flush_and_exit(
    stack: Stack<'static, IpcSecureConformanceTestStack>,
    shm: &'static ShmCell,
    erase: Option<EraseCode>,
    reason: ExitReason,
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

#[embassy_executor::task]
async fn handle_restarts(stack: Stack<'static, IpcSecureConformanceTestStack>, shm: &'static ShmCell) {
    loop {
        let request = stack.receive_restart_request().await;
        let erase_code = request.erase_code;
        if matches!(erase_code, EraseCode::Other(_)) {
            continue;
        }
        // Yield so the AL's just-pushed `A_Restart_Response`
        // transits TL → NL → link layer before we mutate inner
        // state. Otherwise a Factory Reset wipes the IA while the
        // response is still sitting in the outbox, and NL emits
        // the response with src = `FF FF`.
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
    let (shm_fd, socket_fd) = dut_common::parse_args("conformance-dut-secure");

    set_primary_socket_fd(socket_fd);
    dut_common::init_ipc_logger(socket_fd, dut_common::log_level_from_env());

    // SAFETY: parent passed us a valid SHM fd.
    let shm = unsafe { SharedMemory::from_raw_fd(shm_fd) }.expect("map shared memory");

    let snapshot: SecureConformanceDeviceConfig = shm
        .read_state()
        .expect("read shared memory")
        .expect("shared memory uninitialized — parent should have written initial state");

    // Set up per-peer seqnr storage from the tail of the SHM region.
    // SAFETY: the region is owned by this process for the duration of
    // the program; `seq_region_ptr` stays valid until `shm` is dropped
    // (at `process::exit`).
    zweidraehte_conformance::harness::secure_stack::set_seq_shm_ptr(shm.seq_region_ptr());
    let seq_storage = IpcSecureConformanceTestStack::create_seq_storage();
    let state_init = SecureConformanceStateInit::Loaded { config: snapshot, seq_storage };

    let shm = SHM.init(ShmCell::new(shm));

    let buffers = INJECTION_BUFFERS.init([[0u8; device_info::BUFFER_SIZE]; 16]);
    let buffer_manager = INJECTION_BUFFER_MANAGER.init(unsafe { BufferManager::new(buffers) });
    let dyn_buffer_manager = buffer_manager.dyn_buffer_manager();
    let dyn_buffer_manager: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_buffer_manager) };

    let command_channel = COMMAND_CHANNEL.init(Channel::new());
    let command_tx = command_channel.dyn_sender();
    let command_tx = unsafe { core::mem::transmute(command_tx) };

    let link_layer_builder =
        IpcLinkLayerBuilder::new(socket_fd, dyn_buffer_manager, command_tx).expect("build IPC link layer");

    let resources = STACK_RESOURCES.init(StackResources::new());

    let (stack, runner) = zweidraehte_device::new(resources, link_layer_builder, state_init, (), ConformanceMemoryMap);

    // SAFETY: COT is 'static via StackResources.
    unsafe {
        stack.hook_context().set_cot(stack.communication_object_table());
    }

    spawner.spawn(run_stack(runner)).expect("spawn stack runner");
    spawner.spawn(handle_commands(stack, command_channel, shm)).expect("spawn command handler");
    spawner.spawn(handle_restarts(stack, shm)).expect("spawn restart handler");

    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}
