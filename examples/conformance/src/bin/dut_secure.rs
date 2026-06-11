//! Conformance DUT (Device Under Test) child process — Data Secure stack.
//!
//! Identical structure to [`dut.rs`](conformance-dut); the only variations
//! are the stack type (`IpcSecureConformanceTestStack`) and the seq-storage
//! initialisation from the tail of the shared-memory region.
//!
//! Usage: `conformance-dut-secure --shm-fd <N> --socket-fd <M>`

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;

use zweidraehte_conformance::dut_common::{self, CommandChannel, ShmCell};
use zweidraehte_conformance::harness::ipc::{IpcLinkLayerBuilder, set_primary_socket_fd};
use zweidraehte_conformance::harness::secure_stack::{
    IpcSecureConformanceTestStack, SecureConformanceDeviceConfig, SecureConformanceStateInit, set_seq_shm_ptr,
};
use zweidraehte_conformance::harness::shm::SharedMemory;
use zweidraehte_conformance::harness::stack::{ConformanceMemoryMap, device_info};

use zweidraehte_device::{Runner, Stack, StackResources};
use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};

// ============================================================================
// Static Resources
// ============================================================================

static STACK_RESOURCES: StaticCell<StackResources<IpcSecureConformanceTestStack, { device_info::BUFFER_SIZE }, 4>> =
    StaticCell::new();
static INJECTION_BUFFERS: StaticCell<[[u8; device_info::BUFFER_SIZE]; 16]> = StaticCell::new();
static INJECTION_BUFFER_MANAGER: StaticCell<BufferManager<16>> = StaticCell::new();
static COMMAND_CHANNEL: StaticCell<CommandChannel> = StaticCell::new();
static SHM: StaticCell<ShmCell> = StaticCell::new();

// ============================================================================
// Embassy tasks
// ============================================================================

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, IpcSecureConformanceTestStack>) {
    runner.run().await;
}

#[embassy_executor::task]
async fn handle_commands(
    stack: Stack<'static, IpcSecureConformanceTestStack>,
    commands: &'static CommandChannel,
    shm: &'static ShmCell,
) {
    loop {
        let cmd = commands.receive().await;
        dut_common::handle_ipc_command::<IpcSecureConformanceTestStack>(stack, shm, cmd).await;
    }
}

#[embassy_executor::task]
async fn handle_restarts(stack: Stack<'static, IpcSecureConformanceTestStack>, shm: &'static ShmCell) {
    loop {
        let request = stack.receive_restart_request().await;
        dut_common::handle_restart_request::<IpcSecureConformanceTestStack>(stack, shm, request.erase_code).await;
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
    set_seq_shm_ptr(shm.seq_region_ptr());
    let seq_storage = IpcSecureConformanceTestStack::create_seq_storage();
    let state_init = SecureConformanceStateInit::Loaded { config: snapshot, seq_storage };

    let shm = SHM.init(ShmCell::new(shm));

    let buffers = INJECTION_BUFFERS.init([[0u8; device_info::BUFFER_SIZE]; 16]);
    let buffer_manager = INJECTION_BUFFER_MANAGER.init(unsafe { BufferManager::new(buffers) });
    let dyn_buffer_manager = buffer_manager.dyn_buffer_manager();
    // SAFETY: buffer manager lives in a StaticCell ('static).
    let dyn_buffer_manager: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_buffer_manager) };

    let command_channel = COMMAND_CHANNEL.init(CommandChannel::new());
    let command_tx = command_channel.dyn_sender();
    // SAFETY: the channel is static.
    let command_tx = unsafe { core::mem::transmute(command_tx) };

    let link_layer_builder =
        IpcLinkLayerBuilder::new(socket_fd, dyn_buffer_manager, command_tx).expect("build IPC link layer");

    let resources = STACK_RESOURCES.init(StackResources::new());

    let (stack, runner) = zweidraehte_device::new(resources, link_layer_builder, state_init, (), ConformanceMemoryMap);

    // Publish the CoTab reference used by the conformance-specific
    // shadow-object hook (`ComObjectBusHook` impl on
    // `ConformanceComObjects`). SAFETY: the CoTab lives inside
    // `StackResources` which is 'static — the pointer remains valid
    // for the process.
    unsafe {
        zweidraehte_conformance::harness::stack::set_conformance_cot(stack.communication_object_table());
    }

    // Spawn the lifecycle → IPC bridge BEFORE the stack runner so its
    // subscriber is registered on the PubSubChannel before the AL's
    // first `poll()` publishes `ReadOnInitComplete`.
    let lifecycle_sub = stack.lifecycle_events();
    // SAFETY: `stack` lives for the duration of the process via
    // `STACK_RESOURCES: StaticCell<...>`, so the subscriber borrows
    // from a `'static` channel.
    let lifecycle_sub: embassy_sync::pubsub::DynSubscriber<'static, zweidraehte_device::lifecycle::LifecycleEvent> =
        unsafe { core::mem::transmute(lifecycle_sub) };
    spawner.spawn(dut_common::bridge_lifecycle_to_ipc(lifecycle_sub)).expect("spawn lifecycle bridge");

    spawner.spawn(run_stack(runner)).expect("spawn stack runner");
    spawner.spawn(handle_commands(stack, command_channel, shm)).expect("spawn command handler");
    spawner.spawn(handle_restarts(stack, shm)).expect("spawn restart handler");

    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}
