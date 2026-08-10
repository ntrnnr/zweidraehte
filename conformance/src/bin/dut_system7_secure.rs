//! Conformance DUT child process — System 7 family with KNX Data Secure.
//!
//! Identical structure to [`dut_systemb_secure.rs`](conformance-dut-systemb-secure); the
//! variations are the stack type (`IpcSystem7SecureTestStack`, mask
//! 0705h) and the CoTab publication for this DUT's own shadow-object
//! hook.
//!
//! Usage: `conformance-dut-system7-secure --shm-fd <N> --socket-fd <M>`

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;

use zweidraehte_conformance::dut_common::{self, CommandChannel, DutConfigStore, DutSystemControl, ShmCell};
use zweidraehte_conformance::harness::fixture_common::{DutSecureStorage, set_seq_shm_ptr};
use zweidraehte_conformance::harness::ipc::{IpcLinkLayerBuilder, set_primary_socket_fd};
use zweidraehte_conformance::harness::shm::SharedMemory;
use zweidraehte_conformance::harness::system7_secure_stack::{
    IpcSystem7SecureTestStack, SecureSystem7MemoryMap, System7SecureDutConfig, device_info, set_system7_secure_cot,
    state_init_from_snapshot,
};

use zweidraehte_device::storage::NoSaveGuard;
use zweidraehte_device::{Runner, Stack, StackResources};
use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};

// ============================================================================
// Static Resources
// ============================================================================

static STACK_RESOURCES: StaticCell<StackResources<IpcSystem7SecureTestStack, { device_info::BUFFER_SIZE }, 4>> =
    StaticCell::new();
static INJECTION_BUFFERS: StaticCell<[[u8; device_info::BUFFER_SIZE]; 16]> = StaticCell::new();
static INJECTION_BUFFER_MANAGER: StaticCell<BufferManager<16>> = StaticCell::new();
static COMMAND_CHANNEL: StaticCell<CommandChannel> = StaticCell::new();
static SHM: StaticCell<ShmCell> = StaticCell::new();
static STORAGE: StaticCell<DutSecureStorage<IpcSystem7SecureTestStack>> = StaticCell::new();

// The device stack's own persistence task — the same one every firmware
// target runs, which is the point: its restart ordering is what we want
// under test. `DutSystemControl` exits the process in place of pulling a
// reset line, and the runner respawns us from the snapshot the task just
// saved.
zweidraehte_device::storage_task! {
    device: IpcSystem7SecureTestStack,
    system: DutSystemControl,
    guard: NoSaveGuard,
}

// ============================================================================
// Embassy tasks
// ============================================================================

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, IpcSystem7SecureTestStack>) {
    runner.run().await;
}

#[embassy_executor::task]
async fn handle_commands(
    stack: Stack<'static, IpcSystem7SecureTestStack>,
    commands: &'static CommandChannel,
    shm: &'static ShmCell,
) {
    loop {
        let cmd = commands.receive().await;
        dut_common::handle_ipc_command::<IpcSystem7SecureTestStack>(stack, shm, cmd).await;
    }
}

// ============================================================================
// Entry point
// ============================================================================

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let (shm_fd, socket_fd) = dut_common::parse_args("conformance-dut-system7-secure");

    set_primary_socket_fd(socket_fd);
    dut_common::init_ipc_logger(socket_fd, dut_common::log_level_from_env());

    // SAFETY: parent passed us a valid SHM fd.
    let shm = unsafe { SharedMemory::from_raw_fd(shm_fd) }.expect("map shared memory");

    let snapshot: System7SecureDutConfig = shm
        .read_state()
        .expect("read shared memory")
        .expect("shared memory uninitialized — parent should have written initial state");

    // Per-peer seqnr storage lives in the tail of the SHM region, same
    // as the System B secure DUT. SAFETY: the region is owned by this
    // process for the duration of the program.
    set_seq_shm_ptr(shm.seq_region_ptr());
    let secure_storage = zweidraehte_conformance::harness::fixture_common::init_secure_storage();
    let state_init = state_init_from_snapshot(snapshot);

    let shm = SHM.init(ShmCell::new(shm));
    let storage = &*STORAGE.init(DutSecureStorage::new(DutConfigStore::new(shm), secure_storage));

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

    let (stack, runner) =
        zweidraehte_device::new(resources, link_layer_builder, state_init, (), SecureSystem7MemoryMap, storage);

    // Publish the CoTab reference used by this DUT's shadow-object hook.
    // SAFETY: the CoTab lives inside `StackResources`, which is 'static.
    unsafe {
        set_system7_secure_cot(stack.communication_object_table());
    }

    // Spawn the lifecycle → IPC bridge BEFORE the stack runner so its
    // subscriber is registered before the AL's first poll publishes
    // `ReadOnInitComplete`.
    let lifecycle_sub = stack.lifecycle_events();
    // SAFETY: `stack` lives for the duration of the process.
    let lifecycle_sub: embassy_sync::pubsub::DynSubscriber<'static, zweidraehte_device::lifecycle::LifecycleEvent> =
        unsafe { core::mem::transmute(lifecycle_sub) };
    spawner.spawn(dut_common::bridge_lifecycle_to_ipc(lifecycle_sub)).expect("spawn lifecycle bridge");

    spawner.spawn(run_stack(runner)).expect("spawn stack runner");
    spawner.spawn(handle_commands(stack, command_channel, shm)).expect("spawn command handler");
    spawner.spawn(storage_task(stack)).expect("storage_task spawnable once");

    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}
