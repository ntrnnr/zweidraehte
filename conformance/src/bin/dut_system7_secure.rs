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

use zweidraehte_conformance::dut::common as dut_common;
use zweidraehte_conformance::dut::common::{
    CommandChannel, DutRestartHook, DutSystemControl, ShmCell, open_dut_config,
};
use zweidraehte_conformance::dut::fixture_common::{
    DutSecureStorage, create_seq_storage, seed_eitt_boot_siat, set_seq_shm_ptr,
};
use zweidraehte_conformance::dut::link::{IpcLinkLayerBuilder, set_primary_socket_fd};
use zweidraehte_conformance::dut::system7_secure_stack::{
    IpcSystem7SecureTestStack, SecureSystem7MemoryMap, device_info, set_system7_secure_cot,
};
use zweidraehte_conformance::ipc::shm::SharedMemory;
use zweidraehte_nv::Loaded;

use zweidraehte_device::buffers::{BufferManager, DynBufferManager};
use zweidraehte_device::storage::NoSaveGuard;
use zweidraehte_device::{Runner, Stack, StackResources};

// ============================================================================
// Static Resources
// ============================================================================

static STACK_RESOURCES: StaticCell<StackResources<IpcSystem7SecureTestStack>> = StaticCell::new();
static INJECTION_BUFFERS: StaticCell<[[u8; device_info::BUFFER_SIZE]; 16]> = StaticCell::new();
static INJECTION_BUFFER_MANAGER: StaticCell<BufferManager<16>> = StaticCell::new();
static COMMAND_CHANNEL: StaticCell<CommandChannel> = StaticCell::new();
static SHM: StaticCell<ShmCell> = StaticCell::new();
static STORAGE: StaticCell<DutSecureStorage> = StaticCell::new();

// The device stack's own persistence task — the same one every firmware
// target runs, which is the point: its restart ordering is what we want
// under test. `DutSystemControl` exits the process in place of pulling a
// reset line, and the runner respawns us from the snapshot the task just
// saved.
zweidraehte_device::storage_task! {
    device: IpcSystem7SecureTestStack,
    system: DutSystemControl,
    guard: NoSaveGuard,
    restart_hook: DutRestartHook,
}

// ============================================================================
// Embassy tasks
// ============================================================================

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, IpcSystem7SecureTestStack>) {
    runner.run().await;
}

#[embassy_executor::task]
async fn handle_commands(stack: Stack<'static, IpcSystem7SecureTestStack>, commands: &'static CommandChannel) {
    loop {
        let cmd = commands.receive().await;
        dut_common::handle_ipc_command::<IpcSystem7SecureTestStack>(stack, cmd).await;
    }
}

// ============================================================================
// Entry point
// ============================================================================

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let (shm_fd, socket_fd) = dut_common::parse_args("conformance-dut-system7-secure");

    set_primary_socket_fd(socket_fd);
    dut_common::init_ipc_logger(dut_common::log_level_from_env());

    // SAFETY: parent passed us a valid SHM fd.
    let shm = unsafe { SharedMemory::from_raw_fd(shm_fd) }.expect("map shared memory");

    // Per-peer seqnr storage lives in the tail of the SHM region, same
    // as the System B secure DUT. SAFETY: the region is owned by this
    // process for the duration of the program.
    set_seq_shm_ptr(shm.seq_region_ptr());

    let shm = SHM.init(ShmCell::new(shm));
    let storage = &*STORAGE.init(DutSecureStorage::new(open_dut_config(shm), create_seq_storage()));

    let buffers = INJECTION_BUFFERS.init([[0u8; device_info::BUFFER_SIZE]; 16]);
    let buffer_manager = INJECTION_BUFFER_MANAGER.init(unsafe { BufferManager::new(buffers) });
    let dyn_buffer_manager = buffer_manager.dyn_buffer_manager();
    // SAFETY: buffer manager lives in a StaticCell ('static).
    let dyn_buffer_manager: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_buffer_manager) };

    let command_channel: &'static CommandChannel = COMMAND_CHANNEL.init(CommandChannel::new());
    let command_tx = command_channel.dyn_sender();

    let link_layer_builder =
        IpcLinkLayerBuilder::new(socket_fd, dyn_buffer_manager, command_tx).expect("build IPC link layer");

    let resources = STACK_RESOURCES.init(StackResources::new());

    let (stack, runner) =
        zweidraehte_device::new(resources, link_layer_builder, (), (), SecureSystem7MemoryMap, storage)
            .expect("the DUT's section layout fits the shared memory");

    // `new` restored the durable configuration. A blank region (the first
    // boot, or a full reset: the parent never constructs state) loads as
    // `Fresh`; the DUT then installs its conformance setup, makes it durable
    // and seeds the setup's SIAT entries before the runner starts. A respawn
    // keeps what the cases wrote.
    if stack.loaded_at_boot() == Loaded::Fresh {
        stack.state().configure();
        stack.flush_config().expect("the shared memory takes the conformance setup");
        seed_eitt_boot_siat(&mut storage.seq.borrow_mut());
    }

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
    spawner.spawn(handle_commands(stack, command_channel)).expect("spawn command handler");
    spawner.spawn(storage_task(stack)).expect("storage_task spawnable once");

    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}
