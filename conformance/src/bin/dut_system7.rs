//! Conformance DUT child process — System 7 stack (mask 0705h).
//!
//! Spawned by the conformance-runner parent for the System 7 suites and
//! the System 7 EITT profile. Same lifecycle as the plain DUT
//! (`dut.rs`), specialised for `IpcSystem7TestStack`: the shadow-object
//! hook and the EEPROM test regions live in the conformance wrapper
//! types (`dut::system7_stack`), with the family memory map
//! underneath as the surface under test.
//!
//! Usage: `conformance-dut-system7 --shm-fd <N> --socket-fd <M>`

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;

use zweidraehte_conformance::dut::common as dut_common;
use zweidraehte_conformance::dut::common::{CommandChannel, DutConfigStore, DutSystemControl, ShmCell};
use zweidraehte_conformance::dut::link::{IpcLinkLayerBuilder, set_primary_socket_fd};
use zweidraehte_conformance::dut::system7_stack::{
    ConformanceSystem7MemoryMap, IpcSystem7TestStack, System7DutConfig, comm_objs, device_info,
    state_init_from_snapshot,
};
use zweidraehte_conformance::ipc::shm::SharedMemory;

use zweidraehte_device::objects::comm::{ComObjectEvent, ComObjectIndex, ComObjects};
use zweidraehte_device::storage::NoSaveGuard;
use zweidraehte_device::{Runner, Stack, StackResources};
use zweidraehte_proto::dpt::DPT_Switch;
use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};

// ============================================================================
// Static Resources
// ============================================================================

static STACK_RESOURCES: StaticCell<StackResources<IpcSystem7TestStack, { device_info::BUFFER_SIZE }, 4>> =
    StaticCell::new();
static INJECTION_BUFFERS: StaticCell<[[u8; device_info::BUFFER_SIZE]; 16]> = StaticCell::new();
static INJECTION_BUFFER_MANAGER: StaticCell<BufferManager<16>> = StaticCell::new();
static COMMAND_CHANNEL: StaticCell<CommandChannel> = StaticCell::new();
static SHM: StaticCell<ShmCell> = StaticCell::new();
static STORAGE: StaticCell<DutConfigStore<IpcSystem7TestStack>> = StaticCell::new();

// The device stack's own persistence task — the same one every firmware
// target runs, which is the point: its restart ordering is what we want
// under test. `DutSystemControl` exits the process in place of pulling a
// reset line, and the runner respawns us from the snapshot the task just
// saved.
zweidraehte_device::storage_task! {
    device: IpcSystem7TestStack,
    system: DutSystemControl,
    guard: NoSaveGuard,
}

// ============================================================================
// Embassy tasks
// ============================================================================

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, IpcSystem7TestStack>) {
    runner.run().await;
}

#[embassy_executor::task]
async fn handle_commands(
    stack: Stack<'static, IpcSystem7TestStack>,
    commands: &'static CommandChannel,
    shm: &'static ShmCell,
) {
    loop {
        let cmd = commands.receive().await;
        dut_common::handle_ipc_command::<IpcSystem7TestStack>(stack, shm, cmd).await;
    }
}

/// Mirror Management association-table inputs to their status objects.
///
/// This is application behavior: the resulting writes still pass through the
/// ordinary Group Object Server and the configured association table.
#[embassy_executor::task]
async fn run_association_application(stack: Stack<'static, IpcSystem7TestStack>) {
    let mut events = stack.events();

    loop {
        let (input, event) = events.next_message_pure().await;

        if event != ComObjectEvent::Updated {
            continue;
        }

        let status = match input {
            comm_objs::Index::AssociationInputA => comm_objs::Index::AssociationStatusA,
            comm_objs::Index::AssociationInputB => comm_objs::Index::AssociationStatusB,
            _ => continue,
        };

        let value = {
            let objects = stack.objects().borrow();
            objects
                .value(input.index())
                .and_then(|value| value.first())
                .copied()
                .expect("association input has one byte")
        };

        if let Err(error) = stack.update_object(status, DPT_Switch::from(value != 0)).await {
            log::warn!("association status object update failed: {error:?}");
        }
    }
}

// ============================================================================
// Entry point
// ============================================================================

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let (shm_fd, socket_fd) = dut_common::parse_args("conformance-dut-system7");

    set_primary_socket_fd(socket_fd);
    dut_common::init_ipc_logger(dut_common::log_level_from_env());

    // SAFETY: the parent passed us a valid fd for a SHM region.
    let mut shm = unsafe { SharedMemory::from_raw_fd(shm_fd) }.expect("map shared memory");

    // Deserialize state from SHM. A blank region means the parent wants
    // us factory-fresh, so we seed it ourselves — the parent never
    // constructs a snapshot.
    let snapshot = dut_common::load_or_seed_snapshot(&mut shm, System7DutConfig::default_snapshot);

    let state_init = state_init_from_snapshot(snapshot);
    let shm = SHM.init(ShmCell::new(shm));
    let storage = &*STORAGE.init(DutConfigStore::new(shm));

    let buffers = INJECTION_BUFFERS.init([[0u8; device_info::BUFFER_SIZE]; 16]);
    // SAFETY: single-threaded buffer manager over our static buffers.
    let buffer_manager = INJECTION_BUFFER_MANAGER.init(unsafe { BufferManager::new(buffers) });
    let dyn_buffer_manager = buffer_manager.dyn_buffer_manager();
    // SAFETY: buffer manager lives in a StaticCell ('static).
    let dyn_buffer_manager: DynBufferManager<'static> = unsafe { core::mem::transmute(dyn_buffer_manager) };

    let command_channel: &'static CommandChannel = COMMAND_CHANNEL.init(CommandChannel::new());
    let command_tx = command_channel.dyn_sender();

    let link_layer_builder =
        IpcLinkLayerBuilder::new(socket_fd, dyn_buffer_manager, command_tx).expect("build IPC link layer");

    let resources = STACK_RESOURCES.init(StackResources::new());

    let (stack, runner) = zweidraehte_device::new(
        resources,
        link_layer_builder,
        state_init,
        (),
        ConformanceSystem7MemoryMap::new(),
        storage,
    );

    // The shadow-object hook needs the live CoTab; the stack's tables live in
    // STACK_RESOURCES, which is 'static, so the pointer remains valid for the
    // process.
    // SAFETY: the pointer outlives the stack (process-lifetime).
    unsafe {
        zweidraehte_conformance::dut::system7_stack::set_system7_cot(stack.communication_object_table());
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

    // Register before the runner can publish the first incoming bus update.
    spawner.spawn(run_association_application(stack)).expect("spawn association application");
    spawner.spawn(run_stack(runner)).expect("spawn stack runner");
    spawner.spawn(handle_commands(stack, command_channel, shm)).expect("spawn command handler");
    spawner.spawn(storage_task(stack)).expect("storage_task spawnable once");

    // Main keeps the executor alive; the worker tasks handle IO.
    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}
