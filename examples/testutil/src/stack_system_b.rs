//! System B Device Test Utility
//!
//! Binary entry point for running the System B KNX/IP demo device.
//! The device definition (parameters, comm objects, stack traits) lives in
//! [`testutil::devices::system_b_demo`]; this file only contains the runtime
//! logic: state persistence, restart handling, and the main event loop.
//!
//! Run with: `cargo run --bin stack_system_b`

use embassy_executor::Spawner;
use embassy_sync::pubsub::WaitResult;
use embassy_time::Duration;
use env_logger::Env;
use static_cell::StaticCell;
use std::net::SocketAddrV4;
use zweidraehte_device::prelude::*;
use zweidraehte_device::{
    bcus::system_b::{SystemBStackDefinition, SystemBStateInit},
    layers::linklayers::knxip::KnxNetIpBuilder,
    restart::EraseCode,
};

use testutil::devices::system_b_demo::*;
use testutil::storage::{FileIdentity, JsonStorage};
use testutil::util::keyboard;

/// Default path for the device state JSON file.
const STATE_FILE_PATH: &str = "system_b_device_state.json";

/// Default path for the device identity file.
///
/// Contains the factory-programmed serial number in JSON format.
/// Created automatically on first run with the default serial from
/// the device definition. See [`FileIdentity`] for details.
const IDENTITY_FILE_PATH: &str = "device_identity.json";

// ============================================================================
// State Persistence
// ============================================================================

/// Save the current device state to JSON storage.
fn save_state(state: &DemoState, storage: &mut JsonStorage<DemoState, FileIdentity>) {
    match storage.save(state) {
        Ok(()) => {
            state.clear_dirty();
            log::info!("State saved to {}", STATE_FILE_PATH);
        }
        Err(e) => log::error!("Failed to save state: {}", e),
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, DemoStack>) {
    println!("Running System B KNX/IP stack...");
    runner.run().await;
}

/// Restart handler task — executes resets, persists state, and triggers restart.
///
/// When the stack receives an A_Restart message, this task:
/// 1. Executes the appropriate reset based on the erase code
/// 2. Saves the modified state to JSON
/// 3. Sends the A_Restart_Response back to the stack
/// 4. Waits briefly for the response to be sent on the bus
/// 5. Re-execs the process via `LinuxSystem::restart()`
#[embassy_executor::task]
async fn handle_restarts(stack: Stack<'static, DemoStack>) {
    println!("Restart handler task started");

    // The loop body either performs a process re-exec (which doesn't return)
    // or panics on failure, so it effectively runs at most once.
    #[allow(clippy::never_loop)]
    loop {
        let request = stack.receive_restart_request().await;
        let state = stack.state();

        println!("\n********************************************");
        println!("*** RESTART REQUEST RECEIVED ***");
        println!("*** Erase Code: {} ***", request.erase_code);
        println!("*** Channel: {} ***", request.channel);
        println!("*** Access Level: {:?} ***", request.access_ctx);
        println!("*** Needs Response: {} ***", request.needs_response);
        println!("********************************************\n");

        // The stack already sent the A_Restart_Response on the bus before
        // delivering this request. We just need to execute the reset.
        match request.erase_code {
            EraseCode::Basic | EraseCode::Confirmed => {
                println!("Performing basic restart (no data reset)...");
            }
            EraseCode::FactoryReset => {
                println!("Performing FACTORY RESET — all data will be cleared!");
                state.factory_reset();
            }
            EraseCode::ResetIA => {
                println!("Resetting Individual Address to 15.15.255...");
                state.reset_individual_address();
            }
            EraseCode::ResetAP => {
                println!("Resetting Application Program...");
                state.reset_application();
            }
            EraseCode::ResetParam => {
                println!("Resetting Parameters to defaults...");
                state.reset_parameters();
            }
            EraseCode::ResetLinks => {
                println!("Resetting links (Group Address + Association tables)...");
                state.apply_erase_code(EraseCode::ResetLinks);
            }
            EraseCode::FactoryResetKeepIA => {
                println!("Performing Factory Reset (keeping Individual Address)...");
                state.factory_reset_keep_ia();
            }
            EraseCode::Other(code) => {
                println!("Unsupported erase code: 0x{:02X} — ignoring", code);
            }
        }

        // Persist the post-reset state before restarting so it survives
        // the process re-exec.
        if state.is_dirty() {
            // Construct a temporary storage with the same identity for the
            // restart handler. The identity file was already provisioned at
            // startup, so this just re-reads it.
            let identity = FileIdentity::load_or_provision(IDENTITY_FILE_PATH, SERIAL_NUMBER)
                .expect("load device identity for restart save");
            save_state(state, &mut JsonStorage::new(STATE_FILE_PATH, identity));
        }

        // Give the stack a moment to send the response on the bus.
        embassy_time::Timer::after(Duration::from_millis(100)).await;

        // Re-exec the process. This call does not return on success.
        use zweidraehte_platform::SystemControl;
        let mut system = zweidraehte_platform::LinuxSystem;
        let Err(e) = system.restart().await;
        panic!("Failed to restart: {:?}", e);
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    println!("=== System B Device Test Utility ===\n");

    // Load device identity from file (provisions with default serial on first run).
    let identity =
        FileIdentity::load_or_provision(IDENTITY_FILE_PATH, SERIAL_NUMBER).expect("load or provision device identity");

    // Print device information
    println!("Device Configuration:");
    println!("  Mask Version: {}", DEVICE_DESCRIPTOR.mask_version);
    println!("  Serial Number: {:02X?}", identity.serial_number());
    println!("  Manufacturer ID: {:04X}", DEVICE_DESCRIPTOR.manufacturer_id);
    println!();

    // Load device config from storage. The actual runtime state is
    // constructed later by the runner via `create_state`, which has access to
    // the `LayerContext`.
    let mut storage = JsonStorage::<DemoState, _>::new(STATE_FILE_PATH, identity);
    let loaded_config = match storage.load_config() {
        Ok(Some(config)) => {
            println!("Loaded device config from {}", STATE_FILE_PATH);
            Some(config)
        }
        Ok(None) => {
            println!("No stored config found, starting fresh");
            None
        }
        Err(e) => {
            println!("Error loading device config: {}", e);
            None
        }
    };
    let state_init = SystemBStateInit::new(StaticIdentity::new(*storage.identity().serial_number()), loaded_config);

    // Create KNX/IP link layer
    let control_endpoint = SocketAddrV4::new("192.168.1.200".parse().unwrap(), 3671);

    let interface_addr =
        zweidraehte_platform::get_interface_address(INTERFACE_NAME).expect("Failed to get interface address");
    // Features (routing + remote-config + TCP) and sizing (UDP socket
    // pool, TCP stream count, etc.) all flow from `DemoStack`'s
    // `KnxNetIpDefinition` impl. No more enable_*() chain — features
    // are pinned by `Definition::Features = KnxIpDeviceTcp`.
    let link_layer_builder = KnxNetIpBuilder::<DemoStack>::new(INTERFACE_NAME, interface_addr, control_endpoint, ());

    // Create stack resources and initialize the stack
    static RESOURCES: StaticCell<
        StackResources<
            DemoStack,
            { zweidraehte_device::config::buffer_size_for_apdu(<DemoStack as StackDefinition>::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();
    let (stack, runner) = zweidraehte_device::new(
        RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        MockIpPlatform::default(),
        DemoStack::memory_map(),
        (),
    );

    spawner.spawn(run_stack(runner)).unwrap();
    spawner.spawn(handle_restarts(stack)).unwrap();

    println!("=== Stack Running ===");
    println!("Listening for KNX messages...");
    println!("Press 'p' to toggle programming mode, 'q' to quit\n");

    // Main application loop
    let mut events = stack.events();
    let mut last_print = embassy_time::Instant::now();

    loop {
        // Check for keyboard input (non-blocking)
        if let Some(key) = keyboard::poll_key() {
            match key {
                'p' | 'P' => {
                    let interface_objects = stack.interface_objects();
                    let current_mode = interface_objects.is_programming_mode();
                    interface_objects.set_programming_mode_enabled(!current_mode);
                    let new_mode = interface_objects.is_programming_mode();
                    let current_addr = stack.state().individual_address();
                    println!("\n********************************************");
                    println!("*** Programming mode: {} ***", if new_mode { "ENABLED" } else { "DISABLED" });
                    println!("*** Current address: {} ***", current_addr);
                    println!("*** Device will respond to IndividualAddress_Read ***");
                    println!("*** Device will accept IndividualAddress_Write ***");
                    println!("********************************************\n");
                }
                'q' | 'Q' => {
                    println!("\nShutting down...");
                    if stack.state().is_dirty() {
                        save_state(stack.state(), &mut storage);
                    }
                    break;
                }
                _ => {}
            }
        }

        if embassy_time::Instant::now().duration_since(last_print) > Duration::from_secs(10) {
            let objects = stack.objects();
            let co_borrow = objects.borrow();
            let interface_objects = stack.interface_objects();
            let state = stack.state();
            let app = state.app().borrow();

            println!("\n--- Device Status ---");
            println!(
                "  Programming mode: {}",
                if interface_objects.is_programming_mode() { "ENABLED" } else { "DISABLED" }
            );
            println!("  Application state: Loaded={}, Running={}", app.is_loaded(), app.is_running());

            println!("  Communication Objects:");
            for i in 1..=4u16 {
                println!("    CO {}: {:02X?}", i, co_borrow.value(i));
            }

            // Print application parameters if loaded
            if app.is_loaded() {
                let params = app.params();
                let raw_bytes: &[u8] = unsafe {
                    core::slice::from_raw_parts(params as *const _ as *const u8, core::mem::size_of_val(params))
                };
                println!("  Application Parameters (raw {} bytes): {:02X?}", raw_bytes.len(), raw_bytes);
                println!("  Application Parameters:");

                print!("    Channel A Config: ");
                match &params.channel_a_config {
                    OutputConfig::Disabled => println!("Disabled"),
                    OutputConfig::Switch { invert } => println!("Switch (invert: {:?})", invert),
                    OutputConfig::Dimmer { min_level, max_level } => {
                        println!("Dimmer (range: {}-{})", min_level, max_level)
                    }
                    OutputConfig::Pwm { frequency, duty_cycle } => {
                        println!("PWM (freq: {} Hz, duty: {}%)", frequency, duty_cycle)
                    }
                }

                print!("    Channel B Config: ");
                match &params.channel_b_config {
                    OutputConfig::Disabled => println!("Disabled"),
                    OutputConfig::Switch { invert } => println!("Switch (invert: {:?})", invert),
                    OutputConfig::Dimmer { min_level, max_level } => {
                        println!("Dimmer (range: {}-{})", min_level, max_level)
                    }
                    OutputConfig::Pwm { frequency, duty_cycle } => {
                        println!("PWM (freq: {} Hz, duty: {}%)", frequency, duty_cycle)
                    }
                }

                println!("    Send Cycle Time: {}s", params.send_cycle_time.get());
                println!("    Lock Behavior: {}", match params.lock_behavior {
                    0 => "No Action",
                    1 => "Lock Off",
                    2 => "Lock On",
                    3 => "Lock Toggle",
                    _ => "Unknown",
                });

                match &params.scene_config {
                    SceneConfig::Disabled => {
                        println!("    Scene Config: Disabled");
                    }
                    SceneConfig::RecallOnly { scene_number } => {
                        println!("    Scene Config: Recall Only (Scene: {})", scene_number);
                    }
                    SceneConfig::StoreAndRecall { scene_number, store_time } => {
                        println!(
                            "    Scene Config: Store & Recall (Scene: {}, Store Time: {}00ms)",
                            scene_number, store_time
                        );
                    }
                }
            } else {
                println!("  Application Parameters: Not loaded");
            }

            println!("---------------------\n");
            last_print = embassy_time::Instant::now();

            // Periodically persist any state changes from ETS programming
            // (table writes, parameter changes, address changes, etc.).
            if stack.state().is_dirty() {
                save_state(stack.state(), &mut storage);
            }
        }

        match embassy_time::with_timeout(Duration::from_millis(100), events.next_message()).await {
            Ok(WaitResult::Message((index, event))) => {
                println!("Event: {:?} on CO {}", event, index.index());
            }
            Ok(WaitResult::Lagged(count)) => println!("Warning: Missed {} events", count),
            Err(_) => {}
        }
    }
}
