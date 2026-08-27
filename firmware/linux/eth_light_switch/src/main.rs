//! Linux-hosted KNX/IP light switch.
//!
//! Binary entry point for running the shared [`devices::light_switch`]
//! definition on the host over KNX/IP (UDP + TCP, routing + remote config, no
//! tunnelling). The device definition (parameters, comm objects, page layout)
//! lives in [`devices::light_switch`]; the Linux-specific stack wiring is in
//! [`stack`]; this file contains the runtime logic: state persistence, restart
//! handling, and the main event loop.
//!
//! Run with: `cargo run` in this directory.

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_sync::pubsub::WaitResult;
use embassy_time::Duration;
use env_logger::Env;
use static_cell::StaticCell;
use std::net::SocketAddrV4;
use zweidraehte_device::prelude::*;
use zweidraehte_device::storage::{ConfigStorage, NoSaveGuard};
use zweidraehte_device::{bcus::system_b::SystemBStateInit, layers::linklayers::knxip::KnxNetIpBuilder};
use zweidraehte_platform::LinuxSystem;

use devices::light_switch::{
    LightSwitchDevice,
    full::{self as app, ButtonId},
};
use support::storage::{FileIdentity, JsonStorage};
use support::util::{
    EvdevButton, EvdevButtonId, EvdevChannels, keyboard, open_keyboard, resolve_knx_interface, spawn_evdev_reader,
    terminal_key_to_button,
};

mod stack;
use stack::{LightSwitchStorage, LinuxEthLightSwitch};

// All persistence (on-demand saves, the periodic dirty poll, restart handling)
// runs through the framework's generic `storage_task`, spawned in `main`. This
// monomorphic wrapper is what the embassy executor spawns — the same shape
// every embedded device uses. KNX/IP saves never stall a link layer, so the
// guard is `NoSaveGuard`; a re-exec on restart is `LinuxSystem`.
zweidraehte_device::storage_task! {
    device: LinuxEthLightSwitch,
    system: LinuxSystem,
    guard: NoSaveGuard,
}

/// Default path for the device state JSON file.
const STATE_FILE_PATH: &str = "light_switch_device_state.json";

/// Default path for the device identity file.
///
/// Contains the factory-programmed serial number in JSON format. Created
/// automatically on first run with the default serial below. See
/// [`FileIdentity`] for details.
const IDENTITY_FILE_PATH: &str = "device_identity.json";

/// Factory serial number for the KNX/IP light switch — the same serial the
/// knxprod generator files under the IP hardware entry (`SERIAL_NUMBER_IP` in
/// `gen_light_switch_mtxml`), so a device provisioned from this binary matches
/// the catalogue entry.
const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x03];

// ============================================================================
// Main Entry Point
// ============================================================================

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, LinuxEthLightSwitch>) {
    println!("Running KNX/IP light switch stack...");
    runner.run().await;
}

// ============================================================================
// Button emulation (keyboard via evdev)
// ============================================================================

/// Button application task — the host twin of the RP2040 `app_task`.
///
/// Reads emulated presses from the keyboard (key `1` = Button 1, key `2` =
/// Button 2, via evdev) and drives the shared light-switch app logic. Buttons
/// are inert until ETS has downloaded and started the application
/// (`is_running`), because the parameter memory and comm objects are not
/// configured before then.
#[embassy_executor::task]
async fn app_task(knx: Stack<'static, LinuxEthLightSwitch>, mut btn1: EvdevButton, mut btn2: EvdevButton) -> ! {
    // Per-button dimming direction, flipped on each long press so the user can
    // reverse direction.
    let mut btn1_state = app::ButtonState::new();
    let mut btn2_state = app::ButtonState::new();

    loop {
        if !knx.state().is_running() {
            embassy_time::Timer::after(Duration::from_millis(200)).await;
            continue;
        }

        // Re-read parameters each iteration so a fresh ETS download takes effect
        // immediately.
        let params = *knx.state().app().borrow().params();
        let debounce = params.debounce_time.as_duration();
        let long_press = params.long_press_time.as_duration();

        match select(btn1.wait_for_event(debounce, Some(long_press)), btn2.wait_for_event(debounce, Some(long_press)))
            .await
        {
            Either::First(event) => {
                app::handle_button_event(&knx, &params, event, ButtonId::Btn1, &mut btn1_state).await;
            }
            Either::Second(event) => {
                app::handle_button_event(&knx, &params, event, ButtonId::Btn2, &mut btn2_state).await;
            }
        }
    }
}

/// Terminal-fallback hold for a **short** press: comfortably under any
/// realistic long-press threshold so it classifies as [`ButtonEvent::ShortPress`].
const TERMINAL_SHORT_HOLD: Duration = Duration::from_millis(20);

/// Terminal-fallback hold for a **long** press: comfortably over the default
/// 500 ms long-press threshold so it classifies as [`ButtonEvent::LongPressStart`]
/// and then self-releases (dimming/blind-move runs for roughly this long).
const TERMINAL_LONG_HOLD: Duration = Duration::from_millis(800);

/// Inject one synthetic terminal press (down, hold, up) into the button
/// channels. Spawned per keypress so the hold does not block the main loop.
#[embassy_executor::task(pool_size = 4)]
async fn inject_task(channels: &'static EvdevChannels, button: EvdevButtonId, hold: Duration) {
    channels.inject_press(button, hold).await;
}

/// Set up keyboard button emulation and spawn the button task.
///
/// Prefers **evdev** (`/dev/input/event*`), which gives true key press/hold/
/// release semantics — but that needs `input`-group membership or root. When
/// evdev is not accessible, falls back to reading `1`/`2` (and `!`/`@` for long
/// press) from the **terminal**, alongside the existing `p`/`q` keys — zero
/// privilege, works over SSH, at the cost of a terminal having no key-release
/// (long press is a distinct key, and resolves after the app's long-press
/// window rather than on a real release).
///
/// Always spawns the [`app_task`]; the button edges come from the evdev reader
/// thread or, in fallback mode, from the main loop injecting into the returned
/// channels. Returns `Some(channels)` in terminal-fallback mode (the main loop
/// must inject), `None` when evdev drives the channels directly.
fn spawn_button_emulation(
    spawner: &Spawner,
    stack: Stack<'static, LinuxEthLightSwitch>,
) -> Option<&'static EvdevChannels> {
    static CHANNELS: StaticCell<EvdevChannels> = StaticCell::new();
    let channels = &*CHANNELS.init(EvdevChannels::new());
    let (btn1, btn2) = EvdevButton::pair(channels);
    spawner.spawn(app_task(stack, btn1, btn2)).expect("app_task spawnable once");

    match open_keyboard(None) {
        Ok(device) => {
            spawn_evdev_reader(device, channels);
            println!("Button emulation (evdev): press keys '1' / '2' to actuate Button 1 / 2");
            println!("  (short tap = short press, hold = long press; acts only after ETS loads the app)");
            None
        }
        Err(e) => {
            log::info!("evdev unavailable ({e}); using terminal button fallback");
            println!("Button emulation (terminal): press '1' / '2' for a short press, '!' / '@' for a long press");
            println!("  (for true press/hold, run with evdev access — root or the `input` group)");
            println!("  (acts only after ETS loads the app)");
            Some(channels)
        }
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    println!("=== KNX/IP Light Switch (Linux) ===\n");

    // Load device identity from file (provisions with default serial on first run).
    let identity =
        FileIdentity::load_or_provision(IDENTITY_FILE_PATH, SERIAL_NUMBER).expect("load or provision device identity");

    // Print device information
    println!("Device Configuration:");
    println!("  Mask Version: 57B0 (System B KNX/IP)");
    println!("  Serial Number: {:02X?}", identity.serial_number());
    println!("  Manufacturer ID: {:04X}", LightSwitchDevice::MANUFACTURER_ID);
    println!(
        "  Application:     {:04X} v{:02X}",
        LightSwitchDevice::APPLICATION_ID_IP,
        LightSwitchDevice::APPLICATION_VERSION
    );
    println!();

    // The config store rides on the stack: wrap the JSON-file backend in the
    // framework's `ConfigStorage` composite and promote it to `'static` so the
    // shared `storage_task` (spawned below) can reach it through
    // `HasConfigStore`. The serial is captured before the identity moves into
    // the backend, to seed the runtime state's own identity.
    let serial = *identity.serial_number();
    static STORAGE: StaticCell<LightSwitchStorage> = StaticCell::new();
    let storage = &*STORAGE.init(ConfigStorage::new(JsonStorage::new(STATE_FILE_PATH, identity)));

    // Load the persisted config once at boot to seed `create_state` (which the
    // runner calls later, with access to the `LayerContext`). A blank or
    // unreadable file yields `None` and the device boots from factory defaults.
    let loaded_config = storage.load_config();
    if loaded_config.is_some() {
        println!("Loaded device config from {}", STATE_FILE_PATH);
    } else {
        println!("No stored config found, starting fresh");
    }
    let state_init = SystemBStateInit::new(StaticIdentity::new(serial), loaded_config);

    // Which interface the device lives on is a property of the host, not of
    // the firmware, so it is resolved at startup (`--interface` / the
    // `KNX_INTERFACE` environment variable, else auto-detected) rather than
    // compiled in.
    let (interface_name, interface_addr) = resolve_knx_interface();

    // The read-only platform reports the host's actual network configuration
    // to the stack (the OS owns networking, so KNX-driven reconfiguration is a
    // no-op).
    let platform = zweidraehte_platform::LinuxIpPlatform::new(interface_name);
    let control_endpoint = SocketAddrV4::new(interface_addr, 3671);

    // Features (routing + remote config + TCP) and sizing all flow from
    // `LinuxEthLightSwitch`'s `KnxNetIpDefinition` impl — features are pinned
    // by `Definition::Features = KnxIpDeviceTcp`.
    let link_layer_builder =
        KnxNetIpBuilder::<LinuxEthLightSwitch>::new(interface_name, interface_addr, control_endpoint, ());

    // Create stack resources and initialize the stack.
    static RESOURCES: StaticCell<
        StackResources<
            LinuxEthLightSwitch,
            {
                zweidraehte_device::config::buffer_size_for_apdu(
                    <LinuxEthLightSwitch as StackDefinition>::MAX_APDU_LENGTH,
                )
            },
        >,
    > = StaticCell::new();
    let (stack, runner) = zweidraehte_device::new(
        RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        platform,
        LinuxEthLightSwitch::memory_map(),
        storage,
    );

    spawner.spawn(run_stack(runner)).unwrap();
    // The generic storage task owns restart handling and all persistence
    // (on-demand saves, the ETS-download persist, and the periodic dirty poll).
    spawner.spawn(storage_task(stack)).expect("storage_task spawnable once");

    // Keyboard button emulation. `Some(channels)` means we are in terminal
    // fallback mode and the main loop below must inject button edges; `None`
    // means evdev drives the buttons directly.
    let button_channels = spawn_button_emulation(&spawner, stack);

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
                    // Force a final synchronous save before exit — the storage
                    // task's dirty poll may not fire before `process::exit`.
                    if stack.state().is_dirty() {
                        storage.save_config(stack.state());
                        stack.state().clear_dirty();
                    }
                    // The embassy `arch-std` executor's `run` is `-> !` and
                    // loops forever, so a returning `main` task never ends the
                    // process — and the evdev reader is a non-daemon thread
                    // blocked in `fetch_events`. Terminate explicitly.
                    std::process::exit(0);
                }
                // Terminal button fallback: only active when evdev is
                // unavailable (`button_channels` is `Some`). `1`/`2` = short
                // press, `!`/`@` = long press.
                other => {
                    if let (Some(channels), Some((button, long))) = (button_channels, terminal_key_to_button(other)) {
                        let hold = if long { TERMINAL_LONG_HOLD } else { TERMINAL_SHORT_HOLD };
                        spawner.spawn(inject_task(channels, button, hold)).ok();
                    }
                }
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
            for i in 1..=LightSwitchDevice::MAX_COM_OBJECTS {
                println!("    CO {}: {:02X?}", i, co_borrow.value(i));
            }

            // Print the ETS-programmed parameters once the application is loaded.
            if app.is_loaded() {
                let params = app.params();
                println!("  Application Parameters:");
                println!("    Buttons mode:     {:?}", params.buttons_mode);
                println!("    Rocker direction: {:?}", params.rocker_direction);
                println!("    Button 1 config:  {:?}", params.button1_config);
                println!("    Button 2 config:  {:?}", params.button2_config);
                println!("    Debounce time:    {:?}", params.debounce_time);
                println!("    Long-press time:  {:?}", params.long_press_time);
            } else {
                println!("  Application Parameters: Not loaded");
            }

            println!("---------------------\n");
            last_print = embassy_time::Instant::now();
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
