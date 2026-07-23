// `type LightSwitchSecureState = SecureIpInterfaceStateFor<…>` expands to const
// expressions over `SystemBStackDefinition::{ADT,AST,COT}_SIZE` — the same flag
// `zweidraehte-device` already requires.
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

//! Linux-hosted **KNX IP Secure + Data Secure** light switch.
//!
//! Secure sibling of `firmware/linux/eth_light_switch`, and the host-target
//! twin of `firmware/rp2040/eth_secure_light_switch`. The device definition
//! (parameters, comm objects, page layout) lives in [`devices::light_switch`];
//! the Linux-specific secure stack wiring is in [`stack`]; this file holds the
//! runtime logic: identity + FDSK, the file-backed sequence/SIAT store, JSON
//! config persistence, restart handling, and the main event loop.
//!
//! # Security notes
//!
//! - **FDSK lives in a build-time constant.** This host shell uses a fixed dev
//!   default ([`DEV_FDSK`]); a real deployment would provision a unique key.
//!   There is no readout protection — whoever can read the process memory or
//!   the sequence file can learn nothing secret from the file (it holds only
//!   sequence numbers), but the FDSK in the binary is not protected.
//! - **Sequence/SIAT durability.** The [`LinuxSecureSeqStorage`] persists the
//!   sending counter, tool counter, and SIAT to a file so a restart cannot
//!   replay already-seen frames. The IP-Secure multicast-timer watermark is
//!   *not* persisted (it re-acquires from the group on the next sync).
//!
//! Run with: `cargo run` in this directory.

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_sync::pubsub::WaitResult;
use embassy_time::Duration;
use env_logger::Env;
use static_cell::StaticCell;
use std::net::SocketAddrV4;
use zweidraehte_device::bcus::system_b::{
    IpSecureResources, SecureResources, SystemBStackDefinition, SystemBStateInit,
};
use zweidraehte_device::layers::linklayers::knxip::KnxNetIpBuilder;
use zweidraehte_device::prelude::*;
use zweidraehte_device::restart::EraseCode;
use zweidraehte_device::storage::StaticSecureIdentity;

use devices::light_switch::{
    LightSwitchDevice,
    app::{self, ButtonId, WaitForRelease},
};
use support::storage::{JsonStorage, LinuxSecureSeqStorage};
use support::util::{
    EvdevButton, EvdevButtonId, EvdevChannels, keyboard, open_keyboard, spawn_evdev_reader, terminal_key_to_button,
};

mod stack;
use stack::{LightSwitchSecureState, LinuxEthSecureLightSwitch};

/// Network interface name for KNX/IP communication.
const INTERFACE_NAME: &str = "knxdevbridgeif";

/// Default path for the device state JSON file (config only — the sequence
/// state lives in its own file, see [`SEQ_FILE_PATH`]).
const STATE_FILE_PATH: &str = "secure_light_switch_device_state.json";

/// Path for the file-backed sequence/SIAT store.
const SEQ_FILE_PATH: &str = "secure_light_switch_seq.bin";

/// Factory serial number for the secure KNX/IP light switch — the serial the
/// knxprod generator files under the IP-Secure hardware entry
/// (`SERIAL_NUMBER_IP_SECURE` in `gen_light_switch_mtxml`).
const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x09];

/// Dev-default Factory Default Setup Key. Seeds both the IP Secure Device
/// Authentication Code (PID 92) and the Data Secure tool key (Security IO PID
/// 56). **Not for production** — a real device provisions a unique FDSK.
const DEV_FDSK: [u8; 16] =
    [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

// ============================================================================
// State Persistence
// ============================================================================

/// Save the current device config to JSON storage.
fn save_state(state: &LightSwitchSecureState, storage: &mut JsonStorage<LightSwitchSecureState, StaticSecureIdentity>) {
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
async fn run_stack(runner: Runner<'static, LinuxEthSecureLightSwitch>) {
    println!("Running KNX/IP Secure light switch stack...");
    runner.run().await;
}

/// Restart handler task — executes resets, persists state, and triggers restart.
#[embassy_executor::task]
async fn handle_restarts(stack: Stack<'static, LinuxEthSecureLightSwitch>) {
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

        // Persist the post-reset config before restarting so it survives the
        // process re-exec. The sequence/SIAT store persists itself in place.
        if state.is_dirty() {
            let identity = StaticSecureIdentity::new(SERIAL_NUMBER, DEV_FDSK);
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

// ============================================================================
// Button emulation (keyboard via evdev)
// ============================================================================

/// Bridges [`EvdevButton::wait_for_release`] to the [`WaitForRelease`] trait
/// the device application logic expects.
struct ReleaseWaiter<'a> {
    btn: &'a mut EvdevButton,
    debounce: Duration,
}

impl WaitForRelease for ReleaseWaiter<'_> {
    async fn wait_for_release(&mut self) {
        self.btn.wait_for_release(self.debounce).await;
    }
}

/// Button application task — identical to the plain target's, but the group
/// telegrams it triggers are Data-Secure-encrypted once ETS has provisioned
/// keys (the Secure Application Layer wraps them transparently). Buttons are
/// inert until ETS downloads and starts the application (`is_running`).
#[embassy_executor::task]
async fn app_task(knx: Stack<'static, LinuxEthSecureLightSwitch>, mut btn1: EvdevButton, mut btn2: EvdevButton) -> ! {
    let mut btn1_dim_up = true;
    let mut btn2_dim_up = true;

    loop {
        if !knx.state().is_running() {
            embassy_time::Timer::after(Duration::from_millis(200)).await;
            continue;
        }

        let params = *knx.state().app().borrow().params();
        let debounce = params.debounce_time.as_duration();
        let long_press = params.long_press_time.as_duration();

        match select(btn1.wait_for_press(debounce, Some(long_press)), btn2.wait_for_press(debounce, Some(long_press)))
            .await
        {
            Either::First(event) => {
                let mut waiter = ReleaseWaiter { btn: &mut btn1, debounce };
                app::handle_button_press(&knx, &params, event, ButtonId::Btn1, &mut waiter, &mut btn1_dim_up).await;
            }
            Either::Second(event) => {
                let mut waiter = ReleaseWaiter { btn: &mut btn2, debounce };
                app::handle_button_press(&knx, &params, event, ButtonId::Btn2, &mut waiter, &mut btn2_dim_up).await;
            }
        }
    }
}

/// Terminal-fallback short-press hold (see the plain target for the rationale).
const TERMINAL_SHORT_HOLD: Duration = Duration::from_millis(20);
/// Terminal-fallback long-press hold.
const TERMINAL_LONG_HOLD: Duration = Duration::from_millis(800);

/// Inject one synthetic terminal press (down, hold, up) into the button
/// channels. Spawned per keypress so the hold does not block the main loop.
#[embassy_executor::task(pool_size = 4)]
async fn inject_task(channels: &'static EvdevChannels, button: EvdevButtonId, hold: Duration) {
    channels.inject_press(button, hold).await;
}

/// Set up keyboard button emulation and spawn the button task.
///
/// Prefers evdev (true press/hold, needs `input`-group / root); falls back to
/// terminal `1`/`2` + `!`/`@` when evdev is inaccessible. See the plain target
/// (`firmware/linux/eth_light_switch`) for the full rationale. Returns
/// `Some(channels)` in terminal-fallback mode (main loop injects edges), `None`
/// when evdev drives the buttons.
fn spawn_button_emulation(
    spawner: &Spawner,
    stack: Stack<'static, LinuxEthSecureLightSwitch>,
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

    println!("=== KNX/IP Secure Light Switch (Linux) ===\n");

    // Static secure identity: serial + FDSK. On a real device the FDSK would be
    // provisioned per unit; this host shell uses a dev default.
    let identity = StaticSecureIdentity::new(SERIAL_NUMBER, DEV_FDSK);

    println!("Device Configuration:");
    println!("  Mask Version: 57B0 (System B KNX/IP), IP Secure + Data Secure");
    println!("  Serial Number: {:02X?}", identity.serial_number());
    println!("  Manufacturer ID: {:04X}", LightSwitchDevice::MANUFACTURER_ID);
    println!(
        "  Application:     {:04X} v{:02X}",
        LightSwitchDevice::APPLICATION_ID_IP_SECURE,
        LightSwitchDevice::APPLICATION_VERSION
    );
    println!();

    // Boot the file-backed sequence/SIAT store, reconstructing the sending /
    // tool counters and the SIAT from the file (defaults for a fresh file).
    // A boot failure is fatal — without durable counters the device cannot
    // offer cross-reboot replay protection, so we refuse to start.
    static STORAGE: StaticCell<LinuxSecureSeqStorage> = StaticCell::new();
    let seq_storage = &*STORAGE.init(LinuxSecureSeqStorage::open(SEQ_FILE_PATH).expect("open sequence/SIAT store"));

    // Load device config (JSON, out-of-band — the secure builder needs only the
    // seq store on the stack). The runtime state is constructed later by the
    // runner via `create_state`. `StaticSecureIdentity` is not `Clone`, so the
    // JSON storage gets its own instance built from the same constants.
    let mut storage = JsonStorage::<LightSwitchSecureState, _>::new(
        STATE_FILE_PATH,
        StaticSecureIdentity::new(SERIAL_NUMBER, DEV_FDSK),
    );
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

    // Data Secure construction resources: the IP Secure FDSK seed (`inner`) and
    // the Data Secure tool-key FDSK seed. Both take the same physical value from
    // the identity — one seeds the IP Secure Device Authentication Code (PID
    // 92), the other the Data Secure tool key (Security IO PID 56).
    let fdsk = *identity.fdsk();
    let resources = SecureResources { inner: IpSecureResources { fdsk }, fdsk };
    let state_init = SystemBStateInit { identity, loaded_config, resources };

    // The read-only platform reports the host's actual network configuration.
    let platform = zweidraehte_platform::LinuxIpPlatform::new(INTERFACE_NAME);
    let interface_addr = platform.current_ip_address();
    assert!(!interface_addr.is_unspecified(), "interface {INTERFACE_NAME} not found or has no IPv4 address");
    let control_endpoint = SocketAddrV4::new(interface_addr, 3671);

    let link_layer_builder =
        KnxNetIpBuilder::<LinuxEthSecureLightSwitch>::new(INTERFACE_NAME, interface_addr, control_endpoint, ());

    static RESOURCES: StaticCell<
        StackResources<
            LinuxEthSecureLightSwitch,
            {
                zweidraehte_device::config::buffer_size_for_apdu(
                    <LinuxEthSecureLightSwitch as StackDefinition>::MAX_APDU_LENGTH,
                )
            },
        >,
    > = StaticCell::new();
    let (stack, runner) = zweidraehte_device::new(
        RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        platform,
        LinuxEthSecureLightSwitch::memory_map(),
        seq_storage,
    );

    spawner.spawn(run_stack(runner)).unwrap();
    spawner.spawn(handle_restarts(stack)).unwrap();

    // Keyboard button emulation. `Some(channels)` = terminal fallback mode
    // (main loop injects edges); `None` = evdev drives the buttons.
    let button_channels = spawn_button_emulation(&spawner, stack);

    println!("=== Stack Running ===");
    println!("Listening for KNX messages (plain until ETS provisions keys)...");
    println!("Press 'p' to toggle programming mode, 'q' to quit\n");

    let mut events = stack.events();
    let mut last_print = embassy_time::Instant::now();

    loop {
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
                    println!("********************************************\n");
                }
                'q' | 'Q' => {
                    println!("\nShutting down...");
                    if stack.state().is_dirty() {
                        save_state(stack.state(), &mut storage);
                    }
                    // The embassy `arch-std` executor's `run` is `-> !` and
                    // loops forever, so a returning `main` task never ends the
                    // process — and the evdev reader is a non-daemon thread
                    // blocked in `fetch_events`. Terminate explicitly.
                    std::process::exit(0);
                }
                // Terminal button fallback (only when evdev is unavailable):
                // `1`/`2` = short press, `!`/`@` = long press.
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

            if app.is_loaded() {
                let params = app.params();
                println!("  Application Parameters:");
                println!("    Buttons mode:     {:?}", params.buttons_mode);
                println!("    Rocker direction: {:?}", params.rocker_direction);
                println!("    Button 1 config:  {:?}", params.button1_config);
                println!("    Button 2 config:  {:?}", params.button2_config);
            } else {
                println!("  Application Parameters: Not loaded");
            }

            println!("---------------------\n");
            last_print = embassy_time::Instant::now();

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
