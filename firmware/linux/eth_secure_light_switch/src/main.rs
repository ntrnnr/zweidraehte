// The standard secure IP preset derives table and link-layer capacities in
// generic const expressions. Same flag `zweidraehte-device` already requires.
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
//! - **FDSK lives in the identity file.** The serial number and FDSK are
//!   provisioned to `secure_device_identity.json` on first run (from
//!   [`DEFAULT_SERIAL_NUMBER`] / [`DEFAULT_FDSK`]) and read back on every
//!   later boot, so the key can be changed per device without a rebuild.
//!   It is stored in plaintext with no readout protection — protect it with
//!   file permissions; a real deployment provisions a unique key during
//!   manufacturing.
//! - **Sequence/SIAT durability.** The file-backed SIAT store
//!   ([`support::storage::open_siat_store`]) persists the sending counter, tool
//!   counter, and SIAT so a restart cannot replay already-seen frames. The
//!   IP-Secure multicast-timer watermark is *not* persisted (it re-acquires
//!   from the group on the next sync).
//!
//! Run with: `cargo run` in this directory.

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_sync::pubsub::WaitResult;
use embassy_time::Duration;
use env_logger::Env;
use static_cell::StaticCell;
use std::net::SocketAddrV4;
use zweidraehte_device::bcus::system_b::{IpSecureResources, SecureResources, SystemBStateInit};
use zweidraehte_device::layers::linklayers::knxip::KnxNetIpBuilder;
use zweidraehte_device::prelude::*;
use zweidraehte_device::storage::{NoSaveGuard, SecureDeviceIdentity, SecureStorage, StaticIdentity};
use zweidraehte_platform::LinuxSystem;

use devices::light_switch::{
    LightSwitchDevice,
    full::{self as app, ButtonId},
};
use support::storage::{FileSecureIdentity, JsonStorage, open_siat_store};
use support::util::{
    EvdevButton, EvdevButtonId, EvdevChannels, keyboard, open_keyboard, resolve_knx_interface, spawn_evdev_reader,
    terminal_key_to_button,
};

mod stack;
use stack::{LightSwitchSecureState, LightSwitchSecureStorage, LinuxEthSecureLightSwitch};

// All persistence (on-demand saves, the periodic dirty poll, restart handling)
// runs through the framework's generic `storage_task`. `SecureStorage`'s
// `StorageHooks::erase` also re-inits a near-exhausted sending counter on a
// factory reset (03/05/01 §6.1.4), which the old hand-rolled handler never did.
zweidraehte_device::storage_task! {
    device: LinuxEthSecureLightSwitch,
    system: LinuxSystem,
    guard: NoSaveGuard,
}

/// Default path for the device state JSON file (config only — the sequence
/// state lives in its own file, see [`SEQ_FILE_PATH`]).
const STATE_FILE_PATH: &str = "secure_light_switch_device_state.json";

/// Path for the file-backed sequence/SIAT store.
const SEQ_FILE_PATH: &str = "secure_light_switch_seq.bin";

/// Path for the device identity file (serial number + FDSK).
///
/// Created automatically on first run from the defaults below; edit the file
/// (or provision it ahead of time) to give the device a different serial or
/// key without rebuilding. See [`FileSecureIdentity`].
const IDENTITY_FILE_PATH: &str = "secure_device_identity.json";

/// Default factory serial number, used only when provisioning a fresh
/// [`IDENTITY_FILE_PATH`] — the serial the knxprod generator files under the
/// IP-Secure hardware entry (`SERIAL_NUMBER_IP_SECURE` in
/// `gen_light_switch_mtxml`).
const DEFAULT_SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x09];

/// Dev-default Factory Default Setup Key, used only when provisioning a fresh
/// [`IDENTITY_FILE_PATH`]. Seeds both the IP Secure Device Authentication Code
/// (PID 92) and the Data Secure tool key (Security IO PID 56).
///
/// **Not for production** — every device that boots without an identity file
/// gets this same key. A real device provisions a unique FDSK during
/// manufacturing and prints it on the label for ETS.
const DEFAULT_FDSK: [u8; 16] =
    [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

// ============================================================================
// Main Entry Point
// ============================================================================

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, LinuxEthSecureLightSwitch>) {
    println!("Running KNX/IP Secure light switch stack...");
    runner.run().await;
}

// ============================================================================
// Button emulation (keyboard via evdev)
// ============================================================================

/// Button application task — identical to the plain target's, but the group
/// telegrams it triggers are Data-Secure-encrypted once ETS has provisioned
/// keys (the Secure Application Layer wraps them transparently). Buttons are
/// inert until ETS downloads and starts the application (`is_running`).
#[embassy_executor::task]
async fn app_task(knx: Stack<'static, LinuxEthSecureLightSwitch>, mut btn1: EvdevButton, mut btn2: EvdevButton) -> ! {
    let mut btn1_state = app::ButtonState::new();
    let mut btn2_state = app::ButtonState::new();

    loop {
        if !knx.state().is_running() {
            embassy_time::Timer::after(Duration::from_millis(200)).await;
            continue;
        }

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

    // File-backed secure identity: serial + FDSK, provisioned with the dev
    // defaults on first run. Editing the file (or provisioning it beforehand)
    // changes the device's key without a rebuild.
    let identity = FileSecureIdentity::load_or_provision(IDENTITY_FILE_PATH, DEFAULT_SERIAL_NUMBER, DEFAULT_FDSK)
        .expect("load or provision secure device identity");

    println!("Device Configuration:");
    println!("  Mask Version: 57B0 (System B KNX/IP), IP Secure + Data Secure");
    println!("  Serial Number: {:02X?}", identity.serial_number());
    println!("  Manufacturer ID: {:04X}", LightSwitchDevice::MANUFACTURER_ID);
    println!(
        "  Application:     {:04X} v{:02X}",
        LightSwitchDevice::APPLICATION_ID_IP_SECURE,
        LightSwitchDevice::APPLICATION_VERSION
    );
    println!("  Identity file:   {}", IDENTITY_FILE_PATH);
    // ETS needs this key to commission the device; print the same label + QR
    // the `knx-provision` tool puts on physical device labels, so the operator
    // can scan it instead of opening the identity file.
    fdsk_label::print_label(identity.serial_number(), identity.fdsk(), "  ");
    println!();

    // Both persistent stores ride on the stack in one `SecureStorage` handle:
    // the JSON config blob and the file-backed sequence/SIAT store. Booting the
    // seq store reconstructs the sending / tool counters and the SIAT from the
    // file (defaults for a fresh file); a boot failure is fatal — without
    // durable counters the device cannot offer cross-reboot replay protection,
    // so we refuse to start. The config backend keeps the serial only — it
    // never touches the FDSK, which stays with the device identity.
    let seq = open_siat_store(SEQ_FILE_PATH).expect("open sequence/SIAT store");
    let config =
        JsonStorage::<LightSwitchSecureState, _>::new(STATE_FILE_PATH, StaticIdentity::new(*identity.serial_number()));
    static STORAGE: StaticCell<LightSwitchSecureStorage> = StaticCell::new();
    let storage = &*STORAGE.init(SecureStorage::new(config, seq));

    // Load the persisted config once at boot to seed `create_state` (which the
    // runner calls later, with access to the `LayerContext`). A blank or
    // unreadable file yields `None` and the device boots from factory defaults.
    let loaded_config = storage.load_config();
    if loaded_config.is_some() {
        println!("Loaded device config from {}", STATE_FILE_PATH);
    } else {
        println!("No stored config found, starting fresh");
    }

    // Data Secure construction resources: the IP Secure FDSK seed (`inner`) and
    // the Data Secure tool-key FDSK seed. Both take the same physical value from
    // the identity — one seeds the IP Secure Device Authentication Code (PID
    // 92), the other the Data Secure tool key (Security IO PID 56).
    let fdsk = *identity.fdsk();
    let resources = SecureResources { inner: IpSecureResources { fdsk }, fdsk };
    let state_init = SystemBStateInit { identity, loaded_config, resources };

    // Which interface the device lives on is a property of the host, not of
    // the firmware, so it is resolved at startup (`--interface` / the
    // `KNX_INTERFACE` environment variable, else auto-detected) rather than
    // compiled in.
    let (interface_name, interface_addr) = resolve_knx_interface();

    // The read-only platform reports the host's actual network configuration.
    let platform = zweidraehte_platform::LinuxIpPlatform::new(interface_name);
    let control_endpoint = SocketAddrV4::new(interface_addr, 3671);

    let link_layer_builder =
        KnxNetIpBuilder::<LinuxEthSecureLightSwitch>::new(interface_name, interface_addr, control_endpoint, ());

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
        storage,
    );

    spawner.spawn(run_stack(runner)).unwrap();
    // The generic storage task owns restart handling and all persistence
    // (on-demand saves, the ETS-download persist, and the periodic dirty poll).
    spawner.spawn(storage_task(stack)).expect("storage_task spawnable once");

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
