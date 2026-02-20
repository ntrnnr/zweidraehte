#![no_std]
#![no_main]
#![feature(never_type)]

use core::cell::RefCell;
use core::net::Ipv4Addr;

use defmt::*;
use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_net::{DhcpConfig, StackResources as NetStackResources};
use embassy_net_wiznet::chip::W5500;
use embassy_rp::flash;
use embassy_rp::gpio::{Input, Level, Output, Pull};
use embassy_rp::peripherals::SPI0;
use embassy_rp::spi::{Async, Config as SpiConfig, Spi};
use embassy_time::{Delay, Duration, Timer};
use embedded_hal_bus::spi::ExclusiveDevice;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use devices::light_switch::{
    self, LightSwitchDevice, LightSwitchParams,
    comm_objs::{Index, LightSwitchComObjects},
    params::{ButtonConfig, ButtonsMode, RockerDirection, SwitchAction},
};

use zweidraehte::bcus::system_b::{
    DefaultKnxIpInterfaceObjects, IpSystemBDeviceState, PersistedIpConfig, PersistedState,
    StaticIdentity, SystemBIpDeviceDef, SystemBMemoryMap, create_knxip_objects,
};
use zweidraehte::dpt::*;
use zweidraehte::layers::linklayers::knxip::KnxNetIpBuilder;
use zweidraehte::messages::knxip::substructs::HPAI;
use zweidraehte::prelude::*;
use zweidraehte::restart::{RestartError, RestartResponse};
use zweidraehte::storage::DeviceStorage;

use rp_common::button::{ButtonEvent, DebouncedButton};
use rp_common::{EmbassyIpTransport, EmbassyNetworkInfo, RpFlashStorage};

// ================================================================================
// Device Definition
// ================================================================================

/// Device descriptor from the light switch device definition (KNX/IP variant).
const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_IP;

/// Serial number: manufacturer ID (0x00FA) + device-specific bytes.
/// TODO: Read from RP2040 flash unique ID for production.
const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x04];

/// MAC address for the W5500 (locally administered).
/// The W5500 has no built-in MAC, so we provide one ourselves.
/// TODO: Derive from RP2040 flash unique ID for production.
const MAC_ADDR: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x04];

/// Device state combining System B tables with IP link-layer state.
type PicoEthState = IpSystemBDeviceState<
    { DEVICE_DESCRIPTOR.address_table_size() },
    { DEVICE_DESCRIPTOR.association_table_size() },
    { DEVICE_DESCRIPTOR.comm_object_table_size() },
    LightSwitchParams,
    EmbassyNetworkInfo,
>;

/// Serializable snapshot of the full device state for flash persistence.
type PicoEthPersistedState = PersistedState<
    { DEVICE_DESCRIPTOR.address_table_size() },
    { DEVICE_DESCRIPTOR.association_table_size() },
    { DEVICE_DESCRIPTOR.comm_object_table_size() },
    LightSwitchParams,
    PersistedIpConfig,
>;

/// Flash storage handle, shared between the main loop (periodic save)
/// and the restart handler (save before reset).
type Storage = RpFlashStorage<PicoEthPersistedState>;

// ----------------------------------------------------------------------------
// SystemBIpDeviceDef + StackDefinition
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct PicoEthLightSwitch;

impl SystemBIpDeviceDef for PicoEthLightSwitch {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const INTERFACE_NAME: &'static str = "eth0";

    type P = LightSwitchParams;
    type CO = LightSwitchComObjects;
    type Transport = EmbassyIpTransport;
    type Platform = EmbassyNetworkInfo;
    type State = PicoEthState;
}

impl StackDefinition for PicoEthLightSwitch {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const TL_STYLE: TlStyle = TlStyle::Style1;

    type P = LightSwitchParams;
    type CO = LightSwitchComObjects;
    type LLB = KnxNetIpBuilder<EmbassyIpTransport, 2>;
    type State = PicoEthState;
    type Mem = SystemBMemoryMap;
    type InterfaceObjects<'a> = DefaultKnxIpInterfaceObjects<'a, PicoEthState>;

    fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
    {
        create_knxip_objects::<Self, _>(state, &Self::memory_layout())
    }
}

// ================================================================================
// GPIO Assignments
// ================================================================================

// Programming mode.
// PIN_16 = programming mode LED (active high)
// PIN_17 = programming mode button (active low, internal pull-up)

// Physical push buttons for the light switch, active low with internal pull-ups.
// PIN_18 = button 1 / "up"   ("top" in 1-function rocker mode)
// PIN_19 = button 2 / "down" ("bottom" in 1-function rocker mode)

// On-board LED.
// PIN_25 = heartbeat LED

// ================================================================================
// Embassy tasks
// ================================================================================

#[embassy_executor::task]
async fn knx_task(runner: Runner<'static, PicoEthLightSwitch>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn w5500_task(
    runner: embassy_net_wiznet::Runner<
        'static,
        W5500,
        ExclusiveDevice<Spi<'static, SPI0, Async>, Output<'static>, Delay>,
        Input<'static>,
        Output<'static>,
    >,
) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, embassy_net_wiznet::Device<'static>>) -> ! {
    runner.run().await
}

// ================================================================================
// Application Logic
// ================================================================================

/// Programming mode button handler.
///
/// Toggles programming mode on each debounced press. The LED is
/// updated from the heartbeat loop so it also tracks remote changes
/// from ETS without interfering with edge detection here.
#[embassy_executor::task]
async fn prog_task(
    knx: Stack<'static, PicoEthLightSwitch>,
    prog_btn_pin: Input<'static>,
) -> ! {
    let mut btn = DebouncedButton::new(prog_btn_pin);
    let debounce = Duration::from_millis(50);

    loop {
        // Block until a real press — long press detection is not
        // needed here, any press toggles programming mode.
        btn.wait_for_press(debounce, None).await;

        let current = knx.state().is_programming_mode();
        knx.state().set_programming_mode(!current);
        info!("Programming mode: {}", !current);
    }
}

/// Restart handler — executes resets from ETS, persists state, and reboots.
///
/// When the KNX stack receives an A_Restart request (e.g. from ETS during
/// programming or factory reset), this task:
/// 1. Executes the appropriate reset based on the erase code
/// 2. Saves the (possibly modified) state to flash
/// 3. Sends the A_Restart_Response back to the stack
/// 4. Triggers a Cortex-M system reset
#[embassy_executor::task]
async fn restart_task(
    knx: Stack<'static, PicoEthLightSwitch>,
    storage: &'static RefCell<Storage>,
) -> ! {
    use rp_common::CortexMSystem;
    use platform::SystemControl;
    use zweidraehte::restart::EraseCode;

    loop {
        let request = knx.receive_restart_request().await;
        let req = request.get();
        let state = knx.state();

        info!("Restart request: erase_code={}", req.erase_code);

        let response = match req.erase_code {
            EraseCode::Basic | EraseCode::Confirmed => {
                info!("Basic restart (no data reset)");
                RestartResponse::success()
            }
            EraseCode::FactoryReset => {
                info!("Factory reset — clearing all data");
                state.factory_reset();
                RestartResponse::success()
            }
            EraseCode::ResetIA => {
                info!("Resetting individual address");
                state.reset_individual_address();
                RestartResponse::success()
            }
            EraseCode::ResetAP => {
                info!("Resetting application program");
                state.reset_application();
                RestartResponse::success()
            }
            EraseCode::ResetParam => {
                info!("Resetting parameters");
                state.reset_parameters();
                RestartResponse::success()
            }
            EraseCode::FactoryResetKeepIA => {
                info!("Factory reset (keeping individual address)");
                state.factory_reset_keep_ia();
                RestartResponse::success()
            }
            EraseCode::ResetLinks | EraseCode::Other(_) => {
                warn!("Unsupported erase code");
                RestartResponse::error(RestartError::UnsupportedEraseCode)
            }
        };

        // Persist the post-reset state before rebooting.
        if state.is_dirty() {
            save_state(state, storage);
        }

        // Send the response back (which the stack forwards on the bus).
        request.reply(response).await;

        // Brief delay so the response can be sent on the wire.
        Timer::after(Duration::from_millis(100)).await;

        // Cortex-M system reset — does not return.
        let mut system = CortexMSystem;
        let Err(_e) = system.restart().await;
        // unreachable on success, but the compiler needs the loop
    }
}

/// Save device state to flash. Logs errors but does not propagate them
/// (flash failure is non-fatal — the device continues with in-RAM state).
fn save_state(state: &PicoEthState, storage: &RefCell<Storage>) {
    let persisted = state.to_persisted();
    match storage.borrow_mut().save(&persisted) {
        Ok(()) => {
            state.clear_dirty();
            info!("State saved to flash");
        }
        Err(e) => {
            warn!("Flash save failed: {}", e);
        }
    }
}

/// Main application task: handles button 1 and button 2 presses.
///
/// Reads the ETS-programmed parameters to determine button mode
/// (1-function rocker vs 2-function independent) and function type
/// (switch, dimmer, blind, scene), then publishes to the appropriate
/// communication objects on the KNX bus.
#[embassy_executor::task]
async fn app_task(
    knx: Stack<'static, PicoEthLightSwitch>,
    btn1_pin: Input<'static>,
    btn2_pin: Input<'static>,
) -> ! {
    let mut btn1 = DebouncedButton::new(btn1_pin);
    let mut btn2 = DebouncedButton::new(btn2_pin);

    // Per-button dimming direction state. Alternates between brighter
    // and darker on each long press so the user can reverse direction.
    let mut btn1_dim_up = true;
    let mut btn2_dim_up = true;

    loop {
        // Wait until the application has been loaded and started by ETS.
        // Before that, the parameter memory is uninitialized and comm
        // objects are not configured, so button presses would be meaningless.
        if !knx.state().is_running() {
            Timer::after(Duration::from_millis(200)).await;
            continue;
        }

        // Read the current ETS-programmed parameters. We re-read every
        // iteration so parameter changes from a new ETS download take
        // effect immediately.
        let params = *knx.state().app().borrow().params();
        let debounce = params.debounce_time.as_duration();
        let long_press = params.long_press_time.as_duration();

        // Race both buttons — whichever fires first gets processed.
        match select(
            btn1.wait_for_press(debounce, Some(long_press)),
            btn2.wait_for_press(debounce, Some(long_press)),
        )
        .await
        {
            Either::First(event) => {
                handle_button_press(
                    &knx, &params, event, ButtonId::Btn1,
                    &mut btn1, &mut btn1_dim_up, debounce,
                )
                .await;
            }
            Either::Second(event) => {
                handle_button_press(
                    &knx, &params, event, ButtonId::Btn2,
                    &mut btn2, &mut btn2_dim_up, debounce,
                )
                .await;
            }
        }
    }
}

// ================================================================================
// Button Press Handling
// ================================================================================

/// Which physical button was pressed.
#[derive(Debug, Clone, Copy)]
enum ButtonId {
    Btn1,
    Btn2,
}

/// Resolve which ButtonConfig and comm object indices to use, taking
/// into account the buttons_mode (1-function vs 2-function) and
/// rocker direction settings.
///
/// Returns `(config, primary_obj, status_obj, secondary_obj, is_on_direction)`.
/// `is_on_direction` is `Some(true)` for the ON/up/brighter side of
/// a rocker pair, `Some(false)` for the OFF/down/darker side, or
/// `None` in 2-function mode where direction is per-config.
fn resolve_button(
    params: &LightSwitchParams,
    button: ButtonId,
) -> (&ButtonConfig, Index, Index, Index, Option<bool>) {
    match params.buttons_mode {
        ButtonsMode::OneFunction => {
            // Both physical buttons share button1_config. The rocker
            // direction determines which button is "on" vs "off".
            let is_top = matches!(button, ButtonId::Btn1);
            let is_on = match params.rocker_direction {
                RockerDirection::Normal => is_top,
                RockerDirection::Inverted => !is_top,
            };
            (
                &params.button1_config,
                Index::Btn1Primary,
                Index::Btn1Status,
                Index::Btn1Secondary,
                Some(is_on),
            )
        }
        ButtonsMode::TwoFunction => {
            // Each button is independent with its own config and objects.
            match button {
                ButtonId::Btn1 => (
                    &params.button1_config,
                    Index::Btn1Primary,
                    Index::Btn1Status,
                    Index::Btn1Secondary,
                    None,
                ),
                ButtonId::Btn2 => (
                    &params.button2_config,
                    Index::Btn2Primary,
                    Index::Btn2Status,
                    Index::Btn2Secondary,
                    None,
                ),
            }
        }
    }
}

/// Read the current status object value as a bool (for toggle logic).
fn read_status(knx: &Stack<'_, PicoEthLightSwitch>, status_obj: Index) -> bool {
    let objs = knx.objects().borrow();
    let val = objs.value(status_obj.index());
    val.first().map_or(false, |&b| b & 1 != 0)
}

/// Process a button press event and publish to KNX comm objects.
async fn handle_button_press(
    knx: &Stack<'_, PicoEthLightSwitch>,
    params: &LightSwitchParams,
    event: ButtonEvent,
    button: ButtonId,
    btn: &mut DebouncedButton<Input<'static>>,
    dim_up: &mut bool,
    debounce: Duration,
) {
    let (config, primary, status, secondary, rocker_on) = resolve_button(params, button);

    match config {
        ButtonConfig::Switch { action } => {
            handle_switch(knx, event, *action, primary, status, rocker_on).await;
        }
        ButtonConfig::Dimmer => {
            handle_dimmer(knx, event, primary, status, secondary, rocker_on, btn, dim_up, debounce).await;
        }
        ButtonConfig::Blind => {
            handle_blind(knx, event, primary, secondary, rocker_on, btn, debounce).await;
        }
        ButtonConfig::Scene { scene_number } => {
            handle_scene(knx, event, primary, *scene_number as u8).await;
        }
    }
}

// ================================================================================
// Per-Mode Handlers
// ================================================================================

/// Switch mode: short press sends on/off on the primary object.
///
/// In 1-function (rocker) mode, `rocker_on` determines direction
/// regardless of the SwitchAction setting. In 2-function mode,
/// the action parameter selects toggle/on/off behavior.
async fn handle_switch(
    knx: &Stack<'_, PicoEthLightSwitch>,
    event: ButtonEvent,
    action: SwitchAction,
    primary: Index,
    status: Index,
    rocker_on: Option<bool>,
) {
    // Long press has no effect in switch mode.
    if event == ButtonEvent::LongPress {
        return;
    }

    let value = match rocker_on {
        // 1-function rocker: direction is fixed by physical position.
        Some(on) => on,
        // 2-function: use the configured action.
        None => match action {
            SwitchAction::Toggle => !read_status(knx, status),
            SwitchAction::On => true,
            SwitchAction::Off => false,
        },
    };

    let dpt = DPT_Switch::from(value);
    if let Err(_e) = knx.update_object(primary, dpt).await {
        warn!("Switch send failed (object busy)");
    }
}

/// Dimmer mode:
/// - Short press: toggle on/off via primary object.
/// - Long press start: begin relative dimming via secondary object.
/// - Long press release: send dimming stop via secondary object.
///
/// Alternates dimming direction between consecutive long presses.
async fn handle_dimmer(
    knx: &Stack<'_, PicoEthLightSwitch>,
    event: ButtonEvent,
    primary: Index,
    status: Index,
    secondary: Index,
    rocker_on: Option<bool>,
    btn: &mut DebouncedButton<Input<'static>>,
    dim_up: &mut bool,
    debounce: Duration,
) {
    match event {
        ButtonEvent::ShortPress => {
            // Toggle on/off.
            let current = read_status(knx, status);
            let value = match rocker_on {
                Some(on) => on,
                None => !current,
            };
            let dpt = DPT_Switch::from(value);
            if let Err(_e) = knx.update_object(primary, dpt).await {
                warn!("Dimmer toggle failed (object busy)");
            }
        }
        ButtonEvent::LongPress => {
            // Determine dim direction: in rocker mode it's fixed,
            // in 2-function mode it alternates.
            let up = rocker_on.unwrap_or(*dim_up);

            // DPT 3.007 format: bit 3 = control (1=dim), bits 0-2 = step code.
            // Step code 1 = 100% (full range dim). Control bit + step = start dimming.
            let start_byte: u8 = if up { 0b0000_1001 } else { 0b0000_0001 };
            let dpt = DPT_Control_Dimming::new(start_byte.into());
            if let Err(_e) = knx.update_object(secondary, dpt).await {
                warn!("Dimmer start failed (object busy)");
            }

            // Wait for button release.
            btn.wait_for_release(debounce).await;

            // Send stop: step code 0 = break (stop dimming).
            let stop_byte: u8 = if up { 0b0000_1000 } else { 0b0000_0000 };
            let stop_dpt = DPT_Control_Dimming::new(stop_byte.into());
            if let Err(_e) = knx.update_object(secondary, stop_dpt).await {
                warn!("Dimmer stop failed (object busy)");
            }

            // Alternate direction for next long press (2-function only;
            // in rocker mode, rocker_on overrides this).
            if rocker_on.is_none() {
                *dim_up = !*dim_up;
            }
        }
    }
}

/// Blind mode:
/// - Short press: send step/stop on secondary object.
/// - Long press: send move up/down on primary object.
///
/// In 1-function mode, the rocker position determines direction.
/// In 2-function mode, short press always sends step-stop and
/// long press direction alternates (same pattern as dimmer).
async fn handle_blind(
    knx: &Stack<'_, PicoEthLightSwitch>,
    event: ButtonEvent,
    primary: Index,
    secondary: Index,
    rocker_on: Option<bool>,
    btn: &mut DebouncedButton<Input<'static>>,
    debounce: Duration,
) {
    match event {
        ButtonEvent::ShortPress => {
            // Step/stop: DPT 1.007.
            // In rocker mode we send the direction-appropriate step;
            // in 2-function mode we send a step-stop (value=0 for increase).
            let step_up = rocker_on.unwrap_or(true);
            let dpt = DPT_Step::from(!step_up); // DPT_Step: 0=increase, 1=decrease
            if let Err(_e) = knx.update_object(secondary, dpt).await {
                warn!("Blind step failed (object busy)");
            }
        }
        ButtonEvent::LongPress => {
            // Move up/down: DPT 1.008.
            // 0 = Up, 1 = Down.
            let go_up = rocker_on.unwrap_or(true);
            let value: u8 = if go_up { 0 } else { 1 };
            let dpt = DPT_UpDown::new(value.into());
            if let Err(_e) = knx.update_object(primary, dpt).await {
                warn!("Blind move failed (object busy)");
            }

            // Wait for release, then send stop (step with same direction).
            btn.wait_for_release(debounce).await;
            let stop_dpt = DPT_Step::from(!go_up);
            if let Err(_e) = knx.update_object(secondary, stop_dpt).await {
                warn!("Blind stop failed (object busy)");
            }
        }
    }
}

/// Scene mode:
/// - Short press: recall scene (activate).
/// - Long press: store scene (learn).
///
/// DPT 18.001 format: bit 7 = learn flag, bits 0-5 = scene number (0-63).
async fn handle_scene(
    knx: &Stack<'_, PicoEthLightSwitch>,
    event: ButtonEvent,
    primary: Index,
    scene_number: u8,
) {
    let value = match event {
        ButtonEvent::ShortPress => scene_number & 0x3F,            // Recall
        ButtonEvent::LongPress => (scene_number & 0x3F) | 0x80,   // Store
    };
    let dpt = DPT_SceneControl::new(value.into());
    if let Err(_e) = knx.update_object(primary, dpt).await {
        warn!("Scene send failed (object busy)");
    }
}

// ================================================================================
// Entry point
// ================================================================================

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());
    info!("Pico Ethernet (W5500) initializing");

    // ========================================================================
    // W5500 SPI init
    // ========================================================================

    // SPI0 connected to the W5500 module.
    // Pin assignments: MISO=GP4, MOSI=GP3, SCK=GP2, CS=GP5, RST=GP10, INT=GP11
    let mut spi_cfg = SpiConfig::default();
    spi_cfg.frequency = 10_000_000;
    let spi = Spi::new(
        p.SPI0, p.PIN_2, p.PIN_3, p.PIN_4,
        p.DMA_CH0, p.DMA_CH1, spi_cfg,
    );
    let cs = Output::new(p.PIN_5, Level::High);
    let w5500_int = Input::new(p.PIN_11, Pull::Up);
    let w5500_reset = Output::new(p.PIN_10, Level::High);

    let spi_dev = ExclusiveDevice::new(spi, cs, Delay)
        .expect("SPI ExclusiveDevice init infallible for Output CS");

    static W5500_STATE: StaticCell<embassy_net_wiznet::State<8, 8>> = StaticCell::new();
    let (net_device, w5500_runner) = embassy_net_wiznet::new(
        MAC_ADDR,
        W5500_STATE.init(embassy_net_wiznet::State::new()),
        spi_dev,
        w5500_int,
        w5500_reset,
    )
    .await
    .expect("W5500 init");

    info!("W5500 initialized successfully");

    spawner.spawn(w5500_task(w5500_runner)).expect("w5500_task spawnable once");

    // ========================================================================
    // Embassy-net stack init (DHCP)
    // ========================================================================

    // Use a deterministic seed derived from the chip's unique flash ID
    // so multicast IGMP joins get a consistent random delay.
    let seed = 0x0123_4567_89AB_CDEFu64; // TODO: read from flash unique ID

    static NET_RESOURCES: StaticCell<NetStackResources<3>> = StaticCell::new();
    let (stack, net_runner) = embassy_net::new(
        net_device,
        embassy_net::Config::dhcpv4(DhcpConfig::default()),
        NET_RESOURCES.init(NetStackResources::new()),
        seed,
    );

    spawner.spawn(net_task(net_runner)).expect("net_task spawnable once");

    // Wait for DHCP lease before proceeding.
    info!("Waiting for DHCP...");
    loop {
        if let Some(config) = stack.config_v4() {
            info!("DHCP acquired: {}", config.address);
            break;
        }
        Timer::after(Duration::from_millis(100)).await;
    }

    // ========================================================================
    // Platform layer
    // ========================================================================

    info!("MAC address: {:02x}", MAC_ADDR);

    // Initialize the global network context so EmbassyNetworkInfo::default()
    // works during device state construction (IpLinkLayerState::from_config
    // calls P::default()).
    EmbassyNetworkInfo::init(stack, MAC_ADDR);

    // ========================================================================
    // Persistent storage
    // ========================================================================

    // Device identity — serial number burned into the device.
    let identity = StaticIdentity::new(SERIAL_NUMBER);

    // Flash storage for persistent device state (last 4KB sector).
    let flash = embassy_rp::flash::Flash::<_, flash::Blocking, { 2 * 1024 * 1024 }>::new_blocking(p.FLASH);
    let mut storage = RpFlashStorage::<PicoEthPersistedState>::new(flash);

    let device_state = match storage.load() {
        Ok(Some(persisted)) => {
            info!("Loaded persisted state from flash");
            PicoEthState::from_persisted(&identity, persisted)
        }
        Ok(None) => {
            info!("No persisted state found, starting fresh");
            PicoEthState::new(&identity)
        }
        Err(e) => {
            warn!("Flash load failed: {}, starting fresh", e);
            PicoEthState::new(&identity)
        }
    };

    // Put storage in a static RefCell so both the restart handler and the
    // main loop can access it. Both run on the same single-threaded
    // executor, so RefCell is safe (no concurrent borrow possible).
    static STORAGE: StaticCell<RefCell<Storage>> = StaticCell::new();
    let storage = &*STORAGE.init(RefCell::new(storage));

    // ========================================================================
    // KNX stack
    // ========================================================================

    // The DHCP-assigned IP is used as the local address and control endpoint.
    let local_ip = stack
        .config_v4()
        .map(|c| Ipv4Addr::from(c.address.address().octets()))
        .unwrap_or(Ipv4Addr::UNSPECIFIED);

    let control_endpoint = HPAI::Ipv4Udp { addr: local_ip, port: 3671 };

    // The embassy-net stack handle is passed as socket context — when the
    // KNX/IP servers call EmbassyUdpSocket::bind(), they receive it directly.
    let link_layer_builder =
        KnxNetIpBuilder::<EmbassyIpTransport, 2>::new("eth0", local_ip, control_endpoint, stack)
            .enable_routing_server()
            .enable_remote_config_server();

    // Allocate stack resources in a static (embassy tasks need 'static).
    static KNX_RESOURCES: StaticCell<
        StackResources<
            PicoEthLightSwitch,
            { zweidraehte::config::buffer_size_for_apdu(<PicoEthLightSwitch as StackDefinition>::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte::new(
        KNX_RESOURCES.init(StackResources::new()),
        LightSwitchComObjects::new(),
        (), // hook context — not needed, app logic runs via the stack handle
        link_layer_builder,
        device_state,
        PicoEthLightSwitch::memory_map(),
    );

    spawner
        .spawn(knx_task(knx_runner))
        .expect("knx_task spawnable once");

    info!("KNX/IP stack started");
    info!("  Manufacturer: {:04x}", LightSwitchDevice::MANUFACTURER_ID);
    info!("  Application:  {:04x} v{:02x}", LightSwitchDevice::APPLICATION_ID, LightSwitchDevice::APPLICATION_VERSION);
    info!("  Local IP:     {}", local_ip);
    info!("  Mask version: 57B0 (System B KNX/IP)");

    // ========================================================================
    // Application GPIO + tasks
    // ========================================================================

    // Push buttons — active low with internal pull-ups.
    let btn1_pin = Input::new(p.PIN_18, Pull::Up);
    let btn2_pin = Input::new(p.PIN_19, Pull::Up);
    let prog_btn_pin = Input::new(p.PIN_17, Pull::Up);

    spawner
        .spawn(app_task(knx_stack, btn1_pin, btn2_pin))
        .expect("app_task spawnable once");
    spawner
        .spawn(prog_task(knx_stack, prog_btn_pin))
        .expect("prog_task spawnable once");
    spawner
        .spawn(restart_task(knx_stack, storage))
        .expect("restart_task spawnable once");

    // ========================================================================
    // Main loop: heartbeat LED + programming mode LED + periodic save
    // ========================================================================

    // The programming LED is driven here (not in prog_task) so it also
    // tracks remote programming mode changes from ETS without
    // interfering with the button's edge detection.
    let mut prog_led = Output::new(p.PIN_16, Level::Low);
    let mut led = Output::new(p.PIN_25, Level::Low);
    loop {
        led.toggle();

        if knx_stack.state().is_programming_mode() {
            prog_led.set_high();
        } else {
            prog_led.set_low();
        }

        // Periodically persist any state changes from ETS programming
        // (table writes, parameter changes, address changes, etc.).
        // The restart handler also saves before rebooting, but this
        // catches changes that don't involve a restart.
        if knx_stack.state().is_dirty() {
            save_state(knx_stack.state(), storage);
        }

        Timer::after(Duration::from_millis(500)).await;
    }
}
