#![no_std]
#![no_main]
#![feature(never_type)]

use core::cell::RefCell;
use core::net::{Ipv4Addr, SocketAddrV4};

use defmt::*;
use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_net::{DhcpConfig, StackResources as NetStackResources};
use embassy_net_wiznet::chip::W5500;
use embassy_rp::{
    flash,
    gpio::{Input, Level, Output, Pull},
    peripherals::SPI0,
    spi::{Async, Config as SpiConfig, Spi},
};
use embassy_time::{Delay, Duration, Timer};
use embedded_hal::digital::InputPin;
use embedded_hal_async::digital::Wait;
use embedded_hal_bus::spi::ExclusiveDevice;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use devices::light_switch::{
    self, LightSwitchDevice, LightSwitchParams,
    app::{self, ButtonId, WaitForRelease},
    comm_objs::LightSwitchComObjects,
};

use zweidraehte::{
    bcus::system_b::*,
    layers::linklayers::knxip::{KnxNetIpBuilder, features::KnxIpDeviceUdp},
    prelude::*,
    storage::DeviceStorage,
};

use rp_common::button::DebouncedButton;
use rp_common::{EmbassyIpTransport, EmbassyNetworkInfo, RpFlashStorage, FlashIdentityData};

// ================================================================================
// Device Definition
// ================================================================================

/// Device descriptor from the light switch device definition (KNX/IP variant).
const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_IP;

/// MAC vendor prefix for locally-administered MAC addresses.
/// Bit 1 (locally administered) is forced set by `derive_mac_address`.
const MAC_OUI: [u8; 3] = [0x02, 0x00, 0xFA];

const ADT_SIZE: usize = DEVICE_DESCRIPTOR.address_table_size();
const AST_SIZE: usize = DEVICE_DESCRIPTOR.association_table_size();
const COT_SIZE: usize = DEVICE_DESCRIPTOR.comm_object_table_size();

/// Device state combining System B tables with IP link-layer state.
type PicoEthState = IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, LightSwitchParams, EmbassyNetworkInfo>;

/// Flash storage handle, shared between the main loop (periodic save)
/// and the restart handler (save before reset).
type Storage = RpFlashStorage<PicoEthState, FlashIdentityData>;

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
    type LLB = KnxNetIpBuilder<EmbassyIpTransport, KnxIpDeviceUdp, 2>;
    type State = PicoEthState;
    type Mem = SystemBMemoryMap;
    type InterfaceObjects<'a> = DefaultKnxIpInterfaceObjects<'a, PicoEthState>;

    fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
    {
        create_knxip_objects::<Self, _>(state, &Self::memory_layout())
    }

    type Layers<'a> = InsecureDeviceLayers<'a, Self>;

    fn build_layers<'a>(ctx: &'a LayerContext<'a, Self>) -> Self::Layers<'a>
    where
        Self: 'a,
    {
        InsecureDeviceLayers::new(ctx)
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
        let state = knx.state();

        info!("Restart request: erase_code={}", request.erase_code);

        // The stack already sent the A_Restart_Response on the bus.
        match request.erase_code {
            EraseCode::Basic | EraseCode::Confirmed => {
                info!("Basic restart (no data reset)");
            }
            EraseCode::FactoryReset => {
                info!("Factory reset — clearing all data");
                state.factory_reset();
            }
            EraseCode::ResetIA => {
                info!("Resetting individual address");
                state.reset_individual_address();
            }
            EraseCode::ResetAP => {
                info!("Resetting application program");
                state.reset_application();
            }
            EraseCode::ResetParam => {
                info!("Resetting parameters");
                state.reset_parameters();
            }
            EraseCode::FactoryResetKeepIA => {
                info!("Factory reset (keeping individual address)");
                state.factory_reset_keep_ia();
            }
            EraseCode::ResetLinks | EraseCode::Other(_) => {
                warn!("Unsupported erase code — ignoring");
            }
        }

        // Persist the post-reset state before rebooting.
        if state.is_dirty() {
            save_state(state, storage);
        }

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
    match storage.borrow_mut().save(state) {
        Ok(()) => {
            state.clear_dirty();
            info!("State saved to flash");
        }
        Err(e) => {
            warn!("Flash save failed: {}", e);
        }
    }
}

/// Lifecycle event logger.
///
/// Logs application start/stop transitions so we can observe ETS
/// programming completing (or unloading) via defmt.
#[embassy_executor::task]
async fn lifecycle_task(knx: Stack<'static, PicoEthLightSwitch>) -> ! {
    let mut events = knx.lifecycle_events();
    loop {
        match events.next_message_pure().await {
            LifecycleEvent::ApplicationStarted => {
                info!("Application STARTED — app is now running");
            }
            LifecycleEvent::ApplicationStopped => {
                info!("Application STOPPED — app is no longer running");
            }
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
                let mut waiter = ReleaseWaiter { btn: &mut btn1, debounce };
                app::handle_button_press(
                    &knx, &params, event, ButtonId::Btn1,
                    &mut waiter, &mut btn1_dim_up,
                )
                .await;
            }
            Either::Second(event) => {
                let mut waiter = ReleaseWaiter { btn: &mut btn2, debounce };
                app::handle_button_press(
                    &knx, &params, event, ButtonId::Btn2,
                    &mut waiter, &mut btn2_dim_up,
                )
                .await;
            }
        }
    }
}

// ================================================================================
// Button Release Adapter
// ================================================================================

/// Bridges [`DebouncedButton::wait_for_release`] to the
/// [`WaitForRelease`] trait expected by the device application logic.
struct ReleaseWaiter<'a, P: InputPin + Wait> {
    btn: &'a mut DebouncedButton<P>,
    debounce: Duration,
}

impl<P: InputPin + Wait> WaitForRelease for ReleaseWaiter<'_, P> {
    async fn wait_for_release(&mut self) {
        self.btn.wait_for_release(self.debounce).await;
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
    // Device identity (from flash — must happen before W5500 init for MAC)
    // ========================================================================

    let mut flash = embassy_rp::flash::Flash::<_, flash::Blocking, { 2 * 1024 * 1024 }>::new_blocking(p.FLASH);
    let identity_data = rp_common::read_or_provision_identity(
        &mut flash,
        LightSwitchDevice::MANUFACTURER_ID.to_be_bytes(),
    );

    let mac_addr = identity_data.derive_mac_address(MAC_OUI);
    let seed = identity_data.derive_seed();
    info!("Serial: {=[u8]:02x}", identity_data.serial_number);
    info!("MAC:    {=[u8]:02x}", mac_addr);

    // ========================================================================
    // W5500 SPI init
    // ========================================================================

    // SPI0 connected to the W5500 module.
    // Pin assignments: MISO=GP4, MOSI=GP3, SCK=GP2, CS=GP5, RST=GP10, INT=GP11
    let mut spi_cfg = SpiConfig::default();
    spi_cfg.frequency = 50_000_000;
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
        mac_addr,
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

    // Initialize the global network context so EmbassyNetworkInfo::default()
    // works during device state construction (IpLinkLayerState::from_config
    // calls P::default()).
    EmbassyNetworkInfo::init(stack, mac_addr);

    // ========================================================================
    // Persistent storage
    // ========================================================================

    // Flash storage for persistent device state (last 4 KiB sector).
    // The `flash` handle was used transiently for identity provisioning
    // above and is now passed to RpFlashStorage for config persistence.
    let mut storage = RpFlashStorage::<PicoEthState, _>::new(flash, identity_data);

    let device_state = match storage.load() {
        Ok(Some(state)) => {
            info!("Loaded persisted state from flash");
            state
        }
        Ok(None) => {
            info!("No persisted state found, starting fresh");
            PicoEthState::new(storage.identity())
        }
        Err(e) => {
            warn!("Flash load failed: {}, starting fresh", e);
            PicoEthState::new(storage.identity())
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

    let control_endpoint = SocketAddrV4::new(local_ip, 3671);

    // The embassy-net stack handle is passed as socket context — when the
    // KNX/IP servers call EmbassyUdpSocket::bind(), they receive it directly.
    let link_layer_builder =
        KnxNetIpBuilder::<EmbassyIpTransport, _, 2>::new("eth0", local_ip, control_endpoint, stack)
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
    info!("  Application:  {:04x} v{:02x}", LightSwitchDevice::APPLICATION_ID_IP, LightSwitchDevice::APPLICATION_VERSION);
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
    spawner
        .spawn(lifecycle_task(knx_stack))
        .expect("lifecycle_task spawnable once");

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
