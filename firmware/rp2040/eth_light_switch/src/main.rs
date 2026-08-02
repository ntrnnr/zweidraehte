#![no_std]
#![no_main]

use core::net::{Ipv4Addr, SocketAddrV4};

use defmt::*;
use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_net::{DhcpConfig, Ipv4Cidr, StackResources as NetStackResources, StaticConfigV4};
use embassy_net_wiznet::chip::W5500;
use embassy_rp::{
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
    easter_egg::EasterEggAugment,
};

use zweidraehte_device::{
    bcus::system_b::*,
    layers::linklayers::knxip::{KnxNetIpBuilder, KnxNetIpDefinition, features::KnxIpDeviceUdp},
    prelude::*,
};

use embedded_common::DebouncedButton;
use rp_common::{
    EmbassyIpTransport, EmbassyNetworkInfo, EmbassyUdpContext, FlashIdentityData, RpConfigRegion, RpFlash, RpFlashIo,
    UdpPool,
};

// ================================================================================
// Device Definition
// ================================================================================

/// Device descriptor from the light switch device definition (KNX/IP variant).
const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_IP;

// ================================================================================
// Capacity knobs
// ================================================================================
//
// All sizes the KNX/IP and embassy-net stacks need, named once so the
// numbers don't drift apart. UDP-only routing device — no TCP.

/// UDP buffer pool size — must match `<PicoEthLightSwitch as
/// KnxNetIpDefinition>::MAX_UDP_SOCKETS`. Three sockets cover
/// discovery + control + routing on this UDP-only routing device.
const UDP_POOL_SIZE: usize = 3;

/// Device state combining System B tables with IP link-layer state.
type PicoEthState = IpStateFor<PicoEthLightSwitch, KnxIpDeviceUdp>;

// ----------------------------------------------------------------------------
// Storage layout — one config region on the shared RpFlash chip
// ----------------------------------------------------------------------------

// The device's storage memory map: a single config blob carrying this
// device's state as its payload. The `Placed` entry derives its placement,
// store type, and open() from the layout.
use zweidraehte_device::config::buffer_size_for_apdu;
use zweidraehte_device::layers::application::services::{DomainAddressService, StandardAlServices};
use zweidraehte_device::lifecycle::lifecycle_event_logger;
use zweidraehte_device::service::ServiceRegistry;
use zweidraehte_device::storage::NoSaveGuard;
use zweidraehte_device::storage::{ConfigStorage, Placed, RegionSpec, StorageLayout, StoreOf};

// `pub`: the map reaches the public `StackDefinition` surface through
// `DeviceStorage`'s `StoreOf` projection.
pub struct StorageMap;
type Cfg = Placed<RpConfigRegion<PicoEthState>, RpFlash, StorageMap>;
impl StorageLayout for StorageMap {
    const REGIONS: &'static [RegionSpec] = &[Cfg::SPEC];
}
type DeviceStorage = ConfigStorage<StoreOf<Cfg>>;

// ----------------------------------------------------------------------------
// StackDefinition
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct PicoEthLightSwitch;

/// Augment chain: IP medium augment (KNXnet/IP Parameter object) plus
/// the Easter Egg demo augment.
#[derive(ServiceRegistry)]
pub struct PicoEthAugments<'a> {
    #[service(augment)]
    ip: IpAugmentFor<'a, EmbassyNetworkInfo, KnxIpDeviceUdp>,
    #[service(augment)]
    easter: EasterEggAugment,
}

// IP-specific link-layer bill of materials. Routing-only UDP device
// with three UDP sockets (discovery + control + routing).
impl KnxNetIpDefinition for PicoEthLightSwitch {
    type Transport = EmbassyIpTransport<{ <Self as KnxNetIpDefinition>::MAX_UDP_SOCKETS }>;
    type Features = KnxIpDeviceUdp;
    const MAX_UDP_SOCKETS: usize = 3;
}

zweidraehte_device::system_b_standard_stack! {
    stack: PicoEthLightSwitch,
    device: &DEVICE_DESCRIPTOR,
    tl_style: TlStyle::Style3,
    params: LightSwitchParams,
    com_objects: LightSwitchComObjects,
    link_layer_builder: KnxNetIpBuilder<PicoEthLightSwitch>,
    platform: EmbassyNetworkInfo,
    extension_state: IpExtensionFor<KnxIpDeviceUdp>,
    state: PicoEthState,
    al_extensions: (
        StandardAlServices,
        DomainAddressService,
    ),
    layer_builder: PlainIpDeviceBuilder,
    augments: {
        bundle: PicoEthAugments,
        create: |state, platform, _layer_ctx| PicoEthAugments {
            ip: state.extension_state().create_augment::<Self>(platform),
            easter: EasterEggAugment,
        },
    },
    extra {
        type Identity = FlashIdentityData;
        // The storage handle rides on the stack; the storage task pulls the
        // config store out of it.
        type Storage = &'static DeviceStorage;
    },
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
async fn prog_task(knx: Stack<'static, PicoEthLightSwitch>, prog_btn_pin: Input<'static>) -> ! {
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

zweidraehte_device::storage_task! {
    device: PicoEthLightSwitch,
    system: embedded_common::CortexMSystem,
    guard: NoSaveGuard,
}

/// Lifecycle event logger.
///
/// Logs application start/stop transitions so we can observe ETS
/// programming completing (or unloading) via defmt.
#[embassy_executor::task]
async fn lifecycle_task(knx: Stack<'static, PicoEthLightSwitch>) -> ! {
    lifecycle_event_logger(knx).await
}

/// Main application task: handles button 1 and button 2 presses.
///
/// Reads the ETS-programmed parameters to determine button mode
/// (1-function rocker vs 2-function independent) and function type
/// (switch, dimmer, blind, scene), then publishes to the appropriate
/// communication objects on the KNX bus.
#[embassy_executor::task]
async fn app_task(knx: Stack<'static, PicoEthLightSwitch>, btn1_pin: Input<'static>, btn2_pin: Input<'static>) -> ! {
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

// ================================================================================
// Identity load
// ================================================================================

#[cfg(feature = "provision-on-boot")]
mod dev_provisioning {
    include!(concat!(env!("OUT_DIR"), "/dev_provisioning.rs"));
}

rp_common::rp_identity_loader!(plain, fdsk: None, mac: Some(dev_provisioning::DEV_MAC));

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

    // The `Storage` `ConfigStore` borrows the `FLASH` peripheral through a
    // shared `&'static RefCell` (so secure devices can share it with their
    // sequence-number store). This device has no second flash consumer, but
    // must satisfy the same API, so lift the handle into a `StaticCell` too.
    let flash = rp_common::rp_flash_cell!(p.FLASH);
    let identity_data = load_identity(&mut flash.borrow_mut());

    let mac_addr = identity_data.mac_address();
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
    let spi = Spi::new(p.SPI0, p.PIN_2, p.PIN_3, p.PIN_4, p.DMA_CH0, p.DMA_CH1, spi_cfg);
    let cs = Output::new(p.PIN_5, Level::High);
    let w5500_int = Input::new(p.PIN_11, Pull::Up);
    let w5500_reset = Output::new(p.PIN_10, Level::High);

    let spi_dev = ExclusiveDevice::new(spi, cs, Delay).expect("SPI ExclusiveDevice init infallible for Output CS");

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
    // Early prog button read (before network init)
    // ========================================================================

    // Sample the programming button early: if held during boot, we force
    // DHCP regardless of the persisted IP assignment method. The pin is
    // read synchronously here, then later handed off to prog_task for
    // runtime toggling.
    let prog_btn_pin = Input::new(p.PIN_17, Pull::Up);
    let prog_button_held = prog_btn_pin.is_low();
    if prog_button_held {
        info!("Prog button held at boot — forcing DHCP");
    }

    // ========================================================================
    // Persistent storage — peek at IP config before creating the stack
    // ========================================================================

    // Read the device config from flash WITHOUT constructing the full
    // runtime state. We need the IP assignment method to decide whether
    // to configure the embassy-net stack with DHCP or static IP before
    // creating it. The stores struct lives in a static so the storage task
    // can reach it; each store sits behind its own RefCell, borrowed per
    // call on the single-threaded executor.
    static STORAGE: StaticCell<DeviceStorage> = StaticCell::new();
    let storage =
        &*STORAGE.init(DeviceStorage::new(Cfg::open(RpFlashIo::new(flash)).expect("config open is infallible")));
    let loaded_config = storage.load_config();
    let ip_config = loaded_config.as_ref().map(|c| &c.extension_config);

    // ========================================================================
    // IP assignment procedure (KNX spec Core 8.5, Figure 42)
    // ========================================================================

    // Determine the initial embassy-net config. The prog button forces
    // DHCP as a recovery mechanism (ignoring persisted config).
    use rp_common::{IP_ASSIGN_DHCP, IP_ASSIGN_MANUAL};

    let (net_config, initial_ip_method) = if prog_button_held {
        info!("Prog button override: using DHCP");
        (embassy_net::Config::dhcpv4(DhcpConfig::default()), IP_ASSIGN_DHCP)
    } else if let Some(ip) = ip_config {
        if ip.ip_assignment_method & IP_ASSIGN_MANUAL != 0 {
            // Manual/static requested — validate the persisted address.
            let addr = Ipv4Addr::from(ip.configured_ip);
            let mask = Ipv4Addr::from(ip.configured_subnet);
            if addr.is_unspecified() || mask.is_unspecified() {
                warn!("Static IP config invalid — falling back to DHCP");
                (embassy_net::Config::dhcpv4(DhcpConfig::default()), IP_ASSIGN_DHCP)
            } else {
                let prefix = rp_common::mask_to_prefix(mask);
                let gw = Ipv4Addr::from(ip.configured_gateway);
                let gateway = if gw.is_unspecified() { None } else { Some(gw) };
                info!("Using stored static IP: {}/{}", addr, prefix);
                (
                    embassy_net::Config::ipv4_static(StaticConfigV4 {
                        address: Ipv4Cidr::new(addr, prefix),
                        gateway,
                        dns_servers: Default::default(),
                    }),
                    IP_ASSIGN_MANUAL,
                )
            }
        } else if ip.ip_assignment_method & IP_ASSIGN_DHCP != 0 {
            info!("IP assignment: DHCP");
            (embassy_net::Config::dhcpv4(DhcpConfig::default()), IP_ASSIGN_DHCP)
        } else {
            warn!("Unsupported IP assignment method 0x{:02x}, using DHCP", ip.ip_assignment_method);
            (embassy_net::Config::dhcpv4(DhcpConfig::default()), IP_ASSIGN_DHCP)
        }
    } else {
        info!("No stored config, using DHCP");
        (embassy_net::Config::dhcpv4(DhcpConfig::default()), IP_ASSIGN_DHCP)
    };

    // ========================================================================
    // Embassy-net stack init
    // ========================================================================

    static NET_RESOURCES: StaticCell<NetStackResources<{ PicoEthLightSwitch::EMBASSY_NET_SOCKETS }>> =
        StaticCell::new();
    let (stack, net_runner) =
        embassy_net::new(net_device, net_config, NET_RESOURCES.init(NetStackResources::new()), seed);

    spawner.spawn(net_task(net_runner)).expect("net_task spawnable once");

    // ========================================================================
    // Platform + device state construction
    // ========================================================================

    let platform = EmbassyNetworkInfo::new(stack, mac_addr, initial_ip_method);

    // Build state init from the device config loaded earlier.
    let state_init = SystemBStateInit::new(identity_data, loaded_config);

    // Wait for an IP address. For static this is immediate; for DHCP
    // this waits for a lease.
    if initial_ip_method == IP_ASSIGN_DHCP {
        info!("Waiting for DHCP...");
    }
    loop {
        if stack.config_v4().is_some() {
            break;
        }
        Timer::after(Duration::from_millis(100)).await;
    }
    let ip = stack.config_v4().expect("IP config available after wait loop");
    info!("IP ready: {}", ip.address);

    // ========================================================================
    // KNX stack
    // ========================================================================

    // Read the current IP (DHCP or static, depending on what was applied above).
    let local_ip =
        stack.config_v4().map(|c| Ipv4Addr::from(c.address.address().octets())).unwrap_or(Ipv4Addr::UNSPECIFIED);

    let control_endpoint = SocketAddrV4::new(local_ip, 3671);

    // Static UDP buffer pool — sized via the `KnxNetIpDefinition`
    // impl on `PicoEthLightSwitch`.
    static UDP_POOL: UdpPool<UDP_POOL_SIZE> = UdpPool::new();

    let socket_ctx = EmbassyUdpContext { stack, udp_pool: &UDP_POOL };

    // Features (routing + remote-config) and every numeric sizing knob
    // come from `PicoEthLightSwitch`'s `KnxNetIpDefinition` impl. No
    // more `enable_*()` chain, no manually matched const generics.
    let link_layer_builder = KnxNetIpBuilder::<PicoEthLightSwitch>::new("eth0", local_ip, control_endpoint, socket_ctx);

    // Allocate stack resources in a static (embassy tasks need 'static).
    static KNX_RESOURCES: StaticCell<
        StackResources<
            PicoEthLightSwitch,
            { buffer_size_for_apdu(<PicoEthLightSwitch as StackDefinition>::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        platform,
        PicoEthLightSwitch::memory_map(),
        storage,
    );

    spawner.spawn(knx_task(knx_runner)).expect("knx_task spawnable once");

    info!("KNX/IP stack started");
    info!("  Manufacturer: {:04x}", LightSwitchDevice::MANUFACTURER_ID);
    info!(
        "  Application:  {:04x} v{:02x}",
        LightSwitchDevice::APPLICATION_ID_IP,
        LightSwitchDevice::APPLICATION_VERSION
    );
    info!("  Local IP:     {}", local_ip);
    info!("  Mask version: 57B0 (System B KNX/IP)");

    // ========================================================================
    // Application GPIO + tasks
    // ========================================================================

    // Push buttons — active low with internal pull-ups.
    // (prog_btn_pin was created earlier for the boot-time prog button check.)
    let btn1_pin = Input::new(p.PIN_18, Pull::Up);
    let btn2_pin = Input::new(p.PIN_19, Pull::Up);

    spawner.spawn(app_task(knx_stack, btn1_pin, btn2_pin)).expect("app_task spawnable once");
    spawner.spawn(prog_task(knx_stack, prog_btn_pin)).expect("prog_task spawnable once");
    spawner.spawn(storage_task(knx_stack)).expect("storage_task spawnable once");
    spawner.spawn(lifecycle_task(knx_stack)).expect("lifecycle_task spawnable once");

    // ========================================================================
    // Main loop: heartbeat LED + programming mode LED (saves live in the
    // storage task)
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

        Timer::after(Duration::from_millis(500)).await;
    }
}
