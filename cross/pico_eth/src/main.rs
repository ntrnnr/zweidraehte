#![no_std]
#![no_main]
#![feature(never_type)]

use core::net::Ipv4Addr;

use defmt::*;
use embassy_executor::Spawner;
use embassy_net::{DhcpConfig, StackResources as NetStackResources};
use embassy_net_wiznet::chip::W5500;
use embassy_rp::gpio::{Input, Level, Output, Pull};
use embassy_rp::peripherals::SPI0;
use embassy_rp::spi::{Async, Config as SpiConfig, Spi};
use embassy_time::{Delay, Duration, Timer};
use embedded_hal_bus::spi::ExclusiveDevice;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use devices::light_switch::{
    self, LightSwitchDevice, LightSwitchParams,
    comm_objs::LightSwitchComObjects,
};
use zweidraehte::bcus::system_b::{
    DefaultKnxIpInterfaceObjects, IpSystemBDeviceState, MemoryLayout, StaticIdentity,
    SystemBIpDeviceDef, SystemBMemoryMap,
    create_knxip_objects,
};
use zweidraehte::layers::linklayers::knxip::KnxNetIpBuilder;
use zweidraehte::messages::knxip::substructs::HPAI;
use zweidraehte::prelude::*;

use rp_common::{EmbassyIpTransport, EmbassyNetworkInfo};

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

/// Memory layout for the device, derived from the descriptor.
const MEMORY_LAYOUT: MemoryLayout = MemoryLayout::from_descriptor(
    SystemBMemoryMap::DEFAULT_BASE_ADDRESS,
    &DEVICE_DESCRIPTOR,
    core::mem::size_of::<LightSwitchParams>(),
);

/// Memory map for the device.
const MEMORY_MAP: SystemBMemoryMap = SystemBMemoryMap::new(MEMORY_LAYOUT);

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
        create_knxip_objects::<Self, _>(state, &MEMORY_LAYOUT)
    }
}

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

    // Flash storage for persistent device state.
    // TODO: Load persisted state from flash instead of starting fresh.
    // let flash = embassy_rp::flash::Flash::<_, flash::Blocking, { 2 * 1024 * 1024 }>::new_blocking(p.FLASH);
    // let _storage = rp_common::RpFlashStorage::<PersistedState>::new(flash);

    // ========================================================================
    // KNX stack
    // ========================================================================

    // Device identity — serial number burned into the device.
    let identity = StaticIdentity::new(SERIAL_NUMBER);

    // Fresh device state (tables empty, default individual address 15.15.255).
    // ETS will program the actual address, tables, and parameters.
    let device_state = PicoEthState::new(&identity);

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
        (), // hook context — no application hooks yet
        link_layer_builder,
        device_state,
        MEMORY_MAP,
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
    // Main loop: heartbeat LED
    // ========================================================================

    // Discard the stack handle — this minimal firmware has no application
    // logic beyond what ETS programs. The KNX runner task handles all
    // protocol processing autonomously.
    let _ = knx_stack;

    // Standard Pico has the LED on GP25 (direct GPIO, unlike Pico W where
    // it's behind the CYW43 chip).
    let mut led = Output::new(p.PIN_25, Level::Low);
    loop {
        led.set_high();
        Timer::after(Duration::from_millis(500)).await;
        led.set_low();
        Timer::after(Duration::from_millis(500)).await;
    }
}
