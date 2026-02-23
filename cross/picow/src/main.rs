#![no_std]
#![no_main]
#![feature(never_type)]

use core::net::{Ipv4Addr, SocketAddrV4};

use cyw43_pio::PioSpi;
use defmt::*;
use embassy_executor::Spawner;
use embassy_net::{DhcpConfig, StackResources as NetStackResources};
use embassy_rp::{
    bind_interrupts,
    gpio::{Level, Output},
    peripherals::{DMA_CH0, PIO0},
    pio::{self, Pio},
};
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use devices::light_switch::{
    self, LightSwitchDevice, LightSwitchParams,
    comm_objs::LightSwitchComObjects,
};
use zweidraehte::{
    bcus::system_b::{
        DefaultKnxIpInterfaceObjects, IpSystemBDeviceState, StaticIdentity, SystemBIpDeviceDef,
        SystemBMemoryMap, create_knxip_objects,
    },
    layers::linklayers::knxip::KnxNetIpBuilder,
    prelude::*,
};

use rp_common::{EmbassyIpTransport, EmbassyNetworkInfo};

// ================================================================================
// Device Definition
// ================================================================================

/// Device descriptor from the light switch device definition (KNX/IP variant).
const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_IP;

/// Serial number: manufacturer ID (0x00FA) + device-specific bytes.
/// TODO: Read from RP2040 flash unique ID for production.
const SERIAL_NUMBER: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x03];

const ADT_SIZE: usize = DEVICE_DESCRIPTOR.address_table_size();
const AST_SIZE: usize = DEVICE_DESCRIPTOR.association_table_size();
const COT_SIZE: usize = DEVICE_DESCRIPTOR.comm_object_table_size();

/// Device state combining System B tables with IP link-layer state.
type PicoWState = IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, LightSwitchParams, EmbassyNetworkInfo>;

// ----------------------------------------------------------------------------
// SystemBIpDeviceDef + StackDefinition
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct PicoWLightSwitch;

impl SystemBIpDeviceDef for PicoWLightSwitch {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const INTERFACE_NAME: &'static str = "wlan0";

    type P = LightSwitchParams;
    type CO = LightSwitchComObjects;
    type Transport = EmbassyIpTransport;
    type Platform = EmbassyNetworkInfo;
    type State = PicoWState;
}

impl StackDefinition for PicoWLightSwitch {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const TL_STYLE: TlStyle = TlStyle::Style1;

    type P = LightSwitchParams;
    type CO = LightSwitchComObjects;
    type LLB = KnxNetIpBuilder<EmbassyIpTransport, 2>;
    type State = PicoWState;
    type Mem = SystemBMemoryMap;
    type InterfaceObjects<'a> = DefaultKnxIpInterfaceObjects<'a, PicoWState>;

    fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
    {
        create_knxip_objects::<Self, _>(state, &Self::memory_layout())
    }
}

// ================================================================================
// KNX stack runner task
// ================================================================================

#[embassy_executor::task]
async fn knx_task(runner: Runner<'static, PicoWLightSwitch>) -> ! {
    runner.run().await
}

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => pio::InterruptHandler<PIO0>;
});

#[embassy_executor::task]
async fn cyw43_task(
    runner: cyw43::Runner<'static, Output<'static>, PioSpi<'static, PIO0, 0, DMA_CH0>>,
) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, cyw43::NetDriver<'static>>) -> ! {
    runner.run().await
}

// ================================================================================
// Firmware blobs
// ================================================================================

// The CYW43439 WiFi chip requires firmware to be loaded at init time.
// These blobs come from the embassy cyw43-firmware directory, originally
// sourced from https://github.com/georgerobotics/cyw43-driver.
// Licensed under the Infineon Permissive Binary License.

// Ensure 4-byte alignment for DMA transfers.
#[repr(C, align(4))]
struct Aligned<const N: usize>([u8; N]);

static FW: Aligned<{ include_bytes!("../firmware/43439A0.bin").len() }> =
    Aligned(*include_bytes!("../firmware/43439A0.bin"));

static CLM: Aligned<{ include_bytes!("../firmware/43439A0_clm.bin").len() }> =
    Aligned(*include_bytes!("../firmware/43439A0_clm.bin"));

// ================================================================================
// Entry point
// ================================================================================

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());
    info!("Pico W initializing");

    // ========================================================================
    // CYW43 WiFi driver init
    // ========================================================================

    // The Pico W onboard LED is controlled via the CYW43 WiFi chip
    // (not a direct GPIO), so we must initialize the WiFi driver even
    // just to blink the LED.
    let pwr = Output::new(p.PIN_23, Level::Low);
    let cs = Output::new(p.PIN_25, Level::High);
    let mut pio = Pio::new(p.PIO0, Irqs);
    let spi = PioSpi::new(
        &mut pio.common,
        pio.sm0,
        cyw43_pio::DEFAULT_CLOCK_DIVIDER,
        pio.irq0,
        cs,
        p.PIN_24,
        p.PIN_29,
        p.DMA_CH0,
    );

    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let (net_device, mut control, runner) = cyw43::new(state, pwr, spi, &FW.0).await;

    spawner
        .spawn(cyw43_task(runner))
        .expect("cyw43_task spawnable once");

    control.init(&CLM.0).await;
    control
        .set_power_management(cyw43::PowerManagementMode::PowerSave)
        .await;

    // ========================================================================
    // WiFi connection
    // ========================================================================

    let ssid = env!("WIFI_SSID");
    let pass = env!("WIFI_PASS");
    info!("Connecting to WiFi '{}' ...", ssid);

    loop {
        let mut opts = cyw43::JoinOptions::default();
        opts.passphrase = pass.as_bytes();
        match control.join(ssid, opts).await {
            Ok(_) => break,
            Err(e) => {
                info!("WiFi join failed: status={}", e.status);
                Timer::after(Duration::from_secs(1)).await;
            }
        }
    }
    info!("WiFi connected");

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

    let mac = control.address().await;
    info!("MAC address: {:02x}", mac);

    // Initialize the global network context so EmbassyNetworkInfo::default()
    // works during device state construction (IpLinkLayerState::from_config
    // calls P::default()).
    EmbassyNetworkInfo::init(stack, mac);

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
    let device_state = PicoWState::new(&identity);

    // The DHCP-assigned IP is used as the local address and control endpoint.
    let local_ip = stack
        .config_v4()
        .map(|c| Ipv4Addr::from(c.address.address().octets()))
        .unwrap_or(Ipv4Addr::UNSPECIFIED);

    let control_endpoint = SocketAddrV4::new(local_ip, 3671);

    // The embassy-net stack handle is passed as socket context — when the
    // KNX/IP servers call EmbassyUdpSocket::bind(), they receive it directly.
    let link_layer_builder =
        KnxNetIpBuilder::<EmbassyIpTransport, 2>::new("wlan0", local_ip, control_endpoint, stack)
            .enable_routing_server()
            .enable_remote_config_server();

    // Allocate stack resources in a static (embassy tasks need 'static).
    static KNX_RESOURCES: StaticCell<
        StackResources<
            PicoWLightSwitch,
            { zweidraehte::config::buffer_size_for_apdu(<PicoWLightSwitch as StackDefinition>::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte::new(
        KNX_RESOURCES.init(StackResources::new()),
        LightSwitchComObjects::new(),
        (), // hook context — no application hooks yet
        link_layer_builder,
        device_state,
        PicoWLightSwitch::memory_map(),
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
    // Main loop: heartbeat LED + event monitoring
    // ========================================================================

    // Discard the stack handle — this minimal firmware has no application
    // logic beyond what ETS programs. The KNX runner task handles all
    // protocol processing autonomously.
    let _ = knx_stack;

    loop {
        control.gpio_set(0, true).await;
        Timer::after(Duration::from_millis(500)).await;
        control.gpio_set(0, false).await;
        Timer::after(Duration::from_millis(500)).await;
    }
}
