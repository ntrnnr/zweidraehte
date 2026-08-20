#![no_std]
#![no_main]

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
    self, LightSwitchDevice, LightSwitchParams, comm_objs::LightSwitchComObjects, full::easter_egg::EasterEggAugment,
};
use zweidraehte_device::{
    bcus::system_b::{Ip, SystemBStateInit},
    layers::linklayers::knxip::{KnxNetIpBuilder, KnxNetIpDefinition, features::KnxIpDeviceUdp},
    prelude::*,
};

use rp_common::{
    EmbassyIpTransport, EmbassyNetworkInfo, EmbassyUdpContext, RpConfigRegion, RpFlash, RpFlashIo, UdpPool,
};

// ================================================================================
// Device Definition
// ================================================================================

/// Device descriptor from the light switch device definition (KNX/IP variant).
const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_IP;

#[derive(Debug, Clone, Copy)]
pub struct PicoWLightSwitchDefinition;

pub type PicoWLightSwitch = Ip<PicoWLightSwitchDefinition>;

// ================================================================================
// Capacity knobs
// ================================================================================
//
// All KNX/IP link-layer sizing flows from `KnxNetIpDefinition` defaults
// (`MAX_UDP_SOCKETS = 2`, no tunneling so `TUNNEL_CAPACITY = 0`, etc.).
// The embassy-net pool needs one extra slot for the DHCPv4 client.

/// UDP buffer pool size — must match `<PicoWLightSwitch as
/// KnxNetIpDefinition>::MAX_UDP_SOCKETS` (the trait default of 2).
/// Plus one slack slot for the always-bound discovery socket on the
/// System Setup multicast that lives outside the dedup pool.
const UDP_POOL_SIZE: usize = 3;

/// Device state combining System B tables with IP link-layer state.
type PicoWState = <PicoWLightSwitch as StackDefinition>::State;

// ----------------------------------------------------------------------------
// Storage layout — one config region on the shared RpFlash chip
// ----------------------------------------------------------------------------

// The device's storage memory map: a single config blob carrying this
// device's state as its payload. The `Placed` entry derives its placement,
// store type, and open() from the layout.
use zweidraehte_device::config::buffer_size_for_apdu;
use zweidraehte_device::storage::NoSaveGuard;
use zweidraehte_device::storage::{ConfigStorage, Placed, RegionSpec, StorageLayout, StoreOf};

// `pub`: the map reaches the public `StackDefinition` surface through
// `DeviceStorage`'s `StoreOf` projection.
pub struct StorageMap;
type Cfg = Placed<RpConfigRegion<PicoWState>, RpFlash, StorageMap>;
impl StorageLayout for StorageMap {
    const REGIONS: &'static [RegionSpec] = &[Cfg::SPEC];
}
type DeviceStorage = ConfigStorage<StoreOf<Cfg>>;

// ----------------------------------------------------------------------------
// Standard stack inputs
// ----------------------------------------------------------------------------

pub struct PicoWHooks;

impl DeviceHooks for PicoWHooks {
    type Augments<'a, D: StackDefinition> = EasterEggAugment;

    fn create_augments<'a, D: StackDefinition>(
        _state: &'a D::State,
        _platform: &'a D::Platform,
        _layer_ctx: &'a zweidraehte_device::context::layer::LayerContext<D>,
    ) -> Self::Augments<'a, D> {
        EasterEggAugment
    }
}

// IP-specific link-layer bill of materials. Routing-only UDP device,
// so `MAX_TCP_STREAMS / MAX_TCP_CHANNELS` default to 0 and produce
// zero-sized `TcpManager` storage. `MAX_UDP_SOCKETS = 3` covers
// discovery + control + routing — one slot more than the trait default
// of 2 because this device's routing multicast lives on a separate
// socket from the System Setup discovery multicast.
impl KnxNetIpDefinition for PicoWLightSwitchDefinition {
    type Transport = EmbassyIpTransport<{ <Self as KnxNetIpDefinition>::MAX_UDP_SOCKETS }>;
    type Features = KnxIpDeviceUdp;
    const MAX_UDP_SOCKETS: usize = 3;
}

impl DeviceDefinition for PicoWLightSwitchDefinition {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;

    type Platform = EmbassyNetworkInfo;
    type Params = LightSwitchParams;
    type ComObjects = LightSwitchComObjects;
    type LinkLayer = KnxNetIpBuilder<PicoWLightSwitch>;
    type Identity = rp_common::FlashIdentityData;
    type Storage = &'static DeviceStorage;
    type Hooks = PicoWHooks;
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
async fn cyw43_task(runner: cyw43::Runner<'static, Output<'static>, PioSpi<'static, PIO0, 0, DMA_CH0>>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, cyw43::NetDriver<'static>>) -> ! {
    runner.run().await
}

// ================================================================================
// Application Logic
// ================================================================================

zweidraehte_device::storage_task! {
    device: PicoWLightSwitch,
    system: embedded_common::CortexMSystem,
    guard: NoSaveGuard,
}

// ================================================================================
// Identity load
// ================================================================================
//
// Production builds: read the `KNXP` page; panic on any error.
// `provision-on-boot` builds: write the dev defaults from
// `dev_provisioning::DEV_*` and re-read.
//
// Pico W is special: the WiFi MAC comes from the cyw43 chip directly,
// so the KNXP `MAC` tag is ignored on this target. We still consume
// `SERIAL`; the Pico W has no Data Secure variant today, so `FDSK` is
// also ignored.

#[cfg(feature = "provision-on-boot")]
mod dev_provisioning {
    include!(concat!(env!("OUT_DIR"), "/dev_provisioning.rs"));
}

rp_common::rp_identity_loader!(plain, fdsk: None, mac: None);

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
    // Device identity (from flash — read/provision before anything else)
    // ========================================================================

    // The `Storage` `ConfigStore` borrows the `FLASH` peripheral through a
    // shared `&'static RefCell` (so secure devices can share it with their
    // sequence-number store). This device has no second flash consumer, but
    // must satisfy the same API, so lift the handle into a `StaticCell` too.
    let flash = rp_common::rp_flash_cell!(p.FLASH);
    let identity_data = load_identity(&mut flash.borrow_mut());

    let seed = identity_data.derive_seed();
    info!("Serial: {=[u8]:02x}", identity_data.serial_number);

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

    spawner.spawn(cyw43_task(runner)).expect("cyw43_task spawnable once");

    control.init(&CLM.0).await;
    control.set_power_management(cyw43::PowerManagementMode::PowerSave).await;

    // ========================================================================
    // WiFi connection
    // ========================================================================

    // WiFi credentials are baked in at compile time. We use `option_env!`
    // rather than `env!` so that a bare `cargo build` succeeds without the
    // variables set (e.g. for CI / build checks); the placeholder defaults
    // obviously won't join a real network. For a flashable firmware, set
    // `WIFI_SSID` and `WIFI_PASS` at build time:
    //
    //     WIFI_SSID=my-net WIFI_PASS=secret cargo build
    //
    // `build.rs` emits `rerun-if-env-changed` for both, so changing them
    // forces a rebuild even though the source is untouched.
    let ssid = option_env!("WIFI_SSID").unwrap_or("CHANGEME-SSID");
    let pass = option_env!("WIFI_PASS").unwrap_or("CHANGEME-PASS");
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

    static NET_RESOURCES: StaticCell<NetStackResources<{ PicoWLightSwitch::EMBASSY_NET_SOCKETS }>> = StaticCell::new();
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

    let platform = EmbassyNetworkInfo::new(stack, mac, rp_common::IP_ASSIGN_DHCP);

    // ========================================================================
    // Persistent storage
    // ========================================================================

    // Flash storage for persistent device state (the CONFIG region,
    // auto-placed at `RpFlash::BASE` by the layout consts above).
    // The `flash` handle was used transiently for identity provisioning
    // above and is now passed to the `ConfigStore` for config persistence.
    // The stores struct lives in a static so the storage task can reach it;
    // each store sits behind its own RefCell, borrowed per call on the
    // single-threaded executor.
    static STORAGE: StaticCell<DeviceStorage> = StaticCell::new();
    let storage =
        &*STORAGE.init(DeviceStorage::new(Cfg::open(RpFlashIo::new(flash)).expect("config open is infallible")));
    let loaded_config = storage.load_config();

    let state_init = SystemBStateInit::new(identity_data, loaded_config);

    // ========================================================================
    // KNX stack
    // ========================================================================

    // The DHCP-assigned IP is used as the local address and control endpoint.
    let local_ip =
        stack.config_v4().map(|c| Ipv4Addr::from(c.address.address().octets())).unwrap_or(Ipv4Addr::UNSPECIFIED);

    let control_endpoint = SocketAddrV4::new(local_ip, 3671);

    // Static UDP buffer pool — sized via the `KnxNetIpDefinition`
    // impl on `PicoWLightSwitch`. Owned by the binary so the device
    // pays for exactly the sockets it uses.
    static UDP_POOL: UdpPool<UDP_POOL_SIZE> = UdpPool::new();

    let socket_ctx = EmbassyUdpContext { stack, udp_pool: &UDP_POOL };

    // Features (routing + remote-config) and every numeric sizing knob
    // come from `PicoWLightSwitch`'s `KnxNetIpDefinition` impl. No more
    // `enable_*()` chain, no manually matched const generics.
    let link_layer_builder = KnxNetIpBuilder::<PicoWLightSwitch>::new("wlan0", local_ip, control_endpoint, socket_ctx);

    // Allocate stack resources in a static (embassy tasks need 'static).
    static KNX_RESOURCES: StaticCell<
        StackResources<
            PicoWLightSwitch,
            { buffer_size_for_apdu(<PicoWLightSwitch as StackDefinition>::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        platform,
        PicoWLightSwitch::memory_map(),
        storage,
    );

    spawner.spawn(knx_task(knx_runner)).expect("knx_task spawnable once");
    spawner.spawn(storage_task(knx_stack)).expect("storage_task spawnable once");

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
    // Main loop: heartbeat LED (saves live in the storage task)
    // ========================================================================

    loop {
        control.gpio_set(0, true).await;
        Timer::after(Duration::from_millis(500)).await;
        control.gpio_set(0, false).await;
        Timer::after(Duration::from_millis(500)).await;
    }
}
