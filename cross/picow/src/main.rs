#![no_std]
#![no_main]
#![feature(never_type)]

mod net;
mod network_info;
mod storage;
mod system;

use cyw43_pio::PioSpi;
use defmt::*;
use embassy_executor::Spawner;
use embassy_net::{DhcpConfig, StackResources as NetStackResources};
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{DMA_CH0, PIO0};
use embassy_rp::pio::{self, Pio};
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

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

    // The stack handle is passed to KnxNetIpBuilder as the socket context,
    // so EmbassyUdpSocket::bind() receives it directly — no global needed.

    // ========================================================================
    // Platform layer
    // ========================================================================

    let mac = control.address().await;
    info!("MAC address: {:02x}", mac);

    let _network_info = network_info::PicoWNetworkInfo::new(stack, mac, 0x04 /* DHCP */);
    let _system = system::PicoWSystem;

    // Flash storage for persistent device state.
    // let flash = embassy_rp::flash::Flash::<_, flash::Blocking, { 2 * 1024 * 1024 }>::new_blocking(p.FLASH);
    // let _storage = storage::FlashStorage::<PersistedState>::new(flash);

    // ========================================================================
    // KNX stack (TODO)
    // ========================================================================

    // TODO: Define device descriptor, communication objects, and StackDefinition
    // impl for this embedded KNX/IP device. Then:
    //
    // 1. Create KnxNetIpBuilder::<PicoWIpTransport, 2>::new(..., stack)
    //    with .enable_routing_server().enable_remote_config_server()
    //
    // 2. Create SystemBDeviceState with IpLinkLayerState<PicoWNetworkInfo>
    //    (or load from flash via FlashStorage)
    //
    // 3. Call zweidraehte::new(resources, comm_objs, (), builder, state, memory_map)
    //
    // 4. Spawn runner.run() as a separate task
    //
    // 5. Main loop: handle application events, blink LED as heartbeat

    info!("Platform layer initialized, entering heartbeat loop");
    info!("KNX stack wiring is TODO — see main.rs comments");

    // ========================================================================
    // Heartbeat LED
    // ========================================================================

    loop {
        control.gpio_set(0, true).await;
        Timer::after(Duration::from_millis(500)).await;
        control.gpio_set(0, false).await;
        Timer::after(Duration::from_millis(500)).await;
    }
}
