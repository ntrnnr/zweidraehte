//! KNX IP Interface on Raspberry Pi Pico (RP2040)
//!
//! Bridges KNX/IP tunneling connections to a TP1 bus. Combines:
//! - W5500 Ethernet (SPI0) for KNX/IP tunneling + discovery
//! - NCN5120 TPUART (UART0) for TP1 bus access
//!
//! The composite `IpInterfaceLinkLayerBuilder` wraps both link layers
//! behind a single `LinkLayerBuilder` that the KNX stack sees as one unit.

#![no_std]
#![no_main]

use core::net::{Ipv4Addr, SocketAddrV4};

use defmt::*;
use embassy_executor::Spawner;
use embassy_net::{DhcpConfig, StackResources as NetStackResources};
use embassy_net_wiznet::chip::W5500;
use embassy_rp::{
    bind_interrupts,
    gpio::{Input, Level, Output, Pull},
    peripherals::{SPI0, UART0},
    spi::{Async, Config as SpiConfig, Spi},
    uart::{Config as UartConfig, Parity, Uart},
};
use embassy_time::{Delay, Duration, Timer};
use embedded_hal_bus::spi::ExclusiveDevice;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use devices::ip_interface::{DEVICE_DESCRIPTOR, IpInterfaceComObjects, IpInterfaceDevice, IpInterfaceParams};

use zweidraehte_device::{
    bcus::system_b::*,
    config::MAX_APDU_LENGTH_EXTENDED,
    layers::linklayers::{
        ip_interface::IpInterfaceLinkLayerBuilder,
        knxip::{KnxNetIpBuilder, KnxNetIpDefinition, features::KnxIpInterfaceTcp},
    },
    prelude::*,
};

use embedded_common::DebouncedButton;
use rp_common::uart::{DirectInterruptHandler, DirectUart, DirectUartRx, DirectUartTx};
use rp_common::{
    EmbassyIpTransportTcp, EmbassyNetworkInfo, EmbassyTcpContext, FlashIdentityData, RpConfigRegion, RpFlash,
    RpFlashIo, TcpPool, UdpPool,
};

// ================================================================================
// Interrupt Bindings
// ================================================================================

bind_interrupts!(struct Irqs {
    UART0_IRQ => DirectInterruptHandler<UART0>;
});

// ================================================================================
// Device Definition
// ================================================================================

// The standard IP-interface preset keeps the product's TP1 System B mask while
// composing the IP Parameter Object, additional tunnelling addresses, and the
// composite KNX/IP-to-TP1 link layer.

// ================================================================================
// Capacity knobs
// ================================================================================
//
// One source of truth: `MAX_TUNNEL_CONNECTIONS`. Everything else is
// either a fixed-by-the-spec dimension (UDP socket count after port
// dedup) or a worst-case derivation from the tunnel count.
//
// The KNX/IP stack and embassy-net pools each take their own const
// generics. They all eventually trace back to one of these names —
// avoid repeating bare numbers.

/// Maximum number of concurrent tunneling connections (additional
/// individual addresses).
/// Maximum concurrent tunneling connections. Drives every other
/// link-layer sizing through `KnxNetIpDefinition`'s defaults
/// (`MAX_TCP_STREAMS`, `MAX_TCP_CHANNELS`, `MAX_SECURE_SESSIONS` all
/// default to `TUNNEL_CAPACITY`). One number, one place.
const MAX_TUNNEL_CONNECTIONS: usize = 4;

#[derive(Debug, Clone, Copy)]
pub struct PicoIpInterfaceDefinition;

pub type PicoIpInterface = IpInterface<PicoIpInterfaceDefinition>;
type IpIfState = <PicoIpInterface as StackDefinition>::State;

// ----------------------------------------------------------------------------
// Storage layout — one config region on the shared RpFlash chip
// ----------------------------------------------------------------------------

// The device's storage memory map: a single config blob carrying this
// device's state as its payload. The `Placed` entry derives its placement,
// store type, and open() from the layout.
use zweidraehte_device::config::buffer_size_for_apdu;
use zweidraehte_device::lifecycle::lifecycle_event_logger;
use zweidraehte_device::storage::NoSaveGuard;
use zweidraehte_device::storage::{ConfigStorage, Placed, RegionSpec, StorageLayout, StoreOf};

// `pub`: the map reaches the public `StackDefinition` surface through
// `DeviceStorage`'s `StoreOf` projection.
pub struct StorageMap;
type Cfg = Placed<RpConfigRegion<IpIfState>, RpFlash, StorageMap>;
impl StorageLayout for StorageMap {
    const REGIONS: &'static [RegionSpec] = &[Cfg::SPEC];
}
type DeviceStorage = ConfigStorage<StoreOf<Cfg>>;

// ================================================================================
// Standard stack inputs
// ================================================================================

// The IP Interface needs both TPUART (bus) and KNX/IP (tunneling), so it
// uses `IpInterfaceLinkLayerBuilder` instead of the standard single-medium
// link layer builders.

// IP-specific link-layer bill of materials. `KnxIpInterfaceTcp<N>`
// pins routing+remote-config+tunneling+TCP. Every numeric sizing knob
// derives from `TUNNEL_CAPACITY = N` via the trait's defaults; only
// `MAX_UDP_SOCKETS = 2` (one for the System Setup multicast, one for
// unicast control on KNX_PORT) overrides the trait default.
impl KnxNetIpDefinition for PicoIpInterfaceDefinition {
    type Transport = EmbassyIpTransportTcp<
        { <Self as KnxNetIpDefinition>::MAX_UDP_SOCKETS },
        { <Self as KnxNetIpDefinition>::MAX_TCP_STREAMS },
    >;
    type Features = KnxIpInterfaceTcp<MAX_TUNNEL_CONNECTIONS>;
}

impl DeviceDefinition for PicoIpInterfaceDefinition {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_EXTENDED;

    type Platform = EmbassyNetworkInfo;
    type Params = IpInterfaceParams;
    type ComObjects = IpInterfaceComObjects;
    type LinkLayer = IpInterfaceLinkLayerBuilder<DirectUartTx, DirectUartRx, PicoIpInterface>;
    type Identity = FlashIdentityData;
    type Storage = &'static DeviceStorage;
}

// ================================================================================
// Embassy Tasks
// ================================================================================

#[embassy_executor::task]
async fn knx_task(runner: Runner<'static, PicoIpInterface>) -> ! {
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

/// Programming mode button handler.
#[embassy_executor::task]
async fn prog_task(knx: Stack<'static, PicoIpInterface>, prog_btn_pin: Input<'static>) -> ! {
    let mut btn = DebouncedButton::new(prog_btn_pin);
    let debounce = Duration::from_millis(50);

    loop {
        btn.wait_for_event(debounce, None).await;

        let current = knx.state().is_programming_mode();
        knx.state().set_programming_mode(!current);
        info!("Programming mode: {}", !current);
    }
}

zweidraehte_device::storage_task! {
    device: PicoIpInterface,
    system: embedded_common::CortexMSystem,
    guard: NoSaveGuard,
}

/// Lifecycle event logger.
#[embassy_executor::task]
async fn lifecycle_task(knx: Stack<'static, PicoIpInterface>) -> ! {
    lifecycle_event_logger(knx).await
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
// Entry Point
// ================================================================================

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());
    info!("Pico IP Interface (W5500 + NCN5120) initializing");

    // ========================================================================
    // Device identity (from flash — must happen before W5500 init for MAC)
    // ========================================================================

    // The flash peripheral is shared through a `&'static RefCell` so the
    // `RpFlashIo` handle can be lent to the config store without lifetime
    // friction. This device has no second flash consumer, but the API
    // requires a shared reference, so we lift the handle into a `StaticCell`.
    let flash = rp_common::rp_flash_cell!(p.FLASH);
    let identity_data = load_identity(&mut flash.borrow_mut());

    let mac_addr = identity_data.mac_address();
    let seed = identity_data.derive_seed();
    info!("Serial: {=[u8]:02x}", identity_data.serial_number);
    info!("MAC:    {=[u8]:02x}", mac_addr);

    // ========================================================================
    // UART0 init — NCN5120 TPUART at 19200 baud, even parity
    // ========================================================================

    let mut uart_config = UartConfig::default();
    uart_config.baudrate = 19200;
    uart_config.parity = Parity::ParityEven;

    let uart = Uart::new_blocking(
        p.UART0,
        p.PIN_0, // TX = GP0
        p.PIN_1, // RX = GP1
        uart_config,
    );
    let (uart_tx, uart_rx) = DirectUart::new::<UART0>(uart, Irqs);

    info!("UART0 initialized (19200 8E1, direct register access)");

    // ========================================================================
    // W5500 SPI init
    // ========================================================================

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

    info!("W5500 initialized");

    spawner.spawn(w5500_task(w5500_runner)).expect("w5500_task spawnable once");

    // ========================================================================
    // Embassy-net stack init (DHCP)
    // ========================================================================

    // Embassy-net socket pool: DHCP + every UDP socket the link-layer
    // binds + every TCP stream it accepts. Centralised on the
    // `KnxNetIpDefinition` impl as `EMBASSY_NET_SOCKETS`; no more
    // hand-coordinated arithmetic.
    static NET_RESOURCES: StaticCell<NetStackResources<{ PicoIpInterface::EMBASSY_NET_SOCKETS }>> = StaticCell::new();
    let (stack, net_runner) = embassy_net::new(
        net_device,
        embassy_net::Config::dhcpv4(DhcpConfig::default()),
        NET_RESOURCES.init(NetStackResources::new()),
        seed,
    );

    spawner.spawn(net_task(net_runner)).expect("net_task spawnable once");

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

    let platform = EmbassyNetworkInfo::new(stack, mac_addr, rp_common::IP_ASSIGN_DHCP);

    // ========================================================================
    // Persistent storage
    // ========================================================================

    // The stores struct lives in a static so the storage task can reach it;
    // each store sits behind its own RefCell, borrowed per call on the
    // single-threaded executor.
    static STORAGE: StaticCell<DeviceStorage> = StaticCell::new();
    let storage =
        &*STORAGE.init(DeviceStorage::new(Cfg::open(RpFlashIo::new(flash)).expect("config open is infallible")));
    let loaded_config = storage.load_config();

    let state_init = SystemBStateInit::new(identity_data, loaded_config);

    // ========================================================================
    // KNX stack — composite link layer (TPUART + KNX/IP)
    // ========================================================================

    let local_ip =
        stack.config_v4().map(|c| Ipv4Addr::from(c.address.address().octets())).unwrap_or(Ipv4Addr::UNSPECIFIED);

    let control_endpoint = SocketAddrV4::new(local_ip, 3671);

    static UDP_POOL: UdpPool<{ PicoIpInterface::MAX_UDP_SOCKETS }> = UdpPool::new();
    static TCP_POOL: TcpPool<{ PicoIpInterface::MAX_TCP_STREAMS }> = TcpPool::new();

    let socket_ctx = EmbassyTcpContext { stack, udp_pool: &UDP_POOL, tcp_pool: &TCP_POOL };

    // Build the KNX/IP part. Features (tunneling + remote-config + TCP)
    // and every numeric sizing knob come from `PicoIpInterface`'s
    // `KnxNetIpDefinition` impl. No `enable_*()` chain, no manually
    // matched const generics.
    let knxip_builder = KnxNetIpBuilder::<PicoIpInterface>::new("eth0", local_ip, control_endpoint, socket_ctx);

    // Wrap TPUART + KNX/IP into a single composite link layer.
    let link_layer_builder = IpInterfaceLinkLayerBuilder::new(uart_tx, uart_rx, knxip_builder);

    static KNX_RESOURCES: StaticCell<
        StackResources<
            PicoIpInterface,
            { buffer_size_for_apdu(<PicoIpInterface as StackDefinition>::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        platform,
        PicoIpInterface::memory_map(),
        storage,
    );

    spawner.spawn(knx_task(knx_runner)).expect("knx_task spawnable once");

    info!("KNX IP Interface started");
    info!("  Manufacturer: {:04x}", IpInterfaceDevice::MANUFACTURER_ID);
    info!("  Application:  {:04x} v{:02x}", IpInterfaceDevice::APPLICATION_ID, IpInterfaceDevice::APPLICATION_VERSION);
    info!("  Local IP:     {}", local_ip);
    info!("  Mask version: 07B0 (System B TP1)");
    info!("  Tunnels:      {}", IpInterfaceDevice::ADDITIONAL_IA_COUNT);

    // ========================================================================
    // GPIO tasks
    // ========================================================================

    let prog_btn_pin = Input::new(p.PIN_17, Pull::Up);

    spawner.spawn(prog_task(knx_stack, prog_btn_pin)).expect("prog_task spawnable once");
    spawner.spawn(storage_task(knx_stack)).expect("storage_task spawnable once");
    spawner.spawn(lifecycle_task(knx_stack)).expect("lifecycle_task spawnable once");

    // ========================================================================
    // Main loop: heartbeat LED + programming mode LED
    // ========================================================================

    // No application-level logic — IP Interface is a pure bridge device.
    // No periodic flash saves — flash sector erase stalls the CPU for
    // ~45-73ms which causes UART overruns at 19200 baud. State is saved
    // exclusively in the restart handler before reboot.

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
