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
#![feature(never_type)]

use core::cell::RefCell;
use core::net::{Ipv4Addr, SocketAddrV4};

use defmt::*;
use embassy_executor::Spawner;
use embassy_net::{DhcpConfig, StackResources as NetStackResources};
use embassy_net_wiznet::chip::W5500;
use embassy_rp::{
    bind_interrupts, flash,
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
    EmbassyIpTransportTcp, EmbassyNetworkInfo, EmbassyTcpContext, FlashIdentityData, RpFlashStorage, TcpPool, UdpPool,
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

/// Device state: System B tables + IP link-layer state (additional IAs, IP config).
///
/// Uses `IpSystemBDeviceState` even though the mask is TP1 (07B0) — the state
/// type is mask-agnostic. The IP link-layer state stores additional individual
/// addresses for tunneling connections and IP configuration. Table sizes
/// derive from `DEVICE_DESCRIPTOR` via the `SystemBStackDefinition`
/// associated consts.

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

type IpIfState = IpInterfaceStateFor<PicoIpInterface, KnxIpInterfaceTcp<MAX_TUNNEL_CONNECTIONS>>;

type Storage = RpFlashStorage<IpIfState, FlashIdentityData>;

// ================================================================================
// StackDefinition
// ================================================================================

// The IP Interface needs both TPUART (bus) and KNX/IP (tunneling), so it
// uses `IpInterfaceLinkLayerBuilder` instead of the standard single-medium
// link layer builders.

#[derive(Debug, Clone, Copy)]
struct PicoIpInterface;

// IP-specific link-layer bill of materials. `KnxIpInterfaceTcp<N>`
// pins routing+remote-config+tunneling+TCP. Every numeric sizing knob
// derives from `TUNNEL_CAPACITY = N` via the trait's defaults; only
// `MAX_UDP_SOCKETS = 2` (one for the System Setup multicast, one for
// unicast control on KNX_PORT) overrides the trait default.
impl KnxNetIpDefinition for PicoIpInterface {
    type Transport = EmbassyIpTransportTcp<
        { <Self as KnxNetIpDefinition>::MAX_UDP_SOCKETS },
        { <Self as KnxNetIpDefinition>::MAX_TCP_STREAMS },
    >;
    type Features = KnxIpInterfaceTcp<MAX_TUNNEL_CONNECTIONS>;
}

zweidraehte_device::system_b_standard_stack! {
    stack: PicoIpInterface,
    device: &DEVICE_DESCRIPTOR,
    tl_style: TlStyle::Style1,
    params: IpInterfaceParams,
    com_objects: IpInterfaceComObjects,
    link_layer_builder: IpInterfaceLinkLayerBuilder<DirectUartTx, DirectUartRx, PicoIpInterface>,
    platform: EmbassyNetworkInfo,
    extension_state: IpInterfaceExtensionFor<KnxIpInterfaceTcp<MAX_TUNNEL_CONNECTIONS>>,
    state: IpIfState,
    al_extensions: (
        zweidraehte_device::layers::application::services::SystemBAlServices,
        zweidraehte_device::layers::application::services::DomainAddressService,
    ),
    layer_builder: InsecureIpDeviceBuilder,
    extra {
        const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_EXTENDED;
        type Identity = FlashIdentityData;
    },
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
        btn.wait_for_press(debounce, None).await;

        let current = knx.state().is_programming_mode();
        knx.state().set_programming_mode(!current);
        info!("Programming mode: {}", !current);
    }
}

/// Restart handler — executes resets from ETS, persists state, and reboots.
#[embassy_executor::task]
async fn restart_task(knx: Stack<'static, PicoIpInterface>, storage: &'static RefCell<Storage>) -> ! {
    use embedded_common::CortexMSystem;
    use zweidraehte_device::restart::EraseCode;
    use zweidraehte_platform::SystemControl;

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
    }
}

/// Save device state to flash. Logs errors but does not propagate them.
fn save_state(state: &IpIfState, storage: &RefCell<Storage>) {
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
#[embassy_executor::task]
async fn lifecycle_task(knx: Stack<'static, PicoIpInterface>) -> ! {
    let mut events = knx.lifecycle_events();
    loop {
        match events.next_message_pure().await {
            LifecycleEvent::ApplicationStarted => {
                info!("Application STARTED");
            }
            LifecycleEvent::ApplicationStopped => {
                info!("Application STOPPED");
            }
            LifecycleEvent::PeiStarted => {
                info!("PEI STARTED");
            }
            LifecycleEvent::PeiStopped => {
                info!("PEI STOPPED");
            }
            _ => {}
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

fn load_identity(
    flash: &mut embassy_rp::flash::Flash<'static, embassy_rp::peripherals::FLASH, flash::Blocking, { 2 * 1024 * 1024 }>,
) -> FlashIdentityData {
    let mut unique_id = [0u8; 8];
    flash.blocking_unique_id(&mut unique_id).expect("flash unique ID");

    match rp_common::read_provisioning(flash) {
        Ok(rec) => rp_common::identity_from_record(&rec, unique_id),

        #[cfg(feature = "provision-on-boot")]
        Err(e) => {
            warn!("no KNXP record ({:?}); writing dev defaults from build.rs", e);
            rp_common::synthesize_and_write(flash, dev_provisioning::DEV_SERIAL, None, Some(dev_provisioning::DEV_MAC))
                .expect("write dev KNXP");
            let rec = rp_common::read_provisioning(flash).expect("re-read freshly written KNXP");
            rp_common::identity_from_record(&rec, unique_id)
        }

        #[cfg(not(feature = "provision-on-boot"))]
        Err(e) => defmt::panic!("no valid KNXP record: {:?}", e),
    }
}

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

    let mut flash = embassy_rp::flash::Flash::<_, flash::Blocking, { 2 * 1024 * 1024 }>::new_blocking(p.FLASH);
    let identity_data = load_identity(&mut flash);

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

    let mut storage = RpFlashStorage::<IpIfState, _>::new(flash, identity_data);

    let loaded_config = match storage.load_config() {
        Ok(Some(c)) => {
            info!("Loaded device config from flash");
            Some(c)
        }
        Ok(None) => {
            info!("No stored config found, starting fresh");
            None
        }
        Err(e) => {
            warn!("Flash load failed: {}, starting fresh", e);
            None
        }
    };

    let state_init = SystemBStateInit::new(storage.identity().clone(), loaded_config);

    static STORAGE: StaticCell<RefCell<Storage>> = StaticCell::new();
    let storage = &*STORAGE.init(RefCell::new(storage));

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
            { zweidraehte_device::config::buffer_size_for_apdu(<PicoIpInterface as StackDefinition>::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        platform,
        PicoIpInterface::memory_map(),
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
    spawner.spawn(restart_task(knx_stack, storage)).expect("restart_task spawnable once");
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
