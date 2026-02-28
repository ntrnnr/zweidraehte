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
    bind_interrupts,
    flash,
    gpio::{Input, Level, Output, Pull},
    peripherals::{SPI0, UART0},
    spi::{Async, Config as SpiConfig, Spi},
    uart::{Config as UartConfig, Parity, Uart},
};
use embassy_time::{Delay, Duration, Timer};
use embedded_hal_bus::spi::ExclusiveDevice;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use devices::ip_interface::{
    IpInterfaceComObjects, IpInterfaceDevice, IpInterfaceParams, DEVICE_DESCRIPTOR,
};

use zweidraehte::{
    bcus::system_b::*,
    config::MAX_APDU_LENGTH_EXTENDED,
    layers::linklayers::{
        ip_interface::IpInterfaceLinkLayerBuilder,
        knxip::{KnxNetIpBuilder, features::KnxIpInterfaceUdp},
    },
    prelude::*,
    restart::{RestartError, RestartResponse},
    storage::DeviceStorage,
};

use rp_common::button::DebouncedButton;
use rp_common::uart::{DirectInterruptHandler, DirectUart, DirectUartRx, DirectUartTx};
use rp_common::{EmbassyIpTransport, EmbassyNetworkInfo, FlashIdentityData, RpFlashStorage};

// ================================================================================
// Interrupt Bindings
// ================================================================================

bind_interrupts!(struct Irqs {
    UART0_IRQ => DirectInterruptHandler<UART0>;
});

// ================================================================================
// Device Definition
// ================================================================================

/// MAC vendor prefix for locally-administered MAC addresses.
const MAC_OUI: [u8; 3] = [0x02, 0x00, 0xFA];

const ADT_SIZE: usize = DEVICE_DESCRIPTOR.address_table_size();
const AST_SIZE: usize = DEVICE_DESCRIPTOR.association_table_size();
const COT_SIZE: usize = DEVICE_DESCRIPTOR.comm_object_table_size();

/// Device state: System B tables + IP link-layer state (additional IAs, IP config).
///
/// Uses `IpSystemBDeviceState` even though the mask is TP1 (07B0) — the state
/// type is mask-agnostic. The IP link-layer state stores additional individual
/// addresses for tunneling connections and IP configuration.
/// Maximum number of concurrent tunneling connections (additional individual addresses).
const MAX_TUNNEL_CONNECTIONS: usize = 4;

type IpIfState = IpSystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, IpInterfaceParams, EmbassyNetworkInfo, MAX_TUNNEL_CONNECTIONS>;

type Storage = RpFlashStorage<IpIfState, FlashIdentityData>;

// ================================================================================
// StackDefinition
// ================================================================================

// The IP Interface doesn't fit neatly into either `SystemBIpDeviceDef` or
// `SystemBTpDeviceDef` — it needs both TPUART (bus) and KNX/IP (tunneling).
// We implement `StackDefinition` directly and provide the memory helpers
// that the convenience traits would normally supply.

#[derive(Debug, Clone, Copy)]
struct PicoIpInterface;

impl PicoIpInterface {
    fn memory_layout() -> MemoryLayout {
        MemoryLayout::from_descriptor(
            SystemBMemoryMap::DEFAULT_BASE_ADDRESS,
            &DEVICE_DESCRIPTOR,
            core::mem::size_of::<IpInterfaceParams>(),
        )
    }

    fn memory_map() -> SystemBMemoryMap {
        SystemBMemoryMap::new(Self::memory_layout())
    }
}

impl StackDefinition for PicoIpInterface {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_EXTENDED;
    const TL_STYLE: TlStyle = TlStyle::Style1;

    type P = IpInterfaceParams;
    type CO = IpInterfaceComObjects;
    type LLB = IpInterfaceLinkLayerBuilder<DirectUartTx, DirectUartRx, EmbassyIpTransport, KnxIpInterfaceUdp<MAX_TUNNEL_CONNECTIONS>, 2, 1, 1>;
    type State = IpIfState;
    type Mem = SystemBMemoryMap;
    type InterfaceObjects<'a> = DefaultKnxIpInterfaceObjects<'a, IpIfState, (TunnelingAugment, ())>;

    fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
    {
        create_knxip_tunneling_objects::<Self, _>(state, &Self::memory_layout())
    }
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
async fn prog_task(
    knx: Stack<'static, PicoIpInterface>,
    prog_btn_pin: Input<'static>,
) -> ! {
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
async fn restart_task(
    knx: Stack<'static, PicoIpInterface>,
    storage: &'static RefCell<Storage>,
) -> ! {
    use platform::SystemControl;
    use rp_common::CortexMSystem;
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

        request.reply(response).await;

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
        }
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
    let identity_data = rp_common::read_or_provision_identity(
        &mut flash,
        IpInterfaceDevice::MANUFACTURER_ID.to_be_bytes(),
    );

    let mac_addr = identity_data.derive_mac_address(MAC_OUI);
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

    info!("W5500 initialized");

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
    // works during device state construction.
    EmbassyNetworkInfo::init(stack, mac_addr);

    // ========================================================================
    // Persistent storage
    // ========================================================================

    let mut storage = RpFlashStorage::<IpIfState, _>::new(flash, identity_data);

    let device_state = match storage.load() {
        Ok(Some(state)) => {
            info!("Loaded persisted state from flash");
            state
        }
        Ok(None) => {
            info!("No persisted state found, starting fresh");
            IpIfState::new(storage.identity())
        }
        Err(e) => {
            warn!("Flash load failed: {}, starting fresh", e);
            IpIfState::new(storage.identity())
        }
    };

    static STORAGE: StaticCell<RefCell<Storage>> = StaticCell::new();
    let storage = &*STORAGE.init(RefCell::new(storage));

    // ========================================================================
    // KNX stack — composite link layer (TPUART + KNX/IP)
    // ========================================================================

    let local_ip = stack
        .config_v4()
        .map(|c| Ipv4Addr::from(c.address.address().octets()))
        .unwrap_or(Ipv4Addr::UNSPECIFIED);

    let control_endpoint = SocketAddrV4::new(local_ip, 3671);

    // Build the KNX/IP part — tunneling + remote config (no routing).
    let knxip_builder =
        KnxNetIpBuilder::<EmbassyIpTransport, _, 2>::new("eth0", local_ip, control_endpoint, stack)
            .enable_tunneling::<MAX_TUNNEL_CONNECTIONS>()
            .enable_remote_config_server();

    // Wrap TPUART + KNX/IP into a single composite link layer.
    let link_layer_builder = IpInterfaceLinkLayerBuilder::new(uart_tx, uart_rx, knxip_builder);

    static KNX_RESOURCES: StaticCell<
        StackResources<
            PicoIpInterface,
            { zweidraehte::config::buffer_size_for_apdu(<PicoIpInterface as StackDefinition>::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte::new(
        KNX_RESOURCES.init(StackResources::new()),
        IpInterfaceComObjects::new(),
        (),
        link_layer_builder,
        device_state,
        PicoIpInterface::memory_map(),
    );

    spawner
        .spawn(knx_task(knx_runner))
        .expect("knx_task spawnable once");

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
