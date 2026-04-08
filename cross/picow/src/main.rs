#![no_std]
#![no_main]
#![feature(never_type)]

use core::cell::RefCell;
use core::net::{Ipv4Addr, SocketAddrV4};

use cyw43_pio::PioSpi;
use defmt::*;
use embassy_executor::Spawner;
use embassy_net::{DhcpConfig, StackResources as NetStackResources};
use embassy_rp::{
    bind_interrupts, flash,
    gpio::{Level, Output},
    peripherals::{DMA_CH0, PIO0},
    pio::{self, Pio},
};
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use devices::light_switch::{
    self, LightSwitchDevice, LightSwitchParams, comm_objs::LightSwitchComObjects, easter_egg::EasterEggAugment,
};
use zweidraehte_device::{
    bcus::system_b::{
        DefaultSystemBInterfaceObjects, IpAugmentFor, IpDeviceState, IpExtension, SystemBMemoryMap,
        SystemBStackDefinition, create_system_b_objects_with_extra,
    },
    layers::linklayers::knxip::{KnxNetIpBuilder, features::KnxIpDeviceUdp},
    prelude::*,
    storage::DeviceStorage,
};

use rp_common::{EmbassyIpTransport, EmbassyNetworkInfo, RpFlashStorage};

// ================================================================================
// Device Definition
// ================================================================================

/// Device descriptor from the light switch device definition (KNX/IP variant).
const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_IP;

const ADT_SIZE: usize = DEVICE_DESCRIPTOR.address_table_size();
const AST_SIZE: usize = DEVICE_DESCRIPTOR.association_table_size();
const COT_SIZE: usize = DEVICE_DESCRIPTOR.comm_object_table_size();

/// Device state combining System B tables with IP link-layer state.
type PicoWState = IpDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, LightSwitchParams, KnxIpDeviceUdp>;

/// Flash storage handle, shared between the main loop (periodic save)
/// and the restart handler (save before reset).
type Storage = RpFlashStorage<PicoWState, rp_common::FlashIdentityData>;

// ----------------------------------------------------------------------------
// StackDefinition
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct PicoWLightSwitch;

impl SystemBStackDefinition for PicoWLightSwitch {}

impl StackDefinition for PicoWLightSwitch {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const TL_STYLE: TlStyle = TlStyle::Style1;

    type P = LightSwitchParams;
    type CO = LightSwitchComObjects;
    type LLB = KnxNetIpBuilder<EmbassyIpTransport, KnxIpDeviceUdp, 2>;
    type Platform = EmbassyNetworkInfo;
    type ES = IpExtension<KnxIpDeviceUdp>;
    type State = PicoWState;
    type Mem = SystemBMemoryMap;
    type InterfaceObjects<'a> = DefaultSystemBInterfaceObjects<
        'a,
        PicoWState,
        (IpAugmentFor<'a, EmbassyNetworkInfo, KnxIpDeviceUdp>, EasterEggAugment),
    >;

    fn create_interface_objects<'a>(state: &'a Self::State, platform: &'a Self::Platform) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
    {
        create_system_b_objects_with_extra::<Self, _>(state, platform, &Self::memory_layout(), EasterEggAugment)
    }

    type AlExtension = (
        zweidraehte_device::layers::application::extensions::SystemBAlExtensions,
        zweidraehte_device::layers::application::extensions::DomainAddressExtension,
    );
    type LayerBuilder = InsecureIpDeviceBuilder;
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

/// Restart handler — executes resets from ETS, persists state, and reboots.
///
/// When the KNX stack receives an A_Restart request (e.g. from ETS during
/// programming or factory reset), this task:
/// 1. Executes the appropriate reset based on the erase code
/// 2. Saves the (possibly modified) state to flash
/// 3. Sends the A_Restart_Response back to the stack
/// 4. Triggers a Cortex-M system reset
#[embassy_executor::task]
async fn restart_task(knx: Stack<'static, PicoWLightSwitch>, storage: &'static RefCell<Storage>) -> ! {
    use rp_common::CortexMSystem;
    use zweidraehte_device::restart::EraseCode;
    use zweidraehte_platform::SystemControl;

    loop {
        let request = knx.receive_restart_request().await;
        let state = knx.state();

        info!("Restart request: erase_code={}", request.erase_code);

        // The stack already sent the A_Restart_Response on the bus.
        // We just need to execute the reset.
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
fn save_state(state: &PicoWState, storage: &RefCell<Storage>) {
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

    let mut flash = embassy_rp::flash::Flash::<_, flash::Blocking, { 2 * 1024 * 1024 }>::new_blocking(p.FLASH);
    let identity_data =
        rp_common::read_or_provision_identity(&mut flash, LightSwitchDevice::MANUFACTURER_ID.to_be_bytes());

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

    let platform = EmbassyNetworkInfo::new(stack, mac, rp_common::IP_ASSIGN_DHCP);

    // ========================================================================
    // Persistent storage
    // ========================================================================

    // Flash storage for persistent device state (last 4 KiB sector).
    // The `flash` handle was used transiently for identity provisioning
    // above and is now passed to RpFlashStorage for config persistence.
    let mut storage = RpFlashStorage::<PicoWState, _>::new(flash, identity_data);

    let device_state = match storage.load() {
        Ok(Some(state)) => {
            info!("Loaded persisted state from flash");
            state
        }
        Ok(None) => {
            info!("No persisted state found, starting fresh");
            PicoWState::new(storage.identity())
        }
        Err(e) => {
            warn!("Flash load failed: {}, starting fresh", e);
            PicoWState::new(storage.identity())
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
    let local_ip =
        stack.config_v4().map(|c| Ipv4Addr::from(c.address.address().octets())).unwrap_or(Ipv4Addr::UNSPECIFIED);

    let control_endpoint = SocketAddrV4::new(local_ip, 3671);

    // The embassy-net stack handle is passed as socket context — when the
    // KNX/IP servers call EmbassyUdpSocket::bind(), they receive it directly.
    let link_layer_builder =
        KnxNetIpBuilder::<EmbassyIpTransport, _, 2>::new("wlan0", local_ip, control_endpoint, stack)
            .enable_routing_server()
            .enable_remote_config_server();

    // Allocate stack resources in a static (embassy tasks need 'static).
    static KNX_RESOURCES: StaticCell<
        StackResources<
            PicoWLightSwitch,
            {
                zweidraehte_device::config::buffer_size_for_apdu(<PicoWLightSwitch as StackDefinition>::MAX_APDU_LENGTH)
            },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        LightSwitchComObjects::new(),
        (), // hook context — no application hooks yet
        link_layer_builder,
        device_state,
        platform,
        PicoWLightSwitch::memory_map(),
    );

    spawner.spawn(knx_task(knx_runner)).expect("knx_task spawnable once");
    spawner.spawn(restart_task(knx_stack, storage)).expect("restart_task spawnable once");

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
    // Main loop: heartbeat LED + periodic save
    // ========================================================================

    loop {
        control.gpio_set(0, true).await;
        Timer::after(Duration::from_millis(500)).await;
        control.gpio_set(0, false).await;
        Timer::after(Duration::from_millis(500)).await;

        // Periodically persist any state changes from ETS programming
        // (table writes, parameter changes, address changes, etc.).
        // The restart handler also saves before rebooting, but this
        // catches changes that don't involve a restart.
        if knx_stack.state().is_dirty() {
            save_state(knx_stack.state(), storage);
        }
    }
}
