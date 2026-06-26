#![no_std]
#![no_main]

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
    bcus::system_b::{Extension, IpAugmentFor, IpExtensionFor, IpStateFor, SystemBStackDefinition, SystemBStateInit},
    layers::linklayers::knxip::{KnxNetIpBuilder, KnxNetIpDefinition, features::KnxIpDeviceUdp},
    prelude::*,
};

use rp_common::{EmbassyIpTransport, EmbassyNetworkInfo, EmbassyUdpContext, RpFlashStorage, UdpPool};

// ================================================================================
// Device Definition
// ================================================================================

/// Device descriptor from the light switch device definition (KNX/IP variant).
const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_IP;

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
type PicoWState = IpStateFor<PicoWLightSwitch, KnxIpDeviceUdp>;

/// Flash storage handle, shared between the main loop (periodic save)
/// and the restart handler (save before reset).
type Storage = RpFlashStorage<PicoWState, rp_common::FlashIdentityData>;

// ----------------------------------------------------------------------------
// StackDefinition
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct PicoWLightSwitch;

/// Augment chain: KNXnet/IP medium augment plus the demo Easter Egg
/// augment.
#[derive(zweidraehte_device::service::ServiceRegistry)]
struct PicoWAugments<'a> {
    #[service(augment)]
    ip: IpAugmentFor<'a, EmbassyNetworkInfo, KnxIpDeviceUdp>,
    #[service(augment)]
    easter: EasterEggAugment,
}

// IP-specific link-layer bill of materials. Routing-only UDP device,
// so `MAX_TCP_STREAMS / MAX_TCP_CHANNELS` default to 0 and produce
// zero-sized `TcpManager` storage. `MAX_UDP_SOCKETS = 3` covers
// discovery + control + routing — one slot more than the trait default
// of 2 because this device's routing multicast lives on a separate
// socket from the System Setup discovery multicast.
impl KnxNetIpDefinition for PicoWLightSwitch {
    type Transport = EmbassyIpTransport<{ <Self as KnxNetIpDefinition>::MAX_UDP_SOCKETS }>;
    type Features = KnxIpDeviceUdp;
    const MAX_UDP_SOCKETS: usize = 3;
}

zweidraehte_device::system_b_standard_stack! {
    stack: PicoWLightSwitch,
    device: &DEVICE_DESCRIPTOR,
    tl_style: TlStyle::Style1,
    params: LightSwitchParams,
    com_objects: LightSwitchComObjects,
    link_layer_builder: KnxNetIpBuilder<PicoWLightSwitch>,
    platform: EmbassyNetworkInfo,
    extension_state: IpExtensionFor<KnxIpDeviceUdp>,
    state: PicoWState,
    al_extensions: (
        zweidraehte_device::layers::application::services::SystemBAlServices,
        zweidraehte_device::layers::application::services::DomainAddressService,
    ),
    layer_builder: InsecureIpDeviceBuilder,
    augments: {
        bundle: PicoWAugments,
        create: |state, platform, _layer_ctx| PicoWAugments {
            ip: state.extension_state().create_augment::<Self>(platform),
            easter: EasterEggAugment,
        },
    },
    extra {
        type Identity = rp_common::FlashIdentityData;
    },
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
    use embedded_common::CortexMSystem;
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

/// On-demand persistence handler.
///
/// The stack requests an immediate save when waiting for the periodic
/// poll or restart would be wrong — at the end of an ETS download
/// (`EtsDownloadComplete`) and for spec-mandated durability points
/// (e.g. the IP Secure mc_timer watermark, which gates secure routing
/// sends on the reply). The signal is always answered (`done()`), even
/// when the save failed — gated requesters inside the stack block
/// until the reply.
#[embassy_executor::task]
async fn persist_task(knx: Stack<'static, PicoWLightSwitch>, storage: &'static RefCell<Storage>) -> ! {
    loop {
        let request = knx.receive_persist_request().await;
        if knx.state().is_dirty() {
            info!("Persist request — saving state");
            save_state(knx.state(), storage);
        }
        request.reply(()).await;
    }
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

fn load_identity(
    flash: &mut embassy_rp::flash::Flash<
        'static,
        embassy_rp::peripherals::FLASH,
        embassy_rp::flash::Blocking,
        { 2 * 1024 * 1024 },
    >,
) -> rp_common::FlashIdentityData {
    let mut unique_id = [0u8; 8];
    flash.blocking_unique_id(&mut unique_id).expect("flash unique ID");

    match rp_common::read_provisioning(flash) {
        Ok(rec) => rp_common::identity_from_record(&rec, unique_id),
        #[cfg(feature = "provision-on-boot")]
        Err(e) => {
            warn!("no KNXP record ({:?}); writing dev defaults from build.rs", e);
            rp_common::synthesize_and_write(flash, dev_provisioning::DEV_SERIAL, None, None).expect("write dev KNXP");
            let rec = rp_common::read_provisioning(flash).expect("re-read freshly written KNXP");
            rp_common::identity_from_record(&rec, unique_id)
        }

        #[cfg(not(feature = "provision-on-boot"))]
        Err(e) => defmt::panic!("no valid KNXP record: {:?}", e),
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

    // `RpFlashStorage` borrows the `FLASH` peripheral through a shared
    // `&'static RefCell` (so secure devices can share it with their
    // sequence-number store). This device has no second flash consumer, but
    // must satisfy the same API, so lift the handle into a `StaticCell` too.
    let flash = embassy_rp::flash::Flash::<_, flash::Blocking, { 2 * 1024 * 1024 }>::new_blocking(p.FLASH);
    static FLASH_CELL: StaticCell<
        RefCell<
            embassy_rp::flash::Flash<'static, embassy_rp::peripherals::FLASH, flash::Blocking, { 2 * 1024 * 1024 }>,
        >,
    > = StaticCell::new();
    let flash = &*FLASH_CELL.init(RefCell::new(flash));
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

    // Flash storage for persistent device state (last 4 KiB sector).
    // The `flash` handle was used transiently for identity provisioning
    // above and is now passed to RpFlashStorage for config persistence.
    let mut storage = rp_common::rp_flash_storage::<PicoWState, _>(flash, identity_data);

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
            {
                zweidraehte_device::config::buffer_size_for_apdu(<PicoWLightSwitch as StackDefinition>::MAX_APDU_LENGTH)
            },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        platform,
        PicoWLightSwitch::memory_map(),
    );

    spawner.spawn(knx_task(knx_runner)).expect("knx_task spawnable once");
    spawner.spawn(restart_task(knx_stack, storage)).expect("restart_task spawnable once");
    spawner.spawn(persist_task(knx_stack, storage)).expect("persist_task spawnable once");

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
