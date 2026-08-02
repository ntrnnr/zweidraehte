#![no_std]
#![no_main]
// `type PicoEthSecureState = SecureIpInterfaceStateFor<…>` expands to
// const expressions over `SystemBStackDefinition::{ADT,AST,COT}_SIZE` —
// the same flag `zweidraehte-device` already requires.
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

//! Raspberry Pi Pico + W5500 **KNX IP Secure + Data Secure** light switch.
//!
//! Secure sibling of [`pico_eth_light_switch`](../eth_light_switch). Same hardware (W5500 SPI
//! Ethernet on an RP2040) and same application logic, but the stack adds
//! two independent security mechanisms:
//!
//! - **KNX IP Secure (secure multicast routing)** — the KNXnet/IP
//!   backbone is secured with `SecureGroupSync` + `SecureWrapper` once
//!   ETS provisions a backbone key (PID 91) and enables the secured
//!   Routing family (PID 94). Until then the device routes plain, exactly
//!   like `pico_eth_light_switch`. The feature set is routing-only secure
//!   ([`SecureRoutingTcp`]) — no tunnelling, but with TCP, which every KNX
//!   IP Secure profile must provide (Core v2, 03/08/09 §2.5.1.1 +
//!   03/08/02 Core §9.2).
//! - **KNX Data Secure** — group telegrams are encrypted end-to-end via
//!   the [`SecureApplicationLayer`], independent of the IP medium. Driven
//!   by `SecureIpDeviceBuilder`.
//!
//! These are orthogonal: ETS can enable either, both, or neither. The
//! plain-routing/plain-APDU factory default is the same as `pico_eth_light_switch`.
//!
//! # Security notes
//!
//! - **FDSK lives in plain flash.** Production units get it from the
//!   `KNXP` provisioning record written by `tools/knx-provision` over
//!   SWD; `provision-on-boot` dev builds synthesize the record from
//!   build-time dev defaults (`ZZ_FDSK_HEX`-overridable). Either way
//!   there is no readout protection — whoever can read the flash can
//!   extract the key.
//! - **RNG seed quality** — the RP2040 ROSC is a low-quality entropy
//!   source. We oversample and condition it (see `rp_common::rng`), but
//!   it is weaker than a real TRNG.

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
    layers::linklayers::knxip::{KnxNetIpBuilder, KnxNetIpDefinition, features::KnxIpSecureRoutingTcp},
    prelude::*,
    storage::SecureDeviceIdentity,
};

use embedded_common::DebouncedButton;
use rp_common::storage::SECTOR_SIZE;
use rp_common::{
    EmbassyIpTransportTcp, EmbassyNetworkInfo, EmbassyTcpContext, FlashSecureIdentityData, RpCommonRng, RpConfigRegion,
    RpFlash, RpFlashIo, RpMcTimerRegion, TcpPool, UdpPool,
};

// ================================================================================
// Device Definition
// ================================================================================

/// Device descriptor from the light switch device definition (combined
/// IP Secure + Data Secure KNX/IP variant, mask 57B0, application 0x0305).
const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_IP_SECURE;

// ================================================================================
// Capacity knobs
// ================================================================================
//
// All sizes the KNX/IP, embassy-net, and Data Secure stacks need, named
// once so the numbers don't drift apart. Routing device with no tunnelling,
// but with TCP: mandatory for a KNX IP Secure profile (Core v2, 03/08/09
// §2.5.1.1 + 03/08/02 §9.2).

/// UDP buffer pool size — must match `<PicoEthSecureLightSwitch as
/// KnxNetIpDefinition>::MAX_UDP_SOCKETS`. Three sockets cover discovery +
/// control + routing.
const UDP_POOL_SIZE: usize = 3;

/// P2P key table capacity. Group-only device with no secure P2P traffic,
/// so zero — matches the secure TP1 light switch (`P2P_SIZE = 0`).
const P2P_SIZE: usize = 0;

/// Security Individual Address Table capacity. Per 03/03/07 §5.3 the SIAT
/// stores `LastValidSeqNr` for every non-tool secure sender — group
/// senders included — so even a group-only device needs `SIAT > 0`.
/// Mirrors the secure TP1 light switch.
const SIAT_SIZE: usize = 32;

/// SIAT capacity for the sequence/SIAT store.
///
/// The store *is* the SIAT (single source of truth, 03/05/01 §6.3.8): it holds
/// the live `LastValidSeqNr` for every secure sender, updated on every accepted
/// frame and read live by PID 54. Sizing it to `SIAT_SIZE` lets it hold every
/// authorized sender, so the overflow / silent-drop path is unreachable.
const SEQ_CACHE: usize = SIAT_SIZE;

/// IP Secure password-hash table capacity. One slot for the management
/// user, which backs the DAC / `SESSION_RESPONSE` path.
const MAX_PW: usize = 1;

/// IP Secure tunnelling-user table capacity. Zero — this device does no
/// secure tunnelling (routing-only secure; tunnelling is optional for a
/// KNX IP end device per 03/08/09 §2.5.1.1).
const MAX_TU: usize = 0;

/// Feature set: the `KnxIpSecureRoutingTcp` preset — KNX/IP routing +
/// remote config + **IP Secure** + TCP, with no tunnelling. TCP is not
/// optional for a secure device: 03/08/09 §2.5.1.1 makes Core **v02**
/// mandatory for every KNX IP Secure profile and 03/08/02 Core §9.2 makes
/// `IPV4_TCP` Required at v2. The preset's parameter sizes the
/// secure-session pool — one session, matching the single TCP stream a
/// tunnel-less device gets.
type SecureRoutingTcp = KnxIpSecureRoutingTcp<1>;

/// Live-record capacity of the wear-levelled flash log: the SIAT entries plus
/// the two singleton sequence counters (sending watermark + tool).
const SEQ_RECORDS: usize = SEQ_CACHE + 2;

/// Device state: System B tables + the Data-Secure wrapper around the IP
/// **Secure** interface extension (PIDs 91–97). This is the
/// `SecureExtensionState<IpSecureInterfaceExtension<...>, SEQ, ...>`
/// composition realised through the `SecureIpInterfaceStateFor` alias.
type PicoEthSecureState =
    SecureIpInterfaceStateFor<PicoEthSecureLightSwitch, SecureRoutingTcp, P2P_SIZE, MAX_PW, MAX_TU>;

// ----------------------------------------------------------------------------
// Storage layout — chips + auto-placed regions
// ----------------------------------------------------------------------------

use zweidraehte_device::storage::FlashSiatRegion;

/// This device's SIAT + sequence-counter region: a six-sector append log on
/// the internal flash (whole sectors — the wear log rotates through them),
/// with `BATCH = 256` keeping the hot sending counter off flash for 256
/// sends at a time. The region type is the single source of the extent, the
/// `KNXR` magic, the mechanism, and the store capacities; the storage layer
/// derives the offset, and the wear-levelled store plus the `SiatStore` view
/// derive from the region.
type SeqRegion = FlashSiatRegion<{ 6 * SECTOR_SIZE }, SEQ_RECORDS, SEQ_CACHE, 256>;

// The device's storage memory map: a pure layout list — each `Placed` entry
// names the shared [`RpFlash`] chip and a self-describing region, and
// derives its placement, store type, and open() from the layout. No offset,
// sector count, magic, or store type is hand-written, and a placement can
// never end up at another region's entry.
//
// All three regions have stores-struct slots — the SIAT store is owned by
// the stores struct too; the secure stack pulls it out through
// `HasSeqStore`.
use zweidraehte_device::bcus::system_b::IpSecureResources;
use zweidraehte_device::config::buffer_size_for_apdu;
use zweidraehte_device::layers::application::services::StandardSecureAlServices;
use zweidraehte_device::lifecycle::lifecycle_event_logger;
use zweidraehte_device::service::ServiceRegistry;
use zweidraehte_device::storage::NoSaveGuard;
use zweidraehte_device::storage::{Placed, RegionSpec, SecureIpStorage, StorageLayout, StoreOf};

// `pub`: the map reaches the public `StackDefinition` surface through
// `DeviceStorage`'s `StoreOf` projections.
pub struct StorageMap;
type Seq = Placed<SeqRegion, RpFlash, StorageMap>;
type Mct = Placed<RpMcTimerRegion, RpFlash, StorageMap>;
type Cfg = Placed<RpConfigRegion<PicoEthSecureState>, RpFlash, StorageMap>;
impl StorageLayout for StorageMap {
    const REGIONS: &'static [RegionSpec] = &[Seq::SPEC, Mct::SPEC, Cfg::SPEC];
}
type DeviceStorage = SecureIpStorage<StoreOf<Cfg>, StoreOf<Seq>, StoreOf<Mct>>;

// ----------------------------------------------------------------------------
// StackDefinition
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct PicoEthSecureLightSwitch;

/// Security augment type alias — produced by the secure extension for
/// `PicoEthSecureLightSwitch`. It carries the Security IO (IOT 0x11) plus
/// the IP medium + IP Secure objects.
type SecAugment<'a> = SecureAugmentBundle<
    'a,
    <IpSecureInterfaceExtensionFor<SecureRoutingTcp, MAX_PW, MAX_TU> as Extension<EmbassyNetworkInfo>>::Augment<
        'a,
        PicoEthSecureLightSwitch,
    >,
    StoreOf<Seq>,
    { <PicoEthSecureLightSwitch as SystemBStackDefinition>::ADT_ENTRIES },
    P2P_SIZE,
    { <PicoEthSecureLightSwitch as SystemBStackDefinition>::COT_ENTRIES },
>;

/// Augment chain: KNX Data Secure augment (Security IO 0x11) + the IP
/// medium / IP Secure augment, plus the Easter Egg demo augment. The
/// secure augment bundles the IP augment internally (the secure extension
/// wraps the IP Secure interface extension), so there is no separate
/// `ip:` field as in the insecure `pico_eth_light_switch`.
#[derive(ServiceRegistry)]
pub struct PicoEthSecureAugments<'a> {
    #[service(augment)]
    sec: SecAugment<'a>,
    #[service(augment)]
    easter: EasterEggAugment,
}

// IP-specific link-layer bill of materials. Routing-only device (no
// tunnelling) with three UDP sockets (discovery + control + routing) plus
// the TCP listener every secure profile must provide. `type Rng` is
// required by `SecureIpDeviceBuilder` (`NoRng` is rejected) and feeds the
// Secure Application Layer's `S-A_Sync` challenges plus IP Secure session
// nonces.
impl KnxNetIpDefinition for PicoEthSecureLightSwitch {
    type Transport = EmbassyIpTransportTcp<
        { <Self as KnxNetIpDefinition>::MAX_UDP_SOCKETS },
        { <Self as KnxNetIpDefinition>::MAX_TCP_STREAMS },
    >;
    type Features = SecureRoutingTcp;
    type Rng = RpCommonRng;
    const MAX_UDP_SOCKETS: usize = 3;
}

zweidraehte_device::system_b_standard_stack! {
    stack: PicoEthSecureLightSwitch,
    device: &DEVICE_DESCRIPTOR,
    tl_style: TlStyle::Style3,
    params: LightSwitchParams,
    com_objects: LightSwitchComObjects,
    link_layer_builder: KnxNetIpBuilder<PicoEthSecureLightSwitch>,
    platform: EmbassyNetworkInfo,
    // Data Secure wrapper around the IP Secure interface extension.
    // `GRP`/`GO` are entry counts (one group key slot per address table
    // entry, one flag byte per communication object), matching
    // `SecureStateFor`'s invariant.
    extension_state: SecureExtensionState<
        IpSecureInterfaceExtensionFor<SecureRoutingTcp, MAX_PW, MAX_TU>,
        { Self::ADT_ENTRIES },
        P2P_SIZE,
        { Self::COT_ENTRIES },
    >,
    state: PicoEthSecureState,
    al_extensions: StandardSecureAlServices,
    layer_builder: SecureIpDeviceBuilder,
    // The RAM sequence-number storage + the IP Secure FDSK seed are built
    // in `main` and threaded through `StateInit`. `SecureResources::inner`
    // is the IP Secure extension's own `IpSecureResources { fdsk }`.
    resources: SecureResources<IpSecureInterfaceExtensionFor<SecureRoutingTcp, MAX_PW, MAX_TU>>,
    augments: {
        bundle: PicoEthSecureAugments,
        create: |state, platform, layer_ctx| PicoEthSecureAugments {
            sec: state.extension_state().create_secure_augment(platform, layer_ctx),
            easter: EasterEggAugment,
        },
    },
    extra {
        // Flash-backed identity carrying the FDSK.
        type Identity = FlashSecureIdentityData;
        // ROSC-seeded ChaCha20 CSPRNG (see `rp_common::rng`).
        type Rng = RpCommonRng;
        // The device's stores struct, wired onto the LayerContext so the
        // secure layers pull the SIAT store out of it through
        // `HasSeqStore`.
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
async fn knx_task(runner: Runner<'static, PicoEthSecureLightSwitch>) -> ! {
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

/// Programming mode button handler. Toggles programming mode on each
/// debounced press; the LED is updated from the heartbeat loop so it also
/// tracks remote changes from ETS.
#[embassy_executor::task]
async fn prog_task(knx: Stack<'static, PicoEthSecureLightSwitch>, prog_btn_pin: Input<'static>) -> ! {
    let mut btn = DebouncedButton::new(prog_btn_pin);
    let debounce = Duration::from_millis(50);

    loop {
        btn.wait_for_press(debounce, None).await;
        let current = knx.state().is_programming_mode();
        knx.state().set_programming_mode(!current);
        info!("Programming mode: {}", !current);
    }
}

zweidraehte_device::storage_task! {
    device: PicoEthSecureLightSwitch,
    system: embedded_common::CortexMSystem,
    guard: NoSaveGuard,
}

/// Lifecycle event logger.
#[embassy_executor::task]
async fn lifecycle_task(knx: Stack<'static, PicoEthSecureLightSwitch>) -> ! {
    lifecycle_event_logger(knx).await
}

/// Main application task: handles button 1 and button 2 presses.
#[embassy_executor::task]
async fn app_task(
    knx: Stack<'static, PicoEthSecureLightSwitch>,
    btn1_pin: Input<'static>,
    btn2_pin: Input<'static>,
) -> ! {
    let mut btn1 = DebouncedButton::new(btn1_pin);
    let mut btn2 = DebouncedButton::new(btn2_pin);

    // Per-button dimming direction state.
    let mut btn1_dim_up = true;
    let mut btn2_dim_up = true;

    loop {
        // Wait until the application has been loaded and started by ETS.
        if !knx.state().is_running() {
            Timer::after(Duration::from_millis(200)).await;
            continue;
        }

        let params = *knx.state().app().borrow().params();
        let debounce = params.debounce_time.as_duration();
        let long_press = params.long_press_time.as_duration();

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

// Load the secure device identity (serial + MAC + FDSK) from the `KNXP`
// provisioning record. Unlike `pico_eth_light_switch`'s insecure load, the record
// MUST carry the FDSK tag — a secure device cannot derive its tool key
// without it.
rp_common::rp_identity_loader!(secure, fdsk: Some(dev_provisioning::DEV_FDSK), mac: Some(dev_provisioning::DEV_MAC));

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
    info!("Pico Ethernet (W5500) Secure initializing");

    // ========================================================================
    // CSPRNG seed (must happen before the secure stack runs)
    // ========================================================================
    //
    // Seed the ChaCha20 CSPRNG from ROSC noise. The Secure Application
    // Layer's `S-A_Sync` challenges and the IP Secure session nonces draw
    // from this; an unseeded `RpCommonRng::fill` panics.
    rp_common::rng::seed_from_rosc();

    // ========================================================================
    // Device identity (from flash — must happen before W5500 init for MAC)
    // ========================================================================

    // The RP2040 has a single `FLASH` peripheral but two independent flash
    // consumers: the config store (the `Storage` `ConfigStore`, outside the KNX
    // stack) and the wear-levelled sequence/SIAT store (`SiatStore`, inside it).
    // Lift the handle into a `&'static RefCell` so both can share it — sound
    // because the embassy executor is single-threaded and every flash op is
    // synchronous (`blocking_*`, never held across an `.await`).
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

    let prog_btn_pin = Input::new(p.PIN_17, Pull::Up);
    let prog_button_held = prog_btn_pin.is_low();
    if prog_button_held {
        info!("Prog button held at boot — forcing DHCP");
    }

    // ========================================================================
    // Persistent storage — open every store, then peek at the IP config
    // ========================================================================

    // Opening the seq store scans its flash region to recover the persisted
    // SIAT + counters. A scan failure is fatal — without durable counters the
    // device cannot offer cross-reboot replay protection, so we refuse to boot.
    //
    // The IP Secure mc_timer watermark (03/08/09 §2.2.4.2) lives in its own
    // wear-levelled region, *not* the config blob, so a forced persist is
    // one ~12-byte append instead of a 4 KiB config erase+rewrite. A blank
    // region yields watermark 0, which is the correct fresh-device start
    // (the timer re-acquires from the group).
    //
    // The device's stores struct in its static home: config + SIAT + mc_timer,
    // all three opened over copies of the one flash handle at their
    // layout-derived placements. Each store sits behind its own RefCell,
    // borrowed per call; the storage task drives it through the capability
    // traits, and the secure stack pulls the SIAT store out via `HasSeqStore`.
    static STORAGE: StaticCell<DeviceStorage> = StaticCell::new();
    let storage = &*STORAGE.init(DeviceStorage::new(
        Cfg::open(RpFlashIo::new(flash)).expect("config open is infallible"),
        Seq::open(RpFlashIo::new(flash)).expect("boot the flash sequence/SIAT store"),
        Mct::open(RpFlashIo::new(flash)).expect("open mc_timer watermark store"),
    ));
    let loaded_config = storage.load_config();

    // The persisted IP config lives deeper than in `pico_eth_light_switch`: the Data
    // Secure wrapper nests the medium config under `extension_config.inner`,
    // and the IP Secure interface extension nests the plain IP config under
    // `(ip_interface, ip_secure).0 = (ip, tunnelling)` → `.0 = ip`. So the
    // `IpExtensionConfig` (carrying ip_assignment_method / configured_ip /
    // …) is `extension_config.inner.0.0`.
    let ip_config = loaded_config.as_ref().map(|c| &c.extension_config.inner.0.0);

    // ========================================================================
    // IP assignment procedure (KNX spec Core 8.5, Figure 42)
    // ========================================================================

    use rp_common::{IP_ASSIGN_DHCP, IP_ASSIGN_MANUAL};

    let (net_config, initial_ip_method) = if prog_button_held {
        info!("Prog button override: using DHCP");
        (embassy_net::Config::dhcpv4(DhcpConfig::default()), IP_ASSIGN_DHCP)
    } else if let Some(ip) = ip_config {
        if ip.ip_assignment_method & IP_ASSIGN_MANUAL != 0 {
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

    static NET_RESOURCES: StaticCell<NetStackResources<{ PicoEthSecureLightSwitch::EMBASSY_NET_SOCKETS }>> =
        StaticCell::new();
    let (stack, net_runner) =
        embassy_net::new(net_device, net_config, NET_RESOURCES.init(NetStackResources::new()), seed);

    spawner.spawn(net_task(net_runner)).expect("net_task spawnable once");

    // ========================================================================
    // Platform + device state construction
    // ========================================================================

    let platform = EmbassyNetworkInfo::new(stack, mac_addr, initial_ip_method);

    // Build the Data Secure construction resources: the reference to the
    // storage-layer-owned sequence store, the IP Secure FDSK seed (`inner`),
    // and the Data Secure tool-key FDSK seed. Both FDSK fields take the same
    // physical value from the device identity — one seeds the IP Secure Device
    // Authentication Code (PID 92), the other the Data Secure tool key
    // (Security IO PID 56).
    let fdsk = *SecureDeviceIdentity::fdsk(&identity_data);
    let resources = SecureResources { inner: IpSecureResources { fdsk }, fdsk };
    let state_init = SystemBStateInit { identity: identity_data.clone(), loaded_config, resources };

    // Wait for an IP address.
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

    let local_ip =
        stack.config_v4().map(|c| Ipv4Addr::from(c.address.address().octets())).unwrap_or(Ipv4Addr::UNSPECIFIED);

    let control_endpoint = SocketAddrV4::new(local_ip, 3671);

    static UDP_POOL: UdpPool<UDP_POOL_SIZE> = UdpPool::new();
    static TCP_POOL: TcpPool<{ PicoEthSecureLightSwitch::MAX_TCP_STREAMS }> = TcpPool::new();
    let socket_ctx = EmbassyTcpContext { stack, udp_pool: &UDP_POOL, tcp_pool: &TCP_POOL };

    let link_layer_builder =
        KnxNetIpBuilder::<PicoEthSecureLightSwitch>::new("eth0", local_ip, control_endpoint, socket_ctx);

    static KNX_RESOURCES: StaticCell<
        StackResources<
            PicoEthSecureLightSwitch,
            { buffer_size_for_apdu(<PicoEthSecureLightSwitch as StackDefinition>::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        platform,
        PicoEthSecureLightSwitch::memory_map(),
        storage,
    );

    spawner.spawn(knx_task(knx_runner)).expect("knx_task spawnable once");

    info!("KNX/IP Secure stack started");
    info!("  Manufacturer: {:04x}", LightSwitchDevice::MANUFACTURER_ID);
    info!(
        "  Application:  {:04x} v{:02x}",
        LightSwitchDevice::APPLICATION_ID_IP_SECURE,
        LightSwitchDevice::APPLICATION_VERSION
    );
    info!("  Local IP:     {}", local_ip);
    info!("  Mask version: 57B0 (System B KNX/IP), IP Secure + Data Secure");

    // ========================================================================
    // Application GPIO + tasks
    // ========================================================================

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
