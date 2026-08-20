#![no_std]
#![no_main]
// The standard secure RF preset derives table capacities from the descriptor in
// generic const expressions. Same flag `zweidraehte-device` already requires.
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

//! STM32G0B0RE **KNX Data Secure** KNX-RF light switch (Semtech SX1211).
//!
//! The secure analogue of [`stm32g0_knxrf_device`](../stm32g0_knxrf_device): the
//! same `devices::light_switch` definition driven over a Semtech SX1211 KNX-RF
//! transceiver, but with KNX Data Secure (`SecureDeviceBuilder`), the RF medium
//! extension wrapped in the Data-Secure wrapper, a FRAM-backed sequence-number
//! store on SPI2, and the `S-A_Sync` PRNG seeded from ADC noise. Structurally it
//! is to the insecure RF device what
//! [`stm32g0_tp1_secure_light_switch`](../stm32g0_tp1_secure_light_switch) is to
//! the insecure TP1 device.
//!
//! # Security notes (same as the TP1 secure variant)
//!
//! - The FDSK lives in plain flash: the `KNXP` provisioning record written by
//!   `tools/knx-provision` over SWD (or, in `provision-on-boot` dev builds,
//!   synthesized from build-time dev defaults, `ZZ_FDSK_HEX`-overridable).
//! - The RNG is a non-crypto PRNG seeded from ADC noise on a floating PA0; the
//!   G0B0 has no TRNG.
//!
//! Sequence numbers persist to an external SPI2 FRAM (FM25L16B) so cross-reboot
//! replay protection survives power loss.

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::{
    Config, bind_interrupts,
    exti::{self, ExtiInput},
    gpio::{Input, Level, Output, Pull, Speed},
    mode::Blocking,
    spi::{self, Spi, mode::Master},
    time::Hertz,
};
use embassy_time::{Duration, Timer};
use embedded_common::DebouncedButton;
use knxrf::sx1211::Sx1211;
use static_cell::StaticCell;
use stm32_common::flash_io::StmFlashIo;
use stm32_common::sx1211_adapter::Sx1211Adapter;
use stm32_common::{
    FlashSecureIdentityData, Fm25l16b, Fram, FramRegion, Stm32CommonRng, StmConfigRegion, StmFlash, StmFramCs,
    StmFramSpi, StmSiatRegion,
};
use {defmt_rtt as _, panic_probe as _};

use devices::light_switch::{
    self, LightSwitchDevice, LightSwitchParams,
    comm_objs::{Index, LightSwitchComObjects},
    full::{self as app, ButtonId, easter_egg::EasterEggAugment},
};

use zweidraehte_device::storage::SecureDeviceIdentity;
use zweidraehte_device::{
    bcus::system_b::*, config::MAX_APDU_LENGTH_RF, layers::linklayers::knxrf::KnxRfLinkLayerBuilder, prelude::*,
};

#[cfg(feature = "provision-on-boot")]
mod dev_provisioning {
    include!(concat!(env!("OUT_DIR"), "/dev_provisioning.rs"));
}

// ================================================================================
// Interrupt Bindings
// ================================================================================

// SX1211 status pins: PD3 (PLL_LOCK → EXTI2_3), PD4/PD5 (IRQ1/IRQ0 → EXTI4_15);
// prog button PD2 (EXTI2_3); user button PC8 (EXTI4_15).
bind_interrupts!(struct Irqs {
    EXTI2_3 => exti::InterruptHandler<embassy_stm32::interrupt::typelevel::EXTI2_3>;
    EXTI4_15 => exti::InterruptHandler<embassy_stm32::interrupt::typelevel::EXTI4_15>;
});

// ================================================================================
// Flash Layout
// ================================================================================

// ================================================================================
// Device Definition
// ================================================================================

const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_RF_SECURE;

/// SIAT capacity (Security Individual Address Table) — per 03/03/07 §5.3 it
/// covers every non-tool secure sender, including group-only senders. Also sizes
/// the FRAM peer slots in the packed SIAT layout.
const SIAT_SIZE: usize = 32;

/// Concrete SX1211 transceiver: blocking SPI3 plus two GPIO chip-selects.
type Radio = Sx1211Adapter<Spi<'static, Blocking, Master>, Output<'static>, Output<'static>>;

pub struct Stm32G0KnxRfSecureDefinition;

/// Standard System B RF Data Secure stack.
pub type Stm32G0KnxRfSecure = SecureRf<Stm32G0KnxRfSecureDefinition>;

/// Nominal state spelling for the state-parameterized config store.
type Stm32G0SecureState = SecureRfStateFor<Stm32G0KnxRfSecure, 0>;

// ----------------------------------------------------------------------------
// Storage layout — config on internal flash, SIAT on the FRAM (two chips)
// ----------------------------------------------------------------------------

// A genuine two-chip layout: the config blob on the `StmFlash` chip, the SIAT
// on the separate `Fram` chip. Each `Placed` entry derives its placement,
// store type, and open() from the layout; the secure stack reaches the seq
// store through `HasSeqStore`.
use zweidraehte_device::config::buffer_size_for_apdu;
use zweidraehte_device::lifecycle::lifecycle_event_logger;
use zweidraehte_device::storage::NoSaveGuard;
use zweidraehte_device::storage::{Placed, RegionSpec, SecureStorage, StorageLayout, StoreOf};

type FramChip = Fram<StmFramSpi, StmFramCs>;

// `pub`: the map reaches the public `StackDefinition` surface through
// `DeviceStorage`'s `StoreOf` projections.
pub struct StorageMap;
type Cfg = Placed<StmConfigRegion<Stm32G0SecureState>, StmFlash, StorageMap>;
type Seq = Placed<StmSiatRegion<SIAT_SIZE>, FramChip, StorageMap>;
impl StorageLayout for StorageMap {
    const REGIONS: &'static [RegionSpec] = &[Cfg::SPEC, Seq::SPEC];
}
type DeviceStorage = SecureStorage<StoreOf<Cfg>, StoreOf<Seq>>;

pub struct Stm32G0KnxRfSecureHooks;

impl DeviceHooks for Stm32G0KnxRfSecureHooks {
    type Augments<'a, D: StackDefinition> = EasterEggAugment;

    fn create_augments<'a, D: StackDefinition>(
        _state: &'a D::State,
        _platform: &'a D::Platform,
        _layer_ctx: &'a zweidraehte_device::context::layer::LayerContext<D>,
    ) -> Self::Augments<'a, D> {
        EasterEggAugment
    }
}

impl DeviceDefinition for Stm32G0KnxRfSecureDefinition {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    // The 55-octet ceiling leaves 42 octets of plaintext after the Data
    // Secure envelope while keeping every pool buffer small.
    const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_RF;

    type Rng = Stm32CommonRng;
    type Params = LightSwitchParams;
    type ComObjects = LightSwitchComObjects;
    type LinkLayer = KnxRfLinkLayerBuilder<Radio>;
    type Identity = FlashSecureIdentityData;
    type Storage = &'static DeviceStorage;
    type Hooks = Stm32G0KnxRfSecureHooks;
}

// ================================================================================
// GPIO Pinout (STM32G0B0RE)
// ================================================================================
//
// KNX-RF (Semtech SX1211) on SPI3 (1 MHz, mode 0):
//   SCK=PC10, MISO=PC11, MOSI=PC12
//   NSS_CONFIG=PD0, NSS_DATA=PD1          (outputs, idle high)
//   PLL_LOCK=PD3, IRQ1=PD4, IRQ0=PD5, DATA=PD6  (inputs)
//
// Secure sequence-number FRAM (FM25L16B) on SPI2 (4 MHz, mode 0):
//   SCK=PB13, MOSI=PB15, MISO=PB14, ~CS=PB12, ~WP=PB9
//
// RNG seed: ADC1 on a floating PA0 (no pull, no trace).
//
// Local I/O:
//   PC8  = user button (active low, internal pull-up)
//   PC9  = user LED (on/off, reflects Btn1 status)
//   PD2  = programming-mode button (active low, internal pull-up)
//   PB8  = programming-mode LED (active high)

// ================================================================================
// Tasks
// ================================================================================

#[embassy_executor::task]
async fn knx_task(runner: Runner<'static, Stm32G0KnxRfSecure>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn prog_task(knx: Stack<'static, Stm32G0KnxRfSecure>, prog_btn_pin: ExtiInput<'static>) -> ! {
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
    device: Stm32G0KnxRfSecure,
    system: embedded_common::CortexMSystem,
    guard: NoSaveGuard,
}

#[embassy_executor::task]
async fn lifecycle_task(knx: Stack<'static, Stm32G0KnxRfSecure>) -> ! {
    lifecycle_event_logger(knx).await
}

#[embassy_executor::task]
async fn app_task(knx: Stack<'static, Stm32G0KnxRfSecure>, btn_pin: ExtiInput<'static>) -> ! {
    let mut btn = DebouncedButton::new(btn_pin);
    let mut button_state = app::ButtonState::new();

    loop {
        if !knx.state().is_running() {
            Timer::after(Duration::from_millis(200)).await;
            continue;
        }

        let params = *knx.state().app().borrow().params();
        let debounce = params.debounce_time.as_duration();
        let long_press = params.long_press_time.as_duration();

        let event = btn.wait_for_event(debounce, Some(long_press)).await;
        app::handle_button_event(&knx, &params, event, ButtonId::Btn1, &mut button_state).await;
    }
}

/// User-LED task — plain on/off GPIO on PC9 mirroring `Btn1`'s status (PC12, the
/// TP1 variant's PWM pin, is the SX1211 SPI MOSI here).
#[embassy_executor::task]
async fn led_task(knx: Stack<'static, Stm32G0KnxRfSecure>, mut led: Output<'static>) -> ! {
    let mut last = false;
    loop {
        let on = knx.state().is_running() && app::read_status(&knx, Index::Btn1Status);
        if on != last {
            if on {
                led.set_high();
            } else {
                led.set_low();
            }
            last = on;
        }
        Timer::after(Duration::from_millis(50)).await;
    }
}

// ================================================================================
// Identity load (secure: carries the FDSK)
// ================================================================================

// Boot logic is shared across all secure STM32 firmware; only the
// `provision-on-boot` dev defaults are device-local (rendered into this
// crate's `OUT_DIR`).
stm32_common::stm32_identity_loader!(secure);

// ================================================================================
// Entry point
// ================================================================================

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_stm32::init(Config::default());
    info!("STM32G0 KNX-RF **Data Secure** light switch (SX1211) initializing");

    // Seed the PRNG from ADC noise on a floating PA0 before the secure stack
    // starts (the S-A_Sync challenge generator panics if used unseeded).
    stm32_common::rng::seed_from_adc(p.ADC1, p.PA0);

    // --- Identity (FDSK from the KNXP provisioning page) --------------------
    let flash = stm32_common::stm32_flash_cell!(p.FLASH);
    let identity_data = load_secure_identity(&mut flash.borrow_mut());
    info!("Serial: {=[u8]:02x}  FDSK: {=[u8]:02x}", identity_data.serial_number, identity_data.fdsk);
    let fdsk_str = identity_data.fdsk_string();
    info!("Device label code (paste into ETS): {=str}", core::str::from_utf8(&fdsk_str).unwrap_or("<invalid utf8>"));

    // --- SX1211 radio on SPI3 -----------------------------------------------
    let mut spi_cfg = spi::Config::default();
    spi_cfg.frequency = Hertz(1_000_000);
    let spi = Spi::new_blocking(p.SPI3, p.PC10, p.PC12, p.PC11, spi_cfg);
    let nss_cfg = Output::new(p.PD0, Level::High, Speed::VeryHigh);
    let nss_data = Output::new(p.PD1, Level::High, Speed::VeryHigh);
    let pll_lock = ExtiInput::new(p.PD3, p.EXTI3, Pull::None, Irqs);
    let threshold = ExtiInput::new(p.PD4, p.EXTI4, Pull::None, Irqs);
    let irq0 = ExtiInput::new(p.PD5, p.EXTI5, Pull::None, Irqs);
    let data = Input::new(p.PD6, Pull::Up);

    let mut radio = Sx1211::new(spi, nss_cfg, nss_data);
    if let Err(e) = radio.init() {
        error!("SX1211 init failed (check SPI wiring): {}", e);
        halt().await;
    }
    if let Err(e) = radio.set_channel_ready() {
        error!("SX1211 channel setup failed: {}", e);
        halt().await;
    }
    info!("SX1211 initialised — KNX-RF on 868.300 MHz");
    let link_layer_builder = KnxRfLinkLayerBuilder::new(Sx1211Adapter::new(radio, pll_lock, threshold, irq0, data));

    // --- FRAM (FM25L16B) on SPI2 — persistent secure sequence numbers ------
    // The FM25L16B rates its SPI at well above 4 MHz; 4 MHz keeps margin on
    // the breadboard wiring. `~WP` only gates WRSR (which the driver never
    // writes), so the pin is parked high for the device's lifetime —
    // dropping the `Output` would re-configure it back to its reset state.
    let mut fram_cfg = spi::Config::default();
    fram_cfg.frequency = Hertz(4_000_000);
    let fram_spi: StmFramSpi = Spi::new_blocking(p.SPI2, p.PB13, p.PB15, p.PB14, fram_cfg);
    let fram_cs: StmFramCs = Output::new(p.PB12, Level::High, Speed::VeryHigh);
    static FRAM_WP: StaticCell<Output<'static>> = StaticCell::new();
    FRAM_WP.init(Output::new(p.PB9, Level::High, Speed::Low));
    static FRAM: StaticCell<core::cell::RefCell<Fm25l16b<StmFramSpi, StmFramCs>>> = StaticCell::new();
    let fram = &*FRAM.init(core::cell::RefCell::new(Fm25l16b::new(fram_spi, fram_cs)));
    info!("FRAM online (SPI2 @ 4 MHz, 2 KiB FM25L16B)");

    // --- Persistent storage --------------------------------------------------
    // The config blob on internal flash, the SIAT on the FRAM — each opened
    // at its layout-derived placement. A boot failure of the seq store is
    // fatal: without durable counters the device cannot offer cross-reboot
    // replay protection.
    static STORAGE: StaticCell<DeviceStorage> = StaticCell::new();
    let storage = &*STORAGE.init(DeviceStorage::new(
        Cfg::open(StmFlashIo::new(flash)).expect("config open is infallible"),
        Seq::open(FramRegion::new(fram)).expect("boot the FRAM sequence/SIAT store"),
    ));
    let loaded_config = storage.load_config();

    let fdsk = *SecureDeviceIdentity::fdsk(&identity_data);
    let resources = SecureResources::simple(fdsk);
    let state_init = SystemBStateInit { identity: identity_data, loaded_config, resources };

    // --- KNX secure stack ----------------------------------------------------
    static KNX_RESOURCES: StaticCell<
        StackResources<
            Stm32G0KnxRfSecure,
            { buffer_size_for_apdu(<Stm32G0KnxRfSecure as StackDefinition>::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        (),
        Stm32G0KnxRfSecure::memory_map(),
        storage,
    );

    spawner.spawn(knx_task(knx_runner)).expect("knx_task spawnable once");

    info!("KNX Data Secure RF stack started");
    info!("  Manufacturer: {:04x}", LightSwitchDevice::MANUFACTURER_ID);

    // --- Application GPIO + tasks -------------------------------------------
    let user_btn_pin = ExtiInput::new(p.PC8, p.EXTI8, Pull::Up, Irqs);
    let prog_btn_pin = ExtiInput::new(p.PD2, p.EXTI2, Pull::Up, Irqs);
    let user_led = Output::new(p.PC9, Level::Low, Speed::Low);

    spawner.spawn(app_task(knx_stack, user_btn_pin)).expect("app_task spawnable once");
    spawner.spawn(prog_task(knx_stack, prog_btn_pin)).expect("prog_task spawnable once");
    spawner.spawn(storage_task(knx_stack)).expect("storage_task spawnable once");
    spawner.spawn(lifecycle_task(knx_stack)).expect("lifecycle_task spawnable once");
    spawner.spawn(led_task(knx_stack, user_led)).expect("led_task spawnable once");

    // --- Main loop: prog LED mirrors programming mode ------------------------
    let mut prog_led = Output::new(p.PB8, Level::Low, Speed::Low);
    loop {
        if knx_stack.state().is_programming_mode() {
            prog_led.set_high();
        } else {
            prog_led.set_low();
        }
        Timer::after(Duration::from_millis(200)).await;
    }
}

/// Park forever after an unrecoverable init error, keeping the executor alive.
async fn halt() -> ! {
    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}
