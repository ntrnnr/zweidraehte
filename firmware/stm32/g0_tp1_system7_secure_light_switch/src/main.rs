#![no_std]
#![no_main]

//! STM32G0B0RE **KNX Data Secure** TP1 light switch on the System 7
//! family (mask 0705h).
//!
//! The crossing of
//! [`stm32g0_tp1_system7_light_switch`](../stm32g0_tp1_system7_light_switch)
//! (System 7 management model: RT8 tables, absolute memory map,
//! memory-mapped load controls, 16 authorization levels, the
//! `ProductProcedure` download) and
//! [`stm32g0_tp1_secure_light_switch`](../stm32g0_tp1_secure_light_switch)
//! (KNX Data Secure: `SecureDeviceBuilder`, FRAM-backed sequence
//! numbers, FDSK identity). KNX Data Security is a profile module
//! (06 Profiles v02.02.01 §9.1) composed onto the base profile, so the
//! mask stays 0705h — ETS programs it through the same absolute-segment
//! download as the plain System 7 variant, from `gen_light_switch_mtxml`'s
//! secure System 7 variant (application 0x0307).
//!
//! Beyond the System B secure target, the augment chain also carries
//! the Group Object Table Object (Type 9): System 7's base roster has
//! no OT 9 (the System 7 group object table is memory-mapped, no load state
//! machine), but §9.2.1.1.1.1 makes the object mandatory once GO
//! Diagnostics is implemented, which §9.1.2.4 footnote b requires of an
//! S-Mode secure device with group objects. `PID_GO_DIAGNOSTICS` lives
//! on it.
//!
//! # Security notes
//!
//! - **FDSK lives in plain flash.** Production units get it from the
//!   `KNXP` provisioning record written by `tools/knx-provision` over
//!   SWD; `provision-on-boot` dev builds synthesize the record from
//!   build-time dev defaults (`ZZ_FDSK_HEX`-overridable). No readout
//!   protection is configured — whoever can read the flash can
//!   extract the key.
//! - **RNG is not cryptographic**. G0B0 has no TRNG; we seed a
//!   xoshiro from the factory UID + boot-time ticks. Session keys
//!   derived from this are weak against an attacker who knows the
//!   UID (which is public via management).
//!
//! # Sequence-number persistence
//!
//! Sequence numbers live on an external SPI FRAM (Infineon FM25L16B)
//! wired to SPI2 — see `StmSiatRegion`. Every outbound secure
//! frame writes the updated counter through to FRAM before the
//! telegram goes on the bus, so cross-reboot replay protection holds
//! even through power loss.

use core::sync::atomic::{AtomicI8, Ordering};

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::{
    Config, bind_interrupts,
    exti::{self, ExtiInput},
    gpio::{Level, Output, OutputType, Pull, Speed},
    peripherals::{TIM14, USART1, USART3},
    spi::{self, Spi},
    time::Hertz,
    timer::{
        Channel,
        low_level::CountingMode,
        simple_pwm::{PwmPin, SimplePwm, SimplePwmChannel},
    },
    usart::{Config as UartConfig, Parity, Uart},
};
use embassy_time::{Duration, Timer};
use embedded_common::DebouncedButton;
use embedded_io_async::{Read as _, Write as _};
use static_cell::StaticCell;
use stm32_common::flash_io::StmFlashIo;
use stm32_common::uart::{DirectInterruptHandler, DirectUart, DirectUartRx, DirectUartTx};
use stm32_common::{
    FlashSecureIdentityData, Fm25l16b, Fram, FramRegion, Stm32CommonRng, StmConfigRegion, StmFlash, StmFramCs,
    StmFramSpi, StmSiatRegion,
};
use {defmt_rtt as _, panic_probe as _};

use devices::light_switch::{
    self, LightSwitchDevice, LightSwitchParams,
    comm_objs::{Index, LightSwitchComObjects},
    full::{self as app, ButtonEvent, ButtonId, easter_egg::EasterEggAugment},
    params::{ButtonConfig, ButtonsMode, RockerDirection},
};

use zweidraehte_device::{
    bcus::system_7::*, config::MAX_APDU_LENGTH_EXTENDED, layers::linklayers::tpuart::TpUartLinkLayerBuilder, prelude::*,
};

use zweidraehte_device::config::buffer_size_for_apdu;
use zweidraehte_device::lifecycle::lifecycle_event_logger;
use zweidraehte_device::security::SecureResources;
use zweidraehte_device::storage::{Placed, RegionSpec, SecureDeviceIdentity, SecureStorage, StorageLayout, StoreOf};

// Under `provision-on-boot`, `build.rs` renders dev-default constants
// into `$OUT_DIR/dev_provisioning.rs`. The file is only present when
// the feature is on; production builds rely on the SWD-written `KNXP`
// page and never read these constants.
#[cfg(feature = "provision-on-boot")]
mod dev_provisioning {
    include!(concat!(env!("OUT_DIR"), "/dev_provisioning.rs"));
}

// ================================================================================
// Busy gating for flash saves
// ================================================================================

// STM32G0 flash erase/program stalls any flash fetch on the single bank,
// freezing code execution — far beyond the ~1.7 ms TP1 acknowledge
// window. Saves therefore run behind the busy gate: the software flag
// turns ACKs into BUSY acknowledges, and the rendezvous channel arms the
// transceiver's autonomous busy mode so the chip keeps answering BUSY
// while the CPU is stalled. The remote sender's link layer retries
// (busy_retry_count) until the save finishes.
embedded_common::tp1_busy_gate!();

// ================================================================================
// Interrupt Bindings
// ================================================================================

bind_interrupts!(struct Irqs {
    USART1 => DirectInterruptHandler<USART1>;
    USART3_4_5_6 => DirectInterruptHandler<USART3>;
    EXTI2_3 => exti::InterruptHandler<embassy_stm32::interrupt::typelevel::EXTI2_3>;
    EXTI4_15 => exti::InterruptHandler<embassy_stm32::interrupt::typelevel::EXTI4_15>;
});

// ================================================================================
// Device Definition
// ================================================================================

const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_TP1_SYSTEM7_SECURE;

/// SIAT capacity (Security Individual Address Table).
///
/// Per 03/03/07 §5.3 the SIAT stores the Last Valid SeqNr for every
/// non-tool secure sender — including senders that only write to
/// group addresses, not just P2P partners. So a group-only secure
/// device still needs `SIAT > 0`. Sized to 32 to cover a realistic
/// installation where up to 32 distinct KNX devices send secure group
/// telegrams into this light switch. Also sizes the FRAM peer slots
/// in the packed FRAM layout since those persist the same seqnr values
/// outside the power-cycle-volatile SIAT runtime state.
const SIAT_SIZE: usize = 32;

pub struct Stm32G0S7SecureLightSwitchDefinition;

/// Standard System 7 TP1 Data Secure stack. The COT address must remain in
/// lock-step with the product database's `4200` segment.
pub type Stm32G0S7SecureLightSwitch = SecureTp1<Stm32G0S7SecureLightSwitchDefinition, 0x4200>;

/// Runtime state selected by the secure System 7 preset.
type Stm32G0S7SecureState = SecureTp1State<Stm32G0S7SecureLightSwitchDefinition, 0x4200>;

// ----------------------------------------------------------------------------
// Storage layout — config on internal flash, SIAT on the FRAM (two chips)
// ----------------------------------------------------------------------------

// A two-chip layout: the config blob on the `StmFlash` chip, the SIAT on the
// separate `Fram` chip. Each `Placed` entry derives its placement, store
// type, and open() from the layout; the secure stack reaches the seq store
// through `HasSeqStore`. `StmSiatRegion`/`FramRegion` are chip-agnostic and
// carry over from the System B secure target unchanged.

type FramChip = Fram<StmFramSpi, StmFramCs>;

// `pub`: the map reaches the public `StackDefinition` surface through
// `DeviceStorage`'s `StoreOf` projections.
pub struct StorageMap;
type Cfg = Placed<StmConfigRegion<Stm32G0S7SecureState>, StmFlash, StorageMap>;
type Seq = Placed<StmSiatRegion<SIAT_SIZE>, FramChip, StorageMap>;
impl StorageLayout for StorageMap {
    const REGIONS: &'static [RegionSpec] = &[Cfg::SPEC, Seq::SPEC];
}
type DeviceStorage = SecureStorage<StoreOf<Cfg>, StoreOf<Seq>>;

pub struct Stm32G0S7SecureLightSwitchHooks;

impl DeviceHooks for Stm32G0S7SecureLightSwitchHooks {
    type Augments<'a, D: StackDefinition> = EasterEggAugment;

    fn create_augments<'a, D: StackDefinition>(
        _state: &'a D::State,
        _platform: &'a D::Platform,
        _layer_ctx: &'a zweidraehte_device::context::layer::LayerContext<D>,
    ) -> Self::Augments<'a, D> {
        EasterEggAugment
    }
}

impl DeviceDefinition for Stm32G0S7SecureLightSwitchDefinition {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_EXTENDED;

    type Rng = Stm32CommonRng;
    type Params = LightSwitchParams;
    type ComObjects = LightSwitchComObjects;
    type LinkLayer = TpUartLinkLayerBuilder<DirectUartTx, DirectUartRx>;
    type Identity = FlashSecureIdentityData;
    type Storage = &'static DeviceStorage;
    type Hooks = Stm32G0S7SecureLightSwitchHooks;
}

// ================================================================================
// User-LED state machine
// ================================================================================
//
// PC12 drives the user LED via TIM14_CH1 (AF2). The behaviour is
// identical to the non-secure variant — see
// `firmware/stm32/g0_tp1_light_switch/src/main.rs` for the full design
// rationale on why we read `btn1_status` for the steady on/off level
// and use a shared `DIM_RAMP` flag during local dimming long-presses.

static DIM_RAMP: AtomicI8 = AtomicI8::new(0);

const LED_PWM_FREQ: Hertz = Hertz(1_000);
const LED_TICK: Duration = Duration::from_millis(20);
const DIM_FULL_SWEEP_TICKS: u32 = 60;

// ================================================================================
// Tasks
// ================================================================================

#[embassy_executor::task]
async fn knx_task(runner: Runner<'static, Stm32G0S7SecureLightSwitch>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn debug_task(mut dbg_tx: DirectUartTx, mut dbg_rx: DirectUartRx) -> ! {
    use embassy_futures::select::{Either, select};

    let mut counter: u32 = 0;
    let mut rx_byte = [0u8; 1];

    let _ = dbg_tx.write_all(b"\r\n[stm32g0 s7 secure debug uart online]\r\n").await;

    loop {
        match select(Timer::after(Duration::from_millis(500)), dbg_rx.read(&mut rx_byte)).await {
            Either::First(()) => {
                let mut buf = [0u8; 24];
                buf[..16].copy_from_slice(b"dbg alive, tick ");
                let c = counter;
                buf[16] = b'0' + ((c / 10000 % 10) as u8);
                buf[17] = b'0' + ((c / 1000 % 10) as u8);
                buf[18] = b'0' + ((c / 100 % 10) as u8);
                buf[19] = b'0' + ((c / 10 % 10) as u8);
                buf[20] = b'0' + ((c % 10) as u8);
                buf[21] = b'\r';
                buf[22] = b'\n';
                let _ = dbg_tx.write_all(&buf[..23]).await;
                counter = counter.wrapping_add(1);
            }
            Either::Second(Ok(_n)) => {
                let b = rx_byte[0];
                let out = [b'[', b, b']'];
                let _ = dbg_tx.write_all(&out).await;
            }
            Either::Second(Err(_e)) => {
                let _ = dbg_tx.write_all(b"[!]").await;
            }
        }
    }
}

#[embassy_executor::task]
async fn prog_task(knx: Stack<'static, Stm32G0S7SecureLightSwitch>, prog_btn_pin: ExtiInput<'static>) -> ! {
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
    device: Stm32G0S7SecureLightSwitch,
    system: embedded_common::CortexMSystem,
    guard: busy_gate(),
}

#[embassy_executor::task]
async fn lifecycle_task(knx: Stack<'static, Stm32G0S7SecureLightSwitch>) -> ! {
    lifecycle_event_logger(knx).await
}

#[embassy_executor::task]
async fn app_task(knx: Stack<'static, Stm32G0S7SecureLightSwitch>, btn_pin: ExtiInput<'static>) -> ! {
    let mut btn = DebouncedButton::new(btn_pin);
    let mut button_state = app::ButtonState::new();

    loop {
        if !knx.is_running() {
            DIM_RAMP.store(0, Ordering::Relaxed);
            Timer::after(Duration::from_millis(200)).await;
            continue;
        }

        let params = *knx.state().app().borrow().params();
        let debounce = params.debounce_time.as_duration();
        let long_press = params.long_press_time.as_duration();

        let event = btn.wait_for_event(debounce, Some(long_press)).await;

        if event == ButtonEvent::LongPressStart && matches!(params.button1_config, ButtonConfig::Dimmer { .. }) {
            let up = dim_direction_for_long_press(&params, ButtonId::Btn1, button_state.next_dim_up());
            DIM_RAMP.store(if up { 1 } else { -1 }, Ordering::Relaxed);
        } else if event == ButtonEvent::LongPressRelease {
            DIM_RAMP.store(0, Ordering::Relaxed);
        }

        app::handle_button_event(&knx, &params, event, ButtonId::Btn1, &mut button_state).await;
    }
}

/// See `firmware/stm32/g0_tp1_light_switch/src/main.rs` for the full
/// rationale; same logic, copied here so this binary remains
/// self-contained.
fn dim_direction_for_long_press(params: &LightSwitchParams, button: ButtonId, dim_up: bool) -> bool {
    match params.buttons_mode {
        ButtonsMode::OneFunction => {
            let is_top = matches!(button, ButtonId::Btn1);
            match params.rocker_direction {
                RockerDirection::Normal => is_top,
                RockerDirection::Inverted => !is_top,
            }
        }
        ButtonsMode::TwoFunction => dim_up,
    }
}

#[embassy_executor::task]
async fn led_task(knx: Stack<'static, Stm32G0S7SecureLightSwitch>, mut pwm_ch: SimplePwmChannel<'static, TIM14>) -> ! {
    let max_duty: u32 = pwm_ch.max_duty_cycle();
    let ramp_step: u32 = (max_duty / DIM_FULL_SWEEP_TICKS).max(1);
    let mut duty: u32 = 0;
    let mut last_status = false;

    pwm_ch.set_duty_cycle(0);
    pwm_ch.enable();

    loop {
        let ramp = DIM_RAMP.load(Ordering::Relaxed);
        if ramp != 0 {
            duty = if ramp > 0 { duty.saturating_add(ramp_step).min(max_duty) } else { duty.saturating_sub(ramp_step) };
        } else {
            let on = if knx.is_running() { app::read_status(&knx, Index::Btn1Status) } else { false };
            if on != last_status {
                duty = if on { max_duty } else { 0 };
                last_status = on;
            }
        }

        pwm_ch.set_duty_cycle(duty);
        Timer::after(LED_TICK).await;
    }
}

// ================================================================================
// Identity load
// ================================================================================
//
// Production builds: read the `KNXP` page; panic on any error. The
// provisioning page is written once by `tools/knx-provision` over SWD,
// so a missing record means the chip slipped past production
// provisioning and must not run anything that exposes the FDSK.
//
// `provision-on-boot` builds: on a missing/corrupt record, write the
// dev defaults from `dev_provisioning::DEV_*` and re-read. After the
// first boot the unit looks identical to a factory-provisioned one.

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
    info!("STM32G0 TP1 System 7 **Data Secure** light switch initializing");

    // Seed the ChaCha20 CSPRNG from ADC noise on a floating PA0
    // before the secure stack starts. `fill` panics if called before
    // this. The pin must be physically unconnected on the board — no
    // pull, no trace — so the ADC samples only thermal / EMI noise.
    stm32_common::rng::seed_from_adc(p.ADC1, p.PA0);

    // --- Identity (from the KNXP provisioning page) --------------------------
    let flash = stm32_common::stm32_flash_cell!(p.FLASH);
    let identity_data = load_secure_identity(&mut flash.borrow_mut());
    info!("Serial: {=[u8]:02x}  FDSK: {=[u8]:02x}", identity_data.serial_number, identity_data.fdsk);
    // Hyphenated Base32 encoding — this is what ETS prompts for when
    // commissioning the device. Not specified normatively in the spec
    // (03/05/01 §6.1.3 leaves the label format open) but the de-facto
    // encoding ETS accepts.
    let fdsk_str = identity_data.fdsk_string();
    info!("Device label code (paste into ETS): {=str}", core::str::from_utf8(&fdsk_str).unwrap_or("<invalid utf8>"));

    // --- USART1 — NCN5120/E981.03 TPUART at 19200 8E1 -----------------------
    let mut uart_config = UartConfig::default();
    uart_config.baudrate = 19200;
    uart_config.parity = Parity::ParityEven;
    let uart = Uart::new_blocking(p.USART1, p.PA10, p.PA9, uart_config).expect("USART1 init");
    let (uart_tx, uart_rx) = DirectUart::new::<USART1>(uart, Irqs);
    info!("USART1 initialized (19200 8E1, direct register access)");

    // --- USART3 — debug UART at 115200 8N1 on PB0/PB2 ----------------------
    let mut dbg_cfg = UartConfig::default();
    dbg_cfg.baudrate = 115_200;
    let dbg_uart = Uart::new_blocking(p.USART3, p.PB0, p.PB2, dbg_cfg).expect("USART3 init");
    let (dbg_tx, dbg_rx) = DirectUart::new::<USART3>(dbg_uart, Irqs);
    info!("USART3 initialized (115200 8N1, PB2=TX, PB0=RX)");

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
    let state_init = System7StateInit { identity: identity_data, loaded_config, resources };

    // --- KNX secure stack ----------------------------------------------------
    let link_layer_builder = TpUartLinkLayerBuilder::new(uart_tx, uart_rx)
        .with_busy_flag(&BUSY_FLAG)
        .with_chip_busy_channel(CHIP_BUSY.dyn_receiver());

    static KNX_RESOURCES: StaticCell<
        StackResources<
            Stm32G0S7SecureLightSwitch,
            { buffer_size_for_apdu(<Stm32G0S7SecureLightSwitch as StackDefinition>::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        (),
        Stm32G0S7SecureLightSwitch::memory_map(),
        storage,
    );

    spawner.spawn(knx_task(knx_runner)).expect("knx_task spawnable once");

    info!("KNX Data Secure TP1 stack started");
    info!("  Manufacturer: {:04x}", LightSwitchDevice::MANUFACTURER_ID);
    info!(
        "  Application:  {:04x} v{:02x}",
        LightSwitchDevice::APPLICATION_ID_TP1_SYSTEM7_SECURE,
        LightSwitchDevice::APPLICATION_VERSION
    );
    info!("  Mask version: 0705 (System 7 TP1 with Data Secure)");

    let user_btn_pin = ExtiInput::new(p.PC11, p.EXTI11, Pull::Up, Irqs);
    let prog_btn_pin = ExtiInput::new(p.PD2, p.EXTI2, Pull::Up, Irqs);

    // User LED on PC12 driven by TIM14_CH1 (AF2). See the non-secure
    // variant for the design rationale.
    let user_led_pin = PwmPin::new(p.PC12, OutputType::PushPull);
    static USER_LED_PWM: StaticCell<SimplePwm<'static, TIM14>> = StaticCell::new();
    let user_led_pwm = USER_LED_PWM.init(SimplePwm::new(
        p.TIM14,
        Some(user_led_pin),
        None,
        None,
        None,
        LED_PWM_FREQ,
        CountingMode::EdgeAlignedUp,
    ));
    let user_led_ch = user_led_pwm.channel(Channel::Ch1);

    spawner.spawn(app_task(knx_stack, user_btn_pin)).expect("app_task spawnable once");
    spawner.spawn(prog_task(knx_stack, prog_btn_pin)).expect("prog_task spawnable once");
    spawner.spawn(storage_task(knx_stack)).expect("storage_task spawnable once");
    spawner.spawn(lifecycle_task(knx_stack)).expect("lifecycle_task spawnable once");
    spawner.spawn(debug_task(dbg_tx, dbg_rx)).expect("debug_task spawnable once");
    spawner.spawn(led_task(knx_stack, user_led_ch)).expect("led_task spawnable once");

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
