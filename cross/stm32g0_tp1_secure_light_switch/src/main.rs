#![no_std]
#![no_main]
// `type Stm32G0SecureState = SecureTp1StateFor<…>` expands to const
// expressions over `SystemBStackDefinition::{ADT,AST,COT}_SIZE`.
// Same flag `zweidraehte-device` already requires.
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

//! STM32G0B0RE **KNX Data Secure** TP1 light switch.
//!
//! A secure variant of [`stm32g0_tp1_light_switch`](../stm32g0_tp1_light_switch).
//! Uses `SecureDeviceBuilder` instead of `InsecureDeviceBuilder` and
//! plugs [`Stm32CommonRng`] into [`StackDefinition::Rng`][sd] so the
//! Secure Application Layer's `S-A_Sync` challenges come from a small
//! PRNG (see `stm32_common::rng`).
//!
//! [sd]: zweidraehte_device::StackDefinition::Rng
//!
//! # Bring-up limitations (see `SESSION.md`)
//!
//! - **FDSK is compiled into the firmware** via the `ZZ_FDSK_HEX`
//!   env var at build time. Whoever can read the flash can extract
//!   it. Production devices need provisioning-time writes from a
//!   secure station.
//! - **RNG is not cryptographic**. G0B0 has no TRNG; we seed a
//!   xoshiro from the factory UID + boot-time ticks. Session keys
//!   derived from this are weak against an attacker who knows the
//!   UID (which is public via management).
//!
//! # Sequence-number persistence
//!
//! Sequence numbers live on an external SPI FRAM (Infineon FM25L16B)
//! wired to SPI2 — see [`FramSeqStorage`]. Every outbound secure
//! frame writes the updated counter through to FRAM before the
//! telegram goes on the bus, so cross-reboot replay protection holds
//! even through power loss.

use core::cell::RefCell;
use core::sync::atomic::{AtomicI8, Ordering};

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::{
    Config, bind_interrupts,
    exti::{self, ExtiInput},
    flash,
    gpio::{Level, Output, OutputType, Pull, Speed},
    mode::Blocking,
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
use embedded_hal::digital::InputPin;
use embedded_hal_async::digital::Wait;
use embedded_io_async::{Read as _, Write as _};
use static_cell::StaticCell;
use stm32_common::uart::{DirectInterruptHandler, DirectUart, DirectUartRx, DirectUartTx};
use stm32_common::{
    FlashSecureIdentityData, Fm25l16b, FramSeqStorage, Stm32CommonRng, StmFlashStorage,
    read_or_provision_secure_identity,
};
use {defmt_rtt as _, panic_probe as _};

use devices::light_switch::{
    self, LightSwitchDevice, LightSwitchParams,
    app::{self, ButtonEvent, ButtonId, WaitForRelease},
    comm_objs::{Index, LightSwitchComObjects},
    easter_egg::EasterEggAugment,
    params::{ButtonConfig, ButtonsMode, RockerDirection},
};

use zweidraehte_device::{
    bcus::system_b::*, config::MAX_APDU_LENGTH_EXTENDED, layers::linklayers::tpuart::TpUartLinkLayerBuilder,
    prelude::*, storage::HasSequenceStorage,
};

// `build.rs` renders `pub const FDSK_BYTES: [u8; 16] = [...]` from the
// ZZ_FDSK_HEX env var. See that file for validation rules.
include!(concat!(env!("OUT_DIR"), "/fdsk.rs"));

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
// Flash Layout
// ================================================================================

const FLASH_SIZE: u32 = 512 * 1024;
const FLASH_PAGE_SIZE: u32 = 2 * 1024;

// ================================================================================
// Device Definition
// ================================================================================

const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_TP1_SECURE;

/// P2P Key Table capacity. This device does not support point-to-point
/// secure traffic — only tool access (Management) and secure group
/// telegrams — so the P2P Key Table is compiled to zero width.
/// `SecureDeviceBuilder` already defaults to
/// [`NoP2p`](zweidraehte_device::layers::secure_application::NoP2p),
/// so the P2P sync handlers aren't stamped out either.
const P2P_SIZE: usize = 0;

/// SIAT capacity (Security Individual Address Table).
///
/// Per 03/03/07 §5.3 the SIAT stores the Last Valid SeqNr for every
/// non-tool secure sender — including senders that only write to
/// group addresses, not just P2P partners. So a group-only secure
/// device still needs `SIAT > 0`. Sized to 32 to cover a realistic
/// installation where up to 32 distinct KNX devices send secure group
/// telegrams into this light switch. Also sizes the FRAM peer slots
/// in [`FramSeqStorage`] since those persist the same seqnr values
/// outside the power-cycle-volatile SIAT runtime state.
const SIAT_SIZE: usize = 32;

/// Concrete SPI2 handle passed to the FRAM driver. Embassy owns the
/// peripheral through `Peri<'d, ...>`; we build from `'static`
/// singletons so `'d = 'static`. `Master` is reached via the public
/// `spi::mode` submodule even though it isn't re-exported at
/// `embassy_stm32::spi` top level.
type FramSpi = Spi<'static, Blocking, embassy_stm32::spi::mode::Master>;

/// Concrete CS output for the FRAM. Built from `'static` peripherals
/// so the `FramSeqStorage` can live inside the `'static` stack state.
type FramCs = Output<'static>;

/// Full concrete type of the persistent sequence-number store.
type Stm32G0SeqStorage = FramSeqStorage<FramSpi, FramCs, SIAT_SIZE>;

/// Runtime state alias — the vanilla secure TP1 state. The RNG that
/// the Secure Application Layer consumes during `S-A_Sync` is plugged
/// in via `type Rng = Stm32CommonRng;` on the stack definition below,
/// so we don't need a newtype wrapper on the state type.
type Stm32G0SecureState = SecureTp1StateFor<Stm32G0SecureLightSwitch, Stm32G0SeqStorage, P2P_SIZE, SIAT_SIZE>;

type Storage = StmFlashStorage<Stm32G0SecureState, FlashSecureIdentityData, FLASH_SIZE, FLASH_PAGE_SIZE>;

pub struct Stm32G0SecureStateInit {
    pub identity: FlashSecureIdentityData,
    pub seq_storage: Stm32G0SeqStorage,
    pub loaded_config: Option<<Stm32G0SecureState as HasDeviceConfig>::Config>,
}

#[derive(Debug, Clone, Copy)]
pub struct Stm32G0SecureLightSwitch;

// Security augment type alias — produced by the secure extension for
// `Stm32G0SecureLightSwitch`. The conformance DUT uses the same
// pattern; see `examples/conformance/src/harness/secure_stack.rs:871`.
type SecAugment<'a> =
    <<Stm32G0SecureLightSwitch as StackDefinition>::ES as zweidraehte_device::bcus::system_b::Extension<()>>::Augment<
        'a,
        Stm32G0SecureLightSwitch,
    >;

/// Augment chain: KNX Data Secure augment (drives Security IO 0x11)
/// plus the demo Easter Egg augment.
#[derive(zweidraehte_device::service::ServiceRegistry)]
pub struct Stm32G0SecureAugments<'a> {
    #[service(augment)]
    pub sec: SecAugment<'a>,
    #[service(augment)]
    pub easter: EasterEggAugment,
}

impl SystemBStackDefinition for Stm32G0SecureLightSwitch {}

impl HasSequenceStorage for Stm32G0SecureLightSwitch {
    type SeqStorage = Stm32G0SeqStorage;
    fn create_seq_storage() -> Self::SeqStorage {
        // Vestigial: the framework never actually calls this. The
        // real seq-store is built in `main` from the SPI2 peripheral
        // and threaded into the state via `StateInit` →
        // `SecureResources`. `FramSeqStorage` owns real hardware so
        // it cannot be fabricated out of thin air anyway — if the
        // framework ever starts calling this, that's a bug we want
        // to hear about loudly.
        core::unreachable!("seq storage is threaded through StateInit, not this factory callback")
    }
}

impl StackDefinition for Stm32G0SecureLightSwitch {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_EXTENDED;
    const TL_STYLE: TlStyle = TlStyle::Style1;

    type P = LightSwitchParams;
    type CO = LightSwitchComObjects;
    type LLB = TpUartLinkLayerBuilder<DirectUartTx, DirectUartRx>;
    // TP1 extension + Data Secure wrapper.
    type ES = SecureTp1ExtensionState<Stm32G0SeqStorage, { Self::ADT_SIZE }, P2P_SIZE, SIAT_SIZE, { Self::COT_SIZE }>;
    // Flash-backed identity that carries the FDSK.
    type Identity = FlashSecureIdentityData;
    type State = Stm32G0SecureState;
    type StateInit = Stm32G0SecureStateInit;
    type Mem = SystemBMemoryMap;
    // `SecAugment` extends the interface-object list with the Security
    // Object (IOT 0x11) that ETS uses to write group keys etc. It is
    // produced by `state.extension_state().create_augment::<Self>(platform)`
    // (see `create_augments` below) and bundled with `EasterEggAugment`
    // into `Stm32G0SecureAugments` so the property hook chain reaches
    // both via the macro-derived `AugmentRegistry<D>` impl.
    type InterfaceObjects<'a> = DefaultSystemBInterfaceObjects<'a, Self, Self::Augments<'a>>;
    type Augments<'a> = Stm32G0SecureAugments<'a>;

    fn create_state(init: Self::StateInit) -> Self::State {
        let Stm32G0SecureStateInit { identity, seq_storage, loaded_config } = init;
        let fdsk = *SecureDeviceIdentity::fdsk(&identity);
        let resources = SecureResources { inner: (), seq_storage, fdsk };
        match loaded_config {
            Some(config) => Stm32G0SecureState::from_config(identity, config, resources),
            None => Stm32G0SecureState::new(identity, LightSwitchComObjects::new(), resources),
        }
    }

    fn create_interface_objects<'a>(
        state: &'a Self::State,
        _platform: &'a Self::Platform,
        layer_ctx: &'a zweidraehte_device::context::layer::LayerContext<Self>,
        augments: &'a Self::Augments<'a>,
    ) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        create_system_b_objects::<Self, _>(state, layer_ctx, &Self::memory_layout(), augments)
    }

    fn create_augments<'a>(
        state: &'a Self::State,
        platform: &'a Self::Platform,
        _layer_ctx: &'a zweidraehte_device::context::layer::LayerContext<Self>,
    ) -> Self::Augments<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        Stm32G0SecureAugments {
            sec: state.extension_state().create_augment::<Self>(platform),
            easter: EasterEggAugment,
        }
    }


    type AlExtensions = zweidraehte_device::layers::application::services::SystemBSecureAlServices;
    type LayerBuilder = SecureDeviceBuilder;
    // Non-crypto PRNG (see `stm32_common::rng`) — plugs directly into
    // the Secure Application Layer's `S-A_Sync` challenge/nonce
    // generation, no state-type newtype needed.
    type Rng = Stm32CommonRng;
}

// Import the full re-exported set from system_b so the ES alias
// arguments above resolve. (`SecureResources`, `SecureDeviceIdentity`,
// `SecureTp1ExtensionState`, etc. all live here.)
use zweidraehte_device::storage::SecureDeviceIdentity;

// ================================================================================
// User-LED state machine
// ================================================================================
//
// PC12 drives the user LED via TIM14_CH1 (AF2). The behaviour is
// identical to the non-secure variant — see
// `cross/stm32g0_tp1_light_switch/src/main.rs` for the full design
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
async fn knx_task(runner: Runner<'static, Stm32G0SecureLightSwitch>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn debug_task(mut dbg_tx: DirectUartTx, mut dbg_rx: DirectUartRx) -> ! {
    use embassy_futures::select::{Either, select};

    let mut counter: u32 = 0;
    let mut rx_byte = [0u8; 1];

    let _ = dbg_tx.write_all(b"\r\n[stm32g0 secure debug uart online]\r\n").await;

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
async fn prog_task(knx: Stack<'static, Stm32G0SecureLightSwitch>, prog_btn_pin: ExtiInput<'static>) -> ! {
    let mut btn = DebouncedButton::new(prog_btn_pin);
    let debounce = Duration::from_millis(50);
    loop {
        btn.wait_for_press(debounce, None).await;
        let current = knx.state().is_programming_mode();
        knx.state().set_programming_mode(!current);
        info!("Programming mode: {}", !current);
    }
}

#[embassy_executor::task]
async fn restart_task(knx: Stack<'static, Stm32G0SecureLightSwitch>, storage: &'static RefCell<Storage>) -> ! {
    use embedded_common::CortexMSystem;
    use zweidraehte_device::restart::EraseCode;
    use zweidraehte_platform::SystemControl;

    loop {
        let request = knx.receive_restart_request().await;
        let state = knx.state();
        info!("Restart request: erase_code={}", request.erase_code);

        match request.erase_code {
            EraseCode::Basic | EraseCode::Confirmed => info!("Basic restart (no data reset)"),
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

        if state.is_dirty() {
            save_state(state, storage);
        }

        Timer::after(Duration::from_millis(100)).await;

        let mut system = CortexMSystem;
        let Err(_e) = system.restart().await;
    }
}

fn save_state(state: &Stm32G0SecureState, storage: &RefCell<Storage>) {
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

#[embassy_executor::task]
async fn lifecycle_task(knx: Stack<'static, Stm32G0SecureLightSwitch>) -> ! {
    let mut events = knx.lifecycle_events();
    loop {
        match events.next_message_pure().await {
            LifecycleEvent::ApplicationStarted => info!("Application STARTED"),
            LifecycleEvent::ApplicationStopped => info!("Application STOPPED"),
            LifecycleEvent::PeiStarted => info!("PEI STARTED"),
            LifecycleEvent::PeiStopped => info!("PEI STOPPED"),
            _ => {}
        }
    }
}

#[embassy_executor::task]
async fn app_task(knx: Stack<'static, Stm32G0SecureLightSwitch>, btn_pin: ExtiInput<'static>) -> ! {
    let mut btn = DebouncedButton::new(btn_pin);
    let mut dim_up = true;

    loop {
        if !knx.state().is_running() {
            Timer::after(Duration::from_millis(200)).await;
            continue;
        }

        let params = *knx.state().app().borrow().params();
        let debounce = params.debounce_time.as_duration();
        let long_press = params.long_press_time.as_duration();

        let event = btn.wait_for_press(debounce, Some(long_press)).await;

        let dim_ramping = event == ButtonEvent::LongPress && matches!(params.button1_config, ButtonConfig::Dimmer);
        if dim_ramping {
            let up = dim_direction_for_long_press(&params, ButtonId::Btn1, dim_up);
            DIM_RAMP.store(if up { 1 } else { -1 }, Ordering::Relaxed);
        }

        let mut waiter = ReleaseWaiter { btn: &mut btn, debounce };
        app::handle_button_press(&knx, &params, event, ButtonId::Btn1, &mut waiter, &mut dim_up).await;

        if dim_ramping {
            DIM_RAMP.store(0, Ordering::Relaxed);
        }
    }
}

/// See `cross/stm32g0_tp1_light_switch/src/main.rs` for the full
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
async fn led_task(knx: Stack<'static, Stm32G0SecureLightSwitch>, mut pwm_ch: SimplePwmChannel<'static, TIM14>) -> ! {
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
            let on = if knx.state().is_running() { app::read_status(&knx, Index::Btn1Status) } else { false };
            if on != last_status {
                duty = if on { max_duty } else { 0 };
                last_status = on;
            }
        }

        pwm_ch.set_duty_cycle(duty);
        Timer::after(LED_TICK).await;
    }
}

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
    let p = embassy_stm32::init(Config::default());
    info!("STM32G0 TP1 **Data Secure** light switch initializing");

    // Seed the ChaCha20 CSPRNG from ADC noise on a floating PA0
    // before the secure stack starts. `fill` panics if called before
    // this. The pin must be physically unconnected on the board — no
    // pull, no trace — so the ADC samples only thermal / EMI noise.
    stm32_common::rng::seed_from_adc(p.ADC1, p.PA0);

    // --- Identity (from flash, provisioned on first boot) --------------------
    let mut flash_hw = flash::Flash::new_blocking(p.FLASH);
    let identity_data = read_or_provision_secure_identity::<FLASH_SIZE, FLASH_PAGE_SIZE>(
        &mut flash_hw,
        LightSwitchDevice::MANUFACTURER_ID.to_be_bytes(),
        FDSK_BYTES,
    );
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
    //
    // Pinout: SCK=PB13, MOSI=PB15, MISO=PB14, ~CS=PB12, ~WP=PB9.
    //
    // `~WP` only gates WRSR on the chip; the driver never writes the
    // status register, so `~WP` never needs to toggle. Parking it in
    // a `StaticCell` keeps the `Output` alive for the lifetime of the
    // device (static storage). Dropping the value would re-configure
    // the pin back to its reset state.
    let mut spi_config = spi::Config::default();
    spi_config.frequency = Hertz(4_000_000);
    // spi::Config defaults to Mode 0 (CPOL=Low, CPHA=FirstTransition) —
    // what the FM25L16B expects.
    let fram_spi: FramSpi = Spi::new_blocking(p.SPI2, p.PB13, p.PB15, p.PB14, spi_config);
    let fram_cs: FramCs = Output::new(p.PB12, Level::High, Speed::VeryHigh);
    static FRAM_WP: StaticCell<Output<'static>> = StaticCell::new();
    FRAM_WP.init(Output::new(p.PB9, Level::High, Speed::Low));
    let fram_driver = Fm25l16b::new(fram_spi, fram_cs);
    let seq_storage: Stm32G0SeqStorage = FramSeqStorage::new(fram_driver);
    info!("FRAM seq storage online (SPI2 @ 4 MHz, 2 KiB FM25L16B)");

    // --- Persistent storage --------------------------------------------------
    let mut storage = Storage::new(flash_hw, identity_data.clone());
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

    let state_init = Stm32G0SecureStateInit { identity: identity_data, seq_storage, loaded_config };

    static STORAGE: StaticCell<RefCell<Storage>> = StaticCell::new();
    let storage = &*STORAGE.init(RefCell::new(storage));

    // --- KNX secure stack ----------------------------------------------------
    let link_layer_builder = TpUartLinkLayerBuilder::new(uart_tx, uart_rx);

    static KNX_RESOURCES: StaticCell<
        StackResources<
            Stm32G0SecureLightSwitch,
            {
                zweidraehte_device::config::buffer_size_for_apdu(
                    <Stm32G0SecureLightSwitch as StackDefinition>::MAX_APDU_LENGTH,
                )
            },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        (),
        Stm32G0SecureLightSwitch::memory_map(),
    );

    spawner.spawn(knx_task(knx_runner)).expect("knx_task spawnable once");

    info!("KNX Data Secure TP1 stack started");
    info!("  Manufacturer: {:04x}", LightSwitchDevice::MANUFACTURER_ID);
    info!(
        "  Application:  {:04x} v{:02x}",
        LightSwitchDevice::APPLICATION_ID_TP1_SECURE,
        LightSwitchDevice::APPLICATION_VERSION
    );
    info!("  Mask version: 07B0 (System B TP1 with Data Secure)");

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
    spawner.spawn(restart_task(knx_stack, storage)).expect("restart_task spawnable once");
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
