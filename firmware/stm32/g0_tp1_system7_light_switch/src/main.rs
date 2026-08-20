#![no_std]
#![no_main]

//! STM32G0B0RE KNX TP1 light switch on the System 7 family (mask 0705h).
//!
//! The System 7 sibling of `firmware/stm32/g0_tp1_light_switch`: the
//! same single-button `devices::light_switch` definition on the same
//! hardware (NCN5120/TPUART on USART1, same buttons and LEDs), managed
//! through the System 7 model instead of System B — the fixed absolute
//! memory map (RT8 group address table at 4000h with the individual
//! address inside the blob, memory-mapped load controls at
//! 0104h/B6EAh), absolute-segment load procedures, and 16 authorization
//! levels. ETS programs it through the `ProductProcedure` download that
//! `gen_light_switch_mtxml`'s System 7 variant (application 0x0306)
//! generates: tables at 4000h/4100h/4200h, parameters at 4300h.
//!
//! The MCU shell — clocks, pins, UART driver, flash storage, tasks — is
//! the System B target's, unchanged.

use core::sync::atomic::{AtomicI8, Ordering};

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::{
    Config, bind_interrupts,
    exti::{self, ExtiInput},
    gpio::{Level, Output, OutputType, Pull, Speed},
    peripherals::{TIM14, USART1, USART3},
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
use stm32_common::{FlashIdentityData, StmConfigRegion, StmFlash};
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

// EXTI interrupt lines on STM32G0: EXTI line N corresponds to pin N
// across all GPIO ports. PD2 sits on line 2 (group IRQ EXTI2_3); PC11
// sits on line 11 (group IRQ EXTI4_15).
bind_interrupts!(struct Irqs {
    USART1 => DirectInterruptHandler<USART1>;
    // USART3/4/5/6 all share this vector on the G0B0. We only drive USART3
    // directly, so the vector is unambiguously ours.
    USART3_4_5_6 => DirectInterruptHandler<USART3>;
    EXTI2_3 => exti::InterruptHandler<embassy_stm32::interrupt::typelevel::EXTI2_3>;
    EXTI4_15 => exti::InterruptHandler<embassy_stm32::interrupt::typelevel::EXTI4_15>;
});

// ================================================================================
// Flash Layout
// ================================================================================

// STM32G0B0RE — 512 KiB flash, 2 KiB erase page.

// ================================================================================
// Device Definition
// ================================================================================

const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_TP1_SYSTEM7;

#[derive(Debug, Clone, Copy)]
pub struct Stm32G0System7LightSwitchDefinition;

pub type Stm32G0System7LightSwitch = Tp1<Stm32G0System7LightSwitchDefinition, 0x4200>;
type Stm32G0State = <Stm32G0System7LightSwitch as StackDefinition>::State;

// ----------------------------------------------------------------------------
// Storage layout — one config region on the StmFlash chip
// ----------------------------------------------------------------------------

// The device's storage memory map: a single config blob on the `StmFlash`
// chip, carrying this device's state as its payload. The `Placed` entry
// derives its placement, store type, and open() from the layout.
use zweidraehte_device::config::buffer_size_for_apdu;
use zweidraehte_device::lifecycle::lifecycle_event_logger;
use zweidraehte_device::storage::{ConfigStorage, Placed, RegionSpec, StorageLayout, StoreOf};

// `pub`: the map reaches the public `StackDefinition` surface through
// `DeviceStorage`'s `StoreOf` projection.
pub struct StorageMap;
type Cfg = Placed<StmConfigRegion<Stm32G0State>, StmFlash, StorageMap>;
impl StorageLayout for StorageMap {
    const REGIONS: &'static [RegionSpec] = &[Cfg::SPEC];
}
type DeviceStorage = ConfigStorage<StoreOf<Cfg>>;

pub struct Stm32G0System7LightSwitchHooks;

impl DeviceHooks for Stm32G0System7LightSwitchHooks {
    type Augments<'a, D: StackDefinition> = EasterEggAugment;

    fn create_augments<'a, D: StackDefinition>(
        _state: &'a D::State,
        _platform: &'a D::Platform,
        _layer_ctx: &'a zweidraehte_device::context::layer::LayerContext<D>,
    ) -> Self::Augments<'a, D> {
        EasterEggAugment
    }
}

impl DeviceDefinition for Stm32G0System7LightSwitchDefinition {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_EXTENDED;

    type Params = LightSwitchParams;
    type ComObjects = LightSwitchComObjects;
    type LinkLayer = TpUartLinkLayerBuilder<DirectUartTx, DirectUartRx>;
    type Identity = FlashIdentityData;
    type Storage = &'static DeviceStorage;
    type Hooks = Stm32G0System7LightSwitchHooks;
}

// ================================================================================
// GPIO Pinout (STM32G0B0RE)
// ================================================================================
//
// KNX (NCN5120 TPUART) on USART1:
//   PA9  = USART1_TX — connect to TPUART RXD
//   PA10 = USART1_RX — connect to TPUART TXD
//
// Local I/O:
//   PD2  = programming-mode button (active low, internal pull-up)
//   PB8  = programming-mode LED (active high)
//   PC11 = user button (active low, internal pull-up)
//   PC12 = user LED (driven by application logic)
//
// Debug UART on PB0/PB2 uses USART3 (AF4 on both pins per the
// STM32G0B0RE datasheet). Wired through the same `DirectUart` driver as
// the TPUART so we are actually exercising the driver code path and not
// just defmt-rtt. Default baud: 115_200 8N1, no parity — friendly to
// any USB-serial bridge.

// ================================================================================
// User-LED state machine
// ================================================================================
//
// PC12 drives the user LED. We use TIM14_CH1 (AF2 on PC12) as a hardware
// PWM channel so the same pin can render either a steady on/off state or
// a smoothly ramping brightness during local dimming, all without
// burning CPU on software PWM.
//
// The LED tracks **channel 1's local view of the actuator state**:
// `LightSwitchComObjects::btn1_status` (a DPT_Switch). That object is
// updated optimistically when the device sends a switch telegram and is
// overridden by status feedback from the bus, so it's the closest the
// sensor has to "what is the lamp doing right now". In Switch and Dimmer
// modes the value is meaningful; in Blind / Scene modes it's effectively
// a leftover from whatever was last in that slot — fine for a demo.
//
// During a local long-press in Dimmer mode, `app_task` flips
// `DIM_RAMP` to ±1 to indicate the dimming direction it just sent on
// the bus. The LED task then ramps the PWM duty cycle in that
// direction at a fixed rate, freezes when `DIM_RAMP` returns to 0, and
// snaps back to the actuator's reported on/off level on the next
// status edge. The local ramp is purely a UX hint — there is no actual
// brightness feedback channel in this device's comm objects, so the
// LED's brightness will diverge from the real lamp until the next
// switch event re-syncs it.

/// Direction of an in-progress local dimming ramp:
/// `+1` = brighter, `-1` = darker, `0` = no active ramp.
static DIM_RAMP: AtomicI8 = AtomicI8::new(0);

/// Period for the user-LED PWM. 1 kHz is well above the eye's flicker
/// fusion threshold and keeps the timer's resolution comfortable on a
/// 16 MHz HSI bus.
const LED_PWM_FREQ: Hertz = Hertz(1_000);

/// Tick period for the LED task's duty-cycle update loop.
const LED_TICK: Duration = Duration::from_millis(20);

/// Number of LED ticks for a full-range dim sweep (0% → 100%) during a
/// local long-press. Roughly matches a typical KNX dimmer's full-range
/// ramp so the LED visualisation feels in line with what the actuator
/// is doing on the bus.
const DIM_FULL_SWEEP_TICKS: u32 = 60;

// ================================================================================
// Tasks
// ================================================================================

#[embassy_executor::task]
async fn knx_task(runner: Runner<'static, Stm32G0System7LightSwitch>) -> ! {
    runner.run().await
}

/// Debug-UART driver task.
///
/// Exercises both halves of the `DirectUart` driver on USART3 (PB0/PB2):
///
/// 1. A 500 ms heartbeat line on TX — proves the TX path, pin mux,
///    and USART3 clock gate are all working.
/// 2. An echo loop on RX → TX — proves the RX path (ISR, ring buffer,
///    waker) is actually delivering bytes. Each received byte is echoed
///    back with brackets so you can distinguish locally-generated
///    output from a mirrored connection.
#[embassy_executor::task]
async fn debug_task(mut dbg_tx: DirectUartTx, mut dbg_rx: DirectUartRx) -> ! {
    use embassy_futures::select::{Either, select};

    let mut counter: u32 = 0;
    let mut rx_byte = [0u8; 1];

    let _ = dbg_tx.write_all(b"\r\n[stm32g0 debug uart online]\r\n").await;

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

/// Toggles programming mode on each debounced press of the prog button.
/// The LED is driven from the main loop so it reflects remote ETS
/// programming-mode changes too, without racing with edge detection here.
#[embassy_executor::task]
async fn prog_task(knx: Stack<'static, Stm32G0System7LightSwitch>, prog_btn_pin: ExtiInput<'static>) -> ! {
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
    device: Stm32G0System7LightSwitch,
    system: embedded_common::CortexMSystem,
    guard: busy_gate(),
}

#[embassy_executor::task]
async fn lifecycle_task(knx: Stack<'static, Stm32G0System7LightSwitch>) -> ! {
    lifecycle_event_logger(knx).await
}

/// Application task — a single user button (PC11) driving `Btn1`.
///
/// The `LightSwitchComObjects` device still exposes two button slots to
/// ETS; we simply leave `Btn2` physically unwired. Rocker-mode
/// configurations therefore won't work, but single-function modes
/// (switch / dimmer / blind / scene) for `Btn1` do.
///
/// Around each long-press in Dimmer mode we also poke `DIM_RAMP` so
/// that `led_task` can mirror the dim direction with a smooth PWM
/// ramp on the user LED. The direction we publish is the same one
/// `app::handle_button_event` will use — see the comment block on
/// `dim_direction_for_long_press`.
#[embassy_executor::task]
async fn app_task(knx: Stack<'static, Stm32G0System7LightSwitch>, btn_pin: ExtiInput<'static>) -> ! {
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

        // Decide whether to drive the dim-ramp signal **before** delegating
        // to the application adapter, mirroring the shared behavior's
        // direction logic. We deliberately don't try to flip
        // `button_state` ourselves — the helper does that — so the two stay
        // in sync across consecutive long presses.
        if event == ButtonEvent::LongPressStart && matches!(params.button1_config, ButtonConfig::Dimmer { .. }) {
            let up = dim_direction_for_long_press(&params, ButtonId::Btn1, button_state.next_dim_up());
            DIM_RAMP.store(if up { 1 } else { -1 }, Ordering::Relaxed);
        } else if event == ButtonEvent::LongPressRelease {
            DIM_RAMP.store(0, Ordering::Relaxed);
        }

        app::handle_button_event(&knx, &params, event, ButtonId::Btn1, &mut button_state).await;
    }
}

/// Re-derive the dimming direction `app::handle_button_event` is about to use.
///
/// In 1-function (rocker) mode the direction is fixed by which physical
/// button is wired and the configured rocker polarity. In 2-function
/// mode the helper alternates direction across consecutive long
/// presses and stores the next value in `button_state` — so the value we see
/// here is the one the helper will use on the **upcoming** press.
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

/// User-LED state-machine task.
///
/// Polls the local view of channel 1's status object every `LED_TICK`
/// and drives `TIM14_CH1` (PC12) accordingly. While `DIM_RAMP` is
/// non-zero, a long-press is in progress on Btn1 in Dimmer mode and
/// we ramp the duty in that direction at a fixed rate; otherwise the
/// duty snaps to 0% / 100% on each rising/falling status edge.
#[embassy_executor::task]
async fn led_task(knx: Stack<'static, Stm32G0System7LightSwitch>, mut pwm_ch: SimplePwmChannel<'static, TIM14>) -> ! {
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
            // No ramp in progress — sync to whatever the actuator
            // last told us. `read_status` reads the raw object
            // buffer, so it's safe to call before / after the stack
            // has been provisioned (it just returns false).
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
// Production builds: read the `KNXP` page; panic on any error.
// `provision-on-boot` builds: write the dev defaults from
// `dev_provisioning::DEV_*` and re-read.

#[cfg(feature = "provision-on-boot")]
mod dev_provisioning {
    include!(concat!(env!("OUT_DIR"), "/dev_provisioning.rs"));
}

// Boot logic is shared across all non-secure STM32 firmware; only the
// `provision-on-boot` dev serial is device-local (rendered into this crate's
// `OUT_DIR`).
stm32_common::stm32_identity_loader!(plain);

// ================================================================================
// Entry point
// ================================================================================

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // Default embassy-stm32 clocks — HSI at 16 MHz, no PLL. This is
    // plenty for a 19200 baud UART and keeps the init minimal. If ISR
    // jitter becomes an issue, configure PLL → 64 MHz here.
    let p = embassy_stm32::init(Config::default());
    info!("STM32G0 TP1 System 7 light switch (NCN5120) initializing");

    // --- Identity (from the KNXP provisioning page) -------------------------
    let flash = stm32_common::stm32_flash_cell!(p.FLASH);
    let identity_data = load_identity(&mut flash.borrow_mut());
    info!("Serial: {=[u8]:02x}", identity_data.serial_number);

    // --- USART1 — NCN5120 TPUART at 19200 8E1 -------------------------------
    //
    // The embassy `Uart<Blocking>` handles baud, parity, pin muxing. We
    // then hand it to `DirectUart::new`, which disables the FIFO and
    // configures per-byte interrupts with direct register access.
    let mut uart_config = UartConfig::default();
    uart_config.baudrate = 19200;
    // E981.03 datasheet Figure 4 ambiguously labels parity as "odd", but
    // empirically the chip transmits with **even** parity at 19.2 kBd —
    // consistent with the rest of the TPUART family (NCN5120, TPUART2).
    // Odd parity causes every RX byte to fault PE.
    uart_config.parity = Parity::ParityEven;
    let uart = Uart::new_blocking(
        p.USART1,
        p.PA10, // RX
        p.PA9,  // TX
        uart_config,
    )
    .expect("USART1 init");
    let (uart_tx, uart_rx) = DirectUart::new::<USART1>(uart, Irqs);
    info!("USART1 initialized (19200 8E1, direct register access)");

    // --- USART3 — debug UART at 115200 8N1 on PB0/PB2 ----------------------
    //
    // Routed through the same `DirectUart` driver as the TPUART. If the
    // heartbeat comes out of PB2 but TPUART traffic on PA9 is silent, the
    // fault is in USART1 clock/pin config — not the driver.
    let mut dbg_cfg = UartConfig::default();
    dbg_cfg.baudrate = 115_200;
    let dbg_uart = Uart::new_blocking(
        p.USART3, p.PB0, // RX
        p.PB2, // TX
        dbg_cfg,
    )
    .expect("USART3 init");
    let (dbg_tx, dbg_rx) = DirectUart::new::<USART3>(dbg_uart, Irqs);
    info!("USART3 initialized (115200 8N1, PB2=TX, PB0=RX)");

    // --- Persistent storage --------------------------------------------------
    // The stores struct lives in a static so the storage task can reach it;
    // each store sits behind its own RefCell, borrowed per call on the
    // single-threaded executor.
    static STORAGE: StaticCell<DeviceStorage> = StaticCell::new();
    let storage =
        &*STORAGE.init(DeviceStorage::new(Cfg::open(StmFlashIo::new(flash)).expect("config open is infallible")));
    let loaded_config = storage.load_config();

    let state_init = System7StateInit::new(identity_data, loaded_config);

    // --- KNX stack -----------------------------------------------------------
    let link_layer_builder = TpUartLinkLayerBuilder::new(uart_tx, uart_rx)
        .with_busy_flag(&BUSY_FLAG)
        .with_chip_busy_channel(CHIP_BUSY.dyn_receiver());

    static KNX_RESOURCES: StaticCell<
        StackResources<
            Stm32G0System7LightSwitch,
            { buffer_size_for_apdu(<Stm32G0System7LightSwitch as StackDefinition>::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        (),
        Stm32G0System7LightSwitch::memory_map(),
        storage,
    );

    spawner.spawn(knx_task(knx_runner)).expect("knx_task spawnable once");

    info!("KNX TP1 stack started");
    info!("  Manufacturer: {:04x}", LightSwitchDevice::MANUFACTURER_ID);
    info!(
        "  Application:  {:04x} v{:02x}",
        LightSwitchDevice::APPLICATION_ID_TP1_SYSTEM7,
        LightSwitchDevice::APPLICATION_VERSION
    );
    info!("  Mask version: 0705 (System 7 TP1)");

    // --- Application GPIO + tasks -------------------------------------------
    let user_btn_pin = ExtiInput::new(p.PC11, p.EXTI11, Pull::Up, Irqs);
    let prog_btn_pin = ExtiInput::new(p.PD2, p.EXTI2, Pull::Up, Irqs);

    // User LED on PC12 driven by TIM14_CH1 (AF2). `SimplePwm::split`
    // requires a `'static` lifetime on the channel so we can hand the
    // channel to a task; achieve that by parking the `SimplePwm` in a
    // `StaticCell`.
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

    // --- Main loop: prog LED -------------------------------------------------
    //
    // Prog LED on PB8 mirrors `is_programming_mode()` continuously so
    // remote ETS prog-mode changes are reflected without racing the
    // button edge detection in prog_task. The user LED on PC12 is now
    // driven by `led_task` via TIM14_CH1.
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
