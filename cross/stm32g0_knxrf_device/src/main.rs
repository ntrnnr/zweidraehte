#![no_std]
#![no_main]

//! STM32G0B0RE KNX-RF light switch (Semtech SX1211).
//!
//! The MCU-specific shell around the shared `devices::light_switch` definition,
//! driving a Semtech SX1211 KNX-RF transceiver instead of a TPUART. The device
//! stack, ETS parameter surface, and application logic are identical to
//! `cross/stm32g0_tp1_light_switch` — only the link layer (KNX-RF instead of
//! TP1), the medium extension (RF Medium Object + Domain Address), and the radio
//! bring-up differ.
//!
//! The radio drive code (buffered-mode RX drain, listen-before-talk TX) lives in
//! the shared [`stm32_common::sx1211_adapter`] module as an [`Sx1211Adapter`]
//! implementing the stack's `RfTransceiver` trait, ported from
//! `stm32g0_knxrf_playground`.

use core::cell::RefCell;

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::{
    Config, bind_interrupts,
    exti::{self, ExtiInput},
    flash,
    gpio::{Input, Level, Output, Pull, Speed},
    mode::Blocking,
    spi::{Config as SpiConfig, Spi, mode::Master},
    time::Hertz,
};
use embassy_time::{Duration, Timer};
use embedded_common::DebouncedButton;
use embedded_hal::digital::InputPin;
use embedded_hal_async::digital::Wait;
use knxrf::sx1211::Sx1211;
use static_cell::StaticCell;
use stm32_common::sx1211_adapter::Sx1211Adapter;
use stm32_common::{FlashIdentityData, StmFlashStorage};
use {defmt_rtt as _, panic_probe as _};

use devices::light_switch::{
    self, LightSwitchDevice, LightSwitchParams,
    app::{self, ButtonId, WaitForRelease},
    comm_objs::{Index, LightSwitchComObjects},
    easter_egg::EasterEggAugment,
};

use zweidraehte_device::{
    bcus::system_b::*, config::MAX_APDU_LENGTH_EXTENDED, layers::linklayers::knxrf::KnxRfLinkLayerBuilder, prelude::*,
};

// ================================================================================
// Interrupt Bindings
// ================================================================================

// EXTI line N maps to pin N across all ports. The SX1211 status pins live on
// PD3 (PLL_LOCK, line 3 → EXTI2_3) and PD4/PD5 (IRQ1/IRQ0, lines 4/5 →
// EXTI4_15); the prog button is PD2 (line 2 → EXTI2_3) and the user button is
// PC8 (line 8 → EXTI4_15).
bind_interrupts!(struct Irqs {
    EXTI2_3 => exti::InterruptHandler<embassy_stm32::interrupt::typelevel::EXTI2_3>;
    EXTI4_15 => exti::InterruptHandler<embassy_stm32::interrupt::typelevel::EXTI4_15>;
});

// ================================================================================
// Flash Layout
// ================================================================================

// STM32G0B0RE — 512 KiB flash, 2 KiB erase page.
const FLASH_SIZE: u32 = 512 * 1024;
const FLASH_PAGE_SIZE: u32 = 2 * 1024;

// ================================================================================
// Device Definition
// ================================================================================

// KNX-RF System B descriptor (mask version 27B0, application id 0x0303).
const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_RF;

/// Concrete SX1211 transceiver type: blocking SPI3 plus two GPIO chip-selects.
type Radio = Sx1211Adapter<Spi<'static, Blocking, Master>, Output<'static>, Output<'static>>;

type Stm32G0State = RfStateFor<Stm32G0KnxRf>;
type Storage = StmFlashStorage<Stm32G0State, FlashIdentityData, FLASH_SIZE, FLASH_PAGE_SIZE>;

#[derive(Debug, Clone, Copy)]
pub struct Stm32G0KnxRf;

/// Augment chain: the RF medium augment (RF Medium Object) plus the demo Easter
/// Egg augment. The `#[service(augment)]` fields derive the `Augment<D>` chain.
#[derive(zweidraehte_device::service::ServiceRegistry)]
pub struct Stm32G0KnxRfAugments<'a> {
    #[service(augment)]
    pub rf: RfAugment<'a>,
    #[service(augment)]
    pub easter: EasterEggAugment,
}

impl SystemBStackDefinition for Stm32G0KnxRf {}

impl StackDefinition for Stm32G0KnxRf {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_EXTENDED;
    const TL_STYLE: TlStyle = TlStyle::Style1;

    type P = LightSwitchParams;
    type CO = LightSwitchComObjects;
    type LLB = KnxRfLinkLayerBuilder<Radio>;
    type ES = RfExtensionState;
    type Identity = FlashIdentityData;
    type State = Stm32G0State;
    type StateInit = SystemBStateInit<Self::Identity, <Stm32G0State as HasDeviceConfig>::Config>;
    type Mem = SystemBMemoryMap;
    type InterfaceObjects<'a> = SystemBInterfaceObjectsFor<'a, Self>;
    type Augments<'a> = Stm32G0KnxRfAugments<'a>;

    fn create_state(init: Self::StateInit) -> Self::State {
        Stm32G0State::from_init(init)
    }

    fn create_interface_objects<'a>(
        state: &'a Self::State,
        platform: &'a Self::Platform,
        layer_ctx: &'a zweidraehte_device::context::layer::LayerContext<Self>,
        augments: &'a Self::Augments<'a>,
    ) -> Self::InterfaceObjects<'a>
    where
        Self::State: 'a,
        Self::Platform: 'a,
    {
        Self::default_interface_objects(state, platform, layer_ctx, augments)
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
        Stm32G0KnxRfAugments { rf: state.extension_state().create_augment::<Self>(platform), easter: EasterEggAugment }
    }

    // RF devices add the domain-address management services ETS uses during
    // configuration: the serial-number variant (`DomainAddressService`) and the
    // programming-mode broadcast variant (`RfDomainAddressService`, RF-only).
    type AlExtensions = (
        zweidraehte_device::layers::application::services::SystemBAlServices,
        zweidraehte_device::layers::application::services::DomainAddressService,
        zweidraehte_device::layers::application::services::RfDomainAddressService,
    );
    type LayerBuilder = InsecureDeviceBuilder;
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
// Local I/O:
//   PC8  = user button (active low, internal pull-up)
//   PC9  = user LED (on/off, reflects Btn1 status)
//   PD2  = programming-mode button (active low, internal pull-up)
//   PB8  = programming-mode LED (active high)
//
// Reserved for the future secure variant (KNX Data Secure sequence numbers on
// an external SPI2 FRAM): SCK=PB13, MISO=PB14, MOSI=PB15, CS=PB12.

// ================================================================================
// Tasks
// ================================================================================

#[embassy_executor::task]
async fn knx_task(runner: Runner<'static, Stm32G0KnxRf>) -> ! {
    runner.run().await
}

/// Toggles programming mode on each debounced press of the prog button.
#[embassy_executor::task]
async fn prog_task(knx: Stack<'static, Stm32G0KnxRf>, prog_btn_pin: ExtiInput<'static>) -> ! {
    let mut btn = DebouncedButton::new(prog_btn_pin);
    let debounce = Duration::from_millis(50);
    loop {
        btn.wait_for_press(debounce, None).await;
        let current = knx.state().is_programming_mode();
        knx.state().set_programming_mode(!current);
        info!("Programming mode: {}", !current);
    }
}

/// A_Restart handler: execute the requested reset, persist, delay so the
/// A_Restart_Response reaches the wire, then trigger a Cortex-M system reset.
#[embassy_executor::task]
async fn restart_task(knx: Stack<'static, Stm32G0KnxRf>, storage: &'static RefCell<Storage>) -> ! {
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
            EraseCode::ResetLinks | EraseCode::Other(_) => warn!("Unsupported erase code — ignoring"),
        }

        if state.is_dirty() {
            save_state(state, storage);
        }

        Timer::after(Duration::from_millis(100)).await;

        let mut system = CortexMSystem;
        let Err(_e) = system.restart().await;
    }
}

fn save_state(state: &Stm32G0State, storage: &RefCell<Storage>) {
    match storage.borrow_mut().save(state) {
        Ok(()) => {
            state.clear_dirty();
            info!("State saved to flash");
        }
        Err(e) => warn!("Flash save failed: {}", e),
    }
}

#[embassy_executor::task]
async fn lifecycle_task(knx: Stack<'static, Stm32G0KnxRf>) -> ! {
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

/// Application task — a single user button (PC8) driving `Btn1`.
///
/// The `LightSwitchComObjects` device still exposes two button slots to ETS; we
/// leave `Btn2` physically unwired, so single-function modes (switch / dimmer /
/// blind / scene) for `Btn1` work but rocker modes do not.
#[embassy_executor::task]
async fn app_task(knx: Stack<'static, Stm32G0KnxRf>, btn_pin: ExtiInput<'static>) -> ! {
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

        let mut waiter = ReleaseWaiter { btn: &mut btn, debounce };
        app::handle_button_press(&knx, &params, event, ButtonId::Btn1, &mut waiter, &mut dim_up).await;
    }
}

/// User-LED task — a plain on/off GPIO on PC9 mirroring `Btn1`'s status object.
///
/// (The TP1 light switch renders a smooth PWM dim ramp on TIM14_CH1, but that
/// pin (PC12) is the SX1211's SPI MOSI here, so we drop the PWM visualisation.)
#[embassy_executor::task]
async fn led_task(knx: Stack<'static, Stm32G0KnxRf>, mut led: Output<'static>) -> ! {
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
// Identity load
// ================================================================================

#[cfg(feature = "provision-on-boot")]
mod dev_provisioning {
    include!(concat!(env!("OUT_DIR"), "/dev_provisioning.rs"));
}

fn load_identity(flash: &mut flash::Flash<'static, flash::Blocking>) -> FlashIdentityData {
    match stm32_common::read_provisioning::<FLASH_SIZE, FLASH_PAGE_SIZE>(flash) {
        Ok(rec) => stm32_common::identity_from_record(&rec),

        #[cfg(feature = "provision-on-boot")]
        Err(e) => {
            warn!("no KNXP record ({:?}); writing dev defaults from build.rs", e);
            stm32_common::synthesize_and_write::<FLASH_SIZE, FLASH_PAGE_SIZE>(
                flash,
                dev_provisioning::DEV_SERIAL,
                None,
                None,
            )
            .expect("write dev KNXP");
            let rec = stm32_common::read_provisioning::<FLASH_SIZE, FLASH_PAGE_SIZE>(flash)
                .expect("re-read freshly written KNXP");
            stm32_common::identity_from_record(&rec)
        }

        #[cfg(not(feature = "provision-on-boot"))]
        Err(e) => defmt::panic!("no valid KNXP record: {:?}", e),
    }
}

// ================================================================================
// Entry point
// ================================================================================

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_stm32::init(Config::default());
    info!("STM32G0 KNX-RF light switch (SX1211) initializing");

    // --- Identity (from the KNXP provisioning page) -------------------------
    let mut flash_hw = flash::Flash::new_blocking(p.FLASH);
    let identity_data = load_identity(&mut flash_hw);
    info!("Serial: {=[u8]:02x}", identity_data.serial_number);

    // --- SX1211 radio on SPI3 -----------------------------------------------
    //
    // 1 MHz: the SX1211 datasheet rates the FIFO (Data) SPI interface at 1 MHz
    // max; we share one bus for register + FIFO access, so the slower limit
    // applies (running faster corrupts every FIFO byte).
    let mut spi_cfg = SpiConfig::default();
    spi_cfg.frequency = Hertz(1_000_000);
    let spi = Spi::new_blocking(p.SPI3, p.PC10, p.PC12, p.PC11, spi_cfg);

    let nss_cfg = Output::new(p.PD0, Level::High, Speed::VeryHigh);
    let nss_data = Output::new(p.PD1, Level::High, Speed::VeryHigh);

    let pll_lock = ExtiInput::new(p.PD3, p.EXTI3, Pull::None, Irqs);
    let threshold = ExtiInput::new(p.PD4, p.EXTI4, Pull::None, Irqs); // IRQ1 / Fifo_threshold
    let irq0 = ExtiInput::new(p.PD5, p.EXTI5, Pull::None, Irqs); // sync detected
    let data = Input::new(p.PD6, Pull::Up); // demodulated chips (CCA only)

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

    // --- Persistent storage --------------------------------------------------
    let mut storage = Storage::new(flash_hw, identity_data);
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

    // --- KNX stack -----------------------------------------------------------
    static KNX_RESOURCES: StaticCell<
        StackResources<
            Stm32G0KnxRf,
            { zweidraehte_device::config::buffer_size_for_apdu(<Stm32G0KnxRf as StackDefinition>::MAX_APDU_LENGTH) },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        (),
        Stm32G0KnxRf::memory_map(),
    );

    spawner.spawn(knx_task(knx_runner)).expect("knx_task spawnable once");

    info!("KNX-RF stack started");
    info!("  Manufacturer: {:04x}", LightSwitchDevice::MANUFACTURER_ID);

    // --- Application GPIO + tasks -------------------------------------------
    let user_btn_pin = ExtiInput::new(p.PC8, p.EXTI8, Pull::Up, Irqs);
    let prog_btn_pin = ExtiInput::new(p.PD2, p.EXTI2, Pull::Up, Irqs);
    let user_led = Output::new(p.PC9, Level::Low, Speed::Low);

    spawner.spawn(app_task(knx_stack, user_btn_pin)).expect("app_task spawnable once");
    spawner.spawn(prog_task(knx_stack, prog_btn_pin)).expect("prog_task spawnable once");
    spawner.spawn(restart_task(knx_stack, storage)).expect("restart_task spawnable once");
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
