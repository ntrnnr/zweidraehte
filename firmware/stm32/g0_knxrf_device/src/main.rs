#![no_std]
#![no_main]

//! STM32G0B0RE KNX-RF light switch (Semtech SX1211).
//!
//! The MCU-specific shell around the shared `devices::light_switch` definition,
//! driving a Semtech SX1211 KNX-RF transceiver instead of a TPUART. The device
//! stack, ETS parameter surface, and application logic are identical to
//! `firmware/stm32/g0_tp1_light_switch` — only the link layer (KNX-RF instead of
//! TP1), the medium extension (RF Medium Object + Domain Address), and the radio
//! bring-up differ.
//!
//! The radio drive code (buffered-mode RX drain, listen-before-talk TX) lives in
//! the shared [`stm32_common::sx1211_adapter`] module as an [`Sx1211Adapter`]
//! implementing the stack's `RfTransceiver` trait, ported from
//! `stm32g0_knxrf_playground`.

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::{
    Config, bind_interrupts,
    exti::{self, ExtiInput},
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
use stm32_common::flash_io::StmFlashIo;
use stm32_common::sx1211_adapter::Sx1211Adapter;
use stm32_common::{FlashIdentityData, StmConfigRegion, StmFlash};
use {defmt_rtt as _, panic_probe as _};

use devices::light_switch::{
    self, LightSwitchDevice, LightSwitchParams,
    app::{self, ButtonId, WaitForRelease},
    comm_objs::{Index, LightSwitchComObjects},
    easter_egg::EasterEggAugment,
};

use zweidraehte_device::{
    bcus::system_b::*, config::MAX_APDU_LENGTH_RF, layers::linklayers::knxrf::KnxRfLinkLayerBuilder, prelude::*,
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

// ================================================================================
// Device Definition
// ================================================================================

// KNX-RF System B descriptor (mask version 27B0, application id 0x0303).
const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_RF;

/// Concrete SX1211 transceiver type: blocking SPI3 plus two GPIO chip-selects.
type Radio = Sx1211Adapter<Spi<'static, Blocking, Master>, Output<'static>, Output<'static>>;

type Stm32G0State = RfStateFor<Stm32G0KnxRf>;

// ----------------------------------------------------------------------------
// Storage layout — one config region on the StmFlash chip
// ----------------------------------------------------------------------------

// The region declares its payload (this device's state) and derives its
// placement, store type, and open() from the layout — the store type is
// never spelled out.
use zweidraehte_device::storage::{ConfigStorage, Placed, RegionSpec, StorageLayout, StoreOf};

// `pub`: the map reaches the public `StackDefinition` surface through
// `DeviceStorage`'s `StoreOf` projection.
pub struct StorageMap;
type Cfg = Placed<StmConfigRegion<Stm32G0State>, StmFlash, StorageMap>;
impl StorageLayout for StorageMap {
    const REGIONS: &'static [RegionSpec] = &[Cfg::SPEC];
}
type DeviceStorage = ConfigStorage<StoreOf<Cfg>>;

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

zweidraehte_device::system_b_standard_stack! {
    stack: Stm32G0KnxRf,
    device: &DEVICE_DESCRIPTOR,
    tl_style: TlStyle::Style3,
    params: LightSwitchParams,
    com_objects: LightSwitchComObjects,
    link_layer_builder: KnxRfLinkLayerBuilder<Radio>,
    platform: (),
    extension_state: RfExtensionState,
    state: Stm32G0State,
    // RF devices add the domain-address management services ETS uses during
    // configuration: the serial-number variant (`DomainAddressService`) and the
    // programming-mode broadcast variant (`RfDomainAddressService`, RF-only).
    al_extensions: (
        zweidraehte_device::layers::application::services::SystemBAlServices,
        zweidraehte_device::layers::application::services::DomainAddressService,
        zweidraehte_device::layers::application::services::RfDomainAddressService,
    ),
    layer_builder: PlainDeviceBuilder,
    augments: {
        bundle: Stm32G0KnxRfAugments,
        create: |state, platform, _layer_ctx| Stm32G0KnxRfAugments {
            rf: state.extension_state().create_augment::<Self>(platform),
            easter: EasterEggAugment,
        },
    },
    extra {
        // The configured RF APDU ceiling: sizes the pool buffers and is what
        // PID 56 reports (the device state inits the runtime limit to this).
        // Far below the extended-frame 254, saving ~200 B/buffer. See
        // `MAX_APDU_LENGTH_RF`.
        const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_RF;
        type Identity = FlashIdentityData;
        // The storage handle rides on the stack; the storage task pulls the
        // config store out of it.
        type Storage = &'static DeviceStorage;
    },
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

zweidraehte_device::storage_task! {
    device: Stm32G0KnxRf,
    system: embedded_common::CortexMSystem,
    guard: zweidraehte_device::storage::NoSaveGuard,
}

#[embassy_executor::task]
async fn lifecycle_task(knx: Stack<'static, Stm32G0KnxRf>) -> ! {
    zweidraehte_device::lifecycle::lifecycle_event_logger(knx).await
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

// Boot logic is shared across all non-secure STM32 firmware; only the
// `provision-on-boot` dev serial is device-local (rendered into this crate's
// `OUT_DIR`).
stm32_common::stm32_identity_loader!(plain);

// ================================================================================
// Entry point
// ================================================================================

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_stm32::init(Config::default());
    info!("STM32G0 KNX-RF light switch (SX1211) initializing");

    // --- Identity (from the KNXP provisioning page) -------------------------
    let flash = stm32_common::stm32_flash_cell!(p.FLASH);
    let identity_data = load_identity(&mut flash.borrow_mut());
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
    // The stores struct lives in a static so the storage task can reach it;
    // each store sits behind its own RefCell, borrowed per call on the
    // single-threaded executor.
    static STORAGE: StaticCell<DeviceStorage> = StaticCell::new();
    let storage =
        &*STORAGE.init(DeviceStorage::new(Cfg::open(StmFlashIo::new(flash)).expect("config open is infallible")));
    let loaded_config = storage.load_config();

    let state_init = SystemBStateInit::new(identity_data, loaded_config);

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
        storage,
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
