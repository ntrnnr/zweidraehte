#![no_std]
#![no_main]
// `type State = SecureRfStateFor<…>` expands to const expressions over
// `SystemBStackDefinition::{ADT,AST,COT}_SIZE` — same flag the device crate uses.
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
//! # Bring-up limitations (same as the TP1 secure variant)
//!
//! - The FDSK is compiled into the firmware via `ZZ_FDSK_HEX` at build time.
//! - The RNG is a non-crypto PRNG seeded from ADC noise on a floating PA0; the
//!   G0B0 has no TRNG.
//!
//! Sequence numbers persist to an external SPI2 FRAM (FM25L16B) so cross-reboot
//! replay protection survives power loss.

use core::cell::RefCell;

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::{
    Config, bind_interrupts,
    exti::{self, ExtiInput},
    flash,
    gpio::{Input, Level, Output, Pull, Speed},
    mode::Blocking,
    spi::{self, Spi, mode::Master},
    time::Hertz,
};
use embassy_time::{Duration, Timer};
use embedded_common::DebouncedButton;
use embedded_hal::digital::InputPin;
use embedded_hal_async::digital::Wait;
use knxrf::sx1211::Sx1211;
use static_cell::StaticCell;
use stm32_common::sx1211_adapter::Sx1211Adapter;
use stm32_common::{FlashSecureIdentityData, Fm25l16b, FramSeqStorage, Stm32CommonRng, StmFlashStorage};
use {defmt_rtt as _, panic_probe as _};

use devices::light_switch::{
    self, LightSwitchDevice, LightSwitchParams,
    app::{self, ButtonId, WaitForRelease},
    comm_objs::{Index, LightSwitchComObjects},
    easter_egg::EasterEggAugment,
};

use zweidraehte_device::storage::SecureDeviceIdentity;
use zweidraehte_device::{
    bcus::system_b::*, config::MAX_APDU_LENGTH_RF, layers::linklayers::knxrf::KnxRfLinkLayerBuilder, prelude::*,
    storage::HasSequenceStorage,
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

const FLASH_SIZE: u32 = 512 * 1024;
const FLASH_PAGE_SIZE: u32 = 2 * 1024;

// ================================================================================
// Device Definition
// ================================================================================

const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_RF_SECURE;

/// P2P Key Table capacity — zero: this device does only tool access and secure
/// group telegrams, no point-to-point secure links. (See the TP1 secure variant
/// for the rationale.)
const P2P_SIZE: usize = 0;

/// SIAT capacity (Security Individual Address Table) — per 03/03/07 §5.3 it
/// covers every non-tool secure sender, including group-only senders. Also sizes
/// the FRAM peer slots in [`FramSeqStorage`].
const SIAT_SIZE: usize = 32;

/// Concrete SX1211 transceiver: blocking SPI3 plus two GPIO chip-selects.
type Radio = Sx1211Adapter<Spi<'static, Blocking, Master>, Output<'static>, Output<'static>>;

/// Concrete SPI2 handle for the FRAM, and its CS output.
type FramSpi = Spi<'static, Blocking, embassy_stm32::spi::mode::Master>;
type FramCs = Output<'static>;
/// Persistent sequence-number store on the FRAM.
type Stm32G0SeqStorage = FramSeqStorage<FramSpi, FramCs, SIAT_SIZE>;

type Stm32G0SecureState = SecureRfStateFor<Stm32G0KnxRfSecure, Stm32G0SeqStorage, P2P_SIZE, SIAT_SIZE>;
type Storage = StmFlashStorage<Stm32G0SecureState, FlashSecureIdentityData, FLASH_SIZE, FLASH_PAGE_SIZE>;

#[derive(Debug, Clone, Copy)]
pub struct Stm32G0KnxRfSecure;

// Security + RF-medium augment produced by the secure RF extension. The
// `SecureAugmentBundle` composes the inner `RfAugment` (RF Medium Object,
// Type 19) with the `SecurityAugment` (Security IO, Type 0x11), so the RF
// Domain Address property and the secure key tables both reach ETS.
type SecAugment<'a> = ExtensionAugmentFor<'a, Stm32G0KnxRfSecure>;

/// Augment chain: the secure RF medium + security augment, the
/// GO/operation-mode diagnostics augment, plus the demo Easter Egg
/// augment. As a secure device it uses the `SecureGoSendPresent` strategy
/// so the secure GO-diagnostics send-paths are wired up.
#[derive(zweidraehte_device::service::ServiceRegistry)]
pub struct Stm32G0SecureAugments<'a> {
    #[service(augment)]
    pub sec: SecAugment<'a>,
    #[service(augment)]
    pub diag: DiagnosticsAugment<'a, SecureGoSendPresent>,
    #[service(augment)]
    pub easter: EasterEggAugment,
}

impl SystemBStackDefinition for Stm32G0KnxRfSecure {}

impl HasSequenceStorage for Stm32G0KnxRfSecure {
    type SeqStorage = Stm32G0SeqStorage;
    // `create_seq_storage` is intentionally not overridden: the real store is
    // built in `main` from the SPI2 FRAM peripheral and threaded through
    // `StateInit` → `SecureResources`. The trait's default panics if ever
    // called, which it never is for this StateInit-threading device.
}

impl StackDefinition for Stm32G0KnxRfSecure {
    const DEVICE: &'static DeviceDescriptor = &DEVICE_DESCRIPTOR;
    // The configured RF APDU ceiling: sizes the pool buffers and is what PID 56
    // reports (the device state inits the runtime limit to this). The 55-octet
    // ceiling still leaves 42 octets of plaintext after the Data Secure envelope
    // (OVERHEAD = 13). See `MAX_APDU_LENGTH_RF`.
    const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_RF;
    const TL_STYLE: TlStyle = TlStyle::Style1;

    type P = LightSwitchParams;
    type CO = LightSwitchComObjects;
    type LLB = KnxRfLinkLayerBuilder<Radio>;
    // RF extension + Data Secure wrapper. `GRP`/`GO` are entry counts
    // (one group key slot per address table entry, one flag byte per
    // communication object), matching `SecureStateFor`'s invariant.
    type ES =
        SecureRfExtensionState<Stm32G0SeqStorage, { Self::ADT_ENTRIES }, P2P_SIZE, SIAT_SIZE, { Self::COT_ENTRIES }>;
    type Identity = FlashSecureIdentityData;
    type State = Stm32G0SecureState;
    type StateInit = SystemBStateInit<
        Self::Identity,
        <Stm32G0SecureState as HasDeviceConfig>::Config,
        SecureResources<RfExtensionState, Stm32G0SeqStorage>,
    >;
    type Mem = SystemBMemoryMap;
    type InterfaceObjects<'a> = SystemBInterfaceObjectsFor<'a, Self>;
    type Augments<'a> = Stm32G0SecureAugments<'a>;

    fn create_state(init: Self::StateInit) -> Self::State {
        Stm32G0SecureState::from_init(init)
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
        Stm32G0SecureAugments {
            sec: state.extension_state().create_augment::<Self>(platform),
            diag: DiagnosticsAugment::<SecureGoSendPresent>::new(&state.operation_mode),
            easter: EasterEggAugment,
        }
    }

    // Secure AL services plus the RF domain-address management services (the
    // serial-number variant and the RF-only programming-mode broadcast variant).
    type AlExtensions = (
        zweidraehte_device::layers::application::services::SystemBSecureAlServices,
        zweidraehte_device::layers::application::services::DomainAddressService,
        zweidraehte_device::layers::application::services::RfDomainAddressService,
    );
    type LayerBuilder = SecureDeviceBuilder;
    type Rng = Stm32CommonRng;
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
        btn.wait_for_press(debounce, None).await;
        let current = knx.state().is_programming_mode();
        knx.state().set_programming_mode(!current);
        info!("Programming mode: {}", !current);
    }
}

#[embassy_executor::task]
async fn restart_task(knx: Stack<'static, Stm32G0KnxRfSecure>, storage: &'static RefCell<Storage>) -> ! {
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

fn save_state(state: &Stm32G0SecureState, storage: &RefCell<Storage>) {
    match storage.borrow_mut().save(state) {
        Ok(()) => {
            state.clear_dirty();
            info!("State saved to flash");
        }
        Err(e) => warn!("Flash save failed: {}", e),
    }
}

#[embassy_executor::task]
async fn lifecycle_task(knx: Stack<'static, Stm32G0KnxRfSecure>) -> ! {
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
async fn app_task(knx: Stack<'static, Stm32G0KnxRfSecure>, btn_pin: ExtiInput<'static>) -> ! {
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
// Identity load (secure: carries the FDSK)
// ================================================================================

fn load_secure_identity(flash: &mut flash::Flash<'static, flash::Blocking>) -> FlashSecureIdentityData {
    match stm32_common::read_provisioning::<FLASH_SIZE, FLASH_PAGE_SIZE>(flash) {
        Ok(rec) => stm32_common::secure_identity_from_record(&rec)
            .unwrap_or_else(|e| defmt::panic!("KNXP missing FDSK: {:?}", e)),

        #[cfg(feature = "provision-on-boot")]
        Err(e) => {
            warn!("no KNXP record ({:?}); writing dev defaults from build.rs", e);
            stm32_common::synthesize_and_write::<FLASH_SIZE, FLASH_PAGE_SIZE>(
                flash,
                dev_provisioning::DEV_SERIAL,
                Some(dev_provisioning::DEV_FDSK),
                Some(dev_provisioning::DEV_MAC),
            )
            .expect("write dev KNXP");
            let rec = stm32_common::read_provisioning::<FLASH_SIZE, FLASH_PAGE_SIZE>(flash)
                .expect("re-read freshly written KNXP");
            stm32_common::secure_identity_from_record(&rec)
                .unwrap_or_else(|e| defmt::panic!("KNXP missing FDSK after dev synth: {:?}", e))
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
    info!("STM32G0 KNX-RF **Data Secure** light switch (SX1211) initializing");

    // Seed the PRNG from ADC noise on a floating PA0 before the secure stack
    // starts (the S-A_Sync challenge generator panics if used unseeded).
    stm32_common::rng::seed_from_adc(p.ADC1, p.PA0);

    // --- Identity (FDSK from the KNXP provisioning page) --------------------
    let mut flash_hw = flash::Flash::new_blocking(p.FLASH);
    let identity_data = load_secure_identity(&mut flash_hw);
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
    let mut fram_cfg = spi::Config::default();
    fram_cfg.frequency = Hertz(4_000_000);
    let fram_spi: FramSpi = Spi::new_blocking(p.SPI2, p.PB13, p.PB15, p.PB14, fram_cfg);
    let fram_cs: FramCs = Output::new(p.PB12, Level::High, Speed::VeryHigh);
    // ~WP only gates the chip's WRSR, which the driver never issues — park it
    // high for the device's lifetime so the pin keeps its configuration.
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

    let fdsk = *SecureDeviceIdentity::fdsk(&identity_data);
    let resources = SecureResources { inner: (), seq_storage, fdsk };
    let state_init = SystemBStateInit { identity: identity_data, loaded_config, resources };

    static STORAGE: StaticCell<RefCell<Storage>> = StaticCell::new();
    let storage = &*STORAGE.init(RefCell::new(storage));

    // --- KNX secure stack ----------------------------------------------------
    static KNX_RESOURCES: StaticCell<
        StackResources<
            Stm32G0KnxRfSecure,
            {
                zweidraehte_device::config::buffer_size_for_apdu(
                    <Stm32G0KnxRfSecure as StackDefinition>::MAX_APDU_LENGTH,
                )
            },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        (),
        Stm32G0KnxRfSecure::memory_map(),
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
