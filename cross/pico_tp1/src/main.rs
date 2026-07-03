#![no_std]
#![no_main]
#![feature(never_type)]

use defmt::*;
use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_rp::{
    bind_interrupts,
    gpio::{Input, Level, Output, Pull},
    peripherals::UART0,
    uart::{Config as UartConfig, Parity, Uart},
};
use embassy_time::{Duration, Timer};
use embedded_hal::digital::InputPin;
use embedded_hal_async::digital::Wait;
use rp_common::uart::{DirectInterruptHandler, DirectUart, DirectUartRx, DirectUartTx};
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use devices::light_switch::{
    self, LightSwitchDevice, LightSwitchParams,
    app::{self, ButtonId, WaitForRelease},
    comm_objs::LightSwitchComObjects,
    easter_egg::EasterEggAugment,
};

use zweidraehte_device::{
    bcus::system_b::*, config::MAX_APDU_LENGTH_EXTENDED, layers::linklayers::tpuart::TpUartLinkLayerBuilder, prelude::*,
};

use embedded_common::DebouncedButton;
use rp_common::{FlashIdentityData, RpConfigRegion, RpFlash, RpFlashIo};

// ================================================================================
// Busy gating for flash saves
// ================================================================================

// Flash sector erase on RP2040 stalls the entire CPU for ~45-73 ms (XIP
// bus stall), freezing even the UART ISR — far beyond the ~1.7 ms TP1
// acknowledge window. Saves therefore run behind the busy gate: the
// software flag turns ACKs into BUSY acknowledges, and the rendezvous
// channel arms the NCN5120's autonomous busy mode so the chip keeps
// answering BUSY while the CPU is stalled. The remote sender's link
// layer retries (busy_retry_count) until the save finishes.
embedded_common::tp1_busy_gate!();

// ================================================================================
// Interrupt Bindings
// ================================================================================

bind_interrupts!(struct Irqs {
    UART0_IRQ => DirectInterruptHandler<UART0>;
});

// ================================================================================
// Device Definition
// ================================================================================

/// Device descriptor from the light switch device definition (TP1 variant).
const DEVICE_DESCRIPTOR: DeviceDescriptor = light_switch::DEVICE_DESCRIPTOR_TP1;

/// Device state for TP1. Table sizes derive from `DEVICE_DESCRIPTOR`
/// via the `SystemBStackDefinition` associated consts.
type PicoTp1State = Tp1StateFor<PicoTp1LightSwitch>;

// ----------------------------------------------------------------------------
// Storage layout — one config region on the shared RpFlash chip
// ----------------------------------------------------------------------------

// The device's storage memory map: a single config blob carrying this
// device's state as its payload. The `Placed` entry derives its placement,
// store type, and open() from the layout.
use zweidraehte_device::storage::{ConfigStorage, Placed, RegionSpec, StorageLayout, StoreOf};

// `pub`: the map reaches the public `StackDefinition` surface through
// `DeviceStorage`'s `StoreOf` projection.
pub struct StorageMap;
type Cfg = Placed<RpConfigRegion<PicoTp1State>, RpFlash, StorageMap>;
impl StorageLayout for StorageMap {
    const REGIONS: &'static [RegionSpec] = &[Cfg::SPEC];
}
type DeviceStorage = ConfigStorage<StoreOf<Cfg>>;

// ----------------------------------------------------------------------------
// StackDefinition
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct PicoTp1LightSwitch;

/// Augment chain: the TP1 medium augment (borrows the extension state)
/// plus the demo Easter Egg augment. Derives `Augment<D>` from the field
/// annotations.
#[derive(zweidraehte_device::service::ServiceRegistry)]
pub struct PicoTp1Augments<'a> {
    #[service(augment)]
    tp1: Tp1Augment<'a>,
    #[service(augment)]
    easter: EasterEggAugment,
}

zweidraehte_device::system_b_standard_stack! {
    stack: PicoTp1LightSwitch,
    device: &DEVICE_DESCRIPTOR,
    tl_style: TlStyle::Style1,
    params: LightSwitchParams,
    com_objects: LightSwitchComObjects,
    link_layer_builder: TpUartLinkLayerBuilder<DirectUartTx, DirectUartRx>,
    platform: (),
    extension_state: Tp1ExtensionState,
    state: PicoTp1State,
    al_extensions: zweidraehte_device::layers::application::services::SystemBAlServices,
    layer_builder: InsecureDeviceBuilder,
    augments: {
        bundle: PicoTp1Augments,
        create: |state, platform, _layer_ctx| PicoTp1Augments {
            tp1: state.extension_state().create_augment::<Self>(platform),
            easter: EasterEggAugment,
        },
    },
    extra {
        // The NCN5120 supports extended frames (248 bytes from its 256-byte
        // buffer). Allocate compile-time buffers for the full extended range.
        const MAX_APDU_LENGTH: u16 = MAX_APDU_LENGTH_EXTENDED;
        // Everything runs on the same single-threaded executor, so
        // NoopRawMutex (the `Mutex` default) is sufficient.
        // CriticalSectionRawMutex would only be needed if the KNX stack
        // ran on a separate InterruptExecutor.
        type Identity = FlashIdentityData;
        // The storage handle rides on the stack; the storage task pulls the
        // config store out of it.
        type Storage = &'static DeviceStorage;
    },
}

// ================================================================================
// GPIO Assignments
// ================================================================================

// TPUART (NCN5120) on UART0.
// PIN_0 = TX (GP0)
// PIN_1 = RX (GP1)

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
async fn knx_task(runner: Runner<'static, PicoTp1LightSwitch>) -> ! {
    runner.run().await
}

// ================================================================================
// Application Logic
// ================================================================================

/// Programming mode button handler.
///
/// Toggles programming mode on each debounced press. The LED is
/// updated from the heartbeat loop so it also tracks remote changes
/// from ETS without interfering with edge detection here.
#[embassy_executor::task]
async fn prog_task(knx: Stack<'static, PicoTp1LightSwitch>, prog_btn_pin: Input<'static>) -> ! {
    let mut btn = DebouncedButton::new(prog_btn_pin);
    let debounce = Duration::from_millis(50);

    loop {
        // Block until a real press — long press detection is not
        // needed here, any press toggles programming mode.
        btn.wait_for_press(debounce, None).await;

        let current = knx.state().is_programming_mode();
        knx.state().set_programming_mode(!current);
        info!("Programming mode: {}", !current);
    }
}

zweidraehte_device::storage_task! {
    device: PicoTp1LightSwitch,
    system: embedded_common::CortexMSystem,
    guard: busy_gate(),
}

/// Lifecycle event logger.
///
/// Logs application start/stop transitions so we can observe ETS
/// programming completing (or unloading) via defmt.
#[embassy_executor::task]
async fn lifecycle_task(knx: Stack<'static, PicoTp1LightSwitch>) -> ! {
    zweidraehte_device::lifecycle::lifecycle_event_logger(knx).await
}

/// Main application task: handles button 1 and button 2 presses.
///
/// Reads the ETS-programmed parameters to determine button mode
/// (1-function rocker vs 2-function independent) and function type
/// (switch, dimmer, blind, scene), then publishes to the appropriate
/// communication objects on the KNX bus.
#[embassy_executor::task]
async fn app_task(knx: Stack<'static, PicoTp1LightSwitch>, btn1_pin: Input<'static>, btn2_pin: Input<'static>) -> ! {
    let mut btn1 = DebouncedButton::new(btn1_pin);
    let mut btn2 = DebouncedButton::new(btn2_pin);

    // Per-button dimming direction state. Alternates between brighter
    // and darker on each long press so the user can reverse direction.
    let mut btn1_dim_up = true;
    let mut btn2_dim_up = true;

    loop {
        // Wait until the application has been loaded and started by ETS.
        // Before that, the parameter memory is uninitialized and comm
        // objects are not configured, so button presses would be meaningless.
        if !knx.state().is_running() {
            Timer::after(Duration::from_millis(200)).await;
            continue;
        }

        // Read the current ETS-programmed parameters. We re-read every
        // iteration so parameter changes from a new ETS download take
        // effect immediately.
        let params = *knx.state().app().borrow().params();
        let debounce = params.debounce_time.as_duration();
        let long_press = params.long_press_time.as_duration();

        // Race both buttons — whichever fires first gets processed.
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

rp_common::rp_identity_loader!(plain, fdsk: None, mac: None);

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
    info!("Pico TP1 (NCN5120) initializing");

    // ========================================================================
    // Device identity (from flash)
    // ========================================================================

    // The flash peripheral is shared via a `&'static RefCell` so the
    // ConfigStore and any other flash consumer (e.g. a sequence-number store
    // on a secure device) can reach the same hardware handle.
    let flash = rp_common::rp_flash_cell!(p.FLASH);
    let identity_data = load_identity(&mut flash.borrow_mut());

    info!("Serial: {=[u8]:02x}", identity_data.serial_number);

    // ========================================================================
    // UART0 init — NCN5120 TPUART at 19200 baud, even parity
    // ========================================================================

    let mut uart_config = UartConfig::default();
    uart_config.baudrate = 19200;
    uart_config.parity = Parity::ParityEven;

    // Create a blocking UART first (handles baud rate, parity, pin muxing),
    // then convert to DirectUart which disables the FIFO and uses per-byte
    // interrupts with direct register access and an ISR-fed ring buffer.
    let uart = Uart::new_blocking(
        p.UART0,
        p.PIN_0, // TX = GP0
        p.PIN_1, // RX = GP1
        uart_config,
    );
    let (uart_tx, uart_rx) = DirectUart::new::<UART0>(uart, Irqs);

    info!("UART0 initialized (19200 8E1, direct register access)");

    // ========================================================================
    // Persistent storage
    // ========================================================================

    // Flash storage for persistent device state (the CONFIG region,
    // auto-placed at `RpFlash::BASE` by the layout consts above).
    // The `flash` handle was used transiently for identity provisioning
    // above and is now passed to the ConfigStore for config persistence.
    // The stores struct lives in a static so the storage task can reach it;
    // each store sits behind its own RefCell, borrowed per call on the
    // single-threaded executor.
    static STORAGE: StaticCell<DeviceStorage> = StaticCell::new();
    let storage =
        &*STORAGE.init(DeviceStorage::new(Cfg::open(RpFlashIo::new(flash)).expect("config open is infallible")));
    let loaded_config = storage.load_config();

    let state_init = SystemBStateInit::new(identity_data, loaded_config);

    // ========================================================================
    // KNX stack
    // ========================================================================

    let link_layer_builder = TpUartLinkLayerBuilder::new(uart_tx, uart_rx)
        .with_busy_flag(&BUSY_FLAG)
        .with_chip_busy_channel(CHIP_BUSY.dyn_receiver());

    // Allocate stack resources in a static (embassy tasks need 'static).
    static KNX_RESOURCES: StaticCell<
        StackResources<
            PicoTp1LightSwitch,
            {
                zweidraehte_device::config::buffer_size_for_apdu(
                    <PicoTp1LightSwitch as StackDefinition>::MAX_APDU_LENGTH,
                )
            },
        >,
    > = StaticCell::new();

    let (knx_stack, knx_runner) = zweidraehte_device::new(
        KNX_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        (), // no platform needed for TP1
        PicoTp1LightSwitch::memory_map(),
        storage,
    );

    spawner.spawn(knx_task(knx_runner)).expect("knx_task spawnable once");

    info!("KNX TP1 stack started");
    info!("  Manufacturer: {:04x}", LightSwitchDevice::MANUFACTURER_ID);
    info!(
        "  Application:  {:04x} v{:02x}",
        LightSwitchDevice::APPLICATION_ID_TP1,
        LightSwitchDevice::APPLICATION_VERSION
    );
    info!("  Mask version: 07B0 (System B TP1)");

    // ========================================================================
    // Application GPIO + tasks
    // ========================================================================

    // Push buttons — active low with internal pull-ups.
    let btn1_pin = Input::new(p.PIN_18, Pull::Up);
    let btn2_pin = Input::new(p.PIN_19, Pull::Up);
    let prog_btn_pin = Input::new(p.PIN_17, Pull::Up);

    spawner.spawn(app_task(knx_stack, btn1_pin, btn2_pin)).expect("app_task spawnable once");
    spawner.spawn(prog_task(knx_stack, prog_btn_pin)).expect("prog_task spawnable once");
    spawner.spawn(storage_task(knx_stack)).expect("storage_task spawnable once");
    spawner.spawn(lifecycle_task(knx_stack)).expect("lifecycle_task spawnable once");

    // ========================================================================
    // Main loop: heartbeat LED + programming mode LED (saves live in the
    // storage task)
    // ========================================================================

    // The programming LED is driven here (not in prog_task) so it also
    // tracks remote programming mode changes from ETS without
    // interfering with the button's edge detection.
    let mut prog_led = Output::new(p.PIN_16, Level::Low);
    let mut led = Output::new(p.PIN_25, Level::Low);

    // All persistence (on-demand saves, the periodic dirty poll, restart
    // handling) lives in the storage task. The NCN5120 busy mode is armed
    // via `BUSY_FLAG`/`CHIP_BUSY` (wired into the link layer builder above)
    // to keep the chip answering BUSY during each flash stall.

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
