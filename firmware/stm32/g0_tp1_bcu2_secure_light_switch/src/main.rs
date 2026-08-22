//! Data Secure BCU2 (mask 0021h) light switch on the polling micro stack.
//!
//! There is no executor and no async HAL: one main loop polls USART1, the
//! TPUART state machine, stack timers, and the shared light-switch application.
//! The security-specific resources are deliberately separate by write rate:
//!
//! - the final internal-flash page contains the per-device `KNXP` serial/FDSK;
//! - the preceding page stores EEPROM, management and Security IO config only
//!   when a restart is requested;
//! - an external FM25L16B on SPI2 stores every sequence-counter advance and
//!   the SIAT without flash wear.
//!
//! Hardware:
//!   PA9  USART1_TX → TPUART RXD       PA10 USART1_RX ← TPUART TXD
//!   PB13 SPI2_SCK → FRAM SCK          PB14 SPI2_MISO ← FRAM SO
//!   PB15 SPI2_MOSI → FRAM SI          PB12 GPIO → FRAM ~CS
//!   PB9  GPIO → FRAM ~WP (high)       PA0  floating ADC entropy input
//!   PD2  programming button           PB8  programming LED
//!   PC11 user button 1                PC12 user LED

#![no_std]
#![no_main]

mod config;
mod entropy;
mod fram_store;

use core::sync::atomic::{AtomicU32, Ordering};

use cortex_m_rt::{entry, exception};
use defmt_rtt as _;
use devices::light_switch::LightSwitchDevice;
use devices::light_switch::micro::{self, LightSwitchMicroApp};
use heapless::{Deque, Vec};
use panic_probe as _;
use stm32_metapac::{self as pac, GPIOA, GPIOB, GPIOC, GPIOD, RCC, USART1};
use zweidraehte_microdevice::SecureBcu2;
use zweidraehte_microdevice::device::{DeviceIdentity, PollInput, PollOutput};
use zweidraehte_microdevice::frame::SECURE_EXTENDED_FRAME;
use zweidraehte_microdevice::link::tpuart::{TpUart, TpUartEvent};

use fram_store::FramStore;

pub const GROUP_KEY_CAPACITY: usize = micro::BCU2_SECURE_GROUP_KEY_CAPACITY;
pub const GROUP_OBJECT_CAPACITY: usize = micro::BCU2_SECURE_GROUP_OBJECT_CAPACITY;
pub const SIAT_CAPACITY: usize = micro::BCU2_SECURE_SIAT_CAPACITY;

pub type Device = SecureBcu2<FramStore, GROUP_KEY_CAPACITY, GROUP_OBJECT_CAPACITY>;

const FRAME_CAPACITY: usize = SECURE_EXTENDED_FRAME;
const WIRE_CAPACITY: usize = FRAME_CAPACITY + 1;
const TX_CAPACITY: usize = WIRE_CAPACITY * 2;
type PendingFrames = Deque<Vec<u8, FRAME_CAPACITY>, 8>;

// ============================================================================
// Milliseconds via SysTick
// ============================================================================

static MILLIS: AtomicU32 = AtomicU32::new(0);

#[exception]
fn SysTick() {
    MILLIS.store(MILLIS.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);
}

fn now_ms() -> u32 {
    MILLIS.load(Ordering::Relaxed)
}

// ============================================================================
// Bare-metal TPUART and board GPIO
// ============================================================================

fn init_hardware() {
    RCC.gpioenr().modify(|w| {
        w.set_gpioaen(true);
        w.set_gpioben(true);
        w.set_gpiocen(true);
        w.set_gpioden(true);
    });
    RCC.apbenr2().modify(|w| w.set_usart1en(true));

    use pac::gpio::vals::{Moder, Pupdr};
    GPIOA.moder().modify(|w| {
        w.set_moder(9, Moder::ALTERNATE);
        w.set_moder(10, Moder::ALTERNATE);
    });
    GPIOA.afr(1).modify(|w| {
        w.set_afr(1, 1);
        w.set_afr(2, 1);
    });
    GPIOB.moder().modify(|w| w.set_moder(8, Moder::OUTPUT));
    GPIOC.moder().modify(|w| {
        w.set_moder(12, Moder::OUTPUT);
        w.set_moder(11, Moder::INPUT);
    });
    GPIOC.pupdr().modify(|w| w.set_pupdr(11, Pupdr::PULL_UP));
    GPIOD.moder().modify(|w| w.set_moder(2, Moder::INPUT));
    GPIOD.pupdr().modify(|w| w.set_pupdr(2, Pupdr::PULL_UP));

    USART1.brr().write(|w| w.set_brr((16_000_000u32 / 19_200) as u16));
    USART1.cr1().write(|w| {
        w.set_m0(pac::usart::vals::M0::BIT9);
        w.set_pce(true);
        w.set_ps(pac::usart::vals::Ps::EVEN);
        w.set_fifoen(true);
        w.set_te(true);
        w.set_re(true);
        w.set_ue(true);
    });
}

fn uart_read() -> Option<u8> {
    let isr = USART1.isr().read();
    if isr.pe() || isr.fe() || isr.ne() || isr.ore() {
        USART1.icr().write(|w| {
            w.set_pe(true);
            w.set_fe(true);
            w.set_ne(true);
            w.set_ore(true);
        });
    }
    isr.rxne().then(|| USART1.rdr().read().dr() as u8)
}

fn uart_write_blocking(bytes: &[u8]) {
    for &byte in bytes {
        while !USART1.isr().read().txe() {}
        USART1.tdr().write(|w| w.set_dr(u16::from(byte)));
    }
    // `TXE` only means the final byte reached the shift register. Persistence
    // and reset may follow immediately, so wait until it is physically out.
    while !USART1.isr().read().tc() {}
}

fn set_led(port: pac::gpio::Gpio, pin: usize, on: bool) {
    port.bsrr().write(|w| if on { w.set_bs(pin, true) } else { w.set_br(pin, true) });
}

fn button_pressed(port: pac::gpio::Gpio, pin: usize) -> bool {
    port.idr().read().idr(pin) == pac::gpio::vals::Idr::LOW
}

fn queue_output(output: PollOutput<FRAME_CAPACITY>, pending: &mut PendingFrames, restart: &mut bool) {
    for frame in output.frames {
        if pending.push_back(frame).is_err() {
            defmt::warn!("stack output queue full, frame dropped");
        }
    }
    *restart |= output.restart.is_some();
}

fn flush_tpuart<A: Fn(&[u8]) -> bool>(
    tpuart: &mut TpUart<A, WIRE_CAPACITY, TX_CAPACITY>,
    pending: &mut PendingFrames,
    now: u32,
) {
    // Reset requests and immediate ACK bytes can be queued independently of
    // an L_Data transmission; always drain those first.
    if !tpuart.pending_tx().is_empty() {
        uart_write_blocking(tpuart.pending_tx());
        tpuart.clear_tx();
    }
    if tpuart.ready_to_send()
        && let Some(frame) = pending.pop_front()
    {
        if tpuart.send_frame(&frame, now) {
            uart_write_blocking(tpuart.pending_tx());
            tpuart.clear_tx();
        } else {
            defmt::warn!("TPUART refused queued frame");
        }
    }
}

// ============================================================================
// Main loop
// ============================================================================

#[entry]
fn main() -> ! {
    let core = cortex_m::Peripherals::take().expect("first and only take");
    let mut syst = core.SYST;
    syst.set_clock_source(cortex_m::peripheral::syst::SystClkSource::Core);
    syst.set_reload(16_000 - 1);
    syst.clear_current();
    syst.enable_interrupt();
    syst.enable_counter();

    init_hardware();

    let provisioned = config::load_identity().expect("valid KNXP serial and FDSK");
    let rng = entropy::seed_csprng();
    let sequence = FramStore::open(rng).expect("FM25L16B sequence store");
    let restored = config::load(micro::secure_bcu2_definition().build_eeprom_for_mask(0x0021), provisioned.fdsk);
    let identity = DeviceIdentity {
        serial_number: provisioned.serial_number,
        order_info: [0; 10],
        hardware_type: LightSwitchDevice::HARDWARE_TYPE_TP1_BCU2_SECURE,
    };
    let mut stack = restored.into_device(identity, provisioned.fdsk, sequence);
    let mut app = LightSwitchMicroApp::new(micro::BCU2_PARAMS_IMAGE_OFFSET);

    let mut tpuart: TpUart<_, WIRE_CAPACITY, TX_CAPACITY> = TpUart::new_sized(|_header: &[u8]| true);
    // TODO: replace the ack-everything filter with IA/address-table matching
    // once the driver is validated on a multi-device bench.
    let mut pending = PendingFrames::new();
    let mut restart_pending = false;
    let mut prog_button_last = false;
    let mut last_tick = 0u32;

    defmt::info!("secure BCU2 micro stack up, IA {}", stack.individual_address().0);

    loop {
        let now = now_ms();

        while let Some(byte) = uart_read() {
            match tpuart.push_byte(byte, now) {
                TpUartEvent::Frame(frame) if !restart_pending => {
                    let output = stack.poll(PollInput::Frame(&frame), now);
                    queue_output(output, &mut pending, &mut restart_pending);
                }
                TpUartEvent::Frame(_) => {}
                TpUartEvent::ResetIndication => defmt::info!("TPUART reset.ind"),
                TpUartEvent::TxConfirmed { positive } => {
                    if !positive {
                        defmt::warn!("negative L_Data.confirm");
                    }
                }
                TpUartEvent::None => {}
            }
            flush_tpuart(&mut tpuart, &mut pending, now);
        }

        if now != last_tick {
            last_tick = now;
            if let TpUartEvent::TxConfirmed { positive: false } = tpuart.poll_timer(now) {
                defmt::warn!("transmission timed out");
            }
            if !restart_pending {
                let output = stack.poll(PollInput::Timer, now);
                queue_output(output, &mut pending, &mut restart_pending);
            }
        }

        if !restart_pending {
            app.poll(&mut stack, button_pressed(GPIOC, 11), false, now);
            if let Some(on) = app.take_btn1_status_update(&mut stack) {
                set_led(GPIOC, 12, on);
            }

            let prog_button = button_pressed(GPIOD, 2);
            if prog_button && !prog_button_last {
                stack.set_programming_mode(!stack.is_programming_mode());
            }
            prog_button_last = prog_button;
            set_led(GPIOB, 8, stack.is_programming_mode());
        }

        flush_tpuart(&mut tpuart, &mut pending, now);
        if restart_pending && pending.is_empty() && tpuart.ready_to_send() {
            config::save(&stack).expect("persist secure BCU2 config");
            cortex_m::peripheral::SCB::sys_reset();
        }
    }
}
