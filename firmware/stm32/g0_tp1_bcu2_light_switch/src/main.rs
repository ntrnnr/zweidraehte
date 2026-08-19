//! BCU2 (mask 0020h) light switch on the STM32G0 — no executor, no
//! HAL, no async. One polled main loop drives everything, the way the
//! original 68HC05 BCU firmware did:
//!
//! ```text
//! loop {
//!     drain UART → TPUART driver → frames → stack.poll()
//!     stack timer tick → pending transmissions
//!     application: LightSwitchMicroApp — buttons, params, LED
//! }
//! ```
//!
//! The product is the shared 2-button light switch
//! (`devices::light_switch`): six group objects, the ETS-configurable
//! parameters (function per button, debounce and long-press times)
//! read straight out of the EEPROM image ETS writes them into, and
//! the behavior of `light_switch::micro` — the same semantics the
//! System B firmware runs, minus the executor. The mask-0020 product
//! database entry comes from `gen_light_switch_mtxml`, baked from the
//! same `micro::bcu2_definition()` this image boots.
//!
//! One physical button: PC11 drives button 1's configured function;
//! button 2's objects are live on the bus but have no key.
//!
//! Hardware (same board as `g0_tp1_light_switch`):
//!   PA9  = USART1_TX → TPUART RXD        PD2  = prog button (low-active)
//!   PA10 = USART1_RX ← TPUART TXD        PB8  = prog LED
//!   PC11 = user button (low-active)      PC12 = user LED
//!
//! The clock stays on the 16 MHz HSI reset default — a BCU2 needs no
//! more. SysTick supplies the millisecond counter the stack's timeouts
//! run on; the UART is polled (a byte lasts ~570 µs at 19200 baud and
//! the loop is far faster, with the G0's RX FIFO as slack on top).
//!
//! TODO: EEPROM persistence — the image currently lives in RAM only,
//! so a power cycle forgets its configuration. The flash sector
//! store used by the embassy targets wants a sync sibling first.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use cortex_m_rt::{entry, exception};
use defmt_rtt as _;
use devices::light_switch::LightSwitchDevice;
use devices::light_switch::micro::{self, LightSwitchMicroApp};
use panic_probe as _;
use stm32_metapac::{self as pac, GPIOA, GPIOB, GPIOC, GPIOD, RCC, USART1};
use zweidraehte_microdevice::device::{DeviceIdentity, Microdevice, PollInput};
use zweidraehte_microdevice::families::bcu2::Bcu2Family;
use zweidraehte_microdevice::link::tpuart::{TpUart, TpUartEvent};

// ============================================================================
// Milliseconds via SysTick
// ============================================================================

static MILLIS: AtomicU32 = AtomicU32::new(0);

#[exception]
fn SysTick() {
    // Single writer (this handler); plain load/store is race-free and
    // works on thumbv6m, which has no atomic read-modify-write.
    MILLIS.store(MILLIS.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);
}

fn now_ms() -> u32 {
    MILLIS.load(Ordering::Relaxed)
}

// ============================================================================
// Bare-metal peripherals
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
    // PA9/PA10 → USART1 (AF1).
    GPIOA.moder().modify(|w| {
        w.set_moder(9, Moder::ALTERNATE);
        w.set_moder(10, Moder::ALTERNATE);
    });
    GPIOA.afr(1).modify(|w| {
        w.set_afr(1, 1);
        w.set_afr(2, 1);
    });
    // LEDs out, buttons in with pull-ups.
    GPIOB.moder().modify(|w| w.set_moder(8, Moder::OUTPUT));
    GPIOC.moder().modify(|w| {
        w.set_moder(12, Moder::OUTPUT);
        w.set_moder(11, Moder::INPUT);
    });
    GPIOC.pupdr().modify(|w| w.set_pupdr(11, Pupdr::PULL_UP));
    GPIOD.moder().modify(|w| w.set_moder(2, Moder::INPUT));
    GPIOD.pupdr().modify(|w| w.set_pupdr(2, Pupdr::PULL_UP));

    // USART1: 19200 8E1 on the 16 MHz HSI. 8E1 on this IP is nine
    // frame bits (M0 set) with the ninth carried by the parity unit.
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
    // Swallow error flags so a line glitch cannot wedge reception.
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
    for &b in bytes {
        while !USART1.isr().read().txe() {}
        USART1.tdr().write(|w| w.set_dr(u16::from(b)));
    }
}

fn set_led(port: pac::gpio::Gpio, pin: usize, on: bool) {
    port.bsrr().write(|w| if on { w.set_bs(pin, true) } else { w.set_br(pin, true) });
}

fn button_pressed(port: pac::gpio::Gpio, pin: usize) -> bool {
    port.idr().read().idr(pin) == pac::gpio::vals::Idr::LOW
}

// ============================================================================
// Main loop
// ============================================================================

#[entry]
fn main() -> ! {
    let core = cortex_m::Peripherals::take().expect("first and only take");
    let mut syst = core.SYST;
    syst.set_clock_source(cortex_m::peripheral::syst::SystClkSource::Core);
    syst.set_reload(16_000 - 1); // 1 ms at 16 MHz
    syst.clear_current();
    syst.enable_interrupt();
    syst.enable_counter();

    init_hardware();

    let identity = DeviceIdentity {
        serial_number: [0x00, 0xFA, 0x00, 0x00, 0x03, 0x08],
        order_info: [0; 10],
        hardware_type: LightSwitchDevice::HARDWARE_TYPE_TP1_BCU2,
    };
    let mut stack: Microdevice<Bcu2Family> = Microdevice::new(micro::bcu2_definition().build_eeprom(), identity, 1);
    let mut app = LightSwitchMicroApp::new(micro::BCU2_PARAMS_IMAGE_OFFSET);

    // The TPUART acks frames for our IA and for group addresses the
    // table carries. The filter sees the raw header octets; the stack
    // still makes every real addressing decision itself.
    let mut tpuart = TpUart::new(|_header: &[u8]| true);
    // TODO: replace the ack-everything filter with an address check
    // once the driver is validated on the bench — over-acking is
    // harmless on a single-DUT test bus but wrong on a real line.

    defmt::info!("BCU2 micro stack up, IA {}", stack.individual_address().0);

    let mut prog_button_last = false;
    let mut last_tick = 0u32;

    loop {
        let now = now_ms();

        // ── Bus reception ───────────────────────────────────────────
        while let Some(byte) = uart_read() {
            match tpuart.push_byte(byte, now) {
                TpUartEvent::Frame(frame) => {
                    let out = stack.poll(PollInput::Frame(&frame), now);
                    for f in &out.frames {
                        if !tpuart.send_frame(f, now) {
                            defmt::warn!("TX queue full, frame dropped");
                        }
                        uart_write_blocking(tpuart.pending_tx());
                        tpuart.clear_tx();
                    }
                    if out.restart {
                        defmt::info!("A_Restart — resetting");
                        cortex_m::peripheral::SCB::sys_reset();
                    }
                }
                TpUartEvent::ResetIndication => defmt::info!("TPUART reset.ind"),
                TpUartEvent::TxConfirmed { positive } => {
                    if !positive {
                        defmt::warn!("negative L_Data.confirm");
                    }
                }
                TpUartEvent::None => {}
            }
            // Immediate-ack bytes the driver queued mid-frame.
            if !tpuart.pending_tx().is_empty() {
                uart_write_blocking(tpuart.pending_tx());
                tpuart.clear_tx();
            }
        }

        // ── Timers, once per millisecond ────────────────────────────
        if now != last_tick {
            last_tick = now;
            if let TpUartEvent::TxConfirmed { positive: false } = tpuart.poll_timer(now) {
                defmt::warn!("transmission timed out");
            }
            let out = stack.poll(PollInput::Timer, now);
            for f in &out.frames {
                if tpuart.send_frame(f, now) {
                    uart_write_blocking(tpuart.pending_tx());
                    tpuart.clear_tx();
                }
            }
        }

        // ── Application: the shared light-switch behavior ───────────
        // PC11 is button 1; the board has no second button. The user
        // LED mirrors button 1's status object — the actuator feedback
        // in Switch/Dimmer configurations.
        app.poll(&mut stack, button_pressed(GPIOC, 11), false, now);
        if let Some(on) = app.take_btn1_status_update(&mut stack) {
            set_led(GPIOC, 12, on);
        }

        let prog_button = button_pressed(GPIOD, 2);
        if prog_button && !prog_button_last {
            let enabled = !stack.is_programming_mode();
            stack.set_programming_mode(enabled);
        }
        prog_button_last = prog_button;
        set_led(GPIOB, 8, stack.is_programming_mode());
    }
}
