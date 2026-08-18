//! BCU2 (mask 0020h) light switch on the STM32G0 — no executor, no
//! HAL, no async. One polled main loop drives everything, the way the
//! original 68HC05 BCU firmware did:
//!
//! ```text
//! loop {
//!     drain UART → TPUART driver → frames → stack.poll()
//!     stack timer tick → pending transmissions
//!     application: check group-object flags, drive the LED
//! }
//! ```
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
use panic_probe as _;
use stm32_metapac::{self as pac, GPIOA, GPIOB, GPIOC, GPIOD, RCC, USART1};
use zweidraehte_microdevice::co_flags;
use zweidraehte_microdevice::device::{DeviceIdentity, Microdevice, PollInput};
use zweidraehte_microdevice::device_def::{Bcu2CoDescriptor, Bcu2DeviceDefinition};
use zweidraehte_microdevice::family::Bcu2Family;
use zweidraehte_microdevice::link::tpuart::{TpUart, TpUartEvent};
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

// ============================================================================
// The product
// ============================================================================

/// ASAP 0: the switch input — the bus writes it, the LED follows.
const SWITCH_ASAP: u8 = 0;
/// ASAP 1: the status output — the button toggles it and transmits.
const STATUS_ASAP: u8 = 1;

static COM_OBJECTS: &[Bcu2CoDescriptor] = &[
    // 1-bit, communication + write + update, low priority.
    Bcu2CoDescriptor { data_ptr: 0xC6, config: 0x9F, value_type: 0x00 },
    // 1-bit, communication + transmit + read, low priority.
    Bcu2CoDescriptor { data_ptr: 0xC7, config: 0x4F, value_type: 0x00 },
];

fn definition() -> Bcu2DeviceDefinition {
    Bcu2DeviceDefinition {
        manufacturer_id: 0x00FA,
        app_manufacturer_id: 0x00FA,
        device_type: 0x0B21,
        version: 1,
        pei_type: 0,
        // Factory address until ETS commissions one over the bus.
        individual_address: IndividualAddress::new(15, 15, 255),
        max_group_addresses: 8,
        max_associations: 8,
        ram_flags_ptr: 0xD0,
        comm_objects: COM_OBJECTS,
        group_addresses: &[] as &[GroupAddress],
        associations: &[],
    }
}

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

    let identity = DeviceIdentity { serial_number: [0x00, 0xFA, 0x00, 0x00, 0x0B, 0x21], order_info: [0; 10] };
    let mut stack: Microdevice<Bcu2Family> = Microdevice::new(definition().build_eeprom(), identity, 1);

    // The TPUART acks frames for our IA and for group addresses the
    // table carries. The filter sees the raw header octets; the stack
    // still makes every real addressing decision itself.
    let mut tpuart = TpUart::new(|_header: &[u8]| true);
    // TODO: replace the ack-everything filter with an address check
    // once the driver is validated on the bench — over-acking is
    // harmless on a single-DUT test bus but wrong on a real line.

    defmt::info!("BCU2 micro stack up, IA {}", stack.individual_address().0);

    let mut prog_button_last = false;
    let mut user_button_last = false;
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

        // ── Application: the classic flag loop ──────────────────────
        if stack.object_flags(SWITCH_ASAP) & co_flags::UPDATE != 0 {
            stack.clear_update_flag(SWITCH_ASAP);
            let mut value = [0u8; 1];
            stack.read_value(SWITCH_ASAP, &mut value);
            set_led(GPIOC, 12, value[0] & 1 != 0);
        }

        let user_button = button_pressed(GPIOC, 11);
        if user_button && !user_button_last {
            let mut value = [0u8; 1];
            stack.read_value(STATUS_ASAP, &mut value);
            stack.write_value(STATUS_ASAP, &[value[0] ^ 1]);
            stack.set_transmit_request(STATUS_ASAP);
        }
        user_button_last = user_button;

        let prog_button = button_pressed(GPIOD, 2);
        if prog_button && !prog_button_last {
            let enabled = !stack.is_programming_mode();
            stack.set_programming_mode(enabled);
        }
        prog_button_last = prog_button;
        set_led(GPIOB, 8, stack.is_programming_mode());
    }
}
