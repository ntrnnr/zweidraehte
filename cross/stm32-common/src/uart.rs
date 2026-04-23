//! Direct-register UART driver for latency-critical TPUART communication.
//!
//! The STM32 USART peripheral on the `usart_v4` block (used by G0/G4/U5/H7)
//! has an optional byte FIFO. We keep it disabled so each received byte
//! raises an interrupt immediately — exactly like `rp-common::uart`.
//!
//! This driver:
//! - Configures the hardware by consuming an `embassy_stm32::usart::Uart`
//!   in blocking mode (baud, parity, pin muxing all done by embassy).
//! - Disables the FIFO (it is already off by default on G0).
//! - The ISR reads bytes from `RDR` into an embassy `RingBuffer` and wakes
//!   the async task, so upper-layer processing latency cannot cause
//!   HW overruns.
//! - TX writes `TDR` directly from task context; `TXFNFIE` is only enabled
//!   when the FIFO/holding register is full, then cleared in the ISR
//!   before waking the task.
//!
//! # Usage
//!
//! ```ignore
//! use embassy_stm32::{bind_interrupts, peripherals::USART1};
//! use embassy_stm32::usart::{Uart, Config as UartConfig, Parity};
//! use stm32_common::uart::{DirectInterruptHandler, DirectUart};
//!
//! bind_interrupts!(struct Irqs {
//!     USART1 => DirectInterruptHandler<USART1>;
//! });
//!
//! let mut cfg = UartConfig::default();
//! cfg.baudrate = 19200;
//! cfg.parity = Parity::ParityEven;
//! let uart = Uart::new_blocking(p.USART1, p.PA10, p.PA9, cfg).unwrap();
//! let (tx, rx) = DirectUart::new::<USART1>(uart, Irqs);
//! ```

use core::cell::UnsafeCell;
use core::future::poll_fn;
use core::sync::atomic::Ordering;
use core::task::Poll;

use defmt::warn;
use embassy_hal_internal::atomic_ring_buffer::RingBuffer;
use embassy_stm32::interrupt::typelevel::{Binding, Interrupt as _};
use embassy_stm32::mode::Blocking;
use embassy_stm32::pac::usart::Usart as RegBlock;
use embassy_stm32::usart::{Instance, Uart};
use embassy_sync::waitqueue::AtomicWaker;

// ================================================================================
// UART Receive Errors
// ================================================================================

/// UART receive error detected by the USART hardware.
///
/// The USART_v4 ISR register reports framing, parity, overrun, and noise
/// errors. A byte tagged with any of these is corrupted and is not
/// delivered to the reader — the ISR drops it and signals the error via an
/// atomic flag that [`DirectUartRx::read()`] checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum UartError {
    /// Framing error: stop bit was invalid.
    Framing,
    /// Parity error: parity mismatch.
    Parity,
    /// Noise detected: glitches on the line during sampling.
    Noise,
    /// Overrun: data was lost (ring buffer full or RDR overwritten
    /// before the ISR read it).
    Overrun,
}

impl embedded_io_async::Error for UartError {
    fn kind(&self) -> embedded_io_async::ErrorKind {
        embedded_io_async::ErrorKind::Other
    }
}

const RX_ERR_NONE: u8 = 0;
const RX_ERR_FRAMING: u8 = 1;
const RX_ERR_PARITY: u8 = 2;
const RX_ERR_NOISE: u8 = 3;
const RX_ERR_OVERRUN: u8 = 4;

// ================================================================================
// ISR Ring Buffer
// ================================================================================

// Sized to cover one maximum-length KNX frame worth of bytes without task
// intervention (plus a bit of slack). 16 is the same budget `rp-common`
// uses and has been proven in practice on the NCN5120.
const RX_BUF_SIZE: usize = 16;

/// Per-instance state shared between the ISR and the async RX/TX tasks.
///
/// Each USART instance gets its own `State` via a function-local static
/// in its [`DirectUartInstance::state()`] impl — no module-level globals.
struct State {
    rx_waker: AtomicWaker,
    tx_waker: AtomicWaker,
    rx_ring: RingBuffer,
    rx_overrun: portable_atomic::AtomicU32,
    rx_error: portable_atomic::AtomicU8,
    rx_buf: UnsafeCell<[u8; RX_BUF_SIZE]>,
}

// Safety: rx_buf is only accessed through RingBuffer's atomic
// reader/writer protocol. All other fields are Sync (atomics / wakers).
unsafe impl Sync for State {}

impl State {
    const fn new() -> Self {
        Self {
            rx_waker: AtomicWaker::new(),
            tx_waker: AtomicWaker::new(),
            rx_ring: RingBuffer::new(),
            rx_overrun: portable_atomic::AtomicU32::new(0),
            rx_error: portable_atomic::AtomicU8::new(RX_ERR_NONE),
            rx_buf: UnsafeCell::new([0; RX_BUF_SIZE]),
        }
    }
}

// ================================================================================
// Instance → PAC Register Block Mapping
// ================================================================================

mod sealed {
    /// Seals [`DirectUartInstance`](super::DirectUartInstance) so it
    /// cannot be implemented outside this crate.
    pub trait Sealed {}
    impl Sealed for embassy_stm32::peripherals::USART1 {}
    impl Sealed for embassy_stm32::peripherals::USART2 {}
    impl Sealed for embassy_stm32::peripherals::USART3 {}
}

/// Maps an embassy-stm32 USART [`Instance`] to its PAC register block and
/// per-instance state. Sealed — cannot be implemented outside this crate.
///
/// On STM32G0 value-line parts, `USART3`/`USART4`/`USART5`/`USART6` share a
/// single NVIC vector (`USART3_4_5_6`). The ISR dispatch below scans
/// every registered instance's ISR bits on that vector and only acts on
/// the one(s) with pending flags, so a single `DirectUart` on USART3
/// coexists with any number of plain `embassy-stm32` USARTs on that
/// shared vector. What it does **not** support is two separate
/// `DirectUart` instances on the same shared vector — only one member
/// of the group can use this driver at a time.
#[allow(private_interfaces)]
pub trait DirectUartInstance: Instance + sealed::Sealed {
    fn regs() -> RegBlock;

    #[doc(hidden)]
    fn state() -> &'static State;
}

#[allow(private_interfaces)]
impl DirectUartInstance for embassy_stm32::peripherals::USART1 {
    fn regs() -> RegBlock {
        embassy_stm32::pac::USART1
    }
    fn state() -> &'static State {
        static STATE: State = State::new();
        &STATE
    }
}

#[allow(private_interfaces)]
impl DirectUartInstance for embassy_stm32::peripherals::USART2 {
    fn regs() -> RegBlock {
        embassy_stm32::pac::USART2
    }
    fn state() -> &'static State {
        static STATE: State = State::new();
        &STATE
    }
}

#[allow(private_interfaces)]
impl DirectUartInstance for embassy_stm32::peripherals::USART3 {
    fn regs() -> RegBlock {
        embassy_stm32::pac::USART3
    }
    fn state() -> &'static State {
        static STATE: State = State::new();
        &STATE
    }
}

// ================================================================================
// Interrupt Handler
// ================================================================================

/// Interrupt handler for [`DirectUart`].
///
/// On RX: reads bytes from RDR into the ring buffer (dropping bytes with
/// FE/PE/NE/ORE errors and recording the error flag) and wakes the task.
/// On TX: masks TXFNFIE and wakes the task to continue pushing bytes.
pub struct DirectInterruptHandler<T: DirectUartInstance> {
    _uart: core::marker::PhantomData<T>,
}

impl<T: DirectUartInstance> embassy_stm32::interrupt::typelevel::Handler<T::Interrupt> for DirectInterruptHandler<T> {
    unsafe fn on_interrupt() {
        let r = T::regs();
        let state = T::state();
        let isr = r.isr().read();

        // --- Error handling --------------------------------------------------
        //
        // Error bits (PE/FE/NE/ORE) in ISR mark the *next byte* reported in
        // RDR as invalid. They are cleared by writing the corresponding
        // PECF/FECF/NECF/ORECF bits to ICR. We drop the offending byte by
        // reading RDR (so RXNE clears) and record the error for the reader.
        let mut had_error = false;
        if isr.ore() {
            state.rx_overrun.fetch_add(1, Ordering::Relaxed);
            state.rx_error.store(RX_ERR_OVERRUN, Ordering::Release);
            r.icr().write(|w| w.set_ore(true));
            had_error = true;
        }
        if isr.fe() {
            state.rx_error.store(RX_ERR_FRAMING, Ordering::Release);
            r.icr().write(|w| w.set_fe(true));
            had_error = true;
        }
        if isr.pe() {
            state.rx_error.store(RX_ERR_PARITY, Ordering::Release);
            r.icr().write(|w| w.set_pe(true));
            had_error = true;
        }
        if isr.ne() {
            state.rx_error.store(RX_ERR_NOISE, Ordering::Release);
            r.icr().write(|w| w.set_ne(true));
            had_error = true;
        }

        // --- RX: drain received bytes ----------------------------------------
        //
        // RXFNE is the same bit as RXNE in non-FIFO mode (stm32-metapac
        // renames it on the `usart_v4` block). We loop defensively in case
        // multiple interrupts coalesced, though with FIFO off only one byte
        // is normally pending.
        if isr.rxne() || had_error {
            unsafe {
                let mut writer = state.rx_ring.writer();
                while r.isr().read().rxne() {
                    // Reading RDR clears RXNE. The byte is u16 (to
                    // accommodate 9-bit frames); we only use the low 8.
                    let byte = r.rdr().read().0 as u8;
                    if had_error {
                        // First byte after the error: the one that was
                        // flagged. Drop it. Clear the flag so subsequent
                        // bytes this IRQ are accepted.
                        had_error = false;
                        continue;
                    }
                    if !writer.push_one(byte) {
                        state.rx_overrun.fetch_add(1, Ordering::Relaxed);
                        state.rx_error.store(RX_ERR_OVERRUN, Ordering::Release);
                    }
                }
            }
            state.rx_waker.wake();
        }

        // --- TX: space available --------------------------------------------
        //
        // TXFNF = transmit FIFO/holding register has space. With FIFO
        // disabled, this is the classical TXE flag. Mask the interrupt so
        // it does not re-fire before the task has fed more data.
        if isr.txe() {
            // Clear TXFNFIE (bit 7 of CR1). The bit is RW, there is no
            // dedicated clear register — do a small RMW inside a critical
            // section. The M0+ NVIC is single-priority so PRIMASK alone
            // protects us from the ISR re-entering via CS nesting.
            critical_section::with(|_| {
                r.cr1().modify(|w| w.set_txeie(false));
            });
            state.tx_waker.wake();
        }
    }
}

// ================================================================================
// DirectUart — Construction
// ================================================================================

/// Direct-register USART driver, split into independent TX and RX halves.
pub struct DirectUart;

impl DirectUart {
    /// Configure a USART for direct-register async I/O.
    ///
    /// The embassy `Uart<Blocking>` is consumed after configuring the
    /// hardware. Its drop is a no-op in blocking mode (no DMA channels).
    ///
    /// After this call:
    /// - The FIFO is explicitly disabled (FIFOEN = 0) so each byte raises
    ///   an interrupt.
    /// - RXNE interrupts are enabled; error interrupts (PE, plus ORE/FE/NE
    ///   via EIE) are enabled so the ISR can drop corrupted bytes.
    /// - TXE interrupts are enabled only when the sender has more bytes
    ///   to push than TDR can currently hold.
    pub fn new<T: DirectUartInstance>(
        uart: Uart<'_, Blocking>,
        _irq: impl Binding<T::Interrupt, DirectInterruptHandler<T>>,
    ) -> (DirectUartTx, DirectUartRx) {
        // CRITICAL: must NOT drop the embassy `Uart`. Its `Drop` impl
        // restores every USART pin to disconnected (wiping the AF mux)
        // and, on the last-ref drop, gates the peripheral clock. Both
        // leave us with a silent peripheral. Forget it so the pins stay
        // muxed and RCC keeps ticking.
        core::mem::forget(uart);

        let r = T::regs();
        let state = T::state();

        unsafe {
            state.rx_ring.init(state.rx_buf.get() as *mut u8, RX_BUF_SIZE);
        }

        // embassy's `Uart::new_blocking` has already set CR1.{UE,RE,TE}
        // and configured CR2/CR3/BRR for the requested baud and parity.
        // We just layer our interrupt-enable preferences on top.
        r.cr1().modify(|w| {
            // Disable FIFO so each byte triggers RXNE. On STM32G0/G4/U5
            // with usart_v4, FIFOEN defaults to 0 — this is a belt-and-
            // braces guard for any caller that pre-enables it.
            w.set_fifoen(false);
            // Enable receive interrupt (RXNE shared bit with RXFNE).
            w.set_rxneie(true);
            // Parity-error interrupt — fired alongside RXNE for the bad
            // byte, but we check PE in the ISR regardless. Enabling this
            // ensures we notice parity errors even on implementations
            // that do not also raise RXNE for the dropped byte.
            w.set_peie(true);
        });
        // CR3.EIE enables the error interrupt for ORE/FE/NE when DMA is
        // on; with DMA off the errors set bits in ISR alongside RXNE, so
        // EIE is not strictly required — but enabling it is harmless.
        r.cr3().modify(|w| w.set_eie(true));

        // Clear any stale error flags before we start taking interrupts.
        r.icr().write(|w| {
            w.set_ore(true);
            w.set_fe(true);
            w.set_pe(true);
            w.set_ne(true);
        });

        T::Interrupt::unpend();
        unsafe { T::Interrupt::enable() };

        (DirectUartTx { regs: r, state }, DirectUartRx { state })
    }
}

// ================================================================================
// DirectUartTx
// ================================================================================

/// Async USART transmitter using direct register access.
pub struct DirectUartTx {
    regs: RegBlock,
    state: &'static State,
}

// Safety: RegBlock is a thin pointer wrapper; only one DirectUartTx can
// exist per instance (enforced by consuming the embassy Uart singleton).
unsafe impl Send for DirectUartTx {}

impl embedded_io_async::ErrorType for DirectUartTx {
    type Error = core::convert::Infallible;
}

impl embedded_io_async::Write for DirectUartTx {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        poll_fn(|cx| {
            let r = self.regs;

            // Push as many bytes as TDR will currently accept. On the
            // non-FIFO v4 USART, that is one byte when TXE=1. With FIFO
            // disabled, TXFNF and TXE share a bit.
            let mut n = 0;
            for &byte in buf {
                if !r.isr().read().txe() {
                    break;
                }
                r.tdr().write(|w| w.set_dr(byte as u16));
                n += 1;
            }

            if n > 0 {
                Poll::Ready(Ok(n))
            } else {
                self.state.tx_waker.register(cx.waker());
                critical_section::with(|_| {
                    r.cr1().modify(|w| w.set_txeie(true));
                });
                Poll::Pending
            }
        })
        .await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        // TC (transmission complete) asserts when the shift register has
        // fully emptied — exactly the correct semantics for `flush`.
        poll_fn(|cx| {
            if self.regs.isr().read().tc() {
                Poll::Ready(Ok(()))
            } else {
                self.state.tx_waker.register(cx.waker());
                critical_section::with(|_| {
                    self.regs.cr1().modify(|w| w.set_tcie(true));
                });
                Poll::Pending
            }
        })
        .await
    }
}

// ================================================================================
// DirectUartRx
// ================================================================================

/// Async USART receiver backed by an ISR-filled ring buffer.
///
/// The ISR reads each byte from `RDR` into a [`RingBuffer`] (from
/// `embassy-hal-internal`). The task drains the ring buffer via `read()`.
/// This decouples the USART's byte-arrival timing (~573 µs at 19200 8E1)
/// from task-level processing latency.
pub struct DirectUartRx {
    state: &'static State,
}

unsafe impl Send for DirectUartRx {}

impl embedded_io_async::ErrorType for DirectUartRx {
    type Error = UartError;
}

impl embedded_io_async::Read for DirectUartRx {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        poll_fn(|cx| {
            let state = self.state;

            // Drain available bytes from the ISR ring buffer first. If
            // bytes are waiting, deliver them even if an error flag is
            // set — the error byte was already dropped by the ISR, so
            // the buffered bytes precede it chronologically.
            let mut reader = unsafe { state.rx_ring.reader() };
            let n = reader.pop(|ring_buf| {
                let n = ring_buf.len().min(buf.len());
                buf[..n].copy_from_slice(&ring_buf[..n]);
                n
            });
            if n > 0 {
                return Poll::Ready(Ok(n));
            }

            let err = state.rx_error.swap(RX_ERR_NONE, Ordering::Acquire);
            if err != RX_ERR_NONE {
                let overruns = state.rx_overrun.swap(0, Ordering::Relaxed);
                if overruns > 0 {
                    warn!("UART RX: {} byte(s) lost to overrun", overruns);
                }
                let error = match err {
                    RX_ERR_FRAMING => UartError::Framing,
                    RX_ERR_PARITY => UartError::Parity,
                    RX_ERR_NOISE => UartError::Noise,
                    _ => UartError::Overrun,
                };
                return Poll::Ready(Err(error));
            }

            state.rx_waker.register(cx.waker());
            if !state.rx_ring.is_empty() {
                cx.waker().wake_by_ref();
            }
            if state.rx_error.load(Ordering::Acquire) != RX_ERR_NONE {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await
    }
}
