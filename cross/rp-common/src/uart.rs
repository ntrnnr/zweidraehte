//! Direct-register UART driver for latency-critical TPUART communication.
//!
//! Embassy's `BufferedUart` adds significant latency through its ISR → ring
//! buffer → task wake pipeline. For TPUART ACK timing (must respond within
//! ~1.7ms of receiving the 6th header byte), we need to read bytes directly
//! from the hardware data register.
//!
//! This driver:
//! - Disables the UART FIFO so each received byte triggers an interrupt
//! - The ISR reads bytes from DR into an embassy `RingBuffer`
//!   and wakes the async task — this decouples HW timing from task latency
//! - The task drains the ring buffer, never missing bytes even if upper
//!   layer processing (NL/TL/AL in the same `join4` task) takes >573µs
//! - TX writes the data register directly from task context
//! - Implements `embedded_io_async::Read` / `Write` for compatibility with
//!   the TPUART link layer's generic trait bounds
//!
//! # Usage
//!
//! ```ignore
//! use embassy_rp::uart::{Uart, Config as UartConfig, Parity};
//! use embassy_rp::bind_interrupts;
//! use rp_common::uart::{DirectUart, DirectInterruptHandler};
//!
//! bind_interrupts!(struct Irqs {
//!     UART0_IRQ => DirectInterruptHandler<UART0>;
//! });
//!
//! let uart = Uart::new_blocking(p.UART0, p.PIN_0, p.PIN_1, config);
//! let (tx, rx) = DirectUart::new::<UART0>(uart, Irqs);
//! ```

use core::cell::UnsafeCell;
use core::future::poll_fn;
use core::sync::atomic::Ordering;
use core::task::Poll;

use defmt::warn;
use embassy_hal_internal::atomic_ring_buffer::RingBuffer;
use embassy_rp::interrupt::typelevel::{Binding, Interrupt as _};
use embassy_rp::pac::uart::Uart as RegBlock;
use embassy_rp::uart::{Blocking, Instance, Uart};
use embassy_sync::waitqueue::AtomicWaker;

// ================================================================================
// RP2040 Atomic Register Aliases
// ================================================================================

// The RP2040 provides hardware-atomic SET/CLEAR aliases for peripheral
// registers at fixed offsets from the base address:
//   base + 0x2000 → writing atomically ORs (sets bits)
//   base + 0x3000 → writing atomically ANDs complement (clears bits)
// This avoids read-modify-write races, especially between ISR and task.

/// Atomically set bits in a register using the RP2040 SET alias.
///
/// # Safety
/// The register must belong to a peripheral that supports atomic aliases
/// (all RP2040 peripherals in the 0x4000_0000 range do).
#[inline(always)]
unsafe fn reg_set<T: Default + Copy>(
    reg: &embassy_rp::pac::common::Reg<T, embassy_rp::pac::common::RW>,
    f: impl FnOnce(&mut T),
) {
    let mut val = T::default();
    f(&mut val);
    unsafe {
        let ptr = (reg.as_ptr() as *mut u8).add(0x2000) as *mut T;
        ptr.write_volatile(val);
    }
}

/// Atomically clear bits in a register using the RP2040 CLEAR alias.
///
/// # Safety
/// The register must belong to a peripheral that supports atomic aliases.
#[inline(always)]
unsafe fn reg_clear<T: Default + Copy>(
    reg: &embassy_rp::pac::common::Reg<T, embassy_rp::pac::common::RW>,
    f: impl FnOnce(&mut T),
) {
    let mut val = T::default();
    f(&mut val);
    unsafe {
        let ptr = (reg.as_ptr() as *mut u8).add(0x3000) as *mut T;
        ptr.write_volatile(val);
    }
}

// ================================================================================
// ISR Ring Buffer
// ================================================================================

// Uses embassy's lock-free `RingBuffer` from `embassy-hal-internal` for
// ISR-to-task byte transfer. The ISR is the sole writer (pushes bytes from
// the UART data register), the task is the sole reader. The `RingBuffer`
// uses `AtomicUsize` indices with acquire/release ordering — no locks,
// no critical sections, safe across ISR/task boundaries.
//
// We add an `AtomicWaker` for async notification and an overrun counter.

const RX_BUF_SIZE: usize = 16;

/// Per-instance state shared between the ISR and the async RX/TX tasks.
///
/// Each UART instance gets its own `State` via a function-local static
/// in its [`DirectUartInstance::state()`] impl — no module-level globals.
struct State {
    rx_waker: AtomicWaker,
    tx_waker: AtomicWaker,
    rx_ring: RingBuffer,
    rx_overrun: portable_atomic::AtomicU32,
    /// Backing storage for `rx_ring`. Embedded here so that the ring
    /// buffer and its backing memory share the same `'static` lifetime,
    /// eliminating the need for separate `static mut` buffers.
    rx_buf: UnsafeCell<[u8; RX_BUF_SIZE]>,
}

// Safety: `rx_buf` is only accessed through `RingBuffer`'s atomic
// reader/writer protocol (ISR writes, task reads — never concurrent
// writes). All other fields are inherently Sync (atomics).
unsafe impl Sync for State {}

impl State {
    const fn new() -> Self {
        Self {
            rx_waker: AtomicWaker::new(),
            tx_waker: AtomicWaker::new(),
            rx_ring: RingBuffer::new(),
            rx_overrun: portable_atomic::AtomicU32::new(0),
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
    impl Sealed for embassy_rp::peripherals::UART0 {}
    impl Sealed for embassy_rp::peripherals::UART1 {}
}

/// Maps an embassy [`Instance`] type to its PAC register block and
/// per-instance state.
///
/// Embassy's `Instance::info()` is private, so this trait bridges the gap.
/// Each impl provides its own function-local `static State`, following
/// embassy's `SealedInstance::buffered_state()` pattern — the state is
/// associated at the type level, not looked up at runtime.
///
/// Sealed — cannot be implemented outside this crate.
#[allow(private_interfaces)]
pub trait DirectUartInstance: Instance + sealed::Sealed {
    /// PAC register block for this UART instance.
    fn regs() -> RegBlock;

    /// Per-instance shared state (ISR + task).
    #[doc(hidden)]
    fn state() -> &'static State;
}

#[allow(private_interfaces)]
impl DirectUartInstance for embassy_rp::peripherals::UART0 {
    fn regs() -> RegBlock {
        embassy_rp::pac::UART0
    }
    fn state() -> &'static State {
        static STATE: State = State::new();
        &STATE
    }
}

#[allow(private_interfaces)]
impl DirectUartInstance for embassy_rp::peripherals::UART1 {
    fn regs() -> RegBlock {
        embassy_rp::pac::UART1
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
/// On RX: reads the byte from DR into the ring buffer and wakes the task.
/// On TX: just wakes the task (TX writes happen in task context).
pub struct DirectInterruptHandler<T: DirectUartInstance> {
    _uart: core::marker::PhantomData<T>,
}

impl<T: DirectUartInstance> embassy_rp::interrupt::typelevel::Handler<T::Interrupt>
    for DirectInterruptHandler<T>
{
    unsafe fn on_interrupt() {
        let r = T::regs();
        let state = T::state();

        let mis = r.uartmis().read();

        // RX: drain all available bytes from DR into the ring buffer.
        // With FIFO disabled this is typically 1 byte, but we loop
        // defensively in case multiple interrupts coalesced.
        if mis.rxmis() || mis.rtmis() {
            unsafe {
                let mut writer = state.rx_ring.writer();

                while !r.uartfr().read().rxfe() {
                    let dr = r.uartdr().read();
                    if !writer.push_one(dr.data()) {
                        // Ring buffer full — count the dropped byte.
                        // Logged at task level in DirectUartRx::read().
                        state.rx_overrun.fetch_add(1, Ordering::Relaxed);
                    }

                    // HW overrun: a byte was lost before we got the IRQ.
                    // Don't log here — defmt takes a critical section which
                    // extends ISR time and cascades into more overruns.
                    if dr.oe() {
                        state.rx_overrun.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            // Clear RX/RT interrupt flags.
            r.uarticr().write(|w| {
                w.set_rxic(true);
                w.set_rtic(true);
            });

            state.rx_waker.wake();
        }

        // TX: space available in transmit holding register
        if mis.txmis() {
            unsafe {
                reg_clear(&r.uartimsc(), |w| {
                    w.set_txim(true);
                });
            }
            // Clear TX interrupt flag.
            r.uarticr().write(|w| {
                w.set_txic(true);
            });

            state.tx_waker.wake();
        }
    }
}

// ================================================================================
// DirectUart — Construction
// ================================================================================

/// Direct-register UART driver, split into independent TX and RX halves.
pub struct DirectUart;

impl DirectUart {
    /// Create direct-access TX and RX handles from an embassy blocking UART.
    ///
    /// The embassy `Uart<Blocking>` is consumed after configuring the hardware
    /// (baud rate, parity, pin muxing). Its drop is a no-op since blocking
    /// mode doesn't allocate DMA channels.
    ///
    /// After this call:
    /// - The UART FIFO is **disabled** so each byte triggers an interrupt
    /// - The ISR reads bytes into a ring buffer
    /// - RX and TX interrupts are enabled
    pub fn new<T: DirectUartInstance>(
        _uart: Uart<'_, Blocking>,
        _irq: impl Binding<T::Interrupt, DirectInterruptHandler<T>>,
    ) -> (DirectUartTx, DirectUartRx) {
        let r = T::regs();
        let state = T::state();

        // Initialize the ring buffer with the per-instance backing storage
        // embedded in State. `UnsafeCell::get()` returns a stable `*mut`
        // pointer to the static's memory — exactly what `RingBuffer::init()`
        // needs.
        unsafe {
            state.rx_ring.init(state.rx_buf.get() as *mut u8, RX_BUF_SIZE);
        }

        // Disable the FIFO so each received byte triggers an immediate
        // interrupt. The PL011's lowest FIFO threshold is 1/8 (4 bytes),
        // which would batch bytes and add up to ~2.3ms latency at 19200
        // baud — too much for TPUART ACK timing (U_ACK_INF must be sent
        // within ~1.7ms of receiving the 6th header byte). With FIFO
        // disabled, each byte triggers an interrupt, and the
        // ring buffer provides overrun protection.
        //
        // The trade-off: without the HW FIFO, any critical section >573us
        // (one byte time at 19200 8E1) causes an HW overrun. Embassy's
        // timer driver and defmt-rtt both take critical sections that can
        // exceed this. The ring buffer absorbs task-level latency, but
        // cannot help when interrupts are globally masked by PRIMASK.
        unsafe {
            reg_clear(&r.uartlcr_h(), |w| {
                w.set_fen(true);
            });
        }

        // Clear any stale interrupt flags.
        r.uarticr().write(|w| {
            w.set_rxic(true);
            w.set_txic(true);
            w.set_rtic(true);
        });

        // Enable RX interrupt (byte received) and RT interrupt (receive
        // timeout — fires when data sits in the holding register without
        // new data arriving, ~32 bit times).
        unsafe {
            reg_set(&r.uartimsc(), |w| {
                w.set_rxim(true);
                w.set_rtim(true);
            });
        }

        // Enable the UART interrupt in the NVIC.
        T::Interrupt::unpend();
        unsafe { T::Interrupt::enable() };

        (
            DirectUartTx { regs: r, state },
            DirectUartRx { state },
        )
    }
}

// ================================================================================
// DirectUartTx
// ================================================================================

/// Async UART transmitter using direct register access.
pub struct DirectUartTx {
    regs: RegBlock,
    state: &'static State,
}

// Safety: RegBlock is a thin pointer wrapper with no thread affinity. Only
// one DirectUartTx exists per UART instance (enforced by consuming the
// embassy Uart singleton).
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

            let mut n = 0;
            for &byte in buf {
                if r.uartfr().read().txff() {
                    break;
                }
                r.uartdr().write(|w| w.set_data(byte));
                n += 1;
            }

            if n > 0 {
                Poll::Ready(Ok(n))
            } else {
                self.state.tx_waker.register(cx.waker());
                unsafe {
                    reg_set(&r.uartimsc(), |w| {
                        w.set_txim(true);
                    });
                }
                Poll::Pending
            }
        })
        .await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        poll_fn(|cx| {
            if !self.regs.uartfr().read().busy() {
                Poll::Ready(Ok(()))
            } else {
                self.state.tx_waker.register(cx.waker());
                unsafe {
                    reg_set(&self.regs.uartimsc(), |w| {
                        w.set_txim(true);
                    });
                }
                Poll::Pending
            }
        })
        .await
    }
}

// ================================================================================
// DirectUartRx
// ================================================================================

/// Async UART receiver backed by an ISR-filled ring buffer.
///
/// The ISR reads each byte from the UART data register into a
/// [`RingBuffer`] (from `embassy-hal-internal`). The task drains the ring
/// buffer via `read()`. This decouples the UART's byte-arrival timing
/// (~573µs at 19200 baud) from task-level processing latency, preventing
/// overruns even when upper-layer stack processing (NL/TL/AL in the same
/// `join4` task) takes several milliseconds.
pub struct DirectUartRx {
    state: &'static State,
}

unsafe impl Send for DirectUartRx {}

impl embedded_io_async::ErrorType for DirectUartRx {
    type Error = core::convert::Infallible;
}

impl embedded_io_async::Read for DirectUartRx {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        poll_fn(|cx| {
            let state = self.state;

            // Check for overruns since last read.
            let overruns = state.rx_overrun.swap(0, Ordering::Relaxed);
            if overruns > 0 {
                warn!("UART RX: {} byte(s) lost to overrun", overruns);
            }

            // Drain available bytes from the ISR ring buffer.
            let mut reader = unsafe { state.rx_ring.reader() };
            let n = reader.pop(|ring_buf| {
                let n = ring_buf.len().min(buf.len());
                buf[..n].copy_from_slice(&ring_buf[..n]);
                n
            });

            if n > 0 {
                Poll::Ready(Ok(n))
            } else {
                state.rx_waker.register(cx.waker());
                // Re-check after registering waker to avoid missed wakeup.
                if !state.rx_ring.is_empty() {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
        })
        .await
    }
}
