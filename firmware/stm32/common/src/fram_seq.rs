//! FRAM medium adapter for KNX Data Secure persistence.
//!
//! FRAM is byte-addressable with no write-cycle time and unlimited endurance,
//! so every write is a direct write-through — no wear-levelling needed. The
//! packed layout and all the offset arithmetic live once in the core
//! storage backends
//! ([`PackedSeqStore`](zweidraehte_device::storage::PackedSeqStore)); this
//! module supplies only the *medium*: the [`FramChip`] `ByteIo` handle over
//! the shared FM25L16B SPI driver (see [`fm25l16b`]), the I/O of the
//! [`Fram`](crate::storage::Fram) medium a device can place stores on.

use core::cell::RefCell;

use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;

use zweidraehte_device::storage::ByteIo;

use fm25l16b::{CAPACITY as FRAM_CAPACITY, Fm25l16b, FramError};

/// A [`ByteIo`] over the whole FM25L16B FRAM — a `Copy` handle over the
/// shared driver cell. Each store opens over its own
/// [`Region`](zweidraehte_device::storage::Region) of it.
///
/// The FRAM driver needs `&mut` for an SPI transaction, but
/// [`ByteIo::read_at`] is `&self` (so `PackedSeqStore::get` can serve from
/// it) and the handle must be `Copy` (so several stores' regions can share
/// the one physical chip). The `&'static RefCell` covers both: the embassy
/// executor is single-threaded and every transaction is synchronous, so the
/// inner borrow can only re-enter on a reentrant call path — which would be
/// a bug.
pub struct FramChip<BUS: 'static, CS: 'static> {
    fram: &'static RefCell<Fm25l16b<BUS, CS>>,
}

impl<BUS, CS, E> FramChip<BUS, CS>
where
    BUS: SpiBus<u8, Error = E>,
    CS: OutputPin,
{
    pub fn new(fram: &'static RefCell<Fm25l16b<BUS, CS>>) -> Self {
        Self { fram }
    }
}

// Manual Clone/Copy: a derive would demand `BUS: Copy`/`CS: Copy`, but the
// handle is just a shared reference.
impl<BUS, CS> Clone for FramChip<BUS, CS> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<BUS, CS> Copy for FramChip<BUS, CS> {}

impl<BUS, CS, E> ByteIo for FramChip<BUS, CS>
where
    BUS: SpiBus<u8, Error = E>,
    CS: OutputPin,
{
    type Error = FramError<E>;

    // The seam's `u32` offsets narrow to the FM25L16B's 11-bit address here;
    // the capacity debug_asserts make an out-of-range offset loud before the
    // truncating cast could wrap it.
    fn read_at(&self, off: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        debug_assert!(off as usize + buf.len() <= FRAM_CAPACITY as usize, "FRAM read past capacity");
        self.fram.borrow_mut().read(off as u16, buf)
    }

    fn write_at(&mut self, off: u32, data: &[u8]) -> Result<(), Self::Error> {
        debug_assert!(off as usize + data.len() <= FRAM_CAPACITY as usize, "FRAM write past capacity");
        self.fram.borrow_mut().write(off as u16, data)
    }
}

// ================================================================================
// The shared FRAM wiring — concrete bus/CS types
// ================================================================================

/// Concrete SPI handle of the shared FRAM wiring: blocking SPI2 master.
/// The `BUS` every STM32G0 secure device plugs into [`FramChip`].
pub type StmFramSpi = embassy_stm32::spi::Spi<'static, embassy_stm32::mode::Blocking, embassy_stm32::spi::mode::Master>;

/// Concrete ~CS output of the shared FRAM wiring — the matching `CS`.
pub type StmFramCs = embassy_stm32::gpio::Output<'static>;
