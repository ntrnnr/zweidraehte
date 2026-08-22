//! FRAM medium adapter and chip descriptor for KNX Data Secure persistence.
//!
//! FRAM is byte-addressable with no write-cycle time and unlimited endurance,
//! so every write is a direct write-through — no wear-levelling needed. The
//! packed layouts and all the offset arithmetic live once in the core
//! storage backends
//! ([`packed_seq`](zweidraehte_device::storage::backends::packed_seq), the
//! byte-medium watermark); this module supplies only the *medium*: the
//! [`Fram`] chip descriptor and the [`FramRegion`] `ByteIo` handle over the
//! shared FM25L16B SPI driver (see [`fm25l16b`]).
//!
//! A secure device declares its FRAM regions like any others —
//!
//! ```ignore
//! type FramChip = Fram<StmFramSpi, StmFramCs>;
//! type Seq = Placed<StmSiatRegion<SIAT_SIZE>, FramChip, StorageMap>;
//! // main(): SPI bring-up (device pins), then
//! let seq = Seq::open(FramRegion::new(fram_cell)).expect("boot the FRAM seq store");
//! ```

use core::cell::RefCell;
use core::marker::PhantomData;

use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;

use zweidraehte_device::storage::backends::ByteIo;
use zweidraehte_device::storage::region::{Chip, FramSiatRegion};

use fm25l16b::{CAPACITY as FRAM_CAPACITY, Fm25l16b, FramError};

/// An [`ByteIo`] over the FM25L16B FRAM — a `Copy` handle over the shared
/// driver cell, the [`Fram`] chip's `Io`.
///
/// The FRAM driver needs `&mut` for an SPI transaction, but
/// [`ByteIo::read_at`] is `&self` (so `PackedSeqStore::get` can serve from
/// it) and the handle must be `Copy` (so several FRAM regions can share the
/// one physical chip). The `&'static RefCell` covers both: the embassy
/// executor is single-threaded and every transaction is synchronous, so the
/// inner borrow can only re-enter on a reentrant call path — which would be
/// a bug.
pub struct FramRegion<BUS: 'static, CS: 'static> {
    fram: &'static RefCell<Fm25l16b<BUS, CS>>,
}

impl<BUS, CS, E> FramRegion<BUS, CS>
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
impl<BUS, CS> Clone for FramRegion<BUS, CS> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<BUS, CS> Copy for FramRegion<BUS, CS> {}

impl<BUS, CS, E> ByteIo for FramRegion<BUS, CS>
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

/// The SIAT region every STM32G0 secure device places on its FRAM chip:
/// write-in-place over the FM25L16B's whole 2 KiB, with the FRAM-appropriate
/// write-through batch (`BATCH = 1` — unlimited endurance, so every counter
/// update is durable immediately). `SLOTS` sizes both the packed peer table
/// and the SIAT RAM cache. Carving out a smaller region would leave packed
/// room for a future second write-in-place region (e.g. a
/// [`FramMcTimerRegion`](zweidraehte_device::storage::region::FramMcTimerRegion))
/// on the same chip.
pub type StmSiatRegion<const SLOTS: usize> = FramSiatRegion<{ FRAM_CAPACITY as usize }, SLOTS>;

// ================================================================================
// The shared FRAM wiring — concrete bus/CS types
// ================================================================================

/// Concrete SPI handle of the shared FRAM wiring: blocking SPI2 master.
/// The `BUS` every STM32G0 secure device plugs into [`Fram`].
pub type StmFramSpi = embassy_stm32::spi::Spi<'static, embassy_stm32::mode::Blocking, embassy_stm32::spi::mode::Master>;

/// Concrete ~CS output of the shared FRAM wiring — the matching `CS`.
pub type StmFramCs = embassy_stm32::gpio::Output<'static>;

// ================================================================================
// Fram — the storage layer's view of the FM25L16B FRAM chip
// ================================================================================

/// The FM25L16B SPI FRAM, as a [`Chip`] the storage layer packs regions onto.
///
/// A first-class second chip (distinct `TAG` from the internal flash) so a
/// secure device's layout can place its SIAT region here while the config
/// blob stays on flash — a genuine two-chip layout. `BASE = 0` and regions
/// pack upward; each write-in-place store opens at its derived placement, so
/// several regions can share the chip (over copies of the one
/// [`FramRegion`] handle).
///
/// Generic over the SPI bus/CS so a device names the concrete
/// `Fram<StmFramSpi, StmFramCs>` in its layout.
pub struct Fram<BUS: 'static, CS: 'static>(PhantomData<(BUS, CS)>);

impl<BUS, CS> Chip for Fram<BUS, CS> {
    const TAG: u32 = 1;
    const BASE: u32 = 0;
    const CAPACITY: u32 = FRAM_CAPACITY as u32;
    // Byte-writable medium — no erase granule. This is what makes a
    // write-in-place placement valid here (and an append-log placement a
    // compile error).
    const SECTOR_SIZE: u32 = 1;
    type Io = FramRegion<BUS, CS>;
}
