//! FRAM-backed [`KeyValueStore`] for KNX Data Secure persistence.
//!
//! FRAM is byte-addressable with no write-cycle time and unlimited endurance, so
//! every write is a direct write-through — no wear-levelling needed. The packed
//! sequence-number layout (magic, sending/tool singletons, a peer table) and all
//! the offset arithmetic live once in
//! [`zweidraehte_device::kvstore::packed_seq`]; this module supplies only the
//! medium: a [`ByteRegion`] over the FM25L16B SPI FRAM (see [`super::fram`]).
//! `FramKv` is then just `PackedSeqStore` over that region. Wrap it in a typed
//! view (`SiatStore<FramKv<..>, N, K>`) exactly like the flash backends.

use core::cell::RefCell;

use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;

use zweidraehte_device::kvstore::packed_seq::{ByteRegion, PackedSeqStore, region_len};

use crate::fram::{Fm25l16b, FramError};

/// A [`ByteRegion`] over the FM25L16B FRAM.
///
/// The FRAM driver needs `&mut` for an SPI transaction, but
/// [`ByteRegion::read_at`] is `&self` (so `PackedSeqStore::get` can serve from
/// it). A `RefCell` bridges this: the embassy executor is single-threaded and
/// every transaction is synchronous, so the inner borrow can only re-enter on a
/// reentrant call path — which would be a bug.
pub struct FramRegion<BUS, CS> {
    fram: RefCell<Fm25l16b<BUS, CS>>,
}

impl<BUS, CS, E> FramRegion<BUS, CS>
where
    BUS: SpiBus<u8, Error = E>,
    CS: OutputPin,
{
    pub fn new(fram: Fm25l16b<BUS, CS>) -> Self {
        Self { fram: RefCell::new(fram) }
    }
}

impl<BUS, CS, E> ByteRegion for FramRegion<BUS, CS>
where
    BUS: SpiBus<u8, Error = E>,
    CS: OutputPin,
{
    type Error = FramError<E>;

    fn read_at(&self, off: u16, buf: &mut [u8]) -> Result<(), Self::Error> {
        debug_assert!(off as usize + buf.len() <= crate::fram::CAPACITY as usize, "FRAM read past capacity");
        self.fram.borrow_mut().read(off, buf)
    }

    fn write_at(&mut self, off: u16, data: &[u8]) -> Result<(), Self::Error> {
        debug_assert!(off as usize + data.len() <= crate::fram::CAPACITY as usize, "FRAM write past capacity");
        self.fram.borrow_mut().write(off, data)
    }
}

/// FRAM-backed key-value store for the SIAT and sequence counters.
///
/// `PEER_SLOTS` caps the per-IA SIAT table size; size it ≥ the device's
/// authorized-sender count (an over-full table silently drops new entries).
/// Default 16 fits the FM25L16B's 2 KiB with room to spare.
pub type FramKv<BUS, CS, const PEER_SLOTS: usize = 16> = PackedSeqStore<FramRegion<BUS, CS>, PEER_SLOTS>;

/// Construct a [`FramKv`] over an already-configured FRAM driver.
///
/// A free function rather than an inherent `new` because `FramKv` is a type
/// alias for `PackedSeqStore`, whose `new` takes the region — this wraps the
/// driver in a [`FramRegion`] first and asserts the peer table fits the chip.
pub fn fram_kv<BUS, CS, E, const PEER_SLOTS: usize>(fram: Fm25l16b<BUS, CS>) -> FramKv<BUS, CS, PEER_SLOTS>
where
    BUS: SpiBus<u8, Error = E>,
    CS: OutputPin,
{
    assert!(
        region_len(PEER_SLOTS) <= crate::fram::CAPACITY as usize,
        "FramKv peer table overflows the FM25L16B's 2 KiB capacity",
    );
    PackedSeqStore::new(FramRegion::new(fram))
}
