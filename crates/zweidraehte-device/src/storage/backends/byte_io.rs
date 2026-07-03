//! The byte-addressable medium seam, counterpart of [`SectorIo`](super::SectorIo).

/// Byte-addressable non-volatile memory: write-in-place, no erase, unlimited
/// endurance (FRAM, MRAM, battery-backed SRAM, shared memory).
///
/// The counterpart to the [`SectorIo`](super::SectorIo) seam: flash is
/// sector-erase NOR with a bounded cycle budget; this seam is the opposite
/// contract — every byte is independently writable, so there is no `erase`.
/// Offsets are `u32`, symmetric with `SectorIo` — an adapter over a small part
/// (the FM25L16B's 2 KiB) narrows internally.
///
/// `read_at` takes `&self` so
/// [`PackedSeqStore`](super::PackedSeqStore) can serve the `&self`
/// `KeyValueStore::get`/`for_each` from it. A medium that needs `&mut` to read
/// (an SPI FRAM driver) puts the interior mutability *inside its own adapter*
/// (a `RefCell` around the driver), keeping this seam — and the store built on
/// it — clean.
pub trait ByteIo {
    type Error;

    /// Read `buf.len()` bytes starting at `off` into `buf`.
    fn read_at(&self, off: u32, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Write `data` starting at `off`.
    fn write_at(&mut self, off: u32, data: &[u8]) -> Result<(), Self::Error>;
}
