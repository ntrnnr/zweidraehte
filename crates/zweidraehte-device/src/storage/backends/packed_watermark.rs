//! The IP-Secure mc_timer watermark in a fixed packed byte layout.
//!
//! [`PackedWatermark`] is the byte-medium sibling of the wear-levelled
//! mc_timer store: on flash the watermark rides a single-record
//! [`WearLeveledKv`](super::WearLeveledKv) under the
//! [`McTimerStore`](crate::storage::views::McTimerStore) view; on FRAM (no
//! wear concern, byte-granular writes) it is simply overwritten in place.
//! It implements [`McTimerStoreBackend`] directly — there is no key/value
//! indirection to route through for one singleton counter.
//!
//! Deliberately **not** folded into
//! [`PackedSeqStore`](super::PackedSeqStore)'s layout: the watermark is its
//! own [`FramMcTimerRegion`](crate::storage::region::FramMcTimerRegion)
//! (`KNXM`) packed beside the SIAT's region, because the seq store and the
//! mc_timer store live in *separate* stores-struct slots — one shared
//! backing store would need shared ownership across two `RefCell`s, and
//! appending to the seq layout would break its on-media format.
//!
//! # Layout
//!
//! ```text
//! Offset 0:  magic[4]      blank-medium guard ("KNXM", from the bound region)
//! Offset 4:  value[8]      the watermark, little-endian u64
//! ```
//!
//! A missing magic reads as watermark 0 — the correct fresh-device start
//! (the timer re-acquires from the group on the next sync). `clear` blanks
//! the magic, so a factory reset needs no erase primitive.

use crate::storage::definition::McTimerStoreBackend;
use crate::storage::region::{Chip, Region, RegionKind, RegionPlacement};

use super::byte_io::ByteIo;

/// Header magic width plus the 8-byte watermark.
const RECORD_LEN: usize = 12;
const OFF_MAGIC: u32 = 0;
const OFF_VALUE: u32 = 4;

/// The packed write-in-place watermark record over any [`ByteIo`], bound to
/// its byte-medium mc_timer region (the single source of the magic).
pub struct PackedWatermark<M, R: Region> {
    medium: M,
    base: u32,
    _region: core::marker::PhantomData<R>,
}

impl<M: ByteIo, R: Region> PackedWatermark<M, R> {
    // The bound region must be write-in-place and hold the 12-byte record —
    // both static facts of `R`, checked at compile time (forced by the
    // constructor).
    const _VALIDATE: () = {
        core::assert!(
            R::KIND.eq(RegionKind::WriteInPlace),
            "PackedWatermark requires a write-in-place region (Region::KIND == WriteInPlace)"
        );
        core::assert!(RECORD_LEN <= R::SIZE as usize, "PackedWatermark's record exceeds the bound region's SIZE");
    };

    /// Build at the bound region's storage-layer-derived placement. Only
    /// `R`'s own placement is accepted — another region's placement is a
    /// type error. The chip is a free parameter — the chip↔`medium` pairing
    /// is enforced one level up, where `Stored::open` takes `C::Io`.
    pub fn open_at<C: Chip>(medium: M, placement: RegionPlacement<R, C>) -> Self {
        let _ = Self::_VALIDATE;
        Self { medium, base: placement.offset, _region: core::marker::PhantomData }
    }

    fn has_magic(&self) -> Result<bool, M::Error> {
        let mut buf = [0u8; 4];
        self.medium.read_at(self.base + OFF_MAGIC, &mut buf)?;
        Ok(buf == R::MAGIC.to_be_bytes())
    }
}

impl<M: ByteIo, R: Region> McTimerStoreBackend for PackedWatermark<M, R> {
    type Error = M::Error;

    fn load(&self) -> u64 {
        // Any read failure degrades to 0, the fresh-device value — same
        // policy as the flash-backed store's blank read.
        let mut buf = [0u8; 8];
        match self.has_magic() {
            Ok(true) => match self.medium.read_at(self.base + OFF_VALUE, &mut buf) {
                Ok(()) => u64::from_le_bytes(buf),
                Err(_) => 0,
            },
            _ => 0,
        }
    }

    fn save(&mut self, value: u64) -> Result<(), Self::Error> {
        // Value first, magic second: a fresh record only becomes readable
        // once its payload is in place, so a power cut between the two
        // writes reads back as blank (0), never as a torn value paired with
        // a valid magic. (Overwrites of an already-stamped record can still
        // tear — acceptable for a watermark that only lags the live timer.)
        self.medium.write_at(self.base + OFF_VALUE, &value.to_le_bytes())?;
        self.medium.write_at(self.base + OFF_MAGIC, &R::MAGIC.to_be_bytes())
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        // Blanking the magic is enough: `load` gates on it.
        self.medium.write_at(self.base + OFF_MAGIC, &[0u8; 4])
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::cell::RefCell;

    use super::*;
    use crate::storage::region::FramMcTimerRegion;

    /// A 32-byte in-RAM byte medium.
    #[derive(Default)]
    struct MemBytes(RefCell<[u8; 32]>);

    impl ByteIo for &MemBytes {
        type Error = ();
        fn read_at(&self, offset: u32, buf: &mut [u8]) -> Result<(), ()> {
            let mem = self.0.borrow();
            buf.copy_from_slice(&mem[offset as usize..offset as usize + buf.len()]);
            Ok(())
        }
        fn write_at(&mut self, offset: u32, data: &[u8]) -> Result<(), ()> {
            self.0.borrow_mut()[offset as usize..offset as usize + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    struct TestFram;
    impl Chip for TestFram {
        const TAG: u32 = 1;
        const BASE: u32 = 0;
        const CAPACITY: u32 = 32;
        const SECTOR_SIZE: u32 = 1;
        type Io = ();
    }

    #[test]
    fn blank_reads_zero_save_persists_clear_resets() {
        let mem = MemBytes::default();
        let placement = RegionPlacement::<FramMcTimerRegion, TestFram>::from_raw(4, 1);
        let mut store = PackedWatermark::<_, FramMcTimerRegion>::open_at(&mem, placement);

        assert_eq!(store.load(), 0, "blank medium reads as watermark 0");

        store.save(0x0000_1234_5678_9ABC).expect("RAM write cannot fail");
        assert_eq!(store.load(), 0x0000_1234_5678_9ABC);

        // A fresh view over the same medium sees the persisted value.
        let reopened = PackedWatermark::<_, FramMcTimerRegion>::open_at(&mem, placement);
        assert_eq!(reopened.load(), 0x0000_1234_5678_9ABC);

        store.clear().expect("RAM write cannot fail");
        assert_eq!(store.load(), 0, "cleared watermark reads as 0");
    }
}
