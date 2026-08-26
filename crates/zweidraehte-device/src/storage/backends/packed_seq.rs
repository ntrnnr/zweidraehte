//! The KNX Data Secure sequence state in a fixed packed byte layout.
//!
//! [`PackedSeqStore`] holds exactly what the secure stack persists — the two
//! singleton sequence counters (sending, tool) and the positional SIAT — at
//! fixed offsets behind a magic, and exposes them through [`KeyValueStore`] so
//! a [`SiatStore`](crate::storage::SiatStore) sits on it like any other backend. The
//! layout is the storage format, not a general-purpose map: the namespaces,
//! widths, and offsets are all sequence-number-specific.
//!
//! It is parameterised over the [`ByteIo`] seam (see
//! `byte_io`) so a backing medium reduces to a thin
//! read/write adapter: the embedded FRAM (`FramRegion` in `stm32-common`) and
//! the conformance harness's shared-memory region (`ShmSeqStorage`) share this
//! one layout. Being HAL-free (only `read_at`/`write_at` and integer arithmetic)
//! it lives in the core crate, the only crate both the FRAM store (a `firmware/`
//! workspace member) and the conformance store (the main workspace) depend on.
//!
//! # Layout
//!
//! ```text
//! Offset 0:   magic[4]            blank-medium guard (see below)
//! Offset 4:   sending[6]                    NS_SENDING singleton
//! Offset 10:  tool[6]                       NS_TOOL singleton (all-zero = unset)
//! Offset 16:  peer_count[2]       big-endian u16
//! Offset 18:  peer_entries[N]     each 8 bytes: ia[2] + seq[6]   (NS_SIAT)
//! ```
//!
//! The SIAT records are keyed by 0-based element index and the packed entry
//! *is* the record value (`ia[2] + seq[6]`), so `NS_SIAT` access is direct
//! slot addressing — the element position is the `IA_Index` the P2P key
//! table joins on (03/05/01 §6.3.6.2), and it is the [`SiatStore`] view on
//! top that owns the IA lookups.
//!
//! A read checks the magic first and reports a blank store (`get` → `None`,
//! `for_each` → nothing) until the first `put` stamps it, so a [`SiatStore`]
//! over a fresh (zeroed or erased) medium boots to defaults. The magic comes
//! from the bound [`Region`] type — a `FramSiatRegion` (`"KNXR"`) on every
//! current medium, FRAM and the conformance shared memory alike — so
//! co-located regions on one byte chip stay distinguishable and the layout
//! guard's same-chip magic-uniqueness check means something on byte media
//! too.
//!
//! [`SiatStore`]: crate::storage::views::SiatStore

use crate::storage::kv::{KeyValueStore, NS_SENDING, NS_SIAT, NS_TOOL};
use crate::storage::region::{Chip, Region, RegionKind, RegionPlacement};

use super::byte_io::ByteIo;

// ============================================================================
// Layout constants
// ============================================================================

const OFF_MAGIC: u32 = 0;
const OFF_SENDING: u32 = 4;
const OFF_TOOL: u32 = 10;
const OFF_PEER_COUNT: u32 = 16;
const OFF_PEER_ENTRIES: u32 = 18;
/// Bytes per peer entry: IA (2) + SeqNr (6).
const PEER_ENTRY_SIZE: u32 = 8;
/// Sequence-number width (sending, tool, and each peer's last-valid SeqNr).
const SEQ_LEN: usize = 6;

/// Smallest region that holds the header and `PEER_SLOTS` peer entries — the
/// bound an [`ByteIo`] adapter's capacity must satisfy.
pub const fn region_len(peer_slots: usize) -> usize {
    OFF_PEER_ENTRIES as usize + peer_slots * PEER_ENTRY_SIZE as usize
}

// ============================================================================
// PackedSeqStore
// ============================================================================

/// The sending/tool counters and the SIAT table in the packed [layout](self)
/// over any [`ByteIo`]. Implements [`KeyValueStore`] so a
/// [`SiatStore`](crate::storage::SiatStore) can drive it like any other backend.
///
/// `R` is the bound [`Region`] — the single source of the blank-medium
/// magic. `PEER_SLOTS` caps the SIAT; size it ≥ the device's
/// authorized-sender count (an over-capacity element write is silently
/// dropped, matching the other backends' policy).
///
/// The layout sits at `base` within the adapter's address space — 0 via
/// [`new`](Self::new) (the region owns the whole medium, as in the
/// conformance shared memory), or `R`'s derived [`RegionPlacement`] offset
/// via [`open_at`](Self::open_at), which is what lets several
/// write-in-place regions share one byte-addressed chip.
pub struct PackedSeqStore<M, R: Region, const PEER_SLOTS: usize = 16> {
    medium: M,
    base: u32,
    _region: core::marker::PhantomData<R>,
}

impl<M: ByteIo, R: Region, const PEER_SLOTS: usize> PackedSeqStore<M, R, PEER_SLOTS> {
    // The bound region must be write-in-place and large enough for the
    // packed layout at this table size — both are static sizing facts of
    // `R` and `PEER_SLOTS`, so they fail at compile time (forced by the
    // constructors) instead of silently overrunning the region.
    const _VALIDATE: () = {
        core::assert!(
            R::KIND.eq(RegionKind::WriteInPlace),
            "PackedSeqStore requires a write-in-place region (Region::KIND == WriteInPlace)"
        );
        core::assert!(
            region_len(PEER_SLOTS) <= R::SIZE as usize,
            "PackedSeqStore's packed layout (region_len(PEER_SLOTS)) exceeds the bound region's SIZE"
        );
    };

    /// Build over an already-configured medium adapter with the layout at
    /// offset 0 — for a medium the region owns outright (the conformance
    /// shared-memory tail), where no `REGIONS` array exists to derive a
    /// placement from.
    pub fn new(medium: M) -> Self {
        // Referencing the associated const forces its lazy assertion.
        #[allow(clippy::let_unit_value)]
        let _ = Self::_VALIDATE;

        Self { medium, base: 0, _region: core::marker::PhantomData }
    }

    /// Build at the bound region's storage-layer-derived placement: the
    /// layout starts at `placement.offset` within the adapter's address
    /// space and is guarded by `R`'s magic. Only `R`'s own placement is
    /// accepted — another region's placement is a type error, so co-located
    /// regions on one byte chip cannot be misread as each other. The chip is
    /// a free parameter — the chip↔`medium` pairing is enforced one level
    /// up, where `Stored::open` takes `C::Io`.
    pub fn open_at<C: Chip>(medium: M, placement: RegionPlacement<R, C>) -> Self {
        // Referencing the associated const forces its lazy assertion.
        #[allow(clippy::let_unit_value)]
        let _ = Self::_VALIDATE;

        Self { medium, base: placement.offset, _region: core::marker::PhantomData }
    }

    /// This region's blank-medium guard as four big-endian bytes.
    fn magic_bytes(&self) -> [u8; 4] {
        R::MAGIC.to_be_bytes()
    }

    /// An absolute adapter offset for a layout-relative one.
    fn at(&self, off: u32) -> u32 {
        self.base + off
    }

    fn has_magic(&self) -> Result<bool, M::Error> {
        let mut buf = [0u8; 4];
        self.medium.read_at(self.at(OFF_MAGIC), &mut buf)?;
        Ok(buf == self.magic_bytes())
    }

    fn peer_count(&self) -> Result<u16, M::Error> {
        let mut buf = [0u8; 2];
        self.medium.read_at(self.at(OFF_PEER_COUNT), &mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    fn set_peer_count(&mut self, count: u16) -> Result<(), M::Error> {
        self.medium.write_at(self.at(OFF_PEER_COUNT), &count.to_be_bytes())
    }

    fn peer_entry_offset(index: u16) -> u32 {
        OFF_PEER_ENTRIES + index as u32 * PEER_ENTRY_SIZE
    }
}

/// Read a key's 2-byte big-endian element index (the only multi-byte key in
/// this layout).
fn key_index(key: &[u8]) -> u16 {
    u16::from_be_bytes([key[0], key[1]])
}

impl<M: ByteIo, R: Region, const PEER_SLOTS: usize> KeyValueStore for PackedSeqStore<M, R, PEER_SLOTS> {
    type Error = M::Error;

    fn get(&self, ns: u8, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        if !self.has_magic()? {
            return Ok(None);
        }
        match ns {
            NS_SENDING => {
                // All-zero means "never written", same convention as NS_TOOL.
                // Magic is stamped on the first `put` of *any* namespace (e.g. a
                // SIAT entry), so without this guard a medium with SIAT data but
                // no sending write yet would return the raw bytes at OFF_SENDING.
                // Zero is never a legal sending counter (spec min is 1; the PID 59
                // write rejects [0;6] with ValueOutOfRange), so all-zero is an
                // unambiguous "unset" — and `SiatStore::boot` then falls back to
                // DEFAULT_SENDING, matching the Mirror backends.
                let mut seq = [0u8; SEQ_LEN];
                self.medium.read_at(self.at(OFF_SENDING), &mut seq)?;
                if seq == [0u8; SEQ_LEN] {
                    Ok(None)
                } else {
                    buf[..SEQ_LEN].copy_from_slice(&seq);
                    Ok(Some(SEQ_LEN))
                }
            }
            NS_TOOL => {
                // All-zero means "never set" — the tool counter has no entry
                // until the first secure tool exchange.
                let mut seq = [0u8; SEQ_LEN];
                self.medium.read_at(self.at(OFF_TOOL), &mut seq)?;
                if seq == [0u8; SEQ_LEN] {
                    Ok(None)
                } else {
                    buf[..SEQ_LEN].copy_from_slice(&seq);
                    Ok(Some(SEQ_LEN))
                }
            }
            NS_SIAT => {
                let idx = key_index(key);
                if idx >= self.peer_count()? {
                    return Ok(None);
                }
                let off = Self::peer_entry_offset(idx);
                self.medium.read_at(self.at(off), &mut buf[..PEER_ENTRY_SIZE as usize])?;
                Ok(Some(PEER_ENTRY_SIZE as usize))
            }
            _ => Ok(None),
        }
    }

    fn put(&mut self, ns: u8, key: &[u8], val: &[u8]) -> Result<(), Self::Error> {
        // Any write stamps the magic so a fresh medium becomes initialised.
        let magic = self.magic_bytes();
        self.medium.write_at(self.at(OFF_MAGIC), &magic)?;
        match ns {
            NS_SENDING => self.medium.write_at(self.at(OFF_SENDING), &val[..SEQ_LEN]),
            NS_TOOL => self.medium.write_at(self.at(OFF_TOOL), &val[..SEQ_LEN]),
            NS_SIAT => {
                let idx = key_index(key);
                // Silently drop past capacity (table must be sized ≥ the
                // authorized-sender count); same policy as the RAM-mirror
                // backends.
                if (idx as usize) >= PEER_SLOTS {
                    return Ok(());
                }
                let off = Self::peer_entry_offset(idx);
                self.medium.write_at(self.at(off), &val[..PEER_ENTRY_SIZE as usize])?;
                if idx >= self.peer_count()? {
                    self.set_peer_count(idx + 1)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn remove(&mut self, ns: u8, key: &[u8]) -> Result<(), Self::Error> {
        // Only SIAT entries are removable, and only from the tail: the
        // SiatStore view truncates and clears by popping the highest index,
        // so removing element `idx` shrinks the table to `idx` elements. The
        // singletons are always present once the medium is initialised.
        if ns != NS_SIAT {
            return Ok(());
        }
        let idx = key_index(key);
        if idx < self.peer_count()? {
            self.set_peer_count(idx)?;
        }
        Ok(())
    }

    fn for_each(&self, ns: u8, f: &mut dyn FnMut(&[u8], &[u8])) {
        // Boot-path scan: a read error is treated as "nothing here" so a blank
        // or unreadable medium yields an empty store (boot to defaults) rather
        // than propagating an error the boot path could not recover from.
        if !self.has_magic().unwrap_or(false) {
            return;
        }
        match ns {
            NS_SENDING => {
                // All-zero == unset (see `get`), so don't surface an unwritten
                // counter to the boot scan.
                let mut seq = [0u8; SEQ_LEN];
                if self.medium.read_at(self.at(OFF_SENDING), &mut seq).is_ok() && seq != [0u8; SEQ_LEN] {
                    f(&[0], &seq);
                }
            }
            NS_TOOL => {
                let mut seq = [0u8; SEQ_LEN];
                if self.medium.read_at(self.at(OFF_TOOL), &mut seq).is_ok() && seq != [0u8; SEQ_LEN] {
                    f(&[0], &seq);
                }
            }
            NS_SIAT => {
                let count = self.peer_count().unwrap_or(0);
                for i in 0..count {
                    let off = Self::peer_entry_offset(i);
                    let mut entry = [0u8; PEER_ENTRY_SIZE as usize];
                    if self.medium.read_at(self.at(off), &mut entry).is_ok() {
                        f(&i.to_be_bytes(), &entry);
                    }
                }
            }
            _ => {}
        }
    }
}

// ============================================================================
// Host tests — PackedSeqStore over a RAM-backed ByteIo
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// An `ByteIo` over a fixed RAM buffer for codec tests.
    struct RamRegion<const LEN: usize> {
        bytes: [u8; LEN],
    }

    impl<const LEN: usize> RamRegion<LEN> {
        fn new() -> Self {
            // Zero-filled, matching the media this layout runs on: the
            // conformance shared-memory region (mmap is zeroed) and a
            // freshly-erased FRAM. The magic gates reads, but the peer-count
            // field is read on the first SIAT `put` before any write to it, so
            // the layout assumes that field starts at zero on a blank medium.
            Self { bytes: [0u8; LEN] }
        }
    }

    impl<const LEN: usize> ByteIo for RamRegion<LEN> {
        type Error = core::convert::Infallible;
        fn read_at(&self, off: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
            let off = off as usize;
            buf.copy_from_slice(&self.bytes[off..off + buf.len()]);
            Ok(())
        }
        fn write_at(&mut self, off: u32, data: &[u8]) -> Result<(), Self::Error> {
            let off = off as usize;
            self.bytes[off..off + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    use crate::storage::region::FramSiatRegion;

    /// The write-in-place SIAT region marker the test stores bind, sized
    /// exactly to the four-slot packed layout.
    type TestSiat = FramSiatRegion<{ region_len(4) }, 4>;
    type TestStore = PackedSeqStore<RamRegion<{ region_len(4) }>, TestSiat, 4>;

    /// A layout opened at a nonzero placement offset addresses its own window
    /// under the bound region's magic: the bytes below `base` stay
    /// untouched, reads come back through the same base, and the on-medium
    /// magic is the region's — this is what lets two write-in-place regions
    /// share a chip without being misread as each other.
    #[test]
    fn open_at_addresses_from_the_placement_offset() {
        use crate::storage::region::RegionPlacement;

        /// The byte-medium test chip the placement is typed to.
        struct TestFram;
        impl Chip for TestFram {
            const TAG: u32 = 1;
            const BASE: u32 = 0;
            const CAPACITY: u32 = 0x100;
            const SECTOR_SIZE: u32 = 1;
            type Io = ();
        }

        const BASE: u32 = 32;
        let placement: RegionPlacement<TestSiat, TestFram> = RegionPlacement::from_raw(BASE, 1);
        let mut s: PackedSeqStore<RamRegion<{ 32 + region_len(4) }>, TestSiat, 4> =
            PackedSeqStore::open_at(RamRegion::new(), placement);
        s.put(NS_SENDING, &[0], &[0, 0, 0, 0, 0, 7]).unwrap();
        let mut buf = [0u8; 6];
        assert_eq!(s.get(NS_SENDING, &[0], &mut buf).unwrap(), Some(6));
        assert_eq!(buf, [0, 0, 0, 0, 0, 7]);
        // The window below the base is untouched, and the bound region's
        // magic landed at BASE.
        assert_eq!(&s.medium.bytes[..4], &[0, 0, 0, 0]);
        assert_eq!(&s.medium.bytes[BASE as usize..BASE as usize + 4], b"KNXR");
    }

    /// `new()` places the layout at offset 0 and stamps the bound region's
    /// magic there on the first write.
    #[test]
    fn new_stamps_the_region_magic_at_offset_zero() {
        let mut s = TestStore::new(RamRegion::new());
        s.put(NS_SENDING, &[0], &[0, 0, 0, 0, 0, 1]).unwrap();
        assert_eq!(&s.medium.bytes[..4], b"KNXR");
    }

    #[test]
    fn blank_region_reads_empty() {
        let s = TestStore::new(RamRegion::new());
        let mut buf = [0u8; 6];
        assert_eq!(s.get(NS_SENDING, &[0], &mut buf).unwrap(), None);
        assert_eq!(s.get(NS_TOOL, &[0], &mut buf).unwrap(), None);
        assert_eq!(s.peer_count().unwrap_or(0), 0);
    }

    #[test]
    fn singletons_roundtrip() {
        let mut s = TestStore::new(RamRegion::new());
        s.put(NS_SENDING, &[0], &[0, 0, 0, 0, 0, 7]).unwrap();
        s.put(NS_TOOL, &[0], &[0, 0, 0, 0, 0, 9]).unwrap();
        let mut buf = [0u8; 6];
        assert_eq!(s.get(NS_SENDING, &[0], &mut buf).unwrap(), Some(6));
        assert_eq!(buf, [0, 0, 0, 0, 0, 7]);
        assert_eq!(s.get(NS_TOOL, &[0], &mut buf).unwrap(), Some(6));
        assert_eq!(buf, [0, 0, 0, 0, 0, 9]);
    }

    #[test]
    fn sending_unset_after_siat_write_reads_none() {
        // Writing a SIAT entry stamps the magic, but the sending counter has
        // never been written — it must still read as unset (None), not as the
        // raw all-zero bytes at OFF_SENDING. This is the FRAM/Shm divergence the
        // guard fixes: without it, a reboot here would boot sending_live = 0.
        let mut s = TestStore::new(RamRegion::new());
        s.put(NS_SIAT, &0u16.to_be_bytes(), &[0x11, 0x01, 0, 0, 0, 0, 0, 5]).unwrap();
        let mut buf = [0u8; 6];
        assert_eq!(s.get(NS_SENDING, &[0], &mut buf).unwrap(), None);
        // A real sending write is then visible.
        s.put(NS_SENDING, &[0], &[0, 0, 0, 0, 0, 1]).unwrap();
        assert_eq!(s.get(NS_SENDING, &[0], &mut buf).unwrap(), Some(6));
    }

    #[test]
    fn peer_entries_are_positional() {
        let mut s = TestStore::new(RamRegion::new());
        let idx = |n: u16| n.to_be_bytes();
        let entry = |ia: u16, n: u8| {
            let mut e = [0u8; 8];
            e[..2].copy_from_slice(&ia.to_be_bytes());
            e[7] = n;
            e
        };
        s.put(NS_SIAT, &idx(0), &entry(0x1101, 1)).unwrap();
        s.put(NS_SIAT, &idx(1), &entry(0x1102, 2)).unwrap();
        s.put(NS_SIAT, &idx(2), &entry(0x1103, 3)).unwrap();
        assert_eq!(s.peer_count().unwrap(), 3);

        // Update element 1 in place — with a different IA, positionally.
        s.put(NS_SIAT, &idx(1), &entry(0x1109, 9)).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(s.get(NS_SIAT, &idx(1), &mut buf).unwrap(), Some(8));
        assert_eq!(buf, entry(0x1109, 9));

        // Removing element 1 truncates to one element (the SiatStore view
        // only ever pops from the tail).
        s.remove(NS_SIAT, &idx(1)).unwrap();
        assert_eq!(s.peer_count().unwrap(), 1);
        assert_eq!(s.get(NS_SIAT, &idx(1), &mut buf).unwrap(), None);
        assert_eq!(s.get(NS_SIAT, &idx(0), &mut buf).unwrap(), Some(8));
    }

    #[test]
    fn over_capacity_drops_silently() {
        let mut s = TestStore::new(RamRegion::new());
        for i in 0..6u16 {
            // PEER_SLOTS = 4: last two dropped.
            let mut e = [0u8; 8];
            e[..2].copy_from_slice(&(0x1100 + i).to_be_bytes());
            e[7] = i as u8;
            s.put(NS_SIAT, &i.to_be_bytes(), &e).unwrap();
        }
        assert_eq!(s.peer_count().unwrap(), 4);
        let mut buf = [0u8; 8];
        assert_eq!(s.get(NS_SIAT, &3u16.to_be_bytes(), &mut buf).unwrap(), Some(8));
        assert_eq!(s.get(NS_SIAT, &4u16.to_be_bytes(), &mut buf).unwrap(), None);
    }

    #[test]
    fn for_each_visits_peers() {
        let mut s = TestStore::new(RamRegion::new());
        s.put(NS_SIAT, &0u16.to_be_bytes(), &[0x11, 0x01, 0, 0, 0, 0, 0, 1]).unwrap();
        s.put(NS_SIAT, &1u16.to_be_bytes(), &[0x11, 0x02, 0, 0, 0, 0, 0, 2]).unwrap();
        let mut seen = 0u32;
        s.for_each(NS_SIAT, &mut |key, val| {
            assert_eq!(key.len(), 2);
            assert_eq!(val.len(), 8);
            seen += 1;
        });
        assert_eq!(seen, 2);
    }
}
