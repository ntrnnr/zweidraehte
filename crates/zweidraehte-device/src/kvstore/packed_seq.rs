//! The KNX Data Secure sequence state in a fixed packed byte layout.
//!
//! [`PackedSeqStore`] holds exactly what the secure stack persists — the two
//! singleton sequence counters (sending, tool) and the per-IA SIAT table — at
//! fixed offsets behind a magic, and exposes them through [`KeyValueStore`] so
//! a [`SiatStore`](super::SiatStore) sits on it like any other backend. The
//! layout is the storage format, not a general-purpose map: the namespaces,
//! widths, and offsets are all sequence-number-specific.
//!
//! It is parameterised over a [`ByteRegion`] seam so a backing medium reduces
//! to a thin read/write adapter: the embedded FRAM (`FramKv` in `stm32-common`)
//! and the conformance harness's shared-memory region (`ShmSeqStorage`) share
//! this one layout. Being HAL-free (only `read_at`/`write_at` and integer
//! arithmetic) it lives in the core crate, the only crate both the FRAM store
//! (a `cross/` workspace member) and the conformance store (the main workspace)
//! depend on.
//!
//! # Layout
//!
//! ```text
//! Offset 0:   magic[4]            "SEQ\0"   blank-medium guard
//! Offset 4:   sending[6]                    NS_SENDING singleton
//! Offset 10:  tool[6]                       NS_TOOL singleton (all-zero = unset)
//! Offset 16:  peer_count[2]       big-endian u16
//! Offset 18:  peer_entries[N]     each 8 bytes: ia[2] + seq[6]   (NS_SIAT)
//! ```
//!
//! A read checks the magic first and reports a blank store (`get` → `None`,
//! `for_each` → nothing) until the first `put` stamps it, so a [`SiatStore`]
//! over a fresh medium boots to defaults.
//!
//! [`SiatStore`]: super::SiatStore

use super::{KeyValueStore, NS_SENDING, NS_SIAT, NS_TOOL};

// ============================================================================
// ByteRegion — the medium seam
// ============================================================================

/// A small, byte-addressable persistent region (FRAM, shared memory).
///
/// `read_at` takes `&self` so [`PackedSeqStore`] can serve the `&self`
/// `KeyValueStore::get`/`for_each` from it. A medium that needs `&mut` to read
/// (an SPI FRAM driver) puts the interior mutability *inside its own adapter*
/// (a `RefCell` around the driver), keeping this seam — and the store built on
/// it — clean. Offsets are `u16`: these regions are a few hundred bytes.
pub trait ByteRegion {
    type Error;

    /// Read `buf.len()` bytes starting at `off` into `buf`.
    fn read_at(&self, off: u16, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Write `data` starting at `off`.
    fn write_at(&mut self, off: u16, data: &[u8]) -> Result<(), Self::Error>;
}

// ============================================================================
// Layout constants
// ============================================================================

const MAGIC: [u8; 4] = *b"SEQ\0";
const OFF_MAGIC: u16 = 0;
const OFF_SENDING: u16 = 4;
const OFF_TOOL: u16 = 10;
const OFF_PEER_COUNT: u16 = 16;
const OFF_PEER_ENTRIES: u16 = 18;
/// Bytes per peer entry: IA (2) + SeqNr (6).
const PEER_ENTRY_SIZE: u16 = 8;
/// Sequence-number width (sending, tool, and each peer's last-valid SeqNr).
const SEQ_LEN: usize = 6;

/// Smallest region that holds the header and `PEER_SLOTS` peer entries — the
/// bound a [`ByteRegion`] adapter's capacity must satisfy.
pub const fn region_len(peer_slots: usize) -> usize {
    OFF_PEER_ENTRIES as usize + peer_slots * PEER_ENTRY_SIZE as usize
}

// ============================================================================
// PackedSeqStore
// ============================================================================

/// The sending/tool counters and the SIAT table in the packed [layout](self)
/// over any [`ByteRegion`]. Implements [`KeyValueStore`] so a
/// [`SiatStore`](super::SiatStore) can drive it like any other backend.
///
/// `PEER_SLOTS` caps the per-IA SIAT table; size it ≥ the device's authorized-
/// sender count (an over-full table silently drops new entries, matching the
/// other backends' policy).
pub struct PackedSeqStore<R, const PEER_SLOTS: usize = 16> {
    region: R,
}

impl<R: ByteRegion, const PEER_SLOTS: usize> PackedSeqStore<R, PEER_SLOTS> {
    /// Build over an already-configured region adapter.
    pub fn new(region: R) -> Self {
        Self { region }
    }

    fn has_magic(&self) -> Result<bool, R::Error> {
        let mut buf = [0u8; 4];
        self.region.read_at(OFF_MAGIC, &mut buf)?;
        Ok(buf == MAGIC)
    }

    fn peer_count(&self) -> Result<u16, R::Error> {
        let mut buf = [0u8; 2];
        self.region.read_at(OFF_PEER_COUNT, &mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    fn set_peer_count(&mut self, count: u16) -> Result<(), R::Error> {
        self.region.write_at(OFF_PEER_COUNT, &count.to_be_bytes())
    }

    fn peer_entry_offset(index: u16) -> u16 {
        OFF_PEER_ENTRIES + index * PEER_ENTRY_SIZE
    }

    /// Offset of the entry whose IA matches `key`, or `None` if absent.
    fn find_peer(&self, ia: u16) -> Result<Option<u16>, R::Error> {
        let count = self.peer_count()?;
        let target = ia.to_be_bytes();
        for i in 0..count {
            let off = Self::peer_entry_offset(i);
            let mut stored = [0u8; 2];
            self.region.read_at(off, &mut stored)?;
            if stored == target {
                return Ok(Some(off));
            }
        }
        Ok(None)
    }
}

/// Read a key's 2-byte IA (the only multi-byte key in this layout).
fn key_ia(key: &[u8]) -> u16 {
    u16::from_be_bytes([key[0], key[1]])
}

impl<R: ByteRegion, const PEER_SLOTS: usize> KeyValueStore for PackedSeqStore<R, PEER_SLOTS> {
    type Error = R::Error;

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
                self.region.read_at(OFF_SENDING, &mut seq)?;
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
                self.region.read_at(OFF_TOOL, &mut seq)?;
                if seq == [0u8; SEQ_LEN] {
                    Ok(None)
                } else {
                    buf[..SEQ_LEN].copy_from_slice(&seq);
                    Ok(Some(SEQ_LEN))
                }
            }
            NS_SIAT => match self.find_peer(key_ia(key))? {
                Some(off) => {
                    self.region.read_at(off + 2, &mut buf[..SEQ_LEN])?;
                    Ok(Some(SEQ_LEN))
                }
                None => Ok(None),
            },
            _ => Ok(None),
        }
    }

    fn put(&mut self, ns: u8, key: &[u8], val: &[u8]) -> Result<(), Self::Error> {
        // Any write stamps the magic so a fresh medium becomes initialised.
        self.region.write_at(OFF_MAGIC, &MAGIC)?;
        match ns {
            NS_SENDING => self.region.write_at(OFF_SENDING, &val[..SEQ_LEN]),
            NS_TOOL => self.region.write_at(OFF_TOOL, &val[..SEQ_LEN]),
            NS_SIAT => {
                let ia = key_ia(key);
                if let Some(off) = self.find_peer(ia)? {
                    self.region.write_at(off + 2, &val[..SEQ_LEN])
                } else {
                    let count = self.peer_count()?;
                    // Silently drop past capacity (table must be sized ≥ the
                    // authorized-sender count); same policy as the RAM-mirror
                    // backends.
                    if (count as usize) < PEER_SLOTS {
                        let off = Self::peer_entry_offset(count);
                        self.region.write_at(off, &ia.to_be_bytes())?;
                        self.region.write_at(off + 2, &val[..SEQ_LEN])?;
                        self.set_peer_count(count + 1)?;
                    }
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    fn remove(&mut self, ns: u8, key: &[u8]) -> Result<(), Self::Error> {
        // Only SIAT entries are removable (count truncation / clear); the
        // singletons are always present once the medium is initialised.
        if ns != NS_SIAT {
            return Ok(());
        }
        let ia = key_ia(key);
        if let Some(off) = self.find_peer(ia)? {
            // Swap the last entry into the freed slot and shrink the count —
            // the peer table carries no ordering invariant (the SiatStore view
            // sorts in RAM).
            let count = self.peer_count()?;
            let last_off = Self::peer_entry_offset(count - 1);
            if off != last_off {
                let mut last = [0u8; PEER_ENTRY_SIZE as usize];
                self.region.read_at(last_off, &mut last)?;
                self.region.write_at(off, &last)?;
            }
            self.set_peer_count(count - 1)?;
        }
        Ok(())
    }

    fn for_each(&self, ns: u8, f: &mut dyn FnMut(&[u8], &[u8])) {
        // Boot-path scan: a read error is treated as "nothing here" so a blank
        // or unreadable medium yields an empty store rather than propagating
        // (matching the prior backends, which also swallowed scan errors).
        if !self.has_magic().unwrap_or(false) {
            return;
        }
        match ns {
            NS_SENDING => {
                // All-zero == unset (see `get`), so don't surface an unwritten
                // counter to the boot scan.
                let mut seq = [0u8; SEQ_LEN];
                if self.region.read_at(OFF_SENDING, &mut seq).is_ok() && seq != [0u8; SEQ_LEN] {
                    f(&[0], &seq);
                }
            }
            NS_TOOL => {
                let mut seq = [0u8; SEQ_LEN];
                if self.region.read_at(OFF_TOOL, &mut seq).is_ok() && seq != [0u8; SEQ_LEN] {
                    f(&[0], &seq);
                }
            }
            NS_SIAT => {
                let count = self.peer_count().unwrap_or(0);
                for i in 0..count {
                    let off = Self::peer_entry_offset(i);
                    let mut entry = [0u8; PEER_ENTRY_SIZE as usize];
                    if self.region.read_at(off, &mut entry).is_ok() {
                        f(&entry[0..2], &entry[2..PEER_ENTRY_SIZE as usize]);
                    }
                }
            }
            _ => {}
        }
    }
}

// ============================================================================
// Host tests — PackedSeqStore over a RAM-backed ByteRegion
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A `ByteRegion` over a fixed RAM buffer for codec tests.
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

    impl<const LEN: usize> ByteRegion for RamRegion<LEN> {
        type Error = core::convert::Infallible;
        fn read_at(&self, off: u16, buf: &mut [u8]) -> Result<(), Self::Error> {
            let off = off as usize;
            buf.copy_from_slice(&self.bytes[off..off + buf.len()]);
            Ok(())
        }
        fn write_at(&mut self, off: u16, data: &[u8]) -> Result<(), Self::Error> {
            let off = off as usize;
            self.bytes[off..off + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    type TestStore = PackedSeqStore<RamRegion<{ region_len(4) }>, 4>;

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
        s.put(NS_SIAT, &0x1101u16.to_be_bytes(), &[0, 0, 0, 0, 0, 5]).unwrap();
        let mut buf = [0u8; 6];
        assert_eq!(s.get(NS_SENDING, &[0], &mut buf).unwrap(), None);
        // A real sending write is then visible.
        s.put(NS_SENDING, &[0], &[0, 0, 0, 0, 0, 1]).unwrap();
        assert_eq!(s.get(NS_SENDING, &[0], &mut buf).unwrap(), Some(6));
    }

    #[test]
    fn peer_insert_update_and_remove_swaps_last() {
        let mut s = TestStore::new(RamRegion::new());
        let ia = |n: u16| n.to_be_bytes();
        s.put(NS_SIAT, &ia(0x1101), &[0, 0, 0, 0, 0, 1]).unwrap();
        s.put(NS_SIAT, &ia(0x1102), &[0, 0, 0, 0, 0, 2]).unwrap();
        s.put(NS_SIAT, &ia(0x1103), &[0, 0, 0, 0, 0, 3]).unwrap();
        assert_eq!(s.peer_count().unwrap(), 3);

        // Update in place.
        s.put(NS_SIAT, &ia(0x1102), &[0, 0, 0, 0, 0, 9]).unwrap();
        let mut buf = [0u8; 6];
        assert_eq!(s.get(NS_SIAT, &ia(0x1102), &mut buf).unwrap(), Some(6));
        assert_eq!(buf, [0, 0, 0, 0, 0, 9]);

        // Remove the middle entry: last (0x1103) swaps into its slot.
        s.remove(NS_SIAT, &ia(0x1102)).unwrap();
        assert_eq!(s.peer_count().unwrap(), 2);
        assert_eq!(s.get(NS_SIAT, &ia(0x1102), &mut buf).unwrap(), None);
        assert_eq!(s.get(NS_SIAT, &ia(0x1101), &mut buf).unwrap(), Some(6));
        assert_eq!(s.get(NS_SIAT, &ia(0x1103), &mut buf).unwrap(), Some(6));
    }

    #[test]
    fn over_capacity_drops_silently() {
        let mut s = TestStore::new(RamRegion::new());
        for i in 0..6u16 {
            // PEER_SLOTS = 4: last two dropped.
            s.put(NS_SIAT, &(0x1100 + i).to_be_bytes(), &[0, 0, 0, 0, 0, i as u8]).unwrap();
        }
        assert_eq!(s.peer_count().unwrap(), 4);
        let mut buf = [0u8; 6];
        assert_eq!(s.get(NS_SIAT, &0x1103u16.to_be_bytes(), &mut buf).unwrap(), Some(6));
        assert_eq!(s.get(NS_SIAT, &0x1104u16.to_be_bytes(), &mut buf).unwrap(), None);
    }

    #[test]
    fn for_each_visits_peers() {
        let mut s = TestStore::new(RamRegion::new());
        s.put(NS_SIAT, &0x1101u16.to_be_bytes(), &[0, 0, 0, 0, 0, 1]).unwrap();
        s.put(NS_SIAT, &0x1102u16.to_be_bytes(), &[0, 0, 0, 0, 0, 2]).unwrap();
        let mut seen = 0u32;
        s.for_each(NS_SIAT, &mut |key, val| {
            assert_eq!(key.len(), 2);
            assert_eq!(val.len(), 6);
            seen += 1;
        });
        assert_eq!(seen, 2);
    }
}
