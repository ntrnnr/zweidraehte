//! The KNX Data Secure sequence state in a fixed packed layout on byte media.
//!
//! [`PackedSeqStore`] holds exactly what a secure device persists — the two
//! singleton sequence counters (sending, tool) and the positional SIAT — at
//! fixed offsets behind a magic, over any [`ByteIo`] medium: FRAM on the
//! STM32 boards (both stacks), the conformance harness's shared memory, and a
//! file on Linux. It implements the `zweidraehte_proto::security` traits
//! directly and serves every lookup from the medium, so it needs no RAM
//! mirror; byte media are fast enough to read per frame and do not wear.
//! Flash cannot do that and uses [`SiatStore`](crate::SiatStore) over the
//! wear-levelled log instead. Both follow the same rules, which
//! `tests/siat.rs` checks with one suite.
//!
//! # Layout
//!
//! ```text
//! base + 0:   magic[4]        blank-medium guard, big-endian
//! base + 4:   sending[6]      all-zero = never written → DEFAULT_SENDING
//! base + 10:  tool[6]         all-zero = never set
//! base + 16:  count[2]        SIAT element count, big-endian
//! base + 18:  entries[N]      each ia[2] + seq[6]
//! ```
//!
//! An element's position is its `IA_Index`, the join key into the
//! Point-to-point Key Table (03/05/01 §6.3.6.2), so the table is stored
//! exactly as written — duplicates and unsorted rows included.
//!
//! # Initialisation
//!
//! A medium without the magic reads as a fresh device (default counters,
//! empty table), whatever its other bytes hold: a factory-fresh FRAM is not
//! guaranteed to be zero-filled. The first write zeroes the header fields and
//! programs the magic *last*, so a cut during initialisation leaves a medium
//! that still reads as fresh and initialises again.

use zweidraehte_proto::security::{DEFAULT_SENDING, SequenceNumberStorage, SiatAccess};

use crate::ByteIo;

// ============================================================================
// Layout constants
// ============================================================================

const OFF_MAGIC: u32 = 0;
const OFF_SENDING: u32 = 4;
const OFF_TOOL: u32 = 10;
const OFF_COUNT: u32 = 16;
const OFF_ENTRIES: u32 = 18;
/// Bytes per SIAT element: IA (2) + SeqNr (6).
const ENTRY_SIZE: u32 = 8;
/// Sequence-number width.
const SEQ_LEN: usize = 6;

/// An unprovisioned element: what a gap left by writing past the end reads
/// as, the shape of a zeroed array-property segment. IA 0 is not a real
/// device address, so it never satisfies an IA lookup.
const EMPTY_ENTRY: [u8; ENTRY_SIZE as usize] = [0; ENTRY_SIZE as usize];

/// The medium bytes the layout needs for `slots` SIAT elements: the bound a
/// [`ByteIo`] adapter's capacity must satisfy.
pub const fn region_len(slots: usize) -> usize {
    OFF_ENTRIES as usize + slots * ENTRY_SIZE as usize
}

// ============================================================================
// PackedSeqStore
// ============================================================================

/// The sending and tool counters and a SIAT of up to `N` elements, stored in
/// the packed [layout](self) at `base` within the medium, under `magic`.
///
/// Every write goes straight to the medium; there is no skip-ahead batching
/// of the sending counter, because byte media do not wear.
pub struct PackedSeqStore<M, const N: usize> {
    medium: M,
    base: u32,
    magic: u32,
}

impl<M: ByteIo, const N: usize> PackedSeqStore<M, N> {
    /// The medium bytes this store's layout needs.
    pub const REGION_LEN: usize = region_len(N);

    /// Open the layout at `base` within `medium`, guarded by `magic`.
    ///
    /// Distinct layouts on one medium, or firmware variants whose `N`
    /// differs, use distinct magics so neither reads the other's counters.
    ///
    /// # Panics
    ///
    /// If `magic` is `0` or `FFFF_FFFF`: those are what blank media read as,
    /// so a fresh medium would look initialised.
    pub fn new(medium: M, base: u32, magic: u32) -> Self {
        assert!(magic != 0 && magic != u32::MAX, "PackedSeqStore: the magic must not look like blank media");
        Self { medium, base, magic }
    }

    /// The medium behind the store.
    pub fn medium(&self) -> &M {
        &self.medium
    }

    // ------------------------------------------------------------------------
    // Raw layout access
    // ------------------------------------------------------------------------

    fn read(&self, off: u32, buf: &mut [u8]) -> Result<(), M::Error> {
        self.medium.read_at(self.base + off, buf)
    }

    fn write(&mut self, off: u32, data: &[u8]) -> Result<(), M::Error> {
        self.medium.write_at(self.base + off, data)
    }

    fn initialised(&self) -> Result<bool, M::Error> {
        let mut magic = [0u8; 4];
        self.read(OFF_MAGIC, &mut magic)?;
        Ok(u32::from_be_bytes(magic) == self.magic)
    }

    /// Make the medium a valid, empty layout before its first write (see
    /// module docs): header fields first, magic last.
    fn ensure_initialised(&mut self) -> Result<(), M::Error> {
        if self.initialised()? {
            return Ok(());
        }
        self.write(OFF_SENDING, &[0; SEQ_LEN])?;
        self.write(OFF_TOOL, &[0; SEQ_LEN])?;
        self.write(OFF_COUNT, &[0; 2])?;
        let magic = self.magic.to_be_bytes();
        self.write(OFF_MAGIC, &magic)
    }

    /// A six-octet counter, `None` while the medium is fresh or the counter
    /// was never written (all-zero: no legal counter is zero).
    fn read_counter(&self, off: u32) -> Result<Option<[u8; SEQ_LEN]>, M::Error> {
        if !self.initialised()? {
            return Ok(None);
        }
        let mut seq = [0u8; SEQ_LEN];
        self.read(off, &mut seq)?;
        Ok((seq != [0; SEQ_LEN]).then_some(seq))
    }

    /// The element count, clamped to `N` so a corrupt count can never make
    /// a read run past the layout.
    fn count(&self) -> Result<u16, M::Error> {
        if !self.initialised()? {
            return Ok(0);
        }
        let mut count = [0u8; 2];
        self.read(OFF_COUNT, &mut count)?;
        Ok(u16::from_be_bytes(count).min(N as u16))
    }

    fn set_count(&mut self, count: u16) -> Result<(), M::Error> {
        self.write(OFF_COUNT, &count.to_be_bytes())
    }

    fn entry_offset(index: u16) -> u32 {
        OFF_ENTRIES + u32::from(index) * ENTRY_SIZE
    }

    fn read_entry(&self, index: u16) -> Result<(u16, [u8; SEQ_LEN]), M::Error> {
        let mut entry = [0u8; ENTRY_SIZE as usize];
        self.read(Self::entry_offset(index), &mut entry)?;
        let mut seq = [0u8; SEQ_LEN];
        seq.copy_from_slice(&entry[2..]);
        Ok((u16::from_be_bytes([entry[0], entry[1]]), seq))
    }

    fn write_entry(&mut self, index: u16, ia: u16, seq: &[u8; SEQ_LEN]) -> Result<(), M::Error> {
        let mut entry = [0u8; ENTRY_SIZE as usize];
        entry[..2].copy_from_slice(&ia.to_be_bytes());
        entry[2..].copy_from_slice(seq);
        self.write(Self::entry_offset(index), &entry)
    }

    /// Position of the *first* element holding `ia`. First match is what an
    /// array-walking reference device does when partial positional
    /// overwrites leave duplicates.
    fn find(&self, ia: u16) -> Result<Option<u16>, M::Error> {
        for index in 0..self.count()? {
            if self.read_entry(index)?.0 == ia {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }

    /// Write empty elements over `from..to`. Called before the count grows,
    /// so the new elements never expose bytes a longer, since-truncated table
    /// left behind.
    fn clear_entries(&mut self, from: u16, to: u16) -> Result<(), M::Error> {
        for index in from..to {
            self.write(Self::entry_offset(index), &EMPTY_ENTRY)?;
        }
        Ok(())
    }
}

// ============================================================================
// SequenceNumberStorage
// ============================================================================
//
// The per-IA receiving counter *is* the SIAT element's SeqNr (03/05/01
// §6.3.8): there is no separate receiving store, which is what makes a PID 54
// read return the live value.

impl<M: ByteIo, const N: usize> SequenceNumberStorage for PackedSeqStore<M, N> {
    type Error = M::Error;

    fn load_sending_seq(&self) -> Result<[u8; 6], Self::Error> {
        Ok(self.read_counter(OFF_SENDING)?.unwrap_or(DEFAULT_SENDING))
    }

    fn save_sending_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.ensure_initialised()?;
        self.write(OFF_SENDING, seq)
    }

    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error> {
        match self.find(peer_ia)? {
            Some(index) => Ok(Some(self.read_entry(index)?.1)),
            None => Ok(None),
        }
    }

    /// Update-only: an IA that is not in the table is ignored. Membership is
    /// the MaC's to decide (03/05/01 §6.3.8.5), and an insert would invent an
    /// `IA_Index` no key table refers to.
    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error> {
        match self.find(peer_ia)? {
            Some(index) => self.write_entry(index, peer_ia, seq),
            None => Ok(()),
        }
    }

    fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, Self::Error> {
        self.read_counter(OFF_TOOL)
    }

    fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.ensure_initialised()?;
        self.write(OFF_TOOL, seq)
    }
}

// ============================================================================
// SiatAccess
// ============================================================================
//
// The trait's infallible accessors read a medium that can fail; a read error
// reports "absent" (count 0, no entry), which errs toward rejecting a frame
// rather than accepting one against an unknown counter.

impl<M: ByteIo, const N: usize> SiatAccess for PackedSeqStore<M, N> {
    type Error = M::Error;

    fn siat_count(&self) -> u16 {
        self.count().unwrap_or(0)
    }

    fn siat_index_of(&self, ia: u16) -> Option<u16> {
        self.find(ia).ok().flatten().map(|index| index + 1)
    }

    fn siat_read_entry(&self, idx: u16) -> Option<(u16, [u8; 6])> {
        if idx >= self.siat_count() {
            return None;
        }
        self.read_entry(idx).ok()
    }

    /// Positional replace. Writing at or beyond the count extends the table
    /// through `idx`, filling any gap with empty elements; the count is
    /// written last, so a cut leaves the old table intact. Writes beyond the
    /// capacity are ignored; the property layer refuses them upstream.
    fn siat_write_entry(&mut self, idx: u16, ia: u16, seq: [u8; 6]) -> Result<(), Self::Error> {
        if usize::from(idx) >= N {
            return Ok(());
        }
        self.ensure_initialised()?;
        let count = self.count()?;
        if idx < count {
            return self.write_entry(idx, ia, &seq);
        }
        self.clear_entries(count, idx)?;
        self.write_entry(idx, ia, &seq)?;
        self.set_count(idx + 1)
    }

    /// `0` clears. A smaller count truncates the tail; a larger one appends
    /// empty elements for the entry writes that follow (the array-property
    /// load procedure). Clamped to the capacity.
    fn siat_set_count(&mut self, count: u16) -> Result<(), Self::Error> {
        let count = count.min(N as u16);
        self.ensure_initialised()?;
        let old = self.count()?;
        if count > old {
            self.clear_entries(old, count)?;
        }
        self.set_count(count)
    }

    fn siat_clear(&mut self) -> Result<(), Self::Error> {
        if !self.initialised()? {
            return Ok(());
        }
        self.set_count(0)
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;
    use crate::stores::sequence::MAGIC;
    use crate::tests::RamIo;

    #[test]
    fn layout_is_byte_exact_at_the_base_offset() {
        let io = RamIo::zeroed(64 + region_len(4));
        let mut store = PackedSeqStore::<_, 4>::new(io.clone(), 64, MAGIC);
        store.save_sending_seq(&[0, 0, 0, 0, 0, 7]).unwrap();
        store.save_tool_receiving_seq(&[0, 0, 0, 0, 0, 9]).unwrap();
        store.siat_write_entry(1, 0x1102, [0, 0, 0, 0, 0, 2]).unwrap();

        let bytes = io.bytes();
        assert!(bytes[..64].iter().all(|&b| b == 0), "bytes below the base were touched");
        let layout: Vec<u8> =
            [&b"KNXR"[..], &[0, 0, 0, 0, 0, 7], &[0, 0, 0, 0, 0, 9], &[0, 2], &[0; 8], &[0x11, 0x02, 0, 0, 0, 0, 0, 2]]
                .concat();
        assert_eq!(&bytes[64..64 + layout.len()], &layout[..]);
    }

    /// Media written by the micro stack's former `FramStore` (which
    /// initialised the sending counter to `DEFAULT_SENDING` and zero-filled
    /// the rest) read back unchanged: the format did not change.
    #[test]
    fn reads_a_medium_written_by_the_former_micro_fram_store() {
        let format = u32::from_be_bytes(*b"S7S1");
        let io = RamIo::filled(region_len(4), 0xA5);
        let image: Vec<u8> =
            [&format.to_be_bytes()[..], &[0, 0, 0, 0, 0, 0x2A], &[0; 6], &[0, 1], &[0x11, 0x01, 0, 0, 0, 0, 0, 0x05]]
                .concat();
        io.poke(0, &image);

        let store = PackedSeqStore::<_, 4>::new(io, 0, format);
        assert_eq!(store.load_sending_seq().unwrap(), [0, 0, 0, 0, 0, 0x2A]);
        assert_eq!(store.load_tool_receiving_seq().unwrap(), None);
        assert_eq!(store.siat_count(), 1);
        assert_eq!(store.load_receiving_seq(0x1101).unwrap(), Some([0, 0, 0, 0, 0, 5]));
    }

    /// A non-blank medium without the magic reads as fresh, and the first
    /// write clears the garbage header before stamping the magic.
    #[test]
    fn garbage_medium_initialises_on_first_write() {
        let io = RamIo::filled(region_len(4), 0xA5);
        let mut store = PackedSeqStore::<_, 4>::new(io.clone(), 0, MAGIC);
        assert_eq!(store.siat_count(), 0);
        assert_eq!(store.load_sending_seq().unwrap(), DEFAULT_SENDING);

        store.save_tool_receiving_seq(&[0, 0, 0, 0, 0, 1]).unwrap();
        assert_eq!(store.siat_count(), 0, "the garbage count survived initialisation");
        assert_eq!(store.load_sending_seq().unwrap(), DEFAULT_SENDING);
        assert_eq!(&io.bytes()[..4], b"KNXR");
    }

    #[test]
    #[should_panic(expected = "must not look like blank media")]
    fn blank_looking_magic_panics() {
        let _ = PackedSeqStore::<_, 4>::new(RamIo::zeroed(region_len(4)), 0, 0);
    }
}
