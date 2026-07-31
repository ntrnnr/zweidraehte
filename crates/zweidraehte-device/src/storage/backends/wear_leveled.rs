//! Wear-levelled [`KeyValueStore`] over a circular flash append-log.
//!
//! Fixed-size record slots hold generic `(namespace, key, value)` triples; a
//! per-sector header is written **last** as a crash-safe commit marker, with
//! monotonic generation counters, highest-generation recovery, and snapshot
//! compaction on rotation. Per-record append is what makes a single SIAT-entry
//! update cheap (one slot), which is the whole point of wear-levelling.
//!
//! # Slot format (12 bytes, fixed)
//!
//! ```text
//! Sector header (slot 0): [b'K'][b'N'][b'X'][b'R'][gen:4 BE][crc8][FF FF FF]
//! Record (slots 1..):     [ns:1][klen:1][key…][vlen:1][val…][crc8][FF…]
//! Free slot:              all 0xFF
//! ```
//!
//! `klen ≤ MAX_KEY (2)` and `vlen ≤ MAX_VAL (8)`, so the largest record
//! (`1+1+2+1+8+1 = 14`) fits the 16-byte slot. A `remove` is a record with
//! `vlen == 0xFF` (tombstone); last-writer-wins on replay, so a tombstone after
//! a value cancels it. A non-blank slot failing its CRC is *torn* (power cut
//! mid-append): recovery skips it and keeps replaying — the record being
//! written at the crash is lost (its `put` never returned), but records
//! appended after an earlier crash stay visible, and the slot is never
//! re-programmed.
//!
//! The header magic comes from the bound [`Region`] type (`SiatRegion` →
//! `KNXR`, `McTimerRegion` → `KNXM`); a firmware that changes its region
//! magic starts the region fresh, ignoring records written under the old
//! one (ETS re-syncs). A device that carves several wear-levelled regions
//! out of one flash binds each store to its own region type, so a region
//! scan never mistakes one region's stale records for another's.

use core::marker::PhantomData;

use crate::storage::region::{Chip, Region, RegionKind, RegionPlacement};

use super::mirror::Mirror;
use super::sector_io::{SectorIo, crc8};
use super::{KeyValueStore, MAX_KEY, MAX_VAL};

/// Bytes per slot. The largest record is `ns(1)+klen(1)+key(2)+vlen(1)+val(8)
/// +crc(1) = 14`; the slot is 16 so every power-of-two `WRITE_ALIGN` up to 16
/// divides it (14 would shut out align-4 and align-8 media).
const SLOT_SIZE: usize = 16;

/// Tombstone marker in the `vlen` byte: the record removes its `(ns, key)`.
const TOMBSTONE_VLEN: u8 = 0xFF;

// Compile-time guarantee that the widest record fits a slot.
const _: () = core::assert!(1 + 1 + MAX_KEY + 1 + MAX_VAL + 1 <= SLOT_SIZE, "record exceeds the 16-byte slot");

/// Wear-levelled key-value store over `ENTRIES` live records, `SECTORS` flash
/// sectors of `SECTOR_SIZE` bytes starting at `REGION_OFFSET`.
///
/// The RAM `Mirror` is the authoritative current contents; the flash log is
/// the durable backing. `get`/`for_each` read the mirror (no flash I/O);
/// `put`/`remove` append one slot and rotate+compact when a sector fills. Only
/// the slot codec and rotation below are wear-level-specific — the mirror is
/// shared with the other backends.
///
/// # Capacity constraint
///
/// Rotation compacts the *entire* live mirror into one fresh sector (header
/// slot + `ENTRIES` record slots), so `ENTRIES` must fit:
/// `ENTRIES <= sector_size / SLOT_SIZE - 1`, and there must be at least two
/// sectors to rotate between. `open` asserts both — a violation
/// would otherwise surface as silent corruption of the *next* region when a
/// full mirror rotates past the sector boundary.
pub struct WearLeveledKv<F: SectorIo, R: Region, const ENTRIES: usize> {
    io: F,
    mirror: Mirror<ENTRIES>,
    /// Region placement — supplied at `open` time by the storage layer (which
    /// auto-derives the offset from the region sizes), not baked into the type.
    /// `SECTOR_SIZE`/`SECTORS`/`OFFSET` are only scalar I/O addresses and loop
    /// bounds, so they live here as runtime fields; `ENTRIES` (sizing the
    /// `Mirror`) stays a const generic, and the magic comes from `R`.
    region_offset: u32,
    sector_size: usize,
    sectors: usize,
    /// Sector currently being appended to (0..sectors).
    active_sector: usize,
    /// Next free slot within the active sector (1..=slots_per_sector).
    next_slot: usize,
    /// Generation of the active sector (monotonic across rotations).
    generation: u32,
    _region: PhantomData<R>,
}

impl<F: SectorIo, R: Region, const ENTRIES: usize> WearLeveledKv<F, R, ENTRIES> {
    // The bound region must actually be an append log — a store type
    // instantiated with e.g. a write-in-place FRAM region is a sizing
    // mistake this catches at compile time (forced by every `open`).
    const _MECHANISM: () = core::assert!(
        R::KIND.eq(RegionKind::AppendLog),
        "WearLeveledKv requires an append-log region (Region::KIND == AppendLog)"
    );

    // Slots are written individually at a SLOT_SIZE pitch, so every write
    // must itself be whole write-granules — a medium programming doublewords
    // (STM32G0, WRITE_ALIGN = 8) cannot take 12-byte slot writes; such
    // devices use the byte-medium path (`FramSiatRegion` + `PackedSeqStore`).
    const _WRITE_ALIGN: () = core::assert!(
        SLOT_SIZE % F::WRITE_ALIGN == 0,
        "WearLeveledKv slot writes require the medium's WRITE_ALIGN to divide SLOT_SIZE (16) — use FramSiatRegion/PackedSeqStore on media with a coarser write grain"
    );

    /// Slots per sector, from the runtime sector size. `SLOT_SIZE` is a const so
    /// this division const-folds at the call site.
    fn slots_per_sector(&self) -> usize {
        self.sector_size / SLOT_SIZE
    }
    /// This region's header magic as four big-endian bytes.
    fn magic_bytes(&self) -> [u8; 4] {
        R::MAGIC.to_be_bytes()
    }

    /// Open the store at the bound region's storage-layer-derived
    /// [`RegionPlacement`]. Only `R`'s own placement is accepted — handing
    /// another region's placement here is a type error, so offset, sector
    /// count, and magic can never come from the wrong region. The chip is a
    /// free parameter — the chip↔`io` pairing is enforced one level up,
    /// where `Stored::open` takes `C::Io`.
    pub fn open_at<C: Chip>(io: F, placement: RegionPlacement<R, C>) -> Result<Self, F::Error> {
        Self::open(io, placement.offset, placement.sector_size as usize, (R::SIZE / placement.sector_size) as usize)
    }

    /// Open the store over `R`'s region at `region_offset`, spanning
    /// `sectors` sectors of `sector_size` bytes. Scans the sectors,
    /// reconstructs the RAM mirror, and locates the append cursor; a blank
    /// region yields an empty store.
    ///
    /// Prefer [`open_at`](Self::open_at) with the derived placement; this
    /// is the primitive it unpacks into (and what tests drive directly).
    ///
    /// # Panics
    ///
    /// If the capacity constraint is violated (see the type docs): the mirror
    /// must compact into one sector (`ENTRIES <= sector_size / SLOT_SIZE - 1`)
    /// and rotation needs a second sector (`sectors >= 2`). Both are static
    /// sizing mistakes, so failing loudly at open beats corrupting the
    /// neighbouring region at the first rotation.
    pub(crate) fn open(io: F, region_offset: u32, sector_size: usize, sectors: usize) -> Result<Self, F::Error> {
        let _ = Self::_MECHANISM;
        let _ = Self::_WRITE_ALIGN;
        assert!(
            ENTRIES <= sector_size / SLOT_SIZE - 1,
            "WearLeveledKv: ENTRIES exceeds one sector's record slots (rotation would overrun the sector)"
        );
        assert!(sectors >= 2, "WearLeveledKv: rotation needs at least two sectors");
        let mut s = Self {
            io,
            mirror: Mirror::new(),
            region_offset,
            sector_size,
            sectors,
            active_sector: sectors - 1,
            next_slot: sector_size / SLOT_SIZE,
            generation: 0,
            _region: PhantomData,
        };
        s.recover()?;
        Ok(s)
    }

    fn sector_offset(&self, sector: usize) -> u32 {
        self.region_offset + (sector * self.sector_size) as u32
    }
    fn slot_offset(&self, sector: usize, slot: usize) -> u32 {
        self.sector_offset(sector) + (slot * SLOT_SIZE) as u32
    }

    // ------------------------------------------------------------------------
    // Recovery
    // ------------------------------------------------------------------------

    /// Among sectors with a valid header, the `(index, generation)` of the
    /// highest generation — the live sector after any crash.
    fn newest_sector(&mut self) -> Result<Option<(usize, u32)>, F::Error> {
        let mut best: Option<(usize, u32)> = None;
        let magic_bytes = self.magic_bytes();
        for sector in 0..self.sectors {
            let mut hdr = [0u8; SLOT_SIZE];
            self.io.read(self.slot_offset(sector, 0), &mut hdr)?;
            if hdr[0..4] != magic_bytes || crc8(&hdr[0..8]) != hdr[8] {
                continue;
            }
            let generation = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
            if best.is_none_or(|(_, g)| generation > g) {
                best = Some((sector, generation));
            }
        }
        Ok(best)
    }

    fn recover(&mut self) -> Result<(), F::Error> {
        let Some((sector, generation)) = self.newest_sector()? else {
            // Blank region: cursor parked on the last sector so the first append
            // rotates into sector 0 at generation 1.
            self.active_sector = self.sectors - 1;
            self.next_slot = self.slots_per_sector();
            self.generation = 0;
            return Ok(());
        };

        // Replay records in order; last writer wins per (ns, key). The whole
        // sector is scanned: a *torn* slot (non-blank, bad CRC — a power cut
        // mid-append) is skipped, not treated as the end of the log, because
        // valid records appended after an earlier crash sit beyond it —
        // stopping there would silently roll the sequence counters back, a
        // replay-protection hole. Appends resume one past the last non-blank
        // slot; the torn slot is never re-programmed (NOR bits only clear, so
        // overwriting it could not produce a valid record) — it stays wasted
        // until rotation reclaims the sector.
        let slots_per_sector = self.slots_per_sector();
        let mut cursor = 1;
        for slot in 1..slots_per_sector {
            let mut buf = [0u8; SLOT_SIZE];
            self.io.read(self.slot_offset(sector, slot), &mut buf)?;
            if buf.iter().all(|&b| b == 0xFF) {
                continue; // free slot (appends are sequential, but keep scanning defensively)
            }
            cursor = slot + 1;
            match Self::decode(&buf) {
                Some((ns, key, Some(val))) => self.mirror.upsert(ns, key, val),
                Some((ns, key, None)) => self.mirror.remove(ns, key),
                None => {} // torn slot — skip; later records are still valid
            }
        }

        self.active_sector = sector;
        self.next_slot = cursor;
        self.generation = generation;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Record codec
    // ------------------------------------------------------------------------

    /// Encode `(ns, key, value-or-tombstone)` into a 12-byte slot. `value =
    /// None` is a tombstone.
    fn encode(ns: u8, key: &[u8], value: Option<&[u8]>) -> [u8; SLOT_SIZE] {
        let mut slot = [0xFFu8; SLOT_SIZE];
        slot[0] = ns;
        slot[1] = key.len() as u8;
        let mut i = 2;
        slot[i..i + key.len()].copy_from_slice(key);
        i += key.len();
        match value {
            Some(v) => {
                slot[i] = v.len() as u8;
                i += 1;
                slot[i..i + v.len()].copy_from_slice(v);
                i += v.len();
            }
            None => {
                slot[i] = TOMBSTONE_VLEN;
                i += 1;
            }
        }
        slot[i] = crc8(&slot[0..i]);
        slot
    }

    /// Decode a slot. `None` for a free (all-0xFF) or torn (CRC fail) slot;
    /// otherwise `(ns, key, Some(val))` or `(ns, key, None)` for a tombstone.
    fn decode(slot: &[u8; SLOT_SIZE]) -> Option<(u8, &[u8], Option<&[u8]>)> {
        let ns = slot[0];
        if ns == 0xFF {
            return None; // free slot
        }
        let klen = slot[1] as usize;
        if klen > MAX_KEY {
            return None;
        }
        let vlen_pos = 2 + klen;
        let vlen_byte = slot[vlen_pos];
        if vlen_byte == TOMBSTONE_VLEN {
            // Tombstone: crc over [0..vlen_pos+1].
            let end = vlen_pos + 1;
            if crc8(&slot[0..end]) != slot[end] {
                return None;
            }
            return Some((ns, &slot[2..2 + klen], None));
        }
        let vlen = vlen_byte as usize;
        if vlen > MAX_VAL {
            return None;
        }
        let val_start = vlen_pos + 1;
        let crc_pos = val_start + vlen;
        if crc8(&slot[0..crc_pos]) != slot[crc_pos] {
            return None;
        }
        Some((ns, &slot[2..2 + klen], Some(&slot[val_start..val_start + vlen])))
    }

    // ------------------------------------------------------------------------
    // Append / rotation
    // ------------------------------------------------------------------------

    fn append_slot(&mut self, slot: &[u8; SLOT_SIZE]) -> Result<(), F::Error> {
        if self.next_slot >= self.slots_per_sector() {
            self.rotate()?;
        }
        let offset = self.slot_offset(self.active_sector, self.next_slot);
        self.io.write(offset, slot)?;
        self.next_slot += 1;
        Ok(())
    }

    /// Migrate to a fresh sector with a compacted snapshot of the live mirror,
    /// committing the header **last** (crash-safe — see module docs).
    fn rotate(&mut self) -> Result<(), F::Error> {
        let next_sector = (self.active_sector + 1) % self.sectors;
        let next_gen = self.generation.wrapping_add(1);
        let base = self.sector_offset(next_sector);

        self.io.erase(base, base + self.sector_size as u32)?;

        // Snapshot the live mirror into slots 1.. directly (not via append_slot,
        // which keys off the old cursor and could re-enter rotate). `mirror` and
        // `io` are disjoint fields, so we borrow the mirror immutably while
        // writing through `io` — no clone needed.
        let (mirror, io) = (&self.mirror, &mut self.io);
        let mut slot = 1usize;
        for e in mirror.iter() {
            let encoded = Self::encode(e.ns(), e.key(), Some(e.val()));
            io.write(base + (slot * SLOT_SIZE) as u32, &encoded)?;
            slot += 1;
        }

        // Header last — the commit marker.
        let mut hdr = [0xFFu8; SLOT_SIZE];
        hdr[0..4].copy_from_slice(&self.magic_bytes());
        hdr[4..8].copy_from_slice(&next_gen.to_be_bytes());
        hdr[8] = crc8(&hdr[0..8]);
        self.io.write(base, &hdr)?;

        self.active_sector = next_sector;
        self.generation = next_gen;
        self.next_slot = slot;
        Ok(())
    }
}

impl<F: SectorIo, R: Region, const ENTRIES: usize> KeyValueStore for WearLeveledKv<F, R, ENTRIES> {
    type Error = F::Error;

    fn get(&self, ns: u8, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Ok(self.mirror.get_into(ns, key, buf))
    }

    fn put(&mut self, ns: u8, key: &[u8], val: &[u8]) -> Result<(), Self::Error> {
        let slot = Self::encode(ns, key, Some(val));
        self.append_slot(&slot)?;
        self.mirror.upsert(ns, key, val);
        Ok(())
    }

    fn remove(&mut self, ns: u8, key: &[u8]) -> Result<(), Self::Error> {
        if !self.mirror.contains(ns, key) {
            return Ok(()); // absent — nothing to persist
        }
        let slot = Self::encode(ns, key, None);
        self.append_slot(&slot)?;
        self.mirror.remove(ns, key);
        Ok(())
    }

    fn for_each(&self, ns: u8, f: &mut dyn FnMut(&[u8], &[u8])) {
        self.mirror.for_each(ns, f);
    }
}
