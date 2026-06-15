//! Wear-levelled [`KeyValueStore`] over a circular flash append-log.
//!
//! Generalised from the original Data-Secure `SeqLog`. The mechanics are
//! unchanged — fixed-size record slots, a per-sector header written **last** as
//! a crash-safe commit marker, monotonic generation counters, highest-generation
//! recovery, and snapshot compaction on rotation — but the records are now
//! generic `(namespace, key, value)` triples rather than the three hardcoded
//! sequence-number kinds. Per-record append is what makes a single SIAT-entry
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
//! `klen ≤ MAX_KEY (2)` and `vlen ≤ MAX_VAL (6)`, so the largest record
//! (`1+1+2+1+6+1 = 12`) fills the slot exactly. A `remove` is a record with
//! `vlen == 0xFF` (tombstone); last-writer-wins on replay, so a tombstone after
//! a value cancels it.
//!
//! The magic is `KNXR` (vs the old `KNXQ`) so old and new firmware ignore each
//! other's regions — a firmware change starts the region fresh (ETS re-syncs).

use heapless::Vec;

use super::flash_io::{FlashIo, crc8};
use super::{KeyValueStore, MAX_KEY, MAX_VAL};

/// Bytes per slot. The largest record is `ns(1)+klen(1)+key(2)+vlen(1)+val(6)
/// +crc(1) = 12`.
const SLOT_SIZE: usize = 12;

/// Sector-header magic ("KNXR" — distinct from the config `KNXS`, provisioning
/// `KNXP`, and the old seq-log `KNXQ`).
const HEADER_MAGIC: [u8; 4] = *b"KNXR";

/// Tombstone marker in the `vlen` byte: the record removes its `(ns, key)`.
const TOMBSTONE_VLEN: u8 = 0xFF;

// Compile-time guarantee that the widest record fits a slot.
const _: () = core::assert!(1 + 1 + MAX_KEY + 1 + MAX_VAL + 1 <= SLOT_SIZE, "record exceeds the 12-byte slot");

/// One live `(namespace, key) -> value` pair held in RAM. Key/value are stored
/// inline at their maximum widths with explicit lengths — no_alloc.
#[derive(Clone, Copy)]
struct Entry {
    ns: u8,
    klen: u8,
    key: [u8; MAX_KEY],
    vlen: u8,
    val: [u8; MAX_VAL],
}

impl Entry {
    fn key(&self) -> &[u8] {
        &self.key[..self.klen as usize]
    }
    fn val(&self) -> &[u8] {
        &self.val[..self.vlen as usize]
    }
    fn matches(&self, ns: u8, key: &[u8]) -> bool {
        self.ns == ns && self.key() == key
    }
}

/// Wear-levelled key-value store over `ENTRIES` live records, `SECTORS` flash
/// sectors of `SECTOR_SIZE` bytes starting at `REGION_OFFSET`.
///
/// The RAM mirror (`entries`) is the authoritative current contents; the flash
/// log is the durable backing. `get`/`for_each` read the mirror (no flash I/O);
/// `put`/`remove` append one slot and rotate+compact when a sector fills.
pub struct WearLeveledKv<
    F: FlashIo,
    const REGION_OFFSET: u32,
    const SECTOR_SIZE: usize,
    const SECTORS: usize,
    const ENTRIES: usize,
> {
    io: F,
    entries: Vec<Entry, ENTRIES>,
    /// Sector currently being appended to (0..SECTORS).
    active_sector: usize,
    /// Next free slot within the active sector (1..=slots_per_sector).
    next_slot: usize,
    /// Generation of the active sector (monotonic across rotations).
    generation: u32,
}

impl<F: FlashIo, const REGION_OFFSET: u32, const SECTOR_SIZE: usize, const SECTORS: usize, const ENTRIES: usize>
    WearLeveledKv<F, REGION_OFFSET, SECTOR_SIZE, SECTORS, ENTRIES>
{
    const SLOTS_PER_SECTOR: usize = SECTOR_SIZE / SLOT_SIZE;

    /// Open the store: scan sectors, reconstruct the RAM mirror, locate the
    /// append cursor. A blank region yields an empty store.
    pub fn open(io: F) -> Result<Self, F::Error> {
        let mut s = Self {
            io,
            entries: Vec::new(),
            active_sector: SECTORS - 1,
            next_slot: Self::SLOTS_PER_SECTOR,
            generation: 0,
        };
        s.recover()?;
        Ok(s)
    }

    fn sector_offset(sector: usize) -> u32 {
        REGION_OFFSET + (sector * SECTOR_SIZE) as u32
    }
    fn slot_offset(sector: usize, slot: usize) -> u32 {
        Self::sector_offset(sector) + (slot * SLOT_SIZE) as u32
    }

    // ------------------------------------------------------------------------
    // Recovery
    // ------------------------------------------------------------------------

    /// Among sectors with a valid header, the `(index, generation)` of the
    /// highest generation — the live sector after any crash.
    fn newest_sector(&mut self) -> Result<Option<(usize, u32)>, F::Error> {
        let mut best: Option<(usize, u32)> = None;
        for sector in 0..SECTORS {
            let mut hdr = [0u8; SLOT_SIZE];
            self.io.read(Self::slot_offset(sector, 0), &mut hdr)?;
            if hdr[0..4] != HEADER_MAGIC || crc8(&hdr[0..8]) != hdr[8] {
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
            self.active_sector = SECTORS - 1;
            self.next_slot = Self::SLOTS_PER_SECTOR;
            self.generation = 0;
            return Ok(());
        };

        // Replay records in order; last writer wins per (ns, key). Stop at the
        // first free/torn slot — that's where appends resume.
        let mut slot = 1;
        while slot < Self::SLOTS_PER_SECTOR {
            let mut buf = [0u8; SLOT_SIZE];
            self.io.read(Self::slot_offset(sector, slot), &mut buf)?;
            match Self::decode(&buf) {
                Some((ns, key, Some(val))) => self.mirror_upsert(ns, key, val),
                Some((ns, key, None)) => self.mirror_remove(ns, key),
                None => break, // free or torn slot
            }
            slot += 1;
        }

        self.active_sector = sector;
        self.next_slot = slot;
        self.generation = generation;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // RAM mirror
    // ------------------------------------------------------------------------

    fn mirror_find(&self, ns: u8, key: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.matches(ns, key))
    }

    fn mirror_upsert(&mut self, ns: u8, key: &[u8], val: &[u8]) {
        let mut e = Entry { ns, klen: key.len() as u8, key: [0; MAX_KEY], vlen: val.len() as u8, val: [0; MAX_VAL] };
        e.key[..key.len()].copy_from_slice(key);
        e.val[..val.len()].copy_from_slice(val);
        match self.mirror_find(ns, key) {
            Some(idx) => self.entries[idx] = e,
            None => {
                let _ = self.entries.push(e); // silently drop if full
            }
        }
    }

    fn mirror_remove(&mut self, ns: u8, key: &[u8]) {
        if let Some(idx) = self.mirror_find(ns, key) {
            self.entries.swap_remove(idx);
        }
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
        if self.next_slot >= Self::SLOTS_PER_SECTOR {
            self.rotate()?;
        }
        let offset = Self::slot_offset(self.active_sector, self.next_slot);
        self.io.write(offset, slot)?;
        self.next_slot += 1;
        Ok(())
    }

    /// Migrate to a fresh sector with a compacted snapshot of the live mirror,
    /// committing the header **last** (crash-safe — see module docs).
    fn rotate(&mut self) -> Result<(), F::Error> {
        let next_sector = (self.active_sector + 1) % SECTORS;
        let next_gen = self.generation.wrapping_add(1);
        let base = Self::sector_offset(next_sector);

        self.io.erase(base, base + SECTOR_SIZE as u32)?;

        // Snapshot the live mirror into slots 1.. directly (not via append_slot,
        // which keys off the old cursor and could re-enter rotate). Copy the
        // entries out first to avoid borrowing self.entries while writing
        // through self.io.
        let snapshot: Vec<Entry, ENTRIES> = self.entries.clone();
        let mut slot = 1usize;
        for e in &snapshot {
            let encoded = Self::encode(e.ns, e.key(), Some(e.val()));
            self.io.write(base + (slot * SLOT_SIZE) as u32, &encoded)?;
            slot += 1;
        }

        // Header last — the commit marker.
        let mut hdr = [0xFFu8; SLOT_SIZE];
        hdr[0..4].copy_from_slice(&HEADER_MAGIC);
        hdr[4..8].copy_from_slice(&next_gen.to_be_bytes());
        hdr[8] = crc8(&hdr[0..8]);
        self.io.write(base, &hdr)?;

        self.active_sector = next_sector;
        self.generation = next_gen;
        self.next_slot = slot;
        Ok(())
    }
}

impl<F: FlashIo, const REGION_OFFSET: u32, const SECTOR_SIZE: usize, const SECTORS: usize, const ENTRIES: usize>
    KeyValueStore for WearLeveledKv<F, REGION_OFFSET, SECTOR_SIZE, SECTORS, ENTRIES>
{
    type Error = F::Error;

    fn get(&self, ns: u8, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        match self.mirror_find(ns, key) {
            Some(idx) => {
                let v = self.entries[idx].val();
                buf[..v.len()].copy_from_slice(v);
                Ok(Some(v.len()))
            }
            None => Ok(None),
        }
    }

    fn put(&mut self, ns: u8, key: &[u8], val: &[u8]) -> Result<(), Self::Error> {
        let slot = Self::encode(ns, key, Some(val));
        self.append_slot(&slot)?;
        self.mirror_upsert(ns, key, val);
        Ok(())
    }

    fn remove(&mut self, ns: u8, key: &[u8]) -> Result<(), Self::Error> {
        if self.mirror_find(ns, key).is_none() {
            return Ok(()); // absent — nothing to persist
        }
        let slot = Self::encode(ns, key, None);
        self.append_slot(&slot)?;
        self.mirror_remove(ns, key);
        Ok(())
    }

    fn for_each(&self, ns: u8, f: &mut dyn FnMut(&[u8], &[u8])) {
        for e in &self.entries {
            if e.ns == ns {
                f(e.key(), e.val());
            }
        }
    }
}
