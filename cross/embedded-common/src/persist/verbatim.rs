//! Verbatim (non-wear-levelled) [`KeyValueStore`] over a single flash region.
//!
//! For rarely-written data (whole tables/objects). Every `put`/`remove` does a
//! load-modify-rewrite: update the in-RAM mirror, erase the region, write the
//! full packed blob. O(region) per write — fine because this backend is only
//! chosen for data written during ETS download, not per frame. It implements the
//! *same* [`KeyValueStore`] interface as [`super::WearLeveledKv`], so a typed
//! view (e.g. `SiatStore`) is identical over either — wear-levelling is a
//! construction-time choice, not a code path.
//!
//! # Region format
//!
//! ```text
//! [magic: 4B "KNXV"][count: 2B LE][record…]
//! record: [ns:1][klen:1][key…][vlen:1][val…]
//! ```
//!
//! The magic guards against reading uninitialised flash (all 0xFF). No CRC: a
//! torn whole-region write is rare (only on ETS download) and re-download
//! recovers; the magic alone gates a blank region.

use super::flash_io::FlashIo;
use super::mirror::Mirror;
use super::{KeyValueStore, MAX_KEY, MAX_VAL};

const MAGIC: [u8; 4] = *b"KNXV";
const HEADER: usize = 6; // magic(4) + count(2 LE)

/// Verbatim key-value store over `[REGION_OFFSET, REGION_OFFSET + REGION_SIZE)`,
/// holding up to `ENTRIES` records.
///
/// The RAM [`Mirror`] holds the live contents; only the packed-region
/// `open`/`flush` codec below is verbatim-specific.
pub struct VerbatimKv<F: FlashIo, const REGION_OFFSET: u32, const REGION_SIZE: usize, const ENTRIES: usize> {
    io: F,
    mirror: Mirror<ENTRIES>,
}

impl<F: FlashIo, const REGION_OFFSET: u32, const REGION_SIZE: usize, const ENTRIES: usize>
    VerbatimKv<F, REGION_OFFSET, REGION_SIZE, ENTRIES>
{
    /// Open the store, loading the packed region into the RAM [`Mirror`]. A
    /// blank region (missing magic) yields an empty store.
    pub fn open(mut io: F) -> Result<Self, F::Error> {
        let mut mirror: Mirror<ENTRIES> = Mirror::new();

        // Read the whole region. REGION_SIZE is small (one sector) so a stack
        // buffer is fine; bound it to avoid a giant frame.
        let mut buf = [0u8; REGION_SIZE];
        io.read(REGION_OFFSET, &mut buf)?;

        if buf[0..4] == MAGIC {
            let count = u16::from_le_bytes([buf[4], buf[5]]) as usize;
            let mut i = HEADER;
            for _ in 0..count {
                if i + 2 > buf.len() {
                    break;
                }
                let ns = buf[i];
                let klen = buf[i + 1] as usize;
                i += 2;
                if klen > MAX_KEY || i + klen + 1 > buf.len() {
                    break;
                }
                let key_start = i;
                i += klen;
                let vlen = buf[i] as usize;
                i += 1;
                if vlen > MAX_VAL || i + vlen > buf.len() {
                    break;
                }
                mirror.upsert(ns, &buf[key_start..key_start + klen], &buf[i..i + vlen]);
                i += vlen;
            }
        }

        Ok(Self { io, mirror })
    }

    /// Serialise the mirror to the packed format and rewrite the whole region.
    fn flush(&mut self) -> Result<(), F::Error> {
        let mut buf = [0xFFu8; REGION_SIZE];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4..6].copy_from_slice(&(self.mirror.len() as u16).to_le_bytes());
        let mut i = HEADER;
        for e in self.mirror.iter() {
            buf[i] = e.ns();
            buf[i + 1] = e.key().len() as u8;
            i += 2;
            buf[i..i + e.key().len()].copy_from_slice(e.key());
            i += e.key().len();
            buf[i] = e.val().len() as u8;
            i += 1;
            buf[i..i + e.val().len()].copy_from_slice(e.val());
            i += e.val().len();
        }
        self.io.erase(REGION_OFFSET, REGION_OFFSET + REGION_SIZE as u32)?;
        self.io.write(REGION_OFFSET, &buf[..i])?;
        Ok(())
    }
}

impl<F: FlashIo, const REGION_OFFSET: u32, const REGION_SIZE: usize, const ENTRIES: usize> KeyValueStore
    for VerbatimKv<F, REGION_OFFSET, REGION_SIZE, ENTRIES>
{
    type Error = F::Error;

    fn get(&self, ns: u8, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Ok(self.mirror.get_into(ns, key, buf))
    }

    fn put(&mut self, ns: u8, key: &[u8], val: &[u8]) -> Result<(), Self::Error> {
        self.mirror.upsert(ns, key, val);
        self.flush()
    }

    fn remove(&mut self, ns: u8, key: &[u8]) -> Result<(), Self::Error> {
        if !self.mirror.contains(ns, key) {
            return Ok(()); // absent — no rewrite needed
        }
        self.mirror.remove(ns, key);
        self.flush()
    }

    fn for_each(&self, ns: u8, f: &mut dyn FnMut(&[u8], &[u8])) {
        self.mirror.for_each(ns, f);
    }
}
