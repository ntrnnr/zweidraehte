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

use heapless::Vec;

use super::flash_io::FlashIo;
use super::{KeyValueStore, MAX_KEY, MAX_VAL};

const MAGIC: [u8; 4] = *b"KNXV";
const HEADER: usize = 6; // magic(4) + count(2 LE)

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

/// Verbatim key-value store over `[REGION_OFFSET, REGION_OFFSET + REGION_SIZE)`,
/// holding up to `ENTRIES` records.
pub struct VerbatimKv<F: FlashIo, const REGION_OFFSET: u32, const REGION_SIZE: usize, const ENTRIES: usize> {
    io: F,
    entries: Vec<Entry, ENTRIES>,
}

impl<F: FlashIo, const REGION_OFFSET: u32, const REGION_SIZE: usize, const ENTRIES: usize>
    VerbatimKv<F, REGION_OFFSET, REGION_SIZE, ENTRIES>
{
    /// Open the store, loading the packed region into the RAM mirror. A blank
    /// region (missing magic) yields an empty store.
    pub fn open(mut io: F) -> Result<Self, F::Error> {
        let mut entries: Vec<Entry, ENTRIES> = Vec::new();

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
                let mut e = Entry { ns, klen: klen as u8, key: [0; MAX_KEY], vlen: 0, val: [0; MAX_VAL] };
                e.key[..klen].copy_from_slice(&buf[i..i + klen]);
                i += klen;
                let vlen = buf[i] as usize;
                i += 1;
                if vlen > MAX_VAL || i + vlen > buf.len() {
                    break;
                }
                e.vlen = vlen as u8;
                e.val[..vlen].copy_from_slice(&buf[i..i + vlen]);
                i += vlen;
                let _ = entries.push(e);
            }
        }

        Ok(Self { io, entries })
    }

    fn find(&self, ns: u8, key: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.matches(ns, key))
    }

    /// Serialise the mirror to the packed format and rewrite the whole region.
    fn flush(&mut self) -> Result<(), F::Error> {
        let mut buf = [0xFFu8; REGION_SIZE];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4..6].copy_from_slice(&(self.entries.len() as u16).to_le_bytes());
        let mut i = HEADER;
        for e in &self.entries {
            buf[i] = e.ns;
            buf[i + 1] = e.klen;
            i += 2;
            buf[i..i + e.klen as usize].copy_from_slice(e.key());
            i += e.klen as usize;
            buf[i] = e.vlen;
            i += 1;
            buf[i..i + e.vlen as usize].copy_from_slice(e.val());
            i += e.vlen as usize;
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
        match self.find(ns, key) {
            Some(idx) => {
                let v = self.entries[idx].val();
                buf[..v.len()].copy_from_slice(v);
                Ok(Some(v.len()))
            }
            None => Ok(None),
        }
    }

    fn put(&mut self, ns: u8, key: &[u8], val: &[u8]) -> Result<(), Self::Error> {
        let mut e = Entry { ns, klen: key.len() as u8, key: [0; MAX_KEY], vlen: val.len() as u8, val: [0; MAX_VAL] };
        e.key[..key.len()].copy_from_slice(key);
        e.val[..val.len()].copy_from_slice(val);
        match self.find(ns, key) {
            Some(idx) => self.entries[idx] = e,
            None => {
                let _ = self.entries.push(e); // silently drop if full
            }
        }
        self.flush()
    }

    fn remove(&mut self, ns: u8, key: &[u8]) -> Result<(), Self::Error> {
        match self.find(ns, key) {
            Some(idx) => {
                self.entries.swap_remove(idx);
                self.flush()
            }
            None => Ok(()),
        }
    }

    fn for_each(&self, ns: u8, f: &mut dyn FnMut(&[u8], &[u8])) {
        for e in &self.entries {
            if e.ns == ns {
                f(e.key(), e.val());
            }
        }
    }
}
