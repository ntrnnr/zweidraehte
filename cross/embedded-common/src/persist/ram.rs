//! RAM-only [`KeyValueStore`] for lab bring-up.
//!
//! Holds entries in a `heapless::Vec`; nothing is persisted, so all state is
//! **lost on power cycle**. That breaks cross-reboot replay protection — ETS
//! re-syncs via `S-A_Sync` after each reset, but a recorded ciphertext can be
//! replayed in the window before sync completes. Use a flash- or FRAM-backed
//! [`KeyValueStore`] in production.
//!
//! Wrap it in a typed view exactly like the durable backends, e.g.
//! `SiatStore<RamKv<N>, N, K>`, so bring-up and production share one code path.

use heapless::Vec;

use super::{KeyValueStore, MAX_KEY, MAX_VAL};

#[derive(Clone, Copy)]
struct Entry {
    ns: u8,
    klen: u8,
    key: [u8; MAX_KEY],
    vlen: u8,
    val: [u8; MAX_VAL],
}

impl Entry {
    fn matches(&self, ns: u8, key: &[u8]) -> bool {
        self.ns == ns && &self.key[..self.klen as usize] == key
    }
}

/// RAM-only key-value store holding up to `ENTRIES` records.
pub struct RamKv<const ENTRIES: usize = 16> {
    entries: Vec<Entry, ENTRIES>,
}

impl<const ENTRIES: usize> RamKv<ENTRIES> {
    pub const fn new() -> Self {
        Self { entries: Vec::new() }
    }
    fn find(&self, ns: u8, key: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.matches(ns, key))
    }
}

impl<const ENTRIES: usize> Default for RamKv<ENTRIES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const ENTRIES: usize> KeyValueStore for RamKv<ENTRIES> {
    type Error = core::convert::Infallible;

    fn get(&self, ns: u8, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        match self.find(ns, key) {
            Some(i) => {
                let e = &self.entries[i];
                let v = &e.val[..e.vlen as usize];
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
            Some(i) => self.entries[i] = e,
            None => {
                let _ = self.entries.push(e); // silently drop if full
            }
        }
        Ok(())
    }

    fn remove(&mut self, ns: u8, key: &[u8]) -> Result<(), Self::Error> {
        if let Some(i) = self.find(ns, key) {
            self.entries.swap_remove(i);
        }
        Ok(())
    }

    fn for_each(&self, ns: u8, f: &mut dyn FnMut(&[u8], &[u8])) {
        for e in &self.entries {
            if e.ns == ns {
                f(&e.key[..e.klen as usize], &e.val[..e.vlen as usize]);
            }
        }
    }
}
