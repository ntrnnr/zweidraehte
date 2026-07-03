//! The in-RAM mirror backing [`WearLeveledKv`](super::WearLeveledKv).
//!
//! The wear-levelled append-log keeps the *current* contents in a
//! fixed-capacity `heapless::Vec` and serves `get`/`for_each` from it without
//! touching flash; the log is only the durable backing. The mirror lives in
//! its own module (rather than inside `wear_leveled`) so a future
//! [`KeyValueStore`] backend that also wants a RAM mirror can share it —
//! `PackedSeqStore` doesn't (FRAM reads are cheap enough to serve directly).
//!
//! Keys and values are stored inline at their maximum widths
//! ([`MAX_KEY`]/[`MAX_VAL`]) with explicit lengths — no allocation.
//!
//! [`KeyValueStore`]: super::KeyValueStore

use heapless::Vec;

use super::{MAX_KEY, MAX_VAL};

/// One live `(namespace, key) -> value` pair held in RAM.
#[derive(Clone, Copy)]
pub struct MirrorEntry {
    ns: u8,
    klen: u8,
    key: [u8; MAX_KEY],
    vlen: u8,
    val: [u8; MAX_VAL],
}

impl MirrorEntry {
    /// Build an entry from borrowed `(ns, key, val)`. `key`/`val` must fit
    /// [`MAX_KEY`]/[`MAX_VAL`] (the only namespaces this stack stores do).
    pub fn new(ns: u8, key: &[u8], val: &[u8]) -> Self {
        let mut e =
            MirrorEntry { ns, klen: key.len() as u8, key: [0; MAX_KEY], vlen: val.len() as u8, val: [0; MAX_VAL] };
        e.key[..key.len()].copy_from_slice(key);
        e.val[..val.len()].copy_from_slice(val);
        e
    }

    pub fn ns(&self) -> u8 {
        self.ns
    }
    pub fn key(&self) -> &[u8] {
        &self.key[..self.klen as usize]
    }
    pub fn val(&self) -> &[u8] {
        &self.val[..self.vlen as usize]
    }

    fn matches(&self, ns: u8, key: &[u8]) -> bool {
        self.ns == ns && self.key() == key
    }
}

/// Fixed-capacity in-RAM map of [`MirrorEntry`], the authoritative current
/// contents of a backend.
///
/// Lookup is a linear scan — `ENTRIES` is the device's small key-space (the
/// SIAT capacity plus the two singleton counters), not a general-purpose map.
pub struct Mirror<const ENTRIES: usize> {
    entries: Vec<MirrorEntry, ENTRIES>,
}

impl<const ENTRIES: usize> Mirror<ENTRIES> {
    pub const fn new() -> Self {
        Self { entries: Vec::new() }
    }

    fn find(&self, ns: u8, key: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.matches(ns, key))
    }

    /// Whether `(ns, key)` is present, without copying its value.
    pub fn contains(&self, ns: u8, key: &[u8]) -> bool {
        self.find(ns, key).is_some()
    }

    /// Insert or replace `(ns, key) = val`.
    ///
    /// **Capacity policy:** if the key is new and the mirror is full, the entry
    /// is *silently dropped*. Every backend shares this — callers must size
    /// `ENTRIES` ≥ their key-space (SIAT authorized-sender count + singletons).
    /// A dropped entry means a later `get` returns `None` for a key that
    /// appeared to `put` successfully; that is acceptable only because the
    /// table is statically sized to the device's provisioned partner count.
    pub fn upsert(&mut self, ns: u8, key: &[u8], val: &[u8]) {
        let e = MirrorEntry::new(ns, key, val);
        match self.find(ns, key) {
            Some(idx) => self.entries[idx] = e,
            None => {
                let _ = self.entries.push(e); // see capacity policy above
            }
        }
    }

    /// Remove `(ns, key)` if present (unordered `swap_remove`; the mirror keeps
    /// no positional invariant).
    pub fn remove(&mut self, ns: u8, key: &[u8]) {
        if let Some(idx) = self.find(ns, key) {
            self.entries.swap_remove(idx);
        }
    }

    /// Copy the value of `(ns, key)` into `buf`, returning its length, or `None`
    /// if absent. `buf` must hold the value width (callers size it to the known
    /// width).
    pub fn get_into(&self, ns: u8, key: &[u8], buf: &mut [u8]) -> Option<usize> {
        let idx = self.find(ns, key)?;
        let v = self.entries[idx].val();
        buf[..v.len()].copy_from_slice(v);
        Some(v.len())
    }

    /// Visit every live `(key, value)` pair in `ns`, in unspecified order.
    pub fn for_each(&self, ns: u8, f: &mut dyn FnMut(&[u8], &[u8])) {
        for e in &self.entries {
            if e.ns == ns {
                f(e.key(), e.val());
            }
        }
    }

    /// Iterate every entry across all namespaces — used by the wear-level
    /// rotation snapshot to serialise the whole live mirror into a fresh sector.
    pub fn iter(&self) -> impl Iterator<Item = &MirrorEntry> {
        self.entries.iter()
    }
}

impl<const ENTRIES: usize> Default for Mirror<ENTRIES> {
    fn default() -> Self {
        Self::new()
    }
}
