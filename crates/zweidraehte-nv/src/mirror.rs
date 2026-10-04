//! The in-RAM mirror backing [`WearLeveledKv`](crate::WearLeveledKv).
//!
//! The wear-levelled log keeps the *current* contents in a fixed-capacity
//! `heapless::Vec` and serves `get`/`for_each` from it without touching
//! flash; the log is only the durable backing, and compaction re-emits the
//! mirror into a fresh bank.
//!
//! Keys and values are stored inline at their maximum widths
//! ([`MAX_KEY`]/[`MAX_VAL`]) with explicit lengths — no allocation.

use heapless::Vec;

use crate::kv::{MAX_KEY, MAX_VAL};

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

    /// Whether this key can be updated or inserted without exceeding the
    /// mirror's fixed capacity.
    pub(crate) fn can_upsert(&self, ns: u8, key: &[u8]) -> bool {
        self.contains(ns, key) || self.entries.len() < ENTRIES
    }

    /// Insert or replace `(ns, key) = val`.
    ///
    /// # Panics
    ///
    /// If a new key exceeds the mirror's fixed capacity. A replay with more
    /// live keys than `ENTRIES` cannot safely serve reads or compact.
    pub fn upsert(&mut self, ns: u8, key: &[u8], val: &[u8]) {
        let e = MirrorEntry::new(ns, key, val);

        match self.find(ns, key) {
            Some(idx) => self.entries[idx] = e,
            None => self.entries.push(e).unwrap_or_else(|_| panic!("Mirror: capacity exceeded")),
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

    /// Iterate every entry across all namespaces — used by the log
    /// compaction snapshot to re-emit the whole live mirror into a fresh bank.
    pub fn iter(&self) -> impl Iterator<Item = &MirrorEntry> {
        self.entries.iter()
    }
}

impl<const ENTRIES: usize> Default for Mirror<ENTRIES> {
    fn default() -> Self {
        Self::new()
    }
}
