//! Typed views over the [`KeyValueStore`] seam: the security tables.
//!
//! A view is written once, generic over the backend, so the
//! wear-levelled-vs-verbatim choice is a construction-time type decision the
//! view code never branches on. [`SiatStore`] makes the KNX Security
//! Individual Address Table (SIAT) the single source of truth for each
//! communication partner's *Last Valid SeqNr*, as the spec requires (03/05/01
//! Resources §6.3.8 — updated in place on every accepted secure frame, read
//! live, saved/restored across power cycles). [`McTimerStore`] is the
//! IP-Secure multicast-timer watermark (03/08/09 §2.2.4.2) as the same shape
//! of view.
//!
//! The seam itself — [`KeyValueStore`], the namespaces, the seq codec helpers —
//! lives in [`kv`](super::kv); the backends implementing it live in
//! [`backends`](super::backends).

use heapless::Vec;

use crate::storage::SequenceNumberStorage;
use crate::storage::kv::{
    DEFAULT_SENDING, KeyValueStore, NS_MC_TIMER, NS_SENDING, NS_SIAT, NS_TOOL, SEQ6_MAX, SINGLETON_KEY, seq6_to_u64,
    u64_to_seq6,
};

// ============================================================================
// SiatStore — the SIAT + sending/tool counters as one typed view
// ============================================================================

/// One SIAT entry: a sender IA and its last-valid receiving sequence number.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SiatEntry {
    ia: u16,
    seq: [u8; 6],
}

/// The Security Individual Address Table plus the two singleton sequence
/// counters (sending, tool), backed by any [`KeyValueStore`].
///
/// Holds the authoritative state in RAM (a `heapless::Vec` of entries in
/// **array order** — element `i` is the property's element `i + 1`) and writes
/// through to the backend. Per-IA receiving sequence numbers *are* the SIAT
/// entries — there is no separate receiving store — which is what makes the SIAT
/// the single source of truth and a PID 54 read return the live value.
///
/// The table is positional, not IA-keyed. 03/05/01 §6.3.8.3 obliges the *MaC*
/// to write it sorted by Individual Address, but that is ETS's duty, not an
/// invariant the device may enforce: the conformance templates overwrite single
/// elements of a non-empty table and then resolve P2P keys through the element
/// positions they wrote (`IA_Index`, §6.3.6.2/§6.3.8.4), so the device has to
/// store what it was given, position included — duplicates and unsorted tables
/// land exactly as written, as on a reference device.
///
/// * `N` — SIAT capacity (≥ the device's authorized-sender count; writes past
///   the capacity are refused by the property layer's element-range check).
/// * `K` — sending-counter skip-ahead watermark: flash is touched only once per
///   `K` sends (the counter resumes from the watermark after a reboot, never
///   reusing a value). Spec-bounded `K ≤ 0xFFFF` (03/03/07 NOTE 33).
pub struct SiatStore<S: KeyValueStore, const N: usize, const K: u64 = 256> {
    kv: S,
    /// In-RAM mirror in array order (spec element `i + 1` at index `i`).
    entries: Vec<SiatEntry, N>,
    /// Live sending counter (next value to embed in an outgoing frame).
    sending_live: u64,
    /// Highest sending value durably persisted; always ≥ `sending_live`.
    sending_watermark: u64,
    /// Tool-access receiving counter (`None` until first set).
    tool: Option<[u8; 6]>,
}

/// An unprovisioned array slot: writing element 3 of an empty table gives
/// elements 1 and 2 this value, exactly as a zeroed array-property segment
/// would on a reference device. IA 0 is not a real device address, so such a
/// slot can never satisfy an IA lookup.
const EMPTY_SLOT: SiatEntry = SiatEntry { ia: 0, seq: [0u8; 6] };

impl<S: KeyValueStore, const N: usize, const K: u64> SiatStore<S, N, K> {
    // `core::assert!` avoids defmt's non-const `assert!` override (the crate
    // does `#[macro_use] extern crate defmt`).
    const _GUARD_K: () = core::assert!(K <= 0xFFFF, "sending watermark K exceeds the spec re-init ceiling (FFFFh)");

    /// Open the store over `kv`, reconstructing the SIAT and counters from the
    /// backend's current contents.
    ///
    /// SIAT records are keyed by 0-based element index (2 octets BE) holding
    /// `IA(2) + SeqNr(6)`. Records in the pre-positional layout (IA-keyed,
    /// 6-octet value) fail the length filter and read as an empty table — the
    /// correct fresh state, since ETS rewrites the SIAT in full whenever it
    /// changes (§6.3.8.5).
    pub fn boot(kv: S) -> Result<Self, S::Error> {
        // Referencing the associated const forces its lazy assertion.
        #[allow(clippy::let_unit_value)]
        let _ = Self::_GUARD_K;

        let mut entries: Vec<SiatEntry, N> = Vec::new();
        kv.for_each(NS_SIAT, &mut |key, val| {
            if key.len() == 2 && val.len() == 8 {
                let idx = u16::from_be_bytes([key[0], key[1]]) as usize;
                let ia = u16::from_be_bytes([val[0], val[1]]);
                let mut seq = [0u8; 6];
                seq.copy_from_slice(&val[2..8]);
                if idx < N {
                    while entries.len() <= idx {
                        let _ = entries.push(EMPTY_SLOT);
                    }
                    entries[idx] = SiatEntry { ia, seq };
                }
            }
        });

        // Sending counter: stored value is the persisted watermark; resume from
        // it so we never reuse a value across a reboot.
        let mut buf = [0u8; 6];
        let sending = match kv.get(NS_SENDING, SINGLETON_KEY, &mut buf)? {
            Some(6) => seq6_to_u64(&buf),
            _ => seq6_to_u64(&DEFAULT_SENDING),
        };

        let tool = match kv.get(NS_TOOL, SINGLETON_KEY, &mut buf)? {
            Some(6) => Some(buf),
            _ => None,
        };

        Ok(Self { kv, entries, sending_live: sending, sending_watermark: sending, tool })
    }

    // ------------------------------------------------------------------------
    // SIAT — by-IA access (the secure hot path)
    // ------------------------------------------------------------------------

    /// Position of the *first* element holding `ia`, or `None`.
    ///
    /// First match mirrors what an array-walking reference device does when a
    /// table holds duplicates — which partial positional overwrites can
    /// legitimately produce (NOTE 98 wants each IA at most once, but that binds
    /// the MaC, and mid-rewrite states break it transiently).
    fn find(entries: &[SiatEntry], ia: u16) -> Option<usize> {
        entries.iter().position(|e| e.ia == ia)
    }

    /// Whether `ia` is present in the SIAT.
    pub fn contains(&self, ia: u16) -> bool {
        Self::find(&self.entries, ia).is_some()
    }

    /// The 1-based array index of `ia` — its `IA_Index` — or `None` if absent.
    ///
    /// This is the join key into the Point-to-point Key Table: 03/05/01 §6.3.8.4
    /// has the MaS look an IA up here and "use the found IA_Index to find the
    /// key in the Point-to-point Key Table" (§6.3.6.2). The index is literally
    /// the element's position, so it survives whatever order ETS — or a test
    /// bench overwriting single elements — chose to write.
    pub fn index_of(&self, ia: u16) -> Option<u16> {
        Self::find(&self.entries, ia).map(|idx| idx as u16 + 1)
    }

    /// The last-valid receiving SeqNr for `ia`, or `None` if absent.
    pub fn load_seq(&self, ia: u16) -> Option<[u8; 6]> {
        Self::find(&self.entries, ia).map(|idx| self.entries[idx].seq)
    }

    /// Update `ia`'s receiving SeqNr (called per accepted secure frame).
    ///
    /// Update-only: an IA that is not already in the table is ignored, not
    /// inserted. Membership is the MaC's to decide (03/05/01 §6.3.8.5 — ETS
    /// fills the table during configuration), and an insert here would grow the
    /// array and thereby invent an `IA_Index` no key table refers to.
    pub fn save_seq(&mut self, ia: u16, seq: &[u8; 6]) -> Result<(), S::Error> {
        let Some(idx) = Self::find(&self.entries, ia) else {
            debug!("SIAT: dropping SeqNr update for unprovisioned IA {:#06X}", ia);
            return Ok(());
        };
        self.entries[idx].seq = *seq;
        self.persist_entry(idx)
    }

    // ------------------------------------------------------------------------
    // SIAT — by-index access (the PID 54 property service)
    // ------------------------------------------------------------------------

    /// Write element `idx` through to the backend (index-keyed record).
    fn persist_entry(&mut self, idx: usize) -> Result<(), S::Error> {
        let e = self.entries[idx];
        let mut val = [0u8; 8];
        val[..2].copy_from_slice(&e.ia.to_be_bytes());
        val[2..].copy_from_slice(&e.seq);
        self.kv.put(NS_SIAT, &(idx as u16).to_be_bytes(), &val)
    }

    /// Number of SIAT entries (PID 54 element-count read at index 0).
    pub fn count(&self) -> u16 {
        self.entries.len() as u16
    }

    /// The entry at 0-based `idx` in array order, or `None` if out of range.
    pub fn read_entry(&self, idx: u16) -> Option<(u16, [u8; 6])> {
        self.entries.get(idx as usize).map(|e| (e.ia, e.seq))
    }

    /// Provision the element at 0-based `idx` (PID 54 entry write).
    ///
    /// A pure positional replace: whatever was at `idx` is gone, everything
    /// else keeps its position — and with it the `IA_Index` the P2P key table
    /// refers to. Writing past the current end extends the table, filling any
    /// gap with [`EMPTY_SLOT`]s, the same shape a zeroed array-property
    /// segment has. Beyond-capacity writes are refused upstream by the
    /// property layer's range check; here they are ignored.
    pub fn write_entry(&mut self, idx: u16, ia: u16, seq: [u8; 6]) -> Result<(), S::Error> {
        let idx = idx as usize;
        if idx >= N {
            return Ok(());
        }
        while self.entries.len() <= idx {
            let _ = self.entries.push(EMPTY_SLOT);
        }
        self.entries[idx] = SiatEntry { ia, seq };
        self.persist_entry(idx)
    }

    /// Set the SIAT element count (PID 54 write at index 0).
    ///
    /// `count == 0` clears the table. A smaller count truncates the tail; a
    /// larger one pre-allocates empty elements for the entry writes that
    /// follow (KNX array-property load procedure).
    pub fn set_count(&mut self, count: u16) -> Result<(), S::Error> {
        if count == 0 {
            return self.clear();
        }
        let count = (count as usize).min(N);
        while self.entries.len() > count {
            self.entries.pop();
            self.kv.remove(NS_SIAT, &(self.entries.len() as u16).to_be_bytes())?;
        }
        while self.entries.len() < count {
            let _ = self.entries.push(EMPTY_SLOT);
            self.persist_entry(self.entries.len() - 1)?;
        }
        Ok(())
    }

    /// Remove all SIAT entries (factory reset / count-0 write).
    pub fn clear(&mut self) -> Result<(), S::Error> {
        // Drain the mirror first so a backend error leaves a clear RAM view
        // (replay protection stays correct); persist the removals as we go.
        while self.entries.pop().is_some() {
            self.kv.remove(NS_SIAT, &(self.entries.len() as u16).to_be_bytes())?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Sending counter (singleton, K-watermark batched)
    // ------------------------------------------------------------------------

    /// The current Sequence Number Sending (value to embed in the next frame).
    pub fn load_sending(&self) -> [u8; 6] {
        u64_to_seq6(self.sending_live)
    }

    /// Set the sending counter to `seq`.
    ///
    /// During normal monotonic operation this persists a fresh watermark
    /// `seq + K` only when `seq` reaches the current watermark, so the backend
    /// is touched at most once per `K` sends (the post-reboot counter resumes
    /// from the watermark, never reusing a value).
    ///
    /// A write that goes **backward** relative to the current live value
    /// (`seq < sending_live`) is an authoritative re-initialisation — a
    /// factory-reset re-init (03/05/01 §6.1.4) or an ETS PID 59 write, both of
    /// which may set a *lower* value. These are persisted verbatim (the batching
    /// optimisation only applies to forward increments), re-anchoring the
    /// watermark at `seq`. A forward step that stays within the current batch
    /// window (`sending_live ≤ seq < watermark`) only advances the live value in
    /// RAM — no backend write, since the durable watermark already covers it.
    pub fn save_sending(&mut self, seq: &[u8; 6]) -> Result<(), S::Error> {
        let next = seq6_to_u64(seq);
        if next >= self.sending_watermark {
            // Forward step that crosses the batch window: skip ahead by K,
            // clamped to the 6-octet width — an unclamped watermark past
            // 2^48-1 would truncate through `u64_to_seq6` and restore as a
            // tiny (replayable) counter after the next reboot.
            let new_watermark = next.saturating_add(K).min(SEQ6_MAX);
            self.kv.put(NS_SENDING, SINGLETON_KEY, &u64_to_seq6(new_watermark))?;
            self.sending_watermark = new_watermark;
        } else if next < self.sending_live {
            // Non-forward write (re-init / ETS rewrite): persist verbatim and
            // re-anchor so the next increment re-batches from here.
            self.kv.put(NS_SENDING, SINGLETON_KEY, seq)?;
            self.sending_watermark = next;
        }
        // else: a forward step still inside the current batch window — the live
        // value advances in RAM, the durable watermark already covers it.
        self.sending_live = next;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Tool-access receiving counter (singleton)
    // ------------------------------------------------------------------------

    /// The tool-access receiving SeqNr, or `None` if never set.
    pub fn load_tool(&self) -> Option<[u8; 6]> {
        self.tool
    }

    /// Update the tool-access receiving SeqNr (write-through).
    pub fn save_tool(&mut self, seq: &[u8; 6]) -> Result<(), S::Error> {
        self.tool = Some(*seq);
        self.kv.put(NS_TOOL, SINGLETON_KEY, seq)
    }
}

// ============================================================================
// SiatAccess — the index/membership surface the PID 54 property path needs
// ============================================================================

// The trait itself is `zweidraehte_proto::security::SiatAccess` — the SIAT is
// a KNX resource, not a storage-backend concept — and is re-exported here
// because this is the module that implements it.
pub use zweidraehte_proto::security::SiatAccess;

impl<S: KeyValueStore, const N: usize, const K: u64> SiatAccess for SiatStore<S, N, K> {
    type Error = S::Error;

    fn siat_count(&self) -> u16 {
        self.count()
    }
    fn siat_index_of(&self, ia: u16) -> Option<u16> {
        self.index_of(ia)
    }
    fn siat_contains(&self, ia: u16) -> bool {
        self.contains(ia)
    }
    fn siat_read_entry(&self, idx: u16) -> Option<(u16, [u8; 6])> {
        self.read_entry(idx)
    }
    fn siat_write_entry(&mut self, idx: u16, ia: u16, seq: [u8; 6]) -> Result<(), S::Error> {
        self.write_entry(idx, ia, seq)
    }
    fn siat_set_count(&mut self, count: u16) -> Result<(), S::Error> {
        self.set_count(count)
    }
    fn siat_clear(&mut self) -> Result<(), S::Error> {
        self.clear()
    }
}

// ============================================================================
// SequenceNumberStorage — lets the S-AL use a SiatStore unchanged
// ============================================================================
//
// The per-IA receiving counter *is* the SIAT entry's SeqNr (single source of
// truth), so `load/save_receiving_seq` map straight onto the SIAT. Sending and
// tool are the two singletons. This impl means the entire Secure Application
// Layer keeps working over `SEQ: SequenceNumberStorage` with no changes.

impl<S: KeyValueStore, const N: usize, const K: u64> SequenceNumberStorage for SiatStore<S, N, K> {
    type Error = S::Error;

    fn load_sending_seq(&self) -> Result<[u8; 6], Self::Error> {
        Ok(self.load_sending())
    }
    fn save_sending_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.save_sending(seq)
    }
    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error> {
        Ok(self.load_seq(peer_ia))
    }
    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.save_seq(peer_ia, seq)
    }
    fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, Self::Error> {
        Ok(self.load_tool())
    }
    fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.save_tool(seq)
    }
}

// ============================================================================
// McTimerStore — the IP-Secure mc_timer watermark view
// ============================================================================

/// The durable IP-Secure multicast-timer watermark (03/08/09 §2.2.4.2), as a
/// backend-agnostic view over any [`KeyValueStore`].
///
/// Like [`SiatStore`], this separates *what* is stored (one 48-bit counter under
/// a singleton key) from *where* — so the same view serves a wear-levelled flash
/// region on one device, an FRAM region on another, and a shared-memory region
/// in the conformance harness, just by choosing the backend type `S`. A device
/// that wants the watermark "somewhere else" swaps `S`; no new store type.
///
/// The value is the low 48 bits of the timer, encoded as a 6-byte big-endian
/// counter via the shared [`u64_to_seq6`] / [`seq6_to_u64`] codec. A blank
/// backend reads as 0 — the correct fresh-device start (the timer re-acquires
/// from the group on the next sync).
///
/// This is independent of [`SiatStore`]: a routing-only IP-Secure device has an
/// mc_timer but no SIAT, so the two are never coupled. They use disjoint
/// namespaces ([`NS_MC_TIMER`] vs the SIAT's), so a device *could* back both
/// with one store, but each normally gets its own region.
pub struct McTimerStore<S: KeyValueStore> {
    kv: S,
}

impl<S: KeyValueStore> McTimerStore<S> {
    /// Wrap an already-opened backend. The backend's current contents are read
    /// lazily on [`load`](Self::load); nothing is scanned here.
    pub fn new(kv: S) -> Self {
        Self { kv }
    }

    /// The last persisted watermark, or 0 if the backend is blank.
    pub fn load(&self) -> u64 {
        let mut buf = [0u8; 6];
        match self.kv.get(NS_MC_TIMER, SINGLETON_KEY, &mut buf) {
            Ok(Some(6)) => seq6_to_u64(&buf),
            _ => 0,
        }
    }

    /// Persist `value` (low 48 bits) as the new watermark.
    pub fn save(&mut self, value: u64) -> Result<(), S::Error> {
        self.kv.put(NS_MC_TIMER, SINGLETON_KEY, &u64_to_seq6(value))
    }

    /// Clear the watermark (factory reset). The next [`load`](Self::load) is 0.
    pub fn clear(&mut self) -> Result<(), S::Error> {
        self.kv.remove(NS_MC_TIMER, SINGLETON_KEY)
    }
}

impl<S: KeyValueStore> crate::storage::McTimerStoreBackend for McTimerStore<S> {
    type Error = S::Error;

    fn load(&self) -> u64 {
        McTimerStore::load(self)
    }
    fn save(&mut self, value: u64) -> Result<(), Self::Error> {
        McTimerStore::save(self, value)
    }
    fn clear(&mut self) -> Result<(), Self::Error> {
        McTimerStore::clear(self)
    }
}

// ============================================================================
// Host tests — a RAM KeyValueStore exercising the view (backend-agnostic part)
// ============================================================================
//
// The wear-levelled / verbatim flash backends and their crash/recovery tests
// live in `embedded-common` (they need the SectorIo seam + MockFlash). Here we
// test the view's logic over a trivial in-memory KeyValueStore so the SIAT
// semantics (sorted reads, set_count, clear, watermark) are covered in the core
// crate without a HAL.

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec as StdVec;

    use super::*;

    /// Minimal in-RAM KeyValueStore for view tests.
    #[derive(Default)]
    struct MemKv {
        // (ns, key, val) triples; last write wins (we overwrite in put).
        entries: StdVec<(u8, StdVec<u8>, StdVec<u8>)>,
    }

    impl KeyValueStore for MemKv {
        type Error = core::convert::Infallible;

        fn get(&self, ns: u8, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            for (n, k, v) in &self.entries {
                if *n == ns && k.as_slice() == key {
                    buf[..v.len()].copy_from_slice(v);
                    return Ok(Some(v.len()));
                }
            }
            Ok(None)
        }

        fn put(&mut self, ns: u8, key: &[u8], val: &[u8]) -> Result<(), Self::Error> {
            for (n, k, v) in &mut self.entries {
                if *n == ns && k.as_slice() == key {
                    *v = val.to_vec();
                    return Ok(());
                }
            }
            self.entries.push((ns, key.to_vec(), val.to_vec()));
            Ok(())
        }

        fn remove(&mut self, ns: u8, key: &[u8]) -> Result<(), Self::Error> {
            self.entries.retain(|(n, k, _)| !(*n == ns && k.as_slice() == key));
            Ok(())
        }

        fn for_each(&self, ns: u8, f: &mut dyn FnMut(&[u8], &[u8])) {
            for (n, k, v) in &self.entries {
                if *n == ns {
                    f(k, v);
                }
            }
        }
    }

    type TestStore = SiatStore<MemKv, 8, 4>;

    fn s6(v: u64) -> [u8; 6] {
        u64_to_seq6(v)
    }

    #[test]
    fn fresh_defaults() {
        let s = TestStore::boot(MemKv::default()).unwrap();
        assert_eq!(s.count(), 0);
        assert_eq!(s.load_sending(), DEFAULT_SENDING);
        assert_eq!(s.load_tool(), None);
        assert!(!s.contains(0x1101));
    }

    /// Elements land at the position the writer named and stay there —
    /// `index_of` reads back the 1-based `IA_Index` the Point-to-point Key
    /// Table refers to (03/05/01 §6.3.6.2), regardless of address order.
    #[test]
    fn entries_are_positional() {
        let mut s = TestStore::boot(MemKv::default()).unwrap();
        s.write_entry(0, 0x1103, s6(3)).unwrap();
        s.write_entry(1, 0x1101, s6(1)).unwrap();
        s.write_entry(2, 0x1102, s6(2)).unwrap();
        assert_eq!(s.count(), 3);
        assert_eq!(s.read_entry(0), Some((0x1103, s6(3))));
        assert_eq!(s.read_entry(1), Some((0x1101, s6(1))));
        assert_eq!(s.read_entry(2), Some((0x1102, s6(2))));
        assert_eq!(s.index_of(0x1103), Some(1));
        assert_eq!(s.index_of(0x1102), Some(3));
        assert_eq!(s.index_of(0x1104), None);
    }

    /// The TSSJ 3.3.4 shape: overwriting element 1 of a dirty table replaces
    /// exactly that element — even if the same IA already sits elsewhere —
    /// and the overwritten IA resolves to the position it was written at.
    #[test]
    fn positional_overwrite_replaces_the_named_element() {
        let mut s = TestStore::boot(MemKv::default()).unwrap();
        // 3.2.13 leftovers: {AFFD@1, AFFE@2}.
        s.write_entry(0, 0xAFFD, s6(3)).unwrap();
        s.write_entry(1, 0xAFFE, s6(1)).unwrap();
        // 3.3.4 writes element 1 := (AFFE, 1) without clearing.
        s.write_entry(0, 0xAFFE, s6(1)).unwrap();
        assert_eq!(s.count(), 2);
        assert_eq!(s.read_entry(0), Some((0xAFFE, s6(1))));
        assert_eq!(s.read_entry(1), Some((0xAFFE, s6(1))));
        // First match: IA_Index 1, which is where the P2P key was written.
        assert_eq!(s.index_of(0xAFFE), Some(1));
        assert_eq!(s.index_of(0xAFFD), None, "the overwritten IA is gone");
    }

    /// Writing past the current end extends the table, filling the gap with
    /// empty slots — the shape of a zeroed array-property segment.
    #[test]
    fn write_past_end_fills_gap() {
        let mut s = TestStore::boot(MemKv::default()).unwrap();
        s.write_entry(2, 0x1103, s6(3)).unwrap();
        assert_eq!(s.count(), 3);
        assert_eq!(s.read_entry(0), Some((0x0000, s6(0))));
        assert_eq!(s.read_entry(2), Some((0x1103, s6(3))));
        assert_eq!(s.index_of(0x1103), Some(3));
    }

    #[test]
    fn save_seq_updates_in_place_and_persists() {
        let mut s = TestStore::boot(MemKv::default()).unwrap();
        s.write_entry(0, 0x1101, s6(5)).unwrap();
        s.save_seq(0x1101, &s6(9)).unwrap();
        assert_eq!(s.count(), 1);
        assert_eq!(s.load_seq(0x1101), Some(s6(9)));
        // Reboot over the same backend: live value survives.
        let kv = s.kv;
        let s2 = TestStore::boot(kv).unwrap();
        assert_eq!(s2.load_seq(0x1101), Some(s6(9)));
        assert_eq!(s2.index_of(0x1101), Some(1), "position survives the reboot");
    }

    /// The receiving path never grows the table. An insert would invent an
    /// `IA_Index` no key table refers to.
    #[test]
    fn save_seq_ignores_unprovisioned_ia() {
        let mut s = TestStore::boot(MemKv::default()).unwrap();
        s.write_entry(0, 0x1102, s6(2)).unwrap();
        s.save_seq(0x1101, &s6(7)).unwrap();
        assert_eq!(s.count(), 1);
        assert_eq!(s.load_seq(0x1101), None);
        assert_eq!(s.index_of(0x1102), Some(1), "the provisioned entry keeps its IA_Index");
    }

    #[test]
    fn set_count_truncates_the_tail() {
        let mut s = TestStore::boot(MemKv::default()).unwrap();
        for (i, ia) in [0x1101u16, 0x1102, 0x1103].into_iter().enumerate() {
            s.write_entry(i as u16, ia, s6(ia as u64)).unwrap();
        }
        s.set_count(2).unwrap();
        assert_eq!(s.count(), 2);
        assert!(s.contains(0x1101));
        assert!(s.contains(0x1102));
        assert!(!s.contains(0x1103));
        // Persisted: reboot drops the truncated entry too.
        let s2 = TestStore::boot(s.kv).unwrap();
        assert!(!s2.contains(0x1103));
    }

    #[test]
    fn clear_empties_and_persists() {
        let mut s = TestStore::boot(MemKv::default()).unwrap();
        s.write_entry(0, 0x1101, s6(1)).unwrap();
        s.write_entry(1, 0x1102, s6(2)).unwrap();
        s.set_count(0).unwrap();
        assert_eq!(s.count(), 0);
        let s2 = TestStore::boot(s.kv).unwrap();
        assert_eq!(s2.count(), 0);
    }

    #[test]
    fn sending_watermark_batches_and_never_regresses() {
        // K = 4.
        let mut s = TestStore::boot(MemKv::default()).unwrap();
        for v in 1u64..=10 {
            s.save_sending(&s6(v + 1)); // mirror reserve_next_seq_nr: use v, persist v+1
            assert_eq!(s.load_sending(), s6(v + 1));
        }
        // Reboot: restored value is the watermark, strictly above the last used.
        let s2 = TestStore::boot(s.kv).unwrap();
        assert!(seq6_to_u64(&s2.load_sending()) >= 11);
    }

    #[test]
    fn tool_counter_roundtrips() {
        let mut s = TestStore::boot(MemKv::default()).unwrap();
        assert_eq!(s.load_tool(), None);
        s.save_tool(&s6(42)).unwrap();
        let s2 = TestStore::boot(s.kv).unwrap();
        assert_eq!(s2.load_tool(), Some(s6(42)));
    }

    #[test]
    fn full_table_drops_new_entries() {
        let mut s = TestStore::boot(MemKv::default()).unwrap();
        for i in 0..10u16 {
            // capacity 8; last two ignored
            s.write_entry(i, 0x1100 + i, s6(i as u64)).unwrap();
        }
        assert_eq!(s.count(), 8);
        assert!(s.contains(0x1107));
        assert!(!s.contains(0x1108));
    }

    /// The generic `McTimerStore` view round-trips the watermark through any
    /// backend (here the RAM `MemKv`): blank reads 0, save/load round-trips the
    /// low 48 bits, and clear resets to 0 — the same behaviour the RP flash
    /// backend gives, proving the view is backend-agnostic.
    #[test]
    fn mc_timer_view_roundtrips_over_any_backend() {
        let mut mc = McTimerStore::new(MemKv::default());
        assert_eq!(mc.load(), 0, "blank backend reads 0");

        mc.save(0x0000_1234_5678_9ABC).unwrap();
        // Only the low 48 bits are significant (the 6-byte counter).
        assert_eq!(mc.load(), 0x0000_1234_5678_9ABC & 0xFFFF_FFFF_FFFF);

        mc.clear().unwrap();
        assert_eq!(mc.load(), 0, "clear resets to 0");
    }
}
