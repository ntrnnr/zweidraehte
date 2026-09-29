//! Typed views over the [`KeyValueStore`] seam.
//!
//! [`McTimerStore`] is the IP-Secure multicast-timer watermark (03/08/09
//! §2.2.4.2). The Data Secure sequence state — [`SiatStore`] for flash, the
//! packed byte-medium store for FRAM and shared memory — lives in
//! `zweidraehte-nv`, where the micro stack can use it too, and is re-exported
//! here.
//!
//! The seam itself — [`KeyValueStore`], the namespaces, the seq codec helpers —
//! lives in [`kv`](super::kv); the backends implementing it live in
//! [`backends`](super::backends).

pub use zweidraehte_nv::SiatStore;
pub use zweidraehte_proto::security::SiatAccess;

use crate::storage::kv::{KeyValueStore, NS_MC_TIMER, SINGLETON_KEY, seq6_to_u64, u64_to_seq6};

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
// Host tests — a RAM KeyValueStore exercising the view
// ============================================================================
//
// The SIAT views and their suite live in `zweidraehte-nv`. Here the mc_timer
// view runs over a trivial in-memory KeyValueStore.

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
