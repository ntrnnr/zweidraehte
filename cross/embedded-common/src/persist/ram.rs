//! RAM-only [`KeyValueStore`] for lab bring-up.
//!
//! Holds entries in a [`Mirror`]; nothing is persisted, so all state is
//! **lost on power cycle**. That breaks cross-reboot replay protection — ETS
//! re-syncs via `S-A_Sync` after each reset, but a recorded ciphertext can be
//! replayed in the window before sync completes. Use a flash- or FRAM-backed
//! [`KeyValueStore`] in production.
//!
//! Wrap it in a typed view exactly like the durable backends, e.g.
//! `SiatStore<RamKv<N>, N, K>`, so bring-up and production share one code path.
//!
//! There is no medium-specific codec here: a `RamKv` *is* the bare [`Mirror`],
//! which is exactly what makes it the floor the durable backends build on.

use super::KeyValueStore;
use super::mirror::Mirror;

/// RAM-only key-value store holding up to `ENTRIES` records.
pub struct RamKv<const ENTRIES: usize = 16> {
    mirror: Mirror<ENTRIES>,
}

impl<const ENTRIES: usize> RamKv<ENTRIES> {
    pub const fn new() -> Self {
        Self { mirror: Mirror::new() }
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
        Ok(self.mirror.get_into(ns, key, buf))
    }

    fn put(&mut self, ns: u8, key: &[u8], val: &[u8]) -> Result<(), Self::Error> {
        self.mirror.upsert(ns, key, val);
        Ok(())
    }

    fn remove(&mut self, ns: u8, key: &[u8]) -> Result<(), Self::Error> {
        self.mirror.remove(ns, key);
        Ok(())
    }

    fn for_each(&self, ns: u8, f: &mut dyn FnMut(&[u8], &[u8])) {
        self.mirror.for_each(ns, f);
    }
}
