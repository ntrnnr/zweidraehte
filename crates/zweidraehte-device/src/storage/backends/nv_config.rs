//! The write-through configuration backend: a device state's persistent
//! sections in an [`NvStore`].
//!
//! [`NvConfig`] is what a device puts in its stores struct's config slot
//! (`ConfigStorage`, `SecureStorage`, `SecureIpStorage`). Its [`ConfigFlush`]
//! is enabled, so the router persists every change before the response to it
//! leaves the device, and the storage task flushes after an erase code and
//! compacts the store when it asks. The store's medium decides the format:
//! [`ByteNv`](zweidraehte_nv::ByteNv) on a file, FRAM or shared memory,
//! [`FlashLog`](zweidraehte_nv::FlashLog) on erase-block flash. The sections
//! are applied at boot by [`NvConfig::load`].

use core::cell::RefCell;

use zweidraehte_nv::{Flusher, Loaded, NvError, NvStore};

use crate::sections::PersistentSections;
use crate::storage::flush::ConfigFlush;

/// Write-through configuration storage in the store `N`.
///
/// The store is not tied to a state type: it reads and writes through
/// whichever state it is handed. That lets a device name its storage before
/// its state type exists, which a secure device's storage has to, because
/// the state's type is projected from the definition that names the storage.
pub struct NvConfig<N> {
    store: RefCell<N>,
    flusher: Flusher,
}

impl<N: NvStore> NvConfig<N> {
    /// A backend over `store`, opened by [`load`](Self::load).
    pub const fn new(store: N) -> Self {
        Self { store: RefCell::new(store), flusher: Flusher::new() }
    }

    /// Boot: apply the durable sections to `state`, which must be
    /// factory-fresh, or format the medium with it (see [`NvStore::load`]).
    /// Call it once, after the stack is created and before its runner runs.
    pub fn load<St: PersistentSections>(&self, state: &St) -> Result<Loaded, NvError<N::Error>> {
        self.store.borrow_mut().load(state)
    }
}

impl<N: NvStore, St: PersistentSections> ConfigFlush<St> for NvConfig<N> {
    const ENABLED: bool = true;

    fn flush_config(&self, state: &St) -> Result<(), ()> {
        self.flusher.flush(state, &mut *self.store.borrow_mut()).map_err(|_| ())
    }

    fn needs_compaction(&self) -> bool {
        self.store.borrow().needs_compaction()
    }

    fn compact(&self, state: &St) -> Result<(), ()> {
        self.store.borrow_mut().compact(state).map_err(|_| ())
    }
}
