//! The write-through configuration backend: a device state's persistent
//! sections in an [`NvStore`].
//!
//! [`NvConfig`] is what a device puts in its [`Storage`](crate::storage::Storage)'s
//! config slot. It is [`DeviceStorage`] with write-through, so the router
//! persists every change before the response to it leaves the device, and the storage task flushes after an erase code and
//! compacts the store when it asks. The store's medium decides the format:
//! [`ByteNv`](zweidraehte_nv::ByteNv) on a file, FRAM or shared memory,
//! [`FlashLog`](zweidraehte_nv::FlashLog) on erase-block flash. The sections
//! are applied at boot by [`NvConfig::load`].

use core::cell::RefCell;

use zweidraehte_nv::{Flusher, Loaded, NvError, NvStore};

use crate::sections::PersistentSections;
use crate::storage::definition::DeviceStorage;

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
    /// A backend over `store`, opened by [`DeviceStorage::load`].
    pub const fn new(store: N) -> Self {
        Self { store: RefCell::new(store), flusher: Flusher::new() }
    }
}

impl<N: NvStore, St: PersistentSections> DeviceStorage<St> for NvConfig<N>
where
    N::Error: core::fmt::Debug,
{
    const WRITE_THROUGH: bool = true;
    type Error = NvError<N::Error>;

    /// Boot: apply the durable sections to `state`, which must be
    /// factory-fresh, or format the medium with it (see [`NvStore::load`]).
    /// Call it once, after the stack is created and before its runner runs.
    fn load(&self, state: &St) -> Result<Loaded, Self::Error> {
        self.store.borrow_mut().load(state)
    }

    fn flush(&self, state: &St) -> Result<(), ()> {
        self.flusher.flush(state, &mut *self.store.borrow_mut()).map_err(|_| ())
    }

    fn needs_compaction(&self) -> bool {
        self.store.borrow().needs_compaction()
    }

    fn compact(&self, state: &St) -> Result<(), ()> {
        self.store.borrow_mut().compact(state).map_err(|_| ())
    }
}
