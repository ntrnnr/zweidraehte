//! The write-through configuration backend: a device state's persistent
//! sections in an [`NvStore`].
//!
//! [`NvConfig`] is what a device hands its stores struct (`ConfigStorage`,
//! `SecureStorage`, `SecureIpStorage`) in place of a whole-config blob store.
//! Its [`ConfigFlush`] is enabled, so the router persists every change before
//! the response to it leaves the device. The store's medium decides the
//! format: [`ByteNv`](zweidraehte_nv::ByteNv) on a file, FRAM or shared
//! memory, [`FlashLog`](zweidraehte_nv::FlashLog) on erase-block flash.
//!
//! # The storage task
//!
//! The storage task still drives erase codes and restarts through
//! [`ConfigStoreBackend`], saving a "snapshot" afterwards. For this backend a
//! snapshot *is* the flush: it persists whatever the erase changed, and the
//! save that follows only reports whether that worked, so a failed flush
//! keeps the change pending instead of acknowledging it. There is never a
//! blob to load; the sections are applied at boot by [`NvConfig::load`].
// TODO: once the storage task persists through `ConfigFlush` directly, the
// `ConfigStoreBackend` adapter goes away (plans/CONFIG_STORAGE_PLAN.md).

use core::cell::RefCell;
use core::marker::PhantomData;

use zweidraehte_nv::{Flusher, Loaded, NvError, NvStore};

use crate::sections::PersistentSections;
use crate::storage::definition::ConfigStoreBackend;
use crate::storage::flush::ConfigFlush;

/// A flush of the pending configuration changes failed; they stay pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FlushFailed;

/// Write-through configuration storage for a device state `S` in the store
/// `N`.
pub struct NvConfig<N, S> {
    store: RefCell<N>,
    flusher: Flusher,
    _state: PhantomData<fn(&S)>,
}

impl<N: NvStore, S> NvConfig<N, S> {
    /// A backend over `store`, opened by [`load`](Self::load).
    pub const fn new(store: N) -> Self {
        Self { store: RefCell::new(store), flusher: Flusher::new(), _state: PhantomData }
    }

    /// Boot: apply the durable sections to `state`, which must be
    /// factory-fresh, or format the medium with it (see [`NvStore::load`]).
    /// Call it once, after the stack is created and before its runner runs.
    pub fn load<St: PersistentSections>(&self, state: &St) -> Result<Loaded, NvError<N::Error>> {
        self.store.borrow_mut().load(state)
    }

    /// Make every pending change of `state` durable.
    fn flush<St: PersistentSections>(&self, state: &St) -> Result<(), FlushFailed> {
        self.flusher.flush(state, &mut *self.store.borrow_mut()).map_err(|_| FlushFailed)
    }
}

impl<N: NvStore, S, St: PersistentSections> ConfigFlush<St> for NvConfig<N, S> {
    const ENABLED: bool = true;

    fn flush_config(&self, state: &St) -> Result<(), ()> {
        self.flush(state).map_err(|FlushFailed| ())
    }
}

impl<N: NvStore, S: PersistentSections> ConfigStoreBackend for NvConfig<N, S> {
    type State = S;
    /// Whether the flush the snapshot performed succeeded.
    type Config = Result<(), FlushFailed>;
    type Error = FlushFailed;

    fn snapshot(&self, state: &S) -> Self::Config {
        self.flush(state)
    }

    fn save(&mut self, config: &Self::Config) -> Result<(), FlushFailed> {
        *config
    }

    fn load(&mut self) -> Option<Self::Config> {
        None
    }
}
