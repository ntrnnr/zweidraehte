//! The write-through configuration backend: a device state's persistent
//! sections in an [`NvStore`].
//!
//! [`NvConfig`] is what a device puts in its [`Storage`](crate::storage::Storage)'s
//! config slot. It is [`DeviceStorage`] with write-through, so the router
//! persists every change before the response to it leaves the device, and the storage task flushes after an erase code and
//! compacts the store when it asks. The store's medium decides the format:
//! [`ByteNv`](zweidraehte_nv::ByteNv) on a file, FRAM or shared memory,
//! [`FlashLog`] on erase-block flash ([`ConfigLog`]). The sections are
//! applied at boot by [`DeviceStorage::load`].

use core::cell::RefCell;

use zweidraehte_nv::{FlashLog, Flusher, Loaded, NvError, NvStore};

use crate::sections::PersistentSections;
use crate::storage::definition::{DeviceStorage, FlushError};

/// The longest padded record of a [`ConfigLog`].
///
/// A record carries at most 255 payload bytes behind 4 of framing, padded to
/// the medium's write granule, and `REC` must be whole granules: 256 is
/// valid on every medium up to 16-byte granules (the RP2040's 1, the
/// STM32G0's 8). It leaves 249 section bytes per record, so a single
/// A_Memory_Write (at most 63 bytes) fits one record and applies atomically
/// after a power cut (see [`FlashLog`]).
pub const CONFIG_LOG_REC: usize = 256;

/// The write-through configuration on erase-block flash: an [`NvConfig`] over
/// a [`FlashLog`] of [`CONFIG_LOG_REC`]-byte records. Open it over a
/// [`LogGeometry::two_banks`](zweidraehte_nv::LogGeometry::two_banks) area:
/// each bank must hold a whole snapshot of the state. The log header carries
/// the layout fingerprint, so another firmware's log reads as foreign.
pub type ConfigLog<Io> = NvConfig<FlashLog<Io, CONFIG_LOG_REC>>;

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

    fn flush(&self, state: &St) -> Result<(), FlushError> {
        self.flusher.flush(state, &mut *self.store.borrow_mut()).map_err(|error| match error {
            NvError::NeedsMaintenance => FlushError::Deferred,
            _ => FlushError::Failed,
        })
    }

    fn needs_compaction(&self) -> bool {
        self.store.borrow().needs_compaction()
    }

    fn compact(&self, state: &St) -> Result<(), ()> {
        self.store.borrow_mut().compact(state).map_err(|_| ())?;

        // The snapshot includes pending changes, including any Image range
        // whose earlier append was denied. Re-appending them could fill a
        // dense bank immediately after compaction.
        self.flusher.snapshot_committed(state);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use zweidraehte_nv::mock::{Backing, MockFlash};
    use zweidraehte_nv::{FlashLog, LogGeometry};

    use super::NvConfig;
    use crate::sections::{PersistentSections, Section, SectionError, SectionId, SectionKind, apply_image, read_image};
    use crate::storage::definition::{DeviceStorage, FlushError};

    const IMAGE: SectionId = 1;
    const GEOMETRY: LogGeometry = LogGeometry::two_banks(0, 2 * 4096, 4096);

    /// One Image whose tracked writes report their range, as a table does.
    #[derive(Default)]
    struct OneImage {
        bytes: RefCell<[u8; 32]>,
        dirty: RefCell<Option<(u16, u16)>>,
    }

    impl OneImage {
        fn write(&self, bytes: [u8; 32]) {
            *self.bytes.borrow_mut() = bytes;
            *self.dirty.borrow_mut() = Some((0, 32));
        }
    }

    impl PersistentSections for OneImage {
        fn for_each_section(&self, f: &mut impl FnMut(Section)) {
            f(Section { id: IMAGE, len: 32, kind: SectionKind::Image });
        }

        fn read_section(&self, _id: SectionId, offset: u16, buf: &mut [u8]) {
            read_image(&*self.bytes.borrow(), offset, buf);
        }

        fn apply_section(&self, _id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
            apply_image(&mut *self.bytes.borrow_mut(), offset, bytes)
        }

        fn reset_section(&self, _id: SectionId) {
            *self.bytes.borrow_mut() = [0; 32];
        }

        fn take_dirty_images(&self, f: &mut impl FnMut(SectionId, u16, u16)) {
            let range = self.dirty.borrow_mut().take();
            if let Some((offset, len)) = range {
                f(IMAGE, offset, len);
            }
        }
    }

    fn open(medium: &Backing) -> NvConfig<FlashLog<MockFlash<1>, 64>> {
        NvConfig::new(FlashLog::new(medium.open(), GEOMETRY))
    }

    /// A full bank is maintenance, not a medium failure. The compaction the
    /// storage task then runs makes the deferred change durable.
    #[test]
    fn a_full_flash_bank_defers_the_flush() {
        let medium = Backing::new(2 * 4096, 4096);
        let state = OneImage::default();
        let config = open(&medium);
        config.load(&state).expect("format");

        let mut round = 0u8;
        let error = loop {
            round = round.wrapping_add(1);
            state.write([round; 32]);

            if let Err(error) = config.flush(&state) {
                break error;
            }
        };

        assert_eq!(error, FlushError::Deferred);
        assert!(DeviceStorage::<OneImage>::needs_compaction(&config));

        config.compact(&state).expect("compact");
        assert_eq!(config.flush(&state), Ok(()));
        drop(config);

        let rebooted = OneImage::default();
        open(&medium).load(&rebooted).expect("reboot");
        assert_eq!(*rebooted.bytes.borrow(), [round; 32], "the deferred change was lost");
    }
}
