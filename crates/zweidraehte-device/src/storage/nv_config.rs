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

    use super::{CONFIG_LOG_REC, NvConfig};
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

    // ========================================================================
    // Sparse downloads
    // ========================================================================
    //
    // A client that writes every second byte of a table sends one
    // A_Memory_Write per byte, and the router flushes after each, so every
    // byte becomes its own log record: `[id][offset BE][byte]` plus 4 octets
    // of framing, one 8-byte doubleword on the STM32G0. Nothing coalesces
    // across dispatches, so such a download costs eight times the table's
    // size in log space. That is wear, not growth: a bank is fixed, the
    // layout check guarantees a snapshot plus one record fits it, and a
    // compaction therefore always makes room for the next write.

    /// The shipped STM32G0 config area: 16 KiB in two banks of 2 KiB sectors.
    const STM32_GEOMETRY: LogGeometry = LogGeometry::two_banks(0, 16 * 1024, 2048);
    const STM32_LEN: usize = 16 * 1024;
    const STM32_SECTOR: usize = 2048;

    /// A table image large enough that a sparse pass outgrows several banks.
    const SPARSE_LEN: usize = 4096;

    /// Log bytes one sparse write costs on a doubleword-programmed medium.
    const SPARSE_RECORD: usize = 8;

    type StmConfig = NvConfig<FlashLog<MockFlash<8>, CONFIG_LOG_REC>>;

    /// One table-sized Image whose tracked writes queue their range, as
    /// a table's A_Memory_Write does.
    struct SparseImage {
        bytes: RefCell<std::vec::Vec<u8>>,
        dirty: RefCell<std::vec::Vec<(u16, u16)>>,
    }

    impl SparseImage {
        fn new() -> Self {
            Self { bytes: RefCell::new(std::vec![0; SPARSE_LEN]), dirty: RefCell::new(std::vec::Vec::new()) }
        }

        fn write(&self, offset: u16, value: u8) {
            self.bytes.borrow_mut()[usize::from(offset)] = value;
            self.dirty.borrow_mut().push((offset, 1));
        }
    }

    impl PersistentSections for SparseImage {
        fn for_each_section(&self, f: &mut impl FnMut(Section)) {
            f(Section { id: IMAGE, len: SPARSE_LEN as u16, kind: SectionKind::Image });
        }

        fn read_section(&self, _id: SectionId, offset: u16, buf: &mut [u8]) {
            read_image(&self.bytes.borrow(), offset, buf);
        }

        fn apply_section(&self, _id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
            apply_image(&mut self.bytes.borrow_mut(), offset, bytes)
        }

        fn reset_section(&self, _id: SectionId) {
            self.bytes.borrow_mut().fill(0);
        }

        fn take_dirty_images(&self, f: &mut impl FnMut(SectionId, u16, u16)) {
            let ranges: std::vec::Vec<_> = self.dirty.borrow_mut().drain(..).collect();
            for (offset, len) in ranges {
                f(IMAGE, offset, len);
            }
        }
    }

    fn open_stm(medium: &Backing) -> StmConfig {
        NvConfig::new(FlashLog::new(medium.open_aligned(), STM32_GEOMETRY))
    }

    /// The image a reboot would restore, read from a copy of the medium so
    /// the running store keeps its own view.
    fn durable_image(medium: &Backing) -> std::vec::Vec<u8> {
        let copy = Backing::new(STM32_LEN, STM32_SECTOR);
        copy.poke(0, &medium.bytes());

        let rebooted = SparseImage::new();
        open_stm(&copy).load(&rebooted).expect("reboot");

        rebooted.bytes.into_inner()
    }

    /// The storage task's maintenance arm, which a flush wakes whenever the
    /// store asks: compact under the guard. Returns whether it compacted.
    fn maintain(config: &StmConfig, state: &SparseImage) -> bool {
        if !DeviceStorage::<SparseImage>::needs_compaction(config) {
            return false;
        }

        config.compact(state).expect("guarded compaction");

        true
    }

    /// Flush one dispatch and check that it erased nothing: erases belong to
    /// guarded maintenance, never to the router's dispatch path.
    fn dispatch(
        config: &StmConfig,
        state: &SparseImage,
        medium: &Backing,
        offset: u16,
        value: u8,
    ) -> Result<(), FlushError> {
        state.write(offset, value);

        let erases = medium.erases();
        let result = config.flush(state);
        assert_eq!(medium.erases(), erases, "a dispatch flush erased flash");

        result
    }

    /// The byte a pass writes at `offset`: distinct per pass and offset, and
    /// never the factory zero, so a lost write shows.
    fn sparse_value(pass: u8, offset: u16) -> u8 {
        (offset as u8).wrapping_mul(31).wrapping_add(pass) | 1
    }

    /// Two every-second-byte passes over a 4 KiB table on the STM32 area
    /// stay inside the bank, erase only under maintenance, and lose nothing.
    ///
    /// The snapshot takes 4232 bytes of each 8 KiB bank, so maintenance
    /// starts after 371 one-byte records and the two passes of 2048 writes
    /// cost 11 compactions. Every compaction reclaims at least the
    /// threshold's worth of history, which bounds the wear.
    #[test]
    fn sparse_download_stays_bounded_and_durable() {
        let medium = Backing::new(STM32_LEN, STM32_SECTOR);
        let state = SparseImage::new();
        let config = open_stm(&medium);
        config.load(&state).expect("format");

        // The format wrote one snapshot and nothing else, so its size is
        // what a compaction can never reclaim.
        let snapshot = medium.bytes_written();
        let threshold = (STM32_GEOMETRY.bank_size() as usize - snapshot) / 4 * 3;

        let mut writes = 0;
        let mut compactions = 0;

        for (pass, first) in [(1u8, 0u16), (2, 1)] {
            for offset in (first..SPARSE_LEN as u16).step_by(2) {
                // The flush that crosses the threshold wakes the storage
                // task, which compacts before the next write arrives, so the
                // quarter bank left above the threshold never fills.
                dispatch(&config, &state, &medium, offset, sparse_value(pass, offset))
                    .expect("a sparse write was not admitted");
                writes += 1;

                if maintain(&config, &state) {
                    compactions += 1;
                    assert_eq!(durable_image(&medium), *state.bytes.borrow(), "a compaction lost data");
                }
            }
        }

        assert_eq!(durable_image(&medium), *state.bytes.borrow(), "the download was not durable");
        assert!(compactions > 0, "the download never reached maintenance");
        assert!(
            compactions <= writes * SPARSE_RECORD / threshold + 1,
            "{compactions} compactions for {writes} sparse writes exceed the wear bound"
        );
        assert_eq!(medium.erases(), compactions + 1, "an erase ran outside the format and maintenance");
    }

    /// If the storage task cannot run before the bank fills (a burst of
    /// writes faster than it is scheduled), the full bank defers the write:
    /// every write still becomes durable after the compaction, and the next
    /// write is admitted.
    #[test]
    fn sparse_download_survives_a_full_bank_before_maintenance() {
        let medium = Backing::new(STM32_LEN, STM32_SECTOR);
        let state = SparseImage::new();
        let config = open_stm(&medium);
        config.load(&state).expect("format");

        let mut deferrals = 0;
        let mut offsets = (0..SPARSE_LEN as u16).step_by(2);

        while let Some(offset) = offsets.next() {
            match dispatch(&config, &state, &medium, offset, sparse_value(1, offset)) {
                Ok(()) => {}
                Err(FlushError::Deferred) => {
                    deferrals += 1;

                    // A dispatch that lands before the guard is raised
                    // defers too: the bank stays closed until the
                    // compaction, and nothing erases in between.
                    if let Some(raced) = offsets.next() {
                        let result = dispatch(&config, &state, &medium, raced, sparse_value(1, raced));
                        assert_eq!(result, Err(FlushError::Deferred), "a full bank admitted a write");
                    }

                    assert!(maintain(&config, &state), "a deferral did not request compaction");
                    assert_eq!(durable_image(&medium), *state.bytes.borrow(), "a deferred write was lost");
                }
                Err(FlushError::Failed) => panic!("a sparse write failed on a healthy medium"),
            }
        }

        assert!(deferrals > 0, "the download never filled a bank");
        assert_eq!(durable_image(&medium), *state.bytes.borrow(), "the download was not durable");
    }
}
