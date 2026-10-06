//! One state across a flash log and a byte medium: routing, failure and
//! retry, independent layouts, and compaction covering both halves.

use core::cell::RefCell;
use std::vec;
use std::vec::Vec;

use crate::mock::{Backing, MockBytes, MockFlash};
use crate::sections::{PersistentSections, Section, SectionError, SectionId, SectionKind, apply_image, read_image};
use crate::{ByteNv, FlashLog, Flusher, Loaded, LogGeometry, NvError, NvStore, Routes, SplitError, SplitNv};

// ============================================================================
// A state with a Record and an Image in each half
// ============================================================================

const TABLE_CONTROL: SectionId = 3;
const TABLE_DATA: SectionId = 8;
const PARAMS_CONTROL: SectionId = 0x10;
const PARAMS_DATA: SectionId = 0x11;

/// The parameters and their control Record live in the second store.
struct ParamsOnSecond;

impl Routes for ParamsOnSecond {
    const SECOND: &'static [SectionId] = &[PARAMS_CONTROL, PARAMS_DATA];
}

struct SplitState {
    table_control: RefCell<[u8; 4]>,
    table: RefCell<Vec<u8>>,
    params_control: RefCell<[u8; 4]>,
    params: RefCell<Vec<u8>>,
    dirty: RefCell<Vec<(SectionId, u16, u16)>>,
}

impl SplitState {
    /// Factory state; `params_len` varies the second half's layout.
    fn new(params_len: usize) -> Self {
        Self {
            table_control: RefCell::new([0; 4]),
            table: RefCell::new(vec![0; 64]),
            params_control: RefCell::new([0; 4]),
            params: RefCell::new(vec![0; params_len]),
            dirty: RefCell::new(Vec::new()),
        }
    }

    /// A tracked Image change, as a table write reports it.
    fn write_image(&self, id: SectionId, offset: u16, bytes: &[u8]) {
        self.apply_section(id, offset, bytes).expect("valid change");
        self.dirty.borrow_mut().push((id, offset, bytes.len() as u16));
    }

    fn snapshot(&self) -> [Vec<u8>; 4] {
        [
            self.table_control.borrow().to_vec(),
            self.table.borrow().clone(),
            self.params_control.borrow().to_vec(),
            self.params.borrow().clone(),
        ]
    }
}

impl PersistentSections for SplitState {
    fn for_each_section(&self, f: &mut impl FnMut(Section)) {
        f(Section { id: TABLE_CONTROL, len: 4, kind: SectionKind::Record });
        f(Section { id: TABLE_DATA, len: self.table.borrow().len() as u16, kind: SectionKind::Image });
        f(Section { id: PARAMS_CONTROL, len: 4, kind: SectionKind::Record });
        f(Section { id: PARAMS_DATA, len: self.params.borrow().len() as u16, kind: SectionKind::Image });
    }

    fn read_section(&self, id: SectionId, offset: u16, buf: &mut [u8]) {
        match id {
            TABLE_CONTROL => read_image(&*self.table_control.borrow(), offset, buf),
            TABLE_DATA => read_image(&self.table.borrow(), offset, buf),
            PARAMS_CONTROL => read_image(&*self.params_control.borrow(), offset, buf),
            PARAMS_DATA => read_image(&self.params.borrow(), offset, buf),
            _ => panic!("no such section"),
        }
    }

    fn apply_section(&self, id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
        match id {
            TABLE_CONTROL => apply_image(&mut *self.table_control.borrow_mut(), offset, bytes),
            TABLE_DATA => apply_image(&mut self.table.borrow_mut(), offset, bytes),
            PARAMS_CONTROL => apply_image(&mut *self.params_control.borrow_mut(), offset, bytes),
            PARAMS_DATA => apply_image(&mut self.params.borrow_mut(), offset, bytes),
            _ => Err(SectionError::UnknownSection),
        }
    }

    fn reset_section(&self, id: SectionId) {
        match id {
            TABLE_CONTROL => *self.table_control.borrow_mut() = [0; 4],
            TABLE_DATA => self.table.borrow_mut().fill(0),
            PARAMS_CONTROL => *self.params_control.borrow_mut() = [0; 4],
            PARAMS_DATA => self.params.borrow_mut().fill(0),
            _ => {}
        }
    }

    fn take_dirty_images(&self, f: &mut impl FnMut(SectionId, u16, u16)) {
        let ranges: Vec<_> = self.dirty.borrow_mut().drain(..).collect();
        for (id, offset, len) in ranges {
            f(id, offset, len);
        }
    }
}

// ============================================================================
// The two media
// ============================================================================

const FLASH_GEOMETRY: LogGeometry = LogGeometry { offset: 0, sector_size: 1024, sectors_per_bank: 1, banks: 2 };

type Store = SplitNv<FlashLog<MockFlash<1>, 64>, ByteNv<MockBytes>, ParamsOnSecond>;

struct Media {
    flash: Backing,
    bytes: Backing,
}

impl Media {
    fn new() -> Self {
        Self { flash: Backing::new(2 * 1024, 1024), bytes: Backing::new(512, 1) }
    }

    fn open(&self) -> Store {
        SplitNv::new(FlashLog::new(self.flash.open(), FLASH_GEOMETRY), ByteNv::new(self.bytes.open_bytes(), 0, 512))
    }

    /// A fresh state loaded from these media, as a reboot sees them.
    fn boot(&self, params_len: usize) -> (SplitState, Loaded) {
        let state = SplitState::new(params_len);
        let loaded = self.open().load(&state).expect("load");
        (state, loaded)
    }
}

/// Configure every section away from its factory value.
fn configure(state: &SplitState) {
    state.apply_section(TABLE_CONTROL, 0, &[1, 2, 3, 4]).expect("table control");
    state.write_image(TABLE_DATA, 0, &[0x11; 16]);
    state.apply_section(PARAMS_CONTROL, 0, &[5, 6, 7, 8]).expect("params control");
    state.write_image(PARAMS_DATA, 4, &[0x22; 8]);
}

// ============================================================================
// Tests
// ============================================================================

/// Every section survives a reboot, and each lives in the store its route
/// names: wiping one medium loses exactly that store's sections.
#[test]
fn sections_round_trip_in_their_routed_store() {
    let media = Media::new();
    let (state, loaded) = media.boot(32);
    assert_eq!(loaded, Loaded::Fresh);

    configure(&state);
    let configured = state.snapshot();
    let mut store = media.open();
    store.load(&SplitState::new(32)).expect("open");
    Flusher::new().flush(&state, &mut store).expect("flush");
    drop(store);

    let (rebooted, loaded) = media.boot(32);
    assert_eq!(loaded, Loaded::Restored);
    assert_eq!(rebooted.snapshot(), configured);

    // The parameters were on the byte medium: a blank one loses them only.
    let blank_bytes = Media { flash: media.flash.clone(), bytes: Backing::new(512, 1) };
    let (rebooted, loaded) = blank_bytes.boot(32);
    assert_eq!(loaded, Loaded::Restored);
    assert_eq!(rebooted.snapshot()[..2], configured[..2]);
    assert_eq!(rebooted.snapshot()[2..], SplitState::new(32).snapshot()[2..]);

    // And the table was in the flash log.
    let blank_flash = Media { flash: Backing::new(2 * 1024, 1024), bytes: media.bytes.clone() };
    let (rebooted, _) = blank_flash.boot(32);
    assert_eq!(rebooted.snapshot()[..2], SplitState::new(32).snapshot()[..2]);
    assert_eq!(rebooted.snapshot()[2..], configured[2..]);
}

/// A write failure in the second store fails the flush and keeps the change
/// pending; the next flush makes it durable.
#[test]
fn a_failed_second_store_keeps_the_change_pending() {
    let media = Media::new();
    let (state, _) = media.boot(32);
    let mut store = media.open();
    store.load(&SplitState::new(32)).expect("open");
    let flusher = Flusher::new();

    state.write_image(PARAMS_DATA, 0, &[0x33; 4]);
    media.bytes.set_failing(true);
    assert_eq!(flusher.flush(&state, &mut store), Err(NvError::Io(SplitError::Second(()))));

    media.bytes.set_failing(false);
    flusher.flush(&state, &mut store).expect("retry");
    drop(store);

    let (rebooted, _) = media.boot(32);
    assert_eq!(&rebooted.params.borrow()[..4], &[0x33; 4]);
}

/// A layout change in the second half boots that store fresh and leaves the
/// first store's sections restored.
#[test]
fn a_layout_change_in_one_store_leaves_the_other() {
    let media = Media::new();
    let (state, _) = media.boot(32);
    configure(&state);
    let configured = state.snapshot();
    let mut store = media.open();
    store.load(&SplitState::new(32)).expect("open");
    Flusher::new().flush(&state, &mut store).expect("flush");
    drop(store);

    let (rebooted, loaded) = media.boot(40);
    assert_eq!(loaded, Loaded::Restored);
    assert_eq!(rebooted.snapshot()[..2], configured[..2], "the first store's sections were lost");
    assert_eq!(rebooted.snapshot()[2..], SplitState::new(40).snapshot()[2..]);
}

/// When the flash log defers a write, compaction makes the whole state
/// durable on both media, including the second store's change the deferred
/// flush never reached.
#[test]
fn compaction_makes_both_stores_durable() {
    let media = Media::new();
    let (state, _) = media.boot(32);
    let mut store = media.open();
    store.load(&SplitState::new(32)).expect("open");
    let flusher = Flusher::new();

    let mut round = 0u8;
    loop {
        round = round.wrapping_add(1);
        state.write_image(TABLE_DATA, 0, &[round; 16]);
        state.write_image(PARAMS_DATA, 0, &[round; 4]);

        match flusher.flush(&state, &mut store) {
            Ok(()) => {}
            Err(NvError::NeedsMaintenance) => break,
            Err(error) => panic!("unexpected flush error: {error:?}"),
        }
    }

    assert!(store.needs_compaction());
    store.compact(&state).expect("compact");
    flusher.snapshot_committed(&state);
    drop(store);

    let (rebooted, _) = media.boot(32);
    assert_eq!(&rebooted.table.borrow()[..16], &[round; 16]);
    assert_eq!(&rebooted.params.borrow()[..4], &[round; 4], "the second store's pending change was lost");
}
