//! Both configuration stores against one suite: round trips, fresh media,
//! layout changes, and a power cut at every programmed byte of a download.

use core::cell::RefCell;
use std::vec;
use std::vec::Vec;

use crate::mock::{Backing, MockFlash};
use crate::sections::{
    PersistentSections, Section, SectionError, SectionId, SectionKind, apply_image, read_image, whole_record,
};
use crate::{ByteNv, FlashLog, Flusher, Loaded, LogGeometry, NvError, NvStore};

// ============================================================================
// A test state
// ============================================================================

const REC_SMALL: SectionId = 1;
const REC_LARGE: SectionId = 2;
const IMG_LARGE: SectionId = 5;
const IMG_SMALL: SectionId = 6;

/// Two Records and two Images. A Record is valid when its last byte is the
/// XOR of the others, so a torn mix of two records is (almost always)
/// rejected, the way a real Record's validation rejects nonsense.
struct TestState {
    small: RefCell<[u8; 4]>,
    large: RefCell<[u8; 40]>,
    image: RefCell<Vec<u8>>,
    tiny: RefCell<[u8; 20]>,
    /// Image ranges changed through [`TestState::write`], for the flusher.
    dirty: RefCell<Vec<(SectionId, u16, u16)>>,
}

impl TestState {
    /// Factory state; `image_len` varies the layout for fingerprint tests.
    fn new(image_len: usize) -> Self {
        Self {
            small: RefCell::new([0; 4]),
            large: RefCell::new([0; 40]),
            image: RefCell::new(vec![0; image_len]),
            tiny: RefCell::new([0; 20]),
            dirty: RefCell::new(Vec::new()),
        }
    }

    /// A tracked change: apply `bytes` and remember the range if the
    /// section is an Image, as a real state's table owner does.
    fn write(&self, id: SectionId, offset: u16, bytes: &[u8]) {
        self.apply_section(id, offset, bytes).expect("valid change");
        if id == IMG_LARGE || id == IMG_SMALL {
            self.dirty.borrow_mut().push((id, offset, bytes.len() as u16));
        }
    }

    fn snapshot(&self) -> Vec<Vec<u8>> {
        vec![
            self.small.borrow().to_vec(),
            self.large.borrow().to_vec(),
            self.image.borrow().clone(),
            self.tiny.borrow().to_vec(),
        ]
    }
}

fn valid_record(bytes: &[u8]) -> bool {
    let (body, check) = bytes.split_at(bytes.len() - 1);
    body.iter().fold(0, |x, b| x ^ b) == check[0]
}

impl PersistentSections for TestState {
    fn for_each_section(&self, f: &mut impl FnMut(Section)) {
        f(Section { id: REC_SMALL, len: 4, kind: SectionKind::Record });
        f(Section { id: REC_LARGE, len: 40, kind: SectionKind::Record });
        f(Section { id: IMG_LARGE, len: self.image.borrow().len() as u16, kind: SectionKind::Image });
        f(Section { id: IMG_SMALL, len: 20, kind: SectionKind::Image });
    }

    fn read_section(&self, id: SectionId, offset: u16, buf: &mut [u8]) {
        match id {
            REC_SMALL => read_image(&*self.small.borrow(), offset, buf),
            REC_LARGE => read_image(&*self.large.borrow(), offset, buf),
            IMG_LARGE => read_image(&self.image.borrow(), offset, buf),
            IMG_SMALL => read_image(&*self.tiny.borrow(), offset, buf),
            _ => panic!("no such section"),
        }
    }

    fn apply_section(&self, id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
        match id {
            REC_SMALL => {
                let record = whole_record::<4>(offset, bytes)?;
                valid_record(record).then(|| *self.small.borrow_mut() = *record).ok_or(SectionError::Malformed)
            }
            REC_LARGE => {
                let record = whole_record::<40>(offset, bytes)?;
                valid_record(record).then(|| *self.large.borrow_mut() = *record).ok_or(SectionError::Malformed)
            }
            IMG_LARGE => apply_image(&mut self.image.borrow_mut(), offset, bytes),
            IMG_SMALL => apply_image(&mut *self.tiny.borrow_mut(), offset, bytes),
            _ => Err(SectionError::UnknownSection),
        }
    }

    fn take_dirty_images(&self, f: &mut impl FnMut(SectionId, u16, u16)) {
        let ranges: Vec<_> = self.dirty.borrow_mut().drain(..).collect();
        for (id, offset, len) in ranges {
            f(id, offset, len);
        }
    }

    fn reset_section(&self, id: SectionId) {
        match id {
            REC_SMALL => *self.small.borrow_mut() = [0; 4],
            REC_LARGE => *self.large.borrow_mut() = [0; 40],
            IMG_LARGE => self.image.borrow_mut().fill(0),
            IMG_SMALL => *self.tiny.borrow_mut() = [0; 20],
            _ => {}
        }
    }
}

// ============================================================================
// A scripted download
// ============================================================================

/// One configuration change: new bytes for a range of a section.
#[derive(Clone)]
struct Op {
    id: SectionId,
    offset: u16,
    bytes: Vec<u8>,
}

impl Op {
    fn apply(&self, state: &TestState) {
        state.apply_section(self.id, self.offset, &self.bytes).expect("scripted op is valid");
    }

    /// Apply the change to `state` and persist it.
    fn run<N: NvStore>(&self, state: &TestState, store: &mut N) -> Result<(), NvError<N::Error>> {
        self.apply(state);
        store.persist(state, self.id, self.offset, self.bytes.len() as u16)
    }
}

/// A record of `len` bytes derived from `seed`, with a valid check byte.
fn record(len: usize, seed: u8) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..len - 1).map(|i| seed.wrapping_mul(31).wrapping_add(i as u8)).collect();
    bytes.push(bytes.iter().fold(0, |x, b| x ^ b));
    bytes
}

/// Records and image ranges of every size class, repeated enough to force
/// several compactions of a small flash log.
fn script() -> Vec<Op> {
    let mut ops = Vec::new();
    for round in 0..6u8 {
        ops.push(Op { id: REC_SMALL, offset: 0, bytes: record(4, round) });
        ops.push(Op { id: IMG_LARGE, offset: 17, bytes: (0..150).map(|i| round ^ i as u8).collect() });
        ops.push(Op { id: REC_LARGE, offset: 0, bytes: record(40, round.wrapping_add(100)) });
        ops.push(Op { id: IMG_SMALL, offset: 3, bytes: vec![round + 1; 9] });
        ops.push(Op { id: IMG_LARGE, offset: 280, bytes: vec![round ^ 0x5A; 20] });
    }
    ops
}

// ============================================================================
// Backends under test
// ============================================================================

/// A backend: how to make its medium and open a store over it.
trait Backend {
    type Store: NvStore<Error = ()>;
    /// Largest bytes per flash record, or `None` on byte media.
    const CHUNK: Option<usize>;
    fn medium() -> Backing;
    fn open(medium: &Backing) -> Self::Store;
}

struct Bytes;

impl Backend for Bytes {
    type Store = ByteNv<crate::mock::MockBytes>;
    const CHUNK: Option<usize> = None;
    fn medium() -> Backing {
        Backing::new(1024, 1)
    }
    fn open(medium: &Backing) -> Self::Store {
        ByteNv::new(medium.open_bytes(), 0, 1024)
    }
}

/// A flash log with small records, so the 150-byte range spans three.
struct Flash;

const FLASH_GEOMETRY: LogGeometry = LogGeometry { offset: 0, sector_size: 1024, sectors_per_bank: 1, banks: 3 };

impl Backend for Flash {
    type Store = FlashLog<MockFlash<1>, 64>;
    const CHUNK: Option<usize> = Some(60 - 3);
    fn medium() -> Backing {
        Backing::new(3 * 1024, 1024)
    }
    fn open(medium: &Backing) -> Self::Store {
        FlashLog::new(medium.open_aligned(), FLASH_GEOMETRY)
    }
}

/// A doubleword flash (STM32G0) with the production record size.
struct FlashDoubleword;

const DOUBLEWORD_GEOMETRY: LogGeometry = LogGeometry { offset: 0, sector_size: 2048, sectors_per_bank: 1, banks: 2 };

impl Backend for FlashDoubleword {
    type Store = FlashLog<MockFlash<8>, 264>;
    const CHUNK: Option<usize> = Some(257 - 3);
    fn medium() -> Backing {
        Backing::new(2 * 2048, 2048)
    }
    fn open(medium: &Backing) -> Self::Store {
        FlashLog::new(medium.open_aligned(), DOUBLEWORD_GEOMETRY)
    }
}

/// Boot a fresh state from the medium.
fn boot<B: Backend>(medium: &Backing) -> (TestState, B::Store, Loaded) {
    let state = TestState::new(300);
    let mut store = B::open(medium);
    let loaded = store.load(&state).expect("load");
    (state, store, loaded)
}

/// Index of a section in `TestState::snapshot`.
fn slot(id: SectionId) -> usize {
    match id {
        REC_SMALL => 0,
        REC_LARGE => 1,
        IMG_LARGE => 2,
        IMG_SMALL => 3,
        _ => unreachable!(),
    }
}

// ============================================================================
// The suite
// ============================================================================

fn round_trip<B: Backend>() {
    let medium = B::medium();
    let (state, mut store, loaded) = boot::<B>(&medium);
    assert_eq!(loaded, Loaded::Fresh);
    for op in script() {
        op.run(&state, &mut store).expect("persist");
    }
    let expected = state.snapshot();
    drop(store);

    let (state, _, loaded) = boot::<B>(&medium);
    assert_eq!(loaded, Loaded::Restored);
    assert_eq!(state.snapshot(), expected);
}

/// A blank medium boots fresh and then holds the factory state; the same
/// medium under another layout boots fresh instead of misreading it.
fn fresh_and_layout_change<B: Backend>() {
    let medium = B::medium();
    let (state, store, loaded) = boot::<B>(&medium);
    assert_eq!(loaded, Loaded::Fresh);
    drop(store);
    let (_, _, loaded) = boot::<B>(&medium);
    assert_eq!(loaded, Loaded::Restored, "a fresh load leaves a valid medium");

    let mut store = B::open(&medium);
    store.load(&state).expect("load");
    Op { id: REC_SMALL, offset: 0, bytes: record(4, 9) }.run(&state, &mut store).expect("persist");
    drop(store);

    let other = TestState::new(280);
    let loaded = B::open(&medium).load(&other).expect("load under another layout");
    assert_eq!(loaded, Loaded::Fresh);
    assert_eq!(other.snapshot(), TestState::new(280).snapshot(), "bytes of another layout were applied");
}

/// The content a section may hold after a cut during `op`: its old value,
/// its new value, or a prefix of its writes applied.
fn allowed_after_cut<B: Backend>(op: &Op, old: &[u8], new: &[u8], kind: SectionKind) -> Vec<Vec<u8>> {
    let mut allowed = vec![old.to_vec(), new.to_vec()];
    if kind == SectionKind::Image {
        let chunk = B::CHUNK.unwrap_or(1);
        let mut partial = old.to_vec();
        for start in (0..op.bytes.len()).step_by(chunk) {
            let end = (start + chunk).min(op.bytes.len());
            let at = usize::from(op.offset);
            partial[at + start..at + end].copy_from_slice(&op.bytes[start..end]);
            allowed.push(partial.clone());
        }
    }
    allowed
}

/// Cut power after every programmed byte of load + download, reboot, and
/// check each section; then prove a write after the reboot is durable.
fn power_cut_sweep<B: Backend>() {
    let ops = script();

    // A clean run: the state after each op, and the bytes programmed.
    let clean = B::medium();
    let (state, mut store, _) = boot::<B>(&clean);
    let mut states = vec![state.snapshot()];
    for op in &ops {
        op.run(&state, &mut store).expect("persist");
        states.push(state.snapshot());
    }
    let total = clean.bytes_written();

    for budget in 0..total {
        let medium = B::medium();
        medium.cut_power_after(budget);

        let state = TestState::new(300);
        let mut store = B::open(&medium);
        store.load(&state).expect("load");
        let lost_in_load = medium.power_lost();

        let mut completed = 0;
        if !lost_in_load {
            for op in &ops {
                op.run(&state, &mut store).expect("persist");
                if medium.power_lost() {
                    break;
                }
                completed += 1;
            }
        }
        drop(store);
        medium.restore_power();

        let (rebooted, mut store, _) = boot::<B>(&medium);
        let recovered = rebooted.snapshot();

        if lost_in_load {
            assert_eq!(recovered, states[0], "budget {budget}: a cut while loading must leave the factory state");
        } else if completed < ops.len() {
            let op = &ops[completed];
            for (index, section) in recovered.iter().enumerate() {
                if index == slot(op.id) {
                    let kind =
                        if op.id == IMG_LARGE || op.id == IMG_SMALL { SectionKind::Image } else { SectionKind::Record };
                    let allowed =
                        allowed_after_cut::<B>(op, &states[completed][index], &states[completed + 1][index], kind);
                    assert!(allowed.contains(section), "budget {budget}: interrupted section {} is torn", op.id);
                } else {
                    assert_eq!(section, &states[completed][index], "budget {budget}: section {index} changed");
                }
            }
        }

        // A write after the reboot is durable too.
        let later = Op { id: REC_LARGE, offset: 0, bytes: record(40, 77) };
        later.run(&rebooted, &mut store).expect("persist after reboot");
        let expected = rebooted.snapshot();
        drop(store);
        let (again, _, _) = boot::<B>(&medium);
        assert_eq!(again.snapshot(), expected, "budget {budget}: a write after recovery was lost");
    }
}

/// The flusher finds changed Records by comparing with the store, and
/// persists only the Image ranges the state reported.
fn flusher_persists_what_changed<B: Backend>() {
    let medium = B::medium();
    let (state, mut store, _) = boot::<B>(&medium);
    let flusher = Flusher::new();

    // Nothing changed: a flush writes nothing.
    let before = medium.bytes_written();
    flusher.flush(&state, &mut store).expect("flush");
    assert_eq!(medium.bytes_written(), before, "an idle flush programmed bytes");

    // Records change without telling anyone; images through the tracker.
    state.apply_section(REC_LARGE, 0, &record(40, 3)).expect("record");
    state.write(IMG_LARGE, 100, &[7; 30]);
    state.write(IMG_SMALL, 0, &[9; 20]);
    flusher.flush(&state, &mut store).expect("flush");
    assert!(store.record_matches(&state, REC_LARGE).expect("compare"));
    assert!(store.record_matches(&state, REC_SMALL).expect("compare"));
    let expected = state.snapshot();
    drop(store);

    let (rebooted, _, _) = boot::<B>(&medium);
    assert_eq!(rebooted.snapshot(), expected);
}

/// A flush that fails part-way loses the ranges it took; the next one
/// persists every Image whole, so nothing is lost.
fn flusher_resyncs_after_a_failed_flush<B: Backend>() {
    let medium = B::medium();
    let (state, mut store, _) = boot::<B>(&medium);
    let flusher = Flusher::new();

    state.write(IMG_LARGE, 10, &[5; 40]);
    medium.set_failing(true);
    assert!(flusher.flush(&state, &mut store).is_err());
    medium.set_failing(false);

    // No new change is reported; only the resync can save the range.
    flusher.flush(&state, &mut store).expect("flush");
    let expected = state.snapshot();
    drop(store);

    let (rebooted, _, _) = boot::<B>(&medium);
    assert_eq!(rebooted.snapshot(), expected);
}

macro_rules! suite {
    ($($backend:ident => $module:ident),* $(,)?) => {
        $(
            mod $module {
                #[test]
                fn flusher_persists_what_changed() {
                    super::flusher_persists_what_changed::<super::$backend>();
                }
                #[test]
                fn flusher_resyncs_after_a_failed_flush() {
                    super::flusher_resyncs_after_a_failed_flush::<super::$backend>();
                }
                #[test]
                fn round_trip() {
                    super::round_trip::<super::$backend>();
                }
                #[test]
                fn fresh_and_layout_change() {
                    super::fresh_and_layout_change::<super::$backend>();
                }
                #[test]
                fn power_cut_sweep() {
                    super::power_cut_sweep::<super::$backend>();
                }
            }
        )*
    };
}

suite!(Bytes => byte_nv, Flash => flash_log, FlashDoubleword => flash_log_doubleword);

// ============================================================================
// Backend specifics
// ============================================================================

/// If the newest copy of a Record is corrupt, the older copy wins.
#[test]
fn byte_nv_corrupt_newest_record_falls_back() {
    let medium = Bytes::medium();
    let (state, mut store, _) = boot::<Bytes>(&medium);
    let first = record(4, 1);
    Op { id: REC_SMALL, offset: 0, bytes: first.clone() }.run(&state, &mut store).expect("persist");
    Op { id: REC_SMALL, offset: 0, bytes: record(4, 2) }.run(&state, &mut store).expect("persist");
    drop(store);

    // Formatting wrote generation 0 to slot 0; the two persists went to
    // slot 1 (generation 1) and slot 0 (generation 2). Corrupt slot 0.
    let slot0 = 10;
    let byte = medium.bytes()[slot0 + 2];
    medium.poke(slot0 + 2, &[byte ^ 0xFF]);

    let (state, _, _) = boot::<Bytes>(&medium);
    assert_eq!(&state.small.borrow()[..], &first[..]);
}

/// A bad private Image CRC does not discard bytes or make a later
/// partial update lose untouched bytes.
#[test]
fn byte_nv_restores_image_bytes_despite_bad_crc() {
    let medium = Bytes::medium();
    let (state, mut store, _) = boot::<Bytes>(&medium);
    Op { id: IMG_LARGE, offset: 0, bytes: vec![7; 300] }.run(&state, &mut store).expect("persist image");
    drop(store);

    let image_at = 10 + 2 * (1 + 4 + 2) + 2 * (1 + 40 + 2);
    medium.poke(image_at, &[9]);
    let (state, mut store, loaded) = boot::<Bytes>(&medium);
    assert_eq!(loaded, Loaded::Restored);
    assert_eq!(state.image.borrow()[0], 9);
    assert_eq!(state.image.borrow()[1], 7);

    Op { id: IMG_LARGE, offset: 1, bytes: vec![42] }.run(&state, &mut store).expect("persist partial update");
    drop(store);

    let (state, _, _) = boot::<Bytes>(&medium);
    assert_eq!(state.image.borrow()[0], 9);
    assert_eq!(state.image.borrow()[1], 42);
    assert_eq!(state.image.borrow()[2], 7);
}

#[test]
fn byte_nv_rejects_a_layout_larger_than_the_medium() {
    let medium = Backing::new(64, 1);
    let mut store = ByteNv::new(medium.open_bytes(), 0, 64);
    assert_eq!(store.load(&TestState::new(300)), Err(NvError::LayoutTooLarge));
}

/// A boot that finds the active bank above the threshold compacts it.
#[test]
fn flash_log_boot_compacts_above_threshold() {
    let medium = Flash::medium();
    let (state, mut store, _) = boot::<Flash>(&medium);
    let op = Op { id: IMG_SMALL, offset: 0, bytes: vec![1; 20] };
    while !store.needs_compaction() {
        op.run(&state, &mut store).expect("persist");
    }
    drop(store);

    let (_, store, loaded) = boot::<Flash>(&medium);
    assert_eq!(loaded, Loaded::Restored);
    assert!(!store.needs_compaction(), "the boot left the bank above the threshold");
}

#[test]
fn flash_log_rejects_records_and_snapshots_that_do_not_fit() {
    // 40-byte Record in 32-byte log records.
    let medium = Flash::medium();
    let mut store = FlashLog::<MockFlash<1>, 32>::new(medium.open_aligned(), FLASH_GEOMETRY);
    assert_eq!(store.load(&TestState::new(300)), Err(NvError::LayoutTooLarge));

    // A snapshot larger than a 1 KiB bank.
    let mut store = FlashLog::<MockFlash<1>, 64>::new(medium.open_aligned(), FLASH_GEOMETRY);
    assert_eq!(store.load(&TestState::new(1000)), Err(NvError::LayoutTooLarge));
}

/// Compaction moves every Record; the index follows, so comparisons stay
/// exact afterwards.
#[test]
fn flash_log_record_index_follows_compaction() {
    let medium = Flash::medium();
    let (state, mut store, _) = boot::<Flash>(&medium);
    Op { id: REC_SMALL, offset: 0, bytes: record(4, 4) }.run(&state, &mut store).expect("persist");

    let image = Op { id: IMG_SMALL, offset: 0, bytes: vec![2; 20] };
    while !store.needs_compaction() {
        image.run(&state, &mut store).expect("persist");
    }
    store.compact(&state).expect("compact");

    assert!(store.record_matches(&state, REC_SMALL).expect("compare"));
    assert!(store.record_matches(&state, REC_LARGE).expect("compare"));
    state.apply_section(REC_SMALL, 0, &record(4, 5)).expect("record");
    assert!(!store.record_matches(&state, REC_SMALL).expect("compare"));
}
