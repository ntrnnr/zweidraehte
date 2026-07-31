//! Host tests for the flash-backed `KeyValueStore` backends.
//!
//! A `MockFlash` models NOR flash faithfully: an erased cell is `0xFF`, a write
//! can only clear bits (`&=`), and a write budget simulates power loss mid-write.
//! Bugs that rely on rewriting an already-written slot would corrupt under these
//! rules, just as on hardware.
//!
//! The suite exercises the `KeyValueStore` behaviour of the wear-levelled
//! backend (including reboot and rotation recovery), then runs a `SiatStore`
//! body over it to prove the typed view round-trips through the backend.

extern crate std;
use std::cell::RefCell;
use std::rc::Rc;
use std::vec;
use std::vec::Vec;

// When the host test binary is built with the `defmt` feature, the crate's
// `defmt::*` log macros leave the `_defmt_*` symbols undefined at link time; a
// no-op global logger satisfies them (the tests assert on values, not log
// output, so dropping the bytes is fine). Without the feature the logging
// facade is the silent no-op and no shim is needed — so gate it on `defmt`.
// Only compiled for `#[cfg(test)]`, never into firmware (which uses defmt-rtt).
#[cfg(feature = "defmt")]
#[defmt::global_logger]
struct HostLogger;

#[cfg(feature = "defmt")]
unsafe impl defmt::Logger for HostLogger {
    fn acquire() {}
    unsafe fn flush() {}
    unsafe fn release() {}
    unsafe fn write(_bytes: &[u8]) {}
}

use crate::storage::kv::{seq6_to_u64, u64_to_seq6};
use crate::storage::views::SiatStore;

use super::sector_io::SectorIo;
use super::{KeyValueStore, WearLeveledKv};

use crate::storage::region::FlashSiatRegion;

/// The region marker the wear-levelled test stores bind — the single source
/// of their `KNXR` sector-header magic, exactly as on a real device.
type TestSiat = FlashSiatRegion<TEST_REGION_SIZE, 16, 16>;

// ============================================================================
// MockFlash
// ============================================================================

const TEST_REGION_OFFSET: u32 = 0;
const TEST_SECTOR_SIZE: usize = 4096;
const TEST_SECTORS: usize = 4;
const TEST_REGION_SIZE: usize = TEST_SECTOR_SIZE * TEST_SECTORS;

/// Backing store shared by clones, so a "reboot" can re-open the same bytes
/// after the previous store (which owned its `MockFlash`) is dropped.
#[derive(Clone)]
struct Backing {
    bytes: Rc<RefCell<Vec<u8>>>,
    /// Byte-writes remaining before further writes are dropped (power loss).
    write_budget: Rc<RefCell<Option<usize>>>,
}

impl Backing {
    fn new() -> Self {
        Self { bytes: Rc::new(RefCell::new(vec![0xFFu8; TEST_REGION_SIZE])), write_budget: Rc::new(RefCell::new(None)) }
    }
    /// A `MockFlash` view over the same bytes (a "reboot").
    fn reopen(&self) -> MockFlash {
        self.reopen_aligned()
    }
    /// A reboot view with a chosen write alignment — for the `ConfigStore`
    /// padding tests (the alignment is a fact of the `SectorIo` impl).
    fn reopen_aligned<const WRITE_ALIGN: usize>(&self) -> MockFlashAligned<WRITE_ALIGN> {
        MockFlashAligned { backing: self.clone() }
    }
    fn set_write_budget(&self, n: usize) {
        *self.write_budget.borrow_mut() = Some(n);
    }
}

/// The NOR mock, parameterised by its advertised write granularity (the
/// bytes themselves accept any write — the alignment only steers the
/// stores' padding math, which is what the tests observe).
struct MockFlashAligned<const WRITE_ALIGN: usize> {
    backing: Backing,
}

/// The common byte-granular mock.
type MockFlash = MockFlashAligned<1>;

impl<const WRITE_ALIGN: usize> MockFlashAligned<WRITE_ALIGN> {
    fn new() -> Self {
        Self { backing: Backing::new() }
    }
    fn backing(&self) -> Backing {
        self.backing.clone()
    }
}

impl<const WRITE_ALIGN: usize> SectorIo for MockFlashAligned<WRITE_ALIGN> {
    type Error = ();

    const WRITE_ALIGN: usize = WRITE_ALIGN;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), ()> {
        let s = offset as usize;
        buf.copy_from_slice(&self.backing.bytes.borrow()[s..s + buf.len()]);
        Ok(())
    }

    fn erase(&mut self, start: u32, end: u32) -> Result<(), ()> {
        assert_eq!(start as usize % TEST_SECTOR_SIZE, 0, "erase start not sector-aligned");
        assert_eq!(end as usize % TEST_SECTOR_SIZE, 0, "erase end not sector-aligned");
        for b in &mut self.backing.bytes.borrow_mut()[start as usize..end as usize] {
            *b = 0xFF;
        }
        Ok(())
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), ()> {
        let s = offset as usize;
        let mut bytes = self.backing.bytes.borrow_mut();
        let mut budget = self.backing.write_budget.borrow_mut();
        for (i, &d) in data.iter().enumerate() {
            if let Some(b) = budget.as_mut() {
                if *b == 0 {
                    return Ok(()); // power lost mid-write
                }
                *b -= 1;
            }
            bytes[s + i] &= d; // NOR: writes can only clear bits
        }
        Ok(())
    }
}

// Concrete backend type over the test region. Placement (offset/sector
// size/sector count) is passed at `open` time; the magic comes from the
// bound region type.
type WlKv = WearLeveledKv<MockFlash, TestSiat, 16>;

/// Open a `WlKv` at the standard test region.
fn open_wl(io: MockFlash) -> Result<WlKv, ()> {
    WearLeveledKv::open(io, TEST_REGION_OFFSET, TEST_SECTOR_SIZE, TEST_SECTORS)
}

const NS: u8 = 0x01;

/// The capacity assert fires at `open` when the mirror could not compact into
/// one sector at rotation (header slot + ENTRIES record slots must fit).
#[test]
#[should_panic(expected = "ENTRIES exceeds one sector's record slots")]
fn wl_over_entries_construction_panics() {
    // TEST_SECTOR_SIZE / SLOT_SIZE slots per sector, minus the header slot —
    // an ENTRIES equal to the raw slot count is one too many.
    const TOO_MANY: usize = TEST_SECTOR_SIZE / 12;
    let _ = WearLeveledKv::<MockFlash, TestSiat, TOO_MANY>::open(
        MockFlash::new(),
        TEST_REGION_OFFSET,
        TEST_SECTOR_SIZE,
        TEST_SECTORS,
    );
}

/// Rotation needs a spare sector; a single-sector region is refused at `open`.
#[test]
#[should_panic(expected = "at least two sectors")]
fn wl_single_sector_construction_panics() {
    let _ = WlKv::open(MockFlash::new(), TEST_REGION_OFFSET, TEST_SECTOR_SIZE, 1);
}

// ============================================================================
// KeyValueStore behaviour
// ============================================================================

/// Run a closure with a fresh backend instance. Kept generic over the
/// `KeyValueStore` so the same body could exercise a future backend.
fn kv_get_absent_is_none<S: KeyValueStore>(mut s: S)
where
    S::Error: core::fmt::Debug,
{
    let mut buf = [0u8; 6];
    assert_eq!(s.get(NS, &[1, 2], &mut buf).unwrap(), None);
    s.put(NS, &[1, 2], &[9, 9, 9, 9, 9, 9]).unwrap();
    assert_eq!(s.get(NS, &[1, 2], &mut buf).unwrap(), Some(6));
    assert_eq!(&buf, &[9, 9, 9, 9, 9, 9]);
}

#[test]
fn get_put_wear_leveled() {
    kv_get_absent_is_none(open_wl(MockFlash::new()).unwrap());
}

fn kv_overwrite_and_remove<S: KeyValueStore>(mut s: S)
where
    S::Error: core::fmt::Debug,
{
    let mut buf = [0u8; 6];
    s.put(NS, &[0, 1], &[1; 6]).unwrap();
    s.put(NS, &[0, 1], &[2; 6]).unwrap(); // overwrite
    assert_eq!(s.get(NS, &[0, 1], &mut buf).unwrap(), Some(6));
    assert_eq!(&buf, &[2; 6]);
    s.remove(NS, &[0, 1]).unwrap();
    assert_eq!(s.get(NS, &[0, 1], &mut buf).unwrap(), None);
}

#[test]
fn overwrite_remove_wear_leveled() {
    kv_overwrite_and_remove(open_wl(MockFlash::new()).unwrap());
}

#[test]
fn wear_leveled_survives_reboot_and_rotation() {
    let flash = MockFlash::new();
    let backing = flash.backing();
    let mut s = open_wl(flash).unwrap();
    // Many writes to the same key force several rotations (341 slots/sector).
    for v in 0u64..1000 {
        s.put(NS, &[0, 1], &u64_to_seq6(v)).unwrap();
    }
    s.put(NS, &[0, 2], &u64_to_seq6(42)).unwrap();
    drop(s);
    // Reboot over the same bytes: latest values survive across rotations.
    let s2 = open_wl(backing.reopen()).unwrap();
    let mut buf = [0u8; 6];
    assert_eq!(s2.get(NS, &[0, 1], &mut buf).unwrap(), Some(6));
    assert_eq!(&buf, &u64_to_seq6(999));
    assert_eq!(s2.get(NS, &[0, 2], &mut buf).unwrap(), Some(6));
    assert_eq!(&buf, &u64_to_seq6(42));
}

#[test]
fn wear_leveled_crash_mid_rotation_falls_back() {
    let flash = MockFlash::new();
    let backing = flash.backing();
    let mut s = open_wl(flash).unwrap();
    s.put(NS, &[0, 1], &u64_to_seq6(7)).unwrap(); // committed in sector 0
    // Fill toward a rotation, then cut power partway through the next rotation's
    // writes (after erase, before header commit).
    for v in 0u64..340 {
        s.put(NS, &[0, 2], &u64_to_seq6(v)).unwrap();
    }
    backing.set_write_budget(3); // only 3 byte-writes succeed, then "power loss"
    let _ = s.put(NS, &[0, 2], &u64_to_seq6(999)); // provokes rotation, truncated
    drop(s);
    // Clean reboot: the half-written sector has no valid header → ignored; the
    // prior sector (holding key [0,1]=7) wins.
    let s2 = open_wl(backing.reopen()).unwrap();
    let mut buf = [0u8; 6];
    assert_eq!(s2.get(NS, &[0, 1], &mut buf).unwrap(), Some(6));
    assert_eq!(&buf, &u64_to_seq6(7));
}

/// A power cut mid-append leaves a torn (non-blank, bad-CRC) slot. Recovery
/// must skip it — not treat it as the end of the log — and must park the
/// append cursor *past* it (NOR bits only clear, so re-programming the torn
/// slot could never yield a valid record). The security-relevant case is the
/// second reboot: records appended after the torn slot must survive replay,
/// otherwise the sequence counters silently roll back.
#[test]
fn wear_leveled_torn_append_skipped_and_later_records_survive() {
    let flash = MockFlash::new();
    let backing = flash.backing();
    let mut s = open_wl(flash).unwrap();
    s.put(NS, &[0, 1], &u64_to_seq6(7)).unwrap(); // slot 1, committed
    backing.set_write_budget(3); // power lost 3 bytes into the next append
    let _ = s.put(NS, &[0, 1], &u64_to_seq6(8)); // slot 2, torn
    drop(s);
    backing.set_write_budget(usize::MAX);

    // Reboot 1: the torn slot is skipped, the committed value is intact.
    let mut s2 = open_wl(backing.reopen()).unwrap();
    let mut buf = [0u8; 6];
    assert_eq!(s2.get(NS, &[0, 1], &mut buf).unwrap(), Some(6));
    assert_eq!(&buf, &u64_to_seq6(7));

    // A fresh append must land *after* the torn slot, leaving its bytes
    // untouched. (Blank region + first rotation puts the log in sector 0:
    // slot 0 header, slot 1 = committed record, slot 2 = torn.)
    let torn_range = || {
        let start = TEST_REGION_OFFSET as usize + 2 * 12;
        backing.bytes.borrow()[start..start + 12].to_vec()
    };
    let torn_before = torn_range();
    s2.put(NS, &[0, 2], &u64_to_seq6(42)).unwrap();
    assert_eq!(torn_range(), torn_before, "append re-programmed the torn slot");
    drop(s2);

    // Reboot 2: the record written beyond the torn slot survives replay.
    let s3 = open_wl(backing.reopen()).unwrap();
    assert_eq!(s3.get(NS, &[0, 1], &mut buf).unwrap(), Some(6));
    assert_eq!(&buf, &u64_to_seq6(7));
    assert_eq!(s3.get(NS, &[0, 2], &mut buf).unwrap(), Some(6));
    assert_eq!(&buf, &u64_to_seq6(42));
}

// ============================================================================
// SiatStore over the wear-levelled backend
// ============================================================================

fn s6(v: u64) -> [u8; 6] {
    u64_to_seq6(v)
}

/// One SIAT body run over a backend opened from `backing`, then re-opened
/// (reboot) to prove durability. Kept generic over the `KeyValueStore` so the
/// same body could exercise a future backend.
fn siat_roundtrip<S, F>(backing: Backing, open: F)
where
    S: KeyValueStore,
    S::Error: core::fmt::Debug,
    F: Fn(MockFlash) -> S,
{
    let mut store: SiatStore<S, 8, 4> = SiatStore::boot(open(backing.reopen())).unwrap();
    store.write_entry(0, 0x1101, s6(1)).unwrap();
    store.write_entry(1, 0x1102, s6(2)).unwrap();
    store.write_entry(2, 0x1103, s6(3)).unwrap();
    // Positional reads: element i is what was written at i.
    assert_eq!(store.read_entry(0), Some((0x1101, s6(1))));
    assert_eq!(store.read_entry(2), Some((0x1103, s6(3))));
    assert_eq!(store.count(), 3);
    // In-place update.
    store.save_seq(0x1102, &s6(99)).unwrap();
    assert_eq!(store.load_seq(0x1102), Some(s6(99)));
    // Truncate.
    store.set_count(2).unwrap();
    assert_eq!(store.count(), 2);
    assert!(store.contains(0x1101));
    assert!(!store.contains(0x1103));
    drop(store);

    // Reboot: the live SIAT (including the in-place update and truncation) is
    // recovered from the backend.
    let store2: SiatStore<S, 8, 4> = SiatStore::boot(open(backing.reopen())).unwrap();
    assert_eq!(store2.count(), 2);
    assert_eq!(store2.load_seq(0x1102), Some(s6(99)));
    assert!(!store2.contains(0x1103));
}

#[test]
fn siat_over_wear_leveled() {
    let backing = Backing::new();
    siat_roundtrip(backing, |f| open_wl(f).unwrap());
}

// ============================================================================
// ConfigStore — the postcard-blob device-config store over SectorIo
// ============================================================================
//
// Exercised over the same NOR-faithful `MockFlash`. We use a trivial state
// type so the test stays in this crate without pulling a full device state in;
// the codec and the WRITE_ALIGN padding are what we're checking, not the shape
// of any real `S::Config`.

use crate::storage::HasDeviceConfig;
use serde::{Deserialize, Serialize};

use super::{ConfigStore, ConfigStoreError};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TestConfig {
    a: u32,
    b: [u8; 5],
}

struct TestState {
    cfg: TestConfig,
}

impl HasDeviceConfig for TestState {
    type Config = TestConfig;
    fn to_config(&self) -> TestConfig {
        TestConfig { a: self.cfg.a, b: self.cfg.b }
    }
}

// One sector region; offset (0 here) is passed to `new` at construction.
// The payload type is a marker parameter — the region *is* "a TestState
// config blob", exactly as on a real device.
type CfgRegion = crate::storage::region::ConfigRegion<TEST_SECTOR_SIZE, TestState>;
type CfgStore<const WRITE_ALIGN: usize> =
    ConfigStore<MockFlashAligned<WRITE_ALIGN>, TestState, CfgRegion, TEST_SECTOR_SIZE>;

/// Round-trip a config through save + reboot, for a given write alignment
/// (a fact of the mock's `SectorIo` impl).
fn config_roundtrips<const WRITE_ALIGN: usize>() {
    let backing = Backing::new();
    let mut store: CfgStore<WRITE_ALIGN> = ConfigStore::new(backing.reopen_aligned(), 0);

    let state = TestState { cfg: TestConfig { a: 0xDEAD_BEEF, b: [1, 2, 3, 4, 5] } };
    store.save(&state).unwrap();
    drop(store);

    // Reboot over the same bytes: the persisted config reads back identically.
    let mut store2: CfgStore<WRITE_ALIGN> = ConfigStore::new(backing.reopen_aligned(), 0);
    let loaded = store2.load_config().unwrap().expect("a config was saved");
    assert_eq!(loaded, TestConfig { a: 0xDEAD_BEEF, b: [1, 2, 3, 4, 5] });
}

#[test]
fn config_roundtrips_unpadded() {
    // RP2040: byte-granular writes, no padding.
    config_roundtrips::<1>();
}

#[test]
fn config_roundtrips_doubleword_padded() {
    // STM32: writes padded up to an 8-byte doubleword.
    config_roundtrips::<8>();
}

#[test]
fn config_blank_flash_reads_none() {
    let mut store: CfgStore<1> = ConfigStore::new(MockFlash::new(), 0);
    // Erased flash is all 0xFF — no magic, so no config.
    assert!(store.load_config().unwrap().is_none());
}

#[test]
fn config_corrupt_magic_reads_none() {
    let backing = Backing::new();
    let mut store: CfgStore<1> = ConfigStore::new(backing.reopen(), 0);
    store.save(&TestState { cfg: TestConfig { a: 7, b: [0; 5] } }).unwrap();
    // Clobber the first magic byte; the store must treat it as absent.
    backing.bytes.borrow_mut()[0] = 0x00;
    let mut store2: CfgStore<1> = ConfigStore::new(backing.reopen(), 0);
    assert!(store2.load_config().unwrap().is_none());
}

#[test]
fn config_error_type_is_exported() {
    // Smoke-check the re-exported error name resolves (call sites match on it).
    fn _accepts(_: ConfigStoreError) {}
}

// ============================================================================
// Offset-placed wear-levelled store (mc_timer watermark pattern)
// ============================================================================
//
// The IP-Secure mc_timer watermark store is a single-record `WearLeveledKv`
// bound to its own region type (own magic) at its own absolute offset — the
// offset is passed to `open` directly. These tests model that shape: a
// 2-sector region starting at sector 2 of the shared MockFlash and a 6-byte
// watermark value.

/// Region base: sector 2 of the 4-sector MockFlash, leaving sectors 0..2
/// outside the region to prove placement honours the offset.
const MC_BASE: u32 = (TEST_SECTOR_SIZE * 2) as u32;

const MC_NS: u8 = 0x10;
const MC_KEY: &[u8] = &[0];

/// The mc_timer-shaped region (`KNXM` magic) spanning the two test sectors.
type TestMcRegion = crate::storage::region::McTimerRegion<{ TEST_SECTOR_SIZE * 2 }>;

/// Single-record wear-levelled store; placement passed at `open`.
type McKv = WearLeveledKv<MockFlash, TestMcRegion, 1>;
fn open_mc(io: MockFlash) -> Result<McKv, ()> {
    WearLeveledKv::open(io, MC_BASE, TEST_SECTOR_SIZE, 2)
}

/// A watermark written at the region offset reads back, survives a reboot, and
/// physically lands at the region (not at flash offset 0).
#[test]
fn placed_watermark_roundtrips_and_lands_at_offset() {
    let backing = Backing::new();
    let mut store = open_mc(backing.reopen()).unwrap();

    let watermark: u64 = 0x0000_1234_5678_9ABC & 0x0000_FFFF_FFFF_FFFF; // 48-bit
    store.put(MC_NS, MC_KEY, &u64_to_seq6(watermark)).unwrap();

    // Read back through the same store.
    let mut buf = [0u8; 6];
    assert_eq!(store.get(MC_NS, MC_KEY, &mut buf).unwrap(), Some(6));
    assert_eq!(seq6_to_u64(&buf), watermark);

    // Survives a reboot (re-open the same bytes at the same offset).
    drop(store);
    let reopened = open_mc(backing.reopen()).unwrap();
    let mut buf2 = [0u8; 6];
    assert_eq!(reopened.get(MC_NS, MC_KEY, &mut buf2).unwrap(), Some(6));
    assert_eq!(seq6_to_u64(&buf2), watermark);

    // Nothing was written below the region (sectors 0..2 stay erased).
    let bytes = backing.bytes.borrow();
    assert!(bytes[..MC_BASE as usize].iter().all(|&b| b == 0xFF), "data leaked below the region offset");
}

/// A SIAT-bound (`KNXR`) store opened over sectors already populated by an
/// mc_timer-bound (`KNXM`) store sees nothing — the region-derived magic
/// isolates regions that happen to share physical sectors across a firmware
/// change. This is what lets the mc_timer store ignore stale sequence-log
/// records in repurposed sectors.
#[test]
fn distinct_magic_ignores_foreign_records() {
    let backing = Backing::new();

    // Populate the region with the mc_timer-bound (`KNXM`) store.
    let mut alt = open_mc(backing.reopen()).unwrap();
    alt.put(MC_NS, MC_KEY, &u64_to_seq6(0xAABBCCDD)).unwrap();
    drop(alt);

    // Open the same sectors bound to the SIAT region (`KNXR`) — it must not
    // adopt the `KNXM` sector header, so the record is invisible.
    type ForeignKv = WearLeveledKv<MockFlash, FlashSiatRegion<{ TEST_SECTOR_SIZE * 2 }, 1, 1>, 1>;
    let def = ForeignKv::open(backing.reopen(), MC_BASE, TEST_SECTOR_SIZE, 2).unwrap();
    let mut buf = [0u8; 6];
    assert_eq!(def.get(MC_NS, MC_KEY, &mut buf).unwrap(), None, "foreign-magic record was adopted");
}
