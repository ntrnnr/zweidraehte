//! Host tests for the flash-backed `KeyValueStore` backends.
//!
//! A `MockFlash` models NOR flash faithfully: an erased cell is `0xFF`, a write
//! can only clear bits (`&=`), and a write budget simulates power loss mid-write.
//! Bugs that rely on rewriting an already-written slot would corrupt under these
//! rules, just as on hardware.
//!
//! The suite runs the same `KeyValueStore` behaviour over both backends, then a
//! transparency test runs one `SiatStore` body over both — proving the typed
//! view is agnostic to wear-levelling.

extern crate std;
use std::cell::RefCell;
use std::rc::Rc;
use std::vec;
use std::vec::Vec;

// The crate pulls in `defmt` unconditionally (for `defmt::warn!` /
// `#[derive(defmt::Format)]`), which leaves the `_defmt_*` symbols undefined
// when linking the host test binary. A no-op global logger satisfies them; the
// tests assert on values, not log output, so dropping the bytes is fine. Only
// compiled for `#[cfg(test)]`, never into firmware (which uses defmt-rtt).
#[defmt::global_logger]
struct HostLogger;

unsafe impl defmt::Logger for HostLogger {
    fn acquire() {}
    unsafe fn flush() {}
    unsafe fn release() {}
    unsafe fn write(_bytes: &[u8]) {}
}

use zweidraehte_device::kvstore::{SiatStore, u64_to_seq6};

use super::flash_io::FlashIo;
use super::{KeyValueStore, VerbatimKv, WearLeveledKv};

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
        MockFlash { backing: self.clone() }
    }
    fn set_write_budget(&self, n: usize) {
        *self.write_budget.borrow_mut() = Some(n);
    }
}

struct MockFlash {
    backing: Backing,
}

impl MockFlash {
    fn new() -> Self {
        MockFlash { backing: Backing::new() }
    }
    fn backing(&self) -> Backing {
        self.backing.clone()
    }
}

impl FlashIo for MockFlash {
    type Error = ();

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

// Concrete backend types over the test region.
type WlKv = WearLeveledKv<MockFlash, TEST_REGION_OFFSET, TEST_SECTOR_SIZE, TEST_SECTORS, 16>;
type VbKv = VerbatimKv<MockFlash, TEST_REGION_OFFSET, TEST_REGION_SIZE, 16>;

const NS: u8 = 0x01;

// ============================================================================
// KeyValueStore behaviour — run over both backends
// ============================================================================

/// Run a closure with a fresh instance of each backend, so one test body
/// exercises both. Returns the post-test backing bytes for reboot checks.
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
    kv_get_absent_is_none(WlKv::open(MockFlash::new()).unwrap());
}
#[test]
fn get_put_verbatim() {
    kv_get_absent_is_none(VbKv::open(MockFlash::new()).unwrap());
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
    kv_overwrite_and_remove(WlKv::open(MockFlash::new()).unwrap());
}
#[test]
fn overwrite_remove_verbatim() {
    kv_overwrite_and_remove(VbKv::open(MockFlash::new()).unwrap());
}

#[test]
fn wear_leveled_survives_reboot_and_rotation() {
    let flash = MockFlash::new();
    let backing = flash.backing();
    let mut s = WlKv::open(flash).unwrap();
    // Many writes to the same key force several rotations (341 slots/sector).
    for v in 0u64..1000 {
        s.put(NS, &[0, 1], &u64_to_seq6(v)).unwrap();
    }
    s.put(NS, &[0, 2], &u64_to_seq6(42)).unwrap();
    drop(s);
    // Reboot over the same bytes: latest values survive across rotations.
    let s2 = WlKv::open(backing.reopen()).unwrap();
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
    let mut s = WlKv::open(flash).unwrap();
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
    let s2 = WlKv::open(backing.reopen()).unwrap();
    let mut buf = [0u8; 6];
    assert_eq!(s2.get(NS, &[0, 1], &mut buf).unwrap(), Some(6));
    assert_eq!(&buf, &u64_to_seq6(7));
}

// ============================================================================
// SiatStore transparency — one body, both backends
// ============================================================================

fn s6(v: u64) -> [u8; 6] {
    u64_to_seq6(v)
}

/// One SIAT body run over a backend opened from `backing`, then re-opened
/// (reboot) to prove durability — identical for both wear-leveled and verbatim.
fn siat_roundtrip<S, F>(backing: Backing, open: F)
where
    S: KeyValueStore,
    S::Error: core::fmt::Debug,
    F: Fn(MockFlash) -> S,
{
    let mut store: SiatStore<S, 8, 4> = SiatStore::boot(open(backing.reopen())).unwrap();
    store.save_seq(0x1103, &s6(3)).unwrap();
    store.save_seq(0x1101, &s6(1)).unwrap();
    store.save_seq(0x1102, &s6(2)).unwrap();
    // Sorted reads regardless of insertion order.
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
    siat_roundtrip(backing, |f| WlKv::open(f).unwrap());
}
#[test]
fn siat_over_verbatim() {
    let backing = Backing::new();
    siat_roundtrip(backing, |f| VbKv::open(f).unwrap());
}

// ============================================================================
// ConfigStore — the postcard-blob device-config store over FlashIo
// ============================================================================
//
// Exercised over the same NOR-faithful `MockFlash`. We use a trivial state
// type so the test stays in this crate without pulling a full device state in;
// the codec and the WRITE_ALIGN padding are what we're checking, not the shape
// of any real `S::Config`.

use serde::{Deserialize, Serialize};
use zweidraehte_device::bcus::system_b::HasDeviceConfig;
use zweidraehte_device::storage::DeviceIdentity;

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

struct TestIdentity;
impl DeviceIdentity for TestIdentity {
    fn serial_number(&self) -> &[u8; 6] {
        &[0xAA; 6]
    }
}

// One sector region at offset 0 — satisfies MockFlash's sector-aligned erase.
type CfgStore<const WRITE_ALIGN: usize> =
    ConfigStore<MockFlash, TestState, TestIdentity, 0, TEST_SECTOR_SIZE, WRITE_ALIGN>;

/// Round-trip a config through save + reboot, for a given write alignment.
fn config_roundtrips<const WRITE_ALIGN: usize>() {
    let backing = Backing::new();
    let mut store: CfgStore<WRITE_ALIGN> = ConfigStore::new(backing.reopen(), TestIdentity);
    assert!(!store.is_dirty());

    let state = TestState { cfg: TestConfig { a: 0xDEAD_BEEF, b: [1, 2, 3, 4, 5] } };
    store.mark_dirty();
    assert!(store.is_dirty());
    store.save(&state).unwrap();
    assert!(!store.is_dirty(), "save clears the dirty flag");
    drop(store);

    // Reboot over the same bytes: the persisted config reads back identically.
    let mut store2: CfgStore<WRITE_ALIGN> = ConfigStore::new(backing.reopen(), TestIdentity);
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
    let mut store: CfgStore<1> = ConfigStore::new(MockFlash::new(), TestIdentity);
    // Erased flash is all 0xFF — no magic, so no config.
    assert!(store.load_config().unwrap().is_none());
}

#[test]
fn config_corrupt_magic_reads_none() {
    let backing = Backing::new();
    let mut store: CfgStore<1> = ConfigStore::new(backing.reopen(), TestIdentity);
    store.save(&TestState { cfg: TestConfig { a: 7, b: [0; 5] } }).unwrap();
    // Clobber the first magic byte; the store must treat it as absent.
    backing.bytes.borrow_mut()[0] = 0x00;
    let mut store2: CfgStore<1> = ConfigStore::new(backing.reopen(), TestIdentity);
    assert!(store2.load_config().unwrap().is_none());
}

#[test]
fn config_error_type_is_exported() {
    // Smoke-check the re-exported error name resolves (call sites match on it).
    fn _accepts(_: ConfigStoreError) {}
}
