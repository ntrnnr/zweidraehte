//! Host tests for the flash-backed stores bound to this crate's regions.
//!
//! They run over `zweidraehte-nv`'s NOR flash model (`mock::MockFlash`):
//! erased cells read `0xFF`, writes only clear bits, and writes must be whole
//! `WRITE_ALIGN` granules. The wear-levelled key/value store and its
//! crash-recovery tests live in `zweidraehte-nv`; here a `SiatStore` body runs
//! over it to prove the typed view round-trips through the backend, and the
//! `ConfigStore` codec is checked at both write granularities.

extern crate std;

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

use zweidraehte_nv::LogGeometry;
use zweidraehte_nv::mock::{Backing, MockFlash};

use crate::storage::kv::u64_to_seq6;
use crate::storage::views::SiatStore;

use crate::storage::kv::KeyValueStore;

use super::WearLeveledKv;

const TEST_SECTOR_SIZE: usize = 4096;
const TEST_SECTORS: usize = 4;
const TEST_REGION_SIZE: usize = TEST_SECTOR_SIZE * TEST_SECTORS;

fn test_backing() -> Backing {
    Backing::new(TEST_REGION_SIZE, TEST_SECTOR_SIZE)
}

/// The SIAT log over the whole test flash, one sector per bank, under the
/// SIAT region's `KNXR` magic.
fn open_wl(io: MockFlash<1>) -> Result<WearLeveledKv<MockFlash<1>, 16>, ()> {
    let geometry = LogGeometry {
        offset: 0,
        sector_size: TEST_SECTOR_SIZE as u32,
        sectors_per_bank: 1,
        banks: TEST_SECTORS as u32,
    };
    WearLeveledKv::open(io, geometry, u32::from_be_bytes(*b"KNXR"))
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
    F: Fn(MockFlash<1>) -> S,
{
    let mut store: SiatStore<S, 8, 4> = SiatStore::boot(open(backing.open())).unwrap();
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
    let store2: SiatStore<S, 8, 4> = SiatStore::boot(open(backing.open())).unwrap();
    assert_eq!(store2.count(), 2);
    assert_eq!(store2.load_seq(0x1102), Some(s6(99)));
    assert!(!store2.contains(0x1103));
}

#[test]
fn siat_over_wear_leveled() {
    siat_roundtrip(test_backing(), |f| open_wl(f).unwrap());
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
type CfgStore<const WRITE_ALIGN: usize> = ConfigStore<MockFlash<WRITE_ALIGN>, TestState, CfgRegion, TEST_SECTOR_SIZE>;

/// Round-trip a config through save + reboot, for a given write alignment
/// (a fact of the mock's `SectorIo` impl).
fn config_roundtrips<const WRITE_ALIGN: usize>() {
    let backing = test_backing();
    let mut store: CfgStore<WRITE_ALIGN> = ConfigStore::new(backing.open_aligned(), 0);

    let state = TestState { cfg: TestConfig { a: 0xDEAD_BEEF, b: [1, 2, 3, 4, 5] } };
    store.save(&state).unwrap();
    drop(store);

    // Reboot over the same bytes: the persisted config reads back identically.
    let mut store2: CfgStore<WRITE_ALIGN> = ConfigStore::new(backing.open_aligned(), 0);
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
    let mut store: CfgStore<1> = ConfigStore::new(test_backing().open(), 0);
    // Erased flash is all 0xFF — no magic, so no config.
    assert!(store.load_config().unwrap().is_none());
}

#[test]
fn config_corrupt_magic_reads_none() {
    let backing = test_backing();
    let mut store: CfgStore<1> = ConfigStore::new(backing.open(), 0);
    store.save(&TestState { cfg: TestConfig { a: 7, b: [0; 5] } }).unwrap();
    // Clobber the first magic byte; the store must treat it as absent.
    backing.poke(0, &[0x00]);
    let mut store2: CfgStore<1> = ConfigStore::new(backing.open(), 0);
    assert!(store2.load_config().unwrap().is_none());
}

#[test]
fn config_error_type_is_exported() {
    // Smoke-check the re-exported error name resolves (call sites match on it).
    fn _accepts(_: ConfigStoreError) {}
}
