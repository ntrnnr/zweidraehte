//! Host tests for the flash-backed stores bound to this crate's regions.
//!
//! They run over `zweidraehte-nv`'s NOR flash model (`mock::MockFlash`):
//! erased cells read `0xFF`, writes only clear bits, and writes must be whole
//! `WRITE_ALIGN` granules. The wear-levelled key/value store and its
//! crash-recovery tests live in `zweidraehte-nv`; here a `SiatStore` body runs
//! over it to prove the typed view round-trips through the backend.

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
