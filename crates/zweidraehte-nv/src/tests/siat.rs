//! One semantics suite for both SIAT implementations.
//!
//! [`SiatStore`] (RAM mirror over the flash log) and [`PackedSeqStore`]
//! (direct on byte media) implement the same `zweidraehte_proto::security`
//! traits for the same secure layers. Every rule below runs against both,
//! and against a byte medium full of garbage, with reboots between writes and
//! checks, so the two implementations cannot drift apart.

use core::fmt::Debug;

use zweidraehte_proto::security::{DEFAULT_SENDING, SequenceNumberStorage, SiatAccess, seq6_to_u64, u64_to_seq6};

use super::RamIo;
use crate::mock::{Backing, MockFlash};
use crate::{LogGeometry, McTimerWatermark, PackedSeqStore, SiatStore, WearLeveledKv};

/// SIAT capacity under test.
const N: usize = 8;
const MAGIC: u32 = u32::from_be_bytes(*b"KNXR");

fn s6(v: u64) -> [u8; 6] {
    u64_to_seq6(v)
}

// ============================================================================
// Media
// ============================================================================

/// A medium plus a way to boot a store over it; every `boot` is a reboot.
trait Medium {
    type Error: Debug;
    type Store: SequenceNumberStorage<Error = Self::Error> + SiatAccess<Error = Self::Error> + McTimerWatermark;
    fn boot(&self) -> Self::Store;
}

/// Flash: `SiatStore` over the wear-levelled log, K = 256 as on RP2040.
struct Flash(Backing);

impl Flash {
    fn new() -> Self {
        Self(Backing::new(8192, 4096))
    }
}

impl Medium for Flash {
    type Error = ();
    type Store = SiatStore<WearLeveledKv<MockFlash<1>, 16>, N, 256, true>;
    fn boot(&self) -> Self::Store {
        let geometry = LogGeometry { offset: 0, sector_size: 4096, sectors_per_bank: 1, banks: 2 };
        SiatStore::boot(WearLeveledKv::open(self.0.open(), geometry, MAGIC).unwrap()).unwrap()
    }
}

/// Byte medium: `PackedSeqStore` directly.
struct Bytes(RamIo);

impl Bytes {
    fn zeroed() -> Self {
        Self(RamIo::zeroed(PackedSeqStore::<RamIo, N, true>::REGION_LEN))
    }
    fn garbage() -> Self {
        Self(RamIo::filled(PackedSeqStore::<RamIo, N, true>::REGION_LEN, 0xA5))
    }
}

impl Medium for Bytes {
    type Error = core::convert::Infallible;
    type Store = PackedSeqStore<RamIo, N, true>;
    fn boot(&self) -> Self::Store {
        PackedSeqStore::new(self.0.clone(), 0, MAGIC)
    }
}

// The stores under test keep the IP Secure watermark (`MC_TIMER`); a store
// without it ignores the watermark, which the per-store tests check.

/// Instantiate every rule for every medium.
macro_rules! suite {
    ($($rule:ident),* $(,)?) => {
        mod flash {
            $( #[test] fn $rule() { super::$rule(&super::Flash::new()); } )*
        }
        mod bytes_zeroed {
            $( #[test] fn $rule() { super::$rule(&super::Bytes::zeroed()); } )*
        }
        mod bytes_garbage {
            $( #[test] fn $rule() { super::$rule(&super::Bytes::garbage()); } )*
        }
    };
}

suite!(
    fresh_medium_has_defaults,
    elements_are_positional_across_reboots,
    positional_overwrite_keeps_first_match,
    writing_past_the_end_fills_the_gap_with_empty_elements,
    receiving_counter_updates_in_place_and_ignores_unknown_ias,
    set_count_truncates_and_grows,
    clear_survives_reboot,
    writes_beyond_capacity_are_ignored,
    sending_counter_never_regresses_across_reboot,
    backward_sending_write_is_authoritative,
    tool_counter_roundtrips,
    watermark_is_absent_on_a_fresh_medium,
    watermark_survives_reboot,
    cleared_watermark_stays_cleared,
    watermark_and_counters_do_not_disturb_each_other,
);

// ============================================================================
// Rules
// ============================================================================

fn fresh_medium_has_defaults(m: &impl Medium) {
    let s = m.boot();
    assert_eq!(s.siat_count(), 0);
    assert_eq!(s.load_sending_seq().unwrap(), DEFAULT_SENDING);
    assert_eq!(s.load_tool_receiving_seq().unwrap(), None);
    assert_eq!(s.load_receiving_seq(0x1101).unwrap(), None);
    assert_eq!(s.siat_index_of(0x1101), None);
}

/// Elements land where the writer named them and stay there: `IA_Index` is
/// the 1-based position the Point-to-point Key Table joins on (03/05/01
/// §6.3.6.2), regardless of address order.
fn elements_are_positional_across_reboots(m: &impl Medium) {
    let mut s = m.boot();
    s.siat_write_entry(0, 0x1103, s6(3)).unwrap();
    s.siat_write_entry(1, 0x1101, s6(1)).unwrap();
    s.siat_write_entry(2, 0x1102, s6(2)).unwrap();
    drop(s);

    let s = m.boot();
    assert_eq!(s.siat_count(), 3);
    assert_eq!(s.siat_read_entry(0), Some((0x1103, s6(3))));
    assert_eq!(s.siat_read_entry(2), Some((0x1102, s6(2))));
    assert_eq!(s.siat_read_entry(3), None);
    assert_eq!(s.siat_index_of(0x1103), Some(1));
    assert_eq!(s.siat_index_of(0x1102), Some(3));
    assert_eq!(s.load_receiving_seq(0x1101).unwrap(), Some(s6(1)));
}

/// The TSSJ 3.3.4 shape: overwriting element 1 of a dirty table replaces
/// exactly that element, even when the IA already sits elsewhere, and a
/// lookup resolves to the first match.
fn positional_overwrite_keeps_first_match(m: &impl Medium) {
    let mut s = m.boot();
    s.siat_write_entry(0, 0xAFFD, s6(3)).unwrap();
    s.siat_write_entry(1, 0xAFFE, s6(1)).unwrap();
    s.siat_write_entry(0, 0xAFFE, s6(1)).unwrap();
    drop(s);

    let s = m.boot();
    assert_eq!(s.siat_count(), 2);
    assert_eq!(s.siat_index_of(0xAFFE), Some(1));
    assert_eq!(s.siat_index_of(0xAFFD), None, "the overwritten IA is gone");
}

/// Gap elements read as `(0, 0)` — also where a longer, since-truncated
/// table left real entries behind on the medium.
fn writing_past_the_end_fills_the_gap_with_empty_elements(m: &impl Medium) {
    let mut s = m.boot();
    for (index, ia) in [0x1101u16, 0x1102, 0x1103].into_iter().enumerate() {
        s.siat_write_entry(index as u16, ia, s6(u64::from(ia))).unwrap();
    }
    s.siat_set_count(1).unwrap();
    s.siat_write_entry(3, 0x1104, s6(4)).unwrap();
    drop(s);

    let s = m.boot();
    assert_eq!(s.siat_count(), 4);
    assert_eq!(s.siat_read_entry(0), Some((0x1101, s6(0x1101))));
    assert_eq!(s.siat_read_entry(1), Some((0, [0; 6])));
    assert_eq!(s.siat_read_entry(2), Some((0, [0; 6])), "a truncated entry resurfaced");
    assert_eq!(s.siat_index_of(0x1104), Some(4));
    assert!(!s.siat_contains(0x1103));
}

/// The receiving path never grows the table: an insert would invent an
/// `IA_Index` no key table refers to.
fn receiving_counter_updates_in_place_and_ignores_unknown_ias(m: &impl Medium) {
    let mut s = m.boot();
    s.siat_write_entry(0, 0x1101, s6(5)).unwrap();
    s.save_receiving_seq(0x1101, &s6(9)).unwrap();
    s.save_receiving_seq(0x1199, &s6(7)).unwrap();
    drop(s);

    let s = m.boot();
    assert_eq!(s.siat_count(), 1);
    assert_eq!(s.load_receiving_seq(0x1101).unwrap(), Some(s6(9)));
    assert_eq!(s.load_receiving_seq(0x1199).unwrap(), None);
}

fn set_count_truncates_and_grows(m: &impl Medium) {
    let mut s = m.boot();
    for (index, ia) in [0x1101u16, 0x1102, 0x1103].into_iter().enumerate() {
        s.siat_write_entry(index as u16, ia, s6(1)).unwrap();
    }
    s.siat_set_count(2).unwrap();
    drop(s);

    let mut s = m.boot();
    assert_eq!(s.siat_count(), 2);
    assert!(!s.siat_contains(0x1103));

    // Growing pre-allocates empty elements for the writes that follow.
    s.siat_set_count(4).unwrap();
    drop(s);
    let s = m.boot();
    assert_eq!(s.siat_count(), 4);
    assert_eq!(s.siat_read_entry(2), Some((0, [0; 6])));
    assert_eq!(s.siat_read_entry(3), Some((0, [0; 6])));
}

fn clear_survives_reboot(m: &impl Medium) {
    let mut s = m.boot();
    s.siat_write_entry(0, 0x1101, s6(1)).unwrap();
    s.siat_clear().unwrap();
    drop(s);
    assert_eq!(m.boot().siat_count(), 0);

    let mut s = m.boot();
    s.siat_write_entry(0, 0x1101, s6(1)).unwrap();
    s.siat_set_count(0).unwrap();
    drop(s);
    assert_eq!(m.boot().siat_count(), 0);
}

/// Failed deletion must leave the entry in RAM so the same request can
/// remove it once the medium works again.
#[test]
fn flash_clear_retries_failed_removal() {
    let flash = Flash::new();
    let mut store = flash.boot();

    store.siat_write_entry(0, 0x1101, s6(1)).expect("first entry");
    store.siat_write_entry(1, 0x1102, s6(2)).expect("second entry");

    flash.0.set_failing(true);
    assert!(store.siat_clear().is_err());
    assert_eq!(store.siat_count(), 2);
    assert!(store.siat_contains(0x1102));

    flash.0.set_failing(false);
    store.siat_clear().expect("retry clear");
    drop(store);

    assert_eq!(flash.boot().siat_count(), 0);
}

/// A failed count reduction must also leave its tail entry available for a
/// retry, including after the durable deletion succeeds on the second call.
#[test]
fn flash_count_shrink_retries_failed_removal() {
    let flash = Flash::new();
    let mut store = flash.boot();

    store.siat_write_entry(0, 0x1101, s6(1)).expect("first entry");
    store.siat_write_entry(1, 0x1102, s6(2)).expect("second entry");

    flash.0.set_failing(true);
    assert!(store.siat_set_count(1).is_err());
    assert_eq!(store.siat_count(), 2);
    assert!(store.siat_contains(0x1102));

    flash.0.set_failing(false);
    store.siat_set_count(1).expect("retry shrink");
    drop(store);

    let restored = flash.boot();
    assert_eq!(restored.siat_count(), 1);
    assert!(restored.siat_contains(0x1101));
    assert!(!restored.siat_contains(0x1102));
}

/// The property layer refuses out-of-range writes upstream; the stores
/// ignore them rather than corrupting a neighbouring layout.
fn writes_beyond_capacity_are_ignored(m: &impl Medium) {
    let mut s = m.boot();
    for index in 0..N as u16 + 2 {
        s.siat_write_entry(index, 0x1100 + index, s6(1)).unwrap();
    }
    s.siat_set_count(N as u16 + 5).unwrap();
    drop(s);

    let s = m.boot();
    assert_eq!(s.siat_count(), N as u16);
    assert!(s.siat_contains(0x1100 + N as u16 - 1));
    assert!(!s.siat_contains(0x1100 + N as u16));
}

/// A reboot may resume above the last used value (flash batches it) but
/// never below it: a reused sequence number is a replay.
fn sending_counter_never_regresses_across_reboot(m: &impl Medium) {
    let mut s = m.boot();
    for v in 2..20u64 {
        s.save_sending_seq(&s6(v)).unwrap();
        assert_eq!(s.load_sending_seq().unwrap(), s6(v));
    }
    drop(s);
    assert!(seq6_to_u64(&m.boot().load_sending_seq().unwrap()) >= 19);
}

/// A lower value (factory re-initialisation, an ETS PID 59 write) is
/// persisted exactly, not rounded up to a batch boundary.
fn backward_sending_write_is_authoritative(m: &impl Medium) {
    let mut s = m.boot();
    s.save_sending_seq(&s6(1000)).unwrap();
    s.save_sending_seq(&s6(5)).unwrap();
    drop(s);
    assert_eq!(m.boot().load_sending_seq().unwrap(), s6(5));
}

fn tool_counter_roundtrips(m: &impl Medium) {
    let mut s = m.boot();
    s.save_tool_receiving_seq(&s6(42)).unwrap();
    drop(s);
    assert_eq!(m.boot().load_tool_receiving_seq().unwrap(), Some(s6(42)));
}

fn watermark_is_absent_on_a_fresh_medium(m: &impl Medium) {
    assert_eq!(m.boot().load_mc_timer().unwrap(), None);
}

fn watermark_survives_reboot(m: &impl Medium) {
    let mut s = m.boot();
    s.save_mc_timer(3_600_000).unwrap();
    s.save_mc_timer(7_200_000).unwrap();
    drop(s);
    assert_eq!(m.boot().load_mc_timer().unwrap(), Some(7_200_000));
}

fn cleared_watermark_stays_cleared(m: &impl Medium) {
    let mut s = m.boot();
    s.save_mc_timer(3_600_000).unwrap();
    s.clear_mc_timer().unwrap();
    assert_eq!(s.load_mc_timer().unwrap(), None);
    drop(s);
    assert_eq!(m.boot().load_mc_timer().unwrap(), None);
}

/// The watermark shares the store with the counters and the SIAT; neither
/// side's writes may change the other's values.
fn watermark_and_counters_do_not_disturb_each_other(m: &impl Medium) {
    let mut s = m.boot();
    s.siat_write_entry(N as u16 - 1, 0x1108, s6(8)).unwrap();
    s.save_sending_seq(&s6(1000)).unwrap();
    s.save_tool_receiving_seq(&s6(77)).unwrap();
    s.save_mc_timer(0xABCD_EF01_2345).unwrap();
    drop(s);

    let s = m.boot();
    assert_eq!(s.load_mc_timer().unwrap(), Some(0xABCD_EF01_2345));
    assert!(seq6_to_u64(&s.load_sending_seq().unwrap()) >= 1000);
    assert_eq!(s.load_tool_receiving_seq().unwrap(), Some(s6(77)));
    assert_eq!(s.siat_read_entry(N as u16 - 1), Some((0x1108, s6(8))));
}

/// On flash the watermark is one more record in the sequence log, and it
/// must ride through the log's compaction like the counters do.
#[test]
fn flash_watermark_survives_compaction() {
    let flash = Flash::new();
    let mut s = flash.boot();
    s.save_mc_timer(3_600_000).unwrap();
    // Each re-initialising write of the sending counter is a record of its
    // own; enough of them fill a bank and force compactions.
    for round in 0..2_000u64 {
        s.save_sending_seq(&s6(10_000 - round)).unwrap();
    }
    drop(s);
    assert_eq!(flash.boot().load_mc_timer().unwrap(), Some(3_600_000));
}
