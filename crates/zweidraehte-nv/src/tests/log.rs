//! Format and crash-recovery tests of the bare [`AppendLog`].
//!
//! The owner state these tests model is a plain list of payloads; the
//! snapshot re-emits the whole list, which is what a real view does with its
//! mirror.

use std::vec;
use std::vec::Vec;

use crate::crc::crc16;
use crate::mock::{Backing, MockFlash};
use crate::{AppendLog, Compactor, LogGeometry, SectorIo};

const MAGIC: u32 = 0x4C4F_4754; // "LOGT"
const SECTOR: u32 = 512;

fn geometry(sectors_per_bank: u32, banks: u32) -> LogGeometry {
    LogGeometry { offset: 0, sector_size: SECTOR, sectors_per_bank, banks }
}

fn backing_for(geometry: LogGeometry) -> Backing {
    Backing::new((geometry.bank_size() * geometry.banks) as usize, geometry.sector_size as usize)
}

/// A log plus the payloads it replayed at open.
fn open<const A: usize, const REC: usize>(
    backing: &Backing,
    geometry: LogGeometry,
) -> (AppendLog<MockFlash<A>, REC>, Vec<Vec<u8>>) {
    let mut replayed = Vec::new();
    let log = AppendLog::open(backing.open_aligned::<A>(), geometry, MAGIC, |p| replayed.push(p.to_vec())).unwrap();
    (log, replayed)
}

/// Append `payload` to a log whose owner state is `state`, keeping `state`
/// in step (the snapshot re-emits it on compaction).
fn append<F: SectorIo<Error = ()>, const REC: usize>(
    log: &mut AppendLog<F, REC>,
    state: &mut Vec<Vec<u8>>,
    payload: &[u8],
) {
    let snapshot = state.clone();
    log.append(&[payload], |c: &mut Compactor<'_, F, REC>| {
        for p in &snapshot {
            c.push(&[p])?;
        }
        Ok(())
    })
    .unwrap();
    state.push(payload.to_vec());
}

/// The payloads a snapshot of `state` needs to keep: the owner below keeps
/// only the newest `keep`, so compaction shrinks the log.
fn trimmed(state: &mut Vec<Vec<u8>>, keep: usize) {
    let excess = state.len().saturating_sub(keep);
    state.drain(..excess);
}

// ============================================================================
// Format
// ============================================================================

/// Payloads of every length class replay in order, at byte and doubleword
/// write granularity.
fn variable_lengths_roundtrip<const A: usize, const REC: usize>() {
    let geometry = geometry(1, 2);
    let backing = backing_for(geometry);
    let (mut log, replayed) = open::<A, REC>(&backing, geometry);
    assert!(replayed.is_empty(), "a blank region replays nothing");

    let long: Vec<u8> = (0..=254u8).collect();
    let mut state = Vec::new();
    for payload in [&[][..], &[7], &long] {
        append(&mut log, &mut state, payload);
    }
    drop(log);

    let (_, replayed) = open::<A, REC>(&backing, geometry);
    assert_eq!(replayed, vec![vec![], vec![7], long]);
}

#[test]
fn variable_lengths_roundtrip_byte_granular() {
    variable_lengths_roundtrip::<1, 259>();
}

#[test]
fn variable_lengths_roundtrip_doubleword() {
    variable_lengths_roundtrip::<8, 264>();
}

/// The bytes on flash are exactly the documented frame, padded with 0xFF to
/// the write granule.
#[test]
fn record_frame_is_padded_to_the_write_granule() {
    let geometry = geometry(1, 2);
    let backing = backing_for(geometry);
    let (mut log, _) = open::<8, 16>(&backing, geometry);
    append(&mut log, &mut Vec::new(), &[0xA5]);

    // The first append compacts the blank region into bank 0, so the record
    // sits right behind bank 0's 16-byte padded header.
    let header_len = AppendLog::<MockFlash<8>, 16>::header_len() as usize;
    assert_eq!(header_len, 16);
    let crc = crc16(&[1, 0xFE, 0xA5]).to_be_bytes();
    let bytes = backing.bytes();
    assert_eq!(&bytes[header_len..header_len + 8], &[1, 0xFE, 0xA5, crc[0], crc[1], 0xFF, 0xFF, 0xFF]);
    assert!(bytes[header_len + 8..SECTOR as usize].iter().all(|&b| b == 0xFF));
}

#[test]
fn fill_counts_header_and_padded_records() {
    let geometry = geometry(1, 2);
    let backing = backing_for(geometry);
    let (mut log, _) = open::<1, 64>(&backing, geometry);
    assert_eq!(log.fill(), (10, SECTOR));
    assert!(log.compaction_pending(), "a blank region compacts on the first append");

    append(&mut log, &mut Vec::new(), &[1, 2, 3]);
    assert_eq!(log.fill(), (10 + 7, SECTOR));
    assert!(!log.compaction_pending());
}

/// A record may straddle a sector boundary inside a multi-sector bank, and
/// compaction still rotates whole banks.
#[test]
fn multi_sector_banks_replay_across_sector_boundaries() {
    let geometry = geometry(2, 2);
    let backing = backing_for(geometry);
    let (mut log, _) = open::<1, 128>(&backing, geometry);

    // 100-byte payloads frame to 104 bytes: the fifth record (at 10 + 4·104)
    // crosses the 512-byte sector boundary.
    let mut state = Vec::new();
    for i in 0..9u8 {
        append(&mut log, &mut state, &[i; 100]);
    }
    drop(log);
    let (mut log, replayed) = open::<1, 128>(&backing, geometry);
    assert_eq!(replayed, state);

    // Fill past the bank and keep only the last two payloads on compaction.
    for i in 9..40u8 {
        trimmed(&mut state, 2);
        append(&mut log, &mut state, &[i; 100]);
    }
    drop(log);
    // Every payload is the previous one plus one, so a correct replay is an
    // unbroken run ending at the newest payload.
    let (_, replayed) = open::<1, 128>(&backing, geometry);
    let expected: Vec<Vec<u8>> = (40 - replayed.len() as u8..40).map(|i| vec![i; 100]).collect();
    assert!(replayed.len() >= 3, "the snapshot and the appends behind it replay");
    assert_eq!(replayed, expected);
}

#[test]
fn foreign_magic_replays_nothing() {
    let geometry = geometry(1, 2);
    let backing = backing_for(geometry);
    let (mut log, _) = open::<1, 64>(&backing, geometry);
    append(&mut log, &mut Vec::new(), &[1]);
    drop(log);

    let mut replayed = 0;
    let _ = AppendLog::<_, 64>::open(backing.open(), geometry, MAGIC ^ 1, |_| replayed += 1).unwrap();
    assert_eq!(replayed, 0);
}

// ============================================================================
// Tears
// ============================================================================

/// A cut after the length pair but inside the payload leaves a record with
/// a known extent and a bad CRC. Replay skips it; the next append lands
/// behind it without re-programming it, and survives the next reboot.
#[test]
fn torn_payload_is_skipped_and_later_records_survive() {
    let geometry = geometry(1, 2);
    let backing = backing_for(geometry);
    let (mut log, _) = open::<1, 64>(&backing, geometry);
    let mut state = Vec::new();
    append(&mut log, &mut state, &[1; 8]);
    let torn_at = log.fill().0 as usize;

    backing.cut_power_after(5);
    append(&mut log, &mut state, &[2; 8]);
    drop(log);
    backing.restore_power();
    let torn_before = backing.bytes()[torn_at..torn_at + 12].to_vec();

    let (mut log, replayed) = open::<1, 64>(&backing, geometry);
    assert_eq!(replayed, vec![vec![1; 8]]);
    assert!(!log.compaction_pending(), "a torn payload has a known extent");
    append(&mut log, &mut vec![vec![1; 8]], &[3; 8]);
    assert_eq!(backing.bytes()[torn_at..torn_at + 12], torn_before[..], "the torn record was re-programmed");
    drop(log);

    let (_, replayed) = open::<1, 64>(&backing, geometry);
    assert_eq!(replayed, vec![vec![1; 8], vec![3; 8]]);
}

/// A partly programmed length pair has some bit still 1 in both octets, so it
/// is never a valid complement pair. Replay stops there, and the next append
/// compacts into a fresh bank instead of writing behind unparseable bytes.
#[test]
fn torn_length_stops_replay_and_forces_compaction() {
    let geometry = geometry(1, 2);
    let backing = backing_for(geometry);
    let (mut log, _) = open::<1, 64>(&backing, geometry);
    let mut state = Vec::new();
    append(&mut log, &mut state, &[1; 4]);
    let torn_at = log.fill().0 as usize;
    drop(log);

    // Intended pair 05/FA, cut with bits 3 and 2 of each still erased.
    backing.poke(torn_at, &[0x0F, 0xFE, 0x42]);
    let (mut log, replayed) = open::<1, 64>(&backing, geometry);
    assert_eq!(replayed, state);
    assert!(log.compaction_pending());

    append(&mut log, &mut state, &[2; 4]);
    assert_eq!(&backing.bytes()[torn_at..torn_at + 3], &[0x0F, 0xFE, 0x42], "the old bank was touched");
    drop(log);

    let (log, replayed) = open::<1, 64>(&backing, geometry);
    assert_eq!(replayed, vec![vec![1; 4], vec![2; 4]]);
    assert!(!log.compaction_pending());
}

/// A cut during compaction, before the new bank's header is programmed,
/// leaves the previous bank live.
#[test]
fn interrupted_compaction_keeps_the_previous_bank() {
    let geometry = geometry(1, 2);
    let backing = backing_for(geometry);
    let (mut log, _) = open::<1, 64>(&backing, geometry);
    let mut state = Vec::new();

    // Fill bank 0 exactly with 14-byte records until the next one compacts.
    let record = AppendLog::<MockFlash<1>, 64>::record_len(10);
    let mut next = 0u8;
    while log.fill().0 + record <= SECTOR {
        trimmed(&mut state, 1);
        append(&mut log, &mut state, &[next; 10]);
        next += 1;
    }
    let committed = state.clone();

    backing.cut_power_after(20); // snapshot record written, header not
    trimmed(&mut state, 1);
    append(&mut log, &mut state, &[0xEE; 10]);
    drop(log);
    backing.restore_power();

    let (_, replayed) = open::<1, 64>(&backing, geometry);
    assert_eq!(replayed.last(), committed.last());
    assert!(!replayed.contains(&vec![0xEE; 10]));
}

// ============================================================================
// Sizing mistakes
// ============================================================================

#[test]
#[should_panic(expected = "compaction snapshot overflows the bank")]
fn oversized_snapshot_panics() {
    let geometry = geometry(1, 2);
    let backing = backing_for(geometry);
    let (mut log, _) = open::<1, 259>(&backing, geometry);
    let _ = log.compact(|c| {
        for _ in 0..3 {
            c.push(&[&[0u8; 255]])?;
        }
        Ok(())
    });
}

#[test]
#[should_panic(expected = "rotation needs at least two banks")]
fn single_bank_panics() {
    let geometry = geometry(1, 1);
    let _ = open::<1, 64>(&backing_for(geometry), geometry);
}

#[test]
#[should_panic(expected = "payload exceeds the log's record size")]
fn oversized_payload_panics() {
    let geometry = geometry(1, 2);
    let (mut log, _) = open::<1, 16>(&backing_for(geometry), geometry);
    append(&mut log, &mut Vec::new(), &[0; 13]);
}
