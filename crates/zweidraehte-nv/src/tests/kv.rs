//! Behaviour and crash-recovery tests of [`WearLeveledKv`].

use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

use crate::mock::{Backing, MockFlash};
use crate::{KeyValueStore, LogGeometry, WearLeveledKv};

const SIAT_MAGIC: u32 = u32::from_be_bytes(*b"KNXR");
const MC_MAGIC: u32 = u32::from_be_bytes(*b"KNXM");
const NS: u8 = 0x01;

/// The shape of today's RP2040 SIAT region: four 4 KiB sectors, one bank
/// each.
const SECTOR: u32 = 4096;
const SIAT_GEOMETRY: LogGeometry = LogGeometry { offset: 0, sector_size: SECTOR, sectors_per_bank: 1, banks: 4 };

type SiatKv = WearLeveledKv<MockFlash<1>, 16>;

fn siat_backing() -> Backing {
    Backing::new((SECTOR * 4) as usize, SECTOR as usize)
}

fn open_siat(backing: &Backing) -> SiatKv {
    WearLeveledKv::open(backing.open(), SIAT_GEOMETRY, SIAT_MAGIC).unwrap()
}

fn get<S: KeyValueStore<Error = ()>>(store: &S, ns: u8, key: &[u8]) -> Option<Vec<u8>> {
    let mut buf = [0u8; 8];
    store.get(ns, key, &mut buf).unwrap().map(|len| buf[..len].to_vec())
}

// ============================================================================
// Behaviour
// ============================================================================

#[test]
fn get_put_overwrite_remove() {
    let mut store = open_siat(&siat_backing());
    assert_eq!(get(&store, NS, &[1, 2]), None);

    store.put(NS, &[1, 2], &[9; 6]).unwrap();
    assert_eq!(get(&store, NS, &[1, 2]), Some(vec![9; 6]));

    store.put(NS, &[1, 2], &[8; 6]).unwrap();
    assert_eq!(get(&store, NS, &[1, 2]), Some(vec![8; 6]));

    store.remove(NS, &[1, 2]).unwrap();
    assert_eq!(get(&store, NS, &[1, 2]), None);
}

/// Namespaces keep equal keys apart, `for_each` visits one namespace, and
/// empty keys and values (singletons, zero-length markers) round-trip.
#[test]
fn namespaces_and_empty_fields_roundtrip_a_reboot() {
    let backing = siat_backing();
    let mut store = open_siat(&backing);
    store.put(1, &[0], &[1; 8]).unwrap();
    store.put(2, &[0], &[2; 6]).unwrap();
    store.put(3, &[], &[]).unwrap();
    drop(store);

    let store = open_siat(&backing);
    assert_eq!(get(&store, 1, &[0]), Some(vec![1; 8]));
    assert_eq!(get(&store, 2, &[0]), Some(vec![2; 6]));
    assert_eq!(get(&store, 3, &[]), Some(vec![]));

    let mut seen = Vec::new();
    store.for_each(2, &mut |key, val| seen.push((key.to_vec(), val.to_vec())));
    assert_eq!(seen, vec![(vec![0], vec![2; 6])]);
}

#[test]
fn survives_reboot_and_rotation() {
    let backing = siat_backing();
    let mut store = open_siat(&backing);
    // Enough writes to one key to rotate through every bank several times.
    for v in 0u64..2000 {
        store.put(NS, &[0, 1], &v.to_be_bytes()[2..]).unwrap();
    }
    store.put(NS, &[0, 2], &[42; 6]).unwrap();
    drop(store);

    let store = open_siat(&backing);
    assert_eq!(get(&store, NS, &[0, 1]), Some(1999u64.to_be_bytes()[2..].to_vec()));
    assert_eq!(get(&store, NS, &[0, 2]), Some(vec![42; 6]));
}

/// STM32G0 programs doublewords; the same records work at that grain.
#[test]
fn doubleword_medium_roundtrips_through_rotation() {
    let backing = Backing::new(1024, 256);
    let geometry = LogGeometry { offset: 0, sector_size: 256, sectors_per_bank: 1, banks: 4 };
    let mut store = WearLeveledKv::<MockFlash<8>, 4>::open(backing.open_aligned(), geometry, SIAT_MAGIC).unwrap();
    for v in 0..100u8 {
        store.put(NS, &[v % 3], &[v; 6]).unwrap();
    }
    drop(store);

    let store = WearLeveledKv::<MockFlash<8>, 4>::open(backing.open_aligned(), geometry, SIAT_MAGIC).unwrap();
    assert_eq!(get(&store, NS, &[0]), Some(vec![99; 6]));
    assert_eq!(get(&store, NS, &[1]), Some(vec![97; 6]));
    assert_eq!(get(&store, NS, &[2]), Some(vec![98; 6]));
}

/// A region placed at an offset stays inside it, and a store bound to
/// another region's magic never adopts its records.
#[test]
fn placed_region_is_isolated_by_offset_and_magic() {
    let backing = siat_backing();
    let mc_geometry = LogGeometry { offset: 2 * SECTOR, sector_size: SECTOR, sectors_per_bank: 1, banks: 2 };

    let mut mc = WearLeveledKv::<_, 1>::open(backing.open(), mc_geometry, MC_MAGIC).unwrap();
    mc.put(0x10, &[0], &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]).unwrap();
    drop(mc);

    let mc = WearLeveledKv::<_, 1>::open(backing.open(), mc_geometry, MC_MAGIC).unwrap();
    assert_eq!(get(&mc, 0x10, &[0]), Some(vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]));
    assert!(backing.bytes()[..2 * SECTOR as usize].iter().all(|&b| b == 0xFF), "data leaked below the region offset");

    let foreign = WearLeveledKv::<_, 1>::open(backing.open(), mc_geometry, SIAT_MAGIC).unwrap();
    assert_eq!(get(&foreign, 0x10, &[0]), None, "foreign-magic record was adopted");
}

// ============================================================================
// Sizing mistakes
// ============================================================================

#[test]
#[should_panic(expected = "ENTRIES exceeds what one bank can hold after compaction")]
fn too_many_entries_panics() {
    // 4096 / 16 = 256 records per bank, one of them the header.
    let _ = WearLeveledKv::<MockFlash<1>, 255>::open(siat_backing().open(), SIAT_GEOMETRY, SIAT_MAGIC);
}

#[test]
fn largest_entry_count_that_fits_opens_and_rotates() {
    // Header (10 → one 16-byte slot's worth) + 254 entries + one new record.
    let backing = siat_backing();
    let mut store = WearLeveledKv::<MockFlash<1>, 254>::open(backing.open(), SIAT_GEOMETRY, SIAT_MAGIC).unwrap();
    for i in 0..254u16 {
        store.put(NS, &i.to_be_bytes(), &[0; 8]).unwrap();
    }
    for round in 0..3u8 {
        for i in 0..254u16 {
            store.put(NS, &i.to_be_bytes(), &[round; 8]).unwrap();
        }
    }
    drop(store);
    let store = WearLeveledKv::<MockFlash<1>, 254>::open(backing.open(), SIAT_GEOMETRY, SIAT_MAGIC).unwrap();
    assert_eq!(get(&store, NS, &253u16.to_be_bytes()), Some(vec![2; 8]));
}

// ============================================================================
// Power-cut sweep
// ============================================================================

/// One scripted operation.
#[derive(Clone, Copy)]
enum Op {
    Put(u8, u8),
    Remove(u8),
}

/// A mix of overwrites and removals on four keys, long enough to rotate the
/// small test geometry through its banks several times.
fn script() -> Vec<Op> {
    (0..120u8).map(|i| if i % 7 == 3 { Op::Remove(i % 4) } else { Op::Put(i % 4, i) }).collect()
}

type Model = BTreeMap<u8, Vec<u8>>;

fn apply<S: KeyValueStore<Error = ()>>(store: &mut S, model: &mut Model, op: Op) {
    match op {
        Op::Put(key, v) => {
            store.put(NS, &[key], &[v; 6]).unwrap();
            model.insert(key, vec![v; 6]);
        }
        Op::Remove(key) => {
            store.remove(NS, &[key]).unwrap();
            model.remove(&key);
        }
    }
}

fn contents<S: KeyValueStore<Error = ()>>(store: &S) -> Model {
    (0..4u8).filter_map(|key| get(store, NS, &[key]).map(|v| (key, v))).collect()
}

/// For every byte at which power can fail during the script, the recovered
/// store equals the model after the last completed operation or after the
/// interrupted one — never a mix, never older. A second boot after further
/// writes proves the recovered log is also safe to append to.
fn power_cut_sweep<const A: usize>() {
    let geometry = LogGeometry { offset: 0, sector_size: 256, sectors_per_bank: 1, banks: 3 };
    let open = |backing: &Backing| {
        WearLeveledKv::<MockFlash<A>, 4>::open(backing.open_aligned(), geometry, SIAT_MAGIC).unwrap()
    };

    // A clean run gives the model after each op and the total bytes written.
    let clean = Backing::new(768, 256);
    let mut store = open(&clean);
    let mut model = Model::new();
    let mut models = vec![model.clone()];
    for op in script() {
        apply(&mut store, &mut model, op);
        models.push(model.clone());
    }
    let total = clean.bytes_written();
    assert!(total > 3 * 256, "the script must rotate through every bank");

    for budget in 0..total {
        let backing = Backing::new(768, 256);
        let mut store = open(&backing);
        backing.cut_power_after(budget);

        // `completed` counts ops that finished while power was still on.
        let mut completed = 0;
        let mut scratch = Model::new();
        for op in script() {
            apply(&mut store, &mut scratch, op);
            if backing.power_lost() {
                break;
            }
            completed += 1;
        }
        drop(store);
        backing.restore_power();

        let mut store = open(&backing);
        let recovered = contents(&store);
        assert!(
            recovered == models[completed] || recovered == models[completed + 1],
            "budget {budget}: recovered {recovered:?} after {completed} completed ops"
        );

        let mut expected = recovered;
        for (key, v) in [(0u8, 0xA0u8), (1, 0xA1), (0, 0xA2)] {
            apply(&mut store, &mut expected, Op::Put(key, v));
        }
        drop(store);
        assert_eq!(contents(&open(&backing)), expected, "budget {budget}: writes after recovery were lost");
    }
}

#[test]
fn power_cut_sweep_byte_granular() {
    power_cut_sweep::<1>();
}

#[test]
fn power_cut_sweep_doubleword() {
    power_cut_sweep::<8>();
}
