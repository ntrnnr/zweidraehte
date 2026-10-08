//! The independent watermark survives reboot, interruption, and erase.

use crate::mock::Backing;
use crate::stores::mc_timer::MAGIC;
use crate::{ByteMcTimer, LogGeometry, McTimerStore, WearLeveledKv};

#[test]
fn byte_slots_keep_the_last_committed_value_on_power_cut() {
    for cut in 0..=13 {
        let medium = Backing::new(ByteMcTimer::<crate::mock::MockBytes>::REGION_LEN as usize, 1);
        let mut store = ByteMcTimer::new(medium.open_bytes(), 0);
        assert_eq!(store.load().expect("fresh read"), None);
        store.save(100).expect("first value");

        medium.cut_power_after(cut);
        store.save(200).expect("power cut is silent");
        medium.restore_power();

        let mut rebooted = ByteMcTimer::new(medium.open_bytes(), 0);
        assert_eq!(rebooted.load().expect("reboot"), Some(if cut == 13 { 200 } else { 100 }));
        rebooted.clear().expect("clear");
        assert_eq!(ByteMcTimer::new(medium.open_bytes(), 0).load().expect("reboot after clear"), None);
    }
}

#[test]
fn flash_watermark_has_its_own_log() {
    let medium = Backing::new(8192, 4096);
    let geometry = LogGeometry::one_sector_per_bank(0, 8192, 4096);
    let open = || WearLeveledKv::<_, 1>::open(medium.open(), geometry, MAGIC).expect("open watermark log");

    let mut store = open();
    assert_eq!(McTimerStore::load(&store).expect("fresh read"), None);
    McTimerStore::save(&mut store, 123_456).expect("save");
    drop(store);

    let mut store = open();
    assert_eq!(McTimerStore::load(&store).expect("reboot"), Some(123_456));
    McTimerStore::clear(&mut store).expect("clear");
    assert_eq!(McTimerStore::load(&open()).expect("reboot after clear"), None);
}
