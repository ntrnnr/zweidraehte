//! [`load`] and [`store`] over the NOR flash model.

use crate::Area;
use crate::mock::Backing;
use crate::provisioning::{Error, ProvisioningError, ProvisioningRecord, load, store};

const SECTOR: usize = 256;

/// The second of three sectors, so a stray write on either side shows.
const AREA: Area = Area::new(SECTOR as u32, SECTOR as u32);

fn secure_record() -> ProvisioningRecord {
    ProvisioningRecord {
        serial: [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78],
        fdsk: Some([0xA5; 16]),
        mac: Some([0x02, 0x00, 0x00, 0x12, 0x34, 0x56]),
    }
}

#[test]
fn a_record_round_trips_on_byte_and_doubleword_media() {
    let backing = Backing::new(3 * SECTOR, SECTOR);
    store(&mut backing.open(), AREA, &secure_record()).expect("store on a byte-granular medium");
    assert_eq!(load(&mut backing.open(), AREA), Ok(secure_record()));

    // The STM32G0 programs doublewords; the mock rejects a write that is not
    // whole granules, so this also proves the padding.
    let backing = Backing::new(3 * SECTOR, SECTOR);
    store(&mut backing.open_aligned::<8>(), AREA, &secure_record()).expect("store on a doubleword medium");
    assert_eq!(load(&mut backing.open_aligned::<8>(), AREA), Ok(secure_record()));
}

#[test]
fn a_blank_area_has_no_record() {
    let backing = Backing::new(3 * SECTOR, SECTOR);

    assert_eq!(load(&mut backing.open(), AREA), Err(Error::Record(ProvisioningError::MagicMismatch)));
}

#[test]
fn a_store_replaces_the_previous_record() {
    let backing = Backing::new(3 * SECTOR, SECTOR);
    store(&mut backing.open(), AREA, &secure_record()).expect("store the first record");

    // A plain re-provisioning drops the FDSK and MAC. Without the erase the
    // NOR model would AND the two encodings together and fail the CRC.
    let plain = ProvisioningRecord::from_serial([0x00, 0xFA, 0x00, 0x00, 0x00, 0x01]);
    store(&mut backing.open(), AREA, &plain).expect("store the replacement");

    assert_eq!(load(&mut backing.open(), AREA), Ok(plain));
}

#[test]
fn a_store_stays_inside_its_area() {
    let backing = Backing::new(3 * SECTOR, SECTOR);
    store(&mut backing.open(), AREA, &secure_record()).expect("store the record");

    let bytes = backing.bytes();
    assert!(bytes[..SECTOR].iter().all(|&b| b == 0xFF), "the sector below was written");
    assert!(bytes[2 * SECTOR..].iter().all(|&b| b == 0xFF), "the sector above was written");
}

#[test]
fn an_io_failure_is_reported_as_such() {
    let backing = Backing::new(3 * SECTOR, SECTOR);
    backing.set_failing(true);

    assert_eq!(store(&mut backing.open(), AREA, &secure_record()), Err(Error::Io(())));
}
