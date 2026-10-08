//! The firmware persistence record: encode a configured device, decode it,
//! and bring up a device that matches it, for both families the STM32 micro
//! targets ship.

use zweidraehte_microdevice::device::{DeviceIdentity, Microdevice};
use zweidraehte_microdevice::families::bcu1::Bcu1Family;
use zweidraehte_microdevice::families::bcu2::Bcu2Family;
use zweidraehte_microdevice::families::system7::System7Family;
use zweidraehte_microdevice::family::MicroDeviceFamily;
use zweidraehte_microdevice::frame::MAX_FRAME;
use zweidraehte_microdevice::management::ManagementState;
use zweidraehte_microdevice::persist::{StoredManagement, encode, management_len};
use zweidraehte_microdevice::security::NoSecurity;
use zweidraehte_proto::messages::apdu::load_control::LoadState;
use zweidraehte_proto::pid;
use zweidraehte_proto::properties::PropertyAccess;

type Bcu2 = Bcu2Family;
type System7 = System7Family<0x400, 0x4200, 0x0083, 0x0705, 1, 0>;

/// The compiled-in identity both the original and the restored device start from.
fn identity() -> DeviceIdentity {
    DeviceIdentity { serial_number: [0, 0x83, 0, 0, 0, 1], order_info: [0; 10], hardware_type: [0; 6] }
}

/// A device with every persisted field away from its factory value.
fn configured<F: MicroDeviceFamily>() -> Microdevice<F> {
    let mut eeprom = F::blank_eeprom();
    for (index, byte) in eeprom.as_mut().iter_mut().enumerate() {
        *byte = index as u8;
    }

    let mut identity = identity();
    identity.hardware_type = [1, 2, 3, 4, 5, 6];

    let mut device: Microdevice<F> = Microdevice::new(eeprom, identity, 1);
    for (level, key) in device.mgmt.auth_keys[..F::AUTH_LEVELS].iter_mut().enumerate() {
        *key = [level as u8, 0x11, 0x22, 0x33];
    }
    // As a key write does: no key is the default one any more, so the
    // disconnected access level becomes the free level.
    device.mgmt.reset_connection_auth::<F>();
    for (machine, lsm) in device.mgmt.lsm[..F::LSM_COUNT].iter_mut().enumerate() {
        lsm.state = if machine % 2 == 0 { LoadState::Loaded } else { LoadState::Err };
        lsm.table_ref = 0x4000 + machine as u16 * 0x100;
    }
    device.mgmt.option_reg = 0x5A;
    device.mgmt.program_version = Some([0x00, 0x83, 0x12, 0x34, 0x05]);
    device
}

fn round_trip<F: MicroDeviceFamily>() {
    let original = configured::<F>();
    let mut record = vec![0u8; management_len::<F>()];
    encode(&original, &mut record);

    let stored = StoredManagement::<F>::decode(&record).expect("a record of the right length decodes");
    let restored: Microdevice<F, MAX_FRAME, NoSecurity> = stored.into_device(identity(), 1, ());

    assert_eq!(restored.eeprom(), original.eeprom());
    assert_eq!(restored.mgmt.auth_keys, original.mgmt.auth_keys);
    for (restored, original) in restored.mgmt.lsm.iter().zip(&original.mgmt.lsm) {
        assert_eq!(restored.state, original.state);
        assert_eq!(restored.table_ref, original.table_ref);
    }
    assert_eq!(restored.mgmt.option_reg, 0x5A);

    // Only a family whose downloads change them keeps the hardware type and
    // the program version; the others boot with the compiled-in identity.
    if F::DOWNLOAD_IDENTITY {
        assert_eq!(
            restored.hardware_type(),
            &[1, 2, 3, 4, 5, 6],
            "the stored hardware type replaces the compiled-in one"
        );
        assert_eq!(restored.mgmt.program_version, Some([0x00, 0x83, 0x12, 0x34, 0x05]));
    } else {
        assert_eq!(restored.hardware_type(), &[0; 6]);
        assert_eq!(restored.mgmt.program_version, None);
    }
    assert_eq!(restored.mgmt.auth_level, original.mgmt.auth_level, "the access level resolves from the restored keys");
}

#[test]
fn bcu2_record_round_trips() {
    round_trip::<Bcu2>();
}

#[test]
fn system7_record_round_trips() {
    round_trip::<System7>();
}

#[test]
fn decode_rejects_a_record_of_another_length() {
    let record = vec![0u8; management_len::<Bcu2>()];

    assert!(StoredManagement::<Bcu2>::decode(&record[1..]).is_none());
    assert!(StoredManagement::<System7>::decode(&record).is_none(), "the families' records differ in length");
}

#[test]
fn an_unknown_load_state_restores_as_unloaded() {
    let original = configured::<Bcu2>();
    let mut record = vec![0u8; management_len::<Bcu2>()];
    encode(&original, &mut record);

    // The first load-state octet follows the EEPROM image and the keys.
    record[<Bcu2 as MicroDeviceFamily>::EEPROM_SIZE + <Bcu2 as MicroDeviceFamily>::AUTH_LEVELS * 4] = 0xEE;

    let stored = StoredManagement::<Bcu2>::decode(&record).expect("the length is right");
    let restored: Microdevice<Bcu2> = stored.into_device(identity(), 1, ());
    assert_eq!(restored.mgmt.lsm[0].state, LoadState::Unloaded);
}

/// `DOWNLOAD_IDENTITY` must be set exactly when a download can change an
/// identity value the EEPROM image does not hold: a writable
/// PID_HARDWARE_TYPE, or a program version the task segment announces.
/// Otherwise a restart silently drops the value, or the record carries
/// bytes nothing writes.
fn download_identity_matches_the_family<F: MicroDeviceFamily>() {
    let writable_hardware_type = F::property_spec_by_id(0, pid::device::HARDWARE_TYPE)
        .is_some_and(|(_, spec)| spec.descriptor.access == PropertyAccess::ReadWrite);

    let mut mgmt = ManagementState::new();
    for machine in 0..F::LSM_COUNT {
        F::task_segment_loaded(machine, [0x00, 0x83, 0x12, 0x34, 0x05], &mut mgmt);
    }
    let task_segment_version = mgmt.program_version.is_some();

    assert_eq!(
        F::DOWNLOAD_IDENTITY,
        writable_hardware_type || task_segment_version,
        "DOWNLOAD_IDENTITY of {}",
        core::any::type_name::<F>()
    );
}

#[test]
fn download_identity_matches_every_family() {
    download_identity_matches_the_family::<Bcu1Family>();
    download_identity_matches_the_family::<Bcu2Family<0x0020>>();
    download_identity_matches_the_family::<Bcu2Family<0x0021>>();
    download_identity_matches_the_family::<Bcu2Family<0x0025>>();
    download_identity_matches_the_family::<System7>();
}
