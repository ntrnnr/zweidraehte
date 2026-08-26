//! The two TP1 BCU2 masks defined by 09/04/01: the legacy 0020h
//! compatibility target and the documented 0021h implementation.
//!
//! Data Secure is deliberately absent from this comparison. It is a
//! composable profile module, not a meaning encoded by mask 0021h.

mod common;
use common::{DUT, apdu, connect, exchange};

use zweidraehte_microdevice::device::{DeviceIdentity, Microdevice};
use zweidraehte_microdevice::families::bcu2::{Bcu2CoDescriptor, Bcu2DeviceDefinition, Bcu2Family};
use zweidraehte_microdevice::family::MicroDeviceFamily;
use zweidraehte_microdevice::frame::ApciCode;
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::messages::apdu::load_control::LoadState;
use zweidraehte_proto::pid;
use zweidraehte_proto::properties::PropertyAccess;

static COS: &[Bcu2CoDescriptor] = &[Bcu2CoDescriptor { data_ptr: 0xC6, config: 0x9F, value_type: 0x00 }];
static GAS: &[GroupAddress] = &[GroupAddress::from_three_level(1, 0, 1)];

fn definition() -> Bcu2DeviceDefinition {
    Bcu2DeviceDefinition {
        manufacturer_id: 0x0083,
        app_manufacturer_id: 0x0083,
        device_type: 0x1234,
        version: 1,
        pei_type: 0,
        individual_address: DUT,
        max_group_addresses: 4,
        max_associations: 4,
        ram_flags_ptr: 0xD0,
        comm_objects: COS,
        group_addresses: GAS,
        associations: &[(1, 0)],
        app_params: None,
    }
}

fn device<const MASK: u16>() -> Microdevice<Bcu2Family<MASK>> {
    let def = definition();
    let identity = DeviceIdentity {
        serial_number: [0, 0x83, 0, 0, 0, 1],
        order_info: [0; 10],
        hardware_type: [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
    };
    let mut dev = Microdevice::new(def.build_eeprom_for_mask(MASK), identity, 1);
    dev.mgmt.lsm[0].state = LoadState::Loaded;
    dev.mgmt.lsm[1].state = LoadState::Loaded;
    dev.mgmt.lsm[2].state = LoadState::Loaded;
    dev
}

#[test]
fn dd0_reports_mask_0021() {
    let mut dev = device::<0x0021>();
    connect(&mut dev);
    let rsp = exchange(&mut dev, 0, ApciCode::DeviceDescriptorRead, 0, &[], 0).expect("DD0 answered");
    assert_eq!(apdu(&rsp), &[0x43, 0x40, 0x00, 0x21]);
}

#[test]
fn ram2_matches_the_documented_0021_memory_map() {
    assert_eq!(Bcu2Family::<0x0021>::RAM2_BASE, 0x0900);
    assert_eq!(Bcu2Family::<0x0021>::RAM2_SIZE, 208);
}

#[test]
fn mask_0021_inverts_the_individual_address_write_enable_bit() {
    let def = definition();
    let enabled = def.build_eeprom_for_mask(0x0021);
    assert!(Bcu2Family::<0x0021>::individual_address_write_enabled(&enabled));

    let mut disabled = enabled;
    let base = zweidraehte_microdevice::families::bcu2::offsets::SERVICE_CONTROL;
    disabled[base..base + 2].copy_from_slice(&4u16.to_be_bytes());
    assert!(!Bcu2Family::<0x0021>::individual_address_write_enabled(&disabled));
}

#[test]
fn property_write_levels_match_the_mask_columns() {
    // 06 Profiles Annex A.2.3--A.2.6. The original implementation read
    // the generic System-2 column as mask 0020h and shifted every mask by
    // one column; pin the actual 0020h/0021h columns directly.
    for mask_0021 in [false, true] {
        let device = if mask_0021 {
            Bcu2Family::<0x0021>::property_spec_by_id(0, pid::DEVICE_CONTROL)
        } else {
            Bcu2Family::<0x0020>::property_spec_by_id(0, pid::DEVICE_CONTROL)
        }
        .expect("Device Control exists")
        .1;
        assert_eq!(device.descriptor.write_level, 0);

        let table = if mask_0021 {
            Bcu2Family::<0x0021>::property_spec_by_id(1, pid::LOAD_STATE_CONTROL)
        } else {
            Bcu2Family::<0x0020>::property_spec_by_id(1, pid::LOAD_STATE_CONTROL)
        }
        .expect("table Load State Control exists")
        .1;
        assert_eq!(table.descriptor.write_level, 1);

        let application = if mask_0021 {
            Bcu2Family::<0x0021>::property_spec_by_id(3, pid::LOAD_STATE_CONTROL)
        } else {
            Bcu2Family::<0x0020>::property_spec_by_id(3, pid::LOAD_STATE_CONTROL)
        }
        .expect("application Load State Control exists")
        .1;
        assert_eq!(application.descriptor.write_level, 0);
    }
}

#[test]
fn plain_0020_exposes_the_mandatory_writable_configuration_properties() {
    // 06 Profiles Annex A.2.3/A.2.6. Poll Group Settings belongs here
    // because polling is mandatory for the BCU2 profile (Annex 2.3.1), even
    // though the host-side property test cannot exercise a TP1 poll frame.
    for (object, property) in [
        (0, pid::SERVICE_CONTROL),
        (0, pid::DEVICE_CONTROL),
        (0, pid::PORT_CONFIGURATION),
        (0, pid::POLL_GROUP_SETTINGS),
        (3, pid::LOAD_STATE_CONTROL),
        (3, pid::RUN_STATE_CONTROL),
        (3, pid::PEI_TYPE),
    ] {
        let descriptor = Bcu2Family::<0x0020>::property_spec_by_id(object, property)
            .unwrap_or_else(|| panic!("object {object} lacks mandatory PID {property}"))
            .1
            .descriptor;
        assert_eq!(descriptor.access, PropertyAccess::ReadWrite, "object {object}, PID {property}");
        assert_eq!(descriptor.write_level, 0, "object {object}, PID {property}");
    }
}

#[test]
fn factory_property_access_matches_each_bcu2_mask() {
    for property in [pid::SERIAL_NUMBER, pid::MANUFACTURER_ID, pid::ORDER_INFO, pid::MANUFACTURER_DATA] {
        let mask_0020 = Bcu2Family::<0x0020>::property_spec_by_id(0, property)
            .unwrap_or_else(|| panic!("mask 0020h lacks PID {property}"))
            .1
            .descriptor;

        assert_eq!(mask_0020.access, PropertyAccess::ReadOnly, "mask 0020h PID {property}");

        let mask_0021 = Bcu2Family::<0x0021>::property_spec_by_id(0, property)
            .unwrap_or_else(|| panic!("mask 0021h lacks PID {property}"))
            .1
            .descriptor;

        assert_eq!(mask_0021.access, PropertyAccess::ReadWrite, "mask 0021h PID {property}");
        assert_eq!(mask_0021.write_level, 0, "mask 0021h PID {property}");
    }
}

#[test]
fn plain_0021_factory_properties_roundtrip() {
    let mut dev = device::<0x0021>();
    connect(&mut dev);

    for (iteration, property, value) in [
        (0, pid::SERIAL_NUMBER, &[1, 2, 3, 4, 5, 6][..]),
        (1, pid::MANUFACTURER_ID, &[0x12, 0x34][..]),
        (2, pid::ORDER_INFO, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9][..]),
        (3, pid::MANUFACTURER_DATA, &[0xAA, 0xBB, 0xCC, 0xDD][..]),
    ] {
        let mut write = vec![0, property as u8, 0x10, 0x01];
        write.extend_from_slice(value);

        let written = exchange(&mut dev, iteration * 2, ApciCode::PropertyValueWrite, 0, &write, 0)
            .unwrap_or_else(|| panic!("PID {property} write answered"));

        assert_eq!(&apdu(&written)[6..], value, "PID {property} write response");

        let read =
            exchange(&mut dev, iteration * 2 + 1, ApciCode::PropertyValueRead, 0, &[0, property as u8, 0x10, 0x01], 0)
                .unwrap_or_else(|| panic!("PID {property} read answered"));

        assert_eq!(&apdu(&read)[6..], value, "PID {property} read response");
    }
}

#[test]
#[cfg(feature = "std")]
fn plain_0021_factory_properties_persist() {
    use zweidraehte_microdevice::snapshot::MicroSnapshot;

    let mut dev = device::<0x0021>();
    connect(&mut dev);

    for (seq, property, value) in [
        (0, pid::SERIAL_NUMBER, &[1, 2, 3, 4, 5, 6][..]),
        (1, pid::MANUFACTURER_ID, &[0x12, 0x34][..]),
        (2, pid::ORDER_INFO, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9][..]),
        (3, pid::MANUFACTURER_DATA, &[0xAA, 0xBB, 0xCC, 0xDD][..]),
    ] {
        let mut write = vec![0, property as u8, 0x10, 0x01];
        write.extend_from_slice(value);

        exchange(&mut dev, seq, ApciCode::PropertyValueWrite, 0, &write, 0)
            .unwrap_or_else(|| panic!("PID {property} write answered"));
    }

    let snapshot = MicroSnapshot::capture(&dev);
    let mut restored = snapshot.restore::<Bcu2Family<0x0021>>(
        DeviceIdentity { serial_number: [0; 6], order_info: [0; 10], hardware_type: [0; 6] },
        1,
    );
    connect(&mut restored);

    for (seq, property, expected) in [
        (0, pid::SERIAL_NUMBER, &[1, 2, 3, 4, 5, 6][..]),
        (1, pid::MANUFACTURER_ID, &[0x12, 0x34][..]),
        (2, pid::ORDER_INFO, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9][..]),
        (3, pid::MANUFACTURER_DATA, &[0xAA, 0xBB, 0xCC, 0xDD][..]),
    ] {
        let read = exchange(&mut restored, seq, ApciCode::PropertyValueRead, 0, &[0, property as u8, 0x10, 0x01], 0)
            .unwrap_or_else(|| panic!("PID {property} persisted read answered"));

        assert_eq!(&apdu(&read)[6..], expected, "PID {property} persisted value");
    }
}

#[test]
fn user_save_pointer_matches_the_ets_mask_procedures() {
    let def = definition();
    // Volume 9 names 0115h UsrSavPtr. The value 48h comes from the ETS
    // 0020h/0021h mask-procedure fixtures rather than a standard resource
    // called ManagementStyle.
    assert_eq!(def.build_eeprom()[0x15], 0x48);
    assert_eq!(def.build_eeprom_for_mask(0x0021)[0x15], 0x48);
}
