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
fn user_save_pointer_matches_the_ets_mask_procedures() {
    let def = definition();
    // Volume 9 names 0115h UsrSavPtr. The value 48h comes from the ETS
    // 0020h/0021h mask-procedure fixtures rather than a standard resource
    // called ManagementStyle.
    assert_eq!(def.build_eeprom()[0x15], 0x48);
    assert_eq!(def.build_eeprom_for_mask(0x0021)[0x15], 0x48);
}
