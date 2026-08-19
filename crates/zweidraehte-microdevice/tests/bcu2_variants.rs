//! The BCU2 sibling masks 0021h and 0025h on the same family core:
//! what actually differs from 0020h on the device side — the DD0
//! value, mask 0025h's `PID_HARDWARE_TYPE` identity property and
//! missing ManagementStyle cell, and the Absolute Stack Allocation
//! sub-control the 0021h/0025h profiles require.

mod common;
use common::{DUT, apdu, connect, exchange};

use zweidraehte_microdevice::device::{DeviceIdentity, Microdevice};
use zweidraehte_microdevice::families::bcu2::{Bcu2CoDescriptor, Bcu2DeviceDefinition, Bcu2Family};
use zweidraehte_microdevice::frame::ApciCode;
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::messages::apdu::load_control::{
    AbsSegment, LoadControlRecord, LoadEvent, LoadSegment, LoadState,
};

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
fn dd0_reports_the_sibling_masks() {
    let mut dev = device::<0x0021>();
    connect(&mut dev);
    let rsp = exchange(&mut dev, 0, ApciCode::DeviceDescriptorRead, 0, &[], 0).expect("DD0 answered");
    assert_eq!(apdu(&rsp), &[0x43, 0x40, 0x00, 0x21]);

    let mut dev = device::<0x0025>();
    connect(&mut dev);
    let rsp = exchange(&mut dev, 0, ApciCode::DeviceDescriptorRead, 0, &[], 0).expect("DD0 answered");
    assert_eq!(apdu(&rsp), &[0x43, 0x40, 0x00, 0x25]);
}

#[test]
fn hardware_type_answers_on_0025_only() {
    // Mask 0025h (AN059) adds the PID 78 identity resources so ETS can
    // guard hardware compatibility.
    let mut dev = device::<0x0025>();
    connect(&mut dev);
    let rsp = exchange(&mut dev, 0, ApciCode::PropertyValueRead, 0, &[0, 78, 0x10, 0x01], 0).expect("answered");
    assert_eq!(&apdu(&rsp)[6..12], &[0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
    let rsp = exchange(&mut dev, 1, ApciCode::PropertyDescriptionRead, 0, &[0, 78, 0], 0).expect("described");
    assert_eq!(&apdu(&rsp)[2..], &[0x00, 0x4E, 0x0B, 0x16, 0x60, 0x01, 0x30]);

    // The HC05 masks predate the property: negative response (element
    // count zeroed, no data).
    let mut dev = device::<0x0020>();
    connect(&mut dev);
    let rsp = exchange(&mut dev, 0, ApciCode::PropertyValueRead, 0, &[0, 78, 0x10, 0x01], 0).expect("answered");
    assert_eq!(apdu(&rsp).len(), 6, "no data in the negative response");
    assert_eq!(apdu(&rsp)[4] & 0xF0, 0, "element count zeroed");
    let rsp = exchange(&mut dev, 1, ApciCode::PropertyDescriptionRead, 0, &[0, 78, 0], 0).expect("negative reply");
    assert_eq!(&apdu(&rsp)[2..], &[0x00, 0x4E, 0x00, 0, 0, 0, 0]);
}

#[test]
fn stack_allocation_record_is_accepted_while_loading() {
    // 06 Profiles: masks 0021h/0025h additionally require the Absolute
    // Stack Allocation sub-control (event 03h, segment 01h). The stack
    // announcement is informational for a device that runs no HC05
    // machine code — the machine must stay in Loading, not error out.
    let mut dev = device::<0x0021>();
    connect(&mut dev);

    // Application controls on 0021h require level 0. A wrong key drops
    // the connection to free access and the write must have no side effect.
    let rsp = exchange(&mut dev, 0, ApciCode::AuthorizeRequest, 0, &[0x00, 0xDE, 0xAD, 0xBE, 0xEF], 0)
        .expect("authorize answered");
    assert_eq!(apdu(&rsp)[2], 3);
    let rsp =
        exchange(&mut dev, 1, ApciCode::PropertyValueWrite, 0, &[3, 5, 0x10, 0x01, 0x04], 0).expect("denial answered");
    assert_eq!(&apdu(&rsp)[2..], &[3, 5, 0, 1]);
    assert_eq!(dev.mgmt.lsm[2].state, LoadState::Loaded);

    let rsp =
        exchange(&mut dev, 2, ApciCode::AuthorizeRequest, 0, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF], 0).expect("authorized");
    assert_eq!(apdu(&rsp)[2], 0);

    let mut seq = 3u8;
    let mut send_record = |dev: &mut Microdevice<Bcu2Family<0x0021>>, obj: u8, record: &[u8]| -> Vec<u8> {
        let mut payload = vec![obj, 5, 0x10, 0x01];
        payload.extend_from_slice(record);
        let rsp = exchange(dev, seq, ApciCode::PropertyValueWrite, 0, &payload, 0).expect("property write answered");
        seq = (seq + 1) & 0x0F;
        rsp
    };

    let rsp = send_record(&mut dev, 3, &LoadControlRecord::event(LoadEvent::Unload));
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Unloaded));
    let rsp = send_record(&mut dev, 3, &LoadControlRecord::event(LoadEvent::StartLoading));
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Loading));

    let mut stack_record = LoadControlRecord::abs_segment(&AbsSegment::eeprom(0x0972, 0x0018));
    stack_record[1] = LoadSegment::AbsoluteStack.into();
    let rsp = send_record(&mut dev, 3, &stack_record);
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Loading), "stack record keeps Loading");

    let rsp = send_record(&mut dev, 3, &LoadControlRecord::abs_segment(&AbsSegment::eeprom(0x011E, 0x0080)));
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Loading));
    let rsp = send_record(&mut dev, 3, &LoadControlRecord::event(LoadEvent::LoadCompleted));
    assert_eq!(apdu(&rsp)[6], u8::from(LoadState::Loaded));
}

#[test]
fn management_style_cell_exists_on_hc05_masks_only() {
    let def = definition();
    // 0020h/0021h expose ManagementStyle 48h at 0115h; 0025h declares
    // the style as a master-data constant and leaves the cell blank.
    assert_eq!(def.build_eeprom()[0x15], 0x48);
    assert_eq!(def.build_eeprom_for_mask(0x0021)[0x15], 0x48);
    assert_eq!(def.build_eeprom_for_mask(0x0025)[0x15], 0x00);
}
