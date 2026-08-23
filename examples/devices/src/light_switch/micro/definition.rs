//! Baked BCU2 and System 7 product definitions for the micro stack.

use zweidraehte_microdevice::families::CoDescriptor;
use zweidraehte_microdevice::families::bcu2::Bcu2DeviceDefinition;
use zweidraehte_microdevice::families::builder::{build_bcu2_descriptors, build_system7_descriptors};
use zweidraehte_microdevice::families::system7::{System7CoDescriptor, System7DeviceDefinition, System7Family};
use zweidraehte_proto::address::IndividualAddress;

use super::super::LightSwitchDevice;
use super::super::comm_objs::LightSwitchComObjects;
use super::super::params::DEFAULT_PARAM_BYTES;

/// Page-0 RAM address of the first object's value slot. Slot widths come from
/// the declaration, so the layout follows the shared metadata.
const DATA_BASE: u8 = 0xC6;
/// Page-0 RAM address of the first RAM-flags byte.
const RAM_FLAGS_PTR: u8 = 0xD0;

/// The RT2 group object table baked into the BCU2 boot image and product
/// database. It is derived from the same declaration as the full-stack
/// runtime container.
pub(super) const CO_DESCRIPTORS_BCU2: [CoDescriptor; 6] = build_bcu2_descriptors(
    LightSwitchComObjects::ETS_COMM_OBJECTS,
    LightSwitchComObjects::ETS_COMM_OBJECT_REFS,
    DATA_BASE,
);

/// The micro System 7 group object table, with two-byte data pointers.
pub(super) const CO_DESCRIPTORS_S7: [System7CoDescriptor; 6] = build_system7_descriptors(
    LightSwitchComObjects::ETS_COMM_OBJECTS,
    LightSwitchComObjects::ETS_COMM_OBJECT_REFS,
    DATA_BASE as u16,
);

/// Image offset (from 0100h) of the BCU2 parameter block — device address
/// 0200h, clear of the RT2 table page below it.
pub const BCU2_PARAMS_IMAGE_OFFSET: usize = 0x100;

/// Data Secure table capacities shared by the MV-0021 firmware and product
/// metadata. P2P is deliberately absent; the micro profile supports tool
/// access and secure group communication only.
pub const BCU2_SECURE_SIAT_CAPACITY: usize = 8;
pub const BCU2_SECURE_GROUP_KEY_CAPACITY: usize = LightSwitchDevice::MAX_ADDRESS_TABLE_ENTRIES as usize;
pub const BCU2_SECURE_GROUP_OBJECT_CAPACITY: usize = LightSwitchDevice::MAX_COM_OBJECTS as usize;
pub const BCU2_SECURE_P2P_KEY_CAPACITY: usize = 0;

/// The micro System 7 family: 1 KiB of user EEPROM from 4000h, with its group
/// object table published at 4200h.
pub type LightSwitchS7Family = System7Family<0x400, 0x4200>;

/// Image offset (from 4000h) of the System 7 parameter block at device address
/// 4300h.
pub const S7_PARAMS_IMAGE_OFFSET: usize = 0x300;

/// The BCU2 (mask 0020h) light-switch product definition.
pub const fn bcu2_definition() -> Bcu2DeviceDefinition {
    Bcu2DeviceDefinition {
        manufacturer_id: LightSwitchDevice::MANUFACTURER_ID,
        app_manufacturer_id: LightSwitchDevice::MANUFACTURER_ID,
        device_type: LightSwitchDevice::APPLICATION_ID_TP1_BCU2,
        version: LightSwitchDevice::APPLICATION_VERSION,
        pei_type: LightSwitchDevice::PEI_TYPE,
        individual_address: IndividualAddress::new(15, 15, 255),
        max_group_addresses: LightSwitchDevice::MAX_ADDRESS_TABLE_ENTRIES as u8,
        max_associations: LightSwitchDevice::MAX_ASSOCIATION_TABLE_ENTRIES as u8,
        ram_flags_ptr: RAM_FLAGS_PTR,
        comm_objects: &CO_DESCRIPTORS_BCU2,
        group_addresses: &[],
        associations: &[],
        app_params: Some((&DEFAULT_PARAM_BYTES, BCU2_PARAMS_IMAGE_OFFSET)),
    }
}

/// The Data Secure BCU2 (mask 0021h) light-switch definition.
///
/// Its EEPROM geometry and communication-object descriptors deliberately
/// match our ETS-backed 0020h fixture. This is a product choice, not a claim
/// that Volume 9 defines the two masks as byte-for-byte identical; it only
/// guarantees upward compatibility and explicitly calls out different user
/// RAM capacity.
pub const fn secure_bcu2_definition() -> Bcu2DeviceDefinition {
    let mut definition = bcu2_definition();
    definition.device_type = LightSwitchDevice::APPLICATION_ID_TP1_BCU2_SECURE;
    definition
}

/// The micro System 7 definition. It deliberately shares identity and
/// geometry with the full-stack System 7 product, so either implementation is
/// programmed from the same mask-0705 product database.
pub const fn system7_definition() -> System7DeviceDefinition {
    System7DeviceDefinition {
        manufacturer_id: LightSwitchDevice::MANUFACTURER_ID,
        device_type: LightSwitchDevice::APPLICATION_ID_TP1_SYSTEM7,
        version: LightSwitchDevice::APPLICATION_VERSION,
        individual_address: IndividualAddress::new(15, 15, 255),
        max_group_addresses: LightSwitchDevice::MAX_ADDRESS_TABLE_ENTRIES as u8,
        max_associations: LightSwitchDevice::MAX_ASSOCIATION_TABLE_ENTRIES as u8,
        ram_flags_ptr: RAM_FLAGS_PTR as u16,
        comm_objects: &CO_DESCRIPTORS_S7,
        group_addresses: &[],
        associations: &[],
        ast_offset: 0x100,
        app_offset: S7_PARAMS_IMAGE_OFFSET,
        app_params: &DEFAULT_PARAM_BYTES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the derived tables to the previous hand-written wire values. The
    /// boot images, product database, and download overlay all depend on them.
    #[test]
    fn derived_co_descriptors_match_the_wire_tables() {
        for (i, row) in CO_DESCRIPTORS_BCU2.iter().enumerate() {
            assert_eq!(row.data_ptr, 0xC6 + i as u8, "object {i} slot");
            let expected_config = if i % 3 == 1 { 0xF7 } else { 0x47 };
            assert_eq!(row.config, expected_config, "object {i} config");
            let expected_type = if i % 3 == 2 { 0x03 } else { 0x00 };
            assert_eq!(row.value_type, expected_type, "object {i} type");
        }
        for (bcu2, s7) in CO_DESCRIPTORS_BCU2.iter().zip(CO_DESCRIPTORS_S7.iter()) {
            assert_eq!(s7.data_ptr, bcu2.data_ptr as u16);
            assert_eq!(s7.config, bcu2.config);
            assert_eq!(s7.value_type, bcu2.value_type);
        }
    }

    #[test]
    fn s7_image_matches_the_shared_product_geometry() {
        let image = LightSwitchS7Family::build_eeprom(&system7_definition());
        // COT at 4200h: count 6, RAM flags at 00D0h, first row at 00C6h.
        assert_eq!(image[0x200], 6);
        assert_eq!(&image[0x201..0x203], &[0x00, 0xD0]);
        assert_eq!(&image[0x203..0x205], &[0x00, 0xC6]);
        assert_eq!(&image[0x300..0x300 + DEFAULT_PARAM_BYTES.len()], &DEFAULT_PARAM_BYTES);
    }
}
