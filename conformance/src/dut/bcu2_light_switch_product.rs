//! The real BCU2 light-switch products, rendered in-process.
//!
//! Unlike [`super::bcu2_product`] — the fixture product mirroring the
//! conformance DUT's own object roster — this is the *shipping* BCU2
//! light switch: `devices::light_switch` with its ETS-configurable
//! parameters, generated through the same `Bcu2MemoryLayout` path as
//! `gen_light_switch_mtxml` and from the same
//! `micro::{bcu2_definition, secure_bcu2_definition}()` the firmware boots.
//! The configuration runner downloads them against the matching BCU2 DUT to
//! prove a genuine
//! parameterized product survives the round trip: table pointers
//! preserved out of the product's segment data, parameter bytes
//! patched into the 0200h segment.

use devices::light_switch::params::{DEFAULT_PARAM_BYTES, LIGHT_SWITCH_VIRTUAL_PARAMS};
use devices::light_switch::{
    DEVICE_DESCRIPTOR_TP1_BCU2, DEVICE_DESCRIPTOR_TP1_BCU2_SECURE, LightSwitchDevice, LightSwitchParams, comm_objs,
    micro,
};
use zweidraehte_knxprod::{ApplicationProgramDef, Bcu2MemoryLayout, KnxprodBuilder, SingleDeviceDef};
use zweidraehte_microdevice::Bcu2DeviceDefinition;
use zweidraehte_microdevice::families::bcu2::BCU2_EEPROM_SIZE;

/// Generate the light-switch MV-0020 application program MTXML.
pub fn generate_mtxml() -> Result<String, String> {
    generate(ProductVariant::Plain0020)
}

/// Generate a non-secure light-switch application for mask 0021h.
pub fn generate_plain_0021_mtxml() -> Result<String, String> {
    generate(ProductVariant::Plain0021)
}

/// Generate the Data Secure light-switch MV-0021 application program MTXML.
pub fn generate_secure_mtxml() -> Result<String, String> {
    generate(ProductVariant::Secure0021)
}

#[derive(Clone, Copy)]
enum ProductVariant {
    Plain0020,
    Plain0021,
    Secure0021,
}

impl ProductVariant {
    fn definition(self) -> Bcu2DeviceDefinition {
        match self {
            Self::Plain0020 => micro::bcu2_definition(),
            Self::Plain0021 | Self::Secure0021 => micro::secure_bcu2_definition(),
        }
    }

    fn build_eeprom(self, definition: &Bcu2DeviceDefinition) -> [u8; BCU2_EEPROM_SIZE] {
        match self {
            Self::Plain0020 => definition.build_eeprom(),
            Self::Plain0021 | Self::Secure0021 => definition.build_eeprom_for_mask(0x0021),
        }
    }
}

fn generate(variant: ProductVariant) -> Result<String, String> {
    let def = variant.definition();
    let image = variant.build_eeprom(&def);
    // Leaked once per process — the generator wants 'static segment data.
    let tables: &'static [u8] = Box::leak(image[..micro::BCU2_PARAMS_IMAGE_OFFSET].to_vec().into_boxed_slice());

    let (name, descriptor, hardware_type, hardware_name, product_name, order_number) = match variant {
        ProductVariant::Plain0020 => (
            "LightSwitch2TPBCU2",
            &DEVICE_DESCRIPTOR_TP1_BCU2,
            LightSwitchDevice::HARDWARE_TYPE_TP1_BCU2,
            "2-Button Light Switch TP1 BCU2",
            "Light Switch 2-fold (TP1, BCU2)",
            "LS-0002-TP-B2",
        ),
        ProductVariant::Plain0021 => (
            "LightSwitch2TPBCU20021",
            &DEVICE_DESCRIPTOR_TP1_BCU2_SECURE,
            LightSwitchDevice::HARDWARE_TYPE_TP1_BCU2_SECURE,
            "2-Button Light Switch TP1 BCU2 0021",
            "Light Switch 2-fold (TP1, BCU2 0021)",
            "LS-0002-TP-B2-21",
        ),
        ProductVariant::Secure0021 => (
            "LightSwitch2TPBCU2Secure",
            &DEVICE_DESCRIPTOR_TP1_BCU2_SECURE,
            LightSwitchDevice::HARDWARE_TYPE_TP1_BCU2_SECURE,
            "2-Button Light Switch TP1 BCU2 Secure",
            "Light Switch 2-fold (TP1, BCU2, Secure)",
            "LS-0002-TP-B2-SEC",
        ),
    };

    let app = ApplicationProgramDef {
        name,
        device: descriptor,
        params: LightSwitchParams::ETS_PARAMS_EXT,
        virtual_params: Some(LIGHT_SWITCH_VIRTUAL_PARAMS),
        param_defaults: &DEFAULT_PARAM_BYTES,
        comm_objects: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECTS,
        comm_object_refs: comm_objs::LightSwitchComObjects::ETS_COMM_OBJECT_REFS,
        union_fields: Some(LightSwitchParams::ETS_UNIONS),
        channel_name: "General",
        absolute_segment_address: None,
        bcu2_layout: Some(Bcu2MemoryLayout {
            tables_address: 0x0100,
            tables_data: tables,
            addr_table_offset: def.addr_table_offset() as u32,
            assoc_table_offset: def.assoc_table_offset() as u32,
            cot_offset: def.cot_offset() as u32,
            params_address: 0x0100 + micro::BCU2_PARAMS_IMAGE_OFFSET as u32,
        }),
        system7_layout: None,
        application_hash: None,
        non_reg_relevant_data_version: None,
        replaces_versions: None,
        application_data_hash: None,
        // The auto-generated Dynamic section is enough for a download —
        // the shipping page layout only shapes the ETS UI.
        page_layout: None,
        modules: None,
        baggages: None,
        translations: None,
        bus_interfaces: None,
        additional_addresses_count: None,
        ip_config: None,
        is_secure_enabled: matches!(variant, ProductVariant::Secure0021).then_some(true),
        max_user_entries: None,
        max_tunneling_user_entries: None,
        max_security_individual_address_entries: matches!(variant, ProductVariant::Secure0021)
            .then_some(micro::BCU2_SECURE_SIAT_CAPACITY as u16),
        max_security_group_key_table_entries: matches!(variant, ProductVariant::Secure0021)
            .then_some(micro::BCU2_SECURE_GROUP_KEY_CAPACITY as u16),
        max_security_p2p_key_table_entries: matches!(variant, ProductVariant::Secure0021)
            .then_some(micro::BCU2_SECURE_P2P_KEY_CAPACITY as u16),
    };

    let output = KnxprodBuilder::single_device(SingleDeviceDef {
        app: &app,
        serial_number: hardware_type,
        hardware_version: 1,
        hardware_name,
        product_name,
        order_number,
        is_rail_mounted: false,
        catalog_section: "Push Buttons",
        is_ip_enabled: None,
        is_rf_retransmitter: None,
        rf_rx_capabilities: None,
        rf_tx_capabilities: None,
    })
    .generate_all()
    .map_err(|e| format!("generating the light-switch product file: {e}"))?;

    output
        .application_programs
        .into_iter()
        .next()
        .map(|(_, xml)| xml)
        .ok_or_else(|| "the generator produced no application program".to_string())
}

#[cfg(test)]
mod tests {
    use zweidraehte_client::download::ProductData;
    use zweidraehte_proto::device::MaskVersion;

    use super::*;

    #[test]
    fn secure_product_matches_the_firmware_profile() {
        let xml = generate_secure_mtxml().expect("secure light-switch product generates");
        let product = ProductData::from_mtxml_str(&xml).expect("secure light-switch product parses");

        assert_eq!(product.mask_version, Some(MaskVersion::Bcu2Tp1));
        assert!(product.is_secure_enabled);
        assert_eq!(product.com_object_numbers.len(), LightSwitchDevice::MAX_COM_OBJECTS as usize);
        assert_eq!(product.max_security_individual_address_entries, Some(micro::BCU2_SECURE_SIAT_CAPACITY as u16));
        assert_eq!(product.max_security_group_key_table_entries, Some(micro::BCU2_SECURE_GROUP_KEY_CAPACITY as u16));
        assert_eq!(product.max_security_p2p_key_table_entries, Some(0));
    }
}
