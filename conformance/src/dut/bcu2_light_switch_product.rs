//! The real mask-0020 light-switch product, rendered in-process.
//!
//! Unlike [`super::bcu2_product`] — the fixture product mirroring the
//! conformance DUT's own object roster — this is the *shipping* BCU2
//! light switch: `devices::light_switch` with its ETS-configurable
//! parameters, generated through the same `Bcu2MemoryLayout` path as
//! `gen_light_switch_mtxml` and from the same
//! `micro::bcu2_definition()` the firmware boots. The configuration
//! runner downloads it against a BCU2 DUT to prove a genuine
//! parameterized product survives the round trip: table pointers
//! preserved out of the product's segment data, parameter bytes
//! patched into the 0200h segment.

use devices::light_switch::params::{DEFAULT_PARAM_BYTES, LIGHT_SWITCH_VIRTUAL_PARAMS};
use devices::light_switch::{DEVICE_DESCRIPTOR_TP1_BCU2, LightSwitchParams, comm_objs, micro};
use zweidraehte_knxprod::{ApplicationProgramDef, Bcu2MemoryLayout, KnxprodBuilder, SingleDeviceDef};

/// Generate the light-switch MV-0020 application program MTXML.
pub fn generate_mtxml() -> Result<String, String> {
    let def = micro::bcu2_definition();
    let image = def.build_eeprom();
    // Leaked once per process — the generator wants 'static segment data.
    let tables: &'static [u8] = Box::leak(image[..micro::BCU2_PARAMS_IMAGE_OFFSET].to_vec().into_boxed_slice());

    let app = ApplicationProgramDef {
        name: "LightSwitch2TPBCU2",
        device: &DEVICE_DESCRIPTOR_TP1_BCU2,
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
        is_secure_enabled: None,
        max_user_entries: None,
        max_tunneling_user_entries: None,
        max_security_individual_address_entries: None,
        max_security_group_key_table_entries: None,
        max_security_p2p_key_table_entries: None,
    };

    let output = KnxprodBuilder::single_device(SingleDeviceDef {
        app: &app,
        serial_number: devices::light_switch::LightSwitchDevice::HARDWARE_TYPE_TP1_BCU2,
        hardware_version: 1,
        hardware_name: "2-Button Light Switch TP1 BCU2",
        product_name: "Light Switch 2-fold (TP1, BCU2)",
        order_number: "LS-0002-TP-B2",
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
